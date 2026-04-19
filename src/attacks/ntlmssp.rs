// ntlmssp — microsoft challenge/response auth parser.
//
// reference: ms-nlmp (https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/)
//
// three message types (all start with "NTLMSSP\0" + u32 le MessageType):
//   type 1 NEGOTIATE     client→server  "hi, i'd like to auth"
//   type 2 CHALLENGE     server→client  contains 8-byte server challenge
//   type 3 AUTHENTICATE  client→server  contains username + NtChallengeResponse
//
// to build a hashcat netntlmv2 hash (mode 5600) we need:
//   - the 8-byte ServerChallenge from the type-2 message, and
//   - the username / domain / NtChallengeResponse from the type-3 message
// these arrive in separate packets, so a pairing tracker lives in the
// forwarding layer (per-flow state).
//
// this module is pure — it parses bytes and formats output, nothing else.

const SIGNATURE: &[u8] = b"NTLMSSP\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NtlmMessageType {
    Negotiate = 1,
    Challenge = 2,
    Authenticate = 3,
}

// scan `data` for the first embedded NTLMSSP message; return (offset, type).
// used when the ntlmssp blob is inside a larger container (base64-decoded
// http header, a hypothetical smb2 security buffer, etc.).
pub fn find_message(data: &[u8]) -> Option<(usize, NtlmMessageType)> {
    if data.len() < 12 {
        return None;
    }
    for i in 0..=data.len() - 12 {
        if &data[i..i + 8] == SIGNATURE {
            let t = u32::from_le_bytes([
                data[i + 8],
                data[i + 9],
                data[i + 10],
                data[i + 11],
            ]);
            let msg_type = match t {
                1 => NtlmMessageType::Negotiate,
                2 => NtlmMessageType::Challenge,
                3 => NtlmMessageType::Authenticate,
                _ => continue,
            };
            return Some((i, msg_type));
        }
    }
    None
}

// type-2 server challenge: 8 bytes at offset 24
pub fn parse_challenge(msg: &[u8]) -> Option<[u8; 8]> {
    if msg.len() < 32 || &msg[0..8] != SIGNATURE {
        return None;
    }
    if u32::from_le_bytes([msg[8], msg[9], msg[10], msg[11]]) != 2 {
        return None;
    }
    let mut out = [0u8; 8];
    out.copy_from_slice(&msg[24..32]);
    Some(out)
}

#[derive(Debug, Clone)]
pub struct NtlmAuthenticate {
    pub domain: String,
    pub username: String,
    // full NtChallengeResponse bytes. for v2: first 16 bytes are NTproofStr,
    // remainder is the NTLMv2_CLIENT_CHALLENGE blob (hashcat wants them split).
    pub nt_response: Vec<u8>,
}

pub fn parse_authenticate(msg: &[u8]) -> Option<NtlmAuthenticate> {
    if msg.len() < 52 || &msg[0..8] != SIGNATURE {
        return None;
    }
    if u32::from_le_bytes([msg[8], msg[9], msg[10], msg[11]]) != 3 {
        return None;
    }

    // security buffer layout (all little-endian):
    //   LmChallengeResponseFields   @ 12
    //   NtChallengeResponseFields   @ 20
    //   DomainNameFields            @ 28
    //   UserNameFields              @ 36
    //   WorkstationFields           @ 44
    let (nt_len, nt_off) = read_security_buffer(msg, 20)?;
    let (dom_len, dom_off) = read_security_buffer(msg, 28)?;
    let (usr_len, usr_off) = read_security_buffer(msg, 36)?;

    let domain = slice_field(msg, dom_off, dom_len).map(decode_utf16le)?;
    let username = slice_field(msg, usr_off, usr_len).map(decode_utf16le)?;
    let nt_response = slice_field(msg, nt_off, nt_len)?.to_vec();

    Some(NtlmAuthenticate {
        domain,
        username,
        nt_response,
    })
}

// hashcat mode 5600 (netntlmv2):
//   username::domain:serverChallenge:NTproofStr:NTLMv2_CLIENT_CHALLENGE_blob
// all three binary fields are lowercase hex.
//
// returns None if nt_response is too short to be v2 (v1 responses are exactly
// 24 bytes; v2 is always > 24 because it includes a >=8-byte client challenge
// appended after the 16-byte NTproofStr).
pub fn format_hashcat_5600(
    username: &str,
    domain: &str,
    challenge: &[u8; 8],
    nt_response: &[u8],
) -> Option<String> {
    if nt_response.len() <= 24 {
        return None; // likely ntlmv1 or malformed
    }
    let (nt_proof, blob) = nt_response.split_at(16);
    Some(format!(
        "{}::{}:{}:{}:{}",
        username,
        domain,
        hex(challenge),
        hex(nt_proof),
        hex(blob)
    ))
}

// rfc 4648 base64 encoder (needed by tests and future rogue auth servers
// that will emit their own CHALLENGE responses in http headers).
#[allow(dead_code)] // phase 4 rogue-auth server will emit b64 challenges
pub fn base64_encode(data: &[u8]) -> String {
    const ALPHA: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    let mut i = 0;
    while i + 3 <= data.len() {
        let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8) | (data[i + 2] as u32);
        out.push(ALPHA[((n >> 18) & 63) as usize] as char);
        out.push(ALPHA[((n >> 12) & 63) as usize] as char);
        out.push(ALPHA[((n >> 6) & 63) as usize] as char);
        out.push(ALPHA[(n & 63) as usize] as char);
        i += 3;
    }
    let rem = data.len() - i;
    if rem == 1 {
        let n = (data[i] as u32) << 16;
        out.push(ALPHA[((n >> 18) & 63) as usize] as char);
        out.push(ALPHA[((n >> 12) & 63) as usize] as char);
        out.push_str("==");
    } else if rem == 2 {
        let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8);
        out.push(ALPHA[((n >> 18) & 63) as usize] as char);
        out.push(ALPHA[((n >> 12) & 63) as usize] as char);
        out.push(ALPHA[((n >> 6) & 63) as usize] as char);
        out.push('=');
    }
    out
}

// rfc 4648 base64 decoder. accepts padded or unpadded, ignores whitespace.
// returns None on invalid chars.
pub fn base64_decode(input: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    for c in input.chars() {
        let v: u32 = match c {
            'A'..='Z' => c as u32 - 'A' as u32,
            'a'..='z' => c as u32 - 'a' as u32 + 26,
            '0'..='9' => c as u32 - '0' as u32 + 52,
            '+' => 62,
            '/' => 63,
            '=' => break,
            c if c.is_whitespace() => continue,
            _ => return None,
        };
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1u32 << bits) - 1;
        }
    }
    Some(out)
}

// ─── internals ────────────────────────────────────────────────────────────

// security buffer = 2B length, 2B maxlength, 4B offset (all LE, from message start)
fn read_security_buffer(msg: &[u8], field_offset: usize) -> Option<(usize, usize)> {
    if field_offset + 8 > msg.len() {
        return None;
    }
    let len = u16::from_le_bytes([msg[field_offset], msg[field_offset + 1]]) as usize;
    let buf_offset = u32::from_le_bytes([
        msg[field_offset + 4],
        msg[field_offset + 5],
        msg[field_offset + 6],
        msg[field_offset + 7],
    ]) as usize;
    Some((len, buf_offset))
}

fn slice_field(msg: &[u8], offset: usize, len: usize) -> Option<&[u8]> {
    let end = offset.checked_add(len)?;
    msg.get(offset..end)
}

fn decode_utf16le(bytes: &[u8]) -> String {
    let mut words = Vec::with_capacity(bytes.len() / 2);
    for chunk in bytes.chunks_exact(2) {
        words.push(u16::from_le_bytes([chunk[0], chunk[1]]));
    }
    String::from_utf16_lossy(&words)
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

// test fixtures shared with forwarding.rs integration tests.
#[cfg(test)]
pub(crate) fn build_challenge_msg_for_tests(challenge: [u8; 8]) -> Vec<u8> {
    let mut m = vec![0u8; 48];
    m[0..8].copy_from_slice(SIGNATURE);
    m[8..12].copy_from_slice(&2u32.to_le_bytes());
    m[16..20].copy_from_slice(&48u32.to_le_bytes());
    m[24..32].copy_from_slice(&challenge);
    m[44..48].copy_from_slice(&48u32.to_le_bytes());
    m
}

#[cfg(test)]
pub(crate) fn build_authenticate_msg_for_tests(
    domain: &str,
    user: &str,
    nt_response: &[u8],
) -> Vec<u8> {
    let dom: Vec<u8> = domain.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let usr: Vec<u8> = user.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let fixed = 52;
    let lm_off = fixed;
    let nt_off = lm_off;
    let dom_off = nt_off + nt_response.len();
    let usr_off = dom_off + dom.len();
    let total = usr_off + usr.len();

    let mut m = vec![0u8; total];
    m[0..8].copy_from_slice(SIGNATURE);
    m[8..12].copy_from_slice(&3u32.to_le_bytes());

    // LmChallengeResponseFields @ 12: len=0, offset=lm_off
    m[16..20].copy_from_slice(&(lm_off as u32).to_le_bytes());
    // NtChallengeResponseFields @ 20
    m[20..22].copy_from_slice(&(nt_response.len() as u16).to_le_bytes());
    m[22..24].copy_from_slice(&(nt_response.len() as u16).to_le_bytes());
    m[24..28].copy_from_slice(&(nt_off as u32).to_le_bytes());
    // DomainNameFields @ 28
    m[28..30].copy_from_slice(&(dom.len() as u16).to_le_bytes());
    m[30..32].copy_from_slice(&(dom.len() as u16).to_le_bytes());
    m[32..36].copy_from_slice(&(dom_off as u32).to_le_bytes());
    // UserNameFields @ 36
    m[36..38].copy_from_slice(&(usr.len() as u16).to_le_bytes());
    m[38..40].copy_from_slice(&(usr.len() as u16).to_le_bytes());
    m[40..44].copy_from_slice(&(usr_off as u32).to_le_bytes());

    m[nt_off..dom_off].copy_from_slice(nt_response);
    m[dom_off..usr_off].copy_from_slice(&dom);
    m[usr_off..total].copy_from_slice(&usr);
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    // build a minimal but valid type-2 CHALLENGE message.
    // 8B sig + 4B type + 8B targetname-fields + 4B flags + 8B challenge + 8B
    // reserved + 8B targetinfo-fields = 48 bytes minimum; we put targetname/
    // targetinfo at the tail but length=0 so no string body needed.
    fn build_challenge(challenge: [u8; 8]) -> Vec<u8> {
        let mut m = vec![0u8; 48];
        m[0..8].copy_from_slice(SIGNATURE);
        m[8..12].copy_from_slice(&2u32.to_le_bytes());
        // TargetNameFields: len=0, maxlen=0, offset=48 (past end, but len=0 → ok)
        m[12..14].copy_from_slice(&0u16.to_le_bytes());
        m[14..16].copy_from_slice(&0u16.to_le_bytes());
        m[16..20].copy_from_slice(&48u32.to_le_bytes());
        // NegotiateFlags
        m[20..24].copy_from_slice(&0u32.to_le_bytes());
        // ServerChallenge
        m[24..32].copy_from_slice(&challenge);
        // Reserved @ 32..40 — already zero
        // TargetInfoFields: len=0, offset=48
        m[40..42].copy_from_slice(&0u16.to_le_bytes());
        m[42..44].copy_from_slice(&0u16.to_le_bytes());
        m[44..48].copy_from_slice(&48u32.to_le_bytes());
        m
    }

    fn encode_utf16le(s: &str) -> Vec<u8> {
        let mut out = Vec::with_capacity(s.len() * 2);
        for c in s.encode_utf16() {
            out.extend_from_slice(&c.to_le_bytes());
        }
        out
    }

    // build a type-3 AUTHENTICATE with the given user/domain/workstation and
    // an nt_response of `nt_response` bytes. string bodies appended after the
    // fixed 52-byte field section.
    fn build_authenticate(
        domain: &str,
        user: &str,
        workstation: &str,
        nt_response: &[u8],
        lm_response: &[u8],
    ) -> Vec<u8> {
        let dom_bytes = encode_utf16le(domain);
        let usr_bytes = encode_utf16le(user);
        let ws_bytes = encode_utf16le(workstation);

        // layout: [fixed 52B header][lm][nt][dom][usr][ws]
        let fixed_len = 52;
        let lm_off = fixed_len;
        let nt_off = lm_off + lm_response.len();
        let dom_off = nt_off + nt_response.len();
        let usr_off = dom_off + dom_bytes.len();
        let ws_off = usr_off + usr_bytes.len();
        let total = ws_off + ws_bytes.len();

        let mut m = vec![0u8; total];
        m[0..8].copy_from_slice(SIGNATURE);
        m[8..12].copy_from_slice(&3u32.to_le_bytes());

        let write_sb = |buf: &mut [u8], field: usize, len: usize, off: usize| {
            buf[field..field + 2].copy_from_slice(&(len as u16).to_le_bytes());
            buf[field + 2..field + 4].copy_from_slice(&(len as u16).to_le_bytes());
            buf[field + 4..field + 8].copy_from_slice(&(off as u32).to_le_bytes());
        };
        write_sb(&mut m, 12, lm_response.len(), lm_off);
        write_sb(&mut m, 20, nt_response.len(), nt_off);
        write_sb(&mut m, 28, dom_bytes.len(), dom_off);
        write_sb(&mut m, 36, usr_bytes.len(), usr_off);
        write_sb(&mut m, 44, ws_bytes.len(), ws_off);

        m[lm_off..nt_off].copy_from_slice(lm_response);
        m[nt_off..dom_off].copy_from_slice(nt_response);
        m[dom_off..usr_off].copy_from_slice(&dom_bytes);
        m[usr_off..ws_off].copy_from_slice(&usr_bytes);
        m[ws_off..total].copy_from_slice(&ws_bytes);

        m
    }

    #[test]
    fn test_find_message_challenge() {
        let msg = build_challenge([0x11; 8]);
        let (off, t) = find_message(&msg).unwrap();
        assert_eq!(off, 0);
        assert_eq!(t, NtlmMessageType::Challenge);
    }

    #[test]
    fn test_find_message_with_prefix_junk() {
        let mut data = vec![0xdeu8, 0xad, 0xbe, 0xef, 0xca, 0xfe];
        let msg = build_challenge([0x22; 8]);
        data.extend_from_slice(&msg);
        let (off, t) = find_message(&data).unwrap();
        assert_eq!(off, 6);
        assert_eq!(t, NtlmMessageType::Challenge);
    }

    #[test]
    fn test_find_message_returns_none_on_empty() {
        assert!(find_message(&[]).is_none());
        assert!(find_message(b"NTLMSSP").is_none()); // missing null + type
    }

    #[test]
    fn test_find_message_ignores_bad_type_byte() {
        // signature present but MessageType = 42 → skipped
        let mut msg = vec![0u8; 12];
        msg[0..8].copy_from_slice(SIGNATURE);
        msg[8..12].copy_from_slice(&42u32.to_le_bytes());
        assert!(find_message(&msg).is_none());
    }

    #[test]
    fn test_parse_challenge_extracts_bytes() {
        let challenge = [0xaa, 0xbb, 0xcc, 0xdd, 0x11, 0x22, 0x33, 0x44];
        let msg = build_challenge(challenge);
        assert_eq!(parse_challenge(&msg).unwrap(), challenge);
    }

    #[test]
    fn test_parse_challenge_rejects_type_3() {
        let auth = build_authenticate("D", "U", "W", &[0u8; 32], &[0u8; 24]);
        assert!(parse_challenge(&auth).is_none());
    }

    #[test]
    fn test_parse_challenge_rejects_too_short() {
        assert!(parse_challenge(b"NTLMSSP\0\x02\x00\x00\x00").is_none());
    }

    #[test]
    fn test_parse_authenticate_roundtrip() {
        let nt = {
            let mut v = Vec::new();
            v.extend_from_slice(&[0x11; 16]); // NTproof
            v.extend_from_slice(&[0x22; 32]); // blob
            v
        };
        let lm = vec![0u8; 24];
        let msg = build_authenticate("CORP", "alice", "DESKTOP01", &nt, &lm);

        let auth = parse_authenticate(&msg).unwrap();
        assert_eq!(auth.domain, "CORP");
        assert_eq!(auth.username, "alice");
        assert_eq!(auth.nt_response, nt);
    }

    #[test]
    fn test_parse_authenticate_rejects_challenge() {
        let msg = build_challenge([0u8; 8]);
        assert!(parse_authenticate(&msg).is_none());
    }

    #[test]
    fn test_format_hashcat_5600_shape() {
        let challenge = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        let mut nt = Vec::new();
        nt.extend_from_slice(&[0xaa; 16]); // NTproof
        nt.extend_from_slice(&[0xbb; 24]); // blob
        let line = format_hashcat_5600("alice", "CORP", &challenge, &nt).unwrap();
        // shape: alice::CORP:<16 hex>:<32 hex>:<48 hex>
        let parts: Vec<&str> = line.split(':').collect();
        assert_eq!(parts[0], "alice");
        assert_eq!(parts[1], ""); // ::
        assert_eq!(parts[2], "CORP");
        assert_eq!(parts[3], "0123456789abcdef");
        assert_eq!(parts[4].len(), 32); // 16 bytes hex
        assert_eq!(parts[5].len(), 48); // 24 bytes hex
    }

    #[test]
    fn test_format_hashcat_5600_rejects_short_response() {
        // ntlmv1 response is exactly 24 bytes → refuse (not v2)
        let nt = vec![0u8; 24];
        assert!(format_hashcat_5600("u", "d", &[0u8; 8], &nt).is_none());
    }

    #[test]
    fn test_base64_decode_padded() {
        // "Hello" → "SGVsbG8="
        assert_eq!(base64_decode("SGVsbG8=").unwrap(), b"Hello");
    }

    #[test]
    fn test_base64_decode_unpadded() {
        assert_eq!(base64_decode("SGVsbG8").unwrap(), b"Hello");
    }

    #[test]
    fn test_base64_decode_whitespace_tolerant() {
        assert_eq!(base64_decode("SGVs\n bG8=").unwrap(), b"Hello");
    }

    #[test]
    fn test_base64_decode_rejects_garbage() {
        assert!(base64_decode("@@@@").is_none());
    }

    #[test]
    fn test_base64_roundtrip_ntlm_type2() {
        // encode/decode a crafted challenge, verify we recover the bytes
        let msg = build_challenge([0x42; 8]);
        let b64 = base64_encode(&msg);
        let decoded = base64_decode(&b64).unwrap();
        assert_eq!(decoded, msg);
    }

    // v2 boundary: exactly 24-byte nt_response is rejected (looks like v1),
    // 25-byte is accepted (smallest valid v2).
    #[test]
    fn test_format_hashcat_5600_boundary_exactly_24() {
        let nt = vec![0u8; 24];
        assert!(format_hashcat_5600("u", "d", &[0u8; 8], &nt).is_none());
    }

    #[test]
    fn test_format_hashcat_5600_boundary_25_accepted() {
        let nt = vec![0u8; 25];
        let line = format_hashcat_5600("u", "d", &[0u8; 8], &nt).unwrap();
        let parts: Vec<&str> = line.split(':').collect();
        assert_eq!(parts[4].len(), 32); // NTproof hex (16 bytes)
        assert_eq!(parts[5].len(), 18); // blob hex (9 bytes)
    }

    // empty username and domain — common with some clients; still valid
    #[test]
    fn test_format_hashcat_5600_empty_user_and_domain() {
        let mut nt = vec![0u8; 16];
        nt.extend_from_slice(&[0u8; 16]);
        let line = format_hashcat_5600("", "", &[0u8; 8], &nt).unwrap();
        assert!(line.starts_with("::"));
    }

    // malformed: security buffer points past end of message → None
    #[test]
    fn test_parse_authenticate_bad_offset_returns_none() {
        let mut msg = vec![0u8; 52];
        msg[0..8].copy_from_slice(SIGNATURE);
        msg[8..12].copy_from_slice(&3u32.to_le_bytes());
        msg[36..38].copy_from_slice(&100u16.to_le_bytes());
        msg[40..44].copy_from_slice(&9999u32.to_le_bytes());
        assert!(parse_authenticate(&msg).is_none());
    }

    // base64 double-padded input
    #[test]
    fn test_base64_decode_double_padded() {
        assert_eq!(base64_decode("SA==").unwrap(), b"H");
    }

    // short but non-empty base64 inputs must not panic
    #[test]
    fn test_base64_decode_short_inputs_no_panic() {
        let _ = base64_decode("A");
        let _ = base64_decode("AB");
        let _ = base64_decode("ABC");
    }

    #[test]
    fn test_end_to_end_pairing() {
        // type-2 with a known challenge + type-3 with known user/domain/nt →
        // format_hashcat_5600 produces a well-formed line.
        let challenge = [0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe];
        let c_msg = build_challenge(challenge);
        let ch = parse_challenge(&c_msg).unwrap();
        assert_eq!(ch, challenge);

        let mut nt = Vec::new();
        nt.extend_from_slice(&[0x77; 16]);
        nt.extend_from_slice(&[0x88; 40]);
        let a_msg = build_authenticate("EXAMPLE", "bob", "LAPTOP", &nt, &[0u8; 24]);
        let auth = parse_authenticate(&a_msg).unwrap();

        let line = format_hashcat_5600(&auth.username, &auth.domain, &ch, &auth.nt_response)
            .unwrap();
        assert!(line.starts_with("bob::EXAMPLE:deadbeefcafebabe:"));
        let parts: Vec<&str> = line.split(':').collect();
        assert_eq!(parts[4], "77777777777777777777777777777777"); // 16 * "77"
    }

}
