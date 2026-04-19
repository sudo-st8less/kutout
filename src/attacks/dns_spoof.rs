// dns spoofing

use std::net::Ipv4Addr;

#[derive(Debug, Clone)]
pub struct DnsSpoofRule {
    pub domain: String,
    pub spoof_ip: Ipv4Addr,
}

// parse wire-format name at offset
pub fn parse_dns_name(data: &[u8], offset: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut pos = offset;
    let mut jumped = false;
    let mut jump_pos = 0;

    loop {
        if pos >= data.len() {
            return None;
        }

        let len = data[pos] as usize;

        // compression pointer
        if len & 0xc0 == 0xc0 {
            if pos + 1 >= data.len() {
                return None;
            }
            if !jumped {
                jump_pos = pos + 2;
            }
            pos = (len & 0x3f) << 8 | data[pos + 1] as usize;
            jumped = true;
            continue;
        }

        // end
        if len == 0 {
            if !jumped {
                jump_pos = pos + 1;
            }
            break;
        }

        pos += 1;
        if pos + len > data.len() {
            return None;
        }

        let label = std::str::from_utf8(&data[pos..pos + len]).ok()?;
        labels.push(label.to_string());
        pos += len;
    }

    Some((labels.join("."), jump_pos - offset))
}

// extract query name from dns payload
pub fn extract_query_name(dns_payload: &[u8]) -> Option<String> {
    if dns_payload.len() < 12 {
        return None;
    }

    // must be query (qr=0)
    let flags = u16::from_be_bytes([dns_payload[2], dns_payload[3]]);
    if flags & 0x8000 != 0 {
        return None;
    }

    let qdcount = u16::from_be_bytes([dns_payload[4], dns_payload[5]]);
    if qdcount == 0 {
        return None;
    }

    let (name, _consumed) = parse_dns_name(dns_payload, 12)?;
    Some(name.to_lowercase())
}

// "i would rather have questions that can't be answered
//  than answers that can't be questioned." — richard feynman

// build spoofed A record response
pub fn build_spoofed_response(query_payload: &[u8], spoof_ip: Ipv4Addr) -> Option<Vec<u8>> {
    if query_payload.len() < 12 {
        return None;
    }

    let txid = [query_payload[0], query_payload[1]];

    let (_name, name_bytes) = parse_dns_name(query_payload, 12)?;
    let question_end = 12 + name_bytes + 4;

    if question_end > query_payload.len() {
        return None;
    }

    let mut resp = Vec::with_capacity(question_end + 16);

    // header
    resp.push(txid[0]);
    resp.push(txid[1]);
    resp.push(0x85); // qr=1, aa=1, rd=1
    resp.push(0x80); // ra=1
    resp.push(0x00); resp.push(0x01); // qdcount
    resp.push(0x00); resp.push(0x01); // ancount
    resp.push(0x00); resp.push(0x00); // nscount
    resp.push(0x00); resp.push(0x00); // arcount

    // question
    resp.extend_from_slice(&query_payload[12..question_end]);

    // answer: pointer to name
    resp.push(0xc0);
    resp.push(0x0c);
    resp.push(0x00); resp.push(0x01); // type A
    resp.push(0x00); resp.push(0x01); // class IN
    resp.push(0x00); resp.push(0x00); resp.push(0x01); resp.push(0x2c); // ttl 300
    resp.push(0x00); resp.push(0x04); // rdlength
    let octets = spoof_ip.octets();
    resp.extend_from_slice(&octets);

    Some(resp)
}

// domain matching with wildcard support
pub fn matches_rule(query_name: &str, rule_domain: &str) -> bool {
    let q = query_name.to_lowercase();
    let r = rule_domain.to_lowercase();

    if q == r {
        return true;
    }

    // *.example.com
    if let Some(suffix) = r.strip_prefix("*.") {
        return q.ends_with(suffix) && q.len() > suffix.len();
    }

    // subdomain match
    q.ends_with(&format!(".{}", r))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_dns_name(name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for label in name.split('.') {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out
    }

    fn build_test_query(domain: &str) -> Vec<u8> {
        let mut buf = vec![
            0xab, 0xcd, // txid
            0x01, 0x00, // flags
            0x00, 0x01, // qdcount
            0, 0, 0, 0, 0, 0, // an/ns/ar counts
        ];
        buf.extend_from_slice(&encode_dns_name(domain));
        buf.extend_from_slice(&[
            0x00, 0x01, // type A
            0x00, 0x01, // class IN
        ]);
        buf
    }

    #[test]
    fn test_parse_dns_name() {
        let data = encode_dns_name("www.example.com");
        let mut buf = vec![0u8; 0];
        buf.extend_from_slice(&data);
        let (name, consumed) = parse_dns_name(&buf, 0).unwrap();
        assert_eq!(name, "www.example.com");
        assert_eq!(consumed, data.len());
    }

    #[test]
    fn test_extract_query_name() {
        let query = build_test_query("evil.com");
        let name = extract_query_name(&query).unwrap();
        assert_eq!(name, "evil.com");
    }

    #[test]
    fn test_extract_query_name_rejects_response() {
        let mut query = build_test_query("evil.com");
        query[2] |= 0x80;
        assert!(extract_query_name(&query).is_none());
    }

    #[test]
    fn test_build_spoofed_response() {
        let query = build_test_query("evil.com");
        let spoof_ip = Ipv4Addr::new(192, 168, 1, 99);
        let resp = build_spoofed_response(&query, spoof_ip).unwrap();

        assert!(resp[2] & 0x80 != 0, "qr bit should be set");
        assert_eq!(resp[0], 0xab);
        assert_eq!(resp[1], 0xcd);
        assert_eq!(resp[6], 0x00);
        assert_eq!(resp[7], 0x01);
        let len = resp.len();
        assert_eq!(&resp[len - 4..], &[192, 168, 1, 99]);
    }

    #[test]
    fn test_matches_rule_exact() {
        assert!(matches_rule("evil.com", "evil.com"));
        assert!(matches_rule("Evil.Com", "evil.com"));
        assert!(!matches_rule("notevil.com", "evil.com"));
    }

    #[test]
    fn test_matches_rule_subdomain() {
        assert!(matches_rule("sub.evil.com", "evil.com"));
        assert!(matches_rule("deep.sub.evil.com", "evil.com"));
        assert!(!matches_rule("evil.com", "sub.evil.com"));
    }

    #[test]
    fn test_matches_rule_wildcard() {
        assert!(matches_rule("foo.evil.com", "*.evil.com"));
        assert!(matches_rule("bar.evil.com", "*.evil.com"));
        assert!(!matches_rule("evil.com", "*.evil.com"));
    }

    #[test]
    fn test_build_spoofed_response_too_short() {
        assert!(build_spoofed_response(&[0; 5], Ipv4Addr::LOCALHOST).is_none());
    }

    #[test]
    fn test_parse_dns_name_empty() {
        let data = [0u8];
        let (name, consumed) = parse_dns_name(&data, 0).unwrap();
        assert_eq!(name, "");
        assert_eq!(consumed, 1);
    }
}
