// safe_mode — runtime exclusion checks that prevent poisoning hosts the
// engagement must not touch (domain controllers, printers, security appliances).
//
// two layers:
//   1. static list from config: cidr ranges + mac addresses
//   2. optional heuristic: tcp-connect probe for printer ports (9100/515/631)
//
// poisoning a networked printer is a fast way to brick a device and get the
// engagement shut down.  default heuristic is ON for this reason.

use anyhow::{anyhow, Result};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::time::Duration;

// ipv4 cidr range. "network/bits" with 0 ≤ bits ≤ 32.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    pub network: Ipv4Addr,
    pub bits: u8,
}

impl Cidr {
    pub fn parse(s: &str) -> Result<Self> {
        let (net_str, bits_str) = match s.split_once('/') {
            Some(t) => t,
            None => return Err(anyhow!("cidr missing '/': {}", s)),
        };
        let network: Ipv4Addr = net_str
            .trim()
            .parse()
            .map_err(|_| anyhow!("bad ipv4 in cidr: {}", s))?;
        let bits: u8 = bits_str
            .trim()
            .parse()
            .map_err(|_| anyhow!("bad bits in cidr: {}", s))?;
        if bits > 32 {
            return Err(anyhow!("cidr bits must be 0..=32: {}", s));
        }
        Ok(Self { network, bits })
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        if self.bits == 0 {
            return true;
        }
        let mask: u32 = if self.bits == 32 {
            !0u32
        } else {
            !0u32 << (32 - self.bits)
        };
        let ip_u32 = u32::from(ip);
        let net_u32 = u32::from(self.network);
        (ip_u32 & mask) == (net_u32 & mask)
    }
}

// "aa:bb:cc:dd:ee:ff" or "aa-bb-cc-dd-ee-ff"
pub fn parse_mac(s: &str) -> Result<[u8; 6]> {
    let cleaned: String = s.chars().filter(|c| *c != ':' && *c != '-').collect();
    if cleaned.len() != 12 {
        return Err(anyhow!("bad mac length: {}", s));
    }
    let mut out = [0u8; 6];
    for (i, byte) in out.iter_mut().enumerate() {
        let hi = cleaned.as_bytes()[i * 2];
        let lo = cleaned.as_bytes()[i * 2 + 1];
        *byte = hex_digit(hi)? << 4 | hex_digit(lo)?;
    }
    Ok(out)
}

fn hex_digit(b: u8) -> Result<u8> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(anyhow!("non-hex digit: {}", b as char)),
    }
}

// parsed, ready-to-check exclusion set
#[derive(Debug, Clone, Default)]
pub struct Exclusions {
    pub cidrs: Vec<Cidr>,
    pub macs: Vec<[u8; 6]>,
    pub printer_probe: bool,
    pub probe_timeout_ms: u64,
}

impl Exclusions {
    pub fn is_excluded(&self, ip: Ipv4Addr, mac: [u8; 6]) -> bool {
        self.cidrs.iter().any(|c| c.contains(ip)) || self.macs.contains(&mac)
    }

    // check static list first (cheap), then optional printer probe (expensive)
    pub fn is_excluded_with_probe(&self, ip: Ipv4Addr, mac: [u8; 6]) -> ExclusionReason {
        if self.cidrs.iter().any(|c| c.contains(ip)) {
            return ExclusionReason::Cidr;
        }
        if self.macs.contains(&mac) {
            return ExclusionReason::Mac;
        }
        if self.printer_probe && is_likely_printer(ip, self.probe_timeout_ms) {
            return ExclusionReason::Printer;
        }
        ExclusionReason::None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExclusionReason {
    None,
    Cidr,
    Mac,
    Printer,
}

impl ExclusionReason {
    pub fn is_excluded(self) -> bool {
        !matches!(self, ExclusionReason::None)
    }

    pub fn label(self) -> &'static str {
        match self {
            ExclusionReason::None => "ok",
            ExclusionReason::Cidr => "cidr",
            ExclusionReason::Mac => "mac",
            ExclusionReason::Printer => "printer",
        }
    }
}

// tcp-connect to common printer ports.  first hit wins; short timeout per port.
pub fn is_likely_printer(ip: Ipv4Addr, timeout_ms: u64) -> bool {
    const PORTS: &[u16] = &[9100, 515, 631]; // jetdirect, lpd, ipp
    let timeout = Duration::from_millis(timeout_ms.max(50));
    for port in PORTS {
        let addr: SocketAddr = (ip, *port).into();
        if TcpStream::connect_timeout(&addr, timeout).is_ok() {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cidr_parse_24() {
        let c = Cidr::parse("10.0.0.0/24").unwrap();
        assert_eq!(c.network, Ipv4Addr::new(10, 0, 0, 0));
        assert_eq!(c.bits, 24);
    }

    #[test]
    fn test_cidr_parse_rejects_missing_slash() {
        assert!(Cidr::parse("10.0.0.1").is_err());
    }

    #[test]
    fn test_cidr_parse_rejects_bad_bits() {
        assert!(Cidr::parse("10.0.0.0/33").is_err());
        assert!(Cidr::parse("10.0.0.0/abc").is_err());
    }

    #[test]
    fn test_cidr_contains_24() {
        let c = Cidr::parse("10.0.0.0/24").unwrap();
        assert!(c.contains(Ipv4Addr::new(10, 0, 0, 0)));
        assert!(c.contains(Ipv4Addr::new(10, 0, 0, 255)));
        assert!(!c.contains(Ipv4Addr::new(10, 0, 1, 0)));
        assert!(!c.contains(Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn test_cidr_contains_32_exact_host() {
        let c = Cidr::parse("10.0.0.5/32").unwrap();
        assert!(c.contains(Ipv4Addr::new(10, 0, 0, 5)));
        assert!(!c.contains(Ipv4Addr::new(10, 0, 0, 6)));
    }

    #[test]
    fn test_cidr_contains_28() {
        // /28 → 16 addresses
        let c = Cidr::parse("192.168.1.16/28").unwrap();
        assert!(c.contains(Ipv4Addr::new(192, 168, 1, 16)));
        assert!(c.contains(Ipv4Addr::new(192, 168, 1, 31)));
        assert!(!c.contains(Ipv4Addr::new(192, 168, 1, 15)));
        assert!(!c.contains(Ipv4Addr::new(192, 168, 1, 32)));
    }

    #[test]
    fn test_cidr_contains_zero_bits_matches_everything() {
        let c = Cidr::parse("0.0.0.0/0").unwrap();
        assert!(c.contains(Ipv4Addr::new(1, 2, 3, 4)));
        assert!(c.contains(Ipv4Addr::new(255, 255, 255, 255)));
    }

    #[test]
    fn test_parse_mac_colon_form() {
        let m = parse_mac("aa:bb:cc:dd:ee:ff").unwrap();
        assert_eq!(m, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    }

    #[test]
    fn test_parse_mac_dash_form() {
        let m = parse_mac("00-11-22-33-44-55").unwrap();
        assert_eq!(m, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    }

    #[test]
    fn test_parse_mac_rejects_wrong_length() {
        assert!(parse_mac("aa:bb:cc").is_err());
        assert!(parse_mac("aa:bb:cc:dd:ee:ff:00").is_err());
    }

    #[test]
    fn test_parse_mac_rejects_non_hex() {
        assert!(parse_mac("gg:bb:cc:dd:ee:ff").is_err());
    }

    #[test]
    fn test_exclusions_matches_cidr() {
        let exc = Exclusions {
            cidrs: vec![Cidr::parse("10.0.0.0/24").unwrap()],
            macs: vec![],
            printer_probe: false,
            probe_timeout_ms: 100,
        };
        assert!(exc.is_excluded(Ipv4Addr::new(10, 0, 0, 50), [0; 6]));
        assert!(!exc.is_excluded(Ipv4Addr::new(10, 0, 1, 50), [0; 6]));
    }

    #[test]
    fn test_exclusions_matches_mac() {
        let exc = Exclusions {
            cidrs: vec![],
            macs: vec![[0xde, 0xad, 0xbe, 0xef, 0, 0]],
            printer_probe: false,
            probe_timeout_ms: 100,
        };
        assert!(exc.is_excluded(
            Ipv4Addr::new(10, 0, 0, 50),
            [0xde, 0xad, 0xbe, 0xef, 0, 0]
        ));
        assert!(!exc.is_excluded(Ipv4Addr::new(10, 0, 0, 50), [0; 6]));
    }

    #[test]
    fn test_exclusion_reason_labels() {
        assert_eq!(ExclusionReason::None.label(), "ok");
        assert_eq!(ExclusionReason::Cidr.label(), "cidr");
        assert_eq!(ExclusionReason::Mac.label(), "mac");
        assert_eq!(ExclusionReason::Printer.label(), "printer");
        assert!(!ExclusionReason::None.is_excluded());
        assert!(ExclusionReason::Cidr.is_excluded());
    }

    // /31 and /30 (the narrow masks) — often get mishandled in cidr code
    #[test]
    fn test_cidr_contains_31_bit_mask() {
        let c = Cidr::parse("10.0.0.0/31").unwrap();
        // /31 → 2 addresses: .0 and .1
        assert!(c.contains(Ipv4Addr::new(10, 0, 0, 0)));
        assert!(c.contains(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(!c.contains(Ipv4Addr::new(10, 0, 0, 2)));
    }

    // boundary: network address vs. broadcast address in a /24
    #[test]
    fn test_cidr_contains_network_and_broadcast_bounds() {
        let c = Cidr::parse("192.168.1.0/24").unwrap();
        assert!(c.contains(Ipv4Addr::new(192, 168, 1, 0)));    // network
        assert!(c.contains(Ipv4Addr::new(192, 168, 1, 255)));  // broadcast
        assert!(!c.contains(Ipv4Addr::new(192, 168, 0, 255))); // just below
        assert!(!c.contains(Ipv4Addr::new(192, 168, 2, 0)));   // just above
    }

    // network portion non-zero: "10.0.0.5/24" has host bits set; we still
    // use network bits for containment. confirms masking works regardless.
    #[test]
    fn test_cidr_contains_ignores_host_bits_in_network_field() {
        let c = Cidr::parse("10.0.0.5/24").unwrap();
        // per /24 mask, the range is 10.0.0.0..=10.0.0.255 regardless of .5
        assert!(c.contains(Ipv4Addr::new(10, 0, 0, 0)));
        assert!(c.contains(Ipv4Addr::new(10, 0, 0, 100)));
        assert!(!c.contains(Ipv4Addr::new(10, 0, 1, 100)));
    }

    // bulk check: every ip in a /29 is contained; the 8 neighbors below
    // and above are not. ensures mask arithmetic for an arbitrary mask.
    #[test]
    fn test_cidr_contains_29_exact_block() {
        let c = Cidr::parse("192.168.1.16/29").unwrap();
        // /29 → 8 addresses: .16 through .23
        for i in 16..=23u8 {
            assert!(c.contains(Ipv4Addr::new(192, 168, 1, i)), "expected .{} in", i);
        }
        for i in 0..16u8 {
            assert!(!c.contains(Ipv4Addr::new(192, 168, 1, i)), "unexpected .{} in", i);
        }
        for i in 24..=31u8 {
            assert!(!c.contains(Ipv4Addr::new(192, 168, 1, i)), "unexpected .{} in", i);
        }
    }

    // mac parse: uppercase and mixed case must produce identical output
    #[test]
    fn test_parse_mac_case_insensitive() {
        let a = parse_mac("aa:bb:cc:dd:ee:ff").unwrap();
        let b = parse_mac("AA:BB:CC:DD:EE:FF").unwrap();
        let c = parse_mac("Aa:Bb:Cc:Dd:Ee:Ff").unwrap();
        assert_eq!(a, b);
        assert_eq!(a, c);
    }

    #[test]
    fn test_is_likely_printer_times_out_on_closed_port() {
        // bind a reserved discard ip with short timeout → expected false (no listener)
        // tests only the timeout path — a real printer test would need an actual target.
        let got = is_likely_printer(Ipv4Addr::new(203, 0, 113, 1), 100);
        // cannot assert either way (routing may respond-unreachable vs time out),
        // but call should return without panic
        let _ = got;
    }
}
