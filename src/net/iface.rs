// interfaces

use anyhow::{anyhow, Context, Result};
use pnet_datalink::{self, NetworkInterface};
use std::fs;
use std::net::Ipv4Addr;
use std::str::FromStr;

#[derive(Debug, Clone)]
pub struct IfaceInfo {
    pub name: String,
    pub mac: [u8; 6],
    pub ip: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub gateway_ip: Ipv4Addr,
    pub gateway_mac: Option<[u8; 6]>,
    pub iface: NetworkInterface,
}

// gateway from /proc/net/route
pub fn detect_gateway(iface_name: &str) -> Result<Ipv4Addr> {
    let content = fs::read_to_string("/proc/net/route")
        .context("failed to read /proc/net/route")?;

    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 3 {
            continue;
        }
        if fields[0] == iface_name && fields[1] == "00000000" {
            let hex = fields[2];
            let raw = u32::from_str_radix(hex, 16)
                .context("bad hex in route table")?;
            return Ok(Ipv4Addr::from(raw.to_be()));
        }
    }
    Err(anyhow!("no default gateway found for {}", iface_name))
}

// mac from /proc/net/arp
pub fn lookup_arp_cache(ip: Ipv4Addr) -> Option<[u8; 6]> {
    let content = fs::read_to_string("/proc/net/arp").ok()?;
    let ip_str = ip.to_string();

    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 {
            continue;
        }
        if fields[0] == ip_str {
            return parse_mac_str(fields[3]);
        }
    }
    None
}

// "aa:bb:cc:dd:ee:ff" -> [u8; 6]
pub fn parse_mac_str(s: &str) -> Option<[u8; 6]> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    let mut mac = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(part, 16).ok()?;
    }
    Some(mac)
}

// [u8; 6] -> "aa:bb:cc:dd:ee:ff"
pub fn format_mac(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

// usable interfaces
pub fn list_interfaces() -> Vec<NetworkInterface> {
    pnet_datalink::interfaces()
        .into_iter()
        .filter(|iface| {
            !iface.is_loopback()
                && iface.mac.is_some()
                && iface.ips.iter().any(|ip| ip.is_ipv4())
        })
        .collect()
}

// build iface info
pub fn get_iface_info(name: &str) -> Result<IfaceInfo> {
    let ifaces = pnet_datalink::interfaces();
    let iface = ifaces
        .into_iter()
        .find(|i| i.name == name)
        .ok_or_else(|| anyhow!("interface '{}' not found", name))?;

    let mac_addr = iface
        .mac
        .ok_or_else(|| anyhow!("interface '{}' has no mac", name))?;
    let mac = mac_addr.octets();

    let ip_net = iface
        .ips
        .iter()
        .find(|ip| ip.is_ipv4())
        .ok_or_else(|| anyhow!("interface '{}' has no ipv4", name))?;

    let ip = match ip_net.ip() {
        std::net::IpAddr::V4(v4) => v4,
        _ => unreachable!(),
    };

    let prefix = ip_net.prefix();
    let mask_bits = if prefix == 0 {
        0u32
    } else {
        !0u32 << (32 - prefix)
    };
    let netmask = Ipv4Addr::from(mask_bits);

    let gateway_ip = detect_gateway(name)?;
    let gateway_mac = lookup_arp_cache(gateway_ip);

    Ok(IfaceInfo {
        name: name.to_string(),
        mac,
        ip,
        netmask,
        gateway_ip,
        gateway_mac,
        iface,
    })
}

// auto-detect best interface
pub fn auto_detect_iface() -> Result<String> {
    let content = fs::read_to_string("/proc/net/route")
        .context("failed to read /proc/net/route")?;

    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 3 && fields[1] == "00000000" {
            return Ok(fields[0].to_string());
        }
    }
    Err(anyhow!("no interface with default route found"))
}

// all host ips in subnet
pub fn subnet_hosts(ip: Ipv4Addr, netmask: Ipv4Addr) -> Vec<Ipv4Addr> {
    let ip_u32 = u32::from(ip);
    let mask_u32 = u32::from(netmask);
    let network = ip_u32 & mask_u32;
    let broadcast = network | !mask_u32;

    let mut hosts = Vec::new();
    let start = network + 1;
    let end = broadcast;

    if end <= start {
        return hosts;
    }

    for addr in start..end {
        hosts.push(Ipv4Addr::from(addr));
    }
    hosts
}

// parse cidr
pub fn parse_cidr(cidr: &str) -> Result<Vec<Ipv4Addr>> {
    let parts: Vec<&str> = cidr.splitn(2, '/').collect();
    if parts.len() != 2 {
        return Err(anyhow!(
            "invalid cidr notation, expected ip/prefix (e.g. 192.168.1.0/24)"
        ));
    }
    let ip: Ipv4Addr = parts[0].parse().context("invalid ip in cidr range")?;
    let prefix: u32 = parts[1].parse().context("invalid prefix length in cidr range")?;
    if prefix > 32 {
        return Err(anyhow!("cidr prefix must be 0-32, got {}", prefix));
    }
    if prefix < 16 {
        return Err(anyhow!(
            "cidr prefix /{} is too broad (max 65534 hosts), use /16 or narrower",
            prefix
        ));
    }
    if prefix == 32 {
        return Ok(vec![ip]);
    }
    let mask = !0u32 << (32 - prefix);
    let netmask = Ipv4Addr::from(mask);
    Ok(subnet_hosts(ip, netmask))
}

// ".1" -> full ip
pub fn expand_gateway_shorthand(shorthand: &str, our_ip: Ipv4Addr) -> Result<Ipv4Addr> {
    if let Ok(full) = Ipv4Addr::from_str(shorthand) {
        return Ok(full);
    }
    if let Some(last_octet) = shorthand.strip_prefix('.') {
        let octets = our_ip.octets();
        let last: u8 = last_octet.parse().context("bad gateway shorthand")?;
        return Ok(Ipv4Addr::new(octets[0], octets[1], octets[2], last));
    }
    Err(anyhow!("can't parse gateway: {}", shorthand))
}

const IP_FORWARD_PATH: &str = "/proc/sys/net/ipv4/ip_forward";

pub fn ip_forward_enabled() -> Result<bool> {
    let content = fs::read_to_string(IP_FORWARD_PATH)
        .context("failed to read ip_forward")?;
    Ok(content.trim() == "1")
}

pub fn set_ip_forward(enable: bool) -> Result<bool> {
    let was_enabled = ip_forward_enabled()?;
    let val = if enable { "1" } else { "0" };
    fs::write(IP_FORWARD_PATH, val)
        .context("failed to write ip_forward (are you root?)")?;
    log::info!("ip_forward: {} -> {}", if was_enabled { "1" } else { "0" }, val);
    Ok(was_enabled)
}

// restores ip_forward on drop
pub struct IpForwardGuard {
    original: bool,
}

impl IpForwardGuard {
    pub fn enable() -> Result<Self> {
        let original = set_ip_forward(true)?;
        Ok(Self { original })
    }
}

impl Drop for IpForwardGuard {
    fn drop(&mut self) {
        if let Err(e) = set_ip_forward(self.original) {
            log::error!("failed to restore ip_forward: {}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_mac_str_valid() {
        let mac = parse_mac_str("aa:bb:cc:dd:ee:ff").unwrap();
        assert_eq!(mac, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    }

    #[test]
    fn test_parse_mac_str_invalid() {
        assert!(parse_mac_str("not-a-mac").is_none());
        assert!(parse_mac_str("aa:bb:cc").is_none());
        assert!(parse_mac_str("gg:hh:ii:jj:kk:ll").is_none());
    }

    #[test]
    fn test_format_mac() {
        let mac = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01];
        assert_eq!(format_mac(&mac), "de:ad:be:ef:00:01");
    }

    #[test]
    fn test_subnet_hosts_24() {
        let hosts = subnet_hosts(
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(255, 255, 255, 0),
        );
        assert_eq!(hosts.len(), 254);
        assert_eq!(hosts[0], Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(hosts[253], Ipv4Addr::new(192, 168, 1, 254));
    }

    #[test]
    fn test_subnet_hosts_28() {
        let hosts = subnet_hosts(
            Ipv4Addr::new(10, 0, 0, 5),
            Ipv4Addr::new(255, 255, 255, 240),
        );
        assert_eq!(hosts.len(), 14);
    }

    #[test]
    fn test_expand_gateway_shorthand() {
        let ip = Ipv4Addr::new(192, 168, 1, 50);
        let gw = expand_gateway_shorthand(".1", ip).unwrap();
        assert_eq!(gw, Ipv4Addr::new(192, 168, 1, 1));

        let gw2 = expand_gateway_shorthand("10.0.0.1", ip).unwrap();
        assert_eq!(gw2, Ipv4Addr::new(10, 0, 0, 1));
    }

    #[test]
    fn test_expand_gateway_shorthand_invalid() {
        let ip = Ipv4Addr::new(192, 168, 1, 50);
        assert!(expand_gateway_shorthand("garbage", ip).is_err());
        assert!(expand_gateway_shorthand(".999", ip).is_err());
    }

    #[test]
    fn test_parse_cidr_24() {
        let hosts = parse_cidr("192.168.1.0/24").unwrap();
        assert_eq!(hosts.len(), 254);
        assert_eq!(hosts[0], Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(hosts[253], Ipv4Addr::new(192, 168, 1, 254));
    }

    #[test]
    fn test_parse_cidr_28() {
        let hosts = parse_cidr("10.0.0.0/28").unwrap();
        assert_eq!(hosts.len(), 14);
    }

    #[test]
    fn test_parse_cidr_32_single_host() {
        let hosts = parse_cidr("10.0.0.1/32").unwrap();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0], Ipv4Addr::new(10, 0, 0, 1));
    }

    #[test]
    fn test_parse_cidr_invalid() {
        assert!(parse_cidr("not-cidr").is_err());
        assert!(parse_cidr("192.168.1.0").is_err());
        assert!(parse_cidr("192.168.1.0/33").is_err());
        assert!(parse_cidr("192.168.1.0/8").is_err());
    }

    #[test]
    fn test_parse_cidr_nonzero_host_bits() {
        let hosts = parse_cidr("192.168.1.50/24").unwrap();
        assert_eq!(hosts.len(), 254);
        assert_eq!(hosts[0], Ipv4Addr::new(192, 168, 1, 1));
    }
}
