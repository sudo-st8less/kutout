// app state

use crate::events::{EventKind, PentestEvent};
use crate::net::arp::Host;
use std::collections::VecDeque;
use std::net::Ipv4Addr;

const MAX_LOG_ENTRIES: usize = 500;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Panel {
    Hosts,
    Log,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum InputMode {
    Normal,
    DnsInput,
}

#[derive(Debug, Clone)]
pub struct PoisonEntry {
    pub target_ip: Ipv4Addr,
    pub kill_mode: bool,
    pub packets_forwarded: u64,
}

#[derive(Debug, Clone)]
pub struct LogEntry {
    pub kind: LogKind,
    pub message: String,
}

// "in the pursuit of learning, every day something is acquired.
//  in the pursuit of tao, every day something is dropped." — tao te ching, 48

#[derive(Debug, Clone)]
pub enum LogKind {
    Info,
    Credential,
    DnsQuery,
    DnsSpoof,
    PacketForward,
    Kill,
    Error,
}

pub struct App {
    pub running: bool,
    pub active_panel: Panel,
    pub hosts: Vec<Host>,
    pub host_scroll: usize,
    pub poisons: Vec<PoisonEntry>,
    pub log: VecDeque<LogEntry>,
    pub log_scroll: usize,
    pub packets_total: u64,
    pub creds_total: u64,
    pub iface_name: String,
    pub our_ip: Ipv4Addr,
    pub gateway_ip: Ipv4Addr,
    pub status_message: String,
    pub input_mode: InputMode,
    pub input_buffer: String,
    pub dns_rule_count: usize,
    // read-only snapshot of config exclusions for rendering + refusal
    pub exclusions: crate::safe_mode::Exclusions,
    // true when llmnr/mdns/nbt-ns/rogue-http listeners are running
    pub responder_active: bool,
}

impl App {
    pub fn new(
        iface_name: String,
        our_ip: Ipv4Addr,
        gateway_ip: Ipv4Addr,
        exclusions: crate::safe_mode::Exclusions,
    ) -> Self {
        Self {
            running: true,
            active_panel: Panel::Hosts,
            hosts: Vec::new(),
            host_scroll: 0,
            poisons: Vec::new(),
            log: VecDeque::with_capacity(MAX_LOG_ENTRIES),
            log_scroll: 0,
            packets_total: 0,
            creds_total: 0,
            iface_name,
            our_ip,
            gateway_ip,
            status_message: "ready".into(),
            input_mode: InputMode::Normal,
            input_buffer: String::new(),
            dns_rule_count: 0,
            exclusions,
            responder_active: false,
        }
    }

    // static cheap check (no printer probe) — used by tui host list + keybinds
    pub fn is_excluded(&self, ip: Ipv4Addr, mac: [u8; 6]) -> bool {
        self.exclusions.is_excluded(ip, mac)
    }

    // log, evict oldest if full
    pub fn push_log(&mut self, kind: LogKind, message: String) {
        if self.log.len() >= MAX_LOG_ENTRIES {
            self.log.pop_front();
        }
        self.log.push_back(LogEntry { kind, message });
    }

    // consume a pentest event, update counters, append to log
    pub fn handle_event(&mut self, event: &PentestEvent) {
        match &event.kind {
            EventKind::PacketForwarded { src, dst, len, proto } => {
                self.packets_total += 1;
                for p in &mut self.poisons {
                    if p.target_ip == *src || p.target_ip == *dst {
                        p.packets_forwarded += 1;
                    }
                }
                // log every 100th
                if self.packets_total.is_multiple_of(100) {
                    self.push_log(
                        LogKind::PacketForward,
                        format!("{} -> {} ({} bytes, proto {})", src, dst, len, proto),
                    );
                }
            }
            EventKind::Credential { proto, detail, .. } => {
                self.creds_total += 1;
                self.push_log(LogKind::Credential, format!("[{}] {}", proto, detail));
            }
            EventKind::DnsQuery { name, src } => {
                self.push_log(LogKind::DnsQuery, format!("{} -> {}", src, name));
            }
            EventKind::DnsSpoofed { name, spoof_ip, src } => {
                self.push_log(
                    LogKind::DnsSpoof,
                    format!("{} -> {} spoofed to {}", src, name, spoof_ip),
                );
            }
            EventKind::PacketDropped { src, dst } => {
                self.push_log(LogKind::Kill, format!("dropped {} -> {}", src, dst));
            }
            EventKind::DnsRuleAdded { domain, ip } => {
                self.push_log(LogKind::Info, format!("dns spoof: {} -> {}", domain, ip));
            }
            EventKind::DnsRulesCleared => {
                self.push_log(LogKind::Info, "dns rules cleared".into());
            }
            EventKind::NameQuery { protocol, name, src } => {
                self.push_log(
                    LogKind::DnsQuery,
                    format!("{}: {} from {}", protocol, name, src),
                );
            }
            EventKind::NamePoisoned { protocol, name, spoof_ip, src } => {
                self.push_log(
                    LogKind::DnsSpoof,
                    format!("{}: {} poisoned for {} -> {}", protocol, name, src, spoof_ip),
                );
            }
            EventKind::ArpPoisonStarted { target_ip, gateway_ip, .. } => {
                self.push_log(
                    LogKind::Info,
                    format!("poisoning {} <-> {}", target_ip, gateway_ip),
                );
            }
            EventKind::ArpPoisonStopped { target_ip } => {
                self.push_log(LogKind::Info, format!("stopped poisoning {}", target_ip));
            }
            EventKind::ArpCured => {
                self.push_log(LogKind::Info, "arp tables restored".into());
            }
            EventKind::KillEnabled { target_ip } => {
                self.push_log(LogKind::Info, format!("{} -> kill mode", target_ip));
            }
            EventKind::KillDisabled { target_ip } => {
                self.push_log(LogKind::Info, format!("{} -> forward mode", target_ip));
            }
            EventKind::HostDiscovered { ip, .. } => {
                self.push_log(LogKind::Info, format!("host: {}", ip));
            }
            EventKind::ScanStarted { target_count } => {
                self.push_log(LogKind::Info, format!("scan: probing {}", target_count));
            }
            EventKind::ScanCompleted { host_count } => {
                self.push_log(LogKind::Info, format!("scan: {} hosts found", host_count));
            }
            EventKind::SessionStarted { iface, .. } => {
                self.push_log(LogKind::Info, format!("started on {}", iface));
            }
            EventKind::SessionEnded => {
                self.push_log(LogKind::Info, "session ended".into());
            }
            EventKind::Info { message } => {
                self.push_log(LogKind::Info, message.clone());
            }
            EventKind::Error { message } => {
                self.push_log(LogKind::Error, message.clone());
            }
        }
    }

    pub fn scroll_hosts(&mut self, delta: i32) {
        let max = self.hosts.len().saturating_sub(1);
        if delta > 0 {
            self.host_scroll = (self.host_scroll + delta as usize).min(max);
        } else {
            self.host_scroll = self.host_scroll.saturating_sub((-delta) as usize);
        }
    }

    pub fn scroll_log(&mut self, delta: i32) {
        let max = self.log.len().saturating_sub(1);
        if delta > 0 {
            self.log_scroll = (self.log_scroll + delta as usize).min(max);
        } else {
            self.log_scroll = self.log_scroll.saturating_sub((-delta) as usize);
        }
    }

    pub fn toggle_panel(&mut self) {
        self.active_panel = match self.active_panel {
            Panel::Hosts => Panel::Log,
            Panel::Log => Panel::Hosts,
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::CredentialKind;

    fn make_app() -> App {
        App::new(
            "eth0".into(),
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(192, 168, 1, 1),
            Default::default(),
        )
    }

    fn make_poison(target_ip: Ipv4Addr) -> PoisonEntry {
        PoisonEntry {
            target_ip,
            kill_mode: false,
            packets_forwarded: 0,
        }
    }

    fn pkt(src: Ipv4Addr, dst: Ipv4Addr) -> PentestEvent {
        PentestEvent::new(EventKind::PacketForwarded {
            src,
            dst,
            len: 64,
            proto: 6,
        })
    }

    #[test]
    fn test_new_defaults() {
        let app = make_app();
        assert!(app.running);
        assert_eq!(app.active_panel, Panel::Hosts);
        assert!(app.hosts.is_empty());
        assert!(app.poisons.is_empty());
        assert!(app.log.is_empty());
        assert_eq!(app.packets_total, 0);
        assert_eq!(app.creds_total, 0);
        assert_eq!(app.iface_name, "eth0");
        assert_eq!(app.input_mode, InputMode::Normal);
        assert_eq!(app.status_message, "ready");
        assert_eq!(app.dns_rule_count, 0);
    }

    #[test]
    fn test_push_log_adds_entry() {
        let mut app = make_app();
        app.push_log(LogKind::Info, "hello".into());
        assert_eq!(app.log.len(), 1);
        assert_eq!(app.log[0].message, "hello");
    }

    #[test]
    fn test_push_log_eviction_at_max() {
        let mut app = make_app();
        for i in 0..MAX_LOG_ENTRIES {
            app.push_log(LogKind::Info, format!("msg-{}", i));
        }
        assert_eq!(app.log.len(), MAX_LOG_ENTRIES);
        assert_eq!(app.log[0].message, "msg-0");

        app.push_log(LogKind::Info, "overflow".into());
        assert_eq!(app.log.len(), MAX_LOG_ENTRIES);
        assert_eq!(app.log[0].message, "msg-1");
        assert_eq!(app.log[MAX_LOG_ENTRIES - 1].message, "overflow");
    }

    #[test]
    fn test_push_log_preserves_kind() {
        let mut app = make_app();
        app.push_log(LogKind::Credential, "cred".into());
        app.push_log(LogKind::Error, "err".into());
        assert!(matches!(app.log[0].kind, LogKind::Credential));
        assert!(matches!(app.log[1].kind, LogKind::Error));
    }

    #[test]
    fn test_handle_packet_forwarded_increments_total() {
        let mut app = make_app();
        let src = Ipv4Addr::new(192, 168, 1, 50);
        let dst = Ipv4Addr::new(8, 8, 8, 8);
        app.handle_event(&pkt(src, dst));
        assert_eq!(app.packets_total, 1);
    }

    #[test]
    fn test_handle_packet_forwarded_updates_poison_counter() {
        let mut app = make_app();
        let target = Ipv4Addr::new(192, 168, 1, 50);
        app.poisons.push(make_poison(target));

        app.handle_event(&pkt(target, Ipv4Addr::new(8, 8, 8, 8)));
        assert_eq!(app.poisons[0].packets_forwarded, 1);

        app.handle_event(&pkt(Ipv4Addr::new(8, 8, 8, 8), target));
        assert_eq!(app.poisons[0].packets_forwarded, 2);
    }

    #[test]
    fn test_handle_packet_forwarded_logs_every_100() {
        let mut app = make_app();
        let src = Ipv4Addr::new(10, 0, 0, 1);
        let dst = Ipv4Addr::new(10, 0, 0, 2);
        for _ in 0..100 {
            app.handle_event(&pkt(src, dst));
        }
        assert_eq!(app.packets_total, 100);
        assert_eq!(app.log.len(), 1);
    }

    #[test]
    fn test_handle_packet_forwarded_no_log_under_100() {
        let mut app = make_app();
        let src = Ipv4Addr::new(10, 0, 0, 1);
        let dst = Ipv4Addr::new(10, 0, 0, 2);
        for _ in 0..99 {
            app.handle_event(&pkt(src, dst));
        }
        assert_eq!(app.packets_total, 99);
        assert!(app.log.is_empty());
    }

    #[test]
    fn test_handle_credential() {
        let mut app = make_app();
        app.handle_event(&PentestEvent::new(EventKind::Credential {
            kind: CredentialKind::Cleartext,
            proto: "FTP".into(),
            detail: "user:pass".into(),
            src: None,
            dst: None,
        }));
        assert_eq!(app.creds_total, 1);
        assert_eq!(app.log.len(), 1);
        assert!(matches!(app.log[0].kind, LogKind::Credential));
        assert!(app.log[0].message.contains("FTP"));
    }

    #[test]
    fn test_handle_dns_query() {
        let mut app = make_app();
        app.handle_event(&PentestEvent::new(EventKind::DnsQuery {
            name: "example.com".into(),
            src: Ipv4Addr::new(192, 168, 1, 50),
        }));
        assert_eq!(app.log.len(), 1);
        assert!(matches!(app.log[0].kind, LogKind::DnsQuery));
        assert!(app.log[0].message.contains("example.com"));
    }

    #[test]
    fn test_handle_dns_spoofed() {
        let mut app = make_app();
        app.handle_event(&PentestEvent::new(EventKind::DnsSpoofed {
            name: "evil.com".into(),
            spoof_ip: Ipv4Addr::new(6, 6, 6, 6),
            src: Ipv4Addr::new(192, 168, 1, 50),
        }));
        assert_eq!(app.log.len(), 1);
        assert!(matches!(app.log[0].kind, LogKind::DnsSpoof));
        assert!(app.log[0].message.contains("evil.com"));
        assert!(app.log[0].message.contains("6.6.6.6"));
    }

    #[test]
    fn test_handle_dropped() {
        let mut app = make_app();
        app.handle_event(&PentestEvent::new(EventKind::PacketDropped {
            src: Ipv4Addr::new(10, 0, 0, 1),
            dst: Ipv4Addr::new(10, 0, 0, 2),
        }));
        assert_eq!(app.log.len(), 1);
        assert!(matches!(app.log[0].kind, LogKind::Kill));
    }

    #[test]
    fn test_handle_error_event() {
        let mut app = make_app();
        app.handle_event(&PentestEvent::error("boom"));
        assert_eq!(app.log.len(), 1);
        assert!(matches!(app.log[0].kind, LogKind::Error));
        assert!(app.log[0].message.contains("boom"));
    }

    #[test]
    fn test_scroll_hosts_down() {
        let mut app = make_app();
        for i in 0..5 {
            app.hosts.push(Host {
                ip: Ipv4Addr::new(192, 168, 1, i),
                mac: [i; 6],
            });
        }
        app.scroll_hosts(2);
        assert_eq!(app.host_scroll, 2);
    }

    #[test]
    fn test_scroll_hosts_clamp_bottom() {
        let mut app = make_app();
        for i in 0..3 {
            app.hosts.push(Host {
                ip: Ipv4Addr::new(192, 168, 1, i),
                mac: [i; 6],
            });
        }
        app.scroll_hosts(100);
        assert_eq!(app.host_scroll, 2);
    }

    #[test]
    fn test_scroll_hosts_up_clamp_zero() {
        let mut app = make_app();
        app.hosts.push(Host {
            ip: Ipv4Addr::new(192, 168, 1, 1),
            mac: [1; 6],
        });
        app.scroll_hosts(-5);
        assert_eq!(app.host_scroll, 0);
    }

    #[test]
    fn test_scroll_log_clamp() {
        let mut app = make_app();
        for i in 0..5 {
            app.push_log(LogKind::Info, format!("msg-{}", i));
        }
        app.scroll_log(3);
        assert_eq!(app.log_scroll, 3);
        app.scroll_log(100);
        assert_eq!(app.log_scroll, 4);
        app.scroll_log(-100);
        assert_eq!(app.log_scroll, 0);
    }

    // every EventKind must flow through handle_event without panic,
    // catches missing match arms. does NOT strictly verify what ends up in
    // the log — just that each variant is accepted.
    #[test]
    fn test_handle_event_accepts_every_variant() {
        let mut app = make_app();
        for ev in crate::events::all_event_samples() {
            app.handle_event(&ev);
        }
        // sanity: PacketForwarded + Credential both bumped counters
        assert!(app.packets_total >= 1);
        assert!(app.creds_total >= 2); // cleartext + ntlmv2 samples
        assert!(!app.log.is_empty());
    }

    #[test]
    fn test_toggle_panel() {
        let mut app = make_app();
        assert_eq!(app.active_panel, Panel::Hosts);
        app.toggle_panel();
        assert_eq!(app.active_panel, Panel::Log);
        app.toggle_panel();
        assert_eq!(app.active_panel, Panel::Hosts);
    }
}
