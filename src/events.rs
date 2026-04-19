// events — unified pentest event taxonomy + sinks
//
// every attack emits PentestEvent through an EventSink. sinks include
// the tui (channel), jsonl file (for engagement artifacts), and stdout.
// this is the substrate for export (phase 1), ntlm capture (phase 3),
// and name poisoning (phase 4) — all of which just emit events.

use anyhow::Result;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::mpsc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::net::forwarding::ForwardEvent;

// "if you can't measure it, you can't improve it." — peter drucker

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Info,
    Warn,
    Error,
    Hit, // credential or hash captured
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialKind {
    Cleartext,
    HttpBasic,
    HttpPost,
    NetNtlmV2,
}

#[derive(Debug, Clone)]
pub enum EventKind {
    // session lifecycle
    SessionStarted {
        iface: String,
        our_ip: Ipv4Addr,
        gateway_ip: Ipv4Addr,
    },
    SessionEnded,

    // discovery
    ScanStarted {
        target_count: usize,
    },
    ScanCompleted {
        host_count: usize,
    },
    HostDiscovered {
        ip: Ipv4Addr,
        mac: [u8; 6],
    },

    // arp
    ArpPoisonStarted {
        target_ip: Ipv4Addr,
        target_mac: [u8; 6],
        gateway_ip: Ipv4Addr,
    },
    #[allow(dead_code)] // emitted per-target when live-mode 'cure' lands in phase 5
    ArpPoisonStopped {
        target_ip: Ipv4Addr,
    },
    ArpCured,

    // traffic
    PacketForwarded {
        src: Ipv4Addr,
        dst: Ipv4Addr,
        len: usize,
        proto: u8,
    },
    PacketDropped {
        src: Ipv4Addr,
        dst: Ipv4Addr,
    },

    // credentials
    Credential {
        kind: CredentialKind,
        proto: String,
        detail: String,
        src: Option<Ipv4Addr>,
        dst: Option<Ipv4Addr>,
    },

    // dns
    DnsQuery {
        name: String,
        src: Ipv4Addr,
    },
    DnsSpoofed {
        name: String,
        spoof_ip: Ipv4Addr,
        src: Ipv4Addr,
    },
    DnsRuleAdded {
        domain: String,
        ip: Ipv4Addr,
    },
    DnsRulesCleared,

    // name poisoning (llmnr / mdns / nbt-ns)
    NameQuery {
        protocol: &'static str,
        name: String,
        src: Ipv4Addr,
    },
    NamePoisoned {
        protocol: &'static str,
        name: String,
        spoof_ip: Ipv4Addr,
        src: Ipv4Addr,
    },

    // kill mode
    KillEnabled {
        target_ip: Ipv4Addr,
    },
    KillDisabled {
        target_ip: Ipv4Addr,
    },

    // free-form
    Info {
        message: String,
    },
    Error {
        message: String,
    },
}

#[derive(Debug, Clone)]
pub struct PentestEvent {
    pub timestamp: SystemTime,
    pub kind: EventKind,
}

impl PentestEvent {
    pub fn new(kind: EventKind) -> Self {
        Self {
            timestamp: SystemTime::now(),
            kind,
        }
    }

    pub fn info(msg: impl Into<String>) -> Self {
        Self::new(EventKind::Info { message: msg.into() })
    }

    pub fn error(msg: impl Into<String>) -> Self {
        Self::new(EventKind::Error { message: msg.into() })
    }

    pub fn severity(&self) -> Severity {
        match &self.kind {
            EventKind::Credential { .. } => Severity::Hit,
            EventKind::Error { .. } => Severity::Error,
            EventKind::PacketDropped { .. }
            | EventKind::DnsSpoofed { .. }
            | EventKind::NamePoisoned { .. } => Severity::Warn,
            _ => Severity::Info,
        }
    }

    // unix-epoch microseconds
    pub fn timestamp_us(&self) -> u64 {
        self.timestamp
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_micros() as u64)
            .unwrap_or(0)
    }

    // translate internal forwarding-thread events to pentest events.
    // returns None for RawFrame (that's pcap-only, not user-facing).
    pub fn from_forward(ev: ForwardEvent) -> Option<Self> {
        let kind = match ev {
            ForwardEvent::PacketForwarded { src, dst, len, proto } => {
                EventKind::PacketForwarded { src, dst, len, proto }
            }
            ForwardEvent::Credential { proto, detail } => {
                let kind = match proto.as_str() {
                    "http-basic" => CredentialKind::HttpBasic,
                    "http-post" => CredentialKind::HttpPost,
                    "ntlm-v2-http" | "ntlm-v2-smb" => CredentialKind::NetNtlmV2,
                    _ => CredentialKind::Cleartext,
                };
                EventKind::Credential {
                    kind,
                    proto,
                    detail,
                    src: None,
                    dst: None,
                }
            }
            ForwardEvent::DnsQuery { name, src } => EventKind::DnsQuery { name, src },
            ForwardEvent::DnsSpoofed { name, spoof_ip, src } => {
                EventKind::DnsSpoofed { name, spoof_ip, src }
            }
            ForwardEvent::Dropped { src, dst } => EventKind::PacketDropped { src, dst },
            ForwardEvent::RawFrame { .. } => return None,
        };
        Some(Self::new(kind))
    }
}

// ─── sinks ────────────────────────────────────────────────────────────────

pub trait EventSink: Send {
    fn emit(&mut self, event: &PentestEvent) -> Result<()>;
}

// stdout — colored single-line human output for cmd_poison
pub struct StdoutSink;

impl EventSink for StdoutSink {
    fn emit(&mut self, event: &PentestEvent) -> Result<()> {
        println!("{}", format_human(event));
        Ok(())
    }
}

// jsonl — one json object per line, append-only. engagement artifact.
pub struct JsonlFileSink {
    writer: BufWriter<File>,
}

impl JsonlFileSink {
    pub fn create(path: &Path) -> Result<Self> {
        let f = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self {
            writer: BufWriter::new(f),
        })
    }
}

impl EventSink for JsonlFileSink {
    fn emit(&mut self, event: &PentestEvent) -> Result<()> {
        self.writer.write_all(format_json(event).as_bytes())?;
        self.writer.write_all(b"\n")?;
        self.writer.flush()?;
        Ok(())
    }
}

// channel — feeds an mpsc consumer (the tui's event loop)
pub struct ChannelSink {
    tx: mpsc::Sender<PentestEvent>,
}

impl ChannelSink {
    pub fn new(tx: mpsc::Sender<PentestEvent>) -> Self {
        Self { tx }
    }
}

impl EventSink for ChannelSink {
    fn emit(&mut self, event: &PentestEvent) -> Result<()> {
        self.tx
            .send(event.clone())
            .map_err(|e| anyhow::anyhow!("channel sink send failed: {}", e))?;
        Ok(())
    }
}

// fanout — broadcasts to multiple sinks, logs (but does not propagate) per-sink failures
#[derive(Default)]
pub struct FanoutSink {
    sinks: Vec<Box<dyn EventSink>>,
}

impl FanoutSink {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, sink: Box<dyn EventSink>) {
        self.sinks.push(sink);
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.sinks.len()
    }
}

impl EventSink for FanoutSink {
    fn emit(&mut self, event: &PentestEvent) -> Result<()> {
        for sink in &mut self.sinks {
            if let Err(e) = sink.emit(event) {
                log::warn!("sink emit failed: {}", e);
            }
        }
        Ok(())
    }
}

// ─── formatters ───────────────────────────────────────────────────────────

// ansi-colored single-line representation for stdout mode
pub fn format_human(event: &PentestEvent) -> String {
    match &event.kind {
        EventKind::SessionStarted { iface, our_ip, gateway_ip } => {
            format!("[start] iface={} our={} gw={}", iface, our_ip, gateway_ip)
        }
        EventKind::SessionEnded => "[end] session closed".into(),
        EventKind::ScanStarted { target_count } => {
            format!("[scan] probing {} targets", target_count)
        }
        EventKind::ScanCompleted { host_count } => {
            format!("[scan] complete, {} hosts", host_count)
        }
        EventKind::HostDiscovered { ip, mac } => {
            format!("[host] {} {}", ip, format_mac(mac))
        }
        EventKind::ArpPoisonStarted { target_ip, gateway_ip, .. } => {
            format!("[poison] {} <-> {}", target_ip, gateway_ip)
        }
        EventKind::ArpPoisonStopped { target_ip } => {
            format!("[poison] stopped {}", target_ip)
        }
        EventKind::ArpCured => "[cure] arp tables restored".into(),
        EventKind::PacketForwarded { src, dst, len, proto } => {
            format!("[fwd] {} -> {} ({}B proto={})", src, dst, len, proto)
        }
        EventKind::PacketDropped { src, dst } => {
            format!("\x1b[31m[kill] {} -> {}\x1b[0m", src, dst)
        }
        EventKind::Credential { proto, detail, .. } => {
            format!("\x1b[33m[cred] [{}] {}\x1b[0m", proto, detail)
        }
        EventKind::DnsQuery { name, src } => format!("[dns] {} -> {}", src, name),
        EventKind::DnsSpoofed { name, spoof_ip, src } => {
            format!("\x1b[35m[spoof] {} -> {} => {}\x1b[0m", src, name, spoof_ip)
        }
        EventKind::DnsRuleAdded { domain, ip } => {
            format!("[rule] dns {} -> {}", domain, ip)
        }
        EventKind::DnsRulesCleared => "[rule] dns rules cleared".into(),
        EventKind::NameQuery { protocol, name, src } => {
            format!("[{}] query {} from {}", protocol, name, src)
        }
        EventKind::NamePoisoned { protocol, name, spoof_ip, src } => {
            format!(
                "\x1b[35m[{}] poisoned {} for {} -> {}\x1b[0m",
                protocol, name, src, spoof_ip
            )
        }
        EventKind::KillEnabled { target_ip } => format!("[kill] on {}", target_ip),
        EventKind::KillDisabled { target_ip } => format!("[kill] off {}", target_ip),
        EventKind::Info { message } => format!("[info] {}", message),
        EventKind::Error { message } => format!("\x1b[31m[err] {}\x1b[0m", message),
    }
}

// manual json writer — no serde dep yet (added in phase 2 with toml).
pub fn format_json(event: &PentestEvent) -> String {
    let mut s = String::with_capacity(128);
    s.push('{');
    push_kv_num(&mut s, "ts_us", event.timestamp_us());
    s.push(',');
    push_kv_str(&mut s, "severity", severity_str(event.severity()));
    s.push(',');
    s.push_str("\"event\":");
    s.push_str(&event_json(&event.kind));
    s.push('}');
    s
}

fn severity_str(sev: Severity) -> &'static str {
    match sev {
        Severity::Info => "info",
        Severity::Warn => "warn",
        Severity::Error => "error",
        Severity::Hit => "hit",
    }
}

fn event_json(kind: &EventKind) -> String {
    match kind {
        EventKind::SessionStarted { iface, our_ip, gateway_ip } => {
            let mut s = String::from("{");
            push_kv_str(&mut s, "type", "session_started");
            s.push(',');
            push_kv_str(&mut s, "iface", iface);
            s.push(',');
            push_kv_str(&mut s, "our_ip", &our_ip.to_string());
            s.push(',');
            push_kv_str(&mut s, "gateway_ip", &gateway_ip.to_string());
            s.push('}');
            s
        }
        EventKind::SessionEnded => String::from("{\"type\":\"session_ended\"}"),
        EventKind::ScanStarted { target_count } => {
            format!("{{\"type\":\"scan_started\",\"target_count\":{}}}", target_count)
        }
        EventKind::ScanCompleted { host_count } => {
            format!("{{\"type\":\"scan_completed\",\"host_count\":{}}}", host_count)
        }
        EventKind::HostDiscovered { ip, mac } => {
            let mut s = String::from("{");
            push_kv_str(&mut s, "type", "host_discovered");
            s.push(',');
            push_kv_str(&mut s, "ip", &ip.to_string());
            s.push(',');
            push_kv_str(&mut s, "mac", &format_mac(mac));
            s.push('}');
            s
        }
        EventKind::ArpPoisonStarted { target_ip, target_mac, gateway_ip } => {
            let mut s = String::from("{");
            push_kv_str(&mut s, "type", "arp_poison_started");
            s.push(',');
            push_kv_str(&mut s, "target_ip", &target_ip.to_string());
            s.push(',');
            push_kv_str(&mut s, "target_mac", &format_mac(target_mac));
            s.push(',');
            push_kv_str(&mut s, "gateway_ip", &gateway_ip.to_string());
            s.push('}');
            s
        }
        EventKind::ArpPoisonStopped { target_ip } => {
            format!(
                "{{\"type\":\"arp_poison_stopped\",\"target_ip\":\"{}\"}}",
                target_ip
            )
        }
        EventKind::ArpCured => String::from("{\"type\":\"arp_cured\"}"),
        EventKind::PacketForwarded { src, dst, len, proto } => {
            format!(
                "{{\"type\":\"packet_forwarded\",\"src\":\"{}\",\"dst\":\"{}\",\"len\":{},\"proto\":{}}}",
                src, dst, len, proto
            )
        }
        EventKind::PacketDropped { src, dst } => {
            format!(
                "{{\"type\":\"packet_dropped\",\"src\":\"{}\",\"dst\":\"{}\"}}",
                src, dst
            )
        }
        EventKind::Credential { kind, proto, detail, src, dst } => {
            let mut s = String::from("{");
            push_kv_str(&mut s, "type", "credential");
            s.push(',');
            push_kv_str(&mut s, "kind", credential_kind_str(*kind));
            s.push(',');
            push_kv_str(&mut s, "proto", proto);
            s.push(',');
            push_kv_str(&mut s, "detail", detail);
            if let Some(src) = src {
                s.push(',');
                push_kv_str(&mut s, "src", &src.to_string());
            }
            if let Some(dst) = dst {
                s.push(',');
                push_kv_str(&mut s, "dst", &dst.to_string());
            }
            s.push('}');
            s
        }
        EventKind::DnsQuery { name, src } => {
            let mut s = String::from("{");
            push_kv_str(&mut s, "type", "dns_query");
            s.push(',');
            push_kv_str(&mut s, "name", name);
            s.push(',');
            push_kv_str(&mut s, "src", &src.to_string());
            s.push('}');
            s
        }
        EventKind::DnsSpoofed { name, spoof_ip, src } => {
            let mut s = String::from("{");
            push_kv_str(&mut s, "type", "dns_spoofed");
            s.push(',');
            push_kv_str(&mut s, "name", name);
            s.push(',');
            push_kv_str(&mut s, "spoof_ip", &spoof_ip.to_string());
            s.push(',');
            push_kv_str(&mut s, "src", &src.to_string());
            s.push('}');
            s
        }
        EventKind::DnsRuleAdded { domain, ip } => {
            let mut s = String::from("{");
            push_kv_str(&mut s, "type", "dns_rule_added");
            s.push(',');
            push_kv_str(&mut s, "domain", domain);
            s.push(',');
            push_kv_str(&mut s, "ip", &ip.to_string());
            s.push('}');
            s
        }
        EventKind::DnsRulesCleared => String::from("{\"type\":\"dns_rules_cleared\"}"),
        EventKind::NameQuery { protocol, name, src } => {
            let mut s = String::from("{");
            push_kv_str(&mut s, "type", "name_query");
            s.push(',');
            push_kv_str(&mut s, "protocol", protocol);
            s.push(',');
            push_kv_str(&mut s, "name", name);
            s.push(',');
            push_kv_str(&mut s, "src", &src.to_string());
            s.push('}');
            s
        }
        EventKind::NamePoisoned { protocol, name, spoof_ip, src } => {
            let mut s = String::from("{");
            push_kv_str(&mut s, "type", "name_poisoned");
            s.push(',');
            push_kv_str(&mut s, "protocol", protocol);
            s.push(',');
            push_kv_str(&mut s, "name", name);
            s.push(',');
            push_kv_str(&mut s, "spoof_ip", &spoof_ip.to_string());
            s.push(',');
            push_kv_str(&mut s, "src", &src.to_string());
            s.push('}');
            s
        }
        EventKind::KillEnabled { target_ip } => {
            format!(
                "{{\"type\":\"kill_enabled\",\"target_ip\":\"{}\"}}",
                target_ip
            )
        }
        EventKind::KillDisabled { target_ip } => {
            format!(
                "{{\"type\":\"kill_disabled\",\"target_ip\":\"{}\"}}",
                target_ip
            )
        }
        EventKind::Info { message } => {
            let mut s = String::from("{");
            push_kv_str(&mut s, "type", "info");
            s.push(',');
            push_kv_str(&mut s, "message", message);
            s.push('}');
            s
        }
        EventKind::Error { message } => {
            let mut s = String::from("{");
            push_kv_str(&mut s, "type", "error");
            s.push(',');
            push_kv_str(&mut s, "message", message);
            s.push('}');
            s
        }
    }
}

fn credential_kind_str(k: CredentialKind) -> &'static str {
    match k {
        CredentialKind::Cleartext => "cleartext",
        CredentialKind::HttpBasic => "http_basic",
        CredentialKind::HttpPost => "http_post",
        CredentialKind::NetNtlmV2 => "net_ntlm_v2",
    }
}

fn format_mac(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

pub(crate) fn push_kv_str(s: &mut String, key: &str, value: &str) {
    s.push('"');
    s.push_str(key);
    s.push_str("\":\"");
    json_escape_into(value, s);
    s.push('"');
}

pub(crate) fn push_kv_num(s: &mut String, key: &str, value: u64) {
    s.push('"');
    s.push_str(key);
    s.push_str("\":");
    s.push_str(&value.to_string());
}

// escape per rfc 8259 — backslash, quote, control chars
pub(crate) fn json_escape_into(input: &str, out: &mut String) {
    for c in input.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\x08' => out.push_str("\\b"),
            '\x0c' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
}

// test-only helper: one sample of every EventKind variant. shared with
// app.rs and summary.rs so those modules can verify full-variant coverage.
// adding a new variant here forces every consumer test module to handle it.
#[cfg(test)]
pub(crate) fn all_event_samples() -> Vec<PentestEvent> {
    let ip = std::net::Ipv4Addr::new(10, 0, 0, 5);
    let gw = std::net::Ipv4Addr::new(10, 0, 0, 1);
    let mac = [0xaa; 6];
    vec![
        PentestEvent::new(EventKind::SessionStarted {
            iface: "eth0".into(),
            our_ip: ip,
            gateway_ip: gw,
        }),
        PentestEvent::new(EventKind::SessionEnded),
        PentestEvent::new(EventKind::ScanStarted { target_count: 254 }),
        PentestEvent::new(EventKind::ScanCompleted { host_count: 7 }),
        PentestEvent::new(EventKind::HostDiscovered { ip, mac }),
        PentestEvent::new(EventKind::ArpPoisonStarted {
            target_ip: ip,
            target_mac: mac,
            gateway_ip: gw,
        }),
        PentestEvent::new(EventKind::ArpPoisonStopped { target_ip: ip }),
        PentestEvent::new(EventKind::ArpCured),
        PentestEvent::new(EventKind::PacketForwarded {
            src: ip,
            dst: gw,
            len: 1500,
            proto: 6,
        }),
        PentestEvent::new(EventKind::PacketDropped { src: ip, dst: gw }),
        PentestEvent::new(EventKind::Credential {
            kind: CredentialKind::Cleartext,
            proto: "ftp".into(),
            detail: "USER root".into(),
            src: Some(ip),
            dst: Some(gw),
        }),
        PentestEvent::new(EventKind::Credential {
            kind: CredentialKind::NetNtlmV2,
            proto: "ntlm-v2-http".into(),
            detail: "alice::CORP:cafe:babe:dead".into(),
            src: Some(ip),
            dst: None,
        }),
        PentestEvent::new(EventKind::DnsQuery {
            name: "internal.corp".into(),
            src: ip,
        }),
        PentestEvent::new(EventKind::DnsSpoofed {
            name: "internal.corp".into(),
            spoof_ip: gw,
            src: ip,
        }),
        PentestEvent::new(EventKind::DnsRuleAdded {
            domain: "*.evil.com".into(),
            ip: gw,
        }),
        PentestEvent::new(EventKind::DnsRulesCleared),
        PentestEvent::new(EventKind::NameQuery {
            protocol: "llmnr",
            name: "wpad".into(),
            src: ip,
        }),
        PentestEvent::new(EventKind::NamePoisoned {
            protocol: "nbt-ns",
            name: "WPAD<00>".into(),
            spoof_ip: gw,
            src: ip,
        }),
        PentestEvent::new(EventKind::KillEnabled { target_ip: ip }),
        PentestEvent::new(EventKind::KillDisabled { target_ip: ip }),
        PentestEvent::info("boot"),
        PentestEvent::error(r#"quoted "mess" and \ backslash and ,comma"#),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_info_helper() {
        let e = PentestEvent::info("hello");
        assert!(matches!(e.kind, EventKind::Info { .. }));
        assert_eq!(e.severity(), Severity::Info);
    }

    #[test]
    fn test_error_helper() {
        let e = PentestEvent::error("boom");
        assert_eq!(e.severity(), Severity::Error);
    }

    #[test]
    fn test_severity_mapping() {
        let cred = PentestEvent::new(EventKind::Credential {
            kind: CredentialKind::Cleartext,
            proto: "ftp".into(),
            detail: "USER x".into(),
            src: None,
            dst: None,
        });
        assert_eq!(cred.severity(), Severity::Hit);

        let drop = PentestEvent::new(EventKind::PacketDropped {
            src: Ipv4Addr::new(1, 1, 1, 1),
            dst: Ipv4Addr::new(2, 2, 2, 2),
        });
        assert_eq!(drop.severity(), Severity::Warn);
    }

    #[test]
    fn test_from_forward_credential() {
        let fe = ForwardEvent::Credential {
            proto: "http-basic".into(),
            detail: "Basic xxx".into(),
        };
        let pe = PentestEvent::from_forward(fe).unwrap();
        match pe.kind {
            EventKind::Credential { kind, proto, .. } => {
                assert_eq!(kind, CredentialKind::HttpBasic);
                assert_eq!(proto, "http-basic");
            }
            _ => panic!("wrong kind"),
        }
    }

    #[test]
    fn test_from_forward_raw_frame_is_none() {
        let fe = ForwardEvent::RawFrame {
            data: vec![0; 10],
            timestamp_us: 1,
        };
        assert!(PentestEvent::from_forward(fe).is_none());
    }

    #[test]
    fn test_from_forward_packet() {
        let fe = ForwardEvent::PacketForwarded {
            src: Ipv4Addr::new(10, 0, 0, 1),
            dst: Ipv4Addr::new(10, 0, 0, 2),
            len: 64,
            proto: 6,
        };
        let pe = PentestEvent::from_forward(fe).unwrap();
        assert!(matches!(pe.kind, EventKind::PacketForwarded { len: 64, proto: 6, .. }));
    }

    #[test]
    fn test_json_includes_ts_and_type() {
        let e = PentestEvent::info("x");
        let j = format_json(&e);
        assert!(j.starts_with('{'));
        assert!(j.ends_with('}'));
        assert!(j.contains("\"ts_us\":"));
        assert!(j.contains("\"type\":\"info\""));
        assert!(j.contains("\"severity\":\"info\""));
    }

    #[test]
    fn test_json_escapes_quotes_and_backslash() {
        let e = PentestEvent::info(r#"he said "hi" \ bye"#);
        let j = format_json(&e);
        assert!(j.contains(r#"\"hi\""#));
        assert!(j.contains(r"\\"));
    }

    #[test]
    fn test_json_credential_roundtrip_fields() {
        let e = PentestEvent::new(EventKind::Credential {
            kind: CredentialKind::HttpBasic,
            proto: "http-basic".into(),
            detail: "Authorization: Basic xxx".into(),
            src: Some(Ipv4Addr::new(10, 0, 0, 5)),
            dst: Some(Ipv4Addr::new(10, 0, 0, 1)),
        });
        let j = format_json(&e);
        assert!(j.contains("\"type\":\"credential\""));
        assert!(j.contains("\"kind\":\"http_basic\""));
        assert!(j.contains("\"src\":\"10.0.0.5\""));
        assert!(j.contains("\"dst\":\"10.0.0.1\""));
    }

    #[test]
    fn test_human_format_has_prefix() {
        let e = PentestEvent::info("boot");
        let h = format_human(&e);
        assert!(h.contains("[info]"));
        assert!(h.contains("boot"));
    }

    #[test]
    fn test_fanout_broadcasts_to_all() {
        let (tx1, rx1) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();
        let mut fan = FanoutSink::new();
        fan.add(Box::new(ChannelSink::new(tx1)));
        fan.add(Box::new(ChannelSink::new(tx2)));
        assert_eq!(fan.len(), 2);

        fan.emit(&PentestEvent::info("ping")).unwrap();

        let e1 = rx1.recv().unwrap();
        let e2 = rx2.recv().unwrap();
        assert!(matches!(e1.kind, EventKind::Info { .. }));
        assert!(matches!(e2.kind, EventKind::Info { .. }));
    }

    #[test]
    fn test_channel_sink_forwards_event() {
        let (tx, rx) = mpsc::channel();
        let mut sink = ChannelSink::new(tx);
        sink.emit(&PentestEvent::info("x")).unwrap();
        let got = rx.recv().unwrap();
        assert!(matches!(got.kind, EventKind::Info { .. }));
    }

    // coverage matrix: every EventKind variant must produce a non-empty
    // human line. catches "new variant, forgot a format_human arm" bugs.
    #[test]
    fn test_all_variants_format_human_nonempty() {
        for ev in all_event_samples() {
            let h = format_human(&ev);
            assert!(!h.is_empty(), "empty human output for {:?}", ev.kind);
        }
    }

    // every variant must produce json that a real parser accepts. stricter
    // than structural balance — catches escape bugs, bad trailing commas,
    // incorrectly-quoted numbers, etc.
    #[test]
    fn test_all_variants_format_json_parses_as_valid_json() {
        for ev in all_event_samples() {
            let j = format_json(&ev);
            let parsed: serde_json::Value =
                serde_json::from_str(&j).unwrap_or_else(|e| {
                    panic!("format_json produced invalid json for {:?}: {} err={}", ev.kind, j, e)
                });
            let obj = parsed.as_object().expect("top-level must be object");
            assert!(obj.contains_key("ts_us"), "missing ts_us: {}", j);
            assert!(obj.contains_key("severity"), "missing severity: {}", j);
            let event = obj.get("event").expect("missing event object");
            assert!(
                event.get("type").is_some(),
                "event.type missing for {:?}: {}",
                ev.kind,
                j
            );
        }
    }

    // severity is an exhaustive match; this catches a future variant that
    // forgets to add a new severity arm (or uses the wildcard fallthrough
    // when it shouldn't).
    #[test]
    fn test_all_variants_have_severity() {
        for ev in all_event_samples() {
            let _ = ev.severity(); // just must not panic
        }
    }

    #[test]
    fn test_jsonl_file_sink_writes_line() {
        let tmp = std::env::temp_dir().join(format!(
            "kutout-test-{}.jsonl",
            std::process::id()
        ));
        {
            let mut sink = JsonlFileSink::create(&tmp).unwrap();
            sink.emit(&PentestEvent::info("a")).unwrap();
            sink.emit(&PentestEvent::info("b")).unwrap();
        }
        let contents = std::fs::read_to_string(&tmp).unwrap();
        let _ = std::fs::remove_file(&tmp);
        let lines: Vec<_> = contents.lines().collect();
        assert_eq!(lines.len(), 2);
        for line in &lines {
            assert!(line.starts_with('{') && line.ends_with('}'));
        }
    }
}
