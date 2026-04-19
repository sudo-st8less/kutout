// summary — aggregates pentestevents into engagement artifacts (json + csv).
//
// a SummarySink lives inside the FanoutSink, shares state via Arc<Mutex<Summary>>,
// so main-loop code (e.g. the 'e' tui keybind) can snapshot the state without
// replaying the jsonl file.

use anyhow::{Context, Result};
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::{Arc, Mutex};

use crate::events::{
    json_escape_into, push_kv_num, push_kv_str, CredentialKind, EventKind, EventSink,
    PentestEvent,
};

// "what gets measured gets managed." — (mis)attributed to peter drucker

#[derive(Debug, Clone)]
pub struct CapturedCredential {
    pub ts_us: u64,
    pub kind: CredentialKind,
    pub proto: String,
    pub detail: String,
    pub src: Option<Ipv4Addr>,
    pub dst: Option<Ipv4Addr>,
}

#[derive(Debug, Default)]
pub struct Summary {
    pub session_start_us: Option<u64>,
    pub session_end_us: Option<u64>,
    pub iface: String,
    pub our_ip: Option<Ipv4Addr>,
    pub gateway_ip: Option<Ipv4Addr>,
    pub hosts: Vec<(Ipv4Addr, [u8; 6])>,
    pub credentials: Vec<CapturedCredential>,
    pub dns_rules: Vec<(String, Ipv4Addr)>,
    pub poisoned_targets: Vec<Ipv4Addr>,
    pub dns_queries: u64,
    pub dns_spoofs: u64,
    pub name_queries: u64,
    pub names_poisoned: u64,
    pub packets_forwarded: u64,
    pub packets_dropped: u64,
    pub scans_completed: u64,
    pub error_count: u64,
}

impl Summary {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&mut self, event: &PentestEvent) {
        let ts = event.timestamp_us();
        if self.session_start_us.is_none() {
            self.session_start_us = Some(ts);
        }
        self.session_end_us = Some(ts);

        match &event.kind {
            EventKind::SessionStarted { iface, our_ip, gateway_ip } => {
                self.iface = iface.clone();
                self.our_ip = Some(*our_ip);
                self.gateway_ip = Some(*gateway_ip);
            }
            EventKind::HostDiscovered { ip, mac } => {
                if !self.hosts.iter().any(|(h, _)| h == ip) {
                    self.hosts.push((*ip, *mac));
                }
            }
            EventKind::Credential { kind, proto, detail, src, dst } => {
                self.credentials.push(CapturedCredential {
                    ts_us: ts,
                    kind: *kind,
                    proto: proto.clone(),
                    detail: detail.clone(),
                    src: *src,
                    dst: *dst,
                });
            }
            EventKind::DnsRuleAdded { domain, ip } => {
                self.dns_rules.push((domain.clone(), *ip));
            }
            EventKind::DnsRulesCleared => {
                self.dns_rules.clear();
            }
            EventKind::DnsQuery { .. } => self.dns_queries += 1,
            EventKind::DnsSpoofed { .. } => self.dns_spoofs += 1,
            EventKind::NameQuery { .. } => self.name_queries += 1,
            EventKind::NamePoisoned { .. } => self.names_poisoned += 1,
            EventKind::PacketForwarded { .. } => self.packets_forwarded += 1,
            EventKind::PacketDropped { .. } => self.packets_dropped += 1,
            EventKind::ArpPoisonStarted { target_ip, .. } => {
                if !self.poisoned_targets.contains(target_ip) {
                    self.poisoned_targets.push(*target_ip);
                }
            }
            EventKind::ArpCured => {
                self.poisoned_targets.clear();
            }
            EventKind::ScanCompleted { .. } => self.scans_completed += 1,
            EventKind::Error { .. } => self.error_count += 1,
            _ => {}
        }
    }

    pub fn duration_us(&self) -> u64 {
        match (self.session_start_us, self.session_end_us) {
            (Some(s), Some(e)) if e >= s => e - s,
            _ => 0,
        }
    }

    pub fn to_json(&self) -> String {
        let mut s = String::with_capacity(512);
        s.push('{');
        push_kv_num(&mut s, "session_start_us", self.session_start_us.unwrap_or(0));
        s.push(',');
        push_kv_num(&mut s, "session_end_us", self.session_end_us.unwrap_or(0));
        s.push(',');
        push_kv_num(&mut s, "duration_us", self.duration_us());
        s.push(',');
        push_kv_str(&mut s, "iface", &self.iface);
        s.push(',');
        push_kv_str(
            &mut s,
            "our_ip",
            &self.our_ip.map(|ip| ip.to_string()).unwrap_or_default(),
        );
        s.push(',');
        push_kv_str(
            &mut s,
            "gateway_ip",
            &self.gateway_ip.map(|ip| ip.to_string()).unwrap_or_default(),
        );
        s.push(',');

        // counters
        push_kv_num(&mut s, "packets_forwarded", self.packets_forwarded);
        s.push(',');
        push_kv_num(&mut s, "packets_dropped", self.packets_dropped);
        s.push(',');
        push_kv_num(&mut s, "dns_queries", self.dns_queries);
        s.push(',');
        push_kv_num(&mut s, "dns_spoofs", self.dns_spoofs);
        s.push(',');
        push_kv_num(&mut s, "name_queries", self.name_queries);
        s.push(',');
        push_kv_num(&mut s, "names_poisoned", self.names_poisoned);
        s.push(',');
        push_kv_num(&mut s, "scans_completed", self.scans_completed);
        s.push(',');
        push_kv_num(&mut s, "error_count", self.error_count);
        s.push(',');

        // hosts
        s.push_str("\"hosts\":[");
        for (i, (ip, mac)) in self.hosts.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push('{');
            push_kv_str(&mut s, "ip", &ip.to_string());
            s.push(',');
            push_kv_str(&mut s, "mac", &format_mac(mac));
            s.push('}');
        }
        s.push(']');
        s.push(',');

        // credentials
        s.push_str("\"credentials\":[");
        for (i, c) in self.credentials.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push('{');
            push_kv_num(&mut s, "ts_us", c.ts_us);
            s.push(',');
            push_kv_str(&mut s, "kind", credential_kind_str(c.kind));
            s.push(',');
            push_kv_str(&mut s, "proto", &c.proto);
            s.push(',');
            push_kv_str(&mut s, "detail", &c.detail);
            s.push(',');
            push_kv_str(
                &mut s,
                "src",
                &c.src.map(|ip| ip.to_string()).unwrap_or_default(),
            );
            s.push(',');
            push_kv_str(
                &mut s,
                "dst",
                &c.dst.map(|ip| ip.to_string()).unwrap_or_default(),
            );
            s.push('}');
        }
        s.push(']');
        s.push(',');

        // dns rules
        s.push_str("\"dns_rules\":[");
        for (i, (domain, ip)) in self.dns_rules.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push('{');
            push_kv_str(&mut s, "domain", domain);
            s.push(',');
            push_kv_str(&mut s, "ip", &ip.to_string());
            s.push('}');
        }
        s.push(']');
        s.push(',');

        // poisoned targets
        s.push_str("\"poisoned_targets\":[");
        for (i, ip) in self.poisoned_targets.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push('"');
            json_escape_into(&ip.to_string(), &mut s);
            s.push('"');
        }
        s.push(']');
        s.push('}');
        s
    }

    pub fn to_hosts_csv(&self) -> String {
        let mut s = String::from("ip,mac\n");
        for (ip, mac) in &self.hosts {
            s.push_str(&ip.to_string());
            s.push(',');
            s.push_str(&format_mac(mac));
            s.push('\n');
        }
        s
    }

    pub fn to_credentials_csv(&self) -> String {
        let mut s = String::from("ts_us,kind,proto,src,dst,detail\n");
        for c in &self.credentials {
            s.push_str(&c.ts_us.to_string());
            s.push(',');
            s.push_str(credential_kind_str(c.kind));
            s.push(',');
            csv_escape_into(&c.proto, &mut s);
            s.push(',');
            s.push_str(&c.src.map(|i| i.to_string()).unwrap_or_default());
            s.push(',');
            s.push_str(&c.dst.map(|i| i.to_string()).unwrap_or_default());
            s.push(',');
            csv_escape_into(&c.detail, &mut s);
            s.push('\n');
        }
        s
    }

    // write summary.json, hosts.csv, credentials.csv to dir
    pub fn write_to_dir(&self, dir: &Path) -> Result<()> {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("mkdir {}", dir.display()))?;
        std::fs::write(dir.join("summary.json"), self.to_json())
            .context("write summary.json")?;
        std::fs::write(dir.join("hosts.csv"), self.to_hosts_csv())
            .context("write hosts.csv")?;
        std::fs::write(dir.join("credentials.csv"), self.to_credentials_csv())
            .context("write credentials.csv")?;
        Ok(())
    }
}

// sink adapter — records into a shared Summary behind Arc<Mutex>
pub struct SummarySink {
    pub state: Arc<Mutex<Summary>>,
}

impl SummarySink {
    pub fn new(state: Arc<Mutex<Summary>>) -> Self {
        Self { state }
    }
}

impl EventSink for SummarySink {
    fn emit(&mut self, event: &PentestEvent) -> Result<()> {
        self.state
            .lock()
            .map_err(|_| anyhow::anyhow!("summary mutex poisoned"))?
            .record(event);
        Ok(())
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

// csv: wrap in quotes and double internal quotes when needed (rfc 4180)
fn csv_escape_into(input: &str, out: &mut String) {
    let needs_quoting = input
        .chars()
        .any(|c| c == ',' || c == '"' || c == '\n' || c == '\r');
    if !needs_quoting {
        out.push_str(input);
        return;
    }
    out.push('"');
    for c in input.chars() {
        if c == '"' {
            out.push('"');
        }
        out.push(c);
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{CredentialKind, EventKind, PentestEvent};

    #[test]
    fn test_record_session_start_populates_metadata() {
        let mut s = Summary::new();
        s.record(&PentestEvent::new(EventKind::SessionStarted {
            iface: "eth0".into(),
            our_ip: Ipv4Addr::new(10, 0, 0, 1),
            gateway_ip: Ipv4Addr::new(10, 0, 0, 254),
        }));
        assert_eq!(s.iface, "eth0");
        assert_eq!(s.our_ip, Some(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(s.gateway_ip, Some(Ipv4Addr::new(10, 0, 0, 254)));
        assert!(s.session_start_us.is_some());
    }

    #[test]
    fn test_record_host_dedupes() {
        let mut s = Summary::new();
        let ip = Ipv4Addr::new(10, 0, 0, 5);
        s.record(&PentestEvent::new(EventKind::HostDiscovered { ip, mac: [1; 6] }));
        s.record(&PentestEvent::new(EventKind::HostDiscovered { ip, mac: [1; 6] }));
        assert_eq!(s.hosts.len(), 1);
    }

    #[test]
    fn test_record_credential_appends() {
        let mut s = Summary::new();
        s.record(&PentestEvent::new(EventKind::Credential {
            kind: CredentialKind::HttpBasic,
            proto: "http-basic".into(),
            detail: "Basic xxx".into(),
            src: Some(Ipv4Addr::new(10, 0, 0, 5)),
            dst: Some(Ipv4Addr::new(10, 0, 0, 1)),
        }));
        assert_eq!(s.credentials.len(), 1);
        assert_eq!(s.credentials[0].proto, "http-basic");
        assert_eq!(s.credentials[0].src, Some(Ipv4Addr::new(10, 0, 0, 5)));
    }

    #[test]
    fn test_record_counters_increment() {
        let mut s = Summary::new();
        for _ in 0..3 {
            s.record(&PentestEvent::new(EventKind::PacketForwarded {
                src: Ipv4Addr::new(1, 1, 1, 1),
                dst: Ipv4Addr::new(2, 2, 2, 2),
                len: 64,
                proto: 6,
            }));
        }
        s.record(&PentestEvent::new(EventKind::PacketDropped {
            src: Ipv4Addr::new(1, 1, 1, 1),
            dst: Ipv4Addr::new(2, 2, 2, 2),
        }));
        s.record(&PentestEvent::new(EventKind::DnsQuery {
            name: "x".into(),
            src: Ipv4Addr::new(1, 1, 1, 1),
        }));
        s.record(&PentestEvent::error("oops"));
        assert_eq!(s.packets_forwarded, 3);
        assert_eq!(s.packets_dropped, 1);
        assert_eq!(s.dns_queries, 1);
        assert_eq!(s.error_count, 1);
    }

    #[test]
    fn test_dns_rules_lifecycle() {
        let mut s = Summary::new();
        s.record(&PentestEvent::new(EventKind::DnsRuleAdded {
            domain: "evil.com".into(),
            ip: Ipv4Addr::new(6, 6, 6, 6),
        }));
        s.record(&PentestEvent::new(EventKind::DnsRuleAdded {
            domain: "*.bank.com".into(),
            ip: Ipv4Addr::new(6, 6, 6, 6),
        }));
        assert_eq!(s.dns_rules.len(), 2);
        s.record(&PentestEvent::new(EventKind::DnsRulesCleared));
        assert!(s.dns_rules.is_empty());
    }

    #[test]
    fn test_poisoned_targets_dedupe_and_cure() {
        let mut s = Summary::new();
        let t1 = Ipv4Addr::new(10, 0, 0, 5);
        let t2 = Ipv4Addr::new(10, 0, 0, 6);
        s.record(&PentestEvent::new(EventKind::ArpPoisonStarted {
            target_ip: t1,
            target_mac: [1; 6],
            gateway_ip: Ipv4Addr::new(10, 0, 0, 1),
        }));
        s.record(&PentestEvent::new(EventKind::ArpPoisonStarted {
            target_ip: t1,
            target_mac: [1; 6],
            gateway_ip: Ipv4Addr::new(10, 0, 0, 1),
        }));
        s.record(&PentestEvent::new(EventKind::ArpPoisonStarted {
            target_ip: t2,
            target_mac: [2; 6],
            gateway_ip: Ipv4Addr::new(10, 0, 0, 1),
        }));
        assert_eq!(s.poisoned_targets.len(), 2);

        s.record(&PentestEvent::new(EventKind::ArpCured));
        assert!(s.poisoned_targets.is_empty());
    }

    #[test]
    fn test_duration_us() {
        let mut s = Summary::new();
        s.session_start_us = Some(1000);
        s.session_end_us = Some(5000);
        assert_eq!(s.duration_us(), 4000);
    }

    #[test]
    fn test_json_structure() {
        let mut s = Summary::new();
        s.record(&PentestEvent::new(EventKind::SessionStarted {
            iface: "eth0".into(),
            our_ip: Ipv4Addr::new(10, 0, 0, 1),
            gateway_ip: Ipv4Addr::new(10, 0, 0, 254),
        }));
        s.record(&PentestEvent::new(EventKind::HostDiscovered {
            ip: Ipv4Addr::new(10, 0, 0, 5),
            mac: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
        }));
        s.record(&PentestEvent::new(EventKind::Credential {
            kind: CredentialKind::Cleartext,
            proto: "ftp".into(),
            detail: "USER admin".into(),
            src: Some(Ipv4Addr::new(10, 0, 0, 5)),
            dst: None,
        }));
        let j = s.to_json();
        assert!(j.starts_with('{'));
        assert!(j.ends_with('}'));
        assert!(j.contains("\"iface\":\"eth0\""));
        assert!(j.contains("\"hosts\":["));
        assert!(j.contains("11:22:33:44:55:66"));
        assert!(j.contains("\"credentials\":["));
        assert!(j.contains("USER admin"));
    }

    #[test]
    fn test_hosts_csv() {
        let mut s = Summary::new();
        s.record(&PentestEvent::new(EventKind::HostDiscovered {
            ip: Ipv4Addr::new(10, 0, 0, 5),
            mac: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        }));
        let csv = s.to_hosts_csv();
        let mut lines = csv.lines();
        assert_eq!(lines.next(), Some("ip,mac"));
        assert_eq!(lines.next(), Some("10.0.0.5,aa:bb:cc:dd:ee:ff"));
    }

    #[test]
    fn test_credentials_csv_escapes_commas_and_quotes() {
        let mut s = Summary::new();
        s.session_start_us = Some(1000);
        s.credentials.push(CapturedCredential {
            ts_us: 1500,
            kind: CredentialKind::HttpPost,
            proto: "http-post".into(),
            detail: r#"user=bob, pass="secret""#.into(),
            src: Some(Ipv4Addr::new(10, 0, 0, 5)),
            dst: None,
        });
        let csv = s.to_credentials_csv();
        let mut lines = csv.lines();
        assert_eq!(
            lines.next(),
            Some("ts_us,kind,proto,src,dst,detail")
        );
        let data = lines.next().unwrap();
        assert!(data.contains("1500,http_post,http-post,10.0.0.5,,"));
        // detail has comma and quotes → must be quoted, internal quotes doubled
        assert!(data.contains(r#""user=bob, pass=""secret""""#));
    }

    #[test]
    fn test_sink_writes_through_mutex() {
        let state = Arc::new(Mutex::new(Summary::new()));
        let mut sink = SummarySink::new(state.clone());
        sink.emit(&PentestEvent::new(EventKind::HostDiscovered {
            ip: Ipv4Addr::new(1, 2, 3, 4),
            mac: [0; 6],
        }))
        .unwrap();
        assert_eq!(state.lock().unwrap().hosts.len(), 1);
    }

    // every EventKind variant must be accepted by record() without panic.
    // catches "new variant, forgot a match arm" in summary aggregation.
    #[test]
    fn test_record_handles_every_event_variant() {
        let mut s = Summary::new();
        for ev in crate::events::all_event_samples() {
            s.record(&ev);
        }
        // at minimum: we saw a SessionStarted so iface should be set
        assert_eq!(s.iface, "eth0");
        // some counters should move
        assert!(s.packets_forwarded >= 1);
        assert!(s.packets_dropped >= 1);
        assert!(s.dns_queries >= 1);
        assert!(s.dns_spoofs >= 1);
        assert!(s.name_queries >= 1);
        assert!(s.names_poisoned >= 1);
        assert!(s.error_count >= 1);
        assert!(s.scans_completed >= 1);
        assert!(!s.credentials.is_empty());
    }

    // end-to-end: realistic engagement → write_to_dir → re-read and parse.
    // summary.json must be valid json (strict parse). csv files validated
    // by field count + content. catches escaping, json malformedness,
    // empty-state regressions.
    #[test]
    fn test_end_to_end_write_reads_back_expected_structure() {
        let mut s = Summary::new();
        for ev in crate::events::all_event_samples() {
            s.record(&ev);
        }

        let dir = std::env::temp_dir().join(format!(
            "kutout-e2e-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        s.write_to_dir(&dir).unwrap();

        let json_text = std::fs::read_to_string(dir.join("summary.json")).unwrap();
        let hosts = std::fs::read_to_string(dir.join("hosts.csv")).unwrap();
        let creds = std::fs::read_to_string(dir.join("credentials.csv")).unwrap();
        let _ = std::fs::remove_dir_all(&dir);

        // summary.json: must be valid json, not just balanced braces
        let json: serde_json::Value = serde_json::from_str(&json_text)
            .expect("summary.json must be valid json");
        let obj = json.as_object().expect("top-level object");
        assert_eq!(obj.get("iface").and_then(|v| v.as_str()), Some("eth0"));
        assert!(obj.get("hosts").and_then(|v| v.as_array()).is_some());
        assert!(obj.get("credentials").and_then(|v| v.as_array()).is_some());
        assert!(obj.get("dns_rules").and_then(|v| v.as_array()).is_some());
        assert!(obj.get("poisoned_targets").and_then(|v| v.as_array()).is_some());
        // counters present as numbers
        for k in &[
            "packets_forwarded",
            "packets_dropped",
            "dns_queries",
            "dns_spoofs",
            "name_queries",
            "names_poisoned",
            "scans_completed",
            "error_count",
        ] {
            assert!(obj.get(*k).and_then(|v| v.as_u64()).is_some(), "{} missing/wrong type", k);
        }

        // hosts.csv: header + at least one row
        let host_lines: Vec<_> = hosts.lines().collect();
        assert_eq!(host_lines[0], "ip,mac");
        assert!(host_lines.len() >= 2);
        assert!(host_lines[1].starts_with("10.0.0.5,"));

        // credentials.csv: header + at least cleartext + ntlmv2 rows
        let cred_lines: Vec<_> = creds.lines().collect();
        assert_eq!(cred_lines[0], "ts_us,kind,proto,src,dst,detail");
        assert!(cred_lines.len() >= 3);
        assert!(creds.contains("cleartext"));
        assert!(creds.contains("net_ntlm_v2"));
    }

    // zero-event summary must still produce valid, parseable outputs
    #[test]
    fn test_empty_summary_writes_valid_files() {
        let s = Summary::new();
        let dir = std::env::temp_dir().join(format!(
            "kutout-empty-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        s.write_to_dir(&dir).unwrap();

        let json_text = std::fs::read_to_string(dir.join("summary.json")).unwrap();
        let hosts = std::fs::read_to_string(dir.join("hosts.csv")).unwrap();
        let creds = std::fs::read_to_string(dir.join("credentials.csv")).unwrap();
        let _ = std::fs::remove_dir_all(&dir);

        // must parse as valid json with empty collections
        let json: serde_json::Value = serde_json::from_str(&json_text)
            .expect("empty summary.json must be valid json");
        let obj = json.as_object().unwrap();
        assert!(obj.get("hosts").unwrap().as_array().unwrap().is_empty());
        assert!(obj.get("credentials").unwrap().as_array().unwrap().is_empty());
        assert!(obj.get("dns_rules").unwrap().as_array().unwrap().is_empty());

        // csvs: header only
        assert_eq!(hosts.trim(), "ip,mac");
        assert_eq!(creds.trim(), "ts_us,kind,proto,src,dst,detail");
    }

    #[test]
    fn test_write_to_dir_creates_files() {
        let dir = std::env::temp_dir().join(format!(
            "kutout-summary-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);

        let mut s = Summary::new();
        s.record(&PentestEvent::new(EventKind::SessionStarted {
            iface: "eth0".into(),
            our_ip: Ipv4Addr::new(10, 0, 0, 1),
            gateway_ip: Ipv4Addr::new(10, 0, 0, 254),
        }));
        s.write_to_dir(&dir).unwrap();

        assert!(dir.join("summary.json").exists());
        assert!(dir.join("hosts.csv").exists());
        assert!(dir.join("credentials.csv").exists());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
