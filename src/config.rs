// config — kutout.toml loader with precedence (cli > project > user > defaults).
//
// two-phase: serde deserializes strings, resolve() parses them into typed
// structures (cidr, mac).  resolve() failures surface bad config at startup
// rather than mid-engagement.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use crate::safe_mode::{parse_mac, Cidr, Exclusions};

const PROJECT_CONFIG: &str = "kutout.toml";
const USER_CONFIG_SUBPATH: &str = "kutout/config.toml";

// raw toml representation — strings-ish, forgiving
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct KutoutConfig {
    #[serde(default)]
    pub interface: Option<String>,
    #[serde(default)]
    pub out_dir: Option<PathBuf>,
    #[serde(default)]
    pub log_file: Option<PathBuf>,
    #[serde(default)]
    pub log_level: Option<String>,

    #[serde(default)]
    pub safe_mode: SafeModeConfig,

    #[serde(default)]
    pub dns_spoofs: Vec<DnsRuleConfig>,

    #[serde(default)]
    pub responder: ResponderConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SafeModeConfig {
    #[serde(default)]
    pub excluded_cidrs: Vec<String>,
    #[serde(default)]
    pub excluded_macs: Vec<String>,
    #[serde(default = "default_printer_probe")]
    pub printer_probe: bool,
    #[serde(default = "default_probe_timeout_ms")]
    pub probe_timeout_ms: u64,
}

impl Default for SafeModeConfig {
    fn default() -> Self {
        Self {
            excluded_cidrs: Vec::new(),
            excluded_macs: Vec::new(),
            printer_probe: default_printer_probe(),
            probe_timeout_ms: default_probe_timeout_ms(),
        }
    }
}

fn default_printer_probe() -> bool {
    true
}

fn default_probe_timeout_ms() -> u64 {
    200
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DnsRuleConfig {
    pub domain: String,
    pub ip: Ipv4Addr,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ResponderConfig {
    #[serde(default)]
    pub match_names: Vec<String>,
    #[serde(default)]
    pub exclude_names: Vec<String>,
}

// resolved/validated — ready to consume at runtime
#[derive(Debug, Clone, Default)]
pub struct ResolvedConfig {
    pub interface: Option<String>,
    pub out_dir: Option<PathBuf>,
    pub log_file: Option<PathBuf>,
    pub log_level: Option<String>,
    pub exclusions: Exclusions,
    pub dns_spoofs: Vec<(String, Ipv4Addr)>,
    pub responder_match: Vec<String>,
    pub responder_exclude: Vec<String>,
}

impl KutoutConfig {
    pub fn resolve(self) -> Result<ResolvedConfig> {
        let mut cidrs = Vec::new();
        for raw in &self.safe_mode.excluded_cidrs {
            cidrs.push(
                Cidr::parse(raw).with_context(|| format!("config safe_mode cidr: {}", raw))?,
            );
        }
        let mut macs = Vec::new();
        for raw in &self.safe_mode.excluded_macs {
            macs.push(
                parse_mac(raw).with_context(|| format!("config safe_mode mac: {}", raw))?,
            );
        }
        let exclusions = Exclusions {
            cidrs,
            macs,
            printer_probe: self.safe_mode.printer_probe,
            probe_timeout_ms: self.safe_mode.probe_timeout_ms,
        };
        let dns_spoofs = self
            .dns_spoofs
            .into_iter()
            .map(|r| (r.domain, r.ip))
            .collect();
        Ok(ResolvedConfig {
            interface: self.interface,
            out_dir: self.out_dir,
            log_file: self.log_file,
            log_level: self.log_level,
            exclusions,
            dns_spoofs,
            responder_match: self.responder.match_names,
            responder_exclude: self.responder.exclude_names,
        })
    }
}

// load config: --config (if given, must exist), else ./kutout.toml, else
// xdg user path, else all-defaults.
pub fn load(explicit: Option<&Path>) -> Result<KutoutConfig> {
    if let Some(path) = explicit {
        return load_file(path);
    }

    let project = Path::new(PROJECT_CONFIG);
    if project.exists() {
        return load_file(project);
    }

    if let Some(user) = xdg_config_path() {
        if user.exists() {
            return load_file(&user);
        }
    }

    Ok(KutoutConfig::default())
}

fn load_file(path: &Path) -> Result<KutoutConfig> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("read config {}", path.display()))?;
    let cfg: KutoutConfig = toml::from_str(&text)
        .with_context(|| format!("parse config {}", path.display()))?;
    Ok(cfg)
}

fn xdg_config_path() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))?;
    Some(base.join(USER_CONFIG_SUBPATH))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_resolves() {
        let c = KutoutConfig::default().resolve().unwrap();
        assert!(c.interface.is_none());
        assert!(c.exclusions.cidrs.is_empty());
        assert!(c.exclusions.printer_probe); // default ON
    }

    #[test]
    fn test_toml_roundtrip() {
        let raw = r#"
            interface = "eth0"
            out_dir = "./engagement"
            log_level = "debug"

            [safe_mode]
            excluded_cidrs = ["10.0.0.0/24", "192.168.1.5/32"]
            excluded_macs = ["aa:bb:cc:dd:ee:ff"]
            printer_probe = false
            probe_timeout_ms = 500

            [[dns_spoofs]]
            domain = "*.evil.com"
            ip = "10.0.0.100"
        "#;
        let cfg: KutoutConfig = toml::from_str(raw).unwrap();
        assert_eq!(cfg.interface.as_deref(), Some("eth0"));
        assert_eq!(cfg.log_level.as_deref(), Some("debug"));
        assert_eq!(cfg.safe_mode.excluded_cidrs.len(), 2);
        assert_eq!(cfg.safe_mode.excluded_macs.len(), 1);
        assert!(!cfg.safe_mode.printer_probe);
        assert_eq!(cfg.safe_mode.probe_timeout_ms, 500);
        assert_eq!(cfg.dns_spoofs.len(), 1);
        assert_eq!(cfg.dns_spoofs[0].domain, "*.evil.com");
    }

    #[test]
    fn test_resolve_parses_cidrs_and_macs() {
        let cfg = KutoutConfig {
            safe_mode: SafeModeConfig {
                excluded_cidrs: vec!["10.0.0.0/24".into()],
                excluded_macs: vec!["00:11:22:33:44:55".into()],
                printer_probe: false,
                probe_timeout_ms: 150,
            },
            ..Default::default()
        };
        let r = cfg.resolve().unwrap();
        assert_eq!(r.exclusions.cidrs.len(), 1);
        assert_eq!(r.exclusions.macs.len(), 1);
        assert_eq!(r.exclusions.macs[0], [0, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert_eq!(r.exclusions.probe_timeout_ms, 150);
    }

    #[test]
    fn test_resolve_rejects_bad_cidr() {
        let cfg = KutoutConfig {
            safe_mode: SafeModeConfig {
                excluded_cidrs: vec!["not-a-cidr".into()],
                ..Default::default()
            },
            ..Default::default()
        };
        let err = cfg.resolve().unwrap_err();
        assert!(err.to_string().contains("cidr"));
    }

    #[test]
    fn test_resolve_rejects_bad_mac() {
        let cfg = KutoutConfig {
            safe_mode: SafeModeConfig {
                excluded_macs: vec!["zz:zz:zz:zz:zz:zz".into()],
                ..Default::default()
            },
            ..Default::default()
        };
        let err = cfg.resolve().unwrap_err();
        assert!(err.to_string().contains("mac"));
    }

    #[test]
    fn test_partial_toml_uses_defaults() {
        let raw = r#"interface = "wlan0""#;
        let cfg: KutoutConfig = toml::from_str(raw).unwrap();
        assert_eq!(cfg.interface.as_deref(), Some("wlan0"));
        // safe_mode defaulted
        assert!(cfg.safe_mode.printer_probe);
        assert!(cfg.safe_mode.excluded_cidrs.is_empty());
        assert_eq!(cfg.safe_mode.probe_timeout_ms, 200);
    }

    #[test]
    fn test_load_explicit_path_reads_file() {
        let tmp = std::env::temp_dir().join(format!(
            "kutout-cfg-test-{}.toml",
            std::process::id()
        ));
        std::fs::write(
            &tmp,
            r#"interface = "eth1"
                [safe_mode]
                printer_probe = false"#,
        )
        .unwrap();

        let cfg = load(Some(&tmp)).unwrap();
        let _ = std::fs::remove_file(&tmp);
        assert_eq!(cfg.interface.as_deref(), Some("eth1"));
        assert!(!cfg.safe_mode.printer_probe);
    }

    #[test]
    fn test_load_missing_explicit_errors() {
        let nope = std::env::temp_dir().join("kutout-does-not-exist.toml");
        let _ = std::fs::remove_file(&nope);
        assert!(load(Some(&nope)).is_err());
    }

    // full-fat toml exercising every field and section. if someone adds
    // a new field without a default, this test will fail to parse → forces
    // thought about backwards compatibility.
    #[test]
    fn test_full_config_roundtrips_through_resolve() {
        let raw = r#"
            interface = "eno1"
            out_dir = "./engage"
            log_file = "./kutout.log"
            log_level = "trace"

            [safe_mode]
            excluded_cidrs = ["10.0.0.254/32", "192.168.1.0/28"]
            excluded_macs = ["aa:bb:cc:dd:ee:ff", "00:11:22:33:44:55"]
            printer_probe = false
            probe_timeout_ms = 250

            [[dns_spoofs]]
            domain = "*.phish.com"
            ip = "10.9.9.9"

            [[dns_spoofs]]
            domain = "internal"
            ip = "10.9.9.10"

            [responder]
            match_names = ["wpad", "*.corp"]
            exclude_names = ["dc01.corp", "printer*"]
        "#;
        let cfg: KutoutConfig = toml::from_str(raw).expect("parse");
        let r = cfg.resolve().expect("resolve");

        assert_eq!(r.interface.as_deref(), Some("eno1"));
        assert_eq!(r.out_dir.as_deref(), Some(std::path::Path::new("./engage")));
        assert_eq!(r.log_file.as_deref(), Some(std::path::Path::new("./kutout.log")));
        assert_eq!(r.log_level.as_deref(), Some("trace"));

        assert_eq!(r.exclusions.cidrs.len(), 2);
        assert_eq!(r.exclusions.macs.len(), 2);
        assert!(!r.exclusions.printer_probe);
        assert_eq!(r.exclusions.probe_timeout_ms, 250);

        assert_eq!(r.dns_spoofs.len(), 2);
        assert_eq!(r.dns_spoofs[0].0, "*.phish.com");
        assert_eq!(r.dns_spoofs[1].1, Ipv4Addr::new(10, 9, 9, 10));

        assert_eq!(r.responder_match, vec!["wpad", "*.corp"]);
        assert_eq!(r.responder_exclude, vec!["dc01.corp", "printer*"]);
    }

    // empty toml file (just whitespace) parses to all defaults.
    // catches "added a field without #[serde(default)]" regressions.
    #[test]
    fn test_empty_toml_uses_all_defaults() {
        let cfg: KutoutConfig = toml::from_str("").expect("empty parse");
        let r = cfg.resolve().unwrap();
        assert!(r.interface.is_none());
        assert!(r.out_dir.is_none());
        assert!(r.log_file.is_none());
        assert!(r.log_level.is_none());
        assert!(r.exclusions.cidrs.is_empty());
        assert!(r.exclusions.macs.is_empty());
        assert!(r.exclusions.printer_probe); // default ON
        assert_eq!(r.exclusions.probe_timeout_ms, 200);
        assert!(r.dns_spoofs.is_empty());
        assert!(r.responder_match.is_empty());
        assert!(r.responder_exclude.is_empty());
    }

    // only responder section, nothing else
    #[test]
    fn test_toml_with_only_responder() {
        let raw = r#"
            [responder]
            match_names = ["wpad"]
        "#;
        let cfg: KutoutConfig = toml::from_str(raw).unwrap();
        let r = cfg.resolve().unwrap();
        assert_eq!(r.responder_match, vec!["wpad"]);
        assert!(r.responder_exclude.is_empty());
        // safe_mode still defaulted
        assert!(r.exclusions.printer_probe);
    }

    // unknown fields should NOT cause a parse error (toml is forgiving by
    // default). if we ever add deny_unknown_fields, this test will fail
    // and prompt us to think about migration.
    #[test]
    fn test_unknown_toml_fields_are_ignored() {
        let raw = r#"
            interface = "eth0"
            random_future_field = "surprise"

            [safe_mode]
            unknown_subfield = 42
        "#;
        let cfg: Result<KutoutConfig, _> = toml::from_str(raw);
        assert!(
            cfg.is_ok(),
            "unknown fields should parse; deny_unknown_fields would break \
             forward-compat for users on old binaries"
        );
    }

    #[test]
    fn test_dns_rules_resolve_to_tuples() {
        let cfg = KutoutConfig {
            dns_spoofs: vec![DnsRuleConfig {
                domain: "evil.com".into(),
                ip: Ipv4Addr::new(6, 6, 6, 6),
            }],
            ..Default::default()
        };
        let r = cfg.resolve().unwrap();
        assert_eq!(r.dns_spoofs.len(), 1);
        assert_eq!(r.dns_spoofs[0].0, "evil.com");
        assert_eq!(r.dns_spoofs[0].1, Ipv4Addr::new(6, 6, 6, 6));
    }
}
