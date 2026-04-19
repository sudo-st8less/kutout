// end-to-end CLI smoke tests.
//
// these run the built binary as a subprocess and assert on exit codes +
// stdout/stderr. they catch:
//   - clap argument parsing regressions
//   - subcommand wiring breaks
//   - help text missing / malformed
//   - config loader error surfaces (missing file, bad toml)
//
// they do NOT test anything that requires root or a network interface
// (arp, poisoning, listener binds) — those can't run in ci reliably.

use std::process::{Command, Stdio};

fn kutout() -> Command {
    Command::new(env!("CARGO_BIN_EXE_kutout"))
}

fn run_with_args(args: &[&str]) -> (i32, String, String) {
    let out = kutout()
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn kutout");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn cli_help_exits_zero() {
    let (code, stdout, _) = run_with_args(&["--help"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("mitm toolkit"));
    assert!(stdout.contains("scan"));
    assert!(stdout.contains("poison"));
    assert!(stdout.contains("live"));
    assert!(stdout.contains("responder"));
    assert!(stdout.contains("ifaces"));
}

#[test]
fn cli_version_exits_zero() {
    let (code, stdout, _) = run_with_args(&["--version"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("kutout"));
}

#[test]
fn cli_subcommand_helps_all_exit_zero() {
    for sub in &["scan", "poison", "live", "responder", "ifaces"] {
        let (code, _, stderr) = run_with_args(&[sub, "--help"]);
        assert_eq!(code, 0, "{} --help failed: {}", sub, stderr);
    }
}

#[test]
fn cli_poison_help_shows_out_dir_flag() {
    let (code, stdout, _) = run_with_args(&["poison", "--help"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("--out-dir"));
    assert!(stdout.contains("--sniff"));
    assert!(stdout.contains("--kill"));
}

#[test]
fn cli_responder_help_shows_protocol_toggles() {
    let (code, stdout, _) = run_with_args(&["responder", "--help"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("--no-llmnr"));
    assert!(stdout.contains("--no-mdns"));
    assert!(stdout.contains("--no-nbt-ns"));
    assert!(stdout.contains("--no-http"));
}

#[test]
fn cli_missing_config_errors_clearly() {
    let nope = std::env::temp_dir().join(format!(
        "kutout-nope-{}.toml",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&nope);
    let path_str = nope.to_string_lossy().into_owned();
    let (code, _, stderr) = run_with_args(&["-c", &path_str, "ifaces"]);
    assert_ne!(code, 0, "missing config should be fatal");
    assert!(
        stderr.to_lowercase().contains("read config")
            || stderr.to_lowercase().contains("no such file"),
        "error should mention config read failure: {}",
        stderr
    );
}

#[test]
fn cli_bad_toml_errors_clearly() {
    let path = std::env::temp_dir().join(format!(
        "kutout-bad-{}.toml",
        std::process::id()
    ));
    std::fs::write(&path, "this is = = not valid [[[ toml").unwrap();
    let path_str = path.to_string_lossy().into_owned();
    let (code, _, stderr) = run_with_args(&["-c", &path_str, "ifaces"]);
    let _ = std::fs::remove_file(&path);
    assert_ne!(code, 0);
    assert!(
        stderr.to_lowercase().contains("parse config")
            || stderr.to_lowercase().contains("invalid"),
        "error should mention parse failure: {}",
        stderr
    );
}

#[test]
fn cli_valid_config_with_ifaces_succeeds() {
    let path = std::env::temp_dir().join(format!(
        "kutout-valid-{}.toml",
        std::process::id()
    ));
    std::fs::write(
        &path,
        r#"
        interface = "lo"
        [safe_mode]
        printer_probe = false
        [responder]
        match_names = ["wpad"]
        "#,
    )
    .unwrap();
    let path_str = path.to_string_lossy().into_owned();
    let (code, _stdout, _stderr) = run_with_args(&["-c", &path_str, "ifaces"]);
    let _ = std::fs::remove_file(&path);
    // ifaces doesn't require root, should succeed
    assert_eq!(code, 0, "valid config + ifaces should succeed");
}

#[test]
fn cli_ifaces_exits_zero_without_root() {
    // ifaces prints interfaces from pnet_datalink — doesn't need root
    let (code, stdout, _) = run_with_args(&["ifaces"]);
    assert_eq!(code, 0);
    // header should be present even when no usable iface
    assert!(stdout.contains("interface") || stdout.contains("no usable"));
}

#[test]
fn cli_unknown_subcommand_fails() {
    let (code, _, _) = run_with_args(&["totally-not-a-command"]);
    assert_ne!(code, 0);
}

#[test]
fn cli_conflicting_flags_do_not_crash() {
    // e.g. bare 'poison' with no target — should fail parse, not panic
    let (code, _, stderr) = run_with_args(&["poison"]);
    assert_ne!(code, 0);
    // clap prints a usage hint on missing required args
    assert!(
        stderr.to_lowercase().contains("required")
            || stderr.to_lowercase().contains("usage"),
        "should explain missing arg: {}",
        stderr
    );
}
