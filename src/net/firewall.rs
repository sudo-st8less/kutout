// iptables kill mode
//
// dedicated KUTOUT chain in FORWARD. never touches other rules.

use anyhow::{anyhow, Result};
use std::net::Ipv4Addr;
use std::process::Command;

const CHAIN: &str = "KUTOUT";

fn run_iptables(args: &[&str]) -> Result<()> {
    let output = Command::new("iptables")
        .args(args)
        .output()
        .map_err(|e| anyhow!("failed to run iptables: {}", e))?;

    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(anyhow!("iptables {:?} failed: {}", args, stderr.trim()))
    }
}

// create chain, insert jump
pub fn init() -> Result<()> {
    cleanup();
    let _ = run_iptables(&["-N", CHAIN]);
    if run_iptables(&["-C", "FORWARD", "-j", CHAIN]).is_err() {
        run_iptables(&["-I", "FORWARD", "-j", CHAIN])?;
    }
    Ok(())
}

// drop both directions
pub fn kill(ip: Ipv4Addr) -> Result<()> {
    let ip_str = ip.to_string();
    run_iptables(&["-I", CHAIN, "-s", &ip_str, "-j", "DROP"])?;
    run_iptables(&["-I", CHAIN, "-d", &ip_str, "-j", "DROP"])?;
    Ok(())
}

// "the usefulness of a pot comes from its emptiness." — tao te ching, 11

// remove drop rules
pub fn unkill(ip: Ipv4Addr) -> Result<()> {
    let ip_str = ip.to_string();
    let _ = run_iptables(&["-D", CHAIN, "-s", &ip_str, "-j", "DROP"]);
    let _ = run_iptables(&["-D", CHAIN, "-d", &ip_str, "-j", "DROP"]);
    Ok(())
}

// flush, remove jump, delete chain
pub fn cleanup() {
    let _ = run_iptables(&["-F", CHAIN]);
    let _ = run_iptables(&["-D", "FORWARD", "-j", CHAIN]);
    let _ = run_iptables(&["-X", CHAIN]);
}

#[cfg(test)]
mod tests {
    use super::*;

    // needs root for real tests

    #[test]
    fn test_run_iptables_bad_command() {
        let result = run_iptables(&["--this-flag-does-not-exist"]);
        assert!(result.is_err());
    }
}
