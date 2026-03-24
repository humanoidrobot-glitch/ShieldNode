//! Kill switch: blocks all non-VPN traffic when the tunnel drops unexpectedly.
//!
//! Uses OS-level firewall rules to prevent IP leaks. When activated, only
//! traffic to the VPN entry node endpoint is allowed. All other outbound
//! traffic is blocked until the kill switch is deactivated (on reconnect or
//! explicit disconnect).
//!
//! Platform support:
//! - Windows: netsh advfirewall (WFP)
//! - Linux: iptables
//! - macOS: pf (packet filter)

use std::net::SocketAddr;
use std::process::Command;
use tracing::{info, warn};

const RULE_NAME: &str = "ShieldNode-KillSwitch";

/// Activate the kill switch: block all traffic except to the VPN entry node.
pub fn activate(entry_endpoint: &str) -> Result<(), String> {
    let addr: SocketAddr = entry_endpoint
        .parse()
        .map_err(|e| format!("invalid entry endpoint: {e}"))?;
    let entry_ip = addr.ip().to_string();

    info!(entry_ip = %entry_ip, "activating kill switch");

    #[cfg(target_os = "windows")]
    activate_windows(&entry_ip)?;

    #[cfg(target_os = "linux")]
    activate_linux(&entry_ip)?;

    #[cfg(target_os = "macos")]
    activate_macos(&entry_ip)?;

    info!("kill switch active — all non-VPN traffic blocked");
    Ok(())
}

/// Deactivate the kill switch: remove all blocking rules and restore normal traffic.
pub fn deactivate() -> Result<(), String> {
    info!("deactivating kill switch");

    #[cfg(target_os = "windows")]
    deactivate_windows()?;

    #[cfg(target_os = "linux")]
    deactivate_linux()?;

    #[cfg(target_os = "macos")]
    deactivate_macos()?;

    info!("kill switch deactivated — normal traffic restored");
    Ok(())
}

/// Check if the kill switch rules are currently active.
pub fn is_active() -> bool {
    #[cfg(target_os = "windows")]
    return is_active_windows();

    #[cfg(target_os = "linux")]
    return is_active_linux();

    #[cfg(target_os = "macos")]
    return is_active_macos();

    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    return false;
}

// ── Windows (netsh advfirewall) ───────────────────────────────────────

#[cfg(target_os = "windows")]
fn activate_windows(entry_ip: &str) -> Result<(), String> {
    // Remove any stale rules first.
    let _ = deactivate_windows();

    // Allow rules must be added BEFORE the block-all rule.
    // Windows Firewall evaluates rules by specificity, but explicit
    // allow rules only override block rules when they exist first.

    // Allow traffic to VPN entry node.
    run_cmd("netsh", &[
        "advfirewall", "firewall", "add", "rule",
        &format!("name={RULE_NAME}-AllowVPN"),
        "dir=out", "action=allow", "enable=yes",
        "profile=any", &format!("remoteip={entry_ip}"),
    ])?;

    // Allow localhost (for local RPC, metrics, etc).
    run_cmd("netsh", &[
        "advfirewall", "firewall", "add", "rule",
        &format!("name={RULE_NAME}-AllowLocal"),
        "dir=out", "action=allow", "enable=yes",
        "profile=any", "remoteip=127.0.0.0/8",
    ])?;

    // Allow DNS (needed for RPC endpoint resolution until DNS-over-tunnel).
    run_cmd("netsh", &[
        "advfirewall", "firewall", "add", "rule",
        &format!("name={RULE_NAME}-AllowDNS"),
        "dir=out", "action=allow", "enable=yes",
        "profile=any", "protocol=udp", "remoteport=53",
    ])?;

    // Block all other outbound traffic.
    run_cmd("netsh", &[
        "advfirewall", "firewall", "add", "rule",
        &format!("name={RULE_NAME}-BlockAll"),
        "dir=out", "action=block", "enable=yes",
        "profile=any", "localip=any", "remoteip=any",
    ])?;

    Ok(())
}

#[cfg(target_os = "windows")]
fn deactivate_windows() -> Result<(), String> {
    for suffix in ["BlockAll", "AllowVPN", "AllowLocal", "AllowDNS"] {
        let name = format!("{RULE_NAME}-{suffix}");
        // Ignore errors — rule may not exist.
        let _ = run_cmd("netsh", &[
            "advfirewall", "firewall", "delete", "rule",
            &format!("name={name}"),
        ]);
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn is_active_windows() -> bool {
    let output = Command::new("netsh")
        .args(["advfirewall", "firewall", "show", "rule", &format!("name={RULE_NAME}-BlockAll")])
        .output();
    match output {
        Ok(o) => o.status.success(),
        Err(_) => false,
    }
}

// ── Linux (iptables) ──────────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn activate_linux(entry_ip: &str) -> Result<(), String> {
    let _ = deactivate_linux();

    // Allow established connections.
    run_cmd("iptables", &[
        "-A", "OUTPUT", "-m", "state", "--state", "ESTABLISHED,RELATED",
        "-j", "ACCEPT", "-m", "comment", "--comment", RULE_NAME,
    ])?;
    // Allow loopback.
    run_cmd("iptables", &[
        "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT",
        "-m", "comment", "--comment", RULE_NAME,
    ])?;
    // Allow VPN entry.
    run_cmd("iptables", &[
        "-A", "OUTPUT", "-d", entry_ip, "-j", "ACCEPT",
        "-m", "comment", "--comment", RULE_NAME,
    ])?;
    // Allow DNS.
    run_cmd("iptables", &[
        "-A", "OUTPUT", "-p", "udp", "--dport", "53", "-j", "ACCEPT",
        "-m", "comment", "--comment", RULE_NAME,
    ])?;
    // Block everything else.
    run_cmd("iptables", &[
        "-A", "OUTPUT", "-j", "DROP",
        "-m", "comment", "--comment", RULE_NAME,
    ])?;

    Ok(())
}

#[cfg(target_os = "linux")]
fn deactivate_linux() -> Result<(), String> {
    // Remove all rules with our comment tag. Loop until no more matches.
    loop {
        let output = Command::new("iptables")
            .args(["-L", "OUTPUT", "--line-numbers", "-n"])
            .output()
            .map_err(|e| format!("iptables list failed: {e}"))?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        // Find the first line containing our rule name and extract its number.
        let line_num = stdout.lines().find_map(|line| {
            if line.contains(RULE_NAME) {
                line.split_whitespace().next()?.parse::<u32>().ok()
            } else {
                None
            }
        });
        match line_num {
            Some(n) => {
                let _ = run_cmd("iptables", &["-D", "OUTPUT", &n.to_string()]);
            }
            None => break,
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn is_active_linux() -> bool {
    let output = Command::new("iptables")
        .args(["-L", "OUTPUT", "-n"])
        .output();
    match output {
        Ok(o) => String::from_utf8_lossy(&o.stdout).contains(RULE_NAME),
        Err(_) => false,
    }
}

// ── macOS (pf) ────────────────────────────────────────────────────────

#[cfg(target_os = "macos")]
fn activate_macos(entry_ip: &str) -> Result<(), String> {
    let _ = deactivate_macos();

    let anchor_rules = format!(
        "# {RULE_NAME}\n\
         pass out quick to {entry_ip}\n\
         pass out quick to 127.0.0.0/8\n\
         pass out quick proto udp to any port 53\n\
         block out all\n"
    );

    let anchor_path = "/etc/pf.anchors/shieldnode";
    std::fs::write(anchor_path, &anchor_rules)
        .map_err(|e| format!("failed to write pf anchor: {e}"))?;

    run_cmd("pfctl", &["-a", "shieldnode", "-f", anchor_path])?;
    run_cmd("pfctl", &["-e"])?;

    Ok(())
}

#[cfg(target_os = "macos")]
fn deactivate_macos() -> Result<(), String> {
    let _ = run_cmd("pfctl", &["-a", "shieldnode", "-F", "all"]);
    let _ = std::fs::remove_file("/etc/pf.anchors/shieldnode");
    Ok(())
}

#[cfg(target_os = "macos")]
fn is_active_macos() -> bool {
    let output = Command::new("pfctl")
        .args(["-a", "shieldnode", "-sr"])
        .output();
    match output {
        Ok(o) => !String::from_utf8_lossy(&o.stdout).trim().is_empty(),
        Err(_) => false,
    }
}

// ── helpers ───────────────────────────────────────────────────────────

fn run_cmd(cmd: &str, args: &[&str]) -> Result<(), String> {
    let output = Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| format!("failed to run {cmd}: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        warn!(cmd, ?args, %stderr, "command failed");
        return Err(format!("{cmd} failed: {stderr}"));
    }
    Ok(())
}
