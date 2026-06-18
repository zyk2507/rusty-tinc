// SPDX-License-Identifier: GPL-2.0-or-later

use std::process::{Command, Output};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

const STRICT_NETNS_ENV: &str = "TINC_NETNS_STRICT";

/// In default developer runs, Rust tests keep their own skip paths. With
/// TINC_NETNS_STRICT=1, missing namespace support is a hard failure.
pub fn assert_can_create_netns() {
    if !strict_netns_gate_enabled() {
        return;
    }

    static CHECK: OnceLock<Result<(), String>> = OnceLock::new();

    if let Err(error) = CHECK.get_or_init(check_can_create_netns) {
        panic!("{error}");
    }
}

pub fn strict_netns_gate_enabled() -> bool {
    std::env::var(STRICT_NETNS_ENV)
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "yes" | "true" | "on"
            )
        })
        .unwrap_or(false)
}

fn check_can_create_netns() -> Result<(), String> {
    if !cfg!(target_os = "linux") {
        return Err(
            "tests require Linux network namespace support; cannot create netns on this platform"
                .to_string(),
        );
    }

    let namespace = format!("tinc-test-gate-{}-{}", std::process::id(), unique_suffix());

    let add = Command::new("ip")
        .args(["netns", "add", &namespace])
        .output()
        .map_err(|error| {
            format!(
                "tests require permission to create network namespaces; failed to execute `ip netns add`: {error}"
            )
        })?;

    if !add.status.success() {
        return Err(format!(
            "tests require permission to create network namespaces; `ip netns add {namespace}` failed{}",
            command_output(&add),
        ));
    }

    let delete = Command::new("ip")
        .args(["netns", "delete", &namespace])
        .output()
        .map_err(|error| {
            format!(
                "tests require permission to create network namespaces; created `{namespace}` but failed to execute `ip netns delete`: {error}"
            )
        })?;

    if !delete.status.success() {
        return Err(format!(
            "tests require permission to create network namespaces; created `{namespace}` but `ip netns delete` failed{}",
            command_output(&delete),
        ));
    }

    Ok(())
}

fn unique_suffix() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0)
}

fn command_output(output: &Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();

    match (stdout.is_empty(), stderr.is_empty()) {
        (true, true) => String::new(),
        (false, true) => format!(": {stdout}"),
        (true, false) => format!(": {stderr}"),
        (false, false) => format!(": {stdout}; {stderr}"),
    }
}
