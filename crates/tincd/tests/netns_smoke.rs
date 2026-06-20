// SPDX-License-Identifier: GPL-2.0-or-later

use std::error::Error;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock, mpsc};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rand_core::OsRng;
use rsa::pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey, LineEnding};
use rsa::{RsaPrivateKey, RsaPublicKey};
use tinc_core::graph::{Edge, OPTION_PMTU_DISCOVERY};
use tinc_core::protocol::{AddEdgeMessage, AnswerKeyMessage, EdgeAddress, MetaMessage, PROT_MINOR};
use tinc_runtime::device::VpnPacket;
use tinc_runtime::legacy_meta::{
    LEGACY_META_PROTOCOL_MINOR, LegacyMetaAuth, LegacyMetaAuthState, LegacyMetaConnectionDriver,
    LegacyMetaPrivateKey,
};
use tinc_runtime::sptps::{ED25519_SEED_LEN, TincEd25519PrivateKey};
use tinc_runtime::transport::{
    CompressionLevel, LegacyCipherAlgorithm, LegacyDigest, LegacyPeerState, LegacyUdpCodec,
    PacketCodec, legacy_compression_is_available,
};
use tincctl::{CliAction as TincCtlAction, run as run_tincctl};

const TINCD: &str = env!("CARGO_BIN_EXE_tincd");
const STRICT_NETNS_ENV: &str = "TINC_NETNS_STRICT";

fn netns_test_guard() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    let guard = LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    assert_privileged_netns_gate_ready();
    guard
}

fn assert_privileged_netns_gate_ready() {
    if !tinc_test_support::strict_netns_gate_enabled() {
        return;
    }

    static READY: OnceLock<()> = OnceLock::new();
    READY.get_or_init(assert_privileged_netns_gate_ready_once);
}

fn assert_privileged_netns_gate_ready_once() {
    assert!(
        cfg!(target_os = "linux"),
        "{STRICT_NETNS_ENV}=1 requires Linux network namespace support"
    );

    for command in ["ip", "ping", "arping", "iperf3", "tcpdump"] {
        assert!(
            command_available(command),
            "{STRICT_NETNS_ENV}=1 requires `{command}` for the full privileged netns gate"
        );
    }

    assert!(
        Path::new("/dev/net/tun").exists(),
        "{STRICT_NETNS_ENV}=1 requires /dev/net/tun for tun/tap daemon tests"
    );

    assert!(
        c_tincd_binary().is_some(),
        "{STRICT_NETNS_ENV}=1 requires C_TINCD_PATH or vendor/tinc/build-c/src/tincd for C/Rust daemon interop"
    );
    assert!(
        c_tinc_binary().is_some(),
        "{STRICT_NETNS_ENV}=1 requires C_TINC_PATH or vendor/tinc/build-c/src/tinc for C/Rust control interop"
    );

    let suffix = unique_suffix();
    let probe_ns = format!("tinc-strict-probe-{suffix}");
    let created = try_ip(&["netns", "add", &probe_ns]);
    if created {
        let _ = Command::new("ip")
            .args(["netns", "delete", &probe_ns])
            .status();
    }
    assert!(
        created,
        "{STRICT_NETNS_ENV}=1 requires permission to create and delete network namespaces"
    );
}

#[test]
fn linux_netns_two_tincd_nodes_can_ping_over_tun() -> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!("skipping netns smoke test: Linux-only test");
        return Ok(());
    }
    if !command_available("ip") || !command_available("ping") {
        eprintln!("skipping netns smoke test: missing ip or ping command");
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!("skipping netns smoke test: /dev/net/tun is not available");
        return Ok(());
    }

    let workspace = TempWorkspace::new("tinc-rust-netns")?;
    let suffix = unique_suffix();
    let ns_alpha = format!("tinc-rust-a-{suffix}");
    let ns_beta = format!("tinc-rust-b-{suffix}");
    let veth_alpha = format!("ta{suffix}");
    let veth_beta = format!("tb{suffix}");
    let mut cleanup = NetnsCleanup::new(workspace.path().to_path_buf());
    cleanup.add_namespace(ns_alpha.clone());
    cleanup.add_namespace(ns_beta.clone());

    create_node_config(
        &workspace.path().join("alpha"),
        NodeConfig {
            name: "alpha",
            peer: "beta",
            port: 16655,
            bind_address: "192.0.2.1",
            peer_address: "192.0.2.2",
            peer_port: 16656,
            interface: "tun-alpha",
            tunnel_address: "10.100.1.1/24",
            subnet: "10.100.1.0/24",
            peer_subnet: "10.100.2.0/24",
            connect_to_peer: true,
            seed: 1,
            peer_seed: 2,
        },
    )?;
    create_node_config(
        &workspace.path().join("beta"),
        NodeConfig {
            name: "beta",
            peer: "alpha",
            port: 16656,
            bind_address: "192.0.2.2",
            peer_address: "192.0.2.1",
            peer_port: 16655,
            interface: "tun-beta",
            tunnel_address: "10.100.2.1/24",
            subnet: "10.100.2.0/24",
            peer_subnet: "10.100.1.0/24",
            connect_to_peer: true,
            seed: 2,
            peer_seed: 1,
        },
    )?;

    if !try_ip(&["netns", "add", &ns_alpha]) || !try_ip(&["netns", "add", &ns_beta]) {
        eprintln!("skipping netns smoke test: cannot create network namespaces");
        return Ok(());
    }

    run_ip(&[
        "link",
        "add",
        &veth_alpha,
        "type",
        "veth",
        "peer",
        "name",
        &veth_beta,
    ])?;
    run_ip(&["link", "set", &veth_alpha, "netns", &ns_alpha])?;
    run_ip(&["link", "set", &veth_beta, "netns", &ns_beta])?;
    run_ip(&["-n", &ns_alpha, "link", "set", "lo", "up"])?;
    run_ip(&["-n", &ns_beta, "link", "set", "lo", "up"])?;
    run_ip(&[
        "-n",
        &ns_alpha,
        "addr",
        "add",
        "192.0.2.1/24",
        "dev",
        &veth_alpha,
    ])?;
    run_ip(&[
        "-n",
        &ns_beta,
        "addr",
        "add",
        "192.0.2.2/24",
        "dev",
        &veth_beta,
    ])?;
    run_ip(&["-n", &ns_alpha, "link", "set", &veth_alpha, "up"])?;
    run_ip(&["-n", &ns_beta, "link", "set", &veth_beta, "up"])?;

    cleanup.spawn(
        "alpha",
        &workspace.path().join("alpha"),
        &ns_alpha,
        &workspace.path().join("alpha.log"),
    )?;
    cleanup.spawn(
        "beta",
        &workspace.path().join("beta"),
        &ns_beta,
        &workspace.path().join("beta.log"),
    )?;

    wait_for_link(&ns_alpha, "tun-alpha", &cleanup)?;
    wait_for_link(&ns_beta, "tun-beta", &cleanup)?;
    wait_for_ping(&ns_alpha, "10.100.2.1", &cleanup)?;
    wait_for_ping(&ns_beta, "10.100.1.1", &cleanup)?;
    wait_for_single_peer_meta_connection(
        &workspace.path().join("alpha"),
        "beta",
        &cleanup,
        "alpha view after simultaneous ConnectTo duplicate resolution",
    )?;
    wait_for_single_peer_meta_connection(
        &workspace.path().join("beta"),
        "alpha",
        &cleanup,
        "beta view after simultaneous ConnectTo duplicate resolution",
    )?;

    Ok(())
}

// P0-SMOKE: p0-smoke label member.
#[test]
fn linux_netns_c_and_rust_tincd_nodes_can_ping_over_tun() -> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!("skipping C/Rust netns interop test: Linux-only test");
        return Ok(());
    }
    if !command_available("ip") || !command_available("ping") {
        eprintln!("skipping C/Rust netns interop test: missing ip or ping command");
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!("skipping C/Rust netns interop test: /dev/net/tun is not available");
        return Ok(());
    }

    let Some(c_tincd) = c_tincd_binary() else {
        eprintln!(
            "skipping C/Rust netns interop test: set C_TINCD_PATH or build vendor/tinc/build-c/src/tincd"
        );
        return Ok(());
    };

    run_c_rust_two_node_tun_interop(&c_tincd, true)?;
    run_c_rust_two_node_tun_interop(&c_tincd, false)?;

    Ok(())
}

#[test]
fn linux_netns_c_and_rust_modern_tincd_does_not_leak_plain_udp_payload_like_tinc()
-> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!("skipping C/Rust modern no-plaintext netns interop test: Linux-only test");
        return Ok(());
    }
    if !command_available("ip") || !command_available("ping") || !command_available("tcpdump") {
        eprintln!(
            "skipping C/Rust modern no-plaintext netns interop test: missing ip, ping, or tcpdump command"
        );
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!(
            "skipping C/Rust modern no-plaintext netns interop test: /dev/net/tun is not available"
        );
        return Ok(());
    }

    let Some(c_tincd) = c_tincd_binary() else {
        eprintln!(
            "skipping C/Rust modern no-plaintext netns interop test: set C_TINCD_PATH or build vendor/tinc/build-c/src/tincd"
        );
        return Ok(());
    };

    run_c_rust_two_node_tun_no_plain_udp_payload(&c_tincd, true)?;
    run_c_rust_two_node_tun_no_plain_udp_payload(&c_tincd, false)?;

    Ok(())
}

#[test]
fn linux_netns_c_and_rust_modern_restart_does_not_fall_back_to_plain_underlay_like_tinc()
-> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!(
            "skipping C/Rust modern restart no-plaintext netns interop test: Linux-only test"
        );
        return Ok(());
    }
    if !command_available("ip")
        || !command_available("ping")
        || !command_available("tcpdump")
        || !command_available("iptables")
    {
        eprintln!(
            "skipping C/Rust modern restart no-plaintext netns interop test: missing ip, ping, tcpdump, or iptables command"
        );
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!(
            "skipping C/Rust modern restart no-plaintext netns interop test: /dev/net/tun is not available"
        );
        return Ok(());
    }

    let Some(c_tincd) = c_tincd_binary() else {
        eprintln!(
            "skipping C/Rust modern restart no-plaintext netns interop test: set C_TINCD_PATH or build vendor/tinc/build-c/src/tincd"
        );
        return Ok(());
    };

    run_c_rust_two_node_tun_restart_no_plain_underlay_payload(&c_tincd, true)?;
    run_c_rust_two_node_tun_restart_no_plain_underlay_payload(&c_tincd, false)?;

    Ok(())
}

#[test]
fn linux_netns_c_and_rust_modern_tcponly_does_not_leak_plain_tcp_payload_like_tinc()
-> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!(
            "skipping C/Rust modern TCPOnly no-plaintext netns interop test: Linux-only test"
        );
        return Ok(());
    }
    if !command_available("ip") || !command_available("ping") || !command_available("tcpdump") {
        eprintln!(
            "skipping C/Rust modern TCPOnly no-plaintext netns interop test: missing ip, ping, or tcpdump command"
        );
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!(
            "skipping C/Rust modern TCPOnly no-plaintext netns interop test: /dev/net/tun is not available"
        );
        return Ok(());
    }

    let Some(c_tincd) = c_tincd_binary() else {
        eprintln!(
            "skipping C/Rust modern TCPOnly no-plaintext netns interop test: set C_TINCD_PATH or build vendor/tinc/build-c/src/tincd"
        );
        return Ok(());
    };

    run_c_rust_two_node_tun_no_plain_tcp_payload(&c_tincd, true)?;
    run_c_rust_two_node_tun_no_plain_tcp_payload(&c_tincd, false)?;

    Ok(())
}

#[test]
fn linux_netns_c_and_rust_modern_static_relay_does_not_leak_plain_udp_payload_like_tinc()
-> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!(
            "skipping C/Rust modern static relay no-plaintext netns interop test: Linux-only test"
        );
        return Ok(());
    }
    if !command_available("ip") || !command_available("ping") || !command_available("tcpdump") {
        eprintln!(
            "skipping C/Rust modern static relay no-plaintext netns interop test: missing ip, ping, or tcpdump command"
        );
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!(
            "skipping C/Rust modern static relay no-plaintext netns interop test: /dev/net/tun is not available"
        );
        return Ok(());
    }

    let Some(c_tincd) = c_tincd_binary() else {
        eprintln!(
            "skipping C/Rust modern static relay no-plaintext netns interop test: set C_TINCD_PATH or build vendor/tinc/build-c/src/tincd"
        );
        return Ok(());
    };

    run_c_rust_three_node_modern_indirect_multihop_interop_with_options(
        &c_tincd,
        true,
        false,
        Some(NoPlaintextCapture::Udp),
        false,
    )?;
    run_c_rust_three_node_modern_indirect_multihop_interop_with_options(
        &c_tincd,
        false,
        false,
        Some(NoPlaintextCapture::Udp),
        false,
    )?;

    Ok(())
}

#[test]
fn linux_netns_c_and_rust_modern_static_relay_peer_restart_has_no_stale_topology_like_tinc()
-> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!(
            "skipping C/Rust modern static relay restart topology netns interop test: Linux-only test"
        );
        return Ok(());
    }
    if !command_available("ip") || !command_available("ping") {
        eprintln!(
            "skipping C/Rust modern static relay restart topology netns interop test: missing ip or ping command"
        );
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!(
            "skipping C/Rust modern static relay restart topology netns interop test: /dev/net/tun is not available"
        );
        return Ok(());
    }

    let Some(c_tincd) = c_tincd_binary() else {
        eprintln!(
            "skipping C/Rust modern static relay restart topology netns interop test: set C_TINCD_PATH or build vendor/tinc/build-c/src/tincd"
        );
        return Ok(());
    };

    run_c_rust_three_node_modern_indirect_multihop_interop_with_options(
        &c_tincd, true, false, None, true,
    )?;
    run_c_rust_three_node_modern_indirect_multihop_interop_with_options(
        &c_tincd, false, false, None, true,
    )?;

    Ok(())
}

#[test]
fn linux_netns_c_and_rust_modern_dynamic_relay_does_not_leak_plain_udp_payload_like_tinc()
-> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!(
            "skipping C/Rust modern dynamic relay no-plaintext netns interop test: Linux-only test"
        );
        return Ok(());
    }
    if !command_available("ip") || !command_available("ping") || !command_available("tcpdump") {
        eprintln!(
            "skipping C/Rust modern dynamic relay no-plaintext netns interop test: missing ip, ping, or tcpdump command"
        );
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!(
            "skipping C/Rust modern dynamic relay no-plaintext netns interop test: /dev/net/tun is not available"
        );
        return Ok(());
    }

    let Some(c_tincd) = c_tincd_binary() else {
        eprintln!(
            "skipping C/Rust modern dynamic relay no-plaintext netns interop test: set C_TINCD_PATH or build vendor/tinc/build-c/src/tincd"
        );
        return Ok(());
    };

    run_c_rust_three_node_modern_dynamic_relay_interop_with_options(
        &c_tincd,
        true,
        false,
        Some(NoPlaintextCapture::Udp),
        false,
    )?;
    run_c_rust_three_node_modern_dynamic_relay_interop_with_options(
        &c_tincd,
        false,
        false,
        Some(NoPlaintextCapture::Udp),
        false,
    )?;

    Ok(())
}

#[test]
fn linux_netns_c_and_rust_modern_dynamic_relay_restart_does_not_leak_plain_udp_payload_like_tinc()
-> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!(
            "skipping C/Rust modern dynamic relay restart no-plaintext netns interop test: Linux-only test"
        );
        return Ok(());
    }
    if !command_available("ip") || !command_available("ping") || !command_available("tcpdump") {
        eprintln!(
            "skipping C/Rust modern dynamic relay restart no-plaintext netns interop test: missing ip, ping, or tcpdump command"
        );
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!(
            "skipping C/Rust modern dynamic relay restart no-plaintext netns interop test: /dev/net/tun is not available"
        );
        return Ok(());
    }

    let Some(c_tincd) = c_tincd_binary() else {
        eprintln!(
            "skipping C/Rust modern dynamic relay restart no-plaintext netns interop test: set C_TINCD_PATH or build vendor/tinc/build-c/src/tincd"
        );
        return Ok(());
    };

    run_c_rust_three_node_modern_dynamic_relay_interop_with_options(
        &c_tincd, true, false, None, true,
    )?;
    run_c_rust_three_node_modern_dynamic_relay_interop_with_options(
        &c_tincd, false, false, None, true,
    )?;

    Ok(())
}

#[test]
fn linux_netns_c_and_rust_tunnel_server_does_not_leak_plain_udp_payload_like_tinc()
-> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!("skipping C/Rust tunnel-server no-plaintext netns interop test: Linux-only test");
        return Ok(());
    }
    if !command_available("ip") || !command_available("ping") || !command_available("tcpdump") {
        eprintln!(
            "skipping C/Rust tunnel-server no-plaintext netns interop test: missing ip, ping, or tcpdump command"
        );
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!(
            "skipping C/Rust tunnel-server no-plaintext netns interop test: /dev/net/tun is not available"
        );
        return Ok(());
    }

    let Some(c_tincd) = c_tincd_binary() else {
        eprintln!(
            "skipping C/Rust tunnel-server no-plaintext netns interop test: set C_TINCD_PATH or build vendor/tinc/build-c/src/tincd"
        );
        return Ok(());
    };

    run_c_rust_tunnel_server_interop_with_options(
        &c_tincd,
        true,
        false,
        false,
        false,
        false,
        Some(NoPlaintextCapture::Udp),
    )?;
    run_c_rust_tunnel_server_interop_with_options(
        &c_tincd,
        false,
        false,
        false,
        false,
        false,
        Some(NoPlaintextCapture::Udp),
    )?;

    Ok(())
}

#[test]
fn linux_netns_c_and_rust_modern_tincd_nodes_reconnect_after_peer_restart()
-> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!("skipping C/Rust modern restart netns interop test: Linux-only test");
        return Ok(());
    }
    if !command_available("ip") || !command_available("ping") {
        eprintln!("skipping C/Rust modern restart netns interop test: missing ip or ping command");
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!(
            "skipping C/Rust modern restart netns interop test: /dev/net/tun is not available"
        );
        return Ok(());
    }

    let Some(c_tincd) = c_tincd_binary() else {
        eprintln!(
            "skipping C/Rust modern restart netns interop test: set C_TINCD_PATH or build vendor/tinc/build-c/src/tincd"
        );
        return Ok(());
    };

    run_c_rust_two_node_tun_interop_with_options(&c_tincd, true, true)?;
    run_c_rust_two_node_tun_interop_with_options(&c_tincd, false, true)?;

    Ok(())
}

// P0-SMOKE: p0-smoke label member.
#[test]
fn linux_netns_c_and_rust_legacy_tincd_nodes_can_ping_over_tun() -> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!("skipping C/Rust legacy netns interop test: Linux-only test");
        return Ok(());
    }
    if !command_available("ip") || !command_available("ping") {
        eprintln!("skipping C/Rust legacy netns interop test: missing ip or ping command");
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!("skipping C/Rust legacy netns interop test: /dev/net/tun is not available");
        return Ok(());
    }

    let Some(c_tincd) = c_tincd_binary() else {
        eprintln!(
            "skipping C/Rust legacy netns interop test: set C_TINCD_PATH or build vendor/tinc/build-c/src/tincd"
        );
        return Ok(());
    };

    run_c_rust_two_node_legacy_tun_interop(&c_tincd, true)?;
    run_c_rust_two_node_legacy_tun_interop(&c_tincd, false)?;

    Ok(())
}

#[test]
fn linux_netns_c_and_rust_legacy_tincd_does_not_leak_plain_udp_payload_like_tinc()
-> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!("skipping C/Rust legacy no-plaintext netns interop test: Linux-only test");
        return Ok(());
    }
    if !command_available("ip") || !command_available("ping") || !command_available("tcpdump") {
        eprintln!(
            "skipping C/Rust legacy no-plaintext netns interop test: missing ip, ping, or tcpdump command"
        );
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!(
            "skipping C/Rust legacy no-plaintext netns interop test: /dev/net/tun is not available"
        );
        return Ok(());
    }

    let Some(c_tincd) = c_tincd_binary() else {
        eprintln!(
            "skipping C/Rust legacy no-plaintext netns interop test: set C_TINCD_PATH or build vendor/tinc/build-c/src/tincd"
        );
        return Ok(());
    };

    run_c_rust_two_node_legacy_tun_no_plain_udp_payload(&c_tincd, true)?;
    run_c_rust_two_node_legacy_tun_no_plain_udp_payload(&c_tincd, false)?;

    Ok(())
}

#[test]
fn linux_netns_c_and_rust_legacy_restart_does_not_fall_back_to_plain_underlay_like_tinc()
-> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!(
            "skipping C/Rust legacy restart no-plaintext netns interop test: Linux-only test"
        );
        return Ok(());
    }
    if !command_available("ip") || !command_available("ping") || !command_available("tcpdump") {
        eprintln!(
            "skipping C/Rust legacy restart no-plaintext netns interop test: missing ip, ping, or tcpdump command"
        );
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!(
            "skipping C/Rust legacy restart no-plaintext netns interop test: /dev/net/tun is not available"
        );
        return Ok(());
    }

    let Some(c_tincd) = c_tincd_binary() else {
        eprintln!(
            "skipping C/Rust legacy restart no-plaintext netns interop test: set C_TINCD_PATH or build vendor/tinc/build-c/src/tincd"
        );
        return Ok(());
    };

    run_c_rust_two_node_legacy_tun_restart_no_plain_underlay_payload(&c_tincd, true)?;
    run_c_rust_two_node_legacy_tun_restart_no_plain_underlay_payload(&c_tincd, false)?;

    Ok(())
}

#[test]
fn linux_netns_c_and_rust_legacy_rekey_does_not_fall_back_to_plain_tcp_like_tinc()
-> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!("skipping C/Rust legacy rekey no-plaintext netns interop test: Linux-only test");
        return Ok(());
    }
    if !command_available("ip") || !command_available("ping") || !command_available("tcpdump") {
        eprintln!(
            "skipping C/Rust legacy rekey no-plaintext netns interop test: missing ip, ping, or tcpdump command"
        );
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!(
            "skipping C/Rust legacy rekey no-plaintext netns interop test: /dev/net/tun is not available"
        );
        return Ok(());
    }

    let Some(c_tincd) = c_tincd_binary() else {
        eprintln!(
            "skipping C/Rust legacy rekey no-plaintext netns interop test: set C_TINCD_PATH or build vendor/tinc/build-c/src/tincd"
        );
        return Ok(());
    };

    run_c_rust_two_node_legacy_tun_rekey_no_plain_tcp_payload(&c_tincd, true)?;
    run_c_rust_two_node_legacy_tun_rekey_no_plain_tcp_payload(&c_tincd, false)?;

    Ok(())
}

#[test]
fn linux_netns_c_and_rust_legacy_rekey_restores_udp_discovery_like_tinc()
-> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!(
            "skipping C/Rust legacy rekey UDP rediscovery netns interop test: Linux-only test"
        );
        return Ok(());
    }
    if !command_available("ip") || !command_available("ping") || !command_available("tcpdump") {
        eprintln!(
            "skipping C/Rust legacy rekey UDP rediscovery netns interop test: missing ip, ping, or tcpdump command"
        );
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!(
            "skipping C/Rust legacy rekey UDP rediscovery netns interop test: /dev/net/tun is not available"
        );
        return Ok(());
    }

    let Some(c_tincd) = c_tincd_binary() else {
        eprintln!(
            "skipping C/Rust legacy rekey UDP rediscovery netns interop test: set C_TINCD_PATH or build vendor/tinc/build-c/src/tincd"
        );
        return Ok(());
    };

    run_c_rust_two_node_legacy_tun_rekey_udp_rediscovery(&c_tincd, true)?;
    run_c_rust_two_node_legacy_tun_rekey_udp_rediscovery(&c_tincd, false)?;

    Ok(())
}

#[test]
fn linux_netns_c_and_rust_legacy_rekey_no_plaintext_then_udp_like_tinc()
-> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!(
            "skipping C/Rust legacy rekey no-plaintext then UDP netns interop test: Linux-only test"
        );
        return Ok(());
    }
    if !command_available("ip")
        || !command_available("ping")
        || !command_available("tcpdump")
        || !command_available("iptables")
    {
        eprintln!(
            "skipping C/Rust legacy rekey no-plaintext then UDP netns interop test: missing ip, ping, tcpdump, or iptables command"
        );
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!(
            "skipping C/Rust legacy rekey no-plaintext then UDP netns interop test: /dev/net/tun is not available"
        );
        return Ok(());
    }

    let Some(c_tincd) = c_tincd_binary() else {
        eprintln!(
            "skipping C/Rust legacy rekey no-plaintext then UDP netns interop test: set C_TINCD_PATH or build vendor/tinc/build-c/src/tincd"
        );
        return Ok(());
    };

    run_c_rust_two_node_legacy_tun_rekey_no_plaintext_then_udp(&c_tincd, true)?;
    run_c_rust_two_node_legacy_tun_rekey_no_plaintext_then_udp(&c_tincd, false)?;

    Ok(())
}

#[test]
fn linux_netns_c_and_rust_legacy_no_crypto_direct_path_like_tinc() -> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!("skipping C/Rust legacy no-crypto netns interop test: Linux-only test");
        return Ok(());
    }
    if !command_available("ip") || !command_available("ping") {
        eprintln!(
            "skipping C/Rust legacy no-crypto netns interop test: missing ip or ping command"
        );
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!(
            "skipping C/Rust legacy no-crypto netns interop test: /dev/net/tun is not available"
        );
        return Ok(());
    }

    let Some(c_tincd) = c_tincd_binary() else {
        eprintln!(
            "skipping C/Rust legacy no-crypto netns interop test: set C_TINCD_PATH or build vendor/tinc/build-c/src/tincd"
        );
        return Ok(());
    };

    run_c_rust_two_node_legacy_tun_with_crypto_config(
        &c_tincd,
        true,
        LegacyCryptoConfig::no_crypto(),
    )?;
    run_c_rust_two_node_legacy_tun_with_crypto_config(
        &c_tincd,
        false,
        LegacyCryptoConfig::no_crypto(),
    )?;

    Ok(())
}

#[test]
fn linux_netns_c_and_rust_legacy_zlib_compression_direct_path_like_tinc()
-> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!("skipping C/Rust legacy zlib netns interop test: Linux-only test");
        return Ok(());
    }
    if !command_available("ip") || !command_available("ping") || !command_available("tcpdump") {
        eprintln!(
            "skipping C/Rust legacy zlib netns interop test: missing ip, ping, or tcpdump command"
        );
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!("skipping C/Rust legacy zlib netns interop test: /dev/net/tun is not available");
        return Ok(());
    }

    let Some(c_tincd) = c_tincd_binary() else {
        eprintln!(
            "skipping C/Rust legacy zlib netns interop test: set C_TINCD_PATH or build vendor/tinc/build-c/src/tincd"
        );
        return Ok(());
    };

    let Some(c_compression_tincd) = c_tincd_with_feature(&c_tincd, "comp_zlib", "zlib")? else {
        assert_compression_unavailable_startup_like_tinc(
            &c_tincd,
            LegacyCryptoConfig::zlib1(),
            "zlib",
            "C tincd",
            "ZLIB",
        )?;
        return Ok(());
    };

    for legacy_crypto in [LegacyCryptoConfig::zlib1(), LegacyCryptoConfig::zlib9()] {
        run_c_rust_two_node_legacy_tun_with_crypto_config(
            &c_compression_tincd,
            true,
            legacy_crypto,
        )?;
        run_c_rust_two_node_legacy_tun_with_crypto_config(
            &c_compression_tincd,
            false,
            legacy_crypto,
        )?;
    }

    Ok(())
}

#[test]
fn linux_netns_c_and_rust_legacy_lz4_compression_direct_path_like_tinc()
-> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!("skipping C/Rust legacy lz4 netns interop test: Linux-only test");
        return Ok(());
    }
    if !command_available("ip") || !command_available("ping") || !command_available("tcpdump") {
        eprintln!(
            "skipping C/Rust legacy lz4 netns interop test: missing ip, ping, or tcpdump command"
        );
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!("skipping C/Rust legacy lz4 netns interop test: /dev/net/tun is not available");
        return Ok(());
    }

    let Some(c_tincd) = c_tincd_binary() else {
        eprintln!(
            "skipping C/Rust legacy lz4 netns interop test: set C_TINCD_PATH or build vendor/tinc/build-c/src/tincd"
        );
        return Ok(());
    };

    let Some(c_compression_tincd) = c_tincd_with_feature(&c_tincd, "comp_lz4", "lz4")? else {
        assert_compression_unavailable_startup_like_tinc(
            &c_tincd,
            LegacyCryptoConfig::lz4(),
            "lz4",
            "C tincd",
            "LZ4",
        )?;
        return Ok(());
    };

    for rust_connects_to_c in [true, false] {
        run_c_rust_two_node_legacy_tun_with_crypto_config(
            &c_compression_tincd,
            rust_connects_to_c,
            LegacyCryptoConfig::lz4(),
        )?;
    }

    Ok(())
}

#[test]
fn linux_netns_rust_tincd_rejects_legacy_lzo_compression_startup_like_tinc()
-> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!("skipping Rust legacy LZO startup netns test: Linux-only test");
        return Ok(());
    }
    if !command_available("ip") {
        eprintln!("skipping Rust legacy LZO startup netns test: missing ip command");
        return Ok(());
    }
    if legacy_compression_is_available(CompressionLevel::LzoLow) {
        eprintln!(
            "skipping Rust legacy LZO startup netns test: Rust tincd was built with LZO support"
        );
        return Ok(());
    }

    assert_compression_unavailable_startup_like_tinc(
        Path::new(TINCD),
        LegacyCryptoConfig::lzo_low(),
        "lzo-rust",
        "Rust tincd",
        "LZO",
    )
}

#[test]
fn linux_netns_c_tincd_rejects_legacy_lzo_compression_without_lzo_like_tinc()
-> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!("skipping C legacy LZO startup netns test: Linux-only test");
        return Ok(());
    }
    if !command_available("ip") {
        eprintln!("skipping C legacy LZO startup netns test: missing ip command");
        return Ok(());
    }

    let Some(c_tincd) = c_tincd_without_feature("comp_lzo")? else {
        eprintln!("skipping C legacy LZO startup netns test: no C tincd binary without comp_lzo");
        return Ok(());
    };

    assert_compression_unavailable_startup_like_tinc(
        &c_tincd,
        LegacyCryptoConfig::lzo_low(),
        "lzo-c",
        "C tincd",
        "LZO",
    )
}

#[test]
fn linux_netns_c_and_rust_legacy_tcponly_does_not_leak_plain_tcp_payload_like_tinc()
-> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!(
            "skipping C/Rust legacy TCPOnly no-plaintext netns interop test: Linux-only test"
        );
        return Ok(());
    }
    if !command_available("ip") || !command_available("ping") || !command_available("tcpdump") {
        eprintln!(
            "skipping C/Rust legacy TCPOnly no-plaintext netns interop test: missing ip, ping, or tcpdump command"
        );
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!(
            "skipping C/Rust legacy TCPOnly no-plaintext netns interop test: /dev/net/tun is not available"
        );
        return Ok(());
    }

    let Some(c_tincd) = c_tincd_binary() else {
        eprintln!(
            "skipping C/Rust legacy TCPOnly no-plaintext netns interop test: set C_TINCD_PATH or build vendor/tinc/build-c/src/tincd"
        );
        return Ok(());
    };

    run_c_rust_two_node_legacy_tun_no_plain_tcp_payload(&c_tincd, true)?;
    run_c_rust_two_node_legacy_tun_no_plain_tcp_payload(&c_tincd, false)?;

    Ok(())
}

#[test]
fn linux_netns_c_and_rust_legacy_static_relay_does_not_leak_plain_udp_payload_like_tinc()
-> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!(
            "skipping C/Rust legacy static relay no-plaintext netns interop test: Linux-only test"
        );
        return Ok(());
    }
    if !command_available("ip") || !command_available("ping") || !command_available("tcpdump") {
        eprintln!(
            "skipping C/Rust legacy static relay no-plaintext netns interop test: missing ip, ping, or tcpdump command"
        );
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!(
            "skipping C/Rust legacy static relay no-plaintext netns interop test: /dev/net/tun is not available"
        );
        return Ok(());
    }

    let Some(c_tincd) = c_tincd_binary() else {
        eprintln!(
            "skipping C/Rust legacy static relay no-plaintext netns interop test: set C_TINCD_PATH or build vendor/tinc/build-c/src/tincd"
        );
        return Ok(());
    };

    run_c_rust_three_node_legacy_indirect_multihop_interop_with_options(
        &c_tincd,
        true,
        false,
        Some(NoPlaintextCapture::TcpAndUdp),
        false,
    )?;
    run_c_rust_three_node_legacy_indirect_multihop_interop_with_options(
        &c_tincd,
        false,
        false,
        Some(NoPlaintextCapture::TcpAndUdp),
        false,
    )?;

    Ok(())
}

#[test]
fn linux_netns_c_and_rust_legacy_static_relay_peer_restart_has_no_stale_topology_like_tinc()
-> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!(
            "skipping C/Rust legacy static relay restart topology netns interop test: Linux-only test"
        );
        return Ok(());
    }
    if !command_available("ip") || !command_available("ping") {
        eprintln!(
            "skipping C/Rust legacy static relay restart topology netns interop test: missing ip or ping command"
        );
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!(
            "skipping C/Rust legacy static relay restart topology netns interop test: /dev/net/tun is not available"
        );
        return Ok(());
    }

    let Some(c_tincd) = c_tincd_binary() else {
        eprintln!(
            "skipping C/Rust legacy static relay restart topology netns interop test: set C_TINCD_PATH or build vendor/tinc/build-c/src/tincd"
        );
        return Ok(());
    };

    run_c_rust_three_node_legacy_indirect_multihop_interop_with_options(
        &c_tincd, true, false, None, true,
    )?;
    run_c_rust_three_node_legacy_indirect_multihop_interop_with_options(
        &c_tincd, false, false, None, true,
    )?;

    Ok(())
}

#[test]
fn linux_netns_c_and_rust_legacy_dynamic_relay_does_not_leak_plain_udp_payload_like_tinc()
-> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!(
            "skipping C/Rust legacy dynamic relay no-plaintext netns interop test: Linux-only test"
        );
        return Ok(());
    }
    if !command_available("ip") || !command_available("ping") || !command_available("tcpdump") {
        eprintln!(
            "skipping C/Rust legacy dynamic relay no-plaintext netns interop test: missing ip, ping, or tcpdump command"
        );
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!(
            "skipping C/Rust legacy dynamic relay no-plaintext netns interop test: /dev/net/tun is not available"
        );
        return Ok(());
    }

    let Some(c_tincd) = c_tincd_binary() else {
        eprintln!(
            "skipping C/Rust legacy dynamic relay no-plaintext netns interop test: set C_TINCD_PATH or build vendor/tinc/build-c/src/tincd"
        );
        return Ok(());
    };

    run_c_rust_three_node_legacy_dynamic_relay_interop_with_options(
        &c_tincd,
        true,
        false,
        Some(NoPlaintextCapture::TcpAndUdp),
        false,
    )?;
    run_c_rust_three_node_legacy_dynamic_relay_interop_with_options(
        &c_tincd,
        false,
        false,
        Some(NoPlaintextCapture::TcpAndUdp),
        false,
    )?;

    Ok(())
}

#[test]
fn linux_netns_c_and_rust_legacy_dynamic_relay_rekey_restores_owner_keys_like_tinc()
-> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!("skipping C/Rust legacy dynamic relay rekey netns interop test: Linux-only test");
        return Ok(());
    }
    if !command_available("ip") || !command_available("ping") {
        eprintln!(
            "skipping C/Rust legacy dynamic relay rekey netns interop test: missing ip or ping command"
        );
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!(
            "skipping C/Rust legacy dynamic relay rekey netns interop test: /dev/net/tun is not available"
        );
        return Ok(());
    }

    let Some(c_tincd) = c_tincd_binary() else {
        eprintln!(
            "skipping C/Rust legacy dynamic relay rekey netns interop test: set C_TINCD_PATH or build vendor/tinc/build-c/src/tincd"
        );
        return Ok(());
    };

    run_c_rust_three_node_legacy_dynamic_relay_interop_with_options(
        &c_tincd, true, false, None, true,
    )?;
    run_c_rust_three_node_legacy_dynamic_relay_interop_with_options(
        &c_tincd, false, false, None, true,
    )?;

    Ok(())
}

#[test]
fn linux_netns_c_and_rust_legacy_dynamic_relay_rekey_does_not_leak_plain_udp_payload_like_tinc()
-> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!(
            "skipping C/Rust legacy dynamic relay rekey no-plaintext netns interop test: Linux-only test"
        );
        return Ok(());
    }
    if !command_available("ip") || !command_available("ping") || !command_available("tcpdump") {
        eprintln!(
            "skipping C/Rust legacy dynamic relay rekey no-plaintext netns interop test: missing ip, ping, or tcpdump command"
        );
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!(
            "skipping C/Rust legacy dynamic relay rekey no-plaintext netns interop test: /dev/net/tun is not available"
        );
        return Ok(());
    }

    let Some(c_tincd) = c_tincd_binary() else {
        eprintln!(
            "skipping C/Rust legacy dynamic relay rekey no-plaintext netns interop test: set C_TINCD_PATH or build vendor/tinc/build-c/src/tincd"
        );
        return Ok(());
    };

    run_c_rust_three_node_legacy_dynamic_relay_interop_with_options(
        &c_tincd,
        true,
        false,
        Some(NoPlaintextCapture::TcpAndUdp),
        true,
    )?;
    run_c_rust_three_node_legacy_dynamic_relay_interop_with_options(
        &c_tincd,
        false,
        false,
        Some(NoPlaintextCapture::TcpAndUdp),
        true,
    )?;

    Ok(())
}

#[test]
fn linux_netns_c_and_rust_legacy_tunnel_server_does_not_leak_plain_udp_payload_like_tinc()
-> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!(
            "skipping C/Rust legacy tunnel-server no-plaintext netns interop test: Linux-only test"
        );
        return Ok(());
    }
    if !command_available("ip") || !command_available("ping") || !command_available("tcpdump") {
        eprintln!(
            "skipping C/Rust legacy tunnel-server no-plaintext netns interop test: missing ip, ping, or tcpdump command"
        );
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!(
            "skipping C/Rust legacy tunnel-server no-plaintext netns interop test: /dev/net/tun is not available"
        );
        return Ok(());
    }

    let Some(c_tincd) = c_tincd_binary() else {
        eprintln!(
            "skipping C/Rust legacy tunnel-server no-plaintext netns interop test: set C_TINCD_PATH or build vendor/tinc/build-c/src/tincd"
        );
        return Ok(());
    };

    run_c_rust_legacy_tunnel_server_interop_with_options(
        &c_tincd,
        true,
        false,
        false,
        false,
        false,
        false,
        Some(NoPlaintextCapture::Udp),
    )?;
    run_c_rust_legacy_tunnel_server_interop_with_options(
        &c_tincd,
        false,
        false,
        false,
        false,
        false,
        false,
        Some(NoPlaintextCapture::Udp),
    )?;

    Ok(())
}

#[test]
fn linux_netns_c_and_rust_legacy_tincd_nodes_rekey_and_keep_ping_over_tun()
-> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!("skipping C/Rust legacy rekey netns interop test: Linux-only test");
        return Ok(());
    }
    if !command_available("ip") || !command_available("ping") {
        eprintln!("skipping C/Rust legacy rekey netns interop test: missing ip or ping command");
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!("skipping C/Rust legacy rekey netns interop test: /dev/net/tun is not available");
        return Ok(());
    }

    let Some(c_tincd) = c_tincd_binary() else {
        eprintln!(
            "skipping C/Rust legacy rekey netns interop test: set C_TINCD_PATH or build vendor/tinc/build-c/src/tincd"
        );
        return Ok(());
    };

    run_c_rust_two_node_legacy_tun_interop_with_options(&c_tincd, true, true, false)?;
    run_c_rust_two_node_legacy_tun_interop_with_options(&c_tincd, false, true, false)?;

    Ok(())
}

#[test]
fn linux_netns_c_and_rust_legacy_tincd_nodes_reconnect_after_peer_restart()
-> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!("skipping C/Rust legacy restart netns interop test: Linux-only test");
        return Ok(());
    }
    if !command_available("ip") || !command_available("ping") {
        eprintln!("skipping C/Rust legacy restart netns interop test: missing ip or ping command");
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!(
            "skipping C/Rust legacy restart netns interop test: /dev/net/tun is not available"
        );
        return Ok(());
    }

    let Some(c_tincd) = c_tincd_binary() else {
        eprintln!(
            "skipping C/Rust legacy restart netns interop test: set C_TINCD_PATH or build vendor/tinc/build-c/src/tincd"
        );
        return Ok(());
    };

    run_c_rust_two_node_legacy_tun_interop_with_options(&c_tincd, true, false, true)?;
    run_c_rust_two_node_legacy_tun_interop_with_options(&c_tincd, false, false, true)?;

    Ok(())
}

#[test]
fn linux_netns_c_and_rust_legacy_tincd_nodes_recover_after_underlay_udp_loss_like_tinc()
-> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!("skipping C/Rust legacy UDP loss netns interop test: Linux-only test");
        return Ok(());
    }
    if !command_available("ip") || !command_available("ping") {
        eprintln!("skipping C/Rust legacy UDP loss netns interop test: missing ip or ping command");
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!(
            "skipping C/Rust legacy UDP loss netns interop test: /dev/net/tun is not available"
        );
        return Ok(());
    }

    let Some(c_tincd) = c_tincd_binary() else {
        eprintln!(
            "skipping C/Rust legacy UDP loss netns interop test: set C_TINCD_PATH or build vendor/tinc/build-c/src/tincd"
        );
        return Ok(());
    };

    run_c_rust_two_node_legacy_tun_interop_with_underlay_udp_loss(&c_tincd, true)?;
    run_c_rust_two_node_legacy_tun_interop_with_underlay_udp_loss(&c_tincd, false)?;

    Ok(())
}

#[test]
fn linux_netns_c_and_rust_legacy_tincd_nodes_reconnect_after_meta_timeout_loss_like_tinc()
-> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!("skipping C/Rust legacy meta timeout loss netns interop test: Linux-only test");
        return Ok(());
    }
    if !command_available("ip") || !command_available("ping") {
        eprintln!(
            "skipping C/Rust legacy meta timeout loss netns interop test: missing ip or ping command"
        );
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!(
            "skipping C/Rust legacy meta timeout loss netns interop test: /dev/net/tun is not available"
        );
        return Ok(());
    }

    let Some(c_tincd) = c_tincd_binary() else {
        eprintln!(
            "skipping C/Rust legacy meta timeout loss netns interop test: set C_TINCD_PATH or build vendor/tinc/build-c/src/tincd"
        );
        return Ok(());
    };

    run_c_rust_two_node_legacy_tun_interop_with_meta_timeout_loss(&c_tincd, true)?;
    run_c_rust_two_node_legacy_tun_interop_with_meta_timeout_loss(&c_tincd, false)?;

    Ok(())
}

#[test]
fn linux_netns_rust_tincd_recovers_from_bad_legacy_ans_key_like_tinc() -> Result<(), Box<dyn Error>>
{
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!("skipping Rust legacy bad ANS_KEY netns test: Linux-only test");
        return Ok(());
    }
    if !command_available("ip") {
        eprintln!("skipping Rust legacy bad ANS_KEY netns test: missing ip command");
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!("skipping Rust legacy bad ANS_KEY netns test: /dev/net/tun is not available");
        return Ok(());
    }

    run_legacy_bad_ans_key_daemon_injection(
        Path::new(TINCD),
        "Rust",
        "tinc-rust-legacy-bad-ans-key",
        !legacy_compression_is_available(CompressionLevel::LzoLow),
    )
}

#[test]
fn linux_netns_c_tincd_handles_bad_legacy_ans_key_like_tinc() -> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!("skipping C legacy bad ANS_KEY netns test: Linux-only test");
        return Ok(());
    }
    if !command_available("ip") {
        eprintln!("skipping C legacy bad ANS_KEY netns test: missing ip command");
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!("skipping C legacy bad ANS_KEY netns test: /dev/net/tun is not available");
        return Ok(());
    }
    let Some(c_tincd) = c_tincd_binary() else {
        eprintln!(
            "skipping C legacy bad ANS_KEY netns test: set C_TINCD_PATH or build vendor/tinc/build-c/src/tincd"
        );
        return Ok(());
    };

    run_legacy_bad_ans_key_daemon_injection(&c_tincd, "C", "tinc-c-legacy-bad-ans-key", false)
}

#[test]
fn linux_netns_rust_tincd_handles_unknown_compression_ans_key_like_tinc()
-> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!("skipping Rust legacy unknown-compression ANS_KEY netns test: Linux-only test");
        return Ok(());
    }
    if !command_available("ip") {
        eprintln!(
            "skipping Rust legacy unknown-compression ANS_KEY netns test: missing ip command"
        );
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!(
            "skipping Rust legacy unknown-compression ANS_KEY netns test: /dev/net/tun is not available"
        );
        return Ok(());
    }

    run_legacy_unknown_compression_ans_key_daemon_injection(
        Path::new(TINCD),
        "Rust",
        "tinc-rust-legacy-unknown-compression-ans-key",
    )
}

#[test]
fn linux_netns_c_tincd_handles_unknown_compression_ans_key_like_tinc() -> Result<(), Box<dyn Error>>
{
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!("skipping C legacy unknown-compression ANS_KEY netns test: Linux-only test");
        return Ok(());
    }
    if !command_available("ip") {
        eprintln!("skipping C legacy unknown-compression ANS_KEY netns test: missing ip command");
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!(
            "skipping C legacy unknown-compression ANS_KEY netns test: /dev/net/tun is not available"
        );
        return Ok(());
    }
    let Some(c_tincd) = c_tincd_binary() else {
        eprintln!(
            "skipping C legacy unknown-compression ANS_KEY netns test: set C_TINCD_PATH or build vendor/tinc/build-c/src/tincd"
        );
        return Ok(());
    };

    run_legacy_unknown_compression_ans_key_daemon_injection(
        &c_tincd,
        "C",
        "tinc-c-legacy-unknown-compression-ans-key",
    )
}

#[test]
fn linux_netns_rust_tincd_handles_lzo_unavailable_ans_key_like_tinc() -> Result<(), Box<dyn Error>>
{
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!("skipping Rust legacy LZO-unavailable ANS_KEY netns test: Linux-only test");
        return Ok(());
    }
    if !command_available("ip") {
        eprintln!("skipping Rust legacy LZO-unavailable ANS_KEY netns test: missing ip command");
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!(
            "skipping Rust legacy LZO-unavailable ANS_KEY netns test: /dev/net/tun is not available"
        );
        return Ok(());
    }
    if legacy_compression_is_available(CompressionLevel::LzoLow) {
        eprintln!(
            "skipping Rust legacy LZO-unavailable ANS_KEY netns test: Rust tincd was built with LZO support"
        );
        return Ok(());
    }

    run_legacy_lzo_unavailable_ans_key_daemon_injection(
        Path::new(TINCD),
        "Rust",
        "tinc-rust-legacy-lzo-unavailable-ans-key",
    )
}

#[test]
fn linux_netns_c_tincd_handles_lzo_unavailable_ans_key_like_tinc() -> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!("skipping C legacy LZO-unavailable ANS_KEY netns test: Linux-only test");
        return Ok(());
    }
    if !command_available("ip") {
        eprintln!("skipping C legacy LZO-unavailable ANS_KEY netns test: missing ip command");
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!(
            "skipping C legacy LZO-unavailable ANS_KEY netns test: /dev/net/tun is not available"
        );
        return Ok(());
    }
    let Some(c_tincd) = c_tincd_binary() else {
        eprintln!(
            "skipping C legacy LZO-unavailable ANS_KEY netns test: set C_TINCD_PATH or build vendor/tinc/build-c/src/tincd"
        );
        return Ok(());
    };
    let version = Command::new(&c_tincd).arg("--version").output()?;
    let version_text = format!(
        "{}{}",
        String::from_utf8_lossy(&version.stdout),
        String::from_utf8_lossy(&version.stderr)
    );
    if version_text.contains("comp_lzo") {
        eprintln!("skipping C legacy LZO-unavailable ANS_KEY netns test: C build has LZO enabled");
        return Ok(());
    }

    run_legacy_lzo_unavailable_ans_key_daemon_injection(
        &c_tincd,
        "C",
        "tinc-c-legacy-lzo-unavailable-ans-key",
    )
}

#[test]
fn linux_netns_rust_tincd_retries_dropped_legacy_req_key_like_tinc() -> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!("skipping Rust legacy dropped REQ_KEY netns test: Linux-only test");
        return Ok(());
    }
    if !command_available("ip") || !command_available("ping") {
        eprintln!("skipping Rust legacy dropped REQ_KEY netns test: missing ip or ping command");
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!("skipping Rust legacy dropped REQ_KEY netns test: /dev/net/tun is not available");
        return Ok(());
    }

    run_legacy_dropped_req_key_retry_daemon_injection(
        Path::new(TINCD),
        "Rust",
        "tinc-rust-legacy-dropped-req-key",
        false,
    )
}

#[test]
fn linux_netns_c_tincd_retries_dropped_legacy_req_key_like_tinc() -> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!("skipping C legacy dropped REQ_KEY netns test: Linux-only test");
        return Ok(());
    }
    if !command_available("ip") || !command_available("ping") {
        eprintln!("skipping C legacy dropped REQ_KEY netns test: missing ip or ping command");
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!("skipping C legacy dropped REQ_KEY netns test: /dev/net/tun is not available");
        return Ok(());
    }
    let Some(c_tincd) = c_tincd_binary() else {
        eprintln!(
            "skipping C legacy dropped REQ_KEY netns test: set C_TINCD_PATH or build vendor/tinc/build-c/src/tincd"
        );
        return Ok(());
    };

    run_legacy_dropped_req_key_retry_daemon_injection(
        &c_tincd,
        "C",
        "tinc-c-legacy-dropped-req-key",
        false,
    )
}

#[test]
fn linux_netns_rust_tincd_tunnel_server_retries_dropped_legacy_req_key_like_tinc()
-> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!("skipping Rust tunnel-server legacy dropped REQ_KEY netns test: Linux-only test");
        return Ok(());
    }
    if !command_available("ip") || !command_available("ping") {
        eprintln!(
            "skipping Rust tunnel-server legacy dropped REQ_KEY netns test: missing ip or ping command"
        );
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!(
            "skipping Rust tunnel-server legacy dropped REQ_KEY netns test: /dev/net/tun is not available"
        );
        return Ok(());
    }

    run_legacy_dropped_req_key_retry_daemon_injection(
        Path::new(TINCD),
        "Rust tunnel-server",
        "tinc-rust-legacy-tunnel-server-dropped-req-key",
        true,
    )
}

#[test]
fn linux_netns_c_tincd_tunnel_server_retries_dropped_legacy_req_key_like_tinc()
-> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!("skipping C tunnel-server legacy dropped REQ_KEY netns test: Linux-only test");
        return Ok(());
    }
    if !command_available("ip") || !command_available("ping") {
        eprintln!(
            "skipping C tunnel-server legacy dropped REQ_KEY netns test: missing ip or ping command"
        );
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!(
            "skipping C tunnel-server legacy dropped REQ_KEY netns test: /dev/net/tun is not available"
        );
        return Ok(());
    }
    let Some(c_tincd) = c_tincd_binary() else {
        eprintln!(
            "skipping C tunnel-server legacy dropped REQ_KEY netns test: set C_TINCD_PATH or build vendor/tinc/build-c/src/tincd"
        );
        return Ok(());
    };

    run_legacy_dropped_req_key_retry_daemon_injection(
        &c_tincd,
        "C tunnel-server",
        "tinc-c-legacy-tunnel-server-dropped-req-key",
        true,
    )
}

#[test]
fn linux_netns_rust_tincd_drops_replayed_legacy_udp_like_tinc() -> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!("skipping Rust legacy UDP replay netns test: Linux-only test");
        return Ok(());
    }
    if !command_available("ip") {
        eprintln!("skipping Rust legacy UDP replay netns test: missing ip command");
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!("skipping Rust legacy UDP replay netns test: /dev/net/tun is not available");
        return Ok(());
    }

    run_legacy_udp_replay_daemon_injection(Path::new(TINCD), "Rust", "tinc-rust-legacy-udp-replay")
}

#[test]
fn linux_netns_c_tincd_drops_replayed_legacy_udp_like_tinc() -> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!("skipping C legacy UDP replay netns test: Linux-only test");
        return Ok(());
    }
    if !command_available("ip") {
        eprintln!("skipping C legacy UDP replay netns test: missing ip command");
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!("skipping C legacy UDP replay netns test: /dev/net/tun is not available");
        return Ok(());
    }
    let Some(c_tincd) = c_tincd_binary() else {
        eprintln!(
            "skipping C legacy UDP replay netns test: set C_TINCD_PATH or build vendor/tinc/build-c/src/tincd"
        );
        return Ok(());
    };

    run_legacy_udp_replay_daemon_injection(&c_tincd, "C", "tinc-c-legacy-udp-replay")
}

#[test]
fn linux_netns_rust_tincd_uses_legacy_local_discovery_like_tinc() -> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!("skipping Rust legacy local discovery netns test: Linux-only test");
        return Ok(());
    }
    if !command_available("ip") || !command_available("ping") {
        eprintln!("skipping Rust legacy local discovery netns test: missing ip or ping command");
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!("skipping Rust legacy local discovery netns test: /dev/net/tun is not available");
        return Ok(());
    }

    run_legacy_local_discovery_daemon_injection(
        Path::new(TINCD),
        "Rust",
        "tinc-rust-legacy-local-discovery",
        true,
    )
}

#[test]
fn linux_netns_c_tincd_uses_legacy_local_discovery_like_tinc() -> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!("skipping C legacy local discovery netns test: Linux-only test");
        return Ok(());
    }
    if !command_available("ip") || !command_available("ping") {
        eprintln!("skipping C legacy local discovery netns test: missing ip or ping command");
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!("skipping C legacy local discovery netns test: /dev/net/tun is not available");
        return Ok(());
    }
    let Some(c_tincd) = c_tincd_binary() else {
        eprintln!(
            "skipping C legacy local discovery netns test: set C_TINCD_PATH or build vendor/tinc/build-c/src/tincd"
        );
        return Ok(());
    };

    run_legacy_local_discovery_daemon_injection(
        &c_tincd,
        "C",
        "tinc-c-legacy-local-discovery",
        true,
    )
}

#[test]
fn linux_netns_rust_tincd_disables_legacy_local_discovery_like_tinc() -> Result<(), Box<dyn Error>>
{
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!("skipping Rust legacy local discovery disabled netns test: Linux-only test");
        return Ok(());
    }
    if !command_available("ip") || !command_available("ping") {
        eprintln!(
            "skipping Rust legacy local discovery disabled netns test: missing ip or ping command"
        );
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!(
            "skipping Rust legacy local discovery disabled netns test: /dev/net/tun is not available"
        );
        return Ok(());
    }

    run_legacy_local_discovery_daemon_injection(
        Path::new(TINCD),
        "Rust",
        "tinc-rust-legacy-local-discovery-disabled",
        false,
    )
}

#[test]
fn linux_netns_c_tincd_disables_legacy_local_discovery_like_tinc() -> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!("skipping C legacy local discovery disabled netns test: Linux-only test");
        return Ok(());
    }
    if !command_available("ip") || !command_available("ping") {
        eprintln!(
            "skipping C legacy local discovery disabled netns test: missing ip or ping command"
        );
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!(
            "skipping C legacy local discovery disabled netns test: /dev/net/tun is not available"
        );
        return Ok(());
    }
    let Some(c_tincd) = c_tincd_binary() else {
        eprintln!(
            "skipping C legacy local discovery disabled netns test: set C_TINCD_PATH or build vendor/tinc/build-c/src/tincd"
        );
        return Ok(());
    };

    run_legacy_local_discovery_daemon_injection(
        &c_tincd,
        "C",
        "tinc-c-legacy-local-discovery-disabled",
        false,
    )
}

#[test]
fn linux_netns_rust_tincd_resets_address_cache_after_udp_probe_reply_like_tinc()
-> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!("skipping Rust legacy UDP probe address-cache netns test: Linux-only test");
        return Ok(());
    }
    if !command_available("ip") || !command_available("ping") || !command_available("tcpdump") {
        eprintln!(
            "skipping Rust legacy UDP probe address-cache netns test: missing ip, ping, or tcpdump command"
        );
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!(
            "skipping Rust legacy UDP probe address-cache netns test: /dev/net/tun is not available"
        );
        return Ok(());
    }

    run_legacy_udp_probe_address_cache_daemon_injection(
        Path::new(TINCD),
        "Rust",
        "tinc-rust-legacy-probe-cache",
    )
}

#[test]
fn linux_netns_c_tincd_resets_address_cache_after_udp_probe_reply_like_tinc()
-> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!("skipping C legacy UDP probe address-cache netns test: Linux-only test");
        return Ok(());
    }
    if !command_available("ip") || !command_available("ping") || !command_available("tcpdump") {
        eprintln!(
            "skipping C legacy UDP probe address-cache netns test: missing ip, ping, or tcpdump command"
        );
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!(
            "skipping C legacy UDP probe address-cache netns test: /dev/net/tun is not available"
        );
        return Ok(());
    }
    let Some(c_tincd) = c_tincd_binary() else {
        eprintln!(
            "skipping C legacy UDP probe address-cache netns test: set C_TINCD_PATH or build vendor/tinc/build-c/src/tincd"
        );
        return Ok(());
    };

    run_legacy_udp_probe_address_cache_daemon_injection(&c_tincd, "C", "tinc-c-legacy-probe-cache")
}

#[allow(clippy::too_many_lines)]
fn run_legacy_local_discovery_daemon_injection(
    daemon_binary: &Path,
    daemon_label: &str,
    workspace_prefix: &str,
    local_discovery: bool,
) -> Result<(), Box<dyn Error>> {
    let workspace = TempWorkspace::new(workspace_prefix)?;
    let suffix = unique_suffix();
    let ns_alpha = format!("tinc-local-disc-a-{suffix}");
    let veth_alpha = format!("ldc{suffix}a");
    let veth_beta = format!("ldc{suffix}b");
    let alpha_port = 17373;
    let beta_listener = TcpListener::bind("0.0.0.0:0")?;
    beta_listener.set_nonblocking(true)?;
    let beta_tcp_port = beta_listener.local_addr()?.port();
    let normal_udp = UdpSocket::bind(("0.0.0.0", beta_tcp_port))?;
    normal_udp.set_read_timeout(Some(Duration::from_millis(200)))?;
    let normal_udp_port = normal_udp.local_addr()?.port();
    let local_udp = UdpSocket::bind("0.0.0.0:0")?;
    local_udp.set_read_timeout(Some(Duration::from_millis(200)))?;
    let local_udp_port = local_udp.local_addr()?.port();
    let alpha_rsa = RsaPrivateKey::new(&mut OsRng, 2048)?;
    let beta_rsa = RsaPrivateKey::new(&mut OsRng, 2048)?;
    let alpha_rsa_public = RsaPublicKey::from(&alpha_rsa);
    let beta_rsa_public = RsaPublicKey::from(&beta_rsa);
    let confdir = workspace.path().join("alpha");
    let mut cleanup = NetnsCleanup::new(workspace.path().to_path_buf());
    cleanup.add_namespace(ns_alpha.clone());
    cleanup.add_root_link(veth_beta.clone());

    create_legacy_node_config(
        &confdir,
        LegacyNodeConfig {
            name: "alpha",
            peer: "beta",
            port: alpha_port,
            bind_address: "192.0.2.61",
            peer_address: "192.0.2.62",
            peer_port: beta_tcp_port,
            interface: "tun-alpha",
            tunnel_address: "10.112.1.1/24",
            subnet: "10.112.1.0/24",
            peer_subnet: "10.112.2.0/24",
            connect_to_peer: true,
            private_key: &alpha_rsa,
            public_key: &alpha_rsa_public,
            peer_public_key: &beta_rsa_public,
            key_expire: None,
            fast_ping: false,
            legacy_crypto: LegacyCryptoConfig::default(),
        },
    )?;
    fs::OpenOptions::new()
        .append(true)
        .open(confdir.join("tinc.conf"))?
        .write_all(
            format!(
                "LocalDiscovery = {}\nUDPDiscoveryInterval = 1\nUDPDiscoveryTimeout = 3\n",
                if local_discovery { "yes" } else { "no" }
            )
            .as_bytes(),
        )?;

    if !try_ip(&["netns", "add", &ns_alpha]) {
        eprintln!(
            "skipping {daemon_label} legacy local discovery netns test: cannot create network namespace"
        );
        return Ok(());
    }
    run_ip(&[
        "link",
        "add",
        &veth_alpha,
        "type",
        "veth",
        "peer",
        "name",
        &veth_beta,
    ])?;
    run_ip(&["link", "set", &veth_alpha, "netns", &ns_alpha])?;
    run_ip(&["-n", &ns_alpha, "link", "set", "lo", "up"])?;
    run_ip(&[
        "-n",
        &ns_alpha,
        "addr",
        "add",
        "192.0.2.61/24",
        "dev",
        &veth_alpha,
    ])?;
    run_ip(&["-n", &ns_alpha, "link", "set", &veth_alpha, "up"])?;
    run_ip(&["addr", "add", "192.0.2.62/24", "dev", &veth_beta])?;
    run_ip(&["link", "set", &veth_beta, "up"])?;

    cleanup.spawn_with_binary(
        "alpha",
        daemon_binary,
        &confdir,
        &ns_alpha,
        &workspace.path().join("alpha.log"),
    )?;
    wait_for_control_socket(&confdir.join("pid.socket"), &cleanup)?;

    let mut fake_beta = wait_for_fake_legacy_connection(&beta_listener, &cleanup)?;
    fake_beta.set_read_timeout(Some(Duration::from_secs(3)))?;
    fake_beta.set_write_timeout(Some(Duration::from_secs(3)))?;
    let mut driver = activate_fake_legacy_peer(
        &mut fake_beta,
        "beta",
        "alpha",
        &beta_rsa,
        &alpha_rsa_public,
        beta_tcp_port,
    )?;
    send_fake_legacy_add_edge(
        &mut fake_beta,
        &mut driver,
        "beta",
        "alpha",
        "192.0.2.62",
        normal_udp_port,
        "192.0.2.62",
        local_udp_port,
    )?;
    wait_for_node_status(&confdir, "beta", 1 << 4, 1 << 1, &cleanup)?;

    fake_beta.write_all(
        &driver
            .send_meta_message(&MetaMessage::RequestKey(
                tinc_core::protocol::RequestKeyMessage::new("beta", "alpha"),
            ))
            .map_err(|error| format!("could not encode fake beta REQ_KEY: {error}"))?,
    )?;
    fake_beta.flush()?;
    let answer = read_latest_legacy_answer_key_from_daemon(&mut fake_beta, &mut driver, "alpha")?;

    let mut beta_codec = LegacyUdpCodec::default();
    beta_codec.insert_peer(
        "alpha",
        LegacyPeerState::from_legacy_answer_key(&answer, 4).map_err(|error| {
            format!("could not install alpha ANS_KEY as fake beta outgoing key: {error}")
        })?,
    );
    let valid_answer = legacy_ans_key_message("beta", "alpha", "42".repeat(48), 0);
    beta_codec
        .apply_incoming_legacy_answer_key("alpha", &valid_answer)
        .map_err(|error| {
            format!("could not install beta ANS_KEY as fake beta incoming key: {error}")
        })?;

    send_fake_legacy_ans_key(
        &mut fake_beta,
        &mut driver,
        valid_answer,
        "local discovery setup",
    )?;
    wait_for_node_status(&confdir, "beta", (1 << 4) | (1 << 1), 0, &cleanup)?;

    let deadline = Instant::now() + Duration::from_secs(12);
    let mut saw_normal_probe = false;
    let mut saw_local_probe = false;
    let mut last_status = String::new();
    while Instant::now() < deadline {
        cleanup.ensure_children_alive()?;
        trigger_ping_without_wait(&ns_alpha, "10.112.2.1")?;

        if receive_legacy_probe_and_maybe_reply(
            &normal_udp,
            &mut beta_codec,
            !local_discovery,
            daemon_label,
            &cleanup,
        )? {
            saw_normal_probe = true;
        }
        if receive_legacy_probe_and_maybe_reply(
            &local_udp,
            &mut beta_codec,
            local_discovery,
            daemon_label,
            &cleanup,
        )? {
            saw_local_probe = true;
        }

        if let Ok(dump) = run_rust_tincctl(&[
            "tinc",
            "--config",
            confdir.to_str().unwrap(),
            "dump",
            "nodes",
        ]) {
            last_status = dump;
            if rust_dump_node_status(&last_status, "beta").is_some_and(|status| {
                status & (1 << 7) != 0 && status & (1 << 8) == 0 && status & (1 << 12) == 0
            }) {
                assert!(
                    saw_normal_probe,
                    "{daemon_label} daemon became udp_confirmed without first sending the normal C try_udp() probe\n{}",
                    cleanup.logs()
                );
                assert!(
                    local_discovery == saw_local_probe,
                    "{daemon_label} daemon local discovery probe behavior did not follow C LocalDiscovery={}: saw_local_probe={saw_local_probe}\n{}",
                    if local_discovery { "yes" } else { "no" },
                    cleanup.logs()
                );
                let cached_addresses =
                    read_c_tinc_address_cache(&confdir.join("cache").join("beta"))?;
                let expected_normal_edge: SocketAddr =
                    format!("192.0.2.62:{normal_udp_port}").parse()?;
                assert_eq!(
                    vec![expected_normal_edge],
                    cached_addresses,
                    "{daemon_label} daemon did not reset cache/beta to C n->connection->edge->address after the first UDP probe reply; LocalDiscovery must not replace it with the local edge address\n{}",
                    cleanup.logs()
                );

                stop_daemon_with_rust_tincctl(&confdir, &mut cleanup, "alpha", daemon_label)?;
                return Ok(());
            }
        }

        thread::sleep(Duration::from_millis(200));
    }

    Err(format!(
        "{daemon_label} daemon did not confirm UDP via C try_udp() local discovery duplicate probe\n\
         LocalDiscovery={} saw_normal_probe={saw_normal_probe} saw_local_probe={saw_local_probe}\n\
         last dump:\n{last_status}\n{}",
        if local_discovery { "yes" } else { "no" },
        cleanup.logs()
    )
    .into())
}

#[allow(clippy::too_many_lines)]
fn run_legacy_udp_probe_address_cache_daemon_injection(
    daemon_binary: &Path,
    daemon_label: &str,
    workspace_prefix: &str,
) -> Result<(), Box<dyn Error>> {
    let workspace = TempWorkspace::new(workspace_prefix)?;
    let suffix = unique_suffix();
    let ns_alpha = format!("tinc-probe-cache-a-{suffix}");
    let veth_alpha = format!("pca{suffix}a");
    let veth_beta = format!("pca{suffix}b");
    let alpha_port = 17374;
    let beta_udp = UdpSocket::bind("0.0.0.0:0")?;
    beta_udp.set_read_timeout(Some(Duration::from_millis(200)))?;
    let beta_udp_port = beta_udp.local_addr()?.port();
    let alpha_rsa = RsaPrivateKey::new(&mut OsRng, 2048)?;
    let beta_rsa = RsaPrivateKey::new(&mut OsRng, 2048)?;
    let alpha_rsa_public = RsaPublicKey::from(&alpha_rsa);
    let beta_rsa_public = RsaPublicKey::from(&beta_rsa);
    let confdir = workspace.path().join("alpha");
    let cache_path = confdir.join("cache").join("beta");
    let stale_cache_address: SocketAddr = "192.0.2.99:9999".parse()?;
    let expected_edge_address: SocketAddr = format!("192.0.2.72:{beta_udp_port}").parse()?;
    let mut cleanup = NetnsCleanup::new(workspace.path().to_path_buf());
    cleanup.add_namespace(ns_alpha.clone());
    cleanup.add_root_link(veth_beta.clone());

    create_legacy_node_config(
        &confdir,
        LegacyNodeConfig {
            name: "alpha",
            peer: "beta",
            port: alpha_port,
            bind_address: "192.0.2.71",
            peer_address: "192.0.2.72",
            peer_port: beta_udp_port,
            interface: "tun-alpha",
            tunnel_address: "10.113.1.1/24",
            subnet: "10.113.1.0/24",
            peer_subnet: "10.113.2.0/24",
            connect_to_peer: false,
            private_key: &alpha_rsa,
            public_key: &alpha_rsa_public,
            peer_public_key: &beta_rsa_public,
            key_expire: None,
            fast_ping: false,
            legacy_crypto: LegacyCryptoConfig::default(),
        },
    )?;
    fs::OpenOptions::new()
        .append(true)
        .open(confdir.join("tinc.conf"))?
        .write_all(b"LocalDiscovery = no\nUDPDiscoveryInterval = 1\nUDPDiscoveryTimeout = 3\n")?;
    write_c_tinc_address_cache(&cache_path, &[stale_cache_address])?;
    if !try_ip(&["netns", "add", &ns_alpha]) {
        eprintln!(
            "skipping {daemon_label} legacy UDP probe address-cache netns test: cannot create network namespace"
        );
        return Ok(());
    }
    run_ip(&[
        "link",
        "add",
        &veth_alpha,
        "type",
        "veth",
        "peer",
        "name",
        &veth_beta,
    ])?;
    run_ip(&["link", "set", &veth_alpha, "netns", &ns_alpha])?;
    run_ip(&["-n", &ns_alpha, "link", "set", "lo", "up"])?;
    run_ip(&[
        "-n",
        &ns_alpha,
        "addr",
        "add",
        "192.0.2.71/24",
        "dev",
        &veth_alpha,
    ])?;
    run_ip(&["-n", &ns_alpha, "link", "set", &veth_alpha, "up"])?;
    run_ip(&["addr", "add", "192.0.2.72/24", "dev", &veth_beta])?;
    run_ip(&["link", "set", &veth_beta, "up"])?;

    cleanup.spawn_with_binary(
        "alpha",
        daemon_binary,
        &confdir,
        &ns_alpha,
        &workspace.path().join("alpha.log"),
    )?;
    wait_for_control_socket(&confdir.join("pid.socket"), &cleanup)?;

    let (mut fake_beta, mut driver) = connect_fake_legacy_peer_to_daemon(
        SocketAddr::new("192.0.2.71".parse()?, alpha_port),
        "beta",
        "alpha",
        &beta_rsa,
        &alpha_rsa_public,
        beta_udp_port,
        &cleanup,
    )?;
    send_fake_legacy_add_edge(
        &mut fake_beta,
        &mut driver,
        "beta",
        "alpha",
        "192.0.2.72",
        beta_udp_port,
        "192.0.2.72",
        beta_udp_port,
    )?;
    wait_for_node_status(&confdir, "beta", 1 << 4, 1 << 1, &cleanup)?;

    fake_beta.write_all(
        &driver
            .send_meta_message(&MetaMessage::RequestKey(
                tinc_core::protocol::RequestKeyMessage::new("beta", "alpha"),
            ))
            .map_err(|error| format!("could not encode fake beta REQ_KEY: {error}"))?,
    )?;
    fake_beta.flush()?;
    let answer = read_latest_legacy_answer_key_from_daemon(&mut fake_beta, &mut driver, "alpha")?;

    let mut beta_codec = LegacyUdpCodec::default();
    beta_codec.insert_peer(
        "alpha",
        LegacyPeerState::from_legacy_answer_key(&answer, 4).map_err(|error| {
            format!("could not install alpha ANS_KEY as fake beta outgoing key: {error}")
        })?,
    );
    let valid_answer = legacy_ans_key_message("beta", "alpha", "42".repeat(48), 0);
    beta_codec
        .apply_incoming_legacy_answer_key("alpha", &valid_answer)
        .map_err(|error| {
            format!("could not install beta ANS_KEY as fake beta incoming key: {error}")
        })?;
    send_fake_legacy_ans_key(
        &mut fake_beta,
        &mut driver,
        valid_answer,
        "UDP probe address-cache setup",
    )?;
    wait_for_node_status(&confdir, "beta", (1 << 4) | (1 << 1), 0, &cleanup)?;
    assert_eq!(
        vec![stale_cache_address],
        read_c_tinc_address_cache(&cache_path)?,
        "{daemon_label} setup should start with the intentionally stale C address cache entry"
    );

    let pcap_path = workspace
        .path()
        .join(format!("probe-cache-{daemon_label}-{suffix}.pcap"));
    let mut tcpdump = spawn_udp_probe_tcpdump(&ns_alpha, &veth_alpha, beta_udp_port, &pcap_path)?;
    thread::sleep(Duration::from_millis(300));

    let deadline = Instant::now() + Duration::from_secs(12);
    let mut saw_probe = false;
    let mut last_status = String::new();
    while Instant::now() < deadline {
        cleanup.ensure_children_alive()?;
        trigger_ping_without_wait(&ns_alpha, "10.113.2.1")?;

        if receive_legacy_probe_and_maybe_reply(
            &beta_udp,
            &mut beta_codec,
            true,
            daemon_label,
            &cleanup,
        )? {
            saw_probe = true;
        }

        if let Ok(dump) = run_rust_tincctl(&[
            "tinc",
            "--config",
            confdir.to_str().unwrap(),
            "dump",
            "nodes",
        ]) {
            last_status = dump;
            if rust_dump_node_status(&last_status, "beta").is_some_and(|status| {
                status & (1 << 7) != 0 && status & (1 << 8) == 0 && status & (1 << 12) == 0
            }) {
                assert!(
                    saw_probe,
                    "{daemon_label} daemon became udp_confirmed without a captured C try_udp() probe\n{}",
                    cleanup.logs()
                );
                let pcap_bytes = finish_tcpdump_capture(
                    &mut tcpdump,
                    &pcap_path,
                    "legacy UDP probe address-cache",
                    &cleanup,
                )?;
                assert!(
                    pcap_record_count(&pcap_bytes) > 0,
                    "{daemon_label} daemon did not produce a tcpdump-observable UDP probe exchange before cache reset\n{}",
                    cleanup.logs()
                );
                let cached_addresses = read_c_tinc_address_cache(&cache_path)?;
                assert_eq!(
                    vec![expected_edge_address, stale_cache_address],
                    cached_addresses,
                    "{daemon_label} daemon did not promote C n->connection->edge->address after the first UDP probe reply while preserving the existing recent list shape\n{}",
                    cleanup.logs()
                );

                stop_daemon_with_rust_tincctl(&confdir, &mut cleanup, "alpha", daemon_label)?;
                return Ok(());
            }
        }

        thread::sleep(Duration::from_millis(200));
    }

    let _ = finish_tcpdump_capture(
        &mut tcpdump,
        &pcap_path,
        "legacy UDP probe address-cache timeout",
        &cleanup,
    );
    Err(format!(
        "{daemon_label} daemon did not confirm UDP and reset address cache after a C-style UDP probe reply\n\
         saw_probe={saw_probe}\nlast dump:\n{last_status}\ncache={:?}\n{}",
        read_c_tinc_address_cache(&cache_path).unwrap_or_default(),
        cleanup.logs()
    )
    .into())
}

fn run_legacy_bad_ans_key_daemon_injection(
    daemon_binary: &Path,
    daemon_label: &str,
    workspace_prefix: &str,
    check_lzo_unavailable: bool,
) -> Result<(), Box<dyn Error>> {
    let workspace = TempWorkspace::new(workspace_prefix)?;
    let suffix = unique_suffix();
    let ns_alpha = format!("tinc-bad-ans-a-{suffix}");
    let veth_alpha = format!("bak{suffix}a");
    let veth_beta = format!("bak{suffix}b");
    let alpha_port = 17370;
    let beta_listener = TcpListener::bind("0.0.0.0:0")?;
    beta_listener.set_nonblocking(true)?;
    let beta_port = beta_listener.local_addr()?.port();
    let alpha_rsa = RsaPrivateKey::new(&mut OsRng, 2048)?;
    let beta_rsa = RsaPrivateKey::new(&mut OsRng, 2048)?;
    let alpha_rsa_public = RsaPublicKey::from(&alpha_rsa);
    let beta_rsa_public = RsaPublicKey::from(&beta_rsa);
    let confdir = workspace.path().join("alpha");
    let mut cleanup = NetnsCleanup::new(workspace.path().to_path_buf());
    cleanup.add_namespace(ns_alpha.clone());
    cleanup.add_root_link(veth_beta.clone());

    create_legacy_node_config(
        &confdir,
        LegacyNodeConfig {
            name: "alpha",
            peer: "beta",
            port: alpha_port,
            bind_address: "192.0.2.31",
            peer_address: "192.0.2.32",
            peer_port: beta_port,
            interface: "tun-alpha",
            tunnel_address: "10.109.1.1/24",
            subnet: "10.109.1.0/24",
            peer_subnet: "10.109.2.0/24",
            connect_to_peer: true,
            private_key: &alpha_rsa,
            public_key: &alpha_rsa_public,
            peer_public_key: &beta_rsa_public,
            key_expire: None,
            fast_ping: false,
            legacy_crypto: LegacyCryptoConfig::default(),
        },
    )?;
    if !try_ip(&["netns", "add", &ns_alpha]) {
        eprintln!("skipping Rust legacy bad ANS_KEY netns test: cannot create network namespace");
        return Ok(());
    }
    run_ip(&[
        "link",
        "add",
        &veth_alpha,
        "type",
        "veth",
        "peer",
        "name",
        &veth_beta,
    ])?;
    run_ip(&["link", "set", &veth_alpha, "netns", &ns_alpha])?;
    run_ip(&["-n", &ns_alpha, "link", "set", "lo", "up"])?;
    run_ip(&[
        "-n",
        &ns_alpha,
        "addr",
        "add",
        "192.0.2.31/24",
        "dev",
        &veth_alpha,
    ])?;
    run_ip(&["-n", &ns_alpha, "link", "set", &veth_alpha, "up"])?;
    run_ip(&["addr", "add", "192.0.2.32/24", "dev", &veth_beta])?;
    run_ip(&["link", "set", &veth_beta, "up"])?;

    cleanup.spawn_with_binary(
        "alpha",
        daemon_binary,
        &confdir,
        &ns_alpha,
        &workspace.path().join("alpha.log"),
    )?;
    wait_for_control_socket(&confdir.join("pid.socket"), &cleanup)?;

    let (mut fake_beta, mut driver) = activate_fake_legacy_beta_for_bad_ans_key(
        &beta_listener,
        &cleanup,
        &confdir,
        &beta_rsa,
        &alpha_rsa_public,
        beta_port,
        alpha_port,
    )?;

    let bad_answer = legacy_ans_key_message("beta", "alpha", "42".repeat(47), 0);
    fake_beta.write_all(
        &driver
            .send_meta_message(&MetaMessage::AnswerKey(bad_answer))
            .map_err(|error| format!("could not encode bad ANS_KEY: {error}"))?,
    )?;
    fake_beta.flush()?;
    wait_for_node_status(&confdir, "beta", 1 << 4, 1 << 1, &cleanup)?;
    if command_available("tcpdump") {
        let payload = assert_underlay_ping_attempt_payload_not_plaintext(
            &ns_alpha,
            &veth_alpha,
            "10.109.2.1",
            &format!("{daemon_label} legacy bad ANS_KEY TCP fallback before valid key"),
            NoPlaintextCapture::TcpAndUdp,
            &cleanup,
        )?;
        let tcp_events =
            read_fake_legacy_meta_events_until(&mut fake_beta, &mut driver, |event| {
                matches!(
                    event,
                    tinc_runtime::meta::MetaConnectionEvent::TcpPacket(packet)
                        if contains_subslice(packet, payload.as_bytes())
                )
            })
            .map_err(|error| {
                format!(
                    "{daemon_label} daemon did not emit TCP fallback ping payload while waiting for initial missing-key packet: {error}\n{}",
                    cleanup.logs()
                )
            })?;
        assert!(
            tcp_events.iter().any(|event| matches!(
                event,
                tinc_runtime::meta::MetaConnectionEvent::TcpPacket(packet)
                    if contains_subslice(packet, payload.as_bytes())
            )),
            "{daemon_label} daemon did not forward the bad-key fallback ping as a C-style meta PACKET body\n{}",
            cleanup.logs()
        );
    }
    fake_beta.write_all(
        &driver
            .send_meta_message(&MetaMessage::Ping)
            .map_err(|error| format!("could not encode post-bad-key ping: {error}"))?,
    )?;
    fake_beta.flush()?;
    let pong_events = read_fake_legacy_events_until(&mut fake_beta, &mut driver, |message| {
        matches!(message, MetaMessage::Pong)
    })?;
    assert!(
        pong_events
            .iter()
            .any(|message| matches!(message, MetaMessage::Pong)),
        "{daemon_label} daemon closed or stopped processing meta after recoverable bad ANS_KEY\n{}",
        cleanup.logs()
    );

    let valid_answer = legacy_ans_key_message("beta", "alpha", "42".repeat(48), 0);
    fake_beta.write_all(
        &driver
            .send_meta_message(&MetaMessage::AnswerKey(valid_answer))
            .map_err(|error| format!("could not encode valid ANS_KEY: {error}"))?,
    )?;
    fake_beta.flush()?;
    wait_for_node_status(&confdir, "beta", (1 << 4) | (1 << 1), 0, &cleanup)?;

    let unknown_compression_answer = legacy_ans_key_message("beta", "alpha", "24".repeat(48), 13);
    fake_beta.write_all(
        &driver
            .send_meta_message(&MetaMessage::AnswerKey(unknown_compression_answer))
            .map_err(|error| format!("could not encode unknown-compression ANS_KEY: {error}"))?,
    )?;
    fake_beta.flush()?;
    wait_for_node_status(&confdir, "beta", 1 << 4, 1 << 1, &cleanup)?;
    fake_beta.write_all(
        &driver
            .send_meta_message(&MetaMessage::Ping)
            .map_err(|error| format!("could not encode post-LZO ping: {error}"))?,
    )?;
    fake_beta.flush()?;
    let pong_events = read_fake_legacy_events_until(&mut fake_beta, &mut driver, |message| {
        matches!(message, MetaMessage::Pong)
    })?;
    assert!(
        pong_events
            .iter()
            .any(|message| matches!(message, MetaMessage::Pong)),
        "{daemon_label} daemon closed or stopped processing meta after unknown-compression ANS_KEY\n{}",
        cleanup.logs()
    );

    if check_lzo_unavailable {
        let lzo_answer = legacy_ans_key_message(
            "beta",
            "alpha",
            "24".repeat(48),
            CompressionLevel::LzoLow as i32,
        );
        fake_beta.write_all(
            &driver
                .send_meta_message(&MetaMessage::AnswerKey(lzo_answer))
                .map_err(|error| format!("could not encode LZO ANS_KEY: {error}"))?,
        )?;
        fake_beta.flush()?;
        wait_for_node_status(&confdir, "beta", 1 << 4, 1 << 1, &cleanup)?;
        fake_beta.write_all(
            &driver
                .send_meta_message(&MetaMessage::Ping)
                .map_err(|error| format!("could not encode post-LZO ping: {error}"))?,
        )?;
        fake_beta.flush()?;
        let pong_events = read_fake_legacy_events_until(&mut fake_beta, &mut driver, |message| {
            matches!(message, MetaMessage::Pong)
        })?;
        assert!(
            pong_events
                .iter()
                .any(|message| matches!(message, MetaMessage::Pong)),
            "{daemon_label} daemon closed or stopped processing meta after unavailable-LZO ANS_KEY\n{}",
            cleanup.logs()
        );
    }

    let mut unknown_cipher = legacy_ans_key_message("beta", "alpha", "42".repeat(48), 0);
    unknown_cipher.cipher = 999_999;
    send_fake_legacy_ans_key(
        &mut fake_beta,
        &mut driver,
        unknown_cipher,
        "unknown cipher",
    )?;
    if command_available("tcpdump") {
        assert_underlay_ping_attempt_payload_not_plaintext_allow_empty(
            &ns_alpha,
            &veth_alpha,
            "10.109.2.1",
            &format!("{daemon_label} legacy bad ANS_KEY unknown cipher"),
            NoPlaintextCapture::TcpAndUdp,
            &cleanup,
        )?;
    }
    wait_for_node_status(&confdir, "beta", 0, (1 << 1) | (1 << 4), &cleanup)?;
    drop(fake_beta);

    let _ = run_rust_tincctl(&["tinc", "--config", confdir.to_str().unwrap(), "retry"])?;
    let (mut fake_beta, mut driver) = activate_fake_legacy_beta_for_bad_ans_key(
        &beta_listener,
        &cleanup,
        &confdir,
        &beta_rsa,
        &alpha_rsa_public,
        beta_port,
        alpha_port,
    )?;

    let mut unknown_digest = legacy_ans_key_message("beta", "alpha", "42".repeat(48), 0);
    unknown_digest.digest = 999_999;
    send_fake_legacy_ans_key(
        &mut fake_beta,
        &mut driver,
        unknown_digest,
        "unknown digest",
    )?;
    if command_available("tcpdump") {
        assert_underlay_ping_attempt_payload_not_plaintext_allow_empty(
            &ns_alpha,
            &veth_alpha,
            "10.109.2.1",
            &format!("{daemon_label} legacy bad ANS_KEY unknown digest"),
            NoPlaintextCapture::TcpAndUdp,
            &cleanup,
        )?;
    }
    wait_for_node_status(&confdir, "beta", 0, (1 << 1) | (1 << 4), &cleanup)?;
    drop(fake_beta);

    let _ = run_rust_tincctl(&["tinc", "--config", confdir.to_str().unwrap(), "retry"])?;
    let (mut fake_beta, mut driver) = activate_fake_legacy_beta_for_bad_ans_key(
        &beta_listener,
        &cleanup,
        &confdir,
        &beta_rsa,
        &alpha_rsa_public,
        beta_port,
        alpha_port,
    )?;

    let mut bogus_mac = legacy_ans_key_message("beta", "alpha", "42".repeat(48), 0);
    bogus_mac.mac_length = 99;
    send_fake_legacy_ans_key(&mut fake_beta, &mut driver, bogus_mac, "bogus MAC length")?;
    if command_available("tcpdump") {
        assert_underlay_ping_attempt_payload_not_plaintext_allow_empty(
            &ns_alpha,
            &veth_alpha,
            "10.109.2.1",
            &format!("{daemon_label} legacy bad ANS_KEY bogus MAC length"),
            NoPlaintextCapture::TcpAndUdp,
            &cleanup,
        )?;
    }
    wait_for_node_status(&confdir, "beta", 0, (1 << 1) | (1 << 4), &cleanup)?;

    let stop = run_rust_tincctl(&["tinc", "--config", confdir.to_str().unwrap(), "stop"]).map_err(
        |error| {
            format!(
                "Rust tincctl stop failed against {daemon_label} daemon: {error}\n{}",
                cleanup.logs()
            )
        },
    )?;
    assert!(stop.is_empty(), "unexpected stop output: {stop}");
    wait_for_child_exit(&mut cleanup, "alpha")?;

    Ok(())
}

fn run_legacy_unknown_compression_ans_key_daemon_injection(
    daemon_binary: &Path,
    daemon_label: &str,
    workspace_prefix: &str,
) -> Result<(), Box<dyn Error>> {
    let workspace = TempWorkspace::new(workspace_prefix)?;
    let suffix = unique_suffix();
    let ns_alpha = format!("tinc-bad-comp-a-{suffix}");
    let veth_alpha = format!("bck{suffix}a");
    let veth_beta = format!("bck{suffix}b");
    let alpha_port = 17372;
    let beta_listener = TcpListener::bind("0.0.0.0:0")?;
    beta_listener.set_nonblocking(true)?;
    let beta_port = beta_listener.local_addr()?.port();
    let alpha_rsa = RsaPrivateKey::new(&mut OsRng, 2048)?;
    let beta_rsa = RsaPrivateKey::new(&mut OsRng, 2048)?;
    let alpha_rsa_public = RsaPublicKey::from(&alpha_rsa);
    let beta_rsa_public = RsaPublicKey::from(&beta_rsa);
    let confdir = workspace.path().join("alpha");
    let mut cleanup = NetnsCleanup::new(workspace.path().to_path_buf());
    cleanup.add_namespace(ns_alpha.clone());
    cleanup.add_root_link(veth_beta.clone());

    create_legacy_node_config(
        &confdir,
        LegacyNodeConfig {
            name: "alpha",
            peer: "beta",
            port: alpha_port,
            bind_address: "192.0.2.31",
            peer_address: "192.0.2.32",
            peer_port: beta_port,
            interface: "tun-alpha",
            tunnel_address: "10.109.1.1/24",
            subnet: "10.109.1.0/24",
            peer_subnet: "10.109.2.0/24",
            connect_to_peer: true,
            private_key: &alpha_rsa,
            public_key: &alpha_rsa_public,
            peer_public_key: &beta_rsa_public,
            key_expire: None,
            fast_ping: false,
            legacy_crypto: LegacyCryptoConfig::default(),
        },
    )?;
    if !try_ip(&["netns", "add", &ns_alpha]) {
        eprintln!(
            "skipping {daemon_label} legacy unknown-compression ANS_KEY netns test: cannot create network namespace"
        );
        return Ok(());
    }
    run_ip(&[
        "link",
        "add",
        &veth_alpha,
        "type",
        "veth",
        "peer",
        "name",
        &veth_beta,
    ])?;
    run_ip(&["link", "set", &veth_alpha, "netns", &ns_alpha])?;
    run_ip(&["-n", &ns_alpha, "link", "set", "lo", "up"])?;
    run_ip(&[
        "-n",
        &ns_alpha,
        "addr",
        "add",
        "192.0.2.31/24",
        "dev",
        &veth_alpha,
    ])?;
    run_ip(&["-n", &ns_alpha, "link", "set", &veth_alpha, "up"])?;
    run_ip(&["addr", "add", "192.0.2.32/24", "dev", &veth_beta])?;
    run_ip(&["link", "set", &veth_beta, "up"])?;

    cleanup.spawn_with_binary(
        "alpha",
        daemon_binary,
        &confdir,
        &ns_alpha,
        &workspace.path().join("alpha.log"),
    )?;
    wait_for_control_socket(&confdir.join("pid.socket"), &cleanup)?;

    let (mut fake_beta, mut driver) = activate_fake_legacy_beta_for_bad_ans_key(
        &beta_listener,
        &cleanup,
        &confdir,
        &beta_rsa,
        &alpha_rsa_public,
        beta_port,
        alpha_port,
    )?;

    let valid_answer = legacy_ans_key_message("beta", "alpha", "42".repeat(48), 0);
    fake_beta.write_all(
        &driver
            .send_meta_message(&MetaMessage::AnswerKey(valid_answer))
            .map_err(|error| format!("could not encode valid ANS_KEY: {error}"))?,
    )?;
    fake_beta.flush()?;
    wait_for_node_status(&confdir, "beta", (1 << 4) | (1 << 1), 0, &cleanup)?;

    let unknown_compression_answer = legacy_ans_key_message("beta", "alpha", "24".repeat(48), 13);
    fake_beta.write_all(
        &driver
            .send_meta_message(&MetaMessage::AnswerKey(unknown_compression_answer))
            .map_err(|error| format!("could not encode unknown-compression ANS_KEY: {error}"))?,
    )?;
    fake_beta.flush()?;

    wait_for_node_status(&confdir, "beta", 1 << 4, 1 << 1, &cleanup)?;
    wait_for_log_contains(
        &cleanup,
        "alpha",
        &[
            "uses bogus compression level",
            "Compression level 13 is unrecognized by this node.",
        ],
        daemon_label,
    )?;

    fake_beta.write_all(
        &driver
            .send_meta_message(&MetaMessage::Ping)
            .map_err(|error| format!("could not encode post-unknown-compression ping: {error}"))?,
    )?;
    fake_beta.flush()?;
    let pong_events = read_fake_legacy_events_until(&mut fake_beta, &mut driver, |message| {
        matches!(message, MetaMessage::Pong)
    })?;
    assert!(
        pong_events
            .iter()
            .any(|message| matches!(message, MetaMessage::Pong)),
        "{daemon_label} daemon closed or stopped processing meta after unknown-compression ANS_KEY\n{}",
        cleanup.logs()
    );

    let stop = run_rust_tincctl(&["tinc", "--config", confdir.to_str().unwrap(), "stop"]).map_err(
        |error| {
            format!(
                "Rust tincctl stop failed against {daemon_label} daemon after unknown-compression ANS_KEY: {error}\n{}",
                cleanup.logs()
            )
        },
    )?;
    assert!(stop.is_empty(), "unexpected stop output: {stop}");
    wait_for_child_exit(&mut cleanup, "alpha")?;

    Ok(())
}

fn run_legacy_lzo_unavailable_ans_key_daemon_injection(
    daemon_binary: &Path,
    daemon_label: &str,
    workspace_prefix: &str,
) -> Result<(), Box<dyn Error>> {
    run_legacy_recoverable_compression_ans_key_daemon_injection(
        daemon_binary,
        daemon_label,
        workspace_prefix,
        "lzo-unavailable",
        CompressionLevel::LzoLow as i32,
        "LZO compression is unavailable on this node.",
    )
}

fn run_legacy_recoverable_compression_ans_key_daemon_injection(
    daemon_binary: &Path,
    daemon_label: &str,
    workspace_prefix: &str,
    case: &str,
    compression: i32,
    expected_log: &str,
) -> Result<(), Box<dyn Error>> {
    let workspace = TempWorkspace::new(workspace_prefix)?;
    let suffix = unique_suffix();
    let ns_alpha = format!("tinc-bad-comp-a-{suffix}");
    let veth_alpha = format!("bck{suffix}a");
    let veth_beta = format!("bck{suffix}b");
    let alpha_port = 17373;
    let beta_listener = TcpListener::bind("0.0.0.0:0")?;
    beta_listener.set_nonblocking(true)?;
    let beta_port = beta_listener.local_addr()?.port();
    let alpha_rsa = RsaPrivateKey::new(&mut OsRng, 2048)?;
    let beta_rsa = RsaPrivateKey::new(&mut OsRng, 2048)?;
    let alpha_rsa_public = RsaPublicKey::from(&alpha_rsa);
    let beta_rsa_public = RsaPublicKey::from(&beta_rsa);
    let confdir = workspace.path().join("alpha");
    let mut cleanup = NetnsCleanup::new(workspace.path().to_path_buf());
    cleanup.add_namespace(ns_alpha.clone());
    cleanup.add_root_link(veth_beta.clone());

    create_legacy_node_config(
        &confdir,
        LegacyNodeConfig {
            name: "alpha",
            peer: "beta",
            port: alpha_port,
            bind_address: "192.0.2.31",
            peer_address: "192.0.2.32",
            peer_port: beta_port,
            interface: "tun-alpha",
            tunnel_address: "10.109.1.1/24",
            subnet: "10.109.1.0/24",
            peer_subnet: "10.109.2.0/24",
            connect_to_peer: true,
            private_key: &alpha_rsa,
            public_key: &alpha_rsa_public,
            peer_public_key: &beta_rsa_public,
            key_expire: None,
            fast_ping: false,
            legacy_crypto: LegacyCryptoConfig::default(),
        },
    )?;
    if !try_ip(&["netns", "add", &ns_alpha]) {
        eprintln!(
            "skipping {daemon_label} legacy {case} ANS_KEY netns test: cannot create network namespace"
        );
        return Ok(());
    }
    run_ip(&[
        "link",
        "add",
        &veth_alpha,
        "type",
        "veth",
        "peer",
        "name",
        &veth_beta,
    ])?;
    run_ip(&["link", "set", &veth_alpha, "netns", &ns_alpha])?;
    run_ip(&["-n", &ns_alpha, "link", "set", "lo", "up"])?;
    run_ip(&[
        "-n",
        &ns_alpha,
        "addr",
        "add",
        "192.0.2.31/24",
        "dev",
        &veth_alpha,
    ])?;
    run_ip(&["-n", &ns_alpha, "link", "set", &veth_alpha, "up"])?;
    run_ip(&["addr", "add", "192.0.2.32/24", "dev", &veth_beta])?;
    run_ip(&["link", "set", &veth_beta, "up"])?;

    cleanup.spawn_with_binary(
        "alpha",
        daemon_binary,
        &confdir,
        &ns_alpha,
        &workspace.path().join("alpha.log"),
    )?;
    wait_for_control_socket(&confdir.join("pid.socket"), &cleanup)?;

    let (mut fake_beta, mut driver) = activate_fake_legacy_beta_for_bad_ans_key(
        &beta_listener,
        &cleanup,
        &confdir,
        &beta_rsa,
        &alpha_rsa_public,
        beta_port,
        alpha_port,
    )?;

    let valid_answer = legacy_ans_key_message("beta", "alpha", "42".repeat(48), 0);
    fake_beta.write_all(
        &driver
            .send_meta_message(&MetaMessage::AnswerKey(valid_answer))
            .map_err(|error| format!("could not encode valid ANS_KEY: {error}"))?,
    )?;
    fake_beta.flush()?;
    wait_for_node_status(&confdir, "beta", (1 << 4) | (1 << 1), 0, &cleanup)?;

    let bad_compression_answer =
        legacy_ans_key_message("beta", "alpha", "24".repeat(48), compression);
    fake_beta.write_all(
        &driver
            .send_meta_message(&MetaMessage::AnswerKey(bad_compression_answer))
            .map_err(|error| format!("could not encode {case} ANS_KEY: {error}"))?,
    )?;
    fake_beta.flush()?;

    wait_for_node_status(&confdir, "beta", 1 << 4, 1 << 1, &cleanup)?;
    wait_for_log_contains(
        &cleanup,
        "alpha",
        &["uses bogus compression level", expected_log],
        daemon_label,
    )?;

    fake_beta.write_all(
        &driver
            .send_meta_message(&MetaMessage::Ping)
            .map_err(|error| format!("could not encode post-{case} ping: {error}"))?,
    )?;
    fake_beta.flush()?;
    let pong_events = read_fake_legacy_events_until(&mut fake_beta, &mut driver, |message| {
        matches!(message, MetaMessage::Pong)
    })?;
    assert!(
        pong_events
            .iter()
            .any(|message| matches!(message, MetaMessage::Pong)),
        "{daemon_label} daemon closed or stopped processing meta after {case} ANS_KEY\n{}",
        cleanup.logs()
    );

    let stop = run_rust_tincctl(&["tinc", "--config", confdir.to_str().unwrap(), "stop"]).map_err(
        |error| {
            format!(
                "Rust tincctl stop failed against {daemon_label} daemon after {case} ANS_KEY: {error}\n{}",
                cleanup.logs()
            )
        },
    )?;
    assert!(stop.is_empty(), "unexpected stop output: {stop}");
    wait_for_child_exit(&mut cleanup, "alpha")?;

    Ok(())
}

fn run_legacy_dropped_req_key_retry_daemon_injection(
    daemon_binary: &Path,
    daemon_label: &str,
    workspace_prefix: &str,
    tunnel_server: bool,
) -> Result<(), Box<dyn Error>> {
    let workspace = TempWorkspace::new(workspace_prefix)?;
    let suffix = unique_suffix();
    let ns_alpha = format!("tinc-drop-req-a-{suffix}");
    let veth_alpha = format!("drk{suffix}a");
    let veth_beta = format!("drk{suffix}b");
    let alpha_port = 17371;
    let beta_listener = TcpListener::bind("0.0.0.0:0")?;
    beta_listener.set_nonblocking(true)?;
    let beta_port = beta_listener.local_addr()?.port();
    let alpha_rsa = RsaPrivateKey::new(&mut OsRng, 2048)?;
    let beta_rsa = RsaPrivateKey::new(&mut OsRng, 2048)?;
    let alpha_rsa_public = RsaPublicKey::from(&alpha_rsa);
    let beta_rsa_public = RsaPublicKey::from(&beta_rsa);
    let confdir = workspace.path().join("alpha");
    let mut cleanup = NetnsCleanup::new(workspace.path().to_path_buf());
    cleanup.add_namespace(ns_alpha.clone());
    cleanup.add_root_link(veth_beta.clone());

    create_legacy_node_config(
        &confdir,
        LegacyNodeConfig {
            name: "alpha",
            peer: "beta",
            port: alpha_port,
            bind_address: "192.0.2.41",
            peer_address: "192.0.2.42",
            peer_port: beta_port,
            interface: "tun-alpha",
            tunnel_address: "10.110.1.1/24",
            subnet: "10.110.1.0/24",
            peer_subnet: "10.110.2.0/24",
            connect_to_peer: true,
            private_key: &alpha_rsa,
            public_key: &alpha_rsa_public,
            peer_public_key: &beta_rsa_public,
            key_expire: None,
            fast_ping: false,
            legacy_crypto: LegacyCryptoConfig::default(),
        },
    )?;
    if tunnel_server {
        fs::OpenOptions::new()
            .append(true)
            .open(confdir.join("tinc.conf"))?
            .write_all(b"TunnelServer = yes\n")?;
    }
    if !try_ip(&["netns", "add", &ns_alpha]) {
        eprintln!(
            "skipping {daemon_label} legacy dropped REQ_KEY netns test: cannot create network namespace"
        );
        return Ok(());
    }
    run_ip(&[
        "link",
        "add",
        &veth_alpha,
        "type",
        "veth",
        "peer",
        "name",
        &veth_beta,
    ])?;
    run_ip(&["link", "set", &veth_alpha, "netns", &ns_alpha])?;
    run_ip(&["-n", &ns_alpha, "link", "set", "lo", "up"])?;
    run_ip(&[
        "-n",
        &ns_alpha,
        "addr",
        "add",
        "192.0.2.41/24",
        "dev",
        &veth_alpha,
    ])?;
    run_ip(&["-n", &ns_alpha, "link", "set", &veth_alpha, "up"])?;
    run_ip(&["addr", "add", "192.0.2.42/24", "dev", &veth_beta])?;
    run_ip(&["link", "set", &veth_beta, "up"])?;

    cleanup.spawn_with_binary(
        "alpha",
        daemon_binary,
        &confdir,
        &ns_alpha,
        &workspace.path().join("alpha.log"),
    )?;
    wait_for_control_socket(&confdir.join("pid.socket"), &cleanup)?;

    let (mut fake_beta, mut driver) = activate_fake_legacy_beta_for_bad_ans_key(
        &beta_listener,
        &cleanup,
        &confdir,
        &beta_rsa,
        &alpha_rsa_public,
        beta_port,
        alpha_port,
    )?;

    let mut first_events = Vec::new();
    if command_available("tcpdump") {
        let payload = assert_underlay_ping_attempt_payload_not_plaintext(
            &ns_alpha,
            &veth_alpha,
            "10.110.2.1",
            &format!("{daemon_label} legacy missing-key TCP fallback before REQ_KEY retry"),
            NoPlaintextCapture::TcpAndUdp,
            &cleanup,
        )?;
        let tcp_events =
            read_fake_legacy_meta_events_until(&mut fake_beta, &mut driver, |event| {
                matches!(
                    event,
                    tinc_runtime::meta::MetaConnectionEvent::TcpPacket(packet)
                        if contains_subslice(packet, payload.as_bytes())
                )
            })?;
        assert!(
            tcp_events.iter().any(|event| matches!(
                event,
                tinc_runtime::meta::MetaConnectionEvent::TcpPacket(packet)
                    if contains_subslice(packet, payload.as_bytes())
            )),
            "{daemon_label} daemon did not forward the missing-key fallback ping as a C-style meta PACKET body\n{}",
            cleanup.logs()
        );
        first_events.extend(tcp_events.into_iter().filter_map(|event| match event {
            tinc_runtime::meta::MetaConnectionEvent::Message(message) => Some(message),
            _ => None,
        }));
    } else {
        trigger_ping_without_wait(&ns_alpha, "10.110.2.1")?;
    }
    let is_initial_req_key = |message: &MetaMessage| {
        matches!(
            message,
            MetaMessage::RequestKey(request)
                if request.from == "alpha" && request.to == "beta" && request.extension.is_none()
        )
    };
    if !first_events.iter().any(is_initial_req_key) {
        first_events.extend(
            read_fake_legacy_events_until(&mut fake_beta, &mut driver, is_initial_req_key)
                .map_err(|error| {
                    format!(
                        "{daemon_label} daemon did not emit initial legacy REQ_KEY after missing-key fallback: {error}\n{}",
                        cleanup.logs()
                    )
                })?,
        );
    }
    assert!(
        first_events.iter().any(|message| matches!(
            message,
            MetaMessage::RequestKey(request)
                if request.from == "alpha" && request.to == "beta" && request.extension.is_none()
        )),
        "{daemon_label} daemon did not send the initial legacy REQ_KEY after TCP fallback\n{}",
        cleanup.logs()
    );
    wait_for_node_status(&confdir, "beta", 1 << 4, 1 << 1, &cleanup)?;

    trigger_ping_without_wait(&ns_alpha, "10.110.2.1")?;
    let early_retry =
        read_fake_legacy_events_for_duration(&mut fake_beta, &mut driver, Duration::from_secs(2))?;
    assert!(
        !early_retry.iter().any(|message| matches!(
            message,
            MetaMessage::RequestKey(request)
                if request.from == "alpha" && request.to == "beta" && request.extension.is_none()
        )),
        "{daemon_label} daemon retransmitted legacy REQ_KEY before C try_tx_legacy() 10s gate\n{}",
        cleanup.logs()
    );

    let retry_deadline = Instant::now() + Duration::from_secs(14);
    let mut retry_events = Vec::new();
    while Instant::now() < retry_deadline {
        cleanup.ensure_children_alive()?;
        trigger_ping_without_wait(&ns_alpha, "10.110.2.1")?;
        retry_events.extend(read_fake_legacy_events_for_duration(
            &mut fake_beta,
            &mut driver,
            Duration::from_millis(700),
        )?);
        if retry_events.iter().any(|message| matches!(
            message,
            MetaMessage::RequestKey(request)
                if request.from == "alpha" && request.to == "beta" && request.extension.is_none()
        )) {
            break;
        }
    }
    assert!(
        retry_events.iter().any(|message| matches!(
            message,
            MetaMessage::RequestKey(request)
                if request.from == "alpha" && request.to == "beta" && request.extension.is_none()
        )),
        "{daemon_label} daemon did not retry dropped legacy REQ_KEY after C 10s gate\n{}",
        cleanup.logs()
    );

    let valid_answer = legacy_ans_key_message("beta", "alpha", "42".repeat(48), 0);
    send_fake_legacy_ans_key(&mut fake_beta, &mut driver, valid_answer, "retry recovery")?;
    wait_for_node_status(&confdir, "beta", (1 << 4) | (1 << 1), 0, &cleanup)?;

    let stop = run_rust_tincctl(&["tinc", "--config", confdir.to_str().unwrap(), "stop"]).map_err(
        |error| {
            format!(
                "Rust tincctl stop failed against {daemon_label} daemon after legacy REQ_KEY retry test: {error}\n{}",
                cleanup.logs()
            )
        },
    )?;
    assert!(stop.is_empty(), "unexpected stop output: {stop}");
    wait_for_child_exit(&mut cleanup, "alpha")?;

    Ok(())
}

fn run_legacy_udp_replay_daemon_injection(
    daemon_binary: &Path,
    daemon_label: &str,
    workspace_prefix: &str,
) -> Result<(), Box<dyn Error>> {
    let workspace = TempWorkspace::new(workspace_prefix)?;
    let suffix = unique_suffix();
    let ns_alpha = format!("tinc-udp-replay-a-{suffix}");
    let veth_alpha = format!("lur{suffix}a");
    let veth_beta = format!("lur{suffix}b");
    let alpha_port = 17372;
    let beta_listener = TcpListener::bind("0.0.0.0:0")?;
    beta_listener.set_nonblocking(true)?;
    let beta_tcp_port = beta_listener.local_addr()?.port();
    let beta_udp = UdpSocket::bind(("0.0.0.0", beta_tcp_port))?;
    beta_udp.set_read_timeout(Some(Duration::from_millis(200)))?;
    let beta_udp_port = beta_udp.local_addr()?.port();
    let alpha_rsa = RsaPrivateKey::new(&mut OsRng, 2048)?;
    let beta_rsa = RsaPrivateKey::new(&mut OsRng, 2048)?;
    let alpha_rsa_public = RsaPublicKey::from(&alpha_rsa);
    let beta_rsa_public = RsaPublicKey::from(&beta_rsa);
    let confdir = workspace.path().join("alpha");
    let mut cleanup = NetnsCleanup::new(workspace.path().to_path_buf());
    cleanup.add_namespace(ns_alpha.clone());
    cleanup.add_root_link(veth_beta.clone());

    create_legacy_node_config(
        &confdir,
        LegacyNodeConfig {
            name: "alpha",
            peer: "beta",
            port: alpha_port,
            bind_address: "192.0.2.51",
            peer_address: "192.0.2.52",
            peer_port: beta_tcp_port,
            interface: "tun-alpha",
            tunnel_address: "10.111.1.1/24",
            subnet: "10.111.1.0/24",
            peer_subnet: "10.111.2.0/24",
            connect_to_peer: true,
            private_key: &alpha_rsa,
            public_key: &alpha_rsa_public,
            peer_public_key: &beta_rsa_public,
            key_expire: None,
            fast_ping: false,
            legacy_crypto: LegacyCryptoConfig::default(),
        },
    )?;
    fs::OpenOptions::new()
        .append(true)
        .open(confdir.join("tinc.conf"))?
        .write_all(b"ReplayWindow = 4\n")?;

    if !try_ip(&["netns", "add", &ns_alpha]) {
        eprintln!(
            "skipping {daemon_label} legacy UDP replay netns test: cannot create network namespace"
        );
        return Ok(());
    }
    run_ip(&[
        "link",
        "add",
        &veth_alpha,
        "type",
        "veth",
        "peer",
        "name",
        &veth_beta,
    ])?;
    run_ip(&["link", "set", &veth_alpha, "netns", &ns_alpha])?;
    run_ip(&["-n", &ns_alpha, "link", "set", "lo", "up"])?;
    run_ip(&[
        "-n",
        &ns_alpha,
        "addr",
        "add",
        "192.0.2.51/24",
        "dev",
        &veth_alpha,
    ])?;
    run_ip(&["-n", &ns_alpha, "link", "set", &veth_alpha, "up"])?;
    run_ip(&["addr", "add", "192.0.2.52/24", "dev", &veth_beta])?;
    run_ip(&["link", "set", &veth_beta, "up"])?;

    cleanup.spawn_with_binary(
        "alpha",
        daemon_binary,
        &confdir,
        &ns_alpha,
        &workspace.path().join("alpha.log"),
    )?;
    wait_for_control_socket(&confdir.join("pid.socket"), &cleanup)?;

    let mut fake_beta = wait_for_fake_legacy_connection(&beta_listener, &cleanup)?;
    fake_beta.set_read_timeout(Some(Duration::from_secs(3)))?;
    fake_beta.set_write_timeout(Some(Duration::from_secs(3)))?;
    let mut driver = activate_fake_legacy_peer(
        &mut fake_beta,
        "beta",
        "alpha",
        &beta_rsa,
        &alpha_rsa_public,
        beta_tcp_port,
    )?;
    send_fake_legacy_add_edge(
        &mut fake_beta,
        &mut driver,
        "beta",
        "alpha",
        "192.0.2.51",
        alpha_port,
        "192.0.2.52",
        beta_udp_port,
    )?;
    wait_for_node_status(&confdir, "beta", 1 << 4, 1 << 1, &cleanup)?;

    fake_beta.write_all(
        &driver
            .send_meta_message(&MetaMessage::RequestKey(
                tinc_core::protocol::RequestKeyMessage::new("beta", "alpha"),
            ))
            .map_err(|error| format!("could not encode fake beta REQ_KEY: {error}"))?,
    )?;
    fake_beta.flush()?;
    let mut answer_events =
        read_fake_legacy_events_until(&mut fake_beta, &mut driver, |message| {
            matches!(
                message,
                MetaMessage::AnswerKey(answer) if answer.from == "alpha" && answer.to == "beta"
            )
        })?;
    answer_events.extend(read_fake_legacy_events_for_duration(
        &mut fake_beta,
        &mut driver,
        Duration::from_millis(500),
    )?);
    let Some(answer) = answer_events
        .into_iter()
        .rev()
        .find_map(|message| match message {
            MetaMessage::AnswerKey(answer) if answer.from == "alpha" && answer.to == "beta" => {
                Some(answer)
            }
            _ => None,
        })
    else {
        return Err(format!(
            "{daemon_label} daemon did not answer fake beta legacy REQ_KEY\n{}",
            cleanup.logs()
        )
        .into());
    };

    let mut beta_codec = LegacyUdpCodec::default();
    beta_codec.insert_peer(
        "alpha",
        LegacyPeerState::from_legacy_answer_key(&answer, 4).map_err(|error| {
            format!("could not install alpha ANS_KEY in fake beta codec: {error}")
        })?,
    );
    let alpha_udp = "192.0.2.51:17372";
    let packet_one = legacy_udp_replay_test_packet([10, 111, 1, 101])?;
    let datagram_one = beta_codec.encode("alpha", &packet_one)?;
    beta_udp.send_to(&datagram_one, alpha_udp)?;
    wait_for_traffic_counters(&confdir, "beta", 1, packet_one.len() as u64, &cleanup)?;

    beta_udp.send_to(&datagram_one, alpha_udp)?;
    assert_traffic_counters_stay(
        &confdir,
        "beta",
        1,
        packet_one.len() as u64,
        Duration::from_secs(2),
        &cleanup,
        &format!("{daemon_label} daemon accepted replayed legacy UDP seqno 1"),
    )?;

    let packet_two = legacy_udp_replay_test_packet([10, 111, 1, 102])?;
    let datagram_two = beta_codec.encode("alpha", &packet_two)?;
    let packet_three = legacy_udp_replay_test_packet([10, 111, 1, 103])?;
    let datagram_three = beta_codec.encode("alpha", &packet_three)?;
    beta_udp.send_to(&datagram_three, alpha_udp)?;
    wait_for_traffic_counters(
        &confdir,
        "beta",
        2,
        (packet_one.len() + packet_three.len()) as u64,
        &cleanup,
    )?;
    beta_udp.send_to(&datagram_two, alpha_udp)?;
    wait_for_traffic_counters(
        &confdir,
        "beta",
        3,
        (packet_one.len() + packet_three.len() + packet_two.len()) as u64,
        &cleanup,
    )?;
    beta_udp.send_to(&datagram_two, alpha_udp)?;
    assert_traffic_counters_stay(
        &confdir,
        "beta",
        3,
        (packet_one.len() + packet_three.len() + packet_two.len()) as u64,
        Duration::from_secs(2),
        &cleanup,
        &format!("{daemon_label} daemon accepted replayed late legacy UDP seqno 2"),
    )?;

    for filler in 4..35 {
        let packet = legacy_udp_replay_test_packet([10, 111, 1, filler as u8])?;
        let _ = beta_codec.encode("alpha", &packet)?;
    }
    let far_packet = legacy_udp_replay_test_packet([10, 111, 1, 200])?;
    let far_datagram = beta_codec.encode("alpha", &far_packet)?;
    beta_udp.send_to(&far_datagram, alpha_udp)?;
    assert_traffic_counters_stay(
        &confdir,
        "beta",
        3,
        (packet_one.len() + packet_three.len() + packet_two.len()) as u64,
        Duration::from_secs(2),
        &cleanup,
        &format!("{daemon_label} daemon accepted far-future legacy UDP seqno"),
    )?;

    let stop = run_rust_tincctl(&["tinc", "--config", confdir.to_str().unwrap(), "stop"]).map_err(
        |error| {
            format!(
                "Rust tincctl stop failed against {daemon_label} daemon after legacy UDP replay test: {error}\n{}",
                cleanup.logs()
            )
        },
    )?;
    assert!(stop.is_empty(), "unexpected stop output: {stop}");
    wait_for_child_exit(&mut cleanup, "alpha")?;

    Ok(())
}

#[test]
fn linux_netns_c_tincctl_dumps_rust_tincd_legacy_status_topology() -> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!("skipping C tincctl/Rust tincd legacy dump interop test: Linux-only test");
        return Ok(());
    }
    if !command_available("ip") || !command_available("ping") {
        eprintln!(
            "skipping C tincctl/Rust tincd legacy dump interop test: missing ip or ping command"
        );
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!(
            "skipping C tincctl/Rust tincd legacy dump interop test: /dev/net/tun is not available"
        );
        return Ok(());
    }

    let Some(c_tincd) = c_tincd_binary() else {
        eprintln!(
            "skipping C tincctl/Rust tincd legacy dump interop test: set C_TINCD_PATH or build vendor/tinc/build-c/src/tincd"
        );
        return Ok(());
    };
    let Some(c_tinc) = c_tinc_binary() else {
        eprintln!(
            "skipping C tincctl/Rust tincd legacy dump interop test: set C_TINC_PATH or build vendor/tinc/build-c/src/tinc"
        );
        return Ok(());
    };

    run_c_rust_two_node_legacy_tun_interop_with_options_and_c_tinc(
        &c_tincd, &c_tinc, true, false, false,
    )?;
    run_c_rust_two_node_legacy_tun_interop_with_options_and_c_tinc(
        &c_tincd, &c_tinc, false, false, false,
    )?;

    Ok(())
}

#[test]
fn linux_netns_c_and_rust_legacy_tincd_nodes_route_indirect_multihop_over_tun()
-> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!("skipping C/Rust legacy multihop netns interop test: Linux-only test");
        return Ok(());
    }
    if !command_available("ip") || !command_available("ping") {
        eprintln!("skipping C/Rust legacy multihop netns interop test: missing ip or ping command");
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!(
            "skipping C/Rust legacy multihop netns interop test: /dev/net/tun is not available"
        );
        return Ok(());
    }

    let Some(c_tincd) = c_tincd_binary() else {
        eprintln!(
            "skipping C/Rust legacy multihop netns interop test: set C_TINCD_PATH or build vendor/tinc/build-c/src/tincd"
        );
        return Ok(());
    };

    run_c_rust_three_node_legacy_indirect_multihop_interop(&c_tincd, true)?;
    run_c_rust_three_node_legacy_indirect_multihop_interop(&c_tincd, false)?;

    Ok(())
}

#[test]
fn linux_netns_c_and_rust_legacy_static_relay_udp_discovery_pmtu_like_tinc()
-> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!(
            "skipping C/Rust legacy static relay UDP discovery netns interop test: Linux-only test"
        );
        return Ok(());
    }
    if !command_available("ip") || !command_available("ping") {
        eprintln!(
            "skipping C/Rust legacy static relay UDP discovery netns interop test: missing ip or ping command"
        );
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!(
            "skipping C/Rust legacy static relay UDP discovery netns interop test: /dev/net/tun is not available"
        );
        return Ok(());
    }

    let Some(c_tincd) = c_tincd_binary() else {
        eprintln!(
            "skipping C/Rust legacy static relay UDP discovery netns interop test: set C_TINCD_PATH or build vendor/tinc/build-c/src/tincd"
        );
        return Ok(());
    };

    run_c_rust_three_node_legacy_indirect_multihop_interop_with_options(
        &c_tincd, true, true, None, false,
    )?;
    run_c_rust_three_node_legacy_indirect_multihop_interop_with_options(
        &c_tincd, false, true, None, false,
    )?;

    Ok(())
}

#[test]
fn linux_netns_c_and_rust_legacy_tincd_nodes_use_dynamic_relay_over_tun()
-> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!("skipping C/Rust legacy dynamic relay netns interop test: Linux-only test");
        return Ok(());
    }
    if !command_available("ip") || !command_available("ping") {
        eprintln!(
            "skipping C/Rust legacy dynamic relay netns interop test: missing ip or ping command"
        );
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!(
            "skipping C/Rust legacy dynamic relay netns interop test: /dev/net/tun is not available"
        );
        return Ok(());
    }

    let Some(c_tincd) = c_tincd_binary() else {
        eprintln!(
            "skipping C/Rust legacy dynamic relay netns interop test: set C_TINCD_PATH or build vendor/tinc/build-c/src/tincd"
        );
        return Ok(());
    };

    run_c_rust_three_node_legacy_dynamic_relay_interop(&c_tincd, true)?;
    run_c_rust_three_node_legacy_dynamic_relay_interop(&c_tincd, false)?;

    Ok(())
}

#[test]
fn linux_netns_c_and_rust_legacy_dynamic_relay_udp_discovery_pmtu_like_tinc()
-> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!(
            "skipping C/Rust legacy dynamic relay UDP discovery netns interop test: Linux-only test"
        );
        return Ok(());
    }
    if !command_available("ip") || !command_available("ping") {
        eprintln!(
            "skipping C/Rust legacy dynamic relay UDP discovery netns interop test: missing ip or ping command"
        );
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!(
            "skipping C/Rust legacy dynamic relay UDP discovery netns interop test: /dev/net/tun is not available"
        );
        return Ok(());
    }

    let Some(c_tincd) = c_tincd_binary() else {
        eprintln!(
            "skipping C/Rust legacy dynamic relay UDP discovery netns interop test: set C_TINCD_PATH or build vendor/tinc/build-c/src/tincd"
        );
        return Ok(());
    };

    run_c_rust_three_node_legacy_dynamic_relay_interop_with_options(
        &c_tincd, true, true, None, false,
    )?;
    run_c_rust_three_node_legacy_dynamic_relay_interop_with_options(
        &c_tincd, false, true, None, false,
    )?;

    Ok(())
}

#[test]
fn linux_netns_c_tincctl_dumps_rust_tincd_legacy_multihop_status_topology()
-> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!(
            "skipping C tincctl/Rust tincd legacy multihop dump interop test: Linux-only test"
        );
        return Ok(());
    }
    if !command_available("ip") || !command_available("ping") {
        eprintln!(
            "skipping C tincctl/Rust tincd legacy multihop dump interop test: missing ip or ping command"
        );
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!(
            "skipping C tincctl/Rust tincd legacy multihop dump interop test: /dev/net/tun is not available"
        );
        return Ok(());
    }

    let Some(c_tinc) = c_tinc_binary() else {
        eprintln!(
            "skipping C tincctl/Rust tincd legacy multihop dump interop test: set C_TINC_PATH or build vendor/tinc/build-c/src/tinc"
        );
        return Ok(());
    };

    run_c_tincctl_rust_tincd_legacy_multihop_status_topology(&c_tinc)
}

#[test]
fn linux_netns_c_tincctl_dumps_rust_tincd_legacy_dynamic_relay_status_topology()
-> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!(
            "skipping C tincctl/Rust tincd legacy dynamic relay dump interop test: Linux-only test"
        );
        return Ok(());
    }
    if !command_available("ip") || !command_available("ping") {
        eprintln!(
            "skipping C tincctl/Rust tincd legacy dynamic relay dump interop test: missing ip or ping command"
        );
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!(
            "skipping C tincctl/Rust tincd legacy dynamic relay dump interop test: /dev/net/tun is not available"
        );
        return Ok(());
    }

    let Some(c_tinc) = c_tinc_binary() else {
        eprintln!(
            "skipping C tincctl/Rust tincd legacy dynamic relay dump interop test: set C_TINC_PATH or build vendor/tinc/build-c/src/tinc"
        );
        return Ok(());
    };

    run_c_tincctl_rust_tincd_legacy_dynamic_relay_status_topology(&c_tinc)
}

#[test]
fn linux_netns_c_and_rust_modern_tincd_nodes_route_indirect_multihop_over_tun()
-> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!("skipping C/Rust modern multihop netns interop test: Linux-only test");
        return Ok(());
    }
    if !command_available("ip") || !command_available("ping") {
        eprintln!("skipping C/Rust modern multihop netns interop test: missing ip or ping command");
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!(
            "skipping C/Rust modern multihop netns interop test: /dev/net/tun is not available"
        );
        return Ok(());
    }

    let Some(c_tincd) = c_tincd_binary() else {
        eprintln!(
            "skipping C/Rust modern multihop netns interop test: set C_TINCD_PATH or build vendor/tinc/build-c/src/tincd"
        );
        return Ok(());
    };

    run_c_rust_three_node_modern_indirect_multihop_interop(&c_tincd, true)?;
    run_c_rust_three_node_modern_indirect_multihop_interop(&c_tincd, false)?;

    Ok(())
}

#[test]
fn linux_netns_c_and_rust_modern_static_relay_udp_discovery_pmtu_like_tinc()
-> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!(
            "skipping C/Rust modern static relay UDP discovery netns interop test: Linux-only test"
        );
        return Ok(());
    }
    if !command_available("ip") || !command_available("ping") {
        eprintln!(
            "skipping C/Rust modern static relay UDP discovery netns interop test: missing ip or ping command"
        );
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!(
            "skipping C/Rust modern static relay UDP discovery netns interop test: /dev/net/tun is not available"
        );
        return Ok(());
    }

    let Some(c_tincd) = c_tincd_binary() else {
        eprintln!(
            "skipping C/Rust modern static relay UDP discovery netns interop test: set C_TINCD_PATH or build vendor/tinc/build-c/src/tincd"
        );
        return Ok(());
    };

    run_c_rust_three_node_modern_indirect_multihop_interop_with_options(
        &c_tincd, true, true, None, false,
    )?;
    run_c_rust_three_node_modern_indirect_multihop_interop_with_options(
        &c_tincd, false, true, None, false,
    )?;

    Ok(())
}

#[test]
fn linux_netns_c_and_rust_modern_tincd_nodes_use_dynamic_relay_over_tun()
-> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!("skipping C/Rust modern dynamic relay netns interop test: Linux-only test");
        return Ok(());
    }
    if !command_available("ip") || !command_available("ping") {
        eprintln!(
            "skipping C/Rust modern dynamic relay netns interop test: missing ip or ping command"
        );
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!(
            "skipping C/Rust modern dynamic relay netns interop test: /dev/net/tun is not available"
        );
        return Ok(());
    }

    let Some(c_tincd) = c_tincd_binary() else {
        eprintln!(
            "skipping C/Rust modern dynamic relay netns interop test: set C_TINCD_PATH or build vendor/tinc/build-c/src/tincd"
        );
        return Ok(());
    };

    run_c_rust_three_node_modern_dynamic_relay_interop(&c_tincd, true)?;
    run_c_rust_three_node_modern_dynamic_relay_interop(&c_tincd, false)?;

    Ok(())
}

#[test]
fn linux_netns_c_and_rust_modern_dynamic_relay_udp_discovery_pmtu_like_tinc()
-> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!(
            "skipping C/Rust modern dynamic relay UDP discovery netns interop test: Linux-only test"
        );
        return Ok(());
    }
    if !command_available("ip") || !command_available("ping") {
        eprintln!(
            "skipping C/Rust modern dynamic relay UDP discovery netns interop test: missing ip or ping command"
        );
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!(
            "skipping C/Rust modern dynamic relay UDP discovery netns interop test: /dev/net/tun is not available"
        );
        return Ok(());
    }

    let Some(c_tincd) = c_tincd_binary() else {
        eprintln!(
            "skipping C/Rust modern dynamic relay UDP discovery netns interop test: set C_TINCD_PATH or build vendor/tinc/build-c/src/tincd"
        );
        return Ok(());
    };

    run_c_rust_three_node_modern_dynamic_relay_interop_with_options(
        &c_tincd, true, true, None, false,
    )?;
    run_c_rust_three_node_modern_dynamic_relay_interop_with_options(
        &c_tincd, false, true, None, false,
    )?;

    Ok(())
}

#[test]
fn linux_netns_c_and_rust_modern_emsgsize_reduces_pmtu_like_tinc() -> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!("skipping C/Rust modern EMSGSIZE PMTU netns interop test: Linux-only test");
        return Ok(());
    }
    if !command_available("ip") || !command_available("ping") {
        eprintln!(
            "skipping C/Rust modern EMSGSIZE PMTU netns interop test: missing ip or ping command"
        );
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!(
            "skipping C/Rust modern EMSGSIZE PMTU netns interop test: /dev/net/tun is not available"
        );
        return Ok(());
    }

    let Some(c_tincd) = c_tincd_binary() else {
        eprintln!(
            "skipping C/Rust modern EMSGSIZE PMTU netns interop test: set C_TINCD_PATH or build vendor/tinc/build-c/src/tincd"
        );
        return Ok(());
    };

    run_c_rust_two_node_modern_emsgsize_pmtu_reduce(&c_tincd, true)?;
    run_c_rust_two_node_modern_emsgsize_pmtu_reduce(&c_tincd, false)?;

    Ok(())
}

#[test]
fn linux_netns_c_and_rust_strict_subnets_forwards_but_ignores_unauthorized_subnet()
-> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!("skipping C/Rust strict subnet netns interop test: Linux-only test");
        return Ok(());
    }
    if !command_available("ip") || !command_available("ping") {
        eprintln!("skipping C/Rust strict subnet netns interop test: missing ip or ping command");
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!(
            "skipping C/Rust strict subnet netns interop test: /dev/net/tun is not available"
        );
        return Ok(());
    }

    let Some(c_tincd) = c_tincd_binary() else {
        eprintln!(
            "skipping C/Rust strict subnet netns interop test: set C_TINCD_PATH or build vendor/tinc/build-c/src/tincd"
        );
        return Ok(());
    };

    run_c_rust_strict_subnet_forward_interop(&c_tincd)?;

    Ok(())
}

#[test]
fn linux_netns_c_and_rust_tunnel_server_isolates_clients_over_tun() -> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!("skipping C/Rust tunnel server netns interop test: Linux-only test");
        return Ok(());
    }
    if !command_available("ip") || !command_available("ping") {
        eprintln!("skipping C/Rust tunnel server netns interop test: missing ip or ping command");
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!(
            "skipping C/Rust tunnel server netns interop test: /dev/net/tun is not available"
        );
        return Ok(());
    }

    let Some(c_tincd) = c_tincd_binary() else {
        eprintln!(
            "skipping C/Rust tunnel server netns interop test: set C_TINCD_PATH or build vendor/tinc/build-c/src/tincd"
        );
        return Ok(());
    };

    run_c_rust_tunnel_server_interop(&c_tincd, true)?;
    run_c_rust_tunnel_server_interop(&c_tincd, false)?;

    Ok(())
}

#[test]
fn linux_netns_c_and_rust_tunnel_server_udp_discovery_pmtu_like_tinc() -> Result<(), Box<dyn Error>>
{
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!(
            "skipping C/Rust tunnel server UDP discovery netns interop test: Linux-only test"
        );
        return Ok(());
    }
    if !command_available("ip") || !command_available("ping") {
        eprintln!(
            "skipping C/Rust tunnel server UDP discovery netns interop test: missing ip or ping command"
        );
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!(
            "skipping C/Rust tunnel server UDP discovery netns interop test: /dev/net/tun is not available"
        );
        return Ok(());
    }

    let Some(c_tincd) = c_tincd_binary() else {
        eprintln!(
            "skipping C/Rust tunnel server UDP discovery netns interop test: set C_TINCD_PATH or build vendor/tinc/build-c/src/tincd"
        );
        return Ok(());
    };

    run_c_rust_tunnel_server_interop_with_options(&c_tincd, true, false, false, false, true, None)?;
    run_c_rust_tunnel_server_interop_with_options(
        &c_tincd, false, false, false, false, true, None,
    )?;

    Ok(())
}

#[test]
fn linux_netns_c_and_rust_tunnel_server_client_restart_keeps_isolation()
-> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!("skipping C/Rust tunnel server restart netns interop test: Linux-only test");
        return Ok(());
    }
    if !command_available("ip") || !command_available("ping") {
        eprintln!(
            "skipping C/Rust tunnel server restart netns interop test: missing ip or ping command"
        );
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!(
            "skipping C/Rust tunnel server restart netns interop test: /dev/net/tun is not available"
        );
        return Ok(());
    }

    let Some(c_tincd) = c_tincd_binary() else {
        eprintln!(
            "skipping C/Rust tunnel server restart netns interop test: set C_TINCD_PATH or build vendor/tinc/build-c/src/tincd"
        );
        return Ok(());
    };

    run_c_rust_tunnel_server_interop_with_options(&c_tincd, true, true, false, false, false, None)?;
    run_c_rust_tunnel_server_interop_with_options(
        &c_tincd, false, true, false, false, false, None,
    )?;

    Ok(())
}

#[test]
fn linux_netns_c_and_rust_tunnel_server_client_restart_does_not_leak_plain_udp_payload_like_tinc()
-> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!(
            "skipping C/Rust tunnel server restart no-plaintext netns interop test: Linux-only test"
        );
        return Ok(());
    }
    if !command_available("ip") || !command_available("ping") || !command_available("tcpdump") {
        eprintln!(
            "skipping C/Rust tunnel server restart no-plaintext netns interop test: missing ip, ping, or tcpdump command"
        );
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!(
            "skipping C/Rust tunnel server restart no-plaintext netns interop test: /dev/net/tun is not available"
        );
        return Ok(());
    }

    let Some(c_tincd) = c_tincd_binary() else {
        eprintln!(
            "skipping C/Rust tunnel server restart no-plaintext netns interop test: set C_TINCD_PATH or build vendor/tinc/build-c/src/tincd"
        );
        return Ok(());
    };

    run_c_rust_tunnel_server_interop_with_options(
        &c_tincd,
        true,
        true,
        false,
        false,
        false,
        Some(NoPlaintextCapture::Udp),
    )?;
    run_c_rust_tunnel_server_interop_with_options(
        &c_tincd,
        false,
        true,
        false,
        false,
        false,
        Some(NoPlaintextCapture::Udp),
    )?;
    run_c_rust_legacy_tunnel_server_interop_with_options(
        &c_tincd,
        true,
        true,
        false,
        false,
        false,
        false,
        Some(NoPlaintextCapture::Udp),
    )?;
    run_c_rust_legacy_tunnel_server_interop_with_options(
        &c_tincd,
        false,
        true,
        false,
        false,
        false,
        false,
        Some(NoPlaintextCapture::Udp),
    )?;

    Ok(())
}

#[test]
fn linux_netns_c_and_rust_tunnel_server_recovers_after_underlay_udp_loss_like_tinc()
-> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!("skipping C/Rust tunnel server UDP loss netns interop test: Linux-only test");
        return Ok(());
    }
    if !command_available("ip") || !command_available("ping") {
        eprintln!(
            "skipping C/Rust tunnel server UDP loss netns interop test: missing ip or ping command"
        );
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!(
            "skipping C/Rust tunnel server UDP loss netns interop test: /dev/net/tun is not available"
        );
        return Ok(());
    }

    let Some(c_tincd) = c_tincd_binary() else {
        eprintln!(
            "skipping C/Rust tunnel server UDP loss netns interop test: set C_TINCD_PATH or build vendor/tinc/build-c/src/tincd"
        );
        return Ok(());
    };

    run_c_rust_tunnel_server_interop_with_options(&c_tincd, true, false, true, false, false, None)?;
    run_c_rust_tunnel_server_interop_with_options(
        &c_tincd, false, false, true, false, false, None,
    )?;

    Ok(())
}

#[test]
fn linux_netns_c_and_rust_tunnel_server_recovers_after_client_meta_timeout_loss_like_tinc()
-> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!("skipping C/Rust tunnel server meta timeout netns interop test: Linux-only test");
        return Ok(());
    }
    if !command_available("ip") || !command_available("ping") {
        eprintln!(
            "skipping C/Rust tunnel server meta timeout netns interop test: missing ip or ping command"
        );
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!(
            "skipping C/Rust tunnel server meta timeout netns interop test: /dev/net/tun is not available"
        );
        return Ok(());
    }

    let Some(c_tincd) = c_tincd_binary() else {
        eprintln!(
            "skipping C/Rust tunnel server meta timeout netns interop test: set C_TINCD_PATH or build vendor/tinc/build-c/src/tincd"
        );
        return Ok(());
    };

    run_c_rust_tunnel_server_interop_with_options(&c_tincd, true, false, false, true, false, None)?;
    run_c_rust_tunnel_server_interop_with_options(
        &c_tincd, false, false, false, true, false, None,
    )?;

    Ok(())
}

#[test]
fn linux_netns_c_and_rust_legacy_tunnel_server_isolates_clients_over_tun()
-> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!("skipping C/Rust legacy tunnel server netns interop test: Linux-only test");
        return Ok(());
    }
    if !command_available("ip") || !command_available("ping") {
        eprintln!(
            "skipping C/Rust legacy tunnel server netns interop test: missing ip or ping command"
        );
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!(
            "skipping C/Rust legacy tunnel server netns interop test: /dev/net/tun is not available"
        );
        return Ok(());
    }

    let Some(c_tincd) = c_tincd_binary() else {
        eprintln!(
            "skipping C/Rust legacy tunnel server netns interop test: set C_TINCD_PATH or build vendor/tinc/build-c/src/tincd"
        );
        return Ok(());
    };

    run_c_rust_legacy_tunnel_server_interop(&c_tincd, true)?;
    run_c_rust_legacy_tunnel_server_interop(&c_tincd, false)?;

    Ok(())
}

#[test]
fn linux_netns_c_and_rust_legacy_tunnel_server_udp_discovery_pmtu_like_tinc()
-> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!(
            "skipping C/Rust legacy tunnel server UDP discovery netns interop test: Linux-only test"
        );
        return Ok(());
    }
    if !command_available("ip") || !command_available("ping") {
        eprintln!(
            "skipping C/Rust legacy tunnel server UDP discovery netns interop test: missing ip or ping command"
        );
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!(
            "skipping C/Rust legacy tunnel server UDP discovery netns interop test: /dev/net/tun is not available"
        );
        return Ok(());
    }

    let Some(c_tincd) = c_tincd_binary() else {
        eprintln!(
            "skipping C/Rust legacy tunnel server UDP discovery netns interop test: set C_TINCD_PATH or build vendor/tinc/build-c/src/tincd"
        );
        return Ok(());
    };

    run_c_rust_legacy_tunnel_server_interop_with_options(
        &c_tincd, true, false, false, false, false, true, None,
    )?;
    run_c_rust_legacy_tunnel_server_interop_with_options(
        &c_tincd, false, false, false, false, false, true, None,
    )?;

    Ok(())
}

#[test]
fn linux_netns_c_and_rust_legacy_tunnel_server_client_restart_keeps_isolation()
-> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!(
            "skipping C/Rust legacy tunnel server restart netns interop test: Linux-only test"
        );
        return Ok(());
    }
    if !command_available("ip") || !command_available("ping") {
        eprintln!(
            "skipping C/Rust legacy tunnel server restart netns interop test: missing ip or ping command"
        );
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!(
            "skipping C/Rust legacy tunnel server restart netns interop test: /dev/net/tun is not available"
        );
        return Ok(());
    }

    let Some(c_tincd) = c_tincd_binary() else {
        eprintln!(
            "skipping C/Rust legacy tunnel server restart netns interop test: set C_TINCD_PATH or build vendor/tinc/build-c/src/tincd"
        );
        return Ok(());
    };

    run_c_rust_legacy_tunnel_server_interop_with_options(
        &c_tincd, true, true, false, false, false, false, None,
    )?;
    run_c_rust_legacy_tunnel_server_interop_with_options(
        &c_tincd, false, true, false, false, false, false, None,
    )?;

    Ok(())
}

#[test]
fn linux_netns_c_and_rust_legacy_tunnel_server_recovers_after_underlay_udp_loss_like_tinc()
-> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!(
            "skipping C/Rust legacy tunnel server UDP loss netns interop test: Linux-only test"
        );
        return Ok(());
    }
    if !command_available("ip") || !command_available("ping") {
        eprintln!(
            "skipping C/Rust legacy tunnel server UDP loss netns interop test: missing ip or ping command"
        );
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!(
            "skipping C/Rust legacy tunnel server UDP loss netns interop test: /dev/net/tun is not available"
        );
        return Ok(());
    }

    let Some(c_tincd) = c_tincd_binary() else {
        eprintln!(
            "skipping C/Rust legacy tunnel server UDP loss netns interop test: set C_TINCD_PATH or build vendor/tinc/build-c/src/tincd"
        );
        return Ok(());
    };

    run_c_rust_legacy_tunnel_server_interop_with_options(
        &c_tincd, true, false, true, false, false, false, None,
    )?;
    run_c_rust_legacy_tunnel_server_interop_with_options(
        &c_tincd, false, false, true, false, false, false, None,
    )?;

    Ok(())
}

#[test]
fn linux_netns_c_and_rust_legacy_tunnel_server_recovers_after_client_meta_timeout_loss_like_tinc()
-> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!(
            "skipping C/Rust legacy tunnel server meta timeout netns interop test: Linux-only test"
        );
        return Ok(());
    }
    if !command_available("ip") || !command_available("ping") {
        eprintln!(
            "skipping C/Rust legacy tunnel server meta timeout netns interop test: missing ip or ping command"
        );
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!(
            "skipping C/Rust legacy tunnel server meta timeout netns interop test: /dev/net/tun is not available"
        );
        return Ok(());
    }

    let Some(c_tincd) = c_tincd_binary() else {
        eprintln!(
            "skipping C/Rust legacy tunnel server meta timeout netns interop test: set C_TINCD_PATH or build vendor/tinc/build-c/src/tincd"
        );
        return Ok(());
    };

    run_c_rust_legacy_tunnel_server_interop_with_options(
        &c_tincd, true, false, false, true, false, false, None,
    )?;
    run_c_rust_legacy_tunnel_server_interop_with_options(
        &c_tincd, false, false, false, true, false, false, None,
    )?;

    Ok(())
}

#[test]
fn linux_netns_c_and_rust_legacy_tunnel_server_rekey_keeps_isolation() -> Result<(), Box<dyn Error>>
{
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!("skipping C/Rust legacy tunnel server rekey netns interop test: Linux-only test");
        return Ok(());
    }
    if !command_available("ip") || !command_available("ping") {
        eprintln!(
            "skipping C/Rust legacy tunnel server rekey netns interop test: missing ip or ping command"
        );
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!(
            "skipping C/Rust legacy tunnel server rekey netns interop test: /dev/net/tun is not available"
        );
        return Ok(());
    }

    let Some(c_tincd) = c_tincd_binary() else {
        eprintln!(
            "skipping C/Rust legacy tunnel server rekey netns interop test: set C_TINCD_PATH or build vendor/tinc/build-c/src/tincd"
        );
        return Ok(());
    };

    run_c_rust_legacy_tunnel_server_interop_with_options(
        &c_tincd, true, false, false, false, true, false, None,
    )?;
    run_c_rust_legacy_tunnel_server_interop_with_options(
        &c_tincd, false, false, false, false, true, false, None,
    )?;

    Ok(())
}

#[test]
fn linux_netns_c_and_rust_legacy_minor_one_upgrade_nodes_can_ping_over_tun()
-> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!("skipping C/Rust legacy minor-1 netns interop test: Linux-only test");
        return Ok(());
    }
    if !command_available("ip") || !command_available("ping") {
        eprintln!("skipping C/Rust legacy minor-1 netns interop test: missing ip or ping command");
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!(
            "skipping C/Rust legacy minor-1 netns interop test: /dev/net/tun is not available"
        );
        return Ok(());
    }

    let Some(c_tincd) = c_tincd_binary() else {
        eprintln!(
            "skipping C/Rust legacy minor-1 netns interop test: set C_TINCD_PATH or build vendor/tinc/build-c/src/tincd"
        );
        return Ok(());
    };

    run_c_rust_two_node_legacy_minor_one_upgrade_interop(&c_tincd, true)?;
    run_c_rust_two_node_legacy_minor_one_upgrade_interop(&c_tincd, false)?;

    Ok(())
}

#[test]
fn linux_netns_c_and_rust_tincd_nodes_exchange_req_pubkey_ans_pubkey_over_relay()
-> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!("skipping C/Rust REQ_PUBKEY netns interop test: Linux-only test");
        return Ok(());
    }
    if !command_available("ip") || !command_available("ping") {
        eprintln!("skipping C/Rust REQ_PUBKEY netns interop test: missing ip or ping command");
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!("skipping C/Rust REQ_PUBKEY netns interop test: /dev/net/tun is not available");
        return Ok(());
    }

    let Some(c_tincd) = c_tincd_binary() else {
        eprintln!(
            "skipping C/Rust REQ_PUBKEY netns interop test: set C_TINCD_PATH or build vendor/tinc/build-c/src/tincd"
        );
        return Ok(());
    };

    run_c_rust_three_node_req_pubkey_interop(&c_tincd)?;

    Ok(())
}

#[test]
fn linux_netns_rust_tincctl_controls_c_tincd_dummy_node() -> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!("skipping Rust tincctl/C tincd control interop test: Linux-only test");
        return Ok(());
    }
    if !command_available("ip") {
        eprintln!("skipping Rust tincctl/C tincd control interop test: missing ip command");
        return Ok(());
    }
    let Some(c_tincd) = c_tincd_binary() else {
        eprintln!(
            "skipping Rust tincctl/C tincd control interop test: set C_TINCD_PATH or build vendor/tinc/build-c/src/tincd"
        );
        return Ok(());
    };

    let workspace = TempWorkspace::new("tinc-rustctl-cdaemon-control")?;
    let suffix = unique_suffix();
    let namespace = format!("tinc-ctl-cd-{suffix}");
    let confdir = workspace.path().join("alpha");
    let mut cleanup = NetnsCleanup::new(workspace.path().to_path_buf());
    cleanup.add_namespace(namespace.clone());

    create_dummy_node_config(&confdir, "alpha", 17455, 41)?;
    if !try_ip(&["netns", "add", &namespace]) {
        eprintln!(
            "skipping Rust tincctl/C tincd control interop test: cannot create network namespace"
        );
        return Ok(());
    }
    run_ip(&["-n", &namespace, "link", "set", "lo", "up"])?;

    cleanup.spawn_with_binary(
        "alpha",
        &c_tincd,
        &confdir,
        &namespace,
        &workspace.path().join("alpha.log"),
    )?;
    wait_for_pidfile(&confdir.join("pid"), &cleanup)?;
    wait_for_control_socket(&confdir.join("pid.socket"), &cleanup)?;

    let connect = run_rust_tincctl(&[
        "tinc",
        "--config",
        confdir.to_str().unwrap(),
        "connect",
        "beta",
    ]);
    assert!(
        connect
            .as_ref()
            .is_err_and(|error| error.to_string().contains("18 -1")),
        "Rust tincctl connect against C tincd should fail on C control_h() default REQ_INVALID path; got {connect:?}\n{}",
        cleanup.logs()
    );
    let disconnect = run_rust_tincctl(&[
        "tinc",
        "--config",
        confdir.to_str().unwrap(),
        "disconnect",
        "beta",
    ]);
    assert!(
        disconnect
            .as_ref()
            .is_err_and(|error| error.to_string().contains("12 -2")),
        "Rust tincctl disconnect against C tincd should fail with C control_h() REQ_DISCONNECT -2 for missing peer; got {disconnect:?}\n{}",
        cleanup.logs()
    );

    let dump = run_rust_tincctl(&[
        "tinc",
        "--config",
        confdir.to_str().unwrap(),
        "dump",
        "nodes",
    ])
    .map_err(|error| {
        format!(
            "Rust tincctl dump against C tincd failed: {error}\n{}",
            cleanup.logs()
        )
    })?;
    assert!(
        dump.contains("alpha id "),
        "Rust tincctl failed to parse C tincd node dump:\n{dump}\n{}",
        cleanup.logs()
    );

    let stop = run_rust_tincctl(&["tinc", "--config", confdir.to_str().unwrap(), "stop"]).map_err(
        |error| {
            format!(
                "Rust tincctl stop against C tincd failed: {error}\n{}",
                cleanup.logs()
            )
        },
    )?;
    assert!(stop.is_empty(), "unexpected stop output: {stop}");
    wait_for_child_exit(&mut cleanup, "alpha")?;

    Ok(())
}

#[test]
fn linux_netns_rust_tincctl_streams_log_from_c_tincd_dummy_node() -> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!("skipping Rust tincctl/C tincd log stream interop test: Linux-only test");
        return Ok(());
    }
    if !command_available("ip") {
        eprintln!("skipping Rust tincctl/C tincd log stream interop test: missing ip command");
        return Ok(());
    }
    let Some(c_tincd) = c_tincd_binary() else {
        eprintln!(
            "skipping Rust tincctl/C tincd log stream interop test: set C_TINCD_PATH or build vendor/tinc/build-c/src/tincd"
        );
        return Ok(());
    };

    let workspace = TempWorkspace::new("tinc-rustctl-cdaemon-log")?;
    let suffix = unique_suffix();
    let namespace = format!("tinc-ctl-log-cd-{suffix}");
    let confdir = workspace.path().join("alpha");
    let mut cleanup = NetnsCleanup::new(workspace.path().to_path_buf());
    cleanup.add_namespace(namespace.clone());

    create_dummy_node_config(&confdir, "alpha", 17457, 43)?;
    if !try_ip(&["netns", "add", &namespace]) {
        eprintln!(
            "skipping Rust tincctl/C tincd log stream interop test: cannot create network namespace"
        );
        return Ok(());
    }
    run_ip(&["-n", &namespace, "link", "set", "lo", "up"])?;

    cleanup.spawn_with_binary(
        "alpha",
        &c_tincd,
        &confdir,
        &namespace,
        &workspace.path().join("alpha.log"),
    )?;
    wait_for_pidfile(&confdir.join("pid"), &cleanup)?;
    wait_for_control_socket(&confdir.join("pid.socket"), &cleanup)?;

    let log_client_one =
        spawn_rust_tincctl_thread(&["tinc", "--config", confdir.to_str().unwrap(), "log", "5"]);
    let log_client_two =
        spawn_rust_tincctl_thread(&["tinc", "--config", confdir.to_str().unwrap(), "log", "5"]);
    thread::sleep(Duration::from_millis(300));
    let _ = run_rust_tincctl(&[
        "tinc",
        "--config",
        confdir.to_str().unwrap(),
        "dump",
        "nodes",
    ]);

    let stop = run_rust_tincctl(&["tinc", "--config", confdir.to_str().unwrap(), "stop"]).map_err(
        |error| {
            format!(
                "could not stop C tincd after Rust tincctl log stream: {error}\n{}",
                cleanup.logs()
            )
        },
    )?;
    assert!(stop.is_empty(), "unexpected stop output: {stop}");
    let log_output_one =
        wait_for_rust_tincctl_thread(log_client_one, Duration::from_secs(8)).map_err(|error| {
            format!(
                "first Rust tincctl log subscriber against C tincd did not exit cleanly: {error}\n{}",
                cleanup.logs()
            )
        })?;
    let log_output_two =
        wait_for_rust_tincctl_thread(log_client_two, Duration::from_secs(8)).map_err(|error| {
            format!(
                "second Rust tincctl log subscriber against C tincd did not exit cleanly: {error}\n{}",
                cleanup.logs()
            )
        })?;
    assert_rust_tincctl_log_from_c_daemon(&log_output_one, "first", &cleanup)?;
    assert_rust_tincctl_log_from_c_daemon(&log_output_two, "second", &cleanup)?;
    wait_for_child_exit(&mut cleanup, "alpha")?;

    Ok(())
}

#[test]
fn linux_netns_rust_tincctl_streams_pcap_from_c_tincd_tun_nodes() -> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!("skipping Rust tincctl/C tincd pcap stream interop test: Linux-only test");
        return Ok(());
    }
    if !command_available("ip") || !command_available("ping") {
        eprintln!(
            "skipping Rust tincctl/C tincd pcap stream interop test: missing ip or ping command"
        );
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!(
            "skipping Rust tincctl/C tincd pcap stream interop test: /dev/net/tun is not available"
        );
        return Ok(());
    }
    let Some(c_tincd) = c_tincd_binary() else {
        eprintln!(
            "skipping Rust tincctl/C tincd pcap stream interop test: set C_TINCD_PATH or build vendor/tinc/build-c/src/tincd"
        );
        return Ok(());
    };

    run_rust_tincctl_c_tincd_pcap_stream(&c_tincd)
}

#[test]
fn linux_netns_rust_tincctl_start_stop_daemonizes_rust_tincd_like_tinc()
-> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!("skipping Rust tincctl start/stop daemonize test: Linux-only test");
        return Ok(());
    }
    if !command_available("ip") {
        eprintln!("skipping Rust tincctl start/stop daemonize test: missing ip command");
        return Ok(());
    }
    let Some(tinc_binary) = rust_tinc_binary() else {
        eprintln!(
            "skipping Rust tincctl start/stop daemonize test: set RUST_TINC_PATH or build target/debug/tinc"
        );
        return Ok(());
    };

    let workspace = TempWorkspace::new("tinc-rustctl-start-rustdaemon")?;
    let suffix = unique_suffix();
    let namespace = format!("tinc-start-rd-{suffix}");
    let confdir = workspace.path().join("alpha");
    let mut cleanup = NetnsCleanup::new(workspace.path().to_path_buf());
    cleanup.add_namespace(namespace.clone());

    create_dummy_node_config(&confdir, "alpha", 17461, 47)?;
    if !try_ip(&["netns", "add", &namespace]) {
        eprintln!(
            "skipping Rust tincctl start/stop daemonize test: cannot create network namespace"
        );
        return Ok(());
    }
    run_ip(&["-n", &namespace, "link", "set", "lo", "up"])?;

    let start = run_rust_tinc_binary(&tinc_binary, &namespace, &confdir, &["start"])?;
    assert!(
        start.contains("Ready"),
        "Rust tincctl start did not forward C-style umbilical Ready log:\n{start}"
    );
    wait_for_pidfile(&confdir.join("pid"), &cleanup)?;
    wait_for_control_socket(&confdir.join("pid.socket"), &cleanup)?;
    cleanup.add_daemon_pidfile(confdir.join("pid"));
    let daemon_pid = read_pidfile_pid(&confdir.join("pid"))?;
    assert!(
        process_is_running(daemon_pid),
        "daemonized Rust tincd pid {daemon_pid} from pidfile is not running"
    );

    let dump = run_rust_tinc_binary(&tinc_binary, &namespace, &confdir, &["dump", "nodes"])?;
    assert!(
        dump.contains("alpha id "),
        "Rust tincctl dump after start failed to read daemonized Rust tincd node dump:\n{dump}"
    );

    let stop = run_rust_tinc_binary(&tinc_binary, &namespace, &confdir, &["stop"])?;
    assert!(stop.is_empty(), "unexpected stop output: {stop}");
    wait_for_pid_exit(daemon_pid)?;
    cleanup.remove_daemon_pidfile(&confdir.join("pid"));

    Ok(())
}

#[test]
fn linux_netns_rust_tincctl_start_daemon_runs_tinc_down_once_like_tinc()
-> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!("skipping Rust daemonized tinc-down test: Linux-only test");
        return Ok(());
    }
    if !command_available("ip") {
        eprintln!("skipping Rust daemonized tinc-down test: missing ip command");
        return Ok(());
    }
    let Some(tinc_binary) = rust_tinc_binary() else {
        eprintln!(
            "skipping Rust daemonized tinc-down test: set RUST_TINC_PATH or build target/debug/tinc"
        );
        return Ok(());
    };

    let workspace = TempWorkspace::new("tinc-rustdaemon-tinc-down")?;
    let suffix = unique_suffix();
    let namespace = format!("tinc-down-rd-{suffix}");
    let confdir = workspace.path().join("alpha");
    let marker = workspace.path().join("tinc-down.marker");
    let mut cleanup = NetnsCleanup::new(workspace.path().to_path_buf());
    cleanup.add_namespace(namespace.clone());

    create_dummy_node_config(&confdir, "alpha", 17465, 51)?;
    write_tinc_down_marker_script(&confdir, &marker)?;
    if !try_ip(&["netns", "add", &namespace]) {
        eprintln!("skipping Rust daemonized tinc-down test: cannot create network namespace");
        return Ok(());
    }
    run_ip(&["-n", &namespace, "link", "set", "lo", "up"])?;

    let start = run_rust_tinc_binary(&tinc_binary, &namespace, &confdir, &["start"])?;
    assert!(
        start.contains("Ready"),
        "Rust tincctl start did not forward C-style umbilical Ready log:\n{start}"
    );
    wait_for_pidfile(&confdir.join("pid"), &cleanup)?;
    wait_for_control_socket(&confdir.join("pid.socket"), &cleanup)?;
    cleanup.add_daemon_pidfile(confdir.join("pid"));
    let daemon_pid = read_pidfile_pid(&confdir.join("pid"))?;
    assert!(
        process_is_running(daemon_pid),
        "daemonized Rust tincd pid {daemon_pid} from pidfile is not running"
    );
    assert!(
        !marker.exists(),
        "tinc-down marker was created before daemon shutdown"
    );

    let stop = run_rust_tinc_binary(&tinc_binary, &namespace, &confdir, &["stop"])?;
    assert!(stop.is_empty(), "unexpected stop output: {stop}");
    wait_for_pid_exit(daemon_pid)?;
    cleanup.remove_daemon_pidfile(&confdir.join("pid"));
    wait_for_file_contains(
        &marker,
        "down NAME=alpha DEVICE=dummy INTERFACE=dummy",
        &cleanup,
        "daemonized tinc-down marker",
    )?;
    let marker_output = fs::read_to_string(&marker)?;
    assert_eq!(
        1,
        marker_output.lines().count(),
        "C device_disable() runs tinc-down exactly once during shutdown\n{marker_output}"
    );

    Ok(())
}

#[test]
fn linux_netns_rust_tincctl_start_reports_umbilical_bind_failure_like_tinc()
-> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!("skipping Rust umbilical start failure test: Linux-only test");
        return Ok(());
    }
    if !command_available("ip") {
        eprintln!("skipping Rust umbilical start failure test: missing ip command");
        return Ok(());
    }
    let Some(tinc_binary) = rust_tinc_binary() else {
        eprintln!(
            "skipping Rust umbilical start failure test: set RUST_TINC_PATH or build target/debug/tinc"
        );
        return Ok(());
    };

    let workspace = TempWorkspace::new("tinc-rustdaemon-start-failure")?;
    let suffix = unique_suffix();
    let namespace = format!("tinc-fail-rd-{suffix}");
    let alpha_confdir = workspace.path().join("alpha");
    let beta_confdir = workspace.path().join("beta");
    let mut cleanup = NetnsCleanup::new(workspace.path().to_path_buf());
    cleanup.add_namespace(namespace.clone());

    create_dummy_node_config(&alpha_confdir, "alpha", 17466, 52)?;
    create_dummy_node_config(&beta_confdir, "beta", 17466, 53)?;
    if !try_ip(&["netns", "add", &namespace]) {
        eprintln!("skipping Rust umbilical start failure test: cannot create network namespace");
        return Ok(());
    }
    run_ip(&["-n", &namespace, "link", "set", "lo", "up"])?;

    let alpha_start = run_rust_tinc_binary(&tinc_binary, &namespace, &alpha_confdir, &["start"])?;
    assert!(
        alpha_start.contains("Ready"),
        "Rust tincctl start did not forward C-style umbilical Ready log:\n{alpha_start}"
    );
    wait_for_pidfile(&alpha_confdir.join("pid"), &cleanup)?;
    wait_for_control_socket(&alpha_confdir.join("pid.socket"), &cleanup)?;
    cleanup.add_daemon_pidfile(alpha_confdir.join("pid"));
    let alpha_pid = read_pidfile_pid(&alpha_confdir.join("pid"))?;
    assert!(
        process_is_running(alpha_pid),
        "daemonized Rust tincd pid {alpha_pid} from pidfile is not running"
    );

    let beta_failure =
        run_rust_tinc_binary_expect_failure(&tinc_binary, &namespace, &beta_confdir, &["start"])?;
    assert!(
        beta_failure.contains("could not start tincd"),
        "Rust tincctl start did not report failure:\n{beta_failure}"
    );
    assert!(
        beta_failure.contains("listen socket error")
            || beta_failure.contains("Address already in use"),
        "Rust tincctl start did not forward the daemon bind failure over the umbilical:\n{beta_failure}"
    );
    assert!(
        !beta_confdir.join("pid").exists(),
        "failed beta daemon left a pidfile behind"
    );
    assert!(
        !beta_confdir.join("pid.socket").exists(),
        "failed beta daemon left a control socket behind"
    );

    let stop = run_rust_tinc_binary(&tinc_binary, &namespace, &alpha_confdir, &["stop"])?;
    assert!(stop.is_empty(), "unexpected stop output: {stop}");
    wait_for_pid_exit(alpha_pid)?;
    cleanup.remove_daemon_pidfile(&alpha_confdir.join("pid"));

    Ok(())
}

#[test]
fn linux_netns_rust_tincctl_start_daemon_reopens_logfile_on_sighup_like_tinc()
-> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!("skipping Rust daemonized SIGHUP logfile reopen test: Linux-only test");
        return Ok(());
    }
    if !command_available("ip") {
        eprintln!("skipping Rust daemonized SIGHUP logfile reopen test: missing ip command");
        return Ok(());
    }
    let Some(tinc_binary) = rust_tinc_binary() else {
        eprintln!(
            "skipping Rust daemonized SIGHUP logfile reopen test: set RUST_TINC_PATH or build target/debug/tinc"
        );
        return Ok(());
    };

    let workspace = TempWorkspace::new("tinc-rustdaemon-sighup-log")?;
    let suffix = unique_suffix();
    let namespace = format!("tinc-hup-rd-{suffix}");
    let confdir = workspace.path().join("alpha");
    let logfile = workspace.path().join("alpha.log");
    let rotated = workspace.path().join("alpha.log.1");
    let mut cleanup = NetnsCleanup::new(workspace.path().to_path_buf());
    cleanup.add_namespace(namespace.clone());

    create_dummy_node_config(&confdir, "alpha", 17463, 49)?;
    if !try_ip(&["netns", "add", &namespace]) {
        eprintln!(
            "skipping Rust daemonized SIGHUP logfile reopen test: cannot create network namespace"
        );
        return Ok(());
    }
    run_ip(&["-n", &namespace, "link", "set", "lo", "up"])?;

    let start = run_rust_tinc_binary(
        &tinc_binary,
        &namespace,
        &confdir,
        &["start", "--logfile", logfile.to_str().unwrap()],
    )?;
    assert!(
        start.contains("Ready"),
        "Rust tincctl start did not forward C-style umbilical Ready log:\n{start}"
    );
    wait_for_pidfile(&confdir.join("pid"), &cleanup)?;
    wait_for_control_socket(&confdir.join("pid.socket"), &cleanup)?;
    cleanup.add_daemon_pidfile(confdir.join("pid"));
    let daemon_pid = read_pidfile_pid(&confdir.join("pid"))?;
    assert!(
        process_is_running(daemon_pid),
        "daemonized Rust tincd pid {daemon_pid} from pidfile is not running"
    );

    wait_for_file_contains(
        &logfile,
        "Ready",
        &cleanup,
        "daemonized logfile before SIGHUP",
    )?;
    fs::rename(&logfile, &rotated)?;
    send_signal_from_pidfile(&namespace, &confdir.join("pid"), "HUP")?;
    wait_for_file_contains(
        &rotated,
        "Got SIGHUP signal",
        &cleanup,
        "rotated logfile after SIGHUP",
    )?;

    let reload = run_rust_tinc_binary(&tinc_binary, &namespace, &confdir, &["reload"])?;
    assert!(reload.is_empty(), "unexpected reload output: {reload}");
    wait_for_file_contains(
        &logfile,
        "Got 'reload' command",
        &cleanup,
        "new logfile after SIGHUP reopen",
    )?;
    let old_output = read_log(&rotated);
    let new_output = read_log(&logfile);
    assert!(
        !old_output.contains("Got 'reload' command"),
        "C-style reopen should move post-SIGHUP control logs to the new logfile\nold:\n{old_output}\nnew:\n{new_output}"
    );

    let stop = run_rust_tinc_binary(&tinc_binary, &namespace, &confdir, &["stop"])?;
    assert!(stop.is_empty(), "unexpected stop output: {stop}");
    wait_for_pid_exit(daemon_pid)?;
    cleanup.remove_daemon_pidfile(&confdir.join("pid"));

    Ok(())
}

#[test]
fn linux_netns_rust_tincctl_start_daemon_cleans_up_on_sigterm_like_tinc()
-> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!("skipping Rust daemonized SIGTERM cleanup test: Linux-only test");
        return Ok(());
    }
    if !command_available("ip") {
        eprintln!("skipping Rust daemonized SIGTERM cleanup test: missing ip command");
        return Ok(());
    }
    let Some(tinc_binary) = rust_tinc_binary() else {
        eprintln!(
            "skipping Rust daemonized SIGTERM cleanup test: set RUST_TINC_PATH or build target/debug/tinc"
        );
        return Ok(());
    };

    let workspace = TempWorkspace::new("tinc-rustdaemon-term-cleanup")?;
    let suffix = unique_suffix();
    let namespace = format!("tinc-term-rd-{suffix}");
    let confdir = workspace.path().join("alpha");
    let pidfile = confdir.join("pid");
    let socket = confdir.join("pid.socket");
    let logfile = workspace.path().join("alpha.log");
    let mut cleanup = NetnsCleanup::new(workspace.path().to_path_buf());
    cleanup.add_namespace(namespace.clone());

    create_dummy_node_config(&confdir, "alpha", 17464, 50)?;
    if !try_ip(&["netns", "add", &namespace]) {
        eprintln!("skipping Rust daemonized SIGTERM cleanup test: cannot create network namespace");
        return Ok(());
    }
    run_ip(&["-n", &namespace, "link", "set", "lo", "up"])?;

    let start = run_rust_tinc_binary(
        &tinc_binary,
        &namespace,
        &confdir,
        &["start", "--logfile", logfile.to_str().unwrap()],
    )?;
    assert!(
        start.contains("Ready"),
        "Rust tincctl start did not forward C-style umbilical Ready log:\n{start}"
    );
    wait_for_pidfile(&pidfile, &cleanup)?;
    wait_for_control_socket(&socket, &cleanup)?;
    cleanup.add_daemon_pidfile(pidfile.clone());
    let daemon_pid = read_pidfile_pid(&pidfile)?;
    assert!(
        process_is_running(daemon_pid),
        "daemonized Rust tincd pid {daemon_pid} from pidfile is not running"
    );

    send_signal_from_pidfile(&namespace, &pidfile, "TERM")?;
    wait_for_pid_exit(daemon_pid)?;
    wait_for_path_removed(&pidfile, &cleanup, "daemonized SIGTERM pidfile cleanup")?;
    wait_for_path_removed(
        &socket,
        &cleanup,
        "daemonized SIGTERM control socket cleanup",
    )?;
    cleanup.remove_daemon_pidfile(&pidfile);

    Ok(())
}

#[test]
fn linux_netns_rust_invite_c_join_minimal_interop_like_tinc() -> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!("skipping Rust invite/C join interop test: Linux-only test");
        return Ok(());
    }
    if !command_available("ip") {
        eprintln!("skipping Rust invite/C join interop test: missing ip command");
        return Ok(());
    }
    let Some(c_tinc) = c_tinc_binary() else {
        eprintln!(
            "skipping Rust invite/C join interop test: set C_TINC_PATH or build vendor/tinc/build-c/src/tinc"
        );
        return Ok(());
    };

    let workspace = TempWorkspace::new("tinc-rust-invite-c-join")?;
    let suffix = unique_suffix();
    let namespace = format!("tinc-invite-cj-{suffix}");
    let alpha_confdir = workspace.path().join("alpha");
    let beta_confdir = workspace.path().join("beta");
    let mut cleanup = NetnsCleanup::new(workspace.path().to_path_buf());
    cleanup.add_namespace(namespace.clone());

    create_invitation_server_node_config(&alpha_confdir, "alpha", 17575, 61)?;
    fs::create_dir_all(&beta_confdir)?;
    if !try_ip(&["netns", "add", &namespace]) {
        eprintln!("skipping Rust invite/C join interop test: cannot create network namespace");
        return Ok(());
    }
    run_ip(&["-n", &namespace, "link", "set", "lo", "up"])?;

    let invite = run_rust_tincctl(&[
        "tinc",
        "--config",
        alpha_confdir.to_str().unwrap(),
        "invite",
        "beta",
    ])?;
    let url = invite.trim();
    assert!(
        url.starts_with("127.0.0.1:17575/") && url.len() > "127.0.0.1:17575/".len(),
        "Rust invite produced unexpected URL: {url:?}"
    );
    let invitation_files = invitation_cookie_files(&alpha_confdir.join("invitations"))?;
    assert_eq!(
        1,
        invitation_files.len(),
        "Rust invite should create one C-style invitation cookie file"
    );

    cleanup.spawn_with_binary(
        "alpha",
        Path::new(TINCD),
        &alpha_confdir,
        &namespace,
        &workspace.path().join("alpha.log"),
    )?;
    wait_for_pidfile(&alpha_confdir.join("pid"), &cleanup)?;
    wait_for_control_socket(&alpha_confdir.join("pid.socket"), &cleanup)?;

    let join = run_c_tinc(&c_tinc, &namespace, &beta_confdir, &["join", url]).map_err(|error| {
        format!(
            "C tinc join failed against Rust invitation server: {error}\n{}",
            cleanup.logs()
        )
    })?;
    assert!(
        join.is_empty(),
        "C tinc join should not write stdout on success, got: {join:?}"
    );

    wait_for_file_contains(
        &alpha_confdir.join("hosts").join("beta"),
        "Ed25519PublicKey = ",
        &cleanup,
        "Rust invitation server accepted C join public key",
    )?;
    assert!(
        !alpha_confdir
            .join("invitations")
            .join(&invitation_files[0])
            .exists(),
        "Rust invitation daemon should remove the consumed invitation file like C"
    );
    assert!(
        !alpha_confdir
            .join("invitations")
            .join(format!("{}.used", invitation_files[0]))
            .exists(),
        "Rust invitation daemon should remove the temporary .used invitation file like C"
    );

    let beta_tinc_conf = fs::read_to_string(beta_confdir.join("tinc.conf"))?;
    assert!(
        beta_tinc_conf.contains("Name = beta\n")
            && beta_tinc_conf.contains("ConnectTo = alpha\n")
            && beta_tinc_conf.contains("Mode = switch\n"),
        "C join did not write expected safe server config from Rust invitation:\n{beta_tinc_conf}"
    );
    let beta_alpha_host = fs::read_to_string(beta_confdir.join("hosts").join("alpha"))?;
    assert!(
        beta_alpha_host.contains("Address = 127.0.0.1 17575\n")
            && beta_alpha_host.contains("Port = 17575\n")
            && beta_alpha_host.contains("Ed25519PublicKey = "),
        "C join did not import Rust inviter host config:\n{beta_alpha_host}"
    );
    let beta_host = fs::read_to_string(beta_confdir.join("hosts").join("beta"))?;
    assert!(
        beta_host.contains("Ed25519PublicKey = ")
            && beta_host.contains("-----BEGIN RSA PUBLIC KEY-----"),
        "C join did not write local Ed25519 and legacy RSA public keys:\n{beta_host}"
    );
    assert!(beta_confdir.join("ed25519_key.priv").exists());
    assert!(beta_confdir.join("rsa_key.priv").exists());
    assert!(beta_confdir.join("invitation-data").exists());

    let stop = run_rust_tincctl(&["tinc", "--config", alpha_confdir.to_str().unwrap(), "stop"])?;
    assert!(
        stop.is_empty(),
        "unexpected Rust daemon stop output: {stop}"
    );
    wait_for_child_exit(&mut cleanup, "alpha")?;

    Ok(())
}

#[test]
fn linux_netns_c_invite_rust_join_minimal_interop_like_tinc() -> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!("skipping C invite/Rust join interop test: Linux-only test");
        return Ok(());
    }
    if !command_available("ip") {
        eprintln!("skipping C invite/Rust join interop test: missing ip command");
        return Ok(());
    }
    let Some(c_tinc) = c_tinc_binary() else {
        eprintln!(
            "skipping C invite/Rust join interop test: set C_TINC_PATH or build vendor/tinc/build-c/src/tinc"
        );
        return Ok(());
    };
    let Some(c_tincd) = c_tincd_binary() else {
        eprintln!(
            "skipping C invite/Rust join interop test: set C_TINCD_PATH or build vendor/tinc/build-c/src/tincd"
        );
        return Ok(());
    };
    let Some(tinc_binary) = rust_tinc_binary() else {
        eprintln!(
            "skipping C invite/Rust join interop test: set RUST_TINC_PATH or build target/debug/tinc"
        );
        return Ok(());
    };

    let workspace = TempWorkspace::new("tinc-c-invite-rust-join")?;
    let suffix = unique_suffix();
    let namespace = format!("tinc-invite-rj-{suffix}");
    let alpha_confdir = workspace.path().join("alpha");
    let beta_confdir = workspace.path().join("beta");
    let mut cleanup = NetnsCleanup::new(workspace.path().to_path_buf());
    cleanup.add_namespace(namespace.clone());

    create_invitation_server_node_config(&alpha_confdir, "alpha", 17576, 62)?;
    fs::create_dir_all(&beta_confdir)?;
    if !try_ip(&["netns", "add", &namespace]) {
        eprintln!("skipping C invite/Rust join interop test: cannot create network namespace");
        return Ok(());
    }
    run_ip(&["-n", &namespace, "link", "set", "lo", "up"])?;

    cleanup.spawn_with_binary(
        "alpha",
        &c_tincd,
        &alpha_confdir,
        &namespace,
        &workspace.path().join("alpha.log"),
    )?;
    wait_for_pidfile(&alpha_confdir.join("pid"), &cleanup)?;
    wait_for_control_socket(&alpha_confdir.join("pid.socket"), &cleanup)?;

    let invite =
        run_c_tinc(&c_tinc, &namespace, &alpha_confdir, &["invite", "beta"]).map_err(|error| {
            format!(
                "C tinc invite failed before Rust join interop: {error}\n{}",
                cleanup.logs()
            )
        })?;
    let url = invite.trim();
    assert!(
        url.starts_with("127.0.0.1:17576/") && url.len() > "127.0.0.1:17576/".len(),
        "C invite produced unexpected URL: {url:?}\n{}",
        cleanup.logs()
    );
    wait_for_log_contains(
        &cleanup,
        "alpha",
        &["Got 'reload' command"],
        "C invite should reload C daemon after creating invitation key",
    )?;
    let invitation_files = invitation_cookie_files(&alpha_confdir.join("invitations"))?;
    assert_eq!(
        1,
        invitation_files.len(),
        "C invite should create one invitation cookie file"
    );

    let join = run_rust_tinc_binary(&tinc_binary, &namespace, &beta_confdir, &["join", url])
        .map_err(|error| {
            format!(
                "Rust tinc join failed against C invitation server: {error}\n{}",
                cleanup.logs()
            )
        })?;
    assert!(
        join.is_empty(),
        "Rust tinc join should not write output on success, got: {join:?}"
    );

    wait_for_file_contains(
        &alpha_confdir.join("hosts").join("beta"),
        "Ed25519PublicKey = ",
        &cleanup,
        "C invitation server accepted Rust join public key",
    )?;
    assert!(
        !alpha_confdir
            .join("invitations")
            .join(&invitation_files[0])
            .exists(),
        "C invitation daemon should remove the consumed invitation file"
    );
    assert!(
        !alpha_confdir
            .join("invitations")
            .join(format!("{}.used", invitation_files[0]))
            .exists(),
        "C invitation daemon should remove the temporary .used invitation file"
    );

    let beta_tinc_conf = fs::read_to_string(beta_confdir.join("tinc.conf"))?;
    assert!(
        beta_tinc_conf.contains("Name = beta\n")
            && beta_tinc_conf.contains("ConnectTo = alpha\n")
            && beta_tinc_conf.contains("Mode = switch\n"),
        "Rust join did not write expected safe server config from C invitation:\n{beta_tinc_conf}"
    );
    let beta_alpha_host = fs::read_to_string(beta_confdir.join("hosts").join("alpha"))?;
    assert!(
        beta_alpha_host.contains("Address = 127.0.0.1 17576\n")
            && beta_alpha_host.contains("Port = 17576\n")
            && beta_alpha_host.contains("Ed25519PublicKey = "),
        "Rust join did not import C inviter host config:\n{beta_alpha_host}"
    );
    let alpha_host = fs::read_to_string(alpha_confdir.join("hosts").join("alpha"))?;
    assert!(
        alpha_host.contains("Port = 0\n") && !alpha_host.contains("Port = 17576\n"),
        "C invite must leave the inviter's original host config unchanged while replacing Port only in the invitation body:\n{alpha_host}"
    );
    let beta_host = fs::read_to_string(beta_confdir.join("hosts").join("beta"))?;
    let alpha_beta_host = fs::read_to_string(alpha_confdir.join("hosts").join("beta"))?;
    let beta_public = beta_host
        .lines()
        .find_map(|line| line.strip_prefix("Ed25519PublicKey = "))
        .ok_or("Rust join did not write local Ed25519PublicKey")?;
    assert!(
        alpha_beta_host.contains(&format!("Ed25519PublicKey = {beta_public}\n")),
        "C invitation server did not store Rust join public key consistently\nserver host:\n{alpha_beta_host}\nlocal host:\n{beta_host}"
    );
    assert!(
        beta_host.contains("-----BEGIN RSA PUBLIC KEY-----"),
        "Rust join did not append legacy RSA public key:\n{beta_host}"
    );
    assert!(beta_confdir.join("ed25519_key.priv").exists());
    assert!(beta_confdir.join("rsa_key.priv").exists());
    assert!(beta_confdir.join("invitation-data").exists());
    let invitation_data = fs::read_to_string(beta_confdir.join("invitation-data"))?;
    assert!(
        invitation_data.contains("Name = beta\n")
            && invitation_data.contains("Name = alpha\n")
            && invitation_data.contains("Port = 17576\n"),
        "Rust join did not preserve C invitation data:\n{invitation_data}"
    );

    let stop = run_c_tinc(&c_tinc, &namespace, &alpha_confdir, &["stop"])?;
    assert!(stop.is_empty(), "unexpected C daemon stop output: {stop}");
    wait_for_child_exit(&mut cleanup, "alpha")?;

    Ok(())
}

#[test]
fn linux_netns_c_tincctl_controls_rust_tincd_dummy_node() -> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!("skipping C tincctl/Rust tincd control interop test: Linux-only test");
        return Ok(());
    }
    if !command_available("ip") {
        eprintln!("skipping C tincctl/Rust tincd control interop test: missing ip command");
        return Ok(());
    }
    let Some(c_tinc) = c_tinc_binary() else {
        eprintln!(
            "skipping C tincctl/Rust tincd control interop test: set C_TINC_PATH or build vendor/tinc/build-c/src/tinc"
        );
        return Ok(());
    };

    let workspace = TempWorkspace::new("tinc-cctl-rustdaemon-control")?;
    let suffix = unique_suffix();
    let namespace = format!("tinc-ctl-rd-{suffix}");
    let confdir = workspace.path().join("alpha");
    let mut cleanup = NetnsCleanup::new(workspace.path().to_path_buf());
    cleanup.add_namespace(namespace.clone());

    create_dummy_node_config(&confdir, "alpha", 17456, 42)?;
    if !try_ip(&["netns", "add", &namespace]) {
        eprintln!(
            "skipping C tincctl/Rust tincd control interop test: cannot create network namespace"
        );
        return Ok(());
    }
    run_ip(&["-n", &namespace, "link", "set", "lo", "up"])?;

    cleanup.spawn(
        "alpha",
        &confdir,
        &namespace,
        &workspace.path().join("alpha.log"),
    )?;
    wait_for_pidfile(&confdir.join("pid"), &cleanup)?;
    wait_for_control_socket(&confdir.join("pid.socket"), &cleanup)?;

    let dump = run_c_tinc(&c_tinc, &namespace, &confdir, &["dump", "nodes"])?;
    assert!(
        dump.contains("alpha id "),
        "C tincctl failed to parse Rust tincd node dump:\n{dump}\n{}",
        cleanup.logs()
    );

    let connect = run_c_tinc_expect_failure(&c_tinc, &namespace, &confdir, &["connect", "beta"])?;
    assert!(
        connect.contains("Could not connect to beta."),
        "C tincctl connect should treat Rust daemon REQ_INVALID response like C control_h(); output:\n{connect}\n{}",
        cleanup.logs()
    );
    let disconnect =
        run_c_tinc_expect_failure(&c_tinc, &namespace, &confdir, &["disconnect", "beta"])?;
    assert!(
        disconnect.contains("Could not disconnect beta."),
        "C tincctl disconnect should treat Rust daemon REQ_DISCONNECT -2 like C control_h(); output:\n{disconnect}\n{}",
        cleanup.logs()
    );

    let stop = run_c_tinc(&c_tinc, &namespace, &confdir, &["stop"])?;
    assert!(stop.is_empty(), "unexpected stop output: {stop}");
    wait_for_child_exit(&mut cleanup, "alpha")?;

    Ok(())
}

#[test]
fn linux_netns_c_tincctl_dumps_rust_tincd_two_node_status_topology() -> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!("skipping C tincctl/Rust tincd two-node dump interop test: Linux-only test");
        return Ok(());
    }
    if !command_available("ip") || !command_available("ping") {
        eprintln!(
            "skipping C tincctl/Rust tincd two-node dump interop test: missing ip or ping command"
        );
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!(
            "skipping C tincctl/Rust tincd two-node dump interop test: /dev/net/tun is not available"
        );
        return Ok(());
    }
    let Some(c_tinc) = c_tinc_binary() else {
        eprintln!(
            "skipping C tincctl/Rust tincd two-node dump interop test: set C_TINC_PATH or build vendor/tinc/build-c/src/tinc"
        );
        return Ok(());
    };

    let workspace = TempWorkspace::new("tinc-cctl-rustdaemon-status")?;
    let suffix = unique_suffix();
    let ns_alpha = format!("tinc-ctl-stat-a-{suffix}");
    let ns_beta = format!("tinc-ctl-stat-b-{suffix}");
    let veth_alpha = format!("sa{suffix}");
    let veth_beta = format!("sb{suffix}");
    let alpha_confdir = workspace.path().join("alpha");
    let beta_confdir = workspace.path().join("beta");
    let mut cleanup = NetnsCleanup::new(workspace.path().to_path_buf());
    cleanup.add_namespace(ns_alpha.clone());
    cleanup.add_namespace(ns_beta.clone());

    create_node_config(
        &alpha_confdir,
        NodeConfig {
            name: "alpha",
            peer: "beta",
            port: 17461,
            bind_address: "192.0.2.51",
            peer_address: "192.0.2.52",
            peer_port: 17462,
            interface: "tun-alpha",
            tunnel_address: "10.251.1.1/24",
            subnet: "10.251.1.0/24",
            peer_subnet: "10.251.2.0/24",
            connect_to_peer: true,
            seed: 47,
            peer_seed: 48,
        },
    )?;
    create_node_config(
        &beta_confdir,
        NodeConfig {
            name: "beta",
            peer: "alpha",
            port: 17462,
            bind_address: "192.0.2.52",
            peer_address: "192.0.2.51",
            peer_port: 17461,
            interface: "tun-beta",
            tunnel_address: "10.251.2.1/24",
            subnet: "10.251.2.0/24",
            peer_subnet: "10.251.1.0/24",
            connect_to_peer: false,
            seed: 48,
            peer_seed: 47,
        },
    )?;

    if !try_ip(&["netns", "add", &ns_alpha]) || !try_ip(&["netns", "add", &ns_beta]) {
        eprintln!(
            "skipping C tincctl/Rust tincd two-node dump interop test: cannot create network namespaces"
        );
        return Ok(());
    }
    run_ip(&[
        "link",
        "add",
        &veth_alpha,
        "type",
        "veth",
        "peer",
        "name",
        &veth_beta,
    ])?;
    run_ip(&["link", "set", &veth_alpha, "netns", &ns_alpha])?;
    run_ip(&["link", "set", &veth_beta, "netns", &ns_beta])?;
    run_ip(&["-n", &ns_alpha, "link", "set", "lo", "up"])?;
    run_ip(&["-n", &ns_beta, "link", "set", "lo", "up"])?;
    run_ip(&[
        "-n",
        &ns_alpha,
        "addr",
        "add",
        "192.0.2.51/24",
        "dev",
        &veth_alpha,
    ])?;
    run_ip(&[
        "-n",
        &ns_beta,
        "addr",
        "add",
        "192.0.2.52/24",
        "dev",
        &veth_beta,
    ])?;
    run_ip(&["-n", &ns_alpha, "link", "set", &veth_alpha, "up"])?;
    run_ip(&["-n", &ns_beta, "link", "set", &veth_beta, "up"])?;

    cleanup.spawn(
        "alpha",
        &alpha_confdir,
        &ns_alpha,
        &workspace.path().join("alpha.log"),
    )?;
    cleanup.spawn(
        "beta",
        &beta_confdir,
        &ns_beta,
        &workspace.path().join("beta.log"),
    )?;
    wait_for_pidfile(&alpha_confdir.join("pid"), &cleanup)?;
    wait_for_control_socket(&alpha_confdir.join("pid.socket"), &cleanup)?;
    wait_for_pidfile(&beta_confdir.join("pid"), &cleanup)?;
    wait_for_control_socket(&beta_confdir.join("pid.socket"), &cleanup)?;
    wait_for_link(&ns_alpha, "tun-alpha", &cleanup)?;
    wait_for_link(&ns_beta, "tun-beta", &cleanup)?;
    wait_for_ping(&ns_alpha, "10.251.2.1", &cleanup)?;
    wait_for_ping(&ns_beta, "10.251.1.1", &cleanup)?;

    let nodes = run_c_tinc(&c_tinc, &ns_alpha, &alpha_confdir, &["dump", "nodes"])?;
    assert_c_dump_node_has_status_words(&nodes, "alpha", &["reachable", "sptps"])?;
    assert_c_dump_node_has_status_words(&nodes, "beta", &["validkey", "reachable", "sptps"])?;
    assert!(
        nodes.lines().any(|line| line.starts_with("beta id ")
            && line.contains(" nexthop beta via beta distance 1 ")),
        "C tinc dump nodes did not expose Rust beta direct route:\n{nodes}\n{}",
        cleanup.logs()
    );

    let edges = run_c_tinc(&c_tinc, &ns_alpha, &alpha_confdir, &["dump", "edges"])?;
    assert!(
        edges.contains("alpha to beta at 192.0.2.52 port 17462")
            || edges.contains("beta to alpha at 192.0.2.51 port 17461"),
        "C tinc dump edges did not parse Rust edge endpoints:\n{edges}\n{}",
        cleanup.logs()
    );

    let subnets = run_c_tinc(&c_tinc, &ns_alpha, &alpha_confdir, &["dump", "subnets"])?;
    assert!(
        subnets.contains("10.251.1.0/24 owner alpha")
            && subnets.contains("10.251.2.0/24 owner beta"),
        "C tinc dump subnets did not parse Rust subnet owners:\n{subnets}\n{}",
        cleanup.logs()
    );

    let connections = run_c_tinc(&c_tinc, &ns_alpha, &alpha_confdir, &["dump", "connections"])?;
    assert!(
        connections.contains("<control> at localhost port unix")
            && connections
                .lines()
                .any(|line| line.starts_with("beta at 192.0.2.52 port ")),
        "C tinc dump connections did not parse Rust runtime connections:\n{connections}\n{}",
        cleanup.logs()
    );

    let info = run_c_tinc(&c_tinc, &ns_alpha, &alpha_confdir, &["info", "beta"])?;
    assert!(
        info.lines().any(|line| line.starts_with("Status:")
            && line.contains("validkey")
            && line.contains("reachable")
            && line.contains("sptps"))
            && (info.contains("Reachability: directly with TCP")
                || info.contains("Reachability: directly with UDP"))
            && info.contains("Subnets:      10.251.2.0/24"),
        "C tinc info beta did not interpret Rust node status/topology like tinc:\n{info}\n{}",
        cleanup.logs()
    );

    let alpha_config = alpha_confdir.join("tinc.conf");
    let alpha_config_contents = fs::read_to_string(&alpha_config)?;
    fs::write(
        &alpha_config,
        alpha_config_contents.replace("ConnectTo = beta\n", ""),
    )?;
    let reload = run_c_tinc(&c_tinc, &ns_alpha, &alpha_confdir, &["reload"])?;
    assert!(
        reload.is_empty(),
        "C tinc reload should succeed after removing alpha ConnectTo before disconnect; output:\n{reload}\n{}",
        cleanup.logs()
    );

    let disconnect = run_c_tinc(&c_tinc, &ns_beta, &beta_confdir, &["disconnect", "alpha"])?;
    assert!(
        disconnect.is_empty(),
        "C tinc disconnect alpha should succeed against active incoming Rust tincd connection; output:\n{disconnect}\n{}",
        cleanup.logs()
    );
    let connections_after_disconnect =
        run_c_tinc(&c_tinc, &ns_beta, &beta_confdir, &["dump", "connections"])?;
    assert!(
        !connections_after_disconnect
            .lines()
            .any(|line| line.starts_with("alpha at 192.0.2.51 port ")),
        "C tinc dump connections still shows alpha after Rust control disconnect:\n{connections_after_disconnect}\n{}",
        cleanup.logs()
    );
    let edges_after_disconnect = run_c_tinc(&c_tinc, &ns_beta, &beta_confdir, &["dump", "edges"])?;
    assert!(
        !edges_after_disconnect.contains("beta to alpha at 192.0.2.51 port 17461"),
        "C tinc dump edges still shows beta -> alpha after Rust control disconnect:\n{edges_after_disconnect}\n{}",
        cleanup.logs()
    );

    let stop = run_rust_tincctl(&["tinc", "--config", alpha_confdir.to_str().unwrap(), "stop"])
        .map_err(|error| {
            format!(
                "Rust tincctl stop against Rust alpha tincd failed after C dump status test: {error}\n{}",
                cleanup.logs()
            )
        })?;
    assert!(stop.is_empty(), "unexpected stop output: {stop}");
    wait_for_child_exit(&mut cleanup, "alpha")?;
    let stop = run_rust_tincctl(&["tinc", "--config", beta_confdir.to_str().unwrap(), "stop"])
        .map_err(|error| {
            format!(
                "Rust tincctl stop against Rust beta tincd failed after C dump status test: {error}\n{}",
                cleanup.logs()
            )
        })?;
    assert!(stop.is_empty(), "unexpected stop output: {stop}");
    wait_for_child_exit(&mut cleanup, "beta")?;

    Ok(())
}

#[test]
fn linux_netns_c_tincctl_dumps_rust_tincd_multihop_status_topology() -> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    run_c_tincctl_rust_tincd_multihop_status_topology(false)?;
    run_c_tincctl_rust_tincd_multihop_status_topology(true)
}

#[test]
fn linux_netns_c_tincctl_dumps_rust_tincd_dynamic_relay_status_topology()
-> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    run_c_tincctl_rust_tincd_dynamic_relay_status_topology()
}

#[test]
fn linux_netns_c_tincctl_dumps_rust_tincd_tunnel_server_status_topology()
-> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!("skipping C tincctl/Rust tincd tunnel-server dump interop test: Linux-only test");
        return Ok(());
    }
    if !command_available("ip") || !command_available("ping") {
        eprintln!(
            "skipping C tincctl/Rust tincd tunnel-server dump interop test: missing ip or ping command"
        );
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!(
            "skipping C tincctl/Rust tincd tunnel-server dump interop test: /dev/net/tun is not available"
        );
        return Ok(());
    }
    let Some(c_tinc) = c_tinc_binary() else {
        eprintln!(
            "skipping C tincctl/Rust tincd tunnel-server dump interop test: set C_TINC_PATH or build vendor/tinc/build-c/src/tinc"
        );
        return Ok(());
    };

    run_c_tincctl_rust_tincd_tunnel_server_status_topology(&c_tinc)
}

#[test]
fn linux_netns_c_tincctl_streams_log_from_rust_tincd_dummy_node() -> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!("skipping C tincctl/Rust tincd log stream interop test: Linux-only test");
        return Ok(());
    }
    if !command_available("ip") {
        eprintln!("skipping C tincctl/Rust tincd log stream interop test: missing ip command");
        return Ok(());
    }
    let Some(c_tinc) = c_tinc_binary() else {
        eprintln!(
            "skipping C tincctl/Rust tincd log stream interop test: set C_TINC_PATH or build vendor/tinc/build-c/src/tinc"
        );
        return Ok(());
    };

    let workspace = TempWorkspace::new("tinc-cctl-rustdaemon-log")?;
    let suffix = unique_suffix();
    let namespace = format!("tinc-ctl-log-rd-{suffix}");
    let confdir = workspace.path().join("alpha");
    let mut cleanup = NetnsCleanup::new(workspace.path().to_path_buf());
    cleanup.add_namespace(namespace.clone());

    create_dummy_node_config(&confdir, "alpha", 17460, 46)?;
    if !try_ip(&["netns", "add", &namespace]) {
        eprintln!(
            "skipping C tincctl/Rust tincd log stream interop test: cannot create network namespace"
        );
        return Ok(());
    }
    run_ip(&["-n", &namespace, "link", "set", "lo", "up"])?;

    cleanup.spawn(
        "alpha",
        &confdir,
        &namespace,
        &workspace.path().join("alpha.log"),
    )?;
    wait_for_pidfile(&confdir.join("pid"), &cleanup)?;
    wait_for_control_socket(&confdir.join("pid.socket"), &cleanup)?;

    let log_client_one = spawn_c_tinc_process(
        &c_tinc,
        &namespace,
        &confdir,
        &workspace.path().join("c-log-1.log"),
        &["log", "5"],
    )?;
    let log_client_two = spawn_c_tinc_process(
        &c_tinc,
        &namespace,
        &confdir,
        &workspace.path().join("c-log-2.log"),
        &["log", "5"],
    )?;
    thread::sleep(Duration::from_millis(300));
    send_signal_from_pidfile(&namespace, &confdir.join("pid"), "HUP")?;
    thread::sleep(Duration::from_millis(300));

    let stop = run_rust_tincctl(&["tinc", "--config", confdir.to_str().unwrap(), "stop"]).map_err(
        |error| {
            format!(
                "Rust tincctl stop against Rust tincd failed after C log stream: {error}\n{}",
                cleanup.logs()
            )
        },
    )?;
    assert!(stop.is_empty(), "unexpected stop output: {stop}");
    let (_, output_one) = wait_for_c_tinc_log_subscriber(log_client_one, "first", &cleanup)?;
    let (_, output_two) = wait_for_c_tinc_log_subscriber(log_client_two, "second", &cleanup)?;
    assert_c_tinc_log_from_rust_daemon(&output_one, "first", &cleanup)?;
    assert_c_tinc_log_from_rust_daemon(&output_two, "second", &cleanup)?;
    wait_for_child_exit(&mut cleanup, "alpha")?;

    Ok(())
}

#[test]
fn linux_netns_c_tincctl_streams_pcap_from_rust_tincd_tun_nodes() -> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!("skipping C tincctl/Rust tincd pcap stream interop test: Linux-only test");
        return Ok(());
    }
    if !command_available("ip") || !command_available("ping") {
        eprintln!(
            "skipping C tincctl/Rust tincd pcap stream interop test: missing ip or ping command"
        );
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!(
            "skipping C tincctl/Rust tincd pcap stream interop test: /dev/net/tun is not available"
        );
        return Ok(());
    }
    let Some(c_tinc) = c_tinc_binary() else {
        eprintln!(
            "skipping C tincctl/Rust tincd pcap stream interop test: set C_TINC_PATH or build vendor/tinc/build-c/src/tinc"
        );
        return Ok(());
    };

    let workspace = TempWorkspace::new("tinc-cctl-rustdaemon-pcap")?;
    let suffix = unique_suffix();
    let ns_alpha = format!("tinc-ctl-pcap-a-{suffix}");
    let ns_beta = format!("tinc-ctl-pcap-b-{suffix}");
    let veth_alpha = format!("ca{suffix}");
    let veth_beta = format!("cb{suffix}");
    let alpha_confdir = workspace.path().join("alpha");
    let beta_confdir = workspace.path().join("beta");
    let mut cleanup = NetnsCleanup::new(workspace.path().to_path_buf());
    cleanup.add_namespace(ns_alpha.clone());
    cleanup.add_namespace(ns_beta.clone());

    create_node_config(
        &alpha_confdir,
        NodeConfig {
            name: "alpha",
            peer: "beta",
            port: 17458,
            bind_address: "192.0.2.41",
            peer_address: "192.0.2.42",
            peer_port: 17459,
            interface: "tun-alpha",
            tunnel_address: "10.250.1.1/24",
            subnet: "10.250.1.0/24",
            peer_subnet: "10.250.2.0/24",
            connect_to_peer: true,
            seed: 44,
            peer_seed: 45,
        },
    )?;
    create_node_config(
        &beta_confdir,
        NodeConfig {
            name: "beta",
            peer: "alpha",
            port: 17459,
            bind_address: "192.0.2.42",
            peer_address: "192.0.2.41",
            peer_port: 17458,
            interface: "tun-beta",
            tunnel_address: "10.250.2.1/24",
            subnet: "10.250.2.0/24",
            peer_subnet: "10.250.1.0/24",
            connect_to_peer: true,
            seed: 45,
            peer_seed: 44,
        },
    )?;
    if !try_ip(&["netns", "add", &ns_alpha]) || !try_ip(&["netns", "add", &ns_beta]) {
        eprintln!(
            "skipping C tincctl/Rust tincd pcap stream interop test: cannot create network namespaces"
        );
        return Ok(());
    }
    run_ip(&[
        "link",
        "add",
        &veth_alpha,
        "type",
        "veth",
        "peer",
        "name",
        &veth_beta,
    ])?;
    run_ip(&["link", "set", &veth_alpha, "netns", &ns_alpha])?;
    run_ip(&["link", "set", &veth_beta, "netns", &ns_beta])?;
    run_ip(&["-n", &ns_alpha, "link", "set", "lo", "up"])?;
    run_ip(&["-n", &ns_beta, "link", "set", "lo", "up"])?;
    run_ip(&[
        "-n",
        &ns_alpha,
        "addr",
        "add",
        "192.0.2.41/24",
        "dev",
        &veth_alpha,
    ])?;
    run_ip(&[
        "-n",
        &ns_beta,
        "addr",
        "add",
        "192.0.2.42/24",
        "dev",
        &veth_beta,
    ])?;
    run_ip(&["-n", &ns_alpha, "link", "set", &veth_alpha, "up"])?;
    run_ip(&["-n", &ns_beta, "link", "set", &veth_beta, "up"])?;

    cleanup.spawn(
        "alpha",
        &alpha_confdir,
        &ns_alpha,
        &workspace.path().join("alpha.log"),
    )?;
    cleanup.spawn(
        "beta",
        &beta_confdir,
        &ns_beta,
        &workspace.path().join("beta.log"),
    )?;
    wait_for_pidfile(&alpha_confdir.join("pid"), &cleanup)?;
    wait_for_control_socket(&alpha_confdir.join("pid.socket"), &cleanup)?;
    wait_for_pidfile(&beta_confdir.join("pid"), &cleanup)?;
    wait_for_control_socket(&beta_confdir.join("pid.socket"), &cleanup)?;
    wait_for_link(&ns_alpha, "tun-alpha", &cleanup)?;
    wait_for_link(&ns_beta, "tun-beta", &cleanup)?;

    let pcap_client_one = spawn_c_tinc_process(
        &c_tinc,
        &ns_alpha,
        &alpha_confdir,
        &workspace.path().join("c-pcap-1.log"),
        &["pcap", "128"],
    )?;
    let pcap_client_two = spawn_c_tinc_process(
        &c_tinc,
        &ns_alpha,
        &alpha_confdir,
        &workspace.path().join("c-pcap-2.log"),
        &["pcap", "128"],
    )?;
    wait_for_control_subscriber_count(
        &alpha_confdir,
        CONNECTION_STATUS_PCAP_RAW,
        2,
        "C pcap subscribers",
        &cleanup,
    )?;
    for _ in 0..4 {
        wait_for_ping(&ns_alpha, "10.250.2.1", &cleanup)?;
    }
    let stop = run_rust_tincctl(&["tinc", "--config", alpha_confdir.to_str().unwrap(), "stop"])
        .map_err(|error| {
            format!(
                "Rust tincctl stop against Rust alpha tincd failed after C pcap stream: {error}\n{}",
                cleanup.logs()
            )
    })?;
    assert!(stop.is_empty(), "unexpected stop output: {stop}");
    let output_one = wait_for_c_tinc_pcap_subscriber(pcap_client_one, "first", &cleanup)?;
    let output_two = wait_for_c_tinc_pcap_subscriber(pcap_client_two, "second", &cleanup)?;
    assert_pcap_packet_count_at_least(&output_one.stdout, 24, 4);
    assert_pcap_packet_count_at_least(&output_two.stdout, 24, 4);
    wait_for_child_exit(&mut cleanup, "alpha")?;
    let stop = run_rust_tincctl(&["tinc", "--config", beta_confdir.to_str().unwrap(), "stop"])
        .map_err(|error| {
            format!(
                "Rust tincctl stop against Rust beta tincd failed after C pcap stream: {error}\n{}",
                cleanup.logs()
            )
        })?;
    assert!(stop.is_empty(), "unexpected stop output: {stop}");
    wait_for_child_exit(&mut cleanup, "beta")?;

    Ok(())
}

#[test]
fn linux_netns_five_tincd_nodes_can_ping_over_tun() -> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!("skipping netns smoke test: Linux-only test");
        return Ok(());
    }
    if !command_available("ip") || !command_available("ping") {
        eprintln!("skipping netns smoke test: missing ip or ping command");
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!("skipping netns smoke test: /dev/net/tun is not available");
        return Ok(());
    }

    let workspace = TempWorkspace::new("tinc-rust-netns-five")?;
    let suffix = unique_suffix();
    let bridge = format!("br{suffix}");
    let nodes = (1..=5)
        .map(|index| MeshNode {
            name: format!("node{index}"),
            namespace: format!("tinc-rust-n{index}-{suffix}"),
            port: 16700 + index as u16,
            underlay_ip: format!("192.0.2.{index}"),
            underlay_cidr: format!("192.0.2.{index}/24"),
            interface: format!("tun-n{index}"),
            tunnel_ip: format!("10.200.{index}.1"),
            tunnel_cidr: format!("10.200.{index}.1/24"),
            subnet: format!("10.200.{index}.0/24"),
            seed: index as u8,
        })
        .collect::<Vec<_>>();
    let mut cleanup = NetnsCleanup::new(workspace.path().to_path_buf());

    for node in &nodes {
        cleanup.add_namespace(node.namespace.clone());
        create_mesh_node_config(workspace.path(), node, &nodes)?;
    }

    for node in &nodes {
        if !try_ip(&["netns", "add", &node.namespace]) {
            eprintln!("skipping netns smoke test: cannot create network namespaces");
            return Ok(());
        }
    }

    if !try_ip(&["link", "add", "name", &bridge, "type", "bridge"]) {
        eprintln!("skipping netns smoke test: cannot create bridge underlay");
        return Ok(());
    }
    cleanup.add_root_link(bridge.clone());
    run_ip(&["link", "set", &bridge, "up"])?;

    for (index, node) in nodes.iter().enumerate() {
        let root_link = format!("r{}{}", index + 1, suffix);
        let peer_link = format!("u{}{}", index + 1, suffix);
        cleanup.add_root_link(root_link.clone());
        run_ip(&[
            "link", "add", &root_link, "type", "veth", "peer", "name", &peer_link,
        ])?;
        run_ip(&["link", "set", &peer_link, "netns", &node.namespace])?;
        run_ip(&["link", "set", &root_link, "master", &bridge])?;
        run_ip(&["link", "set", &root_link, "up"])?;
        run_ip(&["-n", &node.namespace, "link", "set", "lo", "up"])?;
        run_ip(&[
            "-n",
            &node.namespace,
            "addr",
            "add",
            &node.underlay_cidr,
            "dev",
            &peer_link,
        ])?;
        run_ip(&["-n", &node.namespace, "link", "set", &peer_link, "up"])?;
    }

    for node in &nodes {
        cleanup.spawn(
            &node.name,
            &workspace.path().join(&node.name),
            &node.namespace,
            &workspace.path().join(format!("{}.log", node.name)),
        )?;
    }

    for node in &nodes {
        wait_for_link(&node.namespace, &node.interface, &cleanup)?;
    }

    for target in nodes.iter().skip(1) {
        wait_for_ping(&nodes[0].namespace, &target.tunnel_ip, &cleanup)?;
    }
    wait_for_ping(&nodes[4].namespace, &nodes[2].tunnel_ip, &cleanup)?;

    Ok(())
}

#[test]
fn linux_netns_tincd_opens_raw_socket_device_on_veth() -> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!("skipping raw socket netns test: Linux-only test");
        return Ok(());
    }
    if !command_available("ip") {
        eprintln!("skipping raw socket netns test: missing ip command");
        return Ok(());
    }

    let workspace = TempWorkspace::new("tinc-rust-raw-socket")?;
    let suffix = unique_suffix();
    let namespace = format!("tinc-rust-rs-{suffix}");
    let root_link = format!("rr{suffix}");
    let namespace_link = format!("rn{suffix}");
    let confdir = workspace.path().join("raw");
    let mut cleanup = NetnsCleanup::new(workspace.path().to_path_buf());
    cleanup.add_namespace(namespace.clone());
    cleanup.add_root_link(root_link.clone());

    create_raw_socket_node_config(&confdir, "raw", &namespace_link)?;

    if !try_ip(&["netns", "add", &namespace]) {
        eprintln!("skipping raw socket netns test: cannot create network namespace");
        return Ok(());
    }

    run_ip(&[
        "link",
        "add",
        &root_link,
        "type",
        "veth",
        "peer",
        "name",
        &namespace_link,
    ])?;
    run_ip(&["link", "set", &namespace_link, "netns", &namespace])?;
    run_ip(&["link", "set", &root_link, "up"])?;
    run_ip(&["-n", &namespace, "link", "set", "lo", "up"])?;
    run_ip(&["-n", &namespace, "link", "set", &namespace_link, "up"])?;

    cleanup.spawn(
        "raw",
        &confdir,
        &namespace,
        &workspace.path().join("raw.log"),
    )?;
    wait_for_pidfile(&confdir.join("pid"), &cleanup)?;
    cleanup.ensure_children_alive()?;

    Ok(())
}

#[test]
fn linux_netns_five_tincd_nodes_benchmark_and_route_after_link_cut() -> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    run_five_node_cut_scenario(NetnsDeviceMode::Tun, false, true, true)
}

#[test]
fn linux_netns_five_tincd_nodes_directonly_rejects_indirect_after_link_cut()
-> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    run_five_node_cut_scenario(NetnsDeviceMode::Tun, true, false, false)
}

#[test]
fn linux_netns_five_tincd_nodes_tap_benchmark_and_route_after_link_cut()
-> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    run_five_node_cut_scenario(NetnsDeviceMode::Tap, false, true, true)
}

#[test]
fn linux_netns_five_tincd_nodes_tap_directonly_rejects_indirect_after_link_cut()
-> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    run_five_node_cut_scenario(NetnsDeviceMode::Tap, true, false, false)
}

#[test]
fn linux_netns_six_tincd_nodes_concurrent_iperf3_direct_and_relay_after_pair_cuts()
-> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    run_six_node_concurrent_iperf3_direct_and_relay_after_pair_cuts(NetnsDeviceMode::Tun)
}

#[test]
fn linux_netns_six_tincd_nodes_tap_concurrent_iperf3_tcp_udp_direct_and_relay_after_pair_cuts()
-> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    run_six_node_concurrent_iperf3_direct_and_relay_after_pair_cuts(NetnsDeviceMode::Tap)
}

#[test]
fn linux_netns_tap_switch_passes_arp_like_tinc_device_tap_test() -> Result<(), Box<dyn Error>> {
    tinc_test_support::assert_can_create_netns();
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!("skipping tap arp netns test: Linux-only test");
        return Ok(());
    }
    if !command_available("ip") || !command_available("ping") || !command_available("arping") {
        eprintln!("skipping tap arp netns test: missing ip, ping, or arping command");
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!("skipping tap arp netns test: /dev/net/tun is not available");
        return Ok(());
    }

    let workspace = TempWorkspace::new("tinc-rust-tap-switch-arp")?;
    let suffix = unique_suffix();
    let ns_alpha = format!("tinc-rust-tap-a-{suffix}");
    let ns_beta = format!("tinc-rust-tap-b-{suffix}");
    let veth_alpha = format!("tpa{suffix}");
    let veth_beta = format!("tpb{suffix}");
    let mut cleanup = NetnsCleanup::new(workspace.path().to_path_buf());
    cleanup.add_namespace(ns_alpha.clone());
    cleanup.add_namespace(ns_beta.clone());

    create_tap_switch_node_config(
        &workspace.path().join("alpha"),
        TapSwitchNodeConfig {
            name: "alpha",
            peer: "beta",
            port: 17201,
            bind_address: "192.0.2.11",
            peer_address: "192.0.2.12",
            peer_port: 17202,
            interface: "tap-alpha",
            overlay_address: "10.230.0.1/24",
            subnet: "10.230.0.1",
            peer_subnet: "10.230.0.2",
            connect_to_peer: true,
            seed: 81,
            peer_seed: 82,
        },
    )?;
    create_tap_switch_node_config(
        &workspace.path().join("beta"),
        TapSwitchNodeConfig {
            name: "beta",
            peer: "alpha",
            port: 17202,
            bind_address: "192.0.2.12",
            peer_address: "192.0.2.11",
            peer_port: 17201,
            interface: "tap-beta",
            overlay_address: "10.230.0.2/24",
            subnet: "10.230.0.2",
            peer_subnet: "10.230.0.1",
            connect_to_peer: true,
            seed: 82,
            peer_seed: 81,
        },
    )?;

    if !try_ip(&["netns", "add", &ns_alpha]) || !try_ip(&["netns", "add", &ns_beta]) {
        eprintln!("skipping tap arp netns test: cannot create network namespaces");
        return Ok(());
    }

    run_ip(&[
        "link",
        "add",
        &veth_alpha,
        "type",
        "veth",
        "peer",
        "name",
        &veth_beta,
    ])?;
    run_ip(&["link", "set", &veth_alpha, "netns", &ns_alpha])?;
    run_ip(&["link", "set", &veth_beta, "netns", &ns_beta])?;
    run_ip(&["-n", &ns_alpha, "link", "set", "lo", "up"])?;
    run_ip(&["-n", &ns_beta, "link", "set", "lo", "up"])?;
    run_ip(&[
        "-n",
        &ns_alpha,
        "addr",
        "add",
        "192.0.2.11/24",
        "dev",
        &veth_alpha,
    ])?;
    run_ip(&[
        "-n",
        &ns_beta,
        "addr",
        "add",
        "192.0.2.12/24",
        "dev",
        &veth_beta,
    ])?;
    run_ip(&["-n", &ns_alpha, "link", "set", &veth_alpha, "up"])?;
    run_ip(&["-n", &ns_beta, "link", "set", &veth_beta, "up"])?;

    cleanup.spawn(
        "alpha",
        &workspace.path().join("alpha"),
        &ns_alpha,
        &workspace.path().join("alpha.log"),
    )?;
    cleanup.spawn(
        "beta",
        &workspace.path().join("beta"),
        &ns_beta,
        &workspace.path().join("beta.log"),
    )?;

    wait_for_link(&ns_alpha, "tap-alpha", &cleanup)?;
    wait_for_link(&ns_beta, "tap-beta", &cleanup)?;
    wait_for_ping(&ns_alpha, "10.230.0.2", &cleanup)?;

    run_ip(&["-n", &ns_beta, "link", "add", "dummy0", "type", "dummy"])?;
    run_ip(&[
        "-n",
        &ns_beta,
        "addr",
        "add",
        "10.230.0.3/24",
        "dev",
        "dummy0",
    ])?;
    run_ip(&["-n", &ns_beta, "link", "set", "dummy0", "up"])?;
    wait_for_arping(&ns_alpha, "tap-alpha", "10.230.0.3", &cleanup)?;

    Ok(())
}

fn run_six_node_concurrent_iperf3_direct_and_relay_after_pair_cuts(
    device_mode: NetnsDeviceMode,
) -> Result<(), Box<dyn Error>> {
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!("skipping netns smoke test: Linux-only test");
        return Ok(());
    }
    if !command_available("ip") || !command_available("ping") || !command_available("iperf3") {
        eprintln!("skipping netns smoke test: missing ip, ping, or iperf3 command");
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!("skipping netns smoke test: /dev/net/tun is not available");
        return Ok(());
    }

    let workspace = TempWorkspace::new(device_mode.workspace_prefix())?;
    let suffix = unique_suffix();
    let ipv4_octet = device_mode.ipv4_octet();
    let ipv6_segment = device_mode.ipv6_segment();
    let mut nodes = (1..=6)
        .map(|index| LinkNode {
            name: format!("node{index}"),
            namespace: format!("{}-{index}-{suffix}", device_mode.namespace_prefix()),
            port: device_mode.port_base() + index as u16,
            device_type: device_mode.device_type(),
            mode: device_mode.tap_routing_mode(),
            interface: format!("{}-p{index}", device_mode.interface_prefix()),
            tunnel_ip: format!("10.{ipv4_octet}.{index}.1"),
            tunnel_cidr: format!("10.{ipv4_octet}.{index}.1/24"),
            subnet: format!("10.{ipv4_octet}.{index}.0/24"),
            route: format!("10.{ipv4_octet}.0.0/16"),
            tunnel_ipv6: Some(format!("fd7a:{ipv6_segment}:{index}::1")),
            tunnel_ipv6_cidr: Some(format!("fd7a:{ipv6_segment}:{index}::1/64")),
            subnet_ipv6: Some(format!("fd7a:{ipv6_segment}:{index}::/64")),
            route_ipv6: Some(format!("fd7a:{ipv6_segment}::/32")),
            static_mac_subnet: device_mode.tap_static_mac_subnet(index),
            seed: (40 + index) as u8,
            bind_addresses: Vec::new(),
            neighbor_addresses: Vec::new(),
            connect_to: Vec::new(),
            indirect_peers: Vec::new(),
        })
        .collect::<Vec<_>>();
    let links = six_node_concurrent_topology(&suffix);
    apply_links_to_nodes(&mut nodes, &links);
    apply_connect_to(
        &mut nodes,
        &[
            (1, 2),
            (3, 4),
            (5, 6),
            (1, 3),
            (3, 5),
            (5, 2),
            (2, 4),
            (4, 6),
            (6, 1),
        ],
    );

    let mut cleanup = NetnsCleanup::new(workspace.path().to_path_buf());

    for node in &nodes {
        cleanup.add_namespace(node.namespace.clone());
        create_link_node_config(workspace.path(), node, &nodes, false)?;
    }
    for node in &nodes {
        if !try_ip(&["netns", "add", &node.namespace]) {
            eprintln!("skipping netns smoke test: cannot create network namespaces");
            return Ok(());
        }
    }

    for link in &links {
        run_ip(&[
            "link", "add", &link.a_if, "type", "veth", "peer", "name", &link.b_if,
        ])?;
        run_ip(&[
            "link",
            "set",
            &link.a_if,
            "netns",
            &nodes[link.a - 1].namespace,
        ])?;
        run_ip(&[
            "link",
            "set",
            &link.b_if,
            "netns",
            &nodes[link.b - 1].namespace,
        ])?;
        run_ip(&[
            "-n",
            &nodes[link.a - 1].namespace,
            "link",
            "set",
            "lo",
            "up",
        ])?;
        run_ip(&[
            "-n",
            &nodes[link.b - 1].namespace,
            "link",
            "set",
            "lo",
            "up",
        ])?;
        run_ip(&[
            "-n",
            &nodes[link.a - 1].namespace,
            "addr",
            "add",
            &link.a_cidr,
            "dev",
            &link.a_if,
        ])?;
        run_ip(&[
            "-n",
            &nodes[link.b - 1].namespace,
            "addr",
            "add",
            &link.b_cidr,
            "dev",
            &link.b_if,
        ])?;
        run_ip(&[
            "-n",
            &nodes[link.a - 1].namespace,
            "link",
            "set",
            &link.a_if,
            "up",
        ])?;
        run_ip(&[
            "-n",
            &nodes[link.b - 1].namespace,
            "link",
            "set",
            &link.b_if,
            "up",
        ])?;
    }

    for node in &nodes {
        cleanup.spawn(
            &node.name,
            &workspace.path().join(&node.name),
            &node.namespace,
            &workspace.path().join(format!("{}.log", node.name)),
        )?;
    }

    for node in &nodes {
        wait_for_link(&node.namespace, &node.interface, &cleanup)?;
    }
    wait_for_pair_pings(&nodes, &cleanup)?;
    wait_for_pair_ipv6_pings(&nodes, &cleanup)?;
    run_iperf3_pairs_concurrently(
        &nodes,
        &[Iperf3Mode::Tcp, Iperf3Mode::Udp],
        NetnsAddressFamily::Ipv4,
        &cleanup,
    )?;
    run_iperf3_pairs_concurrently(
        &nodes,
        &[Iperf3Mode::Tcp, Iperf3Mode::Udp],
        NetnsAddressFamily::Ipv6,
        &cleanup,
    )?;

    for (a, b) in [(1, 2), (3, 4), (5, 6)] {
        let link = links
            .iter()
            .find(|link| link.a == a && link.b == b)
            .expect("pair link exists");
        run_ip(&[
            "-n",
            &nodes[link.a - 1].namespace,
            "link",
            "set",
            &link.a_if,
            "down",
        ])?;
        run_ip(&[
            "-n",
            &nodes[link.b - 1].namespace,
            "link",
            "set",
            &link.b_if,
            "down",
        ])?;
    }

    wait_for_pair_pings(&nodes, &cleanup)?;
    wait_for_pair_ipv6_pings(&nodes, &cleanup)?;
    run_iperf3_pairs_concurrently(
        &nodes,
        &[Iperf3Mode::Tcp, Iperf3Mode::Udp],
        NetnsAddressFamily::Ipv4,
        &cleanup,
    )?;
    run_iperf3_pairs_concurrently(
        &nodes,
        &[Iperf3Mode::Tcp, Iperf3Mode::Udp],
        NetnsAddressFamily::Ipv6,
        &cleanup,
    )?;

    Ok(())
}

fn run_c_tincctl_rust_tincd_multihop_status_topology(
    indirect_edge: bool,
) -> Result<(), Box<dyn Error>> {
    if !cfg!(target_os = "linux") {
        eprintln!("skipping C tincctl/Rust tincd multihop dump interop test: Linux-only test");
        return Ok(());
    }
    if !command_available("ip") || !command_available("ping") {
        eprintln!(
            "skipping C tincctl/Rust tincd multihop dump interop test: missing ip or ping command"
        );
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!(
            "skipping C tincctl/Rust tincd multihop dump interop test: /dev/net/tun is not available"
        );
        return Ok(());
    }
    let Some(c_tinc) = c_tinc_binary() else {
        eprintln!(
            "skipping C tincctl/Rust tincd multihop dump interop test: set C_TINC_PATH or build vendor/tinc/build-c/src/tinc"
        );
        return Ok(());
    };

    let workspace = TempWorkspace::new(if indirect_edge {
        "tinc-cctl-rustdaemon-multihop-indirect"
    } else {
        "tinc-cctl-rustdaemon-multihop"
    })?;
    let suffix = unique_suffix();
    let mut nodes = (1..=3)
        .map(|index| LinkNode {
            name: format!("node{index}"),
            namespace: format!(
                "tinc-ctl-mhop{}-{index}-{suffix}",
                if indirect_edge { "i" } else { "d" }
            ),
            port: if indirect_edge {
                17570 + index as u16
            } else {
                17560 + index as u16
            },
            device_type: "tun",
            mode: None,
            interface: format!("tun-mh{}-{index}", if indirect_edge { "i" } else { "d" }),
            tunnel_ip: format!("10.252.{}.1", index),
            tunnel_cidr: format!("10.252.{}.1/24", index),
            subnet: format!("10.252.{}.0/24", index),
            route: "10.252.0.0/16".to_owned(),
            tunnel_ipv6: None,
            tunnel_ipv6_cidr: None,
            subnet_ipv6: None,
            route_ipv6: None,
            static_mac_subnet: None,
            seed: 70 + index as u8,
            bind_addresses: Vec::new(),
            neighbor_addresses: Vec::new(),
            connect_to: Vec::new(),
            indirect_peers: Vec::new(),
        })
        .collect::<Vec<_>>();
    let links = multihop_control_topology(&suffix, indirect_edge);
    apply_links_to_nodes(&mut nodes, &links);
    apply_connect_to(&mut nodes, &[(1, 2), (2, 3)]);
    if indirect_edge {
        nodes[1].indirect_peers.push("node3".to_owned());
        nodes[2].indirect_peers.push("node2".to_owned());
    }

    let mut cleanup = NetnsCleanup::new(workspace.path().to_path_buf());
    for node in &nodes {
        cleanup.add_namespace(node.namespace.clone());
        create_link_node_config(workspace.path(), node, &nodes, false)?;
    }
    for node in &nodes {
        if !try_ip(&["netns", "add", &node.namespace]) {
            eprintln!(
                "skipping C tincctl/Rust tincd multihop dump interop test: cannot create network namespaces"
            );
            return Ok(());
        }
    }
    for link in &links {
        create_netns_underlay_link(&nodes, link)?;
    }

    for node in &nodes {
        cleanup.spawn(
            &node.name,
            &workspace.path().join(&node.name),
            &node.namespace,
            &workspace.path().join(format!("{}.log", node.name)),
        )?;
    }
    for node in &nodes {
        wait_for_pidfile(&workspace.path().join(&node.name).join("pid"), &cleanup)?;
        wait_for_control_socket(
            &workspace.path().join(&node.name).join("pid.socket"),
            &cleanup,
        )?;
        wait_for_link(&node.namespace, &node.interface, &cleanup)?;
    }
    wait_for_ping(&nodes[0].namespace, &nodes[2].tunnel_ip, &cleanup)?;

    let node1_confdir = workspace.path().join("node1");
    let nodes_dump = run_c_tinc(
        &c_tinc,
        &nodes[0].namespace,
        &node1_confdir,
        &["dump", "nodes"],
    )?;
    assert_c_dump_node_has_status_words(&nodes_dump, "node1", &["reachable", "sptps"])?;
    assert_c_dump_node_has_status_words(&nodes_dump, "node2", &["reachable", "sptps"])?;
    assert_c_dump_node_has_status_words(&nodes_dump, "node3", &["reachable", "sptps"])?;
    if indirect_edge {
        assert_c_dump_node_has_route(&nodes_dump, "node3", "node2", "node2", 2)?;
        assert_c_dump_node_has_status_words(&nodes_dump, "node3", &["indirect"])?;
        assert_c_dump_node_options_include(&nodes_dump, "node3", 0x1)?;
    } else {
        assert_c_dump_node_has_route(&nodes_dump, "node3", "node2", "node3", 2)?;
    }

    let edges = run_c_tinc(
        &c_tinc,
        &nodes[0].namespace,
        &node1_confdir,
        &["dump", "edges"],
    )?;
    assert!(
        edges.contains("node1 to node2 at 198.20.1.2 port ")
            && edges.contains("node2 to node3 at 198.20.2.2 port "),
        "C tinc dump edges did not parse Rust multihop edge endpoints:\n{edges}\n{}",
        cleanup.logs()
    );
    if indirect_edge {
        assert_c_dump_edge_options_include(&edges, "node2", "node3", 0x1)?;
    }

    let subnets = run_c_tinc(
        &c_tinc,
        &nodes[0].namespace,
        &node1_confdir,
        &["dump", "subnets"],
    )?;
    assert!(
        subnets.contains("10.252.1.0/24 owner node1")
            && subnets.contains("10.252.2.0/24 owner node2")
            && subnets.contains("10.252.3.0/24 owner node3"),
        "C tinc dump subnets did not parse Rust multihop subnet owners:\n{subnets}\n{}",
        cleanup.logs()
    );

    let graph = run_c_tinc(
        &c_tinc,
        &nodes[0].namespace,
        &node1_confdir,
        &["dump", "graph"],
    )?;
    assert!(
        graph.contains("\"node1\"")
            && graph.contains("\"node2\"")
            && graph.contains("\"node3\"")
            && (graph.contains("\"node2\" -- \"node3\"")
                || graph.contains("\"node3\" -- \"node2\"")),
        "C tinc dump graph did not parse Rust multihop node/edge stream:\n{graph}\n{}",
        cleanup.logs()
    );

    let info = run_c_tinc(
        &c_tinc,
        &nodes[0].namespace,
        &node1_confdir,
        &["info", "node3"],
    )?;
    if indirect_edge {
        assert!(
            info.lines().any(|line| line.starts_with("Status:")
                && line.contains("reachable")
                && line.contains("indirect")
                && line.contains("sptps"))
                && info.contains("Reachability: indirectly via node2")
                && info.contains("Subnets:      10.252.3.0/24"),
            "C tinc info node3 did not interpret Rust indirect multihop status/topology like tinc:\n{info}\n{}",
            cleanup.logs()
        );
    } else {
        assert!(
            info.lines().any(|line| line.starts_with("Status:")
                && line.contains("reachable")
                && line.contains("sptps")
                && !line.contains("indirect"))
                && (info.contains("Reachability: directly with TCP")
                    || info.contains("Reachability: directly with UDP")
                    || info.contains("Reachability: none, forwarded via node2")
                    || info.contains("Reachability: unknown"))
                && info.contains("Subnets:      10.252.3.0/24"),
            "C tinc info node3 did not interpret Rust multihop status/topology like tinc:\n{info}\n{}",
            cleanup.logs()
        );
    }

    for node in &nodes {
        let stop = run_rust_tincctl(&[
            "tinc",
            "--config",
            workspace.path().join(&node.name).to_str().unwrap(),
            "stop",
        ])
        .map_err(|error| {
            format!(
                "Rust tincctl stop against Rust {} tincd failed after C multihop dump status test: {error}\n{}",
                node.name,
                cleanup.logs()
            )
        })?;
        assert!(stop.is_empty(), "unexpected stop output: {stop}");
        wait_for_child_exit(&mut cleanup, &node.name)?;
    }

    Ok(())
}

fn run_c_tincctl_rust_tincd_dynamic_relay_status_topology() -> Result<(), Box<dyn Error>> {
    if !cfg!(target_os = "linux") {
        eprintln!("skipping C tincctl/Rust tincd dynamic relay dump interop test: Linux-only test");
        return Ok(());
    }
    if !command_available("ip") || !command_available("ping") {
        eprintln!(
            "skipping C tincctl/Rust tincd dynamic relay dump interop test: missing ip or ping command"
        );
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!(
            "skipping C tincctl/Rust tincd dynamic relay dump interop test: /dev/net/tun is not available"
        );
        return Ok(());
    }
    let Some(c_tinc) = c_tinc_binary() else {
        eprintln!(
            "skipping C tincctl/Rust tincd dynamic relay dump interop test: set C_TINC_PATH or build vendor/tinc/build-c/src/tinc"
        );
        return Ok(());
    };

    let workspace = TempWorkspace::new("tinc-cctl-rustdaemon-dynamic-relay")?;
    let suffix = unique_suffix();
    let mut nodes = (1..=3)
        .map(|index| LinkNode {
            name: format!("node{index}"),
            namespace: format!("tinc-ctl-drelay-{index}-{suffix}"),
            port: 17590 + index as u16,
            device_type: "tun",
            mode: None,
            interface: format!("tun-dr-{index}"),
            tunnel_ip: format!("10.253.{}.1", index),
            tunnel_cidr: format!("10.253.{}.1/24", index),
            subnet: format!("10.253.{}.0/24", index),
            route: "10.253.0.0/16".to_owned(),
            tunnel_ipv6: None,
            tunnel_ipv6_cidr: None,
            subnet_ipv6: None,
            route_ipv6: None,
            static_mac_subnet: None,
            seed: 120 + index as u8,
            bind_addresses: Vec::new(),
            neighbor_addresses: Vec::new(),
            connect_to: Vec::new(),
            indirect_peers: Vec::new(),
        })
        .collect::<Vec<_>>();
    let links = vec![
        UnderlayLink {
            a: 1,
            b: 2,
            a_if: format!("cdr12a{suffix}"),
            b_if: format!("cdr12b{suffix}"),
            a_ip: "198.30.1.1".to_owned(),
            b_ip: "198.30.1.2".to_owned(),
            a_cidr: "198.30.1.1/30".to_owned(),
            b_cidr: "198.30.1.2/30".to_owned(),
        },
        UnderlayLink {
            a: 2,
            b: 3,
            a_if: format!("cdr23a{suffix}"),
            b_if: format!("cdr23b{suffix}"),
            a_ip: "198.30.2.1".to_owned(),
            b_ip: "198.30.2.2".to_owned(),
            a_cidr: "198.30.2.1/30".to_owned(),
            b_cidr: "198.30.2.2/30".to_owned(),
        },
    ];
    apply_links_to_nodes(&mut nodes, &links);
    apply_connect_to(&mut nodes, &[(1, 2), (2, 3)]);
    nodes[0]
        .neighbor_addresses
        .push(("node3".to_owned(), links[1].b_ip.clone()));
    nodes[2]
        .neighbor_addresses
        .push(("node1".to_owned(), links[0].a_ip.clone()));

    let mut cleanup = NetnsCleanup::new(workspace.path().to_path_buf());
    for node in &nodes {
        cleanup.add_namespace(node.namespace.clone());
        create_link_node_config(workspace.path(), node, &nodes, false)?;
    }
    for node in &nodes {
        if !try_ip(&["netns", "add", &node.namespace]) {
            eprintln!(
                "skipping C tincctl/Rust tincd dynamic relay dump interop test: cannot create network namespaces"
            );
            return Ok(());
        }
    }
    for link in &links {
        create_netns_underlay_link(&nodes, link)?;
    }
    run_ip(&[
        "-n",
        &nodes[0].namespace,
        "route",
        "add",
        "unreachable",
        &links[1].b_ip,
    ])?;
    run_ip(&[
        "-n",
        &nodes[2].namespace,
        "route",
        "add",
        "unreachable",
        &links[0].a_ip,
    ])?;

    for node in &nodes {
        cleanup.spawn(
            &node.name,
            &workspace.path().join(&node.name),
            &node.namespace,
            &workspace.path().join(format!("{}.log", node.name)),
        )?;
    }
    for node in &nodes {
        wait_for_pidfile(&workspace.path().join(&node.name).join("pid"), &cleanup)?;
        wait_for_control_socket(
            &workspace.path().join(&node.name).join("pid.socket"),
            &cleanup,
        )?;
        wait_for_link(&node.namespace, &node.interface, &cleanup)?;
    }
    wait_for_node_route_via(
        &workspace.path().join("node1"),
        "node3",
        "node2",
        "node3",
        false,
        &cleanup,
    )?;
    wait_for_ping(&nodes[0].namespace, &nodes[2].tunnel_ip, &cleanup)?;
    wait_for_ping(&nodes[2].namespace, &nodes[0].tunnel_ip, &cleanup)?;

    let node1_confdir = workspace.path().join("node1");
    let nodes_dump = run_c_tinc(
        &c_tinc,
        &nodes[0].namespace,
        &node1_confdir,
        &["dump", "nodes"],
    )?;
    assert_c_dump_node_has_status_words(&nodes_dump, "node1", &["reachable", "sptps"])?;
    assert_c_dump_node_has_status_words(&nodes_dump, "node2", &["reachable", "sptps"])?;
    assert_c_dump_node_has_status_words(&nodes_dump, "node3", &["reachable", "sptps"])?;
    assert_c_dump_node_lacks_status_words(&nodes_dump, "node3", &["indirect"])?;
    assert_c_dump_node_has_route(&nodes_dump, "node3", "node2", "node3", 2)?;

    let edges = run_c_tinc(
        &c_tinc,
        &nodes[0].namespace,
        &node1_confdir,
        &["dump", "edges"],
    )?;
    assert!(
        edges.contains("node1 to node2 at 198.30.1.2 port ")
            && edges.contains("node2 to node3 at 198.30.2.2 port "),
        "C tinc dump edges did not parse Rust dynamic relay edge endpoints:\n{edges}\n{}",
        cleanup.logs()
    );

    let subnets = run_c_tinc(
        &c_tinc,
        &nodes[0].namespace,
        &node1_confdir,
        &["dump", "subnets"],
    )?;
    assert!(
        subnets.contains("10.253.1.0/24 owner node1")
            && subnets.contains("10.253.2.0/24 owner node2")
            && subnets.contains("10.253.3.0/24 owner node3"),
        "C tinc dump subnets did not parse Rust dynamic relay subnet owners:\n{subnets}\n{}",
        cleanup.logs()
    );

    let info = run_c_tinc(
        &c_tinc,
        &nodes[0].namespace,
        &node1_confdir,
        &["info", "node3"],
    )?;
    assert!(
        info.lines().any(|line| line.starts_with("Status:")
            && line.contains("reachable")
            && line.contains("sptps")
            && !line.contains("indirect"))
            && (info.contains("Reachability: none, forwarded via node2")
                || info.contains("Reachability: directly with TCP")
                || info.contains("Reachability: directly with UDP")
                || info.contains("Reachability: unknown"))
            && info.contains("Subnets:      10.253.3.0/24"),
        "C tinc info node3 did not interpret Rust dynamic relay status/topology like tinc:\n{info}\n{}",
        cleanup.logs()
    );

    let stop = run_rust_tincctl(&[
        "tinc",
        "--config",
        node1_confdir.to_str().unwrap(),
        "stop",
    ])
    .map_err(|error| {
        format!(
            "Rust tincctl stop against Rust node1 failed after C dynamic relay dump status test: {error}\n{}",
            cleanup.logs()
        )
    })?;
    assert!(stop.is_empty(), "unexpected stop output: {stop}");
    wait_for_child_exit(&mut cleanup, "node1")?;

    Ok(())
}

fn run_c_tincctl_rust_tincd_tunnel_server_status_topology(
    c_tinc: &Path,
) -> Result<(), Box<dyn Error>> {
    let workspace = TempWorkspace::new("tinc-cctl-rustdaemon-tunnel-server-status")?;
    let suffix = unique_suffix();
    let mut nodes = (1..=3)
        .map(|index| LinkNode {
            name: match index {
                1 => "alpha",
                2 => "beta",
                3 => "gamma",
                _ => unreachable!(),
            }
            .to_owned(),
            namespace: format!("tinc-ctl-ts-{index}-{suffix}"),
            port: 18110 + index as u16,
            device_type: "tun",
            mode: None,
            interface: match index {
                1 => "tun-cts-a",
                2 => "tun-cts-b",
                3 => "tun-cts-g",
                _ => unreachable!(),
            }
            .to_owned(),
            tunnel_ip: format!("10.109.{index}.1"),
            tunnel_cidr: format!("10.109.{index}.1/24"),
            subnet: format!("10.109.{index}.0/24"),
            route: "10.109.0.0/16".to_owned(),
            tunnel_ipv6: None,
            tunnel_ipv6_cidr: None,
            subnet_ipv6: None,
            route_ipv6: None,
            static_mac_subnet: None,
            seed: 110 + index as u8,
            bind_addresses: Vec::new(),
            neighbor_addresses: Vec::new(),
            connect_to: Vec::new(),
            indirect_peers: Vec::new(),
        })
        .collect::<Vec<_>>();
    let links = vec![
        UnderlayLink {
            a: 1,
            b: 2,
            a_if: format!("cts12a{suffix}"),
            b_if: format!("cts12b{suffix}"),
            a_ip: "198.26.1.1".to_owned(),
            b_ip: "198.26.1.2".to_owned(),
            a_cidr: "198.26.1.1/30".to_owned(),
            b_cidr: "198.26.1.2/30".to_owned(),
        },
        UnderlayLink {
            a: 1,
            b: 3,
            a_if: format!("cts13a{suffix}"),
            b_if: format!("cts13b{suffix}"),
            a_ip: "198.26.2.1".to_owned(),
            b_ip: "198.26.2.2".to_owned(),
            a_cidr: "198.26.2.1/30".to_owned(),
            b_cidr: "198.26.2.2/30".to_owned(),
        },
    ];
    apply_links_to_nodes(&mut nodes, &links);
    apply_connect_to(&mut nodes, &[(2, 1), (3, 1)]);

    let mut cleanup = NetnsCleanup::new(workspace.path().to_path_buf());
    for node in &nodes {
        cleanup.add_namespace(node.namespace.clone());
        create_tunnel_server_node_config(workspace.path(), node, &nodes, node.name == "alpha")?;
    }
    for node in &nodes {
        if !try_ip(&["netns", "add", &node.namespace]) {
            eprintln!(
                "skipping C tincctl/Rust tincd tunnel-server dump interop test: cannot create network namespaces"
            );
            return Ok(());
        }
    }
    for link in &links {
        create_netns_underlay_link(&nodes, link)?;
    }

    for node in &nodes {
        cleanup.spawn(
            &node.name,
            &workspace.path().join(&node.name),
            &node.namespace,
            &workspace.path().join(format!("{}.log", node.name)),
        )?;
    }

    for node in &nodes {
        wait_for_pidfile(&workspace.path().join(&node.name).join("pid"), &cleanup)?;
        wait_for_control_socket(
            &workspace.path().join(&node.name).join("pid.socket"),
            &cleanup,
        )?;
        wait_for_link(&node.namespace, &node.interface, &cleanup)?;
    }

    wait_for_ping(&nodes[0].namespace, &nodes[1].tunnel_ip, &cleanup)?;
    wait_for_ping(&nodes[1].namespace, &nodes[0].tunnel_ip, &cleanup)?;
    wait_for_ping(&nodes[0].namespace, &nodes[2].tunnel_ip, &cleanup)?;
    wait_for_ping(&nodes[2].namespace, &nodes[0].tunnel_ip, &cleanup)?;
    wait_for_no_ping(&nodes[1].namespace, &nodes[2].tunnel_ip, &cleanup)?;
    wait_for_no_ping(&nodes[2].namespace, &nodes[1].tunnel_ip, &cleanup)?;

    let alpha_confdir = workspace.path().join("alpha");
    let alpha_nodes = run_c_tinc(
        c_tinc,
        &nodes[0].namespace,
        &alpha_confdir,
        &["dump", "nodes"],
    )?;
    assert_c_dump_node_has_status_words(&alpha_nodes, "alpha", &["reachable", "sptps"])?;
    assert_c_dump_node_has_status_words(&alpha_nodes, "beta", &["validkey", "reachable", "sptps"])?;
    assert_c_dump_node_has_status_words(
        &alpha_nodes,
        "gamma",
        &["validkey", "reachable", "sptps"],
    )?;
    assert_c_dump_node_has_route(&alpha_nodes, "beta", "beta", "beta", 1)?;
    assert_c_dump_node_has_route(&alpha_nodes, "gamma", "gamma", "gamma", 1)?;

    let alpha_edges = run_c_tinc(
        c_tinc,
        &nodes[0].namespace,
        &alpha_confdir,
        &["dump", "edges"],
    )?;
    assert!(
        alpha_edges.contains("alpha to beta at 198.26.1.2 port 18112")
            && alpha_edges.contains("alpha to gamma at 198.26.2.2 port 18113")
            && !alpha_edges.contains("beta to gamma")
            && !alpha_edges.contains("gamma to beta"),
        "C tinc dump edges did not parse Rust tunnel-server server view like C ack_h()/send_everything():\n{alpha_edges}\n{}",
        cleanup.logs()
    );

    let alpha_subnets = run_c_tinc(
        c_tinc,
        &nodes[0].namespace,
        &alpha_confdir,
        &["dump", "subnets"],
    )?;
    assert!(
        alpha_subnets.contains("10.109.1.0/24 owner alpha")
            && alpha_subnets.contains("10.109.2.0/24 owner beta")
            && alpha_subnets.contains("10.109.3.0/24 owner gamma"),
        "C tinc dump subnets did not parse Rust tunnel-server server subnet view:\n{alpha_subnets}\n{}",
        cleanup.logs()
    );

    let alpha_graph = run_c_tinc(
        c_tinc,
        &nodes[0].namespace,
        &alpha_confdir,
        &["dump", "graph"],
    )?;
    assert!(
        alpha_graph.contains("\"alpha\"")
            && alpha_graph.contains("\"beta\"")
            && alpha_graph.contains("\"gamma\"")
            && (alpha_graph.contains("\"alpha\" -- \"beta\"")
                || alpha_graph.contains("\"beta\" -- \"alpha\""))
            && (alpha_graph.contains("\"alpha\" -- \"gamma\"")
                || alpha_graph.contains("\"gamma\" -- \"alpha\""))
            && !alpha_graph.contains("\"beta\" -- \"gamma\"")
            && !alpha_graph.contains("\"gamma\" -- \"beta\""),
        "C tinc dump graph did not parse Rust tunnel-server server graph view:\n{alpha_graph}\n{}",
        cleanup.logs()
    );

    let alpha_info = run_c_tinc(
        c_tinc,
        &nodes[0].namespace,
        &alpha_confdir,
        &["info", "gamma"],
    )?;
    assert!(
        alpha_info.lines().any(|line| line.starts_with("Status:")
            && line.contains("validkey")
            && line.contains("reachable")
            && line.contains("sptps"))
            && (alpha_info.contains("Reachability: directly with TCP")
                || alpha_info.contains("Reachability: directly with UDP"))
            && alpha_info.contains("Subnets:      10.109.3.0/24"),
        "C tinc info gamma did not interpret Rust tunnel-server server view like tinc:\n{alpha_info}\n{}",
        cleanup.logs()
    );

    let beta_confdir = workspace.path().join("beta");
    let beta_nodes = run_c_tinc(
        c_tinc,
        &nodes[1].namespace,
        &beta_confdir,
        &["dump", "nodes"],
    )?;
    assert_c_dump_node_has_status_words(&beta_nodes, "beta", &["reachable", "sptps"])?;
    assert_c_dump_node_has_status_words(&beta_nodes, "alpha", &["validkey", "reachable", "sptps"])?;
    assert_c_dump_node_lacks_status_words(
        &beta_nodes,
        "gamma",
        &["validkey", "reachable", "sptps"],
    )?;

    let beta_edges = run_c_tinc(
        c_tinc,
        &nodes[1].namespace,
        &beta_confdir,
        &["dump", "edges"],
    )?;
    assert!(
        (beta_edges.contains("alpha to beta") || beta_edges.contains("beta to alpha"))
            && !beta_edges.contains("alpha to gamma")
            && !beta_edges.contains("gamma to alpha")
            && !beta_edges.contains("beta to gamma")
            && !beta_edges.contains("gamma to beta"),
        "C tinc dump edges saw another tunnel-server client from Rust client view:\n{beta_edges}\n{}",
        cleanup.logs()
    );

    let beta_subnets = run_c_tinc(
        c_tinc,
        &nodes[1].namespace,
        &beta_confdir,
        &["dump", "subnets"],
    )?;
    assert!(
        beta_subnets.contains("10.109.1.0/24 owner alpha")
            && beta_subnets.contains("10.109.2.0/24 owner beta")
            && !beta_subnets.contains("10.109.3.0/24 owner gamma"),
        "C tinc dump subnets saw another tunnel-server client from Rust client view:\n{beta_subnets}\n{}",
        cleanup.logs()
    );

    let beta_info = run_c_tinc(
        c_tinc,
        &nodes[1].namespace,
        &beta_confdir,
        &["info", "alpha"],
    )?;
    assert!(
        beta_info.lines().any(|line| line.starts_with("Status:")
            && line.contains("validkey")
            && line.contains("reachable")
            && line.contains("sptps"))
            && (beta_info.contains("Reachability: directly with TCP")
                || beta_info.contains("Reachability: directly with UDP"))
            && beta_info.contains("Subnets:      10.109.1.0/24"),
        "C tinc info alpha did not interpret Rust tunnel-server client view like tinc:\n{beta_info}\n{}",
        cleanup.logs()
    );

    let gamma_info = run_c_tinc(
        c_tinc,
        &nodes[1].namespace,
        &beta_confdir,
        &["info", "gamma"],
    )?;
    assert!(
        gamma_info.lines().any(|line| line.starts_with("Status:")
            && !line.contains("validkey")
            && !line.contains("reachable")
            && !line.contains("sptps"))
            && gamma_info.contains("Reachability: unreachable")
            && gamma_info.contains("Subnets:     \n"),
        "C tinc info gamma should only see the local preconfigured unreachable host in Rust tunnel-server client view:\n{gamma_info}\n{}",
        cleanup.logs()
    );

    for node in &nodes {
        let stop = run_rust_tincctl(&[
            "tinc",
            "--config",
            workspace.path().join(&node.name).to_str().unwrap(),
            "stop",
        ])
        .map_err(|error| {
            format!(
                "Rust tincctl stop against Rust {} tincd failed after C tunnel-server dump status test: {error}\n{}",
                node.name,
                cleanup.logs()
            )
        })?;
        assert!(stop.is_empty(), "unexpected stop output: {stop}");
        wait_for_child_exit(&mut cleanup, &node.name)?;
    }

    Ok(())
}

fn run_five_node_cut_scenario(
    device_mode: NetnsDeviceMode,
    direct_only: bool,
    expect_ping_after_cut: bool,
    run_iperf: bool,
) -> Result<(), Box<dyn Error>> {
    let _guard = netns_test_guard();

    if !cfg!(target_os = "linux") {
        eprintln!("skipping netns smoke test: Linux-only test");
        return Ok(());
    }
    if !command_available("ip") || !command_available("ping") {
        eprintln!("skipping netns smoke test: missing ip or ping command");
        return Ok(());
    }
    if run_iperf && !command_available("iperf3") {
        eprintln!("skipping netns smoke test: missing iperf3 command");
        return Ok(());
    }
    if !Path::new("/dev/net/tun").exists() {
        eprintln!("skipping netns smoke test: /dev/net/tun is not available");
        return Ok(());
    }

    let daemon_binary = std::env::var_os("FIVE_NODE_TINCD_BINARY").map(PathBuf::from);
    let workspace = TempWorkspace::new(match (device_mode, direct_only) {
        (NetnsDeviceMode::Tun, true) => "tinc-rust-tun-directonly-cut",
        (NetnsDeviceMode::Tun, false) => "tinc-rust-tun-relay-cut",
        (NetnsDeviceMode::Tap, true) => "tinc-rust-tap-directonly-cut",
        (NetnsDeviceMode::Tap, false) => "tinc-rust-tap-relay-cut",
    })?;
    let suffix = unique_suffix();
    let ipv4_octet = match device_mode {
        NetnsDeviceMode::Tun => 210,
        NetnsDeviceMode::Tap => 211,
    };
    let ipv6_segment = match device_mode {
        NetnsDeviceMode::Tun => "210",
        NetnsDeviceMode::Tap => "211",
    };
    let port_base = match device_mode {
        NetnsDeviceMode::Tun => 16800,
        NetnsDeviceMode::Tap => 17100,
    };
    let mut nodes = (1..=5)
        .map(|index| LinkNode {
            name: format!("node{index}"),
            namespace: format!("{}-c{index}-{suffix}", device_mode.namespace_prefix()),
            port: port_base + index as u16,
            device_type: device_mode.device_type(),
            mode: device_mode.tap_routing_mode(),
            interface: format!("{}-c{index}", device_mode.interface_prefix()),
            tunnel_ip: format!("10.{ipv4_octet}.{index}.1"),
            tunnel_cidr: format!("10.{ipv4_octet}.{index}.1/24"),
            subnet: format!("10.{ipv4_octet}.{index}.0/24"),
            route: format!("10.{ipv4_octet}.0.0/16"),
            tunnel_ipv6: Some(format!("fd7a:{ipv6_segment}:{index}::1")),
            tunnel_ipv6_cidr: Some(format!("fd7a:{ipv6_segment}:{index}::1/64")),
            subnet_ipv6: Some(format!("fd7a:{ipv6_segment}:{index}::/64")),
            route_ipv6: Some(format!("fd7a:{ipv6_segment}::/32")),
            static_mac_subnet: None,
            seed: (20 + index) as u8,
            bind_addresses: Vec::new(),
            neighbor_addresses: Vec::new(),
            connect_to: Vec::new(),
            indirect_peers: Vec::new(),
        })
        .collect::<Vec<_>>();
    let links = link_cut_topology(&suffix);
    apply_links_to_nodes(&mut nodes, &links);
    apply_connect_to(&mut nodes, &[(1, 2), (1, 3), (3, 2), (2, 4), (4, 5)]);

    let mut cleanup = NetnsCleanup::new(workspace.path().to_path_buf());

    for node in &nodes {
        cleanup.add_namespace(node.namespace.clone());
        create_link_node_config(workspace.path(), node, &nodes, direct_only)?;
    }
    for node in &nodes {
        if !try_ip(&["netns", "add", &node.namespace]) {
            eprintln!("skipping netns smoke test: cannot create network namespaces");
            return Ok(());
        }
    }

    for link in &links {
        run_ip(&[
            "link", "add", &link.a_if, "type", "veth", "peer", "name", &link.b_if,
        ])?;
        run_ip(&[
            "link",
            "set",
            &link.a_if,
            "netns",
            &nodes[link.a - 1].namespace,
        ])?;
        run_ip(&[
            "link",
            "set",
            &link.b_if,
            "netns",
            &nodes[link.b - 1].namespace,
        ])?;
        run_ip(&[
            "-n",
            &nodes[link.a - 1].namespace,
            "link",
            "set",
            "lo",
            "up",
        ])?;
        run_ip(&[
            "-n",
            &nodes[link.b - 1].namespace,
            "link",
            "set",
            "lo",
            "up",
        ])?;
        run_ip(&[
            "-n",
            &nodes[link.a - 1].namespace,
            "addr",
            "add",
            &link.a_cidr,
            "dev",
            &link.a_if,
        ])?;
        run_ip(&[
            "-n",
            &nodes[link.b - 1].namespace,
            "addr",
            "add",
            &link.b_cidr,
            "dev",
            &link.b_if,
        ])?;
        run_ip(&[
            "-n",
            &nodes[link.a - 1].namespace,
            "link",
            "set",
            &link.a_if,
            "up",
        ])?;
        run_ip(&[
            "-n",
            &nodes[link.b - 1].namespace,
            "link",
            "set",
            &link.b_if,
            "up",
        ])?;
    }

    for node in &nodes {
        if let Some(binary) = daemon_binary.as_deref() {
            cleanup.spawn_with_binary(
                &node.name,
                binary,
                &workspace.path().join(&node.name),
                &node.namespace,
                &workspace.path().join(format!("{}.log", node.name)),
            )?;
        } else {
            cleanup.spawn(
                &node.name,
                &workspace.path().join(&node.name),
                &node.namespace,
                &workspace.path().join(format!("{}.log", node.name)),
            )?;
        }
    }

    for node in &nodes {
        wait_for_link(&node.namespace, &node.interface, &cleanup)?;
    }
    wait_for_ping(&nodes[0].namespace, &nodes[1].tunnel_ip, &cleanup)?;
    wait_for_ping(
        &nodes[0].namespace,
        nodes[1].tunnel_address(NetnsAddressFamily::Ipv6),
        &cleanup,
    )?;
    if !direct_only {
        wait_for_ping(&nodes[0].namespace, &nodes[4].tunnel_ip, &cleanup)?;
        wait_for_ping(
            &nodes[0].namespace,
            nodes[4].tunnel_address(NetnsAddressFamily::Ipv6),
            &cleanup,
        )?;
    }
    if run_iperf {
        run_iperf_pair(
            &nodes[0].namespace,
            &nodes[4].namespace,
            nodes[4].tunnel_address(NetnsAddressFamily::Ipv4),
            NetnsAddressFamily::Ipv4,
            &cleanup,
        )?;
        run_iperf_pair(
            &nodes[0].namespace,
            &nodes[4].namespace,
            nodes[4].tunnel_address(NetnsAddressFamily::Ipv6),
            NetnsAddressFamily::Ipv6,
            &cleanup,
        )?;
    }

    let cut = links
        .iter()
        .find(|link| link.a == 1 && link.b == 2)
        .expect("cut link exists");
    run_ip(&["-n", &nodes[0].namespace, "link", "set", &cut.a_if, "down"])?;
    run_ip(&["-n", &nodes[1].namespace, "link", "set", &cut.b_if, "down"])?;

    if expect_ping_after_cut {
        wait_for_ping(&nodes[0].namespace, &nodes[1].tunnel_ip, &cleanup)?;
        wait_for_ping(
            &nodes[0].namespace,
            nodes[1].tunnel_address(NetnsAddressFamily::Ipv6),
            &cleanup,
        )?;
    } else {
        wait_for_no_ping(&nodes[0].namespace, &nodes[1].tunnel_ip, &cleanup)?;
        wait_for_no_ping(
            &nodes[0].namespace,
            nodes[1].tunnel_address(NetnsAddressFamily::Ipv6),
            &cleanup,
        )?;
    }

    Ok(())
}

struct NodeConfig<'a> {
    name: &'a str,
    peer: &'a str,
    port: u16,
    bind_address: &'a str,
    peer_address: &'a str,
    peer_port: u16,
    interface: &'a str,
    tunnel_address: &'a str,
    subnet: &'a str,
    peer_subnet: &'a str,
    connect_to_peer: bool,
    seed: u8,
    peer_seed: u8,
}

struct TapSwitchNodeConfig<'a> {
    name: &'a str,
    peer: &'a str,
    port: u16,
    bind_address: &'a str,
    peer_address: &'a str,
    peer_port: u16,
    interface: &'a str,
    overlay_address: &'a str,
    subnet: &'a str,
    peer_subnet: &'a str,
    connect_to_peer: bool,
    seed: u8,
    peer_seed: u8,
}

struct LegacyNodeConfig<'a> {
    name: &'a str,
    peer: &'a str,
    port: u16,
    bind_address: &'a str,
    peer_address: &'a str,
    peer_port: u16,
    interface: &'a str,
    tunnel_address: &'a str,
    subnet: &'a str,
    peer_subnet: &'a str,
    connect_to_peer: bool,
    private_key: &'a RsaPrivateKey,
    public_key: &'a RsaPublicKey,
    peer_public_key: &'a RsaPublicKey,
    key_expire: Option<u16>,
    fast_ping: bool,
    legacy_crypto: LegacyCryptoConfig<'a>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LegacyCryptoConfig<'a> {
    cipher: &'a str,
    digest: &'a str,
    mac_length: Option<u8>,
    compression: u8,
    expected_cipher: i32,
    expected_digest: i32,
    expected_mac_length: i32,
    expected_compression: i32,
    require_no_plaintext: bool,
}

impl Default for LegacyCryptoConfig<'_> {
    fn default() -> Self {
        Self {
            cipher: "aes-256-cbc",
            digest: "sha256",
            mac_length: Some(LEGACY_MAC_LENGTH as u8),
            compression: 0,
            expected_cipher: LEGACY_AES_256_CBC_NID,
            expected_digest: LEGACY_SHA256_NID,
            expected_mac_length: LEGACY_MAC_LENGTH,
            expected_compression: 0,
            require_no_plaintext: false,
        }
    }
}

impl LegacyCryptoConfig<'_> {
    fn no_crypto() -> Self {
        Self {
            cipher: "none",
            digest: "none",
            mac_length: Some(0),
            compression: 0,
            expected_cipher: 0,
            expected_digest: 0,
            expected_mac_length: 0,
            expected_compression: 0,
            require_no_plaintext: false,
        }
    }

    fn zlib1() -> Self {
        Self {
            compression: CompressionLevel::Zlib1 as u8,
            expected_compression: CompressionLevel::Zlib1 as i32,
            require_no_plaintext: true,
            ..Self::default()
        }
    }

    fn zlib9() -> Self {
        Self {
            compression: CompressionLevel::Zlib9 as u8,
            expected_compression: CompressionLevel::Zlib9 as i32,
            require_no_plaintext: true,
            ..Self::default()
        }
    }

    fn lz4() -> Self {
        Self {
            compression: CompressionLevel::Lz4 as u8,
            expected_compression: CompressionLevel::Lz4 as i32,
            require_no_plaintext: true,
            ..Self::default()
        }
    }

    fn lzo_low() -> Self {
        Self {
            compression: CompressionLevel::LzoLow as u8,
            expected_compression: CompressionLevel::LzoLow as i32,
            require_no_plaintext: true,
            ..Self::default()
        }
    }

    const fn compression_name(self) -> &'static str {
        match self.expected_compression {
            1 => "zlib1",
            9 => "zlib9",
            10 => "lzo",
            12 => "lz4",
            _ => "legacy-compression",
        }
    }
}

struct LegacyUpgradeNodeConfig<'a> {
    name: &'a str,
    peer: &'a str,
    port: u16,
    bind_address: &'a str,
    peer_address: &'a str,
    peer_port: u16,
    interface: &'a str,
    tunnel_address: &'a str,
    subnet: &'a str,
    peer_subnet: &'a str,
    connect_to_peer: bool,
    seed: u8,
    private_key: &'a RsaPrivateKey,
    public_key: &'a RsaPublicKey,
    peer_public_key: &'a RsaPublicKey,
}

struct LegacyMultihopNode {
    name: &'static str,
    namespace: String,
    port: u16,
    interface: &'static str,
    tunnel_address: &'static str,
    tunnel_ip: &'static str,
    subnet: &'static str,
    route: &'static str,
    bind_addresses: Vec<String>,
    neighbor_addresses: Vec<(&'static str, String)>,
    connect_to: Vec<&'static str>,
    indirect_peers: Vec<&'static str>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NoPlaintextCapture {
    Tcp,
    TcpAndUdp,
    Udp,
}

fn create_node_config(dir: &Path, config: NodeConfig<'_>) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(dir.join("hosts"))?;
    let node_key = key(config.seed);
    let peer_key = key(config.peer_seed);
    let connect_to = if config.connect_to_peer {
        format!("ConnectTo = {}\n", config.peer)
    } else {
        String::new()
    };

    fs::write(dir.join("ed25519_key.priv"), node_key.to_pem())?;
    fs::write(
        dir.join("tinc.conf"),
        format!(
            "Name = {}\nPort = {}\nAutoConnect = no\nDeviceType = tun\nInterface = {}\nAddressFamily = IPv4\nBindToAddress = {} {}\nStrictSubnets = yes\n{}",
            config.name,
            config.port,
            config.interface,
            config.bind_address,
            config.port,
            connect_to
        ),
    )?;
    fs::write(
        dir.join("hosts").join(config.name),
        format!(
            "Ed25519PublicKey = {}\nSubnet = {}\n",
            node_key.public_key().to_base64(),
            config.subnet
        ),
    )?;
    fs::write(
        dir.join("hosts").join(config.peer),
        format!(
            "Ed25519PublicKey = {}\nAddress = {} {}\nSubnet = {}\n",
            peer_key.public_key().to_base64(),
            config.peer_address,
            config.peer_port,
            config.peer_subnet
        ),
    )?;
    let script = dir.join("tinc-up");
    fs::write(
        &script,
        format!(
            "#!/bin/sh\nip addr add {} dev \"$INTERFACE\"\nip link set \"$INTERFACE\" up\nip route add {} dev \"$INTERFACE\"\n",
            config.tunnel_address, config.peer_subnet
        ),
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mut permissions = fs::metadata(&script)?.permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&script, permissions)?;
    }

    Ok(())
}

fn create_dummy_node_config(
    dir: &Path,
    name: &str,
    port: u16,
    seed: u8,
) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(dir.join("hosts"))?;
    let node_key = key(seed);

    fs::write(dir.join("ed25519_key.priv"), node_key.to_pem())?;
    fs::write(
        dir.join("tinc.conf"),
        format!(
            "Name = {name}\nPort = {port}\nExperimentalProtocol = yes\nAutoConnect = no\nDeviceType = dummy\nAddressFamily = IPv4\nBindToAddress = 127.0.0.1 {port}\nStrictSubnets = yes\nLogLevel = 5\n"
        ),
    )?;
    fs::write(
        dir.join("hosts").join(name),
        format!(
            "Ed25519PublicKey = {}\nSubnet = 10.250.{}.0/24\n",
            node_key.public_key().to_base64(),
            seed
        ),
    )?;

    Ok(())
}

fn create_invitation_server_node_config(
    dir: &Path,
    name: &str,
    port: u16,
    seed: u8,
) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(dir.join("hosts"))?;
    let node_key = key(seed);

    fs::write(dir.join("ed25519_key.priv"), node_key.to_pem())?;
    fs::write(
        dir.join("tinc.conf"),
        format!(
            "Name = {name}\nPort = {port}\nMode = switch\nExperimentalProtocol = yes\nAutoConnect = no\nDeviceType = dummy\nAddressFamily = IPv4\nBindToAddress = 127.0.0.1 {port}\nStrictSubnets = yes\nLogLevel = 5\n"
        ),
    )?;
    fs::write(
        dir.join("hosts").join(name),
        format!(
            "Address = 127.0.0.1 {port}\nPort = 0\nEd25519PublicKey = {}\n",
            node_key.public_key().to_base64()
        ),
    )?;

    Ok(())
}

fn invitation_cookie_files(invitations_dir: &Path) -> Result<Vec<String>, Box<dyn Error>> {
    let mut files = fs::read_dir(invitations_dir)?
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let name = entry.file_name().into_string().ok()?;
            (name.len() == 24).then_some(name)
        })
        .collect::<Vec<_>>();
    files.sort();
    Ok(files)
}

fn write_tinc_down_marker_script(dir: &Path, marker: &Path) -> Result<(), Box<dyn Error>> {
    let script = dir.join("tinc-down");
    fs::write(
        &script,
        format!(
            "#!/bin/sh\nprintf 'down NAME=%s DEVICE=%s INTERFACE=%s\\n' \"$NAME\" \"$DEVICE\" \"$INTERFACE\" >> {}\n",
            shell_quote_path(marker)
        ),
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mut permissions = fs::metadata(&script)?.permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&script, permissions)?;
    }

    Ok(())
}

fn shell_quote_path(path: &Path) -> String {
    let text = path.display().to_string();
    format!("'{}'", text.replace('\'', "'\\''"))
}

fn create_legacy_node_config(
    dir: &Path,
    config: LegacyNodeConfig<'_>,
) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(dir.join("hosts"))?;
    let connect_to = if config.connect_to_peer {
        format!("ConnectTo = {}\n", config.peer)
    } else {
        String::new()
    };
    let key_expire = config
        .key_expire
        .map(|seconds| format!("KeyExpire = {seconds}\n"))
        .unwrap_or_default();
    let ping_timing = if config.fast_ping {
        "PingInterval = 1\nPingTimeout = 1\nMaxTimeout = 5\n"
    } else {
        ""
    };
    let mac_length = config
        .legacy_crypto
        .mac_length
        .map(|length| format!("MACLength = {length}\n"))
        .unwrap_or_default();

    write_private_key_file(dir, config.private_key)?;

    fs::write(
        dir.join("tinc.conf"),
        format!(
            "Name = {}\nPort = {}\nExperimentalProtocol = no\nAutoConnect = no\nDeviceType = tun\nInterface = {}\nAddressFamily = IPv4\nBindToAddress = {} {}\nStrictSubnets = yes\nLogLevel = 5\nCipher = {}\nDigest = {}\n{}Compression = {}\n{}{}{}",
            config.name,
            config.port,
            config.interface,
            config.bind_address,
            config.port,
            config.legacy_crypto.cipher,
            config.legacy_crypto.digest,
            mac_length,
            config.legacy_crypto.compression,
            key_expire,
            ping_timing,
            connect_to
        ),
    )?;
    fs::write(
        dir.join("hosts").join(config.name),
        format!(
            "Subnet = {}\n{}",
            config.subnet,
            config.public_key.to_pkcs1_pem(LineEnding::LF)?
        ),
    )?;
    fs::write(
        dir.join("hosts").join(config.peer),
        format!(
            "Address = {} {}\nSubnet = {}\n{}",
            config.peer_address,
            config.peer_port,
            config.peer_subnet,
            config.peer_public_key.to_pkcs1_pem(LineEnding::LF)?
        ),
    )?;
    let script = dir.join("tinc-up");
    fs::write(
        &script,
        format!(
            "#!/bin/sh\nip addr add {} dev \"$INTERFACE\"\nip link set \"$INTERFACE\" up\nip route add {} dev \"$INTERFACE\"\n",
            config.tunnel_address, config.peer_subnet
        ),
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mut permissions = fs::metadata(&script)?.permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&script, permissions)?;
    }

    Ok(())
}

fn force_tcponly_on_two_node_hosts(confdir: &Path, peer: &str) -> Result<(), Box<dyn Error>> {
    fs::OpenOptions::new()
        .append(true)
        .open(confdir.join("hosts").join(peer))?
        .write_all(b"TCPOnly = yes\n")?;
    Ok(())
}

fn create_legacy_multihop_node_config(
    workspace: &Path,
    node: &LegacyMultihopNode,
    nodes: &[LegacyMultihopNode],
    private_key: &RsaPrivateKey,
    public_keys: &[RsaPublicKey],
) -> Result<(), Box<dyn Error>> {
    create_legacy_multihop_node_config_inner(
        workspace,
        node,
        nodes,
        private_key,
        public_keys,
        None,
        None,
    )
}

fn create_legacy_multihop_node_config_with_tunnel_server(
    workspace: &Path,
    node: &LegacyMultihopNode,
    nodes: &[LegacyMultihopNode],
    private_key: &RsaPrivateKey,
    public_keys: &[RsaPublicKey],
    tunnel_server: bool,
    key_expire: Option<u16>,
) -> Result<(), Box<dyn Error>> {
    create_legacy_multihop_node_config_inner(
        workspace,
        node,
        nodes,
        private_key,
        public_keys,
        Some(tunnel_server),
        key_expire,
    )
}

fn create_legacy_multihop_node_config_inner(
    workspace: &Path,
    node: &LegacyMultihopNode,
    nodes: &[LegacyMultihopNode],
    private_key: &RsaPrivateKey,
    public_keys: &[RsaPublicKey],
    tunnel_server: Option<bool>,
    key_expire: Option<u16>,
) -> Result<(), Box<dyn Error>> {
    let dir = workspace.join(node.name);
    fs::create_dir_all(dir.join("hosts"))?;
    let connect_to = node
        .connect_to
        .iter()
        .map(|peer| format!("ConnectTo = {peer}\n"))
        .collect::<String>();
    let bind_to = node
        .bind_addresses
        .iter()
        .map(|address| format!("BindToAddress = {address} {}\n", node.port))
        .collect::<String>();
    let tunnel_server_config = if tunnel_server == Some(true) {
        "TunnelServer = yes\n"
    } else {
        ""
    };
    let key_expire = key_expire
        .map(|seconds| format!("KeyExpire = {seconds}\n"))
        .unwrap_or_default();

    write_private_key_file(&dir, private_key)?;

    fs::write(
        dir.join("tinc.conf"),
        format!(
            "Name = {}\nPort = {}\nExperimentalProtocol = no\nAutoConnect = no\nDeviceType = tun\nInterface = {}\nAddressFamily = IPv4\nStrictSubnets = yes\n{}LogLevel = 5\nPingInterval = 1\nPingTimeout = 1\nCompression = 0\n{}{}{}",
            node.name,
            node.port,
            node.interface,
            tunnel_server_config,
            key_expire,
            bind_to,
            connect_to
        ),
    )?;

    for (index, host) in nodes.iter().enumerate() {
        let address = node
            .neighbor_addresses
            .iter()
            .find(|(name, _)| name == &host.name)
            .map(|(_, address)| format!("Address = {address} {}\n", host.port))
            .unwrap_or_default();
        let indirect_data = if node.indirect_peers.iter().any(|peer| peer == &host.name) {
            "IndirectData = yes\n"
        } else {
            ""
        };
        let subnet = if tunnel_server
            .map(|is_server| is_server || host.name == node.name || host.name == nodes[0].name)
            .unwrap_or(true)
        {
            format!("Subnet = {}\n", host.subnet)
        } else {
            String::new()
        };
        fs::write(
            dir.join("hosts").join(host.name),
            format!(
                "{}{}{}{}",
                address,
                indirect_data,
                subnet,
                public_keys[index].to_pkcs1_pem(LineEnding::LF)?
            ),
        )?;
    }

    let script = dir.join("tinc-up");
    fs::write(
        &script,
        format!(
            "#!/bin/sh\nip addr add {} dev \"$INTERFACE\"\nip link set \"$INTERFACE\" up\nip route add {} dev \"$INTERFACE\"\n",
            node.tunnel_address, node.route
        ),
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mut permissions = fs::metadata(&script)?.permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&script, permissions)?;
    }

    Ok(())
}

fn write_private_key_file(dir: &Path, key: &RsaPrivateKey) -> Result<(), Box<dyn Error>> {
    let private_key = dir.join("rsa_key.priv");
    fs::write(&private_key, key.to_pkcs1_pem(LineEnding::LF)?.as_str())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mut permissions = fs::metadata(&private_key)?.permissions();
        permissions.set_mode(0o600);
        fs::set_permissions(&private_key, permissions)?;
    }

    Ok(())
}

fn create_legacy_upgrade_node_config(
    dir: &Path,
    config: LegacyUpgradeNodeConfig<'_>,
) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(dir.join("hosts"))?;
    let node_key = key(config.seed);
    let connect_to = if config.connect_to_peer {
        format!("ConnectTo = {}\n", config.peer)
    } else {
        String::new()
    };

    fs::write(dir.join("ed25519_key.priv"), node_key.to_pem())?;
    write_private_key_file(dir, config.private_key)?;

    fs::write(
        dir.join("tinc.conf"),
        format!(
            "Name = {}\nPort = {}\nAutoConnect = no\nDeviceType = tun\nInterface = {}\nAddressFamily = IPv4\nBindToAddress = {} {}\nStrictSubnets = yes\nLogLevel = 5\nCompression = 0\n{}",
            config.name,
            config.port,
            config.interface,
            config.bind_address,
            config.port,
            connect_to
        ),
    )?;
    fs::write(
        dir.join("hosts").join(config.name),
        format!(
            "Subnet = {}\nEd25519PublicKey = {}\n{}",
            config.subnet,
            node_key.public_key().to_base64(),
            config.public_key.to_pkcs1_pem(LineEnding::LF)?
        ),
    )?;
    fs::write(
        dir.join("hosts").join(config.peer),
        format!(
            "Address = {} {}\nSubnet = {}\n{}",
            config.peer_address,
            config.peer_port,
            config.peer_subnet,
            config.peer_public_key.to_pkcs1_pem(LineEnding::LF)?
        ),
    )?;
    let script = dir.join("tinc-up");
    fs::write(
        &script,
        format!(
            "#!/bin/sh\nip addr add {} dev \"$INTERFACE\"\nip link set \"$INTERFACE\" up\nip route add {} dev \"$INTERFACE\"\n",
            config.tunnel_address, config.peer_subnet
        ),
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mut permissions = fs::metadata(&script)?.permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&script, permissions)?;
    }

    Ok(())
}

fn create_tap_switch_node_config(
    dir: &Path,
    config: TapSwitchNodeConfig<'_>,
) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(dir.join("hosts"))?;
    let node_key = key(config.seed);
    let peer_key = key(config.peer_seed);
    let connect_to = if config.connect_to_peer {
        format!("ConnectTo = {}\n", config.peer)
    } else {
        String::new()
    };

    fs::write(dir.join("ed25519_key.priv"), node_key.to_pem())?;
    fs::write(
        dir.join("tinc.conf"),
        format!(
            "Name = {}\nPort = {}\nAutoConnect = no\nDeviceType = tap\nMode = switch\nInterface = {}\nAddressFamily = IPv4\nBindToAddress = {} {}\nStrictSubnets = yes\n{}",
            config.name,
            config.port,
            config.interface,
            config.bind_address,
            config.port,
            connect_to
        ),
    )?;
    fs::write(
        dir.join("hosts").join(config.name),
        format!(
            "Ed25519PublicKey = {}\nSubnet = {}\n",
            node_key.public_key().to_base64(),
            config.subnet
        ),
    )?;
    fs::write(
        dir.join("hosts").join(config.peer),
        format!(
            "Ed25519PublicKey = {}\nAddress = {} {}\nSubnet = {}\n",
            peer_key.public_key().to_base64(),
            config.peer_address,
            config.peer_port,
            config.peer_subnet
        ),
    )?;
    let script = dir.join("tinc-up");
    fs::write(
        &script,
        format!(
            "#!/bin/sh\nip addr add {} dev \"$INTERFACE\"\nip link set \"$INTERFACE\" up\n",
            config.overlay_address
        ),
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mut permissions = fs::metadata(&script)?.permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&script, permissions)?;
    }

    Ok(())
}

fn key(byte: u8) -> TincEd25519PrivateKey {
    TincEd25519PrivateKey::from_seed([byte; ED25519_SEED_LEN])
}

fn create_raw_socket_node_config(
    dir: &Path,
    name: &str,
    interface: &str,
) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(dir.join("hosts"))?;
    let node_key = key(42);

    fs::write(dir.join("ed25519_key.priv"), node_key.to_pem())?;
    fs::write(
        dir.join("tinc.conf"),
        format!(
            "Name = {name}\nPort = 0\nDeviceType = raw_socket\nInterface = {interface}\nAddressFamily = IPv4\nBindToAddress = 127.0.0.1 0\n",
        ),
    )?;
    fs::write(
        dir.join("hosts").join(name),
        format!("Ed25519PublicKey = {}\n", node_key.public_key().to_base64()),
    )?;

    Ok(())
}

struct MeshNode {
    name: String,
    namespace: String,
    port: u16,
    underlay_ip: String,
    underlay_cidr: String,
    interface: String,
    tunnel_ip: String,
    tunnel_cidr: String,
    subnet: String,
    seed: u8,
}

struct LinkNode {
    name: String,
    namespace: String,
    port: u16,
    device_type: &'static str,
    mode: Option<&'static str>,
    interface: String,
    tunnel_ip: String,
    tunnel_cidr: String,
    subnet: String,
    route: String,
    tunnel_ipv6: Option<String>,
    tunnel_ipv6_cidr: Option<String>,
    subnet_ipv6: Option<String>,
    route_ipv6: Option<String>,
    static_mac_subnet: Option<String>,
    seed: u8,
    bind_addresses: Vec<String>,
    neighbor_addresses: Vec<(String, String)>,
    connect_to: Vec<String>,
    indirect_peers: Vec<String>,
}

struct ReqPubkeyNode {
    name: &'static str,
    namespace: String,
    port: u16,
    interface: &'static str,
    tunnel_address: &'static str,
    tunnel_ip: &'static str,
    subnet: &'static str,
    route: &'static str,
    seed: u8,
    bind_addresses: Vec<String>,
    neighbor_addresses: Vec<(&'static str, String)>,
    connect_to: Vec<&'static str>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NetnsDeviceMode {
    Tun,
    Tap,
}

impl NetnsDeviceMode {
    fn workspace_prefix(self) -> &'static str {
        match self {
            Self::Tun => "tinc-rust-six-tun-concurrent-iperf",
            Self::Tap => "tinc-rust-six-tap-concurrent-iperf",
        }
    }

    fn namespace_prefix(self) -> &'static str {
        match self {
            Self::Tun => "tinc-rust-tun6",
            Self::Tap => "tinc-rust-tap6",
        }
    }

    fn interface_prefix(self) -> &'static str {
        match self {
            Self::Tun => "tun",
            Self::Tap => "tap",
        }
    }

    fn device_type(self) -> &'static str {
        match self {
            Self::Tun => "tun",
            Self::Tap => "tap",
        }
    }

    fn tap_routing_mode(self) -> Option<&'static str> {
        match self {
            Self::Tun => None,
            Self::Tap => Some("switch"),
        }
    }

    fn tap_static_mac_subnet(self, index: usize) -> Option<String> {
        match self {
            Self::Tun => None,
            Self::Tap => Some(format!("02:00:00:00:dd:{index:02x}")),
        }
    }

    fn port_base(self) -> u16 {
        match self {
            Self::Tun => 16900,
            Self::Tap => 17000,
        }
    }

    fn ipv4_octet(self) -> u8 {
        match self {
            Self::Tun => 220,
            Self::Tap => 221,
        }
    }

    fn ipv6_segment(self) -> &'static str {
        match self {
            Self::Tun => "220",
            Self::Tap => "221",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Iperf3Mode {
    Tcp,
    Udp,
}

impl Iperf3Mode {
    fn port(self) -> &'static str {
        match self {
            Self::Tcp => "5201",
            Self::Udp => "5202",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NetnsAddressFamily {
    Ipv4,
    Ipv6,
}

impl NetnsAddressFamily {
    fn label(self) -> &'static str {
        match self {
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
        }
    }
}

impl LinkNode {
    fn tunnel_address(&self, family: NetnsAddressFamily) -> &str {
        match family {
            NetnsAddressFamily::Ipv4 => &self.tunnel_ip,
            NetnsAddressFamily::Ipv6 => self
                .tunnel_ipv6
                .as_deref()
                .expect("IPv6 tunnel address is configured for this test"),
        }
    }
}

struct UnderlayLink {
    a: usize,
    b: usize,
    a_if: String,
    b_if: String,
    a_ip: String,
    b_ip: String,
    a_cidr: String,
    b_cidr: String,
}

fn link_cut_topology(suffix: &str) -> Vec<UnderlayLink> {
    [(1, 2), (1, 3), (3, 2), (2, 4), (4, 5)]
        .into_iter()
        .enumerate()
        .map(|(index, (a, b))| {
            let net = index + 1;
            UnderlayLink {
                a,
                b,
                a_if: format!("c{a}{b}a{suffix}"),
                b_if: format!("c{a}{b}b{suffix}"),
                a_ip: format!("198.18.{net}.1"),
                b_ip: format!("198.18.{net}.2"),
                a_cidr: format!("198.18.{net}.1/30"),
                b_cidr: format!("198.18.{net}.2/30"),
            }
        })
        .collect()
}

fn six_node_concurrent_topology(suffix: &str) -> Vec<UnderlayLink> {
    [
        (1, 2),
        (3, 4),
        (5, 6),
        (1, 3),
        (3, 5),
        (5, 2),
        (2, 4),
        (4, 6),
        (6, 1),
    ]
    .into_iter()
    .enumerate()
    .map(|(index, (a, b))| {
        let net = index + 1;
        UnderlayLink {
            a,
            b,
            a_if: format!("p{a}{b}a{suffix}"),
            b_if: format!("p{a}{b}b{suffix}"),
            a_ip: format!("198.19.{net}.1"),
            b_ip: format!("198.19.{net}.2"),
            a_cidr: format!("198.19.{net}.1/30"),
            b_cidr: format!("198.19.{net}.2/30"),
        }
    })
    .collect()
}

fn multihop_control_topology(suffix: &str, indirect_edge: bool) -> Vec<UnderlayLink> {
    [(1, 2), (2, 3)]
        .into_iter()
        .enumerate()
        .map(|(index, (a, b))| {
            let net = index + 1;
            UnderlayLink {
                a,
                b,
                a_if: format!("m{a}{b}a{}{suffix}", if indirect_edge { "i" } else { "d" }),
                b_if: format!("m{a}{b}b{}{suffix}", if indirect_edge { "i" } else { "d" }),
                a_ip: format!("198.20.{net}.1"),
                b_ip: format!("198.20.{net}.2"),
                a_cidr: format!("198.20.{net}.1/30"),
                b_cidr: format!("198.20.{net}.2/30"),
            }
        })
        .collect()
}

fn apply_links_to_nodes(nodes: &mut [LinkNode], links: &[UnderlayLink]) {
    for link in links {
        let a_name = nodes[link.a - 1].name.clone();
        let b_name = nodes[link.b - 1].name.clone();
        nodes[link.a - 1].bind_addresses.push(link.a_ip.clone());
        nodes[link.b - 1].bind_addresses.push(link.b_ip.clone());
        nodes[link.a - 1]
            .neighbor_addresses
            .push((b_name, link.b_ip.clone()));
        nodes[link.b - 1]
            .neighbor_addresses
            .push((a_name, link.a_ip.clone()));
    }
}

fn apply_connect_to(nodes: &mut [LinkNode], edges: &[(usize, usize)]) {
    for (from, to) in edges {
        let peer = nodes[*to - 1].name.clone();
        nodes[*from - 1].connect_to.push(peer);
    }
}

fn create_netns_underlay_link(
    nodes: &[LinkNode],
    link: &UnderlayLink,
) -> Result<(), Box<dyn Error>> {
    run_ip(&[
        "link", "add", &link.a_if, "type", "veth", "peer", "name", &link.b_if,
    ])?;
    run_ip(&[
        "link",
        "set",
        &link.a_if,
        "netns",
        &nodes[link.a - 1].namespace,
    ])?;
    run_ip(&[
        "link",
        "set",
        &link.b_if,
        "netns",
        &nodes[link.b - 1].namespace,
    ])?;
    run_ip(&[
        "-n",
        &nodes[link.a - 1].namespace,
        "link",
        "set",
        "lo",
        "up",
    ])?;
    run_ip(&[
        "-n",
        &nodes[link.b - 1].namespace,
        "link",
        "set",
        "lo",
        "up",
    ])?;
    run_ip(&[
        "-n",
        &nodes[link.a - 1].namespace,
        "addr",
        "add",
        &link.a_cidr,
        "dev",
        &link.a_if,
    ])?;
    run_ip(&[
        "-n",
        &nodes[link.b - 1].namespace,
        "addr",
        "add",
        &link.b_cidr,
        "dev",
        &link.b_if,
    ])?;
    run_ip(&[
        "-n",
        &nodes[link.a - 1].namespace,
        "link",
        "set",
        &link.a_if,
        "up",
    ])?;
    run_ip(&[
        "-n",
        &nodes[link.b - 1].namespace,
        "link",
        "set",
        &link.b_if,
        "up",
    ])?;

    Ok(())
}

fn create_req_pubkey_underlay_link(
    nodes: &[ReqPubkeyNode],
    link: &UnderlayLink,
) -> Result<(), Box<dyn Error>> {
    run_ip(&[
        "link", "add", &link.a_if, "type", "veth", "peer", "name", &link.b_if,
    ])?;
    run_ip(&[
        "link",
        "set",
        &link.a_if,
        "netns",
        &nodes[link.a - 1].namespace,
    ])?;
    run_ip(&[
        "link",
        "set",
        &link.b_if,
        "netns",
        &nodes[link.b - 1].namespace,
    ])?;
    run_ip(&[
        "-n",
        &nodes[link.a - 1].namespace,
        "link",
        "set",
        "lo",
        "up",
    ])?;
    run_ip(&[
        "-n",
        &nodes[link.b - 1].namespace,
        "link",
        "set",
        "lo",
        "up",
    ])?;
    run_ip(&[
        "-n",
        &nodes[link.a - 1].namespace,
        "addr",
        "add",
        &link.a_cidr,
        "dev",
        &link.a_if,
    ])?;
    run_ip(&[
        "-n",
        &nodes[link.b - 1].namespace,
        "addr",
        "add",
        &link.b_cidr,
        "dev",
        &link.b_if,
    ])?;
    run_ip(&[
        "-n",
        &nodes[link.a - 1].namespace,
        "link",
        "set",
        &link.a_if,
        "up",
    ])?;
    run_ip(&[
        "-n",
        &nodes[link.b - 1].namespace,
        "link",
        "set",
        &link.b_if,
        "up",
    ])?;

    Ok(())
}

fn create_legacy_multihop_underlay_link(
    nodes: &[LegacyMultihopNode],
    link: &UnderlayLink,
) -> Result<(), Box<dyn Error>> {
    run_ip(&[
        "link", "add", &link.a_if, "type", "veth", "peer", "name", &link.b_if,
    ])?;
    run_ip(&[
        "link",
        "set",
        &link.a_if,
        "netns",
        &nodes[link.a - 1].namespace,
    ])?;
    run_ip(&[
        "link",
        "set",
        &link.b_if,
        "netns",
        &nodes[link.b - 1].namespace,
    ])?;
    run_ip(&[
        "-n",
        &nodes[link.a - 1].namespace,
        "link",
        "set",
        "lo",
        "up",
    ])?;
    run_ip(&[
        "-n",
        &nodes[link.b - 1].namespace,
        "link",
        "set",
        "lo",
        "up",
    ])?;
    run_ip(&[
        "-n",
        &nodes[link.a - 1].namespace,
        "addr",
        "add",
        &link.a_cidr,
        "dev",
        &link.a_if,
    ])?;
    run_ip(&[
        "-n",
        &nodes[link.b - 1].namespace,
        "addr",
        "add",
        &link.b_cidr,
        "dev",
        &link.b_if,
    ])?;
    run_ip(&[
        "-n",
        &nodes[link.a - 1].namespace,
        "link",
        "set",
        &link.a_if,
        "up",
    ])?;
    run_ip(&[
        "-n",
        &nodes[link.b - 1].namespace,
        "link",
        "set",
        &link.b_if,
        "up",
    ])?;

    Ok(())
}

fn create_mesh_node_config(
    workspace: &Path,
    node: &MeshNode,
    nodes: &[MeshNode],
) -> Result<(), Box<dyn Error>> {
    let dir = workspace.join(&node.name);
    fs::create_dir_all(dir.join("hosts"))?;
    let connect_to = if node.name == "node1" {
        String::new()
    } else {
        "ConnectTo = node1\n".to_owned()
    };

    fs::write(dir.join("ed25519_key.priv"), key(node.seed).to_pem())?;
    fs::write(
        dir.join("tinc.conf"),
        format!(
            "Name = {}\nPort = {}\nDeviceType = tun\nInterface = {}\nAddressFamily = IPv4\nBindToAddress = {} {}\nStrictSubnets = yes\n{}",
            node.name, node.port, node.interface, node.underlay_ip, node.port, connect_to
        ),
    )?;

    for host in nodes {
        let host_key = key(host.seed);
        let address = if host.name == node.name {
            String::new()
        } else {
            format!("Address = {} {}\n", host.underlay_ip, host.port)
        };
        fs::write(
            dir.join("hosts").join(&host.name),
            format!(
                "Ed25519PublicKey = {}\n{}Subnet = {}\n",
                host_key.public_key().to_base64(),
                address,
                host.subnet
            ),
        )?;
    }

    let script = dir.join("tinc-up");
    fs::write(
        &script,
        format!(
            "#!/bin/sh\nip addr add {} dev \"$INTERFACE\"\nip link set \"$INTERFACE\" up\nip route add 10.200.0.0/16 dev \"$INTERFACE\"\n",
            node.tunnel_cidr
        ),
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mut permissions = fs::metadata(&script)?.permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&script, permissions)?;
    }

    Ok(())
}

fn create_req_pubkey_node_config(
    workspace: &Path,
    node: &ReqPubkeyNode,
    nodes: &[ReqPubkeyNode],
    omit_key_for: &[&str],
) -> Result<(), Box<dyn Error>> {
    let dir = workspace.join(node.name);
    fs::create_dir_all(dir.join("hosts"))?;
    let connect_to = node
        .connect_to
        .iter()
        .map(|peer| format!("ConnectTo = {peer}\n"))
        .collect::<String>();
    let bind_to = node
        .bind_addresses
        .iter()
        .map(|address| format!("BindToAddress = {address} {}\n", node.port))
        .collect::<String>();

    fs::write(dir.join("ed25519_key.priv"), key(node.seed).to_pem())?;
    fs::write(
        dir.join("tinc.conf"),
        format!(
            "Name = {}\nPort = {}\nDeviceType = tun\nInterface = {}\nAddressFamily = IPv4\nStrictSubnets = yes\nLogLevel = 5\nPingInterval = 1\nPingTimeout = 1\n{}{}",
            node.name, node.port, node.interface, bind_to, connect_to
        ),
    )?;

    for host in nodes {
        let public_key = if omit_key_for.iter().any(|name| name == &host.name) {
            String::new()
        } else {
            format!(
                "Ed25519PublicKey = {}\n",
                key(host.seed).public_key().to_base64()
            )
        };
        let address = node
            .neighbor_addresses
            .iter()
            .find(|(name, _)| name == &host.name)
            .map(|(_, address)| format!("Address = {address} {}\n", host.port))
            .unwrap_or_default();
        fs::write(
            dir.join("hosts").join(host.name),
            format!("{public_key}{address}Subnet = {}\n", host.subnet),
        )?;
    }

    let script = dir.join("tinc-up");
    fs::write(
        &script,
        format!(
            "#!/bin/sh\nip addr add {} dev \"$INTERFACE\"\nip link set \"$INTERFACE\" up\nip route add {} dev \"$INTERFACE\"\n",
            node.tunnel_address, node.route
        ),
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mut permissions = fs::metadata(&script)?.permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&script, permissions)?;
    }

    Ok(())
}

fn create_link_node_config(
    workspace: &Path,
    node: &LinkNode,
    nodes: &[LinkNode],
    direct_only: bool,
) -> Result<(), Box<dyn Error>> {
    let dir = workspace.join(&node.name);
    fs::create_dir_all(dir.join("hosts"))?;
    let connect_to = node
        .connect_to
        .iter()
        .map(|peer| format!("ConnectTo = {peer}\n"))
        .collect::<String>();
    let direct_only = if direct_only {
        "DirectOnly = yes\n"
    } else {
        ""
    };
    let mode = node
        .mode
        .map(|mode| format!("Mode = {mode}\n"))
        .unwrap_or_default();

    fs::write(dir.join("ed25519_key.priv"), key(node.seed).to_pem())?;
    fs::write(
        dir.join("tinc.conf"),
        format!(
            "Name = {}\nPort = {}\nDeviceType = {}\nInterface = {}\nAddressFamily = IPv4\nStrictSubnets = yes\nPingInterval = 1\nPingTimeout = 1\n{}{}{}",
            node.name, node.port, node.device_type, node.interface, mode, direct_only, connect_to
        ),
    )?;

    for host in nodes {
        let host_key = key(host.seed);
        let address = node
            .neighbor_addresses
            .iter()
            .find(|(name, _)| name == &host.name)
            .map(|(_, address)| format!("Address = {address} {}\n", host.port))
            .unwrap_or_default();
        let indirect_data = if node.indirect_peers.iter().any(|peer| peer == &host.name) {
            "IndirectData = yes\n"
        } else {
            ""
        };
        let subnet_ipv6 = host
            .subnet_ipv6
            .as_ref()
            .map(|subnet| format!("Subnet = {subnet}\n"))
            .unwrap_or_default();
        let static_mac_subnet = host
            .static_mac_subnet
            .as_ref()
            .map(|subnet| format!("Subnet = {subnet}\n"))
            .unwrap_or_default();
        fs::write(
            dir.join("hosts").join(&host.name),
            format!(
                "Ed25519PublicKey = {}\n{}{}Subnet = {}\n{}{}",
                host_key.public_key().to_base64(),
                address,
                indirect_data,
                host.subnet,
                subnet_ipv6,
                static_mac_subnet
            ),
        )?;
    }

    let script = dir.join("tinc-up");
    let mac_script = node
        .static_mac_subnet
        .as_ref()
        .map(|mac| {
            format!(
                "# switch mode with StrictSubnets needs an authorized MAC route for unicast frames.\nip link set dev \"$INTERFACE\" address {mac}\n"
            )
        })
        .unwrap_or_default();
    let ipv6_script = match (&node.tunnel_ipv6_cidr, &node.route_ipv6) {
        (Some(cidr), Some(route)) => {
            format!(
                "ip -6 addr add {cidr} dev \"$INTERFACE\" nodad\nip -6 route add {route} dev \"$INTERFACE\"\n"
            )
        }
        _ => String::new(),
    };
    fs::write(
        &script,
        format!(
            "#!/bin/sh\n{}ip addr add {} dev \"$INTERFACE\"\nip link set \"$INTERFACE\" up\nip route add {} dev \"$INTERFACE\"\n{}",
            mac_script, node.tunnel_cidr, node.route, ipv6_script
        ),
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mut permissions = fs::metadata(&script)?.permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&script, permissions)?;
    }

    Ok(())
}

fn create_strict_subnet_node_config(
    workspace: &Path,
    node: &LinkNode,
    nodes: &[LinkNode],
    strict_subnets: bool,
    extra_self_subnet: Option<&str>,
    authorized_extra_subnets: &[(&str, &str)],
) -> Result<(), Box<dyn Error>> {
    let dir = workspace.join(&node.name);
    fs::create_dir_all(dir.join("hosts"))?;
    let connect_to = node
        .connect_to
        .iter()
        .map(|peer| format!("ConnectTo = {peer}\n"))
        .collect::<String>();
    let bind_to = node
        .bind_addresses
        .iter()
        .map(|address| format!("BindToAddress = {address} {}\n", node.port))
        .collect::<String>();
    let strict = if strict_subnets {
        "StrictSubnets = yes\n"
    } else {
        "StrictSubnets = no\n"
    };

    fs::write(dir.join("ed25519_key.priv"), key(node.seed).to_pem())?;
    fs::write(
        dir.join("tinc.conf"),
        format!(
            "Name = {}\nPort = {}\nDeviceType = tun\nInterface = {}\nAddressFamily = IPv4\n{}LogLevel = 5\nPingInterval = 1\nPingTimeout = 1\n{}{}",
            node.name, node.port, node.interface, strict, bind_to, connect_to
        ),
    )?;

    for host in nodes {
        let host_key = key(host.seed);
        let address = node
            .neighbor_addresses
            .iter()
            .find(|(name, _)| name == &host.name)
            .map(|(_, address)| format!("Address = {address} {}\n", host.port))
            .unwrap_or_default();
        let self_extra = if host.name == node.name {
            extra_self_subnet
                .map(|subnet| format!("Subnet = {subnet}\n"))
                .unwrap_or_default()
        } else {
            String::new()
        };
        let authorized_extra = authorized_extra_subnets
            .iter()
            .filter(|(owner, _)| *owner == host.name)
            .map(|(_, subnet)| format!("Subnet = {subnet}\n"))
            .collect::<String>();
        fs::write(
            dir.join("hosts").join(&host.name),
            format!(
                "Ed25519PublicKey = {}\n{}Subnet = {}\n{}{}",
                host_key.public_key().to_base64(),
                address,
                host.subnet,
                self_extra,
                authorized_extra
            ),
        )?;
    }

    let script = dir.join("tinc-up");
    fs::write(
        &script,
        format!(
            "#!/bin/sh\nip addr add {} dev \"$INTERFACE\"\nip link set \"$INTERFACE\" up\nip route add {} dev \"$INTERFACE\"\n",
            node.tunnel_cidr, node.route
        ),
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mut permissions = fs::metadata(&script)?.permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&script, permissions)?;
    }

    Ok(())
}

fn create_tunnel_server_node_config(
    workspace: &Path,
    node: &LinkNode,
    nodes: &[LinkNode],
    tunnel_server: bool,
) -> Result<(), Box<dyn Error>> {
    let dir = workspace.join(&node.name);
    fs::create_dir_all(dir.join("hosts"))?;
    let connect_to = node
        .connect_to
        .iter()
        .map(|peer| format!("ConnectTo = {peer}\n"))
        .collect::<String>();
    let bind_to = node
        .bind_addresses
        .iter()
        .map(|address| format!("BindToAddress = {address} {}\n", node.port))
        .collect::<String>();
    let is_tunnel_server = tunnel_server;
    let tunnel_server = if is_tunnel_server {
        "TunnelServer = yes\n"
    } else {
        ""
    };

    fs::write(dir.join("ed25519_key.priv"), key(node.seed).to_pem())?;
    fs::write(
        dir.join("tinc.conf"),
        format!(
            "Name = {}\nPort = {}\nDeviceType = tun\nInterface = {}\nAddressFamily = IPv4\nStrictSubnets = yes\n{}LogLevel = 5\nPingInterval = 1\nPingTimeout = 1\n{}{}",
            node.name, node.port, node.interface, tunnel_server, bind_to, connect_to
        ),
    )?;

    for host in nodes {
        let host_key = key(host.seed);
        let address = node
            .neighbor_addresses
            .iter()
            .find(|(name, _)| name == &host.name)
            .map(|(_, address)| format!("Address = {address} {}\n", host.port))
            .unwrap_or_default();
        let subnet = if is_tunnel_server || host.name == node.name || host.name == nodes[0].name {
            format!("Subnet = {}\n", host.subnet)
        } else {
            String::new()
        };
        fs::write(
            dir.join("hosts").join(&host.name),
            format!(
                "Ed25519PublicKey = {}\n{}{}",
                host_key.public_key().to_base64(),
                address,
                subnet
            ),
        )?;
    }

    let script = dir.join("tinc-up");
    fs::write(
        &script,
        format!(
            "#!/bin/sh\nip addr add {} dev \"$INTERFACE\"\nip link set \"$INTERFACE\" up\nip route add {} dev \"$INTERFACE\"\n",
            node.tunnel_cidr, node.route
        ),
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mut permissions = fs::metadata(&script)?.permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&script, permissions)?;
    }

    Ok(())
}

fn run_c_rust_two_node_tun_interop(
    c_tincd: &Path,
    rust_connects_to_c: bool,
) -> Result<(), Box<dyn Error>> {
    run_c_rust_two_node_tun_interop_inner(c_tincd, rust_connects_to_c, false, None)
}

fn run_c_rust_two_node_tun_no_plain_udp_payload(
    c_tincd: &Path,
    rust_connects_to_c: bool,
) -> Result<(), Box<dyn Error>> {
    run_c_rust_two_node_tun_interop_inner(
        c_tincd,
        rust_connects_to_c,
        false,
        Some(NoPlaintextCapture::Udp),
    )
}

fn run_c_rust_two_node_tun_restart_no_plain_underlay_payload(
    c_tincd: &Path,
    rust_connects_to_c: bool,
) -> Result<(), Box<dyn Error>> {
    run_c_rust_two_node_tun_interop_inner(
        c_tincd,
        rust_connects_to_c,
        true,
        Some(NoPlaintextCapture::TcpAndUdp),
    )
}

fn run_c_rust_two_node_tun_no_plain_tcp_payload(
    c_tincd: &Path,
    rust_connects_to_c: bool,
) -> Result<(), Box<dyn Error>> {
    run_c_rust_two_node_tun_interop_inner(
        c_tincd,
        rust_connects_to_c,
        false,
        Some(NoPlaintextCapture::Tcp),
    )
}

fn run_c_rust_two_node_tun_interop_with_options(
    c_tincd: &Path,
    rust_connects_to_c: bool,
    exercise_peer_restart: bool,
) -> Result<(), Box<dyn Error>> {
    run_c_rust_two_node_tun_interop_inner(c_tincd, rust_connects_to_c, exercise_peer_restart, None)
}

fn run_c_rust_two_node_tun_interop_inner(
    c_tincd: &Path,
    rust_connects_to_c: bool,
    exercise_peer_restart: bool,
    no_plaintext_capture: Option<NoPlaintextCapture>,
) -> Result<(), Box<dyn Error>> {
    let workspace = TempWorkspace::new(if rust_connects_to_c {
        if exercise_peer_restart {
            "tinc-rust-c-modern-restart-rust-connects"
        } else if no_plaintext_capture == Some(NoPlaintextCapture::Udp) {
            "tinc-rust-c-modern-no-plain-udp-rust-connects"
        } else if no_plaintext_capture == Some(NoPlaintextCapture::Tcp) {
            "tinc-rust-c-modern-no-plain-tcp-rust-connects"
        } else {
            "tinc-rust-c-interop-rust-connects"
        }
    } else if exercise_peer_restart {
        "tinc-rust-c-modern-restart-c-connects"
    } else if no_plaintext_capture == Some(NoPlaintextCapture::Udp) {
        "tinc-rust-c-modern-no-plain-udp-c-connects"
    } else if no_plaintext_capture == Some(NoPlaintextCapture::Tcp) {
        "tinc-rust-c-modern-no-plain-tcp-c-connects"
    } else {
        "tinc-rust-c-interop-c-connects"
    })?;
    let suffix = unique_suffix();
    let ns_alpha = format!(
        "tinc-interop-a-{}-{suffix}",
        if rust_connects_to_c { "r" } else { "c" }
    );
    let ns_beta = format!(
        "tinc-interop-b-{}-{suffix}",
        if rust_connects_to_c { "c" } else { "r" }
    );
    let veth_alpha = format!("ia{suffix}");
    let veth_beta = format!("ib{suffix}");
    let alpha_port = if rust_connects_to_c { 17255 } else { 17257 };
    let beta_port = if rust_connects_to_c { 17256 } else { 17258 };
    let mut cleanup = NetnsCleanup::new(workspace.path().to_path_buf());
    cleanup.add_namespace(ns_alpha.clone());
    cleanup.add_namespace(ns_beta.clone());

    create_node_config(
        &workspace.path().join("alpha"),
        NodeConfig {
            name: "alpha",
            peer: "beta",
            port: alpha_port,
            bind_address: "192.0.2.11",
            peer_address: "192.0.2.12",
            peer_port: beta_port,
            interface: "tun-alpha",
            tunnel_address: "10.101.1.1/24",
            subnet: "10.101.1.0/24",
            peer_subnet: "10.101.2.0/24",
            connect_to_peer: rust_connects_to_c,
            seed: 11,
            peer_seed: 12,
        },
    )?;
    create_node_config(
        &workspace.path().join("beta"),
        NodeConfig {
            name: "beta",
            peer: "alpha",
            port: beta_port,
            bind_address: "192.0.2.12",
            peer_address: "192.0.2.11",
            peer_port: alpha_port,
            interface: "tun-beta",
            tunnel_address: "10.101.2.1/24",
            subnet: "10.101.2.0/24",
            peer_subnet: "10.101.1.0/24",
            connect_to_peer: !rust_connects_to_c,
            seed: 12,
            peer_seed: 11,
        },
    )?;
    if no_plaintext_capture == Some(NoPlaintextCapture::Tcp) {
        force_tcponly_on_two_node_hosts(&workspace.path().join("alpha"), "beta")?;
        force_tcponly_on_two_node_hosts(&workspace.path().join("beta"), "alpha")?;
    }

    if !try_ip(&["netns", "add", &ns_alpha]) || !try_ip(&["netns", "add", &ns_beta]) {
        eprintln!("skipping C/Rust netns interop test: cannot create network namespaces");
        return Ok(());
    }

    run_ip(&[
        "link",
        "add",
        &veth_alpha,
        "type",
        "veth",
        "peer",
        "name",
        &veth_beta,
    ])?;
    run_ip(&["link", "set", &veth_alpha, "netns", &ns_alpha])?;
    run_ip(&["link", "set", &veth_beta, "netns", &ns_beta])?;
    run_ip(&["-n", &ns_alpha, "link", "set", "lo", "up"])?;
    run_ip(&["-n", &ns_beta, "link", "set", "lo", "up"])?;
    run_ip(&[
        "-n",
        &ns_alpha,
        "addr",
        "add",
        "192.0.2.11/24",
        "dev",
        &veth_alpha,
    ])?;
    run_ip(&[
        "-n",
        &ns_beta,
        "addr",
        "add",
        "192.0.2.12/24",
        "dev",
        &veth_beta,
    ])?;
    run_ip(&["-n", &ns_alpha, "link", "set", &veth_alpha, "up"])?;
    run_ip(&["-n", &ns_beta, "link", "set", &veth_beta, "up"])?;

    let (alpha_binary, beta_binary) = if rust_connects_to_c {
        (Path::new(TINCD), c_tincd)
    } else {
        (c_tincd, Path::new(TINCD))
    };

    cleanup.spawn_with_binary(
        "alpha",
        alpha_binary,
        &workspace.path().join("alpha"),
        &ns_alpha,
        &workspace.path().join("alpha.log"),
    )?;
    cleanup.spawn_with_binary(
        "beta",
        beta_binary,
        &workspace.path().join("beta"),
        &ns_beta,
        &workspace.path().join("beta.log"),
    )?;

    wait_for_link(&ns_alpha, "tun-alpha", &cleanup)?;
    wait_for_link(&ns_beta, "tun-beta", &cleanup)?;
    wait_for_ping(&ns_alpha, "10.101.2.1", &cleanup)?;
    wait_for_ping(&ns_beta, "10.101.1.1", &cleanup)?;

    if !exercise_peer_restart && no_plaintext_capture.is_none() {
        assert_single_ping_updates_traffic_counters_like_tinc(
            &workspace.path().join("alpha"),
            "beta",
            &workspace.path().join("beta"),
            "alpha",
            &ns_alpha,
            "10.101.2.1",
            "modern direct C/Rust data path",
            &cleanup,
        )?;
    }

    if !exercise_peer_restart && no_plaintext_capture.is_none() {
        assert_c_rust_modern_direct_dump_parity(
            &workspace,
            rust_connects_to_c,
            c_tincd,
            &ns_alpha,
            &ns_beta,
            &cleanup,
        )?;
    }

    if no_plaintext_capture.is_some() && !exercise_peer_restart {
        let capture = no_plaintext_capture.expect("checked above");
        let label = match capture {
            NoPlaintextCapture::Tcp => "c/rust modern SPTPS TCP fallback data path",
            NoPlaintextCapture::TcpAndUdp => "c/rust modern SPTPS TCP/UDP data path",
            NoPlaintextCapture::Udp => "c/rust modern SPTPS UDP data path",
        };
        assert_underlay_ping_payload_not_plaintext(
            &ns_alpha,
            &veth_alpha,
            "10.101.2.1",
            label,
            capture,
            &cleanup,
        )?;
    }

    if exercise_peer_restart {
        cleanup.kill_child("beta")?;
        wait_for_no_ping(&ns_alpha, "10.101.2.1", &cleanup)?;
        cleanup.spawn_with_binary(
            "beta",
            beta_binary,
            &workspace.path().join("beta"),
            &ns_beta,
            &workspace.path().join("beta.log"),
        )?;
        wait_for_link(&ns_beta, "tun-beta", &cleanup)?;
        wait_for_ping(&ns_alpha, "10.101.2.1", &cleanup)?;
        wait_for_ping(&ns_beta, "10.101.1.1", &cleanup)?;

        if let Some(capture) = no_plaintext_capture {
            let label = match capture {
                NoPlaintextCapture::Tcp => {
                    "c/rust modern SPTPS short TCP fallback data path after restart"
                }
                NoPlaintextCapture::TcpAndUdp => {
                    "c/rust modern SPTPS short TCP/UDP data path after restart"
                }
                NoPlaintextCapture::Udp => "c/rust modern SPTPS short UDP data path after restart",
            };
            assert_underlay_ping_payload_not_plaintext(
                &ns_alpha,
                &veth_alpha,
                "10.101.2.1",
                label,
                capture,
                &cleanup,
            )?;
        }

        if no_plaintext_capture.is_some() {
            wait_for_direct_udp_discovery_pmtu_min_mtu(
                &workspace.path().join("alpha"),
                "beta",
                &ns_alpha,
                "10.101.2.1",
                "modern direct restart alpha view",
                512,
                &cleanup,
            )?;
            wait_for_direct_udp_discovery_pmtu_min_mtu(
                &workspace.path().join("beta"),
                "alpha",
                &ns_beta,
                "10.101.1.1",
                "modern direct restart beta view",
                512,
                &cleanup,
            )?;
            wait_for_underlay_single_ping_uses_udp_without_tcp_data_fallback(
                &ns_alpha,
                &veth_alpha,
                &ns_alpha,
                "10.101.2.1",
                beta_port,
                "modern direct restart alpha->beta post-rediscovery data path",
                &cleanup,
            )?;
            wait_for_underlay_single_ping_uses_udp_without_tcp_data_fallback(
                &ns_beta,
                &veth_beta,
                &ns_beta,
                "10.101.1.1",
                alpha_port,
                "modern direct restart beta->alpha post-rediscovery data path",
                &cleanup,
            )?;
        }
    }

    Ok(())
}

fn run_rust_tincctl_c_tincd_pcap_stream(c_tincd: &Path) -> Result<(), Box<dyn Error>> {
    let workspace = TempWorkspace::new("tinc-rustctl-cdaemon-pcap")?;
    let suffix = unique_suffix();
    let ns_alpha = format!("tinc-ctl-pcap-ca-{suffix}");
    let ns_beta = format!("tinc-ctl-pcap-cb-{suffix}");
    let veth_alpha = format!("pa{suffix}");
    let veth_beta = format!("pb{suffix}");
    let mut cleanup = NetnsCleanup::new(workspace.path().to_path_buf());
    cleanup.add_namespace(ns_alpha.clone());
    cleanup.add_namespace(ns_beta.clone());

    create_node_config(
        &workspace.path().join("alpha"),
        NodeConfig {
            name: "alpha",
            peer: "beta",
            port: 17470,
            bind_address: "192.0.2.61",
            peer_address: "192.0.2.62",
            peer_port: 17471,
            interface: "tun-alpha",
            tunnel_address: "10.112.1.1/24",
            subnet: "10.112.1.0/24",
            peer_subnet: "10.112.2.0/24",
            connect_to_peer: true,
            seed: 61,
            peer_seed: 62,
        },
    )?;
    create_node_config(
        &workspace.path().join("beta"),
        NodeConfig {
            name: "beta",
            peer: "alpha",
            port: 17471,
            bind_address: "192.0.2.62",
            peer_address: "192.0.2.61",
            peer_port: 17470,
            interface: "tun-beta",
            tunnel_address: "10.112.2.1/24",
            subnet: "10.112.2.0/24",
            peer_subnet: "10.112.1.0/24",
            connect_to_peer: false,
            seed: 62,
            peer_seed: 61,
        },
    )?;

    if !try_ip(&["netns", "add", &ns_alpha]) || !try_ip(&["netns", "add", &ns_beta]) {
        eprintln!(
            "skipping Rust tincctl/C tincd pcap stream interop test: cannot create network namespaces"
        );
        return Ok(());
    }

    run_ip(&[
        "link",
        "add",
        &veth_alpha,
        "type",
        "veth",
        "peer",
        "name",
        &veth_beta,
    ])?;
    run_ip(&["link", "set", &veth_alpha, "netns", &ns_alpha])?;
    run_ip(&["link", "set", &veth_beta, "netns", &ns_beta])?;
    run_ip(&["-n", &ns_alpha, "link", "set", "lo", "up"])?;
    run_ip(&["-n", &ns_beta, "link", "set", "lo", "up"])?;
    run_ip(&[
        "-n",
        &ns_alpha,
        "addr",
        "add",
        "192.0.2.61/24",
        "dev",
        &veth_alpha,
    ])?;
    run_ip(&[
        "-n",
        &ns_beta,
        "addr",
        "add",
        "192.0.2.62/24",
        "dev",
        &veth_beta,
    ])?;
    run_ip(&["-n", &ns_alpha, "link", "set", &veth_alpha, "up"])?;
    run_ip(&["-n", &ns_beta, "link", "set", &veth_beta, "up"])?;

    cleanup.spawn_with_binary(
        "alpha",
        c_tincd,
        &workspace.path().join("alpha"),
        &ns_alpha,
        &workspace.path().join("alpha.log"),
    )?;
    cleanup.spawn_with_binary(
        "beta",
        c_tincd,
        &workspace.path().join("beta"),
        &ns_beta,
        &workspace.path().join("beta.log"),
    )?;

    wait_for_link(&ns_alpha, "tun-alpha", &cleanup)?;
    wait_for_link(&ns_beta, "tun-beta", &cleanup)?;
    wait_for_pidfile(&workspace.path().join("alpha").join("pid"), &cleanup)?;
    wait_for_control_socket(&workspace.path().join("alpha").join("pid.socket"), &cleanup)?;
    wait_for_ping(&ns_alpha, "10.112.2.1", &cleanup)?;

    let alpha_confdir = workspace.path().join("alpha");
    let pcap_client_one = spawn_rust_tincctl_bytes_thread(&[
        "tinc",
        "--config",
        alpha_confdir.to_str().unwrap(),
        "pcap",
        "96",
    ]);
    let pcap_client_two = spawn_rust_tincctl_bytes_thread(&[
        "tinc",
        "--config",
        alpha_confdir.to_str().unwrap(),
        "pcap",
        "96",
    ]);
    thread::sleep(Duration::from_millis(300));
    wait_for_ping(&ns_alpha, "10.112.2.1", &cleanup)?;
    wait_for_ping(&ns_beta, "10.112.1.1", &cleanup)?;

    let stop = run_rust_tincctl(&["tinc", "--config", alpha_confdir.to_str().unwrap(), "stop"])
        .map_err(|error| {
            format!(
                "could not stop C alpha after Rust tincctl pcap stream: {error}\n{}",
                cleanup.logs()
            )
        })?;
    assert!(stop.is_empty(), "unexpected stop output: {stop}");
    let pcap_output_one =
        wait_for_rust_tincctl_pcap_subscriber(pcap_client_one, "first", &cleanup)?;
    let pcap_output_two =
        wait_for_rust_tincctl_pcap_subscriber(pcap_client_two, "second", &cleanup)?;
    assert_pcap_packet_count_at_least(&pcap_output_one, 42, 2);
    assert_pcap_packet_count_at_least(&pcap_output_two, 42, 2);
    wait_for_child_exit(&mut cleanup, "alpha")?;

    let stop = run_rust_tincctl(&[
        "tinc",
        "--config",
        workspace.path().join("beta").to_str().unwrap(),
        "stop",
    ])
    .map_err(|error| {
        format!(
            "could not stop C beta after Rust tincctl pcap stream: {error}\n{}",
            cleanup.logs()
        )
    })?;
    assert!(stop.is_empty(), "unexpected stop output: {stop}");
    wait_for_child_exit(&mut cleanup, "beta")?;

    Ok(())
}

fn run_c_rust_two_node_legacy_tun_interop(
    c_tincd: &Path,
    rust_connects_to_c: bool,
) -> Result<(), Box<dyn Error>> {
    run_c_rust_two_node_legacy_tun_interop_with_options_inner(
        c_tincd,
        None,
        rust_connects_to_c,
        false,
        false,
        false,
        false,
        None,
        LegacyCryptoConfig::default(),
        false,
        None,
    )
}

fn run_c_rust_two_node_legacy_tun_no_plain_udp_payload(
    c_tincd: &Path,
    rust_connects_to_c: bool,
) -> Result<(), Box<dyn Error>> {
    run_c_rust_two_node_legacy_tun_interop_with_options_inner(
        c_tincd,
        None,
        rust_connects_to_c,
        false,
        false,
        false,
        false,
        Some(NoPlaintextCapture::Udp),
        LegacyCryptoConfig::default(),
        false,
        None,
    )
}

fn run_c_rust_two_node_legacy_tun_restart_no_plain_underlay_payload(
    c_tincd: &Path,
    rust_connects_to_c: bool,
) -> Result<(), Box<dyn Error>> {
    run_c_rust_two_node_legacy_tun_interop_with_options_inner(
        c_tincd,
        None,
        rust_connects_to_c,
        false,
        true,
        false,
        false,
        Some(NoPlaintextCapture::TcpAndUdp),
        LegacyCryptoConfig::default(),
        false,
        None,
    )
}

fn run_c_rust_two_node_legacy_tun_rekey_no_plain_tcp_payload(
    c_tincd: &Path,
    rust_connects_to_c: bool,
) -> Result<(), Box<dyn Error>> {
    run_c_rust_two_node_legacy_tun_interop_with_options_inner(
        c_tincd,
        None,
        rust_connects_to_c,
        true,
        false,
        false,
        false,
        Some(NoPlaintextCapture::Tcp),
        LegacyCryptoConfig::default(),
        false,
        Some(1),
    )
}

fn run_c_rust_two_node_legacy_tun_rekey_udp_rediscovery(
    c_tincd: &Path,
    rust_connects_to_c: bool,
) -> Result<(), Box<dyn Error>> {
    run_c_rust_two_node_legacy_tun_interop_with_options_inner(
        c_tincd,
        None,
        rust_connects_to_c,
        true,
        false,
        false,
        false,
        None,
        LegacyCryptoConfig::default(),
        true,
        Some(30),
    )
}

fn run_c_rust_two_node_legacy_tun_rekey_no_plaintext_then_udp(
    c_tincd: &Path,
    rust_connects_to_c: bool,
) -> Result<(), Box<dyn Error>> {
    run_c_rust_two_node_legacy_tun_interop_with_options_inner(
        c_tincd,
        None,
        rust_connects_to_c,
        true,
        false,
        false,
        false,
        Some(NoPlaintextCapture::Tcp),
        LegacyCryptoConfig::default(),
        true,
        Some(30),
    )
}

fn run_c_rust_two_node_legacy_tun_no_plain_tcp_payload(
    c_tincd: &Path,
    rust_connects_to_c: bool,
) -> Result<(), Box<dyn Error>> {
    run_c_rust_two_node_legacy_tun_interop_with_options_inner(
        c_tincd,
        None,
        rust_connects_to_c,
        false,
        false,
        false,
        false,
        Some(NoPlaintextCapture::Tcp),
        LegacyCryptoConfig::default(),
        false,
        None,
    )
}

fn run_c_rust_two_node_legacy_tun_with_crypto_config(
    c_tincd: &Path,
    rust_connects_to_c: bool,
    legacy_crypto: LegacyCryptoConfig<'_>,
) -> Result<(), Box<dyn Error>> {
    run_c_rust_two_node_legacy_tun_interop_with_options_inner(
        c_tincd,
        None,
        rust_connects_to_c,
        false,
        false,
        false,
        false,
        None,
        legacy_crypto,
        false,
        None,
    )
}

fn assert_compression_unavailable_startup_like_tinc(
    daemon_binary: &Path,
    legacy_crypto: LegacyCryptoConfig<'_>,
    case: &str,
    daemon_label: &str,
    compression_name: &str,
) -> Result<(), Box<dyn Error>> {
    let workspace = TempWorkspace::new(&format!("tinc-rust-c-legacy-{case}-unavailable"))?;
    let suffix = unique_suffix();
    let ns_alpha = format!("tinc-{case}-unavail-a-{suffix}");
    let veth_alpha = format!("cua{suffix}a");
    let veth_beta = format!("cua{suffix}b");
    let alpha_rsa = RsaPrivateKey::new(&mut OsRng, 2048)?;
    let beta_rsa = RsaPrivateKey::new(&mut OsRng, 2048)?;
    let alpha_rsa_public = RsaPublicKey::from(&alpha_rsa);
    let beta_rsa_public = RsaPublicKey::from(&beta_rsa);
    let confdir = workspace.path().join("alpha");
    let mut cleanup = NetnsCleanup::new(workspace.path().to_path_buf());
    cleanup.add_namespace(ns_alpha.clone());
    cleanup.add_root_link(veth_beta.clone());

    create_legacy_node_config(
        &confdir,
        LegacyNodeConfig {
            name: "alpha",
            peer: "beta",
            port: 17359,
            bind_address: "192.0.2.31",
            peer_address: "192.0.2.32",
            peer_port: 17360,
            interface: "tun-alpha",
            tunnel_address: "10.103.1.1/24",
            subnet: "10.103.1.0/24",
            peer_subnet: "10.103.2.0/24",
            connect_to_peer: false,
            private_key: &alpha_rsa,
            public_key: &alpha_rsa_public,
            peer_public_key: &beta_rsa_public,
            key_expire: None,
            fast_ping: false,
            legacy_crypto,
        },
    )?;

    if !try_ip(&["netns", "add", &ns_alpha]) {
        eprintln!(
            "skipping C/Rust legacy {case}-unavailable netns test: cannot create network namespace"
        );
        return Ok(());
    }
    run_ip(&[
        "link",
        "add",
        &veth_alpha,
        "type",
        "veth",
        "peer",
        "name",
        &veth_beta,
    ])?;
    run_ip(&["link", "set", &veth_alpha, "netns", &ns_alpha])?;
    run_ip(&["-n", &ns_alpha, "link", "set", "lo", "up"])?;
    run_ip(&[
        "-n",
        &ns_alpha,
        "addr",
        "add",
        "192.0.2.31/24",
        "dev",
        &veth_alpha,
    ])?;
    run_ip(&["-n", &ns_alpha, "link", "set", &veth_alpha, "up"])?;

    assert_tincd_startup_fails_with_compression_unavailable(
        daemon_binary,
        &confdir,
        &ns_alpha,
        daemon_label,
        compression_name,
    )?;

    Ok(())
}

fn run_c_rust_two_node_legacy_tun_interop_with_options(
    c_tincd: &Path,
    rust_connects_to_c: bool,
    exercise_rekey: bool,
    exercise_peer_restart: bool,
) -> Result<(), Box<dyn Error>> {
    run_c_rust_two_node_legacy_tun_interop_with_options_inner(
        c_tincd,
        None,
        rust_connects_to_c,
        exercise_rekey,
        exercise_peer_restart,
        false,
        false,
        None,
        LegacyCryptoConfig::default(),
        false,
        Some(1),
    )
}

fn run_c_rust_two_node_legacy_tun_interop_with_underlay_udp_loss(
    c_tincd: &Path,
    rust_connects_to_c: bool,
) -> Result<(), Box<dyn Error>> {
    run_c_rust_two_node_legacy_tun_interop_with_options_inner(
        c_tincd,
        None,
        rust_connects_to_c,
        false,
        false,
        true,
        false,
        None,
        LegacyCryptoConfig::default(),
        false,
        None,
    )
}

fn run_c_rust_two_node_legacy_tun_interop_with_meta_timeout_loss(
    c_tincd: &Path,
    rust_connects_to_c: bool,
) -> Result<(), Box<dyn Error>> {
    run_c_rust_two_node_legacy_tun_interop_with_options_inner(
        c_tincd,
        None,
        rust_connects_to_c,
        false,
        false,
        false,
        true,
        None,
        LegacyCryptoConfig::default(),
        false,
        None,
    )
}

fn run_c_rust_two_node_legacy_tun_interop_with_options_and_c_tinc(
    c_tincd: &Path,
    c_tinc: &Path,
    rust_connects_to_c: bool,
    exercise_rekey: bool,
    exercise_peer_restart: bool,
) -> Result<(), Box<dyn Error>> {
    run_c_rust_two_node_legacy_tun_interop_with_options_inner(
        c_tincd,
        Some(c_tinc),
        rust_connects_to_c,
        exercise_rekey,
        exercise_peer_restart,
        false,
        false,
        None,
        LegacyCryptoConfig::default(),
        false,
        Some(1),
    )
}

fn run_c_rust_two_node_legacy_tun_interop_with_options_inner(
    c_tincd: &Path,
    c_tinc: Option<&Path>,
    rust_connects_to_c: bool,
    exercise_rekey: bool,
    exercise_peer_restart: bool,
    exercise_underlay_udp_loss: bool,
    exercise_meta_timeout_loss: bool,
    no_plaintext_capture: Option<NoPlaintextCapture>,
    legacy_crypto: LegacyCryptoConfig<'_>,
    rekey_udp_rediscovery: bool,
    key_expire_override: Option<u16>,
) -> Result<(), Box<dyn Error>> {
    let workspace = TempWorkspace::new(if rust_connects_to_c {
        if exercise_peer_restart {
            "tinc-rust-c-legacy-restart-rust-connects"
        } else if exercise_rekey {
            "tinc-rust-c-legacy-rekey-rust-connects"
        } else if exercise_underlay_udp_loss {
            "tinc-rust-c-legacy-udp-loss-rust-connects"
        } else if exercise_meta_timeout_loss {
            "tinc-rust-c-legacy-meta-timeout-rust-connects"
        } else if no_plaintext_capture == Some(NoPlaintextCapture::Udp) {
            "tinc-rust-c-legacy-no-plain-udp-rust-connects"
        } else if no_plaintext_capture == Some(NoPlaintextCapture::Tcp) {
            "tinc-rust-c-legacy-no-plain-tcp-rust-connects"
        } else {
            "tinc-rust-c-legacy-interop-rust-connects"
        }
    } else if exercise_peer_restart {
        "tinc-rust-c-legacy-restart-c-connects"
    } else if exercise_rekey {
        "tinc-rust-c-legacy-rekey-c-connects"
    } else if exercise_underlay_udp_loss {
        "tinc-rust-c-legacy-udp-loss-c-connects"
    } else if exercise_meta_timeout_loss {
        "tinc-rust-c-legacy-meta-timeout-c-connects"
    } else if no_plaintext_capture == Some(NoPlaintextCapture::Udp) {
        "tinc-rust-c-legacy-no-plain-udp-c-connects"
    } else if no_plaintext_capture == Some(NoPlaintextCapture::Tcp) {
        "tinc-rust-c-legacy-no-plain-tcp-c-connects"
    } else {
        "tinc-rust-c-legacy-interop-c-connects"
    })?;
    let suffix = unique_suffix();
    let ns_alpha = format!(
        "tinc-legacy-a-{}-{suffix}",
        if rust_connects_to_c { "r" } else { "c" }
    );
    let ns_beta = format!(
        "tinc-legacy-b-{}-{suffix}",
        if rust_connects_to_c { "c" } else { "r" }
    );
    let veth_alpha = format!("la{suffix}");
    let veth_beta = format!("lb{suffix}");
    let alpha_port = if rust_connects_to_c { 17355 } else { 17357 };
    let beta_port = if rust_connects_to_c { 17356 } else { 17358 };
    let alpha_rsa = RsaPrivateKey::new(&mut OsRng, 2048)?;
    let beta_rsa = RsaPrivateKey::new(&mut OsRng, 2048)?;
    let alpha_rsa_public = RsaPublicKey::from(&alpha_rsa);
    let beta_rsa_public = RsaPublicKey::from(&beta_rsa);
    let mut cleanup = NetnsCleanup::new(workspace.path().to_path_buf());
    cleanup.add_namespace(ns_alpha.clone());
    cleanup.add_namespace(ns_beta.clone());

    create_legacy_node_config(
        &workspace.path().join("alpha"),
        LegacyNodeConfig {
            name: "alpha",
            peer: "beta",
            port: alpha_port,
            bind_address: "192.0.2.21",
            peer_address: "192.0.2.22",
            peer_port: beta_port,
            interface: "tun-alpha",
            tunnel_address: "10.102.1.1/24",
            subnet: "10.102.1.0/24",
            peer_subnet: "10.102.2.0/24",
            connect_to_peer: rust_connects_to_c,
            private_key: &alpha_rsa,
            public_key: &alpha_rsa_public,
            peer_public_key: &beta_rsa_public,
            key_expire: exercise_rekey.then_some(key_expire_override.unwrap_or(1)),
            fast_ping: exercise_meta_timeout_loss,
            legacy_crypto,
        },
    )?;
    create_legacy_node_config(
        &workspace.path().join("beta"),
        LegacyNodeConfig {
            name: "beta",
            peer: "alpha",
            port: beta_port,
            bind_address: "192.0.2.22",
            peer_address: "192.0.2.21",
            peer_port: alpha_port,
            interface: "tun-beta",
            tunnel_address: "10.102.2.1/24",
            subnet: "10.102.2.0/24",
            peer_subnet: "10.102.1.0/24",
            connect_to_peer: !rust_connects_to_c,
            private_key: &beta_rsa,
            public_key: &beta_rsa_public,
            peer_public_key: &alpha_rsa_public,
            key_expire: exercise_rekey.then_some(key_expire_override.unwrap_or(1)),
            fast_ping: exercise_meta_timeout_loss,
            legacy_crypto,
        },
    )?;
    if no_plaintext_capture == Some(NoPlaintextCapture::Tcp) && !exercise_rekey {
        force_tcponly_on_two_node_hosts(&workspace.path().join("alpha"), "beta")?;
        force_tcponly_on_two_node_hosts(&workspace.path().join("beta"), "alpha")?;
    }

    if !try_ip(&["netns", "add", &ns_alpha]) || !try_ip(&["netns", "add", &ns_beta]) {
        eprintln!("skipping C/Rust legacy netns interop test: cannot create network namespaces");
        return Ok(());
    }

    run_ip(&[
        "link",
        "add",
        &veth_alpha,
        "type",
        "veth",
        "peer",
        "name",
        &veth_beta,
    ])?;
    run_ip(&["link", "set", &veth_alpha, "netns", &ns_alpha])?;
    run_ip(&["link", "set", &veth_beta, "netns", &ns_beta])?;
    run_ip(&["-n", &ns_alpha, "link", "set", "lo", "up"])?;
    run_ip(&["-n", &ns_beta, "link", "set", "lo", "up"])?;
    run_ip(&[
        "-n",
        &ns_alpha,
        "addr",
        "add",
        "192.0.2.21/24",
        "dev",
        &veth_alpha,
    ])?;
    run_ip(&[
        "-n",
        &ns_beta,
        "addr",
        "add",
        "192.0.2.22/24",
        "dev",
        &veth_beta,
    ])?;
    run_ip(&["-n", &ns_alpha, "link", "set", &veth_alpha, "up"])?;
    run_ip(&["-n", &ns_beta, "link", "set", &veth_beta, "up"])?;

    let (alpha_binary, beta_binary) = if rust_connects_to_c {
        (Path::new(TINCD), c_tincd)
    } else {
        (c_tincd, Path::new(TINCD))
    };

    cleanup.spawn_with_binary(
        "alpha",
        alpha_binary,
        &workspace.path().join("alpha"),
        &ns_alpha,
        &workspace.path().join("alpha.log"),
    )?;
    cleanup.spawn_with_binary(
        "beta",
        beta_binary,
        &workspace.path().join("beta"),
        &ns_beta,
        &workspace.path().join("beta.log"),
    )?;

    wait_for_link(&ns_alpha, "tun-alpha", &cleanup)?;
    wait_for_link(&ns_beta, "tun-beta", &cleanup)?;
    wait_for_ping(&ns_alpha, "10.102.2.1", &cleanup)?;
    wait_for_ping(&ns_beta, "10.102.1.1", &cleanup)?;

    if exercise_rekey {
        assert_legacy_direct_key_state_like_tinc(
            &workspace.path().join("alpha"),
            "beta",
            &format!(
                "legacy direct pre-KeyExpire alpha view ({})",
                if rust_connects_to_c {
                    "Rust alpha, C beta"
                } else {
                    "C alpha, Rust beta"
                }
            ),
        )?;
        assert_legacy_direct_key_state_like_tinc(
            &workspace.path().join("beta"),
            "alpha",
            &format!(
                "legacy direct pre-KeyExpire beta view ({})",
                if rust_connects_to_c {
                    "Rust alpha, C beta"
                } else {
                    "C alpha, Rust beta"
                }
            ),
        )?;
    }

    if no_plaintext_capture == Some(NoPlaintextCapture::Tcp)
        && !exercise_rekey
        && !exercise_peer_restart
        && !exercise_underlay_udp_loss
        && !exercise_meta_timeout_loss
    {
        assert_single_ping_updates_traffic_counters_like_tinc(
            &workspace.path().join("alpha"),
            "beta",
            &workspace.path().join("beta"),
            "alpha",
            &ns_alpha,
            "10.102.2.1",
            "legacy TCPOnly C/Rust fallback data path",
            &cleanup,
        )?;
    }

    if !exercise_rekey
        && !exercise_peer_restart
        && !exercise_underlay_udp_loss
        && !exercise_meta_timeout_loss
        && no_plaintext_capture.is_none()
    {
        assert_legacy_direct_key_state_with_crypto_like_tinc(
            &workspace.path().join("alpha"),
            "beta",
            legacy_crypto,
            "legacy direct alpha view after C/Rust legacy UDP key exchange",
        )?;
        assert_legacy_direct_key_state_with_crypto_like_tinc(
            &workspace.path().join("beta"),
            "alpha",
            legacy_crypto,
            "legacy direct beta view after C/Rust legacy UDP key exchange",
        )?;
        if legacy_crypto.expected_digest != 0 {
            assert_c_rust_legacy_direct_dump_parity(
                &workspace,
                rust_connects_to_c,
                c_tincd,
                &ns_alpha,
                &ns_beta,
                &cleanup,
                legacy_crypto,
            )?;
        }
    }

    if legacy_crypto.require_no_plaintext {
        assert_underlay_ping_payload_not_plaintext(
            &ns_alpha,
            &veth_alpha,
            "10.102.2.1",
            &format!(
                "c/rust legacy {} compressed UDP data path",
                legacy_crypto.compression_name()
            ),
            NoPlaintextCapture::Udp,
            &cleanup,
        )?;
    }

    if no_plaintext_capture.is_some()
        && !exercise_rekey
        && !exercise_peer_restart
        && !exercise_underlay_udp_loss
        && !exercise_meta_timeout_loss
    {
        let capture = no_plaintext_capture.expect("checked above");
        let label = match capture {
            NoPlaintextCapture::Tcp => "c/rust legacy RSA TCP fallback data path",
            NoPlaintextCapture::TcpAndUdp => "c/rust legacy RSA TCP/UDP data path",
            NoPlaintextCapture::Udp => "c/rust legacy RSA UDP data path",
        };
        assert_underlay_ping_payload_not_plaintext(
            &ns_alpha,
            &veth_alpha,
            "10.102.2.1",
            label,
            capture,
            &cleanup,
        )?;
    }

    if exercise_underlay_udp_loss {
        run_ip(&["-n", &ns_alpha, "link", "set", &veth_alpha, "down"])?;
        run_ip(&["-n", &ns_beta, "link", "set", &veth_beta, "down"])?;
        expect_single_ping_failure(&ns_alpha, "10.102.2.1", &cleanup)?;
        expect_single_ping_failure(&ns_beta, "10.102.1.1", &cleanup)?;
        run_ip(&["-n", &ns_alpha, "link", "set", &veth_alpha, "up"])?;
        run_ip(&["-n", &ns_beta, "link", "set", &veth_beta, "up"])?;
        wait_for_ping(&ns_alpha, "10.102.2.1", &cleanup)?;
        wait_for_ping(&ns_beta, "10.102.1.1", &cleanup)?;
    }

    if exercise_meta_timeout_loss {
        run_ip(&["-n", &ns_alpha, "link", "set", &veth_alpha, "down"])?;
        run_ip(&["-n", &ns_beta, "link", "set", &veth_beta, "down"])?;
        wait_for_legacy_meta_timeout_close(&cleanup)?;
        wait_for_no_ping(&ns_alpha, "10.102.2.1", &cleanup)?;
        run_ip(&["-n", &ns_alpha, "link", "set", &veth_alpha, "up"])?;
        run_ip(&["-n", &ns_beta, "link", "set", &veth_beta, "up"])?;
        wait_for_ping(&ns_alpha, "10.102.2.1", &cleanup)?;
        wait_for_ping(&ns_beta, "10.102.1.1", &cleanup)?;
        wait_for_legacy_reconnect_after_timeout(&cleanup)?;
    }

    if let Some(c_tinc) = c_tinc {
        assert_c_tincctl_legacy_status_topology(
            c_tinc,
            rust_connects_to_c,
            &workspace,
            &ns_alpha,
            &ns_beta,
            &cleanup,
        )?;
    }

    if exercise_peer_restart {
        cleanup.kill_child("beta")?;
        wait_for_no_ping(&ns_alpha, "10.102.2.1", &cleanup)?;
        cleanup.spawn_with_binary(
            "beta",
            beta_binary,
            &workspace.path().join("beta"),
            &ns_beta,
            &workspace.path().join("beta.log"),
        )?;
        wait_for_link(&ns_beta, "tun-beta", &cleanup)?;
        wait_for_ping(&ns_alpha, "10.102.2.1", &cleanup)?;
        wait_for_ping(&ns_beta, "10.102.1.1", &cleanup)?;

        if let Some(capture) = no_plaintext_capture {
            let label = match capture {
                NoPlaintextCapture::Tcp => "c/rust legacy RSA TCP fallback data path after restart",
                NoPlaintextCapture::TcpAndUdp => {
                    "c/rust legacy RSA TCP/UDP data path after restart"
                }
                NoPlaintextCapture::Udp => "c/rust legacy RSA UDP data path after restart",
            };
            assert_underlay_ping_payload_not_plaintext(
                &ns_alpha,
                &veth_alpha,
                "10.102.2.1",
                label,
                capture,
                &cleanup,
            )?;
        }
    }

    if exercise_rekey {
        let checked_rekey_window_no_plaintext =
            no_plaintext_capture == Some(NoPlaintextCapture::Tcp) && rekey_udp_rediscovery;
        if checked_rekey_window_no_plaintext {
            assert_legacy_rekey_window_tcp_payload_not_plaintext(
                &ns_alpha,
                "10.102.2.1",
                "c/rust legacy RSA TCP rekey window data path",
                &cleanup,
            )?;
        } else {
            wait_for_legacy_rekey(&cleanup)?;
        }
        wait_for_ping(&ns_alpha, "10.102.2.1", &cleanup)?;
        wait_for_ping(&ns_beta, "10.102.1.1", &cleanup)?;
        wait_for_ping(&ns_alpha, "10.102.2.1", &cleanup)?;
        wait_for_ping(&ns_beta, "10.102.1.1", &cleanup)?;
        wait_for_legacy_direct_rekey_key_state_like_tinc(
            &workspace.path().join("alpha"),
            "beta",
            &ns_alpha,
            "10.102.2.1",
            "legacy direct post-KeyExpire alpha view",
            &cleanup,
        )?;
        wait_for_legacy_direct_rekey_key_state_like_tinc(
            &workspace.path().join("beta"),
            "alpha",
            &ns_beta,
            "10.102.1.1",
            "legacy direct post-KeyExpire beta view",
            &cleanup,
        )?;

        if let Some(capture) = no_plaintext_capture {
            if !checked_rekey_window_no_plaintext {
                let label = match capture {
                    NoPlaintextCapture::Tcp => {
                        "c/rust legacy RSA short TCP fallback data path after rekey"
                    }
                    NoPlaintextCapture::TcpAndUdp => {
                        "c/rust legacy RSA short TCP/UDP data path after rekey"
                    }
                    NoPlaintextCapture::Udp => "c/rust legacy RSA short UDP data path after rekey",
                };
                assert_underlay_ping_payload_not_plaintext(
                    &ns_alpha,
                    &veth_alpha,
                    "10.102.2.1",
                    label,
                    capture,
                    &cleanup,
                )?;
            }
        }

        if rekey_udp_rediscovery {
            wait_for_direct_udp_discovery_pmtu_min_mtu(
                &workspace.path().join("alpha"),
                "beta",
                &ns_alpha,
                "10.102.2.1",
                "legacy direct post-KeyExpire alpha UDP rediscovery",
                512,
                &cleanup,
            )?;
            wait_for_direct_udp_discovery_pmtu_min_mtu(
                &workspace.path().join("beta"),
                "alpha",
                &ns_beta,
                "10.102.1.1",
                "legacy direct post-KeyExpire beta UDP rediscovery",
                512,
                &cleanup,
            )?;
            wait_for_underlay_single_ping_uses_udp_without_tcp_data_fallback(
                &ns_beta,
                &veth_beta,
                &ns_alpha,
                "10.102.2.1",
                beta_port,
                "legacy direct post-KeyExpire alpha->beta post-rediscovery data path",
                &cleanup,
            )?;
            wait_for_underlay_single_ping_uses_udp_without_tcp_data_fallback(
                &ns_alpha,
                &veth_alpha,
                &ns_beta,
                "10.102.1.1",
                alpha_port,
                "legacy direct post-KeyExpire beta->alpha post-rediscovery data path",
                &cleanup,
            )?;
        }
    }

    Ok(())
}

fn run_c_rust_two_node_modern_emsgsize_pmtu_reduce(
    c_tincd: &Path,
    rust_connects_to_c: bool,
) -> Result<(), Box<dyn Error>> {
    let workspace = TempWorkspace::new(if rust_connects_to_c {
        "tinc-rust-c-modern-emsgsize-rust-connects"
    } else {
        "tinc-rust-c-modern-emsgsize-c-connects"
    })?;
    let suffix = unique_suffix();
    let ns_alpha = format!(
        "tinc-emsg-a-{}-{suffix}",
        if rust_connects_to_c { "r" } else { "c" }
    );
    let ns_beta = format!(
        "tinc-emsg-b-{}-{suffix}",
        if rust_connects_to_c { "c" } else { "r" }
    );
    let veth_alpha = format!("ma{suffix}");
    let veth_beta = format!("mb{suffix}");
    let alpha_port = if rust_connects_to_c { 18255 } else { 18257 };
    let beta_port = if rust_connects_to_c { 18256 } else { 18258 };
    let mut cleanup = NetnsCleanup::new(workspace.path().to_path_buf());
    cleanup.add_namespace(ns_alpha.clone());
    cleanup.add_namespace(ns_beta.clone());

    create_node_config(
        &workspace.path().join("alpha"),
        NodeConfig {
            name: "alpha",
            peer: "beta",
            port: alpha_port,
            bind_address: "192.0.2.81",
            peer_address: "192.0.2.82",
            peer_port: beta_port,
            interface: "tun-alpha",
            tunnel_address: "10.108.1.1/24",
            subnet: "10.108.1.0/24",
            peer_subnet: "10.108.2.0/24",
            connect_to_peer: rust_connects_to_c,
            seed: 81,
            peer_seed: 82,
        },
    )?;
    create_node_config(
        &workspace.path().join("beta"),
        NodeConfig {
            name: "beta",
            peer: "alpha",
            port: beta_port,
            bind_address: "192.0.2.82",
            peer_address: "192.0.2.81",
            peer_port: alpha_port,
            interface: "tun-beta",
            tunnel_address: "10.108.2.1/24",
            subnet: "10.108.2.0/24",
            peer_subnet: "10.108.1.0/24",
            connect_to_peer: !rust_connects_to_c,
            seed: 82,
            peer_seed: 81,
        },
    )?;

    if !try_ip(&["netns", "add", &ns_alpha]) || !try_ip(&["netns", "add", &ns_beta]) {
        eprintln!("skipping C/Rust modern EMSGSIZE PMTU test: cannot create network namespaces");
        return Ok(());
    }

    run_ip(&[
        "link",
        "add",
        &veth_alpha,
        "type",
        "veth",
        "peer",
        "name",
        &veth_beta,
    ])?;
    run_ip(&["link", "set", &veth_alpha, "netns", &ns_alpha])?;
    run_ip(&["link", "set", &veth_beta, "netns", &ns_beta])?;
    run_ip(&["-n", &ns_alpha, "link", "set", "lo", "up"])?;
    run_ip(&["-n", &ns_beta, "link", "set", "lo", "up"])?;
    run_ip(&[
        "-n",
        &ns_alpha,
        "addr",
        "add",
        "192.0.2.81/24",
        "dev",
        &veth_alpha,
    ])?;
    run_ip(&[
        "-n",
        &ns_beta,
        "addr",
        "add",
        "192.0.2.82/24",
        "dev",
        &veth_beta,
    ])?;
    run_ip(&["-n", &ns_alpha, "link", "set", &veth_alpha, "up"])?;
    run_ip(&["-n", &ns_beta, "link", "set", &veth_beta, "up"])?;

    let (alpha_binary, beta_binary) = if rust_connects_to_c {
        (Path::new(TINCD), c_tincd)
    } else {
        (c_tincd, Path::new(TINCD))
    };

    cleanup.spawn_with_binary(
        "alpha",
        alpha_binary,
        &workspace.path().join("alpha"),
        &ns_alpha,
        &workspace.path().join("alpha.log"),
    )?;
    cleanup.spawn_with_binary(
        "beta",
        beta_binary,
        &workspace.path().join("beta"),
        &ns_beta,
        &workspace.path().join("beta.log"),
    )?;

    wait_for_link(&ns_alpha, "tun-alpha", &cleanup)?;
    wait_for_link(&ns_beta, "tun-beta", &cleanup)?;
    wait_for_ping(&ns_alpha, "10.108.2.1", &cleanup)?;
    wait_for_ping(&ns_beta, "10.108.1.1", &cleanup)?;

    wait_for_direct_udp_discovery_pmtu_min_mtu(
        &workspace.path().join("alpha"),
        "beta",
        &ns_alpha,
        "10.108.2.1",
        "modern EMSGSIZE pre-reduction alpha view",
        1200,
        &cleanup,
    )?;
    wait_for_direct_udp_discovery_pmtu_min_mtu(
        &workspace.path().join("beta"),
        "alpha",
        &ns_beta,
        "10.108.1.1",
        "modern EMSGSIZE pre-reduction beta view",
        1200,
        &cleanup,
    )?;

    let alpha_before = raw_node(
        &RawControlDumps::read(&workspace.path().join("alpha"))?,
        "beta",
    )?
    .clone();
    let beta_before = raw_node(
        &RawControlDumps::read(&workspace.path().join("beta"))?,
        "alpha",
    )?
    .clone();
    assert!(
        alpha_before.max_mtu > 900 && beta_before.max_mtu > 900,
        "PMTU precondition did not converge above restricted underlay MTU; alpha={alpha_before:?}, beta={beta_before:?}\n{}",
        cleanup.logs()
    );

    run_ip(&["-n", &ns_alpha, "link", "set", &veth_alpha, "mtu", "900"])?;
    run_ip(&["-n", &ns_beta, "link", "set", &veth_beta, "mtu", "900"])?;

    let (rust_confdir, rust_peer, rust_ns, rust_target, rust_label) = if rust_connects_to_c {
        (
            workspace.path().join("alpha"),
            "beta",
            ns_alpha.as_str(),
            "10.108.2.1",
            "Rust alpha -> C beta",
        )
    } else {
        (
            workspace.path().join("beta"),
            "alpha",
            ns_beta.as_str(),
            "10.108.1.1",
            "Rust beta -> C alpha",
        )
    };
    let (c_confdir, c_peer, c_ns, c_target, c_label) = if rust_connects_to_c {
        (
            workspace.path().join("beta"),
            "alpha",
            ns_beta.as_str(),
            "10.108.1.1",
            "C beta -> Rust alpha",
        )
    } else {
        (
            workspace.path().join("alpha"),
            "beta",
            ns_alpha.as_str(),
            "10.108.2.1",
            "C alpha -> Rust beta",
        )
    };

    trigger_large_ping_for_emsgsize(rust_ns, rust_target, &cleanup)?;
    wait_for_pmtu_reduced_after_emsgsize(&rust_confdir, rust_peer, 900, rust_label, &cleanup)?;
    wait_for_ping(rust_ns, rust_target, &cleanup)?;

    trigger_large_ping_for_emsgsize(c_ns, c_target, &cleanup)?;
    wait_for_pmtu_reduced_after_emsgsize(&c_confdir, c_peer, 900, c_label, &cleanup)?;
    wait_for_ping(c_ns, c_target, &cleanup)?;

    Ok(())
}

fn assert_c_tincctl_legacy_status_topology(
    c_tinc: &Path,
    rust_connects_to_c: bool,
    workspace: &TempWorkspace,
    ns_alpha: &str,
    ns_beta: &str,
    cleanup: &NetnsCleanup,
) -> Result<(), Box<dyn Error>> {
    let (rust_name, peer_name, rust_ns, rust_confdir, peer_subnet, peer_underlay, peer_port) =
        if rust_connects_to_c {
            (
                "alpha",
                "beta",
                ns_alpha,
                workspace.path().join("alpha"),
                "10.102.2.0/24",
                "192.0.2.22",
                17356,
            )
        } else {
            (
                "beta",
                "alpha",
                ns_beta,
                workspace.path().join("beta"),
                "10.102.1.0/24",
                "192.0.2.21",
                17357,
            )
        };

    let nodes = run_c_tinc(c_tinc, rust_ns, &rust_confdir, &["dump", "nodes"])?;
    assert_c_dump_node_has_status_words(&nodes, rust_name, &["reachable"])?;
    assert_c_dump_node_lacks_status_words(&nodes, rust_name, &["sptps"])?;
    assert_c_dump_node_has_status_words(
        &nodes,
        peer_name,
        &["validkey", "validkey_in", "reachable"],
    )?;
    assert_c_dump_node_lacks_status_words(&nodes, peer_name, &["sptps"])?;
    assert!(
        c_dump_node_line(&nodes, peer_name)?.contains(&format!(
            "{peer_underlay} port {peer_port} cipher 427 digest 672 maclength 4 compression 0 "
        )),
        "C tinc dump nodes did not expose Rust legacy AES-256-CBC/SHA256/MACLength fields for {peer_name}:\n{nodes}\n{}",
        cleanup.logs()
    );
    assert_c_dump_node_has_route(&nodes, peer_name, peer_name, peer_name, 1)?;

    let edges = run_c_tinc(c_tinc, rust_ns, &rust_confdir, &["dump", "edges"])?;
    assert!(
        edges.contains(&format!(
            "{rust_name} to {peer_name} at {peer_underlay} port {peer_port}"
        )) || edges.contains(&format!("{peer_name} to {rust_name} at ")),
        "C tinc dump edges did not parse Rust legacy edge endpoints:\n{edges}\n{}",
        cleanup.logs()
    );

    let subnets = run_c_tinc(c_tinc, rust_ns, &rust_confdir, &["dump", "subnets"])?;
    assert!(
        subnets.contains(&format!("{peer_subnet} owner {peer_name}")),
        "C tinc dump subnets did not parse Rust legacy peer subnet owner:\n{subnets}\n{}",
        cleanup.logs()
    );

    let connections = run_c_tinc(c_tinc, rust_ns, &rust_confdir, &["dump", "connections"])?;
    assert!(
        connections.contains("<control> at localhost port unix")
            && connections
                .lines()
                .any(|line| line.starts_with(&format!("{peer_name} at {peer_underlay} port "))),
        "C tinc dump connections did not parse Rust legacy runtime connections:\n{connections}\n{}",
        cleanup.logs()
    );

    let info = run_c_tinc(c_tinc, rust_ns, &rust_confdir, &["info", peer_name])?;
    assert!(
        info.lines().any(|line| line.starts_with("Status:")
            && line.contains("validkey")
            && line.contains("reachable")
            && !line.contains("sptps"))
            && (info.contains("Reachability: directly with TCP")
                || info.contains("Reachability: directly with UDP"))
            && info.contains(&format!("Subnets:      {peer_subnet}")),
        "C tinc info {peer_name} did not interpret Rust legacy node crypto/status/topology like tinc:\n{info}\n{}",
        cleanup.logs()
    );

    Ok(())
}

fn run_c_rust_three_node_modern_indirect_multihop_interop(
    c_tincd: &Path,
    rust_middle: bool,
) -> Result<(), Box<dyn Error>> {
    run_c_rust_three_node_modern_indirect_multihop_interop_with_options(
        c_tincd,
        rust_middle,
        false,
        None,
        false,
    )
}

fn run_c_rust_three_node_modern_indirect_multihop_interop_with_options(
    c_tincd: &Path,
    rust_middle: bool,
    check_udp_discovery_pmtu: bool,
    no_plaintext_capture: Option<NoPlaintextCapture>,
    exercise_peer_restart_topology: bool,
) -> Result<(), Box<dyn Error>> {
    let workspace = TempWorkspace::new(if rust_middle {
        if no_plaintext_capture == Some(NoPlaintextCapture::Udp) {
            "tinc-rust-c-modern-indirect-no-plain-rust-middle"
        } else {
            "tinc-rust-c-modern-indirect-rust-middle"
        }
    } else if no_plaintext_capture == Some(NoPlaintextCapture::Udp) {
        "tinc-rust-c-modern-indirect-no-plain-c-middle"
    } else {
        "tinc-rust-c-modern-indirect-c-middle"
    })?;
    let suffix = unique_suffix();
    let mut nodes = (1..=3)
        .map(|index| LinkNode {
            name: match index {
                1 => "alpha",
                2 => "beta",
                3 => "gamma",
                _ => unreachable!(),
            }
            .to_owned(),
            namespace: format!(
                "tinc-mod-mhop-{}-{index}-{suffix}",
                if (index == 2) == rust_middle {
                    "r"
                } else {
                    "c"
                }
            ),
            port: if rust_middle {
                17860 + index as u16
            } else {
                17870 + index as u16
            },
            device_type: "tun",
            mode: None,
            interface: match index {
                1 => "tun-mm-a",
                2 => "tun-mm-b",
                3 => "tun-mm-g",
                _ => unreachable!(),
            }
            .to_owned(),
            tunnel_ip: format!("10.106.{index}.1"),
            tunnel_cidr: format!("10.106.{index}.1/24"),
            subnet: format!("10.106.{index}.0/24"),
            route: "10.106.0.0/16".to_owned(),
            tunnel_ipv6: None,
            tunnel_ipv6_cidr: None,
            subnet_ipv6: None,
            route_ipv6: None,
            static_mac_subnet: None,
            seed: 80 + index as u8,
            bind_addresses: Vec::new(),
            neighbor_addresses: Vec::new(),
            connect_to: Vec::new(),
            indirect_peers: Vec::new(),
        })
        .collect::<Vec<_>>();
    let links = vec![
        UnderlayLink {
            a: 1,
            b: 2,
            a_if: format!("mm12a{suffix}"),
            b_if: format!("mm12b{suffix}"),
            a_ip: "198.23.1.1".to_owned(),
            b_ip: "198.23.1.2".to_owned(),
            a_cidr: "198.23.1.1/30".to_owned(),
            b_cidr: "198.23.1.2/30".to_owned(),
        },
        UnderlayLink {
            a: 2,
            b: 3,
            a_if: format!("mm23a{suffix}"),
            b_if: format!("mm23b{suffix}"),
            a_ip: "198.23.2.1".to_owned(),
            b_ip: "198.23.2.2".to_owned(),
            a_cidr: "198.23.2.1/30".to_owned(),
            b_cidr: "198.23.2.2/30".to_owned(),
        },
    ];
    apply_links_to_nodes(&mut nodes, &links);
    apply_connect_to(&mut nodes, &[(1, 2), (3, 2)]);
    nodes[0].indirect_peers.push("gamma".to_owned());
    nodes[2].indirect_peers.push("alpha".to_owned());

    let mut cleanup = NetnsCleanup::new(workspace.path().to_path_buf());
    for node in &nodes {
        cleanup.add_namespace(node.namespace.clone());
        create_link_node_config(workspace.path(), node, &nodes, false)?;
    }
    for node in &nodes {
        if !try_ip(&["netns", "add", &node.namespace]) {
            eprintln!(
                "skipping C/Rust modern multihop netns interop test: cannot create network namespaces"
            );
            return Ok(());
        }
    }
    for link in &links {
        create_netns_underlay_link(&nodes, link)?;
    }

    let binaries: [&Path; 3] = if rust_middle {
        [c_tincd, Path::new(TINCD), c_tincd]
    } else {
        [Path::new(TINCD), c_tincd, Path::new(TINCD)]
    };
    for (index, node) in nodes.iter().enumerate() {
        cleanup.spawn_with_binary(
            &node.name,
            binaries[index],
            &workspace.path().join(&node.name),
            &node.namespace,
            &workspace.path().join(format!("{}.log", node.name)),
        )?;
    }

    for node in &nodes {
        wait_for_link(&node.namespace, &node.interface, &cleanup)?;
    }

    wait_for_ping(&nodes[0].namespace, &nodes[2].tunnel_ip, &cleanup)?;
    wait_for_ping(&nodes[2].namespace, &nodes[0].tunnel_ip, &cleanup)?;
    wait_for_ping(&nodes[0].namespace, &nodes[2].tunnel_ip, &cleanup)?;
    wait_for_ping(&nodes[2].namespace, &nodes[0].tunnel_ip, &cleanup)?;

    if check_udp_discovery_pmtu {
        assert_static_relay_udp_discovery_pmtu_like_tinc(
            &workspace,
            &cleanup,
            "alpha",
            "beta",
            "gamma",
            &nodes[0].namespace,
            &nodes[2].tunnel_ip,
            &nodes[2].namespace,
            &nodes[0].tunnel_ip,
        )?;
    }

    if let Some(capture) = no_plaintext_capture {
        assert_relay_underlay_ping_payload_not_plaintext(
            &nodes[0].namespace,
            &links[0].a_if,
            &nodes[0].namespace,
            &nodes[2].tunnel_ip,
            "c/rust modern static relay UDP data path",
            capture,
            &cleanup,
        )?;
        assert_relay_underlay_ping_payload_not_plaintext(
            &nodes[1].namespace,
            &links[1].a_if,
            &nodes[0].namespace,
            &nodes[2].tunnel_ip,
            "c/rust modern static relay forwarded UDP data path",
            capture,
            &cleanup,
        )?;
    }

    if exercise_peer_restart_topology {
        assert_modern_static_relay_raw_topology_like_tinc(
            &workspace,
            &nodes,
            &links,
            "before gamma restart",
        )?;
        cleanup.kill_child("gamma")?;
        wait_for_static_relay_endpoint_unreachable(
            &workspace.path().join("alpha"),
            "gamma",
            "modern static relay after gamma stop",
            &cleanup,
        )?;
        cleanup.spawn_with_binary(
            "gamma",
            binaries[2],
            &workspace.path().join("gamma"),
            &nodes[2].namespace,
            &workspace.path().join("gamma.log"),
        )?;
        wait_for_link(&nodes[2].namespace, &nodes[2].interface, &cleanup)?;
        wait_for_ping(&nodes[0].namespace, &nodes[2].tunnel_ip, &cleanup)?;
        wait_for_ping(&nodes[2].namespace, &nodes[0].tunnel_ip, &cleanup)?;
        wait_for_modern_static_relay_raw_topology_like_tinc(
            &workspace,
            &nodes,
            &links,
            "after gamma restart",
            &cleanup,
        )?;
    }

    Ok(())
}

fn run_c_rust_three_node_modern_dynamic_relay_interop(
    c_tincd: &Path,
    rust_middle: bool,
) -> Result<(), Box<dyn Error>> {
    run_c_rust_three_node_modern_dynamic_relay_interop_with_options(
        c_tincd,
        rust_middle,
        false,
        None,
        false,
    )
}

fn run_c_rust_three_node_modern_dynamic_relay_interop_with_options(
    c_tincd: &Path,
    rust_middle: bool,
    check_udp_discovery_pmtu: bool,
    no_plaintext_capture: Option<NoPlaintextCapture>,
    exercise_endpoint_restart_no_plaintext: bool,
) -> Result<(), Box<dyn Error>> {
    let workspace = TempWorkspace::new(if rust_middle {
        if exercise_endpoint_restart_no_plaintext {
            "tinc-rust-c-modern-dynamic-relay-restart-no-plain-rust-middle"
        } else if no_plaintext_capture == Some(NoPlaintextCapture::Udp) {
            "tinc-rust-c-modern-dynamic-relay-no-plain-rust-middle"
        } else {
            "tinc-rust-c-modern-dynamic-relay-rust-middle"
        }
    } else if exercise_endpoint_restart_no_plaintext {
        "tinc-rust-c-modern-dynamic-relay-restart-no-plain-c-middle"
    } else if no_plaintext_capture == Some(NoPlaintextCapture::Udp) {
        "tinc-rust-c-modern-dynamic-relay-no-plain-c-middle"
    } else {
        "tinc-rust-c-modern-dynamic-relay-c-middle"
    })?;
    let suffix = unique_suffix();
    let mut nodes = (1..=3)
        .map(|index| LinkNode {
            name: match index {
                1 => "alpha",
                2 => "beta",
                3 => "gamma",
                _ => unreachable!(),
            }
            .to_owned(),
            namespace: format!(
                "tinc-mod-drelay-{}-{index}-{suffix}",
                if (index == 2) == rust_middle {
                    "r"
                } else {
                    "c"
                }
            ),
            port: if rust_middle {
                17880 + index as u16
            } else {
                17890 + index as u16
            },
            device_type: "tun",
            mode: None,
            interface: match index {
                1 => "tun-dyn-a",
                2 => "tun-dyn-b",
                3 => "tun-dyn-g",
                _ => unreachable!(),
            }
            .to_owned(),
            tunnel_ip: format!("10.117.{index}.1"),
            tunnel_cidr: format!("10.117.{index}.1/24"),
            subnet: format!("10.117.{index}.0/24"),
            route: "10.117.0.0/16".to_owned(),
            tunnel_ipv6: None,
            tunnel_ipv6_cidr: None,
            subnet_ipv6: None,
            route_ipv6: None,
            static_mac_subnet: None,
            seed: 110 + index as u8,
            bind_addresses: Vec::new(),
            neighbor_addresses: Vec::new(),
            connect_to: Vec::new(),
            indirect_peers: Vec::new(),
        })
        .collect::<Vec<_>>();
    let links = vec![
        UnderlayLink {
            a: 1,
            b: 2,
            a_if: format!("dr12a{suffix}"),
            b_if: format!("dr12b{suffix}"),
            a_ip: "198.29.1.1".to_owned(),
            b_ip: "198.29.1.2".to_owned(),
            a_cidr: "198.29.1.1/30".to_owned(),
            b_cidr: "198.29.1.2/30".to_owned(),
        },
        UnderlayLink {
            a: 2,
            b: 3,
            a_if: format!("dr23a{suffix}"),
            b_if: format!("dr23b{suffix}"),
            a_ip: "198.29.2.1".to_owned(),
            b_ip: "198.29.2.2".to_owned(),
            a_cidr: "198.29.2.1/30".to_owned(),
            b_cidr: "198.29.2.2/30".to_owned(),
        },
    ];
    apply_links_to_nodes(&mut nodes, &links);
    apply_connect_to(&mut nodes, &[(1, 2), (3, 2)]);
    nodes[0]
        .neighbor_addresses
        .push(("gamma".to_owned(), links[1].b_ip.clone()));
    nodes[2]
        .neighbor_addresses
        .push(("alpha".to_owned(), links[0].a_ip.clone()));

    let mut cleanup = NetnsCleanup::new(workspace.path().to_path_buf());
    for node in &nodes {
        cleanup.add_namespace(node.namespace.clone());
        create_link_node_config(workspace.path(), node, &nodes, false)?;
    }
    for node in &nodes {
        if !try_ip(&["netns", "add", &node.namespace]) {
            eprintln!(
                "skipping C/Rust modern dynamic relay netns interop test: cannot create network namespaces"
            );
            return Ok(());
        }
    }
    for link in &links {
        create_netns_underlay_link(&nodes, link)?;
    }

    run_ip(&[
        "-n",
        &nodes[0].namespace,
        "route",
        "add",
        "unreachable",
        &links[1].b_ip,
    ])?;
    run_ip(&[
        "-n",
        &nodes[2].namespace,
        "route",
        "add",
        "unreachable",
        &links[0].a_ip,
    ])?;

    let binaries: [&Path; 3] = if rust_middle {
        [c_tincd, Path::new(TINCD), c_tincd]
    } else {
        [Path::new(TINCD), c_tincd, Path::new(TINCD)]
    };
    for (index, node) in nodes.iter().enumerate() {
        cleanup.spawn_with_binary(
            &node.name,
            binaries[index],
            &workspace.path().join(&node.name),
            &node.namespace,
            &workspace.path().join(format!("{}.log", node.name)),
        )?;
    }

    for node in &nodes {
        wait_for_link(&node.namespace, &node.interface, &cleanup)?;
    }

    wait_for_node_route_via(
        &workspace.path().join("alpha"),
        "gamma",
        "beta",
        "gamma",
        false,
        &cleanup,
    )?;
    wait_for_node_route_via(
        &workspace.path().join("gamma"),
        "alpha",
        "beta",
        "alpha",
        false,
        &cleanup,
    )?;
    wait_for_ping(&nodes[0].namespace, &nodes[2].tunnel_ip, &cleanup)?;
    wait_for_ping(&nodes[2].namespace, &nodes[0].tunnel_ip, &cleanup)?;
    wait_for_ping(&nodes[0].namespace, &nodes[2].tunnel_ip, &cleanup)?;
    wait_for_ping(&nodes[2].namespace, &nodes[0].tunnel_ip, &cleanup)?;
    wait_for_modern_dynamic_relay_raw_topology_like_tinc(&workspace, &nodes, &links, &cleanup)?;

    if check_udp_discovery_pmtu {
        assert_dynamic_relay_udp_discovery_pmtu_like_tinc(
            &workspace,
            &cleanup,
            "alpha",
            "beta",
            "gamma",
            &nodes[0].namespace,
            &nodes[2].tunnel_ip,
            &nodes[2].namespace,
            &nodes[0].tunnel_ip,
        )?;
    }

    if let Some(capture) = no_plaintext_capture {
        assert_relay_underlay_ping_payload_not_plaintext(
            &nodes[0].namespace,
            &links[0].a_if,
            &nodes[0].namespace,
            &nodes[2].tunnel_ip,
            "c/rust modern dynamic relay UDP data path",
            capture,
            &cleanup,
        )?;
        assert_relay_underlay_ping_payload_not_plaintext(
            &nodes[1].namespace,
            &links[1].a_if,
            &nodes[0].namespace,
            &nodes[2].tunnel_ip,
            "c/rust modern dynamic relay forwarded UDP data path",
            capture,
            &cleanup,
        )?;
    }

    if exercise_endpoint_restart_no_plaintext {
        cleanup.kill_child("gamma")?;
        wait_for_no_ping(&nodes[0].namespace, &nodes[2].tunnel_ip, &cleanup)?;
        cleanup.spawn_with_binary(
            &nodes[2].name,
            binaries[2],
            &workspace.path().join(&nodes[2].name),
            &nodes[2].namespace,
            &workspace.path().join(format!("{}.log", nodes[2].name)),
        )?;
        wait_for_pidfile(&workspace.path().join("gamma").join("pid"), &cleanup)?;
        wait_for_control_socket(&workspace.path().join("gamma").join("pid.socket"), &cleanup)?;
        wait_for_link(&nodes[2].namespace, &nodes[2].interface, &cleanup)?;
        wait_for_node_route_via(
            &workspace.path().join("alpha"),
            "gamma",
            "beta",
            "gamma",
            false,
            &cleanup,
        )?;
        wait_for_node_route_via(
            &workspace.path().join("gamma"),
            "alpha",
            "beta",
            "alpha",
            false,
            &cleanup,
        )?;
        wait_for_ping(&nodes[0].namespace, &nodes[2].tunnel_ip, &cleanup)?;
        wait_for_ping(&nodes[2].namespace, &nodes[0].tunnel_ip, &cleanup)?;
        wait_for_modern_dynamic_relay_raw_topology_like_tinc(&workspace, &nodes, &links, &cleanup)?;
        assert_relay_underlay_ping_payload_not_plaintext(
            &nodes[0].namespace,
            &links[0].a_if,
            &nodes[0].namespace,
            &nodes[2].tunnel_ip,
            "c/rust modern dynamic relay UDP data path after endpoint restart",
            NoPlaintextCapture::Udp,
            &cleanup,
        )?;
        assert_relay_underlay_ping_payload_not_plaintext(
            &nodes[1].namespace,
            &links[1].a_if,
            &nodes[0].namespace,
            &nodes[2].tunnel_ip,
            "c/rust modern dynamic relay forwarded UDP data path after endpoint restart",
            NoPlaintextCapture::Udp,
            &cleanup,
        )?;
    }

    Ok(())
}

fn run_c_rust_three_node_legacy_indirect_multihop_interop(
    c_tincd: &Path,
    rust_middle: bool,
) -> Result<(), Box<dyn Error>> {
    run_c_rust_three_node_legacy_indirect_multihop_interop_with_options(
        c_tincd,
        rust_middle,
        false,
        None,
        false,
    )
}

fn run_c_rust_three_node_legacy_indirect_multihop_interop_with_options(
    c_tincd: &Path,
    rust_middle: bool,
    check_udp_discovery_pmtu: bool,
    no_plaintext_capture: Option<NoPlaintextCapture>,
    exercise_peer_restart_topology: bool,
) -> Result<(), Box<dyn Error>> {
    let workspace = TempWorkspace::new(if rust_middle {
        if no_plaintext_capture.is_some() {
            "tinc-rust-c-legacy-indirect-no-plain-rust-middle"
        } else {
            "tinc-rust-c-legacy-indirect-rust-middle"
        }
    } else if no_plaintext_capture.is_some() {
        "tinc-rust-c-legacy-indirect-no-plain-c-middle"
    } else {
        "tinc-rust-c-legacy-indirect-c-middle"
    })?;
    let suffix = unique_suffix();
    let mut nodes = vec![
        LegacyMultihopNode {
            name: "alpha",
            namespace: format!(
                "tinc-leg-mhop-a-{}-{suffix}",
                if rust_middle { "c" } else { "r" }
            ),
            port: if rust_middle { 17761 } else { 17771 },
            interface: "tun-lm-a",
            tunnel_address: "10.105.1.1/24",
            tunnel_ip: "10.105.1.1",
            subnet: "10.105.1.0/24",
            route: "10.105.0.0/16",
            bind_addresses: Vec::new(),
            neighbor_addresses: Vec::new(),
            connect_to: vec!["beta"],
            indirect_peers: Vec::new(),
        },
        LegacyMultihopNode {
            name: "beta",
            namespace: format!(
                "tinc-leg-mhop-b-{}-{suffix}",
                if rust_middle { "r" } else { "c" }
            ),
            port: if rust_middle { 17762 } else { 17772 },
            interface: "tun-lm-b",
            tunnel_address: "10.105.2.1/24",
            tunnel_ip: "10.105.2.1",
            subnet: "10.105.2.0/24",
            route: "10.105.0.0/16",
            bind_addresses: Vec::new(),
            neighbor_addresses: Vec::new(),
            connect_to: Vec::new(),
            indirect_peers: Vec::new(),
        },
        LegacyMultihopNode {
            name: "gamma",
            namespace: format!(
                "tinc-leg-mhop-g-{}-{suffix}",
                if rust_middle { "c" } else { "r" }
            ),
            port: if rust_middle { 17763 } else { 17773 },
            interface: "tun-lm-g",
            tunnel_address: "10.105.3.1/24",
            tunnel_ip: "10.105.3.1",
            subnet: "10.105.3.0/24",
            route: "10.105.0.0/16",
            bind_addresses: Vec::new(),
            neighbor_addresses: Vec::new(),
            connect_to: vec!["beta"],
            indirect_peers: vec!["alpha"],
        },
    ];
    let links = vec![
        UnderlayLink {
            a: 1,
            b: 2,
            a_if: format!("lm12a{suffix}"),
            b_if: format!("lm12b{suffix}"),
            a_ip: "198.22.1.1".to_owned(),
            b_ip: "198.22.1.2".to_owned(),
            a_cidr: "198.22.1.1/30".to_owned(),
            b_cidr: "198.22.1.2/30".to_owned(),
        },
        UnderlayLink {
            a: 2,
            b: 3,
            a_if: format!("lm23a{suffix}"),
            b_if: format!("lm23b{suffix}"),
            a_ip: "198.22.2.1".to_owned(),
            b_ip: "198.22.2.2".to_owned(),
            a_cidr: "198.22.2.1/30".to_owned(),
            b_cidr: "198.22.2.2/30".to_owned(),
        },
    ];
    for link in &links {
        let a_name = nodes[link.a - 1].name;
        let b_name = nodes[link.b - 1].name;
        nodes[link.a - 1].bind_addresses.push(link.a_ip.clone());
        nodes[link.b - 1].bind_addresses.push(link.b_ip.clone());
        nodes[link.a - 1]
            .neighbor_addresses
            .push((b_name, link.b_ip.clone()));
        nodes[link.b - 1]
            .neighbor_addresses
            .push((a_name, link.a_ip.clone()));
    }

    let private_keys = (0..nodes.len())
        .map(|_| RsaPrivateKey::new(&mut OsRng, 2048))
        .collect::<Result<Vec<_>, _>>()?;
    let public_keys = private_keys
        .iter()
        .map(RsaPublicKey::from)
        .collect::<Vec<_>>();

    let mut cleanup = NetnsCleanup::new(workspace.path().to_path_buf());
    for (index, node) in nodes.iter().enumerate() {
        cleanup.add_namespace(node.namespace.clone());
        create_legacy_multihop_node_config(
            workspace.path(),
            node,
            &nodes,
            &private_keys[index],
            &public_keys,
        )?;
    }
    for node in &nodes {
        if !try_ip(&["netns", "add", &node.namespace]) {
            eprintln!(
                "skipping C/Rust legacy multihop netns interop test: cannot create network namespaces"
            );
            return Ok(());
        }
    }
    for link in &links {
        create_legacy_multihop_underlay_link(&nodes, link)?;
    }

    let binaries: [&Path; 3] = if rust_middle {
        [c_tincd, Path::new(TINCD), c_tincd]
    } else {
        [Path::new(TINCD), c_tincd, Path::new(TINCD)]
    };
    for (index, node) in nodes.iter().enumerate() {
        cleanup.spawn_with_binary(
            node.name,
            binaries[index],
            &workspace.path().join(node.name),
            &node.namespace,
            &workspace.path().join(format!("{}.log", node.name)),
        )?;
    }

    for node in &nodes {
        wait_for_link(&node.namespace, node.interface, &cleanup)?;
    }

    wait_for_ping(&nodes[0].namespace, nodes[2].tunnel_ip, &cleanup)?;
    wait_for_ping(&nodes[2].namespace, nodes[0].tunnel_ip, &cleanup)?;
    wait_for_ping(&nodes[0].namespace, nodes[2].tunnel_ip, &cleanup)?;
    wait_for_ping(&nodes[2].namespace, nodes[0].tunnel_ip, &cleanup)?;

    if check_udp_discovery_pmtu {
        assert_static_relay_udp_discovery_pmtu_like_tinc(
            &workspace,
            &cleanup,
            "alpha",
            "beta",
            "gamma",
            &nodes[0].namespace,
            nodes[2].tunnel_ip,
            &nodes[2].namespace,
            nodes[0].tunnel_ip,
        )?;
    }

    if let Some(capture) = no_plaintext_capture {
        assert_relay_underlay_ping_payload_not_plaintext(
            &nodes[0].namespace,
            &links[0].a_if,
            &nodes[0].namespace,
            nodes[2].tunnel_ip,
            "c/rust legacy static relay UDP data path",
            capture,
            &cleanup,
        )?;
        assert_relay_underlay_ping_payload_not_plaintext(
            &nodes[1].namespace,
            &links[1].a_if,
            &nodes[0].namespace,
            nodes[2].tunnel_ip,
            "c/rust legacy static relay forwarded UDP data path",
            capture,
            &cleanup,
        )?;
    }

    if exercise_peer_restart_topology {
        assert_legacy_static_relay_raw_topology_like_tinc(
            &workspace,
            &nodes,
            &links,
            "before gamma restart",
        )?;
        cleanup.kill_child("gamma")?;
        wait_for_static_relay_endpoint_unreachable(
            &workspace.path().join("alpha"),
            "gamma",
            "legacy static relay after gamma stop",
            &cleanup,
        )?;
        cleanup.spawn_with_binary(
            "gamma",
            binaries[2],
            &workspace.path().join("gamma"),
            &nodes[2].namespace,
            &workspace.path().join("gamma.log"),
        )?;
        wait_for_link(&nodes[2].namespace, nodes[2].interface, &cleanup)?;
        wait_for_ping(&nodes[0].namespace, nodes[2].tunnel_ip, &cleanup)?;
        wait_for_ping(&nodes[2].namespace, nodes[0].tunnel_ip, &cleanup)?;
        wait_for_legacy_static_relay_raw_topology_like_tinc(
            &workspace,
            &nodes,
            &links,
            "after gamma restart",
            &cleanup,
        )?;
    }

    Ok(())
}

fn run_c_rust_three_node_legacy_dynamic_relay_interop(
    c_tincd: &Path,
    rust_middle: bool,
) -> Result<(), Box<dyn Error>> {
    run_c_rust_three_node_legacy_dynamic_relay_interop_with_options(
        c_tincd,
        rust_middle,
        false,
        None,
        false,
    )
}

fn run_c_rust_three_node_legacy_dynamic_relay_interop_with_options(
    c_tincd: &Path,
    rust_middle: bool,
    check_udp_discovery_pmtu: bool,
    no_plaintext_capture: Option<NoPlaintextCapture>,
    exercise_rekey: bool,
) -> Result<(), Box<dyn Error>> {
    let workspace = TempWorkspace::new(if rust_middle {
        if exercise_rekey {
            "tinc-rust-c-legacy-dynamic-relay-rekey-rust-middle"
        } else if no_plaintext_capture.is_some() {
            "tinc-rust-c-legacy-dynamic-relay-no-plain-rust-middle"
        } else {
            "tinc-rust-c-legacy-dynamic-relay-rust-middle"
        }
    } else if exercise_rekey {
        "tinc-rust-c-legacy-dynamic-relay-rekey-c-middle"
    } else if no_plaintext_capture.is_some() {
        "tinc-rust-c-legacy-dynamic-relay-no-plain-c-middle"
    } else {
        "tinc-rust-c-legacy-dynamic-relay-c-middle"
    })?;
    let suffix = unique_suffix();
    let mut nodes = vec![
        LegacyMultihopNode {
            name: "alpha",
            namespace: format!(
                "tinc-leg-drelay-a-{}-{suffix}",
                if rust_middle { "c" } else { "r" }
            ),
            port: if rust_middle { 17781 } else { 17791 },
            interface: "tun-ld-a",
            tunnel_address: "10.118.1.1/24",
            tunnel_ip: "10.118.1.1",
            subnet: "10.118.1.0/24",
            route: "10.118.0.0/16",
            bind_addresses: Vec::new(),
            neighbor_addresses: Vec::new(),
            connect_to: vec!["beta"],
            indirect_peers: Vec::new(),
        },
        LegacyMultihopNode {
            name: "beta",
            namespace: format!(
                "tinc-leg-drelay-b-{}-{suffix}",
                if rust_middle { "r" } else { "c" }
            ),
            port: if rust_middle { 17782 } else { 17792 },
            interface: "tun-ld-b",
            tunnel_address: "10.118.2.1/24",
            tunnel_ip: "10.118.2.1",
            subnet: "10.118.2.0/24",
            route: "10.118.0.0/16",
            bind_addresses: Vec::new(),
            neighbor_addresses: Vec::new(),
            connect_to: Vec::new(),
            indirect_peers: Vec::new(),
        },
        LegacyMultihopNode {
            name: "gamma",
            namespace: format!(
                "tinc-leg-drelay-g-{}-{suffix}",
                if rust_middle { "c" } else { "r" }
            ),
            port: if rust_middle { 17783 } else { 17793 },
            interface: "tun-ld-g",
            tunnel_address: "10.118.3.1/24",
            tunnel_ip: "10.118.3.1",
            subnet: "10.118.3.0/24",
            route: "10.118.0.0/16",
            bind_addresses: Vec::new(),
            neighbor_addresses: Vec::new(),
            connect_to: vec!["beta"],
            indirect_peers: Vec::new(),
        },
    ];
    let links = vec![
        UnderlayLink {
            a: 1,
            b: 2,
            a_if: format!("ldr12a{suffix}"),
            b_if: format!("ldr12b{suffix}"),
            a_ip: "198.31.1.1".to_owned(),
            b_ip: "198.31.1.2".to_owned(),
            a_cidr: "198.31.1.1/30".to_owned(),
            b_cidr: "198.31.1.2/30".to_owned(),
        },
        UnderlayLink {
            a: 2,
            b: 3,
            a_if: format!("ldr23a{suffix}"),
            b_if: format!("ldr23b{suffix}"),
            a_ip: "198.31.2.1".to_owned(),
            b_ip: "198.31.2.2".to_owned(),
            a_cidr: "198.31.2.1/30".to_owned(),
            b_cidr: "198.31.2.2/30".to_owned(),
        },
    ];
    for link in &links {
        let a_name = nodes[link.a - 1].name;
        let b_name = nodes[link.b - 1].name;
        nodes[link.a - 1].bind_addresses.push(link.a_ip.clone());
        nodes[link.b - 1].bind_addresses.push(link.b_ip.clone());
        nodes[link.a - 1]
            .neighbor_addresses
            .push((b_name, link.b_ip.clone()));
        nodes[link.b - 1]
            .neighbor_addresses
            .push((a_name, link.a_ip.clone()));
    }
    nodes[0]
        .neighbor_addresses
        .push(("gamma", links[1].b_ip.clone()));
    nodes[2]
        .neighbor_addresses
        .push(("alpha", links[0].a_ip.clone()));

    let private_keys = (0..nodes.len())
        .map(|_| RsaPrivateKey::new(&mut OsRng, 2048))
        .collect::<Result<Vec<_>, _>>()?;
    let public_keys = private_keys
        .iter()
        .map(RsaPublicKey::from)
        .collect::<Vec<_>>();

    let mut cleanup = NetnsCleanup::new(workspace.path().to_path_buf());
    for (index, node) in nodes.iter().enumerate() {
        cleanup.add_namespace(node.namespace.clone());
        create_legacy_multihop_node_config_inner(
            workspace.path(),
            node,
            &nodes,
            &private_keys[index],
            &public_keys,
            None,
            exercise_rekey.then_some(5),
        )?;
    }
    for node in &nodes {
        if !try_ip(&["netns", "add", &node.namespace]) {
            eprintln!(
                "skipping C/Rust legacy dynamic relay netns interop test: cannot create network namespaces"
            );
            return Ok(());
        }
    }
    for link in &links {
        create_legacy_multihop_underlay_link(&nodes, link)?;
    }
    run_ip(&[
        "-n",
        &nodes[0].namespace,
        "route",
        "add",
        "unreachable",
        &links[1].b_ip,
    ])?;
    run_ip(&[
        "-n",
        &nodes[2].namespace,
        "route",
        "add",
        "unreachable",
        &links[0].a_ip,
    ])?;

    let binaries: [&Path; 3] = if rust_middle {
        [c_tincd, Path::new(TINCD), c_tincd]
    } else {
        [Path::new(TINCD), c_tincd, Path::new(TINCD)]
    };
    for (index, node) in nodes.iter().enumerate() {
        cleanup.spawn_with_binary(
            node.name,
            binaries[index],
            &workspace.path().join(node.name),
            &node.namespace,
            &workspace.path().join(format!("{}.log", node.name)),
        )?;
    }

    for node in &nodes {
        wait_for_link(&node.namespace, node.interface, &cleanup)?;
    }

    wait_for_node_route_via(
        &workspace.path().join("alpha"),
        "gamma",
        "beta",
        "gamma",
        false,
        &cleanup,
    )?;
    wait_for_node_route_via(
        &workspace.path().join("gamma"),
        "alpha",
        "beta",
        "alpha",
        false,
        &cleanup,
    )?;
    wait_for_ping(&nodes[0].namespace, nodes[2].tunnel_ip, &cleanup)?;
    wait_for_ping(&nodes[2].namespace, nodes[0].tunnel_ip, &cleanup)?;
    wait_for_ping(&nodes[0].namespace, nodes[2].tunnel_ip, &cleanup)?;
    wait_for_ping(&nodes[2].namespace, nodes[0].tunnel_ip, &cleanup)?;
    if !exercise_rekey {
        wait_for_legacy_dynamic_relay_raw_topology_like_tinc(&workspace, &nodes, &links, &cleanup)?;
    }

    if exercise_rekey {
        wait_for_legacy_rekey(&cleanup)?;
        wait_for_ping(&nodes[0].namespace, nodes[2].tunnel_ip, &cleanup)?;
        wait_for_ping(&nodes[2].namespace, nodes[0].tunnel_ip, &cleanup)?;
        wait_for_ping(&nodes[0].namespace, nodes[2].tunnel_ip, &cleanup)?;
        wait_for_ping(&nodes[2].namespace, nodes[0].tunnel_ip, &cleanup)?;
        wait_for_legacy_dynamic_relay_rekey_raw_topology_like_tinc(
            &workspace, &nodes, &links, &cleanup,
        )?;
    }

    if check_udp_discovery_pmtu {
        assert_dynamic_relay_udp_discovery_pmtu_like_tinc(
            &workspace,
            &cleanup,
            "alpha",
            "beta",
            "gamma",
            &nodes[0].namespace,
            nodes[2].tunnel_ip,
            &nodes[2].namespace,
            nodes[0].tunnel_ip,
        )?;
    }

    if let Some(capture) = no_plaintext_capture {
        assert_relay_underlay_ping_payload_not_plaintext(
            &nodes[0].namespace,
            &links[0].a_if,
            &nodes[0].namespace,
            nodes[2].tunnel_ip,
            "c/rust legacy dynamic relay UDP data path",
            capture,
            &cleanup,
        )?;
        assert_relay_underlay_ping_payload_not_plaintext(
            &nodes[1].namespace,
            &links[1].a_if,
            &nodes[0].namespace,
            nodes[2].tunnel_ip,
            "c/rust legacy dynamic relay forwarded UDP data path",
            capture,
            &cleanup,
        )?;
    }

    Ok(())
}

fn run_c_tincctl_rust_tincd_legacy_multihop_status_topology(
    c_tinc: &Path,
) -> Result<(), Box<dyn Error>> {
    let workspace = TempWorkspace::new("tinc-cctl-rustdaemon-legacy-multihop-status")?;
    let suffix = unique_suffix();
    let mut nodes = vec![
        LegacyMultihopNode {
            name: "alpha",
            namespace: format!("tinc-ctl-leg-mhop-a-{suffix}"),
            port: 18211,
            interface: "tun-clm-a",
            tunnel_address: "10.110.1.1/24",
            tunnel_ip: "10.110.1.1",
            subnet: "10.110.1.0/24",
            route: "10.110.0.0/16",
            bind_addresses: Vec::new(),
            neighbor_addresses: Vec::new(),
            connect_to: vec!["beta"],
            indirect_peers: Vec::new(),
        },
        LegacyMultihopNode {
            name: "beta",
            namespace: format!("tinc-ctl-leg-mhop-b-{suffix}"),
            port: 18212,
            interface: "tun-clm-b",
            tunnel_address: "10.110.2.1/24",
            tunnel_ip: "10.110.2.1",
            subnet: "10.110.2.0/24",
            route: "10.110.0.0/16",
            bind_addresses: Vec::new(),
            neighbor_addresses: Vec::new(),
            connect_to: Vec::new(),
            indirect_peers: vec!["gamma"],
        },
        LegacyMultihopNode {
            name: "gamma",
            namespace: format!("tinc-ctl-leg-mhop-g-{suffix}"),
            port: 18213,
            interface: "tun-clm-g",
            tunnel_address: "10.110.3.1/24",
            tunnel_ip: "10.110.3.1",
            subnet: "10.110.3.0/24",
            route: "10.110.0.0/16",
            bind_addresses: Vec::new(),
            neighbor_addresses: Vec::new(),
            connect_to: vec!["beta"],
            indirect_peers: vec!["beta"],
        },
    ];
    let links = vec![
        UnderlayLink {
            a: 1,
            b: 2,
            a_if: format!("clm12a{suffix}"),
            b_if: format!("clm12b{suffix}"),
            a_ip: "198.27.1.1".to_owned(),
            b_ip: "198.27.1.2".to_owned(),
            a_cidr: "198.27.1.1/30".to_owned(),
            b_cidr: "198.27.1.2/30".to_owned(),
        },
        UnderlayLink {
            a: 2,
            b: 3,
            a_if: format!("clm23a{suffix}"),
            b_if: format!("clm23b{suffix}"),
            a_ip: "198.27.2.1".to_owned(),
            b_ip: "198.27.2.2".to_owned(),
            a_cidr: "198.27.2.1/30".to_owned(),
            b_cidr: "198.27.2.2/30".to_owned(),
        },
    ];
    for link in &links {
        let a_name = nodes[link.a - 1].name;
        let b_name = nodes[link.b - 1].name;
        nodes[link.a - 1].bind_addresses.push(link.a_ip.clone());
        nodes[link.b - 1].bind_addresses.push(link.b_ip.clone());
        nodes[link.a - 1]
            .neighbor_addresses
            .push((b_name, link.b_ip.clone()));
        nodes[link.b - 1]
            .neighbor_addresses
            .push((a_name, link.a_ip.clone()));
    }

    let private_keys = (0..nodes.len())
        .map(|_| RsaPrivateKey::new(&mut OsRng, 2048))
        .collect::<Result<Vec<_>, _>>()?;
    let public_keys = private_keys
        .iter()
        .map(RsaPublicKey::from)
        .collect::<Vec<_>>();
    let mut cleanup = NetnsCleanup::new(workspace.path().to_path_buf());
    for (index, node) in nodes.iter().enumerate() {
        cleanup.add_namespace(node.namespace.clone());
        create_legacy_multihop_node_config(
            workspace.path(),
            node,
            &nodes,
            &private_keys[index],
            &public_keys,
        )?;
    }
    for node in &nodes {
        if !try_ip(&["netns", "add", &node.namespace]) {
            eprintln!(
                "skipping C tincctl/Rust tincd legacy multihop dump interop test: cannot create network namespaces"
            );
            return Ok(());
        }
    }
    for link in &links {
        create_legacy_multihop_underlay_link(&nodes, link)?;
    }

    for node in &nodes {
        cleanup.spawn(
            node.name,
            &workspace.path().join(node.name),
            &node.namespace,
            &workspace.path().join(format!("{}.log", node.name)),
        )?;
    }
    for node in &nodes {
        wait_for_pidfile(&workspace.path().join(node.name).join("pid"), &cleanup)?;
        wait_for_control_socket(
            &workspace.path().join(node.name).join("pid.socket"),
            &cleanup,
        )?;
        wait_for_link(&node.namespace, node.interface, &cleanup)?;
    }

    wait_for_ping(&nodes[0].namespace, nodes[2].tunnel_ip, &cleanup)?;
    wait_for_ping(&nodes[2].namespace, nodes[0].tunnel_ip, &cleanup)?;
    wait_for_ping(&nodes[0].namespace, nodes[2].tunnel_ip, &cleanup)?;
    wait_for_ping(&nodes[2].namespace, nodes[0].tunnel_ip, &cleanup)?;

    let alpha_confdir = workspace.path().join("alpha");
    let nodes_dump = run_c_tinc(
        c_tinc,
        &nodes[0].namespace,
        &alpha_confdir,
        &["dump", "nodes"],
    )?;
    assert_c_dump_node_has_status_words(&nodes_dump, "alpha", &["reachable"])?;
    assert_c_dump_node_lacks_status_words(&nodes_dump, "alpha", &["sptps"])?;
    assert_c_dump_node_has_status_words(
        &nodes_dump,
        "beta",
        &["validkey", "validkey_in", "reachable"],
    )?;
    assert_c_dump_node_lacks_status_words(&nodes_dump, "beta", &["sptps"])?;
    assert_c_dump_node_has_status_words(&nodes_dump, "gamma", &["reachable", "indirect"])?;
    assert_c_dump_node_lacks_status_words(&nodes_dump, "gamma", &["validkey", "validkey_in"])?;
    assert_c_dump_node_lacks_status_words(&nodes_dump, "gamma", &["sptps"])?;
    assert_c_dump_node_has_route(&nodes_dump, "beta", "beta", "beta", 1)?;
    assert_c_dump_node_has_route(&nodes_dump, "gamma", "beta", "beta", 2)?;
    assert_c_dump_node_options_include(&nodes_dump, "gamma", 0x1)?;
    // Original C tinc exposes the static reverse edge endpoint for an indirect
    // legacy node in dump nodes, while leaving its packet key fields unset.
    assert!(
        c_dump_node_line(&nodes_dump, "gamma")?
            .contains("198.27.2.2 port 18213 cipher 0 digest 0 maclength 0 compression 0 "),
        "C tinc dump nodes did not expose Rust legacy static multihop edge endpoint for gamma without packet keys:\n{nodes_dump}\n{}",
        cleanup.logs()
    );

    let edges = run_c_tinc(
        c_tinc,
        &nodes[0].namespace,
        &alpha_confdir,
        &["dump", "edges"],
    )?;
    assert!(
        edges.contains("alpha to beta at 198.27.1.2 port 18212")
            && edges.contains("gamma to beta at 198.27.2.1 port 18212"),
        "C tinc dump edges did not parse Rust legacy multihop edge endpoints:\n{edges}\n{}",
        cleanup.logs()
    );
    assert_c_dump_edge_options_include(&edges, "beta", "gamma", 0x1)
        .or_else(|_| assert_c_dump_edge_options_include(&edges, "gamma", "beta", 0x1))?;

    let subnets = run_c_tinc(
        c_tinc,
        &nodes[0].namespace,
        &alpha_confdir,
        &["dump", "subnets"],
    )?;
    assert!(
        subnets.contains("10.110.1.0/24 owner alpha")
            && subnets.contains("10.110.2.0/24 owner beta")
            && subnets.contains("10.110.3.0/24 owner gamma"),
        "C tinc dump subnets did not parse Rust legacy multihop subnet owners:\n{subnets}\n{}",
        cleanup.logs()
    );

    let graph = run_c_tinc(
        c_tinc,
        &nodes[0].namespace,
        &alpha_confdir,
        &["dump", "graph"],
    )?;
    assert!(
        graph.contains("\"alpha\"")
            && graph.contains("\"beta\"")
            && graph.contains("\"gamma\"")
            && (graph.contains("\"alpha\" -- \"beta\"") || graph.contains("\"beta\" -- \"alpha\""))
            && (graph.contains("\"beta\" -- \"gamma\"") || graph.contains("\"gamma\" -- \"beta\"")),
        "C tinc dump graph did not parse Rust legacy multihop graph:\n{graph}\n{}",
        cleanup.logs()
    );

    let info = run_c_tinc(
        c_tinc,
        &nodes[0].namespace,
        &alpha_confdir,
        &["info", "gamma"],
    )?;
    assert!(
        info.lines().any(|line| line.starts_with("Status:")
            && line.contains("reachable")
            && line.contains("indirect")
            && !line.contains("validkey")
            && !line.contains("sptps"))
            && info.contains("Options:      indirect")
            && info.contains("Reachability: indirectly via beta")
            && info.contains("Subnets:      10.110.3.0/24"),
        "C tinc info gamma did not interpret Rust legacy indirect multihop topology like tinc:\n{info}\n{}",
        cleanup.logs()
    );

    for node in &nodes {
        let stop = run_rust_tincctl(&[
            "tinc",
            "--config",
            workspace.path().join(node.name).to_str().unwrap(),
            "stop",
        ])
        .map_err(|error| {
            format!(
                "Rust tincctl stop against Rust legacy multihop {} failed after C dump status test: {error}\n{}",
                node.name,
                cleanup.logs()
            )
        })?;
        assert!(stop.is_empty(), "unexpected stop output: {stop}");
        wait_for_child_exit(&mut cleanup, node.name)?;
    }

    Ok(())
}

fn run_c_tincctl_rust_tincd_legacy_dynamic_relay_status_topology(
    c_tinc: &Path,
) -> Result<(), Box<dyn Error>> {
    let workspace = TempWorkspace::new("tinc-cctl-rustdaemon-legacy-dynamic-relay-status")?;
    let suffix = unique_suffix();
    let mut nodes = vec![
        LegacyMultihopNode {
            name: "alpha",
            namespace: format!("tinc-ctl-leg-drelay-a-{suffix}"),
            port: 18231,
            interface: "tun-cld-a",
            tunnel_address: "10.119.1.1/24",
            tunnel_ip: "10.119.1.1",
            subnet: "10.119.1.0/24",
            route: "10.119.0.0/16",
            bind_addresses: Vec::new(),
            neighbor_addresses: Vec::new(),
            connect_to: vec!["beta"],
            indirect_peers: Vec::new(),
        },
        LegacyMultihopNode {
            name: "beta",
            namespace: format!("tinc-ctl-leg-drelay-b-{suffix}"),
            port: 18232,
            interface: "tun-cld-b",
            tunnel_address: "10.119.2.1/24",
            tunnel_ip: "10.119.2.1",
            subnet: "10.119.2.0/24",
            route: "10.119.0.0/16",
            bind_addresses: Vec::new(),
            neighbor_addresses: Vec::new(),
            connect_to: Vec::new(),
            indirect_peers: Vec::new(),
        },
        LegacyMultihopNode {
            name: "gamma",
            namespace: format!("tinc-ctl-leg-drelay-g-{suffix}"),
            port: 18233,
            interface: "tun-cld-g",
            tunnel_address: "10.119.3.1/24",
            tunnel_ip: "10.119.3.1",
            subnet: "10.119.3.0/24",
            route: "10.119.0.0/16",
            bind_addresses: Vec::new(),
            neighbor_addresses: Vec::new(),
            connect_to: vec!["beta"],
            indirect_peers: Vec::new(),
        },
    ];
    let links = vec![
        UnderlayLink {
            a: 1,
            b: 2,
            a_if: format!("cld12a{suffix}"),
            b_if: format!("cld12b{suffix}"),
            a_ip: "198.32.1.1".to_owned(),
            b_ip: "198.32.1.2".to_owned(),
            a_cidr: "198.32.1.1/30".to_owned(),
            b_cidr: "198.32.1.2/30".to_owned(),
        },
        UnderlayLink {
            a: 2,
            b: 3,
            a_if: format!("cld23a{suffix}"),
            b_if: format!("cld23b{suffix}"),
            a_ip: "198.32.2.1".to_owned(),
            b_ip: "198.32.2.2".to_owned(),
            a_cidr: "198.32.2.1/30".to_owned(),
            b_cidr: "198.32.2.2/30".to_owned(),
        },
    ];
    for link in &links {
        let a_name = nodes[link.a - 1].name;
        let b_name = nodes[link.b - 1].name;
        nodes[link.a - 1].bind_addresses.push(link.a_ip.clone());
        nodes[link.b - 1].bind_addresses.push(link.b_ip.clone());
        nodes[link.a - 1]
            .neighbor_addresses
            .push((b_name, link.b_ip.clone()));
        nodes[link.b - 1]
            .neighbor_addresses
            .push((a_name, link.a_ip.clone()));
    }
    nodes[0]
        .neighbor_addresses
        .push(("gamma", links[1].b_ip.clone()));
    nodes[2]
        .neighbor_addresses
        .push(("alpha", links[0].a_ip.clone()));

    let private_keys = (0..nodes.len())
        .map(|_| RsaPrivateKey::new(&mut OsRng, 2048))
        .collect::<Result<Vec<_>, _>>()?;
    let public_keys = private_keys
        .iter()
        .map(RsaPublicKey::from)
        .collect::<Vec<_>>();

    let mut cleanup = NetnsCleanup::new(workspace.path().to_path_buf());
    for (index, node) in nodes.iter().enumerate() {
        cleanup.add_namespace(node.namespace.clone());
        create_legacy_multihop_node_config(
            workspace.path(),
            node,
            &nodes,
            &private_keys[index],
            &public_keys,
        )?;
    }
    for node in &nodes {
        if !try_ip(&["netns", "add", &node.namespace]) {
            eprintln!(
                "skipping C tincctl/Rust tincd legacy dynamic relay dump interop test: cannot create network namespaces"
            );
            return Ok(());
        }
    }
    for link in &links {
        create_legacy_multihop_underlay_link(&nodes, link)?;
    }
    run_ip(&[
        "-n",
        &nodes[0].namespace,
        "route",
        "add",
        "unreachable",
        &links[1].b_ip,
    ])?;
    run_ip(&[
        "-n",
        &nodes[2].namespace,
        "route",
        "add",
        "unreachable",
        &links[0].a_ip,
    ])?;

    for node in &nodes {
        cleanup.spawn(
            node.name,
            &workspace.path().join(node.name),
            &node.namespace,
            &workspace.path().join(format!("{}.log", node.name)),
        )?;
    }
    for node in &nodes {
        wait_for_pidfile(&workspace.path().join(node.name).join("pid"), &cleanup)?;
        wait_for_control_socket(
            &workspace.path().join(node.name).join("pid.socket"),
            &cleanup,
        )?;
        wait_for_link(&node.namespace, node.interface, &cleanup)?;
    }

    wait_for_node_route_via(
        &workspace.path().join("alpha"),
        "gamma",
        "beta",
        "gamma",
        false,
        &cleanup,
    )?;
    wait_for_ping(&nodes[0].namespace, nodes[2].tunnel_ip, &cleanup)?;
    wait_for_ping(&nodes[2].namespace, nodes[0].tunnel_ip, &cleanup)?;

    let alpha_confdir = workspace.path().join("alpha");
    let nodes_dump = run_c_tinc(
        c_tinc,
        &nodes[0].namespace,
        &alpha_confdir,
        &["dump", "nodes"],
    )?;
    assert_c_dump_node_has_status_words(&nodes_dump, "alpha", &["reachable"])?;
    assert_c_dump_node_lacks_status_words(&nodes_dump, "alpha", &["sptps"])?;
    assert_c_dump_node_has_status_words(
        &nodes_dump,
        "beta",
        &["validkey", "validkey_in", "reachable"],
    )?;
    assert_c_dump_node_lacks_status_words(&nodes_dump, "beta", &["sptps"])?;
    assert_c_dump_node_has_status_words(
        &nodes_dump,
        "gamma",
        &["validkey", "validkey_in", "reachable"],
    )?;
    assert_c_dump_node_lacks_status_words(&nodes_dump, "gamma", &["indirect", "sptps"])?;
    assert_c_dump_node_has_route(&nodes_dump, "beta", "beta", "beta", 1)?;
    assert_c_dump_node_has_route(&nodes_dump, "gamma", "beta", "gamma", 2)?;
    assert!(
        c_dump_node_line(&nodes_dump, "gamma")?
            .contains("198.32.2.2 port 18233 cipher 427 digest 672 maclength 4 compression 0 "),
        "C tinc dump nodes did not expose Rust legacy dynamic relay crypto/address fields for gamma:\n{nodes_dump}\n{}",
        cleanup.logs()
    );

    let edges = run_c_tinc(
        c_tinc,
        &nodes[0].namespace,
        &alpha_confdir,
        &["dump", "edges"],
    )?;
    assert!(
        edges.contains("alpha to beta at 198.32.1.2 port 18232")
            && edges.contains("gamma to beta at 198.32.2.1 port 18232"),
        "C tinc dump edges did not parse Rust legacy dynamic relay edge endpoints:\n{edges}\n{}",
        cleanup.logs()
    );

    let subnets = run_c_tinc(
        c_tinc,
        &nodes[0].namespace,
        &alpha_confdir,
        &["dump", "subnets"],
    )?;
    assert!(
        subnets.contains("10.119.1.0/24 owner alpha")
            && subnets.contains("10.119.2.0/24 owner beta")
            && subnets.contains("10.119.3.0/24 owner gamma"),
        "C tinc dump subnets did not parse Rust legacy dynamic relay subnet owners:\n{subnets}\n{}",
        cleanup.logs()
    );

    let info = run_c_tinc(
        c_tinc,
        &nodes[0].namespace,
        &alpha_confdir,
        &["info", "gamma"],
    )?;
    assert!(
        info.lines().any(|line| line.starts_with("Status:")
            && line.contains("validkey")
            && line.contains("reachable")
            && !line.contains("indirect")
            && !line.contains("sptps"))
            && (info.contains("Reachability: none, forwarded via beta")
                || info.contains("Reachability: directly with TCP")
                || info.contains("Reachability: directly with UDP")
                || info.contains("Reachability: unknown"))
            && info.contains("Subnets:      10.119.3.0/24"),
        "C tinc info gamma did not interpret Rust legacy dynamic relay topology like tinc:\n{info}\n{}",
        cleanup.logs()
    );

    for node in &nodes {
        let stop = run_rust_tincctl(&[
            "tinc",
            "--config",
            workspace.path().join(node.name).to_str().unwrap(),
            "stop",
        ])
        .map_err(|error| {
            format!(
                "Rust tincctl stop against Rust legacy dynamic relay {} failed after C dump status test: {error}\n{}",
                node.name,
                cleanup.logs()
            )
        })?;
        assert!(stop.is_empty(), "unexpected stop output: {stop}");
        wait_for_child_exit(&mut cleanup, node.name)?;
    }

    Ok(())
}

fn run_c_rust_two_node_legacy_minor_one_upgrade_interop(
    c_tincd: &Path,
    rust_connects_to_c: bool,
) -> Result<(), Box<dyn Error>> {
    let workspace = TempWorkspace::new(if rust_connects_to_c {
        "tinc-rust-c-legacy-minor1-rust-connects"
    } else {
        "tinc-rust-c-legacy-minor1-c-connects"
    })?;
    let suffix = unique_suffix();
    let ns_alpha = format!(
        "tinc-minor1-a-{}-{suffix}",
        if rust_connects_to_c { "r" } else { "c" }
    );
    let ns_beta = format!(
        "tinc-minor1-b-{}-{suffix}",
        if rust_connects_to_c { "c" } else { "r" }
    );
    let veth_alpha = format!("m1a{suffix}");
    let veth_beta = format!("m1b{suffix}");
    let alpha_port = if rust_connects_to_c { 17555 } else { 17557 };
    let beta_port = if rust_connects_to_c { 17556 } else { 17558 };
    let alpha_rsa = RsaPrivateKey::new(&mut OsRng, 2048)?;
    let beta_rsa = RsaPrivateKey::new(&mut OsRng, 2048)?;
    let alpha_rsa_public = RsaPublicKey::from(&alpha_rsa);
    let beta_rsa_public = RsaPublicKey::from(&beta_rsa);
    let alpha_key = key(31);
    let beta_key = key(32);
    let mut cleanup = NetnsCleanup::new(workspace.path().to_path_buf());
    cleanup.add_namespace(ns_alpha.clone());
    cleanup.add_namespace(ns_beta.clone());

    create_legacy_upgrade_node_config(
        &workspace.path().join("alpha"),
        LegacyUpgradeNodeConfig {
            name: "alpha",
            peer: "beta",
            port: alpha_port,
            bind_address: "192.0.2.31",
            peer_address: "192.0.2.32",
            peer_port: beta_port,
            interface: "tun-alpha",
            tunnel_address: "10.103.1.1/24",
            subnet: "10.103.1.0/24",
            peer_subnet: "10.103.2.0/24",
            connect_to_peer: rust_connects_to_c,
            seed: 31,
            private_key: &alpha_rsa,
            public_key: &alpha_rsa_public,
            peer_public_key: &beta_rsa_public,
        },
    )?;
    create_legacy_upgrade_node_config(
        &workspace.path().join("beta"),
        LegacyUpgradeNodeConfig {
            name: "beta",
            peer: "alpha",
            port: beta_port,
            bind_address: "192.0.2.32",
            peer_address: "192.0.2.31",
            peer_port: alpha_port,
            interface: "tun-beta",
            tunnel_address: "10.103.2.1/24",
            subnet: "10.103.2.0/24",
            peer_subnet: "10.103.1.0/24",
            connect_to_peer: !rust_connects_to_c,
            seed: 32,
            private_key: &beta_rsa,
            public_key: &beta_rsa_public,
            peer_public_key: &alpha_rsa_public,
        },
    )?;

    if !try_ip(&["netns", "add", &ns_alpha]) || !try_ip(&["netns", "add", &ns_beta]) {
        eprintln!(
            "skipping C/Rust legacy minor-1 netns interop test: cannot create network namespaces"
        );
        return Ok(());
    }

    run_ip(&[
        "link",
        "add",
        &veth_alpha,
        "type",
        "veth",
        "peer",
        "name",
        &veth_beta,
    ])?;
    run_ip(&["link", "set", &veth_alpha, "netns", &ns_alpha])?;
    run_ip(&["link", "set", &veth_beta, "netns", &ns_beta])?;
    run_ip(&["-n", &ns_alpha, "link", "set", "lo", "up"])?;
    run_ip(&["-n", &ns_beta, "link", "set", "lo", "up"])?;
    run_ip(&[
        "-n",
        &ns_alpha,
        "addr",
        "add",
        "192.0.2.31/24",
        "dev",
        &veth_alpha,
    ])?;
    run_ip(&[
        "-n",
        &ns_beta,
        "addr",
        "add",
        "192.0.2.32/24",
        "dev",
        &veth_beta,
    ])?;
    run_ip(&["-n", &ns_alpha, "link", "set", &veth_alpha, "up"])?;
    run_ip(&["-n", &ns_beta, "link", "set", &veth_beta, "up"])?;

    let (alpha_binary, beta_binary) = if rust_connects_to_c {
        (Path::new(TINCD), c_tincd)
    } else {
        (c_tincd, Path::new(TINCD))
    };

    cleanup.spawn_with_binary(
        "alpha",
        alpha_binary,
        &workspace.path().join("alpha"),
        &ns_alpha,
        &workspace.path().join("alpha.log"),
    )?;
    cleanup.spawn_with_binary(
        "beta",
        beta_binary,
        &workspace.path().join("beta"),
        &ns_beta,
        &workspace.path().join("beta.log"),
    )?;

    wait_for_link(&ns_alpha, "tun-alpha", &cleanup)?;
    wait_for_link(&ns_beta, "tun-beta", &cleanup)?;
    wait_for_host_ed25519_key(
        &workspace.path().join("alpha").join("hosts").join("beta"),
        &beta_key.public_key().to_base64(),
        &cleanup,
    )?;
    wait_for_host_ed25519_key(
        &workspace.path().join("beta").join("hosts").join("alpha"),
        &alpha_key.public_key().to_base64(),
        &cleanup,
    )?;
    wait_for_ping(&ns_alpha, "10.103.2.1", &cleanup)?;
    wait_for_ping(&ns_beta, "10.103.1.1", &cleanup)?;
    let alpha_confdir = workspace.path().join("alpha");
    let beta_confdir = workspace.path().join("beta");
    let alpha_log = workspace.path().join("alpha.log");
    let beta_log = workspace.path().join("beta.log");
    wait_for_legacy_minor_one_termreq_reconnect_like_tinc(
        &alpha_confdir,
        &beta_confdir,
        if rust_connects_to_c {
            &beta_log
        } else {
            &alpha_log
        },
        if rust_connects_to_c { "beta" } else { "alpha" },
        &cleanup,
    )?;

    Ok(())
}

fn run_c_rust_strict_subnet_forward_interop(c_tincd: &Path) -> Result<(), Box<dyn Error>> {
    let workspace = TempWorkspace::new("tinc-rust-c-strict-subnet-forward")?;
    let suffix = unique_suffix();
    let extra_subnet = "10.107.99.0/24";
    let mut nodes = (1..=3)
        .map(|index| LinkNode {
            name: match index {
                1 => "alpha",
                2 => "beta",
                3 => "gamma",
                _ => unreachable!(),
            }
            .to_owned(),
            namespace: format!("tinc-strict-subnet-{index}-{suffix}"),
            port: 17910 + index as u16,
            device_type: "tun",
            mode: None,
            interface: match index {
                1 => "tun-ss-a",
                2 => "tun-ss-b",
                3 => "tun-ss-g",
                _ => unreachable!(),
            }
            .to_owned(),
            tunnel_ip: format!("10.107.{index}.1"),
            tunnel_cidr: format!("10.107.{index}.1/24"),
            subnet: format!("10.107.{index}.0/24"),
            route: "10.107.0.0/16".to_owned(),
            tunnel_ipv6: None,
            tunnel_ipv6_cidr: None,
            subnet_ipv6: None,
            route_ipv6: None,
            static_mac_subnet: None,
            seed: 90 + index as u8,
            bind_addresses: Vec::new(),
            neighbor_addresses: Vec::new(),
            connect_to: Vec::new(),
            indirect_peers: Vec::new(),
        })
        .collect::<Vec<_>>();
    let links = vec![
        UnderlayLink {
            a: 1,
            b: 2,
            a_if: format!("ss12a{suffix}"),
            b_if: format!("ss12b{suffix}"),
            a_ip: "198.24.1.1".to_owned(),
            b_ip: "198.24.1.2".to_owned(),
            a_cidr: "198.24.1.1/30".to_owned(),
            b_cidr: "198.24.1.2/30".to_owned(),
        },
        UnderlayLink {
            a: 1,
            b: 3,
            a_if: format!("ss13a{suffix}"),
            b_if: format!("ss13b{suffix}"),
            a_ip: "198.24.2.1".to_owned(),
            b_ip: "198.24.2.2".to_owned(),
            a_cidr: "198.24.2.1/30".to_owned(),
            b_cidr: "198.24.2.2/30".to_owned(),
        },
    ];
    apply_links_to_nodes(&mut nodes, &links);
    apply_connect_to(&mut nodes, &[(2, 1), (3, 1)]);

    let mut cleanup = NetnsCleanup::new(workspace.path().to_path_buf());
    for node in &nodes {
        cleanup.add_namespace(node.namespace.clone());
    }
    create_strict_subnet_node_config(workspace.path(), &nodes[0], &nodes, true, None, &[])?;
    create_strict_subnet_node_config(
        workspace.path(),
        &nodes[1],
        &nodes,
        true,
        Some(extra_subnet),
        &[],
    )?;
    create_strict_subnet_node_config(workspace.path(), &nodes[2], &nodes, false, None, &[])?;

    for node in &nodes {
        if !try_ip(&["netns", "add", &node.namespace]) {
            eprintln!(
                "skipping C/Rust strict subnet netns interop test: cannot create network namespaces"
            );
            return Ok(());
        }
    }
    for link in &links {
        create_netns_underlay_link(&nodes, link)?;
    }

    let binaries: [&Path; 3] = [Path::new(TINCD), c_tincd, Path::new(TINCD)];
    for (index, node) in nodes.iter().enumerate() {
        cleanup.spawn_with_binary(
            &node.name,
            binaries[index],
            &workspace.path().join(&node.name),
            &node.namespace,
            &workspace.path().join(format!("{}.log", node.name)),
        )?;
    }

    for node in &nodes {
        wait_for_pidfile(&workspace.path().join(&node.name).join("pid"), &cleanup)?;
        wait_for_control_socket(
            &workspace.path().join(&node.name).join("pid.socket"),
            &cleanup,
        )?;
        wait_for_link(&node.namespace, &node.interface, &cleanup)?;
    }

    wait_for_ping(&nodes[0].namespace, &nodes[1].tunnel_ip, &cleanup)?;
    wait_for_ping(&nodes[2].namespace, &nodes[0].tunnel_ip, &cleanup)?;

    let alpha_confdir = workspace.path().join("alpha");
    let gamma_confdir = workspace.path().join("gamma");
    let alpha_subnets = run_rust_tincctl(&[
        "tinc",
        "--config",
        alpha_confdir.to_str().unwrap(),
        "dump",
        "subnets",
    ])?;
    assert!(
        alpha_subnets.contains("10.107.2.0/24 owner beta"),
        "Rust strict alpha did not keep configured beta subnet:\n{alpha_subnets}\n{}",
        cleanup.logs()
    );
    assert!(
        !alpha_subnets.contains("10.107.99.0/24 owner beta"),
        "Rust strict alpha learned unauthorized C beta subnet despite StrictSubnets:\n{alpha_subnets}\n{}",
        cleanup.logs()
    );

    let gamma_subnets = run_rust_tincctl(&[
        "tinc",
        "--config",
        gamma_confdir.to_str().unwrap(),
        "dump",
        "subnets",
    ])?;
    assert!(
        gamma_subnets.contains("10.107.99.0/24 owner beta"),
        "Rust non-strict gamma did not receive forwarded C beta extra subnet via Rust strict alpha:\n{gamma_subnets}\n{}",
        cleanup.logs()
    );

    Ok(())
}

fn run_c_rust_tunnel_server_interop(
    c_tincd: &Path,
    rust_server: bool,
) -> Result<(), Box<dyn Error>> {
    run_c_rust_tunnel_server_interop_with_options(
        c_tincd,
        rust_server,
        false,
        false,
        false,
        false,
        None,
    )
}

fn run_c_rust_tunnel_server_interop_with_options(
    c_tincd: &Path,
    rust_server: bool,
    exercise_client_restart: bool,
    exercise_underlay_udp_loss: bool,
    exercise_meta_timeout_loss: bool,
    check_udp_discovery_pmtu: bool,
    no_plaintext_capture: Option<NoPlaintextCapture>,
) -> Result<(), Box<dyn Error>> {
    let workspace = TempWorkspace::new(if rust_server {
        if exercise_client_restart {
            "tinc-rust-c-tunnel-server-restart-rust-server"
        } else if exercise_underlay_udp_loss {
            "tinc-rust-c-tunnel-server-udp-loss-rust-server"
        } else if exercise_meta_timeout_loss {
            "tinc-rust-c-tunnel-server-meta-timeout-rust-server"
        } else if check_udp_discovery_pmtu {
            "tinc-rust-c-tunnel-server-udp-pmtu-rust-server"
        } else if no_plaintext_capture == Some(NoPlaintextCapture::Udp) {
            "tinc-rust-c-tunnel-server-no-plain-rust-server"
        } else {
            "tinc-rust-c-tunnel-server-rust-server"
        }
    } else if exercise_client_restart {
        "tinc-rust-c-tunnel-server-restart-c-server"
    } else if exercise_underlay_udp_loss {
        "tinc-rust-c-tunnel-server-udp-loss-c-server"
    } else if exercise_meta_timeout_loss {
        "tinc-rust-c-tunnel-server-meta-timeout-c-server"
    } else if check_udp_discovery_pmtu {
        "tinc-rust-c-tunnel-server-udp-pmtu-c-server"
    } else if no_plaintext_capture == Some(NoPlaintextCapture::Udp) {
        "tinc-rust-c-tunnel-server-no-plain-c-server"
    } else {
        "tinc-rust-c-tunnel-server-c-server"
    })?;
    let suffix = unique_suffix();
    let mut nodes = (1..=3)
        .map(|index| LinkNode {
            name: match index {
                1 => "alpha",
                2 => "beta",
                3 => "gamma",
                _ => unreachable!(),
            }
            .to_owned(),
            namespace: format!("tinc-tunnel-server-{index}-{suffix}"),
            port: 18010 + index as u16,
            device_type: "tun",
            mode: None,
            interface: match index {
                1 => "tun-ts-a",
                2 => "tun-ts-b",
                3 => "tun-ts-g",
                _ => unreachable!(),
            }
            .to_owned(),
            tunnel_ip: format!("10.108.{index}.1"),
            tunnel_cidr: format!("10.108.{index}.1/24"),
            subnet: format!("10.108.{index}.0/24"),
            route: "10.108.0.0/16".to_owned(),
            tunnel_ipv6: None,
            tunnel_ipv6_cidr: None,
            subnet_ipv6: None,
            route_ipv6: None,
            static_mac_subnet: None,
            seed: 100 + index as u8,
            bind_addresses: Vec::new(),
            neighbor_addresses: Vec::new(),
            connect_to: Vec::new(),
            indirect_peers: Vec::new(),
        })
        .collect::<Vec<_>>();
    let links = vec![
        UnderlayLink {
            a: 1,
            b: 2,
            a_if: format!("ts12a{suffix}"),
            b_if: format!("ts12b{suffix}"),
            a_ip: "198.25.1.1".to_owned(),
            b_ip: "198.25.1.2".to_owned(),
            a_cidr: "198.25.1.1/30".to_owned(),
            b_cidr: "198.25.1.2/30".to_owned(),
        },
        UnderlayLink {
            a: 1,
            b: 3,
            a_if: format!("ts13a{suffix}"),
            b_if: format!("ts13b{suffix}"),
            a_ip: "198.25.2.1".to_owned(),
            b_ip: "198.25.2.2".to_owned(),
            a_cidr: "198.25.2.1/30".to_owned(),
            b_cidr: "198.25.2.2/30".to_owned(),
        },
    ];
    apply_links_to_nodes(&mut nodes, &links);
    apply_connect_to(&mut nodes, &[(2, 1), (3, 1)]);

    let mut cleanup = NetnsCleanup::new(workspace.path().to_path_buf());
    for node in &nodes {
        cleanup.add_namespace(node.namespace.clone());
    }
    for (index, node) in nodes.iter().enumerate() {
        create_tunnel_server_node_config(workspace.path(), node, &nodes, index == 0)?;
    }

    for node in &nodes {
        if !try_ip(&["netns", "add", &node.namespace]) {
            eprintln!(
                "skipping C/Rust tunnel server netns interop test: cannot create network namespaces"
            );
            return Ok(());
        }
    }
    for link in &links {
        create_netns_underlay_link(&nodes, link)?;
    }

    let binaries: [&Path; 3] = if rust_server {
        [Path::new(TINCD), c_tincd, c_tincd]
    } else {
        [c_tincd, Path::new(TINCD), Path::new(TINCD)]
    };
    let quick_no_ping = exercise_client_restart && no_plaintext_capture.is_some();
    for (index, node) in nodes.iter().enumerate() {
        cleanup.spawn_with_binary(
            &node.name,
            binaries[index],
            &workspace.path().join(&node.name),
            &node.namespace,
            &workspace.path().join(format!("{}.log", node.name)),
        )?;
    }

    for node in &nodes {
        wait_for_pidfile(&workspace.path().join(&node.name).join("pid"), &cleanup)?;
        wait_for_control_socket(
            &workspace.path().join(&node.name).join("pid.socket"),
            &cleanup,
        )?;
        wait_for_link(&node.namespace, &node.interface, &cleanup)?;
    }

    wait_for_ping(&nodes[0].namespace, &nodes[1].tunnel_ip, &cleanup)?;
    wait_for_ping(&nodes[1].namespace, &nodes[0].tunnel_ip, &cleanup)?;
    wait_for_ping(&nodes[0].namespace, &nodes[2].tunnel_ip, &cleanup)?;
    wait_for_ping(&nodes[2].namespace, &nodes[0].tunnel_ip, &cleanup)?;
    wait_for_no_ping_maybe_quick(
        &nodes[1].namespace,
        &nodes[2].tunnel_ip,
        &cleanup,
        quick_no_ping,
    )?;
    wait_for_no_ping_maybe_quick(
        &nodes[2].namespace,
        &nodes[1].tunnel_ip,
        &cleanup,
        quick_no_ping,
    )?;
    wait_for_modern_tunnel_server_raw_topology_like_tinc(
        &workspace,
        &nodes,
        &links,
        "initially",
        &cleanup,
    )?;

    let beta_confdir = workspace.path().join("beta");
    let beta_subnets = run_rust_tincctl(&[
        "tinc",
        "--config",
        beta_confdir.to_str().unwrap(),
        "dump",
        "subnets",
    ])?;
    assert!(
        beta_subnets.contains("10.108.1.0/24 owner alpha"),
        "TunnelServer client beta did not learn alpha's server subnet:\n{beta_subnets}\n{}",
        cleanup.logs()
    );
    assert!(
        !beta_subnets.contains("10.108.3.0/24 owner gamma"),
        "TunnelServer client beta learned gamma's client subnet despite C send_everything() tunnel-server isolation:\n{beta_subnets}\n{}",
        cleanup.logs()
    );

    let beta_edges = run_rust_tincctl(&[
        "tinc",
        "--config",
        beta_confdir.to_str().unwrap(),
        "dump",
        "edges",
    ])?;
    assert!(
        beta_edges.contains("alpha to beta"),
        "TunnelServer client beta did not learn its direct server edge:\n{beta_edges}\n{}",
        cleanup.logs()
    );
    assert!(
        !beta_edges.contains("alpha to gamma") && !beta_edges.contains("gamma to alpha"),
        "TunnelServer client beta learned gamma's direct edge despite C ack_h() tunnel-server per-client edge sync:\n{beta_edges}\n{}",
        cleanup.logs()
    );

    if check_udp_discovery_pmtu {
        assert_tunnel_server_udp_discovery_pmtu_like_tinc(
            &workspace,
            &cleanup,
            "alpha",
            "beta",
            &nodes[0].namespace,
            &nodes[1].tunnel_ip,
            &nodes[1].namespace,
            &nodes[0].tunnel_ip,
        )?;
        assert_tunnel_server_udp_discovery_pmtu_like_tinc(
            &workspace,
            &cleanup,
            "alpha",
            "gamma",
            &nodes[0].namespace,
            &nodes[2].tunnel_ip,
            &nodes[2].namespace,
            &nodes[0].tunnel_ip,
        )?;
        wait_for_modern_tunnel_server_raw_topology_like_tinc(
            &workspace,
            &nodes,
            &links,
            "after UDP discovery/PMTU",
            &cleanup,
        )?;
    }

    if let Some(capture) = no_plaintext_capture {
        assert_underlay_ping_payload_not_plaintext(
            &nodes[0].namespace,
            &links[0].a_if,
            &nodes[1].tunnel_ip,
            "c/rust tunnel-server beta UDP data path",
            capture,
            &cleanup,
        )?;
        assert_underlay_ping_payload_not_plaintext(
            &nodes[0].namespace,
            &links[1].a_if,
            &nodes[2].tunnel_ip,
            "c/rust tunnel-server gamma UDP data path",
            capture,
            &cleanup,
        )?;
    }

    if exercise_underlay_udp_loss {
        run_ip(&[
            "-n",
            &nodes[0].namespace,
            "link",
            "set",
            &links[0].a_if,
            "down",
        ])?;
        run_ip(&[
            "-n",
            &nodes[1].namespace,
            "link",
            "set",
            &links[0].b_if,
            "down",
        ])?;
        expect_single_ping_failure(&nodes[0].namespace, &nodes[1].tunnel_ip, &cleanup)?;
        expect_single_ping_failure(&nodes[1].namespace, &nodes[0].tunnel_ip, &cleanup)?;

        run_ip(&[
            "-n",
            &nodes[0].namespace,
            "link",
            "set",
            &links[0].a_if,
            "up",
        ])?;
        run_ip(&[
            "-n",
            &nodes[1].namespace,
            "link",
            "set",
            &links[0].b_if,
            "up",
        ])?;

        wait_for_ping(&nodes[0].namespace, &nodes[1].tunnel_ip, &cleanup)?;
        wait_for_ping(&nodes[1].namespace, &nodes[0].tunnel_ip, &cleanup)?;
        wait_for_ping(&nodes[0].namespace, &nodes[2].tunnel_ip, &cleanup)?;
        wait_for_ping(&nodes[2].namespace, &nodes[0].tunnel_ip, &cleanup)?;
        wait_for_no_ping(&nodes[1].namespace, &nodes[2].tunnel_ip, &cleanup)?;
        wait_for_no_ping(&nodes[2].namespace, &nodes[1].tunnel_ip, &cleanup)?;
        wait_for_modern_tunnel_server_raw_topology_like_tinc(
            &workspace,
            &nodes,
            &links,
            "after underlay UDP loss",
            &cleanup,
        )?;

        let beta_subnets_after_udp_loss = run_rust_tincctl(&[
            "tinc",
            "--config",
            beta_confdir.to_str().unwrap(),
            "dump",
            "subnets",
        ])?;
        assert!(
            beta_subnets_after_udp_loss.contains("10.108.1.0/24 owner alpha"),
            "TunnelServer client beta lost alpha's server subnet after underlay UDP loss recovery:\n{beta_subnets_after_udp_loss}\n{}",
            cleanup.logs()
        );
        assert!(
            !beta_subnets_after_udp_loss.contains("10.108.3.0/24 owner gamma"),
            "TunnelServer client beta learned gamma's client subnet after underlay UDP loss despite C tunnel-server isolation:\n{beta_subnets_after_udp_loss}\n{}",
            cleanup.logs()
        );

        let beta_edges_after_udp_loss = run_rust_tincctl(&[
            "tinc",
            "--config",
            beta_confdir.to_str().unwrap(),
            "dump",
            "edges",
        ])?;
        assert!(
            beta_edges_after_udp_loss.contains("alpha to beta"),
            "TunnelServer client beta lost its direct server edge after underlay UDP loss recovery:\n{beta_edges_after_udp_loss}\n{}",
            cleanup.logs()
        );
        assert!(
            !beta_edges_after_udp_loss.contains("alpha to gamma")
                && !beta_edges_after_udp_loss.contains("gamma to alpha"),
            "TunnelServer client beta learned gamma's direct edge after underlay UDP loss despite C tunnel-server isolation:\n{beta_edges_after_udp_loss}\n{}",
            cleanup.logs()
        );
    }

    if exercise_meta_timeout_loss {
        run_ip(&[
            "-n",
            &nodes[0].namespace,
            "link",
            "set",
            &links[0].a_if,
            "down",
        ])?;
        run_ip(&[
            "-n",
            &nodes[1].namespace,
            "link",
            "set",
            &links[0].b_if,
            "down",
        ])?;

        wait_for_node_status(&workspace.path().join("alpha"), "beta", 0, 1 << 4, &cleanup)?;
        wait_for_node_status(&workspace.path().join("beta"), "alpha", 0, 1 << 4, &cleanup)?;
        wait_for_no_ping(&nodes[0].namespace, &nodes[1].tunnel_ip, &cleanup)?;
        wait_for_no_ping(&nodes[1].namespace, &nodes[0].tunnel_ip, &cleanup)?;
        wait_for_ping(&nodes[0].namespace, &nodes[2].tunnel_ip, &cleanup)?;
        wait_for_ping(&nodes[2].namespace, &nodes[0].tunnel_ip, &cleanup)?;

        run_ip(&[
            "-n",
            &nodes[0].namespace,
            "link",
            "set",
            &links[0].a_if,
            "up",
        ])?;
        run_ip(&[
            "-n",
            &nodes[1].namespace,
            "link",
            "set",
            &links[0].b_if,
            "up",
        ])?;

        wait_for_ping(&nodes[0].namespace, &nodes[1].tunnel_ip, &cleanup)?;
        wait_for_ping(&nodes[1].namespace, &nodes[0].tunnel_ip, &cleanup)?;
        wait_for_ping(&nodes[0].namespace, &nodes[2].tunnel_ip, &cleanup)?;
        wait_for_ping(&nodes[2].namespace, &nodes[0].tunnel_ip, &cleanup)?;
        wait_for_no_ping(&nodes[1].namespace, &nodes[2].tunnel_ip, &cleanup)?;
        wait_for_no_ping(&nodes[2].namespace, &nodes[1].tunnel_ip, &cleanup)?;
        wait_for_node_status(&workspace.path().join("alpha"), "beta", 1 << 4, 0, &cleanup)?;
        wait_for_node_status(&workspace.path().join("beta"), "alpha", 1 << 4, 0, &cleanup)?;
        wait_for_modern_tunnel_server_raw_topology_like_tinc(
            &workspace,
            &nodes,
            &links,
            "after meta timeout reconnect",
            &cleanup,
        )?;

        let beta_subnets_after_timeout = run_rust_tincctl(&[
            "tinc",
            "--config",
            beta_confdir.to_str().unwrap(),
            "dump",
            "subnets",
        ])?;
        assert!(
            beta_subnets_after_timeout.contains("10.108.1.0/24 owner alpha"),
            "TunnelServer client beta did not relearn alpha's server subnet after meta timeout reconnect:\n{beta_subnets_after_timeout}\n{}",
            cleanup.logs()
        );
        assert!(
            !beta_subnets_after_timeout.contains("10.108.3.0/24 owner gamma"),
            "TunnelServer client beta learned gamma's client subnet after meta timeout reconnect despite C tunnel-server isolation:\n{beta_subnets_after_timeout}\n{}",
            cleanup.logs()
        );

        let beta_edges_after_timeout = run_rust_tincctl(&[
            "tinc",
            "--config",
            beta_confdir.to_str().unwrap(),
            "dump",
            "edges",
        ])?;
        assert!(
            beta_edges_after_timeout.contains("alpha to beta"),
            "TunnelServer client beta did not relearn its direct server edge after meta timeout reconnect:\n{beta_edges_after_timeout}\n{}",
            cleanup.logs()
        );
        assert!(
            !beta_edges_after_timeout.contains("alpha to gamma")
                && !beta_edges_after_timeout.contains("gamma to alpha"),
            "TunnelServer client beta learned gamma's direct edge after meta timeout reconnect despite C tunnel-server isolation:\n{beta_edges_after_timeout}\n{}",
            cleanup.logs()
        );
    }

    if exercise_client_restart {
        cleanup.kill_child("beta")?;
        wait_for_no_ping_maybe_quick(
            &nodes[0].namespace,
            &nodes[1].tunnel_ip,
            &cleanup,
            quick_no_ping,
        )?;
        cleanup.spawn_with_binary(
            "beta",
            binaries[1],
            &workspace.path().join("beta"),
            &nodes[1].namespace,
            &workspace.path().join("beta.log"),
        )?;
        wait_for_pidfile(&workspace.path().join("beta").join("pid"), &cleanup)?;
        wait_for_control_socket(&workspace.path().join("beta").join("pid.socket"), &cleanup)?;
        wait_for_link(&nodes[1].namespace, &nodes[1].interface, &cleanup)?;

        wait_for_ping(&nodes[0].namespace, &nodes[1].tunnel_ip, &cleanup)?;
        wait_for_ping(&nodes[1].namespace, &nodes[0].tunnel_ip, &cleanup)?;
        wait_for_ping(&nodes[0].namespace, &nodes[2].tunnel_ip, &cleanup)?;
        wait_for_ping(&nodes[2].namespace, &nodes[0].tunnel_ip, &cleanup)?;
        wait_for_no_ping_maybe_quick(
            &nodes[1].namespace,
            &nodes[2].tunnel_ip,
            &cleanup,
            quick_no_ping,
        )?;
        wait_for_no_ping_maybe_quick(
            &nodes[2].namespace,
            &nodes[1].tunnel_ip,
            &cleanup,
            quick_no_ping,
        )?;
        wait_for_modern_tunnel_server_raw_topology_like_tinc(
            &workspace,
            &nodes,
            &links,
            "after restart",
            &cleanup,
        )?;

        let beta_subnets_after_restart = run_rust_tincctl(&[
            "tinc",
            "--config",
            beta_confdir.to_str().unwrap(),
            "dump",
            "subnets",
        ])?;
        assert!(
            beta_subnets_after_restart.contains("10.108.1.0/24 owner alpha"),
            "TunnelServer client beta did not relearn alpha's server subnet after restart:\n{beta_subnets_after_restart}\n{}",
            cleanup.logs()
        );
        assert!(
            !beta_subnets_after_restart.contains("10.108.3.0/24 owner gamma"),
            "TunnelServer client beta learned gamma's client subnet after restart despite C send_everything() tunnel-server isolation:\n{beta_subnets_after_restart}\n{}",
            cleanup.logs()
        );

        let beta_edges_after_restart = run_rust_tincctl(&[
            "tinc",
            "--config",
            beta_confdir.to_str().unwrap(),
            "dump",
            "edges",
        ])?;
        assert!(
            beta_edges_after_restart.contains("alpha to beta"),
            "TunnelServer client beta did not relearn its direct server edge after restart:\n{beta_edges_after_restart}\n{}",
            cleanup.logs()
        );
        assert!(
            !beta_edges_after_restart.contains("alpha to gamma")
                && !beta_edges_after_restart.contains("gamma to alpha"),
            "TunnelServer client beta learned gamma's direct edge after restart despite C ack_h() tunnel-server per-client edge sync:\n{beta_edges_after_restart}\n{}",
            cleanup.logs()
        );

        if let Some(capture) = no_plaintext_capture {
            assert_underlay_ping_payload_not_plaintext(
                &nodes[0].namespace,
                &links[0].a_if,
                &nodes[1].tunnel_ip,
                "c/rust tunnel-server beta UDP data path after client restart",
                capture,
                &cleanup,
            )?;
            assert_underlay_ping_payload_not_plaintext(
                &nodes[0].namespace,
                &links[1].a_if,
                &nodes[2].tunnel_ip,
                "c/rust tunnel-server gamma UDP data path after peer client restart",
                capture,
                &cleanup,
            )?;
            wait_for_no_ping_maybe_quick(
                &nodes[1].namespace,
                &nodes[2].tunnel_ip,
                &cleanup,
                quick_no_ping,
            )?;
            wait_for_no_ping_maybe_quick(
                &nodes[2].namespace,
                &nodes[1].tunnel_ip,
                &cleanup,
                quick_no_ping,
            )?;
        }
    }

    Ok(())
}

fn run_c_rust_legacy_tunnel_server_interop(
    c_tincd: &Path,
    rust_server: bool,
) -> Result<(), Box<dyn Error>> {
    run_c_rust_legacy_tunnel_server_interop_with_options(
        c_tincd,
        rust_server,
        false,
        false,
        false,
        false,
        false,
        None,
    )
}

fn run_c_rust_legacy_tunnel_server_interop_with_options(
    c_tincd: &Path,
    rust_server: bool,
    exercise_client_restart: bool,
    exercise_underlay_udp_loss: bool,
    exercise_meta_timeout_loss: bool,
    exercise_rekey: bool,
    check_udp_discovery_pmtu: bool,
    no_plaintext_capture: Option<NoPlaintextCapture>,
) -> Result<(), Box<dyn Error>> {
    let workspace = TempWorkspace::new(if rust_server {
        if exercise_client_restart {
            "tinc-rust-c-legacy-tunnel-server-restart-rust-server"
        } else if exercise_underlay_udp_loss {
            "tinc-rust-c-legacy-tunnel-server-udp-loss-rust-server"
        } else if exercise_meta_timeout_loss {
            "tinc-rust-c-legacy-tunnel-server-meta-timeout-rust-server"
        } else if exercise_rekey {
            "tinc-rust-c-legacy-tunnel-server-rekey-rust-server"
        } else if check_udp_discovery_pmtu {
            "tinc-rust-c-legacy-tunnel-server-udp-pmtu-rust-server"
        } else if no_plaintext_capture == Some(NoPlaintextCapture::Udp) {
            "tinc-rust-c-legacy-tunnel-server-no-plain-rust-server"
        } else {
            "tinc-rust-c-legacy-tunnel-server-rust-server"
        }
    } else if exercise_client_restart {
        "tinc-rust-c-legacy-tunnel-server-restart-c-server"
    } else if exercise_underlay_udp_loss {
        "tinc-rust-c-legacy-tunnel-server-udp-loss-c-server"
    } else if exercise_meta_timeout_loss {
        "tinc-rust-c-legacy-tunnel-server-meta-timeout-c-server"
    } else if exercise_rekey {
        "tinc-rust-c-legacy-tunnel-server-rekey-c-server"
    } else if check_udp_discovery_pmtu {
        "tinc-rust-c-legacy-tunnel-server-udp-pmtu-c-server"
    } else if no_plaintext_capture == Some(NoPlaintextCapture::Udp) {
        "tinc-rust-c-legacy-tunnel-server-no-plain-c-server"
    } else {
        "tinc-rust-c-legacy-tunnel-server-c-server"
    })?;
    let suffix = unique_suffix();
    let mut nodes = vec![
        LegacyMultihopNode {
            name: "alpha",
            namespace: format!(
                "tinc-leg-ts-a-{}-{suffix}",
                if rust_server { "r" } else { "c" }
            ),
            port: if rust_server { 18311 } else { 18321 },
            interface: "tun-lts-a",
            tunnel_address: "10.112.1.1/24",
            tunnel_ip: "10.112.1.1",
            subnet: "10.112.1.0/24",
            route: "10.112.0.0/16",
            bind_addresses: Vec::new(),
            neighbor_addresses: Vec::new(),
            connect_to: Vec::new(),
            indirect_peers: Vec::new(),
        },
        LegacyMultihopNode {
            name: "beta",
            namespace: format!(
                "tinc-leg-ts-b-{}-{suffix}",
                if rust_server { "c" } else { "r" }
            ),
            port: if rust_server { 18312 } else { 18322 },
            interface: "tun-lts-b",
            tunnel_address: "10.112.2.1/24",
            tunnel_ip: "10.112.2.1",
            subnet: "10.112.2.0/24",
            route: "10.112.0.0/16",
            bind_addresses: Vec::new(),
            neighbor_addresses: Vec::new(),
            connect_to: vec!["alpha"],
            indirect_peers: Vec::new(),
        },
        LegacyMultihopNode {
            name: "gamma",
            namespace: format!(
                "tinc-leg-ts-g-{}-{suffix}",
                if rust_server { "c" } else { "r" }
            ),
            port: if rust_server { 18313 } else { 18323 },
            interface: "tun-lts-g",
            tunnel_address: "10.112.3.1/24",
            tunnel_ip: "10.112.3.1",
            subnet: "10.112.3.0/24",
            route: "10.112.0.0/16",
            bind_addresses: Vec::new(),
            neighbor_addresses: Vec::new(),
            connect_to: vec!["alpha"],
            indirect_peers: Vec::new(),
        },
    ];
    let links = vec![
        UnderlayLink {
            a: 1,
            b: 2,
            a_if: format!("lts12a{suffix}"),
            b_if: format!("lts12b{suffix}"),
            a_ip: "198.28.1.1".to_owned(),
            b_ip: "198.28.1.2".to_owned(),
            a_cidr: "198.28.1.1/30".to_owned(),
            b_cidr: "198.28.1.2/30".to_owned(),
        },
        UnderlayLink {
            a: 1,
            b: 3,
            a_if: format!("lts13a{suffix}"),
            b_if: format!("lts13b{suffix}"),
            a_ip: "198.28.2.1".to_owned(),
            b_ip: "198.28.2.2".to_owned(),
            a_cidr: "198.28.2.1/30".to_owned(),
            b_cidr: "198.28.2.2/30".to_owned(),
        },
    ];
    for link in &links {
        let a_name = nodes[link.a - 1].name;
        let b_name = nodes[link.b - 1].name;
        nodes[link.a - 1].bind_addresses.push(link.a_ip.clone());
        nodes[link.b - 1].bind_addresses.push(link.b_ip.clone());
        nodes[link.a - 1]
            .neighbor_addresses
            .push((b_name, link.b_ip.clone()));
        nodes[link.b - 1]
            .neighbor_addresses
            .push((a_name, link.a_ip.clone()));
    }

    let private_keys = (0..nodes.len())
        .map(|_| RsaPrivateKey::new(&mut OsRng, 2048))
        .collect::<Result<Vec<_>, _>>()?;
    let public_keys = private_keys
        .iter()
        .map(RsaPublicKey::from)
        .collect::<Vec<_>>();

    let mut cleanup = NetnsCleanup::new(workspace.path().to_path_buf());
    for (index, node) in nodes.iter().enumerate() {
        cleanup.add_namespace(node.namespace.clone());
        create_legacy_multihop_node_config_with_tunnel_server(
            workspace.path(),
            node,
            &nodes,
            &private_keys[index],
            &public_keys,
            index == 0,
            exercise_rekey.then_some(1),
        )?;
    }
    for node in &nodes {
        if !try_ip(&["netns", "add", &node.namespace]) {
            eprintln!(
                "skipping C/Rust legacy tunnel server netns interop test: cannot create network namespaces"
            );
            return Ok(());
        }
    }
    for link in &links {
        create_legacy_multihop_underlay_link(&nodes, link)?;
    }

    let binaries: [&Path; 3] = if rust_server {
        [Path::new(TINCD), c_tincd, c_tincd]
    } else {
        [c_tincd, Path::new(TINCD), Path::new(TINCD)]
    };
    let quick_no_ping = exercise_client_restart && no_plaintext_capture.is_some();
    for (index, node) in nodes.iter().enumerate() {
        cleanup.spawn_with_binary(
            node.name,
            binaries[index],
            &workspace.path().join(node.name),
            &node.namespace,
            &workspace.path().join(format!("{}.log", node.name)),
        )?;
    }

    for node in &nodes {
        wait_for_pidfile(&workspace.path().join(node.name).join("pid"), &cleanup)?;
        wait_for_control_socket(
            &workspace.path().join(node.name).join("pid.socket"),
            &cleanup,
        )?;
        wait_for_link(&node.namespace, node.interface, &cleanup)?;
    }

    wait_for_ping(&nodes[0].namespace, nodes[1].tunnel_ip, &cleanup)?;
    wait_for_ping(&nodes[1].namespace, nodes[0].tunnel_ip, &cleanup)?;
    wait_for_ping(&nodes[0].namespace, nodes[2].tunnel_ip, &cleanup)?;
    wait_for_ping(&nodes[2].namespace, nodes[0].tunnel_ip, &cleanup)?;
    wait_for_no_ping_maybe_quick(
        &nodes[1].namespace,
        nodes[2].tunnel_ip,
        &cleanup,
        quick_no_ping,
    )?;
    wait_for_no_ping_maybe_quick(
        &nodes[2].namespace,
        nodes[1].tunnel_ip,
        &cleanup,
        quick_no_ping,
    )?;
    wait_for_legacy_tunnel_server_raw_topology_like_tinc(
        &workspace,
        &nodes,
        &links,
        if exercise_rekey {
            "initially with rekey enabled"
        } else {
            "initially"
        },
        &cleanup,
    )?;

    assert_legacy_tunnel_server_client_view_isolated(&workspace, &cleanup, "initially")?;

    if check_udp_discovery_pmtu {
        assert_tunnel_server_udp_discovery_pmtu_like_tinc(
            &workspace,
            &cleanup,
            "alpha",
            "beta",
            &nodes[0].namespace,
            nodes[1].tunnel_ip,
            &nodes[1].namespace,
            nodes[0].tunnel_ip,
        )?;
        assert_tunnel_server_udp_discovery_pmtu_like_tinc(
            &workspace,
            &cleanup,
            "alpha",
            "gamma",
            &nodes[0].namespace,
            nodes[2].tunnel_ip,
            &nodes[2].namespace,
            nodes[0].tunnel_ip,
        )?;
        wait_for_legacy_tunnel_server_raw_topology_like_tinc(
            &workspace,
            &nodes,
            &links,
            "after UDP discovery/PMTU",
            &cleanup,
        )?;
    }

    if let Some(capture) = no_plaintext_capture {
        assert_underlay_ping_payload_not_plaintext(
            &nodes[0].namespace,
            &links[0].a_if,
            nodes[1].tunnel_ip,
            "c/rust legacy tunnel-server beta UDP data path",
            capture,
            &cleanup,
        )?;
        assert_underlay_ping_payload_not_plaintext(
            &nodes[0].namespace,
            &links[1].a_if,
            nodes[2].tunnel_ip,
            "c/rust legacy tunnel-server gamma UDP data path",
            capture,
            &cleanup,
        )?;
    }

    if exercise_underlay_udp_loss {
        run_ip(&[
            "-n",
            &nodes[0].namespace,
            "link",
            "set",
            &links[0].a_if,
            "down",
        ])?;
        run_ip(&[
            "-n",
            &nodes[1].namespace,
            "link",
            "set",
            &links[0].b_if,
            "down",
        ])?;
        expect_single_ping_failure(&nodes[0].namespace, nodes[1].tunnel_ip, &cleanup)?;
        expect_single_ping_failure(&nodes[1].namespace, nodes[0].tunnel_ip, &cleanup)?;

        run_ip(&[
            "-n",
            &nodes[0].namespace,
            "link",
            "set",
            &links[0].a_if,
            "up",
        ])?;
        run_ip(&[
            "-n",
            &nodes[1].namespace,
            "link",
            "set",
            &links[0].b_if,
            "up",
        ])?;

        wait_for_ping(&nodes[0].namespace, nodes[1].tunnel_ip, &cleanup)?;
        wait_for_ping(&nodes[1].namespace, nodes[0].tunnel_ip, &cleanup)?;
        wait_for_ping(&nodes[0].namespace, nodes[2].tunnel_ip, &cleanup)?;
        wait_for_ping(&nodes[2].namespace, nodes[0].tunnel_ip, &cleanup)?;
        wait_for_no_ping(&nodes[1].namespace, nodes[2].tunnel_ip, &cleanup)?;
        wait_for_no_ping(&nodes[2].namespace, nodes[1].tunnel_ip, &cleanup)?;
        wait_for_legacy_tunnel_server_raw_topology_like_tinc(
            &workspace,
            &nodes,
            &links,
            "after underlay UDP loss",
            &cleanup,
        )?;

        assert_legacy_tunnel_server_client_view_isolated(
            &workspace,
            &cleanup,
            "after underlay UDP loss",
        )?;
    }

    if exercise_meta_timeout_loss {
        run_ip(&[
            "-n",
            &nodes[0].namespace,
            "link",
            "set",
            &links[0].a_if,
            "down",
        ])?;
        run_ip(&[
            "-n",
            &nodes[1].namespace,
            "link",
            "set",
            &links[0].b_if,
            "down",
        ])?;

        wait_for_node_status(&workspace.path().join("alpha"), "beta", 0, 1 << 4, &cleanup)?;
        wait_for_node_status(&workspace.path().join("beta"), "alpha", 0, 1 << 4, &cleanup)?;
        wait_for_no_ping(&nodes[0].namespace, nodes[1].tunnel_ip, &cleanup)?;
        wait_for_no_ping(&nodes[1].namespace, nodes[0].tunnel_ip, &cleanup)?;
        wait_for_ping(&nodes[0].namespace, nodes[2].tunnel_ip, &cleanup)?;
        wait_for_ping(&nodes[2].namespace, nodes[0].tunnel_ip, &cleanup)?;

        run_ip(&[
            "-n",
            &nodes[0].namespace,
            "link",
            "set",
            &links[0].a_if,
            "up",
        ])?;
        run_ip(&[
            "-n",
            &nodes[1].namespace,
            "link",
            "set",
            &links[0].b_if,
            "up",
        ])?;

        wait_for_ping(&nodes[0].namespace, nodes[1].tunnel_ip, &cleanup)?;
        wait_for_ping(&nodes[1].namespace, nodes[0].tunnel_ip, &cleanup)?;
        wait_for_ping(&nodes[0].namespace, nodes[2].tunnel_ip, &cleanup)?;
        wait_for_ping(&nodes[2].namespace, nodes[0].tunnel_ip, &cleanup)?;
        wait_for_no_ping(&nodes[1].namespace, nodes[2].tunnel_ip, &cleanup)?;
        wait_for_no_ping(&nodes[2].namespace, nodes[1].tunnel_ip, &cleanup)?;
        wait_for_node_status(&workspace.path().join("alpha"), "beta", 1 << 4, 0, &cleanup)?;
        wait_for_node_status(&workspace.path().join("beta"), "alpha", 1 << 4, 0, &cleanup)?;
        wait_for_legacy_tunnel_server_raw_topology_like_tinc(
            &workspace,
            &nodes,
            &links,
            "after meta timeout reconnect",
            &cleanup,
        )?;

        assert_legacy_tunnel_server_client_view_isolated(
            &workspace,
            &cleanup,
            "after meta timeout reconnect",
        )?;
    }

    if exercise_client_restart {
        cleanup.kill_child("beta")?;
        wait_for_no_ping_maybe_quick(
            &nodes[0].namespace,
            nodes[1].tunnel_ip,
            &cleanup,
            quick_no_ping,
        )?;
        cleanup.spawn_with_binary(
            "beta",
            binaries[1],
            &workspace.path().join("beta"),
            &nodes[1].namespace,
            &workspace.path().join("beta.log"),
        )?;
        wait_for_pidfile(&workspace.path().join("beta").join("pid"), &cleanup)?;
        wait_for_control_socket(&workspace.path().join("beta").join("pid.socket"), &cleanup)?;
        wait_for_link(&nodes[1].namespace, nodes[1].interface, &cleanup)?;

        wait_for_ping(&nodes[0].namespace, nodes[1].tunnel_ip, &cleanup)?;
        wait_for_ping(&nodes[1].namespace, nodes[0].tunnel_ip, &cleanup)?;
        wait_for_ping(&nodes[0].namespace, nodes[2].tunnel_ip, &cleanup)?;
        wait_for_ping(&nodes[2].namespace, nodes[0].tunnel_ip, &cleanup)?;
        wait_for_no_ping_maybe_quick(
            &nodes[1].namespace,
            nodes[2].tunnel_ip,
            &cleanup,
            quick_no_ping,
        )?;
        wait_for_no_ping_maybe_quick(
            &nodes[2].namespace,
            nodes[1].tunnel_ip,
            &cleanup,
            quick_no_ping,
        )?;
        wait_for_legacy_tunnel_server_raw_topology_like_tinc(
            &workspace,
            &nodes,
            &links,
            "after restart",
            &cleanup,
        )?;

        assert_legacy_tunnel_server_client_view_isolated(&workspace, &cleanup, "after restart")?;

        if let Some(capture) = no_plaintext_capture {
            assert_underlay_ping_payload_not_plaintext(
                &nodes[0].namespace,
                &links[0].a_if,
                nodes[1].tunnel_ip,
                "c/rust legacy tunnel-server beta UDP data path after client restart",
                capture,
                &cleanup,
            )?;
            assert_underlay_ping_payload_not_plaintext(
                &nodes[0].namespace,
                &links[1].a_if,
                nodes[2].tunnel_ip,
                "c/rust legacy tunnel-server gamma UDP data path after peer client restart",
                capture,
                &cleanup,
            )?;
            wait_for_no_ping_maybe_quick(
                &nodes[1].namespace,
                nodes[2].tunnel_ip,
                &cleanup,
                quick_no_ping,
            )?;
            wait_for_no_ping_maybe_quick(
                &nodes[2].namespace,
                nodes[1].tunnel_ip,
                &cleanup,
                quick_no_ping,
            )?;
        }
    }

    if exercise_rekey {
        wait_for_legacy_rekey(&cleanup)?;
        wait_for_ping(&nodes[0].namespace, nodes[1].tunnel_ip, &cleanup)?;
        wait_for_ping(&nodes[1].namespace, nodes[0].tunnel_ip, &cleanup)?;
        wait_for_ping(&nodes[0].namespace, nodes[2].tunnel_ip, &cleanup)?;
        wait_for_ping(&nodes[2].namespace, nodes[0].tunnel_ip, &cleanup)?;
        wait_for_no_ping(&nodes[1].namespace, nodes[2].tunnel_ip, &cleanup)?;
        wait_for_no_ping(&nodes[2].namespace, nodes[1].tunnel_ip, &cleanup)?;
        wait_for_legacy_tunnel_server_raw_topology_like_tinc(
            &workspace,
            &nodes,
            &links,
            "after rekey",
            &cleanup,
        )?;

        assert_legacy_tunnel_server_client_view_isolated(&workspace, &cleanup, "after rekey")?;
    }

    Ok(())
}

fn assert_legacy_tunnel_server_client_view_isolated(
    workspace: &TempWorkspace,
    cleanup: &NetnsCleanup,
    phase: &str,
) -> Result<(), Box<dyn Error>> {
    let beta_confdir = workspace.path().join("beta");
    let beta_nodes = run_rust_tincctl(&[
        "tinc",
        "--config",
        beta_confdir.to_str().unwrap(),
        "dump",
        "nodes",
    ])?;
    assert!(
        rust_dump_node_status(&beta_nodes, "alpha").is_some_and(|status| {
            status & (1 << 1) != 0 && status & (1 << 4) != 0 && status & (1 << 6) == 0
        }),
        "Legacy tunnel-server client beta did not see server alpha as reachable non-SPTPS with valid outgoing key {phase}:\n{beta_nodes}\n{}",
        cleanup.logs()
    );
    assert!(
        rust_dump_node_status(&beta_nodes, "gamma")
            .is_none_or(|status| { status & ((1 << 1) | (1 << 4) | (1 << 6)) == 0 }),
        "Legacy tunnel-server client beta learned client gamma as reachable/valid/SPTPS despite C tunnel-server isolation {phase}:\n{beta_nodes}\n{}",
        cleanup.logs()
    );

    let beta_subnets = run_rust_tincctl(&[
        "tinc",
        "--config",
        beta_confdir.to_str().unwrap(),
        "dump",
        "subnets",
    ])?;
    assert!(
        beta_subnets.contains("10.112.1.0/24 owner alpha"),
        "Legacy tunnel-server client beta did not learn alpha's server subnet {phase}:\n{beta_subnets}\n{}",
        cleanup.logs()
    );
    assert!(
        !beta_subnets.contains("10.112.3.0/24 owner gamma"),
        "Legacy tunnel-server client beta learned gamma's client subnet despite C send_everything() isolation {phase}:\n{beta_subnets}\n{}",
        cleanup.logs()
    );

    let beta_edges = run_rust_tincctl(&[
        "tinc",
        "--config",
        beta_confdir.to_str().unwrap(),
        "dump",
        "edges",
    ])?;
    assert!(
        beta_edges.contains("alpha to beta") || beta_edges.contains("beta to alpha"),
        "Legacy tunnel-server client beta did not learn its direct server edge {phase}:\n{beta_edges}\n{}",
        cleanup.logs()
    );
    assert!(
        !beta_edges.contains("alpha to gamma")
            && !beta_edges.contains("gamma to alpha")
            && !beta_edges.contains("beta to gamma")
            && !beta_edges.contains("gamma to beta"),
        "Legacy tunnel-server client beta learned another client edge despite C tunnel-server isolation {phase}:\n{beta_edges}\n{}",
        cleanup.logs()
    );

    Ok(())
}

fn run_c_rust_three_node_req_pubkey_interop(c_tincd: &Path) -> Result<(), Box<dyn Error>> {
    let workspace = TempWorkspace::new("tinc-rust-c-req-pubkey-relay")?;
    let suffix = unique_suffix();
    let mut nodes = vec![
        ReqPubkeyNode {
            name: "alpha",
            namespace: format!("tinc-reqpk-a-{suffix}"),
            port: 17661,
            interface: "tun-rpk-a",
            tunnel_address: "10.104.1.1/24",
            tunnel_ip: "10.104.1.1",
            subnet: "10.104.1.0/24",
            route: "10.104.0.0/16",
            seed: 61,
            bind_addresses: Vec::new(),
            neighbor_addresses: Vec::new(),
            connect_to: vec!["beta"],
        },
        ReqPubkeyNode {
            name: "beta",
            namespace: format!("tinc-reqpk-b-{suffix}"),
            port: 17662,
            interface: "tun-rpk-b",
            tunnel_address: "10.104.2.1/24",
            tunnel_ip: "10.104.2.1",
            subnet: "10.104.2.0/24",
            route: "10.104.0.0/16",
            seed: 62,
            bind_addresses: Vec::new(),
            neighbor_addresses: Vec::new(),
            connect_to: Vec::new(),
        },
        ReqPubkeyNode {
            name: "gamma",
            namespace: format!("tinc-reqpk-g-{suffix}"),
            port: 17663,
            interface: "tun-rpk-g",
            tunnel_address: "10.104.3.1/24",
            tunnel_ip: "10.104.3.1",
            subnet: "10.104.3.0/24",
            route: "10.104.0.0/16",
            seed: 63,
            bind_addresses: Vec::new(),
            neighbor_addresses: Vec::new(),
            connect_to: vec!["beta"],
        },
    ];
    let links = vec![
        UnderlayLink {
            a: 1,
            b: 2,
            a_if: format!("rpk12a{suffix}"),
            b_if: format!("rpk12b{suffix}"),
            a_ip: "198.21.1.1".to_owned(),
            b_ip: "198.21.1.2".to_owned(),
            a_cidr: "198.21.1.1/30".to_owned(),
            b_cidr: "198.21.1.2/30".to_owned(),
        },
        UnderlayLink {
            a: 2,
            b: 3,
            a_if: format!("rpk23a{suffix}"),
            b_if: format!("rpk23b{suffix}"),
            a_ip: "198.21.2.1".to_owned(),
            b_ip: "198.21.2.2".to_owned(),
            a_cidr: "198.21.2.1/30".to_owned(),
            b_cidr: "198.21.2.2/30".to_owned(),
        },
    ];

    for link in &links {
        let a_name = nodes[link.a - 1].name;
        let b_name = nodes[link.b - 1].name;
        nodes[link.a - 1].bind_addresses.push(link.a_ip.clone());
        nodes[link.b - 1].bind_addresses.push(link.b_ip.clone());
        nodes[link.a - 1]
            .neighbor_addresses
            .push((b_name, link.b_ip.clone()));
        nodes[link.b - 1]
            .neighbor_addresses
            .push((a_name, link.a_ip.clone()));
    }

    let mut cleanup = NetnsCleanup::new(workspace.path().to_path_buf());
    for node in &nodes {
        cleanup.add_namespace(node.namespace.clone());
    }

    create_req_pubkey_node_config(workspace.path(), &nodes[0], &nodes, &["gamma"])?;
    create_req_pubkey_node_config(workspace.path(), &nodes[1], &nodes, &[])?;
    create_req_pubkey_node_config(workspace.path(), &nodes[2], &nodes, &["alpha"])?;

    for node in &nodes {
        if !try_ip(&["netns", "add", &node.namespace]) {
            eprintln!(
                "skipping C/Rust REQ_PUBKEY netns interop test: cannot create network namespaces"
            );
            return Ok(());
        }
    }
    create_req_pubkey_underlay_link(&nodes, &links[0])?;
    create_req_pubkey_underlay_link(&nodes, &links[1])?;

    cleanup.spawn_with_binary(
        "alpha",
        Path::new(TINCD),
        &workspace.path().join("alpha"),
        &nodes[0].namespace,
        &workspace.path().join("alpha.log"),
    )?;
    cleanup.spawn_with_binary(
        "beta",
        Path::new(TINCD),
        &workspace.path().join("beta"),
        &nodes[1].namespace,
        &workspace.path().join("beta.log"),
    )?;
    cleanup.spawn_with_binary(
        "gamma",
        c_tincd,
        &workspace.path().join("gamma"),
        &nodes[2].namespace,
        &workspace.path().join("gamma.log"),
    )?;

    for node in &nodes {
        wait_for_link(&node.namespace, node.interface, &cleanup)?;
    }
    wait_for_req_pubkey_exchange(
        &nodes[0].namespace,
        nodes[2].tunnel_ip,
        &workspace.path().join("alpha").join("hosts").join("gamma"),
        &key(nodes[2].seed).public_key().to_base64(),
        &workspace.path().join("gamma").join("hosts").join("alpha"),
        &key(nodes[0].seed).public_key().to_base64(),
        &cleanup,
    )?;
    wait_for_ping(&nodes[0].namespace, nodes[2].tunnel_ip, &cleanup)?;
    wait_for_ping(&nodes[2].namespace, nodes[0].tunnel_ip, &cleanup)?;

    Ok(())
}

fn spawn_tincd(confdir: &Path, netns: &str, log: &Path) -> Result<Child, Box<dyn Error>> {
    spawn_tincd_with_binary(Path::new(TINCD), confdir, netns, log)
}

fn spawn_tincd_with_binary(
    binary: &Path,
    confdir: &Path,
    netns: &str,
    log: &Path,
) -> Result<Child, Box<dyn Error>> {
    let stdout = File::create(log)?;
    let stderr = stdout.try_clone()?;
    Ok(Command::new("ip")
        .args(["netns", "exec", netns])
        .arg(binary)
        .args(["-D", "-c"])
        .arg(confdir)
        .arg(format!("--pidfile={}", confdir.join("pid").display()))
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()?)
}

fn assert_tincd_startup_fails_with_compression_unavailable(
    binary: &Path,
    confdir: &Path,
    netns: &str,
    label: &str,
    compression_name: &str,
) -> Result<(), Box<dyn Error>> {
    let output = Command::new("ip")
        .args(["netns", "exec", netns])
        .arg(binary)
        .args(["-D", "-c"])
        .arg(confdir)
        .arg(format!("--pidfile={}", confdir.join("pid").display()))
        .output()?;
    assert!(
        !output.status.success(),
        "{label} unexpectedly accepted legacy Compression without comp_{}",
        compression_name.to_ascii_lowercase()
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let unavailable = format!("{compression_name} compression is unavailable on this node.");
    assert!(
        combined.contains("Bogus compression level!") && combined.contains(&unavailable),
        "{label} did not reject unavailable {} with C net_setup.c messages\nstatus: {:?}\noutput:\n{combined}",
        compression_name.to_ascii_lowercase(),
        output.status.code()
    );
    Ok(())
}

fn wait_for_link(netns: &str, link: &str, cleanup: &NetnsCleanup) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + Duration::from_secs(8);
    while Instant::now() < deadline {
        cleanup.ensure_children_alive()?;
        if try_ip(&["-n", netns, "link", "show", link]) {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }

    Err(format!("timed out waiting for {link}\n{}", cleanup.logs()).into())
}

fn wait_for_pidfile(pidfile: &Path, cleanup: &NetnsCleanup) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + Duration::from_secs(8);
    while Instant::now() < deadline {
        cleanup.ensure_children_alive()?;
        if pidfile.exists() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }

    Err(format!(
        "timed out waiting for pidfile {}\n{}",
        pidfile.display(),
        cleanup.logs()
    )
    .into())
}

fn wait_for_control_socket(socket: &Path, cleanup: &NetnsCleanup) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + Duration::from_secs(8);
    while Instant::now() < deadline {
        cleanup.ensure_children_alive()?;
        if socket.exists() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }

    Err(format!(
        "timed out waiting for control socket {}\n{}",
        socket.display(),
        cleanup.logs()
    )
    .into())
}

fn wait_for_path_removed(
    path: &Path,
    cleanup: &NetnsCleanup,
    label: &str,
) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + Duration::from_secs(8);
    while Instant::now() < deadline {
        if !path.exists() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }

    Err(format!(
        "{label}: {} still exists\n{}",
        path.display(),
        cleanup.logs()
    )
    .into())
}

fn wait_for_direct_dump_parity(
    alpha_confdir: &Path,
    beta_confdir: &Path,
    cleanup: &NetnsCleanup,
) -> Result<DirectRawDumps, Box<dyn Error>> {
    let deadline = Instant::now() + Duration::from_secs(8);
    let mut last_error = String::new();

    while Instant::now() < deadline {
        cleanup.ensure_children_alive()?;
        match direct_raw_dumps(alpha_confdir, beta_confdir) {
            Ok(dumps) => return Ok(dumps),
            Err(error) => {
                last_error = error.to_string();
                thread::sleep(Duration::from_millis(200));
            }
        }
    }

    Err(format!(
        "timed out waiting for direct two-node raw dump parity\nlast error:\n{last_error}\n{}",
        cleanup.diagnostics()
    )
    .into())
}

fn send_signal_from_pidfile(
    netns: &str,
    pidfile: &Path,
    signal: &str,
) -> Result<(), Box<dyn Error>> {
    let pid = fs::read_to_string(pidfile)?;
    let Some(pid) = pid.split_whitespace().next() else {
        return Err("malformed pidfile".into());
    };
    let output = Command::new("ip")
        .args(["netns", "exec", netns, "kill", &format!("-{signal}"), pid])
        .output()?;
    if output.status.success() {
        return Ok(());
    }

    Err(format!(
        "kill -{signal} {pid} in netns {netns} failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
    .into())
}

fn wait_for_legacy_rekey(cleanup: &NetnsCleanup) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + Duration::from_secs(40);
    while Instant::now() < deadline {
        cleanup.ensure_children_alive()?;
        let logs = cleanup.logs();
        if logs.matches("Expiring symmetric keys").count() >= 2 {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }

    Err(format!(
        "timed out waiting for C/Rust legacy KeyExpire rekey\n{}",
        cleanup.logs()
    )
    .into())
}

fn assert_legacy_rekey_window_tcp_payload_not_plaintext(
    source_netns: &str,
    target_address: &str,
    label: &str,
    cleanup: &NetnsCleanup,
) -> Result<(), Box<dyn Error>> {
    cleanup.ensure_children_alive()?;
    let payload = format!("rky-{}", unique_suffix());
    let pcap = cleanup.workspace.join(format!(
        "underlay-rekey-tcp-{}-{}.pcap",
        source_netns,
        unique_suffix()
    ));
    let mut tcpdump = Command::new("ip")
        .args([
            "netns",
            "exec",
            source_netns,
            "tcpdump",
            "-i",
            "any",
            "-U",
            "-s",
            "0",
            "-c",
            "80",
            "-w",
        ])
        .arg(&pcap)
        .arg("tcp")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    thread::sleep(Duration::from_millis(300));
    let deadline = Instant::now() + Duration::from_secs(45);
    let mut saw_rekey = false;
    let mut last_ping = String::new();

    while Instant::now() < deadline {
        cleanup.ensure_children_alive()?;
        let ping = Command::new("ip")
            .args([
                "netns",
                "exec",
                source_netns,
                "ping",
                if target_address.contains(':') {
                    "-6"
                } else {
                    "-4"
                },
                "-c",
                "1",
                "-W",
                "1",
                "-p",
                &hex_payload(&payload),
                target_address,
            ])
            .output()?;
        last_ping = format!(
            "{}{}",
            String::from_utf8_lossy(&ping.stdout),
            String::from_utf8_lossy(&ping.stderr)
        );

        if cleanup.logs().matches("Expiring symmetric keys").count() >= 2 {
            saw_rekey = true;
            break;
        }
        thread::sleep(Duration::from_millis(250));
    }

    stop_tcpdump(&mut tcpdump);

    if !saw_rekey {
        return Err(format!(
            "timed out waiting for {label} to observe legacy KeyExpire while probing the TCP fallback window\nlast ping:\n{last_ping}\n{}",
            cleanup.logs()
        )
        .into());
    }

    let capture_bytes = fs::read(&pcap).map_err(|error| {
        format!(
            "{label} could not read underlay TCP tcpdump capture {}: {error}\n{}",
            pcap.display(),
            cleanup.logs()
        )
    })?;
    assert!(
        !contains_subslice(&capture_bytes, payload.as_bytes()),
        "{label} leaked the inner ping payload in TCP underlay capture {} during legacy KeyExpire recovery\n{}",
        pcap.display(),
        cleanup.logs()
    );

    Ok(())
}

fn assert_legacy_direct_key_state_like_tinc(
    confdir: &Path,
    peer: &str,
    label: &str,
) -> Result<(), Box<dyn Error>> {
    assert_legacy_direct_key_state_with_crypto_like_tinc(
        confdir,
        peer,
        LegacyCryptoConfig::default(),
        label,
    )
}

fn assert_legacy_direct_key_state_with_crypto_like_tinc(
    confdir: &Path,
    peer: &str,
    legacy_crypto: LegacyCryptoConfig<'_>,
    label: &str,
) -> Result<(), Box<dyn Error>> {
    let dumps = RawControlDumps::read(confdir)?;
    let node = raw_node(&dumps, peer)?;
    assert_status_has(
        node,
        STATUS_VALIDKEY | STATUS_VALIDKEY_IN | STATUS_REACHABLE,
    )?;
    assert_status_lacks(node, STATUS_SPTPS | STATUS_INDIRECT)?;
    assert_eq!(
        legacy_crypto.expected_cipher, node.cipher,
        "{label}: legacy peer cipher mismatch after C send_ans_key()/ans_key_h(): {node:?}"
    );
    assert_eq!(
        legacy_crypto.expected_digest, node.digest,
        "{label}: legacy peer digest mismatch after C send_ans_key()/ans_key_h(): {node:?}"
    );
    assert_eq!(
        legacy_crypto.expected_mac_length, node.mac_length,
        "{label}: legacy peer MAC length mismatch after C send_ans_key()/ans_key_h(): {node:?}"
    );
    assert_eq!(
        legacy_crypto.expected_compression, node.compression,
        "{label}: legacy peer compression mismatch after C send_ans_key()/ans_key_h(): {node:?}"
    );
    Ok(())
}

fn wait_for_legacy_direct_rekey_key_state_like_tinc(
    confdir: &Path,
    peer: &str,
    source_netns: &str,
    peer_tunnel_ip: &str,
    label: &str,
    cleanup: &NetnsCleanup,
) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + Duration::from_secs(12);
    let mut last_error = String::new();

    while Instant::now() < deadline {
        cleanup.ensure_children_alive()?;

        let _ = Command::new("ip")
            .args(ping_args(source_netns, peer_tunnel_ip))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();

        match assert_legacy_direct_key_state_like_tinc(confdir, peer, label) {
            Ok(()) => return Ok(()),
            Err(error) => last_error = error.to_string(),
        }
        thread::sleep(Duration::from_millis(200));
    }

    Err(format!(
        "timed out waiting for {label} to restore C legacy KeyExpire key state for peer {peer}\n\
         last error: {last_error}\n{}",
        cleanup.diagnostics()
    )
    .into())
}

fn wait_for_legacy_meta_timeout_close(cleanup: &NetnsCleanup) -> Result<(), Box<dyn Error>> {
    wait_for_node_status(&cleanup.workspace.join("alpha"), "beta", 0, 1 << 4, cleanup)?;
    wait_for_node_status(&cleanup.workspace.join("beta"), "alpha", 0, 1 << 4, cleanup)?;
    Ok(())
}

fn wait_for_legacy_reconnect_after_timeout(cleanup: &NetnsCleanup) -> Result<(), Box<dyn Error>> {
    wait_for_node_status(
        &cleanup.workspace.join("alpha"),
        "beta",
        (1 << 1) | (1 << 4),
        0,
        cleanup,
    )?;
    wait_for_node_status(
        &cleanup.workspace.join("beta"),
        "alpha",
        (1 << 1) | (1 << 4),
        0,
        cleanup,
    )?;
    Ok(())
}

fn activate_fake_legacy_peer(
    stream: &mut TcpStream,
    fake_name: &str,
    daemon_name: &str,
    fake_private_key: &RsaPrivateKey,
    daemon_public_key: &RsaPublicKey,
    fake_port: u16,
) -> Result<LegacyMetaConnectionDriver, Box<dyn Error>> {
    let mut driver = LegacyMetaConnectionDriver::new(
        LegacyMetaAuth::new(
            fake_name,
            false,
            LegacyMetaPrivateKey::Pem(fake_private_key.clone()),
            daemon_public_key.clone(),
            fake_port.to_string(),
            0,
            0,
        )
        .with_forced_protocol_minor_zero(true)
        .with_protocol_minor(LEGACY_META_PROTOCOL_MINOR),
    );
    let mut buffer = [0_u8; 4096];
    let mut saw_activation = false;
    let deadline = Instant::now() + Duration::from_secs(8);

    while Instant::now() < deadline {
        match stream.read(&mut buffer) {
            Ok(0) => return Err("daemon closed fake legacy connection before activation".into()),
            Ok(read) => {
                let step = driver.receive_bytes(&buffer[..read])?;
                for chunk in step.outbound {
                    stream.write_all(&chunk)?;
                }
                stream.flush()?;
                for event in step.events {
                    if let tinc_runtime::meta::MetaConnectionEvent::Auth(
                        tinc_runtime::meta::MetaAuthEvent::Activated { peer, .. },
                    ) = event
                    {
                        if peer == daemon_name {
                            saw_activation = true;
                        }
                    }
                }
                if saw_activation && driver.auth().state() == LegacyMetaAuthState::Activated {
                    return Ok(driver);
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                thread::sleep(Duration::from_millis(50));
            }
            Err(error) => return Err(error.into()),
        }
    }

    Err(format!("timed out activating fake legacy peer {fake_name}").into())
}

fn connect_fake_legacy_peer_to_daemon(
    daemon: SocketAddr,
    fake_name: &str,
    daemon_name: &str,
    fake_private_key: &RsaPrivateKey,
    daemon_public_key: &RsaPublicKey,
    fake_port: u16,
    cleanup: &NetnsCleanup,
) -> Result<(TcpStream, LegacyMetaConnectionDriver), Box<dyn Error>> {
    let mut stream =
        connect_from_ipv4_addr(SocketAddr::new("192.0.2.72".parse()?, 0), daemon, cleanup)?;
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    stream.set_write_timeout(Some(Duration::from_secs(3)))?;
    let mut driver = LegacyMetaConnectionDriver::new(
        LegacyMetaAuth::new(
            fake_name,
            true,
            LegacyMetaPrivateKey::Pem(fake_private_key.clone()),
            daemon_public_key.clone(),
            fake_port.to_string(),
            0,
            0,
        )
        .with_forced_protocol_minor_zero(true)
        .with_protocol_minor(LEGACY_META_PROTOCOL_MINOR),
    );
    stream.write_all(&driver.initial_id_bytes())?;
    stream.flush()?;

    let mut buffer = [0_u8; 4096];
    let deadline = Instant::now() + Duration::from_secs(8);
    while Instant::now() < deadline {
        match stream.read(&mut buffer) {
            Ok(0) => {
                return Err(
                    "daemon closed incoming fake legacy connection before activation".into(),
                );
            }
            Ok(read) => {
                let step = driver.receive_bytes(&buffer[..read])?;
                for chunk in step.outbound {
                    stream.write_all(&chunk)?;
                }
                stream.flush()?;
                if step.events.iter().any(|event| {
                    matches!(
                        event,
                        tinc_runtime::meta::MetaConnectionEvent::Auth(
                            tinc_runtime::meta::MetaAuthEvent::Activated { peer, .. }
                        ) if peer == daemon_name
                    )
                }) && driver.auth().state() == LegacyMetaAuthState::Activated
                {
                    return Ok((stream, driver));
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                thread::sleep(Duration::from_millis(50));
            }
            Err(error) => return Err(error.into()),
        }
    }

    Err(format!("timed out activating incoming fake legacy peer {fake_name}").into())
}

fn connect_from_ipv4_addr(
    local: SocketAddr,
    remote: SocketAddr,
    cleanup: &NetnsCleanup,
) -> Result<TcpStream, Box<dyn Error>> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, libc::IPPROTO_TCP) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let result = (|| -> Result<TcpStream, Box<dyn Error>> {
        let (raw_local, local_len) = socket_addr_to_c_sockaddr(local)?;
        let bind_status = unsafe {
            libc::bind(
                fd,
                (&raw_local as *const libc::sockaddr_storage).cast(),
                local_len,
            )
        };
        if bind_status < 0 {
            return Err(format!(
                "could not bind fake legacy source socket to {local}: {}\n{}",
                std::io::Error::last_os_error(),
                cleanup.logs()
            )
            .into());
        }

        let (raw_remote, remote_len) = socket_addr_to_c_sockaddr(remote)?;
        let connect_status = unsafe {
            libc::connect(
                fd,
                (&raw_remote as *const libc::sockaddr_storage).cast(),
                remote_len,
            )
        };
        if connect_status < 0 {
            return Err(format!(
                "could not connect fake legacy source socket from {local} to {remote}: {}\n{}",
                std::io::Error::last_os_error(),
                cleanup.logs()
            )
            .into());
        }

        use std::os::fd::FromRawFd;
        Ok(unsafe { TcpStream::from_raw_fd(fd) })
    })();

    if result.is_err() {
        unsafe {
            libc::close(fd);
        }
    }
    result
}

fn socket_addr_to_c_sockaddr(
    address: SocketAddr,
) -> Result<(libc::sockaddr_storage, libc::socklen_t), Box<dyn Error>> {
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    match address {
        SocketAddr::V4(address) => {
            let raw = unsafe {
                &mut *(&mut storage as *mut libc::sockaddr_storage).cast::<libc::sockaddr_in>()
            };
            raw.sin_family = libc::AF_INET as libc::sa_family_t;
            raw.sin_port = address.port().to_be();
            raw.sin_addr = libc::in_addr {
                s_addr: u32::from_ne_bytes(address.ip().octets()),
            };
            Ok((
                storage,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            ))
        }
        SocketAddr::V6(address) => {
            let raw = unsafe {
                &mut *(&mut storage as *mut libc::sockaddr_storage).cast::<libc::sockaddr_in6>()
            };
            raw.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            raw.sin6_port = address.port().to_be();
            raw.sin6_flowinfo = address.flowinfo();
            raw.sin6_addr = libc::in6_addr {
                s6_addr: address.ip().octets(),
            };
            raw.sin6_scope_id = address.scope_id();
            Ok((
                storage,
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            ))
        }
    }
}

fn wait_for_fake_legacy_connection(
    listener: &TcpListener,
    cleanup: &NetnsCleanup,
) -> Result<TcpStream, Box<dyn Error>> {
    let deadline = Instant::now() + Duration::from_secs(8);

    while Instant::now() < deadline {
        cleanup.ensure_children_alive()?;
        match listener.accept() {
            Ok((stream, _)) => return Ok(stream),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(100));
            }
            Err(error) => return Err(error.into()),
        }
    }

    Err(format!(
        "timed out waiting for Rust daemon to connect to fake legacy peer\n{}",
        cleanup.logs()
    )
    .into())
}

fn activate_fake_legacy_beta_for_bad_ans_key(
    listener: &TcpListener,
    cleanup: &NetnsCleanup,
    confdir: &Path,
    beta_rsa: &RsaPrivateKey,
    alpha_rsa_public: &RsaPublicKey,
    beta_port: u16,
    alpha_port: u16,
) -> Result<(TcpStream, LegacyMetaConnectionDriver), Box<dyn Error>> {
    let mut fake_beta = wait_for_fake_legacy_connection(listener, cleanup)?;
    fake_beta.set_read_timeout(Some(Duration::from_secs(3)))?;
    fake_beta.set_write_timeout(Some(Duration::from_secs(3)))?;
    let mut driver = activate_fake_legacy_peer(
        &mut fake_beta,
        "beta",
        "alpha",
        beta_rsa,
        alpha_rsa_public,
        beta_port,
    )?;
    send_fake_legacy_add_edge(
        &mut fake_beta,
        &mut driver,
        "beta",
        "alpha",
        "192.0.2.31",
        alpha_port,
        "192.0.2.32",
        beta_port,
    )?;
    wait_for_node_status(confdir, "beta", 1 << 4, 1 << 1, cleanup)?;

    Ok((fake_beta, driver))
}

fn send_fake_legacy_add_edge(
    stream: &mut TcpStream,
    driver: &mut LegacyMetaConnectionDriver,
    from: &str,
    to: &str,
    address: &str,
    port: u16,
    local_address: &str,
    local_port: u16,
) -> Result<(), Box<dyn Error>> {
    static NONCE: AtomicU32 = AtomicU32::new(0xfeed_babe);

    let edge = Edge::new(from, to, 0)
        .with_options(OPTION_PMTU_DISCOVERY)
        .with_address(tinc_core::graph::EdgeEndpoint::new(
            address.to_owned(),
            port.to_string(),
        ))
        .with_local_address(tinc_core::graph::EdgeEndpoint::new(
            local_address.to_owned(),
            local_port.to_string(),
        ));
    let message = MetaMessage::AddEdge(AddEdgeMessage {
        nonce: NONCE.fetch_add(1, Ordering::Relaxed),
        address: address.to_owned(),
        port: port.to_string(),
        edge,
        local: Some(EdgeAddress {
            address: local_address.to_owned(),
            port: local_port.to_string(),
        }),
    });
    stream.write_all(
        &driver
            .send_meta_message(&message)
            .map_err(|error| format!("could not encode fake ADD_EDGE: {error}"))?,
    )?;
    stream.flush()?;
    Ok(())
}

fn read_c_tinc_address_cache(path: &Path) -> Result<Vec<SocketAddr>, Box<dyn Error>> {
    let bytes = fs::read(path)?;
    decode_c_tinc_address_cache(&bytes)
}

fn write_c_tinc_address_cache(path: &Path, addresses: &[SocketAddr]) -> Result<(), Box<dyn Error>> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, encode_c_tinc_address_cache(addresses))?;
    Ok(())
}

fn encode_c_tinc_address_cache(addresses: &[SocketAddr]) -> Vec<u8> {
    const ADDRESS_CACHE_VERSION: u32 = 1;
    const MAX_CACHED_ADDRESSES: usize = 8;

    let mut bytes = Vec::with_capacity(8 + MAX_CACHED_ADDRESSES * c_sockaddr_cache_slot_len());
    bytes.extend_from_slice(&ADDRESS_CACHE_VERSION.to_ne_bytes());
    bytes.extend_from_slice(&(addresses.len().min(MAX_CACHED_ADDRESSES) as u32).to_ne_bytes());
    for address in addresses.iter().take(MAX_CACHED_ADDRESSES) {
        bytes.extend_from_slice(&encode_c_sockaddr_slot(*address));
    }
    while bytes.len() < 8 + MAX_CACHED_ADDRESSES * c_sockaddr_cache_slot_len() {
        bytes.extend_from_slice(&vec![0; c_sockaddr_cache_slot_len()]);
    }

    bytes
}

fn decode_c_tinc_address_cache(bytes: &[u8]) -> Result<Vec<SocketAddr>, Box<dyn Error>> {
    const ADDRESS_CACHE_VERSION: u32 = 1;
    const MAX_CACHED_ADDRESSES: usize = 8;

    let slot_len = c_sockaddr_cache_slot_len();
    let expected_len = 8 + MAX_CACHED_ADDRESSES * slot_len;
    if bytes.len() < expected_len {
        return Err(format!(
            "short C tinc address cache: {} < {expected_len}",
            bytes.len()
        )
        .into());
    }

    let version = u32::from_ne_bytes(bytes[0..4].try_into()?);
    let used = u32::from_ne_bytes(bytes[4..8].try_into()?) as usize;
    if version != ADDRESS_CACHE_VERSION {
        return Err(format!("unexpected C tinc address cache version {version}").into());
    }
    if used > MAX_CACHED_ADDRESSES {
        return Err(format!("invalid C tinc address cache used count {used}").into());
    }

    let mut addresses = Vec::new();
    for index in 0..used {
        let offset = 8 + index * slot_len;
        let slot = &bytes[offset..offset + slot_len];
        let Some(address) = decode_c_sockaddr_slot(slot) else {
            return Err(format!("invalid sockaddr slot {index} in C tinc address cache").into());
        };
        if !addresses.contains(&address) {
            addresses.push(address);
        }
    }

    Ok(addresses)
}

fn c_sockaddr_cache_slot_len() -> usize {
    let sockaddr_unknown_size = 8 + 2 * std::mem::size_of::<*const libc::c_char>();
    let size = std::mem::size_of::<libc::sockaddr_in6>().max(sockaddr_unknown_size);
    let align =
        std::mem::align_of::<libc::sockaddr_in6>().max(std::mem::align_of::<*const libc::c_char>());
    size.div_ceil(align) * align
}

fn encode_c_sockaddr_slot(address: SocketAddr) -> Vec<u8> {
    let mut bytes = vec![0; c_sockaddr_cache_slot_len()];
    match address {
        SocketAddr::V4(address) => {
            let mut raw: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            raw.sin_family = libc::AF_INET as libc::sa_family_t;
            raw.sin_port = address.port().to_be();
            raw.sin_addr = libc::in_addr {
                s_addr: u32::from_ne_bytes(address.ip().octets()),
            };
            let raw_bytes = unsafe {
                std::slice::from_raw_parts(
                    (&raw as *const libc::sockaddr_in).cast::<u8>(),
                    std::mem::size_of::<libc::sockaddr_in>(),
                )
            };
            bytes[..raw_bytes.len()].copy_from_slice(raw_bytes);
        }
        SocketAddr::V6(address) => {
            let mut raw: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
            raw.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            raw.sin6_port = address.port().to_be();
            raw.sin6_flowinfo = address.flowinfo();
            raw.sin6_addr = libc::in6_addr {
                s6_addr: address.ip().octets(),
            };
            raw.sin6_scope_id = address.scope_id();
            let raw_bytes = unsafe {
                std::slice::from_raw_parts(
                    (&raw as *const libc::sockaddr_in6).cast::<u8>(),
                    std::mem::size_of::<libc::sockaddr_in6>(),
                )
            };
            bytes[..raw_bytes.len()].copy_from_slice(raw_bytes);
        }
    }
    bytes
}

fn decode_c_sockaddr_slot(bytes: &[u8]) -> Option<SocketAddr> {
    if bytes.len() < c_sockaddr_cache_slot_len() {
        return None;
    }
    let family = u16::from_ne_bytes(bytes.get(0..2)?.try_into().ok()?) as libc::c_int;
    match family {
        libc::AF_INET => {
            let mut raw: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            unsafe {
                std::ptr::copy_nonoverlapping(
                    bytes.as_ptr(),
                    (&mut raw as *mut libc::sockaddr_in).cast::<u8>(),
                    std::mem::size_of::<libc::sockaddr_in>(),
                );
            }
            let ip = Ipv4Addr::from(u32::from_be(raw.sin_addr.s_addr));
            let port = u16::from_be(raw.sin_port);
            Some(SocketAddr::new(IpAddr::V4(ip), port))
        }
        libc::AF_INET6 => {
            let mut raw: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
            unsafe {
                std::ptr::copy_nonoverlapping(
                    bytes.as_ptr(),
                    (&mut raw as *mut libc::sockaddr_in6).cast::<u8>(),
                    std::mem::size_of::<libc::sockaddr_in6>(),
                );
            }
            let ip = Ipv6Addr::from(raw.sin6_addr.s6_addr);
            let port = u16::from_be(raw.sin6_port);
            Some(SocketAddr::new(IpAddr::V6(ip), port))
        }
        _ => None,
    }
}

fn send_fake_legacy_ans_key(
    stream: &mut TcpStream,
    driver: &mut LegacyMetaConnectionDriver,
    answer: AnswerKeyMessage,
    case: &str,
) -> Result<(), Box<dyn Error>> {
    stream.write_all(
        &driver
            .send_meta_message(&MetaMessage::AnswerKey(answer))
            .map_err(|error| format!("could not encode {case} ANS_KEY: {error}"))?,
    )?;
    stream.flush()?;
    Ok(())
}

fn read_latest_legacy_answer_key_from_daemon(
    stream: &mut TcpStream,
    driver: &mut LegacyMetaConnectionDriver,
    daemon_name: &str,
) -> Result<AnswerKeyMessage, Box<dyn Error>> {
    let mut events = read_fake_legacy_events_until(stream, driver, |message| {
        matches!(
            message,
            MetaMessage::AnswerKey(answer) if answer.from == daemon_name
        )
    })?;
    events.extend(read_fake_legacy_events_for_duration(
        stream,
        driver,
        Duration::from_millis(300),
    )?);
    events
        .into_iter()
        .rev()
        .find_map(|message| match message {
            MetaMessage::AnswerKey(answer) if answer.from == daemon_name => Some(answer),
            _ => None,
        })
        .ok_or_else(|| format!("daemon did not send legacy ANS_KEY from {daemon_name}").into())
}

fn receive_legacy_probe_and_maybe_reply(
    socket: &UdpSocket,
    codec: &mut LegacyUdpCodec,
    reply: bool,
    daemon_label: &str,
    cleanup: &NetnsCleanup,
) -> Result<bool, Box<dyn Error>> {
    let mut buffer = [0_u8; 4096];
    let mut saw_probe = false;
    loop {
        match socket.recv_from(&mut buffer) {
            Ok((len, peer)) => {
                let packet = codec.decode("alpha", &buffer[..len]).map_err(|error| {
                    format!(
                        "{daemon_label} daemon sent undecodable legacy UDP datagram from {peer}: {error}\n{}",
                        cleanup.logs()
                    )
                })?;
                if !legacy_probe_request_payload(&packet.data) {
                    continue;
                }
                saw_probe = true;
                if reply {
                    let mut payload = packet.data.clone();
                    payload[0] = 2;
                    let len = u16::try_from(packet.data.len()).unwrap_or(u16::MAX);
                    payload[1..3].copy_from_slice(&len.to_be_bytes());
                    payload.truncate(16);
                    let datagram = codec.encode("alpha", &VpnPacket::new(payload)?)?;
                    socket.send_to(&datagram, peer)?;
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                return Ok(saw_probe);
            }
            Err(error) => return Err(error.into()),
        }
    }
}

fn legacy_probe_request_payload(payload: &[u8]) -> bool {
    payload.len() > 13 && payload[0] == 0 && payload[12] == 0 && payload[13] == 0
}

fn stop_daemon_with_rust_tincctl(
    confdir: &Path,
    cleanup: &mut NetnsCleanup,
    name: &str,
    label: &str,
) -> Result<(), Box<dyn Error>> {
    let stop = run_rust_tincctl(&["tinc", "--config", confdir.to_str().unwrap(), "stop"]).map_err(
        |error| {
            format!(
                "Rust tincctl stop failed against {label} daemon: {error}\n{}",
                cleanup.logs()
            )
        },
    )?;
    assert!(stop.is_empty(), "unexpected stop output: {stop}");
    wait_for_child_exit(cleanup, name)
}

fn read_fake_legacy_events_until(
    stream: &mut TcpStream,
    driver: &mut LegacyMetaConnectionDriver,
    predicate: impl Fn(&MetaMessage) -> bool,
) -> Result<Vec<MetaMessage>, Box<dyn Error>> {
    let mut messages = Vec::new();
    let mut buffer = [0_u8; 4096];
    let deadline = Instant::now() + Duration::from_secs(5);

    while Instant::now() < deadline {
        match stream.read(&mut buffer) {
            Ok(0) => {
                return Err("daemon closed fake legacy connection while reading events".into());
            }
            Ok(read) => {
                let step = driver.receive_bytes(&buffer[..read])?;
                let mut matched = false;
                for event in step.events {
                    if let tinc_runtime::meta::MetaConnectionEvent::Message(message) = event {
                        matched |= predicate(&message);
                        messages.push(message);
                    }
                }
                if matched {
                    return Ok(messages);
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                thread::sleep(Duration::from_millis(50));
            }
            Err(error) => return Err(error.into()),
        }
    }

    Err("timed out reading expected fake legacy meta event".into())
}

fn read_fake_legacy_meta_events_until(
    stream: &mut TcpStream,
    driver: &mut LegacyMetaConnectionDriver,
    predicate: impl Fn(&tinc_runtime::meta::MetaConnectionEvent) -> bool,
) -> Result<Vec<tinc_runtime::meta::MetaConnectionEvent>, Box<dyn Error>> {
    let mut events = Vec::new();
    let mut buffer = [0_u8; 4096];
    let deadline = Instant::now() + Duration::from_secs(5);

    while Instant::now() < deadline {
        match stream.read(&mut buffer) {
            Ok(0) => {
                return Err("daemon closed fake legacy connection while reading events".into());
            }
            Ok(read) => {
                let step = driver.receive_bytes(&buffer[..read])?;
                let mut matched = false;
                for event in step.events {
                    matched |= predicate(&event);
                    events.push(event);
                }
                if matched {
                    return Ok(events);
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                thread::sleep(Duration::from_millis(50));
            }
            Err(error) => return Err(error.into()),
        }
    }

    Err("timed out reading expected fake legacy meta event".into())
}

fn read_fake_legacy_events_for_duration(
    stream: &mut TcpStream,
    driver: &mut LegacyMetaConnectionDriver,
    duration: Duration,
) -> Result<Vec<MetaMessage>, Box<dyn Error>> {
    let mut messages = Vec::new();
    let mut buffer = [0_u8; 4096];
    let deadline = Instant::now() + duration;

    while Instant::now() < deadline {
        match stream.read(&mut buffer) {
            Ok(0) => return Err("daemon closed fake legacy connection while reading events".into()),
            Ok(read) => {
                let step = driver.receive_bytes(&buffer[..read])?;
                for event in step.events {
                    if let tinc_runtime::meta::MetaConnectionEvent::Message(message) = event {
                        messages.push(message);
                    }
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                thread::sleep(Duration::from_millis(50));
            }
            Err(error) => return Err(error.into()),
        }
    }

    Ok(messages)
}

fn legacy_udp_replay_test_packet(destination: [u8; 4]) -> Result<VpnPacket, Box<dyn Error>> {
    let mut packet = vec![0_u8; 14 + 20];
    packet[0..6].copy_from_slice(&[0, 1, 2, 3, 4, 5]);
    packet[6..12].copy_from_slice(&[6, 7, 8, 9, 10, 11]);
    packet[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    packet[14] = 0x45;
    packet[16..18].copy_from_slice(&20_u16.to_be_bytes());
    packet[22] = 64;
    packet[23] = 17;
    packet[26..30].copy_from_slice(&[192, 0, 2, 52]);
    packet[30..34].copy_from_slice(&destination);

    Ok(VpnPacket::new(packet)?)
}

fn wait_for_traffic_counters(
    confdir: &Path,
    node: &str,
    expected_in_packets: u64,
    expected_in_bytes: u64,
    cleanup: &NetnsCleanup,
) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + Duration::from_secs(8);
    let mut last_dump = String::new();

    while Instant::now() < deadline {
        match read_raw_traffic_dump(confdir) {
            Ok(dump) => {
                last_dump = dump.join("");
                if let Some(counters) = rust_dump_traffic_counters(&last_dump, node)
                    && counters.in_packets == expected_in_packets
                    && counters.in_bytes == expected_in_bytes
                {
                    return Ok(());
                }
            }
            Err(error) => {
                last_dump = format!("{error}");
            }
        }
        thread::sleep(Duration::from_millis(100));
    }

    Err(format!(
        "timed out waiting for traffic counters for {node}: in_packets={expected_in_packets} in_bytes={expected_in_bytes}\nlast dump:\n{last_dump}\n{}",
        cleanup.logs()
    )
    .into())
}

fn assert_traffic_counters_stay(
    confdir: &Path,
    node: &str,
    expected_in_packets: u64,
    expected_in_bytes: u64,
    duration: Duration,
    cleanup: &NetnsCleanup,
    message: &str,
) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + duration;

    while Instant::now() < deadline {
        cleanup.ensure_children_alive()?;
        let dump = read_raw_traffic_dump(confdir)?.join("");
        if let Some(counters) = rust_dump_traffic_counters(&dump, node)
            && (counters.in_packets != expected_in_packets
                || counters.in_bytes != expected_in_bytes)
        {
            return Err(format!("{message}\nlast dump:\n{dump}\n{}", cleanup.logs()).into());
        }
        thread::sleep(Duration::from_millis(100));
    }

    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TrafficSnapshot {
    in_packets: u64,
    in_bytes: u64,
    out_packets: u64,
    out_bytes: u64,
}

fn assert_single_ping_updates_traffic_counters_like_tinc(
    source_confdir: &Path,
    destination_peer: &str,
    destination_confdir: &Path,
    source_peer: &str,
    source_netns: &str,
    target_address: &str,
    label: &str,
    cleanup: &NetnsCleanup,
) -> Result<(), Box<dyn Error>> {
    let source_before = read_traffic_snapshot(source_confdir, destination_peer)?;
    let destination_before = read_traffic_snapshot(destination_confdir, source_peer)?;

    wait_for_ping(source_netns, target_address, cleanup)?;

    wait_for_traffic_counter_increase(
        source_confdir,
        destination_peer,
        source_before,
        TrafficDirection::Outbound,
        label,
        cleanup,
    )?;
    wait_for_traffic_counter_increase(
        destination_confdir,
        source_peer,
        destination_before,
        TrafficDirection::Inbound,
        label,
        cleanup,
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TrafficDirection {
    Inbound,
    Outbound,
}

fn wait_for_traffic_counter_increase(
    confdir: &Path,
    peer: &str,
    before: TrafficSnapshot,
    direction: TrafficDirection,
    label: &str,
    cleanup: &NetnsCleanup,
) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + Duration::from_secs(8);
    let mut last_dump = String::new();

    while Instant::now() < deadline {
        cleanup.ensure_children_alive()?;
        match read_raw_traffic_dump(confdir) {
            Ok(dump) => {
                last_dump = dump.join("");
                if let Some(after) = rust_dump_traffic_counters(&last_dump, peer) {
                    let packets_increased = match direction {
                        TrafficDirection::Inbound => after.in_packets > before.in_packets,
                        TrafficDirection::Outbound => after.out_packets > before.out_packets,
                    };
                    let bytes_increased = match direction {
                        TrafficDirection::Inbound => after.in_bytes > before.in_bytes,
                        TrafficDirection::Outbound => after.out_bytes > before.out_bytes,
                    };
                    if packets_increased && bytes_increased {
                        return Ok(());
                    }
                }
            }
            Err(error) => {
                last_dump = format!("{error}");
            }
        }
        thread::sleep(Duration::from_millis(100));
    }

    Err(format!(
        "timed out waiting for {direction:?} traffic counters to increase for {peer} in {label}; before={before:?}\nlast dump:\n{last_dump}\n{}",
        cleanup.logs()
    )
    .into())
}

fn read_traffic_snapshot(confdir: &Path, peer: &str) -> Result<TrafficSnapshot, Box<dyn Error>> {
    let dump = read_raw_traffic_dump(confdir)?.join("");
    rust_dump_traffic_counters(&dump, peer)
        .ok_or_else(|| format!("missing traffic counters for {peer}:\n{dump}").into())
}

fn read_raw_traffic_dump(confdir: &Path) -> Result<Vec<String>, Box<dyn Error>> {
    read_raw_control_dump(confdir, REQ_DUMP_TRAFFIC_RAW)
}

fn rust_dump_traffic_counters(dump: &str, node: &str) -> Option<TrafficSnapshot> {
    dump.lines().find_map(|line| {
        let mut parts = line.split_whitespace();
        if parts.next()?.parse::<i32>().ok()? != CONTROL_REQUEST
            || parts.next()?.parse::<i32>().ok()? != REQ_DUMP_TRAFFIC_RAW
            || parts.next()? != node
        {
            return None;
        }
        let in_packets = parts.next()?.parse().ok()?;
        let in_bytes = parts.next()?.parse().ok()?;
        let out_packets = parts.next()?.parse().ok()?;
        let out_bytes = parts.next()?.parse().ok()?;
        Some(TrafficSnapshot {
            in_packets,
            in_bytes,
            out_packets,
            out_bytes,
        })
    })
}

fn legacy_ans_key_message(from: &str, to: &str, key: String, compression: i32) -> AnswerKeyMessage {
    AnswerKeyMessage {
        from: from.to_owned(),
        to: to.to_owned(),
        key,
        cipher: LegacyCipherAlgorithm::Aes256Cbc.nid(),
        digest: LegacyDigest::Sha256 { length: 4 }.nid(),
        mac_length: 4,
        compression,
        address: None,
    }
}

fn wait_for_node_status(
    confdir: &Path,
    node: &str,
    require: u32,
    forbid: u32,
    cleanup: &NetnsCleanup,
) -> Result<u32, Box<dyn Error>> {
    let deadline = Instant::now() + Duration::from_secs(8);
    let mut last_dump = String::new();

    while Instant::now() < deadline {
        match run_rust_tincctl(&[
            "tinc",
            "--config",
            confdir.to_str().unwrap(),
            "dump",
            "nodes",
        ]) {
            Ok(dump) => {
                last_dump = dump;
                if let Some(status) = rust_dump_node_status(&last_dump, node)
                    && status & require == require
                    && status & forbid == 0
                {
                    return Ok(status);
                }
            }
            Err(error) => {
                last_dump = format!("{error}");
            }
        }
        thread::sleep(Duration::from_millis(100));
    }

    Err(format!(
        "timed out waiting for node {node} status require={require:04x} forbid={forbid:04x}\nlast dump:\n{last_dump}\n{}",
        cleanup.logs()
    )
    .into())
}

fn rust_dump_node_status(dump: &str, node: &str) -> Option<u32> {
    dump.lines().find_map(|line| {
        if !line.starts_with(&format!("{node} id ")) {
            return None;
        }
        let status = line.split_once(" status ")?.1.split_whitespace().next()?;
        u32::from_str_radix(status, 16).ok()
    })
}

fn wait_for_node_route_via(
    confdir: &Path,
    node: &str,
    nexthop: &str,
    via: &str,
    indirect: bool,
    cleanup: &NetnsCleanup,
) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut last_dump = String::new();
    let route = format!(" nexthop {nexthop} via {via} ");

    while Instant::now() < deadline {
        match run_rust_tincctl(&[
            "tinc",
            "--config",
            confdir.to_str().unwrap(),
            "dump",
            "nodes",
        ]) {
            Ok(dump) => {
                last_dump = dump;
                if let Some(line) = rust_dump_node_line(&last_dump, node)
                    && line.contains(&route)
                    && rust_dump_node_status(&last_dump, node)
                        .is_some_and(|status| (status & (1 << 5) != 0) == indirect)
                {
                    return Ok(());
                }
            }
            Err(error) => {
                last_dump = format!("{error}");
            }
        }
        cleanup.ensure_children_alive()?;
        thread::sleep(Duration::from_millis(100));
    }

    Err(format!(
        "timed out waiting for node {node} route via {via} indirect={indirect}\nlast dump:\n{last_dump}\n{}",
        cleanup.logs()
    )
    .into())
}

fn rust_dump_node_line<'a>(dump: &'a str, node: &str) -> Option<&'a str> {
    dump.lines()
        .find(|line| line.starts_with(&format!("{node} id ")))
}

fn rust_dump_node_pmtu_fields(dump: &str, node: &str) -> Option<(i32, i32, i32)> {
    let line = rust_dump_node_line(dump, node)?;
    let fields = line.split_whitespace().collect::<Vec<_>>();

    if let Some(index) = fields.iter().position(|field| *field == "pmtu") {
        let pmtu = fields.get(index + 1)?.parse().ok()?;
        let min_mtu = fields.get(index + 3)?.parse().ok()?;
        let max_mtu = fields.get(index + 5)?.trim_end_matches(')').parse().ok()?;
        return Some((pmtu, min_mtu, max_mtu));
    }

    if fields.len() >= 19 {
        return Some((
            fields[16].parse().ok()?,
            fields[17].parse().ok()?,
            fields[18].parse().ok()?,
        ));
    }

    None
}

fn assert_c_rust_modern_direct_dump_parity(
    workspace: &TempWorkspace,
    rust_connects_to_c: bool,
    c_tincd: &Path,
    ns_alpha: &str,
    ns_beta: &str,
    cleanup: &NetnsCleanup,
) -> Result<(), Box<dyn Error>> {
    let alpha_port = if rust_connects_to_c { 17255 } else { 17257 };
    let beta_port = if rust_connects_to_c { 17256 } else { 17258 };
    let dumps = wait_for_direct_dump_parity(
        &workspace.path().join("alpha"),
        &workspace.path().join("beta"),
        cleanup,
    )?;
    assert_modern_direct_raw_view(
        &dumps.alpha,
        DirectViewExpectation {
            local: "alpha",
            peer: "beta",
            local_host: "192.0.2.11",
            local_port: alpha_port,
            local_subnet: "10.101.1.0/24",
            peer_host: "192.0.2.12",
            peer_port: beta_port,
            peer_subnet: "10.101.2.0/24",
        },
    )?;
    assert_modern_direct_raw_view(
        &dumps.beta,
        DirectViewExpectation {
            local: "beta",
            peer: "alpha",
            local_host: "192.0.2.12",
            local_port: beta_port,
            local_subnet: "10.101.2.0/24",
            peer_host: "192.0.2.11",
            peer_port: alpha_port,
            peer_subnet: "10.101.1.0/24",
        },
    )?;

    let (rust_ns, rust_confdir, rust_view) = if rust_connects_to_c {
        (
            ns_alpha,
            workspace.path().join("alpha"),
            DirectViewExpectation {
                local: "alpha",
                peer: "beta",
                local_host: "192.0.2.11",
                local_port: alpha_port,
                local_subnet: "10.101.1.0/24",
                peer_host: "192.0.2.12",
                peer_port: beta_port,
                peer_subnet: "10.101.2.0/24",
            },
        )
    } else {
        (
            ns_beta,
            workspace.path().join("beta"),
            DirectViewExpectation {
                local: "beta",
                peer: "alpha",
                local_host: "192.0.2.12",
                local_port: beta_port,
                local_subnet: "10.101.2.0/24",
                peer_host: "192.0.2.11",
                peer_port: alpha_port,
                peer_subnet: "10.101.1.0/24",
            },
        )
    };
    let Some(c_tinc) = c_tinc_binary() else {
        return Err("missing C tinc binary after strict gate preflight".into());
    };
    assert_c_tincctl_modern_direct_dump_text(&c_tinc, rust_ns, &rust_confdir, rust_view, cleanup)?;

    let (c_confdir, c_ns, c_view) = if rust_connects_to_c {
        (
            workspace.path().join("beta"),
            ns_beta,
            DirectViewExpectation {
                local: "beta",
                peer: "alpha",
                local_host: "192.0.2.12",
                local_port: beta_port,
                local_subnet: "10.101.2.0/24",
                peer_host: "192.0.2.11",
                peer_port: alpha_port,
                peer_subnet: "10.101.1.0/24",
            },
        )
    } else {
        (
            workspace.path().join("alpha"),
            ns_alpha,
            DirectViewExpectation {
                local: "alpha",
                peer: "beta",
                local_host: "192.0.2.11",
                local_port: alpha_port,
                local_subnet: "10.101.1.0/24",
                peer_host: "192.0.2.12",
                peer_port: beta_port,
                peer_subnet: "10.101.2.0/24",
            },
        )
    };
    assert_rust_tincctl_modern_direct_dump_text(c_tincd, c_ns, &c_confdir, c_view, cleanup)?;

    Ok(())
}

fn assert_c_rust_legacy_direct_dump_parity(
    workspace: &TempWorkspace,
    rust_connects_to_c: bool,
    c_tincd: &Path,
    ns_alpha: &str,
    ns_beta: &str,
    cleanup: &NetnsCleanup,
    legacy_crypto: LegacyCryptoConfig<'_>,
) -> Result<(), Box<dyn Error>> {
    let alpha_port = if rust_connects_to_c { 17355 } else { 17357 };
    let beta_port = if rust_connects_to_c { 17356 } else { 17358 };
    wait_for_direct_udp_discovery_pmtu_min_mtu(
        &workspace.path().join("alpha"),
        "beta",
        ns_alpha,
        "10.102.2.1",
        "legacy direct raw parity alpha view",
        1,
        cleanup,
    )?;
    wait_for_direct_udp_discovery_pmtu_min_mtu(
        &workspace.path().join("beta"),
        "alpha",
        ns_beta,
        "10.102.1.1",
        "legacy direct raw parity beta view",
        1,
        cleanup,
    )?;
    let dumps = wait_for_direct_dump_parity(
        &workspace.path().join("alpha"),
        &workspace.path().join("beta"),
        cleanup,
    )?;
    assert_legacy_direct_raw_view(
        &dumps.alpha,
        DirectViewExpectation {
            local: "alpha",
            peer: "beta",
            local_host: "192.0.2.21",
            local_port: alpha_port,
            local_subnet: "10.102.1.0/24",
            peer_host: "192.0.2.22",
            peer_port: beta_port,
            peer_subnet: "10.102.2.0/24",
        },
        legacy_crypto,
    )?;
    assert_legacy_direct_raw_view(
        &dumps.beta,
        DirectViewExpectation {
            local: "beta",
            peer: "alpha",
            local_host: "192.0.2.22",
            local_port: beta_port,
            local_subnet: "10.102.2.0/24",
            peer_host: "192.0.2.21",
            peer_port: alpha_port,
            peer_subnet: "10.102.1.0/24",
        },
        legacy_crypto,
    )?;

    let (rust_ns, rust_confdir, rust_view) = if rust_connects_to_c {
        (
            ns_alpha,
            workspace.path().join("alpha"),
            DirectViewExpectation {
                local: "alpha",
                peer: "beta",
                local_host: "192.0.2.21",
                local_port: alpha_port,
                local_subnet: "10.102.1.0/24",
                peer_host: "192.0.2.22",
                peer_port: beta_port,
                peer_subnet: "10.102.2.0/24",
            },
        )
    } else {
        (
            ns_beta,
            workspace.path().join("beta"),
            DirectViewExpectation {
                local: "beta",
                peer: "alpha",
                local_host: "192.0.2.22",
                local_port: beta_port,
                local_subnet: "10.102.2.0/24",
                peer_host: "192.0.2.21",
                peer_port: alpha_port,
                peer_subnet: "10.102.1.0/24",
            },
        )
    };
    let Some(c_tinc) = c_tinc_binary() else {
        return Err("missing C tinc binary after strict gate preflight".into());
    };
    assert_c_tincctl_legacy_direct_dump_text(
        &c_tinc,
        rust_ns,
        &rust_confdir,
        rust_view,
        cleanup,
        legacy_crypto,
    )?;

    let (c_confdir, c_ns, c_view) = if rust_connects_to_c {
        (
            workspace.path().join("beta"),
            ns_beta,
            DirectViewExpectation {
                local: "beta",
                peer: "alpha",
                local_host: "192.0.2.22",
                local_port: beta_port,
                local_subnet: "10.102.2.0/24",
                peer_host: "192.0.2.21",
                peer_port: alpha_port,
                peer_subnet: "10.102.1.0/24",
            },
        )
    } else {
        (
            workspace.path().join("alpha"),
            ns_alpha,
            DirectViewExpectation {
                local: "alpha",
                peer: "beta",
                local_host: "192.0.2.21",
                local_port: alpha_port,
                local_subnet: "10.102.1.0/24",
                peer_host: "192.0.2.22",
                peer_port: beta_port,
                peer_subnet: "10.102.2.0/24",
            },
        )
    };
    assert_rust_tincctl_legacy_direct_dump_text(
        c_tincd,
        c_ns,
        &c_confdir,
        c_view,
        cleanup,
        legacy_crypto,
    )?;

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn assert_dynamic_relay_udp_discovery_pmtu_like_tinc(
    workspace: &TempWorkspace,
    cleanup: &NetnsCleanup,
    source: &str,
    relay: &str,
    destination: &str,
    source_netns: &str,
    destination_tunnel_ip: &str,
    destination_netns: &str,
    source_tunnel_ip: &str,
) -> Result<(), Box<dyn Error>> {
    wait_for_relay_udp_discovery_pmtu(
        &workspace.path().join(source),
        relay,
        destination,
        source_netns,
        destination_tunnel_ip,
        false,
        "dynamic relay",
        cleanup,
    )?;
    assert_relay_udp_discovery_raw_fields_like_tinc(
        &workspace.path().join(source),
        relay,
        destination,
        "dynamic relay source view",
    )?;
    wait_for_relay_udp_discovery_pmtu(
        &workspace.path().join(destination),
        relay,
        source,
        destination_netns,
        source_tunnel_ip,
        false,
        "dynamic relay",
        cleanup,
    )?;
    assert_relay_udp_discovery_raw_fields_like_tinc(
        &workspace.path().join(destination),
        relay,
        source,
        "dynamic relay destination view",
    )
}

#[allow(clippy::too_many_arguments)]
fn assert_static_relay_udp_discovery_pmtu_like_tinc(
    workspace: &TempWorkspace,
    cleanup: &NetnsCleanup,
    source: &str,
    relay: &str,
    destination: &str,
    source_netns: &str,
    destination_tunnel_ip: &str,
    destination_netns: &str,
    source_tunnel_ip: &str,
) -> Result<(), Box<dyn Error>> {
    wait_for_relay_udp_discovery_pmtu(
        &workspace.path().join(source),
        relay,
        destination,
        source_netns,
        destination_tunnel_ip,
        false,
        "static relay",
        cleanup,
    )?;
    assert_relay_udp_discovery_raw_fields_like_tinc(
        &workspace.path().join(source),
        relay,
        destination,
        "static relay source view",
    )?;
    assert_static_relay_address_cache_negative_like_tinc(
        &workspace.path().join(source),
        relay,
        destination,
        "static relay source view",
    )?;
    wait_for_relay_udp_discovery_pmtu(
        &workspace.path().join(destination),
        relay,
        source,
        destination_netns,
        source_tunnel_ip,
        false,
        "static relay",
        cleanup,
    )?;
    assert_relay_udp_discovery_raw_fields_like_tinc(
        &workspace.path().join(destination),
        relay,
        source,
        "static relay destination view",
    )?;
    assert_static_relay_address_cache_negative_like_tinc(
        &workspace.path().join(destination),
        relay,
        source,
        "static relay destination view",
    )
}

fn assert_relay_udp_discovery_raw_fields_like_tinc(
    confdir: &Path,
    relay: &str,
    destination: &str,
    label: &str,
) -> Result<(), Box<dyn Error>> {
    let dumps = RawControlDumps::read(confdir)?;
    let relay = raw_node(&dumps, relay)?;
    assert_status_has(relay, STATUS_UDP_CONFIRMED)?;
    assert!(
        relay.min_mtu > 0 && relay.max_mtu >= relay.min_mtu,
        "{label}: relay peer should have C PMTU discovery started after try_tx(relay): {relay:?}"
    );
    assert!(
        relay.udp_ping_rtt >= -1,
        "{label}: relay peer UDP RTT field should use the C dump_nodes() sentinel/rtt shape: {relay:?}"
    );

    let destination = raw_node(&dumps, destination)?;
    assert_status_lacks(destination, STATUS_UDP_CONFIRMED)?;
    assert_relay_destination_pmtu_reset_fields_like_tinc(destination, label)?;

    Ok(())
}

fn assert_static_relay_address_cache_negative_like_tinc(
    confdir: &Path,
    relay: &str,
    destination: &str,
    label: &str,
) -> Result<(), Box<dyn Error>> {
    let dumps = RawControlDumps::read(confdir)?;
    let relay = raw_node(&dumps, relay)?;
    let destination = raw_node(&dumps, destination)?;
    assert!(
        destination.host != relay.host || destination.port != relay.port,
        "{label}: static IndirectData final endpoint address was overwritten with the relay address; C handle_incoming_vpn_packet() only calls update_node_udp() for direct packets: relay={relay:?}, destination={destination:?}"
    );

    let Some(relay_address) = raw_node_socket_addr(relay) else {
        return Ok(());
    };
    let cache_path = confdir.join("cache").join(&destination.name);
    if !cache_path.exists() {
        return Ok(());
    }
    let cached_addresses = read_c_tinc_address_cache(&cache_path)?;
    assert!(
        !cached_addresses.contains(&relay_address),
        "{label}: static IndirectData cache/{} contains relay address {relay_address}; C relayed UDP/MTU probes must not update the origin endpoint address cache: {:?}",
        destination.name,
        cached_addresses
    );

    Ok(())
}

fn raw_node_socket_addr(node: &RawNodeDump) -> Option<SocketAddr> {
    if matches!(
        node.host.as_str(),
        "MYSELF" | "unknown" | "unspec" | "-" | ""
    ) {
        return None;
    }

    format!("{}:{}", node.host, node.port).parse().ok()
}

#[allow(clippy::too_many_arguments)]
fn assert_tunnel_server_udp_discovery_pmtu_like_tinc(
    workspace: &TempWorkspace,
    cleanup: &NetnsCleanup,
    server: &str,
    client: &str,
    server_netns: &str,
    client_tunnel_ip: &str,
    client_netns: &str,
    server_tunnel_ip: &str,
) -> Result<(), Box<dyn Error>> {
    wait_for_direct_udp_discovery_pmtu(
        &workspace.path().join(server),
        client,
        server_netns,
        client_tunnel_ip,
        "tunnel-server server view",
        cleanup,
    )?;
    wait_for_direct_udp_discovery_pmtu(
        &workspace.path().join(client),
        server,
        client_netns,
        server_tunnel_ip,
        "tunnel-server client view",
        cleanup,
    )
}

fn wait_for_direct_udp_discovery_pmtu(
    confdir: &Path,
    peer: &str,
    source_netns: &str,
    peer_tunnel_ip: &str,
    label: &str,
    cleanup: &NetnsCleanup,
) -> Result<(), Box<dyn Error>> {
    wait_for_direct_udp_discovery_pmtu_min_mtu(
        confdir,
        peer,
        source_netns,
        peer_tunnel_ip,
        label,
        1,
        cleanup,
    )
}

fn wait_for_direct_udp_discovery_pmtu_min_mtu(
    confdir: &Path,
    peer: &str,
    source_netns: &str,
    peer_tunnel_ip: &str,
    label: &str,
    min_mtu_floor: i32,
    cleanup: &NetnsCleanup,
) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut last_dump = String::new();

    while Instant::now() < deadline {
        cleanup.ensure_children_alive()?;
        let _ = Command::new("ip")
            .args(ping_args(source_netns, peer_tunnel_ip))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();

        match run_rust_tincctl(&[
            "tinc",
            "--config",
            confdir.to_str().unwrap(),
            "dump",
            "nodes",
        ]) {
            Ok(dump) => {
                last_dump = dump;
                let udp_confirmed = rust_dump_node_status(&last_dump, peer)
                    .is_some_and(|status| status & (1 << 7) != 0);
                let mtu_started = rust_dump_node_pmtu_fields(&last_dump, peer).is_some_and(
                    |(_, min_mtu, max_mtu)| min_mtu >= min_mtu_floor && max_mtu >= min_mtu,
                );

                if udp_confirmed && mtu_started {
                    return Ok(());
                }
            }
            Err(error) => {
                last_dump = format!("{error}");
            }
        }

        thread::sleep(Duration::from_millis(200));
    }

    Err(format!(
        "timed out waiting for {label} direct UDP discovery/PMTU state in {}\n\
         expected peer {peer} to become udp_confirmed with minmtu >= {min_mtu_floor}\n\
         last dump:\n{last_dump}\n{}",
        confdir.display(),
        cleanup.logs()
    )
    .into())
}

fn wait_for_pmtu_reduced_after_emsgsize(
    confdir: &Path,
    peer: &str,
    reduced_below: i32,
    label: &str,
    cleanup: &NetnsCleanup,
) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + Duration::from_secs(8);
    let mut last_dump = String::new();

    while Instant::now() < deadline {
        cleanup.ensure_children_alive()?;
        match RawControlDumps::read(confdir) {
            Ok(dumps) => {
                let node = raw_node(&dumps, peer)?;
                last_dump = format!("{node:?}");
                if node.status & STATUS_REACHABLE != 0
                    && node.pmtu > 0
                    && node.pmtu < reduced_below
                    && node.max_mtu > 0
                    && node.max_mtu < reduced_below
                {
                    return Ok(());
                }
            }
            Err(error) => {
                last_dump = format!("{error}");
            }
        }
        thread::sleep(Duration::from_millis(100));
    }

    Err(format!(
        "timed out waiting for {label} peer {peer} pmtu/maxmtu to drop below {reduced_below} after EMSGSIZE\nlast dump:\n{last_dump}\n{}",
        cleanup.logs()
    )
    .into())
}

fn wait_for_relay_udp_discovery_pmtu(
    confdir: &Path,
    relay: &str,
    destination: &str,
    source_netns: &str,
    destination_tunnel_ip: &str,
    expect_destination_udp_confirmed: bool,
    label: &str,
    cleanup: &NetnsCleanup,
) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut last_dump = String::new();

    while Instant::now() < deadline {
        cleanup.ensure_children_alive()?;
        let _ = Command::new("ip")
            .args(ping_args(source_netns, destination_tunnel_ip))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();

        match run_rust_tincctl(&[
            "tinc",
            "--config",
            confdir.to_str().unwrap(),
            "dump",
            "nodes",
        ]) {
            Ok(dump) => {
                last_dump = dump;
                let relay_udp_confirmed = rust_dump_node_status(&last_dump, relay)
                    .is_some_and(|status| status & (1 << 7) != 0);
                let destination_udp_confirmed = rust_dump_node_status(&last_dump, destination)
                    .is_some_and(|status| status & (1 << 7) != 0);
                let relay_mtu_started = rust_dump_node_pmtu_fields(&last_dump, relay)
                    .is_some_and(|(_, min_mtu, max_mtu)| min_mtu > 0 && max_mtu >= min_mtu);
                let destination_mtu_waits_for_direct_udp =
                    rust_dump_node_pmtu_fields(&last_dump, destination)
                        .is_some_and(|(_, min_mtu, max_mtu)| min_mtu == 0 && max_mtu > 0);

                if relay_udp_confirmed
                    && relay_mtu_started
                    && destination_udp_confirmed == expect_destination_udp_confirmed
                    && destination_mtu_waits_for_direct_udp
                {
                    return Ok(());
                }
            }
            Err(error) => {
                last_dump = format!("{error}");
            }
        }

        thread::sleep(Duration::from_millis(200));
    }

    Err(format!(
        "timed out waiting for {label} UDP discovery/PMTU state in {}\n\
         expected relay {relay} to become udp_confirmed with minmtu > 0, and final destination {destination} udp_confirmed={expect_destination_udp_confirmed} with PMTU discovery reset\n\
         last dump:\n{last_dump}\n{}",
        confdir.display(),
        cleanup.logs()
    )
    .into())
}

fn wait_for_static_relay_endpoint_unreachable(
    confdir: &Path,
    endpoint: &str,
    label: &str,
    cleanup: &NetnsCleanup,
) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + Duration::from_secs(12);
    let mut last_dump = String::new();

    while Instant::now() < deadline {
        match RawControlDumps::read(confdir) {
            Ok(dumps) => {
                last_dump = format!("{:?}", dumps.nodes);
                if let Ok(node) = raw_node(&dumps, endpoint) {
                    if node.status & STATUS_REACHABLE == 0 {
                        return Ok(());
                    }
                }
            }
            Err(error) => {
                last_dump = error.to_string();
            }
        }

        thread::sleep(Duration::from_millis(100));
    }

    Err(format!(
        "timed out waiting for {label} to mark {endpoint} unreachable in {}\nlast dump:\n{last_dump}\n{}",
        confdir.display(),
        cleanup.logs()
    )
    .into())
}

fn wait_for_host_ed25519_key(
    host_file: &Path,
    public_key: &str,
    cleanup: &NetnsCleanup,
) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + Duration::from_secs(12);
    while Instant::now() < deadline {
        cleanup.ensure_children_alive()?;
        if fs::read_to_string(host_file)
            .map(|contents| contents.contains(&format!("Ed25519PublicKey = {public_key}")))
            .unwrap_or(false)
        {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }

    Err(format!(
        "timed out waiting for legacy minor-1 Ed25519PublicKey in {}\n{}",
        host_file.display(),
        cleanup.logs()
    )
    .into())
}

fn wait_for_legacy_minor_one_termreq_reconnect_like_tinc(
    alpha_confdir: &Path,
    beta_confdir: &Path,
    c_log: &Path,
    c_node_name: &str,
    cleanup: &NetnsCleanup,
) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + Duration::from_secs(12);
    let mut last_error = String::new();

    while Instant::now() < deadline {
        cleanup.ensure_children_alive()?;
        match assert_legacy_minor_one_termreq_reconnect_like_tinc(
            alpha_confdir,
            beta_confdir,
            c_log,
            c_node_name,
        ) {
            Ok(()) => return Ok(()),
            Err(error) => last_error = error.to_string(),
        }
        thread::sleep(Duration::from_millis(100));
    }

    Err(format!(
        "timed out waiting for legacy minor-1 TERMREQ/reconnect parity\nlast error: {last_error}\n{}",
        cleanup.logs()
    )
    .into())
}

fn assert_legacy_minor_one_termreq_reconnect_like_tinc(
    alpha_confdir: &Path,
    beta_confdir: &Path,
    c_log: &Path,
    c_node_name: &str,
) -> Result<(), Box<dyn Error>> {
    let c_log = read_log(c_log);
    let id_minor_one_line = c_log
        .lines()
        .position(|line| line_mentions_id_minor(line, 1))
        .ok_or_else(|| format!("C log has no initial minor-1 ID from Rust peer:\n{c_log}"))?;
    let termreq_line = c_log
        .lines()
        .position(|line| line.contains("Sending TERMREQ"))
        .ok_or_else(|| format!("C log has no TERMREQ after minor-1 upgrade:\n{c_log}"))?;
    let id_modern_line = c_log
        .lines()
        .enumerate()
        .skip(termreq_line + 1)
        .find_map(|(index, line)| line_mentions_id_minor(line, PROT_MINOR).then_some(index))
        .ok_or_else(|| format!("C log has no modern reconnect ID after TERMREQ:\n{c_log}"))?;

    assert!(
        id_minor_one_line < termreq_line && termreq_line < id_modern_line,
        "C minor-1 upgrade log order must be ID 17.1 -> TERMREQ -> ID 17.{PROT_MINOR}; got lines {id_minor_one_line}, {termreq_line}, {id_modern_line}\n{c_log}"
    );

    let alpha = RawControlDumps::read(alpha_confdir)?;
    let beta = RawControlDumps::read(beta_confdir)?;
    let alpha_peer = raw_node(&alpha, "beta")?;
    let beta_peer = raw_node(&beta, "alpha")?;
    for (label, node) in [
        ("alpha view of beta", alpha_peer),
        ("beta view of alpha", beta_peer),
    ] {
        assert_status_has(node, STATUS_VALIDKEY | STATUS_REACHABLE | STATUS_SPTPS)?;
        assert_status_lacks(node, STATUS_INDIRECT)?;
        assert_eq!(
            1, node.distance,
            "legacy minor-1 reconnect should leave a direct modern edge in {label}: {node:?}"
        );
    }

    let c_dumps = if c_node_name == "alpha" {
        &alpha
    } else {
        &beta
    };
    let rust_peer_name = if c_node_name == "alpha" {
        "beta"
    } else {
        "alpha"
    };
    let rust_peer = raw_node(c_dumps, rust_peer_name)?;
    assert_status_has(rust_peer, STATUS_VALIDKEY | STATUS_REACHABLE | STATUS_SPTPS)?;

    Ok(())
}

fn line_mentions_id_minor(line: &str, minor: u8) -> bool {
    (line.contains("Got ID") || line.contains("Sending ID"))
        && line.contains(&format!("17.{minor}"))
}

fn wait_for_req_pubkey_exchange(
    source_netns: &str,
    target_address: &str,
    rust_host_file: &Path,
    c_public_key: &str,
    c_host_file: &Path,
    rust_public_key: &str,
    cleanup: &NetnsCleanup,
) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut last_ping = String::new();
    while Instant::now() < deadline {
        cleanup.ensure_children_alive()?;
        let ping = Command::new("ip")
            .args(ping_args(source_netns, target_address))
            .output()?;
        last_ping = format!(
            "{}{}",
            String::from_utf8_lossy(&ping.stdout),
            String::from_utf8_lossy(&ping.stderr)
        );

        let rust_learned_c = fs::read_to_string(rust_host_file)
            .map(|contents| contents.contains(&format!("Ed25519PublicKey = {c_public_key}")))
            .unwrap_or(false);
        let c_learned_rust = fs::read_to_string(c_host_file)
            .map(|contents| contents.contains(&format!("Ed25519PublicKey = {rust_public_key}")))
            .unwrap_or(false);
        let c_preemptive_request = cleanup
            .logs()
            .contains("Preemptively requesting Ed25519 key for alpha");
        if rust_learned_c && c_learned_rust && c_preemptive_request {
            return Ok(());
        }

        thread::sleep(Duration::from_millis(200));
    }

    Err(format!(
        "timed out waiting for C/Rust REQ_PUBKEY/ANS_PUBKEY exchange\nlast ping:\n{last_ping}\nrust host file {}:\n{}\nC host file {}:\n{}\n{}",
        rust_host_file.display(),
        fs::read_to_string(rust_host_file).unwrap_or_else(|error| format!("<read failed: {error}>")),
        c_host_file.display(),
        fs::read_to_string(c_host_file).unwrap_or_else(|error| format!("<read failed: {error}>")),
        cleanup.logs()
    )
    .into())
}

fn wait_for_ping(
    source_netns: &str,
    target_address: &str,
    cleanup: &NetnsCleanup,
) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut last_ping = String::new();
    while Instant::now() < deadline {
        cleanup.ensure_children_alive()?;
        let ping = Command::new("ip")
            .args(ping_args(source_netns, target_address))
            .output()?;
        if ping.status.success() {
            return Ok(());
        }
        last_ping = format!(
            "{}{}",
            String::from_utf8_lossy(&ping.stdout),
            String::from_utf8_lossy(&ping.stderr)
        );
        thread::sleep(Duration::from_millis(200));
    }

    Err(format!(
        "netns tincd ping from {source_netns} to {target_address} failed\nlast ping:\n{last_ping}\n{}",
        cleanup.diagnostics()
    )
    .into())
}

fn wait_for_no_ping(
    source_netns: &str,
    target_address: &str,
    cleanup: &NetnsCleanup,
) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + Duration::from_secs(8);
    let mut successful = 0;

    while Instant::now() < deadline {
        cleanup.ensure_children_alive()?;
        let ping = Command::new("ip")
            .args(ping_args(source_netns, target_address))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;
        if ping.success() {
            successful += 1;
        }
        thread::sleep(Duration::from_millis(200));
    }

    if successful == 0 {
        Ok(())
    } else {
        Err(format!(
            "expected ping from {source_netns} to {target_address} to fail after link cut, but {successful} attempts succeeded\n{}",
            cleanup.diagnostics()
        )
        .into())
    }
}

fn wait_for_no_ping_quick(
    source_netns: &str,
    target_address: &str,
    cleanup: &NetnsCleanup,
) -> Result<(), Box<dyn Error>> {
    let attempts = 2;
    let mut successful = 0;

    for _ in 0..attempts {
        cleanup.ensure_children_alive()?;
        let ping = Command::new("ip")
            .args(ping_args(source_netns, target_address))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;
        if ping.success() {
            successful += 1;
        }
        thread::sleep(Duration::from_millis(200));
    }

    if successful == 0 {
        Ok(())
    } else {
        Err(format!(
            "expected ping from {source_netns} to {target_address} to fail, but {successful} of {attempts} attempts succeeded\n{}",
            cleanup.diagnostics()
        )
        .into())
    }
}

fn wait_for_no_ping_maybe_quick(
    source_netns: &str,
    target_address: &str,
    cleanup: &NetnsCleanup,
    quick: bool,
) -> Result<(), Box<dyn Error>> {
    if quick {
        wait_for_no_ping_quick(source_netns, target_address, cleanup)
    } else {
        wait_for_no_ping(source_netns, target_address, cleanup)
    }
}

fn expect_single_ping_failure(
    source_netns: &str,
    target_address: &str,
    cleanup: &NetnsCleanup,
) -> Result<(), Box<dyn Error>> {
    cleanup.ensure_children_alive()?;
    let ping = Command::new("ip")
        .args(ping_args(source_netns, target_address))
        .output()?;
    if !ping.status.success() {
        return Ok(());
    }

    Err(format!(
        "expected one ping from {source_netns} to {target_address} to fail while underlay link was down\nstdout:\n{}\nstderr:\n{}\n{}",
        String::from_utf8_lossy(&ping.stdout),
        String::from_utf8_lossy(&ping.stderr),
        cleanup.diagnostics()
    )
    .into())
}

fn assert_underlay_ping_payload_not_plaintext(
    source_netns: &str,
    underlay_interface: &str,
    target_address: &str,
    label: &str,
    capture: NoPlaintextCapture,
    cleanup: &NetnsCleanup,
) -> Result<(), Box<dyn Error>> {
    assert_underlay_ping_payload_not_plaintext_from(
        source_netns,
        underlay_interface,
        source_netns,
        target_address,
        label,
        capture,
        true,
        true,
        cleanup,
    )
    .map(|_| ())
}

fn assert_relay_underlay_ping_payload_not_plaintext(
    capture_netns: &str,
    underlay_interface: &str,
    ping_source_netns: &str,
    target_address: &str,
    label: &str,
    capture: NoPlaintextCapture,
    cleanup: &NetnsCleanup,
) -> Result<(), Box<dyn Error>> {
    assert_underlay_ping_payload_not_plaintext_from(
        capture_netns,
        underlay_interface,
        ping_source_netns,
        target_address,
        label,
        capture,
        true,
        true,
        cleanup,
    )
    .map(|_| ())
}

fn assert_underlay_ping_attempt_payload_not_plaintext(
    source_netns: &str,
    underlay_interface: &str,
    target_address: &str,
    label: &str,
    capture: NoPlaintextCapture,
    cleanup: &NetnsCleanup,
) -> Result<String, Box<dyn Error>> {
    assert_underlay_ping_payload_not_plaintext_from(
        source_netns,
        underlay_interface,
        source_netns,
        target_address,
        label,
        capture,
        false,
        true,
        cleanup,
    )
}

fn assert_underlay_ping_attempt_payload_not_plaintext_allow_empty(
    source_netns: &str,
    underlay_interface: &str,
    target_address: &str,
    label: &str,
    capture: NoPlaintextCapture,
    cleanup: &NetnsCleanup,
) -> Result<String, Box<dyn Error>> {
    assert_underlay_ping_payload_not_plaintext_from(
        source_netns,
        underlay_interface,
        source_netns,
        target_address,
        label,
        capture,
        false,
        false,
        cleanup,
    )
}

fn assert_underlay_ping_payload_not_plaintext_from(
    capture_netns: &str,
    underlay_interface: &str,
    ping_source_netns: &str,
    target_address: &str,
    label: &str,
    capture: NoPlaintextCapture,
    require_ping_success: bool,
    require_underlay_packets: bool,
    cleanup: &NetnsCleanup,
) -> Result<String, Box<dyn Error>> {
    cleanup.ensure_children_alive()?;
    let payload = format!("tnp-{}", unique_suffix());
    let pcap = cleanup.workspace.join(format!(
        "underlay-no-plain-{}-{}.pcap",
        underlay_interface,
        unique_suffix()
    ));
    let filter = match capture {
        NoPlaintextCapture::Tcp => "tcp",
        NoPlaintextCapture::TcpAndUdp => "tcp or udp",
        NoPlaintextCapture::Udp => "udp",
    };
    let mut tcpdump = Command::new("ip")
        .args([
            "netns",
            "exec",
            capture_netns,
            "tcpdump",
            "-i",
            "any",
            "-U",
            "-s",
            "0",
            "-c",
            "40",
            "-w",
        ])
        .arg(&pcap)
        .arg(filter)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    thread::sleep(Duration::from_millis(300));
    let ping = Command::new("ip")
        .args([
            "netns",
            "exec",
            ping_source_netns,
            "ping",
            if target_address.contains(':') {
                "-6"
            } else {
                "-4"
            },
            "-c",
            "3",
            "-W",
            "1",
            "-p",
            &hex_payload(&payload),
            target_address,
        ])
        .output()?;
    let _ = tcpdump.kill();
    let _ = tcpdump.wait();
    if require_ping_success && !ping.status.success() {
        return Err(format!(
            "{label} plaintext-leak probe ping from {ping_source_netns} to {target_address} failed\nstdout:\n{}\nstderr:\n{}\n{}",
            String::from_utf8_lossy(&ping.stdout),
            String::from_utf8_lossy(&ping.stderr),
            cleanup.diagnostics()
        )
        .into());
    }

    let capture_bytes = fs::read(&pcap).map_err(|error| {
        format!(
            "{label} could not read underlay tcpdump capture {}: {error}\n{}",
            pcap.display(),
            cleanup.logs()
        )
    })?;
    if require_underlay_packets {
        assert!(
            pcap_record_count(&capture_bytes) > 0,
            "{label} underlay tcpdump capture {} did not contain any packets, so the no-plaintext gate did not observe the selected data path\n{}",
            pcap.display(),
            cleanup.logs()
        );
    }
    assert!(
        !contains_subslice(&capture_bytes, payload.as_bytes()),
        "{label} leaked the inner ping payload in underlay capture {}; this would violate tinc's encrypted underlay data path semantics\n{}",
        pcap.display(),
        cleanup.logs()
    );

    Ok(payload)
}

fn assert_underlay_ping_uses_udp_without_tcp_data_fallback(
    capture_netns: &str,
    underlay_interface: &str,
    ping_source_netns: &str,
    target_address: &str,
    peer_port: u16,
    label: &str,
    cleanup: &NetnsCleanup,
) -> Result<(), Box<dyn Error>> {
    cleanup.ensure_children_alive()?;
    let payload = format!("udp-{}", unique_suffix());
    let udp_pcap = cleanup.workspace.join(format!(
        "underlay-udp-no-tcp-{}-{}.pcap",
        underlay_interface,
        unique_suffix()
    ));
    let tcp_pcap = cleanup.workspace.join(format!(
        "underlay-tcp-no-fallback-{}-{}.pcap",
        underlay_interface,
        unique_suffix()
    ));
    let udp_filter = format!("udp and port {peer_port} and greater 180");
    let mut udp_tcpdump = Command::new("ip")
        .args([
            "netns",
            "exec",
            capture_netns,
            "tcpdump",
            "-i",
            underlay_interface,
            "-U",
            "-s",
            "0",
            "-c",
            "20",
            "-w",
        ])
        .arg(&udp_pcap)
        .arg(&udp_filter)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let mut tcp_tcpdump = Command::new("ip")
        .args([
            "netns",
            "exec",
            ping_source_netns,
            "tcpdump",
            "-i",
            "any",
            "-U",
            "-s",
            "0",
            "-c",
            "20",
            "-w",
        ])
        .arg(&tcp_pcap)
        .arg("tcp and greater 180")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    thread::sleep(Duration::from_millis(300));
    let tcp_block = TcpOutputBlock::install(ping_source_netns, peer_port)?;
    let ping = Command::new("ip")
        .args([
            "netns",
            "exec",
            ping_source_netns,
            "ping",
            if target_address.contains(':') {
                "-6"
            } else {
                "-4"
            },
            "-c",
            "3",
            "-W",
            "1",
            "-s",
            "256",
            "-p",
            &hex_payload(&payload),
            target_address,
        ])
        .output()?;
    drop(tcp_block);

    stop_tcpdump(&mut udp_tcpdump);
    stop_tcpdump(&mut tcp_tcpdump);

    if !ping.status.success() {
        return Err(format!(
            "{label} post-rediscovery ping from {ping_source_netns} to {target_address} failed\nstdout:\n{}\nstderr:\n{}\n{}",
            String::from_utf8_lossy(&ping.stdout),
            String::from_utf8_lossy(&ping.stderr),
            cleanup.diagnostics()
        )
        .into());
    }

    let udp_capture = fs::read(&udp_pcap).map_err(|error| {
        format!(
            "{label} could not read underlay UDP tcpdump capture {}: {error}\n{}",
            udp_pcap.display(),
            cleanup.logs()
        )
    })?;
    let tcp_capture = fs::read(&tcp_pcap).map_err(|error| {
        format!(
            "{label} could not read underlay TCP tcpdump capture {}: {error}\n{}",
            tcp_pcap.display(),
            cleanup.logs()
        )
    })?;

    assert!(
        pcap_record_count(&udp_capture) > 0,
        "{label} underlay UDP capture {} did not contain data packets to tinc port {peer_port}; post-rediscovery ping was not proven to use UDP\n{}",
        udp_pcap.display(),
        cleanup.logs()
    );
    assert!(
        !contains_subslice(&udp_capture, payload.as_bytes()),
        "{label} leaked the inner ping payload in UDP underlay capture {}; this would violate tinc's encrypted UDP data path semantics\n{}",
        udp_pcap.display(),
        cleanup.logs()
    );
    assert!(
        !contains_subslice(&tcp_capture, payload.as_bytes()),
        "{label} sent the post-rediscovery ping payload over TCP fallback in {}; C try_tx() should have restored encrypted UDP before this phase\n{}",
        tcp_pcap.display(),
        cleanup.logs()
    );

    Ok(())
}

struct TcpOutputBlock {
    netns: String,
    peer_port: u16,
}

impl TcpOutputBlock {
    fn install(netns: &str, peer_port: u16) -> Result<Self, Box<dyn Error>> {
        run_iptables_in_netns(
            netns,
            &[
                "-I",
                "OUTPUT",
                "1",
                "-p",
                "tcp",
                "--dport",
                &peer_port.to_string(),
                "-j",
                "DROP",
            ],
        )?;
        Ok(Self {
            netns: netns.to_owned(),
            peer_port,
        })
    }
}

impl Drop for TcpOutputBlock {
    fn drop(&mut self) {
        let _ = run_iptables_in_netns(
            &self.netns,
            &[
                "-D",
                "OUTPUT",
                "-p",
                "tcp",
                "--dport",
                &self.peer_port.to_string(),
                "-j",
                "DROP",
            ],
        );
    }
}

fn run_iptables_in_netns(netns: &str, args: &[&str]) -> Result<(), Box<dyn Error>> {
    let output = Command::new("ip")
        .args(["netns", "exec", netns, "iptables"])
        .args(args)
        .output()?;
    if output.status.success() {
        return Ok(());
    }

    Err(format!(
        "ip netns exec {netns} iptables {} failed\nstdout:\n{}\nstderr:\n{}",
        args.join(" "),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
    .into())
}

fn wait_for_underlay_single_ping_uses_udp_without_tcp_data_fallback(
    capture_netns: &str,
    underlay_interface: &str,
    ping_source_netns: &str,
    target_address: &str,
    peer_port: u16,
    label: &str,
    cleanup: &NetnsCleanup,
) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut last_error = String::new();

    while Instant::now() < deadline {
        cleanup.ensure_children_alive()?;
        match assert_underlay_ping_uses_udp_without_tcp_data_fallback(
            capture_netns,
            underlay_interface,
            ping_source_netns,
            target_address,
            peer_port,
            label,
            cleanup,
        ) {
            Ok(()) => return Ok(()),
            Err(error) => last_error = error.to_string(),
        }
        thread::sleep(Duration::from_millis(200));
    }

    Err(format!(
        "timed out waiting for {label} to use UDP without carrying the test payload over TCP fallback to tinc port {peer_port}\nlast error:\n{last_error}\n{}",
        cleanup.logs()
    )
    .into())
}

fn spawn_udp_probe_tcpdump(
    capture_netns: &str,
    underlay_interface: &str,
    peer_port: u16,
    pcap: &Path,
) -> Result<Child, Box<dyn Error>> {
    let filter = format!("udp and port {peer_port}");
    Ok(Command::new("ip")
        .args([
            "netns",
            "exec",
            capture_netns,
            "tcpdump",
            "-i",
            underlay_interface,
            "-U",
            "-s",
            "0",
            "-c",
            "10",
            "-w",
        ])
        .arg(pcap)
        .arg(&filter)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?)
}

fn finish_tcpdump_capture(
    tcpdump: &mut Child,
    pcap: &Path,
    label: &str,
    cleanup: &NetnsCleanup,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        if tcpdump.try_wait()?.is_some() {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    stop_tcpdump(tcpdump);

    fs::read(pcap).map_err(|error| {
        format!(
            "{label} could not read tcpdump capture {}: {error}\n{}",
            pcap.display(),
            cleanup.logs()
        )
        .into()
    })
}

fn stop_tcpdump(tcpdump: &mut Child) {
    if matches!(tcpdump.try_wait(), Ok(None)) {
        let _ = unsafe { libc::kill(tcpdump.id() as libc::pid_t, libc::SIGINT) };
        let sigint_deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < sigint_deadline {
            if !matches!(tcpdump.try_wait(), Ok(None)) {
                break;
            }
            thread::sleep(Duration::from_millis(50));
        }
    }
    if matches!(tcpdump.try_wait(), Ok(None)) {
        let _ = tcpdump.kill();
        let _ = tcpdump.wait();
    }
}

fn pcap_record_count(capture: &[u8]) -> usize {
    if capture.len() < 24 {
        return 0;
    }

    let mut offset = 24;
    let mut records = 0;
    while offset + 16 <= capture.len() {
        let Ok(included) = capture[offset + 8..offset + 12].try_into() else {
            break;
        };
        let included = u32::from_ne_bytes(included) as usize;
        let next = offset + 16 + included;
        if next > capture.len() {
            break;
        }
        records += 1;
        offset = next;
    }
    records
}

fn hex_payload(payload: &str) -> String {
    payload
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn wait_for_arping(
    source_netns: &str,
    interface: &str,
    target_address: &str,
    cleanup: &NetnsCleanup,
) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut last_arping = String::new();

    while Instant::now() < deadline {
        cleanup.ensure_children_alive()?;
        let arping = Command::new("ip")
            .args([
                "netns",
                "exec",
                source_netns,
                "arping",
                "-I",
                interface,
                "-c",
                "1",
                "-w",
                "1",
                target_address,
            ])
            .output()?;
        if arping.status.success() {
            return Ok(());
        }
        last_arping = format!(
            "{}{}",
            String::from_utf8_lossy(&arping.stdout),
            String::from_utf8_lossy(&arping.stderr)
        );
        thread::sleep(Duration::from_millis(200));
    }

    Err(format!(
        "tap arping from {source_netns} to {target_address} on {interface} failed\nlast arping:\n{last_arping}\n{}",
        cleanup.diagnostics()
    )
    .into())
}

fn ping_args<'a>(source_netns: &'a str, target_address: &'a str) -> Vec<&'a str> {
    let mut args = vec!["netns", "exec", source_netns, "ping"];
    args.push(if target_address.contains(':') {
        "-6"
    } else {
        "-4"
    });
    args.extend(["-c", "1", "-W", "1", target_address]);
    args
}

fn trigger_ping_without_wait(
    source_netns: &str,
    target_address: &str,
) -> Result<(), Box<dyn Error>> {
    let mut command = Command::new("ip");
    command.args(ping_args(source_netns, target_address));
    command
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    Ok(())
}

fn trigger_large_ping_for_emsgsize(
    source_netns: &str,
    target_address: &str,
    cleanup: &NetnsCleanup,
) -> Result<(), Box<dyn Error>> {
    cleanup.ensure_children_alive()?;
    let ping = Command::new("ip")
        .args([
            "netns",
            "exec",
            source_netns,
            "ping",
            if target_address.contains(':') {
                "-6"
            } else {
                "-4"
            },
            "-c",
            "1",
            "-W",
            "1",
            "-s",
            "860",
            target_address,
        ])
        .output()?;
    if !ping.status.success() {
        cleanup.ensure_children_alive()?;
    }
    Ok(())
}

fn wait_for_pair_pings(nodes: &[LinkNode], cleanup: &NetnsCleanup) -> Result<(), Box<dyn Error>> {
    wait_for_pair_pings_for_family(nodes, NetnsAddressFamily::Ipv4, cleanup)
}

fn wait_for_pair_ipv6_pings(
    nodes: &[LinkNode],
    cleanup: &NetnsCleanup,
) -> Result<(), Box<dyn Error>> {
    wait_for_pair_pings_for_family(nodes, NetnsAddressFamily::Ipv6, cleanup)
}

fn wait_for_pair_pings_for_family(
    nodes: &[LinkNode],
    family: NetnsAddressFamily,
    cleanup: &NetnsCleanup,
) -> Result<(), Box<dyn Error>> {
    for (source, target) in [(0, 1), (2, 3), (4, 5)] {
        wait_for_ping(
            &nodes[source].namespace,
            nodes[target].tunnel_address(family),
            cleanup,
        )?;
    }
    Ok(())
}

fn run_iperf3_pairs_concurrently(
    nodes: &[LinkNode],
    modes: &[Iperf3Mode],
    family: NetnsAddressFamily,
    cleanup: &NetnsCleanup,
) -> Result<(), Box<dyn Error>> {
    cleanup.ensure_children_alive()?;
    let pairs = [(0, 1), (2, 3), (4, 5)];
    let mut servers = Vec::new();

    for mode in modes {
        for (_, target) in pairs {
            let mut args = vec![
                "netns",
                "exec",
                nodes[target].namespace.as_str(),
                "iperf3",
                "-s",
                "-1",
                "-p",
                mode.port(),
            ];
            args.push(match family {
                NetnsAddressFamily::Ipv4 => "-4",
                NetnsAddressFamily::Ipv6 => "-6",
            });
            servers.push((
                *mode,
                target,
                Command::new("ip")
                    .args(&args)
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()?,
            ));
        }
    }

    thread::sleep(Duration::from_millis(500));
    cleanup.ensure_children_alive()?;

    let mut clients = Vec::new();
    for mode in modes {
        for (source, target) in pairs {
            let mut args = vec![
                "netns",
                "exec",
                nodes[source].namespace.as_str(),
                "iperf3",
                "-c",
                nodes[target].tunnel_address(family),
                "-p",
                mode.port(),
                "-f",
                "m",
            ];
            args.push(match family {
                NetnsAddressFamily::Ipv4 => "-4",
                NetnsAddressFamily::Ipv6 => "-6",
            });
            if *mode == Iperf3Mode::Udp {
                args.extend(["-u", "-b", "1G", "-t", "2"]);
            } else {
                args.extend(["-t", "2"]);
            }
            clients.push((
                *mode,
                source,
                target,
                Command::new("ip")
                    .args(&args)
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()?,
            ));
        }
    }

    let mut client_outputs = Vec::new();
    for (mode, source, target, client) in clients {
        let (completed, output) = wait_with_output_timeout(client, Duration::from_secs(30))?;
        client_outputs.push((mode, source, target, completed, output));
    }

    let mut server_outputs = Vec::new();
    for (mode, target, mut server) in servers {
        let _ = server.kill();
        server_outputs.push((mode, target, server.wait_with_output()?));
    }

    cleanup.ensure_children_alive()?;

    let mut failures = Vec::new();
    for (mode, source, target, completed, output) in client_outputs {
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        if !(completed && output.status.success() && text.contains("bits/sec")) {
            failures.push(format!(
                "{} {} client {} -> {} {}:\n{text}",
                family.label(),
                mode.label(),
                nodes[source].name,
                nodes[target].name,
                if completed { "failed" } else { "timed out" }
            ));
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        let server_text = server_outputs
            .into_iter()
            .map(|(mode, target, output)| {
                format!(
                    "{} {} server {}:\n{}{}",
                    family.label(),
                    mode.label(),
                    nodes[target].name,
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        Err(format!(
            "concurrent iperf3 pairs failed\n{}\n{}\n{}",
            failures.join("\n"),
            server_text,
            cleanup.diagnostics()
        )
        .into())
    }
}

fn wait_with_output_timeout(
    mut child: Child,
    timeout: Duration,
) -> Result<(bool, std::process::Output), Box<dyn Error>> {
    let deadline = Instant::now() + timeout;
    loop {
        if child.try_wait()?.is_some() {
            return Ok((true, child.wait_with_output()?));
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            return Ok((false, child.wait_with_output()?));
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn assert_rust_tincctl_log_from_c_daemon(
    log_output: &str,
    subscriber: &str,
    cleanup: &NetnsCleanup,
) -> Result<(), Box<dyn Error>> {
    if log_output.contains("Connection from")
        || log_output.contains("Got ID from")
        || log_output.contains("Closing connection")
    {
        return Ok(());
    }

    Err(format!(
        "{subscriber} Rust tincctl log subscriber did not receive expected C daemon log output:\n{log_output}\n{}",
        cleanup.logs()
    )
    .into())
}

fn wait_for_c_tinc_log_subscriber(
    child: Child,
    subscriber: &str,
    cleanup: &NetnsCleanup,
) -> Result<(bool, std::process::Output), Box<dyn Error>> {
    let (completed, output) = wait_with_output_timeout(child, Duration::from_secs(8))?;
    if !completed {
        return Err(format!(
            "{subscriber} C tinc log subscriber did not exit after daemon stop\nstdout:\n{}\nstderr:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
            cleanup.logs()
        )
        .into());
    }
    if !output.status.success() {
        return Err(format!(
            "{subscriber} C tinc log subscriber failed\nstdout:\n{}\nstderr:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
            cleanup.logs()
        )
        .into());
    }

    Ok((completed, output))
}

fn assert_c_tinc_log_from_rust_daemon(
    output: &std::process::Output,
    subscriber: &str,
    cleanup: &NetnsCleanup,
) -> Result<(), Box<dyn Error>> {
    let log_output = String::from_utf8_lossy(&output.stdout);
    if log_output.contains("Got SIGHUP signal") {
        return Ok(());
    }

    Err(format!(
        "{subscriber} C tinc log subscriber did not receive expected Rust daemon log output:\n{log_output}\n{}",
        cleanup.logs()
    )
    .into())
}

fn wait_for_rust_tincctl_pcap_subscriber(
    receiver: mpsc::Receiver<Result<Vec<u8>, String>>,
    subscriber: &str,
    cleanup: &NetnsCleanup,
) -> Result<Vec<u8>, Box<dyn Error>> {
    wait_for_rust_tincctl_bytes_thread(receiver, Duration::from_secs(8)).map_err(|error| {
        format!(
            "{subscriber} Rust tincctl pcap subscriber against C tincd did not exit cleanly: {error}\n{}",
            cleanup.logs()
        )
        .into()
    })
}

fn wait_for_c_tinc_pcap_subscriber(
    child: Child,
    subscriber: &str,
    cleanup: &NetnsCleanup,
) -> Result<std::process::Output, Box<dyn Error>> {
    let (completed, output) = wait_with_output_timeout(child, Duration::from_secs(8))?;
    if !completed {
        return Err(format!(
            "{subscriber} C tinc pcap subscriber against Rust tincd did not exit after daemon stop\nstdout bytes: {}\nstderr:\n{}\n{}",
            output.stdout.len(),
            String::from_utf8_lossy(&output.stderr),
            cleanup.logs()
        )
        .into());
    }
    if !output.status.success() {
        return Err(format!(
            "{subscriber} C tinc pcap subscriber against Rust tincd failed\nstdout bytes: {}\nstderr:\n{}\n{}",
            output.stdout.len(),
            String::from_utf8_lossy(&output.stderr),
            cleanup.logs()
        )
        .into());
    }

    Ok(output)
}

fn spawn_rust_tincctl_thread(args: &[&str]) -> mpsc::Receiver<Result<String, String>> {
    let args = args.iter().map(|arg| (*arg).to_owned()).collect::<Vec<_>>();
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let result = match run_tincctl(args.clone()) {
            Ok(TincCtlAction::Exit { code: 0, output }) => Ok(output),
            Ok(TincCtlAction::Exit { code, output }) => Err(format!(
                "rust tincctl {} exited with {code}\n{output}",
                args.join(" ")
            )),
            Ok(TincCtlAction::ExitBytes { code, output }) => Err(format!(
                "rust tincctl {} returned bytes with code {code}\n{}",
                args.join(" "),
                String::from_utf8_lossy(&output)
            )),
            Ok(TincCtlAction::Command(command)) => Err(format!(
                "rust tincctl command {} was not implemented",
                command.name
            )),
            Err(error) => Err(format!("rust tincctl {} failed: {error}", args.join(" "))),
        };
        let _ = sender.send(result);
    });
    receiver
}

fn spawn_rust_tincctl_bytes_thread(args: &[&str]) -> mpsc::Receiver<Result<Vec<u8>, String>> {
    let args = args.iter().map(|arg| (*arg).to_owned()).collect::<Vec<_>>();
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let result = match run_tincctl(args.clone()) {
            Ok(TincCtlAction::ExitBytes { code: 0, output }) => Ok(output),
            Ok(TincCtlAction::ExitBytes { code, output }) => Err(format!(
                "rust tincctl {} returned bytes with code {code}\n{}",
                args.join(" "),
                String::from_utf8_lossy(&output)
            )),
            Ok(TincCtlAction::Exit { code, output }) => Err(format!(
                "rust tincctl {} exited with text code {code}\n{output}",
                args.join(" ")
            )),
            Ok(TincCtlAction::Command(command)) => Err(format!(
                "rust tincctl command {} was not implemented",
                command.name
            )),
            Err(error) => Err(format!("rust tincctl {} failed: {error}", args.join(" "))),
        };
        let _ = sender.send(result);
    });
    receiver
}

fn wait_for_rust_tincctl_thread(
    receiver: mpsc::Receiver<Result<String, String>>,
    timeout: Duration,
) -> Result<String, String> {
    match receiver.recv_timeout(timeout) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Timeout) => Err("timed out".to_owned()),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err("thread disconnected".to_owned()),
    }
}

fn wait_for_rust_tincctl_bytes_thread(
    receiver: mpsc::Receiver<Result<Vec<u8>, String>>,
    timeout: Duration,
) -> Result<Vec<u8>, String> {
    match receiver.recv_timeout(timeout) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Timeout) => Err("timed out".to_owned()),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err("thread disconnected".to_owned()),
    }
}

fn spawn_c_tinc_process(
    binary: &Path,
    netns: &str,
    confdir: &Path,
    log: &Path,
    args: &[&str],
) -> Result<Child, Box<dyn Error>> {
    let stderr = File::create(log)?;
    Ok(Command::new("ip")
        .args(["netns", "exec", netns])
        .arg(binary)
        .args(["-c"])
        .arg(confdir)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::from(stderr))
        .spawn()?)
}

fn assert_pcap_packet_count_at_least(
    output: &[u8],
    minimum_packet_len: usize,
    minimum_packet_count: usize,
) {
    assert!(
        output.len() >= 24,
        "pcap output is shorter than the global header: {} bytes",
        output.len()
    );
    assert_eq!(&0xa1b2c3d4u32.to_ne_bytes(), &output[0..4]);
    assert_eq!(&2u16.to_ne_bytes(), &output[4..6]);
    assert_eq!(&4u16.to_ne_bytes(), &output[6..8]);
    assert_eq!(&1u32.to_ne_bytes(), &output[20..24]);

    let mut offset = 24;
    let mut matching_packets = 0;
    while offset + 16 <= output.len() {
        let included = u32::from_ne_bytes(output[offset + 8..offset + 12].try_into().unwrap());
        let original = u32::from_ne_bytes(output[offset + 12..offset + 16].try_into().unwrap());
        let included = included as usize;
        let original = original as usize;
        let packet_start = offset + 16;
        let packet_end = packet_start + included;
        assert!(
            packet_end <= output.len(),
            "pcap packet record at offset {offset} declares {included} bytes past output length {}",
            output.len()
        );
        assert_eq!(included, original);
        if included >= minimum_packet_len {
            matching_packets += 1;
        }
        offset = packet_end;
    }

    assert!(
        matching_packets >= minimum_packet_count,
        "pcap output contains {matching_packets} packets with at least {minimum_packet_len} bytes, expected at least {minimum_packet_count}; total output bytes: {}",
        output.len()
    );
}

const CONTROL_REQUEST: i32 = 18;
const REQ_DUMP_NODES_RAW: i32 = 3;
const REQ_DUMP_EDGES_RAW: i32 = 4;
const REQ_DUMP_SUBNETS_RAW: i32 = 5;
const REQ_DUMP_TRAFFIC_RAW: i32 = 13;
const OPTION_PMTU_DISCOVERY_RAW: u32 = 0x0004;
const OPTION_CLAMP_MSS_RAW: u32 = 0x0008;
const PROTOCOL_MINOR_RAW: u32 = 7 << 24;
const C_DEFAULT_MTU_RAW: i32 = 1518;
const C_JUMBO_MTU_RAW: i32 = 9018;
const STATUS_VALIDKEY: u32 = 1 << 1;
const STATUS_REACHABLE: u32 = 1 << 4;
const STATUS_INDIRECT: u32 = 1 << 5;
const STATUS_SPTPS: u32 = 1 << 6;
const STATUS_UDP_CONFIRMED: u32 = 1 << 7;
const STATUS_VALIDKEY_IN: u32 = 1 << 10;
const CONNECTION_STATUS_CONTROL_RAW: u32 = 1 << 9;
const CONNECTION_STATUS_PCAP_RAW: u32 = 1 << 10;
const CONNECTION_STATUS_LOG_RAW: u32 = 1 << 11;
const CONNECTION_STATUS_INVITATION_RAW: u32 = 1 << 13;
const CONNECTION_STATUS_INVITATION_USED_RAW: u32 = 1 << 14;
const LEGACY_AES_256_CBC_NID: i32 = 427;
const LEGACY_SHA256_NID: i32 = 672;
const LEGACY_MAC_LENGTH: i32 = 4;

#[derive(Clone, Copy)]
struct DirectViewExpectation<'a> {
    local: &'a str,
    peer: &'a str,
    local_host: &'a str,
    local_port: u16,
    local_subnet: &'a str,
    peer_host: &'a str,
    peer_port: u16,
    peer_subnet: &'a str,
}

#[derive(Clone, Debug)]
struct DirectRawDumps {
    alpha: RawControlDumps,
    beta: RawControlDumps,
}

#[derive(Clone, Debug)]
struct RawControlDumps {
    nodes: Vec<RawNodeDump>,
    edges: Vec<RawEdgeDump>,
    subnets: Vec<RawSubnetDump>,
}

#[derive(Clone, Debug)]
struct RawNodeDump {
    name: String,
    id: String,
    host: String,
    port: String,
    cipher: i32,
    digest: i32,
    mac_length: i32,
    compression: i32,
    options: u32,
    status: u32,
    nexthop: String,
    via: String,
    distance: i32,
    pmtu: i32,
    min_mtu: i32,
    max_mtu: i32,
    udp_ping_rtt: i32,
}

#[derive(Clone, Debug)]
struct CliNodeDump {
    name: String,
    id: String,
    host: String,
    port: String,
    cipher: i32,
    digest: i32,
    mac_length: i32,
    compression: i32,
    options: u32,
    status: u32,
    nexthop: String,
    via: String,
    distance: i32,
    pmtu: i32,
    min_mtu: i32,
    max_mtu: i32,
}

#[derive(Clone, Debug)]
struct CliEdgeDump {
    from: String,
    to: String,
    host: String,
    port: String,
    local_host: String,
    local_port: String,
    options: u32,
    weight: i32,
}

#[derive(Clone, Debug)]
struct CliSubnetDump {
    subnet: String,
    owner: String,
}

#[derive(Clone, Debug)]
struct CliConnectionDump {
    name: String,
    host: String,
    port: String,
    options: u32,
    socket: i32,
    status: u32,
}

#[derive(Clone, Debug)]
struct RawEdgeDump {
    from: String,
    to: String,
    host: String,
    port: String,
    local_host: String,
    local_port: String,
    options: u32,
    weight: i32,
}

#[derive(Clone, Debug)]
struct RawSubnetDump {
    subnet: String,
    owner: String,
}

fn direct_raw_dumps(
    alpha_confdir: &Path,
    beta_confdir: &Path,
) -> Result<DirectRawDumps, Box<dyn Error>> {
    let alpha = RawControlDumps::read(alpha_confdir)?;
    let beta = RawControlDumps::read(beta_confdir)?;
    Ok(DirectRawDumps { alpha, beta })
}

impl RawControlDumps {
    fn read(confdir: &Path) -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            nodes: read_raw_nodes(confdir)?,
            edges: read_raw_edges(confdir)?,
            subnets: read_raw_subnets(confdir)?,
        })
    }
}

fn wait_for_modern_dynamic_relay_raw_topology_like_tinc(
    workspace: &TempWorkspace,
    nodes: &[LinkNode],
    links: &[UnderlayLink],
    cleanup: &NetnsCleanup,
) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + Duration::from_secs(8);
    let mut last_error = String::new();

    while Instant::now() < deadline {
        cleanup.ensure_children_alive()?;
        match assert_modern_dynamic_relay_raw_topology_like_tinc(workspace, nodes, links) {
            Ok(()) => return Ok(()),
            Err(error) => last_error = error.to_string(),
        }
        thread::sleep(Duration::from_millis(100));
    }

    Err(format!(
        "timed out waiting for C-style modern dynamic relay raw topology parity\nlast error: {last_error}\n{}",
        cleanup.logs()
    )
    .into())
}

fn wait_for_modern_static_relay_raw_topology_like_tinc(
    workspace: &TempWorkspace,
    nodes: &[LinkNode],
    links: &[UnderlayLink],
    phase: &str,
    cleanup: &NetnsCleanup,
) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut last_error = String::new();

    while Instant::now() < deadline {
        cleanup.ensure_children_alive()?;
        match assert_modern_static_relay_raw_topology_like_tinc(workspace, nodes, links, phase) {
            Ok(()) => return Ok(()),
            Err(error) => last_error = error.to_string(),
        }
        thread::sleep(Duration::from_millis(100));
    }

    Err(format!(
        "timed out waiting for C-style modern static relay raw topology parity {phase}\nlast error: {last_error}\n{}",
        cleanup.logs()
    )
    .into())
}

fn assert_modern_static_relay_raw_topology_like_tinc(
    workspace: &TempWorkspace,
    nodes: &[LinkNode],
    links: &[UnderlayLink],
    phase: &str,
) -> Result<(), Box<dyn Error>> {
    if nodes.len() != 3 || links.len() != 2 {
        return Err(
            "modern static relay topology helper expects exactly 3 nodes and 2 links".into(),
        );
    }

    let alpha = RawControlDumps::read(&workspace.path().join(&nodes[0].name))?;
    let beta = RawControlDumps::read(&workspace.path().join(&nodes[1].name))?;
    let gamma = RawControlDumps::read(&workspace.path().join(&nodes[2].name))?;

    let options = PROTOCOL_MINOR_RAW | OPTION_PMTU_DISCOVERY_RAW | OPTION_CLAMP_MSS_RAW;
    let alpha_name = nodes[0].name.as_str();
    let beta_name = nodes[1].name.as_str();
    let gamma_name = nodes[2].name.as_str();
    let alpha_port = nodes[0].port.to_string();
    let beta_port = nodes[1].port.to_string();
    let gamma_port = nodes[2].port.to_string();
    let alpha_subnet = nodes[0].subnet.as_str();
    let beta_subnet = nodes[1].subnet.as_str();
    let gamma_subnet = nodes[2].subnet.as_str();
    let alpha_host = links[0].a_ip.as_str();
    let beta_alpha_host = links[0].b_ip.as_str();
    let beta_gamma_host = links[1].a_ip.as_str();
    let gamma_host = links[1].b_ip.as_str();

    assert_modern_static_relay_nodes(
        &alpha,
        &format!("modern alpha endpoint view {phase}"),
        &[
            RawNodeExpectation {
                name: alpha_name,
                host: "MYSELF",
                port: alpha_port.as_str(),
                nexthop: alpha_name,
                via: alpha_name,
                distance: 0,
                local: true,
                allow_unspec_host: false,
            },
            RawNodeExpectation {
                name: beta_name,
                host: beta_alpha_host,
                port: beta_port.as_str(),
                nexthop: beta_name,
                via: beta_name,
                distance: 1,
                local: false,
                allow_unspec_host: false,
            },
            RawNodeExpectation {
                name: gamma_name,
                host: gamma_host,
                port: gamma_port.as_str(),
                nexthop: beta_name,
                via: beta_name,
                distance: 2,
                local: false,
                allow_unspec_host: true,
            },
        ],
        options,
    )?;
    assert_static_relay_raw_edges(
        &alpha,
        StaticRelayEdgeExpectation {
            alpha: alpha_name,
            beta: beta_name,
            gamma: gamma_name,
            alpha_host,
            beta_alpha_host,
            beta_gamma_host,
            gamma_host,
            alpha_port: alpha_port.as_str(),
            beta_port: beta_port.as_str(),
            gamma_port: gamma_port.as_str(),
            options,
        },
    )?;
    assert_exact_raw_subnet_owners(
        &alpha,
        "modern alpha endpoint static relay",
        &[
            (alpha_subnet, alpha_name),
            (beta_subnet, beta_name),
            (gamma_subnet, gamma_name),
        ],
    )?;

    assert_modern_static_relay_nodes(
        &beta,
        &format!("modern middle relay view {phase}"),
        &[
            RawNodeExpectation {
                name: alpha_name,
                host: alpha_host,
                port: alpha_port.as_str(),
                nexthop: alpha_name,
                via: alpha_name,
                distance: 1,
                local: false,
                allow_unspec_host: false,
            },
            RawNodeExpectation {
                name: beta_name,
                host: "MYSELF",
                port: beta_port.as_str(),
                nexthop: beta_name,
                via: beta_name,
                distance: 0,
                local: true,
                allow_unspec_host: false,
            },
            RawNodeExpectation {
                name: gamma_name,
                host: gamma_host,
                port: gamma_port.as_str(),
                nexthop: gamma_name,
                via: gamma_name,
                distance: 1,
                local: false,
                allow_unspec_host: false,
            },
        ],
        options,
    )?;
    assert_static_relay_raw_edges(
        &beta,
        StaticRelayEdgeExpectation {
            alpha: alpha_name,
            beta: beta_name,
            gamma: gamma_name,
            alpha_host,
            beta_alpha_host,
            beta_gamma_host,
            gamma_host,
            alpha_port: alpha_port.as_str(),
            beta_port: beta_port.as_str(),
            gamma_port: gamma_port.as_str(),
            options,
        },
    )?;
    assert_exact_raw_subnet_owners(
        &beta,
        "modern middle static relay",
        &[
            (alpha_subnet, alpha_name),
            (beta_subnet, beta_name),
            (gamma_subnet, gamma_name),
        ],
    )?;

    assert_modern_static_relay_nodes(
        &gamma,
        &format!("modern gamma endpoint view {phase}"),
        &[
            RawNodeExpectation {
                name: alpha_name,
                host: alpha_host,
                port: alpha_port.as_str(),
                nexthop: beta_name,
                via: beta_name,
                distance: 2,
                local: false,
                allow_unspec_host: true,
            },
            RawNodeExpectation {
                name: beta_name,
                host: beta_gamma_host,
                port: beta_port.as_str(),
                nexthop: beta_name,
                via: beta_name,
                distance: 1,
                local: false,
                allow_unspec_host: false,
            },
            RawNodeExpectation {
                name: gamma_name,
                host: "MYSELF",
                port: gamma_port.as_str(),
                nexthop: gamma_name,
                via: gamma_name,
                distance: 0,
                local: true,
                allow_unspec_host: false,
            },
        ],
        options,
    )?;
    assert_static_relay_raw_edges(
        &gamma,
        StaticRelayEdgeExpectation {
            alpha: alpha_name,
            beta: beta_name,
            gamma: gamma_name,
            alpha_host,
            beta_alpha_host,
            beta_gamma_host,
            gamma_host,
            alpha_port: alpha_port.as_str(),
            beta_port: beta_port.as_str(),
            gamma_port: gamma_port.as_str(),
            options,
        },
    )?;
    assert_exact_raw_subnet_owners(
        &gamma,
        "modern gamma endpoint static relay",
        &[
            (alpha_subnet, alpha_name),
            (beta_subnet, beta_name),
            (gamma_subnet, gamma_name),
        ],
    )?;

    Ok(())
}

fn assert_modern_dynamic_relay_raw_topology_like_tinc(
    workspace: &TempWorkspace,
    nodes: &[LinkNode],
    links: &[UnderlayLink],
) -> Result<(), Box<dyn Error>> {
    if nodes.len() != 3 || links.len() != 2 {
        return Err(
            "modern dynamic relay topology helper expects exactly 3 nodes and 2 links".into(),
        );
    }

    let alpha = RawControlDumps::read(&workspace.path().join(&nodes[0].name))?;
    let beta = RawControlDumps::read(&workspace.path().join(&nodes[1].name))?;
    let gamma = RawControlDumps::read(&workspace.path().join(&nodes[2].name))?;

    let options = PROTOCOL_MINOR_RAW | OPTION_PMTU_DISCOVERY_RAW | OPTION_CLAMP_MSS_RAW;
    let alpha_name = nodes[0].name.as_str();
    let beta_name = nodes[1].name.as_str();
    let gamma_name = nodes[2].name.as_str();
    let alpha_port = nodes[0].port.to_string();
    let beta_port = nodes[1].port.to_string();
    let gamma_port = nodes[2].port.to_string();
    let alpha_subnet = nodes[0].subnet.as_str();
    let beta_subnet = nodes[1].subnet.as_str();
    let gamma_subnet = nodes[2].subnet.as_str();
    let alpha_host = links[0].a_ip.as_str();
    let beta_alpha_host = links[0].b_ip.as_str();
    let beta_gamma_host = links[1].a_ip.as_str();
    let gamma_host = links[1].b_ip.as_str();

    assert_modern_dynamic_relay_nodes(
        &alpha,
        "alpha endpoint view",
        &[
            RawNodeExpectation {
                name: alpha_name,
                host: "MYSELF",
                port: alpha_port.as_str(),
                nexthop: alpha_name,
                via: alpha_name,
                distance: 0,
                local: true,
                allow_unspec_host: false,
            },
            RawNodeExpectation {
                name: beta_name,
                host: beta_alpha_host,
                port: beta_port.as_str(),
                nexthop: beta_name,
                via: beta_name,
                distance: 1,
                local: false,
                allow_unspec_host: false,
            },
            RawNodeExpectation {
                name: gamma_name,
                host: gamma_host,
                port: gamma_port.as_str(),
                nexthop: beta_name,
                via: gamma_name,
                distance: 2,
                local: false,
                allow_unspec_host: true,
            },
        ],
        options,
    )?;
    assert_dynamic_relay_raw_edges(
        &alpha,
        DynamicRelayEdgeExpectation {
            alpha: alpha_name,
            beta: beta_name,
            gamma: gamma_name,
            alpha_host,
            beta_alpha_host,
            beta_gamma_host,
            gamma_host,
            alpha_port: alpha_port.as_str(),
            beta_port: beta_port.as_str(),
            gamma_port: gamma_port.as_str(),
            options,
        },
    )?;
    assert_dynamic_relay_raw_subnets(
        &alpha,
        &[
            (alpha_subnet, alpha_name),
            (beta_subnet, beta_name),
            (gamma_subnet, gamma_name),
        ],
    )?;

    assert_modern_dynamic_relay_nodes(
        &beta,
        "middle relay view",
        &[
            RawNodeExpectation {
                name: alpha_name,
                host: alpha_host,
                port: alpha_port.as_str(),
                nexthop: alpha_name,
                via: alpha_name,
                distance: 1,
                local: false,
                allow_unspec_host: false,
            },
            RawNodeExpectation {
                name: beta_name,
                host: "MYSELF",
                port: beta_port.as_str(),
                nexthop: beta_name,
                via: beta_name,
                distance: 0,
                local: true,
                allow_unspec_host: false,
            },
            RawNodeExpectation {
                name: gamma_name,
                host: gamma_host,
                port: gamma_port.as_str(),
                nexthop: gamma_name,
                via: gamma_name,
                distance: 1,
                local: false,
                allow_unspec_host: false,
            },
        ],
        options,
    )?;
    assert_dynamic_relay_raw_edges(
        &beta,
        DynamicRelayEdgeExpectation {
            alpha: alpha_name,
            beta: beta_name,
            gamma: gamma_name,
            alpha_host,
            beta_alpha_host,
            beta_gamma_host,
            gamma_host,
            alpha_port: alpha_port.as_str(),
            beta_port: beta_port.as_str(),
            gamma_port: gamma_port.as_str(),
            options,
        },
    )?;
    assert_dynamic_relay_raw_subnets(
        &beta,
        &[
            (alpha_subnet, alpha_name),
            (beta_subnet, beta_name),
            (gamma_subnet, gamma_name),
        ],
    )?;

    assert_modern_dynamic_relay_nodes(
        &gamma,
        "gamma endpoint view",
        &[
            RawNodeExpectation {
                name: alpha_name,
                host: alpha_host,
                port: alpha_port.as_str(),
                nexthop: beta_name,
                via: alpha_name,
                distance: 2,
                local: false,
                allow_unspec_host: true,
            },
            RawNodeExpectation {
                name: beta_name,
                host: beta_gamma_host,
                port: beta_port.as_str(),
                nexthop: beta_name,
                via: beta_name,
                distance: 1,
                local: false,
                allow_unspec_host: false,
            },
            RawNodeExpectation {
                name: gamma_name,
                host: "MYSELF",
                port: gamma_port.as_str(),
                nexthop: gamma_name,
                via: gamma_name,
                distance: 0,
                local: true,
                allow_unspec_host: false,
            },
        ],
        options,
    )?;
    assert_dynamic_relay_raw_edges(
        &gamma,
        DynamicRelayEdgeExpectation {
            alpha: alpha_name,
            beta: beta_name,
            gamma: gamma_name,
            alpha_host,
            beta_alpha_host,
            beta_gamma_host,
            gamma_host,
            alpha_port: alpha_port.as_str(),
            beta_port: beta_port.as_str(),
            gamma_port: gamma_port.as_str(),
            options,
        },
    )?;
    assert_dynamic_relay_raw_subnets(
        &gamma,
        &[
            (alpha_subnet, alpha_name),
            (beta_subnet, beta_name),
            (gamma_subnet, gamma_name),
        ],
    )?;

    Ok(())
}

fn wait_for_modern_tunnel_server_raw_topology_like_tinc(
    workspace: &TempWorkspace,
    nodes: &[LinkNode],
    links: &[UnderlayLink],
    phase: &str,
    cleanup: &NetnsCleanup,
) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut last_error = String::new();

    while Instant::now() < deadline {
        cleanup.ensure_children_alive()?;
        match assert_modern_tunnel_server_raw_topology_like_tinc(workspace, nodes, links, phase) {
            Ok(()) => return Ok(()),
            Err(error) => last_error = error.to_string(),
        }
        thread::sleep(Duration::from_millis(100));
    }

    Err(format!(
        "timed out waiting for C-style modern tunnel-server raw topology parity {phase}\nlast error: {last_error}\n{}",
        cleanup.logs()
    )
    .into())
}

fn assert_modern_tunnel_server_raw_topology_like_tinc(
    workspace: &TempWorkspace,
    nodes: &[LinkNode],
    links: &[UnderlayLink],
    phase: &str,
) -> Result<(), Box<dyn Error>> {
    if nodes.len() != 3 || links.len() != 2 {
        return Err("modern tunnel-server helper expects exactly 3 nodes and 2 links".into());
    }

    let alpha = RawControlDumps::read(&workspace.path().join(&nodes[0].name))?;
    let beta = RawControlDumps::read(&workspace.path().join(&nodes[1].name))?;
    let gamma = RawControlDumps::read(&workspace.path().join(&nodes[2].name))?;

    let alpha_name = nodes[0].name.as_str();
    let beta_name = nodes[1].name.as_str();
    let gamma_name = nodes[2].name.as_str();
    let alpha_port = nodes[0].port.to_string();
    let beta_port = nodes[1].port.to_string();
    let gamma_port = nodes[2].port.to_string();
    let alpha_subnet = nodes[0].subnet.as_str();
    let beta_subnet = nodes[1].subnet.as_str();
    let gamma_subnet = nodes[2].subnet.as_str();
    let alpha_beta_host = links[0].a_ip.as_str();
    let beta_host = links[0].b_ip.as_str();
    let alpha_gamma_host = links[1].a_ip.as_str();
    let gamma_host = links[1].b_ip.as_str();
    let options = PROTOCOL_MINOR_RAW | OPTION_PMTU_DISCOVERY_RAW | OPTION_CLAMP_MSS_RAW;

    assert_modern_tunnel_server_node(
        raw_node(&alpha, alpha_name)?,
        TunnelServerNodeExpectation {
            label: &format!("modern tunnel-server server view {phase}"),
            host: "MYSELF",
            port: alpha_port.as_str(),
            options,
            nexthop: alpha_name,
            via: alpha_name,
            distance: 0,
            local: true,
            expected_status: STATUS_REACHABLE | STATUS_SPTPS,
        },
    )?;
    assert_modern_tunnel_server_node(
        raw_node(&alpha, beta_name)?,
        TunnelServerNodeExpectation {
            label: &format!("modern tunnel-server server view {phase}"),
            host: beta_host,
            port: beta_port.as_str(),
            options,
            nexthop: beta_name,
            via: beta_name,
            distance: 1,
            local: false,
            expected_status: STATUS_VALIDKEY | STATUS_REACHABLE | STATUS_SPTPS,
        },
    )?;
    assert_modern_tunnel_server_node(
        raw_node(&alpha, gamma_name)?,
        TunnelServerNodeExpectation {
            label: &format!("modern tunnel-server server view {phase}"),
            host: gamma_host,
            port: gamma_port.as_str(),
            options,
            nexthop: gamma_name,
            via: gamma_name,
            distance: 1,
            local: false,
            expected_status: STATUS_VALIDKEY | STATUS_REACHABLE | STATUS_SPTPS,
        },
    )?;
    assert_tunnel_server_raw_edges(
        &alpha,
        TunnelServerEdgeExpectation {
            server: alpha_name,
            first_client: beta_name,
            second_client: gamma_name,
            first_client_host: beta_host,
            first_client_port: beta_port.as_str(),
            first_server_host: alpha_beta_host,
            second_client_host: gamma_host,
            second_client_port: gamma_port.as_str(),
            second_server_host: alpha_gamma_host,
            server_port: alpha_port.as_str(),
            options,
            label: &format!("modern tunnel-server server view {phase}"),
        },
    )?;
    assert_exact_raw_subnet_owners(
        &alpha,
        &format!("modern tunnel-server server view {phase}"),
        &[
            (alpha_subnet, alpha_name),
            (beta_subnet, beta_name),
            (gamma_subnet, gamma_name),
        ],
    )?;

    assert_modern_tunnel_server_client_view(
        &beta,
        &format!("modern tunnel-server beta client view {phase}"),
        TunnelServerClientExpectation {
            local: beta_name,
            server: alpha_name,
            other_client: gamma_name,
            local_port: beta_port.as_str(),
            server_host: alpha_beta_host,
            server_port: alpha_port.as_str(),
            local_subnet: beta_subnet,
            server_subnet: alpha_subnet,
            other_subnet: gamma_subnet,
            options,
            require_validkey_in: true,
        },
    )?;
    assert_tunnel_server_single_client_raw_edge(
        &beta,
        alpha_name,
        beta_name,
        beta_host,
        beta_port.as_str(),
        alpha_beta_host,
        alpha_port.as_str(),
        options,
        &format!("modern tunnel-server beta client view {phase}"),
    )?;

    assert_modern_tunnel_server_client_view(
        &gamma,
        &format!("modern tunnel-server gamma client view {phase}"),
        TunnelServerClientExpectation {
            local: gamma_name,
            server: alpha_name,
            other_client: beta_name,
            local_port: gamma_port.as_str(),
            server_host: alpha_gamma_host,
            server_port: alpha_port.as_str(),
            local_subnet: gamma_subnet,
            server_subnet: alpha_subnet,
            other_subnet: beta_subnet,
            options,
            require_validkey_in: true,
        },
    )?;
    assert_tunnel_server_single_client_raw_edge(
        &gamma,
        alpha_name,
        gamma_name,
        gamma_host,
        gamma_port.as_str(),
        alpha_gamma_host,
        alpha_port.as_str(),
        options,
        &format!("modern tunnel-server gamma client view {phase}"),
    )?;

    Ok(())
}

fn wait_for_legacy_tunnel_server_raw_topology_like_tinc(
    workspace: &TempWorkspace,
    nodes: &[LegacyMultihopNode],
    links: &[UnderlayLink],
    phase: &str,
    cleanup: &NetnsCleanup,
) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut last_error = String::new();

    while Instant::now() < deadline {
        cleanup.ensure_children_alive()?;
        match assert_legacy_tunnel_server_raw_topology_like_tinc(
            workspace,
            nodes,
            links,
            phase,
            phase.contains("rekey"),
        ) {
            Ok(()) => return Ok(()),
            Err(error) => last_error = error.to_string(),
        }
        thread::sleep(Duration::from_millis(100));
    }

    Err(format!(
        "timed out waiting for C-style legacy tunnel-server raw topology parity {phase}\nlast error: {last_error}\n{}",
        cleanup.logs()
    )
    .into())
}

fn assert_legacy_tunnel_server_raw_topology_like_tinc(
    workspace: &TempWorkspace,
    nodes: &[LegacyMultihopNode],
    links: &[UnderlayLink],
    phase: &str,
    rekey_phase: bool,
) -> Result<(), Box<dyn Error>> {
    if nodes.len() != 3 || links.len() != 2 {
        return Err("legacy tunnel-server helper expects exactly 3 nodes and 2 links".into());
    }

    let alpha = RawControlDumps::read(&workspace.path().join(nodes[0].name))?;
    let beta = RawControlDumps::read(&workspace.path().join(nodes[1].name))?;
    let gamma = RawControlDumps::read(&workspace.path().join(nodes[2].name))?;

    let alpha_name = nodes[0].name;
    let beta_name = nodes[1].name;
    let gamma_name = nodes[2].name;
    let alpha_port = nodes[0].port.to_string();
    let beta_port = nodes[1].port.to_string();
    let gamma_port = nodes[2].port.to_string();
    let alpha_subnet = nodes[0].subnet;
    let beta_subnet = nodes[1].subnet;
    let gamma_subnet = nodes[2].subnet;
    let alpha_beta_host = links[0].a_ip.as_str();
    let beta_host = links[0].b_ip.as_str();
    let alpha_gamma_host = links[1].a_ip.as_str();
    let gamma_host = links[1].b_ip.as_str();
    let local_options = PROTOCOL_MINOR_RAW | OPTION_PMTU_DISCOVERY_RAW | OPTION_CLAMP_MSS_RAW;
    let peer_options = OPTION_PMTU_DISCOVERY_RAW | OPTION_CLAMP_MSS_RAW;
    let legacy_peer_status = if rekey_phase {
        STATUS_VALIDKEY | STATUS_REACHABLE
    } else {
        STATUS_VALIDKEY | STATUS_REACHABLE | STATUS_UDP_CONFIRMED | STATUS_VALIDKEY_IN
    };

    assert_legacy_tunnel_server_node(
        raw_node(&alpha, alpha_name)?,
        TunnelServerNodeExpectation {
            label: &format!("legacy tunnel-server server view {phase}"),
            host: "MYSELF",
            port: alpha_port.as_str(),
            options: local_options,
            nexthop: alpha_name,
            via: alpha_name,
            distance: 0,
            local: true,
            expected_status: STATUS_REACHABLE,
        },
    )?;
    assert_legacy_tunnel_server_node(
        raw_node(&alpha, beta_name)?,
        TunnelServerNodeExpectation {
            label: &format!("legacy tunnel-server server view {phase}"),
            host: beta_host,
            port: beta_port.as_str(),
            options: peer_options,
            nexthop: beta_name,
            via: beta_name,
            distance: 1,
            local: false,
            expected_status: legacy_peer_status,
        },
    )?;
    assert_legacy_tunnel_server_node(
        raw_node(&alpha, gamma_name)?,
        TunnelServerNodeExpectation {
            label: &format!("legacy tunnel-server server view {phase}"),
            host: gamma_host,
            port: gamma_port.as_str(),
            options: peer_options,
            nexthop: gamma_name,
            via: gamma_name,
            distance: 1,
            local: false,
            expected_status: legacy_peer_status,
        },
    )?;
    assert_tunnel_server_raw_edges(
        &alpha,
        TunnelServerEdgeExpectation {
            server: alpha_name,
            first_client: beta_name,
            second_client: gamma_name,
            first_client_host: beta_host,
            first_client_port: beta_port.as_str(),
            first_server_host: alpha_beta_host,
            second_client_host: gamma_host,
            second_client_port: gamma_port.as_str(),
            second_server_host: alpha_gamma_host,
            server_port: alpha_port.as_str(),
            options: peer_options,
            label: &format!("legacy tunnel-server server view {phase}"),
        },
    )?;
    assert_exact_raw_subnet_owners(
        &alpha,
        &format!("legacy tunnel-server server view {phase}"),
        &[
            (alpha_subnet, alpha_name),
            (beta_subnet, beta_name),
            (gamma_subnet, gamma_name),
        ],
    )?;

    assert_legacy_tunnel_server_client_view(
        &beta,
        &format!("legacy tunnel-server beta client view {phase}"),
        TunnelServerClientExpectation {
            local: beta_name,
            server: alpha_name,
            other_client: gamma_name,
            local_port: beta_port.as_str(),
            server_host: alpha_beta_host,
            server_port: alpha_port.as_str(),
            local_subnet: beta_subnet,
            server_subnet: alpha_subnet,
            other_subnet: gamma_subnet,
            options: peer_options,
            require_validkey_in: !rekey_phase,
        },
    )?;
    assert_tunnel_server_single_client_raw_edge(
        &beta,
        alpha_name,
        beta_name,
        beta_host,
        beta_port.as_str(),
        alpha_beta_host,
        alpha_port.as_str(),
        peer_options,
        &format!("legacy tunnel-server beta client view {phase}"),
    )?;

    assert_legacy_tunnel_server_client_view(
        &gamma,
        &format!("legacy tunnel-server gamma client view {phase}"),
        TunnelServerClientExpectation {
            local: gamma_name,
            server: alpha_name,
            other_client: beta_name,
            local_port: gamma_port.as_str(),
            server_host: alpha_gamma_host,
            server_port: alpha_port.as_str(),
            local_subnet: gamma_subnet,
            server_subnet: alpha_subnet,
            other_subnet: beta_subnet,
            options: peer_options,
            require_validkey_in: !rekey_phase,
        },
    )?;
    assert_tunnel_server_single_client_raw_edge(
        &gamma,
        alpha_name,
        gamma_name,
        gamma_host,
        gamma_port.as_str(),
        alpha_gamma_host,
        alpha_port.as_str(),
        peer_options,
        &format!("legacy tunnel-server gamma client view {phase}"),
    )?;

    Ok(())
}

fn wait_for_legacy_dynamic_relay_raw_topology_like_tinc(
    workspace: &TempWorkspace,
    nodes: &[LegacyMultihopNode],
    links: &[UnderlayLink],
    cleanup: &NetnsCleanup,
) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + Duration::from_secs(8);
    let mut last_error = String::new();

    while Instant::now() < deadline {
        cleanup.ensure_children_alive()?;
        match assert_legacy_dynamic_relay_raw_topology_like_tinc(workspace, nodes, links) {
            Ok(()) => return Ok(()),
            Err(error) => last_error = error.to_string(),
        }
        thread::sleep(Duration::from_millis(100));
    }

    Err(format!(
        "timed out waiting for C-style legacy dynamic relay raw topology parity\nlast error: {last_error}\n{}",
        cleanup.logs()
    )
    .into())
}

fn wait_for_legacy_dynamic_relay_rekey_raw_topology_like_tinc(
    workspace: &TempWorkspace,
    nodes: &[LegacyMultihopNode],
    links: &[UnderlayLink],
    cleanup: &NetnsCleanup,
) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + Duration::from_secs(12);
    let mut last_error = String::new();

    while Instant::now() < deadline {
        cleanup.ensure_children_alive()?;
        match assert_legacy_dynamic_relay_rekey_raw_topology_like_tinc(workspace, nodes, links) {
            Ok(()) => return Ok(()),
            Err(error) => last_error = error.to_string(),
        }
        thread::sleep(Duration::from_millis(200));
    }

    Err(format!(
        "timed out waiting for C-style legacy dynamic relay KeyExpire key-state parity\nlast error: {last_error}\n{}",
        cleanup.diagnostics()
    )
    .into())
}

fn wait_for_legacy_static_relay_raw_topology_like_tinc(
    workspace: &TempWorkspace,
    nodes: &[LegacyMultihopNode],
    links: &[UnderlayLink],
    phase: &str,
    cleanup: &NetnsCleanup,
) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut last_error = String::new();

    while Instant::now() < deadline {
        cleanup.ensure_children_alive()?;
        match assert_legacy_static_relay_raw_topology_like_tinc(workspace, nodes, links, phase) {
            Ok(()) => return Ok(()),
            Err(error) => last_error = error.to_string(),
        }
        thread::sleep(Duration::from_millis(100));
    }

    Err(format!(
        "timed out waiting for C-style legacy static relay raw topology parity {phase}\nlast error: {last_error}\n{}",
        cleanup.logs()
    )
    .into())
}

fn assert_legacy_static_relay_raw_topology_like_tinc(
    workspace: &TempWorkspace,
    nodes: &[LegacyMultihopNode],
    links: &[UnderlayLink],
    phase: &str,
) -> Result<(), Box<dyn Error>> {
    if nodes.len() != 3 || links.len() != 2 {
        return Err(
            "legacy static relay topology helper expects exactly 3 nodes and 2 links".into(),
        );
    }

    let alpha = RawControlDumps::read(&workspace.path().join(nodes[0].name))?;
    let beta = RawControlDumps::read(&workspace.path().join(nodes[1].name))?;
    let gamma = RawControlDumps::read(&workspace.path().join(nodes[2].name))?;

    let options = OPTION_PMTU_DISCOVERY_RAW | OPTION_CLAMP_MSS_RAW;
    let alpha_name = nodes[0].name;
    let beta_name = nodes[1].name;
    let gamma_name = nodes[2].name;
    let alpha_port = nodes[0].port.to_string();
    let beta_port = nodes[1].port.to_string();
    let gamma_port = nodes[2].port.to_string();
    let alpha_subnet = nodes[0].subnet;
    let beta_subnet = nodes[1].subnet;
    let gamma_subnet = nodes[2].subnet;
    let alpha_host = links[0].a_ip.as_str();
    let beta_alpha_host = links[0].b_ip.as_str();
    let beta_gamma_host = links[1].a_ip.as_str();
    let gamma_host = links[1].b_ip.as_str();

    assert_legacy_static_relay_nodes(
        &alpha,
        &format!("legacy alpha endpoint view {phase}"),
        &[
            RawNodeExpectation {
                name: alpha_name,
                host: "MYSELF",
                port: alpha_port.as_str(),
                nexthop: alpha_name,
                via: alpha_name,
                distance: 0,
                local: true,
                allow_unspec_host: false,
            },
            RawNodeExpectation {
                name: beta_name,
                host: beta_alpha_host,
                port: beta_port.as_str(),
                nexthop: beta_name,
                via: beta_name,
                distance: 1,
                local: false,
                allow_unspec_host: false,
            },
            RawNodeExpectation {
                name: gamma_name,
                host: gamma_host,
                port: gamma_port.as_str(),
                nexthop: beta_name,
                via: beta_name,
                distance: 2,
                local: false,
                allow_unspec_host: true,
            },
        ],
    )?;
    assert_static_relay_raw_edges(
        &alpha,
        StaticRelayEdgeExpectation {
            alpha: alpha_name,
            beta: beta_name,
            gamma: gamma_name,
            alpha_host,
            beta_alpha_host,
            beta_gamma_host,
            gamma_host,
            alpha_port: alpha_port.as_str(),
            beta_port: beta_port.as_str(),
            gamma_port: gamma_port.as_str(),
            options,
        },
    )?;
    assert_exact_raw_subnet_owners(
        &alpha,
        "legacy alpha endpoint static relay",
        &[
            (alpha_subnet, alpha_name),
            (beta_subnet, beta_name),
            (gamma_subnet, gamma_name),
        ],
    )?;

    assert_legacy_static_relay_nodes(
        &beta,
        &format!("legacy middle relay view {phase}"),
        &[
            RawNodeExpectation {
                name: alpha_name,
                host: alpha_host,
                port: alpha_port.as_str(),
                nexthop: alpha_name,
                via: alpha_name,
                distance: 1,
                local: false,
                allow_unspec_host: false,
            },
            RawNodeExpectation {
                name: beta_name,
                host: "MYSELF",
                port: beta_port.as_str(),
                nexthop: beta_name,
                via: beta_name,
                distance: 0,
                local: true,
                allow_unspec_host: false,
            },
            RawNodeExpectation {
                name: gamma_name,
                host: gamma_host,
                port: gamma_port.as_str(),
                nexthop: gamma_name,
                via: gamma_name,
                distance: 1,
                local: false,
                allow_unspec_host: false,
            },
        ],
    )?;
    assert_static_relay_raw_edges(
        &beta,
        StaticRelayEdgeExpectation {
            alpha: alpha_name,
            beta: beta_name,
            gamma: gamma_name,
            alpha_host,
            beta_alpha_host,
            beta_gamma_host,
            gamma_host,
            alpha_port: alpha_port.as_str(),
            beta_port: beta_port.as_str(),
            gamma_port: gamma_port.as_str(),
            options,
        },
    )?;
    assert_exact_raw_subnet_owners(
        &beta,
        "legacy middle static relay",
        &[
            (alpha_subnet, alpha_name),
            (beta_subnet, beta_name),
            (gamma_subnet, gamma_name),
        ],
    )?;

    assert_legacy_static_relay_nodes(
        &gamma,
        &format!("legacy gamma endpoint view {phase}"),
        &[
            RawNodeExpectation {
                name: alpha_name,
                host: alpha_host,
                port: alpha_port.as_str(),
                nexthop: beta_name,
                via: beta_name,
                distance: 2,
                local: false,
                allow_unspec_host: true,
            },
            RawNodeExpectation {
                name: beta_name,
                host: beta_gamma_host,
                port: beta_port.as_str(),
                nexthop: beta_name,
                via: beta_name,
                distance: 1,
                local: false,
                allow_unspec_host: false,
            },
            RawNodeExpectation {
                name: gamma_name,
                host: "MYSELF",
                port: gamma_port.as_str(),
                nexthop: gamma_name,
                via: gamma_name,
                distance: 0,
                local: true,
                allow_unspec_host: false,
            },
        ],
    )?;
    assert_static_relay_raw_edges(
        &gamma,
        StaticRelayEdgeExpectation {
            alpha: alpha_name,
            beta: beta_name,
            gamma: gamma_name,
            alpha_host,
            beta_alpha_host,
            beta_gamma_host,
            gamma_host,
            alpha_port: alpha_port.as_str(),
            beta_port: beta_port.as_str(),
            gamma_port: gamma_port.as_str(),
            options,
        },
    )?;
    assert_exact_raw_subnet_owners(
        &gamma,
        "legacy gamma endpoint static relay",
        &[
            (alpha_subnet, alpha_name),
            (beta_subnet, beta_name),
            (gamma_subnet, gamma_name),
        ],
    )?;

    Ok(())
}

fn assert_legacy_dynamic_relay_rekey_raw_topology_like_tinc(
    workspace: &TempWorkspace,
    nodes: &[LegacyMultihopNode],
    links: &[UnderlayLink],
) -> Result<(), Box<dyn Error>> {
    if nodes.len() != 3 || links.len() != 2 {
        return Err("legacy dynamic relay rekey helper expects exactly 3 nodes and 2 links".into());
    }

    let alpha = RawControlDumps::read(&workspace.path().join(nodes[0].name))?;
    let beta = RawControlDumps::read(&workspace.path().join(nodes[1].name))?;
    let gamma = RawControlDumps::read(&workspace.path().join(nodes[2].name))?;

    let alpha_name = nodes[0].name;
    let beta_name = nodes[1].name;
    let gamma_name = nodes[2].name;

    let alpha_from_beta = raw_node(&beta, nodes[0].name)?;
    let gamma_from_beta = raw_node(&beta, nodes[2].name)?;
    for peer in [alpha_from_beta, gamma_from_beta] {
        assert_status_has(
            peer,
            STATUS_VALIDKEY | STATUS_VALIDKEY_IN | STATUS_REACHABLE,
        )?;
        assert_status_lacks(peer, STATUS_SPTPS | STATUS_INDIRECT)?;
        assert_eq!(
            1, peer.distance,
            "legacy dynamic relay middle must only install keys for direct neighbors after KeyExpire, not transit endpoint owner state: {peer:?}"
        );
        assert_eq!(
            peer.name, peer.nexthop,
            "legacy dynamic relay middle next-hop should stay the direct peer after KeyExpire: {peer:?}"
        );
        assert_eq!(
            peer.name, peer.via,
            "legacy dynamic relay middle via should stay the direct peer after KeyExpire: {peer:?}"
        );
    }

    let gamma_from_alpha = raw_node(&alpha, gamma_name)?;
    assert_status_has(
        gamma_from_alpha,
        STATUS_VALIDKEY | STATUS_VALIDKEY_IN | STATUS_REACHABLE,
    )?;
    assert_status_lacks(gamma_from_alpha, STATUS_SPTPS | STATUS_INDIRECT)?;
    assert_eq!(beta_name, gamma_from_alpha.nexthop);
    assert_eq!(gamma_name, gamma_from_alpha.via);
    assert_eq!(2, gamma_from_alpha.distance);

    let alpha_from_gamma = raw_node(&gamma, alpha_name)?;
    assert_status_has(
        alpha_from_gamma,
        STATUS_VALIDKEY | STATUS_VALIDKEY_IN | STATUS_REACHABLE,
    )?;
    assert_status_lacks(alpha_from_gamma, STATUS_SPTPS | STATUS_INDIRECT)?;
    assert_eq!(beta_name, alpha_from_gamma.nexthop);
    assert_eq!(alpha_name, alpha_from_gamma.via);
    assert_eq!(2, alpha_from_gamma.distance);

    assert_dynamic_relay_raw_edges(
        &alpha,
        DynamicRelayEdgeExpectation {
            alpha: alpha_name,
            beta: beta_name,
            gamma: gamma_name,
            alpha_host: links[0].a_ip.as_str(),
            beta_alpha_host: links[0].b_ip.as_str(),
            beta_gamma_host: links[1].a_ip.as_str(),
            gamma_host: links[1].b_ip.as_str(),
            alpha_port: nodes[0].port.to_string().as_str(),
            beta_port: nodes[1].port.to_string().as_str(),
            gamma_port: nodes[2].port.to_string().as_str(),
            options: OPTION_PMTU_DISCOVERY_RAW | OPTION_CLAMP_MSS_RAW,
        },
    )?;

    Ok(())
}

fn assert_legacy_dynamic_relay_raw_topology_like_tinc(
    workspace: &TempWorkspace,
    nodes: &[LegacyMultihopNode],
    links: &[UnderlayLink],
) -> Result<(), Box<dyn Error>> {
    if nodes.len() != 3 || links.len() != 2 {
        return Err(
            "legacy dynamic relay topology helper expects exactly 3 nodes and 2 links".into(),
        );
    }

    let alpha = RawControlDumps::read(&workspace.path().join(nodes[0].name))?;
    let beta = RawControlDumps::read(&workspace.path().join(nodes[1].name))?;
    let gamma = RawControlDumps::read(&workspace.path().join(nodes[2].name))?;

    let options = OPTION_PMTU_DISCOVERY_RAW | OPTION_CLAMP_MSS_RAW;
    let alpha_name = nodes[0].name;
    let beta_name = nodes[1].name;
    let gamma_name = nodes[2].name;
    let alpha_port = nodes[0].port.to_string();
    let beta_port = nodes[1].port.to_string();
    let gamma_port = nodes[2].port.to_string();
    let alpha_subnet = nodes[0].subnet;
    let beta_subnet = nodes[1].subnet;
    let gamma_subnet = nodes[2].subnet;
    let alpha_host = links[0].a_ip.as_str();
    let beta_alpha_host = links[0].b_ip.as_str();
    let beta_gamma_host = links[1].a_ip.as_str();
    let gamma_host = links[1].b_ip.as_str();

    assert_legacy_dynamic_relay_nodes(
        &alpha,
        "legacy alpha endpoint view",
        &[
            RawNodeExpectation {
                name: alpha_name,
                host: "MYSELF",
                port: alpha_port.as_str(),
                nexthop: alpha_name,
                via: alpha_name,
                distance: 0,
                local: true,
                allow_unspec_host: false,
            },
            RawNodeExpectation {
                name: beta_name,
                host: beta_alpha_host,
                port: beta_port.as_str(),
                nexthop: beta_name,
                via: beta_name,
                distance: 1,
                local: false,
                allow_unspec_host: false,
            },
            RawNodeExpectation {
                name: gamma_name,
                host: gamma_host,
                port: gamma_port.as_str(),
                nexthop: beta_name,
                via: gamma_name,
                distance: 2,
                local: false,
                allow_unspec_host: true,
            },
        ],
        LegacyDynamicViewRole::Endpoint,
    )?;
    assert_dynamic_relay_raw_edges(
        &alpha,
        DynamicRelayEdgeExpectation {
            alpha: alpha_name,
            beta: beta_name,
            gamma: gamma_name,
            alpha_host,
            beta_alpha_host,
            beta_gamma_host,
            gamma_host,
            alpha_port: alpha_port.as_str(),
            beta_port: beta_port.as_str(),
            gamma_port: gamma_port.as_str(),
            options,
        },
    )?;
    assert_dynamic_relay_raw_subnets(
        &alpha,
        &[
            (alpha_subnet, alpha_name),
            (beta_subnet, beta_name),
            (gamma_subnet, gamma_name),
        ],
    )?;

    assert_legacy_dynamic_relay_nodes(
        &beta,
        "legacy middle relay view",
        &[
            RawNodeExpectation {
                name: alpha_name,
                host: alpha_host,
                port: alpha_port.as_str(),
                nexthop: alpha_name,
                via: alpha_name,
                distance: 1,
                local: false,
                allow_unspec_host: false,
            },
            RawNodeExpectation {
                name: beta_name,
                host: "MYSELF",
                port: beta_port.as_str(),
                nexthop: beta_name,
                via: beta_name,
                distance: 0,
                local: true,
                allow_unspec_host: false,
            },
            RawNodeExpectation {
                name: gamma_name,
                host: gamma_host,
                port: gamma_port.as_str(),
                nexthop: gamma_name,
                via: gamma_name,
                distance: 1,
                local: false,
                allow_unspec_host: false,
            },
        ],
        LegacyDynamicViewRole::Middle,
    )?;
    assert_dynamic_relay_raw_edges(
        &beta,
        DynamicRelayEdgeExpectation {
            alpha: alpha_name,
            beta: beta_name,
            gamma: gamma_name,
            alpha_host,
            beta_alpha_host,
            beta_gamma_host,
            gamma_host,
            alpha_port: alpha_port.as_str(),
            beta_port: beta_port.as_str(),
            gamma_port: gamma_port.as_str(),
            options,
        },
    )?;
    assert_dynamic_relay_raw_subnets(
        &beta,
        &[
            (alpha_subnet, alpha_name),
            (beta_subnet, beta_name),
            (gamma_subnet, gamma_name),
        ],
    )?;

    assert_legacy_dynamic_relay_nodes(
        &gamma,
        "legacy gamma endpoint view",
        &[
            RawNodeExpectation {
                name: alpha_name,
                host: alpha_host,
                port: alpha_port.as_str(),
                nexthop: beta_name,
                via: alpha_name,
                distance: 2,
                local: false,
                allow_unspec_host: true,
            },
            RawNodeExpectation {
                name: beta_name,
                host: beta_gamma_host,
                port: beta_port.as_str(),
                nexthop: beta_name,
                via: beta_name,
                distance: 1,
                local: false,
                allow_unspec_host: false,
            },
            RawNodeExpectation {
                name: gamma_name,
                host: "MYSELF",
                port: gamma_port.as_str(),
                nexthop: gamma_name,
                via: gamma_name,
                distance: 0,
                local: true,
                allow_unspec_host: false,
            },
        ],
        LegacyDynamicViewRole::Endpoint,
    )?;
    assert_dynamic_relay_raw_edges(
        &gamma,
        DynamicRelayEdgeExpectation {
            alpha: alpha_name,
            beta: beta_name,
            gamma: gamma_name,
            alpha_host,
            beta_alpha_host,
            beta_gamma_host,
            gamma_host,
            alpha_port: alpha_port.as_str(),
            beta_port: beta_port.as_str(),
            gamma_port: gamma_port.as_str(),
            options,
        },
    )?;
    assert_dynamic_relay_raw_subnets(
        &gamma,
        &[
            (alpha_subnet, alpha_name),
            (beta_subnet, beta_name),
            (gamma_subnet, gamma_name),
        ],
    )?;

    Ok(())
}

struct RawNodeExpectation<'a> {
    name: &'a str,
    host: &'a str,
    port: &'a str,
    nexthop: &'a str,
    via: &'a str,
    distance: i32,
    local: bool,
    allow_unspec_host: bool,
}

struct TunnelServerNodeExpectation<'a> {
    label: &'a str,
    host: &'a str,
    port: &'a str,
    options: u32,
    nexthop: &'a str,
    via: &'a str,
    distance: i32,
    local: bool,
    expected_status: u32,
}

struct TunnelServerClientExpectation<'a> {
    local: &'a str,
    server: &'a str,
    other_client: &'a str,
    local_port: &'a str,
    server_host: &'a str,
    server_port: &'a str,
    local_subnet: &'a str,
    server_subnet: &'a str,
    other_subnet: &'a str,
    options: u32,
    require_validkey_in: bool,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum LegacyDynamicViewRole {
    Endpoint,
    Middle,
}

fn assert_modern_tunnel_server_client_view(
    dumps: &RawControlDumps,
    label: &str,
    expected: TunnelServerClientExpectation<'_>,
) -> Result<(), Box<dyn Error>> {
    assert_modern_tunnel_server_node(
        raw_node(dumps, expected.local)?,
        TunnelServerNodeExpectation {
            label,
            host: "MYSELF",
            port: expected.local_port,
            options: PROTOCOL_MINOR_RAW | OPTION_PMTU_DISCOVERY_RAW | OPTION_CLAMP_MSS_RAW,
            nexthop: expected.local,
            via: expected.local,
            distance: 0,
            local: true,
            expected_status: STATUS_REACHABLE | STATUS_SPTPS,
        },
    )?;
    assert_modern_tunnel_server_node(
        raw_node(dumps, expected.server)?,
        TunnelServerNodeExpectation {
            label,
            host: expected.server_host,
            port: expected.server_port,
            options: expected.options,
            nexthop: expected.server,
            via: expected.server,
            distance: 1,
            local: false,
            expected_status: STATUS_VALIDKEY | STATUS_REACHABLE | STATUS_SPTPS,
        },
    )?;
    assert_unreachable_tunnel_server_other_client(dumps, expected.other_client, label, true)?;
    assert_exact_raw_subnet_owners(
        dumps,
        label,
        &[
            (expected.local_subnet, expected.local),
            (expected.server_subnet, expected.server),
        ],
    )?;
    assert_no_raw_subnet_owner(dumps, expected.other_subnet, expected.other_client, label)?;
    Ok(())
}

fn assert_legacy_tunnel_server_client_view(
    dumps: &RawControlDumps,
    label: &str,
    expected: TunnelServerClientExpectation<'_>,
) -> Result<(), Box<dyn Error>> {
    let server_status = if expected.require_validkey_in {
        STATUS_VALIDKEY | STATUS_REACHABLE | STATUS_UDP_CONFIRMED | STATUS_VALIDKEY_IN
    } else {
        STATUS_VALIDKEY | STATUS_REACHABLE
    };
    assert_legacy_tunnel_server_node(
        raw_node(dumps, expected.local)?,
        TunnelServerNodeExpectation {
            label,
            host: "MYSELF",
            port: expected.local_port,
            options: PROTOCOL_MINOR_RAW | OPTION_PMTU_DISCOVERY_RAW | OPTION_CLAMP_MSS_RAW,
            nexthop: expected.local,
            via: expected.local,
            distance: 0,
            local: true,
            expected_status: STATUS_REACHABLE,
        },
    )?;
    assert_legacy_tunnel_server_node(
        raw_node(dumps, expected.server)?,
        TunnelServerNodeExpectation {
            label,
            host: expected.server_host,
            port: expected.server_port,
            options: expected.options,
            nexthop: expected.server,
            via: expected.server,
            distance: 1,
            local: false,
            expected_status: server_status,
        },
    )?;
    assert_unreachable_tunnel_server_other_client(dumps, expected.other_client, label, false)?;
    assert_exact_raw_subnet_owners(
        dumps,
        label,
        &[
            (expected.local_subnet, expected.local),
            (expected.server_subnet, expected.server),
        ],
    )?;
    assert_no_raw_subnet_owner(dumps, expected.other_subnet, expected.other_client, label)?;
    Ok(())
}

fn assert_modern_tunnel_server_node(
    node: &RawNodeDump,
    expected: TunnelServerNodeExpectation<'_>,
) -> Result<(), Box<dyn Error>> {
    assert_eq!(
        12,
        node.id.len(),
        "{}: node id should be C node_id_t hex for {node:?}",
        expected.label
    );
    assert_eq!(
        expected.host, node.host,
        "{}: host mismatch for {node:?}",
        expected.label
    );
    assert_eq!(
        expected.port, node.port,
        "{}: port mismatch for {node:?}",
        expected.label
    );
    assert_eq!(
        0, node.cipher,
        "{}: modern cipher field should be zero for {node:?}",
        expected.label
    );
    assert_eq!(
        0, node.digest,
        "{}: modern digest field should be zero for {node:?}",
        expected.label
    );
    assert_eq!(
        0, node.mac_length,
        "{}: modern maclength field should be zero for {node:?}",
        expected.label
    );
    assert_eq!(
        0, node.compression,
        "{}: modern compression field should be zero for {node:?}",
        expected.label
    );
    assert_eq!(
        expected.options, node.options,
        "{}: options mismatch for {node:?}",
        expected.label
    );
    assert_status_has(node, expected.expected_status)?;
    let local_validkey_mask = if expected.local { STATUS_VALIDKEY } else { 0 };
    let local_udp_confirmed_mask = if expected.local {
        STATUS_UDP_CONFIRMED
    } else {
        0
    };
    assert_status_lacks(
        node,
        STATUS_INDIRECT | STATUS_VALIDKEY_IN | local_validkey_mask | local_udp_confirmed_mask,
    )?;
    assert_eq!(
        expected.nexthop, node.nexthop,
        "{}: nexthop mismatch for {node:?}",
        expected.label
    );
    assert_eq!(
        expected.via, node.via,
        "{}: via mismatch for {node:?}",
        expected.label
    );
    assert_eq!(
        expected.distance, node.distance,
        "{}: distance mismatch for {node:?}",
        expected.label
    );
    if expected.local {
        assert_default_mtu_fields(node)?;
    } else {
        assert_direct_peer_pmtu_fields(node)?;
    }
    Ok(())
}

fn assert_legacy_tunnel_server_node(
    node: &RawNodeDump,
    expected: TunnelServerNodeExpectation<'_>,
) -> Result<(), Box<dyn Error>> {
    assert_eq!(
        12,
        node.id.len(),
        "{}: node id should be C node_id_t hex for {node:?}",
        expected.label
    );
    assert_eq!(
        expected.host, node.host,
        "{}: host mismatch for {node:?}",
        expected.label
    );
    assert_eq!(
        expected.port, node.port,
        "{}: port mismatch for {node:?}",
        expected.label
    );
    assert_eq!(
        expected.options, node.options,
        "{}: options mismatch for {node:?}",
        expected.label
    );
    assert_eq!(
        expected.nexthop, node.nexthop,
        "{}: nexthop mismatch for {node:?}",
        expected.label
    );
    assert_eq!(
        expected.via, node.via,
        "{}: via mismatch for {node:?}",
        expected.label
    );
    assert_eq!(
        expected.distance, node.distance,
        "{}: distance mismatch for {node:?}",
        expected.label
    );
    assert_status_has(node, expected.expected_status)?;
    let local_validkey_mask = if expected.local { STATUS_VALIDKEY } else { 0 };
    assert_status_lacks(node, STATUS_INDIRECT | STATUS_SPTPS | local_validkey_mask)?;

    if expected.local {
        assert_eq!(
            0, node.cipher,
            "{}: local cipher should be zero",
            expected.label
        );
        assert_eq!(
            0, node.digest,
            "{}: local digest should be zero",
            expected.label
        );
        assert_eq!(
            0, node.mac_length,
            "{}: local maclength should be zero",
            expected.label
        );
        assert_eq!(
            0, node.compression,
            "{}: local compression should be zero",
            expected.label
        );
        assert_status_lacks(node, STATUS_UDP_CONFIRMED | STATUS_VALIDKEY_IN)?;
        assert_default_mtu_fields(node)?;
    } else {
        assert_eq!(
            LEGACY_AES_256_CBC_NID, node.cipher,
            "{}: legacy peer cipher mismatch for {node:?}",
            expected.label
        );
        assert_eq!(
            LEGACY_SHA256_NID, node.digest,
            "{}: legacy peer digest mismatch for {node:?}",
            expected.label
        );
        assert_eq!(
            LEGACY_MAC_LENGTH, node.mac_length,
            "{}: legacy peer maclength mismatch for {node:?}",
            expected.label
        );
        assert_eq!(
            0, node.compression,
            "{}: legacy peer compression mismatch for {node:?}",
            expected.label
        );
        assert_direct_peer_pmtu_fields(node)?;
    }

    Ok(())
}

fn assert_unreachable_tunnel_server_other_client(
    dumps: &RawControlDumps,
    other_client: &str,
    label: &str,
    modern: bool,
) -> Result<(), Box<dyn Error>> {
    let Some(node) = dumps.nodes.iter().find(|node| node.name == other_client) else {
        return Ok(());
    };

    assert_eq!(
        12,
        node.id.len(),
        "{label}: other client id should still use C node_id_t hex for {node:?}"
    );
    assert_status_lacks(
        node,
        STATUS_VALIDKEY
            | STATUS_REACHABLE
            | STATUS_UDP_CONFIRMED
            | STATUS_VALIDKEY_IN
            | STATUS_SPTPS,
    )?;
    if modern {
        assert_eq!(
            0, node.cipher,
            "{label}: modern unreachable other client cipher should be zero"
        );
        assert_eq!(
            0, node.digest,
            "{label}: modern unreachable other client digest should be zero"
        );
        assert_eq!(
            0, node.mac_length,
            "{label}: modern unreachable other client maclength should be zero"
        );
    } else {
        assert!(
            node.cipher == 0 || node.cipher == LEGACY_AES_256_CBC_NID,
            "{label}: legacy unreachable other client should have no active outgoing cipher or C legacy cipher: {node:?}"
        );
        assert!(
            node.digest == 0 || node.digest == LEGACY_SHA256_NID,
            "{label}: legacy unreachable other client should have no active outgoing digest or C legacy digest: {node:?}"
        );
    }
    assert_eq!(
        0, node.compression,
        "{label}: unreachable other client compression should be zero"
    );
    assert_eq!(
        -1, node.distance,
        "{label}: unreachable other client should keep C dump_nodes() distance sentinel: {node:?}"
    );
    assert_eq!(
        "-", node.nexthop,
        "{label}: unreachable other client should not have a nexthop: {node:?}"
    );
    assert_eq!(
        "-", node.via,
        "{label}: unreachable other client should not have via: {node:?}"
    );
    assert_default_mtu_fields(node)?;

    Ok(())
}

fn assert_modern_dynamic_relay_nodes(
    dumps: &RawControlDumps,
    label: &str,
    expected: &[RawNodeExpectation<'_>],
    expected_options: u32,
) -> Result<(), Box<dyn Error>> {
    for expectation in expected {
        let node = raw_node(dumps, expectation.name)?;
        assert_eq!(
            12,
            node.id.len(),
            "{label}: node id should be C node_id_t hex for {node:?}"
        );
        let expected_host = node.host == expectation.host && node.port == expectation.port;
        let c_udp_info_unspec =
            expectation.allow_unspec_host && node.host == "unspec" && node.port == "unspec";
        let c_unknown_address =
            expectation.allow_unspec_host && node.host == "unknown" && node.port == "unknown";
        assert!(
            expected_host || c_udp_info_unspec || c_unknown_address,
            "{label}: host/port mismatch for {node:?}; expected {} port {}{}",
            expectation.host,
            expectation.port,
            if expectation.allow_unspec_host {
                " or C UDP_INFO unspec/unspec or unknown/unknown"
            } else {
                ""
            }
        );
        assert_eq!(
            0, node.cipher,
            "{label}: modern cipher field should be zero"
        );
        assert_eq!(
            0, node.digest,
            "{label}: modern digest field should be zero"
        );
        assert_eq!(
            0, node.mac_length,
            "{label}: modern maclength field should be zero"
        );
        assert_eq!(
            0, node.compression,
            "{label}: modern compression field should be zero"
        );
        assert_eq!(
            expected_options, node.options,
            "{label}: options mismatch for {node:?}"
        );
        assert_status_has(node, STATUS_REACHABLE | STATUS_SPTPS)?;
        assert_status_lacks(node, STATUS_INDIRECT)?;
        if expectation.local {
            assert_status_lacks(
                node,
                STATUS_VALIDKEY | STATUS_UDP_CONFIRMED | STATUS_VALIDKEY_IN,
            )?;
            assert_default_mtu_fields(node)?;
        } else {
            assert_direct_peer_pmtu_fields(node)?;
        }
        assert_eq!(
            expectation.nexthop, node.nexthop,
            "{label}: nexthop mismatch for {node:?}"
        );
        if expectation.distance <= 1 || node.status & STATUS_INDIRECT != 0 {
            assert_eq!(
                expectation.via, node.via,
                "{label}: via mismatch for {node:?}"
            );
        }
        assert_eq!(
            expectation.distance, node.distance,
            "{label}: distance mismatch for {node:?}"
        );
    }

    Ok(())
}

fn assert_legacy_dynamic_relay_nodes(
    dumps: &RawControlDumps,
    label: &str,
    expected: &[RawNodeExpectation<'_>],
    role: LegacyDynamicViewRole,
) -> Result<(), Box<dyn Error>> {
    for expectation in expected {
        let node = raw_node(dumps, expectation.name)?;
        assert_eq!(
            12,
            node.id.len(),
            "{label}: node id should be C node_id_t hex for {node:?}"
        );
        let expected_host = node.host == expectation.host && node.port == expectation.port;
        let c_udp_info_unspec =
            expectation.allow_unspec_host && node.host == "unspec" && node.port == "unspec";
        let c_unknown_address =
            expectation.allow_unspec_host && node.host == "unknown" && node.port == "unknown";
        assert!(
            expected_host || c_udp_info_unspec || c_unknown_address,
            "{label}: host/port mismatch for {node:?}; expected {} port {}{}",
            expectation.host,
            expectation.port,
            if expectation.allow_unspec_host {
                " or C UDP_INFO unspec/unspec or unknown/unknown"
            } else {
                ""
            }
        );
        assert_eq!(
            expectation.nexthop, node.nexthop,
            "{label}: nexthop mismatch for {node:?}"
        );
        if expectation.distance <= 1 || node.status & STATUS_INDIRECT != 0 {
            assert_eq!(
                expectation.via, node.via,
                "{label}: via mismatch for {node:?}"
            );
        }
        assert_eq!(
            expectation.distance, node.distance,
            "{label}: distance mismatch for {node:?}"
        );
        assert_status_has(node, STATUS_REACHABLE)?;
        assert_status_lacks(node, STATUS_INDIRECT | STATUS_SPTPS)?;

        if expectation.local {
            assert_eq!(0, node.cipher, "{label}: local cipher should be zero");
            assert_eq!(0, node.digest, "{label}: local digest should be zero");
            assert_eq!(
                0, node.mac_length,
                "{label}: local maclength should be zero"
            );
            assert_eq!(
                0, node.compression,
                "{label}: local compression should be zero"
            );
            assert_eq!(
                PROTOCOL_MINOR_RAW | OPTION_PMTU_DISCOVERY_RAW | OPTION_CLAMP_MSS_RAW,
                node.options,
                "{label}: C setup_myself() keeps PROT_MINOR in local legacy dump options"
            );
            assert_status_lacks(
                node,
                STATUS_VALIDKEY | STATUS_UDP_CONFIRMED | STATUS_VALIDKEY_IN,
            )?;
            assert_default_mtu_fields(node)?;
            continue;
        }

        assert_eq!(
            LEGACY_AES_256_CBC_NID, node.cipher,
            "{label}: legacy peer cipher mismatch for {node:?}"
        );
        assert_eq!(
            LEGACY_SHA256_NID, node.digest,
            "{label}: legacy peer digest mismatch for {node:?}"
        );
        assert_eq!(
            LEGACY_MAC_LENGTH, node.mac_length,
            "{label}: legacy peer maclength mismatch for {node:?}"
        );
        assert_eq!(
            0, node.compression,
            "{label}: legacy peer compression mismatch for {node:?}"
        );
        assert_eq!(
            OPTION_PMTU_DISCOVERY_RAW | OPTION_CLAMP_MSS_RAW,
            node.options,
            "{label}: legacy peer options mismatch for {node:?}"
        );
        assert_status_has(node, STATUS_VALIDKEY | STATUS_VALIDKEY_IN)?;

        let adjacent = expectation.distance == 1 || role == LegacyDynamicViewRole::Middle;
        if adjacent {
            assert_status_has(node, STATUS_UDP_CONFIRMED)?;
            assert_direct_peer_pmtu_fields(node)?;
        } else {
            assert!(
                node.max_mtu >= node.min_mtu,
                "{label}: legacy dynamic endpoint MTU bounds are invalid: {node:?}"
            );
            assert!(
                node.udp_ping_rtt >= -1,
                "{label}: legacy dynamic endpoint UDP RTT should use C sentinel/rtt shape: {node:?}"
            );
        }
    }

    Ok(())
}

fn assert_modern_static_relay_nodes(
    dumps: &RawControlDumps,
    label: &str,
    expected: &[RawNodeExpectation<'_>],
    expected_options: u32,
) -> Result<(), Box<dyn Error>> {
    for expectation in expected {
        let node = raw_node(dumps, expectation.name)?;
        assert_eq!(
            12,
            node.id.len(),
            "{label}: node id should be C node_id_t hex for {node:?}"
        );
        let expected_host = node.host == expectation.host && node.port == expectation.port;
        let c_udp_info_unspec =
            expectation.allow_unspec_host && node.host == "unspec" && node.port == "unspec";
        let c_unknown_address =
            expectation.allow_unspec_host && node.host == "unknown" && node.port == "unknown";
        assert!(
            expected_host || c_udp_info_unspec || c_unknown_address,
            "{label}: host/port mismatch for {node:?}; expected {} port {}{}",
            expectation.host,
            expectation.port,
            if expectation.allow_unspec_host {
                " or C UDP_INFO unspec/unspec or unknown/unknown"
            } else {
                ""
            }
        );
        assert_eq!(
            0, node.cipher,
            "{label}: modern cipher field should be zero"
        );
        assert_eq!(
            0, node.digest,
            "{label}: modern digest field should be zero"
        );
        assert_eq!(
            0, node.mac_length,
            "{label}: modern maclength field should be zero"
        );
        assert_eq!(
            0, node.compression,
            "{label}: modern compression field should be zero"
        );
        assert_eq!(
            expected_options, node.options,
            "{label}: options mismatch for {node:?}"
        );
        assert_status_has(node, STATUS_REACHABLE | STATUS_SPTPS)?;
        if expectation.local {
            assert_status_lacks(
                node,
                STATUS_VALIDKEY | STATUS_INDIRECT | STATUS_UDP_CONFIRMED | STATUS_VALIDKEY_IN,
            )?;
            assert_default_mtu_fields(node)?;
        } else {
            assert!(
                node.max_mtu >= node.min_mtu,
                "{label}: static relay node MTU bounds are invalid: {node:?}"
            );
            assert!(
                node.udp_ping_rtt >= -1,
                "{label}: static relay node UDP RTT should use C sentinel/rtt shape: {node:?}"
            );
        }
        assert_eq!(
            expectation.nexthop, node.nexthop,
            "{label}: nexthop mismatch for {node:?}"
        );
        if expectation.distance <= 1 || node.status & STATUS_INDIRECT != 0 {
            assert_eq!(
                expectation.via, node.via,
                "{label}: via mismatch for {node:?}"
            );
        }
        assert_eq!(
            expectation.distance, node.distance,
            "{label}: distance mismatch for {node:?}"
        );
    }

    Ok(())
}

fn assert_legacy_static_relay_nodes(
    dumps: &RawControlDumps,
    label: &str,
    expected: &[RawNodeExpectation<'_>],
) -> Result<(), Box<dyn Error>> {
    for expectation in expected {
        let node = raw_node(dumps, expectation.name)?;
        assert_eq!(
            12,
            node.id.len(),
            "{label}: node id should be C node_id_t hex for {node:?}"
        );
        let expected_host = node.host == expectation.host && node.port == expectation.port;
        let c_udp_info_unspec =
            expectation.allow_unspec_host && node.host == "unspec" && node.port == "unspec";
        let c_unknown_address =
            expectation.allow_unspec_host && node.host == "unknown" && node.port == "unknown";
        assert!(
            expected_host || c_udp_info_unspec || c_unknown_address,
            "{label}: host/port mismatch for {node:?}; expected {} port {}{}",
            expectation.host,
            expectation.port,
            if expectation.allow_unspec_host {
                " or C UDP_INFO unspec/unspec or unknown/unknown"
            } else {
                ""
            }
        );
        assert_eq!(
            expectation.nexthop, node.nexthop,
            "{label}: nexthop mismatch for {node:?}"
        );
        if expectation.distance <= 1 || node.status & STATUS_INDIRECT != 0 {
            assert_eq!(
                expectation.via, node.via,
                "{label}: via mismatch for {node:?}"
            );
        }
        assert_eq!(
            expectation.distance, node.distance,
            "{label}: distance mismatch for {node:?}"
        );
        assert_status_has(node, STATUS_REACHABLE)?;
        assert_status_lacks(node, STATUS_SPTPS)?;

        if expectation.local {
            assert_eq!(0, node.cipher, "{label}: local cipher should be zero");
            assert_eq!(0, node.digest, "{label}: local digest should be zero");
            assert_eq!(
                0, node.mac_length,
                "{label}: local maclength should be zero"
            );
            assert_eq!(
                0, node.compression,
                "{label}: local compression should be zero"
            );
            assert_eq!(
                PROTOCOL_MINOR_RAW | OPTION_PMTU_DISCOVERY_RAW | OPTION_CLAMP_MSS_RAW,
                node.options,
                "{label}: C setup_myself() keeps PROT_MINOR in local legacy dump options"
            );
            assert_status_lacks(
                node,
                STATUS_VALIDKEY | STATUS_INDIRECT | STATUS_UDP_CONFIRMED | STATUS_VALIDKEY_IN,
            )?;
            assert_default_mtu_fields(node)?;
            continue;
        }

        assert_eq!(
            LEGACY_AES_256_CBC_NID, node.cipher,
            "{label}: legacy peer cipher mismatch for {node:?}"
        );
        assert_eq!(
            LEGACY_SHA256_NID, node.digest,
            "{label}: legacy peer digest mismatch for {node:?}"
        );
        assert_eq!(
            LEGACY_MAC_LENGTH, node.mac_length,
            "{label}: legacy peer maclength mismatch for {node:?}"
        );
        assert_eq!(
            0, node.compression,
            "{label}: legacy peer compression mismatch for {node:?}"
        );
        assert_eq!(
            OPTION_PMTU_DISCOVERY_RAW | OPTION_CLAMP_MSS_RAW,
            node.options,
            "{label}: legacy peer options mismatch for {node:?}"
        );
        assert_status_has(node, STATUS_VALIDKEY | STATUS_VALIDKEY_IN)?;

        assert!(
            node.max_mtu >= node.min_mtu,
            "{label}: legacy static relay node MTU bounds are invalid: {node:?}"
        );
        assert!(
            node.udp_ping_rtt >= -1,
            "{label}: legacy static relay node UDP RTT should use C sentinel/rtt shape: {node:?}"
        );
    }

    Ok(())
}

#[derive(Clone, Copy)]
struct DynamicRelayEdgeExpectation<'a> {
    alpha: &'a str,
    beta: &'a str,
    gamma: &'a str,
    alpha_host: &'a str,
    beta_alpha_host: &'a str,
    beta_gamma_host: &'a str,
    gamma_host: &'a str,
    alpha_port: &'a str,
    beta_port: &'a str,
    gamma_port: &'a str,
    options: u32,
}

#[derive(Clone, Copy)]
struct StaticRelayEdgeExpectation<'a> {
    alpha: &'a str,
    beta: &'a str,
    gamma: &'a str,
    alpha_host: &'a str,
    beta_alpha_host: &'a str,
    beta_gamma_host: &'a str,
    gamma_host: &'a str,
    alpha_port: &'a str,
    beta_port: &'a str,
    gamma_port: &'a str,
    options: u32,
}

#[derive(Clone, Copy)]
struct TunnelServerEdgeExpectation<'a> {
    server: &'a str,
    first_client: &'a str,
    second_client: &'a str,
    first_client_host: &'a str,
    first_client_port: &'a str,
    first_server_host: &'a str,
    second_client_host: &'a str,
    second_client_port: &'a str,
    second_server_host: &'a str,
    server_port: &'a str,
    options: u32,
    label: &'a str,
}

fn assert_tunnel_server_raw_edges(
    dumps: &RawControlDumps,
    expected: TunnelServerEdgeExpectation<'_>,
) -> Result<(), Box<dyn Error>> {
    assert_tunnel_server_single_client_raw_edge(
        dumps,
        expected.server,
        expected.first_client,
        expected.first_client_host,
        expected.first_client_port,
        expected.first_server_host,
        expected.server_port,
        expected.options,
        expected.label,
    )?;
    assert_tunnel_server_single_client_raw_edge(
        dumps,
        expected.server,
        expected.second_client,
        expected.second_client_host,
        expected.second_client_port,
        expected.second_server_host,
        expected.server_port,
        expected.options,
        expected.label,
    )?;
    assert_no_raw_edge(dumps, expected.first_client, expected.second_client)?;
    assert_no_raw_edge(dumps, expected.second_client, expected.first_client)?;
    Ok(())
}

fn assert_tunnel_server_single_client_raw_edge(
    dumps: &RawControlDumps,
    server: &str,
    client: &str,
    client_host: &str,
    client_port: &str,
    server_host: &str,
    server_port: &str,
    expected_options: u32,
    label: &str,
) -> Result<(), Box<dyn Error>> {
    let server_to_client = raw_edge(dumps, server, client)?;
    assert_eq!(
        client_host, server_to_client.host,
        "{label}: server->client edge host mismatch: {server_to_client:?}"
    );
    assert_eq!(
        client_port, server_to_client.port,
        "{label}: server->client edge port mismatch: {server_to_client:?}"
    );
    assert_eq!(
        expected_options, server_to_client.options,
        "{label}: server->client edge options mismatch: {server_to_client:?}"
    );
    assert!(
        !server_to_client.local_host.is_empty() && !server_to_client.local_port.is_empty(),
        "{label}: server->client edge should include C ADD_EDGE local address fields: {server_to_client:?}"
    );

    let client_to_server = raw_edge(dumps, client, server)?;
    assert_eq!(
        server_host, client_to_server.host,
        "{label}: client->server edge host mismatch: {client_to_server:?}"
    );
    assert_eq!(
        server_port, client_to_server.port,
        "{label}: client->server edge port mismatch: {client_to_server:?}"
    );
    assert_eq!(
        expected_options, client_to_server.options,
        "{label}: client->server edge options mismatch: {client_to_server:?}"
    );
    assert!(
        !client_to_server.local_host.is_empty() && !client_to_server.local_port.is_empty(),
        "{label}: client->server edge should include C ADD_EDGE local address fields: {client_to_server:?}"
    );
    assert_eq!(
        server_to_client.weight, client_to_server.weight,
        "{label}: tunnel-server edge weights should match both C dump_edges() directions"
    );
    Ok(())
}

fn assert_static_relay_raw_edges(
    dumps: &RawControlDumps,
    expect: StaticRelayEdgeExpectation<'_>,
) -> Result<(), Box<dyn Error>> {
    assert_raw_edge_pair(
        dumps,
        expect.alpha,
        expect.beta,
        expect.beta_alpha_host,
        expect.beta_port,
        expect.alpha_host,
        expect.alpha_port,
        expect.options,
    )?;
    assert_raw_edge_pair(
        dumps,
        expect.beta,
        expect.gamma,
        expect.gamma_host,
        expect.gamma_port,
        expect.beta_gamma_host,
        expect.beta_port,
        expect.options,
    )?;
    assert_no_raw_edge(dumps, expect.alpha, expect.gamma)?;
    assert_no_raw_edge(dumps, expect.gamma, expect.alpha)?;
    Ok(())
}

fn assert_dynamic_relay_raw_edges(
    dumps: &RawControlDumps,
    expect: DynamicRelayEdgeExpectation<'_>,
) -> Result<(), Box<dyn Error>> {
    assert_raw_edge_pair(
        dumps,
        expect.alpha,
        expect.beta,
        expect.beta_alpha_host,
        expect.beta_port,
        expect.alpha_host,
        expect.alpha_port,
        expect.options,
    )?;
    assert_raw_edge_pair(
        dumps,
        expect.beta,
        expect.gamma,
        expect.gamma_host,
        expect.gamma_port,
        expect.beta_gamma_host,
        expect.beta_port,
        expect.options,
    )?;
    assert_no_raw_edge(dumps, expect.alpha, expect.gamma)?;
    assert_no_raw_edge(dumps, expect.gamma, expect.alpha)?;
    Ok(())
}

fn assert_raw_edge_pair(
    dumps: &RawControlDumps,
    from: &str,
    to: &str,
    to_host: &str,
    to_port: &str,
    from_host: &str,
    from_port: &str,
    expected_options: u32,
) -> Result<(), Box<dyn Error>> {
    let forward = raw_edge(dumps, from, to)?;
    assert_eq!(
        to_host, forward.host,
        "forward edge host mismatch: {forward:?}"
    );
    assert_eq!(
        to_port, forward.port,
        "forward edge port mismatch: {forward:?}"
    );
    assert_eq!(
        expected_options, forward.options,
        "forward edge options mismatch: {forward:?}"
    );
    assert!(
        !forward.local_host.is_empty() && !forward.local_port.is_empty(),
        "forward edge should include C ADD_EDGE local address fields: {forward:?}"
    );
    assert!(
        forward.weight >= 0,
        "forward edge weight should be non-negative: {forward:?}"
    );

    let reverse = raw_edge(dumps, to, from)?;
    assert_eq!(
        from_host, reverse.host,
        "reverse edge host mismatch: {reverse:?}"
    );
    assert_eq!(
        from_port, reverse.port,
        "reverse edge port mismatch: {reverse:?}"
    );
    assert_eq!(
        expected_options, reverse.options,
        "reverse edge options mismatch: {reverse:?}"
    );
    assert!(
        !reverse.local_host.is_empty() && !reverse.local_port.is_empty(),
        "reverse edge should include C ADD_EDGE local address fields: {reverse:?}"
    );
    assert_eq!(
        forward.weight, reverse.weight,
        "C dump_edges() should report equal weights for the two directions of a live meta edge"
    );

    Ok(())
}

fn assert_no_raw_edge(dumps: &RawControlDumps, from: &str, to: &str) -> Result<(), Box<dyn Error>> {
    if dumps
        .edges
        .iter()
        .any(|edge| edge.from == from && edge.to == to)
    {
        return Err(format!(
            "dynamic relay should not create a direct edge {from}->{to}: {:?}",
            dumps.edges
        )
        .into());
    }

    Ok(())
}

fn assert_no_raw_subnet_owner(
    dumps: &RawControlDumps,
    subnet: &str,
    owner: &str,
    label: &str,
) -> Result<(), Box<dyn Error>> {
    if dumps
        .subnets
        .iter()
        .any(|dump| dump.subnet == subnet && dump.owner == owner)
    {
        return Err(format!(
            "{label}: tunnel-server client view leaked subnet {subnet} owner {owner}: {:?}",
            dumps.subnets
        )
        .into());
    }

    Ok(())
}

fn assert_dynamic_relay_raw_subnets(
    dumps: &RawControlDumps,
    expected: &[(&str, &str)],
) -> Result<(), Box<dyn Error>> {
    for (subnet, owner) in expected {
        if !dumps
            .subnets
            .iter()
            .any(|dump| dump.subnet == *subnet && dump.owner == *owner)
        {
            return Err(format!(
                "missing dynamic relay subnet {subnet} owner {owner}: {:?}",
                dumps.subnets
            )
            .into());
        }
    }

    Ok(())
}

fn assert_exact_raw_subnet_owners(
    dumps: &RawControlDumps,
    label: &str,
    expected: &[(&str, &str)],
) -> Result<(), Box<dyn Error>> {
    assert_dynamic_relay_raw_subnets(dumps, expected)?;
    for subnet in &dumps.subnets {
        let Some((_, owner)) = expected
            .iter()
            .find(|(expected_subnet, _)| *expected_subnet == subnet.subnet)
        else {
            continue;
        };
        if *owner != subnet.owner {
            return Err(format!(
                "{label}: stale or conflicting owner for subnet {}: expected {}, got {}; all subnets: {:?}",
                subnet.subnet, owner, subnet.owner, dumps.subnets
            )
            .into());
        }
    }
    Ok(())
}

fn assert_modern_direct_raw_view(
    dumps: &RawControlDumps,
    expect: DirectViewExpectation<'_>,
) -> Result<(), Box<dyn Error>> {
    let local = raw_node(dumps, expect.local)?;
    assert_eq!(12, local.id.len(), "node id should be C node_id_t hex");
    assert_eq!("MYSELF", local.host);
    assert_eq!(expect.local_port.to_string(), local.port);
    assert_eq!(0, local.cipher);
    assert_eq!(0, local.digest);
    assert_eq!(0, local.mac_length);
    assert_eq!(0, local.compression);
    assert_eq!(
        PROTOCOL_MINOR_RAW | OPTION_PMTU_DISCOVERY_RAW | OPTION_CLAMP_MSS_RAW,
        local.options
    );
    assert_status_has(local, STATUS_REACHABLE | STATUS_SPTPS)?;
    assert_status_lacks(
        local,
        STATUS_VALIDKEY | STATUS_UDP_CONFIRMED | STATUS_VALIDKEY_IN,
    )?;
    assert_eq!(expect.local, local.nexthop);
    assert_eq!(expect.local, local.via);
    assert_eq!(0, local.distance);
    assert_default_mtu_fields(local)?;

    let peer = raw_node(dumps, expect.peer)?;
    assert_eq!(12, peer.id.len(), "node id should be C node_id_t hex");
    assert_eq!(expect.peer_host, peer.host);
    assert_eq!(expect.peer_port.to_string(), peer.port);
    assert_eq!(0, peer.cipher);
    assert_eq!(0, peer.digest);
    assert_eq!(0, peer.mac_length);
    assert_eq!(0, peer.compression);
    assert_eq!(
        PROTOCOL_MINOR_RAW | OPTION_PMTU_DISCOVERY_RAW | OPTION_CLAMP_MSS_RAW,
        peer.options
    );
    assert_status_has(peer, STATUS_VALIDKEY | STATUS_REACHABLE | STATUS_SPTPS)?;
    assert_eq!(expect.peer, peer.nexthop);
    assert_eq!(expect.peer, peer.via);
    assert_eq!(1, peer.distance);
    assert_direct_peer_pmtu_fields(peer)?;

    assert_direct_edges(
        dumps,
        expect,
        PROTOCOL_MINOR_RAW | OPTION_PMTU_DISCOVERY_RAW | OPTION_CLAMP_MSS_RAW,
    )?;
    assert_direct_subnets(dumps, expect)?;
    Ok(())
}

fn assert_legacy_direct_raw_view(
    dumps: &RawControlDumps,
    expect: DirectViewExpectation<'_>,
    legacy_crypto: LegacyCryptoConfig<'_>,
) -> Result<(), Box<dyn Error>> {
    let local = raw_node(dumps, expect.local)?;
    assert_eq!(12, local.id.len(), "node id should be C node_id_t hex");
    assert_eq!("MYSELF", local.host);
    assert_eq!(expect.local_port.to_string(), local.port);
    assert_eq!(0, local.cipher);
    assert_eq!(0, local.digest);
    assert_eq!(0, local.mac_length);
    assert_eq!(0, local.compression);
    assert_eq!(
        PROTOCOL_MINOR_RAW | OPTION_PMTU_DISCOVERY_RAW | OPTION_CLAMP_MSS_RAW,
        local.options
    );
    assert_status_has(local, STATUS_REACHABLE)?;
    assert_status_lacks(
        local,
        STATUS_VALIDKEY | STATUS_SPTPS | STATUS_UDP_CONFIRMED | STATUS_VALIDKEY_IN,
    )?;
    assert_eq!(expect.local, local.nexthop);
    assert_eq!(expect.local, local.via);
    assert_eq!(0, local.distance);
    assert_default_mtu_fields(local)?;

    let peer = raw_node(dumps, expect.peer)?;
    assert_eq!(12, peer.id.len(), "node id should be C node_id_t hex");
    assert_eq!(expect.peer_host, peer.host);
    assert_eq!(expect.peer_port.to_string(), peer.port);
    assert_eq!(legacy_crypto.expected_cipher, peer.cipher);
    assert_eq!(legacy_crypto.expected_digest, peer.digest);
    assert_eq!(legacy_crypto.expected_mac_length, peer.mac_length);
    assert_eq!(legacy_crypto.expected_compression, peer.compression);
    assert_eq!(
        OPTION_PMTU_DISCOVERY_RAW | OPTION_CLAMP_MSS_RAW,
        peer.options
    );
    assert_status_has(
        peer,
        STATUS_VALIDKEY | STATUS_REACHABLE | STATUS_UDP_CONFIRMED | STATUS_VALIDKEY_IN,
    )?;
    assert_status_lacks(peer, STATUS_SPTPS)?;
    assert_eq!(expect.peer, peer.nexthop);
    assert_eq!(expect.peer, peer.via);
    assert_eq!(1, peer.distance);
    assert!(
        peer.pmtu > 0,
        "legacy peer should expose a positive C dump_nodes() PMTU field: {peer:?}"
    );
    assert!(
        peer.max_mtu >= peer.min_mtu,
        "legacy peer MTU bounds are invalid: {peer:?}"
    );
    assert!(
        peer.udp_ping_rtt >= -1,
        "legacy peer UDP RTT field should use the C dump_nodes() sentinel/rtt shape: {peer:?}"
    );

    assert_direct_edges(
        dumps,
        expect,
        OPTION_PMTU_DISCOVERY_RAW | OPTION_CLAMP_MSS_RAW,
    )?;
    assert_direct_subnets(dumps, expect)?;
    Ok(())
}

fn assert_direct_edges(
    dumps: &RawControlDumps,
    expect: DirectViewExpectation<'_>,
    expected_options: u32,
) -> Result<(), Box<dyn Error>> {
    let local_to_peer = raw_edge(dumps, expect.local, expect.peer)?;
    assert_eq!(expect.peer_host, local_to_peer.host);
    assert_eq!(expect.peer_port.to_string(), local_to_peer.port);
    assert_eq!(expected_options, local_to_peer.options);
    assert!(
        !local_to_peer.local_host.is_empty() && !local_to_peer.local_port.is_empty(),
        "direct edge should include C ADD_EDGE local address fields: {local_to_peer:?}"
    );

    let peer_to_local = raw_edge(dumps, expect.peer, expect.local)?;
    assert_eq!(expect.local_host, peer_to_local.host);
    assert_eq!(expect.local_port.to_string(), peer_to_local.port);
    assert_eq!(expected_options, peer_to_local.options);
    assert_eq!(
        local_to_peer.weight, peer_to_local.weight,
        "direct edge weights should match both C dump_edges() directions"
    );
    assert!(
        local_to_peer.weight >= 0,
        "direct edge weight should be the non-negative C ACK negotiated weight: {local_to_peer:?}"
    );
    assert!(
        !peer_to_local.local_host.is_empty() && !peer_to_local.local_port.is_empty(),
        "reverse direct edge should include C ADD_EDGE local address fields: {peer_to_local:?}"
    );

    Ok(())
}

fn assert_direct_subnets(
    dumps: &RawControlDumps,
    expect: DirectViewExpectation<'_>,
) -> Result<(), Box<dyn Error>> {
    assert!(
        dumps
            .subnets
            .iter()
            .any(|subnet| subnet.subnet == expect.local_subnet && subnet.owner == expect.local),
        "missing local subnet {} owner {} in raw subnet dump: {:?}",
        expect.local_subnet,
        expect.local,
        dumps.subnets
    );
    assert!(
        dumps
            .subnets
            .iter()
            .any(|subnet| subnet.subnet == expect.peer_subnet && subnet.owner == expect.peer),
        "missing peer subnet {} owner {} in raw subnet dump: {:?}",
        expect.peer_subnet,
        expect.peer,
        dumps.subnets
    );
    Ok(())
}

fn assert_default_mtu_fields(node: &RawNodeDump) -> Result<(), Box<dyn Error>> {
    assert_tinc_default_mtu(node.pmtu, "default PMTU", node)?;
    assert_eq!(
        0, node.min_mtu,
        "unexpected C default minmtu field: {node:?}"
    );
    assert_eq!(
        node.pmtu, node.max_mtu,
        "unexpected C default maxmtu field: {node:?}"
    );
    assert_eq!(
        -1, node.udp_ping_rtt,
        "unexpected default UDP RTT field: {node:?}"
    );
    Ok(())
}

fn assert_relay_destination_pmtu_reset_fields_like_tinc(
    node: &RawNodeDump,
    label: &str,
) -> Result<(), Box<dyn Error>> {
    assert_tinc_default_mtu(node.max_mtu, "reset maxmtu", node)?;
    assert!(
        node.pmtu > 0 && node.pmtu <= node.max_mtu,
        "{label}: final destination PMTU should keep the C default/provisional MTU_INFO shape: {node:?}"
    );
    assert_eq!(
        0, node.min_mtu,
        "{label}: final destination minmtu must stay reset because try_tx() only probes the relay peer: {node:?}"
    );
    assert_eq!(
        -1, node.udp_ping_rtt,
        "{label}: final destination UDP RTT must keep the C !udp_confirmed sentinel: {node:?}"
    );
    Ok(())
}

fn assert_tinc_default_mtu(
    mtu: i32,
    field: &str,
    node: &RawNodeDump,
) -> Result<(), Box<dyn Error>> {
    assert!(
        matches!(mtu, C_DEFAULT_MTU_RAW | C_JUMBO_MTU_RAW),
        "unexpected C {field} field: {node:?}"
    );
    Ok(())
}

fn assert_tinc_cli_default_mtu(
    mtu: i32,
    field: &str,
    node: &CliNodeDump,
    label: &str,
) -> Result<(), Box<dyn Error>> {
    assert!(
        matches!(mtu, C_DEFAULT_MTU_RAW | C_JUMBO_MTU_RAW),
        "{label}: unexpected C {field} field: {node:?}"
    );
    Ok(())
}

fn assert_direct_peer_pmtu_fields(node: &RawNodeDump) -> Result<(), Box<dyn Error>> {
    assert!(
        node.pmtu > 0,
        "direct peer should expose a positive C dump_nodes() PMTU field: {node:?}"
    );
    assert!(
        node.max_mtu >= node.min_mtu,
        "direct peer MTU bounds are invalid: {node:?}"
    );
    assert!(
        node.udp_ping_rtt >= -1,
        "direct peer UDP RTT field should use the C dump_nodes() sentinel/rtt shape: {node:?}"
    );
    Ok(())
}

fn assert_status_has(node: &RawNodeDump, mask: u32) -> Result<(), Box<dyn Error>> {
    if node.status & mask == mask {
        Ok(())
    } else {
        Err(format!(
            "node {} missing status mask {mask:#x}; status={:#x}; node={node:?}",
            node.name, node.status
        )
        .into())
    }
}

fn assert_status_lacks(node: &RawNodeDump, mask: u32) -> Result<(), Box<dyn Error>> {
    if node.status & mask == 0 {
        Ok(())
    } else {
        Err(format!(
            "node {} unexpectedly has status mask {mask:#x}; status={:#x}; node={node:?}",
            node.name, node.status
        )
        .into())
    }
}

fn raw_node<'a>(dumps: &'a RawControlDumps, name: &str) -> Result<&'a RawNodeDump, Box<dyn Error>> {
    dumps
        .nodes
        .iter()
        .find(|node| node.name == name)
        .ok_or_else(|| format!("missing raw node {name}: {:?}", dumps.nodes).into())
}

fn raw_edge<'a>(
    dumps: &'a RawControlDumps,
    from: &str,
    to: &str,
) -> Result<&'a RawEdgeDump, Box<dyn Error>> {
    dumps
        .edges
        .iter()
        .find(|edge| edge.from == from && edge.to == to)
        .ok_or_else(|| format!("missing raw edge {from}->{to}: {:?}", dumps.edges).into())
}

fn assert_c_tincctl_modern_direct_dump_text(
    c_tinc: &Path,
    netns: &str,
    confdir: &Path,
    expect: DirectViewExpectation<'_>,
    _cleanup: &NetnsCleanup,
) -> Result<(), Box<dyn Error>> {
    let nodes = run_c_tinc(c_tinc, netns, confdir, &["dump", "nodes"])?;
    assert_cli_modern_direct_nodes(&nodes, expect, "C tinc dump nodes against Rust tincd")?;

    let edges = run_c_tinc(c_tinc, netns, confdir, &["dump", "edges"])?;
    assert_cli_direct_edges(
        &edges,
        expect,
        PROTOCOL_MINOR_RAW | OPTION_PMTU_DISCOVERY_RAW | OPTION_CLAMP_MSS_RAW,
        "C tinc dump edges against Rust tincd",
    )?;

    let subnets = run_c_tinc(c_tinc, netns, confdir, &["dump", "subnets"])?;
    assert_cli_direct_subnets(&subnets, expect, "C tinc dump subnets against Rust tincd")?;

    let connections = run_c_tinc(c_tinc, netns, confdir, &["dump", "connections"])?;
    assert_cli_direct_connections(
        &connections,
        expect,
        PROTOCOL_MINOR_RAW | OPTION_PMTU_DISCOVERY_RAW | OPTION_CLAMP_MSS_RAW,
        "C tinc dump connections against Rust tincd",
    )?;

    Ok(())
}

fn assert_c_tincctl_legacy_direct_dump_text(
    c_tinc: &Path,
    netns: &str,
    confdir: &Path,
    expect: DirectViewExpectation<'_>,
    _cleanup: &NetnsCleanup,
    legacy_crypto: LegacyCryptoConfig<'_>,
) -> Result<(), Box<dyn Error>> {
    let nodes = run_c_tinc(c_tinc, netns, confdir, &["dump", "nodes"])?;
    assert_cli_legacy_direct_nodes(
        &nodes,
        expect,
        "C tinc dump nodes against Rust tincd",
        legacy_crypto,
    )?;

    let edges = run_c_tinc(c_tinc, netns, confdir, &["dump", "edges"])?;
    assert_cli_direct_edges(
        &edges,
        expect,
        OPTION_PMTU_DISCOVERY_RAW | OPTION_CLAMP_MSS_RAW,
        "C tinc dump edges against Rust tincd",
    )?;

    let subnets = run_c_tinc(c_tinc, netns, confdir, &["dump", "subnets"])?;
    assert_cli_direct_subnets(&subnets, expect, "C tinc dump subnets against Rust tincd")?;

    let connections = run_c_tinc(c_tinc, netns, confdir, &["dump", "connections"])?;
    assert_cli_direct_connections(
        &connections,
        expect,
        OPTION_PMTU_DISCOVERY_RAW | OPTION_CLAMP_MSS_RAW,
        "C tinc dump connections against Rust tincd",
    )?;

    Ok(())
}

fn assert_rust_tincctl_modern_direct_dump_text(
    c_tincd: &Path,
    netns: &str,
    confdir: &Path,
    expect: DirectViewExpectation<'_>,
    _cleanup: &NetnsCleanup,
) -> Result<(), Box<dyn Error>> {
    let nodes = run_rust_tincctl_for_daemon(c_tincd, netns, confdir, &["dump", "nodes"])?;
    assert_cli_modern_direct_nodes(&nodes, expect, "Rust tincctl dump nodes against C tincd")?;

    let edges = run_rust_tincctl_for_daemon(c_tincd, netns, confdir, &["dump", "edges"])?;
    assert_cli_direct_edges(
        &edges,
        expect,
        PROTOCOL_MINOR_RAW | OPTION_PMTU_DISCOVERY_RAW | OPTION_CLAMP_MSS_RAW,
        "Rust tincctl dump edges against C tincd",
    )?;

    let subnets = run_rust_tincctl_for_daemon(c_tincd, netns, confdir, &["dump", "subnets"])?;
    assert_cli_direct_subnets(
        &subnets,
        expect,
        "Rust tincctl dump subnets against C tincd",
    )?;

    let connections =
        run_rust_tincctl_for_daemon(c_tincd, netns, confdir, &["dump", "connections"])?;
    assert_cli_direct_connections(
        &connections,
        expect,
        PROTOCOL_MINOR_RAW | OPTION_PMTU_DISCOVERY_RAW | OPTION_CLAMP_MSS_RAW,
        "Rust tincctl dump connections against C tincd",
    )?;

    Ok(())
}

fn assert_rust_tincctl_legacy_direct_dump_text(
    c_tincd: &Path,
    netns: &str,
    confdir: &Path,
    expect: DirectViewExpectation<'_>,
    _cleanup: &NetnsCleanup,
    legacy_crypto: LegacyCryptoConfig<'_>,
) -> Result<(), Box<dyn Error>> {
    let nodes = run_rust_tincctl_for_daemon(c_tincd, netns, confdir, &["dump", "nodes"])?;
    assert_cli_legacy_direct_nodes(
        &nodes,
        expect,
        "Rust tincctl dump nodes against C tincd",
        legacy_crypto,
    )?;

    let edges = run_rust_tincctl_for_daemon(c_tincd, netns, confdir, &["dump", "edges"])?;
    assert_cli_direct_edges(
        &edges,
        expect,
        OPTION_PMTU_DISCOVERY_RAW | OPTION_CLAMP_MSS_RAW,
        "Rust tincctl dump edges against C tincd",
    )?;

    let subnets = run_rust_tincctl_for_daemon(c_tincd, netns, confdir, &["dump", "subnets"])?;
    assert_cli_direct_subnets(
        &subnets,
        expect,
        "Rust tincctl dump subnets against C tincd",
    )?;

    let connections =
        run_rust_tincctl_for_daemon(c_tincd, netns, confdir, &["dump", "connections"])?;
    assert_cli_direct_connections(
        &connections,
        expect,
        OPTION_PMTU_DISCOVERY_RAW | OPTION_CLAMP_MSS_RAW,
        "Rust tincctl dump connections against C tincd",
    )?;

    Ok(())
}

fn assert_cli_modern_direct_nodes(
    dump: &str,
    expect: DirectViewExpectation<'_>,
    label: &str,
) -> Result<(), Box<dyn Error>> {
    let local = cli_node(dump, expect.local)?;
    assert_eq!(
        12,
        local.id.len(),
        "{label}: local id should be C node_id_t hex"
    );
    assert_eq!(
        "MYSELF", local.host,
        "{label}: local node should be rendered with C MYSELF host"
    );
    assert_eq!(expect.local_port.to_string(), local.port);
    assert_eq!(0, local.cipher);
    assert_eq!(0, local.digest);
    assert_eq!(0, local.mac_length);
    assert_eq!(0, local.compression);
    assert_eq!(
        PROTOCOL_MINOR_RAW | OPTION_PMTU_DISCOVERY_RAW | OPTION_CLAMP_MSS_RAW,
        local.options
    );
    assert_cli_status_has(&local, STATUS_REACHABLE | STATUS_SPTPS, label)?;
    assert_cli_status_lacks(
        &local,
        STATUS_VALIDKEY | STATUS_UDP_CONFIRMED | STATUS_VALIDKEY_IN,
        label,
    )?;
    assert_eq!(expect.local, local.nexthop);
    assert_eq!(expect.local, local.via);
    assert_eq!(0, local.distance);
    assert_tinc_cli_default_mtu(local.pmtu, "local PMTU", &local, label)?;
    assert_eq!(0, local.min_mtu);
    assert_eq!(local.pmtu, local.max_mtu);

    let peer = cli_node(dump, expect.peer)?;
    assert_eq!(
        12,
        peer.id.len(),
        "{label}: peer id should be C node_id_t hex"
    );
    assert_eq!(expect.peer_host, peer.host);
    assert_eq!(expect.peer_port.to_string(), peer.port);
    assert_eq!(0, peer.cipher);
    assert_eq!(0, peer.digest);
    assert_eq!(0, peer.mac_length);
    assert_eq!(0, peer.compression);
    assert_eq!(
        PROTOCOL_MINOR_RAW | OPTION_PMTU_DISCOVERY_RAW | OPTION_CLAMP_MSS_RAW,
        peer.options
    );
    assert_cli_status_has(
        &peer,
        STATUS_VALIDKEY | STATUS_REACHABLE | STATUS_SPTPS,
        label,
    )?;
    assert_eq!(expect.peer, peer.nexthop);
    assert_eq!(expect.peer, peer.via);
    assert_eq!(1, peer.distance);
    assert!(
        peer.pmtu > 0 && peer.max_mtu >= peer.min_mtu,
        "{label}: peer should expose C-style direct MTU fields after ping: {peer:?}"
    );

    Ok(())
}

fn assert_cli_legacy_direct_nodes(
    dump: &str,
    expect: DirectViewExpectation<'_>,
    label: &str,
    legacy_crypto: LegacyCryptoConfig<'_>,
) -> Result<(), Box<dyn Error>> {
    let local = cli_node(dump, expect.local)?;
    assert_eq!(
        12,
        local.id.len(),
        "{label}: local id should be C node_id_t hex"
    );
    assert_eq!(
        "MYSELF", local.host,
        "{label}: local node should be rendered with C MYSELF host"
    );
    assert_eq!(expect.local_port.to_string(), local.port);
    assert_eq!(0, local.cipher);
    assert_eq!(0, local.digest);
    assert_eq!(0, local.mac_length);
    assert_eq!(0, local.compression);
    assert_eq!(
        PROTOCOL_MINOR_RAW | OPTION_PMTU_DISCOVERY_RAW | OPTION_CLAMP_MSS_RAW,
        local.options
    );
    assert_cli_status_has(&local, STATUS_REACHABLE, label)?;
    assert_cli_status_lacks(
        &local,
        STATUS_VALIDKEY | STATUS_SPTPS | STATUS_UDP_CONFIRMED | STATUS_VALIDKEY_IN,
        label,
    )?;
    assert_eq!(expect.local, local.nexthop);
    assert_eq!(expect.local, local.via);
    assert_eq!(0, local.distance);
    assert_tinc_cli_default_mtu(local.pmtu, "local PMTU", &local, label)?;
    assert_eq!(0, local.min_mtu);
    assert_eq!(local.pmtu, local.max_mtu);

    let peer = cli_node(dump, expect.peer)?;
    assert_eq!(
        12,
        peer.id.len(),
        "{label}: peer id should be C node_id_t hex"
    );
    assert_eq!(expect.peer_host, peer.host);
    assert_eq!(expect.peer_port.to_string(), peer.port);
    assert_eq!(legacy_crypto.expected_cipher, peer.cipher);
    assert_eq!(legacy_crypto.expected_digest, peer.digest);
    assert_eq!(legacy_crypto.expected_mac_length, peer.mac_length);
    assert_eq!(legacy_crypto.expected_compression, peer.compression);
    assert_eq!(
        OPTION_PMTU_DISCOVERY_RAW | OPTION_CLAMP_MSS_RAW,
        peer.options
    );
    assert_cli_status_has(
        &peer,
        STATUS_VALIDKEY | STATUS_REACHABLE | STATUS_UDP_CONFIRMED | STATUS_VALIDKEY_IN,
        label,
    )?;
    assert_cli_status_lacks(&peer, STATUS_SPTPS, label)?;
    assert_eq!(expect.peer, peer.nexthop);
    assert_eq!(expect.peer, peer.via);
    assert_eq!(1, peer.distance);
    assert!(
        peer.pmtu > 0 && peer.max_mtu >= peer.min_mtu,
        "{label}: legacy peer should expose C-style UDP/MTU fields after ping: {peer:?}"
    );

    Ok(())
}

fn cli_node(dump: &str, node: &str) -> Result<CliNodeDump, Box<dyn Error>> {
    parse_cli_node_dump_line(c_dump_node_line(dump, node)?)
}

fn assert_cli_direct_edges(
    dump: &str,
    expect: DirectViewExpectation<'_>,
    expected_options: u32,
    label: &str,
) -> Result<(), Box<dyn Error>> {
    let local_to_peer = cli_edge(dump, expect.local, expect.peer)?;
    assert_eq!(
        expect.local, local_to_peer.from,
        "{label}: direct edge source"
    );
    assert_eq!(expect.peer, local_to_peer.to, "{label}: direct edge target");
    assert_eq!(
        expect.peer_host, local_to_peer.host,
        "{label}: direct edge peer host"
    );
    assert_eq!(
        expect.peer_port.to_string(),
        local_to_peer.port,
        "{label}: direct edge peer port"
    );
    assert_eq!(
        expected_options, local_to_peer.options,
        "{label}: direct edge options"
    );
    assert!(
        !local_to_peer.local_host.is_empty() && !local_to_peer.local_port.is_empty(),
        "{label}: C cmd_dump() edge text should expose local endpoint fields: {local_to_peer:?}"
    );

    let peer_to_local = cli_edge(dump, expect.peer, expect.local)?;
    assert_eq!(
        expect.peer, peer_to_local.from,
        "{label}: reverse direct edge source"
    );
    assert_eq!(
        expect.local, peer_to_local.to,
        "{label}: reverse direct edge target"
    );
    assert_eq!(
        expect.local_host, peer_to_local.host,
        "{label}: reverse direct edge host"
    );
    assert_eq!(
        expect.local_port.to_string(),
        peer_to_local.port,
        "{label}: reverse direct edge port"
    );
    assert_eq!(
        expected_options, peer_to_local.options,
        "{label}: reverse direct edge options"
    );
    assert_eq!(
        local_to_peer.weight, peer_to_local.weight,
        "{label}: direct edge weights should match both C dump_edges() directions"
    );
    assert!(
        local_to_peer.weight >= 0,
        "{label}: direct edge weight should be non-negative: {local_to_peer:?}"
    );
    assert!(
        !peer_to_local.local_host.is_empty() && !peer_to_local.local_port.is_empty(),
        "{label}: C cmd_dump() reverse edge text should expose local endpoint fields: {peer_to_local:?}"
    );

    Ok(())
}

fn assert_cli_direct_subnets(
    dump: &str,
    expect: DirectViewExpectation<'_>,
    label: &str,
) -> Result<(), Box<dyn Error>> {
    let local = cli_subnet(dump, expect.local_subnet, expect.local)?;
    assert_eq!(expect.local_subnet, local.subnet, "{label}: local subnet");
    assert_eq!(expect.local, local.owner, "{label}: local subnet owner");

    let peer = cli_subnet(dump, expect.peer_subnet, expect.peer)?;
    assert_eq!(expect.peer_subnet, peer.subnet, "{label}: peer subnet");
    assert_eq!(expect.peer, peer.owner, "{label}: peer subnet owner");

    Ok(())
}

fn assert_cli_direct_connections(
    dump: &str,
    expect: DirectViewExpectation<'_>,
    expected_options: u32,
    label: &str,
) -> Result<(), Box<dyn Error>> {
    let control = cli_connection(dump, "<control>")?;
    assert_eq!(
        "<control>", control.name,
        "{label}: control connection name"
    );
    assert_eq!(
        "localhost", control.host,
        "{label}: control connection host"
    );
    assert_eq!("unix", control.port, "{label}: control connection port");
    assert_eq!(0, control.options, "{label}: control connection options");
    assert!(
        control.socket >= 0,
        "{label}: control connection socket/fd should be numeric: {control:?}"
    );
    assert!(
        control.status & CONNECTION_STATUS_CONTROL_RAW != 0,
        "{label}: control connection should have C control status bit: {control:?}"
    );

    let peer = cli_connection(dump, expect.peer)?;
    assert_eq!(expect.peer, peer.name, "{label}: peer connection name");
    assert_eq!(expect.peer_host, peer.host, "{label}: peer connection host");
    assert!(
        peer.port.parse::<u16>().is_ok(),
        "{label}: peer connection port should be the numeric meta TCP peer port from C connection_t.hostname: {peer:?}"
    );
    assert_eq!(
        expected_options, peer.options,
        "{label}: peer connection options"
    );
    assert!(
        peer.socket >= 0,
        "{label}: peer connection socket/id should be numeric: {peer:?}"
    );
    assert!(
        peer.status
            & (CONNECTION_STATUS_CONTROL_RAW
                | CONNECTION_STATUS_PCAP_RAW
                | CONNECTION_STATUS_LOG_RAW
                | CONNECTION_STATUS_INVITATION_RAW
                | CONNECTION_STATUS_INVITATION_USED_RAW)
            == 0,
        "{label}: peer meta connection should not be reported as control/pcap/log/invitation: {peer:?}"
    );
    Ok(())
}

fn wait_for_single_peer_meta_connection(
    confdir: &Path,
    peer: &str,
    cleanup: &NetnsCleanup,
    label: &str,
) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + Duration::from_secs(8);
    let mut last_dump = String::new();
    while Instant::now() < deadline {
        cleanup.ensure_children_alive()?;
        last_dump = run_rust_tincctl(&[
            "tinc",
            "--config",
            confdir.to_str().unwrap(),
            "dump",
            "connections",
        ])?;
        let peer_count = last_dump
            .lines()
            .filter(|line| line.starts_with(&format!("{peer} at ")))
            .count();
        let other_meta = last_dump
            .lines()
            .filter(|line| !line.starts_with("<control> at "))
            .filter(|line| !line.starts_with(&format!("{peer} at ")))
            .count();
        if peer_count == 1 && other_meta == 0 {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }

    Err(format!(
        "{label}: C ack_h() duplicate cleanup should leave exactly one active meta connection to {peer}\nlast dump:\n{last_dump}\n{}",
        cleanup.logs()
    )
    .into())
}

fn wait_for_control_subscriber_count(
    confdir: &Path,
    status_bit: u32,
    expected: usize,
    label: &str,
    cleanup: &NetnsCleanup,
) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + Duration::from_secs(8);
    let mut last_dump = String::new();
    while Instant::now() < deadline {
        cleanup.ensure_children_alive()?;
        last_dump = run_rust_tincctl(&[
            "tinc",
            "--config",
            confdir.to_str().unwrap(),
            "dump",
            "connections",
        ])?;
        let count = last_dump
            .lines()
            .filter_map(|line| parse_cli_connection_dump_line(line).ok())
            .filter(|connection| connection.status & status_bit != 0)
            .count();
        if count >= expected {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }

    Err(format!(
        "timed out waiting for {expected} {label}\nlast dump:\n{last_dump}\n{}",
        cleanup.logs()
    )
    .into())
}

fn cli_edge(dump: &str, from: &str, to: &str) -> Result<CliEdgeDump, Box<dyn Error>> {
    let prefix = format!("{from} to {to} ");
    let line = dump
        .lines()
        .find(|line| line.starts_with(&prefix))
        .ok_or_else(|| format!("missing CLI edge {from}->{to} in dump:\n{dump}"))?;
    parse_cli_edge_dump_line(line)
}

fn cli_subnet(dump: &str, subnet: &str, owner: &str) -> Result<CliSubnetDump, Box<dyn Error>> {
    let line = dump
        .lines()
        .find(|line| line.starts_with(&format!("{subnet} owner {owner}")))
        .ok_or_else(|| format!("missing CLI subnet {subnet} owner {owner} in dump:\n{dump}"))?;
    parse_cli_subnet_dump_line(line)
}

fn cli_connection(dump: &str, name: &str) -> Result<CliConnectionDump, Box<dyn Error>> {
    let line = dump
        .lines()
        .find(|line| line.starts_with(&format!("{name} at ")))
        .ok_or_else(|| format!("missing CLI connection {name} in dump:\n{dump}"))?;
    parse_cli_connection_dump_line(line)
}

fn parse_cli_node_dump_line(line: &str) -> Result<CliNodeDump, Box<dyn Error>> {
    let fields = line.split_whitespace().collect::<Vec<_>>();
    if !(fields.len() == 37 || fields.len() == 39)
        || fields.get(1) != Some(&"id")
        || fields.get(3) != Some(&"at")
        || fields.get(5) != Some(&"port")
        || fields.get(7) != Some(&"cipher")
        || fields.get(9) != Some(&"digest")
        || fields.get(11) != Some(&"maclength")
        || fields.get(13) != Some(&"compression")
        || fields.get(15) != Some(&"options")
        || fields.get(17) != Some(&"status")
        || fields.get(19) != Some(&"nexthop")
        || fields.get(21) != Some(&"via")
        || fields.get(23) != Some(&"distance")
        || fields.get(25) != Some(&"pmtu")
        || fields.get(27) != Some(&"(min")
        || fields.get(29) != Some(&"max")
        || fields.get(31) != Some(&"rx")
        || fields.get(34) != Some(&"tx")
        || (fields.len() == 39 && fields.get(37) != Some(&"rtt"))
    {
        return Err(format!("bad C-style tincctl dump nodes line: {line}").into());
    }

    let _in_packets = fields[32].parse::<u64>()?;
    let _in_bytes = fields[33].parse::<u64>()?;
    let _out_packets = fields[35].parse::<u64>()?;
    let _out_bytes = fields[36].parse::<u64>()?;
    if fields.len() == 39 && !fields[38].contains('.') {
        return Err(format!("bad C-style RTT field in tincctl dump nodes line: {line}").into());
    }

    Ok(CliNodeDump {
        name: fields[0].to_owned(),
        id: fields[2].to_owned(),
        host: fields[4].to_owned(),
        port: fields[6].to_owned(),
        cipher: fields[8].parse()?,
        digest: fields[10].parse()?,
        mac_length: fields[12].parse()?,
        compression: fields[14].parse()?,
        options: u32::from_str_radix(fields[16], 16)?,
        status: u32::from_str_radix(fields[18], 16)?,
        nexthop: fields[20].to_owned(),
        via: fields[22].to_owned(),
        distance: fields[24].parse()?,
        pmtu: fields[26].parse()?,
        min_mtu: fields[28].parse()?,
        max_mtu: fields[30].trim_end_matches(')').parse()?,
    })
}

fn parse_cli_edge_dump_line(line: &str) -> Result<CliEdgeDump, Box<dyn Error>> {
    let fields = line.split_whitespace().collect::<Vec<_>>();
    if fields.len() != 15
        || fields.get(1) != Some(&"to")
        || fields.get(3) != Some(&"at")
        || fields.get(5) != Some(&"port")
        || fields.get(7) != Some(&"local")
        || fields.get(9) != Some(&"port")
        || fields.get(11) != Some(&"options")
        || fields.get(13) != Some(&"weight")
    {
        return Err(format!("bad C-style tincctl dump edges line: {line}").into());
    }

    Ok(CliEdgeDump {
        from: fields[0].to_owned(),
        to: fields[2].to_owned(),
        host: fields[4].to_owned(),
        port: fields[6].to_owned(),
        local_host: fields[8].to_owned(),
        local_port: fields[10].to_owned(),
        options: u32::from_str_radix(fields[12], 16)?,
        weight: fields[14].parse()?,
    })
}

fn parse_cli_subnet_dump_line(line: &str) -> Result<CliSubnetDump, Box<dyn Error>> {
    let fields = line.split_whitespace().collect::<Vec<_>>();
    if fields.len() != 3 || fields.get(1) != Some(&"owner") {
        return Err(format!("bad C-style tincctl dump subnets line: {line}").into());
    }

    Ok(CliSubnetDump {
        subnet: fields[0].to_owned(),
        owner: fields[2].to_owned(),
    })
}

fn parse_cli_connection_dump_line(line: &str) -> Result<CliConnectionDump, Box<dyn Error>> {
    let fields = line.split_whitespace().collect::<Vec<_>>();
    if fields.len() != 11
        || fields.get(1) != Some(&"at")
        || fields.get(3) != Some(&"port")
        || fields.get(5) != Some(&"options")
        || fields.get(7) != Some(&"socket")
        || fields.get(9) != Some(&"status")
    {
        return Err(format!("bad C-style tincctl dump connections line: {line}").into());
    }

    Ok(CliConnectionDump {
        name: fields[0].to_owned(),
        host: fields[2].to_owned(),
        port: fields[4].to_owned(),
        options: u32::from_str_radix(fields[6], 16)?,
        socket: fields[8].parse()?,
        status: u32::from_str_radix(fields[10], 16).or_else(|_| fields[10].parse())?,
    })
}

fn assert_cli_status_has(node: &CliNodeDump, mask: u32, label: &str) -> Result<(), Box<dyn Error>> {
    if node.status & mask == mask {
        Ok(())
    } else {
        Err(format!(
            "{label}: node {} missing status mask {mask:#x}; status={:#x}; node={node:?}",
            node.name, node.status
        )
        .into())
    }
}

fn assert_cli_status_lacks(
    node: &CliNodeDump,
    mask: u32,
    label: &str,
) -> Result<(), Box<dyn Error>> {
    if node.status & mask == 0 {
        Ok(())
    } else {
        Err(format!(
            "{label}: node {} unexpectedly has status mask {mask:#x}; status={:#x}; node={node:?}",
            node.name, node.status
        )
        .into())
    }
}

fn assert_c_dump_node_has_status_words(
    dump: &str,
    node: &str,
    words: &[&str],
) -> Result<(), Box<dyn Error>> {
    let line = c_dump_node_line(dump, node)?;
    let Some(status) = c_dump_node_status_field(line) else {
        return Err(format!("missing status field for {node} in C dump line:\n{line}").into());
    };
    let bits = u32::from_str_radix(status, 16)?;

    for word in words {
        if !c_node_status_has_word(bits, word) {
            return Err(format!(
                "missing status bit {word:?} for {node}; status field {status:?}; line:\n{line}"
            )
            .into());
        }
    }

    Ok(())
}

fn assert_c_dump_node_lacks_status_words(
    dump: &str,
    node: &str,
    words: &[&str],
) -> Result<(), Box<dyn Error>> {
    let line = c_dump_node_line(dump, node)?;
    let Some(status) = c_dump_node_status_field(line) else {
        return Err(format!("missing status field for {node} in C dump line:\n{line}").into());
    };
    let bits = u32::from_str_radix(status, 16)?;

    for word in words {
        if c_node_status_has_word(bits, word) {
            return Err(format!(
                "unexpected status bit {word:?} for {node}; status field {status:?}; line:\n{line}"
            )
            .into());
        }
    }

    Ok(())
}

fn assert_c_dump_node_has_route(
    dump: &str,
    node: &str,
    nexthop: &str,
    via: &str,
    distance: i32,
) -> Result<(), Box<dyn Error>> {
    let line = c_dump_node_line(dump, node)?;
    let needle = format!(" nexthop {nexthop} via {via} distance {distance} ");
    if line.contains(&needle) {
        return Ok(());
    }

    Err(format!("missing route {needle:?} for {node} in C dump line:\n{line}").into())
}

fn assert_c_dump_node_options_include(
    dump: &str,
    node: &str,
    mask: u32,
) -> Result<(), Box<dyn Error>> {
    let line = c_dump_node_line(dump, node)?;
    let Some(options) = c_dump_node_options_field(line) else {
        return Err(format!("missing options field for {node} in C dump line:\n{line}").into());
    };
    let bits = u32::from_str_radix(options, 16)?;
    if bits & mask == mask {
        return Ok(());
    }

    Err(format!(
        "missing options mask {mask:#x} for {node}; options field {options:?}; line:\n{line}"
    )
    .into())
}

fn assert_c_dump_edge_options_include(
    dump: &str,
    from: &str,
    to: &str,
    mask: u32,
) -> Result<(), Box<dyn Error>> {
    let prefix = format!("{from} to {to} ");
    let Some(line) = dump.lines().find(|line| line.starts_with(&prefix)) else {
        return Err(format!("missing edge {from}->{to} in C dump edges output:\n{dump}").into());
    };
    let Some(options) = line
        .split_once(" options ")
        .and_then(|(_, rest)| rest.split_once(" weight "))
        .map(|(options, _)| options)
    else {
        return Err(format!("missing options field for edge {from}->{to}:\n{line}").into());
    };
    let bits = u32::from_str_radix(options, 16)?;
    if bits & mask == mask {
        return Ok(());
    }

    Err(format!(
        "missing options mask {mask:#x} for edge {from}->{to}; options field {options:?}; line:\n{line}"
    )
    .into())
}

fn c_dump_node_line<'a>(dump: &'a str, node: &str) -> Result<&'a str, Box<dyn Error>> {
    dump.lines()
        .find(|line| line.starts_with(&format!("{node} id ")))
        .ok_or_else(|| format!("missing {node} in C dump nodes output:\n{dump}").into())
}

fn c_dump_node_options_field(line: &str) -> Option<&str> {
    let after_options = line.split_once(" options ")?.1;
    after_options
        .split_once(" status ")
        .map(|(options, _)| options)
}

fn c_dump_node_status_field(line: &str) -> Option<&str> {
    let after_status = line.split_once(" status ")?.1;
    after_status
        .split_once(" nexthop ")
        .map(|(status, _)| status)
}

fn c_node_status_has_word(bits: u32, word: &str) -> bool {
    let mask = match word {
        "validkey" => 1 << 1,
        "waitingforkey" => 1 << 2,
        "visited" => 1 << 3,
        "reachable" => 1 << 4,
        "indirect" => 1 << 5,
        "sptps" => 1 << 6,
        "udp_confirmed" => 1 << 7,
        "send_locally" => 1 << 8,
        "udppacket" => 1 << 9,
        "validkey_in" => 1 << 10,
        "has_address" => 1 << 11,
        "ping_sent" => 1 << 12,
        _ => return false,
    };
    bits & mask != 0
}

fn run_iperf_pair(
    source_netns: &str,
    target_netns: &str,
    target_address: &str,
    family: NetnsAddressFamily,
    cleanup: &NetnsCleanup,
) -> Result<(), Box<dyn Error>> {
    run_iperf_once(
        source_netns,
        target_netns,
        target_address,
        family,
        false,
        cleanup,
    )?;
    run_iperf_once(
        source_netns,
        target_netns,
        target_address,
        family,
        true,
        cleanup,
    )
}

fn run_iperf_once(
    source_netns: &str,
    target_netns: &str,
    target_address: &str,
    family: NetnsAddressFamily,
    udp: bool,
    cleanup: &NetnsCleanup,
) -> Result<(), Box<dyn Error>> {
    cleanup.ensure_children_alive()?;
    let mut server_args = vec!["netns", "exec", target_netns, "iperf3", "-s", "-1"];
    server_args.push(match family {
        NetnsAddressFamily::Ipv4 => "-4",
        NetnsAddressFamily::Ipv6 => "-6",
    });
    let mut server = Command::new("ip")
        .args(&server_args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    thread::sleep(Duration::from_millis(300));

    let mut client_args = vec![
        "netns",
        "exec",
        source_netns,
        "iperf3",
        "-c",
        target_address,
        "-f",
        "m",
    ];
    client_args.push(match family {
        NetnsAddressFamily::Ipv4 => "-4",
        NetnsAddressFamily::Ipv6 => "-6",
    });
    if udp {
        client_args.extend(["-u", "-b", "1G", "-t", "2"]);
    } else {
        client_args.extend(["-t", "2"]);
    }
    let client = Command::new("ip")
        .args(&client_args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let (client_completed, client) = wait_with_output_timeout(client, Duration::from_secs(30))?;
    let _ = server.kill();
    let server_output = server.wait_with_output()?;

    let client_text = format!(
        "{}{}",
        String::from_utf8_lossy(&client.stdout),
        String::from_utf8_lossy(&client.stderr)
    );
    let server_text = format!(
        "{}{}",
        String::from_utf8_lossy(&server_output.stdout),
        String::from_utf8_lossy(&server_output.stderr)
    );
    if client_completed && client.status.success() && client_text.contains("bits/sec") {
        return Ok(());
    }

    Err(format!(
        "{} iperf from {source_netns} to {target_address} {}\nclient:\n{client_text}\nserver:\n{server_text}\n{}",
        if udp { "UDP" } else { "TCP" },
        if client_completed { "failed" } else { "timed out" },
        cleanup.diagnostics()
    )
    .into())
}

fn run_ip(args: &[&str]) -> Result<(), Box<dyn Error>> {
    let output = Command::new("ip").args(args).output()?;
    if output.status.success() {
        return Ok(());
    }

    Err(format!(
        "ip {} failed\nstdout:\n{}\nstderr:\n{}",
        args.join(" "),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
    .into())
}

fn run_rust_tincctl(args: &[&str]) -> Result<String, Box<dyn Error>> {
    match run_tincctl(args.iter().map(|arg| (*arg).to_owned()).collect())? {
        TincCtlAction::Exit { code: 0, output } => Ok(output),
        TincCtlAction::Exit { code, output } => Err(format!(
            "rust tincctl {} exited with {code}\n{output}",
            args.join(" ")
        )
        .into()),
        TincCtlAction::ExitBytes { code, output } => Err(format!(
            "rust tincctl {} returned bytes with code {code}\n{}",
            args.join(" "),
            String::from_utf8_lossy(&output)
        )
        .into()),
        TincCtlAction::Command(command) => {
            Err(format!("rust tincctl command {} was not implemented", command.name).into())
        }
    }
}

fn run_rust_tinc_binary(
    binary: &Path,
    netns: &str,
    confdir: &Path,
    args: &[&str],
) -> Result<String, Box<dyn Error>> {
    let output = Command::new("ip")
        .args(["netns", "exec", netns])
        .arg(binary)
        .args(["--config"])
        .arg(confdir)
        .args(args)
        .output()?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    if output.status.success() {
        Ok(text)
    } else {
        Err(format!(
            "Rust tinc binary {} failed with status {:?}\n{text}",
            args.join(" "),
            output.status.code()
        )
        .into())
    }
}

fn run_rust_tinc_binary_expect_failure(
    binary: &Path,
    netns: &str,
    confdir: &Path,
    args: &[&str],
) -> Result<String, Box<dyn Error>> {
    let output = Command::new("ip")
        .args(["netns", "exec", netns])
        .arg(binary)
        .args(["--config"])
        .arg(confdir)
        .args(args)
        .output()?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    if output.status.success() {
        Err(format!(
            "Rust tinc binary {} unexpectedly succeeded\n{text}",
            args.join(" ")
        )
        .into())
    } else {
        Ok(text)
    }
}

fn rust_tinc_binary() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("RUST_TINC_PATH") {
        let path = PathBuf::from(path);
        if path.is_file() {
            return Some(path);
        }
    }

    let tincd = Path::new(TINCD);
    for ancestor in tincd.ancestors() {
        let candidate = ancestor.join("tinc");
        if candidate.is_file() {
            return Some(candidate);
        }
    }

    let candidate = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("target")
        .join("debug")
        .join("tinc");
    if candidate.is_file() {
        return Some(candidate);
    }

    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = Command::new(cargo)
        .args(["build", "-p", "tincctl", "--bin", "tinc"])
        .current_dir(&workspace)
        .output();

    match output {
        Ok(output) if output.status.success() => {
            if candidate.is_file() {
                return Some(candidate);
            }
        }
        Ok(output) => eprintln!(
            "failed to build Rust tinc binary with cargo build -p tincctl --bin tinc\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
        Err(error) => eprintln!("failed to run cargo build -p tincctl --bin tinc: {error}"),
    }

    None
}

fn run_rust_tincctl_for_daemon(
    _daemon_binary: &Path,
    netns: &str,
    confdir: &Path,
    args: &[&str],
) -> Result<String, Box<dyn Error>> {
    let Some(tinc_binary) = rust_tinc_binary() else {
        return Err(format!(
            "could not find Rust tinc binary; set RUST_TINC_PATH or build target/debug/tinc"
        )
        .into());
    };

    run_rust_tinc_binary(&tinc_binary, netns, confdir, args)
}

fn run_c_tinc(
    binary: &Path,
    netns: &str,
    confdir: &Path,
    args: &[&str],
) -> Result<String, Box<dyn Error>> {
    let output = Command::new("ip")
        .args(["netns", "exec", netns])
        .arg(binary)
        .args(["-c"])
        .arg(confdir)
        .args(args)
        .output()?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        Err(format!(
            "C tinc {} failed with status {:?}\n{text}",
            args.join(" "),
            output.status.code()
        )
        .into())
    }
}

fn run_c_tinc_expect_failure(
    binary: &Path,
    netns: &str,
    confdir: &Path,
    args: &[&str],
) -> Result<String, Box<dyn Error>> {
    let output = Command::new("ip")
        .args(["netns", "exec", netns])
        .arg(binary)
        .args(["-c"])
        .arg(confdir)
        .args(args)
        .output()?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    if output.status.success() {
        Err(format!("C tinc {} unexpectedly succeeded\n{text}", args.join(" ")).into())
    } else {
        Ok(text)
    }
}

fn wait_for_child_exit(cleanup: &mut NetnsCleanup, name: &str) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + Duration::from_secs(8);
    let Some(index) = cleanup
        .children
        .iter()
        .position(|(child_name, _)| child_name == name)
    else {
        return Err(format!("unknown child {name}").into());
    };

    while Instant::now() < deadline {
        if cleanup.children[index].1.try_wait()?.is_some() {
            let (_, mut child) = cleanup.children.remove(index);
            let _ = child.wait();
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }

    Err(format!(
        "timed out waiting for {name} tincd to exit\n{}",
        cleanup.logs()
    )
    .into())
}

fn wait_for_pid_exit(pid: u32) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + Duration::from_secs(8);
    while Instant::now() < deadline {
        if !process_is_running(pid) {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }

    Err(format!("timed out waiting for process {pid} to exit").into())
}

fn read_pidfile_pid(pidfile: &Path) -> Result<u32, Box<dyn Error>> {
    let contents = fs::read_to_string(pidfile)?;
    contents
        .split_whitespace()
        .next()
        .ok_or_else(|| format!("pidfile {} is empty", pidfile.display()).into())
        .and_then(|pid| {
            pid.parse::<u32>().map_err(|error| {
                format!(
                    "pidfile {} has invalid pid {pid}: {error}",
                    pidfile.display()
                )
                .into()
            })
        })
}

fn try_ip(args: &[&str]) -> bool {
    Command::new("ip")
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn process_is_running(pid: u32) -> bool {
    Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn command_available(command: &str) -> bool {
    Command::new(command)
        .arg("--help")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

fn c_tincd_binary() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("C_TINCD_PATH") {
        let path = PathBuf::from(path);
        if path.is_file() {
            return Some(path);
        }
        eprintln!(
            "skipping configured C tincd binary because it does not exist: {}",
            path.display()
        );
        return None;
    }

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let candidate = manifest_dir.join("../../vendor/tinc/build-c/src/tincd");
    if candidate.is_file() {
        Some(candidate)
    } else {
        None
    }
}

fn c_zlib_tincd_binary() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("C_TINCD_ZLIB_PATH") {
        let path = PathBuf::from(path);
        if path.is_file() {
            return Some(path);
        }
        eprintln!(
            "configured zlib-enabled C tincd binary does not exist: {}",
            path.display()
        );
        return None;
    }

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let candidate = manifest_dir.join("../../vendor/tinc/build-c-zlib/src/tincd");
    if candidate.is_file() {
        Some(candidate)
    } else {
        None
    }
}

fn c_compression_tincd_binary() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("C_TINCD_COMPRESSION_PATH") {
        let path = PathBuf::from(path);
        if path.is_file() {
            return Some(path);
        }
        eprintln!(
            "configured compression-enabled C tincd binary does not exist: {}",
            path.display()
        );
        return None;
    }

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let candidate = manifest_dir.join("../../vendor/tinc/build-c-compression/src/tincd");
    if candidate.is_file() {
        Some(candidate)
    } else {
        None
    }
}

fn c_lz4_tincd_binary() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("C_TINCD_LZ4_PATH") {
        let path = PathBuf::from(path);
        if path.is_file() {
            return Some(path);
        }
        eprintln!(
            "configured lz4-enabled C tincd binary does not exist: {}",
            path.display()
        );
        return None;
    }

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let candidate = manifest_dir.join("../../vendor/tinc/build-c-lz4/src/tincd");
    if candidate.is_file() {
        Some(candidate)
    } else {
        None
    }
}

fn c_tinc_binary() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("C_TINC_PATH") {
        let path = PathBuf::from(path);
        if path.is_file() {
            return Some(path);
        }
        eprintln!(
            "skipping configured C tinc binary because it does not exist: {}",
            path.display()
        );
        return None;
    }

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let candidate = manifest_dir.join("../../vendor/tinc/build-c/src/tinc");
    if candidate.is_file() {
        Some(candidate)
    } else {
        None
    }
}

fn c_tincd_with_feature(
    default_binary: &Path,
    feature: &str,
    legacy_name: &str,
) -> Result<Option<PathBuf>, Box<dyn Error>> {
    if c_tincd_has_feature(default_binary, feature)? {
        return Ok(Some(default_binary.to_path_buf()));
    }

    for candidate in [
        c_compression_tincd_binary(),
        c_zlib_tincd_binary(),
        c_lz4_tincd_binary(),
    ]
    .into_iter()
    .flatten()
    {
        if c_tincd_has_feature(&candidate, feature)? {
            return Ok(Some(candidate));
        }
        eprintln!(
            "skipping {} C tincd candidate without {feature}: {}",
            legacy_name,
            candidate.display()
        );
    }

    Ok(None)
}

fn c_tincd_without_feature(feature: &str) -> Result<Option<PathBuf>, Box<dyn Error>> {
    let mut candidates = Vec::new();
    if let Some(binary) = c_tincd_binary() {
        candidates.push(binary);
    }
    if let Some(binary) = c_compression_tincd_binary() {
        candidates.push(binary);
    }
    if let Some(binary) = c_zlib_tincd_binary() {
        candidates.push(binary);
    }
    if let Some(binary) = c_lz4_tincd_binary() {
        candidates.push(binary);
    }

    for candidate in candidates {
        if !c_tincd_has_feature(&candidate, feature)? {
            return Ok(Some(candidate));
        }
        eprintln!(
            "skipping C tincd candidate with {feature}: {}",
            candidate.display()
        );
    }

    Ok(None)
}

fn c_tincd_has_feature(binary: &Path, feature: &str) -> Result<bool, Box<dyn Error>> {
    let output = Command::new(binary).arg("--version").output()?;
    let version = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    if !output.status.success() {
        return Err(format!(
            "could not read C tincd features from {}:\n{version}",
            binary.display()
        )
        .into());
    }
    Ok(version
        .lines()
        .find_map(|line| line.strip_prefix("Features:"))
        .is_some_and(|features| features.split_whitespace().any(|token| token == feature)))
}

fn read_log(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|error| format!("<could not read log: {error}>"))
}

fn wait_for_file_contains(
    path: &Path,
    needle: &str,
    cleanup: &NetnsCleanup,
    label: &str,
) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut last_contents = String::new();

    while Instant::now() < deadline {
        cleanup.ensure_children_alive()?;
        last_contents = read_log(path);
        if last_contents.contains(needle) {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }

    Err(format!(
        "{label} did not contain expected entry {needle:?}\nlast contents:\n{last_contents}\n{}",
        cleanup.logs()
    )
    .into())
}

fn wait_for_log_contains(
    cleanup: &NetnsCleanup,
    child_name: &str,
    needles: &[&str],
    label: &str,
) -> Result<(), Box<dyn Error>> {
    let path = cleanup.workspace.join(format!("{child_name}.log"));
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut last_log = String::new();

    while Instant::now() < deadline {
        cleanup.ensure_children_alive()?;
        last_log = read_log(&path);
        if needles.iter().all(|needle| last_log.contains(needle)) {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }

    Err(format!(
        "{label} daemon log did not contain expected entries {:?}\nlast log:\n{last_log}\n{}",
        needles,
        cleanup.logs()
    )
    .into())
}

fn unique_suffix() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!(
        "{:x}",
        (nanos ^ u128::from(std::process::id())) & 0x00ff_ffff
    )
}

struct TempWorkspace {
    path: PathBuf,
}

impl TempWorkspace {
    fn new(prefix: &str) -> Result<Self, Box<dyn Error>> {
        let path = std::env::temp_dir().join(format!("{prefix}-{}", unique_suffix()));
        fs::create_dir_all(&path)?;
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempWorkspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

struct NetnsCleanup {
    workspace: PathBuf,
    namespaces: Vec<String>,
    root_links: Vec<String>,
    children: Vec<(String, Child)>,
    daemon_pidfiles: Vec<PathBuf>,
}

impl NetnsCleanup {
    fn new(workspace: PathBuf) -> Self {
        Self {
            workspace,
            namespaces: Vec::new(),
            root_links: Vec::new(),
            children: Vec::new(),
            daemon_pidfiles: Vec::new(),
        }
    }

    fn add_namespace(&mut self, namespace: String) {
        self.namespaces.push(namespace);
    }

    fn add_root_link(&mut self, link: String) {
        self.root_links.push(link);
    }

    fn add_daemon_pidfile(&mut self, pidfile: PathBuf) {
        if !self.daemon_pidfiles.iter().any(|path| path == &pidfile) {
            self.daemon_pidfiles.push(pidfile);
        }
    }

    fn remove_daemon_pidfile(&mut self, pidfile: &Path) {
        self.daemon_pidfiles.retain(|path| path != pidfile);
    }

    fn spawn(
        &mut self,
        name: &str,
        confdir: &Path,
        netns: &str,
        log: &Path,
    ) -> Result<(), Box<dyn Error>> {
        self.children
            .push((name.to_owned(), spawn_tincd(confdir, netns, log)?));
        Ok(())
    }

    fn spawn_with_binary(
        &mut self,
        name: &str,
        binary: &Path,
        confdir: &Path,
        netns: &str,
        log: &Path,
    ) -> Result<(), Box<dyn Error>> {
        self.children.push((
            name.to_owned(),
            spawn_tincd_with_binary(binary, confdir, netns, log)?,
        ));
        Ok(())
    }

    fn kill_child(&mut self, name: &str) -> Result<(), Box<dyn Error>> {
        let Some(index) = self
            .children
            .iter()
            .position(|(child_name, _)| child_name == name)
        else {
            return Err(format!("cannot kill unknown tincd child {name}").into());
        };
        let (_, mut child) = self.children.remove(index);
        let _ = child.kill();
        let _ = child.wait();
        Ok(())
    }

    fn ensure_children_alive(&self) -> Result<(), Box<dyn Error>> {
        for (name, child) in &self.children {
            if !child_is_running(child) {
                return Err(format!(
                    "{name} tincd exited\n{}",
                    read_log(&self.workspace.join(format!("{name}.log")))
                )
                .into());
            }
        }

        Ok(())
    }

    fn logs(&self) -> String {
        self.children
            .iter()
            .map(|(name, _)| {
                format!(
                    "{name} log:\n{}",
                    read_log(&self.workspace.join(format!("{name}.log")))
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn diagnostics(&self) -> String {
        let dumps = self
            .children
            .iter()
            .map(|(name, _)| {
                format!(
                    "{name} nodes:\n{}",
                    dump_nodes(&self.workspace.join(name))
                        .unwrap_or_else(|error| { format!("<could not dump nodes: {error}>") })
                )
            })
            .collect::<Vec<_>>()
            .join("\n");

        format!("{}\n{}", self.logs(), dumps)
    }
}

fn dump_nodes(confdir: &Path) -> Result<String, Box<dyn Error>> {
    Ok(read_raw_control_dump(confdir, REQ_DUMP_NODES_RAW)?.join(""))
}

fn read_raw_nodes(confdir: &Path) -> Result<Vec<RawNodeDump>, Box<dyn Error>> {
    read_raw_control_dump(confdir, REQ_DUMP_NODES_RAW)?
        .into_iter()
        .map(|line| parse_raw_node_dump(&line))
        .collect()
}

fn read_raw_edges(confdir: &Path) -> Result<Vec<RawEdgeDump>, Box<dyn Error>> {
    read_raw_control_dump(confdir, REQ_DUMP_EDGES_RAW)?
        .into_iter()
        .map(|line| parse_raw_edge_dump(&line))
        .collect()
}

fn read_raw_subnets(confdir: &Path) -> Result<Vec<RawSubnetDump>, Box<dyn Error>> {
    read_raw_control_dump(confdir, REQ_DUMP_SUBNETS_RAW)?
        .into_iter()
        .map(|line| parse_raw_subnet_dump(&line))
        .collect()
}

fn read_raw_control_dump(confdir: &Path, request: i32) -> Result<Vec<String>, Box<dyn Error>> {
    let pid = fs::read_to_string(confdir.join("pid"))?;
    let fields = pid.split_whitespace().collect::<Vec<_>>();
    if fields.len() < 2 {
        return Err("malformed pidfile".into());
    }
    let cookie = fields[1];
    let socket_path = confdir.join("pid.socket");
    let mut stream = std::os::unix::net::UnixStream::connect(socket_path)?;
    stream.set_read_timeout(Some(Duration::from_secs(1)))?;
    stream.set_write_timeout(Some(Duration::from_secs(1)))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut line = String::new();
    write!(stream, "0 ^{cookie} 0\n")?;
    stream.flush()?;
    reader.read_line(&mut line)?;
    line.clear();
    reader.read_line(&mut line)?;
    write!(stream, "{CONTROL_REQUEST} {request}\n")?;
    stream.flush()?;

    let mut output = Vec::new();
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() == 2
            && fields[0].parse::<i32>().ok() == Some(CONTROL_REQUEST)
            && fields[1].parse::<i32>().ok() == Some(request)
        {
            break;
        }
        output.push(line.clone());
    }
    Ok(output)
}

fn parse_raw_node_dump(line: &str) -> Result<RawNodeDump, Box<dyn Error>> {
    let fields = line.split_whitespace().collect::<Vec<_>>();
    if fields.len() != 25
        || fields[0].parse::<i32>().ok() != Some(CONTROL_REQUEST)
        || fields[1].parse::<i32>().ok() != Some(REQ_DUMP_NODES_RAW)
        || fields[5] != "port"
    {
        return Err(format!("bad raw node dump line: {line}").into());
    }

    Ok(RawNodeDump {
        name: fields[2].to_owned(),
        id: fields[3].to_owned(),
        host: fields[4].to_owned(),
        port: fields[6].to_owned(),
        cipher: fields[7].parse()?,
        digest: fields[8].parse()?,
        mac_length: fields[9].parse()?,
        compression: fields[10].parse()?,
        options: u32::from_str_radix(fields[11], 16)?,
        status: u32::from_str_radix(fields[12], 16)?,
        nexthop: fields[13].to_owned(),
        via: fields[14].to_owned(),
        distance: fields[15].parse()?,
        pmtu: fields[16].parse()?,
        min_mtu: fields[17].parse()?,
        max_mtu: fields[18].parse()?,
        udp_ping_rtt: fields[20].parse()?,
    })
}

fn parse_raw_edge_dump(line: &str) -> Result<RawEdgeDump, Box<dyn Error>> {
    let fields = line.split_whitespace().collect::<Vec<_>>();
    if fields.len() != 12
        || fields[0].parse::<i32>().ok() != Some(CONTROL_REQUEST)
        || fields[1].parse::<i32>().ok() != Some(REQ_DUMP_EDGES_RAW)
        || fields[5] != "port"
        || fields[8] != "port"
    {
        return Err(format!("bad raw edge dump line: {line}").into());
    }

    Ok(RawEdgeDump {
        from: fields[2].to_owned(),
        to: fields[3].to_owned(),
        host: fields[4].to_owned(),
        port: fields[6].to_owned(),
        local_host: fields[7].to_owned(),
        local_port: fields[9].to_owned(),
        options: u32::from_str_radix(fields[10], 16)?,
        weight: fields[11].parse()?,
    })
}

fn parse_raw_subnet_dump(line: &str) -> Result<RawSubnetDump, Box<dyn Error>> {
    let fields = line.split_whitespace().collect::<Vec<_>>();
    if fields.len() != 4
        || fields[0].parse::<i32>().ok() != Some(CONTROL_REQUEST)
        || fields[1].parse::<i32>().ok() != Some(REQ_DUMP_SUBNETS_RAW)
    {
        return Err(format!("bad raw subnet dump line: {line}").into());
    }

    Ok(RawSubnetDump {
        subnet: fields[2]
            .split_once('#')
            .map(|(subnet, _)| subnet)
            .unwrap_or(fields[2])
            .to_owned(),
        owner: fields[3].to_owned(),
    })
}

impl Drop for NetnsCleanup {
    fn drop(&mut self) {
        for (_, child) in &mut self.children {
            let _ = child.kill();
            let _ = child.wait();
        }
        for pidfile in &self.daemon_pidfiles {
            if let Some(confdir) = pidfile.parent() {
                let _ = run_rust_tincctl(&["tinc", "--config", confdir.to_str().unwrap(), "stop"]);
            }
            if let Ok(pid) = read_pidfile_pid(pidfile) {
                let _ = Command::new("kill").arg(pid.to_string()).status();
            }
        }
        for link in &self.root_links {
            let _ = Command::new("ip").args(["link", "del", link]).status();
        }
        for namespace in &self.namespaces {
            let _ = Command::new("ip")
                .args(["netns", "del", namespace])
                .status();
        }
    }
}

fn child_is_running(child: &Child) -> bool {
    Command::new("kill")
        .args(["-0", &child.id().to_string()])
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}
