use crate::*;

#[cfg(test)]
pub(crate) fn runtime_local_options(config: &RuntimeConfig) -> u32 {
    runtime_meta_options(
        config.state.experimental,
        config.daemon.indirect_data,
        config.daemon.tcp_only,
        config.daemon.pmtu_discovery,
        config.daemon.clamp_mss,
        None,
    )
}

pub(crate) fn runtime_meta_options(
    experimental: bool,
    local_indirect_data: bool,
    local_tcp_only: bool,
    local_pmtu_discovery: bool,
    local_clamp_mss: bool,
    peer: Option<&PeerMetaConfig>,
) -> u32 {
    let mut options = if experimental {
        (PROT_MINOR as u32) << 24
    } else {
        0
    };

    if local_indirect_data || peer.is_some_and(|peer| peer.indirect_data) {
        options |= OPTION_INDIRECT;
    }

    if local_tcp_only || peer.is_some_and(|peer| peer.tcp_only) {
        options |= OPTION_TCPONLY | OPTION_INDIRECT;
    }

    if local_pmtu_discovery && options & OPTION_TCPONLY == 0 {
        options |= OPTION_PMTU_DISCOVERY;
    }

    let mut clamp_mss = local_clamp_mss;
    if let Some(peer_clamp_mss) = peer.and_then(|peer| peer.clamp_mss) {
        clamp_mss = peer_clamp_mss;
    }

    if clamp_mss {
        options |= OPTION_CLAMP_MSS;
    }

    options
}

pub(crate) fn runtime_config_for_keys(config: &RuntimeConfig, keys: &RuntimeKeys) -> RuntimeConfig {
    let mut config = config.clone();
    reconcile_runtime_config_with_keys(&mut config, keys);
    config
}

pub(crate) fn reconcile_runtime_config_with_keys(config: &mut RuntimeConfig, keys: &RuntimeKeys) {
    let experimental = config
        .experimental_protocol
        .unwrap_or(keys.private_key.is_some());
    config.state.experimental = experimental;

    if let Some(myself) = config.state.graph.node_mut(&config.name) {
        myself.status.sptps = experimental;
        myself.options = runtime_meta_options(
            true,
            config.daemon.indirect_data,
            config.daemon.tcp_only,
            config.daemon.pmtu_discovery,
            config.daemon.clamp_mss,
            None,
        );
    }
}

pub(crate) fn runtime_sptps_key_exchange(
    config: &RuntimeConfig,
    keys: &RuntimeKeys,
) -> Option<SptpsKeyExchange> {
    let private_key = keys.private_key.clone()?;
    let mut exchange = SptpsKeyExchange::new(
        config.name.clone(),
        private_key,
        runtime_sptps_packet_type(config),
    )
    .expect("SPTPS UDP packet type is a valid application record");
    exchange = exchange.with_replay_window_bytes(runtime_sptps_replay_window_bytes(config));

    for (peer, key) in &keys.peer_public_keys {
        exchange.insert_peer_public_key(peer.clone(), *key);
    }

    Some(exchange)
}

pub(crate) fn runtime_sptps_packet_type(config: &RuntimeConfig) -> u8 {
    if config.engine.route.routing_mode == RoutingMode::Router {
        SPTPS_UDP_ROUTER_PACKET_TYPE
    } else {
        SPTPS_PACKET_TYPE_MAC
    }
}

pub(crate) fn runtime_sptps_replay_window_bytes(config: &RuntimeConfig) -> usize {
    config
        .daemon
        .replay_window
        .unwrap_or(DEFAULT_SPTPS_REPLAY_WINDOW_BYTES)
}

pub(crate) fn runtime_legacy_replay_window_bytes(config: &RuntimeConfig) -> usize {
    config
        .daemon
        .replay_window
        .unwrap_or(DEFAULT_REPLAY_WINDOW_BYTES)
}

pub(crate) fn runtime_legacy_udp_codec(config: &RuntimeConfig) -> LegacyUdpCodec {
    LegacyUdpCodec::new(runtime_legacy_replay_window_bytes(config))
}

pub(crate) fn runtime_sptps_packet_codec(
    config: &RuntimeConfig,
    state: &NetworkState,
) -> SptpsPacketCodec {
    SptpsPacketCodec::new(
        NodeId::from_name(&config.name),
        NodeIdTable::from_network_state(state),
    )
}
