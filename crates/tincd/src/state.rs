use crate::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RuntimeIoProgress {
    Processed,
    NotReady,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Default)]
pub(crate) struct RuntimeUdpRecvBatch {
    buffers: Vec<[u8; MAX_DATAGRAM_SIZE]>,
    addrs: Vec<libc::sockaddr_storage>,
}

#[cfg(target_os = "linux")]
impl RuntimeUdpRecvBatch {
    fn ensure_capacity(&mut self, count: usize) {
        while self.buffers.len() < count {
            self.buffers.push([0u8; MAX_DATAGRAM_SIZE]);
            self.addrs.push(unsafe { std::mem::zeroed() });
        }
    }

    fn prepare(&mut self, count: usize) -> (Vec<libc::iovec>, Vec<libc::mmsghdr>) {
        self.ensure_capacity(count);
        let mut iovecs = Vec::with_capacity(count);
        let mut messages = Vec::with_capacity(count);
        for index in 0..count {
            self.addrs[index] = unsafe { std::mem::zeroed() };
            iovecs.push(libc::iovec {
                iov_base: self.buffers[index].as_mut_ptr().cast(),
                iov_len: MAX_DATAGRAM_SIZE,
            });
            let mut message: libc::mmsghdr = unsafe { std::mem::zeroed() };
            message.msg_hdr.msg_name =
                (&mut self.addrs[index] as *mut libc::sockaddr_storage).cast();
            message.msg_hdr.msg_namelen =
                std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
            message.msg_hdr.msg_iov = &mut iovecs[index];
            message.msg_hdr.msg_iovlen = 1;
            messages.push(message);
        }
        (iovecs, messages)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeListenSocketInfo {
    pub address: SocketAddr,
    pub bind_to: bool,
}

#[derive(Debug)]
pub struct RuntimeDaemonState {
    pub(crate) listen_sockets: Vec<RuntimeListenSocket>,
    #[cfg(target_os = "linux")]
    pub(crate) udp_recv_batch: RuntimeUdpRecvBatch,
    pub(crate) meta_connections: Vec<RuntimeMetaConnection>,
    pub(crate) state: NetworkState,
    pub(crate) runtime_config: RuntimeConfig,
    pub(crate) local_edge_connections: BTreeMap<String, u64>,
    pub(crate) local_name: String,
    pub(crate) netname: Option<String>,
    pub(crate) local_port: String,
    pub(crate) local_indirect_data: bool,
    pub(crate) local_tcp_only: bool,
    pub(crate) local_pmtu_discovery: bool,
    pub(crate) local_clamp_mss: bool,
    pub(crate) local_weight: i32,
    pub(crate) strict_subnets: bool,
    pub(crate) tunnel_server: bool,
    pub(crate) bypass_security: bool,
    pub(crate) proxy: ProxyConfig,
    pub(crate) peer_meta_configs: BTreeMap<String, PeerMetaConfig>,
    pub(crate) fwmark: i32,
    pub(crate) max_output_buffer_size: usize,
    pub(crate) max_outgoing_retry_timeout_secs: u64,
    pub(crate) outgoing_retry: BTreeMap<String, OutgoingRetryState>,
    pub(crate) autoconnect_outgoing: BTreeMap<String, OutgoingRetryState>,
    pub(crate) outgoing_address_cursors: BTreeMap<String, usize>,
    pub(crate) max_connection_burst: u64,
    pub(crate) connection_burst: ConnectionBurstCounter,
    pub(crate) samehost_burst: ConnectionBurstCounter,
    pub(crate) previous_tarpit_peer: Option<IpAddr>,
    pub(crate) tarpit: VecDeque<TcpStream>,
    pub(crate) topology_backoff: RuntimeTopologyBackoff,
    pub(crate) next_tinc_periodic: Instant,
    pub(crate) next_meta_ping_check: Instant,
    pub(crate) device_standby: bool,
    pub(crate) device_enabled: bool,
    pub(crate) device_read_errors: u32,
    pub(crate) device_read_backoff_until: Option<Instant>,
    pub(crate) ping_interval: Duration,
    pub(crate) ping_timeout: Duration,
    pub(crate) mac_expire: i32,
    pub(crate) next_mac_subnet_age: Instant,
    pub(crate) mtu_info_interval: Duration,
    pub(crate) udp_info_interval: Duration,
    pub(crate) local_discovery: bool,
    pub(crate) udp_discovery: bool,
    pub(crate) udp_discovery_keepalive_interval: Duration,
    pub(crate) udp_discovery_interval: Duration,
    pub(crate) udp_discovery_timeout: Duration,
    pub(crate) hostnames: bool,
    pub(crate) udp_unconfirmed_guess_counter: usize,
    pub(crate) mtu_info_sent: BTreeMap<String, Instant>,
    pub(crate) udp_info_sent: BTreeMap<String, Instant>,
    pub(crate) udp_probe: BTreeMap<String, RuntimeUdpProbeState>,
    pub(crate) udp_socket_by_peer: BTreeMap<String, usize>,
    pub(crate) legacy_last_req_key: BTreeMap<String, Instant>,
    pub(crate) legacy_last_hard_try_secs: i64,
    pub(crate) sptps_last_req_key: BTreeMap<String, Instant>,
    pub(crate) key_lifetime_secs: i32,
    pub(crate) next_key_expire: Option<Instant>,
    pub(crate) keys: RuntimeKeys,
    pub(crate) addresses: NodeAddressTable,
    pub(crate) key_exchange: Option<SptpsKeyExchange>,
    pub(crate) packet_codec: SptpsPacketCodec,
    pub(crate) legacy_codec: LegacyUdpCodec,
    pub(crate) legacy_cipher: LegacyCipherAlgorithm,
    pub(crate) legacy_digest: LegacyDigest,
    pub(crate) legacy_compression: CompressionLevel,
    pub(crate) engine_config: EngineConfig,
    pub(crate) device: RuntimeDevice,
    pub(crate) traffic: BTreeMap<String, TrafficCounters>,
    pub(crate) pcap_subscribers: Vec<RuntimeControlPcapSubscriber>,
    #[cfg(test)]
    pub(crate) log_entries: VecDeque<RuntimeLogEntry>,
    pub(crate) log_subscribers: Vec<RuntimeControlLogSubscriber>,
    pub(crate) log_sink: Option<RuntimeLogSink>,
    pub(crate) upnp_log_receiver: Option<RuntimeUpnpLogReceiver>,
    #[cfg(unix)]
    pub(crate) umbilical_log_sink: Option<RuntimeUmbilicalLogSink>,
    pub(crate) debug_level: i32,
    pub(crate) confbase: Option<PathBuf>,
    pub(crate) script_context: Option<RuntimeScriptContext>,
    pub(crate) invitation: Option<RuntimeInvitationContext>,
    pub(crate) next_connection_id: u64,
    pub(crate) next_meta_nonce: u32,
    pub(crate) past_requests: PastRequestCache,
    pub(crate) next_past_request_age: Option<Instant>,
    pub(crate) strict_forwarded_topology: VecDeque<MetaMessage>,
    pub(crate) packet_diag_counts: BTreeMap<String, u64>,
    pub(crate) pending_close_reason: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct RuntimeUdpProbeState {
    pub(crate) udp_ping_sent: Option<Instant>,
    pub(crate) udp_reply_sent: Option<Instant>,
    pub(crate) udp_ping_timeout: Option<Instant>,
    pub(crate) udp_ping_rtt: Option<Duration>,
    pub(crate) mtu_ping_sent: Option<Instant>,
    pub(crate) max_recent_len: usize,
}

#[derive(Clone, Debug)]
pub(crate) struct RuntimeScriptContext {
    pub(crate) config: RuntimeConfig,
    pub(crate) options: TincdOptions,
    pub(crate) device_info: DeviceInfo,
}

#[derive(Clone, Debug)]
pub(crate) struct RuntimeInvitationContext {
    pub(crate) confbase: PathBuf,
    pub(crate) key: TincEd25519PrivateKey,
    pub(crate) expire: Duration,
}

impl RuntimeDaemonState {
    pub fn new(
        listen_sockets: Vec<RuntimeListenSocket>,
        config: &RuntimeConfig,
        keys: RuntimeKeys,
    ) -> Self {
        let config = runtime_config_for_keys(config, &keys);
        let config = &config;
        let now = Instant::now();
        let now_secs = current_unix_secs();
        let local_port = runtime_local_port(config, &listen_sockets);
        let mut network_state = config.state.clone();
        if let Some(myself) = network_state.graph.node_mut(&config.name) {
            myself.last_state_change = now_secs;
        }
        let mut state = Self {
            listen_sockets,
            #[cfg(target_os = "linux")]
            udp_recv_batch: RuntimeUdpRecvBatch::default(),
            meta_connections: Vec::new(),
            state: network_state,
            runtime_config: config.clone(),
            local_edge_connections: BTreeMap::new(),
            local_name: config.name.clone(),
            netname: None,
            local_port,
            local_indirect_data: config.daemon.indirect_data,
            local_tcp_only: config.daemon.tcp_only,
            local_pmtu_discovery: config.daemon.pmtu_discovery,
            local_clamp_mss: config.daemon.clamp_mss,
            local_weight: runtime_local_weight(config),
            strict_subnets: config.strict_subnets,
            tunnel_server: config.tunnel_server,
            bypass_security: false,
            proxy: config.daemon.proxy.clone(),
            peer_meta_configs: config.peer_meta_configs.clone(),
            fwmark: config.daemon.fwmark,
            max_output_buffer_size: config.daemon.max_output_buffer_size,
            max_outgoing_retry_timeout_secs: config.daemon.max_timeout as u64,
            outgoing_retry: BTreeMap::new(),
            autoconnect_outgoing: BTreeMap::new(),
            outgoing_address_cursors: BTreeMap::new(),
            max_connection_burst: config.daemon.max_connection_burst as u64,
            connection_burst: ConnectionBurstCounter::new(Instant::now()),
            samehost_burst: ConnectionBurstCounter::new(Instant::now()),
            previous_tarpit_peer: None,
            tarpit: VecDeque::new(),
            topology_backoff: RuntimeTopologyBackoff::default(),
            next_tinc_periodic: now,
            next_meta_ping_check: now + tinc_timer_jitter_duration(ping_timeout_duration(config)),
            device_standby: config.daemon.device_standby,
            device_enabled: !config.daemon.device_standby,
            device_read_errors: 0,
            device_read_backoff_until: None,
            ping_interval: Duration::from_secs(config.daemon.ping_interval.max(1) as u64),
            ping_timeout: Duration::from_secs(config.daemon.ping_timeout.max(1) as u64),
            mac_expire: config.daemon.mac_expire,
            next_mac_subnet_age: now + tinc_timer_jitter_duration(TINC_AGING_INTERVAL),
            mtu_info_interval: Duration::from_secs(config.daemon.mtu_info_interval.max(0) as u64),
            udp_info_interval: Duration::from_secs(config.daemon.udp_info_interval.max(0) as u64),
            local_discovery: config.daemon.local_discovery,
            udp_discovery: config.daemon.udp_discovery,
            udp_discovery_keepalive_interval: Duration::from_secs(
                config.daemon.udp_discovery_keepalive_interval.max(0) as u64,
            ),
            udp_discovery_interval: Duration::from_secs(
                config.daemon.udp_discovery_interval.max(0) as u64,
            ),
            udp_discovery_timeout: Duration::from_secs(
                config.daemon.udp_discovery_timeout.max(0) as u64
            ),
            hostnames: config.daemon.hostnames,
            udp_unconfirmed_guess_counter: 0,
            mtu_info_sent: BTreeMap::new(),
            udp_info_sent: BTreeMap::new(),
            udp_probe: BTreeMap::new(),
            udp_socket_by_peer: BTreeMap::new(),
            legacy_last_req_key: BTreeMap::new(),
            legacy_last_hard_try_secs: 0,
            sptps_last_req_key: BTreeMap::new(),
            key_lifetime_secs: config.daemon.key_expire,
            next_key_expire: schedule_next_key_expire(now, config.daemon.key_expire),
            key_exchange: runtime_sptps_key_exchange(config, &keys),
            packet_codec: runtime_sptps_packet_codec(config, &config.state),
            legacy_codec: runtime_legacy_udp_codec(config),
            legacy_cipher: config.daemon.legacy_cipher,
            legacy_digest: config.daemon.legacy_digest,
            legacy_compression: config.daemon.legacy_compression,
            keys,
            addresses: config.addresses.clone(),
            engine_config: config.engine.clone(),
            device: RuntimeDevice::memory(),
            traffic: BTreeMap::new(),
            pcap_subscribers: Vec::new(),
            #[cfg(test)]
            log_entries: VecDeque::new(),
            log_subscribers: Vec::new(),
            log_sink: None,
            upnp_log_receiver: None,
            #[cfg(unix)]
            umbilical_log_sink: None,
            debug_level: config.daemon.log_level.unwrap_or(DEBUG_NOTHING),
            confbase: None,
            script_context: None,
            invitation: None,
            next_connection_id: 1,
            next_meta_nonce: random_meta_nonce_start(),
            past_requests: PastRequestCache::new(config.daemon.ping_interval.max(1) as u64),
            next_past_request_age: None,
            strict_forwarded_topology: VecDeque::new(),
            packet_diag_counts: BTreeMap::new(),
            pending_close_reason: None,
        };
        state.record_log_with_priority(
            0,
            LOG_NOTICE,
            format!("tincd runtime initialized for {}", config.name),
        );
        state
    }

    pub fn new_configured(
        listen_sockets: Vec<RuntimeListenSocket>,
        config: &RuntimeConfig,
        keys: RuntimeKeys,
    ) -> Result<Self, TincdError> {
        let mut state = Self::new(listen_sockets, config, keys);
        state.device = RuntimeDevice::open(config)?;
        Ok(state)
    }

    pub fn enable_scripts(&mut self, config: &RuntimeConfig, options: &TincdOptions) {
        self.netname = options.netname.clone();
        self.script_context = Some(RuntimeScriptContext {
            config: config.clone(),
            options: options.clone(),
            device_info: self.device.info().clone(),
        });
    }

    pub fn set_bypass_security(&mut self, bypass_security: bool) {
        self.bypass_security = bypass_security;
    }

    pub fn set_confbase(&mut self, confbase: PathBuf) {
        self.confbase = Some(confbase);
    }

    pub fn enable_invitations(
        &mut self,
        confbase: PathBuf,
        config: &RuntimeConfig,
    ) -> Result<(), TincdError> {
        self.invitation = read_runtime_invitation_context(confbase, config)?;
        Ok(())
    }

    pub fn run_local_subnet_up_scripts(&self) {
        let local_name = self.local_name.clone();
        self.run_all_subnet_scripts(&local_name, true);
    }

    pub fn listen_sockets(&self) -> &[RuntimeListenSocket] {
        &self.listen_sockets
    }

    pub fn meta_connection_infos(&self) -> Vec<RuntimeMetaConnectionInfo> {
        self.meta_connections
            .iter()
            .map(RuntimeMetaConnection::info)
            .collect()
    }

    pub fn state(&self) -> &NetworkState {
        &self.state
    }

    pub fn device_writes(&self) -> &[VpnPacket] {
        self.device.writes()
    }

    pub fn push_device_packet(&mut self, packet: VpnPacket) -> Result<(), TincdError> {
        self.device.push_read(packet)
    }

    #[cfg(unix)]
    pub(crate) fn device_poll_fd(&self) -> Option<RawFd> {
        if self.device_enabled && !self.device_read_backoff_active(Instant::now()) {
            self.device.poll_fd()
        } else {
            None
        }
    }

    pub(crate) fn device_read_backoff_active(&self, now: Instant) -> bool {
        self.device_read_backoff_until
            .is_some_and(|deadline| now < deadline)
    }

    #[cfg(unix)]
    pub(crate) fn upnp_log_poll_fd(&self) -> Option<RawFd> {
        self.upnp_log_receiver
            .as_ref()
            .and_then(RuntimeUpnpLogReceiver::poll_fd)
    }

    pub fn set_debug_level(&mut self, level: i32) {
        self.debug_level = level;
    }

    pub fn debug_level(&self) -> i32 {
        self.debug_level
    }

    pub fn enable_logfile(&mut self, path: &Path) -> Result<(), TincdError> {
        self.log_sink = Some(RuntimeLogSink::open(path, "tinc")?);
        Ok(())
    }

    pub fn enable_stderr_log(&mut self, colorize: bool) {
        self.log_sink = Some(RuntimeLogSink::stderr(colorize));
    }

    #[cfg(unix)]
    pub fn enable_umbilical_log_from_env(&mut self) {
        self.umbilical_log_sink = RuntimeUmbilicalLogSink::from_env();
    }

    #[cfg(all(unix, test))]
    pub(crate) fn enable_umbilical_log_from_spec_for_test(&mut self, fd: i32, colorize: bool) {
        self.umbilical_log_sink =
            RuntimeUmbilicalLogSink::from_spec(UmbilicalSpec { fd, colorize });
    }

    #[cfg(unix)]
    pub(crate) fn notify_umbilical_success_and_close(&mut self) -> Result<(), TincdError> {
        let Some(sink) = self.umbilical_log_sink.take() else {
            return notify_umbilical_success();
        };
        sink.write_success_and_close()
            .map_err(|error| TincdError::ControlIo(error.to_string()))
    }

    #[cfg(test)]
    pub(crate) fn enable_log_writer_for_test(
        &mut self,
        writer: Box<dyn Write + Send>,
        colorize: bool,
    ) {
        self.log_sink = Some(RuntimeLogSink::pretty_for_test(writer, colorize));
    }

    #[cfg(unix)]
    pub fn enable_syslog(&mut self) -> Result<(), TincdError> {
        self.log_sink = Some(RuntimeLogSink::syslog("tinc")?);
        Ok(())
    }

    pub fn record_log(&mut self, level: i32, message: impl Into<String>) {
        self.record_log_with_priority(level, LOG_INFO, message);
    }

    pub fn record_log_with_priority(
        &mut self,
        level: i32,
        priority: i32,
        message: impl Into<String>,
    ) {
        let message = message.into();
        if level > self.debug_level && self.log_subscribers.is_empty() {
            return;
        }

        self.publish_control_log_entry(level, priority, &message);

        if level > self.debug_level {
            return;
        }

        #[cfg(test)]
        self.log_entries.push_back(RuntimeLogEntry {
            level,
            priority,
            message: message.clone(),
        });
        if let Some(sink) = &mut self.log_sink {
            let _ = sink.write_entry(priority, &message);
        }
        #[cfg(unix)]
        if let Some(sink) = &mut self.umbilical_log_sink {
            sink.write_log(priority, &message);
        }
    }

    pub(crate) fn publish_control_log_entry(&mut self, level: i32, priority: i32, message: &str) {
        if self.log_subscribers.is_empty() {
            return;
        }

        let debug_level = self.debug_level;
        for subscriber in &mut self.log_subscribers {
            if level > control_log_level(subscriber.level, debug_level) {
                continue;
            }

            let pretty = format_pretty_log_entry(priority, message, subscriber.colorize);
            let bytes = pretty.as_bytes();
            let payload = &bytes[..bytes.len().min(LOG_CONTROL_BUFFER_SIZE)];
            subscriber.writer.queue_payload(REQ_LOG, payload);
        }
    }

    pub(crate) fn register_control_log_subscriber(
        &mut self,
        level: i32,
        colorize: bool,
        stream: RuntimeControlSubscriberStream,
    ) -> Result<(), TincdError> {
        let writer = RuntimeControlSubscriberWriter::new(self.next_control_subscriber_id(), stream)
            .map_err(control_io)?;
        self.log_subscribers.push(RuntimeControlLogSubscriber {
            level: level.clamp(DEBUG_UNSET, DEBUG_SCARY_THINGS),
            colorize,
            writer,
        });
        Ok(())
    }

    pub(crate) fn register_control_pcap_subscriber(
        &mut self,
        snaplen: usize,
        stream: RuntimeControlSubscriberStream,
    ) -> Result<(), TincdError> {
        let writer = RuntimeControlSubscriberWriter::new(self.next_control_subscriber_id(), stream)
            .map_err(control_io)?;
        self.pcap_subscribers
            .push(RuntimeControlPcapSubscriber { snaplen, writer });
        Ok(())
    }

    pub(crate) fn next_control_subscriber_id(&mut self) -> u64 {
        let id = self.next_connection_id;
        self.next_connection_id = self.next_connection_id.wrapping_add(1);
        id
    }

    pub(crate) fn control_subscriber_writers(
        &self,
    ) -> impl Iterator<Item = &RuntimeControlSubscriberWriter> {
        self.log_subscribers
            .iter()
            .map(|subscriber| &subscriber.writer)
            .chain(
                self.pcap_subscribers
                    .iter()
                    .map(|subscriber| &subscriber.writer),
            )
    }

    pub(crate) fn flush_control_subscriber_by_id(
        &mut self,
        id: u64,
    ) -> Result<RuntimeIoProgress, TincdError> {
        if let Some(index) = self
            .log_subscribers
            .iter()
            .position(|subscriber| subscriber.writer.id == id)
        {
            return match self.log_subscribers[index].writer.flush_once() {
                Ok(progress) => Ok(progress),
                Err(_) => {
                    self.log_subscribers.remove(index);
                    Ok(RuntimeIoProgress::Processed)
                }
            };
        }

        if let Some(index) = self
            .pcap_subscribers
            .iter()
            .position(|subscriber| subscriber.writer.id == id)
        {
            return match self.pcap_subscribers[index].writer.flush_once() {
                Ok(progress) => Ok(progress),
                Err(_) => {
                    self.pcap_subscribers.remove(index);
                    Ok(RuntimeIoProgress::Processed)
                }
            };
        }

        Ok(RuntimeIoProgress::NotReady)
    }

    pub(crate) fn reopen_logger(&mut self) {
        let Some(sink) = &mut self.log_sink else {
            return;
        };

        match sink.reopen() {
            Ok(_) => {}
            Err((path, error)) => self.record_log_with_priority(
                0,
                LOG_ERR,
                format!("Unable to reopen log file {}: {error}", path.display()),
            ),
        }
    }

    #[cfg(test)]
    pub(crate) fn test_log_entries(&self, max_level: i32, colorize: bool) -> Vec<String> {
        let max_level = control_log_level(max_level, self.debug_level);

        self.log_entries
            .iter()
            .filter(|entry| entry.level <= max_level)
            .map(|entry| format_pretty_log_entry(entry.priority, &entry.message, colorize))
            .collect()
    }

    pub(crate) fn record_inbound_traffic(&mut self, source: &str, bytes: usize) {
        let counters = self.traffic.entry(source.to_owned()).or_default();
        counters.in_packets = counters.in_packets.saturating_add(1);
        counters.in_bytes = counters.in_bytes.saturating_add(bytes as u64);
    }

    pub(crate) fn capture_control_pcap_packet(&mut self, packet: &VpnPacket) {
        publish_control_pcap_packet(&mut self.pcap_subscribers, &packet.data);
    }

    pub fn purge_unreachable(&mut self, config: &RuntimeConfig) {
        let result = self.state.purge_unreachable_at(
            PurgeOptions {
                strict_subnets: config.strict_subnets,
                autoconnect: config.autoconnect,
            },
            current_unix_secs(),
        );
        self.run_reachability_scripts(&result.reachability);
        for subnet in &result.removed_subnets {
            self.run_subnet_script_for_subnet("subnet-down", subnet);
        }
    }

    pub fn apply_reloaded_config(
        &mut self,
        config: &RuntimeConfig,
        keys: RuntimeKeys,
    ) -> Result<(), TincdError> {
        let config = runtime_config_for_keys(config, &keys);
        let config = &config;
        if config.name != self.local_name {
            return Err(TincdError::ControlIo(
                "cannot reload configuration with a different Name".to_owned(),
            ));
        }

        self.local_indirect_data = config.daemon.indirect_data;
        self.local_tcp_only = config.daemon.tcp_only;
        self.local_pmtu_discovery = config.daemon.pmtu_discovery;
        self.local_clamp_mss = config.daemon.clamp_mss;
        self.local_weight = runtime_local_weight(config);
        self.strict_subnets = config.strict_subnets;
        self.tunnel_server = config.tunnel_server;
        self.proxy = config.daemon.proxy.clone();
        self.peer_meta_configs = config.peer_meta_configs.clone();
        self.fwmark = config.daemon.fwmark;
        self.max_outgoing_retry_timeout_secs = config.daemon.max_timeout as u64;
        self.runtime_config = config.clone();
        self.sync_outgoing_retry_state(config);
        self.max_connection_burst = config.daemon.max_connection_burst as u64;
        self.ping_interval = Duration::from_secs(config.daemon.ping_interval.max(1) as u64);
        self.ping_timeout = Duration::from_secs(config.daemon.ping_timeout.max(1) as u64);
        self.next_meta_ping_check = Instant::now() + tinc_timer_jitter_duration(self.ping_timeout);
        self.mac_expire = config.daemon.mac_expire;
        self.mtu_info_interval = Duration::from_secs(config.daemon.mtu_info_interval.max(0) as u64);
        self.udp_info_interval = Duration::from_secs(config.daemon.udp_info_interval.max(0) as u64);
        self.local_discovery = config.daemon.local_discovery;
        self.udp_discovery = config.daemon.udp_discovery;
        self.udp_discovery_keepalive_interval =
            Duration::from_secs(config.daemon.udp_discovery_keepalive_interval.max(0) as u64);
        self.udp_discovery_interval =
            Duration::from_secs(config.daemon.udp_discovery_interval.max(0) as u64);
        self.udp_discovery_timeout =
            Duration::from_secs(config.daemon.udp_discovery_timeout.max(0) as u64);
        self.hostnames = config.daemon.hostnames;
        self.key_lifetime_secs = config.daemon.key_expire;
        self.next_key_expire = schedule_next_key_expire(Instant::now(), config.daemon.key_expire);
        self.key_exchange = runtime_sptps_key_exchange(config, &keys);
        self.keys = keys;
        self.addresses = config.addresses.clone();
        let legacy_replay_window = runtime_legacy_replay_window_bytes(config);
        if self.legacy_codec.replay_window_bytes() != legacy_replay_window {
            self.legacy_codec = LegacyUdpCodec::new(legacy_replay_window);
        }
        self.legacy_cipher = config.daemon.legacy_cipher;
        self.legacy_digest = config.daemon.legacy_digest;
        self.legacy_compression = config.daemon.legacy_compression;
        self.engine_config = config.engine.clone();
        if let Some(script_context) = &mut self.script_context {
            script_context.config = config.clone();
        }
        self.sync_reloaded_nodes(config);
        self.sync_reloaded_subnets(config);
        self.state.experimental = config.state.experimental;
        let reachability = self.state.recompute_routes_at(current_unix_secs());
        self.update_route_udp_endpoints_like_tinc(&reachability);
        *self.packet_codec.ids_mut() = NodeIdTable::from_network_state(&self.state);

        Ok(())
    }

    #[cfg(test)]
    pub fn poll_once(&mut self) -> Result<bool, TincdError> {
        let mut did_work = false;
        did_work |= self.drain_upnp_logs();
        self.accept_meta_connections()?;
        did_work |= self.drain_device_packets()?;
        did_work |= self.drain_udp_datagrams()?;
        self.read_meta_connections()?;
        self.expire_symmetric_keys()?;
        self.expire_dynamic_mac_subnets()?;
        self.age_past_requests_like_tinc();
        self.expire_udp_probe_timeouts_like_tinc();
        self.run_meta_ping_timer_once_like_tinc()?;
        Ok(did_work)
    }

    pub(crate) fn run_timers_once_with_periodic(
        &mut self,
        config: Option<&RuntimeConfig>,
    ) -> Result<usize, TincdError> {
        let autoconnected = self.run_tinc_periodic_once(config)?;
        self.expire_symmetric_keys()?;
        self.expire_dynamic_mac_subnets()?;
        self.age_past_requests_like_tinc();
        self.expire_udp_probe_timeouts_like_tinc();
        self.run_meta_ping_timer_once_like_tinc()?;
        Ok(autoconnected)
    }

    pub(crate) fn run_tinc_periodic_once(
        &mut self,
        config: Option<&RuntimeConfig>,
    ) -> Result<usize, TincdError> {
        let now = Instant::now();
        let mut autoconnected = 0;
        if now >= self.next_tinc_periodic {
            self.apply_topology_backoff_periodic_check(now);
            if let Some(config) = config
                && config.autoconnect
                && self.state.graph.nodes().count() > 1
            {
                autoconnected = self.do_autoconnect_like_tinc(config)?;
            }
            self.next_tinc_periodic = now + tinc_timer_jitter_duration(AUTOCONNECT_INTERVAL);
        }
        Ok(autoconnected)
    }

    pub(crate) fn apply_topology_backoff_periodic_check(&mut self, now: Instant) {
        if let Some(delay) = self.topology_backoff.apply_periodic_check(now) {
            self.record_log_with_priority(
                0,
                LOG_WARNING,
                format!(
                    "Possible node with same Name as us! Sleeping {} seconds.",
                    delay.as_secs()
                ),
            );
        }
    }

    pub(crate) fn run_meta_ping_timer_once_like_tinc(&mut self) -> Result<(), TincdError> {
        let now = Instant::now();
        if now < self.next_meta_ping_check {
            return Ok(());
        }
        self.send_meta_keepalives_at(now)?;
        self.next_meta_ping_check = now + tinc_timer_jitter_duration(Duration::from_secs(1));
        Ok(())
    }

    pub(crate) fn age_past_requests_like_tinc(&mut self) {
        self.age_past_requests_at_like_tinc(Instant::now(), current_unix_secs().max(0) as u64);
    }

    pub(crate) fn age_past_requests_at_like_tinc(&mut self, now: Instant, now_secs: u64) {
        let Some(deadline) = self.next_past_request_age else {
            return;
        };
        if now < deadline {
            return;
        }

        let deleted = self.past_requests.age(now_secs);
        let left = self.past_requests.len();
        if left > 0 || deleted > 0 {
            self.record_log_with_priority(
                DEBUG_SCARY_THINGS,
                LOG_DEBUG,
                format!("Aging past requests: deleted {deleted}, left {left}"),
            );
        }
        self.next_past_request_age = if self.past_requests.is_empty() {
            None
        } else {
            Some(now + tinc_timer_jitter_duration(TINC_AGING_INTERVAL))
        };
    }

    pub(crate) fn expire_udp_probe_timeouts_like_tinc(&mut self) {
        let now = Instant::now();
        let peers = self
            .udp_probe
            .iter()
            .filter_map(|(peer, state)| {
                state
                    .udp_ping_timeout
                    .is_some_and(|timeout| now >= timeout)
                    .then(|| peer.clone())
            })
            .collect::<Vec<_>>();

        for peer in peers {
            self.expire_udp_probe_timeout(&peer, now);
        }
    }

    pub(crate) fn drain_upnp_logs(&mut self) -> bool {
        let Some(receiver) = self.upnp_log_receiver.take() else {
            return false;
        };
        let mut entries = Vec::new();
        let mut disconnected = false;
        loop {
            match receiver.receiver.try_recv() {
                Ok(entry) => entries.push(entry),
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    disconnected = true;
                    break;
                }
            }
        }
        receiver.drain_wake();
        if !disconnected {
            self.upnp_log_receiver = Some(receiver);
        }
        for entry in &entries {
            self.record_log_with_priority(entry.level, entry.priority, entry.message.clone());
        }
        !entries.is_empty()
    }

    pub fn connect_configured_peers(
        &mut self,
        config: &RuntimeConfig,
    ) -> Result<usize, TincdError> {
        self.sync_outgoing_retry_state(config);
        let mut connected = 0;
        let now = Instant::now();

        for peer in &config.connect_to {
            if self.has_meta_connection_with_name(peer) {
                continue;
            }

            if self.connect_peer(config, peer)? {
                connected += 1;
            } else {
                self.mark_outgoing_failed(peer, now);
            }
        }

        Ok(connected)
    }

    pub fn do_autoconnect_like_tinc(
        &mut self,
        config: &RuntimeConfig,
    ) -> Result<usize, TincdError> {
        if !config.autoconnect || self.state.graph.nodes().count() <= 1 {
            return Ok(0);
        }

        let active_connections = self.active_edge_connection_count_like_tinc();
        if active_connections < 3 {
            return self.make_new_autoconnect_connection_like_tinc(config);
        }

        if active_connections > 3 {
            self.drop_superfluous_outgoing_connection_like_tinc()?;
        }
        self.drop_superfluous_pending_autoconnect_like_tinc();
        self.connect_to_unreachable_like_tinc(config)
    }

    pub(crate) fn drop_superfluous_outgoing_connection_like_tinc(
        &mut self,
    ) -> Result<bool, TincdError> {
        let candidates = self
            .meta_connections
            .iter()
            .enumerate()
            .filter(|(_, connection)| connection.outgoing_autoconnect)
            .filter(|(_, connection)| connection.is_active_authenticated())
            .filter_map(|(index, connection)| {
                let peer = connection.active_name()?;
                let edge_count = self
                    .state
                    .graph
                    .edges()
                    .filter(|edge| edge.from == peer)
                    .count();
                if edge_count < 2 {
                    return None;
                }
                Some((index, peer.to_owned()))
            })
            .collect::<Vec<_>>();

        if candidates.is_empty() {
            return Ok(false);
        }

        let (index, peer) = candidates[prng_below(candidates.len())].clone();
        self.record_log_with_priority(1, LOG_INFO, format!("Autodisconnecting from {peer}"));
        self.autoconnect_outgoing.remove(&peer);
        self.close_meta_connection_for_reason(index, "autoconnect-superfluous")?;
        Ok(true)
    }

    pub(crate) fn drop_superfluous_pending_autoconnect_like_tinc(&mut self) {
        let active = self
            .meta_connections
            .iter()
            .filter_map(RuntimeMetaConnection::active_name)
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let mut cancelled = Vec::new();
        self.autoconnect_outgoing.retain(|peer, _| {
            let keep = active.iter().any(|active_peer| active_peer == peer);
            if !keep {
                cancelled.push(peer.clone());
            }
            keep
        });
        for peer in cancelled {
            self.record_log_with_priority(
                1,
                LOG_INFO,
                format!("Cancelled outgoing connection to {peer}"),
            );
        }
    }

    pub(crate) fn retry_autoconnect_outgoing_like_tinc(
        &mut self,
        config: &RuntimeConfig,
    ) -> Result<usize, TincdError> {
        if !config.autoconnect {
            return Ok(0);
        }

        let now = Instant::now();
        let peers = self
            .autoconnect_outgoing
            .iter()
            .filter(|(peer, retry)| {
                retry.next_attempt <= now
                    && !self.has_pending_or_authenticated_meta_connection_with_name(peer)
            })
            .map(|(peer, _)| peer.clone())
            .collect::<Vec<_>>();

        let mut connected = 0;
        for peer in peers {
            if self.connect_peer(config, &peer)? {
                self.mark_autoconnect_connected(&peer, now);
                self.mark_latest_connection_autoconnect(&peer);
                connected += 1;
            } else {
                self.mark_autoconnect_failed(&peer, now);
            }
        }

        Ok(connected)
    }

    pub(crate) fn active_edge_connection_count_like_tinc(&self) -> usize {
        self.meta_connections
            .iter()
            .filter(|connection| connection.is_active_authenticated())
            .filter_map(RuntimeMetaConnection::active_name)
            .filter(|peer| self.state.graph.edge(&self.local_name, peer).is_some())
            .count()
    }

    pub(crate) fn make_new_autoconnect_connection_like_tinc(
        &mut self,
        config: &RuntimeConfig,
    ) -> Result<usize, TincdError> {
        let candidates = self
            .state
            .graph
            .nodes()
            .filter(|node| node.name != self.local_name)
            .filter(|node| !self.has_pending_or_authenticated_meta_connection_with_name(&node.name))
            .filter(|node| node.status.has_address || node.status.reachable)
            .map(|node| node.name.clone())
            .collect::<Vec<_>>();

        if candidates.is_empty() {
            return Ok(0);
        }

        let peer = &candidates[prng_below(candidates.len())];
        if self.autoconnect_outgoing.contains_key(peer) {
            return Ok(0);
        }

        self.record_log_with_priority(1, LOG_INFO, format!("Autoconnecting to {peer}"));
        if self.connect_peer(config, peer)? {
            self.mark_autoconnect_connected(peer, Instant::now());
            self.mark_latest_connection_autoconnect(peer);
            Ok(1)
        } else {
            self.mark_autoconnect_failed(peer, Instant::now());
            Ok(0)
        }
    }

    pub(crate) fn connect_to_unreachable_like_tinc(
        &mut self,
        config: &RuntimeConfig,
    ) -> Result<usize, TincdError> {
        let node_count = self.state.graph.nodes().count();
        if node_count == 0 {
            return Ok(0);
        }
        self.connect_to_unreachable_at_index_like_tinc(config, prng_below(node_count))
    }

    pub(crate) fn connect_to_unreachable_at_index_like_tinc(
        &mut self,
        config: &RuntimeConfig,
        selected: usize,
    ) -> Result<usize, TincdError> {
        let Some(peer) = self
            .state
            .graph
            .nodes()
            .nth(selected)
            .map(|node| node.name.clone())
        else {
            return Ok(0);
        };

        let Some(node) = self.state.graph.node(&peer) else {
            return Ok(0);
        };
        if peer == self.local_name
            || self.has_pending_or_authenticated_meta_connection_with_name(&peer)
            || node.status.reachable
            || !node.status.has_address
        {
            return Ok(0);
        }

        if self.autoconnect_outgoing.contains_key(&peer) {
            return Ok(0);
        }

        self.record_log_with_priority(1, LOG_INFO, format!("Autoconnecting to {peer}"));
        if self.connect_peer(config, &peer)? {
            self.mark_autoconnect_connected(&peer, Instant::now());
            self.mark_latest_connection_autoconnect(&peer);
            Ok(1)
        } else {
            self.mark_autoconnect_failed(&peer, Instant::now());
            Ok(0)
        }
    }

    pub fn connect_peer(&mut self, config: &RuntimeConfig, peer: &str) -> Result<bool, TincdError> {
        if self.has_pending_or_authenticated_meta_connection_with_name(peer) {
            return Ok(true);
        }

        let candidates = self.outgoing_address_candidates_like_tinc(config, peer);
        let mut cursor = self.outgoing_address_cursors.remove(peer).unwrap_or(0);
        while cursor < candidates.len() {
            let address = candidates[cursor];
            cursor += 1;
            if self.connect_peer_to_address(
                peer,
                address,
                config.daemon.fwmark,
                config.daemon.bind_to_interface.as_deref(),
            )? {
                self.outgoing_address_cursors
                    .insert(peer.to_owned(), cursor);
                return Ok(true);
            }
        }

        self.outgoing_address_cursors.remove(peer);
        Ok(false)
    }

    pub(crate) fn outgoing_address_candidates_like_tinc(
        &self,
        config: &RuntimeConfig,
        peer: &str,
    ) -> Vec<SocketAddr> {
        let mut cache = self.read_address_cache(peer);
        let mut candidates = Vec::new();

        for address in cache.drain(..) {
            push_unique_socket_addr(&mut candidates, address);
        }
        for address in self.known_reverse_edge_addresses_like_tinc(peer) {
            push_unique_socket_addr(&mut candidates, address);
        }
        if let Some(addresses) = config.addresses.addresses(peer) {
            for address in addresses {
                push_unique_socket_addr(&mut candidates, *address);
            }
        }

        candidates
    }

    pub fn disconnect_peer(&mut self, peer: &str) -> Result<bool, TincdError> {
        let mut found = false;

        while let Some(index) = self.meta_connections.iter().position(|connection| {
            matches!(
                &connection.kind,
                RuntimeMetaConnectionKind::Active {
                    name: Some(name),
                    ..
                } if name == peer
            )
        }) {
            found = true;
            self.close_meta_connection(index)?;
        }

        if found {
            self.packet_codec.remove_peer(peer);
        }

        Ok(found)
    }

    pub fn retry_configured_peers(&mut self, config: &RuntimeConfig) -> Result<usize, TincdError> {
        self.sync_outgoing_retry_state(config);
        let now = Instant::now();
        let mut connected = 0;

        for peer in &config.connect_to {
            if self.has_meta_connection_with_name(peer) {
                continue;
            }

            let Some(retry) = self.outgoing_retry.get(peer) else {
                continue;
            };
            if retry.next_attempt > now {
                continue;
            }

            if self.connect_peer(config, peer)? {
                connected += 1;
            } else {
                self.mark_outgoing_failed(peer, now);
            }
        }

        Ok(connected)
    }

    pub fn retry_configured_peers_now(
        &mut self,
        config: &RuntimeConfig,
    ) -> Result<usize, TincdError> {
        self.sync_outgoing_retry_state(config);
        let now = Instant::now();
        for peer in &config.connect_to {
            self.outgoing_retry
                .entry(peer.clone())
                .or_insert_with(|| OutgoingRetryState::ready(now))
                .reset(now);
        }

        self.connect_configured_peers(config)
    }

    pub(crate) fn sync_outgoing_retry_state(&mut self, config: &RuntimeConfig) {
        self.outgoing_retry.retain(|peer, _| {
            config
                .connect_to
                .iter()
                .any(|configured| configured == peer)
        });

        let now = Instant::now();
        for peer in &config.connect_to {
            self.outgoing_retry
                .entry(peer.clone())
                .or_insert_with(|| OutgoingRetryState::ready(now));
        }
    }

    pub(crate) fn mark_outgoing_connected(&mut self, peer: &str, now: Instant) {
        self.outgoing_retry
            .entry(peer.to_owned())
            .or_insert_with(|| OutgoingRetryState::ready(now))
            .mark_connected(now);
    }

    pub(crate) fn mark_outgoing_failed(&mut self, peer: &str, now: Instant) {
        self.outgoing_retry
            .entry(peer.to_owned())
            .or_insert_with(|| OutgoingRetryState::ready(now))
            .mark_failed(now, self.max_outgoing_retry_timeout_secs);
    }

    pub(crate) fn mark_autoconnect_connected(&mut self, peer: &str, now: Instant) {
        self.autoconnect_outgoing
            .entry(peer.to_owned())
            .or_insert_with(|| OutgoingRetryState::ready(now))
            .mark_connected(now);
    }

    pub(crate) fn mark_latest_connection_autoconnect(&mut self, peer: &str) {
        if let Some(connection) =
            self.meta_connections.iter_mut().rev().find(|connection| {
                connection.active_name() == Some(peer) && connection.is_outgoing()
            })
        {
            connection.outgoing_autoconnect = true;
        }
    }

    pub(crate) fn mark_autoconnect_failed(&mut self, peer: &str, now: Instant) {
        let retry = self
            .autoconnect_outgoing
            .entry(peer.to_owned())
            .or_insert_with(|| OutgoingRetryState::ready(now));
        retry.mark_failed(now, self.max_outgoing_retry_timeout_secs);
        let timeout_secs = retry.timeout_secs;
        self.record_log_with_priority(
            1,
            LOG_NOTICE,
            format!(
                "Trying to re-establish outgoing connection in {} seconds",
                timeout_secs
            ),
        );
    }

    pub(crate) fn address_cache_path(&self, peer: &str) -> Option<PathBuf> {
        Some(self.confbase.as_ref()?.join("cache").join(peer))
    }

    pub(crate) fn read_address_cache(&self, peer: &str) -> Vec<SocketAddr> {
        let Some(path) = self.address_cache_path(peer) else {
            return Vec::new();
        };
        read_tinc_address_cache(&path)
    }

    pub(crate) fn write_address_cache(&self, peer: &str, addresses: &[SocketAddr]) {
        let Some(path) = self.address_cache_path(peer) else {
            return;
        };
        let _ = write_tinc_address_cache(&path, addresses);
    }

    pub(crate) fn add_recent_meta_address_like_tinc(&mut self, peer: &str, address: SocketAddr) {
        self.outgoing_address_cursors.remove(peer);
        let mut addresses = self.read_address_cache(peer);
        promote_recent_address(&mut addresses, address);
        self.write_address_cache(peer, &addresses);
        self.addresses.promote(peer.to_owned(), address);
    }

    pub(crate) fn reset_address_cache_to_meta_address_like_tinc(
        &mut self,
        peer: &str,
        address: SocketAddr,
    ) {
        self.outgoing_address_cursors.remove(peer);
        let mut addresses = self.read_address_cache(peer);
        promote_recent_address(&mut addresses, address);
        self.write_address_cache(peer, &addresses);
        self.addresses.promote(peer.to_owned(), address);
    }

    pub(crate) fn reset_address_cache_to_local_edge_address_like_tinc(&mut self, peer: &str) {
        let Some(address) = self
            .state
            .graph
            .edge(&self.local_name, peer)
            .and_then(|edge| edge.address.as_ref())
            .and_then(edge_endpoint_socket_addr)
        else {
            return;
        };

        self.reset_address_cache_to_meta_address_like_tinc(peer, address);
    }

    pub(crate) fn handle_pong_address_cache_like_tinc(&mut self, index: usize) {
        let Some((peer, address)) = self.meta_connections.get(index).and_then(|connection| {
            connection
                .outgoing_peer
                .as_ref()
                .map(|peer| (peer.clone(), connection.peer))
        }) else {
            return;
        };

        let Some(retry) = self.outgoing_retry.get(&peer) else {
            return;
        };
        if retry.timeout_secs == 0 {
            return;
        }

        self.reset_address_cache_to_meta_address_like_tinc(&peer, address);
        self.mark_outgoing_connected(&peer, Instant::now());
    }

    pub(crate) fn known_reverse_edge_addresses_like_tinc(&self, peer: &str) -> Vec<SocketAddr> {
        let mut addresses = Vec::new();
        for edge in self.state.graph.edges().filter(|edge| edge.from == peer) {
            let Some(reverse) = self.state.graph.edge(&edge.to, &edge.from) else {
                continue;
            };
            let Some(address) = reverse.address.as_ref().and_then(edge_endpoint_socket_addr) else {
                continue;
            };
            push_unique_socket_addr(&mut addresses, address);
        }
        addresses
    }

    pub(crate) fn sync_reloaded_nodes(&mut self, config: &RuntimeConfig) {
        let configured_nodes = config
            .state
            .graph
            .nodes()
            .map(|node| (node.name.clone(), node.status.has_address))
            .collect::<Vec<_>>();

        for (name, _) in &configured_nodes {
            self.state.graph.ensure_node(name);
        }

        let current_nodes = self
            .state
            .graph
            .nodes()
            .map(|node| node.name.clone())
            .collect::<Vec<_>>();

        for name in current_nodes {
            if let Some(state_node) = self.state.graph.node_mut(&name) {
                state_node.status.has_address = configured_nodes
                    .iter()
                    .any(|(configured_name, has_address)| configured_name == &name && *has_address);
            }
        }
    }

    pub(crate) fn sync_reloaded_subnets(&mut self, config: &RuntimeConfig) {
        let owners = self
            .state
            .subnets
            .iter()
            .filter_map(|subnet| subnet.owner.clone())
            .collect::<Vec<_>>();

        for owner in owners {
            if owner == self.local_name || config.strict_subnets {
                self.state.subnets.remove_owner(&owner);
            }
        }

        for subnet in config.state.subnets.iter().cloned() {
            if subnet.owner.as_deref() == Some(&self.local_name) || config.strict_subnets {
                self.state.subnets.add_unique(subnet);
            }
        }
        if !config.strict_subnets {
            self.strict_forwarded_topology.clear();
        }
    }

    pub(crate) fn connect_peer_to_address(
        &mut self,
        peer: &str,
        address: SocketAddr,
        fwmark: i32,
        bind_to_interface: Option<&str>,
    ) -> Result<bool, TincdError> {
        let Some(driver) = self.meta_driver_for_peer(peer, true)? else {
            return Ok(false);
        };
        let proxy_target = match outgoing_proxy_connect_target(
            &self.proxy,
            address,
            &self.local_name,
            peer,
            self.netname.as_deref(),
        ) {
            Ok(target) => target,
            Err(error) => {
                self.record_log_with_priority(
                    1,
                    LOG_ERR,
                    format!("Could not set up proxy connection to {peer}: {error}"),
                );
                return Ok(false);
            }
        };
        let (stream, local, connecting, proxy_state, proxy_request, exec_proxy) = match proxy_target
        {
            OutgoingProxyTarget::Tcp {
                address: connect_address,
                handshake,
                request,
            } => {
                let bind_address = self.outgoing_bind_address_for(connect_address);
                let Ok((stream, connecting)) =
                    connect_tcp_stream(connect_address, fwmark, bind_to_interface, bind_address)
                else {
                    return Ok(false);
                };
                let local = stream.local_addr().unwrap_or(connect_address);
                (stream, local, connecting, handshake, request, None)
            }
            OutgoingProxyTarget::Exec { stream, child } => {
                let local = stream.local_addr().unwrap_or(address);
                (
                    stream,
                    local,
                    false,
                    ProxyHandshake::None,
                    None,
                    Some(RuntimeExecProxyChild::new(child)),
                )
            }
        };

        let mut outbound = Vec::new();
        if let Some(proxy_request) = proxy_request {
            outbound.extend_from_slice(&proxy_request);
        }
        outbound.extend_from_slice(&driver.initial_id_bytes());
        if stream.set_nonblocking(true).is_err() {
            return Ok(false);
        }

        let now = Instant::now();
        self.meta_connections.push(RuntimeMetaConnection {
            id: self.next_connection_id,
            stream,
            peer: address,
            local,
            bytes_read: 0,
            bytes_written: 0,
            outbound: Vec::new(),
            outbound_offset: 0,
            status: CONNECTION_STATUS_ACTIVE,
            options: 0,
            outgoing_peer: Some(peer.to_owned()),
            outgoing_autoconnect: false,
            connecting,
            close_requested: false,
            last_activity: now,
            last_ping_time: now,
            last_ping_sent: None,
            edge_peer: None,
            exec_proxy,
            kind: RuntimeMetaConnectionKind::Active {
                driver,
                name: Some(peer.to_owned()),
                proxy: proxy_state,
            },
        });
        self.next_connection_id = self.next_connection_id.wrapping_add(1);

        if let Some(connection) = self.meta_connections.last_mut() {
            queue_meta_chunk(connection, &outbound);
            if !connection.connecting && connection.flush_meta_output().is_err() {
                self.meta_connections.pop();
                return Ok(false);
            }
        }

        Ok(true)
    }

    pub(crate) fn outgoing_bind_address_for(&self, address: SocketAddr) -> Option<SocketAddr> {
        let mut matches = self
            .listen_sockets
            .iter()
            .take_while(|socket| socket.bind_to)
            .filter(|socket| socket.address.is_ipv4() == address.is_ipv4())
            .map(|socket| {
                let mut bind = socket.address;
                bind.set_port(0);
                bind
            });
        let bind = matches.next()?;
        if matches.next().is_some() {
            return None;
        }
        Some(bind)
    }

    #[cfg(test)]
    pub(crate) fn accept_meta_connections(&mut self) -> Result<(), TincdError> {
        for index in 0..self.listen_sockets.len() {
            loop {
                if !self.accept_meta_connection_once(index)? {
                    break;
                }
            }
        }

        Ok(())
    }

    pub(crate) fn accept_meta_connection_once(&mut self, index: usize) -> Result<bool, TincdError> {
        let Some(listener) = self.listen_sockets.get(index) else {
            return Ok(false);
        };
        let fwmark = self.fwmark;
        let default_local = listener.address;

        match listener.tcp.accept() {
            Ok((stream, peer)) => {
                if self.should_tarpit_meta_connection(peer, Instant::now()) {
                    self.tarpit_meta_connection(stream);
                    return Ok(true);
                }
                if let Err(error) = configure_tcp_stream(&stream, fwmark) {
                    self.record_log_with_priority(
                        0,
                        LOG_ERR,
                        format!("Could not configure meta connection: {error}"),
                    );
                    return Ok(true);
                }
                let local = stream.local_addr().unwrap_or(default_local);
                let now = Instant::now();
                self.meta_connections.push(RuntimeMetaConnection {
                    id: self.next_connection_id,
                    stream,
                    peer,
                    local,
                    bytes_read: 0,
                    bytes_written: 0,
                    outbound: Vec::new(),
                    outbound_offset: 0,
                    status: CONNECTION_STATUS_PENDING,
                    options: 0,
                    outgoing_peer: None,
                    outgoing_autoconnect: false,
                    connecting: false,
                    close_requested: false,
                    last_activity: now,
                    last_ping_time: now,
                    last_ping_sent: None,
                    edge_peer: None,
                    exec_proxy: None,
                    kind: RuntimeMetaConnectionKind::PendingIncoming { buffer: Vec::new() },
                });
                self.next_connection_id = self.next_connection_id.wrapping_add(1);
                Ok(true)
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(false),
            Err(error) => {
                self.record_log_with_priority(
                    0,
                    LOG_ERR,
                    format!("Accepting a new connection failed: {error}"),
                );
                Ok(false)
            }
        }
    }

    pub(crate) fn should_tarpit_meta_connection(&mut self, peer: SocketAddr, now: Instant) -> bool {
        if is_local_connection(peer) {
            return false;
        }

        if self.previous_tarpit_peer == Some(peer.ip()) {
            let samehost_burst = self.samehost_burst.increment(now);
            if samehost_burst > self.max_connection_burst {
                return true;
            }
        }
        self.previous_tarpit_peer = Some(peer.ip());

        let connection_burst = self.connection_burst.increment(now);
        if connection_burst >= self.max_connection_burst {
            self.connection_burst.cap(self.max_connection_burst);
            return true;
        }

        false
    }

    pub(crate) fn tarpit_meta_connection(&mut self, stream: TcpStream) {
        if self.tarpit.len() >= TARPIT_CAPACITY {
            self.tarpit.pop_front();
        }
        self.tarpit.push_back(stream);
    }

    pub(crate) fn peer_options_snapshot(&self) -> BTreeMap<String, u32> {
        self.state
            .graph
            .nodes()
            .map(|node| (node.name.clone(), node.options))
            .collect()
    }

    pub(crate) fn legacy_key_snapshot(&self) -> BTreeMap<String, RuntimeLegacyKeySnapshot> {
        self.state
            .graph
            .nodes()
            .filter(|node| node.name != self.local_name)
            .map(|node| {
                (
                    node.name.clone(),
                    RuntimeLegacyKeySnapshot {
                        reachable: node.status.reachable,
                        sptps: node.status.sptps,
                        valid_key: node.status.valid_key,
                        valid_key_in: node.status.valid_key_in,
                        next_hop: node.route.next_hop.clone(),
                        min_mtu: node.min_mtu,
                    },
                )
            })
            .collect()
    }

    pub(crate) fn sptps_route_snapshot(&self) -> BTreeMap<String, RuntimeSptpsRouteSnapshot> {
        self.state
            .graph
            .nodes()
            .filter(|node| node.name != self.local_name)
            .map(|node| {
                (
                    node.name.clone(),
                    RuntimeSptpsRouteSnapshot {
                        next_hop: node.route.next_hop.clone(),
                        via: node.route.via.clone(),
                        min_mtu: node.min_mtu,
                    },
                )
            })
            .collect()
    }

    pub(crate) fn handle_legacy_key_actions(
        &mut self,
        actions: Vec<RuntimeLegacyKeyAction>,
    ) -> Result<(), TincdError> {
        for action in actions {
            match action {
                RuntimeLegacyKeyAction::SendAnswer { peer, next_hop } => {
                    let message = self.generate_legacy_answer_key_message(&peer)?;
                    self.send_active_meta_message_to_peer(&next_hop, &message)?;
                }
                RuntimeLegacyKeyAction::SendRequest { peer, next_hop } => {
                    let message =
                        MetaMessage::RequestKey(RequestKeyMessage::new(&self.local_name, &peer));
                    self.send_active_meta_message_to_peer(&next_hop, &message)?;
                }
            }
        }

        Ok(())
    }

    pub(crate) fn handle_sptps_key_actions(
        &mut self,
        actions: Vec<RuntimeSptpsKeyAction>,
    ) -> Result<(), TincdError> {
        for action in actions {
            if self.packet_codec.peer(&action.peer).is_some() {
                continue;
            }
            if !self.sptps_req_key_due(&action.peer) {
                continue;
            }
            self.restart_pending_sptps_key_exchange(&action.peer);
            let messages = self.start_sptps_key_exchange(&action.peer)?;
            if messages.is_empty() {
                continue;
            }
            for message in messages {
                self.send_active_meta_message_to_peer(&action.next_hop, &message)?;
            }
        }

        Ok(())
    }

    pub(crate) fn handle_legacy_nested_tx_targets_like_tinc(
        &mut self,
        targets: Vec<String>,
    ) -> Result<(), TincdError> {
        for target in targets {
            self.try_tx_like_tinc(&target, true)?;
        }

        Ok(())
    }

    pub(crate) fn sptps_req_key_due(&self, peer: &str) -> bool {
        if self
            .state
            .graph
            .node(peer)
            .is_some_and(|node| !node.status.waiting_for_key)
        {
            return true;
        }

        self.sptps_last_req_key
            .get(peer)
            .is_none_or(|sent| sent.elapsed() > SPTPS_REQ_KEY_INTERVAL)
    }

    pub(crate) fn legacy_req_key_due(&self, peer: &str) -> bool {
        self.legacy_last_req_key
            .get(peer)
            .is_none_or(|sent| sent.elapsed() >= LEGACY_REQ_KEY_INTERVAL)
    }

    pub(crate) fn restart_pending_sptps_key_exchange(&mut self, peer: &str) {
        let waiting_for_key = self
            .state
            .graph
            .node(peer)
            .is_some_and(|node| node.status.waiting_for_key);
        let recently_requested = self
            .sptps_last_req_key
            .get(peer)
            .is_some_and(|sent| sent.elapsed() <= SPTPS_REQ_KEY_INTERVAL);
        if waiting_for_key && recently_requested {
            return;
        }

        if let Some(key_exchange) = &mut self.key_exchange {
            key_exchange.remove_pending_session(peer);
        }
        if let Some(node) = self.state.graph.node_mut(peer) {
            node.status.waiting_for_key = false;
            node.status.valid_key = false;
        }
    }

    #[cfg(test)]
    pub(crate) fn drain_device_packets(&mut self) -> Result<bool, TincdError> {
        let mut did_work = false;

        loop {
            if !self.poll_device_packet()? {
                return Ok(did_work);
            }
            did_work = true;
        }
    }

    pub(crate) fn poll_device_packet(&mut self) -> Result<bool, TincdError> {
        if self.device_read_backoff_active(Instant::now()) {
            return Ok(false);
        }

        let packet = match self.device.read_packet() {
            Ok(Some(packet)) => {
                self.device_read_errors = 0;
                self.device_read_backoff_until = None;
                packet
            }
            Ok(None) => return Ok(false),
            Err(error) => return self.handle_device_read_error_like_tinc(error),
        };
        let peer_options = self.peer_options_snapshot();
        let udp_target_snapshots = self.udp_target_snapshot();
        let sptps_route_snapshots = self.sptps_route_snapshot();
        let legacy_key_snapshots = self.legacy_key_snapshot();
        let mut legacy_key_actions = Vec::new();
        let mut sptps_key_actions = Vec::new();
        let mut mtu_reductions = Vec::new();
        let mut legacy_nested_tx_targets = Vec::new();
        let mut transport = RuntimeUdpPacketTransport {
            local_name: &self.local_name,
            sockets: &self.listen_sockets,
            addresses: &self.addresses,
            udp_socket_by_peer: &self.udp_socket_by_peer,
            modern_peer_keys: &self.keys.peer_public_keys,
            meta_connections: &mut self.meta_connections,
            experimental: self.state.experimental,
            local_tcp_only: self.local_tcp_only,
            max_output_buffer_size: self.max_output_buffer_size,
            peer_options,
            packet_codec: &mut self.packet_codec,
            legacy_codec: &mut self.legacy_codec,
            udp_target_snapshots,
            udp_unconfirmed_guess_counter: &mut self.udp_unconfirmed_guess_counter,
            sptps_route_snapshots,
            legacy_key_snapshots,
            legacy_last_req_key: &mut self.legacy_last_req_key,
            legacy_key_actions: &mut legacy_key_actions,
            sptps_key_actions: &mut sptps_key_actions,
            mtu_reductions: &mut mtu_reductions,
            legacy_nested_tx_targets: &mut legacy_nested_tx_targets,
            traffic: &mut self.traffic,
            pcap_subscribers: &mut self.pcap_subscribers,
            priority_inheritance: self.engine_config.route.priority_inheritance,
        };
        let mut engine_config = self.engine_config.clone();
        engine_config.route.mac_expire = self.mac_expire;
        engine_config.route.now_secs = current_unix_secs();

        let events = handle_device_packet_with(
            &mut self.state,
            &mut self.device,
            &mut transport,
            &engine_config,
            packet,
        )
        .map_err(engine_error)?;
        self.handle_legacy_key_actions(legacy_key_actions)?;
        self.handle_sptps_key_actions(sptps_key_actions)?;
        self.apply_mtu_reductions(mtu_reductions);
        self.handle_legacy_nested_tx_targets_like_tinc(legacy_nested_tx_targets)?;
        self.handle_engine_events(events)?;

        Ok(true)
    }

    pub(crate) fn handle_device_read_error_like_tinc(
        &mut self,
        error: DeviceError,
    ) -> Result<bool, TincdError> {
        let device = self.device.info().device.clone();
        let delay = DEVICE_READ_ERROR_BACKOFF_STEP * self.device_read_errors;
        if !delay.is_zero() {
            self.device_read_backoff_until = Some(Instant::now() + delay);
        } else {
            self.device_read_backoff_until = None;
        }
        self.device_read_errors = self.device_read_errors.saturating_add(1);

        self.record_log_with_priority(
            0,
            LOG_ERR,
            format!("Error while reading from {device}: {error}"),
        );

        if self.device_read_errors > DEVICE_READ_ERROR_LIMIT {
            self.record_log_with_priority(
                0,
                LOG_ERR,
                format!("Too many errors from {device}, exiting!"),
            );
            return Err(TincdError::RuntimeState(format!(
                "Too many errors from {device}, exiting!"
            )));
        }

        Ok(false)
    }

    pub(crate) fn handle_engine_events(
        &mut self,
        events: Vec<EngineEvent>,
    ) -> Result<(), TincdError> {
        for event in events {
            match event {
                EngineEvent::DeviceWrite { packet } => {
                    self.record_packet_diag("device-write", |count| {
                        let summary = packet_summary(&packet);
                        format!("diag device-write count={count} {summary}")
                    });
                }
                EngineEvent::LearnedSubnet { mut subnet } => {
                    self.run_subnet_script_for_subnet("subnet-up", &subnet);
                    subnet.owner = None;
                    let message = MetaMessage::AddSubnet(SubnetMessage {
                        nonce: self.next_nonce(),
                        owner: self.local_name.clone(),
                        subnet,
                    });
                    self.broadcast_active_meta_message_except(None, &message)?;
                }
                EngineEvent::TransportSend {
                    owner,
                    target,
                    packet,
                    forced_tcp,
                } => {
                    self.record_packet_diag("transport-send", |count| {
                        let summary = packet_summary(&packet);
                        format!("diag transport-send owner={owner} target={target} count={count} {summary}")
                    });
                    self.try_tx_after_packet_send_like_tinc(&owner, &target, true, forced_tcp)?;
                }
                EngineEvent::TransportDeferred {
                    owner,
                    target,
                    packet,
                    forced_tcp,
                    reason,
                } => {
                    self.record_packet_diag(
                        format!("transport-deferred:{owner}:{target}"),
                        |count| {
                            let summary = packet_summary(&packet);
                            format!(
                                "diag transport-deferred owner={owner} target={target} count={count} reason={reason} {summary}"
                            )
                        },
                    );
                    self.try_tx_after_packet_send_like_tinc(&owner, &target, true, forced_tcp)?;
                }
                EngineEvent::Broadcast { targets, packet } => {
                    self.record_packet_diag("broadcast", |count| {
                        let target_list = targets.join(",");
                        let summary = packet_summary(&packet);
                        format!("diag broadcast targets={target_list} count={count} {summary}")
                    });
                    for target in targets {
                        self.try_udp_for_peer(&target)?;
                        self.try_mtu_for_peer(&target)?;
                    }
                }
                EngineEvent::Drop { reason } => {
                    self.record_packet_diag(format!("drop:{reason:?}"), |count| {
                        format!("diag drop count={count} reason={reason:?}")
                    });
                }
                _ => {}
            }
        }

        Ok(())
    }

    pub(crate) fn record_packet_diag(
        &mut self,
        key: impl Borrow<str>,
        message: impl FnOnce(u64) -> String,
    ) {
        if !self.packet_diag_enabled() {
            return;
        }

        let count = {
            let key = key.borrow();
            if let Some(count) = self.packet_diag_counts.get_mut(key) {
                *count = count.saturating_add(1);
                *count
            } else {
                self.packet_diag_counts.insert(key.to_owned(), 1);
                1
            }
        };

        if count <= 8 || count.is_power_of_two() {
            let message = message(count);
            self.record_log_with_priority(DEBUG_TRAFFIC, LOG_DEBUG, message);
        }
    }

    fn packet_diag_enabled(&self) -> bool {
        DEBUG_TRAFFIC <= self.debug_level
            || self.log_subscribers.iter().any(|subscriber| {
                DEBUG_TRAFFIC <= control_log_level(subscriber.level, self.debug_level)
            })
    }

    pub(crate) fn handle_meta_tcp_packet(
        &mut self,
        index: usize,
        payload: Vec<u8>,
    ) -> Result<(), TincdError> {
        let Some(source) = self.meta_connections[index]
            .active_name()
            .map(str::to_owned)
        else {
            return Ok(());
        };
        let priority = if self.meta_connections[index].options & OPTION_TCPONLY != 0 {
            0
        } else {
            -1
        };
        let packet = VpnPacket::new(payload)
            .map_err(|error| TincdError::RuntimeState(error.to_string()))?
            .with_priority(priority);

        self.handle_network_packet_from_meta(&source, packet)
    }

    pub(crate) fn handle_meta_sptps_packet(
        &mut self,
        _index: usize,
        payload: Vec<u8>,
    ) -> Result<(), TincdError> {
        let envelope = RelayEnvelope::decode(&payload)
            .map_err(|error| TincdError::MetaConnection(error.to_string()))?;
        let myself = NodeId::from_name(&self.local_name);
        let Some(source) = self
            .packet_codec
            .ids()
            .name(envelope.source)
            .map(str::to_owned)
        else {
            return Ok(());
        };

        if !envelope.destination.is_null() && envelope.destination != myself {
            let Some(destination) = self
                .packet_codec
                .ids()
                .name(envelope.destination)
                .map(str::to_owned)
            else {
                return Ok(());
            };

            let Some(destination_node) = self.state.graph.node(&destination) else {
                return Ok(());
            };
            let destination_reachable = destination_node.status.reachable;
            let destination_via = destination_node.route.via.clone();

            if !destination_reachable {
                return Ok(());
            }

            if destination_via.as_deref() == Some(self.local_name.as_str()) {
                let local_name = self.local_name.clone();
                self.send_udp_info(&local_name, &source)?;
            }

            self.forward_sptps_tcp_payload(&destination, &source, &payload)?;

            return Ok(());
        }

        let raw_tcp_packet = _index != usize::MAX;
        if raw_tcp_packet && envelope.destination.is_null() {
            return Ok(());
        }

        let local_name = self.local_name.clone();
        self.send_udp_info(&local_name, &source)?;

        let packet = match self.packet_codec.decode(&source, &payload) {
            Ok(packet) => packet,
            Err(error) => {
                self.record_packet_diag(format!("tcp-drop:sptps-decode:{source}"), |count| {
                    format!(
                        "diag tcp-drop source={source} count={count} reason=sptps-decode error={error}"
                    )
                });
                self.request_sptps_key_after_bad_tcp_packet_like_tinc(&source)?;
                return Ok(());
            }
        };

        self.handle_network_packet_from_meta(&source, packet)?;
        let local_name = self.local_name.clone();
        self.send_mtu_info(&local_name, &source, DEFAULT_MTU)
    }

    pub(crate) fn handle_network_packet_from_meta(
        &mut self,
        source: &str,
        packet: VpnPacket,
    ) -> Result<(), TincdError> {
        self.record_inbound_traffic(source, packet.len());
        self.capture_control_pcap_packet(&packet);

        let peer_options = self.peer_options_snapshot();
        let udp_target_snapshots = self.udp_target_snapshot();
        let sptps_route_snapshots = self.sptps_route_snapshot();
        let legacy_key_snapshots = self.legacy_key_snapshot();
        let mut legacy_key_actions = Vec::new();
        let mut sptps_key_actions = Vec::new();
        let mut mtu_reductions = Vec::new();
        let mut legacy_nested_tx_targets = Vec::new();
        let mut transport = RuntimeUdpPacketTransport {
            local_name: &self.local_name,
            sockets: &self.listen_sockets,
            addresses: &self.addresses,
            udp_socket_by_peer: &self.udp_socket_by_peer,
            modern_peer_keys: &self.keys.peer_public_keys,
            meta_connections: &mut self.meta_connections,
            experimental: self.state.experimental,
            local_tcp_only: self.local_tcp_only,
            max_output_buffer_size: self.max_output_buffer_size,
            peer_options,
            packet_codec: &mut self.packet_codec,
            legacy_codec: &mut self.legacy_codec,
            udp_target_snapshots,
            udp_unconfirmed_guess_counter: &mut self.udp_unconfirmed_guess_counter,
            sptps_route_snapshots,
            legacy_key_snapshots,
            legacy_last_req_key: &mut self.legacy_last_req_key,
            legacy_key_actions: &mut legacy_key_actions,
            sptps_key_actions: &mut sptps_key_actions,
            mtu_reductions: &mut mtu_reductions,
            legacy_nested_tx_targets: &mut legacy_nested_tx_targets,
            traffic: &mut self.traffic,
            pcap_subscribers: &mut self.pcap_subscribers,
            priority_inheritance: self.engine_config.route.priority_inheritance,
        };

        let events = handle_network_packet_with(
            &mut self.state,
            &mut self.device,
            &mut transport,
            &self.engine_config,
            source,
            packet,
        )
        .map_err(engine_error)?;
        self.handle_legacy_key_actions(legacy_key_actions)?;
        self.handle_sptps_key_actions(sptps_key_actions)?;
        self.apply_mtu_reductions(mtu_reductions);
        self.handle_legacy_nested_tx_targets_like_tinc(legacy_nested_tx_targets)?;
        self.handle_engine_events(events)
    }

    #[cfg(test)]
    pub(crate) fn drain_udp_datagrams(&mut self) -> Result<bool, TincdError> {
        let mut did_work = false;

        for index in 0..self.listen_sockets.len() {
            while self.read_udp_datagram_once(index)? {
                did_work = true;
            }
        }

        Ok(did_work)
    }

    #[cfg(any(test, not(target_os = "linux")))]
    pub(crate) fn read_udp_datagram_once(&mut self, index: usize) -> Result<bool, TincdError> {
        let Some(socket) = self.listen_sockets.get(index) else {
            return Ok(false);
        };
        let mut buffer = vec![0u8; MAX_DATAGRAM_SIZE];
        let (len, peer) = match socket.udp.recv_from(&mut buffer) {
            Ok(received) => received,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(false),
            Err(error) => return Err(listen_io(error)),
        };

        self.handle_udp_datagram(index, peer, &buffer[..len])?;
        Ok(true)
    }

    pub(crate) fn read_udp_datagrams_once(
        &mut self,
        index: usize,
        limit: usize,
    ) -> Result<usize, TincdError> {
        if limit == 0 || self.listen_sockets.get(index).is_none() {
            return Ok(0);
        }

        #[cfg(target_os = "linux")]
        {
            self.read_udp_datagrams_recvmmsg(index, limit)
        }

        #[cfg(not(target_os = "linux"))]
        {
            let mut read = 0usize;
            while read < limit && self.read_udp_datagram_once(index)? {
                read += 1;
            }
            Ok(read)
        }
    }

    #[cfg(target_os = "linux")]
    fn read_udp_datagrams_recvmmsg(
        &mut self,
        index: usize,
        limit: usize,
    ) -> Result<usize, TincdError> {
        let Some(socket) = self.listen_sockets.get(index) else {
            return Ok(0);
        };
        let fd = socket.udp.as_raw_fd();
        let count = limit.min(u32::MAX as usize);
        let mut batch = std::mem::take(&mut self.udp_recv_batch);
        let (_iovecs, mut messages) = batch.prepare(count);

        let received = unsafe {
            libc::recvmmsg(
                fd,
                messages.as_mut_ptr(),
                count as libc::c_uint,
                libc::MSG_DONTWAIT,
                std::ptr::null_mut(),
            )
        };

        let result = if received < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::WouldBlock {
                Ok(0)
            } else {
                Err(listen_io(error))
            }
        } else {
            let received = received as usize;
            let mut result = Ok(received);
            for index_in_batch in 0..received {
                let len = messages[index_in_batch].msg_len as usize;
                if len == 0 || len > MAX_DATAGRAM_SIZE {
                    continue;
                }
                let Some(peer) = socket_addr_from_storage(&batch.addrs[index_in_batch]) else {
                    continue;
                };
                if let Err(error) =
                    self.handle_udp_datagram(index, peer, &batch.buffers[index_in_batch][..len])
                {
                    result = Err(error);
                    break;
                }
            }
            result
        };

        self.udp_recv_batch = batch;
        result
    }

    fn handle_udp_datagram(
        &mut self,
        index: usize,
        peer: SocketAddr,
        datagram: &[u8],
    ) -> Result<(), TincdError> {
        let len = datagram.len();
        let source = if let Some(source) = self.udp_source_node(peer) {
            source
        } else {
            match self.packet_codec.verify_direct_datagram_source(datagram) {
                Ok(Some(source)) => source.to_owned(),
                Ok(None) | Err(_) => match self.legacy_udp_try_harder(peer, datagram) {
                    Some(source) => source,
                    None => return Ok(()),
                },
            }
        };
        self.udp_socket_by_peer.insert(source.clone(), index);
        if self.handle_sptps_udp_envelope(&source, peer, index, datagram)? {
            return Ok(());
        }
        let packet = if let Some(session) = self.packet_codec.peer(&source) {
            let expected = session.packet_type();
            let record = match self.packet_codec.decode_record(&source, datagram) {
                Ok(record) => record,
                Err(error) => {
                    self.record_packet_diag(format!("udp-drop:sptps-decode:{source}"), |count| {
                        format!(
                            "diag udp-drop source={source} peer={peer} count={count} reason=sptps-decode error={error} len={len}"
                        )
                    });
                    return Ok(());
                }
            };
            if record.record_type == SPTPS_UDP_PROBE_TYPE {
                self.note_udp_recent_len(&source, record.payload.len());
                self.handle_udp_probe_payload(&source, peer, index, &record.payload, true, true)?;
                self.update_node_udp_like_tinc(&source, peer, index);
                return Ok(());
            }
            if record.record_type != expected {
                self.record_packet_diag(format!("udp-drop:sptps-type:{source}"), |count| {
                    format!(
                        "diag udp-drop source={source} peer={peer} count={count} reason=sptps-type actual={} expected={} payload_len={}",
                        record.record_type,
                        expected,
                        record.payload.len()
                    )
                });
                return Ok(());
            }
            match sptps_packet_from_payload(record.record_type, record.payload) {
                Ok(packet) => packet,
                Err(error) => {
                    self.record_packet_diag(format!("udp-drop:sptps-packet:{source}"), |count| {
                        format!(
                            "diag udp-drop source={source} peer={peer} count={count} reason=sptps-packet error={error}"
                        )
                    });
                    return Ok(());
                }
            }
        } else if self.legacy_codec.peer(&source).is_some() {
            match self.legacy_codec.decode(&source, datagram) {
                Ok(packet) => packet,
                Err(error) => {
                    self.record_packet_diag(format!("udp-drop:legacy-decode:{source}"), |count| {
                        format!(
                            "diag udp-drop source={source} peer={peer} count={count} reason=legacy-decode error={error} len={len}"
                        )
                    });
                    return Ok(());
                }
            }
        } else {
            self.request_sptps_key_after_unkeyed_udp_like_tinc(&source, datagram)?;
            self.record_packet_diag(format!("udp-drop:no-key:{source}"), |count| {
                format!(
                    "diag udp-drop source={source} peer={peer} count={count} reason=no-key len={len}"
                )
            });
            return Ok(());
        };
        self.note_udp_recent_len(&source, packet.len());
        if is_udp_probe_payload(&packet.data) {
            let secure_udp = self.packet_codec.peer(&source).is_some()
                || self.legacy_codec.peer(&source).is_some();
            self.handle_udp_probe_payload(&source, peer, index, &packet.data, secure_udp, true)?;
            self.update_node_udp_like_tinc(&source, peer, index);
            return Ok(());
        }
        self.record_inbound_traffic(&source, packet.len());
        self.capture_control_pcap_packet(&packet);
        let peer_options = self.peer_options_snapshot();
        let udp_target_snapshots = self.udp_target_snapshot();
        let sptps_route_snapshots = self.sptps_route_snapshot();
        let legacy_key_snapshots = self.legacy_key_snapshot();
        let mut legacy_key_actions = Vec::new();
        let mut sptps_key_actions = Vec::new();
        let mut mtu_reductions = Vec::new();
        let mut legacy_nested_tx_targets = Vec::new();
        let mut transport = RuntimeUdpPacketTransport {
            local_name: &self.local_name,
            sockets: &self.listen_sockets,
            addresses: &self.addresses,
            udp_socket_by_peer: &self.udp_socket_by_peer,
            modern_peer_keys: &self.keys.peer_public_keys,
            meta_connections: &mut self.meta_connections,
            experimental: self.state.experimental,
            local_tcp_only: self.local_tcp_only,
            max_output_buffer_size: self.max_output_buffer_size,
            peer_options,
            packet_codec: &mut self.packet_codec,
            legacy_codec: &mut self.legacy_codec,
            udp_target_snapshots,
            udp_unconfirmed_guess_counter: &mut self.udp_unconfirmed_guess_counter,
            sptps_route_snapshots,
            legacy_key_snapshots,
            legacy_last_req_key: &mut self.legacy_last_req_key,
            legacy_key_actions: &mut legacy_key_actions,
            sptps_key_actions: &mut sptps_key_actions,
            mtu_reductions: &mut mtu_reductions,
            legacy_nested_tx_targets: &mut legacy_nested_tx_targets,
            traffic: &mut self.traffic,
            pcap_subscribers: &mut self.pcap_subscribers,
            priority_inheritance: self.engine_config.route.priority_inheritance,
        };

        let events = handle_network_packet_with(
            &mut self.state,
            &mut self.device,
            &mut transport,
            &self.engine_config,
            &source,
            packet,
        )
        .map_err(engine_error)?;
        self.handle_legacy_key_actions(legacy_key_actions)?;
        self.handle_sptps_key_actions(sptps_key_actions)?;
        self.apply_mtu_reductions(mtu_reductions);
        self.handle_legacy_nested_tx_targets_like_tinc(legacy_nested_tx_targets)?;
        self.handle_engine_events(events)?;
        self.update_node_udp_like_tinc(&source, peer, index);
        Ok(())
    }

    pub(crate) fn handle_sptps_udp_envelope(
        &mut self,
        udp_source: &str,
        peer: SocketAddr,
        socket_index: usize,
        datagram: &[u8],
    ) -> Result<bool, TincdError> {
        let Ok(envelope) = RelayEnvelope::decode(datagram) else {
            return Ok(false);
        };
        let Some(source) = self
            .packet_codec
            .ids()
            .name(envelope.source)
            .map(str::to_owned)
        else {
            return Ok(false);
        };
        let myself = NodeId::from_name(&self.local_name);
        let destination = if envelope.destination.is_null() {
            None
        } else if envelope.destination == myself {
            Some(self.local_name.clone())
        } else {
            self.packet_codec
                .ids()
                .name(envelope.destination)
                .map(str::to_owned)
        };

        if !envelope.destination.is_null() {
            let Some(destination) = destination.as_deref() else {
                return Ok(true);
            };
            if self.should_send_udp_info_for_sptps_udp_relay_like_tinc(
                udp_source,
                &source,
                destination,
            ) {
                let local_name = self.local_name.clone();
                self.send_udp_info(&local_name, &source)?;
            }
        }

        if let Some(destination) = destination.as_deref()
            && destination != self.local_name
        {
            self.record_packet_diag(
                format!("udp-relay:{source}:{destination}"),
                |count| {
                    format!(
                        "diag udp-relay source={source} destination={destination} peer={peer} count={count} len={}",
                        datagram.len()
                    )
                },
            );
            self.forward_sptps_relay_record(destination, &source, &envelope.payload)?;
            return Ok(true);
        }

        let relayed_to_local = !envelope.destination.is_null();

        if self.packet_codec.peer(&source).is_none() {
            if relayed_to_local {
                self.request_sptps_key_after_relayed_unkeyed_udp_like_tinc(udp_source, &source)?;
                self.record_packet_diag(format!("udp-drop:no-key:{source}"), |count| {
                    format!(
                        "diag udp-drop source={source} peer={peer} count={count} reason=no-key len={}",
                        datagram.len()
                    )
                });
                return Ok(true);
            }
            return Ok(false);
        }

        let expected = self
            .packet_codec
            .peer(&source)
            .map(|session| session.packet_type())
            .unwrap_or(SPTPS_UDP_ROUTER_PACKET_TYPE);
        let record = match self.packet_codec.decode_record(&source, datagram) {
            Ok(record) => record,
            Err(error) => {
                self.record_packet_diag(format!("udp-drop:relay-decode:{source}"), |count| {
                    format!(
                        "diag udp-drop source={source} peer={peer} count={count} reason=relay-decode error={error} len={}",
                        datagram.len()
                    )
                });
                return Ok(true);
            }
        };

        if record.record_type == SPTPS_UDP_PROBE_TYPE {
            self.note_udp_recent_len(&source, record.payload.len());
            self.handle_udp_probe_payload(
                &source,
                peer,
                socket_index,
                &record.payload,
                true,
                !relayed_to_local,
            )?;
            return Ok(true);
        }
        if record.record_type != expected {
            self.record_packet_diag(format!("udp-drop:relay-type:{source}"), |count| {
                format!(
                    "diag udp-drop source={source} peer={peer} count={count} reason=relay-type actual={} expected={} payload_len={}",
                    record.record_type,
                    expected,
                    record.payload.len()
                )
            });
            return Ok(true);
        }

        let packet = match sptps_packet_from_payload(record.record_type, record.payload) {
            Ok(packet) => packet,
            Err(error) => {
                self.record_packet_diag(format!("udp-drop:relay-packet:{source}"), |count| {
                    format!(
                        "diag udp-drop source={source} peer={peer} count={count} reason=relay-packet error={error}"
                    )
                });
                return Ok(true);
            }
        };
        self.note_udp_recent_len(&source, packet.len());
        self.record_inbound_traffic(&source, packet.len());
        self.capture_control_pcap_packet(&packet);
        self.route_udp_packet_from_source(&source, packet)?;
        if relayed_to_local {
            if let Some(udp_sender) = self.udp_source_node(peer) {
                let local_name = self.local_name.clone();
                self.send_mtu_info(&local_name, &udp_sender, DEFAULT_MTU)?;
            }
        } else {
            self.update_node_udp_like_tinc(&source, peer, socket_index);
        }

        Ok(true)
    }

    pub(crate) fn should_send_udp_info_for_sptps_udp_relay_like_tinc(
        &self,
        udp_source: &str,
        source: &str,
        destination: &str,
    ) -> bool {
        let source_via = self
            .state
            .graph
            .node(source)
            .and_then(|node| node.route.via.as_deref());
        let Some(destination_node) = self.state.graph.node(destination) else {
            return false;
        };
        if !destination_node.status.reachable {
            return false;
        }

        source_via != Some(udp_source)
            && (destination == self.local_name
                || destination_node.route.via.as_deref() == Some(self.local_name.as_str()))
    }

    pub(crate) fn forward_sptps_relay_record(
        &mut self,
        destination: &str,
        source: &str,
        record: &[u8],
    ) -> Result<(), TincdError> {
        let Some(destination_node) = self.state.graph.node(destination) else {
            return Ok(());
        };
        if !destination_node.status.reachable {
            return Ok(());
        }

        let destination_id = destination_node.id;
        let relay_hint = destination_node
            .route
            .next_hop
            .clone()
            .unwrap_or_else(|| destination.to_owned());
        let owner_packet_len = record.len().saturating_sub(SPTPS_DATAGRAM_OVERHEAD);
        let source_id = self
            .state
            .graph
            .node(source)
            .map(|node| node.id)
            .unwrap_or_else(|| NodeId::from_name(source));
        let route_snapshots = self.sptps_route_snapshot();
        let targets = choose_sptps_transport_targets(
            &self.local_name,
            &route_snapshots,
            destination,
            &relay_hint,
            owner_packet_len,
            false,
        );
        let Some(relay_node) = self.state.graph.node(&targets.udp_relay) else {
            return Ok(());
        };
        if !relay_node.status.reachable {
            return Ok(());
        }

        let relay_min_mtu = relay_node.min_mtu;
        let relay_supports_udp_relay = option_version(relay_node.options) >= 4;
        let relay_tcp_only = self.local_tcp_only || relay_node.options & OPTION_TCPONLY != 0;
        let direct = source == self.local_name && targets.udp_relay == destination;
        let needs_tcp_fallback = relay_tcp_only
            || (!direct && !relay_supports_udp_relay)
            || owner_packet_len > relay_min_mtu;

        let envelope = RelayEnvelope::relayed(destination_id, source_id, record.to_vec());
        let datagram = envelope.encode();

        if needs_tcp_fallback {
            let connection_index = self
                .current_meta_connection_id_for_peer(&targets.tcp_target)
                .and_then(|id| self.connection_index_by_id(id));
            if let Some(index) = connection_index {
                let connection = &mut self.meta_connections[index];
                if option_version(connection.options) >= 7 {
                    if let Err(error) = send_sptps_tcp_packet_on_connection(
                        connection,
                        &datagram,
                        self.max_output_buffer_size,
                    ) {
                        if mark_meta_connection_closed_on_scoped_error_like_tinc_for_daemon(
                            connection, error,
                        )? {
                            return Ok(());
                        }
                    }
                } else {
                    let message = MetaMessage::RequestKey(RequestKeyMessage::sptps_tcp_packet(
                        source,
                        destination,
                        record,
                    ));
                    if let Err(error) = send_meta_message_on_connection(connection, &message) {
                        if mark_meta_connection_closed_on_scoped_error_like_tinc_for_daemon(
                            connection, error,
                        )? {
                            return Ok(());
                        }
                    }
                }
            }
            self.try_tx_after_packet_send_like_tinc(destination, &targets.tcp_target, true, false)?;
            return Ok(());
        }

        let Some(address) = self.addresses.address(&targets.udp_relay) else {
            return Ok(());
        };
        let Some(socket_index) = self.listen_socket_index_for_peer(&targets.udp_relay, address)
        else {
            return Ok(());
        };
        let socket = &self.listen_sockets[socket_index];
        let sent = match socket.udp.send_to(&datagram, address) {
            Ok(sent) => sent,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                return Ok(());
            }
            Err(error) if is_message_too_long(&error) => {
                self.reduce_mtu(&targets.udp_relay, owner_packet_len.saturating_sub(1));
                return Ok(());
            }
            Err(error) => {
                return Err(TincdError::ListenIo(format!(
                    "error sending UDP SPTPS relay packet to {}: {error}",
                    targets.udp_relay
                )));
            }
        };
        if sent != datagram.len() {
            return Err(TincdError::ListenIo(format!(
                "short SPTPS UDP relay send: {sent} < {}",
                datagram.len()
            )));
        }
        self.try_tx_after_packet_send_like_tinc(destination, &targets.udp_relay, true, false)?;
        Ok(())
    }

    pub(crate) fn forward_sptps_tcp_payload(
        &mut self,
        destination: &str,
        source: &str,
        payload: &[u8],
    ) -> Result<(), TincdError> {
        match RelayEnvelope::decode(payload) {
            Ok(envelope) if !envelope.destination.is_null() => {
                self.forward_sptps_relay_record(destination, source, &envelope.payload)
            }
            _ => self.forward_sptps_relay_record(destination, source, payload),
        }
    }

    pub(crate) fn route_udp_packet_from_source(
        &mut self,
        source: &str,
        packet: VpnPacket,
    ) -> Result<(), TincdError> {
        let peer_options = self.peer_options_snapshot();
        let udp_target_snapshots = self.udp_target_snapshot();
        let sptps_route_snapshots = self.sptps_route_snapshot();
        let legacy_key_snapshots = self.legacy_key_snapshot();
        let mut legacy_key_actions = Vec::new();
        let mut sptps_key_actions = Vec::new();
        let mut mtu_reductions = Vec::new();
        let mut legacy_nested_tx_targets = Vec::new();
        let mut transport = RuntimeUdpPacketTransport {
            local_name: &self.local_name,
            sockets: &self.listen_sockets,
            addresses: &self.addresses,
            udp_socket_by_peer: &self.udp_socket_by_peer,
            modern_peer_keys: &self.keys.peer_public_keys,
            meta_connections: &mut self.meta_connections,
            experimental: self.state.experimental,
            local_tcp_only: self.local_tcp_only,
            max_output_buffer_size: self.max_output_buffer_size,
            peer_options,
            packet_codec: &mut self.packet_codec,
            legacy_codec: &mut self.legacy_codec,
            udp_target_snapshots,
            udp_unconfirmed_guess_counter: &mut self.udp_unconfirmed_guess_counter,
            sptps_route_snapshots,
            legacy_key_snapshots,
            legacy_last_req_key: &mut self.legacy_last_req_key,
            legacy_key_actions: &mut legacy_key_actions,
            sptps_key_actions: &mut sptps_key_actions,
            mtu_reductions: &mut mtu_reductions,
            legacy_nested_tx_targets: &mut legacy_nested_tx_targets,
            traffic: &mut self.traffic,
            pcap_subscribers: &mut self.pcap_subscribers,
            priority_inheritance: self.engine_config.route.priority_inheritance,
        };

        let events = handle_network_packet_with(
            &mut self.state,
            &mut self.device,
            &mut transport,
            &self.engine_config,
            source,
            packet,
        )
        .map_err(engine_error)?;
        self.handle_legacy_key_actions(legacy_key_actions)?;
        self.handle_sptps_key_actions(sptps_key_actions)?;
        self.apply_mtu_reductions(mtu_reductions);
        self.handle_legacy_nested_tx_targets_like_tinc(legacy_nested_tx_targets)?;
        self.handle_engine_events(events)
    }

    pub(crate) fn note_udp_recent_len(&mut self, source: &str, len: usize) {
        let state = self.udp_probe.entry(source.to_owned()).or_default();
        state.max_recent_len = state.max_recent_len.max(len);
    }

    pub(crate) fn update_node_udp_like_tinc(
        &mut self,
        source: &str,
        peer: SocketAddr,
        socket_index: usize,
    ) {
        if source == self.local_name {
            return;
        }

        let changed = self
            .state
            .graph
            .node(source)
            .and_then(|node| node.udp_address.as_ref())
            .and_then(edge_endpoint_socket_addr)
            != Some(peer);
        if !changed {
            self.udp_socket_by_peer
                .insert(source.to_owned(), socket_index);
            return;
        }

        self.udp_socket_by_peer
            .insert(source.to_owned(), socket_index);
        if let Some(node) = self.state.graph.node_mut(source) {
            node.udp_address = Some(EdgeEndpoint::new(
                peer.ip().to_string(),
                peer.port().to_string(),
            ));
            node.status.udp_confirmed = false;
            node.mtu_probes = 0;
            node.min_mtu = 0;
            node.max_mtu = DEFAULT_MTU;
        }
        if let Some(state) = self.udp_probe.get_mut(source) {
            state.max_recent_len = 0;
            state.udp_ping_timeout = None;
        }
    }

    pub(crate) fn request_sptps_key_after_unkeyed_udp_like_tinc(
        &mut self,
        source: &str,
        datagram: &[u8],
    ) -> Result<(), TincdError> {
        let Some(node) = self.state.graph.node(source) else {
            return Ok(());
        };
        if !node.status.reachable || !node.status.sptps {
            return Ok(());
        }
        if node.status.waiting_for_key || self.packet_codec.peer(source).is_some() {
            return Ok(());
        }

        if option_version(node.options) >= 4 {
            let Ok(envelope) = RelayEnvelope::decode(datagram) else {
                return Ok(());
            };
            if !envelope.destination.is_null() {
                return Ok(());
            }
        }

        let Some(next_hop) = node.route.next_hop.clone() else {
            return Ok(());
        };
        let messages = self.start_sptps_key_exchange(source)?;
        for message in messages {
            self.send_active_meta_message_to_peer(&next_hop, &message)?;
        }

        Ok(())
    }

    pub(crate) fn request_sptps_key_after_relayed_unkeyed_udp_like_tinc(
        &mut self,
        relay: &str,
        source: &str,
    ) -> Result<(), TincdError> {
        let Some(relay_node) = self.state.graph.node(relay) else {
            return Ok(());
        };
        if !relay_node.status.reachable
            || !relay_node.status.sptps
            || !relay_node.status.udp_confirmed
            || option_version(relay_node.options) < 4
        {
            return Ok(());
        }

        let Some(source_node) = self.state.graph.node(source) else {
            return Ok(());
        };
        if !source_node.status.reachable || !source_node.status.sptps {
            return Ok(());
        }
        if source_node.status.waiting_for_key || self.packet_codec.peer(source).is_some() {
            return Ok(());
        }

        let Some(next_hop) = source_node.route.next_hop.clone() else {
            return Ok(());
        };
        let messages = self.start_sptps_key_exchange(source)?;
        for message in messages {
            self.send_active_meta_message_to_peer(&next_hop, &message)?;
        }

        Ok(())
    }

    pub(crate) fn request_sptps_key_after_bad_tcp_packet_like_tinc(
        &mut self,
        source: &str,
    ) -> Result<(), TincdError> {
        if !self.sptps_req_key_due(source) {
            return Ok(());
        }

        let Some(next_hop) = self
            .state
            .graph
            .node(source)
            .and_then(|node| node.route.next_hop.clone())
        else {
            return Ok(());
        };

        self.restart_pending_sptps_key_exchange(source);
        let messages = self.start_sptps_key_exchange(source)?;
        for message in messages {
            self.send_active_meta_message_to_peer(&next_hop, &message)?;
        }

        Ok(())
    }

    pub(crate) fn try_udp_for_peer(&mut self, peer: &str) -> Result<(), TincdError> {
        if !self.udp_discovery {
            return Ok(());
        }

        let now = Instant::now();
        self.expire_udp_probe_timeout(peer, now);

        let Some(node) = self.state.graph.node(peer) else {
            return Ok(());
        };
        let reachable = node.status.reachable;
        let udp_confirmed = node.status.udp_confirmed;
        let options = node.options;
        let valid_legacy_key = node.status.valid_key;
        let has_previous_edge = node.route.previous_edge.is_some();
        let tcp_only = self.local_tcp_only || node.options & OPTION_TCPONLY != 0;
        if !reachable || tcp_only {
            return Ok(());
        }
        if self.packet_codec.peer(peer).is_none()
            && !(valid_legacy_key && self.legacy_codec.peer(peer).is_some())
        {
            return Ok(());
        }

        if option_version(options) >= 3 && udp_confirmed {
            self.send_gratuitous_udp_probe_reply_if_due(peer, options, now)?;
        }

        let interval = if udp_confirmed {
            self.udp_discovery_keepalive_interval
        } else {
            self.udp_discovery_interval
        };
        if !self.udp_probe_request_due(peer, interval, now) {
            return Ok(());
        }

        {
            let state = self.udp_probe.entry(peer.to_owned()).or_default();
            state.udp_ping_sent = Some(now);
        }
        if let Some(node) = self.state.graph.node_mut(peer) {
            node.status.ping_sent = true;
        }
        self.send_udp_probe_packet(peer, UDP_PROBE_MIN_SIZE, false)?;

        if self.local_discovery && !udp_confirmed && has_previous_edge {
            if let Some(node) = self.state.graph.node_mut(peer) {
                node.status.send_locally = true;
            }
            let result = self.send_udp_probe_packet(peer, UDP_PROBE_MIN_SIZE, true);
            if let Some(node) = self.state.graph.node_mut(peer) {
                node.status.send_locally = false;
            }
            result?;
        }

        Ok(())
    }

    pub(crate) fn try_tx_after_packet_send_like_tinc(
        &mut self,
        owner: &str,
        target: &str,
        mtu: bool,
        forced_tcp: bool,
    ) -> Result<(), TincdError> {
        let Some(node) = self.state.graph.node(owner) else {
            return Ok(());
        };
        if !node.status.reachable {
            return Ok(());
        }

        if node.status.sptps {
            self.try_tx_sptps_like_tinc(owner, mtu)
        } else {
            let target_tcp_only = self
                .state
                .graph
                .node(target)
                .is_some_and(|node| node.options & OPTION_TCPONLY != 0);
            if forced_tcp || self.local_tcp_only || target_tcp_only {
                return Ok(());
            }
            self.try_tx_like_tinc(target, mtu)
        }
    }

    pub(crate) fn try_tx_like_tinc(&mut self, peer: &str, mtu: bool) -> Result<(), TincdError> {
        let Some(node) = self.state.graph.node(peer) else {
            return Ok(());
        };
        if !node.status.reachable {
            return Ok(());
        }

        if node.status.sptps {
            self.try_tx_sptps_like_tinc(peer, mtu)
        } else {
            self.try_tx_legacy_like_tinc(peer, mtu)
        }
    }

    pub(crate) fn try_tx_sptps_like_tinc(
        &mut self,
        peer: &str,
        mtu: bool,
    ) -> Result<(), TincdError> {
        let Some(node) = self.state.graph.node(peer) else {
            return Ok(());
        };
        if !node.status.reachable {
            return Ok(());
        }

        let options = node.options;
        let has_direct_connection = self.has_authenticated_meta_connection_with_name(peer);
        if has_direct_connection && (self.local_tcp_only || options & OPTION_TCPONLY != 0) {
            return Ok(());
        }

        if self.packet_codec.peer(peer).is_none() {
            if self.sptps_req_key_due(peer) {
                self.restart_pending_sptps_key_exchange(peer);
                let messages = self.start_sptps_key_exchange(peer)?;
                let next_hop = self
                    .state
                    .graph
                    .node(peer)
                    .and_then(|node| node.route.next_hop.clone());
                if let Some(next_hop) = next_hop {
                    for message in messages {
                        self.send_active_meta_message_to_peer(&next_hop, &message)?;
                    }
                }
            }
        }

        let Some(node) = self.state.graph.node(peer) else {
            return Ok(());
        };
        let via = if node.route.via.as_deref() == Some(self.local_name.as_str()) {
            node.route.next_hop.clone()
        } else {
            node.route.via.clone()
        };

        if via.as_deref().is_some_and(|via| via != peer) {
            if let Some(via) = via {
                if self
                    .state
                    .graph
                    .node(&via)
                    .is_some_and(|via_node| option_version(via_node.options) >= 4)
                {
                    self.try_tx_like_tinc(&via, mtu)?;
                }
            }
            return Ok(());
        }

        self.try_udp_for_peer(peer)?;
        if mtu {
            self.try_mtu_for_peer(peer)?;
        }

        let Some(node) = self.state.graph.node(peer) else {
            return Ok(());
        };
        let next_hop = node.route.next_hop.clone();
        let udp_confirmed = node.status.udp_confirmed;
        if !udp_confirmed && next_hop.as_deref().is_some_and(|hop| hop != peer) {
            if let Some(next_hop) = next_hop {
                if self
                    .state
                    .graph
                    .node(&next_hop)
                    .is_some_and(|hop| option_version(hop.options) >= 4)
                {
                    self.try_tx_like_tinc(&next_hop, mtu)?;
                }
            }
        }

        Ok(())
    }

    pub(crate) fn try_tx_legacy_like_tinc(
        &mut self,
        peer: &str,
        mtu: bool,
    ) -> Result<(), TincdError> {
        let Some((reachable, sptps, valid_key, valid_key_in, next_hop)) =
            self.state.graph.node(peer).map(|node| {
                (
                    node.status.reachable,
                    node.status.sptps,
                    node.status.valid_key,
                    node.status.valid_key_in,
                    node.route.next_hop.clone(),
                )
            })
        else {
            return Ok(());
        };
        if !reachable || sptps {
            return Ok(());
        }
        if !valid_key_in && let Some(next_hop) = next_hop.as_deref() {
            let message = self.generate_legacy_answer_key_message(peer)?;
            self.send_active_meta_message_to_peer(next_hop, &message)?;
        }

        if !valid_key && self.legacy_req_key_due(peer) {
            if let Some(next_hop) = next_hop.as_deref() {
                self.legacy_last_req_key
                    .insert(peer.to_owned(), Instant::now());
                let message =
                    MetaMessage::RequestKey(RequestKeyMessage::new(&self.local_name, peer));
                self.send_active_meta_message_to_peer(next_hop, &message)?;
            }
        }

        if !valid_key {
            return Ok(());
        }

        self.try_udp_for_peer(peer)?;
        if mtu {
            self.try_mtu_for_peer(peer)?;
        }

        Ok(())
    }

    pub(crate) fn try_mtu_for_peer(&mut self, peer: &str) -> Result<(), TincdError> {
        let now = Instant::now();
        let Some(node) = self.state.graph.node(peer) else {
            return Ok(());
        };
        if self.packet_codec.peer(peer).is_none()
            && !(node.status.valid_key && self.legacy_codec.peer(peer).is_some())
        {
            return Ok(());
        }
        if node.options & OPTION_PMTU_DISCOVERY == 0 {
            return Ok(());
        }

        if self.udp_discovery && !node.status.udp_confirmed {
            if let Some(state) = self.udp_probe.get_mut(peer) {
                state.max_recent_len = 0;
            }
            if let Some(node) = self.state.graph.node_mut(peer) {
                node.mtu_probes = 0;
                node.min_mtu = 0;
                node.max_mtu = DEFAULT_MTU;
            }
            return Ok(());
        }

        if !self.mtu_probe_due(peer, node.mtu_probes, now) {
            return Ok(());
        }

        self.udp_probe
            .entry(peer.to_owned())
            .or_default()
            .mtu_ping_sent = Some(now);
        self.try_fix_mtu(peer);

        if self
            .state
            .graph
            .node(peer)
            .is_some_and(|node| node.mtu_probes < -3)
        {
            if let Some(node) = self.state.graph.node_mut(peer) {
                node.mtu_probes = 0;
                node.min_mtu = 0;
            }
        }

        let Some((mtu_probes, max_mtu)) = self
            .state
            .graph
            .node(peer)
            .map(|node| (node.mtu_probes, node.max_mtu))
        else {
            return Ok(());
        };
        if mtu_probes < 0 {
            self.send_udp_probe_packet(peer, max_mtu, false)?;
            if mtu_probes == -1 && max_mtu + 1 < DEFAULT_MTU {
                self.send_udp_probe_packet(peer, max_mtu + 1, false)?;
            }
            if let Some(node) = self.state.graph.node_mut(peer) {
                node.mtu_probes -= 1;
            }
            return Ok(());
        }

        if mtu_probes == 0 {
            let max_mtu = self.choose_initial_max_mtu(peer);
            if let Some(node) = self.state.graph.node_mut(peer) {
                node.max_mtu = max_mtu;
            }
        }

        loop {
            let Some((probe_len, previous_max_mtu)) = self.next_initial_mtu_probe(peer) else {
                break;
            };
            self.send_udp_probe_packet(peer, probe_len, false)?;

            let Some(node) = self.state.graph.node(peer) else {
                break;
            };
            if node.mtu_probes < 0 || node.max_mtu == previous_max_mtu {
                break;
            }
        }

        if let Some(node) = self.state.graph.node_mut(peer)
            && node.mtu_probes >= 0
        {
            node.mtu_probes += 1;
        }

        Ok(())
    }

    pub(crate) fn mtu_probe_due(&self, peer: &str, mtu_probes: i32, now: Instant) -> bool {
        let elapsed = self
            .udp_probe
            .get(peer)
            .and_then(|state| state.mtu_ping_sent)
            .map(|sent| now.saturating_duration_since(sent));

        if mtu_probes >= 0 {
            return mtu_probes == 0
                || elapsed.is_none_or(|elapsed| elapsed >= PMTU_INITIAL_PROBE_INTERVAL);
        }

        if mtu_probes < -1 {
            elapsed.is_none_or(|elapsed| elapsed >= PMTU_NEGATIVE_PROBE_INTERVAL)
        } else {
            elapsed.is_none_or(|elapsed| elapsed >= self.ping_interval)
        }
    }

    pub(crate) fn try_fix_mtu(&mut self, peer: &str) {
        let Some(node) = self.state.graph.node_mut(peer) else {
            return;
        };
        if node.mtu_probes < 0 {
            return;
        }

        if node.mtu_probes == PMTU_INITIAL_PROBES || node.min_mtu >= node.max_mtu {
            if node.min_mtu > node.max_mtu {
                node.min_mtu = node.max_mtu;
            } else {
                node.max_mtu = node.min_mtu;
            }
            node.mtu = node.min_mtu;
            node.mtu_probes = -1;
        }
    }

    pub(crate) fn reduce_mtu(&mut self, peer: &str, mtu: usize) {
        let mtu = mtu.max(MIN_MTU);
        let Some(node) = self.state.graph.node_mut(peer) else {
            return;
        };
        if node.max_mtu > mtu {
            node.max_mtu = mtu;
        }
        if node.mtu > mtu {
            node.mtu = mtu;
        }
        self.try_fix_mtu(peer);
    }

    pub(crate) fn apply_mtu_reductions(&mut self, reductions: Vec<(String, usize)>) {
        for (peer, mtu) in reductions {
            self.reduce_mtu(&peer, mtu);
        }
    }

    pub(crate) fn next_initial_mtu_probe(&self, peer: &str) -> Option<(usize, usize)> {
        let node = self.state.graph.node(peer)?;
        Some((
            pmtu_initial_probe_len(node.min_mtu, node.max_mtu, node.mtu_probes),
            node.max_mtu,
        ))
    }

    pub(crate) fn choose_initial_max_mtu(&mut self, peer: &str) -> usize {
        let Some(target) = self.udp_probe_target(peer) else {
            return DEFAULT_MTU;
        };
        let Some(interface_mtu) = system_udp_path_mtu(target) else {
            return DEFAULT_MTU;
        };
        if interface_mtu < MIN_MTU {
            return DEFAULT_MTU;
        }

        let mut mtu = interface_mtu;
        mtu = mtu.saturating_sub(if target.is_ipv6() { 40 } else { 20 });
        mtu = mtu.saturating_sub(8);

        if self.packet_codec.peer(peer).is_some() {
            mtu = mtu.saturating_sub(SPTPS_DATAGRAM_OVERHEAD);
            if self
                .state
                .graph
                .node(peer)
                .is_some_and(|node| option_version(node.options) >= 4)
            {
                mtu = mtu.saturating_sub(RELAY_HEADER_LEN);
            }
        } else if let Some(peer_state) = self.legacy_codec.peer(peer) {
            mtu = mtu.saturating_sub(peer_state.outgoing.digest.length());
            let block_size = match peer_state.outgoing.cipher.algorithm() {
                LegacyCipherAlgorithm::None => 1,
                LegacyCipherAlgorithm::Aes128Cbc
                | LegacyCipherAlgorithm::Aes192Cbc
                | LegacyCipherAlgorithm::Aes256Cbc => 16,
                LegacyCipherAlgorithm::Unsupported(_) => 1,
            };
            if block_size > 1 {
                mtu = (mtu / block_size) * block_size;
                mtu = mtu.saturating_sub(1);
            }
            mtu = mtu.saturating_sub(LEGACY_SEQNO_LEN);
        }

        mtu.min(DEFAULT_MTU)
    }

    pub(crate) fn expire_udp_probe_timeout(&mut self, peer: &str, now: Instant) {
        let expired = self
            .udp_probe
            .get(peer)
            .and_then(|state| state.udp_ping_timeout)
            .is_some_and(|timeout| now >= timeout);
        if !expired {
            return;
        }

        if let Some(state) = self.udp_probe.get_mut(peer) {
            state.udp_ping_timeout = None;
            state.udp_ping_rtt = None;
            state.max_recent_len = 0;
        }

        let Some(node) = self.state.graph.node_mut(peer) else {
            return;
        };
        if !node.status.udp_confirmed {
            return;
        }

        node.status.udp_confirmed = false;
        node.mtu_probes = 0;
        node.min_mtu = 0;
        node.max_mtu = DEFAULT_MTU;
    }

    pub(crate) fn send_gratuitous_udp_probe_reply_if_due(
        &mut self,
        peer: &str,
        options: u32,
        now: Instant,
    ) -> Result<(), TincdError> {
        let interval = self
            .udp_discovery_keepalive_interval
            .saturating_sub(Duration::from_secs(1));
        let due = match self
            .udp_probe
            .get(peer)
            .and_then(|state| state.udp_reply_sent)
        {
            Some(sent) => now.saturating_duration_since(sent) >= interval,
            None => true,
        };
        if !due {
            return Ok(());
        }

        let max_recent_len = {
            let state = self.udp_probe.entry(peer.to_owned()).or_default();
            state.udp_reply_sent = Some(now);
            let max_recent_len = state.max_recent_len;
            state.max_recent_len = 0;
            max_recent_len
        };
        if max_recent_len == 0 {
            return Ok(());
        }

        let request = udp_probe_request_payload(max_recent_len);
        let Some(reply) = udp_probe_reply_payload(&request, options) else {
            return Ok(());
        };
        self.send_udp_probe_payload(peer, &reply, false)?;
        Ok(())
    }

    pub(crate) fn udp_probe_request_due(
        &self,
        peer: &str,
        interval: Duration,
        now: Instant,
    ) -> bool {
        match self
            .udp_probe
            .get(peer)
            .and_then(|state| state.udp_ping_sent)
        {
            Some(sent) => now.saturating_duration_since(sent) >= interval,
            None => true,
        }
    }

    pub(crate) fn send_udp_probe_packet(
        &mut self,
        peer: &str,
        len: usize,
        send_locally: bool,
    ) -> Result<bool, TincdError> {
        let payload = udp_probe_request_payload(len);
        self.send_udp_probe_payload(peer, &payload, send_locally)
    }

    pub(crate) fn send_udp_probe_payload(
        &mut self,
        peer: &str,
        payload: &[u8],
        send_locally: bool,
    ) -> Result<bool, TincdError> {
        let target = if send_locally {
            self.local_udp_probe_target(peer)
        } else {
            self.udp_probe_target(peer)
        };
        let Some(target) = target else {
            return Ok(false);
        };
        let Some(socket_index) = self.listen_socket_index_for_peer(peer, target) else {
            return Ok(false);
        };
        let Some(datagram) = self.encode_udp_probe_payload(peer, payload)? else {
            return Ok(false);
        };

        let sent = match self.listen_sockets[socket_index]
            .udp
            .send_to(&datagram, target)
        {
            Ok(sent) => sent,
            Err(error) => {
                if error.raw_os_error() == Some(libc::EMSGSIZE) {
                    self.reduce_mtu(peer, payload.len().saturating_sub(1));
                }
                return Ok(false);
            }
        };
        if sent != datagram.len() {
            return Err(TincdError::ListenIo(format!(
                "short UDP probe send: {sent} < {}",
                datagram.len()
            )));
        }

        Ok(true)
    }

    pub(crate) fn encode_udp_probe_payload(
        &mut self,
        peer: &str,
        payload: &[u8],
    ) -> Result<Option<Vec<u8>>, TincdError> {
        if self.packet_codec.peer(peer).is_some() {
            let datagram = self
                .packet_codec
                .encode_direct_record(peer, SPTPS_UDP_PROBE_TYPE, payload)
                .map_err(|error| TincdError::RuntimeState(error.to_string()))?;
            return Ok(Some(datagram));
        }
        if self.legacy_codec.peer(peer).is_some() {
            let packet = VpnPacket::new(payload.to_vec())
                .map_err(|error| TincdError::RuntimeState(error.to_string()))?;
            let datagram = self
                .legacy_codec
                .encode(peer, &packet)
                .map_err(|error| TincdError::RuntimeState(error.to_string()))?;
            return Ok(Some(datagram));
        }

        Ok(None)
    }

    pub(crate) fn send_sptps_udp_probe_payload_like_tinc(
        &mut self,
        peer: &str,
        payload: &[u8],
    ) -> Result<(), TincdError> {
        if self.packet_codec.peer(peer).is_none() {
            return Ok(());
        }

        let Some(node) = self.state.graph.node(peer) else {
            return Ok(());
        };
        if !node.status.reachable {
            return Ok(());
        }

        let relay = node
            .route
            .via
            .as_deref()
            .filter(|via| *via != self.local_name)
            .filter(|via| {
                self.state
                    .graph
                    .node(via)
                    .is_some_and(|via_node| option_version(via_node.options) >= 4)
            })
            .or(node.route.next_hop.as_deref())
            .unwrap_or(peer)
            .to_owned();
        if self.local_tcp_only
            || self
                .state
                .graph
                .node(&relay)
                .is_some_and(|relay_node| relay_node.options & OPTION_TCPONLY != 0)
        {
            return Ok(());
        }

        let Some(target) = self.udp_probe_target(&relay) else {
            return Ok(());
        };
        let Some(socket_index) = self.listen_socket_index_for_peer(&relay, target) else {
            return Ok(());
        };
        let datagram = if relay == peer {
            self.packet_codec
                .encode_direct_record(peer, SPTPS_UDP_PROBE_TYPE, payload)
        } else {
            self.packet_codec
                .encode_relayed_record(peer, SPTPS_UDP_PROBE_TYPE, payload)
        }
        .map_err(|error| TincdError::RuntimeState(error.to_string()))?;

        let sent = match self.listen_sockets[socket_index]
            .udp
            .send_to(&datagram, target)
        {
            Ok(sent) => sent,
            Err(error) => {
                if error.raw_os_error() == Some(libc::EMSGSIZE) {
                    self.reduce_mtu(&relay, payload.len().saturating_sub(1));
                }
                return Ok(());
            }
        };
        if sent != datagram.len() {
            return Err(TincdError::ListenIo(format!(
                "short UDP SPTPS probe send: {sent} < {}",
                datagram.len()
            )));
        }

        Ok(())
    }

    pub(crate) fn udp_probe_target(&mut self, peer: &str) -> Option<SocketAddr> {
        let snapshot = RuntimeUdpTargetSnapshot::from_state(&self.state, &self.addresses, peer);
        choose_udp_target_from_snapshot(&snapshot, &mut self.udp_unconfirmed_guess_counter)
    }

    pub(crate) fn udp_target_snapshot(&self) -> BTreeMap<String, RuntimeUdpTargetSnapshot> {
        self.state
            .graph
            .nodes()
            .filter(|node| node.name != self.local_name)
            .map(|node| {
                (
                    node.name.clone(),
                    RuntimeUdpTargetSnapshot::from_state(&self.state, &self.addresses, &node.name),
                )
            })
            .collect()
    }

    pub(crate) fn local_udp_probe_target(&self, peer: &str) -> Option<SocketAddr> {
        RuntimeUdpTargetSnapshot::from_state(&self.state, &self.addresses, peer)
            .choose_local_target()
    }

    pub(crate) fn udp_source_node(&self, peer: SocketAddr) -> Option<String> {
        self.addresses.node(&peer).map(str::to_owned).or_else(|| {
            self.state
                .graph
                .nodes()
                .filter(|node| node.name != self.local_name)
                .find(|node| {
                    node.udp_address
                        .as_ref()
                        .and_then(edge_endpoint_socket_addr)
                        == Some(peer)
                })
                .map(|node| node.name.clone())
        })
    }

    pub(crate) fn legacy_udp_try_harder(
        &mut self,
        from: SocketAddr,
        datagram: &[u8],
    ) -> Option<String> {
        self.legacy_udp_try_harder_at(from, datagram, current_unix_secs())
    }

    pub(crate) fn legacy_udp_try_harder_at(
        &mut self,
        from: SocketAddr,
        datagram: &[u8],
        now_secs: i64,
    ) -> Option<String> {
        let mut hard_attempted = false;

        for node in self.state.graph.nodes() {
            if node.name == self.local_name || !node.status.reachable {
                continue;
            }

            if self.legacy_codec.peer(&node.name).is_none() {
                continue;
            }

            let soft = self.state.graph.edges().any(|edge| {
                edge.to == node.name
                    && edge.address.as_ref().and_then(edge_endpoint_socket_addr) == Some(from)
            });

            if !soft {
                if self.legacy_last_hard_try_secs == now_secs {
                    continue;
                }
                hard_attempted = true;
            }

            if !self
                .legacy_codec
                .verifies_incoming_source_for(&node.name, datagram)
            {
                continue;
            }

            if hard_attempted {
                self.legacy_last_hard_try_secs = now_secs;
            }
            return Some(node.name.clone());
        }

        if hard_attempted {
            self.legacy_last_hard_try_secs = now_secs;
        }

        None
    }

    pub(crate) fn listen_socket_index_for_peer(
        &self,
        peer: &str,
        target: SocketAddr,
    ) -> Option<usize> {
        self.udp_socket_by_peer
            .get(peer)
            .copied()
            .filter(|index| self.listen_sockets.get(*index).is_some())
            .or_else(|| listen_socket_index_for(&self.listen_sockets, target))
    }

    pub(crate) fn handle_udp_probe_payload(
        &mut self,
        source: &str,
        peer: SocketAddr,
        socket_index: usize,
        payload: &[u8],
        secure_udp: bool,
        direct: bool,
    ) -> Result<(), TincdError> {
        if payload.is_empty() || !secure_udp {
            return Ok(());
        }

        if payload[0] == 0 {
            if direct {
                self.send_udp_probe_reply(source, peer, socket_index, payload)?;
            } else {
                self.send_sptps_udp_probe_reply_like_tinc(source, payload)?;
            }
        } else {
            self.apply_udp_probe_reply(source, payload);
        }

        Ok(())
    }

    pub(crate) fn send_sptps_udp_probe_reply_like_tinc(
        &mut self,
        source: &str,
        request: &[u8],
    ) -> Result<(), TincdError> {
        let Some(options) = self.state.graph.node(source).map(|node| node.options) else {
            return Ok(());
        };
        let Some(reply) = udp_probe_reply_payload(request, options) else {
            return Ok(());
        };
        self.send_sptps_udp_probe_payload_like_tinc(source, &reply)
    }

    pub(crate) fn send_udp_probe_reply(
        &mut self,
        source: &str,
        peer: SocketAddr,
        socket_index: usize,
        request: &[u8],
    ) -> Result<(), TincdError> {
        let Some(socket) = self.listen_sockets.get(socket_index) else {
            return Ok(());
        };
        let options = self.state.graph.node(source).map_or(0, |node| node.options);
        let Some(reply) = udp_probe_reply_payload(request, options) else {
            return Ok(());
        };

        let datagram = if self.packet_codec.peer(source).is_some() {
            self.packet_codec
                .encode_direct_record(source, SPTPS_UDP_PROBE_TYPE, &reply)
                .map_err(|error| TincdError::RuntimeState(error.to_string()))?
        } else if self.legacy_codec.peer(source).is_some() {
            let packet = VpnPacket::new(reply)
                .map_err(|error| TincdError::RuntimeState(error.to_string()))?;
            self.legacy_codec
                .encode(source, &packet)
                .map_err(|error| TincdError::RuntimeState(error.to_string()))?
        } else {
            return Ok(());
        };

        let sent = match socket.udp.send_to(&datagram, peer) {
            Ok(sent) => sent,
            Err(_) => return Ok(()),
        };
        if sent != datagram.len() {
            return Err(TincdError::ListenIo(format!(
                "short UDP probe reply send: {sent} < {}",
                datagram.len()
            )));
        }

        Ok(())
    }

    pub(crate) fn apply_udp_probe_reply(&mut self, source: &str, payload: &[u8]) {
        let now = Instant::now();
        let ping_sent = self
            .state
            .graph
            .node(source)
            .is_some_and(|node| node.status.ping_sent);
        {
            let state = self.udp_probe.entry(source.to_owned()).or_default();
            if ping_sent {
                state.udp_ping_rtt = state
                    .udp_ping_sent
                    .map(|sent| now.saturating_duration_since(sent));
            }
            if self.udp_discovery {
                state.udp_ping_timeout = Some(now + self.udp_discovery_timeout);
            }
        }

        let was_udp_confirmed = self
            .state
            .graph
            .node(source)
            .is_some_and(|node| node.status.udp_confirmed);
        let Some(node) = self.state.graph.node_mut(source) else {
            return;
        };
        let probe_len = udp_probe_reply_len(payload);
        let confirmed_now = !was_udp_confirmed;

        node.status.ping_sent = false;
        node.status.udp_confirmed = true;

        if probe_len > node.max_mtu {
            node.min_mtu = probe_len;
            node.max_mtu = DEFAULT_MTU;
            node.mtu_probes = 1;
            let _ = node;
            if confirmed_now {
                self.reset_address_cache_to_local_edge_address_like_tinc(source);
            }
            return;
        }

        if node.mtu_probes < 0 && probe_len == node.max_mtu {
            node.mtu_probes = -1;
            if let Some(state) = self.udp_probe.get_mut(source) {
                state.mtu_ping_sent = Some(now);
            }
        }
        if node.min_mtu < probe_len {
            node.min_mtu = probe_len;
        }
        let _ = node;
        if confirmed_now {
            self.reset_address_cache_to_local_edge_address_like_tinc(source);
        }
        self.try_fix_mtu(source);
    }

    #[cfg(test)]
    pub(crate) fn read_meta_connections(&mut self) -> Result<(), TincdError> {
        if self.topology_backoff.active(Instant::now()) {
            return Ok(());
        }

        let ids = self
            .meta_connections
            .iter()
            .map(|connection| connection.id)
            .collect::<Vec<_>>();

        for id in ids {
            while matches!(
                self.read_meta_connection_once_by_id(id)?,
                RuntimeIoProgress::Processed
            ) {}
        }

        Ok(())
    }

    pub(crate) fn read_meta_connection_once_by_id(
        &mut self,
        id: u64,
    ) -> Result<RuntimeIoProgress, TincdError> {
        if self.topology_backoff.active(Instant::now()) {
            return Ok(RuntimeIoProgress::NotReady);
        }

        let Some(index) = self.connection_index_by_id(id) else {
            return Ok(RuntimeIoProgress::NotReady);
        };
        self.read_meta_connection_once(index)
    }

    pub(crate) fn read_meta_connection_once(
        &mut self,
        index: usize,
    ) -> Result<RuntimeIoProgress, TincdError> {
        if index >= self.meta_connections.len() {
            return Ok(RuntimeIoProgress::NotReady);
        }
        let connection_id = self.meta_connections[index].id;
        let mut buffer = vec![0u8; MAX_META_BUFFER_SIZE];

        let len = match self.meta_connections[index].stream.read(&mut buffer) {
            Ok(0) => {
                self.close_meta_connection_for_reason(index, "meta-read-eof")?;
                return Ok(RuntimeIoProgress::Processed);
            }
            Ok(len) => len,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if self
                    .connection_index_by_id(connection_id)
                    .is_some_and(|index| {
                        self.meta_connections[index].close_requested
                            && !self.meta_connections[index].has_pending_output()
                    })
                    && let Some(index) = self.connection_index_by_id(connection_id)
                {
                    self.close_meta_connection_for_reason(index, "close-requested-after-drain")?;
                    return Ok(RuntimeIoProgress::Processed);
                }
                return Ok(RuntimeIoProgress::NotReady);
            }
            Err(error) => {
                self.close_meta_connection_with_detail(index, "meta-read-error", error)?;
                return Ok(RuntimeIoProgress::Processed);
            }
        };

        let Some(index) = self.connection_index_by_id(connection_id) else {
            return Ok(RuntimeIoProgress::Processed);
        };
        self.meta_connections[index].bytes_read += len as u64;
        self.meta_connections[index].last_activity = Instant::now();
        if let Err(error) = self.handle_meta_bytes(index, &buffer[..len]) {
            if is_meta_connection_scoped_error(&error) {
                if let Some(index) = self.connection_index_by_id(connection_id) {
                    self.close_meta_connection_with_detail(index, "meta-protocol-error", error)?;
                }
                return Ok(RuntimeIoProgress::Processed);
            }
            return Err(error);
        }

        if let Some(index) = self.connection_index_by_id(connection_id)
            && self.meta_connections[index].close_requested
            && !self.meta_connections[index].has_pending_output()
        {
            self.close_meta_connection_for_reason(index, "close-requested-after-read")?;
        }

        Ok(RuntimeIoProgress::Processed)
    }

    #[cfg(test)]
    pub(crate) fn send_meta_keepalives(&mut self) -> Result<(), TincdError> {
        self.send_meta_keepalives_at(Instant::now())
    }

    pub(crate) fn send_meta_keepalives_at(&mut self, now: Instant) -> Result<(), TincdError> {
        let mut index = 0;

        while index < self.meta_connections.len() {
            let mut close = false;

            if self.meta_connections[index].edge_peer.is_none() {
                let ping_elapsed =
                    now.saturating_duration_since(self.meta_connections[index].last_ping_time);
                close = ping_elapsed >= self.ping_timeout;
            } else {
                let connection_id = self.meta_connections[index].id;
                let ping_elapsed =
                    now.saturating_duration_since(self.meta_connections[index].last_ping_time);

                if ping_elapsed >= self.ping_timeout {
                    if let Some(peer) = self.meta_connections[index]
                        .active_name()
                        .map(str::to_owned)
                    {
                        self.try_tx_like_tinc(&peer, false)?;
                    }

                    let Some(current_index) = self.connection_index_by_id(connection_id) else {
                        continue;
                    };
                    index = current_index;

                    match self.meta_connections[index].last_ping_sent {
                        Some(_) => close = true,
                        None if ping_elapsed >= self.ping_interval => {
                            match self.send_active_meta_message(index, &MetaMessage::Ping) {
                                Ok(chunk) => match self.write_meta_chunk(index, &chunk) {
                                    Ok(()) => {
                                        if let Some(connection) =
                                            self.meta_connections.get_mut(index)
                                        {
                                            connection.last_ping_time = now;
                                            connection.last_ping_sent = Some(now);
                                        } else {
                                            close = true;
                                        }
                                    }
                                    Err(_) => close = true,
                                },
                                Err(_) => close = true,
                            }
                        }
                        None => {}
                    }
                }
            }

            if close {
                self.close_meta_connection_for_reason(index, "meta-keepalive-timeout")?;
            } else {
                index += 1;
            }
        }

        Ok(())
    }

    pub(crate) fn expire_symmetric_keys(&mut self) -> Result<(), TincdError> {
        let now = Instant::now();
        let Some(next_key_expire) = self.next_key_expire else {
            return Ok(());
        };
        if now < next_key_expire {
            return Ok(());
        }

        self.next_key_expire = if self.key_lifetime_secs < 0 {
            None
        } else {
            schedule_next_key_expire(now, self.key_lifetime_secs)
        };
        self.regenerate_symmetric_keys()
    }

    pub(crate) fn expire_dynamic_mac_subnets(&mut self) -> Result<(), TincdError> {
        let now = Instant::now();
        if now < self.next_mac_subnet_age {
            return Ok(());
        }

        self.next_mac_subnet_age = now + tinc_timer_jitter_duration(TINC_AGING_INTERVAL);
        self.expire_dynamic_mac_subnets_at(current_unix_secs())
    }

    pub(crate) fn expire_dynamic_mac_subnets_at(
        &mut self,
        now_secs: i64,
    ) -> Result<(), TincdError> {
        let removed = self
            .state
            .subnets
            .remove_expired_owner_subnets(&self.local_name, now_secs);

        for mut subnet in removed {
            self.run_subnet_script_for_subnet("subnet-down", &subnet);
            subnet.owner = None;
            let message = MetaMessage::DeleteSubnet(SubnetMessage {
                nonce: self.next_nonce(),
                owner: self.local_name.clone(),
                subnet,
            });
            self.broadcast_active_meta_message_except(None, &message)?;
        }

        Ok(())
    }

    pub(crate) fn regenerate_symmetric_keys(&mut self) -> Result<(), TincdError> {
        self.record_log_with_priority(1, LOG_NOTICE, "Expiring symmetric keys");
        let message = MetaMessage::KeyChanged(KeyChangedMessage {
            nonce: self.next_nonce(),
            origin: self.local_name.clone(),
        });
        self.broadcast_active_meta_message_except(None, &message)?;
        self.send_legacy_answer_keys_to_direct_peers()?;
        self.force_sptps_key_exchange_for_established_peers()?;

        let names = self
            .state
            .graph
            .nodes()
            .map(|node| node.name.clone())
            .collect::<Vec<_>>();
        for name in names {
            if let Some(node) = self.state.graph.node_mut(&name) {
                node.status.valid_key_in = false;
            }
        }

        Ok(())
    }

    pub(crate) fn send_legacy_answer_keys_to_direct_peers(&mut self) -> Result<(), TincdError> {
        let targets = self
            .meta_connections
            .iter()
            .filter(|connection| connection.is_active_authenticated())
            .filter_map(|connection| {
                let peer = connection.active_name()?;
                let node = self.state.graph.node(peer)?;
                if node.status.reachable && !node.status.sptps {
                    Some((connection.id, peer.to_owned()))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        for (id, peer) in targets {
            let message = self.generate_legacy_answer_key_message(&peer)?;
            self.send_active_meta_message_to_id(id, &message)?;
        }

        Ok(())
    }

    pub(crate) fn force_sptps_key_exchange_for_established_peers(
        &mut self,
    ) -> Result<(), TincdError> {
        let Some(key_exchange) = self.key_exchange.as_ref() else {
            return Ok(());
        };
        let compression = key_exchange.compression();
        let peers = self
            .packet_codec
            .peer_names()
            .map(str::to_owned)
            .collect::<Vec<_>>();

        for peer in peers {
            let Some(session) = self.packet_codec.peer_mut(&peer) else {
                continue;
            };
            let datagrams = match session.force_key_exchange() {
                Ok(datagrams) => datagrams,
                Err(SptpsError::UnexpectedHandshakeRecord { .. }) => continue,
                Err(SptpsError::MissingHandshakeState(_)) => continue,
                Err(error) => return Err(sptps_key_exchange_error(error.into())),
            };

            for datagram in datagrams {
                let message = MetaMessage::AnswerKey(AnswerKeyMessage::sptps_handshake(
                    &self.local_name,
                    &peer,
                    &datagram,
                    compression,
                ));
                self.send_active_meta_message_to_peer(&peer, &message)?;
            }
        }

        Ok(())
    }

    pub(crate) fn close_meta_connection(&mut self, index: usize) -> Result<(), TincdError> {
        self.close_meta_connection_for_reason(index, "unspecified")
    }

    pub(crate) fn close_meta_connection_for_reason(
        &mut self,
        index: usize,
        reason: &'static str,
    ) -> Result<(), TincdError> {
        self.close_meta_connection_with_report(index, true, reason)
    }

    pub(crate) fn close_meta_connection_with_detail(
        &mut self,
        index: usize,
        reason: &'static str,
        detail: impl fmt::Display,
    ) -> Result<(), TincdError> {
        self.pending_close_reason = Some(format!("{reason}: {detail}"));
        let result = self.close_meta_connection_with_report(index, true, reason);
        if self.pending_close_reason.is_some() {
            self.pending_close_reason = None;
        }
        result
    }

    pub(crate) fn close_meta_connection_by_id_with_detail(
        &mut self,
        id: u64,
        reason: &'static str,
        detail: impl fmt::Display,
    ) -> Result<(), TincdError> {
        if let Some(index) = self.connection_index_by_id(id) {
            self.close_meta_connection_with_detail(index, reason, detail)?;
        }
        Ok(())
    }

    pub(crate) fn close_meta_connection_with_report(
        &mut self,
        index: usize,
        report: bool,
        reason: &'static str,
    ) -> Result<(), TincdError> {
        let connection_id = self.meta_connections[index].id;
        let peer = match &self.meta_connections[index].kind {
            RuntimeMetaConnectionKind::Active {
                name: Some(name), ..
            } => Some(name.clone()),
            _ => None,
        };
        let is_outgoing = self.meta_connections[index].outgoing_peer.is_some();
        let connecting = self.meta_connections[index].connecting;
        let active = self.meta_connections[index].is_active_authenticated();
        let retry_outgoing = is_outgoing
            && self.meta_connections[index]
                .outgoing_peer
                .as_ref()
                .is_some_and(|peer| self.outgoing_retry.contains_key(peer));
        let retry_autoconnect = is_outgoing
            && self.meta_connections[index]
                .outgoing_peer
                .as_ref()
                .is_some_and(|peer| {
                    self.meta_connections[index].outgoing_autoconnect
                        && self.autoconnect_outgoing.contains_key(peer)
                });
        let outgoing_peer = self.meta_connections[index].outgoing_peer.clone();
        let config = self.runtime_config.clone();
        let _exec_proxy = self.meta_connections[index].exec_proxy.take();
        let edge_peer = self.meta_connections[index].edge_peer.take();
        let close_reason = self
            .pending_close_reason
            .take()
            .unwrap_or_else(|| reason.to_owned());
        self.record_log_with_priority(
            DEBUG_CONNECTIONS,
            LOG_DEBUG,
            format!(
                "Closing meta connection id={connection_id} reason={close_reason} peer={} outgoing={is_outgoing} active={active} connecting={connecting} report={report} edge={}",
                peer.as_deref().unwrap_or("<unknown>"),
                edge_peer.as_deref().unwrap_or("<none>")
            ),
        );
        self.meta_connections.remove(index);

        if let Some(peer) = edge_peer.as_deref()
            && self
                .local_edge_connections
                .get(peer)
                .is_none_or(|owner| *owner == connection_id)
        {
            let local_name = self.local_name.clone();
            if self.state.graph.edge(&local_name, peer).is_some() {
                let forward = self.delete_edge_message(&local_name, peer);
                if report && !self.tunnel_server {
                    self.broadcast_active_meta_message_except(None, &forward)?;
                }
                self.apply_runtime_meta_message(forward)?;
                self.local_edge_connections.remove(peer);

                let peer_unreachable = self
                    .state
                    .graph
                    .node(peer)
                    .is_some_and(|node| !node.status.reachable);
                if peer_unreachable && self.state.graph.edge(peer, &local_name).is_some() {
                    let reverse = self.delete_edge_message(peer, &local_name);
                    if report && !self.tunnel_server {
                        self.broadcast_active_meta_message_except(None, &reverse)?;
                    }
                    self.apply_runtime_meta_message(reverse)?;
                }
            }
        }

        if let Some(peer) = outgoing_peer.or(peer)
            && !self.has_meta_connection_with_name(&peer)
        {
            let now = Instant::now();
            if retry_outgoing {
                if self.connect_peer(&config, &peer)? {
                    self.mark_outgoing_connected(&peer, now);
                } else {
                    self.mark_outgoing_failed(&peer, now);
                }
            } else if retry_autoconnect {
                if self.connect_peer(&config, &peer)? {
                    self.mark_autoconnect_connected(&peer, now);
                    self.mark_latest_connection_autoconnect(&peer);
                } else {
                    self.mark_autoconnect_failed(&peer, now);
                }
            }
        }

        Ok(())
    }

    pub(crate) fn close_existing_connection_for_new_ack_like_tinc(
        &mut self,
        new_index: usize,
        peer: &str,
    ) -> Result<(), TincdError> {
        let new_id = self.meta_connections[new_index].id;
        let existing_id = self
            .meta_connections
            .iter()
            .find(|connection| {
                connection.id != new_id && connection.authenticated_name() == Some(peer)
            })
            .map(|connection| connection.id);
        let Some(existing_id) = existing_id else {
            return Ok(());
        };

        if let Some(existing_index) = self.connection_index_by_id(existing_id) {
            let existing_outgoing_peer = self.meta_connections[existing_index].outgoing_peer.take();
            let existing_outgoing = existing_outgoing_peer.is_some();
            let existing_autoconnect = self.meta_connections[existing_index].outgoing_autoconnect;
            if existing_outgoing && let Some(new_index) = self.connection_index_by_id(new_id) {
                self.meta_connections[new_index].outgoing_peer = existing_outgoing_peer;
                self.meta_connections[new_index].outgoing_autoconnect = existing_autoconnect;
            }
            self.close_meta_connection_with_report(existing_index, false, "duplicate-ack")?;
            self.state.recompute_routes();
        }

        Ok(())
    }

    pub(crate) fn connection_index_by_id(&self, id: u64) -> Option<usize> {
        self.meta_connections
            .iter()
            .position(|connection| connection.id == id)
    }

    pub(crate) fn handle_meta_bytes(
        &mut self,
        index: usize,
        bytes: &[u8],
    ) -> Result<(), TincdError> {
        if matches!(
            &self.meta_connections[index].kind,
            RuntimeMetaConnectionKind::PendingIncoming { .. }
        ) {
            return self.handle_pending_incoming_bytes(index, bytes);
        }

        if matches!(
            &self.meta_connections[index].kind,
            RuntimeMetaConnectionKind::Invitation { .. }
        ) {
            return self.handle_invitation_bytes(index, bytes);
        }

        self.handle_active_meta_bytes(index, bytes)
    }

    pub(crate) fn handle_pending_incoming_bytes(
        &mut self,
        index: usize,
        bytes: &[u8],
    ) -> Result<(), TincdError> {
        let Some((id_line, trailing)) = self.pending_incoming_id_line(index, bytes)? else {
            return Ok(());
        };
        let line = String::from_utf8(trim_meta_line(&id_line).to_vec())
            .map_err(|error| TincdError::MetaConnection(error.to_string()))?;
        let message = parse_meta_message(&line)
            .map_err(|error| TincdError::MetaConnection(error.to_string()))?;
        let MetaMessage::Id(id) = message else {
            return Err(TincdError::MetaConnection(format!(
                "expected ID from incoming peer, got {}",
                message.request().name()
            )));
        };

        if let Some(public_key) = id.name.strip_prefix('?') {
            return self.handle_pending_invitation_id(index, public_key, trailing);
        }

        let Some(mut driver) = self.meta_driver_for_incoming_peer(&id.name, id.protocol_minor)?
        else {
            return Err(TincdError::UnknownPeerKey(id.name));
        };
        let response_id = driver.incoming_initial_id_bytes();
        let step = driver.receive_bytes(&id_line)?;

        {
            let connection = &mut self.meta_connections[index];
            connection.status = CONNECTION_STATUS_ACTIVE;
            connection.kind = RuntimeMetaConnectionKind::Active {
                driver,
                name: Some(id.name),
                proxy: ProxyHandshake::None,
            };
        }

        let connection_id = self.meta_connections[index].id;
        if let Some(response_id) = response_id {
            self.write_meta_chunk_to_id(connection_id, &response_id)?;
        }
        self.apply_meta_step(index, step)?;

        if !trailing.is_empty() {
            if let Some(index) = self.connection_index_by_id(connection_id) {
                self.handle_active_meta_bytes(index, &trailing)?;
            }
        }

        Ok(())
    }

    pub(crate) fn handle_pending_invitation_id(
        &mut self,
        index: usize,
        public_key: &str,
        trailing: Vec<u8>,
    ) -> Result<(), TincdError> {
        let context = self.invitation.clone().ok_or_else(|| {
            TincdError::MetaConnection(
                "incoming invitation requested but no invitation key is loaded".to_owned(),
            )
        })?;
        let peer_key = TincEd25519PublicKey::from_base64(public_key)
            .map_err(|error| TincdError::MetaConnection(format!("bad invitation key: {error}")))?;
        let mut session = SptpsHandshakeSession::start_tcp(
            false,
            context.key.clone(),
            peer_key,
            INVITATION_LABEL,
        )
        .map_err(invitation_sptps_error)?;
        let mut chunks = Vec::new();
        chunks.push(
            format!(
                "{} {} {}.{}\n",
                Request::Id.number(),
                self.local_name,
                PROT_MAJOR,
                PROT_MINOR
            )
            .into_bytes(),
        );
        chunks.push(
            format!(
                "{} {}\n",
                Request::Ack.number(),
                context.key.public_key().to_base64()
            )
            .into_bytes(),
        );
        chunks.extend(session.drain_outbound());

        {
            let connection = &mut self.meta_connections[index];
            connection.status = CONNECTION_STATUS_ACTIVE;
            connection.kind = RuntimeMetaConnectionKind::Invitation {
                session,
                decoder: MetaStreamDecoder::new(),
                phase: RuntimeInvitationPhase::AwaitCookie,
            };
        }

        let connection_id = self.meta_connections[index].id;
        for chunk in chunks {
            self.write_meta_chunk_to_id(connection_id, &chunk)?;
        }

        if !trailing.is_empty() {
            if let Some(index) = self.connection_index_by_id(connection_id) {
                self.handle_invitation_bytes(index, &trailing)?;
            }
        }

        Ok(())
    }

    pub(crate) fn handle_invitation_bytes(
        &mut self,
        index: usize,
        bytes: &[u8],
    ) -> Result<(), TincdError> {
        let context = self.invitation.clone().ok_or_else(|| {
            TincdError::MetaConnection("invitation key was unloaded during handshake".to_owned())
        })?;
        let local_name = self.local_name.clone();
        let remote = self.meta_connections[index].peer;
        let mut outbound = Vec::new();
        let mut accepted_peer = None;

        {
            let connection = &mut self.meta_connections[index];
            let RuntimeMetaConnectionKind::Invitation {
                session,
                decoder,
                phase,
            } = &mut connection.kind
            else {
                return Ok(());
            };

            decoder
                .push(bytes)
                .map_err(|error| TincdError::MetaConnection(error.to_string()))?;

            loop {
                let Some(frame) = decoder
                    .next_sptps_frame(session.is_established())
                    .map_err(|error| TincdError::MetaConnection(error.to_string()))?
                else {
                    break;
                };
                let MetaStreamFrame::SptpsRecord(record) = frame else {
                    return Err(TincdError::MetaConnection(
                        "unexpected non-SPTPS frame on invitation connection".to_owned(),
                    ));
                };
                let events = session
                    .receive_datagram(&record)
                    .map_err(invitation_sptps_error)?;
                outbound.extend(session.drain_outbound());

                for event in events {
                    match event {
                        SptpsHandshakeEvent::HandshakeComplete => {}
                        SptpsHandshakeEvent::ApplicationRecord {
                            record_type: 0,
                            payload,
                        } => {
                            if !matches!(phase, RuntimeInvitationPhase::AwaitCookie) {
                                return Err(TincdError::MetaConnection(
                                    "received a second invitation cookie".to_owned(),
                                ));
                            }

                            let invitation =
                                read_runtime_invitation_file(&context, &local_name, &payload)?;
                            for chunk in invitation.data.chunks(1024) {
                                outbound.push(
                                    session
                                        .send_record(0, chunk)
                                        .map_err(invitation_sptps_error)?,
                                );
                            }
                            outbound.push(
                                session
                                    .send_record(1, b"")
                                    .map_err(invitation_sptps_error)?,
                            );
                            *phase = RuntimeInvitationPhase::AwaitPublicKey {
                                name: invitation.name,
                            };
                        }
                        SptpsHandshakeEvent::ApplicationRecord {
                            record_type: 1,
                            payload,
                        } => {
                            let RuntimeInvitationPhase::AwaitPublicKey { name } = phase else {
                                return Err(TincdError::MetaConnection(
                                    "received invited public key before invitation was used"
                                        .to_owned(),
                                ));
                            };
                            let name = name.clone();
                            let key = accept_runtime_invitation_public_key(
                                &context.confbase,
                                &name,
                                &payload,
                            )?;
                            outbound.push(
                                session
                                    .send_record(2, b"")
                                    .map_err(invitation_sptps_error)?,
                            );
                            accepted_peer = Some((name, key));
                            connection.close_requested = true;
                        }
                        SptpsHandshakeEvent::ApplicationRecord { record_type, .. } => {
                            return Err(TincdError::MetaConnection(format!(
                                "unexpected invitation record type {record_type}"
                            )));
                        }
                    }
                }
            }
        }

        let connection_id = self.meta_connections[index].id;
        for chunk in outbound {
            self.write_meta_chunk_to_id(connection_id, &chunk)?;
        }

        if let Some((name, key)) = accepted_peer {
            self.accept_invited_peer(&name, key, remote);
        }

        Ok(())
    }

    pub(crate) fn accept_invited_peer(
        &mut self,
        name: &str,
        key: TincEd25519PublicKey,
        remote: SocketAddr,
    ) {
        self.keys.peer_public_keys.insert(name.to_owned(), key);
        if let Some(key_exchange) = &mut self.key_exchange {
            key_exchange.insert_peer_public_key(name.to_owned(), key);
        }
        self.state.graph.ensure_node(name);
        self.run_event_script(
            "invitation-accepted",
            &[
                ("NODE", name.to_owned()),
                ("REMOTEADDRESS", remote.ip().to_string()),
            ],
        );
    }

    pub(crate) fn accept_legacy_ed25519_upgrade(
        &mut self,
        peer: &str,
        public_key: &str,
    ) -> Result<(), TincdError> {
        let key = TincEd25519PublicKey::from_base64(public_key).map_err(|error| {
            TincdError::MetaConnection(format!("got bad Ed25519 public key from {peer}: {error}"))
        })?;

        if let Some(known_key) = self.keys.peer_public_keys.get(peer).copied() {
            if known_key != key {
                return Err(TincdError::MetaConnection(format!(
                    "already have a different Ed25519 public key for {peer}"
                )));
            }
            return Ok(());
        }

        if let Some(confbase) = self.confbase.clone()
            && let Err(error) =
                append_runtime_host_config(&confbase, peer, "Ed25519PublicKey", public_key)
        {
            self.record_log_with_priority(
                0,
                LOG_ERR,
                format!("Cannot append Ed25519PublicKey to host config for {peer}: {error}"),
            );
        }

        self.keys.peer_public_keys.insert(peer.to_owned(), key);
        if let Some(key_exchange) = &mut self.key_exchange {
            key_exchange.insert_peer_public_key(peer.to_owned(), key);
        }
        self.outgoing_retry
            .entry(peer.to_owned())
            .or_insert_with(|| OutgoingRetryState::ready(Instant::now()))
            .reset(Instant::now());
        Ok(())
    }

    pub(crate) fn has_meta_connection_with_name(&self, peer: &str) -> bool {
        self.meta_connections
            .iter()
            .any(|connection| connection.active_name() == Some(peer))
    }

    pub(crate) fn has_pending_or_authenticated_meta_connection_with_name(
        &self,
        peer: &str,
    ) -> bool {
        self.meta_connections.iter().any(|connection| {
            connection.active_name() == Some(peer)
                || connection.authenticated_name() == Some(peer)
                || connection.outgoing_peer.as_deref() == Some(peer)
        })
    }

    pub(crate) fn has_authenticated_meta_connection_with_name(&self, peer: &str) -> bool {
        self.current_meta_connection_id_for_peer(peer).is_some()
    }

    pub(crate) fn local_options_for_peer(&self, peer: &str) -> u32 {
        runtime_meta_options(
            self.state.experimental,
            self.local_indirect_data,
            self.local_tcp_only,
            self.local_pmtu_discovery,
            self.local_clamp_mss,
            self.peer_meta_configs.get(peer),
        )
    }

    pub(crate) fn local_weight_for_peer(&self, peer: &str) -> i32 {
        self.peer_meta_configs
            .get(peer)
            .and_then(|config| config.weight)
            .unwrap_or(self.local_weight)
    }

    pub(crate) fn meta_driver_for_peer(
        &self,
        peer: &str,
        outgoing: bool,
    ) -> Result<Option<RuntimeMetaDriver>, TincdError> {
        if !self.state.experimental && !self.bypass_security {
            return self.legacy_meta_driver_for_peer(peer, outgoing);
        }

        let Some(private_key) = self.keys.private_key.as_ref() else {
            return Err(TincdError::MetaConnection(
                "missing Ed25519 private key for experimental protocol".to_owned(),
            ));
        };
        let peer_key = match self.keys.peer_public_keys.get(peer).cloned() {
            Some(peer_key) => peer_key,
            None if self.bypass_security => private_key.public_key(),
            None if outgoing => {
                return self.legacy_meta_upgrade_driver_for_peer(
                    peer,
                    outgoing,
                    LEGACY_META_UPGRADE_PROTOCOL_MINOR,
                );
            }
            None => return Ok(None),
        };
        let auth = MetaConnectionAuth::new(
            self.local_name.clone(),
            outgoing,
            private_key.clone(),
            peer_key,
            self.local_port.clone(),
            self.local_weight_for_peer(peer),
            self.local_options_for_peer(peer),
        )
        .with_bypass_security(self.bypass_security);

        Ok(Some(RuntimeMetaDriver::modern(MetaConnectionDriver::new(
            auth,
        ))))
    }

    pub(crate) fn meta_driver_for_incoming_peer(
        &self,
        peer: &str,
        protocol_minor: Option<i32>,
    ) -> Result<Option<RuntimeMetaDriver>, TincdError> {
        let minor = protocol_minor.unwrap_or(0);
        if self.bypass_security || minor >= 2 {
            if !self.bypass_security && !self.state.experimental {
                return self.legacy_meta_driver_for_peer(peer, false);
            }
            return self.meta_driver_for_peer(peer, false);
        }
        if minor < LEGACY_META_UPGRADE_PROTOCOL_MINOR
            && self.keys.peer_public_keys.contains_key(peer)
        {
            return Err(TincdError::MetaConnection(format!(
                "peer {peer} tried to roll back protocol version to {PROT_MAJOR}.{minor}"
            )));
        }
        if minor == LEGACY_META_PROTOCOL_MINOR {
            return self.legacy_meta_driver_for_peer(peer, false);
        }
        self.legacy_meta_upgrade_driver_for_peer(peer, false, PROT_MINOR as i32)
    }

    pub(crate) fn legacy_meta_driver_for_peer(
        &self,
        peer: &str,
        outgoing: bool,
    ) -> Result<Option<RuntimeMetaDriver>, TincdError> {
        self.legacy_meta_driver_for_peer_with_options(
            peer,
            outgoing,
            LEGACY_META_PROTOCOL_MINOR,
            None,
        )
    }

    pub(crate) fn legacy_meta_upgrade_driver_for_peer(
        &self,
        peer: &str,
        outgoing: bool,
        local_protocol_minor: i32,
    ) -> Result<Option<RuntimeMetaDriver>, TincdError> {
        let Some(private_key) = self.keys.private_key.as_ref() else {
            return Err(TincdError::MetaConnection(
                "missing Ed25519 private key for legacy Ed25519 upgrade".to_owned(),
            ));
        };
        self.legacy_meta_driver_for_peer_with_options(
            peer,
            outgoing,
            local_protocol_minor,
            Some(private_key.public_key().to_base64()),
        )
    }

    pub(crate) fn legacy_meta_driver_for_peer_with_options(
        &self,
        peer: &str,
        outgoing: bool,
        local_protocol_minor: i32,
        local_upgrade_public_key: Option<String>,
    ) -> Result<Option<RuntimeMetaDriver>, TincdError> {
        let Some(peer_public_key) = self.keys.peer_rsa_public_keys.get(peer).cloned() else {
            if outgoing {
                return Err(TincdError::UnknownPeerKey(peer.to_owned()));
            }
            return Ok(None);
        };
        let Some(private_key) = self.keys.rsa_private_key.as_ref() else {
            if outgoing {
                return Err(TincdError::MetaConnection(format!(
                    "missing RSA private key for legacy peer {peer}"
                )));
            }
            return Ok(None);
        };
        let mut auth = LegacyMetaAuth::new(
            self.local_name.clone(),
            outgoing,
            private_key.legacy_meta_private_key(),
            peer_public_key,
            self.local_port.clone(),
            self.local_weight_for_peer(peer),
            self.local_options_for_peer(peer),
        )
        .with_protocol_minor(local_protocol_minor);
        if !self.state.experimental {
            auth = auth.with_forced_protocol_minor_zero(true);
        }
        if let Some(public_key) = local_upgrade_public_key {
            auth = auth.with_upgrade_public_key(public_key);
        }
        Ok(Some(RuntimeMetaDriver::legacy(
            LegacyMetaConnectionDriver::new(auth),
        )))
    }

    pub(crate) fn pending_incoming_id_line(
        &mut self,
        index: usize,
        bytes: &[u8],
    ) -> Result<Option<(Vec<u8>, Vec<u8>)>, TincdError> {
        let RuntimeMetaConnectionKind::PendingIncoming { buffer } =
            &mut self.meta_connections[index].kind
        else {
            return Ok(None);
        };

        buffer.extend_from_slice(bytes);
        if buffer.len() > MAX_META_BUFFER_SIZE {
            return Err(TincdError::MetaConnection(format!(
                "meta input buffer full: {} bytes, maximum is {}",
                buffer.len(),
                MAX_META_BUFFER_SIZE
            )));
        }
        let Some(newline) = buffer.iter().position(|byte| *byte == b'\n') else {
            return Ok(None);
        };
        let trailing = buffer.split_off(newline + 1);
        let id_line = std::mem::take(buffer);

        Ok(Some((id_line, trailing)))
    }

    pub(crate) fn handle_active_meta_bytes(
        &mut self,
        index: usize,
        bytes: &[u8],
    ) -> Result<(), TincdError> {
        let bytes = match self.drain_http_proxy_response_like_tinc(index, bytes)? {
            Some(bytes) => bytes,
            None => return Ok(()),
        };
        let step = {
            let RuntimeMetaConnectionKind::Active { driver, .. } =
                &mut self.meta_connections[index].kind
            else {
                return Ok(());
            };

            driver.receive_bytes(&bytes)?
        };

        self.apply_meta_step(index, step)
    }

    pub(crate) fn drain_http_proxy_response_like_tinc(
        &mut self,
        index: usize,
        bytes: &[u8],
    ) -> Result<Option<Vec<u8>>, TincdError> {
        let RuntimeMetaConnectionKind::Active { driver, proxy, .. } =
            &mut self.meta_connections[index].kind
        else {
            return Ok(Some(bytes.to_vec()));
        };
        if driver.is_activated() || !driver.is_outgoing() {
            return Ok(Some(bytes.to_vec()));
        }
        match proxy {
            ProxyHandshake::None => Ok(Some(bytes.to_vec())),
            ProxyHandshake::Http { buffer } => {
                buffer.extend_from_slice(bytes);
                if buffer.len() > MAX_META_BUFFER_SIZE {
                    return Err(TincdError::MetaConnection(format!(
                        "meta input buffer full: {} bytes, maximum is {}",
                        buffer.len(),
                        MAX_META_BUFFER_SIZE
                    )));
                }
                loop {
                    let Some(newline) = buffer.iter().position(|byte| *byte == b'\n') else {
                        return Ok(None);
                    };
                    let trailing = buffer.split_off(newline + 1);
                    let line = std::mem::replace(buffer, trailing);
                    let line = String::from_utf8_lossy(trim_meta_line(&line)).to_string();
                    if line.is_empty() || line == "\r" {
                        let trailing = std::mem::take(buffer);
                        *proxy = ProxyHandshake::None;
                        return Ok(Some(trailing));
                    }
                    if line.to_ascii_lowercase().starts_with("http/1.1 ") {
                        if line.get(9..12) == Some("200") {
                            continue;
                        }
                        return Err(TincdError::MetaConnection(format!(
                            "Proxy request rejected: {}",
                            line.get(9..).unwrap_or("")
                        )));
                    }

                    let trailing = std::mem::take(buffer);
                    *proxy = ProxyHandshake::None;
                    let mut forwarded = line.as_bytes().to_vec();
                    forwarded.push(b'\n');
                    forwarded.extend_from_slice(&trailing);
                    return Ok(Some(forwarded));
                }
            }
            ProxyHandshake::Socks4 { buffer } => {
                buffer.extend_from_slice(bytes);
                if buffer.len() > MAX_META_BUFFER_SIZE {
                    return Err(TincdError::MetaConnection(format!(
                        "meta input buffer full: {} bytes, maximum is {}",
                        buffer.len(),
                        MAX_META_BUFFER_SIZE
                    )));
                }
                let required = SOCKS4_RESPONSE_LEN;
                if buffer.len() < required {
                    return Ok(None);
                }
                let response = buffer[..required].to_vec();
                let trailing = buffer.split_off(required);
                validate_socks4_response_like_tinc(&response)?;
                *proxy = ProxyHandshake::None;
                Ok(Some(trailing))
            }
            ProxyHandshake::Socks5 { buffer } => {
                buffer.extend_from_slice(bytes);
                if buffer.len() > MAX_META_BUFFER_SIZE {
                    return Err(TincdError::MetaConnection(format!(
                        "meta input buffer full: {} bytes, maximum is {}",
                        buffer.len(),
                        MAX_META_BUFFER_SIZE
                    )));
                }
                let required = socks5_response_len(buffer);
                if required == 0 || buffer.len() < required {
                    return Ok(None);
                }
                let response = buffer[..required].to_vec();
                let trailing = buffer.split_off(required);
                validate_socks5_response_like_tinc(&response)?;
                *proxy = ProxyHandshake::None;
                Ok(Some(trailing))
            }
        }
    }

    pub(crate) fn apply_meta_step(
        &mut self,
        index: usize,
        step: tinc_runtime::meta::MetaConnectionStep,
    ) -> Result<(), TincdError> {
        let mut index = index;
        let connection_id = self.meta_connections[index].id;
        let mut responses = Vec::new();
        let mut topology_responses = Vec::new();
        let mut peer_responses = Vec::new();
        let mut topology_broadcasts = Vec::new();
        let mut broadcasts = Vec::new();
        let mut state_syncs = Vec::new();

        for event in step.events {
            match event {
                MetaConnectionEvent::Auth(MetaAuthEvent::Activated {
                    peer,
                    port,
                    weight,
                    options,
                }) => {
                    let connection_id = self.meta_connections[index].id;
                    let connection_peer_address = self.meta_connections[index].peer;
                    let outgoing = self.meta_connections[index].outgoing_peer.is_some();
                    self.close_existing_connection_for_new_ack_like_tinc(index, &peer)?;
                    let Some(updated_index) = self.connection_index_by_id(connection_id) else {
                        continue;
                    };
                    let active_index = updated_index;
                    index = active_index;
                    self.meta_connections[active_index].status = CONNECTION_STATUS_ACTIVE;
                    self.meta_connections[active_index].options = options;
                    if let RuntimeMetaConnectionKind::Active { name, .. } =
                        &mut self.meta_connections[active_index].kind
                    {
                        *name = Some(peer.clone());
                    }
                    self.meta_connections[active_index].edge_peer = Some(peer.clone());
                    self.local_edge_connections
                        .insert(peer.clone(), connection_id);
                    self.record_log_with_priority(
                        DEBUG_CONNECTIONS,
                        LOG_NOTICE,
                        format!("Connection with {peer} activated"),
                    );
                    let existing_state = self.existing_state_messages();
                    let message =
                        self.activated_edge_message(active_index, &peer, &port, weight, options);
                    self.apply_runtime_meta_message(message.clone())?;
                    state_syncs.push((connection_id, existing_state));
                    if self.tunnel_server {
                        topology_responses.push((connection_id, message));
                    } else {
                        topology_broadcasts.push((None, message));
                    }
                    if outgoing {
                        self.add_recent_meta_address_like_tinc(&peer, connection_peer_address);
                    }
                    if !self.bypass_security
                        && self.state.experimental
                        && self.keys.peer_public_keys.contains_key(&peer)
                    {
                        responses.extend(self.start_sptps_key_exchange(&peer)?);
                    }
                }
                MetaConnectionEvent::Auth(MetaAuthEvent::LegacyEd25519Upgrade {
                    peer,
                    public_key,
                }) => {
                    self.accept_legacy_ed25519_upgrade(&peer, &public_key)?;
                    self.meta_connections[index].close_requested = true;
                }
                MetaConnectionEvent::Message(message) => {
                    let should_broadcast = should_broadcast_runtime_message(&message);
                    if should_broadcast && self.mark_seen_runtime_message(&message) {
                        continue;
                    }

                    if self.handle_topology_relay_message(
                        index,
                        &message,
                        &mut responses,
                        &mut broadcasts,
                    ) {
                        continue;
                    }

                    if let MetaMessage::AnswerKey(answer) = &message {
                        if answer.to != self.local_name {
                            self.forward_answer_key_message(answer)?;
                            continue;
                        } else if answer.is_sptps_handshake() {
                            responses.extend(self.handle_sptps_answer_key_message(answer)?);
                            continue;
                        } else {
                            self.handle_legacy_answer_key_message(answer)?;
                            continue;
                        }
                    } else if let MetaMessage::RequestKey(request) = &message {
                        if request.extension.is_none() || !self.state.experimental {
                            if let Some(response) =
                                self.handle_legacy_request_key_message(request)?
                            {
                                peer_responses.push(response);
                            }
                            continue;
                        } else if is_sptps_key_exchange_message(&message) {
                            if request.to == self.local_name {
                                responses.extend(self.handle_sptps_request_key_message(request)?);
                                continue;
                            } else {
                                peer_responses
                                    .extend(self.handle_extended_request_key_message(request)?);
                            }
                        } else {
                            peer_responses
                                .extend(self.handle_extended_request_key_message(request)?);
                            continue;
                        }
                    } else if is_sptps_key_exchange_message(&message) {
                        responses.extend(self.receive_sptps_key_exchange_message(&message)?);
                        continue;
                    } else if let MetaMessage::UdpInfo(message) = &message {
                        self.handle_udp_info_message_like_tinc(message)?;
                        continue;
                    }

                    match &message {
                        MetaMessage::Ping => responses.push(MetaMessage::Pong),
                        MetaMessage::Pong => {
                            if let Some(connection) = self.meta_connections.get_mut(index) {
                                connection.last_ping_sent = None;
                            }
                            self.handle_pong_address_cache_like_tinc(index);
                        }
                        MetaMessage::TerminateRequest => {
                            self.meta_connections[index].close_requested = true;
                        }
                        _ => {}
                    }

                    self.apply_runtime_meta_message(message.clone())?;
                    self.forward_runtime_info_message(&message)?;
                    let stale_reverse_edge = if let MetaMessage::DeleteEdge(message) = &message {
                        self.cleanup_stale_reverse_edge_after_delete_like_tinc(message)?
                    } else {
                        None
                    };
                    if should_broadcast {
                        let tunnel_server_topology = self.tunnel_server
                            && matches!(
                                &message,
                                MetaMessage::AddSubnet(_)
                                    | MetaMessage::DeleteSubnet(_)
                                    | MetaMessage::AddEdge(_)
                                    | MetaMessage::DeleteEdge(_)
                            );
                        let tunnel_server_key_changed =
                            self.tunnel_server && matches!(&message, MetaMessage::KeyChanged(_));
                        if !tunnel_server_topology && !tunnel_server_key_changed {
                            broadcasts.push((Some(connection_id), message));
                        }
                    }
                    if let Some(message) = stale_reverse_edge
                        && !self.tunnel_server
                    {
                        broadcasts.push((None, message));
                    }
                }
                MetaConnectionEvent::TcpPacket(payload) => {
                    self.handle_meta_tcp_packet(index, payload)?;
                }
                MetaConnectionEvent::SptpsPacket(payload) => {
                    self.handle_meta_sptps_packet(index, payload)?;
                }
                _ => {}
            }
        }

        for chunk in step.outbound {
            self.write_meta_chunk_to_id(connection_id, &chunk)?;
        }

        for (id, messages) in state_syncs {
            self.sync_existing_state_messages_to_peer_id(id, messages)?;
        }

        for (id, response) in topology_responses {
            self.send_active_meta_message_to_id(id, &response)?;
        }

        for (source_id, message) in topology_broadcasts {
            self.broadcast_active_meta_message_except_id(source_id, &message)?;
        }

        for response in responses {
            self.send_active_meta_message_to_id(connection_id, &response)?;
        }

        for (peer, response) in peer_responses {
            self.send_active_meta_message_to_peer(&peer, &response)?;
        }

        for (source_id, message) in broadcasts {
            self.broadcast_active_meta_message_except_id(source_id, &message)?;
        }

        Ok(())
    }

    pub(crate) fn cleanup_stale_reverse_edge_after_delete_like_tinc(
        &mut self,
        message: &DeleteEdgeMessage,
    ) -> Result<Option<MetaMessage>, TincdError> {
        let to_unreachable = self
            .state
            .graph
            .node(&message.to)
            .is_some_and(|node| !node.status.reachable);
        if !to_unreachable
            || self
                .state
                .graph
                .edge(&message.to, &self.local_name)
                .is_none()
        {
            return Ok(None);
        }

        let local_name = self.local_name.clone();
        let reverse = self.delete_edge_message(&message.to, &local_name);
        self.apply_runtime_meta_message(reverse.clone())?;
        Ok(Some(reverse))
    }

    pub(crate) fn sync_existing_state_messages_to_peer_id(
        &mut self,
        id: u64,
        messages: Vec<MetaMessage>,
    ) -> Result<(), TincdError> {
        for message in messages {
            self.send_active_meta_message_to_id(id, &message)?;
        }

        Ok(())
    }

    pub(crate) fn activated_edge_message(
        &mut self,
        index: usize,
        peer: &str,
        port: &str,
        weight: i32,
        options: u32,
    ) -> MetaMessage {
        let remote_address = self.meta_connections[index].peer.ip().to_string();
        let local_address = self.meta_connections[index].local.ip().to_string();
        let local_port = self.local_port.clone();
        let edge = Edge::new(self.local_name.clone(), peer.to_owned(), weight)
            .with_address(EdgeEndpoint::new(remote_address.clone(), port.to_owned()))
            .with_local_address(EdgeEndpoint::new(local_address.clone(), local_port.clone()))
            .with_options(options);

        MetaMessage::AddEdge(AddEdgeMessage {
            nonce: self.next_nonce(),
            address: remote_address,
            port: port.to_owned(),
            edge,
            local: Some(EdgeAddress {
                address: local_address,
                port: local_port,
            }),
        })
    }

    pub(crate) fn delete_edge_message(&mut self, from: &str, to: &str) -> MetaMessage {
        MetaMessage::DeleteEdge(DeleteEdgeMessage {
            nonce: self.next_nonce(),
            from: from.to_owned(),
            to: to.to_owned(),
        })
    }

    pub(crate) fn existing_state_messages(&mut self) -> Vec<MetaMessage> {
        let mut messages = Vec::new();

        if self.tunnel_server {
            let subnets = self
                .state
                .subnets
                .owner_subnets(&self.local_name)
                .cloned()
                .collect::<Vec<_>>();
            for mut subnet in subnets {
                let Some(owner) = subnet.owner.take() else {
                    continue;
                };

                messages.push(MetaMessage::AddSubnet(SubnetMessage {
                    nonce: self.next_nonce(),
                    owner,
                    subnet,
                }));
            }

            return messages;
        }

        let subnets = self.state.subnets.iter().cloned().collect::<Vec<_>>();
        let edges = self.state.graph.edges().cloned().collect::<Vec<_>>();

        for mut subnet in subnets {
            let Some(owner) = subnet.owner.take() else {
                continue;
            };

            messages.push(MetaMessage::AddSubnet(SubnetMessage {
                nonce: self.next_nonce(),
                owner,
                subnet,
            }));
        }

        for edge in edges {
            let Some(endpoint) = edge.address.as_ref() else {
                continue;
            };
            let local = edge.local_address.as_ref().map(|endpoint| EdgeAddress {
                address: endpoint.address.clone(),
                port: endpoint.port.clone(),
            });

            messages.push(MetaMessage::AddEdge(AddEdgeMessage {
                nonce: self.next_nonce(),
                address: endpoint.address.clone(),
                port: endpoint.port.clone(),
                edge,
                local,
            }));
        }

        if self.strict_subnets {
            messages.extend(self.strict_forwarded_topology.iter().cloned());
        }

        messages
    }

    pub(crate) fn handle_topology_relay_message(
        &mut self,
        index: usize,
        message: &MetaMessage,
        responses: &mut Vec<MetaMessage>,
        broadcasts: &mut Vec<(Option<u64>, MetaMessage)>,
    ) -> bool {
        let connection_id = self.meta_connections[index].id;
        let peer_name = self.meta_connections[index]
            .active_name()
            .map(str::to_owned);
        let peer = peer_name.as_deref();

        match message {
            MetaMessage::AddSubnet(message) => {
                if self
                    .state
                    .subnets
                    .lookup_owner_subnet(&message.owner, &message.subnet)
                    .is_some()
                {
                    return true;
                }

                if message.owner == self.local_name {
                    responses.push(MetaMessage::DeleteSubnet(SubnetMessage {
                        nonce: self.next_nonce(),
                        owner: self.local_name.clone(),
                        subnet: message.subnet.clone(),
                    }));
                    return true;
                }

                if self.tunnel_server {
                    return true;
                }

                if self.strict_subnets {
                    self.state.graph.ensure_node(&message.owner);
                    *self.packet_codec.ids_mut() = NodeIdTable::from_network_state(&self.state);
                    let forwarded = MetaMessage::AddSubnet(message.clone());
                    self.remember_strict_forwarded_topology(forwarded.clone());
                    broadcasts.push((Some(connection_id), forwarded));
                    return true;
                }

                false
            }
            MetaMessage::DeleteSubnet(message) => {
                if self.tunnel_server
                    && !Self::tunnel_server_direct_edge_endpoint(
                        &self.local_name,
                        peer,
                        &message.owner,
                    )
                {
                    return true;
                }

                let existing = self
                    .state
                    .subnets
                    .lookup_owner_subnet(&message.owner, &message.subnet)
                    .cloned();
                let Some(existing) = existing else {
                    if self.strict_subnets && self.state.graph.node(&message.owner).is_some() {
                        let forwarded = MetaMessage::DeleteSubnet(message.clone());
                        self.remember_strict_forwarded_topology(forwarded.clone());
                        broadcasts.push((Some(connection_id), forwarded));
                    }
                    return true;
                };

                if message.owner == self.local_name {
                    responses.push(MetaMessage::AddSubnet(SubnetMessage {
                        nonce: self.next_nonce(),
                        owner: self.local_name.clone(),
                        subnet: existing,
                    }));
                    return true;
                }

                if self.tunnel_server {
                    return true;
                }

                if self.strict_subnets {
                    let forwarded = MetaMessage::DeleteSubnet(message.clone());
                    self.remember_strict_forwarded_topology(forwarded.clone());
                    broadcasts.push((Some(connection_id), forwarded));
                    return true;
                }

                false
            }
            MetaMessage::AddEdge(message) => {
                let incoming = Self::runtime_edge_from_add_edge_message(message);
                let existing = self
                    .state
                    .graph
                    .edge(&message.edge.from, &message.edge.to)
                    .cloned();

                if existing.as_ref() == Some(&incoming) {
                    return true;
                }

                if message.edge.from == self.local_name {
                    self.topology_backoff.note_add_edge();
                    let correction = existing
                        .and_then(|edge| self.add_edge_message_from_runtime_edge(edge))
                        .unwrap_or_else(|| {
                            self.delete_edge_message(&message.edge.from, &message.edge.to)
                        });
                    responses.push(correction);
                    return true;
                }

                self.tunnel_server
                    && Self::tunnel_server_indirect_edge(
                        &self.local_name,
                        peer,
                        &message.edge.from,
                        &message.edge.to,
                    )
            }
            MetaMessage::DeleteEdge(message) => {
                let existing = self.state.graph.edge(&message.from, &message.to).cloned();
                let Some(existing) = existing else {
                    return true;
                };

                if message.from == self.local_name {
                    self.topology_backoff.note_del_edge();
                    if let Some(correction) = self.add_edge_message_from_runtime_edge(existing) {
                        responses.push(correction);
                    }
                    return true;
                }

                self.tunnel_server
                    && Self::tunnel_server_indirect_edge(
                        &self.local_name,
                        peer,
                        &message.from,
                        &message.to,
                    )
            }
            _ => false,
        }
    }

    pub(crate) fn runtime_edge_from_add_edge_message(message: &AddEdgeMessage) -> Edge {
        let mut edge = message.edge.clone().with_address(EdgeEndpoint::new(
            message.address.clone(),
            message.port.clone(),
        ));
        if let Some(local) = &message.local {
            edge = edge
                .with_local_address(EdgeEndpoint::new(local.address.clone(), local.port.clone()));
        }
        edge
    }

    pub(crate) fn add_edge_message_from_runtime_edge(&mut self, edge: Edge) -> Option<MetaMessage> {
        let endpoint = edge.address.as_ref()?;
        let local = edge.local_address.as_ref().map(|endpoint| EdgeAddress {
            address: endpoint.address.clone(),
            port: endpoint.port.clone(),
        });

        Some(MetaMessage::AddEdge(AddEdgeMessage {
            nonce: self.next_nonce(),
            address: endpoint.address.clone(),
            port: endpoint.port.clone(),
            edge,
            local,
        }))
    }

    pub(crate) fn remember_strict_forwarded_topology(&mut self, message: MetaMessage) {
        if !matches!(
            message,
            MetaMessage::AddSubnet(_) | MetaMessage::DeleteSubnet(_)
        ) {
            return;
        }
        if self
            .strict_forwarded_topology
            .iter()
            .any(|existing| existing == &message)
        {
            return;
        }
        self.strict_forwarded_topology.push_back(message);
    }

    pub(crate) fn tunnel_server_indirect_edge(
        myself: &str,
        peer: Option<&str>,
        from: &str,
        to: &str,
    ) -> bool {
        !Self::tunnel_server_direct_edge_endpoint(myself, peer, from)
            && !Self::tunnel_server_direct_edge_endpoint(myself, peer, to)
    }

    pub(crate) fn tunnel_server_direct_edge_endpoint(
        myself: &str,
        peer: Option<&str>,
        endpoint: &str,
    ) -> bool {
        endpoint == myself || peer == Some(endpoint)
    }

    pub(crate) fn next_nonce(&mut self) -> u32 {
        let nonce = self.next_meta_nonce;
        self.next_meta_nonce = self.next_meta_nonce.wrapping_add(1);
        nonce
    }

    pub(crate) fn mark_seen_runtime_message(&mut self, message: &MetaMessage) -> bool {
        let seen = self
            .past_requests
            .mark_seen(&message.to_string(), current_unix_secs().max(0) as u64);
        if !seen && self.next_past_request_age.is_none() {
            self.next_past_request_age =
                Some(Instant::now() + tinc_timer_jitter_duration(TINC_AGING_INTERVAL));
        } else if self.past_requests.is_empty() {
            self.next_past_request_age = None;
        }
        seen
    }

    pub(crate) fn apply_runtime_meta_message(
        &mut self,
        message: MetaMessage,
    ) -> Result<(), TincdError> {
        let edge_log = match &message {
            MetaMessage::AddEdge(message) => Some((
                "ADD_EDGE",
                message.edge.from.clone(),
                message.edge.to.clone(),
            )),
            MetaMessage::DeleteEdge(message) => {
                Some(("DEL_EDGE", message.from.clone(), message.to.clone()))
            }
            _ => None,
        };
        let mutation = self
            .state
            .apply_meta_message_at(message, current_unix_secs())
            .map_err(|error| TincdError::RuntimeState(error.to_string()))?;
        if let Some((kind, from, to)) = edge_log {
            if kind == "DEL_EDGE" && from == self.local_name {
                self.local_edge_connections.remove(&to);
            }
            match &mutation {
                StateMutation::AddEdge {
                    edge, reachability, ..
                } => {
                    self.record_log_with_priority(
                        DEBUG_PROTOCOL,
                        LOG_DEBUG,
                        format!(
                            "Applied {kind} {from} -> {to}; mutation={edge:?} reachable +{:?} -{:?}",
                            reachability.became_reachable, reachability.became_unreachable
                        ),
                    );
                }
                StateMutation::DeleteEdge {
                    removed,
                    reachability,
                } => {
                    self.record_log_with_priority(
                        DEBUG_PROTOCOL,
                        LOG_DEBUG,
                        format!(
                            "Applied {kind} {from} -> {to}; removed={} reachable +{:?} -{:?}",
                            removed.is_some(),
                            reachability.became_reachable,
                            reachability.became_unreachable
                        ),
                    );
                }
                _ => {}
            }
        }
        self.run_scripts_for_mutation(&mutation);
        if let StateMutation::KeyChanged { origin } = &mutation
            && self
                .state
                .graph
                .node(origin)
                .is_some_and(|node| !node.status.sptps)
        {
            self.legacy_last_req_key.remove(origin);
        }
        if let StateMutation::AddEdge { reachability, .. }
        | StateMutation::DeleteEdge { reachability, .. } = &mutation
        {
            self.update_route_udp_endpoints_like_tinc(reachability);
            self.clear_unreachable_runtime_peer_state_like_tinc(reachability);
        }
        *self.packet_codec.ids_mut() = NodeIdTable::from_network_state(&self.state);
        Ok(())
    }

    pub(crate) fn clear_unreachable_runtime_peer_state_like_tinc(
        &mut self,
        changes: &tinc_core::graph::ReachabilityChanges,
    ) {
        for peer in &changes.became_unreachable {
            self.packet_codec.remove_peer(peer);
            self.legacy_codec.remove_peer(peer);
            self.legacy_last_req_key.remove(peer);
            self.sptps_last_req_key.remove(peer);
            if let Some(key_exchange) = &mut self.key_exchange {
                key_exchange.remove_pending_session(peer);
            }
            self.udp_probe.remove(peer);
            self.udp_socket_by_peer.remove(peer);
            self.mtu_info_sent.remove(peer);
            self.udp_info_sent.remove(peer);
        }
    }

    pub(crate) fn forward_runtime_info_message(
        &mut self,
        message: &MetaMessage,
    ) -> Result<(), TincdError> {
        match message {
            MetaMessage::UdpInfo(message) => self.send_udp_info(&message.from, &message.to),
            MetaMessage::MtuInfo(message) => {
                if self.state.graph.node(&message.from).is_none() {
                    return Ok(());
                }
                self.send_mtu_info(&message.from, &message.to, message.mtu)
            }
            _ => Ok(()),
        }
    }

    pub(crate) fn handle_udp_info_message_like_tinc(
        &mut self,
        message: &UdpInfoMessage,
    ) -> Result<(), TincdError> {
        let Some((from_via, from_has_connection, from_udp_confirmed)) =
            self.state.graph.node(&message.from).map(|node| {
                (
                    node.route.via.clone(),
                    self.has_authenticated_meta_connection_with_name(&message.from),
                    node.status.udp_confirmed,
                )
            })
        else {
            return Ok(());
        };

        if from_via.as_deref() != Some(message.from.as_str()) {
            return Ok(());
        }

        if !from_has_connection && !from_udp_confirmed {
            self.update_node_udp_from_info_like_tinc(&message.from, message.endpoint.clone());
        }

        if self.state.graph.node(&message.to).is_none() {
            return Ok(());
        }

        self.send_udp_info(&message.from, &message.to)
    }

    pub(crate) fn update_node_udp_from_info_like_tinc(
        &mut self,
        source: &str,
        endpoint: EdgeAddress,
    ) {
        if source == self.local_name {
            return;
        }

        let endpoint = EdgeEndpoint::new(endpoint.address, endpoint.port);
        let changed = self
            .state
            .graph
            .node(source)
            .and_then(|node| node.udp_address.as_ref())
            != Some(&endpoint);
        if !changed {
            return;
        }

        self.set_node_udp_endpoint_like_tinc(source, endpoint);
    }

    pub(crate) fn update_route_udp_endpoints_like_tinc(
        &mut self,
        reachability: &tinc_core::graph::ReachabilityChanges,
    ) {
        let became_reachable = reachability
            .became_reachable
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let updates = self
            .state
            .graph
            .nodes()
            .filter(|node| node.name != self.local_name && node.status.reachable)
            .filter(|node| {
                became_reachable.contains(node.name.as_str()) || node.udp_address.is_none()
            })
            .filter_map(|node| {
                let previous = node.route.previous_edge.as_ref()?;
                let endpoint = self
                    .state
                    .graph
                    .edge(&previous.from, &previous.to)?
                    .address
                    .clone()?;
                Some((node.name.clone(), endpoint))
            })
            .collect::<Vec<_>>();

        for (peer, endpoint) in updates {
            self.set_node_udp_endpoint_like_tinc(&peer, endpoint);
        }
    }

    pub(crate) fn set_node_udp_endpoint_like_tinc(&mut self, source: &str, endpoint: EdgeEndpoint) {
        if source == self.local_name {
            return;
        }

        if let Some(target) = edge_endpoint_socket_addr(&endpoint)
            && let Some(socket_index) = listen_socket_index_for(&self.listen_sockets, target)
        {
            self.udp_socket_by_peer
                .insert(source.to_owned(), socket_index);
        }

        if let Some(node) = self.state.graph.node_mut(source) {
            node.udp_address = Some(endpoint);
            node.status.udp_confirmed = false;
            node.mtu_probes = 0;
            node.min_mtu = 0;
            node.max_mtu = DEFAULT_MTU;
        }
        if let Some(state) = self.udp_probe.get_mut(source) {
            state.max_recent_len = 0;
            state.udp_ping_timeout = None;
        }
    }

    pub(crate) fn send_udp_info(&mut self, from: &str, to: &str) -> Result<(), TincdError> {
        let Some(target) = self.info_target(to) else {
            return Ok(());
        };
        if !self.should_send_udp_info(from, &target) {
            return Ok(());
        }
        let Some(next_hop) = self.info_next_hop(&target) else {
            return Ok(());
        };
        let Some(endpoint) = self.udp_info_endpoint(from, &next_hop) else {
            return Ok(());
        };

        let message = MetaMessage::UdpInfo(UdpInfoMessage {
            from: from.to_owned(),
            to: target.clone(),
            endpoint,
        });
        self.send_active_meta_message_to_peer(&next_hop, &message)?;

        if from == self.local_name {
            self.udp_info_sent.insert(target, Instant::now());
        }

        Ok(())
    }

    pub(crate) fn send_mtu_info(
        &mut self,
        from: &str,
        to: &str,
        mtu: usize,
    ) -> Result<(), TincdError> {
        if to == self.local_name {
            return Ok(());
        }
        let Some(to_node) = self.state.graph.node(to) else {
            return Ok(());
        };
        if !to_node.status.reachable {
            return Ok(());
        }
        if from == self.local_name {
            if self.has_authenticated_meta_connection_with_name(to)
                || self.recently_sent_mtu_info(to)
            {
                return Ok(());
            }
        }
        let Some(next_hop) = to_node.route.next_hop.clone() else {
            return Ok(());
        };
        let Some(next_hop_node) = self.state.graph.node(&next_hop) else {
            return Ok(());
        };
        if option_version(next_hop_node.options) < 6 {
            return Ok(());
        }

        let mtu = self.best_mtu_info_value(from, mtu);
        let message = MetaMessage::MtuInfo(MtuInfoMessage {
            from: from.to_owned(),
            to: to.to_owned(),
            mtu,
        });
        self.send_active_meta_message_to_peer(&next_hop, &message)?;

        if from == self.local_name {
            self.mtu_info_sent.insert(to.to_owned(), Instant::now());
        }

        Ok(())
    }

    pub(crate) fn info_target(&self, to: &str) -> Option<String> {
        let node = self.state.graph.node(to)?;
        if node.route.via.as_deref() == Some(self.local_name.as_str()) {
            node.route.next_hop.clone()
        } else {
            node.route.via.clone()
        }
    }

    pub(crate) fn info_next_hop(&self, target: &str) -> Option<String> {
        self.state.graph.node(target)?.route.next_hop.clone()
    }

    pub(crate) fn should_send_udp_info(&self, from: &str, target: &str) -> bool {
        if target == self.local_name {
            return false;
        }
        let Some(target_node) = self.state.graph.node(target) else {
            return false;
        };
        if !target_node.status.reachable {
            return false;
        }
        if from == self.local_name
            && (self.has_authenticated_meta_connection_with_name(target)
                || self.recently_sent_udp_info(target))
        {
            return false;
        }
        let from_options = self
            .state
            .graph
            .node(from)
            .map(|node| node.options)
            .unwrap_or(0);
        if (self.local_options_for_info() | from_options | target_node.options) & OPTION_TCPONLY
            != 0
        {
            return false;
        }
        let Some(next_hop) = target_node.route.next_hop.as_deref() else {
            return false;
        };
        let Some(next_hop_node) = self.state.graph.node(next_hop) else {
            return false;
        };
        option_version(next_hop_node.options) >= 5
    }

    pub(crate) fn udp_info_endpoint(&self, from: &str, target: &str) -> Option<EdgeAddress> {
        if from != self.local_name {
            let Some(node) = self.state.graph.node(from) else {
                return None;
            };
            let Some(endpoint) = node.udp_address.as_ref() else {
                return Some(EdgeAddress {
                    address: "unspec".to_owned(),
                    port: "unspec".to_owned(),
                });
            };
            return Some(EdgeAddress {
                address: endpoint.address.clone(),
                port: endpoint.port.clone(),
            });
        }

        let connection = self
            .meta_connections
            .iter()
            .find(|connection| connection.authenticated_name() == Some(target))?;
        Some(EdgeAddress {
            address: connection.local.ip().to_string(),
            port: connection.local.port().to_string(),
        })
    }

    pub(crate) fn local_options_for_info(&self) -> u32 {
        runtime_meta_options(
            self.state.experimental,
            self.local_indirect_data,
            self.local_tcp_only,
            self.local_pmtu_discovery,
            self.local_clamp_mss,
            None,
        )
    }

    pub(crate) fn best_mtu_info_value(&self, from: &str, mtu: usize) -> usize {
        let Some(from_node) = self.state.graph.node(from) else {
            return mtu.min(DEFAULT_MTU);
        };
        let via = if from_node.route.via.as_deref() == Some(self.local_name.as_str()) {
            from_node.route.next_hop.as_deref()
        } else {
            from_node.route.via.as_deref()
        };

        let mut mtu = mtu.min(DEFAULT_MTU);
        if from_node.min_mtu == from_node.max_mtu
            && from_node.route.via.as_deref() == Some(self.local_name.as_str())
        {
            mtu = from_node.min_mtu;
        } else if let Some(via) = via.and_then(|name| self.state.graph.node(name)) {
            if via.min_mtu == via.max_mtu {
                mtu = mtu.min(via.min_mtu);
            } else if let Some(next_hop) = via
                .route
                .next_hop
                .as_deref()
                .and_then(|name| self.state.graph.node(name))
                && next_hop.min_mtu == next_hop.max_mtu
            {
                mtu = mtu.min(next_hop.min_mtu);
            }
        }

        mtu
    }

    pub(crate) fn recently_sent_udp_info(&self, target: &str) -> bool {
        self.udp_info_sent
            .get(target)
            .is_some_and(|sent| sent.elapsed() < self.udp_info_interval)
    }

    pub(crate) fn recently_sent_mtu_info(&self, target: &str) -> bool {
        self.mtu_info_sent
            .get(target)
            .is_some_and(|sent| sent.elapsed() < self.mtu_info_interval)
    }

    pub(crate) fn start_sptps_key_exchange(
        &mut self,
        peer: &str,
    ) -> Result<Vec<MetaMessage>, TincdError> {
        if self.packet_codec.peer(peer).is_some() {
            return Ok(Vec::new());
        }

        let Some(key_exchange) = &mut self.key_exchange else {
            return Ok(Vec::new());
        };
        let result = match key_exchange.start_initiator(peer) {
            Ok(result) => result,
            Err(SptpsKeyExchangeError::UnknownPeerKey(_)) => {
                return Ok(vec![MetaMessage::RequestKey(RequestKeyMessage {
                    from: self.local_name.clone(),
                    to: peer.to_owned(),
                    extension: Some(RequestKeyExtension {
                        request: Request::RequestPublicKey.number(),
                        payload: None,
                    }),
                })]);
            }
            Err(error) => return Err(sptps_key_exchange_error(error)),
        };

        if !result.outbound.is_empty() {
            self.sptps_last_req_key
                .insert(peer.to_owned(), Instant::now());
            if let Some(node) = self.state.graph.node_mut(peer) {
                node.status.valid_key = false;
                node.status.waiting_for_key = true;
            }
        }

        self.apply_sptps_key_exchange_result(result)
    }

    pub(crate) fn receive_sptps_key_exchange_message(
        &mut self,
        message: &MetaMessage,
    ) -> Result<Vec<MetaMessage>, TincdError> {
        let Some(key_exchange) = &mut self.key_exchange else {
            return Ok(Vec::new());
        };
        let result = key_exchange
            .receive_meta_message(message)
            .map_err(sptps_key_exchange_error)?;

        self.apply_sptps_key_exchange_result(result)
    }

    pub(crate) fn handle_sptps_answer_key_message(
        &mut self,
        message: &AnswerKeyMessage,
    ) -> Result<Vec<MetaMessage>, TincdError> {
        let peer = message.from.clone();
        let result = {
            let Some(key_exchange) = &mut self.key_exchange else {
                return Ok(Vec::new());
            };
            key_exchange.receive_meta_message(&MetaMessage::AnswerKey(message.clone()))
        };

        match result {
            Ok(result) => {
                let established = result.events.iter().any(|event| {
                    matches!(
                        event,
                        SptpsKeyExchangeEvent::Established { peer: established, .. }
                            if established == &peer
                    )
                });
                let responses = self.apply_sptps_key_exchange_result(result)?;
                if established {
                    self.apply_sptps_reflexive_address_like_tinc(&peer, message.address.clone());
                }
                self.send_local_mtu_info_like_tinc(&peer)?;
                Ok(responses)
            }
            Err(error) if is_recoverable_sptps_answer_key_error(&error) => {
                self.restart_sptps_after_bad_meta_key_message(&peer)
            }
            Err(error) => Err(sptps_key_exchange_error(error)),
        }
    }

    pub(crate) fn restart_sptps_after_bad_meta_key_message(
        &mut self,
        peer: &str,
    ) -> Result<Vec<MetaMessage>, TincdError> {
        let Some(sent) = self.sptps_last_req_key.get(peer).copied() else {
            return Ok(Vec::new());
        };
        if sent.elapsed() <= SPTPS_REQ_KEY_INTERVAL {
            return Ok(Vec::new());
        }

        let Some(key_exchange) = &mut self.key_exchange else {
            return Ok(Vec::new());
        };
        let result = match key_exchange.restart_initiator(peer) {
            Ok(result) => result,
            Err(SptpsKeyExchangeError::UnknownPeerKey(_)) => return Ok(Vec::new()),
            Err(error) => return Err(sptps_key_exchange_error(error)),
        };
        self.sptps_last_req_key
            .insert(peer.to_owned(), Instant::now());
        if let Some(node) = self.state.graph.node_mut(peer) {
            node.status.valid_key = false;
            node.status.waiting_for_key = true;
        }

        self.apply_sptps_key_exchange_result(result)
    }

    pub(crate) fn handle_sptps_request_key_message(
        &mut self,
        message: &RequestKeyMessage,
    ) -> Result<Vec<MetaMessage>, TincdError> {
        let peer = message.from.clone();
        let result = {
            let Some(key_exchange) = &mut self.key_exchange else {
                return Ok(Vec::new());
            };
            key_exchange.receive_meta_message(&MetaMessage::RequestKey(message.clone()))
        };

        match result {
            Ok(result) => {
                if let Some(node) = self.state.graph.node_mut(&peer)
                    && request_key_extension_request(message) == Some(Request::RequestKey)
                {
                    node.status.valid_key = false;
                    node.status.waiting_for_key = true;
                    self.sptps_last_req_key.insert(peer.clone(), Instant::now());
                }
                let responses = self.apply_sptps_key_exchange_result(result)?;
                self.send_local_mtu_info_like_tinc(&peer)?;
                Ok(responses)
            }
            Err(SptpsKeyExchangeError::Sptps(_))
                if request_key_extension_request(message) == Some(Request::SptpsPacket) =>
            {
                self.restart_sptps_after_bad_meta_key_message(&message.from)
            }
            Err(error) if is_recoverable_sptps_request_key_error(&error) => Ok(Vec::new()),
            Err(error) => Err(sptps_key_exchange_error(error)),
        }
    }

    pub(crate) fn apply_sptps_reflexive_address_like_tinc(
        &mut self,
        peer: &str,
        reflexive_address: Option<EdgeAddress>,
    ) {
        if let Some(endpoint) = reflexive_address {
            self.update_node_udp_from_info_like_tinc(peer, endpoint);
        }
    }

    pub(crate) fn send_local_mtu_info_like_tinc(&mut self, peer: &str) -> Result<(), TincdError> {
        let local_name = self.local_name.clone();
        self.send_mtu_info(&local_name, peer, DEFAULT_MTU)
    }

    pub(crate) fn handle_legacy_request_key_message(
        &mut self,
        message: &RequestKeyMessage,
    ) -> Result<Option<(String, MetaMessage)>, TincdError> {
        let Some((from_reachable, from_next_hop)) = self
            .state
            .graph
            .node(&message.from)
            .map(|from| (from.status.reachable, from.route.next_hop.clone()))
        else {
            return Ok(None);
        };
        let Some((to_reachable, to_next_hop)) = self
            .state
            .graph
            .node(&message.to)
            .map(|to| (to.status.reachable, to.route.next_hop.clone()))
        else {
            return Ok(None);
        };

        if message.to == self.local_name {
            if !from_reachable {
                return Ok(None);
            }
            let Some(next_hop) = from_next_hop else {
                return Ok(None);
            };
            let response = self.generate_legacy_answer_key_message(&message.from)?;
            return Ok(Some((next_hop, response)));
        }

        if self.tunnel_server {
            return Ok(None);
        }
        if !to_reachable {
            return Ok(None);
        }
        let Some(next_hop) = to_next_hop else {
            return Ok(None);
        };

        self.send_active_meta_message_to_peer(
            &next_hop,
            &MetaMessage::RequestKey(message.clone()),
        )?;
        Ok(None)
    }

    pub(crate) fn handle_extended_request_key_message(
        &mut self,
        message: &RequestKeyMessage,
    ) -> Result<Vec<(String, MetaMessage)>, TincdError> {
        let Some(extension) = &message.extension else {
            return Ok(Vec::new());
        };
        let Some((from_reachable, from_next_hop)) = self
            .state
            .graph
            .node(&message.from)
            .map(|from| (from.status.reachable, from.route.next_hop.clone()))
        else {
            return Ok(Vec::new());
        };
        let Some((to_reachable, to_next_hop)) = self
            .state
            .graph
            .node(&message.to)
            .map(|to| (to.status.reachable, to.route.next_hop.clone()))
        else {
            return Ok(Vec::new());
        };
        let request = Request::try_from(extension.request).ok();

        if message.to == self.local_name {
            if !from_reachable {
                return Ok(Vec::new());
            }
        } else {
            if self.tunnel_server || !to_reachable {
                return Ok(Vec::new());
            }
        }

        self.send_udp_info_for_extended_req_key_like_tinc(request, &message.to, &message.from)?;

        if request == Some(Request::SptpsPacket) {
            let payload = match message.decode_sptps_payload() {
                Ok(payload) => payload,
                Err(_) => return Ok(Vec::new()),
            };
            if message.to != self.local_name {
                if self.engine_config.route.forwarding_mode == ForwardingMode::Internal {
                    self.forward_sptps_relay_record(&message.to, &message.from, &payload.data)?;
                }
            } else {
                let Some(source_id) = self.state.graph.node(&message.from).map(|node| node.id)
                else {
                    return Ok(Vec::new());
                };
                let datagram = RelayEnvelope::direct(source_id, payload.data).encode();
                if self.handle_meta_sptps_packet(usize::MAX, datagram).is_err() {
                    self.try_tx_sptps_like_tinc(&message.from, false)?;
                }
            }
            return Ok(Vec::new());
        }

        if message.to != self.local_name {
            let Some(next_hop) = to_next_hop else {
                return Ok(Vec::new());
            };
            return Ok(vec![(next_hop, MetaMessage::RequestKey(message.clone()))]);
        }

        let Some(next_hop) = from_next_hop else {
            return Ok(Vec::new());
        };

        match request {
            Some(Request::RequestPublicKey) => {
                let mut responses = Vec::new();
                if !self.keys.peer_public_keys.contains_key(&message.from) {
                    responses.push((
                        next_hop.clone(),
                        MetaMessage::RequestKey(RequestKeyMessage {
                            from: self.local_name.clone(),
                            to: message.from.clone(),
                            extension: Some(RequestKeyExtension {
                                request: Request::RequestPublicKey.number(),
                                payload: None,
                            }),
                        }),
                    ));
                }
                let Some(private_key) = self.keys.private_key.as_ref() else {
                    return Ok(responses);
                };
                responses.push((
                    next_hop,
                    MetaMessage::RequestKey(RequestKeyMessage {
                        from: self.local_name.clone(),
                        to: message.from.clone(),
                        extension: Some(RequestKeyExtension {
                            request: Request::AnswerPublicKey.number(),
                            payload: Some(private_key.public_key().to_base64()),
                        }),
                    }),
                ));
                Ok(responses)
            }
            Some(Request::AnswerPublicKey) => {
                if let Some(public_key) = extension.payload.as_deref() {
                    self.learn_peer_public_key_from_ans_pubkey(&message.from, public_key);
                }
                Ok(Vec::new())
            }
            _ => Ok(Vec::new()),
        }
    }

    pub(crate) fn send_udp_info_for_extended_req_key_like_tinc(
        &mut self,
        request: Option<Request>,
        to: &str,
        from: &str,
    ) -> Result<(), TincdError> {
        if !matches!(request, Some(Request::RequestKey | Request::SptpsPacket)) {
            return Ok(());
        }
        let via_self = to == self.local_name
            || self
                .state
                .graph
                .node(to)
                .and_then(|node| node.route.via.as_deref())
                == Some(self.local_name.as_str());
        if via_self {
            let local_name = self.local_name.clone();
            self.send_udp_info(&local_name, from)?;
        }
        Ok(())
    }

    pub(crate) fn learn_peer_public_key_from_ans_pubkey(&mut self, peer: &str, public_key: &str) {
        if self.keys.peer_public_keys.contains_key(peer) {
            return;
        }
        let Ok(key) = TincEd25519PublicKey::from_base64(public_key) else {
            self.record_log_with_priority(
                0,
                LOG_ERR,
                format!("Got bad ANS_PUBKEY from {peer}: invalid Ed25519 public key"),
            );
            return;
        };

        if let Some(confbase) = self.confbase.clone()
            && let Err(error) =
                append_runtime_host_config(&confbase, peer, "Ed25519PublicKey", public_key)
        {
            self.record_log_with_priority(
                0,
                LOG_ERR,
                format!("Cannot append Ed25519PublicKey to host config for {peer}: {error}"),
            );
        }

        self.keys.peer_public_keys.insert(peer.to_owned(), key);
        if let Some(key_exchange) = &mut self.key_exchange {
            key_exchange.insert_peer_public_key(peer.to_owned(), key);
        }
    }

    pub(crate) fn generate_legacy_answer_key_message(
        &mut self,
        peer: &str,
    ) -> Result<MetaMessage, TincdError> {
        self.generate_legacy_answer_key_message_with(peer, |bytes| {
            getrandom::getrandom(bytes).map_err(|error| {
                TincdError::RuntimeState(format!("legacy key random generation failed: {error}"))
            })
        })
    }

    pub(crate) fn generate_legacy_answer_key_message_with<F>(
        &mut self,
        peer: &str,
        mut fill_random: F,
    ) -> Result<MetaMessage, TincdError>
    where
        F: FnMut(&mut [u8]) -> Result<(), TincdError>,
    {
        if self
            .state
            .graph
            .node(peer)
            .is_some_and(|node| node.status.sptps)
        {
            return Err(TincdError::RuntimeState(format!(
                "cannot generate legacy ANS_KEY for SPTPS peer {peer}"
            )));
        }

        let key_len = match self.legacy_cipher {
            LegacyCipherAlgorithm::None => 1,
            cipher => cipher.key_material_len(),
        };
        let mut key = vec![0; key_len];
        fill_random(&mut key)?;

        let message = AnswerKeyMessage {
            from: self.local_name.clone(),
            to: peer.to_owned(),
            key: bin_to_hex(&key),
            cipher: self.legacy_cipher.nid(),
            digest: self.legacy_digest.nid(),
            mac_length: self.legacy_digest.length() as u64,
            compression: self.legacy_compression as i32,
            address: None,
        };
        self.legacy_codec
            .apply_incoming_legacy_answer_key(peer.to_owned(), &message)
            .map_err(legacy_packet_error)?;
        if let Some(node) = self.state.graph.node_mut(peer) {
            node.status.valid_key_in = true;
        }

        Ok(MetaMessage::AnswerKey(message))
    }

    pub(crate) fn apply_legacy_answer_key_message(
        &mut self,
        message: &AnswerKeyMessage,
    ) -> Result<(), TincdError> {
        if message.to != self.local_name {
            return Ok(());
        }
        if self.state.graph.node(&message.from).is_none() {
            return Ok(());
        }

        if !message.is_sptps_handshake() {
            self.legacy_codec.clear_outgoing_key_state(&message.from);
            if let Some(node) = self.state.graph.node_mut(&message.from) {
                node.status.valid_key = false;
            }
        }

        match self.legacy_codec.peer_mut(&message.from) {
            Some(peer) => peer
                .apply_legacy_answer_key(message)
                .map_err(legacy_packet_error)?,
            None => {
                let peer = LegacyPeerState::from_legacy_answer_key(
                    message,
                    self.legacy_codec.replay_window_bytes(),
                )
                .map_err(legacy_packet_error)?;
                self.legacy_codec.insert_peer(message.from.clone(), peer);
            }
        }

        if let Some(node) = self.state.graph.node_mut(&message.from) {
            node.status.valid_key = true;
            node.status.waiting_for_key = false;
        }
        if let Some(endpoint) = message.address.clone() {
            self.apply_runtime_meta_message(MetaMessage::UdpInfo(UdpInfoMessage {
                from: message.from.clone(),
                to: self.local_name.clone(),
                endpoint,
            }))?;
        }

        Ok(())
    }

    pub(crate) fn handle_legacy_answer_key_message(
        &mut self,
        message: &AnswerKeyMessage,
    ) -> Result<(), TincdError> {
        match self.apply_legacy_answer_key_message(message) {
            Ok(()) => Ok(()),
            Err(error) if is_recoverable_legacy_answer_key_error(&error) => {
                self.record_recoverable_legacy_answer_key_error(message, &error);
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    pub(crate) fn record_recoverable_legacy_answer_key_error(
        &mut self,
        message: &AnswerKeyMessage,
        error: &TincdError,
    ) {
        self.legacy_codec.clear_outgoing_key_state(&message.from);
        self.legacy_last_req_key.remove(&message.from);
        match error {
            TincdError::LegacyPacket(LegacyPacketError::InvalidCompression(compression)) => {
                self.record_log_with_priority(
                    0,
                    LOG_ERR,
                    format!("Node {} uses bogus compression level!", message.from),
                );
                self.record_log_with_priority(
                    0,
                    LOG_ERR,
                    format!("Compression level {compression} is unrecognized by this node."),
                );
            }
            TincdError::LegacyPacket(LegacyPacketError::UnsupportedCompression(compression)) => {
                self.record_log_with_priority(
                    0,
                    LOG_ERR,
                    format!("Node {} uses bogus compression level!", message.from),
                );
                let compression_name = match compression {
                    CompressionLevel::LzoLow | CompressionLevel::LzoHigh => "LZO",
                    CompressionLevel::Lz4 => "LZ4",
                    CompressionLevel::Zlib1
                    | CompressionLevel::Zlib2
                    | CompressionLevel::Zlib3
                    | CompressionLevel::Zlib4
                    | CompressionLevel::Zlib5
                    | CompressionLevel::Zlib6
                    | CompressionLevel::Zlib7
                    | CompressionLevel::Zlib8
                    | CompressionLevel::Zlib9 => "ZLIB",
                    CompressionLevel::None => "None",
                };
                self.record_log_with_priority(
                    0,
                    LOG_ERR,
                    format!("{compression_name} compression is unavailable on this node."),
                );
            }
            TincdError::LegacyPacket(LegacyPacketError::InvalidKeyMaterialLength { .. }) => {}
            _ => {}
        }
    }

    pub(crate) fn forward_answer_key_message(
        &mut self,
        message: &AnswerKeyMessage,
    ) -> Result<(), TincdError> {
        if self.tunnel_server {
            return Ok(());
        }
        let Some(from_udp_address) = self
            .state
            .graph
            .node(&message.from)
            .map(|from| from.udp_address.clone())
        else {
            return Ok(());
        };
        let Some((to_reachable, to_next_hop, to_min_mtu)) = self
            .state
            .graph
            .node(&message.to)
            .map(|to| (to.status.reachable, to.route.next_hop.clone(), to.min_mtu))
        else {
            return Ok(());
        };
        if !to_reachable {
            return Ok(());
        }
        let Some(next_hop) = to_next_hop else {
            return Ok(());
        };

        let mut forwarded = message.clone();
        if forwarded.address.is_none()
            && to_min_mtu != 0
            && let Some(endpoint) = from_udp_address
        {
            forwarded.address = Some(EdgeAddress {
                address: endpoint.address,
                port: endpoint.port,
            });
        }

        self.send_active_meta_message_to_peer(&next_hop, &MetaMessage::AnswerKey(forwarded))
    }

    pub(crate) fn apply_sptps_key_exchange_result(
        &mut self,
        result: SptpsKeyExchangeResult,
    ) -> Result<Vec<MetaMessage>, TincdError> {
        for event in result.events {
            match event {
                SptpsKeyExchangeEvent::Established { peer, session } => {
                    if let Some(node) = self.state.graph.node_mut(&peer) {
                        node.status.valid_key = true;
                        node.status.waiting_for_key = false;
                    }
                    self.sptps_last_req_key.remove(&peer);
                    self.packet_codec.insert_peer(peer, *session);
                }
                SptpsKeyExchangeEvent::ApplicationRecord { .. } => {}
            }
        }

        Ok(result.outbound)
    }

    pub(crate) fn run_scripts_for_mutation(&mut self, mutation: &StateMutation) {
        match mutation {
            StateMutation::AddSubnet {
                subnet,
                owner,
                inserted,
                ..
            } => {
                if *inserted && self.node_is_reachable(owner) {
                    self.run_subnet_script_for_subnet("subnet-up", subnet);
                }
            }
            StateMutation::DeleteSubnet { removed } => {
                if let Some(subnet) = removed
                    && let Some(owner) = subnet.owner.as_deref()
                    && self.node_is_reachable(owner)
                {
                    self.run_subnet_script_for_subnet("subnet-down", subnet);
                }
            }
            StateMutation::AddEdge { reachability, .. }
            | StateMutation::DeleteEdge { reachability, .. } => {
                self.run_reachability_scripts(reachability);
                self.apply_device_standby_reachability(reachability);
            }
            _ => {}
        }
    }

    pub(crate) fn run_reachability_scripts(&self, changes: &tinc_core::graph::ReachabilityChanges) {
        for node in &changes.became_reachable {
            self.run_host_scripts(node, true);
            self.run_all_subnet_scripts(node, true);
        }
        for node in &changes.became_unreachable {
            self.run_host_scripts(node, false);
            self.run_all_subnet_scripts(node, false);
        }
    }

    pub(crate) fn apply_device_standby_reachability(
        &mut self,
        changes: &tinc_core::graph::ReachabilityChanges,
    ) {
        if !self.device_standby {
            return;
        }

        let reachable_count = self.reachable_remote_count();
        if reachable_count == 0 && !changes.became_unreachable.is_empty() {
            self.disable_runtime_device_like_tinc();
        } else if reachable_count > 0 && reachable_count == changes.became_reachable.len() {
            self.enable_runtime_device_like_tinc();
        }
    }

    pub(crate) fn reachable_remote_count(&self) -> usize {
        self.state
            .graph
            .nodes()
            .filter(|node| node.name != self.local_name && node.status.reachable)
            .count()
    }

    pub(crate) fn enable_runtime_device_like_tinc(&mut self) {
        if self.device_enabled {
            return;
        }

        let _ = self.device.enable();
        self.device_enabled = true;
        self.run_event_script("tinc-up", &[]);
    }

    pub(crate) fn disable_runtime_device_like_tinc(&mut self) {
        if !self.device_enabled {
            return;
        }

        self.run_event_script("tinc-down", &[]);
        let _ = self.device.disable();
        self.device_enabled = false;
    }

    pub(crate) fn run_host_scripts(&self, node: &str, up: bool) {
        let script = if up { "host-up" } else { "host-down" };
        let host_script = format!("hosts/{node}-{}", if up { "up" } else { "down" });
        let env = self.node_script_env(node);

        self.run_event_script(script, &env);
        self.run_event_script(&host_script, &env);
    }

    pub(crate) fn run_all_subnet_scripts(&self, node: &str, up: bool) {
        let script = if up { "subnet-up" } else { "subnet-down" };
        for subnet in self.state.subnets.owner_subnets(node) {
            self.run_subnet_script_for_subnet(script, subnet);
        }
    }

    pub(crate) fn run_subnet_script_for_subnet(&self, script: &str, subnet: &Subnet) {
        let Some(owner) = subnet.owner.as_deref() else {
            return;
        };
        let mut env = self.node_script_env(owner);
        let (subnet, weight) = script_subnet_env(subnet);
        env.push(("SUBNET", subnet));
        env.push(("WEIGHT", weight));

        self.run_event_script(script, &env);
    }

    pub(crate) fn node_script_env(&self, node: &str) -> Vec<(&'static str, String)> {
        let mut env = vec![("NODE", node.to_owned())];
        let Some(context) = &self.script_context else {
            return env;
        };

        if node != self.local_name
            && let Some(node) = self.state.graph.node(node)
        {
            let (address, port) = self.direct_edge_endpoint(&node.name).unwrap_or_else(|| {
                node_host_port(
                    &context.config,
                    node,
                    Some(&self.local_port),
                    self.hostnames,
                )
            });
            if address != "unknown" && port != "unknown" {
                env.push(("REMOTEADDRESS", address));
                env.push(("REMOTEPORT", port));
            }
        }

        env
    }

    pub(crate) fn direct_edge_endpoint(&self, node: &str) -> Option<(String, String)> {
        self.state
            .graph
            .edges()
            .find(|edge| edge.from == self.local_name && edge.to == node)
            .and_then(|edge| edge.address.as_ref())
            .map(|endpoint| (endpoint.address.clone(), endpoint.port.clone()))
    }

    pub(crate) fn node_is_reachable(&self, node: &str) -> bool {
        if node == self.local_name {
            return true;
        }
        self.state
            .graph
            .node(node)
            .map(|node| node.status.reachable)
            .unwrap_or(false)
    }

    pub(crate) fn run_event_script(&self, script: &str, env: &[(&str, String)]) {
        let Some(context) = &self.script_context else {
            return;
        };
        let _ = run_daemon_script(
            script,
            &context.config,
            &context.options,
            &context.device_info,
            env,
        );
    }

    pub(crate) fn broadcast_active_meta_message_except(
        &mut self,
        source_index: Option<usize>,
        message: &MetaMessage,
    ) -> Result<(), TincdError> {
        let source_id =
            source_index.and_then(|index| self.meta_connections.get(index).map(|c| c.id));
        self.broadcast_active_meta_message_except_id(source_id, message)
    }

    pub(crate) fn broadcast_active_meta_message_except_id(
        &mut self,
        source_id: Option<u64>,
        message: &MetaMessage,
    ) -> Result<(), TincdError> {
        let targets = self
            .meta_connections
            .iter()
            .filter(|connection| source_id != Some(connection.id))
            .filter(|connection| connection.is_active_authenticated())
            .map(|connection| connection.id)
            .collect::<Vec<_>>();

        for id in targets {
            self.send_active_meta_message_to_id(id, message)?;
        }

        Ok(())
    }

    pub(crate) fn send_active_meta_message_to_peer(
        &mut self,
        peer: &str,
        message: &MetaMessage,
    ) -> Result<(), TincdError> {
        let targets = self
            .current_meta_connection_id_for_peer(peer)
            .into_iter()
            .collect::<Vec<_>>();

        for id in targets {
            self.send_active_meta_message_to_id(id, message)?;
        }

        Ok(())
    }

    pub(crate) fn current_meta_connection_id_for_peer(&self, peer: &str) -> Option<u64> {
        self.local_edge_connections
            .get(peer)
            .and_then(|id| {
                self.meta_connections
                    .iter()
                    .find(|connection| {
                        connection.id == *id && connection.can_carry_data_for_peer(peer)
                    })
                    .map(|connection| connection.id)
            })
            .or_else(|| {
                self.meta_connections
                    .iter()
                    .find(|connection| connection.is_current_edge_connection_for_peer(peer))
                    .map(|connection| connection.id)
            })
            .or_else(|| {
                self.meta_connections
                    .iter()
                    .find(|connection| connection.can_carry_data_for_peer(peer))
                    .map(|connection| connection.id)
            })
    }

    pub(crate) fn send_active_meta_message_to_id(
        &mut self,
        id: u64,
        message: &MetaMessage,
    ) -> Result<(), TincdError> {
        let Some(index) = self.connection_index_by_id(id) else {
            return Ok(());
        };
        let chunk = match self.send_active_meta_message(index, message) {
            Ok(chunk) => chunk,
            Err(error) if is_meta_connection_scoped_error(&error) => {
                self.close_meta_connection_by_id_with_detail(id, "meta-send-error", error)?;
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        if let Err(error) = self.write_meta_chunk_to_id(id, &chunk) {
            if is_meta_connection_scoped_error(&error) {
                self.close_meta_connection_by_id_with_detail(id, "meta-write-queue-error", error)?;
            } else {
                return Err(error);
            }
        }
        Ok(())
    }

    pub(crate) fn send_active_meta_message(
        &mut self,
        index: usize,
        message: &MetaMessage,
    ) -> Result<Vec<u8>, TincdError> {
        let Some(connection) = self.meta_connections.get_mut(index) else {
            return Err(TincdError::MetaConnection(
                "meta connection no longer exists".to_owned(),
            ));
        };
        let RuntimeMetaConnectionKind::Active { driver, .. } = &mut connection.kind else {
            return Err(TincdError::MetaConnection(
                "cannot send meta message on pending connection".to_owned(),
            ));
        };

        driver.send_meta_message(message)
    }

    pub(crate) fn write_meta_chunk(
        &mut self,
        index: usize,
        chunk: &[u8],
    ) -> Result<(), TincdError> {
        let Some(connection) = self.meta_connections.get_mut(index) else {
            return Ok(());
        };
        connection.write_meta_chunk(chunk).map_err(listen_io)
    }

    pub(crate) fn write_meta_chunk_to_id(
        &mut self,
        id: u64,
        chunk: &[u8],
    ) -> Result<(), TincdError> {
        let Some(index) = self.connection_index_by_id(id) else {
            return Ok(());
        };
        self.write_meta_chunk(index, chunk)
    }

    #[cfg(test)]
    pub(crate) fn flush_meta_outputs(&mut self) -> Result<(), TincdError> {
        let ids = self
            .meta_connections
            .iter()
            .map(|connection| connection.id)
            .collect::<Vec<_>>();

        for id in ids {
            let Some(index) = self.connection_index_by_id(id) else {
                continue;
            };
            match self.flush_meta_output(index) {
                Ok(()) => {
                    if let Some(index) = self.connection_index_by_id(id)
                        && self.meta_connections[index].close_requested
                        && !self.meta_connections[index].has_pending_output()
                    {
                        self.close_meta_connection_for_reason(
                            index,
                            "close-requested-after-flush",
                        )?;
                    }
                }
                Err(error) => {
                    self.close_meta_connection_with_detail(index, "meta-flush-error", error)?
                }
            }
        }

        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn flush_meta_output(&mut self, index: usize) -> Result<(), TincdError> {
        let Some(connection) = self.meta_connections.get_mut(index) else {
            return Ok(());
        };
        connection.flush_meta_output().map_err(listen_io)
    }

    pub(crate) fn flush_meta_output_by_id(
        &mut self,
        id: u64,
    ) -> Result<RuntimeIoProgress, TincdError> {
        let Some(index) = self.connection_index_by_id(id) else {
            return Ok(RuntimeIoProgress::NotReady);
        };
        match self.meta_connections[index].flush_meta_output_once() {
            Ok(progress) => {
                if let Some(index) = self.connection_index_by_id(id)
                    && self.meta_connections[index].close_requested
                    && !self.meta_connections[index].has_pending_output()
                {
                    self.close_meta_connection_for_reason(
                        index,
                        "close-requested-after-flush-once",
                    )?;
                    return Ok(RuntimeIoProgress::Processed);
                }
                Ok(progress)
            }
            Err(error) => {
                self.close_meta_connection_with_detail(index, "meta-flush-once-error", error)?;
                Ok(RuntimeIoProgress::Processed)
            }
        }
    }
}

pub(crate) fn ping_timeout_duration(config: &RuntimeConfig) -> Duration {
    Duration::from_secs(config.daemon.ping_timeout.max(1) as u64)
}

#[cfg(target_os = "linux")]
fn socket_addr_from_storage(storage: &libc::sockaddr_storage) -> Option<SocketAddr> {
    match storage.ss_family as libc::c_int {
        libc::AF_INET => {
            let addr = unsafe { &*(storage as *const _ as *const libc::sockaddr_in) };
            Some(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::from(addr.sin_addr.s_addr.to_ne_bytes())),
                u16::from_be(addr.sin_port),
            ))
        }
        libc::AF_INET6 => {
            let addr = unsafe { &*(storage as *const _ as *const libc::sockaddr_in6) };
            Some(SocketAddr::V6(std::net::SocketAddrV6::new(
                Ipv6Addr::from(addr.sin6_addr.s6_addr),
                u16::from_be(addr.sin6_port),
                addr.sin6_flowinfo,
                addr.sin6_scope_id,
            )))
        }
        _ => None,
    }
}
