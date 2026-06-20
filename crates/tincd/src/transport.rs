use crate::*;

#[derive(Debug)]
pub struct RuntimeListenSocket {
    pub(crate) tcp: TcpListener,
    pub(crate) udp: UdpSocket,
    pub(crate) address: SocketAddr,
    pub(crate) bind_to: bool,
    pub(crate) priority: Cell<i32>,
}

impl RuntimeListenSocket {
    pub fn info(&self) -> RuntimeListenSocketInfo {
        RuntimeListenSocketInfo {
            address: self.address,
            bind_to: self.bind_to,
        }
    }

    pub fn tcp(&self) -> &TcpListener {
        &self.tcp
    }

    pub fn udp(&self) -> &UdpSocket {
        &self.udp
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RuntimeTopologyBackoff {
    pub(crate) contradicting_add_edge: u32,
    pub(crate) contradicting_del_edge: u32,
    pub(crate) delay: Duration,
    pub(crate) until: Option<Instant>,
}

impl Default for RuntimeTopologyBackoff {
    fn default() -> Self {
        Self {
            contradicting_add_edge: 0,
            contradicting_del_edge: 0,
            delay: TOPOLOGY_BACKOFF_MIN,
            until: None,
        }
    }
}

impl RuntimeTopologyBackoff {
    pub(crate) fn active(&self, now: Instant) -> bool {
        self.until.is_some_and(|deadline| now < deadline)
    }

    pub(crate) fn note_add_edge(&mut self) {
        self.contradicting_add_edge = self.contradicting_add_edge.saturating_add(1);
    }

    pub(crate) fn note_del_edge(&mut self) {
        self.contradicting_del_edge = self.contradicting_del_edge.saturating_add(1);
    }

    pub(crate) fn apply_periodic_check(&mut self, now: Instant) -> Option<Duration> {
        if self.active(now) {
            self.contradicting_add_edge = 0;
            self.contradicting_del_edge = 0;
            return None;
        }

        let should_backoff = self.contradicting_add_edge > TOPOLOGY_CONTRADICTION_LIMIT
            && self.contradicting_del_edge > TOPOLOGY_CONTRADICTION_LIMIT;

        self.contradicting_add_edge = 0;
        self.contradicting_del_edge = 0;

        if should_backoff {
            let delay = self.delay;
            self.until = Some(now + delay);
            self.delay = self
                .delay
                .checked_mul(2)
                .filter(|delay| *delay <= TOPOLOGY_BACKOFF_MAX)
                .unwrap_or(TOPOLOGY_BACKOFF_MAX);
            Some(delay)
        } else {
            self.until = None;
            self.delay = (self.delay / 2).max(TOPOLOGY_BACKOFF_MIN);
            None
        }
    }
}

pub(crate) struct RuntimeUdpPacketTransport<'a> {
    pub(crate) local_name: &'a str,
    pub(crate) sockets: &'a [RuntimeListenSocket],
    pub(crate) addresses: &'a NodeAddressTable,
    pub(crate) udp_socket_by_peer: &'a BTreeMap<String, usize>,
    pub(crate) modern_peer_keys: &'a BTreeMap<String, TincEd25519PublicKey>,
    pub(crate) meta_connections: &'a mut [RuntimeMetaConnection],
    pub(crate) experimental: bool,
    pub(crate) local_tcp_only: bool,
    pub(crate) max_output_buffer_size: usize,
    pub(crate) peer_options: BTreeMap<String, u32>,
    pub(crate) packet_codec: &'a mut SptpsPacketCodec,
    pub(crate) legacy_codec: &'a mut LegacyUdpCodec,
    pub(crate) udp_target_snapshots: BTreeMap<String, RuntimeUdpTargetSnapshot>,
    pub(crate) udp_unconfirmed_guess_counter: &'a mut usize,
    pub(crate) sptps_route_snapshots: BTreeMap<String, RuntimeSptpsRouteSnapshot>,
    pub(crate) legacy_key_snapshots: BTreeMap<String, RuntimeLegacyKeySnapshot>,
    pub(crate) legacy_last_req_key: &'a mut BTreeMap<String, Instant>,
    pub(crate) legacy_key_actions: &'a mut Vec<RuntimeLegacyKeyAction>,
    pub(crate) sptps_key_actions: &'a mut Vec<RuntimeSptpsKeyAction>,
    pub(crate) mtu_reductions: &'a mut Vec<(String, usize)>,
    pub(crate) legacy_nested_tx_targets: &'a mut Vec<String>,
    pub(crate) traffic: &'a mut BTreeMap<String, TrafficCounters>,
    pub(crate) pcap_subscribers: &'a mut Vec<RuntimeControlPcapSubscriber>,
    pub(crate) priority_inheritance: bool,
}

#[derive(Debug)]
pub(crate) struct RuntimeControlLogSubscriber {
    pub(crate) level: i32,
    pub(crate) colorize: bool,
    pub(crate) writer: RuntimeControlSubscriberWriter,
}

#[derive(Debug)]
pub(crate) struct RuntimeControlPcapSubscriber {
    pub(crate) snaplen: usize,
    pub(crate) writer: RuntimeControlSubscriberWriter,
}

#[derive(Debug)]
pub(crate) struct RuntimeControlSubscriberWriter {
    pub(crate) id: u64,
    pub(crate) stream: RuntimeControlSubscriberStream,
    pub(crate) outbound: Vec<u8>,
    pub(crate) outbound_offset: usize,
}

#[derive(Debug)]
pub(crate) enum RuntimeControlSubscriberStream {
    Tcp(TcpStream),
    #[cfg(unix)]
    Unix(std::os::unix::net::UnixStream),
}

impl RuntimeControlSubscriberStream {
    pub(crate) fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        match self {
            Self::Tcp(stream) => stream.set_nonblocking(nonblocking),
            #[cfg(unix)]
            Self::Unix(stream) => stream.set_nonblocking(nonblocking),
        }
    }

    pub(crate) fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        match self {
            Self::Tcp(stream) => stream.write(data),
            #[cfg(unix)]
            Self::Unix(stream) => stream.write(data),
        }
    }
}

#[cfg(unix)]
impl AsRawFd for RuntimeControlSubscriberStream {
    fn as_raw_fd(&self) -> RawFd {
        match self {
            Self::Tcp(stream) => stream.as_raw_fd(),
            Self::Unix(stream) => stream.as_raw_fd(),
        }
    }
}

impl RuntimeControlSubscriberWriter {
    pub(crate) fn new(id: u64, stream: RuntimeControlSubscriberStream) -> io::Result<Self> {
        stream.set_nonblocking(true)?;
        Ok(Self {
            id,
            stream,
            outbound: Vec::new(),
            outbound_offset: 0,
        })
    }

    pub(crate) fn has_pending_output(&self) -> bool {
        self.outbound_offset < self.outbound.len()
    }

    pub(crate) fn queue_payload(&mut self, request: i32, payload: &[u8]) {
        self.compact_outbound();
        let control = Request::Control.number();
        self.outbound
            .extend_from_slice(format!("{control} {request} {}\n", payload.len()).as_bytes());
        self.outbound.extend_from_slice(payload);
    }

    pub(crate) fn flush_once(&mut self) -> io::Result<RuntimeIoProgress> {
        if !self.has_pending_output() {
            return Ok(RuntimeIoProgress::NotReady);
        }

        match self.stream.write(&self.outbound[self.outbound_offset..]) {
            Ok(0) => Ok(RuntimeIoProgress::NotReady),
            Ok(len) => {
                self.outbound_offset += len;
                if !self.has_pending_output() {
                    self.outbound.clear();
                    self.outbound_offset = 0;
                }
                Ok(RuntimeIoProgress::Processed)
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                Ok(RuntimeIoProgress::NotReady)
            }
            Err(error) => Err(error),
        }
    }

    pub(crate) fn compact_outbound(&mut self) {
        if self.outbound_offset == 0 {
            return;
        }
        if self.outbound_offset >= self.outbound.len() {
            self.outbound.clear();
        } else {
            self.outbound.drain(..self.outbound_offset);
        }
        self.outbound_offset = 0;
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RuntimeLegacyKeySnapshot {
    pub(crate) reachable: bool,
    pub(crate) sptps: bool,
    pub(crate) valid_key: bool,
    pub(crate) valid_key_in: bool,
    pub(crate) next_hop: Option<String>,
    pub(crate) min_mtu: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RuntimeSptpsRouteSnapshot {
    pub(crate) next_hop: Option<String>,
    pub(crate) via: Option<String>,
    pub(crate) min_mtu: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SptpsTransportTargets {
    pub(crate) udp_relay: String,
    pub(crate) tcp_target: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum RuntimeLegacyKeyAction {
    SendAnswer { peer: String, next_hop: String },
    SendRequest { peer: String, next_hop: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RuntimeSptpsKeyAction {
    pub(crate) peer: String,
    pub(crate) next_hop: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct RuntimeUdpTargetSnapshot {
    pub(crate) latest: Option<SocketAddr>,
    pub(crate) udp_confirmed: bool,
    pub(crate) edge_candidates: Vec<Option<SocketAddr>>,
    pub(crate) local_candidates: Vec<Option<SocketAddr>>,
}

impl PacketTransport for RuntimeUdpPacketTransport<'_> {
    fn send_packet(&mut self, target: &str, packet: &VpnPacket) -> Result<(), TransportError> {
        self.send_packet_to(target, target, packet)
    }

    fn send_packet_to(
        &mut self,
        owner: &str,
        relay: &str,
        packet: &VpnPacket,
    ) -> Result<(), TransportError> {
        if self.sptps_direct_needs_plain_tcp_fallback(owner, packet) {
            self.send_tcp_packet(owner, packet)?;
            record_outbound_traffic(self.traffic, owner, packet.len());
            publish_control_pcap_packet(self.pcap_subscribers, &packet.data);
            return Ok(());
        }

        if self.packet_codec.peer(owner).is_some() {
            let packet_type = self
                .packet_codec
                .peer(owner)
                .map(|peer| peer.packet_type())
                .expect("peer checked above");
            let payload_len = sptps_payload_from_packet(packet_type, packet)?.len();
            let targets = self.sptps_transport_targets(owner, relay, payload_len, packet_type);

            if self.sptps_needs_tcp_fallback(owner, &targets.udp_relay, payload_len) {
                self.send_sptps_tcp_packet(owner, &targets.tcp_target, packet)?;
                record_outbound_traffic(self.traffic, owner, packet.len());
                publish_control_pcap_packet(self.pcap_subscribers, &packet.data);
                return Ok(());
            }

            let Some(address) = self.udp_target_for(&targets.udp_relay) else {
                return Err(TransportError::Io(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("unknown relay node {}", targets.udp_relay),
                )));
            };
            let Some(socket_index) = self.socket_index_for_peer(&targets.udp_relay, address) else {
                return Err(TransportError::Io(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "no UDP sockets are available",
                )));
            };
            let socket = &self.sockets[socket_index];

            let datagram = if owner == targets.udp_relay {
                self.packet_codec.encode_direct(owner, packet)?
            } else {
                self.packet_codec.encode_relayed(owner, packet)?
            };

            self.enqueue_legacy_key_actions(&targets.udp_relay);

            if self.priority_inheritance {
                set_udp_socket_priority(socket, address, packet.priority);
            }

            let sent = match socket.udp.send_to(&datagram, address) {
                Ok(sent) => sent,
                Err(error) if is_message_too_long(&error) => {
                    self.mtu_reductions
                        .push((targets.udp_relay.clone(), payload_len.saturating_sub(1)));
                    record_outbound_traffic(self.traffic, owner, packet.len());
                    publish_control_pcap_packet(self.pcap_subscribers, &packet.data);
                    return Ok(());
                }
                Err(error) => return Err(error.into()),
            };
            if sent != datagram.len() {
                return Err(TransportError::Io(io::Error::new(
                    io::ErrorKind::WriteZero,
                    format!("short datagram send: {sent} < {}", datagram.len()),
                )));
            }

            record_outbound_traffic(self.traffic, owner, packet.len());
            publish_control_pcap_packet(self.pcap_subscribers, &packet.data);

            return Ok(());
        }

        if self.should_send_tcp_packet(relay, packet) {
            self.send_tcp_packet(relay, packet)?;
            record_outbound_traffic(self.traffic, owner, packet.len());
            publish_control_pcap_packet(self.pcap_subscribers, &packet.data);
            return Ok(());
        }

        if self.legacy_peer_needs_tcp_fallback(relay) {
            let result = self.send_tcp_packet(relay, packet);
            self.enqueue_legacy_key_actions(relay);
            if result.is_ok() {
                record_outbound_traffic(self.traffic, owner, packet.len());
                publish_control_pcap_packet(self.pcap_subscribers, &packet.data);
            }
            return Ok(());
        }

        if let Some(next_hop) = self.legacy_peer_pmtu_fallback_next_hop(relay, packet) {
            if next_hop == relay {
                let result = self.send_tcp_packet(relay, packet);
                self.enqueue_legacy_key_actions(relay);
                if result.is_ok() {
                    record_outbound_traffic(self.traffic, owner, packet.len());
                    publish_control_pcap_packet(self.pcap_subscribers, &packet.data);
                }
                return Ok(());
            }

            if !self
                .legacy_nested_tx_targets
                .iter()
                .any(|queued| queued == &next_hop)
            {
                self.legacy_nested_tx_targets.push(next_hop.clone());
            }
            self.send_packet_to(&next_hop, &next_hop, packet)?;
            if owner != next_hop {
                record_outbound_traffic(self.traffic, owner, packet.len());
            }
            return Ok(());
        }

        let Some(address) = self.udp_target_for(relay) else {
            return Err(TransportError::Io(io::Error::new(
                io::ErrorKind::NotFound,
                format!("unknown relay node {relay}"),
            )));
        };
        let Some(socket_index) = self.socket_index_for_peer(relay, address) else {
            return Err(TransportError::Io(io::Error::new(
                io::ErrorKind::NotConnected,
                "no UDP sockets are available",
            )));
        };
        let socket = &self.sockets[socket_index];

        let datagram = if owner != relay && self.packet_codec.peer(relay).is_some() {
            self.enqueue_sptps_key_action(owner);
            self.packet_codec.encode_direct(relay, packet)?
        } else if owner != relay && self.legacy_codec.peer(relay).is_some() {
            self.enqueue_sptps_key_action(owner);
            self.legacy_codec.encode(relay, packet)?
        } else if self.legacy_codec.peer(owner).is_some() {
            if owner != relay {
                return Err(TransportError::Io(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("missing SPTPS session for relayed target {owner} via {relay}"),
                )));
            }
            self.legacy_codec.encode(owner, packet)?
        } else if self.modern_peer_keys.contains_key(owner) {
            self.enqueue_sptps_key_action(owner);
            return Err(secure_udp_session_missing(owner));
        } else if self.is_legacy_peer(relay) {
            return Err(TransportError::Io(io::Error::new(
                io::ErrorKind::NotFound,
                format!("missing legacy UDP key for relay {relay}"),
            )));
        } else {
            self.enqueue_sptps_key_action(owner);
            self.enqueue_sptps_key_action(relay);
            return Err(TransportError::Io(io::Error::new(
                io::ErrorKind::NetworkUnreachable,
                format!("missing secure UDP state for {owner} via {relay}"),
            )));
        };

        self.enqueue_legacy_key_actions(relay);

        if self.priority_inheritance {
            set_udp_socket_priority(socket, address, packet.priority);
        }

        let sent = match socket.udp.send_to(&datagram, address) {
            Ok(sent) => sent,
            Err(error) if is_message_too_long(&error) => {
                self.mtu_reductions
                    .push((relay.to_owned(), packet.len().saturating_sub(1)));
                record_outbound_traffic(self.traffic, owner, packet.len());
                publish_control_pcap_packet(self.pcap_subscribers, &packet.data);
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        };
        if sent != datagram.len() {
            return Err(TransportError::Io(io::Error::new(
                io::ErrorKind::WriteZero,
                format!("short datagram send: {sent} < {}", datagram.len()),
            )));
        }

        record_outbound_traffic(self.traffic, owner, packet.len());
        publish_control_pcap_packet(self.pcap_subscribers, &packet.data);

        Ok(())
    }
}

pub(crate) fn packet_has_nonzero_ethertype(packet: &VpnPacket) -> bool {
    packet
        .data
        .get(12)
        .zip(packet.data.get(13))
        .is_some_and(|(high, low)| (*high | *low) != 0)
}

impl RuntimeUdpTargetSnapshot {
    pub(crate) fn from_state(
        state: &NetworkState,
        addresses: &NodeAddressTable,
        peer: &str,
    ) -> Self {
        let node = state.graph.node(peer);
        let latest = node
            .and_then(|node| node.udp_address.as_ref())
            .and_then(edge_endpoint_socket_addr)
            .or_else(|| addresses.address(peer));
        let udp_confirmed = node.is_some_and(|node| node.status.udp_confirmed);
        let outgoing_edges = state
            .graph
            .edges()
            .filter(|edge| edge.from == peer)
            .cloned()
            .collect::<Vec<_>>();
        let edge_candidates = outgoing_edges
            .iter()
            .map(|edge| {
                state
                    .graph
                    .edge(&edge.to, &edge.from)
                    .and_then(|reverse| reverse.address.as_ref())
                    .and_then(edge_endpoint_socket_addr)
            })
            .collect();
        let local_candidates = outgoing_edges
            .iter()
            .map(|edge| {
                edge.local_address
                    .as_ref()
                    .and_then(edge_endpoint_socket_addr)
            })
            .collect();

        Self {
            latest,
            udp_confirmed,
            edge_candidates,
            local_candidates,
        }
    }

    pub(crate) fn choose_local_target(&self) -> Option<SocketAddr> {
        if self.local_candidates.is_empty() {
            return None;
        }

        self.local_candidates[prng_below(self.local_candidates.len())]
    }
}

pub(crate) fn choose_udp_target_from_snapshot(
    snapshot: &RuntimeUdpTargetSnapshot,
    unconfirmed_guess_counter: &mut usize,
) -> Option<SocketAddr> {
    if snapshot.udp_confirmed {
        return snapshot.latest;
    }

    *unconfirmed_guess_counter += 1;
    if *unconfirmed_guess_counter >= UDP_UNCONFIRMED_LATEST_GUESS_PERIOD {
        *unconfirmed_guess_counter = 0;
        return snapshot.latest;
    }

    if !snapshot.edge_candidates.is_empty() {
        if let Some(candidate) =
            snapshot.edge_candidates[prng_below(snapshot.edge_candidates.len())]
        {
            return Some(candidate);
        }
    }

    snapshot.latest
}

pub(crate) fn choose_sptps_transport_targets(
    local_name: &str,
    snapshots: &BTreeMap<String, RuntimeSptpsRouteSnapshot>,
    owner: &str,
    relay_hint: &str,
    payload_len: usize,
    static_via_probe: bool,
) -> SptpsTransportTargets {
    let tcp_target = snapshots
        .get(owner)
        .and_then(|snapshot| snapshot.next_hop.clone())
        .unwrap_or_else(|| relay_hint.to_owned());

    let udp_relay = snapshots
        .get(owner)
        .and_then(|snapshot| snapshot.via.as_deref())
        .filter(|via| *via != local_name)
        .and_then(|via| {
            snapshots
                .get(via)
                .filter(|via_snapshot| static_via_probe || payload_len <= via_snapshot.min_mtu)
                .map(|_| via.to_owned())
        })
        .unwrap_or_else(|| tcp_target.clone());

    SptpsTransportTargets {
        udp_relay,
        tcp_target,
    }
}

pub(crate) fn listen_socket_index_for(
    sockets: &[RuntimeListenSocket],
    target: SocketAddr,
) -> Option<usize> {
    sockets
        .iter()
        .position(|socket| socket.address.is_ipv4() == target.is_ipv4())
        .or(if sockets.is_empty() { None } else { Some(0) })
}

impl RuntimeUdpPacketTransport<'_> {
    fn active_meta_connection_index_for_peer(&self, peer: &str) -> Option<usize> {
        self.meta_connections
            .iter()
            .position(|connection| connection.is_current_edge_connection_for_peer(peer))
            .or_else(|| {
                self.meta_connections
                    .iter()
                    .position(|connection| connection.can_carry_data_for_peer(peer))
            })
    }

    pub(crate) fn should_send_tcp_packet(&self, target: &str, packet: &VpnPacket) -> bool {
        packet.priority == -1
            || self.local_tcp_only
            || self
                .peer_options
                .get(target)
                .is_some_and(|options| options & OPTION_TCPONLY != 0)
    }

    pub(crate) fn socket_index_for_peer(&self, peer: &str, target: SocketAddr) -> Option<usize> {
        self.udp_socket_by_peer
            .get(peer)
            .copied()
            .filter(|index| {
                self.sockets
                    .get(*index)
                    .is_some_and(|socket| socket.address.is_ipv4() == target.is_ipv4())
            })
            .or_else(|| listen_socket_index_for(self.sockets, target))
    }

    pub(crate) fn udp_target_for(&mut self, peer: &str) -> Option<SocketAddr> {
        self.udp_target_snapshots
            .get(peer)
            .and_then(|snapshot| {
                choose_udp_target_from_snapshot(snapshot, self.udp_unconfirmed_guess_counter)
            })
            .or_else(|| self.addresses.address(peer))
    }

    pub(crate) fn has_authenticated_meta_connection(&self, peer: &str) -> bool {
        self.active_meta_connection_index_for_peer(peer).is_some()
    }

    pub(crate) fn sptps_direct_needs_plain_tcp_fallback(
        &self,
        owner: &str,
        packet: &VpnPacket,
    ) -> bool {
        if !self.has_authenticated_meta_connection(owner) {
            return false;
        }

        self.legacy_key_snapshots
            .get(owner)
            .is_some_and(|snapshot| {
                snapshot.reachable && snapshot.sptps && packet.len() > snapshot.min_mtu
            })
    }

    pub(crate) fn sptps_needs_tcp_fallback(
        &self,
        owner: &str,
        relay: &str,
        payload_len: usize,
    ) -> bool {
        if self.packet_codec.peer(owner).is_none() {
            return false;
        }

        if self.local_tcp_only
            || self
                .peer_options
                .get(relay)
                .is_some_and(|options| options & OPTION_TCPONLY != 0)
        {
            return true;
        }

        if self
            .peer_options
            .get(relay)
            .is_some_and(|options| option_version(*options) < 4)
        {
            if relay == owner {
                return false;
            }
            return true;
        }

        self.sptps_route_snapshots
            .get(relay)
            .is_some_and(|snapshot| payload_len > snapshot.min_mtu)
    }

    pub(crate) fn sptps_transport_targets(
        &self,
        owner: &str,
        relay_hint: &str,
        payload_len: usize,
        packet_type: u8,
    ) -> SptpsTransportTargets {
        choose_sptps_transport_targets(
            self.local_name,
            &self.sptps_route_snapshots,
            owner,
            relay_hint,
            payload_len,
            packet_type == SPTPS_UDP_PROBE_TYPE,
        )
    }

    pub(crate) fn send_sptps_tcp_packet(
        &mut self,
        owner: &str,
        relay: &str,
        packet: &VpnPacket,
    ) -> Result<(), TransportError> {
        let datagram = self.packet_codec.encode_relayed(owner, packet)?;
        let Some(index) = self.active_meta_connection_index_for_peer(relay) else {
            return Ok(());
        };
        let connection = &mut self.meta_connections[index];

        if option_version(connection.options) >= 7 {
            if let Err(error) = send_sptps_tcp_packet_on_connection(
                connection,
                &datagram,
                self.max_output_buffer_size,
            ) {
                if mark_meta_connection_closed_on_scoped_error_like_tinc(connection, error)? {
                    return Ok(());
                }
            }
        } else {
            let record = RelayEnvelope::decode(&datagram)?.payload;
            let message = MetaMessage::RequestKey(RequestKeyMessage::sptps_tcp_packet(
                self.local_name,
                owner,
                &record,
            ));
            if let Err(error) = send_meta_message_on_connection(connection, &message) {
                if mark_meta_connection_closed_on_scoped_error_like_tinc(connection, error)? {
                    return Ok(());
                }
            }
        }
        Ok(())
    }

    pub(crate) fn send_tcp_packet(
        &mut self,
        target: &str,
        packet: &VpnPacket,
    ) -> Result<(), TransportError> {
        let Some(index) = self.active_meta_connection_index_for_peer(target) else {
            return Err(TransportError::Io(io::Error::new(
                io::ErrorKind::NotConnected,
                format!("no active meta connection to {target} for TCP packet fallback"),
            )));
        };
        let connection = &mut self.meta_connections[index];

        if let Err(error) = send_plain_tcp_packet_on_connection(
            connection,
            &packet.data,
            self.max_output_buffer_size,
        ) {
            if mark_meta_connection_closed_on_scoped_error_like_tinc(connection, error)? {
                return Ok(());
            }
        }
        Ok(())
    }

    pub(crate) fn is_legacy_peer(&self, peer: &str) -> bool {
        self.legacy_key_snapshots
            .get(peer)
            .is_some_and(|snapshot| self.is_runtime_legacy_peer(peer, snapshot))
    }

    pub(crate) fn legacy_peer_needs_tcp_fallback(&self, peer: &str) -> bool {
        self.legacy_key_snapshots.get(peer).is_some_and(|snapshot| {
            self.is_runtime_legacy_peer(peer, snapshot) && !snapshot.valid_key
        })
    }

    pub(crate) fn legacy_peer_pmtu_fallback_next_hop(
        &self,
        peer: &str,
        packet: &VpnPacket,
    ) -> Option<String> {
        let Some(snapshot) = self.legacy_key_snapshots.get(peer) else {
            return None;
        };
        if !self.is_runtime_legacy_peer(peer, snapshot)
            || !snapshot.valid_key
            || self.legacy_codec.peer(peer).is_none()
        {
            return None;
        }
        if self
            .peer_options
            .get(peer)
            .is_none_or(|options| options & OPTION_PMTU_DISCOVERY == 0)
        {
            return None;
        }
        if packet.len() <= snapshot.min_mtu || !packet_has_nonzero_ethertype(packet) {
            return None;
        }

        snapshot.next_hop.clone()
    }

    pub(crate) fn is_runtime_legacy_peer(
        &self,
        peer: &str,
        snapshot: &RuntimeLegacyKeySnapshot,
    ) -> bool {
        snapshot.reachable
            && !snapshot.sptps
            && self.packet_codec.peer(peer).is_none()
            && !self.experimental
    }

    pub(crate) fn enqueue_sptps_key_action(&mut self, peer: &str) {
        if !self.experimental || self.packet_codec.peer(peer).is_some() {
            return;
        }
        let Some(snapshot) = self.legacy_key_snapshots.get(peer) else {
            return;
        };
        if !snapshot.reachable || !snapshot.sptps {
            return;
        }
        let Some(next_hop) = snapshot.next_hop.as_ref() else {
            return;
        };
        if self
            .sptps_key_actions
            .iter()
            .any(|action| action.peer == peer)
        {
            return;
        }

        self.sptps_key_actions.push(RuntimeSptpsKeyAction {
            peer: peer.to_owned(),
            next_hop: next_hop.clone(),
        });
    }

    pub(crate) fn enqueue_legacy_key_actions(&mut self, peer: &str) {
        let Some(snapshot) = self.legacy_key_snapshots.get(peer).cloned() else {
            return;
        };
        if !self.is_runtime_legacy_peer(peer, &snapshot) {
            return;
        }
        let Some(next_hop) = snapshot.next_hop else {
            return;
        };

        if !snapshot.valid_key_in
            && !self.legacy_key_actions.iter().any(|action| {
                matches!(action, RuntimeLegacyKeyAction::SendAnswer { peer: queued, .. } if queued == peer)
            })
        {
            self.legacy_key_actions
                .push(RuntimeLegacyKeyAction::SendAnswer {
                    peer: peer.to_owned(),
                    next_hop: next_hop.clone(),
                });
        }

        if !snapshot.valid_key
            && self.legacy_req_key_due(peer)
            && !self.legacy_key_actions.iter().any(|action| {
                matches!(action, RuntimeLegacyKeyAction::SendRequest { peer: queued, .. } if queued == peer)
            })
        {
            self.legacy_last_req_key
                .insert(peer.to_owned(), Instant::now());
            self.legacy_key_actions
                .push(RuntimeLegacyKeyAction::SendRequest {
                    peer: peer.to_owned(),
                    next_hop,
                });
        }
    }

    pub(crate) fn legacy_req_key_due(&self, peer: &str) -> bool {
        self.legacy_last_req_key
            .get(peer)
            .is_none_or(|sent| sent.elapsed() >= LEGACY_REQ_KEY_INTERVAL)
    }
}
