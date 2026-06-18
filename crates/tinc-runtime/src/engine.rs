// SPDX-License-Identifier: GPL-2.0-or-later

use std::fmt;
use std::io;

use tinc_core::route::{
    ForwardingMode, PacketAction, RouteConfig, RouteDropReason, RoutingMode, route_packet_action,
};
use tinc_core::state::NetworkState;
use tinc_core::subnet::Subnet;

use crate::device::{Device, DeviceError, VpnPacket};

pub trait PacketTransport {
    fn send_packet(&mut self, target: &str, packet: &VpnPacket) -> Result<(), TransportError>;

    fn send_packet_to(
        &mut self,
        owner: &str,
        relay: &str,
        packet: &VpnPacket,
    ) -> Result<(), TransportError> {
        let _ = owner;
        self.send_packet(relay, packet)
    }
}

pub trait PacketReceiver {
    fn receive_packet(&mut self) -> Result<Option<(String, VpnPacket)>, TransportError>;
}

#[derive(Debug)]
pub enum TransportError {
    Io(io::Error),
}

impl Clone for TransportError {
    fn clone(&self) -> Self {
        match self {
            Self::Io(error) => Self::Io(io::Error::new(error.kind(), error.to_string())),
        }
    }
}

impl PartialEq for TransportError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Io(left), Self::Io(right)) => {
                left.kind() == right.kind() && left.to_string() == right.to_string()
            }
        }
    }
}

impl Eq for TransportError {}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for TransportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
        }
    }
}

impl From<io::Error> for TransportError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

#[derive(Debug)]
pub enum EngineError {
    Device(DeviceError),
    Transport(TransportError),
    Packet(DeviceError),
}

impl Clone for EngineError {
    fn clone(&self) -> Self {
        match self {
            Self::Device(error) => Self::Device(error.clone()),
            Self::Transport(error) => Self::Transport(error.clone()),
            Self::Packet(error) => Self::Packet(error.clone()),
        }
    }
}

impl PartialEq for EngineError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Device(left), Self::Device(right))
            | (Self::Packet(left), Self::Packet(right)) => left == right,
            (Self::Transport(left), Self::Transport(right)) => left == right,
            _ => false,
        }
    }
}

impl Eq for EngineError {}

impl fmt::Display for EngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Device(error) => write!(f, "device error: {error}"),
            Self::Transport(error) => write!(f, "transport error: {error}"),
            Self::Packet(error) => write!(f, "packet error: {error}"),
        }
    }
}

impl std::error::Error for EngineError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Device(error) | Self::Packet(error) => Some(error),
            Self::Transport(error) => Some(error),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EngineConfig {
    pub route: RouteConfig,
    pub broadcast: BroadcastMode,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            route: RouteConfig::default(),
            broadcast: BroadcastMode::Mst,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BroadcastMode {
    None,
    Direct,
    Mst,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EngineStep {
    pub input: Option<EngineInput>,
    pub events: Vec<EngineEvent>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EngineInput {
    Device,
    Network { source: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EngineEvent {
    DeviceWrite {
        packet: VpnPacket,
    },
    TransportSend {
        owner: String,
        target: String,
        packet: VpnPacket,
        forced_tcp: bool,
    },
    TransportDeferred {
        owner: String,
        target: String,
        packet: VpnPacket,
        forced_tcp: bool,
    },
    Broadcast {
        targets: Vec<String>,
        packet: VpnPacket,
    },
    Drop {
        reason: RouteDropReason,
    },
    LearnedSubnet {
        subnet: Subnet,
    },
    NoDevicePacket,
    NoNetworkPacket,
}

pub struct RuntimeEngine<D, T> {
    pub state: NetworkState,
    pub device: D,
    pub transport: T,
    pub config: EngineConfig,
}

impl<D, T> RuntimeEngine<D, T> {
    pub fn new(state: NetworkState, device: D, transport: T, config: EngineConfig) -> Self {
        Self {
            state,
            device,
            transport,
            config,
        }
    }
}

impl<D: Device, T: PacketTransport> RuntimeEngine<D, T> {
    pub fn poll_device_once(&mut self) -> Result<EngineStep, EngineError> {
        let Some(packet) = self.device.read_packet().map_err(EngineError::Device)? else {
            return Ok(EngineStep {
                input: Some(EngineInput::Device),
                events: vec![EngineEvent::NoDevicePacket],
            });
        };

        self.handle_device_packet(packet)
    }

    pub fn handle_device_packet(&mut self, packet: VpnPacket) -> Result<EngineStep, EngineError> {
        let source = self.state.graph.myself().to_owned();
        let events = route_and_execute(
            &mut self.state,
            &mut self.device,
            &mut self.transport,
            &self.config,
            &source,
            packet,
        )?;

        Ok(EngineStep {
            input: Some(EngineInput::Device),
            events,
        })
    }

    pub fn handle_network_packet(
        &mut self,
        source: &str,
        packet: VpnPacket,
    ) -> Result<EngineStep, EngineError> {
        let events = route_and_execute(
            &mut self.state,
            &mut self.device,
            &mut self.transport,
            &self.config,
            source,
            packet,
        )?;

        Ok(EngineStep {
            input: Some(EngineInput::Network {
                source: source.to_owned(),
            }),
            events,
        })
    }
}

impl<D: Device, T: PacketTransport + PacketReceiver> RuntimeEngine<D, T> {
    pub fn poll_network_once(&mut self) -> Result<EngineStep, EngineError> {
        let Some((source, packet)) = self
            .transport
            .receive_packet()
            .map_err(EngineError::Transport)?
        else {
            return Ok(EngineStep {
                input: None,
                events: vec![EngineEvent::NoNetworkPacket],
            });
        };

        self.handle_network_packet(&source, packet)
    }
}

pub fn handle_device_packet_with<D: Device, T: PacketTransport>(
    state: &mut NetworkState,
    device: &mut D,
    transport: &mut T,
    config: &EngineConfig,
    packet: VpnPacket,
) -> Result<Vec<EngineEvent>, EngineError> {
    let source = state.graph.myself().to_owned();
    route_and_execute(state, device, transport, config, &source, packet)
}

pub fn handle_network_packet_with<D: Device, T: PacketTransport>(
    state: &mut NetworkState,
    device: &mut D,
    transport: &mut T,
    config: &EngineConfig,
    source: &str,
    packet: VpnPacket,
) -> Result<Vec<EngineEvent>, EngineError> {
    route_and_execute(state, device, transport, config, source, packet)
}

fn route_and_execute<D: Device, T: PacketTransport>(
    state: &mut NetworkState,
    device: &mut D,
    transport: &mut T,
    config: &EngineConfig,
    source: &str,
    packet: VpnPacket,
) -> Result<Vec<EngineEvent>, EngineError> {
    let base_priority = packet.priority;
    let routed = route_packet_action(state, source, &packet.data, config.route);
    let mut events = execute_action(
        state,
        device,
        transport,
        config,
        source,
        routed.action,
        base_priority,
    )?;
    events.extend(
        routed
            .outcome
            .learned
            .into_iter()
            .map(|subnet| EngineEvent::LearnedSubnet { subnet }),
    );
    Ok(events)
}

fn execute_action<D: Device, T: PacketTransport>(
    state: &NetworkState,
    device: &mut D,
    transport: &mut T,
    config: &EngineConfig,
    source: &str,
    action: PacketAction,
    base_priority: i32,
) -> Result<Vec<EngineEvent>, EngineError> {
    match action {
        PacketAction::Send {
            owner,
            via,
            packet,
            priority,
            mss_clamp: _,
        } => send_to_owner(
            state,
            device,
            transport,
            owner,
            via,
            packet,
            priority.unwrap_or(base_priority),
        ),
        PacketAction::SendFragments {
            owner,
            via,
            fragments,
            priority,
        } => {
            let mut events = Vec::new();
            let priority = priority.unwrap_or(base_priority);

            for fragment in fragments {
                events.extend(send_to_owner(
                    state,
                    device,
                    transport,
                    owner.clone(),
                    via.clone(),
                    fragment,
                    priority,
                )?);
            }

            Ok(events)
        }
        PacketAction::Reply {
            target,
            packet,
            priority,
        } => send_to_owner(
            state,
            device,
            transport,
            target,
            None,
            packet,
            priority.unwrap_or(base_priority),
        ),
        PacketAction::Broadcast { packet } => broadcast_packet(
            state,
            device,
            transport,
            config,
            source,
            packet,
            base_priority,
        ),
        PacketAction::DeliverLocal { packet } => {
            write_device(device, packet, base_priority).map(|event| vec![event])
        }
        PacketAction::Drop(reason) => Ok(vec![EngineEvent::Drop { reason }]),
    }
}

fn send_to_owner<D: Device, T: PacketTransport>(
    state: &NetworkState,
    device: &mut D,
    transport: &mut T,
    owner: String,
    via: Option<String>,
    packet: Vec<u8>,
    priority: i32,
) -> Result<Vec<EngineEvent>, EngineError> {
    if owner == state.graph.myself() {
        return write_device(device, packet, priority).map(|event| vec![event]);
    }

    let relay = via.unwrap_or_else(|| owner.clone());
    let packet = VpnPacket::new(packet)
        .map_err(EngineError::Packet)?
        .with_priority(priority);
    if let Err(error) = transport.send_packet_to(&owner, &relay, &packet) {
        if matches!(
            &error,
            TransportError::Io(io_error)
                if matches!(
                    io_error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::NetworkUnreachable
                )
        ) {
            return Ok(vec![EngineEvent::TransportDeferred {
                owner,
                target: relay,
                packet,
                forced_tcp: priority == -1,
            }]);
        }

        return Err(EngineError::Transport(error));
    }

    Ok(vec![EngineEvent::TransportSend {
        owner,
        target: relay,
        packet,
        forced_tcp: priority == -1,
    }])
}

fn write_device<D: Device>(
    device: &mut D,
    packet: Vec<u8>,
    priority: i32,
) -> Result<EngineEvent, EngineError> {
    let packet = VpnPacket::new(packet)
        .map_err(EngineError::Packet)?
        .with_priority(priority);
    device.write_packet(&packet).map_err(EngineError::Device)?;
    Ok(EngineEvent::DeviceWrite { packet })
}

fn broadcast_packet<D: Device, T: PacketTransport>(
    state: &NetworkState,
    device: &mut D,
    transport: &mut T,
    config: &EngineConfig,
    source: &str,
    packet: Vec<u8>,
    priority: i32,
) -> Result<Vec<EngineEvent>, EngineError> {
    let mut events = Vec::new();

    if source != state.graph.myself() {
        events.push(write_device(device, packet.clone(), priority)?);
    }

    if config.broadcast == BroadcastMode::None {
        return Ok(events);
    }

    if source != state.graph.myself()
        && (config.broadcast == BroadcastMode::Direct || config.route.direct_only)
    {
        return Ok(events);
    }

    let targets = broadcast_targets(state, source, config.broadcast, config.route.direct_only);
    let vpn_packet = VpnPacket::new(packet)
        .map_err(EngineError::Packet)?
        .with_priority(priority);

    let mut sent_targets = Vec::new();

    for target in targets {
        if transport.send_packet(&target, &vpn_packet).is_ok() {
            sent_targets.push(target);
        }
    }

    if !sent_targets.is_empty() {
        events.push(EngineEvent::Broadcast {
            targets: sent_targets,
            packet: vpn_packet,
        });
    }

    Ok(events)
}

fn broadcast_targets(
    state: &NetworkState,
    source: &str,
    mode: BroadcastMode,
    direct_only: bool,
) -> Vec<String> {
    let myself = state.graph.myself();
    let source_next_hop = state
        .graph
        .node(source)
        .and_then(|node| node.route.next_hop.as_deref());
    let mut targets = Vec::new();

    if mode == BroadcastMode::Mst {
        for target in state.graph.mst_neighbors(myself) {
            if Some(target.as_str()) == source_next_hop {
                continue;
            }
            if state.graph.node(&target).is_some_and(|node| {
                node.status.reachable
                    && (!direct_only || node.route.next_hop.as_deref() == Some(node.name.as_str()))
            }) {
                targets.push(target);
            }
        }
        return targets;
    }

    for node in state.graph.nodes() {
        if node.name == myself || node.name == source || !node.status.reachable {
            continue;
        }

        match mode {
            BroadcastMode::None => {}
            BroadcastMode::Direct => {
                if node.route.next_hop.as_deref() == Some(node.name.as_str()) {
                    targets.push(node.name.clone());
                }
            }
            BroadcastMode::Mst => unreachable!("MST broadcast returns before scanning route nodes"),
        }
    }

    targets
}

#[allow(dead_code)]
fn _route_config_for_kernel_forwarding() -> RouteConfig {
    RouteConfig {
        forwarding_mode: ForwardingMode::Kernel,
        routing_mode: RoutingMode::Router,
        ..RouteConfig::default()
    }
}

#[cfg(test)]
mod tests {
    use tinc_core::protocol::parse_meta_message;
    use tinc_core::route::{ETH_HLEN, ETH_P_IP, ETH_P_IPV6, ethernet_packet};
    use tinc_core::state::NetworkState;
    use tinc_core::subnet::MacAddr;

    use super::*;
    use crate::device::MemoryDevice;
    use crate::transport::{
        DatagramTransport, MemoryDatagramIo, NodeAddressTable, PlainPacketCodec,
    };

    #[derive(Clone, Debug, Default, Eq, PartialEq)]
    struct MemoryTransport {
        sends: Vec<(String, VpnPacket)>,
    }

    impl PacketTransport for MemoryTransport {
        fn send_packet(&mut self, target: &str, packet: &VpnPacket) -> Result<(), TransportError> {
            self.sends.push((target.to_owned(), packet.clone()));
            Ok(())
        }
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct SelectiveFailTransport {
        fail: String,
        sends: Vec<(String, VpnPacket)>,
    }

    impl PacketTransport for SelectiveFailTransport {
        fn send_packet(&mut self, target: &str, packet: &VpnPacket) -> Result<(), TransportError> {
            if target == self.fail {
                return Err(TransportError::Io(std::io::Error::new(
                    std::io::ErrorKind::NetworkUnreachable,
                    "network unreachable",
                )));
            }
            self.sends.push((target.to_owned(), packet.clone()));
            Ok(())
        }
    }

    fn mac(last: u8) -> MacAddr {
        MacAddr::new([0x02, 0, 0, 0, 0, last])
    }

    fn ipv4_packet(destination: [u8; 4]) -> VpnPacket {
        let mut payload = vec![0; 20];
        payload[0] = 0x45;
        payload[2..4].copy_from_slice(&20u16.to_be_bytes());
        payload[8] = 64;
        payload[9] = 17;
        payload[12..16].copy_from_slice(&[192, 0, 2, 1]);
        payload[16..20].copy_from_slice(&destination);
        VpnPacket::new(ethernet_packet(mac(2), mac(1), ETH_P_IP, &payload)).unwrap()
    }

    fn ipv6_packet(destination: [u8; 16]) -> VpnPacket {
        let mut payload = vec![0; 40];
        payload[0] = 0x60;
        payload[6] = 17;
        payload[7] = 64;
        payload[8..24].copy_from_slice(&[0; 16]);
        payload[24..40].copy_from_slice(&destination);
        VpnPacket::new(ethernet_packet(mac(2), mac(1), ETH_P_IPV6, &payload)).unwrap()
    }

    fn routed_state() -> NetworkState {
        let mut state = NetworkState::new("myself");
        state
            .apply_meta_message(
                parse_meta_message("12 1 myself alpha 203.0.113.1 655 0 1").unwrap(),
            )
            .unwrap();
        state
            .apply_meta_message(
                parse_meta_message("12 2 alpha myself 203.0.113.2 655 0 1").unwrap(),
            )
            .unwrap();
        state
            .apply_meta_message(parse_meta_message("10 3 alpha 10.0.0.0/24").unwrap())
            .unwrap();
        state
    }

    fn routed_ipv6_state() -> NetworkState {
        let mut state = routed_state();
        state
            .apply_meta_message(parse_meta_message("10 4 alpha 2001:db8::/32").unwrap())
            .unwrap();
        state
    }

    fn mst_ring_state() -> NetworkState {
        let mut state = NetworkState::new("myself");

        for node in ["alpha", "beta", "gamma"] {
            state.graph.ensure_node(node);
        }

        state
            .graph
            .connect_bidirectional("myself", "alpha", 1)
            .unwrap();
        state
            .graph
            .connect_bidirectional("alpha", "beta", 1)
            .unwrap();
        state
            .graph
            .connect_bidirectional("beta", "gamma", 1)
            .unwrap();
        state
            .graph
            .connect_bidirectional("gamma", "myself", 50)
            .unwrap();
        state.recompute_routes();

        state
    }

    fn engine_with_state(state: NetworkState) -> RuntimeEngine<MemoryDevice, MemoryTransport> {
        RuntimeEngine::new(
            state,
            MemoryDevice::new([]),
            MemoryTransport::default(),
            EngineConfig::default(),
        )
    }

    fn datagram_engine_with_state(
        state: NetworkState,
        io: MemoryDatagramIo,
    ) -> RuntimeEngine<MemoryDevice, DatagramTransport<MemoryDatagramIo, PlainPacketCodec>> {
        let mut addresses = NodeAddressTable::new();
        addresses.insert("alpha", "127.0.0.1:655".parse().unwrap());

        RuntimeEngine::new(
            state,
            MemoryDevice::new([]),
            DatagramTransport::new(io, PlainPacketCodec, addresses),
            EngineConfig::default(),
        )
    }

    #[test]
    fn device_packet_for_remote_owner_is_sent_to_transport() {
        tinc_test_support::assert_can_create_netns();
        let mut engine = engine_with_state(routed_state());
        let packet = ipv4_packet([10, 0, 0, 42]);

        let step = engine.handle_device_packet(packet.clone()).unwrap();

        assert_eq!(Some(EngineInput::Device), step.input);
        assert_eq!(1, engine.transport.sends.len());
        assert_eq!("alpha", engine.transport.sends[0].0);
        assert_eq!(packet, engine.transport.sends[0].1);
        assert_eq!(
            vec![EngineEvent::TransportSend {
                owner: "alpha".to_owned(),
                target: "alpha".to_owned(),
                packet,
                forced_tcp: false,
            }],
            step.events
        );
    }

    #[test]
    fn failed_transport_attempt_is_deferred_so_daemon_can_continue_try_tx_like_tinc() {
        tinc_test_support::assert_can_create_netns();
        let state = routed_state();
        let mut engine = RuntimeEngine::new(
            state,
            MemoryDevice::new([]),
            SelectiveFailTransport {
                fail: "alpha".to_owned(),
                sends: Vec::new(),
            },
            EngineConfig::default(),
        );
        let packet = ipv4_packet([10, 0, 0, 42]);

        let step = engine.handle_device_packet(packet.clone()).unwrap();

        assert!(engine.transport.sends.is_empty());
        assert_eq!(
            vec![EngineEvent::TransportDeferred {
                owner: "alpha".to_owned(),
                target: "alpha".to_owned(),
                packet,
                forced_tcp: false,
            }],
            step.events,
            "C send_packet() still runs try_tx() after send_sptps_packet()/send_udppacket() cannot send immediately"
        );
    }

    #[test]
    fn device_packet_inherits_ipv4_priority_when_enabled_like_tinc() {
        tinc_test_support::assert_can_create_netns();
        let mut engine = engine_with_state(routed_state());
        engine.config.route.priority_inheritance = true;
        let mut packet = ipv4_packet([10, 0, 0, 42]);
        packet.data[ETH_HLEN + 1] = 0x2e;

        let step = engine.handle_device_packet(packet.clone()).unwrap();

        assert_eq!(1, engine.transport.sends.len());
        assert_eq!(0x2e, engine.transport.sends[0].1.priority);
        assert_eq!(
            vec![EngineEvent::TransportSend {
                owner: "alpha".to_owned(),
                target: "alpha".to_owned(),
                packet: packet.with_priority(0x2e),
                forced_tcp: false,
            }],
            step.events
        );
    }

    #[test]
    fn device_packet_inherits_ipv6_priority_when_enabled_like_tinc() {
        tinc_test_support::assert_can_create_netns();
        let mut engine = engine_with_state(routed_ipv6_state());
        engine.config.route.priority_inheritance = true;
        let mut packet = ipv6_packet(0x20010db8000000000000000000000001u128.to_be_bytes());
        packet.data[ETH_HLEN] = 0x6a;
        packet.data[ETH_HLEN + 1] = 0xb0;

        let step = engine.handle_device_packet(packet.clone()).unwrap();

        assert_eq!(1, engine.transport.sends.len());
        assert_eq!(0xab, engine.transport.sends[0].1.priority);
        assert_eq!(
            vec![EngineEvent::TransportSend {
                owner: "alpha".to_owned(),
                target: "alpha".to_owned(),
                packet: packet.with_priority(0xab),
                forced_tcp: false,
            }],
            step.events
        );
    }

    #[test]
    fn switch_packet_inherits_inner_ip_priority_like_tinc() {
        tinc_test_support::assert_can_create_netns();
        let mut state = routed_state();
        state
            .apply_meta_message(parse_meta_message("10 5 alpha 02:00:00:00:00:09").unwrap())
            .unwrap();
        let mut engine = engine_with_state(state);
        engine.config.route.routing_mode = RoutingMode::Switch;
        engine.config.route.priority_inheritance = true;
        let mut packet = ipv4_packet([10, 0, 0, 42]);
        packet.data[0..6].copy_from_slice(&mac(9).octets());
        packet.data[ETH_HLEN + 1] = 0xb8;

        let step = engine.handle_device_packet(packet.clone()).unwrap();

        assert_eq!(1, engine.transport.sends.len());
        assert_eq!(0xb8, engine.transport.sends[0].1.priority);
        assert!(matches!(
            step.events.as_slice(),
            [
                EngineEvent::TransportSend { owner, target, packet: sent, forced_tcp },
                EngineEvent::LearnedSubnet { .. },
            ] if owner == "alpha" && target == "alpha" && sent == &packet.with_priority(0xb8) && !forced_tcp
        ));
    }

    #[test]
    fn network_packet_for_myself_is_written_to_device() {
        tinc_test_support::assert_can_create_netns();
        let mut state = routed_state();
        state
            .apply_meta_message(parse_meta_message("10 4 myself 10.1.0.0/16").unwrap())
            .unwrap();
        let mut engine = engine_with_state(state);
        let packet = ipv4_packet([10, 1, 0, 42]);

        let step = engine
            .handle_network_packet("alpha", packet.clone())
            .unwrap();

        assert_eq!(
            Some(EngineInput::Network {
                source: "alpha".to_owned()
            }),
            step.input
        );
        assert_eq!(vec![packet.clone()], engine.device.writes());
        assert_eq!(vec![EngineEvent::DeviceWrite { packet }], step.events);
    }

    #[test]
    fn poll_device_once_routes_next_device_packet() {
        tinc_test_support::assert_can_create_netns();
        let packet = ipv4_packet([10, 0, 0, 42]);
        let mut engine = RuntimeEngine::new(
            routed_state(),
            MemoryDevice::new([packet.clone()]),
            MemoryTransport::default(),
            EngineConfig::default(),
        );

        let step = engine.poll_device_once().unwrap();
        assert_eq!(
            vec![EngineEvent::TransportSend {
                owner: "alpha".to_owned(),
                target: "alpha".to_owned(),
                packet,
                forced_tcp: false,
            }],
            step.events
        );

        let step = engine.poll_device_once().unwrap();
        assert_eq!(vec![EngineEvent::NoDevicePacket], step.events);
    }

    #[test]
    fn poll_network_once_routes_received_datagram_packet() {
        tinc_test_support::assert_can_create_netns();
        let mut state = routed_state();
        state
            .apply_meta_message(parse_meta_message("10 4 myself 10.1.0.0/16").unwrap())
            .unwrap();
        let packet = ipv4_packet([10, 1, 0, 42]);
        let mut io = MemoryDatagramIo::new();
        io.push_incoming("127.0.0.1:655".parse().unwrap(), packet.data.clone());
        let mut engine = datagram_engine_with_state(state, io);

        let step = engine.poll_network_once().unwrap();

        assert_eq!(
            Some(EngineInput::Network {
                source: "alpha".to_owned(),
            }),
            step.input
        );
        assert_eq!(vec![packet.clone()], engine.device.writes());
        assert_eq!(vec![EngineEvent::DeviceWrite { packet }], step.events);
    }

    #[test]
    fn poll_network_once_reports_empty_datagram_source() {
        tinc_test_support::assert_can_create_netns();
        let mut engine = datagram_engine_with_state(routed_state(), MemoryDatagramIo::new());

        let step = engine.poll_network_once().unwrap();

        assert_eq!(None, step.input);
        assert_eq!(vec![EngineEvent::NoNetworkPacket], step.events);
    }

    #[test]
    fn poll_network_once_reports_unknown_datagram_source_as_transport_error() {
        tinc_test_support::assert_can_create_netns();
        let mut io = MemoryDatagramIo::new();
        io.push_incoming(
            "127.0.0.1:999".parse().unwrap(),
            ipv4_packet([10, 0, 0, 42]).data,
        );
        let mut engine = datagram_engine_with_state(routed_state(), io);

        assert!(matches!(
            engine.poll_network_once(),
            Err(EngineError::Transport(TransportError::Io(_)))
        ));
    }

    #[test]
    fn unknown_destination_generates_transport_reply_for_remote_source() {
        tinc_test_support::assert_can_create_netns();
        let mut engine = engine_with_state(routed_state());
        let packet = ipv4_packet([203, 0, 113, 99]);

        let step = engine.handle_network_packet("alpha", packet).unwrap();

        assert!(engine.device.writes().is_empty());
        assert_eq!(1, engine.transport.sends.len());
        assert_eq!("alpha", engine.transport.sends[0].0);
        assert!(engine.transport.sends[0].1.data.len() > ETH_HLEN);
        assert!(matches!(
            step.events.as_slice(),
            [EngineEvent::TransportSend { owner, target, .. }] if owner == "alpha" && target == "alpha"
        ));
    }

    #[test]
    fn local_broadcast_is_sent_to_reachable_remote_nodes() {
        tinc_test_support::assert_can_create_netns();
        let mut state = routed_state();
        state
            .apply_meta_message(parse_meta_message("12 4 myself beta 203.0.113.3 655 0 1").unwrap())
            .unwrap();
        state
            .apply_meta_message(parse_meta_message("12 5 beta myself 203.0.113.4 655 0 1").unwrap())
            .unwrap();
        let mut engine = engine_with_state(state);
        engine.config.route.routing_mode = RoutingMode::Hub;
        let packet = ipv4_packet([255, 255, 255, 255]);

        let step = engine.handle_device_packet(packet.clone()).unwrap();

        assert_eq!(2, engine.transport.sends.len());
        assert_eq!(
            vec!["alpha".to_owned(), "beta".to_owned()],
            engine
                .transport
                .sends
                .iter()
                .map(|(target, _)| target.clone())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            vec![EngineEvent::Broadcast {
                targets: vec!["alpha".to_owned(), "beta".to_owned()],
                packet,
            }],
            step.events
        );
    }

    #[test]
    fn mst_broadcast_uses_tree_neighbors_not_all_route_next_hops() {
        tinc_test_support::assert_can_create_netns();
        let mut engine = engine_with_state(mst_ring_state());
        engine.config.route.routing_mode = RoutingMode::Hub;
        let packet = ipv4_packet([255, 255, 255, 255]);

        let step = engine.handle_device_packet(packet.clone()).unwrap();

        assert_eq!(
            vec![("alpha".to_owned(), packet.clone())],
            engine.transport.sends
        );
        assert_eq!(
            vec![EngineEvent::Broadcast {
                targets: vec!["alpha".to_owned()],
                packet,
            }],
            step.events
        );
    }

    #[test]
    fn remote_mst_broadcast_excludes_edge_toward_source() {
        tinc_test_support::assert_can_create_netns();
        let mut engine = engine_with_state(mst_ring_state());
        engine.config.route.routing_mode = RoutingMode::Hub;
        let packet = ipv4_packet([255, 255, 255, 255]);

        let step = engine
            .handle_network_packet("alpha", packet.clone())
            .unwrap();

        assert_eq!(vec![packet.clone()], engine.device.writes());
        assert!(engine.transport.sends.is_empty());
        assert_eq!(vec![EngineEvent::DeviceWrite { packet }], step.events);
    }

    #[test]
    fn broadcast_skips_transport_errors_for_individual_targets() {
        tinc_test_support::assert_can_create_netns();
        let mut state = routed_state();
        state
            .apply_meta_message(parse_meta_message("12 4 myself beta 203.0.113.3 655 0 1").unwrap())
            .unwrap();
        state
            .apply_meta_message(parse_meta_message("12 5 beta myself 203.0.113.4 655 0 1").unwrap())
            .unwrap();
        let packet = ipv4_packet([255, 255, 255, 255]);
        let mut engine = RuntimeEngine::new(
            state,
            MemoryDevice::new([]),
            SelectiveFailTransport {
                fail: "alpha".to_owned(),
                sends: Vec::new(),
            },
            EngineConfig::default(),
        );
        engine.config.route.routing_mode = RoutingMode::Hub;

        let step = engine.handle_device_packet(packet.clone()).unwrap();

        assert_eq!(
            vec![("beta".to_owned(), packet.clone())],
            engine.transport.sends
        );
        assert_eq!(
            vec![EngineEvent::Broadcast {
                targets: vec!["beta".to_owned()],
                packet,
            }],
            step.events
        );
    }

    #[test]
    fn remote_broadcast_writes_local_copy_and_forwards_to_other_nodes() {
        tinc_test_support::assert_can_create_netns();
        let mut state = routed_state();
        state
            .apply_meta_message(parse_meta_message("12 4 myself beta 203.0.113.3 655 0 1").unwrap())
            .unwrap();
        state
            .apply_meta_message(parse_meta_message("12 5 beta myself 203.0.113.4 655 0 1").unwrap())
            .unwrap();
        let mut engine = engine_with_state(state);
        engine.config.route.routing_mode = RoutingMode::Hub;
        let packet = ipv4_packet([255, 255, 255, 255]);

        let step = engine
            .handle_network_packet("alpha", packet.clone())
            .unwrap();

        assert_eq!(vec![packet.clone()], engine.device.writes());
        assert_eq!(
            vec![("beta".to_owned(), packet.clone())],
            engine.transport.sends
        );
        assert_eq!(
            vec![
                EngineEvent::DeviceWrite {
                    packet: packet.clone()
                },
                EngineEvent::Broadcast {
                    targets: vec!["beta".to_owned()],
                    packet,
                }
            ],
            step.events
        );
    }

    #[test]
    fn direct_only_remote_broadcast_writes_local_copy_without_forwarding() {
        tinc_test_support::assert_can_create_netns();
        let mut state = routed_state();
        state
            .apply_meta_message(parse_meta_message("12 4 myself beta 203.0.113.3 655 0 1").unwrap())
            .unwrap();
        state
            .apply_meta_message(parse_meta_message("12 5 beta myself 203.0.113.4 655 0 1").unwrap())
            .unwrap();
        let mut engine = engine_with_state(state);
        engine.config.route.routing_mode = RoutingMode::Hub;
        engine.config.route.direct_only = true;
        let packet = ipv4_packet([255, 255, 255, 255]);

        let step = engine
            .handle_network_packet("alpha", packet.clone())
            .unwrap();

        assert_eq!(vec![packet.clone()], engine.device.writes());
        assert!(
            engine.transport.sends.is_empty(),
            "DirectOnly must not forward remote broadcasts through this node"
        );
        assert_eq!(vec![EngineEvent::DeviceWrite { packet }], step.events);
    }

    #[test]
    fn direct_broadcast_sends_to_direct_next_hop_neighbors() {
        tinc_test_support::assert_can_create_netns();
        let mut state = routed_state();
        state
            .apply_meta_message(parse_meta_message("12 4 myself beta 203.0.113.3 655 0 1").unwrap())
            .unwrap();
        state
            .apply_meta_message(parse_meta_message("12 5 beta myself 203.0.113.4 655 0 1").unwrap())
            .unwrap();
        let mut engine = engine_with_state(state);
        engine.config.route.routing_mode = RoutingMode::Hub;
        engine.config.broadcast = BroadcastMode::Direct;
        let packet = ipv4_packet([255, 255, 255, 255]);

        let step = engine.handle_device_packet(packet.clone()).unwrap();

        assert_eq!(
            vec![
                ("alpha".to_owned(), packet.clone()),
                ("beta".to_owned(), packet.clone())
            ],
            engine.transport.sends
        );
        assert_eq!(
            vec![EngineEvent::Broadcast {
                targets: vec!["alpha".to_owned(), "beta".to_owned()],
                packet,
            }],
            step.events
        );
    }

    #[test]
    fn local_broadcast_none_does_not_forward_like_tinc_tunnelserver() {
        tinc_test_support::assert_can_create_netns();
        let mut state = routed_state();
        state
            .apply_meta_message(parse_meta_message("12 4 myself beta 203.0.113.3 655 0 1").unwrap())
            .unwrap();
        state
            .apply_meta_message(parse_meta_message("12 5 beta myself 203.0.113.4 655 0 1").unwrap())
            .unwrap();
        let mut engine = engine_with_state(state);
        engine.config.route.routing_mode = RoutingMode::Hub;
        engine.config.broadcast = BroadcastMode::None;
        let packet = ipv4_packet([255, 255, 255, 255]);

        let step = engine.handle_device_packet(packet).unwrap();

        assert!(engine.device.writes().is_empty());
        assert!(
            engine.transport.sends.is_empty(),
            "C broadcast_packet() returns immediately for local broadcasts in TunnelServer mode"
        );
        assert!(step.events.is_empty());
    }

    #[test]
    fn remote_broadcast_none_writes_local_copy_without_forwarding_like_tinc_tunnelserver() {
        tinc_test_support::assert_can_create_netns();
        let mut state = routed_state();
        state
            .apply_meta_message(parse_meta_message("12 4 myself beta 203.0.113.3 655 0 1").unwrap())
            .unwrap();
        state
            .apply_meta_message(parse_meta_message("12 5 beta myself 203.0.113.4 655 0 1").unwrap())
            .unwrap();
        let mut engine = engine_with_state(state);
        engine.config.route.routing_mode = RoutingMode::Hub;
        engine.config.broadcast = BroadcastMode::None;
        let packet = ipv4_packet([255, 255, 255, 255]);

        let step = engine
            .handle_network_packet("alpha", packet.clone())
            .unwrap();

        assert_eq!(vec![packet.clone()], engine.device.writes());
        assert!(
            engine.transport.sends.is_empty(),
            "C broadcast_packet() writes the local copy before stopping broadcast forwarding in TunnelServer mode"
        );
        assert_eq!(vec![EngineEvent::DeviceWrite { packet }], step.events);
    }

    #[test]
    fn drop_action_is_reported_without_io() {
        tinc_test_support::assert_can_create_netns();
        let mut engine = engine_with_state(routed_state());
        let short = VpnPacket::new(vec![1, 2, 3]).unwrap();

        let step = engine.handle_device_packet(short).unwrap();

        assert!(engine.transport.sends.is_empty());
        assert!(engine.device.writes().is_empty());
        assert!(matches!(
            step.events.as_slice(),
            [EngineEvent::Drop {
                reason: RouteDropReason::TooShort { .. }
            }]
        ));
    }
}
