// SPDX-License-Identifier: GPL-2.0-or-later

use std::collections::BTreeMap;
use std::fmt;

use tinc_core::graph::Edge;
use tinc_core::protocol::{
    AddEdgeMessage, DeleteEdgeMessage, EdgeAddress, MetaMessage, SubnetMessage,
};
use tinc_core::state::{NetworkState, StateError, StateMutation};
use tinc_core::subnet::Subnet;

use crate::meta::{
    MetaAuthEvent, MetaConnectionDriver, MetaConnectionEdge, MetaConnectionError,
    MetaConnectionEvent, MetaConnectionStep,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetaConnectionTable {
    pub coordinator: MetaNetworkCoordinator,
    connections: BTreeMap<MetaConnectionId, MetaPeerConnection>,
}

impl MetaConnectionTable {
    pub fn new(coordinator: MetaNetworkCoordinator) -> Self {
        Self {
            coordinator,
            connections: BTreeMap::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.connections.is_empty()
    }

    pub fn len(&self) -> usize {
        self.connections.len()
    }

    pub fn connection(&self, id: MetaConnectionId) -> Option<&MetaPeerConnection> {
        self.connections.get(&id)
    }

    pub fn connection_mut(&mut self, id: MetaConnectionId) -> Option<&mut MetaPeerConnection> {
        self.connections.get_mut(&id)
    }

    pub fn insert_connection(
        &mut self,
        id: MetaConnectionId,
        driver: MetaConnectionDriver,
        handle: MetaConnectionHandle,
        send_initial_id: bool,
    ) -> Result<(), MetaConnectionTableError> {
        if self.connections.contains_key(&id) {
            return Err(MetaConnectionTableError::DuplicateConnection(id));
        }

        let mut connection = MetaPeerConnection::new(driver, handle);

        if send_initial_id {
            connection
                .outbound
                .push(connection.driver.initial_id_bytes());
        }

        self.connections.insert(id, connection);
        Ok(())
    }

    pub fn remove_connection(&mut self, id: MetaConnectionId) -> Option<MetaPeerConnection> {
        self.connections.remove(&id)
    }

    pub fn receive_bytes(
        &mut self,
        id: MetaConnectionId,
        bytes: &[u8],
    ) -> Result<MetaConnectionTableStep, MetaConnectionTableError> {
        let step = self
            .connections
            .get_mut(&id)
            .ok_or(MetaConnectionTableError::MissingConnection(id))?
            .driver
            .receive_bytes(bytes)?;

        self.handle_connection_step(id, step)
    }

    pub fn handle_connection_step(
        &mut self,
        id: MetaConnectionId,
        step: MetaConnectionStep,
    ) -> Result<MetaConnectionTableStep, MetaConnectionTableError> {
        let network = {
            let connection = self
                .connections
                .get_mut(&id)
                .ok_or(MetaConnectionTableError::MissingConnection(id))?;

            self.coordinator
                .handle_connection_step(&mut connection.handle, step)?
        };
        let mut queued = Vec::new();

        for send in network.sends.clone() {
            self.queue_network_send(send, &mut queued)?;
        }

        Ok(MetaConnectionTableStep {
            connection: id,
            network,
            queued,
        })
    }

    pub fn drain_outbound(
        &mut self,
        id: MetaConnectionId,
    ) -> Result<Vec<Vec<u8>>, MetaConnectionTableError> {
        Ok(self
            .connections
            .get_mut(&id)
            .ok_or(MetaConnectionTableError::MissingConnection(id))?
            .drain_outbound())
    }

    fn queue_network_send(
        &mut self,
        send: MetaNetworkSend,
        queued: &mut Vec<MetaQueuedSend>,
    ) -> Result<(), MetaConnectionTableError> {
        let targets = self.target_connections(&send.target)?;

        for id in targets {
            let connection = self
                .connections
                .get_mut(&id)
                .ok_or(MetaConnectionTableError::MissingConnection(id))?;
            let bytes = connection.driver.send_meta_message(&send.message)?;
            let bytes_len = bytes.len();

            connection.outbound.push(bytes);
            queued.push(MetaQueuedSend {
                connection: id,
                peer: connection.handle.peer.clone(),
                message: send.message.clone(),
                bytes_len,
            });
        }

        Ok(())
    }

    fn target_connections(
        &self,
        target: &MetaSendTarget,
    ) -> Result<Vec<MetaConnectionId>, MetaConnectionTableError> {
        match target {
            MetaSendTarget::Peer(peer) => self
                .peer_connection_id(peer)
                .map(|id| vec![id])
                .ok_or_else(|| MetaConnectionTableError::MissingPeer(peer.clone())),
            MetaSendTarget::Broadcast { exclude } => Ok(self
                .connections
                .iter()
                .filter(|(_, connection)| connection.handle.is_activated())
                .filter(|(_, connection)| connection.handle.peer.as_ref() != exclude.as_ref())
                .map(|(id, _)| *id)
                .collect()),
        }
    }

    fn peer_connection_id(&self, peer: &str) -> Option<MetaConnectionId> {
        self.connections
            .iter()
            .find(|(_, connection)| connection.handle.peer() == Some(peer))
            .map(|(id, _)| *id)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MetaConnectionId(pub u64);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetaPeerConnection {
    driver: MetaConnectionDriver,
    handle: MetaConnectionHandle,
    outbound: Vec<Vec<u8>>,
}

impl MetaPeerConnection {
    pub fn new(driver: MetaConnectionDriver, handle: MetaConnectionHandle) -> Self {
        Self {
            driver,
            handle,
            outbound: Vec::new(),
        }
    }

    pub fn driver(&self) -> &MetaConnectionDriver {
        &self.driver
    }

    pub fn driver_mut(&mut self) -> &mut MetaConnectionDriver {
        &mut self.driver
    }

    pub fn handle(&self) -> &MetaConnectionHandle {
        &self.handle
    }

    pub fn handle_mut(&mut self) -> &mut MetaConnectionHandle {
        &mut self.handle
    }

    pub fn outbound_len(&self) -> usize {
        self.outbound.len()
    }

    pub fn drain_outbound(&mut self) -> Vec<Vec<u8>> {
        self.outbound.drain(..).collect()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetaConnectionTableStep {
    pub connection: MetaConnectionId,
    pub network: MetaNetworkStep,
    pub queued: Vec<MetaQueuedSend>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetaQueuedSend {
    pub connection: MetaConnectionId,
    pub peer: Option<String>,
    pub message: MetaMessage,
    pub bytes_len: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MetaConnectionTableError {
    DuplicateConnection(MetaConnectionId),
    MissingConnection(MetaConnectionId),
    MissingPeer(String),
    Connection(MetaConnectionError),
    Network(MetaNetworkError),
}

impl fmt::Display for MetaConnectionTableError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateConnection(id) => write!(f, "duplicate meta connection {id:?}"),
            Self::MissingConnection(id) => write!(f, "missing meta connection {id:?}"),
            Self::MissingPeer(peer) => write!(f, "missing meta connection for peer {peer}"),
            Self::Connection(error) => write!(f, "{error}"),
            Self::Network(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for MetaConnectionTableError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Connection(error) => Some(error),
            Self::Network(error) => Some(error),
            Self::DuplicateConnection(_) | Self::MissingConnection(_) | Self::MissingPeer(_) => {
                None
            }
        }
    }
}

impl From<MetaConnectionError> for MetaConnectionTableError {
    fn from(error: MetaConnectionError) -> Self {
        Self::Connection(error)
    }
}

impl From<MetaNetworkError> for MetaConnectionTableError {
    fn from(error: MetaNetworkError) -> Self {
        Self::Network(error)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetaNetworkCoordinator {
    pub state: NetworkState,
    mode: MetaNetworkMode,
    next_nonce: u32,
}

impl MetaNetworkCoordinator {
    pub fn with_nonce_seed(state: NetworkState, mode: MetaNetworkMode, nonce_seed: u32) -> Self {
        Self {
            state,
            mode,
            next_nonce: nonce_seed,
        }
    }

    pub fn mode(&self) -> MetaNetworkMode {
        self.mode
    }

    pub fn handle_connection_step(
        &mut self,
        handle: &mut MetaConnectionHandle,
        step: MetaConnectionStep,
    ) -> Result<MetaNetworkStep, MetaNetworkError> {
        let mut output = MetaNetworkStep::default();

        for event in step.events {
            match event {
                MetaConnectionEvent::Message(message) => {
                    if handle.activated {
                        self.apply_relayed_message(handle, message, &mut output)?;
                    } else {
                        output.events.push(MetaNetworkEvent::Message(message));
                    }
                }
                MetaConnectionEvent::Auth(event @ MetaAuthEvent::Activated { .. }) => {
                    self.activate_connection(handle, event, &mut output)?;
                }
                MetaConnectionEvent::Auth(event) => {
                    output.events.push(MetaNetworkEvent::Auth(event));
                }
                MetaConnectionEvent::TcpPacket(packet) => {
                    output.events.push(MetaNetworkEvent::TcpPacket(packet));
                }
                MetaConnectionEvent::SptpsPacket(packet) => {
                    output.events.push(MetaNetworkEvent::SptpsPacket(packet));
                }
                MetaConnectionEvent::ApplicationRecord {
                    record_type,
                    payload,
                } => output.events.push(MetaNetworkEvent::ApplicationRecord {
                    record_type,
                    payload,
                }),
            }
        }

        Ok(output)
    }

    fn activate_connection(
        &mut self,
        handle: &mut MetaConnectionHandle,
        event: MetaAuthEvent,
        output: &mut MetaNetworkStep,
    ) -> Result<(), MetaNetworkError> {
        let MetaAuthEvent::Activated { peer, .. } = &event else {
            return Ok(());
        };

        for message in self.sync_messages() {
            output.sends.push(MetaNetworkSend {
                target: MetaSendTarget::Peer(peer.clone()),
                message,
            });
        }

        let edge = MetaConnectionEdge::from_activated_event(
            &event,
            handle.remote_address.clone(),
            handle.local_address.clone(),
            handle.edge_nonce,
        )
        .ok_or(MetaNetworkError::MissingActivation)?;
        let message = MetaMessage::AddEdge(edge.add_edge_message(self.state.graph.myself()));
        let mutation = self.state.apply_meta_message(message.clone())?;

        output.events.push(MetaNetworkEvent::Auth(event.clone()));
        output.events.push(MetaNetworkEvent::StateMutation {
            message: message.clone(),
            mutation,
        });
        output.sends.push(MetaNetworkSend {
            target: match self.mode {
                MetaNetworkMode::Mesh => MetaSendTarget::Broadcast { exclude: None },
                MetaNetworkMode::TunnelServer => MetaSendTarget::Peer(peer.clone()),
            },
            message,
        });

        handle.peer = Some(peer.clone());
        handle.activated = true;

        Ok(())
    }

    fn apply_relayed_message(
        &mut self,
        handle: &MetaConnectionHandle,
        message: MetaMessage,
        output: &mut MetaNetworkStep,
    ) -> Result<(), MetaNetworkError> {
        if self.rejects_local_claim(handle, &message, output) {
            return Ok(());
        }
        if self.tunnel_server_ignores_relayed_message(handle, &message, output) {
            return Ok(());
        }

        let forward = self.should_forward(&message);
        let mutation = self.state.apply_meta_message(message.clone())?;

        output.events.push(MetaNetworkEvent::StateMutation {
            message: message.clone(),
            mutation,
        });

        if forward {
            output.sends.push(MetaNetworkSend {
                target: MetaSendTarget::Broadcast {
                    exclude: handle.peer.clone(),
                },
                message,
            });
        }

        Ok(())
    }

    fn rejects_local_claim(
        &mut self,
        handle: &MetaConnectionHandle,
        message: &MetaMessage,
        output: &mut MetaNetworkStep,
    ) -> bool {
        let myself = self.state.graph.myself().to_owned();
        let correction = match message {
            MetaMessage::AddSubnet(message) if message.owner == myself => self
                .state
                .subnets
                .lookup_owner_subnet(&myself, &message.subnet)
                .is_none()
                .then(|| {
                    MetaMessage::DeleteSubnet(SubnetMessage {
                        nonce: self.next_nonce(),
                        owner: myself,
                        subnet: message.subnet.clone(),
                    })
                }),
            MetaMessage::DeleteSubnet(message) if message.owner == myself => self
                .state
                .subnets
                .lookup_owner_subnet(&myself, &message.subnet)
                .is_some()
                .then(|| {
                    let mut subnet = message.subnet.clone();
                    subnet.owner = None;
                    MetaMessage::AddSubnet(SubnetMessage {
                        nonce: self.next_nonce(),
                        owner: myself,
                        subnet,
                    })
                }),
            MetaMessage::AddEdge(message) if message.edge.from == myself => {
                self.local_edge_correction(&message.edge.from, &message.edge.to)
            }
            MetaMessage::DeleteEdge(message) if message.from == myself => self
                .state
                .graph
                .edge(&message.from, &message.to)
                .cloned()
                .and_then(|edge| self.add_edge_message(edge)),
            _ => return false,
        };

        if let (Some(peer), Some(message)) = (handle.peer.clone(), correction.clone()) {
            output.sends.push(MetaNetworkSend {
                target: MetaSendTarget::Peer(peer),
                message,
            });
        }

        output.events.push(MetaNetworkEvent::LocalClaimRejected {
            message: message.clone(),
            correction,
        });

        true
    }

    fn tunnel_server_ignores_relayed_message(
        &self,
        handle: &MetaConnectionHandle,
        message: &MetaMessage,
        output: &mut MetaNetworkStep,
    ) -> bool {
        if self.mode != MetaNetworkMode::TunnelServer {
            return false;
        }

        let myself = self.state.graph.myself();
        let peer = handle.peer.as_deref();
        let ignored = match message {
            MetaMessage::AddSubnet(message) => message.owner != myself,
            MetaMessage::DeleteSubnet(message) => message.owner != myself,
            MetaMessage::AddEdge(message) => {
                tunnel_server_indirect_edge(myself, peer, &message.edge.from, &message.edge.to)
            }
            MetaMessage::DeleteEdge(message) => {
                tunnel_server_indirect_edge(myself, peer, &message.from, &message.to)
            }
            _ => false,
        };

        if ignored {
            output.events.push(MetaNetworkEvent::TunnelServerIgnored {
                message: message.clone(),
            });
        }

        ignored
    }

    fn local_edge_correction(&mut self, from: &str, to: &str) -> Option<MetaMessage> {
        if let Some(edge) = self.state.graph.edge(from, to).cloned() {
            return self
                .add_edge_message(edge)
                .or_else(|| Some(self.delete_edge_message(from, to)));
        }

        Some(self.delete_edge_message(from, to))
    }

    fn should_forward(&self, message: &MetaMessage) -> bool {
        if self.mode != MetaNetworkMode::Mesh {
            return false;
        }

        matches!(
            message,
            MetaMessage::AddSubnet(_)
                | MetaMessage::DeleteSubnet(_)
                | MetaMessage::AddEdge(_)
                | MetaMessage::DeleteEdge(_)
                | MetaMessage::KeyChanged(_)
        )
    }

    fn sync_messages(&mut self) -> Vec<MetaMessage> {
        let subnets = self.state.subnets.iter().cloned().collect::<Vec<_>>();
        let edges = self.state.graph.edges().cloned().collect::<Vec<_>>();
        let mut messages = Vec::new();

        for subnet in subnets {
            if let Some(message) = self.add_subnet_message(subnet) {
                messages.push(message);
            }
        }

        for edge in edges {
            if let Some(message) = self.add_edge_message(edge) {
                messages.push(message);
            }
        }

        messages
    }

    fn add_subnet_message(&mut self, mut subnet: Subnet) -> Option<MetaMessage> {
        let owner = subnet.owner.take()?;

        Some(MetaMessage::AddSubnet(SubnetMessage {
            nonce: self.next_nonce(),
            owner,
            subnet,
        }))
    }

    fn add_edge_message(&mut self, edge: Edge) -> Option<MetaMessage> {
        let endpoint = edge.address.as_ref()?;
        let address = endpoint.address.clone();
        let port = endpoint.port.clone();
        let local = edge.local_address.as_ref().map(|endpoint| EdgeAddress {
            address: endpoint.address.clone(),
            port: endpoint.port.clone(),
        });

        Some(MetaMessage::AddEdge(AddEdgeMessage {
            nonce: self.next_nonce(),
            edge,
            address,
            port,
            local,
        }))
    }

    fn delete_edge_message(&mut self, from: &str, to: &str) -> MetaMessage {
        MetaMessage::DeleteEdge(DeleteEdgeMessage {
            nonce: self.next_nonce(),
            from: from.to_owned(),
            to: to.to_owned(),
        })
    }

    fn next_nonce(&mut self) -> u32 {
        let nonce = self.next_nonce;
        self.next_nonce = self.next_nonce.wrapping_add(1);
        nonce
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetaNetworkMode {
    Mesh,
    TunnelServer,
}

fn tunnel_server_indirect_edge(myself: &str, peer: Option<&str>, from: &str, to: &str) -> bool {
    !edge_endpoint_is_direct(myself, peer, from) && !edge_endpoint_is_direct(myself, peer, to)
}

fn edge_endpoint_is_direct(myself: &str, peer: Option<&str>, endpoint: &str) -> bool {
    endpoint == myself || peer == Some(endpoint)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetaConnectionHandle {
    peer: Option<String>,
    remote_address: String,
    local_address: Option<EdgeAddress>,
    edge_nonce: u32,
    activated: bool,
}

impl MetaConnectionHandle {
    pub fn new(
        remote_address: impl Into<String>,
        local_address: Option<EdgeAddress>,
        edge_nonce: u32,
    ) -> Self {
        Self {
            peer: None,
            remote_address: remote_address.into(),
            local_address,
            edge_nonce,
            activated: false,
        }
    }

    pub fn activated(
        peer: impl Into<String>,
        remote_address: impl Into<String>,
        local_address: Option<EdgeAddress>,
        edge_nonce: u32,
    ) -> Self {
        Self {
            peer: Some(peer.into()),
            remote_address: remote_address.into(),
            local_address,
            edge_nonce,
            activated: true,
        }
    }

    pub fn peer(&self) -> Option<&str> {
        self.peer.as_deref()
    }

    pub fn is_activated(&self) -> bool {
        self.activated
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MetaNetworkStep {
    pub sends: Vec<MetaNetworkSend>,
    pub events: Vec<MetaNetworkEvent>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetaNetworkSend {
    pub target: MetaSendTarget,
    pub message: MetaMessage,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MetaSendTarget {
    Peer(String),
    Broadcast { exclude: Option<String> },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MetaNetworkEvent {
    Message(MetaMessage),
    Auth(MetaAuthEvent),
    StateMutation {
        message: MetaMessage,
        mutation: StateMutation,
    },
    LocalClaimRejected {
        message: MetaMessage,
        correction: Option<MetaMessage>,
    },
    TunnelServerIgnored {
        message: MetaMessage,
    },
    ApplicationRecord {
        record_type: u8,
        payload: Vec<u8>,
    },
    TcpPacket(Vec<u8>),
    SptpsPacket(Vec<u8>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MetaNetworkError {
    State(StateError),
    MissingActivation,
}

impl fmt::Display for MetaNetworkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::State(error) => write!(f, "{error}"),
            Self::MissingActivation => write!(f, "missing activated meta connection event"),
        }
    }
}

impl std::error::Error for MetaNetworkError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::State(error) => Some(error),
            Self::MissingActivation => None,
        }
    }
}

impl From<StateError> for MetaNetworkError {
    fn from(error: StateError) -> Self {
        Self::State(error)
    }
}

#[cfg(test)]
mod tests {
    use tinc_core::graph::{Edge, EdgeEndpoint, OPTION_CLAMP_MSS};
    use tinc_core::protocol::{KeyChangedMessage, PROT_MINOR, parse_meta_message};

    use crate::meta::{MetaAuthState, MetaConnectionAuth, MetaConnectionDriver};
    use crate::sptps::{ED25519_SEED_LEN, TincEd25519PrivateKey};

    use super::*;

    fn key(byte: u8) -> TincEd25519PrivateKey {
        TincEd25519PrivateKey::from_seed([byte; ED25519_SEED_LEN])
    }

    fn flatten_outbound(outbound: Vec<Vec<u8>>) -> Vec<u8> {
        outbound.into_iter().flatten().collect()
    }

    fn driver_pair(
        local_name: &str,
        remote_name: &str,
        local_seed: u8,
        remote_seed: u8,
    ) -> (MetaConnectionDriver, MetaConnectionDriver) {
        let local_key = key(local_seed);
        let remote_key = key(remote_seed);
        let mut local = MetaConnectionDriver::new(MetaConnectionAuth::new(
            local_name,
            true,
            local_key.clone(),
            remote_key.public_key(),
            "655",
            10,
            (PROT_MINOR as u32) << 24,
        ));
        let mut remote = MetaConnectionDriver::new(MetaConnectionAuth::new(
            remote_name,
            false,
            remote_key,
            local_key.public_key(),
            "655",
            10,
            (PROT_MINOR as u32) << 24,
        ));

        let local_id = local.initial_id_bytes();
        let remote_after_id = remote.receive_bytes(&local_id).unwrap();

        let mut remote_to_local = remote.initial_id_bytes();
        remote_to_local.extend(flatten_outbound(remote_after_id.outbound));
        let local_after_remote = local.receive_bytes(&remote_to_local).unwrap();

        let remote_after_local = remote
            .receive_bytes(&flatten_outbound(local_after_remote.outbound))
            .unwrap();
        let local_after_remote = local
            .receive_bytes(&flatten_outbound(remote_after_local.outbound))
            .unwrap();
        remote
            .receive_bytes(&flatten_outbound(local_after_remote.outbound))
            .unwrap();

        assert_eq!(MetaAuthState::Activated, local.auth().state());
        assert_eq!(MetaAuthState::Activated, remote.auth().state());

        (local, remote)
    }

    fn message_request_numbers(messages: &[MetaNetworkSend]) -> Vec<i32> {
        messages
            .iter()
            .map(|send| send.message.request().number())
            .collect()
    }

    #[test]
    fn activation_sends_existing_state_then_broadcasts_new_edge() {
        tinc_test_support::assert_can_create_netns();
        let mut state = NetworkState::new("alice");
        state
            .apply_meta_message(parse_meta_message("10 10 alice 10.0.0.0/24").unwrap())
            .unwrap();
        state
            .apply_meta_message(
                parse_meta_message("12 11 alice carol 203.0.113.30 655 8 25").unwrap(),
            )
            .unwrap();

        let mut coordinator =
            MetaNetworkCoordinator::with_nonce_seed(state, MetaNetworkMode::Mesh, 100);
        let mut handle = MetaConnectionHandle::new(
            "198.51.100.20",
            Some(EdgeAddress {
                address: "192.0.2.10".to_owned(),
                port: "655".to_owned(),
            }),
            0xfeed,
        );
        let step = MetaConnectionStep {
            events: vec![MetaConnectionEvent::Auth(MetaAuthEvent::Activated {
                peer: "bob".to_owned(),
                port: "655".to_owned(),
                weight: 15,
                options: OPTION_CLAMP_MSS,
            })],
            ..MetaConnectionStep::default()
        };

        let output = coordinator
            .handle_connection_step(&mut handle, step)
            .unwrap();

        assert!(handle.is_activated());
        assert_eq!(Some("bob"), handle.peer());
        assert_eq!(vec![10, 12, 12], message_request_numbers(&output.sends));
        assert!(matches!(
            output.sends[0].target,
            MetaSendTarget::Peer(ref peer) if peer == "bob"
        ));
        assert!(matches!(
            output.sends[1].target,
            MetaSendTarget::Peer(ref peer) if peer == "bob"
        ));
        assert_eq!(
            MetaSendTarget::Broadcast { exclude: None },
            output.sends[2].target
        );

        let MetaMessage::AddEdge(add_edge) = &output.sends[2].message else {
            panic!("expected ADD_EDGE broadcast");
        };
        assert_eq!("alice", add_edge.edge.from);
        assert_eq!("bob", add_edge.edge.to);
        assert_eq!("198.51.100.20", add_edge.address);
        assert_eq!("655", add_edge.port);
        assert_eq!(
            Some(&EdgeAddress {
                address: "192.0.2.10".to_owned(),
                port: "655".to_owned(),
            }),
            add_edge.local.as_ref()
        );
        assert!(coordinator.state.graph.edge("alice", "bob").is_some());
    }

    #[test]
    fn activated_connection_applies_and_forwards_mesh_state_messages() {
        tinc_test_support::assert_can_create_netns();
        let state = NetworkState::new("alice");
        let mut coordinator =
            MetaNetworkCoordinator::with_nonce_seed(state, MetaNetworkMode::Mesh, 1);
        let mut handle = MetaConnectionHandle::activated("bob", "198.51.100.20", None, 2);
        let message = parse_meta_message("10 42 bob 10.2.0.0/16").unwrap();
        let step = MetaConnectionStep {
            events: vec![MetaConnectionEvent::Message(message.clone())],
            ..MetaConnectionStep::default()
        };

        let output = coordinator
            .handle_connection_step(&mut handle, step)
            .unwrap();

        assert!(
            coordinator
                .state
                .subnets
                .owner_subnets("bob")
                .any(|subnet| subnet.to_string() == "10.2.0.0/16")
        );
        assert_eq!(
            vec![MetaNetworkSend {
                target: MetaSendTarget::Broadcast {
                    exclude: Some("bob".to_owned())
                },
                message,
            }],
            output.sends
        );
        assert!(matches!(
            output.events.as_slice(),
            [MetaNetworkEvent::StateMutation { .. }]
        ));
    }

    #[test]
    fn tunnelserver_does_not_forward_relayed_mesh_messages() {
        tinc_test_support::assert_can_create_netns();
        let state = NetworkState::new("alice");
        let mut coordinator =
            MetaNetworkCoordinator::with_nonce_seed(state, MetaNetworkMode::TunnelServer, 1);
        let mut handle = MetaConnectionHandle::activated("bob", "198.51.100.20", None, 2);
        let step = MetaConnectionStep {
            events: vec![MetaConnectionEvent::Message(MetaMessage::KeyChanged(
                KeyChangedMessage {
                    nonce: 42,
                    origin: "bob".to_owned(),
                },
            ))],
            ..MetaConnectionStep::default()
        };

        let output = coordinator
            .handle_connection_step(&mut handle, step)
            .unwrap();

        assert!(output.sends.is_empty());
    }

    #[test]
    fn tunnelserver_ignores_subnet_mutations_like_tinc() {
        tinc_test_support::assert_can_create_netns();
        let state = NetworkState::new("alice");
        let mut coordinator =
            MetaNetworkCoordinator::with_nonce_seed(state, MetaNetworkMode::TunnelServer, 1);
        let mut handle = MetaConnectionHandle::activated("bob", "198.51.100.20", None, 2);
        let add = parse_meta_message("10 42 bob 10.2.0.0/16").unwrap();
        let del = parse_meta_message("11 43 bob 10.2.0.0/16").unwrap();

        let add_output = coordinator
            .handle_connection_step(
                &mut handle,
                MetaConnectionStep {
                    events: vec![MetaConnectionEvent::Message(add.clone())],
                    ..MetaConnectionStep::default()
                },
            )
            .unwrap();
        let del_output = coordinator
            .handle_connection_step(
                &mut handle,
                MetaConnectionStep {
                    events: vec![MetaConnectionEvent::Message(del.clone())],
                    ..MetaConnectionStep::default()
                },
            )
            .unwrap();

        assert!(
            coordinator
                .state
                .subnets
                .owner_subnets("bob")
                .next()
                .is_none()
        );
        assert!(add_output.sends.is_empty());
        assert!(del_output.sends.is_empty());
        assert!(matches!(
            add_output.events.as_slice(),
            [MetaNetworkEvent::TunnelServerIgnored { message }] if message == &add
        ));
        assert!(matches!(
            del_output.events.as_slice(),
            [MetaNetworkEvent::TunnelServerIgnored { message }] if message == &del
        ));
    }

    #[test]
    fn tunnelserver_ignores_indirect_edges_but_accepts_direct_edges_like_tinc() {
        tinc_test_support::assert_can_create_netns();
        let state = NetworkState::new("alice");
        let mut coordinator =
            MetaNetworkCoordinator::with_nonce_seed(state, MetaNetworkMode::TunnelServer, 1);
        let mut handle = MetaConnectionHandle::activated("bob", "198.51.100.20", None, 2);
        let indirect = parse_meta_message("12 42 carol dave 203.0.113.4 655 8 25").unwrap();
        let direct = parse_meta_message("12 43 bob carol 203.0.113.5 655 8 25").unwrap();

        let ignored = coordinator
            .handle_connection_step(
                &mut handle,
                MetaConnectionStep {
                    events: vec![MetaConnectionEvent::Message(indirect.clone())],
                    ..MetaConnectionStep::default()
                },
            )
            .unwrap();
        let applied = coordinator
            .handle_connection_step(
                &mut handle,
                MetaConnectionStep {
                    events: vec![MetaConnectionEvent::Message(direct)],
                    ..MetaConnectionStep::default()
                },
            )
            .unwrap();

        assert!(coordinator.state.graph.edge("carol", "dave").is_none());
        assert!(coordinator.state.graph.edge("bob", "carol").is_some());
        assert!(ignored.sends.is_empty());
        assert!(applied.sends.is_empty());
        assert!(matches!(
            ignored.events.as_slice(),
            [MetaNetworkEvent::TunnelServerIgnored { message }] if message == &indirect
        ));
        assert!(matches!(
            applied.events.as_slice(),
            [MetaNetworkEvent::StateMutation { .. }]
        ));
    }

    #[test]
    fn relayed_messages_cannot_add_unknown_local_subnets() {
        tinc_test_support::assert_can_create_netns();
        let state = NetworkState::new("alice");
        let mut coordinator =
            MetaNetworkCoordinator::with_nonce_seed(state, MetaNetworkMode::Mesh, 77);
        let mut handle = MetaConnectionHandle::activated("bob", "198.51.100.20", None, 2);
        let received = parse_meta_message("10 9 alice 10.9.0.0/16").unwrap();
        let step = MetaConnectionStep {
            events: vec![MetaConnectionEvent::Message(received.clone())],
            ..MetaConnectionStep::default()
        };

        let output = coordinator
            .handle_connection_step(&mut handle, step)
            .unwrap();

        assert!(
            coordinator
                .state
                .subnets
                .owner_subnets("alice")
                .next()
                .is_none()
        );
        assert_eq!(1, output.sends.len());
        assert_eq!(
            MetaSendTarget::Peer("bob".to_owned()),
            output.sends[0].target
        );
        let MetaMessage::DeleteSubnet(correction) = &output.sends[0].message else {
            panic!("expected DEL_SUBNET correction");
        };
        assert_eq!(77, correction.nonce);
        assert_eq!("alice", correction.owner);
        assert!(matches!(
            output.events.as_slice(),
            [MetaNetworkEvent::LocalClaimRejected {
                message,
                correction: Some(MetaMessage::DeleteSubnet(_)),
            }] if message == &received
        ));
    }

    #[test]
    fn relayed_messages_cannot_delete_local_edges() {
        tinc_test_support::assert_can_create_netns();
        let mut state = NetworkState::new("alice");
        state
            .apply_meta_message(
                parse_meta_message("12 10 alice carol 203.0.113.30 655 8 25").unwrap(),
            )
            .unwrap();
        let mut coordinator =
            MetaNetworkCoordinator::with_nonce_seed(state, MetaNetworkMode::Mesh, 88);
        let mut handle = MetaConnectionHandle::activated("bob", "198.51.100.20", None, 2);
        let received = parse_meta_message("13 11 alice carol").unwrap();
        let step = MetaConnectionStep {
            events: vec![MetaConnectionEvent::Message(received)],
            ..MetaConnectionStep::default()
        };

        let output = coordinator
            .handle_connection_step(&mut handle, step)
            .unwrap();

        assert!(coordinator.state.graph.edge("alice", "carol").is_some());
        assert_eq!(1, output.sends.len());
        let MetaMessage::AddEdge(correction) = &output.sends[0].message else {
            panic!("expected ADD_EDGE correction");
        };
        assert_eq!(88, correction.nonce);
        assert_eq!("alice", correction.edge.from);
        assert_eq!("carol", correction.edge.to);
    }

    #[test]
    fn sync_skips_edges_without_wire_addresses() {
        tinc_test_support::assert_can_create_netns();
        let mut state = NetworkState::new("alice");
        state.graph.ensure_node("carol");
        state
            .graph
            .upsert_edge(Edge::new("alice", "carol", 10))
            .unwrap();
        state
            .graph
            .upsert_edge(
                Edge::new("carol", "alice", 10)
                    .with_address(EdgeEndpoint::new("203.0.113.30", "655")),
            )
            .unwrap();

        let mut coordinator =
            MetaNetworkCoordinator::with_nonce_seed(state, MetaNetworkMode::Mesh, 7);
        let messages = coordinator.sync_messages();

        assert_eq!(1, messages.len());
        let MetaMessage::AddEdge(message) = &messages[0] else {
            panic!("expected ADD_EDGE");
        };
        assert_eq!("carol", message.edge.from);
        assert_eq!("alice", message.edge.to);
    }

    #[test]
    fn connection_table_queues_activation_broadcast_as_encoded_bytes() {
        tinc_test_support::assert_can_create_netns();
        let (bob_local, mut bob_remote) = driver_pair("alice", "bob", 1, 2);
        let (carol_local, mut carol_remote) = driver_pair("alice", "carol", 3, 4);
        let coordinator = MetaNetworkCoordinator::with_nonce_seed(
            NetworkState::new("alice"),
            MetaNetworkMode::Mesh,
            5,
        );
        let mut table = MetaConnectionTable::new(coordinator);
        let bob_id = MetaConnectionId(1);
        let carol_id = MetaConnectionId(2);

        table
            .insert_connection(
                bob_id,
                bob_local,
                MetaConnectionHandle::new("198.51.100.20", None, 0x100),
                false,
            )
            .unwrap();
        table
            .insert_connection(
                carol_id,
                carol_local,
                MetaConnectionHandle::activated("carol", "198.51.100.30", None, 0x200),
                false,
            )
            .unwrap();

        let step = MetaConnectionStep {
            events: vec![MetaConnectionEvent::Auth(MetaAuthEvent::Activated {
                peer: "bob".to_owned(),
                port: "655".to_owned(),
                weight: 10,
                options: (PROT_MINOR as u32) << 24,
            })],
            ..MetaConnectionStep::default()
        };
        let output = table.handle_connection_step(bob_id, step).unwrap();

        assert!(table.connection(bob_id).unwrap().handle().is_activated());
        assert_eq!(
            vec![bob_id, carol_id],
            output
                .queued
                .iter()
                .map(|send| send.connection)
                .collect::<Vec<_>>()
        );

        let bob_step = bob_remote
            .receive_bytes(&flatten_outbound(table.drain_outbound(bob_id).unwrap()))
            .unwrap();
        let carol_step = carol_remote
            .receive_bytes(&flatten_outbound(table.drain_outbound(carol_id).unwrap()))
            .unwrap();

        for step in [bob_step, carol_step] {
            assert!(step.events.iter().any(|event| {
                matches!(
                    event,
                    MetaConnectionEvent::Message(MetaMessage::AddEdge(message))
                        if message.edge.from == "alice" && message.edge.to == "bob"
                )
            }));
        }
    }

    #[test]
    fn connection_table_receives_and_broadcasts_encoded_relayed_messages() {
        tinc_test_support::assert_can_create_netns();
        let (bob_local, mut bob_remote) = driver_pair("alice", "bob", 1, 2);
        let (carol_local, mut carol_remote) = driver_pair("alice", "carol", 3, 4);
        let coordinator = MetaNetworkCoordinator::with_nonce_seed(
            NetworkState::new("alice"),
            MetaNetworkMode::Mesh,
            5,
        );
        let mut table = MetaConnectionTable::new(coordinator);
        let bob_id = MetaConnectionId(1);
        let carol_id = MetaConnectionId(2);

        table
            .insert_connection(
                bob_id,
                bob_local,
                MetaConnectionHandle::activated("bob", "198.51.100.20", None, 0x100),
                false,
            )
            .unwrap();
        table
            .insert_connection(
                carol_id,
                carol_local,
                MetaConnectionHandle::activated("carol", "198.51.100.30", None, 0x200),
                false,
            )
            .unwrap();

        let message = parse_meta_message("10 42 bob 10.2.0.0/16").unwrap();
        let encoded = bob_remote.send_meta_message(&message).unwrap();
        let output = table.receive_bytes(bob_id, &encoded).unwrap();

        assert_eq!(
            vec![carol_id],
            output
                .queued
                .iter()
                .map(|send| send.connection)
                .collect::<Vec<_>>()
        );
        assert!(table.drain_outbound(bob_id).unwrap().is_empty());

        let carol_step = carol_remote
            .receive_bytes(&flatten_outbound(table.drain_outbound(carol_id).unwrap()))
            .unwrap();

        assert!(
            carol_step
                .events
                .iter()
                .any(|event| event == &MetaConnectionEvent::Message(message.clone()))
        );
        assert!(
            table
                .coordinator
                .state
                .subnets
                .owner_subnets("bob")
                .any(|subnet| subnet.to_string() == "10.2.0.0/16")
        );
    }
}
