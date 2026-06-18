// SPDX-License-Identifier: GPL-2.0-or-later

use std::fmt;

use crate::graph::{
    DEFAULT_MTU, Edge, EdgeEndpoint, EdgeMutation, Graph, GraphError, ReachabilityChanges,
};
use crate::protocol::{
    AddEdgeMessage, KeyChangedMessage, MetaMessage, MtuInfoMessage, SubnetMessage, UdpInfoMessage,
};
use crate::subnet::{Subnet, SubnetTable};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkState {
    pub graph: Graph,
    pub subnets: SubnetTable,
    pub experimental: bool,
}

impl NetworkState {
    pub fn new(myself: impl Into<String>) -> Self {
        Self {
            graph: Graph::new(myself),
            subnets: SubnetTable::new(),
            experimental: true,
        }
    }

    pub fn apply_meta_message(
        &mut self,
        message: MetaMessage,
    ) -> Result<StateMutation, StateError> {
        self.apply_meta_message_at(message, 0)
    }

    pub fn apply_meta_message_at(
        &mut self,
        message: MetaMessage,
        now_secs: i64,
    ) -> Result<StateMutation, StateError> {
        match message {
            MetaMessage::TerminateRequest => Ok(StateMutation::TerminateRequest),
            MetaMessage::Ping => Ok(StateMutation::Ping),
            MetaMessage::Pong => Ok(StateMutation::Pong),
            MetaMessage::AddSubnet(message) => Ok(self.apply_add_subnet(message)),
            MetaMessage::DeleteSubnet(message) => Ok(self.apply_delete_subnet(message)),
            MetaMessage::AddEdge(message) => self.apply_add_edge(message, now_secs),
            MetaMessage::DeleteEdge(message) => {
                Ok(self.apply_delete_edge(&message.from, &message.to, now_secs))
            }
            MetaMessage::KeyChanged(message) => Ok(self.apply_key_changed(message)),
            MetaMessage::UdpInfo(message) => Ok(self.apply_udp_info(message)),
            MetaMessage::MtuInfo(message) => Ok(self.apply_mtu_info(message)),
            MetaMessage::Id(_)
            | MetaMessage::MetaKey(_)
            | MetaMessage::Challenge(_)
            | MetaMessage::ChallengeReply(_)
            | MetaMessage::Ack(_)
            | MetaMessage::RequestKey(_)
            | MetaMessage::AnswerKey(_)
            | MetaMessage::TcpPacket(_)
            | MetaMessage::SptpsTcpPacket(_) => Ok(StateMutation::NoChange),
        }
    }

    pub fn recompute_routes(&mut self) -> ReachabilityChanges {
        self.recompute_routes_at(0)
    }

    pub fn recompute_routes_at(&mut self, now_secs: i64) -> ReachabilityChanges {
        self.graph.sssp_bfs();
        let changes = self
            .graph
            .reconcile_reachability_at(self.experimental, now_secs);
        self.graph.mst_kruskal();
        changes
    }

    pub fn purge_unreachable(&mut self, options: PurgeOptions) -> PurgeResult {
        self.purge_unreachable_at(options, 0)
    }

    pub fn purge_unreachable_at(&mut self, options: PurgeOptions, now_secs: i64) -> PurgeResult {
        let unreachable = self
            .graph
            .nodes()
            .filter(|node| node.name != self.graph.myself() && !node.status.reachable)
            .map(|node| node.name.clone())
            .collect::<Vec<_>>();
        let mut removed_subnets = Vec::new();
        let mut removed_edges = Vec::new();
        let mut removed_nodes = Vec::new();

        for name in &unreachable {
            if !options.strict_subnets {
                removed_subnets.extend(self.subnets.remove_owner(name));
            }

            removed_edges.extend(self.graph.remove_edges_from(name));
        }

        for name in &unreachable {
            let has_claimed_subnets = self.subnets.owner_subnets(name).next().is_some();

            if !options.autoconnect
                && (!options.strict_subnets || !has_claimed_subnets)
                && !self.graph.has_edge_to(name)
                && let Some(node) = self.graph.remove_node(name)
            {
                removed_nodes.push(node.name);
            }
        }

        let reachability = self.recompute_routes_at(now_secs);

        PurgeResult {
            removed_nodes,
            removed_edges,
            removed_subnets,
            reachability,
        }
    }

    fn apply_add_subnet(&mut self, message: SubnetMessage) -> StateMutation {
        let owner_created = self.graph.ensure_node(&message.owner);
        let subnet = message.subnet.with_owner(message.owner.clone());
        let inserted = self.subnets.add_unique(subnet.clone());

        StateMutation::AddSubnet {
            subnet,
            owner: message.owner,
            inserted,
            owner_created,
        }
    }

    fn apply_delete_subnet(&mut self, message: SubnetMessage) -> StateMutation {
        let removed = self
            .subnets
            .remove_owner_subnet(&message.owner, &message.subnet);

        StateMutation::DeleteSubnet { removed }
    }

    fn apply_add_edge(
        &mut self,
        message: AddEdgeMessage,
        now_secs: i64,
    ) -> Result<StateMutation, StateError> {
        let mut created_nodes = Vec::new();

        if self.graph.ensure_node(&message.edge.from) {
            created_nodes.push(message.edge.from.clone());
        }

        if self.graph.ensure_node(&message.edge.to) {
            created_nodes.push(message.edge.to.clone());
        }

        let edge = edge_from_add_edge_message(message);
        let edge = self.graph.upsert_edge(edge)?;
        let reachability = self.recompute_routes_at(now_secs);

        Ok(StateMutation::AddEdge {
            edge,
            created_nodes,
            reachability,
        })
    }

    fn apply_delete_edge(&mut self, from: &str, to: &str, now_secs: i64) -> StateMutation {
        let removed = self.graph.remove_edge(from, to);
        let reachability = self.recompute_routes_at(now_secs);

        StateMutation::DeleteEdge {
            removed,
            reachability,
        }
    }

    fn apply_key_changed(&mut self, message: KeyChangedMessage) -> StateMutation {
        let Some(node) = self.graph.node_mut(&message.origin) else {
            return StateMutation::NoChange;
        };

        if !node.status.sptps {
            node.status.valid_key = false;
        }

        StateMutation::KeyChanged {
            origin: message.origin,
        }
    }

    fn apply_udp_info(&mut self, message: UdpInfoMessage) -> StateMutation {
        if message.from == self.graph.myself() {
            return StateMutation::NoChange;
        }

        let Some(node) = self.graph.node_mut(&message.from) else {
            return StateMutation::NoChange;
        };

        let endpoint = EdgeEndpoint::new(message.endpoint.address, message.endpoint.port);
        let previous = node.udp_address.clone();
        let changed = previous.as_ref() != Some(&endpoint);

        node.status.udp_confirmed = false;
        node.mtu_probes = 0;
        node.min_mtu = 0;
        node.max_mtu = DEFAULT_MTU;
        node.udp_address = Some(endpoint.clone());

        StateMutation::UdpInfo {
            from: message.from,
            to: message.to,
            endpoint,
            changed,
        }
    }

    fn apply_mtu_info(&mut self, message: MtuInfoMessage) -> StateMutation {
        let Some(node) = self.graph.node_mut(&message.from) else {
            return StateMutation::NoChange;
        };

        let previous = node.mtu;

        if node.mtu != message.mtu && node.min_mtu != node.max_mtu {
            node.mtu = message.mtu;
        }

        StateMutation::MtuInfo {
            from: message.from,
            to: message.to,
            mtu: message.mtu,
            previous,
            updated: previous != node.mtu,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PurgeOptions {
    pub strict_subnets: bool,
    pub autoconnect: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PurgeResult {
    pub removed_nodes: Vec<String>,
    pub removed_edges: Vec<Edge>,
    pub removed_subnets: Vec<Subnet>,
    pub reachability: ReachabilityChanges,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StateMutation {
    TerminateRequest,
    Ping,
    Pong,
    AddSubnet {
        subnet: Subnet,
        owner: String,
        inserted: bool,
        owner_created: bool,
    },
    DeleteSubnet {
        removed: Option<Subnet>,
    },
    AddEdge {
        edge: EdgeMutation,
        created_nodes: Vec<String>,
        reachability: ReachabilityChanges,
    },
    DeleteEdge {
        removed: Option<Edge>,
        reachability: ReachabilityChanges,
    },
    KeyChanged {
        origin: String,
    },
    UdpInfo {
        from: String,
        to: String,
        endpoint: EdgeEndpoint,
        changed: bool,
    },
    MtuInfo {
        from: String,
        to: String,
        mtu: usize,
        previous: usize,
        updated: bool,
    },
    NoChange,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StateError {
    Graph(GraphError),
}

impl fmt::Display for StateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Graph(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for StateError {}

impl From<GraphError> for StateError {
    fn from(error: GraphError) -> Self {
        Self::Graph(error)
    }
}

fn edge_from_add_edge_message(message: AddEdgeMessage) -> Edge {
    let mut edge = message
        .edge
        .with_address(EdgeEndpoint::new(message.address, message.port));

    if let Some(local) = message.local {
        edge = edge.with_local_address(EdgeEndpoint::new(local.address, local.port));
    }

    edge
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::OPTION_INDIRECT;
    use crate::protocol::parse_meta_message;

    #[test]
    fn add_subnet_creates_owner_and_avoids_duplicates() {
        tinc_test_support::assert_can_create_netns();
        let mut state = NetworkState::new("myself");
        let message = parse_meta_message("10 1 alpha 192.0.2.0/24").unwrap();

        assert_eq!(
            StateMutation::AddSubnet {
                subnet: "192.0.2.0/24"
                    .parse::<Subnet>()
                    .unwrap()
                    .with_owner("alpha"),
                owner: "alpha".to_owned(),
                inserted: true,
                owner_created: true,
            },
            state.apply_meta_message(message.clone()).unwrap()
        );
        assert_eq!(
            StateMutation::AddSubnet {
                subnet: "192.0.2.0/24"
                    .parse::<Subnet>()
                    .unwrap()
                    .with_owner("alpha"),
                owner: "alpha".to_owned(),
                inserted: false,
                owner_created: false,
            },
            state.apply_meta_message(message).unwrap()
        );

        assert!(state.graph.node("alpha").is_some());
        assert_eq!(1, state.subnets.owner_subnets("alpha").count());
    }

    #[test]
    fn delete_subnet_removes_owner_scoped_entry_only() {
        tinc_test_support::assert_can_create_netns();
        let mut state = NetworkState::new("myself");
        state
            .apply_meta_message(parse_meta_message("10 1 alpha 192.0.2.0/24").unwrap())
            .unwrap();
        state
            .apply_meta_message(parse_meta_message("10 2 beta 192.0.2.0/24").unwrap())
            .unwrap();

        let mutation = state
            .apply_meta_message(parse_meta_message("11 3 alpha 192.0.2.0/24").unwrap())
            .unwrap();

        let StateMutation::DeleteSubnet { removed } = mutation else {
            panic!("expected DEL_SUBNET mutation");
        };

        assert_eq!(Some("alpha"), removed.unwrap().owner.as_deref());
        assert_eq!(0, state.subnets.owner_subnets("alpha").count());
        assert_eq!(1, state.subnets.owner_subnets("beta").count());
    }

    #[test]
    fn add_edge_creates_nodes_stores_addresses_and_recomputes_routes() {
        tinc_test_support::assert_can_create_netns();
        let mut state = NetworkState::new("myself");

        let mutation = state
            .apply_meta_message(
                parse_meta_message("12 1 myself alpha 203.0.113.10 655 1 7 10.0.0.1 655").unwrap(),
            )
            .unwrap();

        assert_eq!(
            StateMutation::AddEdge {
                edge: EdgeMutation::Inserted,
                created_nodes: vec!["alpha".to_owned()],
                reachability: ReachabilityChanges {
                    became_reachable: vec!["myself".to_owned()],
                    became_unreachable: Vec::new(),
                },
            },
            mutation
        );

        let edge = state.graph.edge("myself", "alpha").unwrap();
        assert_eq!(OPTION_INDIRECT, edge.options);
        assert_eq!(7, edge.weight);
        assert_eq!(
            Some(&EdgeEndpoint::new("203.0.113.10", "655")),
            edge.address.as_ref()
        );
        assert_eq!(
            Some(&EdgeEndpoint::new("10.0.0.1", "655")),
            edge.local_address.as_ref()
        );

        let mutation = state
            .apply_meta_message(
                parse_meta_message("12 2 alpha myself 198.51.100.1 655 0 7").unwrap(),
            )
            .unwrap();

        let StateMutation::AddEdge { reachability, .. } = mutation else {
            panic!("expected ADD_EDGE mutation");
        };

        assert_eq!(vec!["alpha".to_owned()], reachability.became_reachable);
        assert!(state.graph.node("alpha").unwrap().status.reachable);
    }

    #[test]
    fn add_edge_updates_existing_edge_like_add_edge_handler() {
        tinc_test_support::assert_can_create_netns();
        let mut state = NetworkState::new("myself");
        state
            .apply_meta_message(
                parse_meta_message("12 1 myself alpha 203.0.113.10 655 0 7").unwrap(),
            )
            .unwrap();

        let mutation = state
            .apply_meta_message(
                parse_meta_message("12 2 myself alpha 203.0.113.20 655 0 8").unwrap(),
            )
            .unwrap();

        let StateMutation::AddEdge { edge, .. } = mutation else {
            panic!("expected ADD_EDGE mutation");
        };

        assert_eq!(EdgeMutation::Updated, edge);
        let edge = state.graph.edge("myself", "alpha").unwrap();
        assert_eq!(8, edge.weight);
        assert_eq!(
            Some(&EdgeEndpoint::new("203.0.113.20", "655")),
            edge.address.as_ref()
        );
    }

    #[test]
    fn delete_edge_removes_direction_and_recomputes_reachability() {
        tinc_test_support::assert_can_create_netns();
        let mut state = NetworkState::new("myself");
        state
            .apply_meta_message(
                parse_meta_message("12 1 myself alpha 203.0.113.10 655 0 7").unwrap(),
            )
            .unwrap();
        state
            .apply_meta_message(
                parse_meta_message("12 2 alpha myself 198.51.100.1 655 0 7").unwrap(),
            )
            .unwrap();

        let mutation = state
            .apply_meta_message(parse_meta_message("13 3 myself alpha").unwrap())
            .unwrap();

        let StateMutation::DeleteEdge {
            removed,
            reachability,
        } = mutation
        else {
            panic!("expected DEL_EDGE mutation");
        };

        assert!(removed.is_some());
        assert_eq!(vec!["alpha".to_owned()], reachability.became_unreachable);
        assert!(state.graph.edge("myself", "alpha").is_none());
        assert!(state.graph.edge("alpha", "myself").is_some());
        assert!(!state.graph.node("alpha").unwrap().status.reachable);
    }

    #[test]
    fn purge_unreachable_removes_dynamic_edges_subnets_and_nodes() {
        tinc_test_support::assert_can_create_netns();
        let mut state = NetworkState::new("myself");
        state
            .apply_meta_message(parse_meta_message("10 1 beta 10.2.0.0/16").unwrap())
            .unwrap();
        state
            .apply_meta_message(parse_meta_message("12 2 beta gamma 198.51.100.9 655 0 7").unwrap())
            .unwrap();

        let result = state.purge_unreachable(PurgeOptions {
            strict_subnets: false,
            autoconnect: false,
        });

        assert_eq!(
            vec!["beta".to_owned(), "gamma".to_owned()],
            result.removed_nodes
        );
        assert_eq!(1, result.removed_edges.len());
        assert_eq!("beta", result.removed_edges[0].from);
        assert_eq!(1, result.removed_subnets.len());
        assert!(state.graph.node("beta").is_none());
        assert!(state.graph.node("gamma").is_none());
        assert_eq!(0, state.subnets.owner_subnets("beta").count());
    }

    #[test]
    fn purge_unreachable_keeps_strict_subnet_nodes_and_autoconnect_nodes() {
        tinc_test_support::assert_can_create_netns();
        let mut strict = NetworkState::new("myself");
        strict
            .apply_meta_message(parse_meta_message("10 1 beta 10.2.0.0/16").unwrap())
            .unwrap();

        let result = strict.purge_unreachable(PurgeOptions {
            strict_subnets: true,
            autoconnect: false,
        });

        assert!(result.removed_nodes.is_empty());
        assert!(result.removed_subnets.is_empty());
        assert!(strict.graph.node("beta").is_some());
        assert_eq!(1, strict.subnets.owner_subnets("beta").count());

        let mut autoconnect = NetworkState::new("myself");
        autoconnect.graph.ensure_node("beta");
        let result = autoconnect.purge_unreachable(PurgeOptions {
            strict_subnets: false,
            autoconnect: true,
        });

        assert!(result.removed_nodes.is_empty());
        assert!(autoconnect.graph.node("beta").is_some());
    }

    #[test]
    fn key_changed_clears_non_sptps_valid_key_state() {
        tinc_test_support::assert_can_create_netns();
        let mut state = NetworkState::new("myself");
        state.graph.ensure_node("alpha");
        state.graph.node_mut("alpha").unwrap().status.valid_key = true;

        assert_eq!(
            StateMutation::KeyChanged {
                origin: "alpha".to_owned(),
            },
            state
                .apply_meta_message(parse_meta_message("14 1 alpha").unwrap())
                .unwrap()
        );
        assert!(!state.graph.node("alpha").unwrap().status.valid_key);
    }

    #[test]
    fn key_changed_keeps_sptps_valid_key_state() {
        tinc_test_support::assert_can_create_netns();
        let mut state = NetworkState::new("myself");
        state.graph.ensure_node("alpha");
        let alpha = state.graph.node_mut("alpha").unwrap();
        alpha.status.valid_key = true;
        alpha.status.sptps = true;

        assert_eq!(
            StateMutation::KeyChanged {
                origin: "alpha".to_owned(),
            },
            state
                .apply_meta_message(parse_meta_message("14 1 alpha").unwrap())
                .unwrap()
        );
        assert!(state.graph.node("alpha").unwrap().status.valid_key);
    }

    #[test]
    fn udp_info_updates_node_udp_address_and_resets_udp_probe_state() {
        tinc_test_support::assert_can_create_netns();
        let mut state = NetworkState::new("myself");
        state.graph.ensure_node("alpha");
        {
            let alpha = state.graph.node_mut("alpha").unwrap();
            alpha.status.udp_confirmed = true;
            alpha.mtu_probes = -1;
            alpha.min_mtu = 1400;
            alpha.max_mtu = 1400;
            alpha.udp_address = Some(EdgeEndpoint::new("198.51.100.1", "655"));
        }

        assert_eq!(
            StateMutation::UdpInfo {
                from: "alpha".to_owned(),
                to: "myself".to_owned(),
                endpoint: EdgeEndpoint::new("203.0.113.1", "655"),
                changed: true,
            },
            state
                .apply_meta_message(parse_meta_message("22 alpha myself 203.0.113.1 655").unwrap())
                .unwrap()
        );

        let alpha = state.graph.node("alpha").unwrap();
        assert_eq!(
            Some(&EdgeEndpoint::new("203.0.113.1", "655")),
            alpha.udp_address.as_ref()
        );
        assert!(!alpha.status.has_address);
        assert!(!alpha.status.udp_confirmed);
        assert_eq!(0, alpha.mtu_probes);
        assert_eq!(0, alpha.min_mtu);
        assert_eq!(DEFAULT_MTU, alpha.max_mtu);

        assert_eq!(
            StateMutation::UdpInfo {
                from: "alpha".to_owned(),
                to: "myself".to_owned(),
                endpoint: EdgeEndpoint::new("203.0.113.1", "655"),
                changed: false,
            },
            state
                .apply_meta_message(parse_meta_message("22 alpha myself 203.0.113.1 655").unwrap())
                .unwrap()
        );
    }

    #[test]
    fn udp_info_does_not_update_myself_like_tinc() {
        tinc_test_support::assert_can_create_netns();
        let mut state = NetworkState::new("myself");

        assert_eq!(
            StateMutation::NoChange,
            state
                .apply_meta_message(parse_meta_message("22 myself alpha 203.0.113.1 655").unwrap())
                .unwrap()
        );
        assert_eq!(None, state.graph.node("myself").unwrap().udp_address);
    }

    #[test]
    fn mtu_info_updates_only_provisional_mtu_state_like_tinc() {
        tinc_test_support::assert_can_create_netns();
        let mut state = NetworkState::new("myself");
        state.graph.ensure_node("alpha");

        assert_eq!(
            StateMutation::MtuInfo {
                from: "alpha".to_owned(),
                to: "myself".to_owned(),
                mtu: 1400,
                previous: DEFAULT_MTU,
                updated: true,
            },
            state
                .apply_meta_message(parse_meta_message("23 alpha myself 1400").unwrap())
                .unwrap()
        );
        assert_eq!(1400, state.graph.node("alpha").unwrap().mtu);

        {
            let alpha = state.graph.node_mut("alpha").unwrap();
            alpha.min_mtu = 1300;
            alpha.max_mtu = 1300;
        }

        assert_eq!(
            StateMutation::MtuInfo {
                from: "alpha".to_owned(),
                to: "myself".to_owned(),
                mtu: 1200,
                previous: 1400,
                updated: false,
            },
            state
                .apply_meta_message(parse_meta_message("23 alpha myself 1200").unwrap())
                .unwrap()
        );
        assert_eq!(1400, state.graph.node("alpha").unwrap().mtu);
    }

    #[test]
    fn simple_meta_requests_return_connection_events() {
        tinc_test_support::assert_can_create_netns();
        let mut state = NetworkState::new("myself");

        assert_eq!(
            StateMutation::TerminateRequest,
            state
                .apply_meta_message(parse_meta_message("7 ignored like c handler").unwrap())
                .unwrap()
        );
        assert_eq!(
            StateMutation::Ping,
            state
                .apply_meta_message(parse_meta_message("8 ignored like c handler").unwrap())
                .unwrap()
        );
        assert_eq!(
            StateMutation::Pong,
            state
                .apply_meta_message(parse_meta_message("9 ignored like c handler").unwrap())
                .unwrap()
        );
    }

    #[test]
    fn request_and_answer_key_messages_are_parsed_but_do_not_mutate_core_state_yet() {
        tinc_test_support::assert_can_create_netns();
        let mut state = NetworkState::new("myself");

        assert_eq!(
            StateMutation::NoChange,
            state
                .apply_meta_message(parse_meta_message("15 alpha beta").unwrap())
                .unwrap()
        );
        assert_eq!(
            StateMutation::NoChange,
            state
                .apply_meta_message(parse_meta_message("16 alpha beta hJ2Y -1 -1 -1 0").unwrap())
                .unwrap()
        );
    }
}
