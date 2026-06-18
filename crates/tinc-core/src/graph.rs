// SPDX-License-Identifier: GPL-2.0-or-later

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;

use sha2::{Digest, Sha512};

pub const OPTION_INDIRECT: u32 = 0x0001;
pub const OPTION_TCPONLY: u32 = 0x0002;
pub const OPTION_PMTU_DISCOVERY: u32 = 0x0004;
pub const OPTION_CLAMP_MSS: u32 = 0x0008;
pub const MIN_MTU: usize = 512;
#[cfg(not(feature = "jumbograms"))]
pub const DEFAULT_MTU: usize = 1518;
#[cfg(feature = "jumbograms")]
pub const DEFAULT_MTU: usize = 9018;
pub const NODE_ID_LEN: usize = 6;

pub const fn option_version(options: u32) -> u8 {
    (options >> 24) as u8
}

#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct NodeId([u8; NODE_ID_LEN]);

impl NodeId {
    pub const NULL: Self = Self([0; NODE_ID_LEN]);

    pub fn new(bytes: [u8; NODE_ID_LEN]) -> Self {
        Self(bytes)
    }

    pub fn from_name(name: &str) -> Self {
        let digest = Sha512::digest(name.as_bytes());
        let mut id = [0; NODE_ID_LEN];
        id.copy_from_slice(&digest[..NODE_ID_LEN]);
        Self(id)
    }

    pub fn as_bytes(&self) -> &[u8; NODE_ID_LEN] {
        &self.0
    }

    pub fn is_null(&self) -> bool {
        *self == Self::NULL
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Node {
    pub name: String,
    pub id: NodeId,
    pub status: NodeStatus,
    pub last_state_change: i64,
    pub route: RouteState,
    pub options: u32,
    pub mtu: usize,
    pub min_mtu: usize,
    pub max_mtu: usize,
    pub mtu_probes: i32,
    pub udp_address: Option<EdgeEndpoint>,
}

impl Node {
    pub fn new(name: impl Into<String>) -> Self {
        let name = name.into();
        let id = NodeId::from_name(&name);

        Self {
            name,
            id,
            status: NodeStatus::default(),
            last_state_change: 0,
            route: RouteState::default(),
            options: 0,
            mtu: DEFAULT_MTU,
            min_mtu: 0,
            max_mtu: DEFAULT_MTU,
            mtu_probes: 0,
            udp_address: None,
        }
    }

    pub fn reachable(mut self, reachable: bool) -> Self {
        self.status.reachable = reachable;
        self
    }

    pub fn with_mtu(mut self, mtu: usize) -> Self {
        self.mtu = mtu;
        self.min_mtu = mtu;
        self.max_mtu = mtu;
        self
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NodeStatus {
    pub valid_key: bool,
    pub waiting_for_key: bool,
    pub visited: bool,
    pub reachable: bool,
    pub indirect: bool,
    pub sptps: bool,
    pub udp_confirmed: bool,
    pub send_locally: bool,
    pub udp_packet: bool,
    pub valid_key_in: bool,
    pub has_address: bool,
    pub ping_sent: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RouteState {
    pub distance: Option<i32>,
    pub weighted_distance: Option<i32>,
    pub next_hop: Option<String>,
    pub previous_edge: Option<EdgeKey>,
    pub via: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Edge {
    pub from: String,
    pub to: String,
    pub address: Option<EdgeEndpoint>,
    pub local_address: Option<EdgeEndpoint>,
    pub options: u32,
    pub weight: i32,
}

impl Edge {
    pub fn new(from: impl Into<String>, to: impl Into<String>, weight: i32) -> Self {
        Self {
            from: from.into(),
            to: to.into(),
            address: None,
            local_address: None,
            options: 0,
            weight,
        }
    }

    pub fn with_options(mut self, options: u32) -> Self {
        self.options = options;
        self
    }

    pub fn with_address(mut self, address: EdgeEndpoint) -> Self {
        self.address = Some(address);
        self
    }

    pub fn with_local_address(mut self, local_address: EdgeEndpoint) -> Self {
        self.local_address = Some(local_address);
        self
    }

    pub fn key(&self) -> EdgeKey {
        EdgeKey {
            from: self.from.clone(),
            to: self.to.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EdgeEndpoint {
    pub address: String,
    pub port: String,
}

impl EdgeEndpoint {
    pub fn new(address: impl Into<String>, port: impl Into<String>) -> Self {
        Self {
            address: address.into(),
            port: port.into(),
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct EdgeKey {
    pub from: String,
    pub to: String,
}

impl EdgeKey {
    pub fn new(from: impl Into<String>, to: impl Into<String>) -> Self {
        Self {
            from: from.into(),
            to: to.into(),
        }
    }

    pub fn reverse(&self) -> Self {
        Self {
            from: self.to.clone(),
            to: self.from.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GraphError {
    DuplicateNode(String),
    MissingNode(String),
    DuplicateEdge(EdgeKey),
}

impl fmt::Display for GraphError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateNode(name) => write!(f, "duplicate node {name}"),
            Self::MissingNode(name) => write!(f, "missing node {name}"),
            Self::DuplicateEdge(edge) => write!(f, "duplicate edge {} -> {}", edge.from, edge.to),
        }
    }
}

impl std::error::Error for GraphError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Graph {
    myself: String,
    nodes: BTreeMap<String, Node>,
    edges: BTreeMap<EdgeKey, Edge>,
    mst_edges: BTreeSet<EdgeKey>,
}

impl Graph {
    pub fn new(myself: impl Into<String>) -> Self {
        let myself = myself.into();
        let mut nodes = BTreeMap::new();
        nodes.insert(myself.clone(), Node::new(&myself));

        Self {
            myself,
            nodes,
            edges: BTreeMap::new(),
            mst_edges: BTreeSet::new(),
        }
    }

    pub fn myself(&self) -> &str {
        &self.myself
    }

    pub fn nodes(&self) -> impl Iterator<Item = &Node> {
        self.nodes.values()
    }

    pub fn edges(&self) -> impl Iterator<Item = &Edge> {
        self.edges.values()
    }

    pub fn mst_neighbors(&self, name: &str) -> Vec<String> {
        self.mst_edges
            .iter()
            .filter(|key| key.from == name)
            .map(|key| key.to.clone())
            .collect()
    }

    pub fn node(&self, name: &str) -> Option<&Node> {
        self.nodes.get(name)
    }

    pub fn node_by_id(&self, id: NodeId) -> Option<&Node> {
        self.nodes.values().find(|node| node.id == id)
    }

    pub fn node_ids(&self) -> impl Iterator<Item = (&str, NodeId)> {
        self.nodes
            .values()
            .map(|node| (node.name.as_str(), node.id))
    }

    pub fn node_mut(&mut self, name: &str) -> Option<&mut Node> {
        self.nodes.get_mut(name)
    }

    pub fn edge(&self, from: &str, to: &str) -> Option<&Edge> {
        self.edges.get(&EdgeKey::new(from, to))
    }

    pub fn add_node(&mut self, node: Node) -> Result<(), GraphError> {
        if self.nodes.contains_key(&node.name) {
            return Err(GraphError::DuplicateNode(node.name));
        }

        self.nodes.insert(node.name.clone(), node);
        Ok(())
    }

    pub fn add_reachable_node(&mut self, name: impl Into<String>) -> Result<(), GraphError> {
        self.add_node(Node::new(name).reachable(true))
    }

    pub fn ensure_node(&mut self, name: impl Into<String>) -> bool {
        let name = name.into();

        if self.nodes.contains_key(&name) {
            return false;
        }

        self.nodes.insert(name.clone(), Node::new(name));
        true
    }

    pub fn add_edge(&mut self, edge: Edge) -> Result<(), GraphError> {
        if !self.nodes.contains_key(&edge.from) {
            return Err(GraphError::MissingNode(edge.from));
        }

        if !self.nodes.contains_key(&edge.to) {
            return Err(GraphError::MissingNode(edge.to));
        }

        let key = edge.key();

        if self.edges.contains_key(&key) {
            return Err(GraphError::DuplicateEdge(key));
        }

        self.edges.insert(key, edge);
        Ok(())
    }

    pub fn upsert_edge(&mut self, edge: Edge) -> Result<EdgeMutation, GraphError> {
        if !self.nodes.contains_key(&edge.from) {
            return Err(GraphError::MissingNode(edge.from));
        }

        if !self.nodes.contains_key(&edge.to) {
            return Err(GraphError::MissingNode(edge.to));
        }

        let key = edge.key();

        match self.edges.get_mut(&key) {
            Some(existing) if existing == &edge => Ok(EdgeMutation::Unchanged),
            Some(existing) => {
                *existing = edge;
                Ok(EdgeMutation::Updated)
            }
            None => {
                self.edges.insert(key, edge);
                Ok(EdgeMutation::Inserted)
            }
        }
    }

    pub fn remove_edge(&mut self, from: &str, to: &str) -> Option<Edge> {
        let key = EdgeKey::new(from, to);
        self.mst_edges.remove(&key);
        self.edges.remove(&key)
    }

    pub fn remove_edges_from(&mut self, from: &str) -> Vec<Edge> {
        let keys = self
            .edges
            .keys()
            .filter(|key| key.from == from)
            .cloned()
            .collect::<Vec<_>>();

        for key in &keys {
            self.mst_edges.remove(key);
        }

        keys.into_iter()
            .filter_map(|key| self.edges.remove(&key))
            .collect()
    }

    pub fn has_edge_to(&self, to: &str) -> bool {
        self.edges.keys().any(|key| key.to == to)
    }

    pub fn remove_node(&mut self, name: &str) -> Option<Node> {
        if name == self.myself {
            return None;
        }

        self.edges
            .retain(|key, _| key.from != name && key.to != name);
        self.mst_edges
            .retain(|key| key.from != name && key.to != name);
        self.nodes.remove(name)
    }

    pub fn connect_bidirectional(
        &mut self,
        first: &str,
        second: &str,
        weight: i32,
    ) -> Result<(), GraphError> {
        self.connect_bidirectional_with_options(first, second, weight, 0, 0)
    }

    pub fn connect_bidirectional_with_options(
        &mut self,
        first: &str,
        second: &str,
        weight: i32,
        first_to_second_options: u32,
        second_to_first_options: u32,
    ) -> Result<(), GraphError> {
        self.add_edge(Edge::new(first, second, weight).with_options(first_to_second_options))?;
        self.add_edge(Edge::new(second, first, weight).with_options(second_to_first_options))?;
        Ok(())
    }

    pub fn sssp_bfs(&mut self) {
        for node in self.nodes.values_mut() {
            node.status.visited = false;
            node.status.indirect = true;
            node.route = RouteState::default();
        }

        let myself = self.myself.clone();
        let Some(myself_node) = self.nodes.get_mut(&myself) else {
            return;
        };

        myself_node.status.visited = true;
        myself_node.status.indirect = false;
        myself_node.route.next_hop = Some(myself.clone());
        myself_node.route.via = Some(myself.clone());
        myself_node.route.distance = Some(0);
        myself_node.route.weighted_distance = Some(0);

        let mut queue = VecDeque::from([myself]);

        while let Some(name) = queue.pop_front() {
            let Some(from_state) = self.route_source_state(&name) else {
                continue;
            };

            for edge in self.outgoing_edges(&name) {
                if edge.to == self.myself || !self.has_reverse_edge(&edge) {
                    continue;
                }

                let new_distance = from_state.distance + 1;
                let new_weighted_distance = from_state.weighted_distance + edge.weight;
                let indirect = from_state.indirect || edge.options & OPTION_INDIRECT != 0;
                let Some(to_node) = self.nodes.get(&edge.to) else {
                    continue;
                };

                if should_keep_existing_route(
                    to_node,
                    indirect,
                    new_distance,
                    new_weighted_distance,
                ) {
                    continue;
                }

                let update_next_hop = !to_node.status.visited
                    || (to_node.route.distance == Some(new_distance)
                        && to_node
                            .route
                            .weighted_distance
                            .is_some_and(|current| current > new_weighted_distance));

                let next_hop = if update_next_hop {
                    Some(if from_state.next_hop == self.myself {
                        edge.to.clone()
                    } else {
                        from_state.next_hop.clone()
                    })
                } else {
                    to_node.route.next_hop.clone()
                };

                let weighted_distance = if update_next_hop {
                    Some(new_weighted_distance)
                } else {
                    to_node.route.weighted_distance
                };

                let via = if indirect {
                    Some(from_state.via.clone())
                } else {
                    Some(edge.to.clone())
                };

                let previous_edge = Some(edge.key());
                let to = edge.to.clone();

                if let Some(to_node) = self.nodes.get_mut(&to) {
                    to_node.status.visited = true;
                    to_node.status.indirect = indirect;
                    to_node.route.next_hop = next_hop;
                    to_node.route.weighted_distance = weighted_distance;
                    to_node.route.previous_edge = previous_edge;
                    to_node.route.via = via;
                    to_node.options = edge.options;
                    to_node.route.distance = Some(new_distance);
                }

                queue.push_back(to);
            }
        }
    }

    pub fn reconcile_reachability(&mut self, experimental: bool) -> ReachabilityChanges {
        self.reconcile_reachability_at(experimental, 0)
    }

    pub fn reconcile_reachability_at(
        &mut self,
        experimental: bool,
        now_secs: i64,
    ) -> ReachabilityChanges {
        let mut changes = ReachabilityChanges::default();

        for node in self.nodes.values_mut() {
            if node.status.visited == node.status.reachable {
                continue;
            }

            node.status.reachable = node.status.visited;
            node.last_state_change = now_secs;

            if node.status.reachable {
                changes.became_reachable.push(node.name.clone());
            } else {
                changes.became_unreachable.push(node.name.clone());
            }

            if experimental && option_version(node.options) >= 2 {
                node.status.sptps = true;
            }

            node.status.valid_key = false;

            if node.status.sptps {
                node.status.waiting_for_key = false;
            }

            node.status.udp_confirmed = false;

            if !node.status.reachable {
                node.status = NodeStatus::default();
                node.options = 0;
                node.udp_address = None;
            }
        }

        changes
    }

    pub fn mst_kruskal(&mut self) {
        self.mst_edges.clear();

        let edges = self.weight_sorted_edges();
        let Some(start) = edges.iter().find(|edge| {
            self.nodes
                .get(&edge.from)
                .is_some_and(|node| node.status.reachable)
        }) else {
            return;
        };

        let mut visited = BTreeSet::from([start.from.clone()]);
        let mut skipped = false;
        let mut index = 0;

        while index < edges.len() {
            let edge = &edges[index];
            let from_visited = visited.contains(&edge.from);
            let to_visited = visited.contains(&edge.to);

            if !self.has_reverse_edge(edge) || from_visited == to_visited {
                skipped = true;
                index += 1;
                continue;
            }

            visited.insert(edge.from.clone());
            visited.insert(edge.to.clone());
            self.mst_edges.insert(edge.key());
            self.mst_edges.insert(edge.key().reverse());

            if skipped {
                skipped = false;
                index = 0;
            } else {
                index += 1;
            }
        }
    }

    fn route_source_state(&self, name: &str) -> Option<RouteSourceState> {
        let node = self.nodes.get(name)?;

        Some(RouteSourceState {
            indirect: node.status.indirect,
            distance: node.route.distance?,
            weighted_distance: node.route.weighted_distance?,
            next_hop: node.route.next_hop.clone()?,
            via: node.route.via.clone()?,
        })
    }

    fn outgoing_edges(&self, from: &str) -> Vec<Edge> {
        self.edges
            .values()
            .filter(|edge| edge.from == from)
            .cloned()
            .collect()
    }

    fn weight_sorted_edges(&self) -> Vec<Edge> {
        let mut edges = self.edges.values().cloned().collect::<Vec<_>>();
        edges.sort_by(|left, right| {
            left.weight
                .cmp(&right.weight)
                .then_with(|| left.from.cmp(&right.from))
                .then_with(|| left.to.cmp(&right.to))
        });
        edges
    }

    fn has_reverse_edge(&self, edge: &Edge) -> bool {
        self.edges.contains_key(&edge.key().reverse())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EdgeMutation {
    Inserted,
    Updated,
    Unchanged,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ReachabilityChanges {
    pub became_reachable: Vec<String>,
    pub became_unreachable: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RouteSourceState {
    indirect: bool,
    distance: i32,
    weighted_distance: i32,
    next_hop: String,
    via: String,
}

fn should_keep_existing_route(
    to_node: &Node,
    indirect: bool,
    new_distance: i32,
    new_weighted_distance: i32,
) -> bool {
    to_node.status.visited
        && (!to_node.status.indirect || indirect)
        && (to_node.route.distance != Some(new_distance)
            || to_node
                .route
                .weighted_distance
                .is_some_and(|current| current <= new_weighted_distance))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn graph_with_planets() -> Graph {
        let mut graph = Graph::new("myself");
        graph.add_reachable_node("mars").unwrap();
        graph.add_reachable_node("saturn").unwrap();
        graph.add_reachable_node("neptune").unwrap();
        graph
    }

    #[test]
    fn node_id_is_first_six_sha512_bytes_of_name() {
        tinc_test_support::assert_can_create_netns();
        assert_eq!(
            NodeId::new([0xa6, 0x61, 0xcc, 0xfe, 0xd5, 0xa8]),
            NodeId::from_name("mars")
        );

        let node = Node::new("mars");
        assert_eq!(NodeId::from_name("mars"), node.id);
    }

    #[test]
    fn graph_can_lookup_nodes_by_node_id() {
        tinc_test_support::assert_can_create_netns();
        let mut graph = Graph::new("myself");
        graph.add_reachable_node("mars").unwrap();
        let id = NodeId::from_name("mars");

        assert_eq!(
            Some("mars"),
            graph.node_by_id(id).map(|node| node.name.as_str())
        );
        assert_eq!(None, graph.node_by_id(NodeId::NULL));
        assert!(
            graph
                .node_ids()
                .any(|(name, node_id)| name == "mars" && node_id == id)
        );
    }

    #[test]
    fn node_tracks_tinc_mtu_state_defaults() {
        tinc_test_support::assert_can_create_netns();
        #[cfg(feature = "jumbograms")]
        assert_eq!(9018, DEFAULT_MTU);
        #[cfg(not(feature = "jumbograms"))]
        assert_eq!(1518, DEFAULT_MTU);

        let node = Node::new("mars");
        assert_eq!(DEFAULT_MTU, node.mtu);
        assert_eq!(0, node.min_mtu);
        assert_eq!(DEFAULT_MTU, node.max_mtu);
        assert_eq!(0, node.mtu_probes);
        assert_eq!(None, node.udp_address);

        let node = Node::new("mars").with_mtu(900);
        assert_eq!(900, node.mtu);
        assert_eq!(900, node.min_mtu);
        assert_eq!(900, node.max_mtu);
    }

    fn assert_route(
        graph: &Graph,
        node: &str,
        distance: i32,
        next_hop: &str,
        previous_from: &str,
        previous_to: &str,
        via: &str,
    ) {
        let node = graph.node(node).unwrap();
        assert!(node.status.visited);
        assert!(!node.status.indirect);
        assert_eq!(Some(distance), node.route.distance);
        assert_eq!(Some(next_hop), node.route.next_hop.as_deref());
        assert_eq!(
            Some(&EdgeKey::new(previous_from, previous_to)),
            node.route.previous_edge.as_ref()
        );
        assert_eq!(Some(via), node.route.via.as_deref());
    }

    #[test]
    fn sssp_bfs_matches_c_weighted_same_hop_behavior() {
        tinc_test_support::assert_can_create_netns();
        let mut graph = graph_with_planets();

        //          50            1000
        // myself ------ mars ------------- neptune
        //      \                             /
        //       ----------------- saturn ----
        //              500                10
        graph.connect_bidirectional("myself", "mars", 50).unwrap();
        graph
            .connect_bidirectional("mars", "neptune", 1000)
            .unwrap();
        graph
            .connect_bidirectional("myself", "saturn", 500)
            .unwrap();
        graph
            .connect_bidirectional("saturn", "neptune", 10)
            .unwrap();

        graph.sssp_bfs();

        assert_route(&graph, "mars", 1, "mars", "myself", "mars", "mars");
        assert_route(&graph, "saturn", 1, "saturn", "myself", "saturn", "saturn");
        assert_route(
            &graph, "neptune", 2, "saturn", "saturn", "neptune", "neptune",
        );
    }

    #[test]
    fn sssp_bfs_matches_c_when_first_two_hop_route_is_more_expensive() {
        tinc_test_support::assert_can_create_netns();
        let mut graph = graph_with_planets();

        //          1000            500
        // myself ---------- mars ------------- neptune
        //      \                              /
        //       ------- saturn --------------
        //          50               501
        graph.connect_bidirectional("myself", "mars", 1000).unwrap();
        graph.connect_bidirectional("mars", "neptune", 500).unwrap();
        graph.connect_bidirectional("myself", "saturn", 50).unwrap();
        graph
            .connect_bidirectional("saturn", "neptune", 501)
            .unwrap();

        graph.sssp_bfs();

        assert_route(&graph, "mars", 1, "mars", "myself", "mars", "mars");
        assert_route(&graph, "saturn", 1, "saturn", "myself", "saturn", "saturn");
        assert_route(
            &graph, "neptune", 2, "saturn", "saturn", "neptune", "neptune",
        );
    }

    #[test]
    fn sssp_bfs_ignores_edges_without_reverse_edge() {
        tinc_test_support::assert_can_create_netns();
        let mut graph = Graph::new("myself");
        graph.add_reachable_node("mars").unwrap();
        graph
            .add_edge(Edge::new("myself", "mars", 1))
            .expect("nodes exist");

        graph.sssp_bfs();

        let mars = graph.node("mars").unwrap();
        assert!(!mars.status.visited);
        assert_eq!(None, mars.route.distance);
    }

    #[test]
    fn mst_kruskal_marks_only_weighted_tree_edges() {
        tinc_test_support::assert_can_create_netns();
        let mut graph = Graph::new("myself");
        graph.add_reachable_node("alpha").unwrap();
        graph.add_reachable_node("beta").unwrap();
        graph.add_reachable_node("gamma").unwrap();
        graph.connect_bidirectional("myself", "alpha", 1).unwrap();
        graph.connect_bidirectional("alpha", "beta", 1).unwrap();
        graph.connect_bidirectional("beta", "gamma", 1).unwrap();
        graph.connect_bidirectional("gamma", "myself", 50).unwrap();

        graph.sssp_bfs();
        graph.reconcile_reachability(true);
        graph.mst_kruskal();

        assert_eq!(vec!["alpha".to_owned()], graph.mst_neighbors("myself"));
        assert_eq!(
            vec!["beta".to_owned(), "myself".to_owned()],
            graph.mst_neighbors("alpha")
        );
        assert_eq!(
            vec!["alpha".to_owned(), "gamma".to_owned()],
            graph.mst_neighbors("beta")
        );
        assert_eq!(vec!["beta".to_owned()], graph.mst_neighbors("gamma"));
    }

    #[test]
    fn upsert_edge_inserts_updates_and_reports_unchanged() {
        tinc_test_support::assert_can_create_netns();
        let mut graph = Graph::new("myself");
        graph.add_reachable_node("mars").unwrap();

        let edge = Edge::new("myself", "mars", 1)
            .with_options(OPTION_INDIRECT)
            .with_address(EdgeEndpoint::new("203.0.113.1", "655"));

        assert_eq!(Ok(EdgeMutation::Inserted), graph.upsert_edge(edge.clone()));
        assert_eq!(Ok(EdgeMutation::Unchanged), graph.upsert_edge(edge));

        let updated = Edge::new("myself", "mars", 2)
            .with_options(OPTION_TCPONLY)
            .with_address(EdgeEndpoint::new("203.0.113.2", "655"));

        assert_eq!(Ok(EdgeMutation::Updated), graph.upsert_edge(updated));
        let stored = graph.edge("myself", "mars").unwrap();
        assert_eq!(2, stored.weight);
        assert_eq!(OPTION_TCPONLY, stored.options);
        assert_eq!(
            Some(&EdgeEndpoint::new("203.0.113.2", "655")),
            stored.address.as_ref()
        );
    }

    #[test]
    fn remove_edge_deletes_only_requested_direction() {
        tinc_test_support::assert_can_create_netns();
        let mut graph = Graph::new("myself");
        graph.add_reachable_node("mars").unwrap();
        graph.connect_bidirectional("myself", "mars", 1).unwrap();

        assert!(graph.remove_edge("myself", "mars").is_some());
        assert!(graph.edge("myself", "mars").is_none());
        assert!(graph.edge("mars", "myself").is_some());
    }

    #[test]
    fn sssp_bfs_propagates_indirect_edges_to_children() {
        tinc_test_support::assert_can_create_netns();
        let mut graph = Graph::new("myself");
        graph.add_reachable_node("relay").unwrap();
        graph.add_reachable_node("target").unwrap();
        graph
            .connect_bidirectional_with_options(
                "myself",
                "relay",
                1,
                OPTION_INDIRECT,
                OPTION_INDIRECT,
            )
            .unwrap();
        graph.connect_bidirectional("relay", "target", 1).unwrap();

        graph.sssp_bfs();

        let relay = graph.node("relay").unwrap();
        assert!(relay.status.visited);
        assert!(relay.status.indirect);
        assert_eq!(Some("myself"), relay.route.via.as_deref());

        let target = graph.node("target").unwrap();
        assert!(target.status.visited);
        assert!(target.status.indirect);
        assert_eq!(Some("relay"), target.route.next_hop.as_deref());
        assert_eq!(Some("myself"), target.route.via.as_deref());
    }

    #[test]
    fn option_version_reads_top_protocol_byte() {
        tinc_test_support::assert_can_create_netns();
        assert_eq!(0, option_version(OPTION_INDIRECT));
        assert_eq!(7, option_version(0x0700_0000 | OPTION_TCPONLY));
    }

    #[test]
    fn reconcile_reachability_marks_newly_visited_nodes_reachable() {
        tinc_test_support::assert_can_create_netns();
        let mut graph = Graph::new("myself");
        graph.add_node(Node::new("mars")).unwrap();
        graph.connect_bidirectional("myself", "mars", 1).unwrap();

        graph.sssp_bfs();
        let changes = graph.reconcile_reachability_at(true, 1234);

        assert_eq!(
            vec!["mars".to_owned(), "myself".to_owned()],
            changes.became_reachable
        );
        assert!(changes.became_unreachable.is_empty());
        assert!(graph.node("mars").unwrap().status.reachable);
        assert_eq!(1234, graph.node("mars").unwrap().last_state_change);

        graph.sssp_bfs();
        let unchanged = graph.reconcile_reachability_at(true, 5678);

        assert!(unchanged.became_reachable.is_empty());
        assert!(unchanged.became_unreachable.is_empty());
        assert_eq!(1234, graph.node("mars").unwrap().last_state_change);
    }

    #[test]
    fn reconcile_reachability_clears_state_for_unreachable_nodes() {
        tinc_test_support::assert_can_create_netns();
        let mut graph = Graph::new("myself");
        graph.add_node(Node::new("mars").reachable(true)).unwrap();

        {
            let mars = graph.nodes.get_mut("mars").unwrap();
            mars.status.valid_key = true;
            mars.status.udp_confirmed = true;
            mars.udp_address = Some(EdgeEndpoint::new("203.0.113.10", "655"));
            mars.options = 0x0200_0000 | OPTION_INDIRECT;
        }

        graph.sssp_bfs();
        let changes = graph.reconcile_reachability(true);

        assert!(changes.became_reachable.contains(&"myself".to_owned()));
        assert_eq!(vec!["mars".to_owned()], changes.became_unreachable);

        let mars = graph.node("mars").unwrap();
        assert!(!mars.status.reachable);
        assert!(!mars.status.valid_key);
        assert!(!mars.status.udp_confirmed);
        assert_eq!(None, mars.udp_address);
        assert_eq!(0, mars.options);
    }

    #[test]
    fn reconcile_reachability_enables_sptps_for_protocol_v2_nodes() {
        tinc_test_support::assert_can_create_netns();
        let mut graph = Graph::new("myself");
        graph.add_node(Node::new("mars")).unwrap();
        graph
            .connect_bidirectional_with_options("myself", "mars", 1, 0x0200_0000, 0)
            .unwrap();

        graph.sssp_bfs();
        graph.reconcile_reachability(true);

        assert!(graph.node("mars").unwrap().status.sptps);
    }
}
