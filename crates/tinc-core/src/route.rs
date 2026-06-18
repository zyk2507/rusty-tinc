// SPDX-License-Identifier: GPL-2.0-or-later

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::graph::{DEFAULT_MTU, OPTION_CLAMP_MSS};
use crate::state::NetworkState;
use crate::subnet::{MacAddr, Subnet};

pub const ETH_HLEN: usize = 14;
pub const ETH_P_IP: u16 = 0x0800;
pub const ETH_P_ARP: u16 = 0x0806;
pub const ETH_P_IPV6: u16 = 0x86DD;
pub const ETH_P_8021Q: u16 = 0x8100;
pub const ARP_PACKET_LEN: usize = 28;
pub const ARPHRD_ETHER: u16 = 1;
pub const ARPOP_REQUEST: u16 = 1;
pub const ARPOP_REPLY: u16 = 2;
pub const IPPROTO_ICMP: u8 = 1;
pub const IPPROTO_ICMPV6: u8 = 58;
pub const IP_MSS: usize = 576;
pub const IPV4_MIN_FULL_MTU: usize = ETH_HLEN + IP_MSS;
pub const IPV6_MIN_PAYLOAD_MTU: usize = 1280;
pub const IPV6_MIN_FULL_MTU: usize = ETH_HLEN + IPV6_MIN_PAYLOAD_MTU;
pub const IP_DF: u16 = 0x4000;
pub const IP_MF: u16 = 0x2000;
pub const IP_OFFMASK: u16 = 0x1fff;
pub const ICMP_SIZE: usize = 8;
pub const ICMP_DEST_UNREACH: u8 = 3;
pub const ICMP_FRAG_NEEDED: u8 = 4;
pub const ICMP_NET_UNKNOWN: u8 = 6;
pub const ICMP_TIME_EXCEEDED: u8 = 11;
pub const ICMP_EXC_TTL: u8 = 0;
pub const ICMP_NET_UNREACH: u8 = 0;
pub const ICMP_NET_ANO: u8 = 9;
pub const ICMPV6_SIZE: usize = 8;
pub const ICMP6_DST_UNREACH_NOROUTE: u8 = 0;
pub const ICMP6_DST_UNREACH: u8 = 1;
pub const ICMP6_PACKET_TOO_BIG: u8 = 2;
pub const ICMP6_TIME_EXCEEDED: u8 = 3;
pub const ICMP6_DST_UNREACH_ADMIN: u8 = 1;
pub const ICMP6_DST_UNREACH_ADDR: u8 = 3;
pub const ICMP6_TIME_EXCEED_TRANSIT: u8 = 0;
pub const ND_NEIGHBOR_SOLICIT: u8 = 135;
pub const ND_NEIGHBOR_ADVERT: u8 = 136;
pub const ND_OPT_SOURCE_LINKADDR: u8 = 1;
pub const ND_OPT_TARGET_LINKADDR: u8 = 2;
pub const ND_NEIGHBOR_SOLICIT_LEN: usize = 24;
pub const ND_OPT_LINKADDR_LEN: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RoutingMode {
    Hub,
    Switch,
    Router,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ForwardingMode {
    Off,
    Internal,
    Kernel,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RouteConfig {
    pub routing_mode: RoutingMode,
    pub forwarding_mode: ForwardingMode,
    pub direct_only: bool,
    pub decrement_ttl: bool,
    pub priority_inheritance: bool,
    pub mac_expire: i32,
    pub now_secs: i64,
}

impl Default for RouteConfig {
    fn default() -> Self {
        Self {
            routing_mode: RoutingMode::Router,
            forwarding_mode: ForwardingMode::Internal,
            direct_only: false,
            decrement_ttl: false,
            priority_inheritance: false,
            mac_expire: 600,
            now_secs: 0,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteOutcome {
    pub decision: RouteDecision,
    pub learned: Vec<Subnet>,
}

impl RouteOutcome {
    fn new(decision: RouteDecision) -> Self {
        Self {
            decision,
            learned: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoutedPacketAction {
    pub outcome: RouteOutcome,
    pub action: PacketAction,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PacketAction {
    Send {
        owner: String,
        via: Option<String>,
        packet: Vec<u8>,
        priority: Option<i32>,
        mss_clamp: Option<MssClamp>,
    },
    SendFragments {
        owner: String,
        via: Option<String>,
        fragments: Vec<Vec<u8>>,
        priority: Option<i32>,
    },
    Reply {
        target: String,
        packet: Vec<u8>,
        priority: Option<i32>,
    },
    Broadcast {
        packet: Vec<u8>,
    },
    DeliverLocal {
        packet: Vec<u8>,
    },
    Drop(RouteDropReason),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RouteDecision {
    Send { owner: String, via: Option<String> },
    Reply { target: String },
    Broadcast,
    DeliverLocal,
    Drop(RouteDropReason),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RouteDropReason {
    TooShort {
        expected_at_least: usize,
        actual: usize,
    },
    UnknownEtherType(u16),
    UnknownIpv4Destination(Ipv4Addr),
    UnknownIpv6Destination(Ipv6Addr),
    LoopbackToSource(String),
    UnreachableOwner(String),
    ForwardingDisabled,
    DirectOnly,
    RoutingLoop(String),
    TtlExpired,
    AddressResolutionFromRemote,
    InvalidArpRequest,
    UnknownArpTarget(Ipv4Addr),
    LocalArpTarget(Ipv4Addr),
    InvalidNeighborSolicitation,
    InvalidNeighborSolicitationChecksum,
    UnknownNeighborTarget(Ipv6Addr),
    LocalNeighborTarget(Ipv6Addr),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EthernetFrame<'a> {
    pub destination: MacAddr,
    pub source: MacAddr,
    pub ether_type: u16,
    pub payload: &'a [u8],
}

impl<'a> EthernetFrame<'a> {
    pub fn parse(packet: &'a [u8]) -> Result<Self, RouteDropReason> {
        if packet.len() < ETH_HLEN {
            return Err(RouteDropReason::TooShort {
                expected_at_least: ETH_HLEN,
                actual: packet.len(),
            });
        }

        let destination = MacAddr::new(packet[0..6].try_into().expect("slice length checked"));
        let source = MacAddr::new(packet[6..12].try_into().expect("slice length checked"));
        let ether_type = u16::from_be_bytes([packet[12], packet[13]]);

        Ok(Self {
            destination,
            source,
            ether_type,
            payload: &packet[ETH_HLEN..],
        })
    }
}

pub fn route_packet(
    state: &mut NetworkState,
    source: &str,
    packet: &[u8],
    config: RouteConfig,
) -> RouteOutcome {
    if config.forwarding_mode == ForwardingMode::Kernel && source != state.graph.myself() {
        return RouteOutcome::new(RouteDecision::DeliverLocal);
    }

    let frame = match EthernetFrame::parse(packet) {
        Ok(frame) => frame,
        Err(reason) => return RouteOutcome::new(RouteDecision::Drop(reason)),
    };

    match config.routing_mode {
        RoutingMode::Hub => RouteOutcome::new(RouteDecision::Broadcast),
        RoutingMode::Switch => route_mac(state, source, frame, config),
        RoutingMode::Router => match frame.ether_type {
            ETH_P_IP => route_ipv4(state, source, packet, config),
            ETH_P_IPV6 => route_ipv6(state, source, packet, config),
            ETH_P_ARP => RouteOutcome::new(RouteDecision::Drop(RouteDropReason::UnknownEtherType(
                ETH_P_ARP,
            ))),
            other => RouteOutcome::new(RouteDecision::Drop(RouteDropReason::UnknownEtherType(
                other,
            ))),
        },
    }
}

pub fn route_packet_mut(
    state: &mut NetworkState,
    source: &str,
    packet: &mut [u8],
    config: RouteConfig,
) -> RouteOutcome {
    let myself = state.graph.myself().to_owned();
    let outcome = route_packet(state, source, packet, config);

    if !config.decrement_ttl || !should_decrement_ttl(&outcome.decision, source, &myself) {
        return outcome;
    }

    match decrement_ttl(packet) {
        Ok(_) => outcome,
        Err(TtlError::Expired) => RouteOutcome {
            decision: RouteDecision::Drop(RouteDropReason::TtlExpired),
            learned: outcome.learned,
        },
        Err(TtlError::TooShort {
            expected_at_least,
            actual,
        }) => RouteOutcome {
            decision: RouteDecision::Drop(RouteDropReason::TooShort {
                expected_at_least,
                actual,
            }),
            learned: outcome.learned,
        },
    }
}

pub fn route_packet_action(
    state: &mut NetworkState,
    source: &str,
    packet: &[u8],
    config: RouteConfig,
) -> RoutedPacketAction {
    if config.routing_mode == RoutingMode::Router
        && let Some(routed) = address_resolution_action(state, source, packet, config)
    {
        return routed;
    }

    let mut routed_packet = packet.to_vec();
    let outcome = route_packet_mut(state, source, &mut routed_packet, config);
    let action = match &outcome.decision {
        RouteDecision::Send { owner, via } => {
            send_packet_action(state, source, owner, via.as_deref(), routed_packet, config)
        }
        RouteDecision::Reply { target } => PacketAction::Reply {
            target: target.clone(),
            packet: routed_packet,
            priority: None,
        },
        RouteDecision::Broadcast => PacketAction::Broadcast {
            packet: routed_packet,
        },
        RouteDecision::DeliverLocal => PacketAction::DeliverLocal {
            packet: routed_packet,
        },
        RouteDecision::Drop(reason) => {
            let priority = if matches!(reason, RouteDropReason::DirectOnly) {
                inherited_packet_priority(&routed_packet, config)
            } else {
                None
            };
            icmp_reply_for_drop(source, &routed_packet, reason, priority)
                .unwrap_or_else(|| PacketAction::Drop(reason.clone()))
        }
    };

    RoutedPacketAction { outcome, action }
}

pub fn decrement_ttl(packet: &mut [u8]) -> Result<TtlMutation, TtlError> {
    let (ether_type, ether_len) = ethernet_payload_type(packet)?;

    match ether_type {
        ETH_P_IP => decrement_ipv4_ttl(packet, ether_len),
        ETH_P_IPV6 => decrement_ipv6_hop_limit(packet, ether_len),
        _ => Ok(TtlMutation::NotApplicable),
    }
}

pub fn internet_checksum(data: &[u8], previous_sum: u16) -> u16 {
    let mut checksum = (previous_sum ^ 0xffff) as u32;
    let mut chunks = data.chunks_exact(2);

    for chunk in &mut chunks {
        checksum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }

    if let [byte] = chunks.remainder() {
        checksum += *byte as u32;
    }

    fold_checksum(checksum)
}

pub fn ipv4_icmp_error_packet(
    packet: &[u8],
    icmp_type: u8,
    icmp_code: u8,
    reply_source: Option<Ipv4Addr>,
) -> Result<Vec<u8>, IcmpErrorPacketError> {
    const IPV4_HEADER_LEN: usize = 20;
    const QUOTE_LIMIT: usize = IP_MSS - IPV4_HEADER_LEN - ICMP_SIZE;

    let (ether_type, ether_len) =
        ethernet_payload_type(packet).map_err(icmp_error_from_payload_error)?;

    if ether_type != ETH_P_IP {
        return Err(IcmpErrorPacketError::NotIpv4(ether_type));
    }

    let expected_at_least = ether_len + IPV4_HEADER_LEN;

    if packet.len() < expected_at_least {
        return Err(IcmpErrorPacketError::TooShort {
            expected_at_least,
            actual: packet.len(),
        });
    }

    let ip_start = ether_len;
    let original_source = Ipv4Addr::new(
        packet[ip_start + 12],
        packet[ip_start + 13],
        packet[ip_start + 14],
        packet[ip_start + 15],
    );
    let original_destination = Ipv4Addr::new(
        packet[ip_start + 16],
        packet[ip_start + 17],
        packet[ip_start + 18],
        packet[ip_start + 19],
    );
    let quoted_len = (packet.len() - ether_len).min(QUOTE_LIMIT);
    let total_len = IPV4_HEADER_LEN + ICMP_SIZE + quoted_len;

    let mut out = Vec::with_capacity(ether_len + total_len);
    out.extend_from_slice(&packet[..ether_len]);
    swap_ethernet_addresses(&mut out);

    let mut header = [0u8; IPV4_HEADER_LEN];
    header[0] = 0x45;
    header[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    header[8] = 255;
    header[9] = IPPROTO_ICMP;
    header[12..16].copy_from_slice(&reply_source.unwrap_or(original_destination).octets());
    header[16..20].copy_from_slice(&original_source.octets());
    let checksum = internet_checksum(&header, 0xffff);
    header[10..12].copy_from_slice(&checksum.to_be_bytes());
    out.extend_from_slice(&header);

    let mut icmp = Vec::with_capacity(ICMP_SIZE + quoted_len);
    icmp.resize(ICMP_SIZE, 0);
    icmp[0] = icmp_type;
    icmp[1] = icmp_code;

    if icmp_type == ICMP_DEST_UNREACH && icmp_code == ICMP_FRAG_NEEDED {
        let next_mtu = (packet.len() - ether_len) as u16;
        icmp[6..8].copy_from_slice(&next_mtu.to_be_bytes());
    }

    icmp.extend_from_slice(&packet[ether_len..ether_len + quoted_len]);
    let checksum = internet_checksum(&icmp, 0xffff);
    icmp[2..4].copy_from_slice(&checksum.to_be_bytes());
    out.extend_from_slice(&icmp);

    Ok(out)
}

pub fn ipv6_icmp_error_packet(
    packet: &[u8],
    icmp_type: u8,
    icmp_code: u8,
    reply_source: Option<Ipv6Addr>,
) -> Result<Vec<u8>, IcmpErrorPacketError> {
    const IPV6_HEADER_LEN: usize = 40;
    const QUOTE_LIMIT: usize = IP_MSS - IPV6_HEADER_LEN - ICMPV6_SIZE;

    let (ether_type, ether_len) =
        ethernet_payload_type(packet).map_err(icmp_error_from_payload_error)?;

    if ether_type != ETH_P_IPV6 {
        return Err(IcmpErrorPacketError::NotIpv6(ether_type));
    }

    let expected_at_least = ether_len + IPV6_HEADER_LEN;

    if packet.len() < expected_at_least {
        return Err(IcmpErrorPacketError::TooShort {
            expected_at_least,
            actual: packet.len(),
        });
    }

    let ip_start = ether_len;
    let original_source = Ipv6Addr::from(
        <[u8; 16]>::try_from(&packet[ip_start + 8..ip_start + 24])
            .expect("slice length checked by expected_at_least"),
    );
    let original_destination = Ipv6Addr::from(
        <[u8; 16]>::try_from(&packet[ip_start + 24..ip_start + 40])
            .expect("slice length checked by expected_at_least"),
    );
    let quoted_len = (packet.len() - ether_len).min(QUOTE_LIMIT);
    let payload_len = ICMPV6_SIZE + quoted_len;
    let response_source = reply_source.unwrap_or(original_destination);

    let mut out = Vec::with_capacity(ether_len + IPV6_HEADER_LEN + payload_len);
    out.extend_from_slice(&packet[..ether_len]);
    swap_ethernet_addresses(&mut out);

    let mut header = [0u8; IPV6_HEADER_LEN];
    header[0..4].copy_from_slice(&0x6000_0000u32.to_be_bytes());
    header[4..6].copy_from_slice(&(payload_len as u16).to_be_bytes());
    header[6] = IPPROTO_ICMPV6;
    header[7] = 255;
    header[8..24].copy_from_slice(&response_source.octets());
    header[24..40].copy_from_slice(&original_source.octets());
    out.extend_from_slice(&header);

    let mut icmp = Vec::with_capacity(payload_len);
    icmp.resize(ICMPV6_SIZE, 0);
    icmp[0] = icmp_type;
    icmp[1] = icmp_code;

    if icmp_type == ICMP6_PACKET_TOO_BIG {
        let mtu = (packet.len() - ether_len) as u32;
        icmp[4..8].copy_from_slice(&mtu.to_be_bytes());
    }

    icmp.extend_from_slice(&packet[ether_len..ether_len + quoted_len]);
    let checksum = ipv6_payload_checksum(
        response_source,
        original_source,
        IPPROTO_ICMPV6,
        payload_len,
        &icmp,
    );
    icmp[2..4].copy_from_slice(&checksum.to_be_bytes());
    out.extend_from_slice(&icmp);

    Ok(out)
}

pub fn arp_reply_packet(
    state: &NetworkState,
    source: &str,
    packet: &[u8],
) -> Result<Option<Vec<u8>>, RouteDropReason> {
    if source != state.graph.myself() {
        return Err(RouteDropReason::AddressResolutionFromRemote);
    }

    if packet.len() < ETH_HLEN + ARP_PACKET_LEN {
        return Err(RouteDropReason::TooShort {
            expected_at_least: ETH_HLEN + ARP_PACKET_LEN,
            actual: packet.len(),
        });
    }

    if u16::from_be_bytes([packet[12], packet[13]]) != ETH_P_ARP {
        return Err(RouteDropReason::UnknownEtherType(u16::from_be_bytes([
            packet[12], packet[13],
        ])));
    }

    let arp_start = ETH_HLEN;
    let hardware_type = u16::from_be_bytes([packet[arp_start], packet[arp_start + 1]]);
    let protocol_type = u16::from_be_bytes([packet[arp_start + 2], packet[arp_start + 3]]);
    let hardware_len = packet[arp_start + 4];
    let protocol_len = packet[arp_start + 5];
    let operation = u16::from_be_bytes([packet[arp_start + 6], packet[arp_start + 7]]);

    if hardware_type != ARPHRD_ETHER
        || protocol_type != ETH_P_IP
        || hardware_len != 6
        || protocol_len != 4
        || operation != ARPOP_REQUEST
    {
        return Err(RouteDropReason::InvalidArpRequest);
    }

    let target = Ipv4Addr::new(
        packet[arp_start + 24],
        packet[arp_start + 25],
        packet[arp_start + 26],
        packet[arp_start + 27],
    );
    let Some(subnet) = state.subnets.lookup_ipv4(target) else {
        return Err(RouteDropReason::UnknownArpTarget(target));
    };

    if subnet.owner.as_deref() == Some(state.graph.myself()) {
        return Err(RouteDropReason::LocalArpTarget(target));
    }

    let mut reply = packet.to_vec();
    let sender_protocol = [
        reply[arp_start + 14],
        reply[arp_start + 15],
        reply[arp_start + 16],
        reply[arp_start + 17],
    ];
    let target_protocol = [
        reply[arp_start + 24],
        reply[arp_start + 25],
        reply[arp_start + 26],
        reply[arp_start + 27],
    ];
    let sender_hardware: [u8; 6] = reply[arp_start + 8..arp_start + 14]
        .try_into()
        .expect("slice length checked by ARP_PACKET_LEN");
    let ethernet_source: [u8; 6] = packet[6..12]
        .try_into()
        .expect("slice length checked by ETH_HLEN");

    reply[arp_start + 6..arp_start + 8].copy_from_slice(&ARPOP_REPLY.to_be_bytes());
    reply[arp_start + 8..arp_start + 14].copy_from_slice(&ethernet_source);
    reply[arp_start + 13] ^= 0xff;
    reply[arp_start + 14..arp_start + 18].copy_from_slice(&target_protocol);
    reply[arp_start + 18..arp_start + 24].copy_from_slice(&sender_hardware);
    reply[arp_start + 24..arp_start + 28].copy_from_slice(&sender_protocol);

    Ok(Some(reply))
}

pub fn neighbor_advertisement_packet(
    state: &NetworkState,
    source: &str,
    packet: &[u8],
) -> Result<Option<Vec<u8>>, RouteDropReason> {
    if source != state.graph.myself() {
        return Err(RouteDropReason::AddressResolutionFromRemote);
    }

    if packet.len() < ETH_HLEN + 40 + ND_NEIGHBOR_SOLICIT_LEN {
        return Err(RouteDropReason::TooShort {
            expected_at_least: ETH_HLEN + 40 + ND_NEIGHBOR_SOLICIT_LEN,
            actual: packet.len(),
        });
    }

    if u16::from_be_bytes([packet[12], packet[13]]) != ETH_P_IPV6
        || packet[ETH_HLEN + 6] != IPPROTO_ICMPV6
    {
        return Err(RouteDropReason::InvalidNeighborSolicitation);
    }

    let icmp_start = ETH_HLEN + 40;
    let has_option = packet.len() >= icmp_start + ND_NEIGHBOR_SOLICIT_LEN + ND_OPT_LINKADDR_LEN;

    if packet[icmp_start] != ND_NEIGHBOR_SOLICIT
        || (has_option && packet[icmp_start + ND_NEIGHBOR_SOLICIT_LEN] != ND_OPT_SOURCE_LINKADDR)
    {
        return Err(RouteDropReason::InvalidNeighborSolicitation);
    }

    let nd_len = if has_option {
        ND_NEIGHBOR_SOLICIT_LEN + ND_OPT_LINKADDR_LEN
    } else {
        ND_NEIGHBOR_SOLICIT_LEN
    };

    if verify_ipv6_payload_checksum(packet, ETH_HLEN, nd_len) != 0 {
        return Err(RouteDropReason::InvalidNeighborSolicitationChecksum);
    }

    let target = Ipv6Addr::from(
        <[u8; 16]>::try_from(&packet[icmp_start + 8..icmp_start + 24])
            .expect("slice length checked by ND_NEIGHBOR_SOLICIT_LEN"),
    );
    let Some(subnet) = state.subnets.lookup_ipv6(target) else {
        return Err(RouteDropReason::UnknownNeighborTarget(target));
    };

    if subnet.owner.as_deref() == Some(state.graph.myself()) {
        return Err(RouteDropReason::LocalNeighborTarget(target));
    }

    let original_source_mac: [u8; 6] = packet[6..12]
        .try_into()
        .expect("slice length checked by ETH_HLEN");
    let mut fake_mac = original_source_mac;
    fake_mac[5] ^= 0xff;

    let mut reply = packet.to_vec();
    reply[0..6].copy_from_slice(&original_source_mac);
    reply[6..12].copy_from_slice(&fake_mac);
    reply[ETH_HLEN + 8..ETH_HLEN + 24].copy_from_slice(&target.octets());
    let original_ip_source: [u8; 16] = packet[ETH_HLEN + 8..ETH_HLEN + 24]
        .try_into()
        .expect("slice length checked by IPv6 header");
    reply[ETH_HLEN + 24..ETH_HLEN + 40].copy_from_slice(&original_ip_source);
    reply[icmp_start] = ND_NEIGHBOR_ADVERT;
    reply[icmp_start + 2] = 0;
    reply[icmp_start + 3] = 0;
    reply[icmp_start + 4..icmp_start + 8].copy_from_slice(&0x4000_0000u32.to_be_bytes());

    if has_option {
        reply[icmp_start + ND_NEIGHBOR_SOLICIT_LEN] = ND_OPT_TARGET_LINKADDR;
        reply[icmp_start + ND_NEIGHBOR_SOLICIT_LEN + 2
            ..icmp_start + ND_NEIGHBOR_SOLICIT_LEN + ND_OPT_LINKADDR_LEN]
            .copy_from_slice(&fake_mac);
    }

    let checksum = ipv6_payload_checksum(
        target,
        Ipv6Addr::from(original_ip_source),
        IPPROTO_ICMPV6,
        nd_len,
        &reply[icmp_start..icmp_start + nd_len],
    );
    reply[icmp_start + 2..icmp_start + 4].copy_from_slice(&checksum.to_be_bytes());

    Ok(Some(reply))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TtlMutation {
    Decremented,
    NotApplicable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TtlError {
    TooShort {
        expected_at_least: usize,
        actual: usize,
    },
    Expired,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IcmpErrorPacketError {
    TooShort {
        expected_at_least: usize,
        actual: usize,
    },
    NotIpv4(u16),
    NotIpv6(u16),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FragmentError {
    TooShort {
        expected_at_least: usize,
        actual: usize,
    },
    NotIpv4(u16),
    UnsupportedHeaderLength(u8),
    LengthMismatch {
        header_total_len: usize,
        actual_payload_len: usize,
    },
    MtuTooSmall {
        mtu: usize,
        required_at_least: usize,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MssClamp {
    Clamped { old: u16, new: u16 },
    AlreadySmall { current: u16, maximum: u16 },
    NoMssOption,
    NotTcp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MssClampError {
    TooShort {
        expected_at_least: usize,
        actual: usize,
    },
    InvalidTcpHeaderLength(u8),
    MtuTooSmall {
        mtu: usize,
        required_at_least: usize,
    },
}

pub fn clamp_tcp_mss(packet: &mut [u8], mtu: usize) -> Result<MssClamp, MssClampError> {
    let (ether_type, ether_len) = ethernet_payload_type(packet).map_err(|error| match error {
        TtlError::TooShort {
            expected_at_least,
            actual,
        } => MssClampError::TooShort {
            expected_at_least,
            actual,
        },
        TtlError::Expired => unreachable!("ethernet payload parsing cannot expire TTL"),
    })?;
    let Some(tcp_start) = tcp_header_start(packet, ether_type, ether_len)? else {
        return Ok(MssClamp::NotTcp);
    };

    if packet.len() == tcp_start + 20 {
        return Ok(MssClamp::NoMssOption);
    }

    if packet.len() < tcp_start + 20 {
        return Err(MssClampError::TooShort {
            expected_at_least: tcp_start + 20,
            actual: packet.len(),
        });
    }

    let data_offset = packet[tcp_start + 12] >> 4;

    if data_offset < 5 {
        return Err(MssClampError::InvalidTcpHeaderLength(data_offset));
    }

    let tcp_header_len = data_offset as usize * 4;

    if tcp_header_len == 20 {
        return Ok(MssClamp::NoMssOption);
    }

    if packet.len() < tcp_start + tcp_header_len {
        return Err(MssClampError::TooShort {
            expected_at_least: tcp_start + tcp_header_len,
            actual: packet.len(),
        });
    }

    let maximum = maximum_mss_for_mtu(mtu, tcp_start)?;
    let options_start = tcp_start + 20;
    let options_len = tcp_header_len - 20;
    let mut offset = 0usize;

    while offset < options_len {
        let kind = packet[options_start + offset];

        match kind {
            0 => break,
            1 => {
                offset += 1;
            }
            2 => {
                if offset + 1 >= options_len {
                    break;
                }

                let option_len = packet[options_start + offset + 1] as usize;

                if option_len != 4 || offset + option_len > options_len {
                    break;
                }

                let mss_offset = options_start + offset + 2;
                let old = u16::from_be_bytes([packet[mss_offset], packet[mss_offset + 1]]);

                if old <= maximum {
                    return Ok(MssClamp::AlreadySmall {
                        current: old,
                        maximum,
                    });
                }

                packet[mss_offset..mss_offset + 2].copy_from_slice(&maximum.to_be_bytes());
                let checksum_offset = tcp_start + 16;
                let checksum =
                    u16::from_be_bytes([packet[checksum_offset], packet[checksum_offset + 1]]);
                let checksum = incremental_transport_checksum_update(checksum, old, maximum);
                packet[checksum_offset..checksum_offset + 2]
                    .copy_from_slice(&checksum.to_be_bytes());

                return Ok(MssClamp::Clamped { old, new: maximum });
            }
            _ => {
                if offset + 1 >= options_len {
                    break;
                }

                let option_len = packet[options_start + offset + 1] as usize;

                if option_len < 2 || offset + option_len > options_len {
                    break;
                }

                offset += option_len;
            }
        }
    }

    Ok(MssClamp::NoMssOption)
}

pub fn fragment_ipv4_packet(packet: &[u8], mtu: usize) -> Result<Vec<Vec<u8>>, FragmentError> {
    let (ether_type, ether_len) =
        ethernet_payload_type_fragment(packet).map_err(|error| match error {
            TtlError::TooShort {
                expected_at_least,
                actual,
            } => FragmentError::TooShort {
                expected_at_least,
                actual,
            },
            TtlError::Expired => unreachable!("ethernet payload parsing cannot expire TTL"),
        })?;

    if ether_type != ETH_P_IP {
        return Err(FragmentError::NotIpv4(ether_type));
    }

    let minimum_len = ether_len + 20;

    if packet.len() < minimum_len {
        return Err(FragmentError::TooShort {
            expected_at_least: minimum_len,
            actual: packet.len(),
        });
    }

    let ihl_words = packet[ether_len] & 0x0f;

    if ihl_words != 5 {
        return Err(FragmentError::UnsupportedHeaderLength(ihl_words));
    }

    let ip_header_len = 20usize;
    let total_len = u16::from_be_bytes([packet[ether_len + 2], packet[ether_len + 3]]) as usize;

    if total_len != packet.len() - ether_len {
        return Err(FragmentError::LengthMismatch {
            header_total_len: total_len,
            actual_payload_len: packet.len() - ether_len,
        });
    }

    let max_payload_len = max_fragment_payload_len(mtu, ether_len, ip_header_len)?;
    let payload = &packet[ether_len + ip_header_len..];
    let mut remaining = payload.len();
    let mut payload_offset = 0usize;
    let original_fragment = u16::from_be_bytes([packet[ether_len + 6], packet[ether_len + 7]]);
    let original_flags = original_fragment & !IP_OFFMASK;
    let mut fragment_offset = original_fragment & IP_OFFMASK;
    let mut fragments = Vec::new();

    while remaining > 0 {
        let fragment_payload_len = remaining.min(max_payload_len);
        remaining -= fragment_payload_len;

        let mut fragment = Vec::with_capacity(ether_len + ip_header_len + fragment_payload_len);
        fragment.extend_from_slice(&packet[..ether_len + ip_header_len]);
        fragment.extend_from_slice(&payload[payload_offset..payload_offset + fragment_payload_len]);

        let fragment_ip_len = ip_header_len + fragment_payload_len;
        fragment[ether_len + 2..ether_len + 4]
            .copy_from_slice(&(fragment_ip_len as u16).to_be_bytes());

        let flags = original_flags | if remaining > 0 { IP_MF } else { 0 };
        fragment[ether_len + 6..ether_len + 8]
            .copy_from_slice(&(flags | fragment_offset).to_be_bytes());

        fragment[ether_len + 10] = 0;
        fragment[ether_len + 11] = 0;
        let checksum = internet_checksum(&fragment[ether_len..ether_len + ip_header_len], 0xffff);
        fragment[ether_len + 10..ether_len + 12].copy_from_slice(&checksum.to_be_bytes());

        fragments.push(fragment);
        payload_offset += fragment_payload_len;
        fragment_offset += (fragment_payload_len / 8) as u16;
    }

    Ok(fragments)
}

fn ethernet_payload_type_fragment(packet: &[u8]) -> Result<(u16, usize), TtlError> {
    ethernet_payload_type(packet)
}

fn max_fragment_payload_len(
    mtu: usize,
    ether_len: usize,
    ip_header_len: usize,
) -> Result<usize, FragmentError> {
    let effective_mtu = mtu.max(590);

    if effective_mtu <= ether_len + ip_header_len {
        return Err(FragmentError::MtuTooSmall {
            mtu,
            required_at_least: ether_len + ip_header_len + 8,
        });
    }

    let max_payload_len = (effective_mtu - ether_len - ip_header_len) & !0x7;

    if max_payload_len == 0 {
        return Err(FragmentError::MtuTooSmall {
            mtu,
            required_at_least: ether_len + ip_header_len + 8,
        });
    }

    Ok(max_payload_len)
}

fn tcp_header_start(
    packet: &[u8],
    ether_type: u16,
    ether_len: usize,
) -> Result<Option<usize>, MssClampError> {
    match ether_type {
        ETH_P_IP => {
            if packet.len() < ether_len + 20 {
                return Err(MssClampError::TooShort {
                    expected_at_least: ether_len + 20,
                    actual: packet.len(),
                });
            }

            let mut ip_start = ether_len;

            if packet[ip_start + 9] == 4 {
                ip_start += 20;

                if packet.len() < ip_start + 20 {
                    return Err(MssClampError::TooShort {
                        expected_at_least: ip_start + 20,
                        actual: packet.len(),
                    });
                }
            }

            if packet[ip_start + 9] != 6 {
                return Ok(None);
            }

            let ip_header_len = (packet[ip_start] & 0x0f) as usize * 4;
            Ok(Some(ip_start + ip_header_len))
        }
        ETH_P_IPV6 => {
            if packet.len() < ether_len + 40 {
                return Err(MssClampError::TooShort {
                    expected_at_least: ether_len + 40,
                    actual: packet.len(),
                });
            }

            if packet[ether_len + 6] == 6 {
                Ok(Some(ether_len + 40))
            } else {
                Ok(None)
            }
        }
        _ => Ok(None),
    }
}

fn maximum_mss_for_mtu(mtu: usize, tcp_start: usize) -> Result<u16, MssClampError> {
    let required_at_least = tcp_start + 21;

    if mtu < required_at_least {
        return Err(MssClampError::MtuTooSmall {
            mtu,
            required_at_least,
        });
    }

    let maximum = mtu - tcp_start - 20;
    u16::try_from(maximum).map_err(|_| MssClampError::MtuTooSmall {
        mtu,
        required_at_least,
    })
}

fn should_decrement_ttl(decision: &RouteDecision, source: &str, myself: &str) -> bool {
    match decision {
        RouteDecision::Broadcast => source != myself,
        RouteDecision::Send { owner, .. } => source != myself && owner != myself,
        RouteDecision::Reply { .. } | RouteDecision::DeliverLocal | RouteDecision::Drop(_) => false,
    }
}

fn address_resolution_action(
    state: &NetworkState,
    source: &str,
    packet: &[u8],
    _config: RouteConfig,
) -> Option<RoutedPacketAction> {
    let frame = EthernetFrame::parse(packet).ok()?;

    match frame.ether_type {
        ETH_P_ARP => Some(packet_reply_action(
            source,
            arp_reply_packet(state, source, packet),
        )),
        ETH_P_IPV6 if is_neighbor_solicitation_packet(packet) => Some(packet_reply_action(
            source,
            neighbor_advertisement_packet(state, source, packet),
        )),
        _ => None,
    }
}

fn packet_reply_action(
    source: &str,
    result: Result<Option<Vec<u8>>, RouteDropReason>,
) -> RoutedPacketAction {
    match result {
        Ok(Some(packet)) => {
            let target = source.to_owned();
            RoutedPacketAction {
                outcome: RouteOutcome::new(RouteDecision::Reply {
                    target: target.clone(),
                }),
                action: PacketAction::Reply {
                    target,
                    packet,
                    priority: None,
                },
            }
        }
        Ok(None) => RoutedPacketAction {
            outcome: RouteOutcome::new(RouteDecision::Drop(
                RouteDropReason::InvalidNeighborSolicitation,
            )),
            action: PacketAction::Drop(RouteDropReason::InvalidNeighborSolicitation),
        },
        Err(reason) => RoutedPacketAction {
            outcome: RouteOutcome::new(RouteDecision::Drop(reason.clone())),
            action: PacketAction::Drop(reason),
        },
    }
}

fn send_packet_action(
    state: &NetworkState,
    source: &str,
    owner: &str,
    via: Option<&str>,
    mut packet: Vec<u8>,
    config: RouteConfig,
) -> PacketAction {
    let via_name = via.unwrap_or(owner);
    let owner_owned = owner.to_owned();
    let via_owned = via.map(str::to_owned);
    let priority = inherited_packet_priority(&packet, config);

    if via_name == state.graph.myself() {
        return PacketAction::Send {
            owner: owner_owned,
            via: via_owned,
            packet,
            priority,
            mss_clamp: None,
        };
    }

    let Some(via_node) = state.graph.node(via_name) else {
        return PacketAction::Drop(RouteDropReason::UnreachableOwner(via_name.to_owned()));
    };

    let mtu = via_node.mtu;

    if packet.len() > effective_route_mtu(&packet, mtu, config.routing_mode)
        && let Some(action) = pmtu_action(
            source,
            owner,
            via,
            &packet,
            mtu,
            config.routing_mode,
            priority,
        )
    {
        return action;
    }

    let source_mtu = state
        .graph
        .node(source)
        .map(|node| node.mtu)
        .unwrap_or(DEFAULT_MTU);
    let clamp_mtu = source_mtu.min(mtu);
    let mss_clamp = if via_node.options & OPTION_CLAMP_MSS != 0 {
        match clamp_tcp_mss(&mut packet, clamp_mtu) {
            Ok(MssClamp::NotTcp | MssClamp::NoMssOption) => None,
            Ok(result @ (MssClamp::Clamped { .. } | MssClamp::AlreadySmall { .. })) => Some(result),
            Err(_) => None,
        }
    } else {
        None
    };

    PacketAction::Send {
        owner: owner_owned,
        via: via_owned,
        packet,
        priority,
        mss_clamp,
    }
}

fn pmtu_action(
    source: &str,
    owner: &str,
    via: Option<&str>,
    packet: &[u8],
    mtu: usize,
    routing_mode: RoutingMode,
    priority: Option<i32>,
) -> Option<PacketAction> {
    let (ether_type, ether_len) = ethernet_payload_type(packet).ok()?;

    match ether_type {
        ETH_P_IP if should_handle_ipv4_pmtu(packet, ether_len, routing_mode) => {
            if ipv4_dont_fragment(packet, ether_len) {
                let len = reported_pmtu_packet_len(packet, ether_len, 20, mtu, routing_mode)?;
                let truncated = packet[..len].to_vec();
                let reply =
                    ipv4_icmp_error_packet(&truncated, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED, None)
                        .ok()?;
                Some(PacketAction::Reply {
                    target: source.to_owned(),
                    packet: reply,
                    priority,
                })
            } else {
                let fragments = fragment_ipv4_packet(packet, mtu).ok()?;
                Some(PacketAction::SendFragments {
                    owner: owner.to_owned(),
                    via: via.map(str::to_owned),
                    fragments,
                    priority,
                })
            }
        }
        ETH_P_IPV6 if should_handle_ipv6_pmtu(packet, ether_len, routing_mode) => {
            let len = reported_pmtu_packet_len(packet, ether_len, 40, mtu, routing_mode)?;
            let truncated = packet[..len].to_vec();
            let reply = ipv6_icmp_error_packet(&truncated, ICMP6_PACKET_TOO_BIG, 0, None).ok()?;
            Some(PacketAction::Reply {
                target: source.to_owned(),
                packet: reply,
                priority,
            })
        }
        _ => None,
    }
}

fn inherited_packet_priority(packet: &[u8], config: RouteConfig) -> Option<i32> {
    if !config.priority_inheritance || packet.len() < ETH_HLEN {
        return None;
    }

    let ether_type = u16::from_be_bytes([packet[12], packet[13]]);

    match ether_type {
        ETH_P_IP if packet.len() >= ETH_HLEN + 20 => Some(packet[ETH_HLEN + 1] as i32),
        ETH_P_IPV6 if packet.len() >= ETH_HLEN + 40 => {
            Some((((packet[ETH_HLEN] & 0x0f) << 4) | (packet[ETH_HLEN + 1] >> 4)) as i32)
        }
        _ => None,
    }
}

fn effective_route_mtu(packet: &[u8], mtu: usize, routing_mode: RoutingMode) -> usize {
    match routing_mode {
        RoutingMode::Router => match ethernet_payload_type(packet).ok().map(|(kind, _)| kind) {
            Some(ETH_P_IP) => mtu.max(IPV4_MIN_FULL_MTU),
            Some(ETH_P_IPV6) => mtu.max(IPV6_MIN_FULL_MTU),
            _ => mtu,
        },
        RoutingMode::Switch | RoutingMode::Hub => mtu,
    }
}

fn should_handle_ipv4_pmtu(packet: &[u8], ether_len: usize, routing_mode: RoutingMode) -> bool {
    match routing_mode {
        RoutingMode::Router => true,
        RoutingMode::Switch | RoutingMode::Hub => packet.len() > IP_MSS + ether_len,
    }
}

fn should_handle_ipv6_pmtu(packet: &[u8], ether_len: usize, routing_mode: RoutingMode) -> bool {
    match routing_mode {
        RoutingMode::Router => true,
        RoutingMode::Switch | RoutingMode::Hub => packet.len() > IPV6_MIN_PAYLOAD_MTU + ether_len,
    }
}

fn reported_pmtu_packet_len(
    packet: &[u8],
    ether_len: usize,
    ip_header_len: usize,
    mtu: usize,
    routing_mode: RoutingMode,
) -> Option<usize> {
    let minimum = ether_len + ip_header_len;

    if packet.len() < minimum {
        return None;
    }

    let desired = match routing_mode {
        RoutingMode::Router => match ip_header_len {
            20 => mtu.max(IPV4_MIN_FULL_MTU),
            40 => mtu.max(IPV6_MIN_FULL_MTU),
            _ => mtu,
        },
        RoutingMode::Switch | RoutingMode::Hub => mtu,
    };

    Some(desired.max(minimum).min(packet.len()))
}

fn ipv4_dont_fragment(packet: &[u8], ether_len: usize) -> bool {
    packet
        .get(ether_len + 6)
        .is_some_and(|fragment_flags| fragment_flags & 0x40 != 0)
}

fn icmp_reply_for_drop(
    source: &str,
    packet: &[u8],
    reason: &RouteDropReason,
    priority: Option<i32>,
) -> Option<PacketAction> {
    let (ether_type, _) = ethernet_payload_type(packet).ok()?;
    let reply = match (ether_type, reason) {
        (ETH_P_IP, RouteDropReason::UnknownIpv4Destination(_)) => {
            ipv4_icmp_error_packet(packet, ICMP_DEST_UNREACH, ICMP_NET_UNKNOWN, None).ok()?
        }
        (ETH_P_IP, RouteDropReason::UnreachableOwner(_)) => {
            ipv4_icmp_error_packet(packet, ICMP_DEST_UNREACH, ICMP_NET_UNREACH, None).ok()?
        }
        (ETH_P_IP, RouteDropReason::ForwardingDisabled | RouteDropReason::DirectOnly) => {
            ipv4_icmp_error_packet(packet, ICMP_DEST_UNREACH, ICMP_NET_ANO, None).ok()?
        }
        (ETH_P_IP, RouteDropReason::TtlExpired) if !is_ipv4_time_exceeded(packet) => {
            ipv4_icmp_error_packet(packet, ICMP_TIME_EXCEEDED, ICMP_EXC_TTL, None).ok()?
        }
        (ETH_P_IPV6, RouteDropReason::UnknownIpv6Destination(_)) => {
            ipv6_icmp_error_packet(packet, ICMP6_DST_UNREACH, ICMP6_DST_UNREACH_ADDR, None).ok()?
        }
        (ETH_P_IPV6, RouteDropReason::UnreachableOwner(_)) => {
            ipv6_icmp_error_packet(packet, ICMP6_DST_UNREACH, ICMP6_DST_UNREACH_NOROUTE, None)
                .ok()?
        }
        (ETH_P_IPV6, RouteDropReason::ForwardingDisabled | RouteDropReason::DirectOnly) => {
            ipv6_icmp_error_packet(packet, ICMP6_DST_UNREACH, ICMP6_DST_UNREACH_ADMIN, None).ok()?
        }
        (ETH_P_IPV6, RouteDropReason::TtlExpired) if !is_ipv6_time_exceeded(packet) => {
            ipv6_icmp_error_packet(packet, ICMP6_TIME_EXCEEDED, ICMP6_TIME_EXCEED_TRANSIT, None)
                .ok()?
        }
        _ => return None,
    };

    Some(PacketAction::Reply {
        target: source.to_owned(),
        packet: reply,
        priority,
    })
}

fn is_ipv4_time_exceeded(packet: &[u8]) -> bool {
    let Ok((ETH_P_IP, ether_len)) = ethernet_payload_type(packet) else {
        return false;
    };

    if packet.len() < ether_len + 20 {
        return false;
    }

    let header_len = ((packet[ether_len] & 0x0f) as usize) * 4;
    packet.len() > ether_len + header_len
        && packet[ether_len + 9] == IPPROTO_ICMP
        && packet[ether_len + header_len] == ICMP_TIME_EXCEEDED
}

fn is_ipv6_time_exceeded(packet: &[u8]) -> bool {
    let Ok((ETH_P_IPV6, ether_len)) = ethernet_payload_type(packet) else {
        return false;
    };

    packet.len() > ether_len + 40
        && packet[ether_len + 6] == IPPROTO_ICMPV6
        && packet[ether_len + 40] == ICMP6_TIME_EXCEEDED
}

fn is_neighbor_solicitation_packet(packet: &[u8]) -> bool {
    let Ok((ETH_P_IPV6, ether_len)) = ethernet_payload_type(packet) else {
        return false;
    };

    packet.len() >= ether_len + 40 + ND_NEIGHBOR_SOLICIT_LEN
        && packet[ether_len + 6] == IPPROTO_ICMPV6
        && packet[ether_len + 40] == ND_NEIGHBOR_SOLICIT
}

fn ethernet_payload_type(packet: &[u8]) -> Result<(u16, usize), TtlError> {
    if packet.len() < ETH_HLEN {
        return Err(TtlError::TooShort {
            expected_at_least: ETH_HLEN,
            actual: packet.len(),
        });
    }

    let mut ether_type = u16::from_be_bytes([packet[12], packet[13]]);
    let mut ether_len = ETH_HLEN;

    if ether_type == ETH_P_8021Q {
        let expected_at_least = ETH_HLEN + 4;

        if packet.len() < expected_at_least {
            return Err(TtlError::TooShort {
                expected_at_least,
                actual: packet.len(),
            });
        }

        ether_type = u16::from_be_bytes([packet[16], packet[17]]);
        ether_len = expected_at_least;
    }

    Ok((ether_type, ether_len))
}

fn icmp_error_from_payload_error(error: TtlError) -> IcmpErrorPacketError {
    match error {
        TtlError::TooShort {
            expected_at_least,
            actual,
        } => IcmpErrorPacketError::TooShort {
            expected_at_least,
            actual,
        },
        TtlError::Expired => unreachable!("ethernet payload parsing cannot expire TTL"),
    }
}

fn swap_ethernet_addresses(packet: &mut [u8]) {
    for index in 0..6 {
        packet.swap(index, index + 6);
    }
}

fn ipv6_payload_checksum(
    source: Ipv6Addr,
    destination: Ipv6Addr,
    next_header: u8,
    payload_len: usize,
    payload: &[u8],
) -> u16 {
    let mut pseudo = Vec::with_capacity(40 + payload.len());
    pseudo.extend_from_slice(&source.octets());
    pseudo.extend_from_slice(&destination.octets());
    pseudo.extend_from_slice(&(payload_len as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, next_header]);
    pseudo.extend_from_slice(payload);
    internet_checksum(&pseudo, 0xffff)
}

fn verify_ipv6_payload_checksum(packet: &[u8], ether_len: usize, payload_len: usize) -> u16 {
    let ip_start = ether_len;
    let payload_start = ip_start + 40;
    let payload_end = payload_start + payload_len;

    if packet.len() < payload_end {
        return 1;
    }

    let source = Ipv6Addr::from(
        <[u8; 16]>::try_from(&packet[ip_start + 8..ip_start + 24])
            .expect("slice length checked by IPv6 header"),
    );
    let destination = Ipv6Addr::from(
        <[u8; 16]>::try_from(&packet[ip_start + 24..ip_start + 40])
            .expect("slice length checked by IPv6 header"),
    );

    ipv6_payload_checksum(
        source,
        destination,
        packet[ip_start + 6],
        payload_len,
        &packet[payload_start..payload_end],
    )
}

fn decrement_ipv4_ttl(packet: &mut [u8], ether_len: usize) -> Result<TtlMutation, TtlError> {
    let expected_at_least = ether_len + 20;

    if packet.len() < expected_at_least {
        return Err(TtlError::TooShort {
            expected_at_least,
            actual: packet.len(),
        });
    }

    let ttl = packet[ether_len + 8];

    if ttl <= 1 {
        return Err(TtlError::Expired);
    }

    let protocol = packet[ether_len + 9];
    let old = u16::from_be_bytes([ttl, protocol]);
    packet[ether_len + 8] = ttl - 1;
    let new = u16::from_be_bytes([ttl - 1, protocol]);

    let checksum_offset = ether_len + 10;
    let checksum = u16::from_be_bytes([packet[checksum_offset], packet[checksum_offset + 1]]);
    let checksum = incremental_checksum_update(checksum, old, new);
    packet[checksum_offset..checksum_offset + 2].copy_from_slice(&checksum.to_be_bytes());

    Ok(TtlMutation::Decremented)
}

fn decrement_ipv6_hop_limit(packet: &mut [u8], ether_len: usize) -> Result<TtlMutation, TtlError> {
    let expected_at_least = ether_len + 40;

    if packet.len() < expected_at_least {
        return Err(TtlError::TooShort {
            expected_at_least,
            actual: packet.len(),
        });
    }

    let hop_limit = packet[ether_len + 7];

    if hop_limit <= 1 {
        return Err(TtlError::Expired);
    }

    packet[ether_len + 7] = hop_limit - 1;
    Ok(TtlMutation::Decremented)
}

fn incremental_checksum_update(checksum: u16, old: u16, new: u16) -> u16 {
    let mut checksum = checksum as u32 + old as u32 + (!new as u32 & 0xffff);

    while checksum >> 16 != 0 {
        checksum = (checksum & 0xffff) + (checksum >> 16);
    }

    checksum as u16
}

fn incremental_transport_checksum_update(checksum: u16, old: u16, new: u16) -> u16 {
    let mut checksum = (checksum ^ 0xffff) as u32;
    checksum += (old ^ 0xffff) as u32;
    checksum += new as u32;
    checksum = (checksum & 0xffff) + (checksum >> 16);
    checksum += checksum >> 16;
    (checksum as u16) ^ 0xffff
}

fn fold_checksum(mut checksum: u32) -> u16 {
    while checksum >> 16 != 0 {
        checksum = (checksum & 0xffff) + (checksum >> 16);
    }

    !(checksum as u16)
}

fn route_ipv4(
    state: &NetworkState,
    source: &str,
    packet: &[u8],
    config: RouteConfig,
) -> RouteOutcome {
    const IPV4_MIN_LEN: usize = ETH_HLEN + 20;

    if packet.len() < IPV4_MIN_LEN {
        return RouteOutcome::new(RouteDecision::Drop(RouteDropReason::TooShort {
            expected_at_least: IPV4_MIN_LEN,
            actual: packet.len(),
        }));
    }

    let destination = Ipv4Addr::new(packet[30], packet[31], packet[32], packet[33]);
    let Some(subnet) = state.subnets.lookup_ipv4(destination) else {
        return RouteOutcome::new(RouteDecision::Drop(
            RouteDropReason::UnknownIpv4Destination(destination),
        ));
    };

    route_to_subnet_owner(state, source, subnet, config, IpFamily::Ipv4)
}

fn route_ipv6(
    state: &NetworkState,
    source: &str,
    packet: &[u8],
    config: RouteConfig,
) -> RouteOutcome {
    const IPV6_MIN_LEN: usize = ETH_HLEN + 40;

    if packet.len() < IPV6_MIN_LEN {
        return RouteOutcome::new(RouteDecision::Drop(RouteDropReason::TooShort {
            expected_at_least: IPV6_MIN_LEN,
            actual: packet.len(),
        }));
    }

    let destination = Ipv6Addr::from(
        <[u8; 16]>::try_from(&packet[38..54]).expect("slice length checked by IPV6_MIN_LEN"),
    );
    let Some(subnet) = state.subnets.lookup_ipv6(destination) else {
        return RouteOutcome::new(RouteDecision::Drop(
            RouteDropReason::UnknownIpv6Destination(destination),
        ));
    };

    route_to_subnet_owner(state, source, subnet, config, IpFamily::Ipv6)
}

fn route_mac(
    state: &mut NetworkState,
    source: &str,
    frame: EthernetFrame<'_>,
    config: RouteConfig,
) -> RouteOutcome {
    let mut outcome = RouteOutcome::new(RouteDecision::Broadcast);

    if source == state.graph.myself() {
        let expires = config.now_secs + i64::from(config.mac_expire);
        let local = Subnet::mac(frame.source).with_owner(state.graph.myself().to_owned());

        if let Some(existing) = state
            .subnets
            .lookup_owner_subnet_mut(state.graph.myself(), &local)
        {
            if existing.expires.is_some() {
                existing.expires = Some(expires);
            }
        } else {
            let local = local.with_expiry(expires);
            state.subnets.add(local.clone());
            outcome.learned.push(local);
        }
    }

    let Some(subnet) = state.subnets.lookup_mac(frame.destination) else {
        return outcome;
    };

    let Some(owner) = subnet.owner.as_deref() else {
        return outcome;
    };

    if owner == source {
        outcome.decision = RouteDecision::Drop(RouteDropReason::LoopbackToSource(owner.to_owned()));
        return outcome;
    }

    if config.forwarding_mode == ForwardingMode::Off
        && source != state.graph.myself()
        && owner != state.graph.myself()
    {
        outcome.decision = RouteDecision::Drop(RouteDropReason::ForwardingDisabled);
        return outcome;
    }

    let via = route_via(state, source, owner);

    if via.as_deref() == Some(source) {
        outcome.decision = RouteDecision::Drop(RouteDropReason::RoutingLoop(source.to_owned()));
        return outcome;
    }

    if config.direct_only && !direct_only_allows(state, owner, via.as_deref()) {
        outcome.decision = RouteDecision::Drop(RouteDropReason::DirectOnly);
        return outcome;
    }

    outcome.decision = RouteDecision::Send {
        owner: owner.to_owned(),
        via,
    };
    outcome
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IpFamily {
    Ipv4,
    Ipv6,
}

fn route_to_subnet_owner(
    state: &NetworkState,
    source: &str,
    subnet: &Subnet,
    config: RouteConfig,
    family: IpFamily,
) -> RouteOutcome {
    let Some(owner) = subnet.owner.as_deref() else {
        return RouteOutcome::new(RouteDecision::Broadcast);
    };

    if owner == source {
        return RouteOutcome::new(RouteDecision::Drop(RouteDropReason::LoopbackToSource(
            owner.to_owned(),
        )));
    }

    let Some(owner_node) = state.graph.node(owner) else {
        return RouteOutcome::new(RouteDecision::Drop(RouteDropReason::UnreachableOwner(
            owner.to_owned(),
        )));
    };

    if !owner_node.status.reachable {
        return RouteOutcome::new(RouteDecision::Drop(RouteDropReason::UnreachableOwner(
            owner.to_owned(),
        )));
    }

    if config.forwarding_mode == ForwardingMode::Off
        && source != state.graph.myself()
        && owner != state.graph.myself()
    {
        return RouteOutcome::new(RouteDecision::Drop(RouteDropReason::ForwardingDisabled));
    }

    let via = route_via(state, source, owner);

    if via.as_deref() == Some(source) {
        return RouteOutcome::new(RouteDecision::Drop(RouteDropReason::RoutingLoop(
            source.to_owned(),
        )));
    }

    if config.direct_only && !direct_only_allows(state, owner, via.as_deref()) {
        return RouteOutcome::new(RouteDecision::Drop(RouteDropReason::DirectOnly));
    }

    let _ = family;

    RouteOutcome::new(RouteDecision::Send {
        owner: owner.to_owned(),
        via,
    })
}

fn route_via(state: &NetworkState, source: &str, owner: &str) -> Option<String> {
    let node = state.graph.node(owner)?;

    let _ = source;
    let via = node.route.via.as_deref();
    if via == Some(state.graph.myself()) {
        node.route.next_hop.clone()
    } else {
        node.route.via.clone()
    }
}

fn direct_only_allows(state: &NetworkState, owner: &str, via: Option<&str>) -> bool {
    state
        .graph
        .node(owner)
        .is_some_and(|node| via == Some(owner) && node.route.next_hop.as_deref() == Some(owner))
}

pub fn ethernet_packet(
    destination: MacAddr,
    source: MacAddr,
    ether_type: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut packet = Vec::with_capacity(ETH_HLEN + payload.len());
    packet.extend_from_slice(&destination.octets());
    packet.extend_from_slice(&source.octets());
    packet.extend_from_slice(&ether_type.to_be_bytes());
    packet.extend_from_slice(payload);
    packet
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::parse_meta_message;

    fn mac(last: u8) -> MacAddr {
        MacAddr::new([0x02, 0, 0, 0, 0, last])
    }

    fn ipv4_packet(destination: Ipv4Addr) -> Vec<u8> {
        ipv4_packet_with_payload(destination, &[])
    }

    fn ipv4_packet_with_payload(destination: Ipv4Addr, body: &[u8]) -> Vec<u8> {
        let mut payload = vec![0; 20];
        payload[0] = 0x45;
        payload[2..4].copy_from_slice(&((20 + body.len()) as u16).to_be_bytes());
        payload[8] = 64;
        payload[9] = 17;
        payload[12..16].copy_from_slice(&Ipv4Addr::new(192, 0, 2, 1).octets());
        payload[16..20].copy_from_slice(&destination.octets());
        let checksum = internet_checksum(&payload, 0xffff);
        payload[10..12].copy_from_slice(&checksum.to_be_bytes());
        payload.extend_from_slice(body);
        ethernet_packet(mac(2), mac(1), ETH_P_IP, &payload)
    }

    fn ipv4_header_checksum(packet: &[u8], ether_len: usize) -> u16 {
        let mut header = packet[ether_len..ether_len + 20].to_vec();
        header[10] = 0;
        header[11] = 0;
        internet_checksum(&header, 0xffff)
    }

    fn ipv6_packet(destination: Ipv6Addr) -> Vec<u8> {
        ipv6_packet_with_payload(destination, 17, &[])
    }

    fn ipv6_packet_with_payload(destination: Ipv6Addr, next_header: u8, body: &[u8]) -> Vec<u8> {
        let mut payload = vec![0; 40];
        payload[0] = 0x60;
        payload[4..6].copy_from_slice(&(body.len() as u16).to_be_bytes());
        payload[6] = next_header;
        payload[7] = 64;
        payload[8..24].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        payload[24..40].copy_from_slice(&destination.octets());
        payload.extend_from_slice(body);
        ethernet_packet(mac(2), mac(1), ETH_P_IPV6, &payload)
    }

    fn arp_request(target: Ipv4Addr) -> Vec<u8> {
        let mut payload = vec![0; ARP_PACKET_LEN];
        payload[0..2].copy_from_slice(&ARPHRD_ETHER.to_be_bytes());
        payload[2..4].copy_from_slice(&ETH_P_IP.to_be_bytes());
        payload[4] = 6;
        payload[5] = 4;
        payload[6..8].copy_from_slice(&ARPOP_REQUEST.to_be_bytes());
        payload[8..14].copy_from_slice(&mac(1).octets());
        payload[14..18].copy_from_slice(&Ipv4Addr::new(192, 0, 2, 1).octets());
        payload[24..28].copy_from_slice(&target.octets());
        ethernet_packet(mac(255), mac(1), ETH_P_ARP, &payload)
    }

    fn neighbor_solicitation(target: Ipv6Addr, include_option: bool) -> Vec<u8> {
        let mut icmp = vec![0; ND_NEIGHBOR_SOLICIT_LEN];
        icmp[0] = ND_NEIGHBOR_SOLICIT;
        icmp[8..24].copy_from_slice(&target.octets());

        if include_option {
            icmp.extend_from_slice(&[
                ND_OPT_SOURCE_LINKADDR,
                1,
                mac(1).octets()[0],
                mac(1).octets()[1],
                mac(1).octets()[2],
                mac(1).octets()[3],
                mac(1).octets()[4],
                mac(1).octets()[5],
            ]);
        }

        let source = Ipv6Addr::LOCALHOST;
        let checksum = ipv6_payload_checksum(source, target, IPPROTO_ICMPV6, icmp.len(), &icmp);
        icmp[2..4].copy_from_slice(&checksum.to_be_bytes());

        let mut payload = vec![0; 40];
        payload[0] = 0x60;
        payload[4..6].copy_from_slice(&(icmp.len() as u16).to_be_bytes());
        payload[6] = IPPROTO_ICMPV6;
        payload[7] = 255;
        payload[8..24].copy_from_slice(&source.octets());
        payload[24..40].copy_from_slice(&target.octets());
        payload.extend_from_slice(&icmp);
        ethernet_packet(mac(255), mac(1), ETH_P_IPV6, &payload)
    }

    fn tcp_header_with_mss(mss: u16) -> Vec<u8> {
        let mut tcp = vec![0; 24];
        tcp[0..2].copy_from_slice(&12345u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&80u16.to_be_bytes());
        tcp[12] = 6 << 4;
        tcp[13] = 0x02;
        tcp[14..16].copy_from_slice(&65535u16.to_be_bytes());
        tcp[20] = 2;
        tcp[21] = 4;
        tcp[22..24].copy_from_slice(&mss.to_be_bytes());
        tcp
    }

    fn tcp_ipv4_packet(mss: u16) -> Vec<u8> {
        let tcp = tcp_header_with_mss(mss);
        let mut packet = ipv4_packet_with_payload(Ipv4Addr::new(10, 0, 0, 42), &tcp);
        packet[ETH_HLEN + 9] = 6;
        packet[ETH_HLEN + 10] = 0;
        packet[ETH_HLEN + 11] = 0;
        let ip_checksum = ipv4_header_checksum(&packet, ETH_HLEN);
        packet[ETH_HLEN + 10..ETH_HLEN + 12].copy_from_slice(&ip_checksum.to_be_bytes());
        let tcp_start = ETH_HLEN + 20;
        let tcp_checksum = tcp_ipv4_checksum(&packet, tcp_start);
        packet[tcp_start + 16..tcp_start + 18].copy_from_slice(&tcp_checksum.to_be_bytes());
        packet
    }

    fn tcp_ipv6_packet(mss: u16) -> Vec<u8> {
        let tcp = tcp_header_with_mss(mss);
        let mut payload = vec![0; 40];
        payload[0] = 0x60;
        payload[4..6].copy_from_slice(&(tcp.len() as u16).to_be_bytes());
        payload[6] = 6;
        payload[7] = 64;
        payload[8..24].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        payload[24..40].copy_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
        payload.extend_from_slice(&tcp);
        let mut packet = ethernet_packet(mac(2), mac(1), ETH_P_IPV6, &payload);
        let tcp_start = ETH_HLEN + 40;
        let checksum = tcp_ipv6_checksum(&packet, tcp_start);
        packet[tcp_start + 16..tcp_start + 18].copy_from_slice(&checksum.to_be_bytes());
        packet
    }

    fn tcp_ipv4_checksum(packet: &[u8], tcp_start: usize) -> u16 {
        let tcp_len = packet.len() - tcp_start;
        let ip_start = tcp_start - 20;
        let mut pseudo = Vec::new();
        pseudo.extend_from_slice(&packet[ip_start + 12..ip_start + 16]);
        pseudo.extend_from_slice(&packet[ip_start + 16..ip_start + 20]);
        pseudo.push(0);
        pseudo.push(6);
        pseudo.extend_from_slice(&(tcp_len as u16).to_be_bytes());
        let mut tcp = packet[tcp_start..].to_vec();
        tcp[16] = 0;
        tcp[17] = 0;
        pseudo.extend_from_slice(&tcp);
        internet_checksum(&pseudo, 0xffff)
    }

    fn tcp_ipv6_checksum(packet: &[u8], tcp_start: usize) -> u16 {
        let tcp_len = packet.len() - tcp_start;
        let ip_start = tcp_start - 40;
        let mut pseudo = Vec::new();
        pseudo.extend_from_slice(&packet[ip_start + 8..ip_start + 24]);
        pseudo.extend_from_slice(&packet[ip_start + 24..ip_start + 40]);
        pseudo.extend_from_slice(&(tcp_len as u32).to_be_bytes());
        pseudo.extend_from_slice(&[0, 0, 0, 6]);
        let mut tcp = packet[tcp_start..].to_vec();
        tcp[16] = 0;
        tcp[17] = 0;
        pseudo.extend_from_slice(&tcp);
        internet_checksum(&pseudo, 0xffff)
    }

    fn ipv6_payload_len(packet: &[u8], ether_len: usize) -> usize {
        let ip_start = ether_len;
        u16::from_be_bytes([packet[ip_start + 4], packet[ip_start + 5]]) as usize
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
            .apply_meta_message(parse_meta_message("10 4 alpha 2001:db8::/32").unwrap())
            .unwrap();
        state
    }

    #[test]
    fn router_mode_routes_ipv4_to_subnet_owner() {
        tinc_test_support::assert_can_create_netns();
        let mut state = routed_state();
        let outcome = route_packet(
            &mut state,
            "myself",
            &ipv4_packet(Ipv4Addr::new(10, 0, 0, 42)),
            RouteConfig::default(),
        );

        assert_eq!(
            RouteOutcome::new(RouteDecision::Send {
                owner: "alpha".to_owned(),
                via: Some("alpha".to_owned()),
            }),
            outcome
        );
    }

    #[test]
    fn router_mode_routes_ipv6_to_subnet_owner() {
        tinc_test_support::assert_can_create_netns();
        let mut state = routed_state();
        let outcome = route_packet(
            &mut state,
            "myself",
            &ipv6_packet("2001:db8::1".parse().unwrap()),
            RouteConfig::default(),
        );

        assert_eq!(
            RouteOutcome::new(RouteDecision::Send {
                owner: "alpha".to_owned(),
                via: Some("alpha".to_owned()),
            }),
            outcome
        );
    }

    #[test]
    fn router_mode_routes_non_indirect_multihop_to_owner_via_owner_like_tinc() {
        tinc_test_support::assert_can_create_netns();
        let mut state = NetworkState::new("myself");
        state.graph.ensure_node("relay");
        state.graph.ensure_node("target");
        state
            .graph
            .connect_bidirectional("myself", "relay", 1)
            .unwrap();
        state
            .graph
            .connect_bidirectional("relay", "target", 1)
            .unwrap();
        state.graph.sssp_bfs();
        state.graph.reconcile_reachability(true);
        state
            .apply_meta_message(parse_meta_message("10 1 target 10.2.0.0/16").unwrap())
            .unwrap();

        let outcome = route_packet(
            &mut state,
            "myself",
            &ipv4_packet(Ipv4Addr::new(10, 2, 0, 42)),
            RouteConfig::default(),
        );

        assert_eq!(
            RouteOutcome::new(RouteDecision::Send {
                owner: "target".to_owned(),
                via: Some("target".to_owned()),
            }),
            outcome,
            "C route_ipv4() computes via = (owner->via == myself) ? owner->nexthop : owner->via, so non-indirect multihop keeps the owner as UDP via"
        );
    }

    #[test]
    fn direct_only_drops_non_direct_multihop_destinations() {
        tinc_test_support::assert_can_create_netns();
        let mut state = NetworkState::new("myself");
        state.graph.ensure_node("relay");
        state.graph.ensure_node("target");
        state
            .graph
            .connect_bidirectional("myself", "relay", 1)
            .unwrap();
        state
            .graph
            .connect_bidirectional("relay", "target", 1)
            .unwrap();
        state.graph.sssp_bfs();
        state.graph.reconcile_reachability(true);
        state
            .apply_meta_message(parse_meta_message("10 1 target 10.2.0.0/16").unwrap())
            .unwrap();
        state
            .apply_meta_message(parse_meta_message("10 2 target 2001:db8:2::/48").unwrap())
            .unwrap();
        state
            .apply_meta_message(parse_meta_message("10 3 target 02:00:00:00:00:09").unwrap())
            .unwrap();

        let config = RouteConfig {
            direct_only: true,
            ..RouteConfig::default()
        };
        assert_eq!(
            RouteDecision::Drop(RouteDropReason::DirectOnly),
            route_packet(
                &mut state,
                "myself",
                &ipv4_packet(Ipv4Addr::new(10, 2, 0, 42)),
                config
            )
            .decision
        );
        assert_eq!(
            RouteDecision::Drop(RouteDropReason::DirectOnly),
            route_packet(
                &mut state,
                "myself",
                &ipv6_packet("2001:db8:2::1".parse().unwrap()),
                config
            )
            .decision
        );
        assert_eq!(
            RouteDecision::Drop(RouteDropReason::DirectOnly),
            route_packet(
                &mut state,
                "myself",
                &ethernet_packet(mac(9), mac(1), ETH_P_IP, &[0; 20]),
                RouteConfig {
                    routing_mode: RoutingMode::Switch,
                    direct_only: true,
                    ..RouteConfig::default()
                },
            )
            .decision
        );
    }

    #[test]
    fn direct_only_allows_direct_destination() {
        tinc_test_support::assert_can_create_netns();
        let mut state = routed_state();

        let outcome = route_packet(
            &mut state,
            "myself",
            &ipv4_packet(Ipv4Addr::new(10, 0, 0, 42)),
            RouteConfig {
                direct_only: true,
                ..RouteConfig::default()
            },
        );

        assert_eq!(
            RouteDecision::Send {
                owner: "alpha".to_owned(),
                via: Some("alpha".to_owned()),
            },
            outcome.decision
        );
    }

    #[test]
    fn router_mode_drops_unknown_ip_destinations() {
        tinc_test_support::assert_can_create_netns();
        let mut state = routed_state();
        let outcome = route_packet(
            &mut state,
            "myself",
            &ipv4_packet(Ipv4Addr::new(203, 0, 113, 1)),
            RouteConfig::default(),
        );

        assert_eq!(
            RouteOutcome::new(RouteDecision::Drop(
                RouteDropReason::UnknownIpv4Destination(Ipv4Addr::new(203, 0, 113, 1)),
            )),
            outcome
        );
    }

    #[test]
    fn router_mode_prevents_source_loopback_and_disabled_forwarding() {
        tinc_test_support::assert_can_create_netns();
        let mut state = routed_state();
        let packet = ipv4_packet(Ipv4Addr::new(10, 0, 0, 42));

        assert_eq!(
            RouteOutcome::new(RouteDecision::Drop(RouteDropReason::LoopbackToSource(
                "alpha".to_owned(),
            ))),
            route_packet(&mut state, "alpha", &packet, RouteConfig::default())
        );

        state.graph.ensure_node("beta");
        assert_eq!(
            RouteOutcome::new(RouteDecision::Drop(RouteDropReason::ForwardingDisabled)),
            route_packet(
                &mut state,
                "beta",
                &packet,
                RouteConfig {
                    forwarding_mode: ForwardingMode::Off,
                    ..RouteConfig::default()
                },
            )
        );
    }

    #[test]
    fn kernel_forwarding_delivers_remote_packets_locally() {
        tinc_test_support::assert_can_create_netns();
        let mut state = routed_state();
        assert_eq!(
            RouteOutcome::new(RouteDecision::DeliverLocal),
            route_packet(
                &mut state,
                "alpha",
                &ipv4_packet(Ipv4Addr::new(10, 0, 0, 42)),
                RouteConfig {
                    forwarding_mode: ForwardingMode::Kernel,
                    ..RouteConfig::default()
                },
            )
        );
    }

    #[test]
    fn switch_mode_learns_local_source_mac_and_broadcasts_unknown_destination() {
        tinc_test_support::assert_can_create_netns();
        let mut state = NetworkState::new("myself");
        let packet = ethernet_packet(mac(9), mac(1), ETH_P_IP, &[0; 20]);

        let outcome = route_packet(
            &mut state,
            "myself",
            &packet,
            RouteConfig {
                routing_mode: RoutingMode::Switch,
                ..RouteConfig::default()
            },
        );

        assert_eq!(RouteDecision::Broadcast, outcome.decision);
        assert_eq!(
            vec![Subnet::mac(mac(1)).with_owner("myself").with_expiry(600)],
            outcome.learned
        );
        assert!(
            state
                .subnets
                .lookup_owner_subnet("myself", &Subnet::mac(mac(1)))
                .is_some()
        );
    }

    #[test]
    fn switch_mode_refreshes_dynamic_local_mac_expiry_like_tinc() {
        tinc_test_support::assert_can_create_netns();
        let mut state = NetworkState::new("myself");
        state
            .subnets
            .add(Subnet::mac(mac(1)).with_owner("myself").with_expiry(120));
        let packet = ethernet_packet(mac(9), mac(1), ETH_P_IP, &[0; 20]);

        let outcome = route_packet(
            &mut state,
            "myself",
            &packet,
            RouteConfig {
                routing_mode: RoutingMode::Switch,
                now_secs: 1000,
                mac_expire: 30,
                ..RouteConfig::default()
            },
        );

        assert_eq!(RouteDecision::Broadcast, outcome.decision);
        assert!(outcome.learned.is_empty());
        assert_eq!(
            Some(1030),
            state
                .subnets
                .lookup_owner_subnet("myself", &Subnet::mac(mac(1)))
                .and_then(|subnet| subnet.expires)
        );
    }

    #[test]
    fn switch_mode_routes_known_destination_mac() {
        tinc_test_support::assert_can_create_netns();
        let mut state = routed_state();
        state
            .apply_meta_message(parse_meta_message("10 5 alpha 02:00:00:00:00:09").unwrap())
            .unwrap();
        let packet = ethernet_packet(mac(9), mac(1), ETH_P_IP, &[0; 20]);

        let outcome = route_packet(
            &mut state,
            "myself",
            &packet,
            RouteConfig {
                routing_mode: RoutingMode::Switch,
                ..RouteConfig::default()
            },
        );

        assert_eq!(
            RouteDecision::Send {
                owner: "alpha".to_owned(),
                via: Some("alpha".to_owned()),
            },
            outcome.decision
        );
    }

    #[test]
    fn route_packet_action_inherits_ip_priority_like_tinc() {
        tinc_test_support::assert_can_create_netns();
        let mut state = routed_state();
        let mut ipv4 = ipv4_packet(Ipv4Addr::new(10, 0, 0, 42));
        ipv4[ETH_HLEN + 1] = 0xb8;

        let action = route_packet_action(
            &mut state,
            "myself",
            &ipv4,
            RouteConfig {
                priority_inheritance: true,
                ..RouteConfig::default()
            },
        );
        let PacketAction::Send { priority, .. } = action.action else {
            panic!("expected send action");
        };
        assert_eq!(Some(0xb8), priority);

        let action = route_packet_action(&mut state, "myself", &ipv4, RouteConfig::default());
        let PacketAction::Send { priority, .. } = action.action else {
            panic!("expected send action");
        };
        assert_eq!(None, priority);

        let mut ipv6 = ipv6_packet("2001:db8::1".parse().unwrap());
        ipv6[ETH_HLEN] = 0x6a;
        ipv6[ETH_HLEN + 1] = 0xb0;
        let action = route_packet_action(
            &mut state,
            "myself",
            &ipv6,
            RouteConfig {
                priority_inheritance: true,
                ..RouteConfig::default()
            },
        );
        let PacketAction::Send { priority, .. } = action.action else {
            panic!("expected send action");
        };
        assert_eq!(Some(0xab), priority);
    }

    #[test]
    fn switch_priority_inheritance_does_not_peek_inside_vlan_like_tinc() {
        tinc_test_support::assert_can_create_netns();
        let mut state = routed_state();
        state
            .apply_meta_message(parse_meta_message("10 5 alpha 02:00:00:00:00:09").unwrap())
            .unwrap();
        let mut inner = ipv4_packet(Ipv4Addr::new(10, 0, 0, 42));
        inner[ETH_HLEN + 1] = 0xb8;

        let mut packet = Vec::new();
        packet.extend_from_slice(&mac(9).octets());
        packet.extend_from_slice(&mac(1).octets());
        packet.extend_from_slice(&ETH_P_8021Q.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&ETH_P_IP.to_be_bytes());
        packet.extend_from_slice(&inner[ETH_HLEN..]);

        let action = route_packet_action(
            &mut state,
            "myself",
            &packet,
            RouteConfig {
                routing_mode: RoutingMode::Switch,
                priority_inheritance: true,
                ..RouteConfig::default()
            },
        );
        let PacketAction::Send { priority, .. } = action.action else {
            panic!("expected send action");
        };
        assert_eq!(None, priority);
    }

    #[test]
    fn hub_mode_broadcasts_every_valid_ethernet_packet() {
        tinc_test_support::assert_can_create_netns();
        let mut state = NetworkState::new("myself");
        let packet = ethernet_packet(mac(9), mac(1), ETH_P_IP, &[0; 20]);

        assert_eq!(
            RouteOutcome::new(RouteDecision::Broadcast),
            route_packet(
                &mut state,
                "myself",
                &packet,
                RouteConfig {
                    routing_mode: RoutingMode::Hub,
                    ..RouteConfig::default()
                },
            )
        );
    }

    #[test]
    fn route_rejects_short_packets() {
        tinc_test_support::assert_can_create_netns();
        let mut state = NetworkState::new("myself");
        assert_eq!(
            RouteOutcome::new(RouteDecision::Drop(RouteDropReason::TooShort {
                expected_at_least: ETH_HLEN,
                actual: 3,
            })),
            route_packet(&mut state, "myself", &[1, 2, 3], RouteConfig::default())
        );
    }

    #[test]
    fn decrement_ttl_updates_ipv4_ttl_and_header_checksum() {
        tinc_test_support::assert_can_create_netns();
        let mut packet = ipv4_packet(Ipv4Addr::new(10, 0, 0, 42));
        let old_checksum = u16::from_be_bytes([packet[ETH_HLEN + 10], packet[ETH_HLEN + 11]]);

        assert_eq!(Ok(TtlMutation::Decremented), decrement_ttl(&mut packet));
        assert_eq!(63, packet[ETH_HLEN + 8]);
        assert_ne!(
            old_checksum,
            u16::from_be_bytes([packet[ETH_HLEN + 10], packet[ETH_HLEN + 11]])
        );

        let mut header = packet[ETH_HLEN..ETH_HLEN + 20].to_vec();
        header[10] = 0;
        header[11] = 0;
        let checksum = internet_checksum(&header, 0xffff);
        assert_eq!(
            checksum,
            u16::from_be_bytes([packet[ETH_HLEN + 10], packet[ETH_HLEN + 11]])
        );
    }

    #[test]
    fn decrement_ttl_updates_ipv6_hop_limit() {
        tinc_test_support::assert_can_create_netns();
        let mut packet = ipv6_packet("2001:db8::1".parse().unwrap());

        assert_eq!(Ok(TtlMutation::Decremented), decrement_ttl(&mut packet));
        assert_eq!(63, packet[ETH_HLEN + 7]);
    }

    #[test]
    fn decrement_ttl_handles_vlan_inner_packet_type() {
        tinc_test_support::assert_can_create_netns();
        let inner = ipv4_packet(Ipv4Addr::new(10, 0, 0, 42));
        let mut packet = Vec::new();
        packet.extend_from_slice(&inner[0..12]);
        packet.extend_from_slice(&ETH_P_8021Q.to_be_bytes());
        packet.extend_from_slice(&[0, 7]);
        packet.extend_from_slice(&ETH_P_IP.to_be_bytes());
        packet.extend_from_slice(&inner[ETH_HLEN..]);

        assert_eq!(Ok(TtlMutation::Decremented), decrement_ttl(&mut packet));
        assert_eq!(63, packet[ETH_HLEN + 4 + 8]);
    }

    #[test]
    fn decrement_ttl_reports_expired_and_short_packets() {
        tinc_test_support::assert_can_create_netns();
        let mut packet = ipv4_packet(Ipv4Addr::new(10, 0, 0, 42));
        packet[ETH_HLEN + 8] = 1;
        assert_eq!(Err(TtlError::Expired), decrement_ttl(&mut packet));

        let mut short = ethernet_packet(mac(2), mac(1), ETH_P_IPV6, &[0; 12]);
        assert_eq!(
            Err(TtlError::TooShort {
                expected_at_least: ETH_HLEN + 40,
                actual: ETH_HLEN + 12,
            }),
            decrement_ttl(&mut short)
        );
    }

    #[test]
    fn ipv4_icmp_error_packet_reverses_addresses_and_quotes_original_ip_packet() {
        tinc_test_support::assert_can_create_netns();
        let body = (0u8..=255).cycle().take(64).collect::<Vec<_>>();
        let packet = ipv4_packet_with_payload(Ipv4Addr::new(10, 0, 0, 42), &body);

        let reply = ipv4_icmp_error_packet(
            &packet,
            ICMP_DEST_UNREACH,
            ICMP_NET_UNKNOWN,
            Some(Ipv4Addr::new(198, 51, 100, 9)),
        )
        .unwrap();

        assert_eq!(&mac(1).octets(), &reply[0..6]);
        assert_eq!(&mac(2).octets(), &reply[6..12]);
        assert_eq!(ETH_P_IP, u16::from_be_bytes([reply[12], reply[13]]));
        assert_eq!(0x45, reply[ETH_HLEN]);
        assert_eq!(
            20 + ICMP_SIZE + packet.len() - ETH_HLEN,
            u16::from_be_bytes([reply[ETH_HLEN + 2], reply[ETH_HLEN + 3]]) as usize
        );
        assert_eq!(255, reply[ETH_HLEN + 8]);
        assert_eq!(IPPROTO_ICMP, reply[ETH_HLEN + 9]);
        assert_eq!(
            &Ipv4Addr::new(198, 51, 100, 9).octets(),
            &reply[ETH_HLEN + 12..ETH_HLEN + 16]
        );
        assert_eq!(
            &Ipv4Addr::new(192, 0, 2, 1).octets(),
            &reply[ETH_HLEN + 16..ETH_HLEN + 20]
        );
        assert_eq!(
            ipv4_header_checksum(&reply, ETH_HLEN),
            u16::from_be_bytes([reply[ETH_HLEN + 10], reply[ETH_HLEN + 11],])
        );

        let icmp_start = ETH_HLEN + 20;
        assert_eq!(ICMP_DEST_UNREACH, reply[icmp_start]);
        assert_eq!(ICMP_NET_UNKNOWN, reply[icmp_start + 1]);
        assert_eq!(
            0,
            internet_checksum(&reply[icmp_start..], 0xffff),
            "ICMP checksum should verify to zero"
        );
        assert_eq!(&packet[ETH_HLEN..], &reply[icmp_start + ICMP_SIZE..]);
    }

    #[test]
    fn ipv4_icmp_error_packet_sets_fragment_needed_mtu_and_preserves_vlan() {
        tinc_test_support::assert_can_create_netns();
        let inner = ipv4_packet_with_payload(Ipv4Addr::new(10, 0, 0, 42), &[0xaa; 90]);
        let mut packet = Vec::new();
        packet.extend_from_slice(&inner[0..12]);
        packet.extend_from_slice(&ETH_P_8021Q.to_be_bytes());
        packet.extend_from_slice(&[0, 7]);
        packet.extend_from_slice(&ETH_P_IP.to_be_bytes());
        packet.extend_from_slice(&inner[ETH_HLEN..]);

        let reply =
            ipv4_icmp_error_packet(&packet, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED, None).unwrap();
        let ether_len = ETH_HLEN + 4;
        let icmp_start = ether_len + 20;

        assert_eq!(ETH_P_8021Q, u16::from_be_bytes([reply[12], reply[13]]));
        assert_eq!(ETH_P_IP, u16::from_be_bytes([reply[16], reply[17]]));
        assert_eq!(
            (packet.len() - ether_len) as u16,
            u16::from_be_bytes([reply[icmp_start + 6], reply[icmp_start + 7]])
        );
        assert_eq!(
            &Ipv4Addr::new(10, 0, 0, 42).octets(),
            &reply[ether_len + 12..ether_len + 16]
        );
        assert_eq!(
            &Ipv4Addr::new(192, 0, 2, 1).octets(),
            &reply[ether_len + 16..ether_len + 20]
        );
        assert_eq!(0, internet_checksum(&reply[icmp_start..], 0xffff));
    }

    #[test]
    fn ipv4_icmp_error_packet_truncates_quote_to_576_byte_mss() {
        tinc_test_support::assert_can_create_netns();
        let packet = ipv4_packet_with_payload(Ipv4Addr::new(10, 0, 0, 42), &[0xbb; 1000]);
        let reply =
            ipv4_icmp_error_packet(&packet, ICMP_TIME_EXCEEDED, ICMP_EXC_TTL, None).unwrap();
        let quoted_len = IP_MSS - 20 - ICMP_SIZE;

        assert_eq!(ETH_HLEN + 20 + ICMP_SIZE + quoted_len, reply.len());
        assert_eq!(
            &packet[ETH_HLEN..ETH_HLEN + quoted_len],
            &reply[ETH_HLEN + 20 + ICMP_SIZE..]
        );
    }

    #[test]
    fn ipv6_icmp_error_packet_reverses_addresses_and_checksums_payload() {
        tinc_test_support::assert_can_create_netns();
        let packet = ipv6_packet_with_payload(
            "2001:db8::42".parse().unwrap(),
            17,
            &(0u8..=255).cycle().take(72).collect::<Vec<_>>(),
        );

        let reply = ipv6_icmp_error_packet(
            &packet,
            ICMP6_DST_UNREACH,
            ICMP6_DST_UNREACH_ADDR,
            Some("2001:db8::99".parse().unwrap()),
        )
        .unwrap();

        assert_eq!(&mac(1).octets(), &reply[0..6]);
        assert_eq!(&mac(2).octets(), &reply[6..12]);
        assert_eq!(ETH_P_IPV6, u16::from_be_bytes([reply[12], reply[13]]));
        assert_eq!(0x60, reply[ETH_HLEN]);
        assert_eq!(IPPROTO_ICMPV6, reply[ETH_HLEN + 6]);
        assert_eq!(255, reply[ETH_HLEN + 7]);
        assert_eq!(
            &"2001:db8::99".parse::<Ipv6Addr>().unwrap().octets(),
            &reply[ETH_HLEN + 8..ETH_HLEN + 24]
        );
        assert_eq!(
            &Ipv6Addr::LOCALHOST.octets(),
            &reply[ETH_HLEN + 24..ETH_HLEN + 40]
        );

        let icmp_start = ETH_HLEN + 40;
        assert_eq!(ICMP6_DST_UNREACH, reply[icmp_start]);
        assert_eq!(ICMP6_DST_UNREACH_ADDR, reply[icmp_start + 1]);
        assert_eq!(
            0,
            verify_ipv6_payload_checksum(&reply, ETH_HLEN, ipv6_payload_len(&reply, ETH_HLEN))
        );
        assert_eq!(&packet[ETH_HLEN..], &reply[icmp_start + ICMPV6_SIZE..]);
    }

    #[test]
    fn ipv6_icmp_error_packet_sets_packet_too_big_mtu_and_truncates() {
        tinc_test_support::assert_can_create_netns();
        let inner = ipv6_packet_with_payload("2001:db8::42".parse().unwrap(), 17, &[0xcc; 1000]);
        let mut packet = Vec::new();
        packet.extend_from_slice(&inner[0..12]);
        packet.extend_from_slice(&ETH_P_8021Q.to_be_bytes());
        packet.extend_from_slice(&[0, 7]);
        packet.extend_from_slice(&ETH_P_IPV6.to_be_bytes());
        packet.extend_from_slice(&inner[ETH_HLEN..]);

        let reply = ipv6_icmp_error_packet(&packet, ICMP6_PACKET_TOO_BIG, 0, None).unwrap();
        let ether_len = ETH_HLEN + 4;
        let icmp_start = ether_len + 40;
        let quoted_len = IP_MSS - 40 - ICMPV6_SIZE;

        assert_eq!(ETH_P_8021Q, u16::from_be_bytes([reply[12], reply[13]]));
        assert_eq!(ETH_P_IPV6, u16::from_be_bytes([reply[16], reply[17]]));
        assert_eq!(ether_len + 40 + ICMPV6_SIZE + quoted_len, reply.len());
        assert_eq!(
            (packet.len() - ether_len) as u32,
            u32::from_be_bytes([
                reply[icmp_start + 4],
                reply[icmp_start + 5],
                reply[icmp_start + 6],
                reply[icmp_start + 7],
            ])
        );
        assert_eq!(
            0,
            verify_ipv6_payload_checksum(&reply, ether_len, ipv6_payload_len(&reply, ether_len))
        );
        assert_eq!(
            &packet[ether_len..ether_len + quoted_len],
            &reply[icmp_start + ICMPV6_SIZE..]
        );
    }

    #[test]
    fn icmp_error_packet_rejects_wrong_family_and_short_packets() {
        tinc_test_support::assert_can_create_netns();
        let ipv4 = ipv4_packet(Ipv4Addr::new(10, 0, 0, 42));
        assert_eq!(
            Err(IcmpErrorPacketError::NotIpv6(ETH_P_IP)),
            ipv6_icmp_error_packet(&ipv4, ICMP6_TIME_EXCEEDED, ICMP6_TIME_EXCEED_TRANSIT, None)
        );

        let ipv6 = ipv6_packet("2001:db8::1".parse().unwrap());
        assert_eq!(
            Err(IcmpErrorPacketError::NotIpv4(ETH_P_IPV6)),
            ipv4_icmp_error_packet(&ipv6, ICMP_TIME_EXCEEDED, ICMP_EXC_TTL, None)
        );

        let short = ethernet_packet(mac(2), mac(1), ETH_P_IP, &[0; 8]);
        assert_eq!(
            Err(IcmpErrorPacketError::TooShort {
                expected_at_least: ETH_HLEN + 20,
                actual: ETH_HLEN + 8,
            }),
            ipv4_icmp_error_packet(&short, ICMP_TIME_EXCEEDED, ICMP_EXC_TTL, None)
        );
    }

    #[test]
    fn clamp_tcp_mss_updates_ipv4_mss_and_checksum() {
        tinc_test_support::assert_can_create_netns();
        let mut packet = tcp_ipv4_packet(1460);
        let tcp_start = ETH_HLEN + 20;

        assert_eq!(
            Ok(MssClamp::Clamped { old: 1460, new: 46 }),
            clamp_tcp_mss(&mut packet, 100)
        );
        assert_eq!(
            46,
            u16::from_be_bytes([packet[tcp_start + 22], packet[tcp_start + 23]])
        );
        assert_eq!(
            tcp_ipv4_checksum(&packet, tcp_start),
            u16::from_be_bytes([packet[tcp_start + 16], packet[tcp_start + 17]])
        );
    }

    #[test]
    fn clamp_tcp_mss_updates_ipv6_mss_and_checksum() {
        tinc_test_support::assert_can_create_netns();
        let mut packet = tcp_ipv6_packet(1460);
        let tcp_start = ETH_HLEN + 40;

        assert_eq!(
            Ok(MssClamp::Clamped { old: 1460, new: 26 }),
            clamp_tcp_mss(&mut packet, 100)
        );
        assert_eq!(
            26,
            u16::from_be_bytes([packet[tcp_start + 22], packet[tcp_start + 23]])
        );
        assert_eq!(
            tcp_ipv6_checksum(&packet, tcp_start),
            u16::from_be_bytes([packet[tcp_start + 16], packet[tcp_start + 17]])
        );
    }

    #[test]
    fn clamp_tcp_mss_handles_vlan_ipv4_packets() {
        tinc_test_support::assert_can_create_netns();
        let inner = tcp_ipv4_packet(1460);
        let mut packet = Vec::new();
        packet.extend_from_slice(&inner[0..12]);
        packet.extend_from_slice(&ETH_P_8021Q.to_be_bytes());
        packet.extend_from_slice(&[0, 7]);
        packet.extend_from_slice(&ETH_P_IP.to_be_bytes());
        packet.extend_from_slice(&inner[ETH_HLEN..]);
        let tcp_start = ETH_HLEN + 4 + 20;

        assert_eq!(
            Ok(MssClamp::Clamped { old: 1460, new: 42 }),
            clamp_tcp_mss(&mut packet, 100)
        );
        assert_eq!(
            42,
            u16::from_be_bytes([packet[tcp_start + 22], packet[tcp_start + 23]])
        );
    }

    #[test]
    fn clamp_tcp_mss_reports_noop_cases() {
        tinc_test_support::assert_can_create_netns();
        let mut small = tcp_ipv4_packet(40);
        assert_eq!(
            Ok(MssClamp::AlreadySmall {
                current: 40,
                maximum: 46,
            }),
            clamp_tcp_mss(&mut small, 100)
        );

        let mut no_options = tcp_ipv4_packet(1460);
        let tcp_start = ETH_HLEN + 20;
        no_options[tcp_start + 12] = 5 << 4;
        no_options.truncate(tcp_start + 20);
        no_options[ETH_HLEN + 2..ETH_HLEN + 4].copy_from_slice(&40u16.to_be_bytes());
        assert_eq!(
            Ok(MssClamp::NoMssOption),
            clamp_tcp_mss(&mut no_options, 100)
        );

        let mut udp = ipv4_packet_with_payload(Ipv4Addr::new(10, 0, 0, 42), &[0; 8]);
        assert_eq!(Ok(MssClamp::NotTcp), clamp_tcp_mss(&mut udp, 100));
    }

    #[test]
    fn clamp_tcp_mss_rejects_short_and_invalid_packets() {
        tinc_test_support::assert_can_create_netns();
        let mut short = ethernet_packet(mac(2), mac(1), ETH_P_IP, &[0; 10]);
        assert_eq!(
            Err(MssClampError::TooShort {
                expected_at_least: ETH_HLEN + 20,
                actual: ETH_HLEN + 10,
            }),
            clamp_tcp_mss(&mut short, 100)
        );

        let mut invalid_data_offset = tcp_ipv4_packet(1460);
        invalid_data_offset[ETH_HLEN + 20 + 12] = 4 << 4;
        assert_eq!(
            Err(MssClampError::InvalidTcpHeaderLength(4)),
            clamp_tcp_mss(&mut invalid_data_offset, 100)
        );

        let mut mtu_too_small = tcp_ipv4_packet(1460);
        assert_eq!(
            Err(MssClampError::MtuTooSmall {
                mtu: 40,
                required_at_least: ETH_HLEN + 20 + 21,
            }),
            clamp_tcp_mss(&mut mtu_too_small, 40)
        );
    }

    #[test]
    fn route_packet_mut_decrements_ttl_for_forwarded_remote_packets() {
        tinc_test_support::assert_can_create_netns();
        let mut state = NetworkState::new("myself");
        state
            .apply_meta_message(parse_meta_message("12 1 myself beta 203.0.113.1 655 0 1").unwrap())
            .unwrap();
        state
            .apply_meta_message(parse_meta_message("12 2 beta myself 203.0.113.2 655 0 1").unwrap())
            .unwrap();
        state
            .apply_meta_message(parse_meta_message("12 3 beta alpha 203.0.113.3 655 0 1").unwrap())
            .unwrap();
        state
            .apply_meta_message(parse_meta_message("12 4 alpha beta 203.0.113.4 655 0 1").unwrap())
            .unwrap();
        state
            .apply_meta_message(parse_meta_message("10 5 alpha 10.0.0.0/24").unwrap())
            .unwrap();

        let mut packet = ipv4_packet(Ipv4Addr::new(10, 0, 0, 42));
        let outcome = route_packet_mut(
            &mut state,
            "beta",
            &mut packet,
            RouteConfig {
                decrement_ttl: true,
                ..RouteConfig::default()
            },
        );

        assert_eq!(
            RouteDecision::Send {
                owner: "alpha".to_owned(),
                via: Some("alpha".to_owned()),
            },
            outcome.decision
        );
        assert_eq!(63, packet[ETH_HLEN + 8]);
    }

    #[test]
    fn route_packet_mut_does_not_decrement_for_local_source_or_drop() {
        tinc_test_support::assert_can_create_netns();
        let mut state = routed_state();
        let mut packet = ipv4_packet(Ipv4Addr::new(10, 0, 0, 42));

        let outcome = route_packet_mut(
            &mut state,
            "myself",
            &mut packet,
            RouteConfig {
                decrement_ttl: true,
                ..RouteConfig::default()
            },
        );

        assert!(matches!(outcome.decision, RouteDecision::Send { .. }));
        assert_eq!(64, packet[ETH_HLEN + 8]);

        let mut unknown = ipv4_packet(Ipv4Addr::new(203, 0, 113, 1));
        let outcome = route_packet_mut(
            &mut state,
            "alpha",
            &mut unknown,
            RouteConfig {
                decrement_ttl: true,
                ..RouteConfig::default()
            },
        );
        assert!(matches!(outcome.decision, RouteDecision::Drop(_)));
        assert_eq!(64, unknown[ETH_HLEN + 8]);
    }

    #[test]
    fn route_packet_action_replies_with_icmp_for_unknown_destinations() {
        tinc_test_support::assert_can_create_netns();
        let mut state = routed_state();
        let packet = ipv4_packet(Ipv4Addr::new(203, 0, 113, 1));

        let action = route_packet_action(&mut state, "beta", &packet, RouteConfig::default());

        assert!(matches!(
            action.outcome.decision,
            RouteDecision::Drop(RouteDropReason::UnknownIpv4Destination(_))
        ));
        let PacketAction::Reply { target, packet, .. } = action.action else {
            panic!("expected ICMP reply");
        };
        assert_eq!("beta", target);
        let icmp_start = ETH_HLEN + 20;
        assert_eq!(ICMP_DEST_UNREACH, packet[icmp_start]);
        assert_eq!(ICMP_NET_UNKNOWN, packet[icmp_start + 1]);
        assert_eq!(0, internet_checksum(&packet[icmp_start..], 0xffff));
    }

    #[test]
    fn route_packet_action_replies_with_time_exceeded_when_ttl_expires() {
        tinc_test_support::assert_can_create_netns();
        let mut state = routed_state();
        let mut packet = ipv4_packet(Ipv4Addr::new(10, 0, 0, 42));
        packet[ETH_HLEN + 8] = 1;

        let action = route_packet_action(
            &mut state,
            "beta",
            &packet,
            RouteConfig {
                decrement_ttl: true,
                ..RouteConfig::default()
            },
        );

        assert_eq!(
            RouteDecision::Drop(RouteDropReason::TtlExpired),
            action.outcome.decision
        );
        let PacketAction::Reply { target, packet, .. } = action.action else {
            panic!("expected time exceeded reply");
        };
        assert_eq!("beta", target);
        let icmp_start = ETH_HLEN + 20;
        assert_eq!(ICMP_TIME_EXCEEDED, packet[icmp_start]);
        assert_eq!(ICMP_EXC_TTL, packet[icmp_start + 1]);

        let mut time_exceeded = ipv4_packet_with_payload(Ipv4Addr::new(10, 0, 0, 42), &[0; 8]);
        time_exceeded[ETH_HLEN + 8] = 1;
        time_exceeded[ETH_HLEN + 9] = IPPROTO_ICMP;
        time_exceeded[ETH_HLEN + 20] = ICMP_TIME_EXCEEDED;
        let action = route_packet_action(
            &mut state,
            "beta",
            &time_exceeded,
            RouteConfig {
                decrement_ttl: true,
                ..RouteConfig::default()
            },
        );
        assert_eq!(
            PacketAction::Drop(RouteDropReason::TtlExpired),
            action.action
        );
    }

    #[test]
    fn route_packet_action_fragments_oversized_ipv4_packets_without_df() {
        tinc_test_support::assert_can_create_netns();
        let mut state = routed_state();
        state.graph.node_mut("alpha").unwrap().mtu = 590;
        let packet = ipv4_packet_with_payload(Ipv4Addr::new(10, 0, 0, 42), &[0xaa; 1000]);

        let action = route_packet_action(&mut state, "beta", &packet, RouteConfig::default());

        let PacketAction::SendFragments {
            owner,
            via,
            fragments,
            ..
        } = action.action
        else {
            panic!("expected fragments");
        };
        assert_eq!("alpha", owner);
        assert_eq!(Some("alpha".to_owned()), via);
        assert!(fragments.len() > 1);
        assert!(fragments.iter().all(|fragment| fragment.len() <= 590));
        assert_eq!(
            IP_MF,
            u16::from_be_bytes([fragments[0][ETH_HLEN + 6], fragments[0][ETH_HLEN + 7]]) & IP_MF
        );
    }

    #[test]
    fn route_packet_action_replies_with_frag_needed_for_ipv4_df_packets() {
        tinc_test_support::assert_can_create_netns();
        let mut state = routed_state();
        state.graph.node_mut("alpha").unwrap().mtu = 500;
        let mut packet = ipv4_packet_with_payload(Ipv4Addr::new(10, 0, 0, 42), &[0xbb; 1000]);
        packet[ETH_HLEN + 6] |= 0x40;

        let action = route_packet_action(&mut state, "beta", &packet, RouteConfig::default());

        let PacketAction::Reply { target, packet, .. } = action.action else {
            panic!("expected frag-needed reply");
        };
        assert_eq!("beta", target);
        let icmp_start = ETH_HLEN + 20;
        assert_eq!(ICMP_DEST_UNREACH, packet[icmp_start]);
        assert_eq!(ICMP_FRAG_NEEDED, packet[icmp_start + 1]);
        assert_eq!(
            IP_MSS as u16,
            u16::from_be_bytes([packet[icmp_start + 6], packet[icmp_start + 7]])
        );
    }

    #[test]
    fn route_packet_action_replies_with_packet_too_big_for_ipv6() {
        tinc_test_support::assert_can_create_netns();
        let mut state = routed_state();
        state.graph.node_mut("alpha").unwrap().mtu = 500;
        let packet = ipv6_packet_with_payload("2001:db8::42".parse().unwrap(), 17, &[0xcc; 1500]);

        let action = route_packet_action(&mut state, "beta", &packet, RouteConfig::default());

        let PacketAction::Reply { target, packet, .. } = action.action else {
            panic!("expected packet-too-big reply");
        };
        assert_eq!("beta", target);
        let icmp_start = ETH_HLEN + 40;
        assert_eq!(ICMP6_PACKET_TOO_BIG, packet[icmp_start]);
        assert_eq!(
            IPV6_MIN_PAYLOAD_MTU as u32,
            u32::from_be_bytes([
                packet[icmp_start + 4],
                packet[icmp_start + 5],
                packet[icmp_start + 6],
                packet[icmp_start + 7],
            ])
        );
        assert_eq!(
            0,
            verify_ipv6_payload_checksum(&packet, ETH_HLEN, ipv6_payload_len(&packet, ETH_HLEN))
        );
    }

    #[test]
    fn route_packet_action_clamps_mss_when_via_requests_it() {
        tinc_test_support::assert_can_create_netns();
        let mut state = routed_state();
        let alpha = state.graph.node_mut("alpha").unwrap();
        alpha.mtu = 100;
        alpha.options |= OPTION_CLAMP_MSS;

        let packet = tcp_ipv4_packet(1460);
        let action = route_packet_action(&mut state, "myself", &packet, RouteConfig::default());

        let PacketAction::Send {
            owner,
            via,
            packet,
            mss_clamp,
            ..
        } = action.action
        else {
            panic!("expected send action");
        };
        assert_eq!("alpha", owner);
        assert_eq!(Some("alpha".to_owned()), via);
        assert_eq!(Some(MssClamp::Clamped { old: 1460, new: 46 }), mss_clamp);
        let tcp_start = ETH_HLEN + 20;
        assert_eq!(
            46,
            u16::from_be_bytes([packet[tcp_start + 22], packet[tcp_start + 23]])
        );
        assert_eq!(
            tcp_ipv4_checksum(&packet, tcp_start),
            u16::from_be_bytes([packet[tcp_start + 16], packet[tcp_start + 17]])
        );
    }

    #[test]
    fn route_packet_action_skips_pmtu_for_local_via() {
        tinc_test_support::assert_can_create_netns();
        let mut state = routed_state();
        state
            .apply_meta_message(parse_meta_message("10 6 myself 10.1.0.0/16").unwrap())
            .unwrap();
        state.graph.node_mut("myself").unwrap().mtu = 500;
        let packet = ipv4_packet_with_payload(Ipv4Addr::new(10, 1, 0, 42), &[0xdd; 1000]);

        let action = route_packet_action(&mut state, "beta", &packet, RouteConfig::default());

        let PacketAction::Send {
            owner, via, packet, ..
        } = action.action
        else {
            panic!("expected local send action");
        };
        assert_eq!("myself", owner);
        assert_eq!(Some("myself".to_owned()), via);
        assert_eq!(ETH_HLEN + 20 + 1000, packet.len());
    }

    #[test]
    fn route_packet_action_replies_to_local_arp_requests_for_remote_subnets() {
        tinc_test_support::assert_can_create_netns();
        let mut state = routed_state();
        let request = arp_request(Ipv4Addr::new(10, 0, 0, 42));

        let action = route_packet_action(&mut state, "myself", &request, RouteConfig::default());

        assert_eq!(
            RouteDecision::Reply {
                target: "myself".to_owned()
            },
            action.outcome.decision
        );
        let PacketAction::Reply { target, packet, .. } = action.action else {
            panic!("expected ARP reply");
        };
        assert_eq!("myself", target);
        let arp_start = ETH_HLEN;
        let mut fake_mac = mac(1).octets();
        fake_mac[5] ^= 0xff;

        assert_eq!(
            ARPOP_REPLY,
            u16::from_be_bytes([packet[arp_start + 6], packet[arp_start + 7]])
        );
        assert_eq!(&fake_mac, &packet[arp_start + 8..arp_start + 14]);
        assert_eq!(
            &Ipv4Addr::new(10, 0, 0, 42).octets(),
            &packet[arp_start + 14..arp_start + 18]
        );
        assert_eq!(&mac(1).octets(), &packet[arp_start + 18..arp_start + 24]);
        assert_eq!(
            &Ipv4Addr::new(192, 0, 2, 1).octets(),
            &packet[arp_start + 24..arp_start + 28]
        );
    }

    #[test]
    fn route_packet_action_drops_arp_for_unknown_local_or_remote_sources() {
        tinc_test_support::assert_can_create_netns();
        let mut state = routed_state();
        let unknown = arp_request(Ipv4Addr::new(203, 0, 113, 99));
        let action = route_packet_action(&mut state, "myself", &unknown, RouteConfig::default());
        assert_eq!(
            PacketAction::Drop(RouteDropReason::UnknownArpTarget(Ipv4Addr::new(
                203, 0, 113, 99,
            ))),
            action.action
        );

        state
            .apply_meta_message(parse_meta_message("10 6 myself 10.1.0.0/16").unwrap())
            .unwrap();
        let local = arp_request(Ipv4Addr::new(10, 1, 0, 42));
        let action = route_packet_action(&mut state, "myself", &local, RouteConfig::default());
        assert_eq!(
            PacketAction::Drop(RouteDropReason::LocalArpTarget(
                Ipv4Addr::new(10, 1, 0, 42,)
            )),
            action.action
        );

        let action = route_packet_action(&mut state, "alpha", &local, RouteConfig::default());
        assert_eq!(
            PacketAction::Drop(RouteDropReason::AddressResolutionFromRemote),
            action.action
        );
    }

    #[test]
    fn route_packet_action_replies_to_neighbor_solicitation_for_remote_subnets() {
        tinc_test_support::assert_can_create_netns();
        let mut state = routed_state();
        let target = "2001:db8::42".parse::<Ipv6Addr>().unwrap();
        let request = neighbor_solicitation(target, true);

        let action = route_packet_action(&mut state, "myself", &request, RouteConfig::default());

        assert_eq!(
            RouteDecision::Reply {
                target: "myself".to_owned()
            },
            action.outcome.decision
        );
        let PacketAction::Reply {
            target: reply_target,
            packet,
            ..
        } = action.action
        else {
            panic!("expected neighbor advertisement");
        };
        assert_eq!("myself", reply_target);

        let mut fake_mac = mac(1).octets();
        fake_mac[5] ^= 0xff;
        assert_eq!(&mac(1).octets(), &packet[0..6]);
        assert_eq!(&fake_mac, &packet[6..12]);
        assert_eq!(&target.octets(), &packet[ETH_HLEN + 8..ETH_HLEN + 24]);
        assert_eq!(
            &Ipv6Addr::LOCALHOST.octets(),
            &packet[ETH_HLEN + 24..ETH_HLEN + 40]
        );

        let icmp_start = ETH_HLEN + 40;
        assert_eq!(ND_NEIGHBOR_ADVERT, packet[icmp_start]);
        assert_eq!(
            0x4000_0000,
            u32::from_be_bytes([
                packet[icmp_start + 4],
                packet[icmp_start + 5],
                packet[icmp_start + 6],
                packet[icmp_start + 7],
            ])
        );
        assert_eq!(
            ND_OPT_TARGET_LINKADDR,
            packet[icmp_start + ND_NEIGHBOR_SOLICIT_LEN]
        );
        assert_eq!(
            &fake_mac,
            &packet[icmp_start + ND_NEIGHBOR_SOLICIT_LEN + 2
                ..icmp_start + ND_NEIGHBOR_SOLICIT_LEN + ND_OPT_LINKADDR_LEN]
        );
        assert_eq!(
            0,
            verify_ipv6_payload_checksum(&packet, ETH_HLEN, ipv6_payload_len(&packet, ETH_HLEN))
        );
    }

    #[test]
    fn route_packet_action_drops_invalid_or_unknown_neighbor_solicitation() {
        tinc_test_support::assert_can_create_netns();
        let mut state = routed_state();
        let unknown = neighbor_solicitation("2001:dead::1".parse().unwrap(), true);
        let action = route_packet_action(&mut state, "myself", &unknown, RouteConfig::default());
        assert_eq!(
            PacketAction::Drop(RouteDropReason::UnknownNeighborTarget(
                "2001:dead::1".parse().unwrap(),
            )),
            action.action
        );

        let mut bad_checksum = neighbor_solicitation("2001:db8::42".parse().unwrap(), true);
        bad_checksum[ETH_HLEN + 40 + 3] ^= 0x01;
        let action =
            route_packet_action(&mut state, "myself", &bad_checksum, RouteConfig::default());
        assert_eq!(
            PacketAction::Drop(RouteDropReason::InvalidNeighborSolicitationChecksum),
            action.action
        );
    }

    #[test]
    fn fragment_ipv4_packet_splits_payload_on_8_byte_boundaries() {
        tinc_test_support::assert_can_create_netns();
        let body = (0u8..=255).cycle().take(1000).collect::<Vec<_>>();
        let packet = ipv4_packet_with_payload(Ipv4Addr::new(10, 0, 0, 42), &body);
        let fragments = fragment_ipv4_packet(&packet, 590).unwrap();

        assert_eq!(2, fragments.len());

        let first = &fragments[0];
        assert_eq!(ETH_HLEN + 20 + 552, first.len());
        assert_eq!(
            20 + 552,
            u16::from_be_bytes([first[16], first[17]]) as usize
        );
        assert_eq!(IP_MF, u16::from_be_bytes([first[20], first[21]]) & IP_MF);
        assert_eq!(0, u16::from_be_bytes([first[20], first[21]]) & IP_OFFMASK);
        assert_eq!(
            ipv4_header_checksum(first, ETH_HLEN),
            u16::from_be_bytes([first[24], first[25]])
        );
        assert_eq!(&body[..552], &first[ETH_HLEN + 20..]);

        let second = &fragments[1];
        assert_eq!(ETH_HLEN + 20 + 448, second.len());
        assert_eq!(
            20 + 448,
            u16::from_be_bytes([second[16], second[17]]) as usize
        );
        assert_eq!(0, u16::from_be_bytes([second[20], second[21]]) & IP_MF);
        assert_eq!(
            69,
            u16::from_be_bytes([second[20], second[21]]) & IP_OFFMASK
        );
        assert_eq!(
            ipv4_header_checksum(second, ETH_HLEN),
            u16::from_be_bytes([second[24], second[25]])
        );
        assert_eq!(&body[552..], &second[ETH_HLEN + 20..]);
    }

    #[test]
    fn fragment_ipv4_packet_preserves_existing_fragment_flags_and_offset() {
        tinc_test_support::assert_can_create_netns();
        let body = vec![0xaa; 800];
        let mut packet = ipv4_packet_with_payload(Ipv4Addr::new(10, 0, 0, 42), &body);
        packet[ETH_HLEN + 6..ETH_HLEN + 8].copy_from_slice(&(IP_DF | 3).to_be_bytes());
        packet[ETH_HLEN + 10] = 0;
        packet[ETH_HLEN + 11] = 0;
        let checksum = ipv4_header_checksum(&packet, ETH_HLEN);
        packet[ETH_HLEN + 10..ETH_HLEN + 12].copy_from_slice(&checksum.to_be_bytes());

        let fragments = fragment_ipv4_packet(&packet, 590).unwrap();

        assert_eq!(
            IP_DF | IP_MF | 3,
            u16::from_be_bytes([fragments[0][ETH_HLEN + 6], fragments[0][ETH_HLEN + 7]])
        );
        assert_eq!(
            IP_DF | 72,
            u16::from_be_bytes([fragments[1][ETH_HLEN + 6], fragments[1][ETH_HLEN + 7]])
        );
    }

    #[test]
    fn fragment_ipv4_packet_supports_vlan_headers() {
        tinc_test_support::assert_can_create_netns();
        let inner = ipv4_packet_with_payload(Ipv4Addr::new(10, 0, 0, 42), &[0xbb; 700]);
        let mut packet = Vec::new();
        packet.extend_from_slice(&inner[0..12]);
        packet.extend_from_slice(&ETH_P_8021Q.to_be_bytes());
        packet.extend_from_slice(&[0, 7]);
        packet.extend_from_slice(&ETH_P_IP.to_be_bytes());
        packet.extend_from_slice(&inner[ETH_HLEN..]);

        let fragments = fragment_ipv4_packet(&packet, 590).unwrap();

        assert_eq!(2, fragments.len());
        assert_eq!(
            ETH_P_8021Q,
            u16::from_be_bytes([fragments[0][12], fragments[0][13]])
        );
        assert_eq!(
            ETH_P_IP,
            u16::from_be_bytes([fragments[0][16], fragments[0][17]])
        );
        assert_eq!(
            0,
            u16::from_be_bytes([fragments[0][24], fragments[0][25]]) & IP_OFFMASK
        );
        assert_eq!(
            69,
            u16::from_be_bytes([fragments[1][24], fragments[1][25]]) & IP_OFFMASK
        );
    }

    #[test]
    fn fragment_ipv4_packet_rejects_invalid_packets() {
        tinc_test_support::assert_can_create_netns();
        assert_eq!(
            Err(FragmentError::NotIpv4(ETH_P_IPV6)),
            fragment_ipv4_packet(&ipv6_packet("2001:db8::1".parse().unwrap()), 590)
        );

        let mut unsupported_ihl = ipv4_packet_with_payload(Ipv4Addr::new(10, 0, 0, 42), &[0; 16]);
        unsupported_ihl[ETH_HLEN] = 0x46;
        assert_eq!(
            Err(FragmentError::UnsupportedHeaderLength(6)),
            fragment_ipv4_packet(&unsupported_ihl, 590)
        );

        let mut mismatch = ipv4_packet_with_payload(Ipv4Addr::new(10, 0, 0, 42), &[0; 16]);
        mismatch[ETH_HLEN + 2..ETH_HLEN + 4].copy_from_slice(&999u16.to_be_bytes());
        assert_eq!(
            Err(FragmentError::LengthMismatch {
                header_total_len: 999,
                actual_payload_len: 36,
            }),
            fragment_ipv4_packet(&mismatch, 590)
        );

        let too_short = ethernet_packet(mac(2), mac(1), ETH_P_IP, &[0; 4]);
        assert_eq!(
            Err(FragmentError::TooShort {
                expected_at_least: ETH_HLEN + 20,
                actual: ETH_HLEN + 4,
            }),
            fragment_ipv4_packet(&too_short, 590)
        );
    }
}
