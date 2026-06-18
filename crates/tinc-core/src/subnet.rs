// SPDX-License-Identifier: GPL-2.0-or-later

use std::cmp::Ordering;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

pub const DEFAULT_WEIGHT: i32 = 10;
pub const MAX_NET_STR: usize = 64;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct MacAddr([u8; 6]);

impl MacAddr {
    pub const fn new(octets: [u8; 6]) -> Self {
        Self(octets)
    }

    pub const fn octets(self) -> [u8; 6] {
        self.0
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum SubnetKind {
    Mac(MacAddr),
    Ipv4 { address: Ipv4Addr, prefix_len: u8 },
    Ipv6 { address: Ipv6Addr, prefix_len: u8 },
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Subnet {
    pub kind: SubnetKind,
    pub weight: i32,
    pub owner: Option<String>,
    pub expires: Option<i64>,
}

impl Subnet {
    pub fn mac(address: MacAddr) -> Self {
        Self::weighted(SubnetKind::Mac(address), DEFAULT_WEIGHT)
    }

    pub fn ipv4(address: Ipv4Addr, prefix_len: u8) -> Result<Self, SubnetParseError> {
        validate_prefix(prefix_len, 32, AddressFamily::Ipv4)?;
        Ok(Self::weighted(
            SubnetKind::Ipv4 {
                address,
                prefix_len,
            },
            DEFAULT_WEIGHT,
        ))
    }

    pub fn ipv6(address: Ipv6Addr, prefix_len: u8) -> Result<Self, SubnetParseError> {
        validate_prefix(prefix_len, 128, AddressFamily::Ipv6)?;
        Ok(Self::weighted(
            SubnetKind::Ipv6 {
                address,
                prefix_len,
            },
            DEFAULT_WEIGHT,
        ))
    }

    pub fn weighted(kind: SubnetKind, weight: i32) -> Self {
        Self {
            kind,
            weight,
            owner: None,
            expires: None,
        }
    }

    pub fn with_owner(mut self, owner: impl Into<String>) -> Self {
        self.owner = Some(owner.into());
        self
    }

    pub fn with_expiry(mut self, expires: i64) -> Self {
        self.expires = Some(expires);
        self
    }

    pub fn type_order(&self) -> u8 {
        match self.kind {
            SubnetKind::Mac(_) => 0,
            SubnetKind::Ipv4 { .. } => 1,
            SubnetKind::Ipv6 { .. } => 2,
        }
    }

    pub fn compare_tinc(&self, other: &Self) -> Ordering {
        let result = self.type_order().cmp(&other.type_order());

        if result != Ordering::Equal {
            return result;
        }

        match (&self.kind, &other.kind) {
            (SubnetKind::Mac(a), SubnetKind::Mac(b)) => compare_common(
                CommonCompare {
                    bytes: a.octets().as_slice(),
                    weight: self.weight,
                    owner: self.owner.as_deref(),
                },
                CommonCompare {
                    bytes: b.octets().as_slice(),
                    weight: other.weight,
                    owner: other.owner.as_deref(),
                },
            ),
            (
                SubnetKind::Ipv4 {
                    address: a,
                    prefix_len: a_prefix,
                },
                SubnetKind::Ipv4 {
                    address: b,
                    prefix_len: b_prefix,
                },
            ) => compare_ip_common(
                *a_prefix,
                *b_prefix,
                CommonCompare {
                    bytes: a.octets().as_slice(),
                    weight: self.weight,
                    owner: self.owner.as_deref(),
                },
                CommonCompare {
                    bytes: b.octets().as_slice(),
                    weight: other.weight,
                    owner: other.owner.as_deref(),
                },
            ),
            (
                SubnetKind::Ipv6 {
                    address: a,
                    prefix_len: a_prefix,
                },
                SubnetKind::Ipv6 {
                    address: b,
                    prefix_len: b_prefix,
                },
            ) => compare_ip_common(
                *a_prefix,
                *b_prefix,
                CommonCompare {
                    bytes: a.octets().as_slice(),
                    weight: self.weight,
                    owner: self.owner.as_deref(),
                },
                CommonCompare {
                    bytes: b.octets().as_slice(),
                    weight: other.weight,
                    owner: other.owner.as_deref(),
                },
            ),
            _ => unreachable!("subnet type orders matched but variants differed"),
        }
    }

    pub fn matches_mac(&self, address: MacAddr) -> bool {
        matches!(self.kind, SubnetKind::Mac(mac) if mac == address)
    }

    pub fn matches_ipv4(&self, address: Ipv4Addr) -> bool {
        match self.kind {
            SubnetKind::Ipv4 {
                address: subnet,
                prefix_len,
            } => mask_cmp(&address.octets(), &subnet.octets(), prefix_len as usize) == 0,
            _ => false,
        }
    }

    pub fn matches_ipv6(&self, address: Ipv6Addr) -> bool {
        match self.kind {
            SubnetKind::Ipv6 {
                address: subnet,
                prefix_len,
            } => mask_cmp(&address.octets(), &subnet.octets(), prefix_len as usize) == 0,
            _ => false,
        }
    }

    pub fn has_canonical_mask(&self) -> bool {
        match self.kind {
            SubnetKind::Mac(_) => true,
            SubnetKind::Ipv4 {
                address,
                prefix_len,
            } => mask_check(&address.octets(), prefix_len as usize),
            SubnetKind::Ipv6 {
                address,
                prefix_len,
            } => mask_check(&address.octets(), prefix_len as usize),
        }
    }
}

impl fmt::Display for Subnet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            SubnetKind::Mac(address) => write!(f, "{address}")?,
            SubnetKind::Ipv4 {
                address,
                prefix_len,
            } => {
                write!(f, "{address}")?;

                if prefix_len != 32 {
                    write!(f, "/{prefix_len}")?;
                }
            }
            SubnetKind::Ipv6 {
                address,
                prefix_len,
            } => {
                write!(f, "{address}")?;

                if prefix_len != 128 {
                    write!(f, "/{prefix_len}")?;
                }
            }
        }

        if self.weight != DEFAULT_WEIGHT {
            write!(f, "#{}", self.weight)?;
        }

        Ok(())
    }
}

impl FromStr for Subnet {
    type Err = SubnetParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        parse_subnet(input)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressFamily {
    Ipv4,
    Ipv6,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SubnetParseError {
    Empty,
    TooLong,
    InvalidWeight,
    InvalidPrefix,
    PrefixNotAllowed(AddressFamily),
    InvalidAddress,
}

impl fmt::Display for SubnetParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "empty subnet"),
            Self::TooLong => write!(f, "subnet string is too long"),
            Self::InvalidWeight => write!(f, "invalid subnet weight"),
            Self::InvalidPrefix => write!(f, "invalid subnet prefix length"),
            Self::PrefixNotAllowed(_) => write!(f, "prefix length is not allowed for this subnet"),
            Self::InvalidAddress => write!(f, "invalid subnet address"),
        }
    }
}

impl std::error::Error for SubnetParseError {}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SubnetTable {
    subnets: Vec<Subnet>,
}

impl SubnetTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.subnets.len()
    }

    pub fn is_empty(&self) -> bool {
        self.subnets.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Subnet> {
        self.subnets.iter()
    }

    pub fn add(&mut self, subnet: Subnet) {
        self.subnets.push(subnet);
        self.subnets.sort_by(Subnet::compare_tinc);
    }

    pub fn add_unique(&mut self, subnet: Subnet) -> bool {
        if self.lookup_exact(&subnet).is_some() {
            return false;
        }

        self.add(subnet);
        true
    }

    pub fn lookup_exact(&self, subnet: &Subnet) -> Option<&Subnet> {
        self.subnets
            .iter()
            .find(|candidate| candidate.compare_tinc(subnet) == Ordering::Equal)
    }

    pub fn lookup_owner_subnet(&self, owner: &str, subnet: &Subnet) -> Option<&Subnet> {
        let mut owned = subnet.clone();
        owned.owner = Some(owner.to_owned());
        self.lookup_exact(&owned)
    }

    pub fn lookup_owner_subnet_mut(&mut self, owner: &str, subnet: &Subnet) -> Option<&mut Subnet> {
        let mut owned = subnet.clone();
        owned.owner = Some(owner.to_owned());
        self.subnets
            .iter_mut()
            .find(|candidate| candidate.compare_tinc(&owned) == Ordering::Equal)
    }

    pub fn remove_owner_subnet(&mut self, owner: &str, subnet: &Subnet) -> Option<Subnet> {
        let mut owned = subnet.clone();
        owned.owner = Some(owner.to_owned());
        self.remove(&owned)
    }

    pub fn owner_subnets<'a>(&'a self, owner: &'a str) -> impl Iterator<Item = &'a Subnet> + 'a {
        self.subnets
            .iter()
            .filter(move |subnet| subnet.owner.as_deref() == Some(owner))
    }

    pub fn remove_owner(&mut self, owner: &str) -> Vec<Subnet> {
        let mut removed = Vec::new();
        let mut retained = Vec::new();

        for subnet in self.subnets.drain(..) {
            if subnet.owner.as_deref() == Some(owner) {
                removed.push(subnet);
            } else {
                retained.push(subnet);
            }
        }

        self.subnets = retained;
        removed
    }

    pub fn remove_expired_owner_subnets(&mut self, owner: &str, now: i64) -> Vec<Subnet> {
        let mut removed = Vec::new();
        let mut retained = Vec::new();

        for subnet in self.subnets.drain(..) {
            let expired = subnet.owner.as_deref() == Some(owner)
                && subnet.expires.is_some_and(|expires| expires < now);

            if expired {
                removed.push(subnet);
            } else {
                retained.push(subnet);
            }
        }

        self.subnets = retained;
        removed
    }

    pub fn remove(&mut self, subnet: &Subnet) -> Option<Subnet> {
        self.subnets
            .iter()
            .position(|candidate| candidate.compare_tinc(subnet) == Ordering::Equal)
            .map(|index| self.subnets.remove(index))
    }

    pub fn lookup_mac(&self, address: MacAddr) -> Option<&Subnet> {
        self.subnets
            .iter()
            .find(|subnet| subnet.matches_mac(address))
    }

    pub fn lookup_ipv4(&self, address: Ipv4Addr) -> Option<&Subnet> {
        self.subnets
            .iter()
            .find(|subnet| subnet.matches_ipv4(address))
    }

    pub fn lookup_ipv6(&self, address: Ipv6Addr) -> Option<&Subnet> {
        self.subnets
            .iter()
            .find(|subnet| subnet.matches_ipv6(address))
    }
}

pub fn parse_subnet(input: &str) -> Result<Subnet, SubnetParseError> {
    if input.is_empty() {
        return Err(SubnetParseError::Empty);
    }

    if input.len() >= MAX_NET_STR {
        return Err(SubnetParseError::TooLong);
    }

    let (address_and_prefix, weight) = match input.split_once('#') {
        Some((address, weight)) => (
            address,
            parse_c_i32(weight, SubnetParseError::InvalidWeight)?,
        ),
        None => (input, DEFAULT_WEIGHT),
    };

    let (address, prefix) = match address_and_prefix.split_once('/') {
        Some((address, prefix)) => (
            address,
            Some(parse_c_i32(prefix, SubnetParseError::InvalidPrefix)?),
        ),
        None => (address_and_prefix, None),
    };

    if let Some(mac) = parse_mac_addr(address) {
        if prefix.is_some() {
            return Err(SubnetParseError::PrefixNotAllowed(AddressFamily::Ipv4));
        }

        return Ok(Subnet::weighted(SubnetKind::Mac(mac), weight));
    }

    if let Ok(address) = address.parse::<Ipv4Addr>() {
        let prefix_len = prefix.unwrap_or(32);
        let prefix_len = i32_to_prefix(prefix_len, 32, AddressFamily::Ipv4)?;

        return Ok(Subnet::weighted(
            SubnetKind::Ipv4 {
                address,
                prefix_len,
            },
            weight,
        ));
    }

    if let Ok(address) = address.parse::<Ipv6Addr>() {
        let prefix_len = prefix.unwrap_or(128);
        let prefix_len = i32_to_prefix(prefix_len, 128, AddressFamily::Ipv6)?;

        return Ok(Subnet::weighted(
            SubnetKind::Ipv6 {
                address,
                prefix_len,
            },
            weight,
        ));
    }

    Err(SubnetParseError::InvalidAddress)
}

pub fn mask_cmp(a: &[u8], b: &[u8], mask_len: usize) -> i32 {
    let full_bytes = mask_len / 8;

    for index in 0..full_bytes {
        let result = a[index] as i32 - b[index] as i32;

        if result != 0 {
            return result;
        }
    }

    let partial_bits = mask_len % 8;

    if partial_bits == 0 {
        return 0;
    }

    let mask = partial_mask(partial_bits);
    (a[full_bytes] & mask) as i32 - (b[full_bytes] & mask) as i32
}

pub fn mask_bytes(bytes: &mut [u8], mask_len: usize) {
    let mut index = mask_len / 8;
    let partial_bits = mask_len % 8;

    if partial_bits != 0 {
        bytes[index] &= partial_mask(partial_bits);
        index += 1;
    }

    for byte in &mut bytes[index..] {
        *byte = 0;
    }
}

pub fn mask_copy(src: &[u8], mask_len: usize) -> Vec<u8> {
    let mut dst = src.to_vec();
    mask_bytes(&mut dst, mask_len);
    dst
}

pub fn mask_check(bytes: &[u8], mask_len: usize) -> bool {
    let mut index = mask_len / 8;
    let partial_bits = mask_len % 8;

    if partial_bits != 0 {
        if bytes[index] & !partial_mask(partial_bits) != 0 {
            return false;
        }

        index += 1;
    }

    bytes[index..].iter().all(|byte| *byte == 0)
}

#[derive(Clone, Copy)]
struct CommonCompare<'a> {
    bytes: &'a [u8],
    weight: i32,
    owner: Option<&'a str>,
}

fn compare_common(a: CommonCompare<'_>, b: CommonCompare<'_>) -> Ordering {
    let result = a.bytes.cmp(b.bytes);

    if result != Ordering::Equal {
        return result;
    }

    let result = a.weight.cmp(&b.weight);

    if result != Ordering::Equal || a.owner.is_none() || b.owner.is_none() {
        return result;
    }

    a.owner.cmp(&b.owner)
}

fn compare_ip_common(
    a_prefix: u8,
    b_prefix: u8,
    a: CommonCompare<'_>,
    b: CommonCompare<'_>,
) -> Ordering {
    let result = b_prefix.cmp(&a_prefix);

    if result != Ordering::Equal {
        return result;
    }

    compare_common(a, b)
}

fn parse_mac_addr(input: &str) -> Option<MacAddr> {
    let parts = input.split(':').collect::<Vec<_>>();

    if parts.len() != 6 {
        return None;
    }

    let mut octets = [0; 6];

    for (index, part) in parts.iter().enumerate() {
        if part.is_empty() || part.len() > 2 {
            return None;
        }

        octets[index] = u8::from_str_radix(part, 16).ok()?;
    }

    Some(MacAddr::new(octets))
}

fn parse_c_i32(input: &str, error: SubnetParseError) -> Result<i32, SubnetParseError> {
    if input.is_empty() {
        return Err(error);
    }

    let trimmed_start = input.trim_start_matches(|c: char| c.is_ascii_whitespace());

    if trimmed_start.is_empty() {
        return Err(error);
    }

    if trimmed_start.chars().any(|c| c.is_ascii_whitespace()) {
        return Err(error);
    }

    trimmed_start.parse::<i32>().map_err(|_| error)
}

fn i32_to_prefix(prefix_len: i32, max: u8, family: AddressFamily) -> Result<u8, SubnetParseError> {
    if prefix_len < 0 {
        return Err(SubnetParseError::InvalidPrefix);
    }

    let prefix_len = u8::try_from(prefix_len).map_err(|_| SubnetParseError::InvalidPrefix)?;
    validate_prefix(prefix_len, max, family)?;
    Ok(prefix_len)
}

fn validate_prefix(
    prefix_len: u8,
    max: u8,
    _family: AddressFamily,
) -> Result<(), SubnetParseError> {
    if prefix_len > max {
        return Err(SubnetParseError::InvalidPrefix);
    }

    Ok(())
}

fn partial_mask(bits: usize) -> u8 {
    debug_assert!((1..8).contains(&bits));
    u8::MAX << (8 - bits)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4(octets: [u8; 4], prefix_len: u8) -> SubnetKind {
        SubnetKind::Ipv4 {
            address: Ipv4Addr::from(octets),
            prefix_len,
        }
    }

    fn ipv6(octets: [u8; 16], prefix_len: u8) -> SubnetKind {
        SubnetKind::Ipv6 {
            address: Ipv6Addr::from(octets),
            prefix_len,
        }
    }

    fn weighted(kind: SubnetKind, weight: i32) -> Subnet {
        Subnet::weighted(kind, weight)
    }

    #[test]
    fn maskcmp_matches_prefix_bits() {
        tinc_test_support::assert_can_create_netns();
        let a = [1, 2, 3, 4];
        let b = [1, 2, 3, 0xff];

        for mask in 0..=24 {
            assert_eq!(0, mask_cmp(&a, &b, mask));
        }

        for mask in 25..=32 {
            assert_ne!(0, mask_cmp(&a, &b, mask));
        }
    }

    #[test]
    fn mask_zeroes_host_bits() {
        tinc_test_support::assert_can_create_netns();
        let mut dst = [0xff, 0xff, 0xff, 0xff];
        mask_bytes(&mut dst, 23);
        assert_eq!([0xff, 0xff, 0xfe, 0x00], dst);
    }

    #[test]
    fn mask_copy_zeroes_host_bits() {
        tinc_test_support::assert_can_create_netns();
        let src = [0xff, 0xff, 0xff, 0xff];
        assert_eq!(vec![0xff, 0xff, 0xfe, 0x00], mask_copy(&src, 23));
    }

    #[test]
    fn compare_orders_different_types_like_tinc() {
        tinc_test_support::assert_can_create_netns();
        let mac = Subnet::mac(MacAddr::new([0; 6]));
        let ipv4 = Subnet::ipv4(Ipv4Addr::UNSPECIFIED, 0).unwrap();
        let ipv6 = Subnet::ipv6(Ipv6Addr::UNSPECIFIED, 0).unwrap();

        assert_ne!(Ordering::Equal, ipv4.compare_tinc(&ipv6));
        assert_ne!(Ordering::Equal, ipv4.compare_tinc(&mac));
        assert_ne!(Ordering::Equal, ipv6.compare_tinc(&mac));
        assert_eq!(Ordering::Less, mac.compare_tinc(&ipv4));
        assert_eq!(Ordering::Less, ipv4.compare_tinc(&ipv6));
    }

    #[test]
    fn compare_mac_address_weight_and_owner() {
        tinc_test_support::assert_can_create_netns();
        let mac1 = MacAddr::new([0x00, 0x01, 0x02, 0x03, 0x04, 0x05]);
        let mac2 = MacAddr::new([0x42, 0x01, 0x02, 0x03, 0x04, 0x05]);

        let a = weighted(SubnetKind::Mac(mac1), 42).with_owner("foo");
        let b = weighted(SubnetKind::Mac(mac1), 42).with_owner("foo");
        let c = weighted(SubnetKind::Mac(mac1), 10).with_owner("foo");
        let d = weighted(SubnetKind::Mac(mac2), 42).with_owner("foo");
        let e = weighted(SubnetKind::Mac(mac1), 42).with_owner("bar");

        assert_eq!(Ordering::Equal, a.compare_tinc(&b));
        assert_eq!(Ordering::Greater, a.compare_tinc(&c));
        assert_eq!(Ordering::Less, a.compare_tinc(&d));
        assert_eq!(Ordering::Greater, a.compare_tinc(&e));
    }

    #[test]
    fn compare_ipv4_prefix_address_weight_and_owner() {
        tinc_test_support::assert_can_create_netns();
        let a = weighted(ipv4([1, 2, 3, 4], 24), 1).with_owner("foo");
        let b = weighted(ipv4([1, 2, 3, 4], 16), 1).with_owner("foo");
        let c = weighted(ipv4([0x11, 0x22, 0x33, 0x44], 16), 1).with_owner("foo");
        let d = weighted(ipv4([1, 2, 3, 4], 24), 2).with_owner("foo");
        let e = weighted(ipv4([1, 2, 3, 4], 24), 1).with_owner("bar");

        assert_eq!(Ordering::Less, a.compare_tinc(&b));
        assert_eq!(Ordering::Less, b.compare_tinc(&c));
        assert_eq!(Ordering::Less, a.compare_tinc(&d));
        assert_eq!(Ordering::Greater, a.compare_tinc(&e));
    }

    #[test]
    fn compare_ipv6_prefix_address_weight_and_owner() {
        tinc_test_support::assert_can_create_netns();
        let a = weighted(
            ipv6([1, 2, 3, 4, 1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0], 24),
            1,
        )
        .with_owner("foo");
        let b = weighted(
            ipv6([1, 2, 3, 4, 1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0], 16),
            1,
        )
        .with_owner("foo");
        let c = weighted(
            ipv6([0x11, 0x22, 3, 4, 1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0], 24),
            1,
        )
        .with_owner("foo");
        let d = weighted(
            ipv6([1, 2, 3, 4, 1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0], 24),
            2,
        )
        .with_owner("foo");
        let e = weighted(
            ipv6([1, 2, 3, 4, 1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0], 24),
            1,
        )
        .with_owner("bar");

        assert_eq!(Ordering::Less, a.compare_tinc(&b));
        assert_eq!(Ordering::Greater, b.compare_tinc(&c));
        assert_eq!(Ordering::Less, a.compare_tinc(&d));
        assert_eq!(Ordering::Greater, a.compare_tinc(&e));
    }

    #[test]
    fn parse_valid_subnets() {
        tinc_test_support::assert_can_create_netns();
        let cases = [
            ("1.2.3.0/24#42", weighted(ipv4([1, 2, 3, 0], 24), 42)),
            (
                "04fb:7deb:78db:1950:2d21:258d:40b6:f0d7/128#999",
                weighted(
                    ipv6(
                        [
                            0x04, 0xfb, 0x7d, 0xeb, 0x78, 0xdb, 0x19, 0x50, 0x2d, 0x21, 0x25, 0x8d,
                            0x40, 0xb6, 0xf0, 0xd7,
                        ],
                        128,
                    ),
                    999,
                ),
            ),
            (
                "fe80::16dd:a9ff:fe7e:b4c2/64",
                weighted(
                    ipv6(
                        [
                            0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x16, 0xdd, 0xa9, 0xff, 0xfe, 0x7e, 0xb4,
                            0xc2,
                        ],
                        64,
                    ),
                    DEFAULT_WEIGHT,
                ),
            ),
            (
                "57:04:13:01:f9:26#60",
                weighted(
                    SubnetKind::Mac(MacAddr::new([0x57, 0x04, 0x13, 0x01, 0xf9, 0x26])),
                    60,
                ),
            ),
            ("1.2.3.4", weighted(ipv4([1, 2, 3, 4], 32), DEFAULT_WEIGHT)),
            (
                "fe80::1",
                weighted(
                    ipv6([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 128),
                    DEFAULT_WEIGHT,
                ),
            ),
        ];

        for (text, expected) in cases {
            assert_eq!(expected, parse_subnet(text).unwrap(), "{text}");
        }
    }

    #[test]
    fn parse_rejects_invalid_subnets() {
        tinc_test_support::assert_can_create_netns();
        let cases = [
            "1.2.256.0",
            "1.2.3.0/",
            "1.2.3.0/42",
            "1.2.3.0/MASK",
            "fe80::/129",
            "fe80::/MASK",
            "cb:0c:1b:60:ed:7a/1",
            "1.2.3.4#WEIGHT",
            "1.2.0.0/16#WEIGHT",
            "1.2.0.0/16#",
            "feff::/16#",
            "feff::/16#w",
        ];

        for text in cases {
            assert!(parse_subnet(text).is_err(), "{text}");
        }
    }

    #[test]
    fn format_subnets_like_tinc() {
        tinc_test_support::assert_can_create_netns();
        let cases = [
            (
                weighted(
                    SubnetKind::Mac(MacAddr::new([0x12, 0xfe, 0xff, 0x3a, 0x28, 0x90])),
                    42,
                ),
                "12:fe:ff:3a:28:90#42",
            ),
            (weighted(ipv4([1, 2, 3, 4], 32), DEFAULT_WEIGHT), "1.2.3.4"),
            (weighted(ipv4([181, 35, 16, 0], 27), 1), "181.35.16.0/27#1"),
            (
                weighted(
                    ipv6(
                        [
                            0x5f, 0xbf, 0x5c, 0xfe, 0x00, 0x00, 0xfd, 0xd2, 0xfd, 0x76, 0, 0, 0, 0,
                            0, 0,
                        ],
                        96,
                    ),
                    900,
                ),
                "5fbf:5cfe:0:fdd2:fd76::/96#900",
            ),
        ];

        for (subnet, expected) in cases {
            assert_eq!(expected, subnet.to_string());
        }
    }

    #[test]
    fn maskcheck_accepts_only_canonical_network_addresses() {
        tinc_test_support::assert_can_create_netns();
        assert!(mask_check(&[10, 0, 0, 0], 8));
        assert!(mask_check(&[192, 168, 0, 0], 16));
        assert!(mask_check(&[192, 168, 24, 0], 24));
        assert!(mask_check(&[10, 0, 0, 0, 0, 0, 0, 0], 8));
        assert!(mask_check(&[10, 20, 0, 0, 0, 0, 0, 0], 32));
        assert!(mask_check(&[192, 168, 24, 0, 0, 0, 0, 0], 48));

        assert!(!mask_check(&[10, 20, 0, 0], 8));
        assert!(!mask_check(&[10, 20, 30, 0], 16));

        let non_zero_ipv6 = [1, 2, 3, 4, 5, 6, 7, 0xaa, 0xbb, 1, 2, 3, 4, 5, 0xaa, 0xbb];

        for mask in (0..128).step_by(8) {
            assert!(!mask_check(&non_zero_ipv6, mask));
        }
    }

    #[test]
    fn subnet_table_prefers_longest_matching_prefix() {
        tinc_test_support::assert_can_create_netns();
        let mut table = SubnetTable::new();
        table.add(weighted(ipv4([10, 0, 0, 0], 8), DEFAULT_WEIGHT).with_owner("wide"));
        table.add(weighted(ipv4([10, 42, 0, 0], 16), DEFAULT_WEIGHT).with_owner("narrow"));

        let result = table.lookup_ipv4(Ipv4Addr::new(10, 42, 9, 1)).unwrap();
        assert_eq!(Some("narrow"), result.owner.as_deref());

        let result = table.lookup_ipv4(Ipv4Addr::new(10, 99, 9, 1)).unwrap();
        assert_eq!(Some("wide"), result.owner.as_deref());
    }

    #[test]
    fn subnet_table_can_manage_owner_scoped_entries() {
        tinc_test_support::assert_can_create_netns();
        let mut table = SubnetTable::new();
        let subnet = weighted(ipv4([192, 0, 2, 0], 24), DEFAULT_WEIGHT);

        assert!(table.add_unique(subnet.clone().with_owner("alpha")));
        assert!(!table.add_unique(subnet.clone().with_owner("alpha")));
        assert!(table.add_unique(subnet.clone().with_owner("beta")));
        assert_eq!(2, table.len());

        assert!(table.lookup_owner_subnet("alpha", &subnet).is_some());
        assert!(table.lookup_owner_subnet("gamma", &subnet).is_none());

        assert_eq!(
            vec![Some("alpha")],
            table
                .owner_subnets("alpha")
                .map(|subnet| subnet.owner.as_deref())
                .collect::<Vec<_>>()
        );

        assert!(table.remove_owner_subnet("alpha", &subnet).is_some());
        assert!(table.lookup_owner_subnet("alpha", &subnet).is_none());
        assert!(table.lookup_owner_subnet("beta", &subnet).is_some());
    }

    #[test]
    fn subnet_table_removes_only_expired_owner_subnets() {
        tinc_test_support::assert_can_create_netns();
        let mut table = SubnetTable::new();
        let expired = Subnet::mac(MacAddr::new([0, 1, 2, 3, 4, 5]))
            .with_owner("alpha")
            .with_expiry(99);
        let fresh = Subnet::mac(MacAddr::new([0, 1, 2, 3, 4, 6]))
            .with_owner("alpha")
            .with_expiry(120);
        let static_subnet = Subnet::mac(MacAddr::new([0, 1, 2, 3, 4, 7])).with_owner("alpha");
        let other_owner = Subnet::mac(MacAddr::new([0, 1, 2, 3, 4, 8]))
            .with_owner("beta")
            .with_expiry(99);

        table.add(expired.clone());
        table.add(fresh.clone());
        table.add(static_subnet.clone());
        table.add(other_owner.clone());

        assert_eq!(
            vec![expired],
            table.remove_expired_owner_subnets("alpha", 100)
        );
        assert!(table.lookup_exact(&fresh).is_some());
        assert!(table.lookup_exact(&static_subnet).is_some());
        assert!(table.lookup_exact(&other_owner).is_some());
    }
}
