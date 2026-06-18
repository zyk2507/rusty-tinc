// SPDX-License-Identifier: GPL-2.0-or-later

use std::fmt;

const HEX: &[u8; 16] = b"0123456789ABCDEF";
const BASE64_ORIGINAL: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const BASE64_URLSAFE: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

pub fn int_to_str(num: i32) -> String {
    num.to_string()
}

pub fn is_decimal(input: &str) -> bool {
    let bytes = input.as_bytes();
    let mut index = 0;

    while index < bytes.len() && bytes[index].is_ascii_whitespace() {
        index += 1;
    }

    if matches!(bytes.get(index), Some(b'-' | b'+')) {
        index += 1;
    }

    let digit_start = index;
    let mut value = 0i64;

    while index < bytes.len() && bytes[index].is_ascii_digit() {
        value = match value
            .checked_mul(10)
            .and_then(|value| value.checked_add((bytes[index] - b'0') as i64))
        {
            Some(value) => value,
            None => return false,
        };
        index += 1;
    }

    digit_start != index && index == bytes.len()
}

pub fn string_eq(first: Option<&str>, second: Option<&str>) -> bool {
    first == second
}

pub fn mem_eq(first: &[u8], second: &[u8]) -> bool {
    if first.len() != second.len() {
        return false;
    }

    first
        .iter()
        .zip(second)
        .fold(0u8, |diff, (a, b)| diff | (a ^ b))
        == 0
}

pub fn hex_to_bin(src: &str, max_len: usize) -> Vec<u8> {
    let bytes = src.as_bytes();
    let mut dst = Vec::with_capacity(max_len);

    for index in 0..max_len {
        let Some(high) = bytes.get(index * 2).and_then(|byte| hex_value(*byte)) else {
            break;
        };
        let Some(low) = bytes.get(index * 2 + 1).and_then(|byte| hex_value(*byte)) else {
            break;
        };

        dst.push((high << 4) | low);
    }

    dst
}

pub fn bin_to_hex(src: &[u8]) -> String {
    let mut dst = vec![0; src.len() * 2];

    for (index, byte) in src.iter().enumerate() {
        dst[index * 2] = HEX[(byte >> 4) as usize];
        dst[index * 2 + 1] = HEX[(byte & 15) as usize];
    }

    String::from_utf8(dst).expect("hex alphabet is valid UTF-8")
}

pub fn b64encode_tinc(src: &[u8]) -> String {
    b64encode_tinc_internal(src, BASE64_ORIGINAL)
}

pub fn b64encode_tinc_urlsafe(src: &[u8]) -> String {
    b64encode_tinc_internal(src, BASE64_URLSAFE)
}

pub fn b64decode_tinc(src: &str) -> Result<Vec<u8>, Base64DecodeError> {
    let bytes = src.as_bytes();
    let mut dst = Vec::with_capacity(bytes.len() / 4 * 3 + 2);
    let mut index = 0;

    while index + 4 <= bytes.len() {
        let triplet = decode_base64_quad(&bytes[index..index + 4])?;
        dst.push((triplet & 0xff) as u8);
        dst.push(((triplet >> 8) & 0xff) as u8);
        dst.push(((triplet >> 16) & 0xff) as u8);
        index += 4;
    }

    match bytes.len() - index {
        0 => {}
        2 => {
            let first = decode_base64_byte(bytes[index])? as u32;
            let second = decode_base64_byte(bytes[index + 1])? as u32;
            let triplet = first | (second << 6);
            dst.push((triplet & 0xff) as u8);
        }
        3 => {
            let first = decode_base64_byte(bytes[index])? as u32;
            let second = decode_base64_byte(bytes[index + 1])? as u32;
            let third = decode_base64_byte(bytes[index + 2])? as u32;
            let triplet = first | (second << 6) | (third << 12);
            dst.push((triplet & 0xff) as u8);
            dst.push(((triplet >> 8) & 0xff) as u8);
        }
        _ => return Err(Base64DecodeError),
    }

    Ok(dst)
}

pub fn check_id(id: &str) -> bool {
    !id.is_empty()
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

pub fn check_netname(netname: &str, strict: bool) -> bool {
    if netname.is_empty() || netname.starts_with('.') {
        return false;
    }

    for c in netname.chars() {
        if c.is_control() || c == '/' || c == '\\' {
            return false;
        }

        if strict && " $%<>:`\"|?*".contains(c) {
            return false;
        }
    }

    true
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Base64DecodeError;

impl fmt::Display for Base64DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid tinc base64 data")
    }
}

impl std::error::Error for Base64DecodeError {}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn b64encode_tinc_internal(src: &[u8], alphabet: &[u8; 64]) -> String {
    let mut dst = Vec::with_capacity(src.len().div_ceil(3) * 4);
    let mut index = 0;

    while index + 3 <= src.len() {
        let triplet =
            src[index] as u32 | ((src[index + 1] as u32) << 8) | ((src[index + 2] as u32) << 16);
        dst.push(alphabet[(triplet & 63) as usize]);
        dst.push(alphabet[((triplet >> 6) & 63) as usize]);
        dst.push(alphabet[((triplet >> 12) & 63) as usize]);
        dst.push(alphabet[(triplet >> 18) as usize]);
        index += 3;
    }

    match src.len() - index {
        0 => {}
        1 => {
            let triplet = src[index] as u32;
            dst.push(alphabet[(triplet & 63) as usize]);
            dst.push(alphabet[(triplet >> 6) as usize]);
        }
        2 => {
            let triplet = src[index] as u32 | ((src[index + 1] as u32) << 8);
            dst.push(alphabet[(triplet & 63) as usize]);
            dst.push(alphabet[((triplet >> 6) & 63) as usize]);
            dst.push(alphabet[(triplet >> 12) as usize]);
        }
        _ => unreachable!(),
    }

    String::from_utf8(dst).expect("base64 alphabet is valid UTF-8")
}

fn decode_base64_quad(bytes: &[u8]) -> Result<u32, Base64DecodeError> {
    Ok(decode_base64_byte(bytes[0])? as u32
        | ((decode_base64_byte(bytes[1])? as u32) << 6)
        | ((decode_base64_byte(bytes[2])? as u32) << 12)
        | ((decode_base64_byte(bytes[3])? as u32) << 18))
}

fn decode_base64_byte(byte: u8) -> Result<u8, Base64DecodeError> {
    match byte {
        b'A'..=b'Z' => Ok(byte - b'A'),
        b'a'..=b'z' => Ok(byte - b'a' + 26),
        b'0'..=b'9' => Ok(byte - b'0' + 52),
        b'+' | b'-' => Ok(62),
        b'/' | b'_' => Ok(63),
        _ => Err(Base64DecodeError),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn int_to_str_returns_expected_decimal() {
        tinc_test_support::assert_can_create_netns();
        assert_eq!("0", int_to_str(0));
        assert_eq!("-1337", int_to_str(-1337));
        assert_eq!("65535", int_to_str(65535));
    }

    #[test]
    fn is_decimal_matches_c_strtol_rules() {
        tinc_test_support::assert_can_create_netns();
        assert!(!is_decimal(""));
        assert!(!is_decimal("DEADBEEF"));
        assert!(!is_decimal("0xCAFE"));
        assert!(!is_decimal("123foobar"));
        assert!(!is_decimal("777 "));

        assert!(is_decimal("0"));
        assert!(is_decimal("123"));
        assert!(is_decimal("-123"));
        assert!(is_decimal("+123"));
        assert!(is_decimal(" \r\n\t 777"));
    }

    #[test]
    fn string_eq_matches_null_aware_c_helper() {
        tinc_test_support::assert_can_create_netns();
        assert!(string_eq(None, None));
        assert!(string_eq(Some(""), Some("")));
        assert!(string_eq(Some("\tfoo 123"), Some("\tfoo 123")));

        assert!(!string_eq(None, Some("")));
        assert!(!string_eq(Some(""), None));
        assert!(!string_eq(Some("foo"), Some("FOO")));
        assert!(!string_eq(Some("foo"), Some(" foo")));
    }

    #[test]
    fn mem_eq_compares_equal_length_buffers() {
        tinc_test_support::assert_can_create_netns();
        assert!(mem_eq(b"secret", b"secret"));
        assert!(!mem_eq(b"secret", b"secRet"));
        assert!(!mem_eq(b"secret", b"secret!"));
    }

    #[test]
    fn hex_helpers_match_tinc_uppercase_output_and_partial_decode() {
        tinc_test_support::assert_can_create_netns();
        assert_eq!("0001020A0FFF", bin_to_hex(&[0, 1, 2, 10, 15, 255]));
        assert_eq!(vec![0, 1, 2, 10, 15, 255], hex_to_bin("0001020a0Fff", 6));
        assert_eq!(vec![0xab], hex_to_bin("abxxcd", 3));
    }

    #[test]
    fn tinc_base64_matches_known_vectors() {
        tinc_test_support::assert_can_create_netns();
        assert_eq!("", b64encode_tinc(b""));
        assert_eq!("hB", b64encode_tinc(b"a"));
        assert_eq!("hJG", b64encode_tinc(b"ab"));
        assert_eq!("hJ2Y", b64encode_tinc(b"abc"));
        assert_eq!("oVGbs9G", b64encode_tinc(b"hello"));
        assert_eq!(
            "AEgADQQBGcACJowCM0gDPARE",
            b64encode_tinc(&(0u8..18).collect::<Vec<_>>())
        );
    }

    #[test]
    fn tinc_base64_urlsafe_differs_only_for_62_and_63() {
        tinc_test_support::assert_can_create_netns();
        let data = (0u8..64).collect::<Vec<_>>();
        assert_eq!(
            "AEgADQQBGcACJowCM0gDPARESMBFVYxFYkhGbwRHe8BIhIyIkUiJngSKqsCLt4yLwEjMzQTN2cDO5ozO80jP/A",
            b64encode_tinc(&data)
        );
        assert_eq!(
            "AEgADQQBGcACJowCM0gDPARESMBFVYxFYkhGbwRHe8BIhIyIkUiJngSKqsCLt4yLwEjMzQTN2cDO5ozO80jP_A",
            b64encode_tinc_urlsafe(&data)
        );
    }

    #[test]
    fn tinc_base64_decodes_original_and_urlsafe_alphabets() {
        tinc_test_support::assert_can_create_netns();
        for input in [
            b"".as_slice(),
            b"a",
            b"ab",
            b"abc",
            b"hello",
            &(0u8..64).collect::<Vec<_>>(),
        ] {
            assert_eq!(input, b64decode_tinc(&b64encode_tinc(input)).unwrap());
            assert_eq!(
                input,
                b64decode_tinc(&b64encode_tinc_urlsafe(input)).unwrap()
            );
        }

        assert!(b64decode_tinc("A").is_err());
        assert!(b64decode_tinc("????").is_err());
    }

    #[test]
    fn check_id_accepts_only_tinc_node_identifiers() {
        tinc_test_support::assert_can_create_netns();
        assert!(check_id("alpha"));
        assert!(check_id("node_123"));
        assert!(!check_id(""));
        assert!(!check_id("node-name"));
        assert!(!check_id("node.name"));
        assert!(!check_id("node/name"));
    }

    #[test]
    fn check_netname_matches_strict_and_non_strict_rules() {
        tinc_test_support::assert_can_create_netns();
        assert!(check_netname("vpn.prod", false));
        assert!(check_netname("vpn prod", false));
        assert!(!check_netname("", false));
        assert!(!check_netname(".hidden", false));
        assert!(!check_netname("bad/name", false));
        assert!(!check_netname("bad\\name", false));
        assert!(!check_netname("bad\nname", false));

        assert!(check_netname("vpn.prod", true));
        assert!(!check_netname("vpn prod", true));
        assert!(!check_netname("vpn:name", true));
    }
}
