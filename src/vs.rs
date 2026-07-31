// Copyright 2026 WritersLogic. All rights reserved.
// Licensed under the Apache License, Version 2.0 or the MIT license,
// at your option.

//! The variation-selector byte codec (C2PA 2.4 Appendix A.8).
//!
//! Maps a byte onto one invisible Unicode variation selector and back. Low
//! nibble values `0x00..=0x0F` use the Variation Selectors block
//! (`U+FE00..U+FE0F`); the remaining `0x10..=0xFF` use Variation Selectors
//! Supplement (`U+E0100..U+E01EF`). The two ranges are contiguous in byte space,
//! so the mapping is a bijection over all 256 byte values.
//!
//! This module is the transport alphabet only. The framing that carries a
//! Manifest Store (magic, version, length, payload) lives in
//! [`crate::wrapper`], and the content binding in [`crate::hardbinding`].

/// First code point of the Variation Selectors block, encoding byte `0x00`.
const VS_START: u32 = 0xFE00;
/// Last code point of the Variation Selectors block, encoding byte `0x0F`.
const VS_END: u32 = 0xFE0F;
/// First code point of Variation Selectors Supplement, encoding byte `0x10`.
const VS_SUP_START: u32 = 0xE0100;
/// Last code point of Variation Selectors Supplement, encoding byte `0xFF`.
const VS_SUP_END: u32 = 0xE01EF;

/// Map a byte to its variation selector (A.8 `byteToVariationSelector`).
pub fn byte_to_vs(b: u8) -> char {
    let cp = if b <= 0x0F {
        VS_START + b as u32
    } else {
        VS_SUP_START + (b as u32 - 0x10)
    };
    // Both ranges are inside the BMP/SMP with no surrogates, so every value is
    // a valid Unicode scalar. Exhaustively covered by `codec_is_a_bijection`.
    char::from_u32(cp).expect("variation-selector code points are valid scalars")
}

/// Map a variation selector back to its byte, or `None` if `c` is not one
/// (A.8 `variationSelectorToByte`).
pub fn vs_to_byte(c: char) -> Option<u8> {
    match c as u32 {
        cp @ VS_START..=VS_END => Some((cp - VS_START) as u8),
        cp @ VS_SUP_START..=VS_SUP_END => Some((cp - VS_SUP_START + 0x10) as u8),
        _ => None,
    }
}

/// Whether `c` is a variation selector usable by this codec.
///
/// Note this is narrower than "is a variation selector": `U+FE0F` and friends
/// are in range, but the Supplement block extends to `U+E01EF` only, which is
/// exactly 240 code points and completes the 256-value byte space.
pub fn is_vs(c: char) -> bool {
    vs_to_byte(c).is_some()
}

/// Encode `bytes` as a bare run of variation selectors, with no marker or frame.
pub fn encode_run(bytes: &[u8]) -> String {
    bytes.iter().map(|&b| byte_to_vs(b)).collect()
}

/// Decode a leading run of variation selectors from `s`, stopping at the first
/// character that is not one. Returns the bytes and the byte offset in `s` where
/// the run ended.
pub fn decode_run(s: &str) -> (Vec<u8>, usize) {
    let mut out = Vec::new();
    for (offset, c) in s.char_indices() {
        match vs_to_byte(c) {
            Some(b) => out.push(b),
            None => return (out, offset),
        }
    }
    (out, s.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_boundary_vectors() {
        assert_eq!(byte_to_vs(0x00), '\u{FE00}');
        assert_eq!(byte_to_vs(0x0F), '\u{FE0F}');
        assert_eq!(byte_to_vs(0x10), '\u{E0100}');
        assert_eq!(byte_to_vs(0xFF), '\u{E01EF}');
    }

    #[test]
    fn codec_is_a_bijection() {
        let mut seen = std::collections::HashSet::new();
        for b in 0u8..=0xFF {
            let c = byte_to_vs(b);
            assert_eq!(vs_to_byte(c), Some(b), "byte {b:#04x} did not round-trip");
            assert!(seen.insert(c), "byte {b:#04x} collided on {c:?}");
        }
        assert_eq!(seen.len(), 256);
    }

    #[test]
    fn non_selectors_are_rejected() {
        // Visible text, the wrapper marker, and code points adjacent to both
        // ranges must all be outside the alphabet.
        for c in ['a', 'Z', '0', ' ', '\n', '\u{FEFF}', '\u{FDFF}', '\u{FE10}'] {
            assert_eq!(vs_to_byte(c), None, "{c:?} was accepted");
            assert!(!is_vs(c));
        }
        // One past the end of the Supplement block.
        assert_eq!(vs_to_byte('\u{E01F0}'), None);
    }

    #[test]
    fn run_round_trips_and_reports_its_end() {
        let payload = [0xDEu8, 0xAD, 0xBE, 0xEF, 0x00, 0x0F, 0x10];
        let run = encode_run(&payload);
        let (decoded, end) = decode_run(&run);
        assert_eq!(decoded, payload);
        assert_eq!(end, run.len());
    }

    #[test]
    fn run_stops_at_visible_text() {
        let mut s = encode_run(&[0x01, 0x02]);
        let run_len = s.len();
        s.push_str("tail");
        let (decoded, end) = decode_run(&s);
        assert_eq!(decoded, vec![0x01, 0x02]);
        assert_eq!(
            end, run_len,
            "end offset must be the first non-selector byte"
        );
        assert_eq!(&s[end..], "tail");
    }

    #[test]
    fn empty_input_decodes_to_nothing() {
        assert_eq!(decode_run(""), (Vec::new(), 0));
        assert_eq!(encode_run(&[]), "");
    }
}
