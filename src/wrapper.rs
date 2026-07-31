// Copyright 2026 WritersLogic. All rights reserved.
// Licensed under the Apache License, Version 2.0 or the MIT license,
// at your option.

//! The `C2PATextManifestWrapper` frame (C2PA 2.4 Appendix A.8).
//!
//! A wrapper is a `U+FEFF` marker followed by the variation-selector encoding of
//! `magic(8) + version(1) + big-endian length(4) + payload + optional padding`.
//! The marker is part of the wrapper for content binding, so the byte range this
//! module reports covers the marker together with the selector run.

use crate::error::Error;
use crate::vs::{byte_to_vs, decode_run, vs_to_byte};

/// Wrapper identifier, `"C2PATXT\0"`.
pub const MAGIC: [u8; 8] = *b"C2PATXT\0";
/// Frame version defined by A.8.
pub const VERSION: u8 = 1;
/// Zero-Width No-Break Space marking the start of a wrapper.
pub const MARKER: char = '\u{FEFF}';
/// `magic(8) + version(1) + length(4)`.
pub const HEADER_LEN: usize = 13;

/// Version 2 frame: the v1 frame followed by a truncated hash over it, so a
/// mangled carrier is rejected rather than decoded to wrong bytes. A
/// WritersLogic extension, not part of A.8.
#[cfg(feature = "checksum-v2")]
pub const VERSION_V2: u8 = 2;
#[cfg(feature = "checksum-v2")]
const CHECKSUM_LEN: usize = 4;

/// A located wrapper and the byte range it occupies in the host text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wrapper {
    /// The Manifest Store bytes, excluding any trailing padding.
    pub payload: Vec<u8>,
    /// The frame version that decoded.
    pub version: u8,
    /// Byte offset of the `U+FEFF` marker in the host text as stored, before
    /// any normalization.
    pub start: usize,
    /// Byte length from the marker through the end of the selector run,
    /// including any trailing padding.
    pub length: usize,
}

impl Wrapper {
    /// The half-open byte range `start..start + length`.
    pub fn range(&self) -> core::ops::Range<usize> {
        self.start..self.start + self.length
    }
}

/// Encode `payload` as a v1 wrapper.
pub fn encode(payload: &[u8]) -> Result<String, Error> {
    encode_with_padding(payload, &[])
}

fn encode_with_padding(payload: &[u8], padding: &[u8]) -> Result<String, Error> {
    let len = u32::try_from(payload.len()).map_err(|_| Error::PayloadTooLarge(payload.len()))?;
    let mut framed = Vec::with_capacity(HEADER_LEN + payload.len() + padding.len());
    framed.extend_from_slice(&MAGIC);
    framed.push(VERSION);
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(payload);
    framed.extend_from_slice(padding);
    Ok(carry(&framed))
}

fn carry(framed: &[u8]) -> String {
    let mut out = String::with_capacity(1 + framed.len() * 4);
    out.push(MARKER);
    out.extend(framed.iter().map(|&b| byte_to_vs(b)));
    out
}

/// Append a v1 wrapper to `text`. A.8 places the wrapper at the end of the
/// visible content.
pub fn embed(text: &str, payload: &[u8]) -> Result<String, Error> {
    Ok(format!("{text}{}", encode(payload)?))
}

/// The deterministic target UTF-8 byte length for a manifest of
/// `manifest_len` bytes: `3 + (13 + M) * 4 + 6`.
///
/// The margin of 6 keeps the gap between this target and the actual unpadded
/// length expressible as `3a + 4b`, which the values 1, 2 and 5 are not.
pub fn target_length(manifest_len: usize) -> usize {
    3 + (HEADER_LEN + manifest_len) * 4 + 6
}

/// Padding bytes whose selector encoding totals exactly `gap` UTF-8 bytes.
///
/// The decomposition is fixed by the specification so that compliant generators
/// emit byte-identical wrappers for the same manifest: `(gap - 4 * (gap mod 3)) / 3`
/// bytes of `0x00`, then `gap mod 3` bytes of `0x10`.
pub fn padding(gap: usize) -> Result<Vec<u8>, Error> {
    if gap == 0 {
        return Ok(Vec::new());
    }
    // 4 = 1 (mod 3), so b = gap mod 3 makes `gap - 4b` divisible by 3.
    let b = gap % 3;
    if gap < 4 * b {
        // Only 1, 2 and 5 are not expressible; the +6 margin excludes them.
        return Err(Error::UnrepresentableGap(gap));
    }
    let a = (gap - 4 * b) / 3;
    let mut out = vec![0x00u8; a];
    out.extend(core::iter::repeat_n(0x10u8, b));
    Ok(out)
}

/// Encode `payload` padded to [`target_length`], so the wrapper's byte length
/// depends only on the manifest size and not on its byte distribution.
pub fn encode_padded(payload: &[u8]) -> Result<String, Error> {
    let target = target_length(payload.len());
    let base = encode(payload)?;
    let gap = target
        .checked_sub(base.len())
        .ok_or(Error::UnrepresentableGap(0))?;
    encode_with_padding(payload, &padding(gap)?)
}

/// Decode one framed byte run into a wrapper, or `None` if it does not decode.
fn decode_frame(run: &[u8], start: usize, length: usize) -> Option<Wrapper> {
    let (body_end, declared_ok) = frame_bounds(run)?;
    if run[8] != VERSION || !declared_ok {
        return None;
    }
    Some(Wrapper {
        payload: run[HEADER_LEN..body_end].to_vec(),
        version: VERSION,
        start,
        length,
    })
}

/// Common header parse: returns the end of the declared body and whether the
/// run is long enough to contain it.
fn frame_bounds(run: &[u8]) -> Option<(usize, bool)> {
    if run.len() < HEADER_LEN || run[..MAGIC.len()] != MAGIC {
        return None;
    }
    let declared = u32::from_be_bytes([run[9], run[10], run[11], run[12]]) as usize;
    let body_end = HEADER_LEN.checked_add(declared)?;
    Some((body_end, run.len() >= body_end))
}

/// Visit every `U+FEFF`-prefixed selector run in `text` as `(run, start, length)`.
fn scan(text: &str, mut visit: impl FnMut(&[u8], usize, usize)) {
    let mut from = 0;
    while let Some(rel) = text[from..].find(MARKER) {
        let start = from + rel;
        let run_start = start + MARKER.len_utf8();
        let (run, consumed) = decode_run(&text[run_start..]);
        let end = run_start + consumed;
        visit(&run, start, end - start);
        // Resume after the run, so a marker inside it is not rescanned.
        from = end.max(run_start);
    }
}

/// Every valid v1 wrapper in `text`, in order of appearance.
///
/// A candidate whose magic matches but whose frame does not decode is not a
/// valid wrapper and is skipped, so a mangled run beside a good one does not
/// discard the asset.
pub fn locate_all(text: &str) -> Vec<Wrapper> {
    let mut found = Vec::new();
    scan(text, |run, start, length| {
        if let Some(w) = decode_frame(run, start, length) {
            found.push(w);
        }
    });
    found
}

/// The single valid wrapper in `text`.
///
/// Zero valid wrappers and no candidate at all is [`Error::NotFound`], the only
/// outcome meaning the text carries no provenance. More than one valid wrapper
/// is [`Error::MultipleWrappers`] (`manifest.text.multipleWrappers`), and a
/// candidate that fails to decode when no valid wrapper was found is
/// [`Error::CorruptedWrapper`] (`manifest.text.corruptedWrapper`) — both are
/// reportable failures. See [`Error::is_no_manifest_located`].
///
/// A candidate that fails to decode *beside* a valid wrapper is skipped rather
/// than reported. The corrupted-wrapper code describes text whose only wrapper
/// is mangled; letting stray bytes carrying the magic invalidate an otherwise
/// good wrapper would hand anyone who can append to the text a denial of
/// service.
pub fn extract(text: &str) -> Result<Wrapper, Error> {
    let mut found = locate_all(text);
    match found.len() {
        1 => Ok(found.remove(0)),
        0 if has_candidate(text) => Err(Error::CorruptedWrapper),
        0 => Err(Error::NotFound),
        _ => Err(Error::MultipleWrappers),
    }
}

/// Whether any marker is followed by a selector run bearing the magic, whether
/// or not the rest of the frame decodes.
fn has_candidate(text: &str) -> bool {
    let mut seen = false;
    scan(text, |run, _, _| {
        if run.len() >= MAGIC.len() && run[..MAGIC.len()] == MAGIC {
            seen = true;
        }
    });
    seen
}

/// The v2 frame: the v1 layout with `version = 2` and a truncated SHA-256 over
/// `magic + version + length + payload` appended.
///
/// A WritersLogic extension, not part of the specified frame. The specification
/// requires a candidate that does not decode to be ignored, which makes a
/// mangled carrier indistinguishable from an absent one. v2 closes that gap for
/// generators that control both ends: a corrupted run fails its checksum and is
/// rejected, rather than decoding to wrong bytes or vanishing silently.
///
/// A v2 wrapper is not a valid A.8 wrapper to a conformant validator, so use it
/// only where both sides opt in.
#[cfg(feature = "checksum-v2")]
pub mod v2 {
    use super::{
        carry, frame_bounds, has_candidate, scan, Error, Wrapper, CHECKSUM_LEN, HEADER_LEN, MAGIC,
        VERSION_V2,
    };
    use crate::hardbinding::{Algorithm, Hasher};

    fn framed(payload: &[u8], hasher: &impl Hasher) -> Result<Vec<u8>, Error> {
        let len =
            u32::try_from(payload.len()).map_err(|_| Error::PayloadTooLarge(payload.len()))?;
        let mut v = Vec::with_capacity(HEADER_LEN + payload.len() + CHECKSUM_LEN);
        v.extend_from_slice(&MAGIC);
        v.push(VERSION_V2);
        v.extend_from_slice(&len.to_be_bytes());
        v.extend_from_slice(payload);
        let sum = hasher.digest(Algorithm::Sha256, &v);
        v.extend_from_slice(&sum[..CHECKSUM_LEN]);
        Ok(v)
    }

    /// Encode `payload` as a v2 wrapper.
    pub fn encode(payload: &[u8], hasher: &impl Hasher) -> Result<String, Error> {
        Ok(carry(&framed(payload, hasher)?))
    }

    /// Append a v2 wrapper to `text`.
    pub fn embed(text: &str, payload: &[u8], hasher: &impl Hasher) -> Result<String, Error> {
        Ok(format!("{text}{}", encode(payload, hasher)?))
    }

    fn decode(run: &[u8], start: usize, length: usize, hasher: &impl Hasher) -> Option<Wrapper> {
        let (body_end, _) = frame_bounds(run)?;
        if run[8] != VERSION_V2 || run.len() < body_end + CHECKSUM_LEN {
            return None;
        }
        let expected = hasher.digest(Algorithm::Sha256, &run[..body_end]);
        if run[body_end..body_end + CHECKSUM_LEN] != expected[..CHECKSUM_LEN] {
            return None;
        }
        Some(Wrapper {
            payload: run[HEADER_LEN..body_end].to_vec(),
            version: VERSION_V2,
            start,
            length,
        })
    }

    /// Every valid v2 wrapper in `text`, checksum verified.
    pub fn locate_all(text: &str, hasher: &impl Hasher) -> Vec<Wrapper> {
        let mut found = Vec::new();
        scan(text, |run, start, length| {
            if let Some(w) = decode(run, start, length, hasher) {
                found.push(w);
            }
        });
        found
    }

    /// The single valid wrapper in `text`, accepting either frame version.
    ///
    /// Tries v1 first, since that is the specified frame. Use this where the
    /// carrier may have been produced by either generator; use [`super::extract`]
    /// where only the specified frame is acceptable.
    pub fn extract_any(text: &str, hasher: &impl Hasher) -> Result<Wrapper, Error> {
        match super::extract(text) {
            Ok(w) => Ok(w),
            Err(v1) => match extract(text, hasher) {
                Ok(w) => Ok(w),
                // Neither frame decoded; keep whichever actually saw a candidate.
                Err(Error::NotFound) => Err(v1),
                Err(v2) => Err(v2),
            },
        }
    }

    /// The single valid v2 wrapper in `text`.
    ///
    /// A run whose checksum fails yields [`Error::CorruptedWrapper`] rather than
    /// [`Error::NotFound`], which is the distinction v2 exists to provide.
    pub fn extract(text: &str, hasher: &impl Hasher) -> Result<Wrapper, Error> {
        let mut found = locate_all(text, hasher);
        match found.len() {
            1 => Ok(found.remove(0)),
            0 if has_candidate(text) => Err(Error::CorruptedWrapper),
            0 => Err(Error::NotFound),
            _ => Err(Error::MultipleWrappers),
        }
    }
}

/// Remove the wrapper occupying `range` from `text`, returning the remaining
/// bytes. The caller normalizes afterwards; see [`crate::hardbinding`].
pub fn strip(text: &str, range: core::ops::Range<usize>) -> Result<String, Error> {
    if range.end > text.len() || range.start > range.end {
        return Err(Error::MalformedExclusion);
    }
    if !text.is_char_boundary(range.start) || !text.is_char_boundary(range.end) {
        return Err(Error::MalformedExclusion);
    }
    let mut out = String::with_capacity(text.len() - (range.end - range.start));
    out.push_str(&text[..range.start]);
    out.push_str(&text[range.end..]);
    Ok(out)
}

/// Decode a bare selector run into bytes, rejecting any non-selector.
pub fn decode_exact(run: &str) -> Result<Vec<u8>, Error> {
    run.chars()
        .map(|c| vs_to_byte(c).ok_or(Error::CorruptedWrapper))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOST: &str = "This sentence carries an invisible C2PA text manifest wrapper at its end.";
    const PAYLOAD: &[u8] = b"c2pa-manifest-01";

    #[test]
    fn round_trip_locates_the_payload_and_its_range() {
        let asset = embed(HOST, PAYLOAD).unwrap();
        let w = extract(&asset).unwrap();
        assert_eq!(w.payload, PAYLOAD);
        assert_eq!(w.version, VERSION);
        assert_eq!(w.start, HOST.len());
        assert_eq!(&asset[w.range()], &asset[HOST.len()..]);
        // The excluded range begins at the marker.
        assert!(asset[w.range()].starts_with(MARKER));
    }

    #[test]
    fn stripping_the_range_leaves_the_visible_text() {
        let asset = embed(HOST, PAYLOAD).unwrap();
        let w = extract(&asset).unwrap();
        assert_eq!(strip(&asset, w.range()).unwrap(), HOST);
    }

    #[test]
    fn padding_uses_the_specified_decomposition() {
        assert_eq!(padding(0).unwrap(), Vec::<u8>::new());
        assert_eq!(padding(6).unwrap(), vec![0x00, 0x00]);
        assert_eq!(padding(7).unwrap(), vec![0x00, 0x10]);
        assert_eq!(padding(8).unwrap(), vec![0x10, 0x10]);
        // 12 admits four 3-byte selectors or three 4-byte ones; the specified
        // decomposition is four 0x00.
        assert_eq!(padding(12).unwrap(), vec![0x00; 4]);
        for gap in [1usize, 2, 5] {
            assert!(padding(gap).is_err(), "gap {gap} should be rejected");
        }
    }

    #[test]
    fn padded_wrapper_hits_the_deterministic_target() {
        for m in [0usize, 1, 16, 200] {
            let payload = vec![0xABu8; m];
            let padded = encode_padded(&payload).unwrap();
            assert_eq!(padded.len(), target_length(m), "manifest of {m} bytes");
            // Padding is ignored on decode.
            let w = extract(&format!("{HOST}{padded}")).unwrap();
            assert_eq!(w.payload, payload);
        }
    }

    #[test]
    fn known_vector_matches_the_published_test_file() {
        // 16-byte payload: E_target 125, unpadded 114, gap 11 -> one 0x00, two 0x10.
        let unpadded = encode(PAYLOAD).unwrap();
        assert_eq!(unpadded.len(), 114);
        assert_eq!(target_length(PAYLOAD.len()), 125);
        assert_eq!(padding(125 - 114).unwrap(), vec![0x00, 0x10, 0x10]);
        assert_eq!(encode_padded(PAYLOAD).unwrap().len(), 125);
    }

    #[test]
    fn no_wrapper_is_absence_but_many_is_a_reportable_failure() {
        assert_eq!(extract(HOST), Err(Error::NotFound));
        assert!(Error::NotFound.is_no_manifest_located());

        let one = embed(HOST, PAYLOAD).unwrap();
        let two = embed(&one, PAYLOAD).unwrap();
        assert_eq!(extract(&two), Err(Error::MultipleWrappers));
        assert_eq!(locate_all(&two).len(), 2);
        // Two wrappers were located, so this is a rejection, not an absence.
        assert!(!Error::MultipleWrappers.is_no_manifest_located());
        assert_eq!(
            Error::MultipleWrappers.code(),
            Some("manifest.text.multipleWrappers")
        );
    }

    #[test]
    fn a_mangled_candidate_beside_a_valid_one_is_ignored() {
        // Wrong version: the candidate does not decode, so it is skipped.
        let mut framed = MAGIC.to_vec();
        framed.push(9);
        framed.extend_from_slice(&16u32.to_be_bytes());
        framed.extend_from_slice(PAYLOAD);
        let bad = carry(&framed);
        let good = encode(PAYLOAD).unwrap();
        let asset = format!("{HOST}{bad}{good}");
        let w = extract(&asset).expect("the valid wrapper is still located");
        assert_eq!(w.payload, PAYLOAD);
        assert_eq!(locate_all(&asset).len(), 1);
    }

    #[test]
    fn a_lone_mangled_candidate_reports_corruption_not_absence() {
        let mut framed = MAGIC.to_vec();
        framed.push(VERSION);
        framed.extend_from_slice(&99u32.to_be_bytes()); // declares more than it carries
        framed.extend_from_slice(PAYLOAD);
        let asset = format!("{HOST}{}", carry(&framed));
        let err = extract(&asset).unwrap_err();
        assert_eq!(err, Error::CorruptedWrapper);
        // A magic number was detected, so this is a reportable failure rather
        // than an unsigned asset.
        assert!(!err.is_no_manifest_located());
        assert_eq!(err.code(), Some("manifest.text.corruptedWrapper"));
    }

    #[test]
    fn a_bad_magic_is_not_a_candidate_at_all() {
        // Final magic byte is 0x01 rather than the required 0x00.
        let mut v = b"C2PATXT\x01".to_vec();
        v.push(VERSION);
        v.extend_from_slice(&16u32.to_be_bytes());
        v.extend_from_slice(PAYLOAD);
        let asset = format!("{HOST}{}", carry(&v));
        // Detection keys on the magic, so this is absence, not corruption.
        assert_eq!(extract(&asset), Err(Error::NotFound));
    }

    #[test]
    fn payload_larger_than_the_length_field_is_rejected() {
        // Constructing 4 GiB is impractical; assert the boundary arithmetic holds.
        assert!(u32::try_from(u32::MAX as usize).is_ok());
        assert!(u32::try_from(u32::MAX as usize + 1).is_err());
    }

    /// Text that legitimately contains variation selectors must not be read as
    /// carrying provenance. Emoji presentation selectors and CJK ideographic
    /// variation sequences are ordinary content, and a bare `U+FEFF` is a common
    /// byte-order mark.
    #[test]
    fn legitimate_selectors_in_clean_text_are_not_payloads() {
        let clean = [
            "A perfectly ordinary paragraph with no hidden provenance whatsoever.",
            "Emoji carry legitimate variation selectors: a smiley \u{263A}\u{FE0F} and a heart \u{2764}\u{FE0F}.",
            "CJK ideographic variation sequence: \u{845B}\u{E0100} is a valid rendering hint.",
            "A stray zero-width joiner \u{200D} and no-break space \u{FEFF} without any magic.",
            "\u{FEFF}A leading byte-order mark followed by ordinary prose.",
            // A marker followed by selectors that are too short to be a header.
            "\u{FEFF}\u{FE00}\u{FE01}",
            "",
        ];
        for s in clean {
            assert_eq!(
                extract(s),
                Err(Error::NotFound),
                "hallucinated provenance in {s:?}"
            );
            assert!(locate_all(s).is_empty());
        }
    }

    #[test]
    fn a_marker_inside_ordinary_text_does_not_shadow_a_real_wrapper() {
        let host = "Quoting a BOM \u{FEFF} mid-sentence, and an emoji \u{2764}\u{FE0F}.";
        let asset = embed(host, PAYLOAD).unwrap();
        let w = extract(&asset).unwrap();
        assert_eq!(w.payload, PAYLOAD);
        assert_eq!(w.start, host.len());
    }

    #[cfg(feature = "checksum-v2")]
    mod checksum_v2 {
        use super::*;
        use crate::hardbinding::{Algorithm, Hasher};

        /// Deterministic stand-in so the frame is testable without pulling in a
        /// real digest.
        struct TestHasher;
        impl Hasher for TestHasher {
            fn digest(&self, _: Algorithm, data: &[u8]) -> Vec<u8> {
                let mut acc: u32 = 0x811C_9DC5;
                for &b in data {
                    acc = (acc ^ b as u32).wrapping_mul(0x0100_0193);
                }
                acc.to_be_bytes().to_vec()
            }
        }

        #[test]
        fn round_trips_and_reports_version_two() {
            let asset = v2::embed(HOST, PAYLOAD, &TestHasher).unwrap();
            let w = v2::extract(&asset, &TestHasher).unwrap();
            assert_eq!(w.payload, PAYLOAD);
            assert_eq!(w.version, VERSION_V2);
            assert_eq!(strip(&asset, w.range()).unwrap(), HOST);
        }

        #[test]
        fn a_corrupted_payload_is_rejected_rather_than_decoded() {
            let asset = v2::embed(HOST, PAYLOAD, &TestHasher).unwrap();
            // Flip one payload byte by re-encoding a mutated payload under the
            // original checksum: rebuild the run with a stale sum.
            let mut mutated = PAYLOAD.to_vec();
            mutated[0] ^= 0x01;
            let good = v2::encode(PAYLOAD, &TestHasher).unwrap();
            let bad = v2::encode(&mutated, &TestHasher).unwrap();
            // Splice the good checksum onto the mutated body: last 4 selectors.
            let good_tail: String = good
                .chars()
                .rev()
                .take(4)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            let bad_body: String = bad.chars().take(bad.chars().count() - 4).collect();
            let spliced = format!("{HOST}{bad_body}{good_tail}");
            assert_eq!(
                v2::extract(&spliced, &TestHasher),
                Err(Error::CorruptedWrapper),
                "a stale checksum must fail closed"
            );
            assert!(!asset.is_empty());
        }

        #[test]
        fn a_v1_wrapper_is_not_a_v2_wrapper_and_the_reverse() {
            let v1 = embed(HOST, PAYLOAD).unwrap();
            assert_eq!(v2::extract(&v1, &TestHasher), Err(Error::CorruptedWrapper));
            let two = v2::embed(HOST, PAYLOAD, &TestHasher).unwrap();
            // v1 detection sees a candidate it cannot decode, so it fails safe.
            assert_eq!(extract(&two), Err(Error::CorruptedWrapper));
        }

        #[test]
        fn clean_text_is_still_not_a_payload() {
            assert_eq!(v2::extract(HOST, &TestHasher), Err(Error::NotFound));
        }

        #[test]
        fn extract_any_accepts_either_frame() {
            let v1 = embed(HOST, PAYLOAD).unwrap();
            let two = v2::embed(HOST, PAYLOAD, &TestHasher).unwrap();
            for asset in [&v1, &two] {
                let w = v2::extract_any(asset, &TestHasher).unwrap();
                assert_eq!(w.payload, PAYLOAD);
            }
            assert_eq!(v2::extract_any(&v1, &TestHasher).unwrap().version, VERSION);
            assert_eq!(
                v2::extract_any(&two, &TestHasher).unwrap().version,
                VERSION_V2
            );
            assert_eq!(
                v2::extract_any(HOST, &TestHasher),
                Err(Error::NotFound),
                "clean text is absence, not corruption"
            );
        }
    }

    #[test]
    fn strip_rejects_ranges_that_split_a_character() {
        let asset = format!("café{}", encode(PAYLOAD).unwrap());
        // Byte 4 is inside the two-byte 'é'.
        assert_eq!(
            strip(&asset, 4..asset.len()),
            Err(Error::MalformedExclusion)
        );
        assert_eq!(
            strip(&asset, 0..asset.len() + 1),
            Err(Error::MalformedExclusion)
        );
    }
}
