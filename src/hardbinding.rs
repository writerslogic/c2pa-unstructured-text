// Copyright 2026 WritersLogic. All rights reserved.
// Licensed under the Apache License, Version 2.0 or the MIT license,
// at your option.

//! The `c2pa.hash.data` hard binding for unstructured text (A.8).
//!
//! # Order of operations
//!
//! The exclusion ranges are byte offsets into the text **as stored**, before any
//! normalization. A validator removes the excluded bytes first, normalizes what
//! remains to NFC, encodes as UTF-8, and hashes that. Normalizing first would
//! shift every offset whenever the stored text is not already NFC.
//!
//! This is the opposite of [`c2pa_structured_text`]'s A.9 binding, which applies
//! no normalization at all: structured text files are byte-stable on disk, while
//! A.8 text is clipboard-portable and may arrive in any normalization form.
//!
//! # Dependency-free by default
//!
//! Hashing and NFC are injected through [`Hasher`] and [`Normalizer`], so the
//! binding algorithm itself pulls nothing in. A host that already provides both
//! (a Cloudflare Worker, a browser) implements the two traits against its
//! runtime. The `hard-binding` feature ships ready-made implementations for
//! callers who would rather not.
//!
//! [`c2pa_structured_text`]: https://crates.io/crates/c2pa-structured-text

use crate::error::Error;
use crate::wrapper;

/// The assertion label for the hard binding.
pub const DATA_HASH_LABEL: &str = "c2pa.hash.data";

/// A byte range excluded from the data hash, matching the `EXCLUSION_RANGE-map`
/// CDDL (`start`, `length`). Offsets are into the text as stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Exclusion {
    pub start: usize,
    pub length: usize,
}

impl Exclusion {
    fn end(&self) -> Option<usize> {
        self.start.checked_add(self.length)
    }
}

/// A C2PA-allowed hash algorithm for the data hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    Sha256,
    Sha384,
    Sha512,
}

impl Algorithm {
    /// The C2PA algorithm identifier used in the `alg` field.
    pub fn id(self) -> &'static str {
        match self {
            Algorithm::Sha256 => "sha256",
            Algorithm::Sha384 => "sha384",
            Algorithm::Sha512 => "sha512",
        }
    }

    pub fn from_id(id: &str) -> Result<Self, Error> {
        match id {
            "sha256" => Ok(Algorithm::Sha256),
            "sha384" => Ok(Algorithm::Sha384),
            "sha512" => Ok(Algorithm::Sha512),
            other => Err(Error::UnsupportedAlgorithm(other.to_string())),
        }
    }
}

/// A digest implementation. Supplied by the caller so the core has no crypto
/// dependency; the `hard-binding` feature provides [`RustCrypto`].
pub trait Hasher {
    fn digest(&self, alg: Algorithm, data: &[u8]) -> Vec<u8>;
}

/// A Unicode NFC normalizer. Supplied by the caller so the core carries no
/// Unicode tables; the `hard-binding` feature provides [`UnicodeNfc`].
pub trait Normalizer {
    fn nfc(&self, text: &str) -> String;
}

/// A computed `c2pa.hash.data` assertion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataHash {
    pub exclusions: Vec<Exclusion>,
    pub alg: String,
    pub hash: Vec<u8>,
    pub name: Option<String>,
}

impl DataHash {
    /// The assertion label, `c2pa.hash.data`.
    pub fn label(&self) -> &'static str {
        DATA_HASH_LABEL
    }

    /// Serialise to the JSON shape consumed when building a manifest, with the
    /// hash as standard Base64. Hand-built to keep the crate dependency-free;
    /// the field set matches the `data-hash-map` CDDL.
    pub fn to_json(&self) -> String {
        let ranges: Vec<String> = self
            .exclusions
            .iter()
            .map(|e| format!("{{\"start\":{},\"length\":{}}}", e.start, e.length))
            .collect();
        let mut json = format!(
            "{{\"exclusions\":[{}],\"alg\":\"{}\",\"hash\":\"{}\"",
            ranges.join(","),
            self.alg,
            base64(&self.hash)
        );
        if let Some(name) = &self.name {
            json.push_str(&format!(",\"name\":\"{name}\""));
        }
        json.push('}');
        json
    }
}

/// Standard Base64 (RFC 4648 §4, with padding). Encode only; the crate never
/// needs to decode one.
fn base64(bytes: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            T[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            T[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// The single exclusion range covering the located wrapper, marker included.
pub fn manifest_exclusion(text: &str) -> Result<Exclusion, Error> {
    let w = wrapper::extract(text)?;
    Ok(Exclusion {
        start: w.start,
        length: w.length,
    })
}

/// Remove `exclusions` from `text`, validating that they are ordered,
/// non-overlapping, within bounds, and on character boundaries.
pub fn apply_exclusions(text: &str, exclusions: &[Exclusion]) -> Result<String, Error> {
    let mut cursor = 0usize;
    let mut out = String::with_capacity(text.len());
    for ex in exclusions {
        let end = ex.end().ok_or(Error::MalformedExclusion)?;
        if ex.start < cursor || end > text.len() {
            return Err(Error::MalformedExclusion);
        }
        if !text.is_char_boundary(ex.start) || !text.is_char_boundary(end) {
            return Err(Error::MalformedExclusion);
        }
        out.push_str(&text[cursor..ex.start]);
        cursor = end;
    }
    out.push_str(&text[cursor..]);
    Ok(out)
}

/// The exact bytes the data hash covers: `text` with `exclusions` removed, then
/// normalized to NFC and encoded as UTF-8. This is the seam shared by
/// computation and verification.
pub fn hashed_bytes(
    text: &str,
    exclusions: &[Exclusion],
    normalizer: &impl Normalizer,
) -> Result<Vec<u8>, Error> {
    let stripped = apply_exclusions(text, exclusions)?;
    Ok(normalizer.nfc(&stripped).into_bytes())
}

/// Compute the hard binding for `text`: locate the wrapper, exclude it, then
/// hash the NFC-normalized remainder.
pub fn compute_data_hash(
    text: &str,
    alg: Algorithm,
    hasher: &impl Hasher,
    normalizer: &impl Normalizer,
) -> Result<DataHash, Error> {
    let exclusion = manifest_exclusion(text)?;
    let covered = hashed_bytes(text, &[exclusion], normalizer)?;
    Ok(DataHash {
        exclusions: vec![exclusion],
        alg: alg.id().to_string(),
        hash: hasher.digest(alg, &covered),
        name: None,
    })
}

/// Verify a `c2pa.hash.data` binding against `text`, following the validator
/// procedure: apply the assertion's own exclusion ranges, normalize, recompute,
/// compare.
///
/// The ranges must match the located wrapper. An assertion that excludes some
/// other span would otherwise hash a document the wrapper does not describe.
pub fn verify_data_hash(
    text: &str,
    data_hash: &DataHash,
    hasher: &impl Hasher,
    normalizer: &impl Normalizer,
) -> Result<(), Error> {
    if data_hash.exclusions.is_empty() {
        return Err(Error::MalformedExclusion);
    }
    let alg = Algorithm::from_id(&data_hash.alg)?;
    let located = manifest_exclusion(text)?;
    if !data_hash.exclusions.contains(&located) {
        return Err(Error::MalformedExclusion);
    }
    let covered = hashed_bytes(text, &data_hash.exclusions, normalizer)?;
    if hasher.digest(alg, &covered) == data_hash.hash {
        Ok(())
    } else {
        Err(Error::HashMismatch)
    }
}

/// Ready-made implementations, behind the `hard-binding` feature — and always
/// present on `wasm32`, where the npm distribution needs them: a JavaScript
/// caller cannot implement the [`Hasher`] and [`Normalizer`] traits.
#[cfg(any(feature = "hard-binding", target_arch = "wasm32"))]
mod provided {
    use super::{Algorithm, Hasher, Normalizer};
    use sha2::{Digest, Sha256, Sha384, Sha512};
    // Imported for its methods only; binding the name would collide with the
    // `UnicodeNfc` type below.
    use unicode_normalization::UnicodeNormalization as _;

    /// [`Hasher`] backed by RustCrypto.
    #[derive(Debug, Default, Clone, Copy)]
    pub struct RustCrypto;

    impl Hasher for RustCrypto {
        fn digest(&self, alg: Algorithm, data: &[u8]) -> Vec<u8> {
            match alg {
                Algorithm::Sha256 => Sha256::digest(data).to_vec(),
                Algorithm::Sha384 => Sha384::digest(data).to_vec(),
                Algorithm::Sha512 => Sha512::digest(data).to_vec(),
            }
        }
    }

    /// [`Normalizer`] backed by `unicode-normalization`.
    #[derive(Debug, Default, Clone, Copy)]
    pub struct UnicodeNfc;

    impl Normalizer for UnicodeNfc {
        fn nfc(&self, text: &str) -> String {
            text.nfc().collect()
        }
    }
}

#[cfg(any(feature = "hard-binding", target_arch = "wasm32"))]
pub use provided::{RustCrypto, UnicodeNfc};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wrapper;

    const HOST: &str = "This sentence carries an invisible C2PA text manifest wrapper at its end.";
    const PAYLOAD: &[u8] = b"c2pa-manifest-01";

    /// A deterministic stand-in so the core is testable without the feature.
    struct SumHasher;
    impl Hasher for SumHasher {
        fn digest(&self, alg: Algorithm, data: &[u8]) -> Vec<u8> {
            let n: u64 = data.iter().map(|&b| b as u64).sum();
            let mut v = alg.id().as_bytes().to_vec();
            v.extend_from_slice(&n.to_be_bytes());
            v
        }
    }
    /// Identity normalizer: correct for the ASCII fixtures used here.
    struct AsciiNormalizer;
    impl Normalizer for AsciiNormalizer {
        fn nfc(&self, text: &str) -> String {
            text.to_string()
        }
    }

    #[test]
    fn exclusion_covers_the_marker_and_the_whole_run() {
        let asset = wrapper::embed(HOST, PAYLOAD).unwrap();
        let ex = manifest_exclusion(&asset).unwrap();
        assert_eq!(ex.start, HOST.len());
        assert_eq!(ex.start + ex.length, asset.len());
        assert!(asset[ex.start..].starts_with(wrapper::MARKER));
    }

    #[test]
    fn padding_is_inside_the_exclusion() {
        let padded = wrapper::encode_padded(PAYLOAD).unwrap();
        let asset = format!("{HOST}{padded}");
        let ex = manifest_exclusion(&asset).unwrap();
        assert_eq!(ex.length, padded.len());
        // Covered bytes are the visible text either way, padded or not.
        let covered = hashed_bytes(&asset, &[ex], &AsciiNormalizer).unwrap();
        assert_eq!(covered, HOST.as_bytes());
    }

    #[test]
    fn covered_bytes_are_the_visible_text() {
        let asset = wrapper::embed(HOST, PAYLOAD).unwrap();
        let ex = manifest_exclusion(&asset).unwrap();
        assert_eq!(
            hashed_bytes(&asset, &[ex], &AsciiNormalizer).unwrap(),
            HOST.as_bytes()
        );
    }

    #[test]
    fn compute_then_verify_round_trips() {
        let asset = wrapper::embed(HOST, PAYLOAD).unwrap();
        let dh =
            compute_data_hash(&asset, Algorithm::Sha256, &SumHasher, &AsciiNormalizer).unwrap();
        assert_eq!(dh.alg, "sha256");
        assert_eq!(dh.label(), "c2pa.hash.data");
        assert!(verify_data_hash(&asset, &dh, &SumHasher, &AsciiNormalizer).is_ok());
    }

    #[test]
    fn editing_the_visible_text_breaks_the_binding() {
        let asset = wrapper::embed(HOST, PAYLOAD).unwrap();
        let dh =
            compute_data_hash(&asset, Algorithm::Sha256, &SumHasher, &AsciiNormalizer).unwrap();
        let tampered = wrapper::embed(&HOST.replace("invisible", "visible!"), PAYLOAD).unwrap();
        assert_eq!(
            verify_data_hash(&tampered, &dh, &SumHasher, &AsciiNormalizer),
            Err(Error::MalformedExclusion)
        );
        // Same length, so the exclusion still matches and the hash is what fails.
        let same_len = wrapper::embed(&HOST.replace("invisible", "invisibIe"), PAYLOAD).unwrap();
        assert_eq!(
            verify_data_hash(&same_len, &dh, &SumHasher, &AsciiNormalizer),
            Err(Error::HashMismatch)
        );
    }

    #[test]
    fn an_exclusion_that_is_not_the_wrapper_is_rejected() {
        let asset = wrapper::embed(HOST, PAYLOAD).unwrap();
        let mut dh =
            compute_data_hash(&asset, Algorithm::Sha256, &SumHasher, &AsciiNormalizer).unwrap();
        dh.exclusions = vec![Exclusion {
            start: 0,
            length: 4,
        }];
        assert_eq!(
            verify_data_hash(&asset, &dh, &SumHasher, &AsciiNormalizer),
            Err(Error::MalformedExclusion)
        );
    }

    #[test]
    fn malformed_ranges_are_rejected() {
        let asset = wrapper::embed(HOST, PAYLOAD).unwrap();
        // Out of order / overlapping.
        let bad = [
            Exclusion {
                start: 10,
                length: 5,
            },
            Exclusion {
                start: 5,
                length: 5,
            },
        ];
        assert_eq!(
            apply_exclusions(&asset, &bad),
            Err(Error::MalformedExclusion)
        );
        // Past the end.
        assert_eq!(
            apply_exclusions(
                &asset,
                &[Exclusion {
                    start: 0,
                    length: asset.len() + 1
                }]
            ),
            Err(Error::MalformedExclusion)
        );
    }

    #[test]
    fn unsupported_algorithm_is_reported() {
        let asset = wrapper::embed(HOST, PAYLOAD).unwrap();
        let mut dh =
            compute_data_hash(&asset, Algorithm::Sha256, &SumHasher, &AsciiNormalizer).unwrap();
        dh.alg = "sha1".into();
        assert_eq!(
            verify_data_hash(&asset, &dh, &SumHasher, &AsciiNormalizer),
            Err(Error::UnsupportedAlgorithm("sha1".into()))
        );
    }

    #[test]
    fn json_shape_matches_the_data_hash_map() {
        let dh = DataHash {
            exclusions: vec![Exclusion {
                start: 73,
                length: 114,
            }],
            alg: "sha256".into(),
            hash: vec![0xDE, 0xAD, 0xBE, 0xEF],
            name: None,
        };
        assert_eq!(
            dh.to_json(),
            r#"{"exclusions":[{"start":73,"length":114}],"alg":"sha256","hash":"3q2+7w=="}"#
        );
    }

    #[test]
    fn base64_matches_rfc4648_vectors() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foob"), "Zm9vYg==");
        assert_eq!(base64(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
    }
}
