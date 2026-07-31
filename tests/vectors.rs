// Copyright 2026 WritersLogic. All rights reserved.
// Licensed under the Apache License, Version 2.0 or the MIT license,
// at your option.

//! Cross-check against the A.8 vectors published to the C2PA public test file
//! corpus. These values are derived from the specification, so a change here is
//! either a deliberate spec update or a regression.

use c2pa_unstructured_text::{hardbinding, wrapper};

const HOST: &str = "This sentence carries an invisible C2PA text manifest wrapper at its end.";
const PAYLOAD: &[u8] = b"c2pa-manifest-01";

/// The unpadded wrapper for the 16-byte payload, as published.
const UNPADDED_HEX: &str = "efbbbff3a084b3f3a084a2f3a08580f3a084b1f3a08584f3a08588f3a08584efb880efb881efb880efb880efb880f3a08480f3a08593f3a084a2f3a085a0f3a08591f3a0849df3a0859df3a08591f3a0859ef3a08599f3a08596f3a08595f3a085a3f3a085a4f3a0849df3a084a0f3a084a1";

/// The same manifest padded to the deterministic target.
const PADDED_HEX: &str = "efbbbff3a084b3f3a084a2f3a08580f3a084b1f3a08584f3a08588f3a08584efb880efb881efb880efb880efb880f3a08480f3a08593f3a084a2f3a085a0f3a08591f3a0849df3a0859df3a08591f3a0859ef3a08599f3a08596f3a08595f3a085a3f3a085a4f3a0849df3a084a0f3a084a1efb880f3a08480f3a08480";

fn hex(s: &str) -> String {
    s.as_bytes().iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn unpadded_wrapper_matches_the_published_vector() {
    let encoded = wrapper::encode(PAYLOAD).unwrap();
    assert_eq!(hex(&encoded), UNPADDED_HEX);
    assert_eq!(encoded.len(), 114);
}

#[test]
fn padded_wrapper_matches_the_published_vector() {
    let encoded = wrapper::encode_padded(PAYLOAD).unwrap();
    assert_eq!(hex(&encoded), PADDED_HEX);
    assert_eq!(encoded.len(), 125);
    assert_eq!(encoded.len(), wrapper::target_length(PAYLOAD.len()));
}

#[test]
fn published_exclusion_range_is_reproduced() {
    let asset = wrapper::embed(HOST, PAYLOAD).unwrap();
    let ex = hardbinding::manifest_exclusion(&asset).unwrap();
    // The corpus records start 73, length 114 for this asset.
    assert_eq!(ex.start, 73);
    assert_eq!(ex.length, 114);
    assert_eq!(HOST.len(), 73);
    assert_eq!(asset.len(), 187);
}

#[test]
fn every_negative_case_reports_the_specified_outcome() {
    let good = wrapper::encode(PAYLOAD).unwrap();

    // Wrong magic: not a candidate at all.
    let bad_magic = {
        let mut v = b"C2PATXT\x01".to_vec();
        v.push(1);
        v.extend_from_slice(&16u32.to_be_bytes());
        v.extend_from_slice(PAYLOAD);
        raw(&v)
    };
    // Unsupported version, and a length exceeding the run.
    let bad_version = {
        let mut v = wrapper::MAGIC.to_vec();
        v.push(2);
        v.extend_from_slice(&16u32.to_be_bytes());
        v.extend_from_slice(PAYLOAD);
        raw(&v)
    };
    let bad_length = {
        let mut v = wrapper::MAGIC.to_vec();
        v.push(1);
        v.extend_from_slice(&24u32.to_be_bytes());
        v.extend_from_slice(PAYLOAD);
        raw(&v)
    };

    // Only text carrying no wrapper at all is unsigned. A frame whose magic
    // matched, and text carrying two valid wrappers, are reportable failures.
    for (name, asset, expected) in [
        ("bad-magic", format!("{HOST}{bad_magic}"), None),
        ("no-wrapper", HOST.to_string(), None),
        (
            "bad-version",
            format!("{HOST}{bad_version}"),
            Some("manifest.text.corruptedWrapper"),
        ),
        (
            "bad-length",
            format!("{HOST}{bad_length}"),
            Some("manifest.text.corruptedWrapper"),
        ),
        (
            "two-wrappers",
            format!("{HOST}{good}{good}"),
            Some("manifest.text.multipleWrappers"),
        ),
    ] {
        let err = wrapper::extract(&asset).unwrap_err();
        assert_eq!(
            err.code(),
            expected,
            "{name}: wrong status code for {err:?}"
        );
        assert_eq!(
            err.is_no_manifest_located(),
            expected.is_none(),
            "{name}: {err:?} misclassified as unsigned"
        );
    }
}

/// Build a marker-prefixed selector run over arbitrary framed bytes, so the
/// negative fixtures can carry frames the encoder would refuse to produce.
fn raw(framed: &[u8]) -> String {
    let mut s = String::from(wrapper::MARKER);
    s.extend(
        framed
            .iter()
            .map(|&b| c2pa_unstructured_text::vs::byte_to_vs(b)),
    );
    s
}

#[cfg(feature = "hard-binding")]
mod bound {
    use super::*;
    use hardbinding::{compute_data_hash, verify_data_hash, Algorithm, RustCrypto, UnicodeNfc};

    #[test]
    fn binding_covers_the_visible_text_only() {
        let asset = wrapper::embed(HOST, PAYLOAD).unwrap();
        let ex = hardbinding::manifest_exclusion(&asset).unwrap();
        let covered = hardbinding::hashed_bytes(&asset, &[ex], &UnicodeNfc).unwrap();
        assert_eq!(covered, HOST.as_bytes());
    }

    #[test]
    fn padding_does_not_change_the_covered_bytes() {
        let plain = wrapper::embed(HOST, PAYLOAD).unwrap();
        let padded = format!("{HOST}{}", wrapper::encode_padded(PAYLOAD).unwrap());
        let a = compute_data_hash(&plain, Algorithm::Sha256, &RustCrypto, &UnicodeNfc).unwrap();
        let b = compute_data_hash(&padded, Algorithm::Sha256, &RustCrypto, &UnicodeNfc).unwrap();
        assert_eq!(
            a.hash, b.hash,
            "the hash covers the visible text either way"
        );
        assert_ne!(a.exclusions, b.exclusions, "but the ranges differ");
    }

    #[test]
    fn nfd_input_still_verifies_because_normalization_follows_exclusion() {
        // "cafe" + combining acute, i.e. NFD.
        let nfd = "caf\u{0065}\u{0301} ";
        let asset = wrapper::embed(nfd, PAYLOAD).unwrap();
        let binding =
            compute_data_hash(&asset, Algorithm::Sha256, &RustCrypto, &UnicodeNfc).unwrap();
        // Offsets are into the stored text, so they address the NFD bytes.
        assert_eq!(binding.exclusions[0].start, nfd.len());
        assert!(verify_data_hash(&asset, &binding, &RustCrypto, &UnicodeNfc).is_ok());
        // The covered bytes are the NFC form, shorter than what was stored.
        let covered = hardbinding::hashed_bytes(&asset, &binding.exclusions, &UnicodeNfc).unwrap();
        assert!(covered.len() < nfd.len());
    }

    #[test]
    fn sha384_and_sha512_round_trip() {
        let asset = wrapper::embed(HOST, PAYLOAD).unwrap();
        for alg in [Algorithm::Sha384, Algorithm::Sha512] {
            let b = compute_data_hash(&asset, alg, &RustCrypto, &UnicodeNfc).unwrap();
            assert_eq!(b.alg, alg.id());
            assert!(verify_data_hash(&asset, &b, &RustCrypto, &UnicodeNfc).is_ok());
        }
    }
}
