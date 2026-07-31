// Copyright 2026 WritersLogic. All rights reserved.
// Licensed under the Apache License, Version 2.0 or the MIT license,
// at your option.

use std::fmt;

/// Errors from locating a wrapper or validating an unstructured-text hard
/// binding.
///
/// # Two wrapper outcomes are reportable failures
///
/// The specification defines two failure codes for wrapper location:
///
/// - `manifest.text.corruptedWrapper` — a magic number was detected but the
///   wrapper was malformed or incomplete. A candidate that does not decode is
///   *not* silently ignored; it is reported.
/// - `manifest.text.multipleWrappers` — more than one *valid* wrapper was found.
///
/// Only [`Error::NotFound`] means the text carries no provenance at all, and
/// only it carries no status code. [`Error::is_no_manifest_located`] draws that
/// line for a caller surfacing provenance state to a user: "unsigned" versus
/// "carried provenance that was rejected".
///
/// # A known tension in the specification
///
/// Placement rule 5 says a validator "may encounter multiple wrappers" and that
/// "selection of the intended wrapper is governed by the `exclusions` field of
/// the `c2pa.hash.data` assertion", which reads as though multiple wrappers are
/// recoverable. The Validation Status Codes section says more than one valid
/// wrapper is a `manifest.text.multipleWrappers` failure. These cannot both be
/// followed.
///
/// This crate follows the explicit failure code, because that is the normative
/// statement a validator is judged against, and because text that accreted a
/// second wrapper has also changed the bytes the hard binding covers — so the
/// "recoverable" reading would let a hash pass over text the claim never
/// described.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// No valid `C2PATextManifestWrapper` was located and no candidate was
    /// detected either: the text simply carries no wrapper.
    NotFound,
    /// One or more candidates were detected (a `U+FEFF` followed by a
    /// variation-selector run whose leading bytes match the magic) but none
    /// fully decoded.
    ///
    /// Reported as `manifest.text.corruptedWrapper`: the magic number was
    /// detected but the wrapper was malformed or incomplete. This is also the
    /// *fail-safe* outcome — the codec rejected a mangled carrier rather than
    /// decoding it to wrong bytes.
    CorruptedWrapper,
    /// More than one valid wrapper was located.
    ///
    /// Reported as `manifest.text.multipleWrappers`. Not a disambiguation
    /// opportunity: text that accreted a second wrapper has also changed the
    /// bytes covered by the hard binding.
    MultipleWrappers,
    /// The payload exceeds the `u32` `manifestLength` field of the wrapper frame.
    PayloadTooLarge(usize),
    /// A padding gap that is not expressible as `3a + 4b`, i.e. 1, 2 or 5. The
    /// margin of 6 in the deterministic target keeps real wrappers clear of
    /// these, so this indicates a hand-built target length.
    UnrepresentableGap(usize),
    /// The exclusion ranges are malformed: out of order, overlapping, extending
    /// past the end of the asset, splitting a UTF-8 sequence, or not matching
    /// the byte range of the located wrapper.
    MalformedExclusion,
    /// The recomputed data hash did not match the value in the assertion.
    HashMismatch,
    /// A hash algorithm identifier outside the C2PA allowed list was requested.
    UnsupportedAlgorithm(String),
}

impl Error {
    /// The registered C2PA validation status code for this error, or `None` when
    /// the condition carries no status code.
    pub fn code(&self) -> Option<&'static str> {
        Some(match self {
            Self::CorruptedWrapper => "manifest.text.corruptedWrapper",
            Self::MultipleWrappers => "manifest.text.multipleWrappers",
            // Carrying no wrapper at all is an unsigned asset, not a failure.
            Self::NotFound => return None,
            // Embed-time input errors, not validation outcomes.
            Self::PayloadTooLarge(_) | Self::UnrepresentableGap(_) => return None,
            Self::MalformedExclusion => "assertion.dataHash.malformed",
            Self::HashMismatch => "assertion.dataHash.mismatch",
            Self::UnsupportedAlgorithm(_) => "algorithm.unsupported",
        })
    }

    /// Whether this error means the asset carries no provenance at all, as
    /// opposed to provenance that was found and rejected. Callers that surface
    /// provenance state to a user need this distinction: the former is
    /// "unsigned", the latter is "invalid".
    ///
    /// Only [`Error::NotFound`] qualifies. A corrupted or duplicated wrapper is
    /// a reportable failure, not an absence.
    pub fn is_no_manifest_located(&self) -> bool {
        matches!(self, Self::NotFound)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => write!(f, "no C2PA text manifest wrapper found"),
            Self::CorruptedWrapper => {
                write!(f, "wrapper candidate detected but it did not fully decode")
            }
            Self::MultipleWrappers => write!(f, "more than one valid wrapper found"),
            Self::PayloadTooLarge(n) => {
                write!(
                    f,
                    "payload of {n} bytes exceeds the u32 manifestLength field"
                )
            }
            Self::UnrepresentableGap(n) => {
                write!(
                    f,
                    "a padding gap of {n} bytes is not expressible as 3a + 4b"
                )
            }
            Self::MalformedExclusion => write!(f, "data hash exclusion range is malformed"),
            Self::HashMismatch => write!(f, "data hash does not match the asset content"),
            Self::UnsupportedAlgorithm(a) => write!(f, "unsupported hash algorithm: {a}"),
        }
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;

    fn all() -> Vec<Error> {
        vec![
            Error::NotFound,
            Error::CorruptedWrapper,
            Error::MultipleWrappers,
            Error::PayloadTooLarge(1 << 33),
            Error::UnrepresentableGap(5),
            Error::MalformedExclusion,
            Error::HashMismatch,
            Error::UnsupportedAlgorithm("sha1".into()),
        ]
    }

    #[test]
    fn display_composes_into_a_sentence_for_every_variant() {
        for e in all() {
            let s = e.to_string();
            assert!(!s.is_empty(), "{e:?} rendered empty");
            // Messages are embedded in larger sentences, so they must not start
            // with a capital or end with a period.
            assert!(!s.ends_with('.'), "{e:?} ends with a period: {s}");
            let first = s.chars().next().expect("checked non-empty above");
            assert!(!first.is_uppercase(), "{e:?} starts uppercase: {s}");
        }
    }

    #[test]
    fn display_carries_the_offending_value() {
        assert!(Error::UnsupportedAlgorithm("sha1".into())
            .to_string()
            .contains("sha1"));
        assert!(Error::PayloadTooLarge(4294967296)
            .to_string()
            .contains("4294967296"));
    }

    #[test]
    fn the_two_wrapper_failure_codes_are_emitted() {
        // Both are registered in the specification's validation-codes registry,
        // so a validator built on this crate must be able to report them.
        assert_eq!(
            Error::CorruptedWrapper.code(),
            Some("manifest.text.corruptedWrapper")
        );
        assert_eq!(
            Error::MultipleWrappers.code(),
            Some("manifest.text.multipleWrappers")
        );
    }

    #[test]
    fn every_code_is_a_registered_identifier() {
        for e in all() {
            if let Some(code) = e.code() {
                assert!(
                    matches!(
                        code,
                        "manifest.text.corruptedWrapper"
                            | "manifest.text.multipleWrappers"
                            | "assertion.dataHash.malformed"
                            | "assertion.dataHash.mismatch"
                            | "algorithm.unsupported"
                    ),
                    "{e:?} reports an unregistered code: {code}"
                );
            }
        }
    }

    #[test]
    fn only_an_absent_wrapper_means_unsigned() {
        assert_eq!(Error::NotFound.code(), None);
        assert!(Error::NotFound.is_no_manifest_located());

        // A corrupted or duplicated wrapper is provenance that was found and
        // rejected, so reporting it as "unsigned" would understate the problem.
        for e in [Error::CorruptedWrapper, Error::MultipleWrappers] {
            assert!(
                !e.is_no_manifest_located(),
                "{e:?} must not classify as unsigned"
            );
            assert!(e.code().is_some(), "{e:?} should report a code");
        }
    }

    #[test]
    fn binding_failures_are_not_no_manifest_located() {
        // A located manifest that fails its binding is "invalid", never "unsigned".
        for e in [
            Error::MalformedExclusion,
            Error::HashMismatch,
            Error::UnsupportedAlgorithm("sha1".into()),
        ] {
            assert!(!e.is_no_manifest_located(), "{e:?} misclassified");
            assert!(e.code().is_some(), "{e:?} should report a code");
        }
    }
}
