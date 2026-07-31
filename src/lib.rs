// Copyright 2026 WritersLogic. All rights reserved.
// Licensed under the Apache License, Version 2.0 or the MIT license,
// at your option.

//! C2PA manifest embedding and hard binding for unstructured text.
//!
//! Implements the *Embedding Manifests into Unstructured Text* section of the
//! C2PA Technical Specification, which carries a C2PA Manifest Store inside a
//! Unicode text stream as a run of non-rendering variation selectors, so that
//! provenance survives copy and paste between systems that have no file.
//!
//! The specification describes this method as one that *should only be used
//! where no other embedding method is feasible*. For source code, configuration,
//! and markup, prefer the structured-text method in
//! [`c2pa-structured-text`](https://crates.io/crates/c2pa-structured-text); for
//! HTML, prefer the dedicated HTML method.
//!
//! # Scope
//!
//! - **Frame** ([`wrapper`]): encode, embed, locate, and strip the
//!   `C2PATextManifestWrapper`, plus the specified deterministic padding.
//! - **Hard binding** ([`hardbinding`]): the exact `c2pa.hash.data` coverage,
//!   with compute and verify.
//!
//! Signature verification, certificate trust, and assertion validation are not
//! implemented here.
//!
//! # Zero dependencies by default
//!
//! The frame and the binding algorithm pull nothing in. Hashing and NFC are
//! injected through [`hardbinding::Hasher`] and [`hardbinding::Normalizer`], so
//! a host that already provides them (a Cloudflare Worker, a browser) supplies
//! its own. Enabling `hard-binding` adds ready-made implementations; it adds
//! convenience, never capability.
//!
//! # Examples
//!
//! Embed a Manifest Store and recover it:
//!
//! ```
//! use c2pa_unstructured_text::wrapper;
//!
//! let asset = wrapper::embed("Hello world.", b"manifest-bytes").unwrap();
//! assert_eq!(wrapper::extract(&asset).unwrap().payload, b"manifest-bytes");
//! ```
//!
//! The wrapper is invisible, so the visible text is unchanged:
//!
//! ```
//! use c2pa_unstructured_text::wrapper;
//!
//! let asset = wrapper::embed("Hello world.", b"m").unwrap();
//! let w = wrapper::extract(&asset).unwrap();
//! assert_eq!(wrapper::strip(&asset, w.range()).unwrap(), "Hello world.");
//! ```
//!
//! Bind the visible text:
//!
//! ```
//! # #[cfg(feature = "hard-binding")] {
//! use c2pa_unstructured_text::hardbinding::{
//!     compute_data_hash, verify_data_hash, Algorithm, RustCrypto, UnicodeNfc,
//! };
//! use c2pa_unstructured_text::wrapper;
//!
//! let asset = wrapper::embed("Hello world.", b"manifest-bytes").unwrap();
//! let binding =
//!     compute_data_hash(&asset, Algorithm::Sha256, &RustCrypto, &UnicodeNfc).unwrap();
//!
//! assert!(verify_data_hash(&asset, &binding, &RustCrypto, &UnicodeNfc).is_ok());
//! # }
//! ```
//!
//! # Relationship to the structured-text binding
//!
//! Both crates expose the same shape, so a dispatcher can treat them alike, but
//! the coverage rules differ deliberately. A.9 hashes the raw file bytes with no
//! normalization, because structured text is byte-stable on disk. A.8 removes
//! the wrapper and then normalizes to NFC, because the text is clipboard
//! portable and may arrive in any normalization form. Offsets are into the text
//! as stored in both cases.
//!
//! # Features
//!
//! - `hard-binding` — [`hardbinding::RustCrypto`] and
//!   [`hardbinding::UnicodeNfc`] (pulls `sha2` and
//!   `unicode-normalization`).
//! - `checksum-v2` — a v2 frame carrying a truncated hash over the header and
//!   payload, so a mangled carrier is rejected rather than decoded to wrong
//!   bytes. A WritersLogic extension, not part of the specified frame.
//!
//! No feature is enabled by default.

#![forbid(unsafe_code)]

pub mod error;
pub mod hardbinding;
pub mod vs;
pub mod wrapper;

#[cfg(feature = "python")]
mod python;

pub use error::Error;
pub use hardbinding::{Algorithm, DataHash, Exclusion, Hasher, Normalizer};
pub use wrapper::{Wrapper, MAGIC, MARKER, VERSION};
