# c2pa-unstructured-text

_C2PA manifest embedding and hard binding for unstructured text using Unicode variation selectors._

<p align="center">
  <a href="https://crates.io/crates/c2pa-unstructured-text"><img src="https://img.shields.io/crates/v/c2pa-unstructured-text.svg" alt="crates.io"></a>
  <a href="https://docs.rs/c2pa-unstructured-text"><img src="https://docs.rs/c2pa-unstructured-text/badge.svg" alt="docs.rs"></a>
  <a href="https://github.com/writerslogic/c2pa-unstructured-text/actions/workflows/ci.yml"><img src="https://github.com/writerslogic/c2pa-unstructured-text/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://scorecard.dev/viewer/?uri=github.com/writerslogic/c2pa-unstructured-text"><img src="https://api.securityscorecards.dev/projects/github.com/writerslogic/c2pa-unstructured-text/badge" alt="OpenSSF Scorecard"></a>
  <a href="#license"><img src="https://img.shields.io/crates/l/c2pa-unstructured-text.svg" alt="License"></a>
</p>

## Overview

Implements the **Embedding Manifests into Unstructured Text** section of the [C2PA Technical Specification](https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html#_embedding_manifests_into_unstructured_text), which carries a C2PA Manifest Store inside a Unicode text stream as a run of non-rendering variation selectors, so provenance survives copy and paste between systems that have no file.

```
Hello world.<U+FEFF><variation-selector run carrying magic|version|length|manifest>
```

> [!IMPORTANT]
> The specification describes this method as one that **should only be used where no other embedding method is feasible**. For source code, configuration, and markup, prefer [`c2pa-structured-text`](https://crates.io/crates/c2pa-structured-text). This crate exists for the case the spec carves out: text with no container.

This crate owns two things:

1. **The frame** — encode, embed, locate, and strip the `C2PATextManifestWrapper`, including the specified deterministic padding.
2. **The hard binding** — the exact `c2pa.hash.data` coverage for unstructured text, with compute and verify.

Signature verification, certificate trust, and assertion validation are not reimplemented here.

> [!NOTE]
> Not certified or conformance-tested by the C2PA. It implements the embedding and hard binding as specified.

## Zero dependencies by default

```toml
[dependencies]
c2pa-unstructured-text = "0.2"
```

The same crate is published for JavaScript/WebAssembly and Python, built from this source:

```bash
npm install c2pa-unstructured-text   # wasm-bindgen build
pip install c2pa-unstructured-text   # PyO3 abi3 wheel, CPython 3.9+
```

The frame and the binding algorithm pull nothing in. Hashing and NFC are injected through two traits, so a host that already provides them supplies its own:

```rust
use c2pa_unstructured_text::hardbinding::{Algorithm, Hasher, Normalizer};

struct HostCrypto;
impl Hasher for HostCrypto {
    fn digest(&self, alg: Algorithm, data: &[u8]) -> Vec<u8> { todo!("call the runtime") }
}
struct HostNfc;
impl Normalizer for HostNfc {
    fn nfc(&self, text: &str) -> String { todo!("call the runtime") }
}
```

That matters at the edge. A Cloudflare Worker or a browser already has SHA-2 and `String.prototype.normalize`, so shipping Unicode tables into the bundle is pure waste. Enable `hard-binding` to get ready-made implementations instead; it adds convenience, never capability.

## Embed and extract

```rust
use c2pa_unstructured_text::wrapper;

let asset = wrapper::embed("Hello world.", b"manifest-bytes").unwrap();

let found = wrapper::extract(&asset).unwrap();
assert_eq!(found.payload, b"manifest-bytes");
assert_eq!(wrapper::strip(&asset, found.range()).unwrap(), "Hello world.");
```

## The hard binding

The exclusion range covers the `U+FEFF` marker together with the selector run, including any trailing padding. Offsets are into the text **as stored**, before normalization. A validator removes the excluded bytes first, normalizes what remains to NFC, then hashes.

```rust
# #[cfg(feature = "hard-binding")] {
use c2pa_unstructured_text::hardbinding::{
    compute_data_hash, verify_data_hash, Algorithm, RustCrypto, UnicodeNfc,
};
use c2pa_unstructured_text::wrapper;

let asset = wrapper::embed("Hello world.", b"manifest-bytes").unwrap();
let binding =
    compute_data_hash(&asset, Algorithm::Sha256, &RustCrypto, &UnicodeNfc).unwrap();

assert!(verify_data_hash(&asset, &binding, &RustCrypto, &UnicodeNfc).is_ok());
# }
```

Normalizing before computing offsets would shift every one of them whenever the stored text is not already NFC, which is why the order is fixed this way.

## Deterministic padding

The wrapper's byte length depends on the manifest's byte distribution, since low bytes encode to three UTF-8 bytes and the rest to four. That is circular when the exclusion length has to go inside the manifest being measured. The specification breaks the cycle with a target that depends only on the manifest size, and fixes the padding byte values so compliant generators emit byte-identical wrappers:

```rust
use c2pa_unstructured_text::wrapper;

assert_eq!(wrapper::target_length(16), 125);
assert_eq!(wrapper::encode(b"c2pa-manifest-01").unwrap().len(), 114);
// The 11-byte gap decomposes as one 0x00 then two 0x10.
assert_eq!(wrapper::padding(11).unwrap(), vec![0x00, 0x10, 0x10]);
assert_eq!(wrapper::encode_padded(b"c2pa-manifest-01").unwrap().len(), 125);
```

This is the part of the method implementations most easily diverge on, so it is covered by vectors cross-checked against the C2PA public test corpus.

## Locating

The specification defines two failure codes here, and the crate reports both:

| outcome | code | meaning |
|---|---|---|
| no wrapper, no candidate | *(none)* | the text is unsigned |
| candidate detected, none decodes | `manifest.text.corruptedWrapper` | magic found, frame malformed |
| more than one valid wrapper | `manifest.text.multipleWrappers` | rejected |

Only the first means the text carries no provenance, which is what
`is_no_manifest_located()` reports — an integrator needs to tell "carries no
provenance" from "carried provenance that was rejected":

```rust
use c2pa_unstructured_text::{wrapper, Error};

let err = wrapper::extract("no wrapper here").unwrap_err();
assert_eq!(err, Error::NotFound);
assert!(err.is_no_manifest_located());
assert_eq!(err.code(), None);
```

A candidate that fails to decode *beside* a valid wrapper is skipped, not
reported: letting stray bytes carrying the magic invalidate an otherwise good
wrapper would hand anyone who can append to the text a denial of service.

> [!WARNING]
> The specification is in tension here. Placement rule 5 says a validator "may
> encounter multiple wrappers" and that selection "is governed by the
> `exclusions` field", while the status-code section makes more than one valid
> wrapper a failure. This crate follows the explicit failure code.

## Comparison with the structured-text binding

Both crates expose the same shape, so a dispatcher can treat them alike, but coverage differs deliberately.

| | unstructured (this crate) | structured |
|---|---|---|
| carrier | variation selectors | ASCII armour comment |
| normalization | NFC, after exclusion | none |
| exclusion | marker + selector run + padding | the manifest block line |
| default deps | none | none |

## Features

- `hard-binding` — `RustCrypto` and `UnicodeNfc` implementations (pulls `sha2` and `unicode-normalization`).
- `checksum-v2` — a v2 frame carrying a truncated hash over the header and payload, so a mangled carrier is rejected rather than decoded to wrong bytes. A WritersLogic extension, not part of the specified frame.

No feature is enabled by default.

## Related Crates

Part of a family of single-purpose crates, one per C2PA embedding method. Each
is standalone and independently versioned.

| Crate | Description |
|---|---|
| [c2pa-structured-text](https://crates.io/crates/c2pa-structured-text) | Structured text: ASCII-armoured manifest in a comment or front matter |
| [c2pa-html](https://crates.io/crates/c2pa-html) | HTML: `script` and `link` elements in the document head |
| [c2pa-http](https://crates.io/crates/c2pa-http) | HTTP: the `c2pa-manifest` `Link` header, with a Tower middleware |
| [c2pa-text-binding](https://crates.io/crates/c2pa-text-binding) | Soft binding and content fingerprinting for text assets |
| [c2pa-vtt](https://crates.io/crates/c2pa-vtt) | WebVTT caption and subtitle embedding |
| [c2pa-zip](https://crates.io/crates/c2pa-zip) | ZIP-based documents: EPUB, DOCX, ODT, OXPS |
| [c2pa-warc](https://crates.io/crates/c2pa-warc) | WARC web archive embedding (ISO 28500) |
| [c2pa-fonts](https://crates.io/crates/c2pa-fonts) | OpenType/TrueType (SFNT) font embedding |
| [c2pa-ml](https://crates.io/crates/c2pa-ml) | ML model containers: GGUF, SafeTensors, ONNX |
| [c2pa](https://crates.io/crates/c2pa) | Official C2PA SDK |

## Security

Found a vulnerability? Please report it privately — see [SECURITY.md](./SECURITY.md).

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT License](LICENSE-MIT) at your option.

Built by [WritersLogic](https://writerslogic.com)
