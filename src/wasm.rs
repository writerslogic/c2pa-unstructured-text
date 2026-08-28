//! WebAssembly bindings, built only for the `wasm32` target and published to
//! npm as `c2pa-unstructured-text`.
//!
//! Text maps to and from JavaScript strings and payloads to `Uint8Array`. Text
//! carrying no wrapper returns `null` from [`extract`](fn.extract.html) rather
//! than throwing; a corrupted or duplicated wrapper *is* a reportable failure
//! and throws with its C2PA status code.
//!
//! The wasm build enables `hard-binding`, since a JavaScript caller cannot
//! implement the Rust `Hasher`/`Normalizer` traits.

use wasm_bindgen::prelude::*;

use crate::hardbinding::{self, Algorithm, DataHash, Exclusion, RustCrypto, UnicodeNfc};

fn js_err(e: crate::Error) -> JsError {
    match e.code() {
        Some(code) => JsError::new(&format!("{e} [{code}]")),
        None => JsError::new(&e.to_string()),
    }
}

fn algorithm(alg: &str) -> Result<Algorithm, JsError> {
    Algorithm::from_id(alg).map_err(js_err)
}

/// Embed a Manifest Store into `text` as an invisible variation-selector run.
#[wasm_bindgen(js_name = embed)]
pub fn embed(text: &str, payload: &[u8]) -> Result<String, JsError> {
    crate::wrapper::embed(text, payload).map_err(js_err)
}

/// Encode a wrapper on its own, without a host text.
#[wasm_bindgen(js_name = encode)]
pub fn encode(payload: &[u8]) -> Result<String, JsError> {
    crate::wrapper::encode(payload).map_err(js_err)
}

/// Encode a wrapper padded to the deterministic target length, so two
/// generators produce byte-identical output for the same manifest.
#[wasm_bindgen(js_name = encodePadded)]
pub fn encode_padded(payload: &[u8]) -> Result<String, JsError> {
    crate::wrapper::encode_padded(payload).map_err(js_err)
}

/// The deterministic wrapper length for a manifest of `manifestLen` bytes.
#[wasm_bindgen(js_name = targetLength)]
pub fn target_length(manifest_len: usize) -> usize {
    crate::wrapper::target_length(manifest_len)
}

/// The single valid wrapper in `text`, or `null` when it carries none.
///
/// Returns an object with `payload`, `version`, `start`, and `length`.
#[wasm_bindgen(js_name = extract)]
pub fn extract(text: &str) -> Result<JsValue, JsError> {
    let w = match crate::wrapper::extract(text) {
        Ok(w) => w,
        Err(crate::Error::NotFound) => return Ok(JsValue::NULL),
        Err(e) => return Err(js_err(e)),
    };
    let out = js_sys::Object::new();
    let _ = js_sys::Reflect::set(
        &out,
        &"payload".into(),
        &js_sys::Uint8Array::from(&w.payload[..]).into(),
    );
    let _ = js_sys::Reflect::set(&out, &"version".into(), &w.version.into());
    let _ = js_sys::Reflect::set(&out, &"start".into(), &(w.start as u32).into());
    let _ = js_sys::Reflect::set(&out, &"length".into(), &(w.length as u32).into());
    Ok(out.into())
}

/// Remove the wrapper occupying `[start, start + length)`, leaving the visible
/// text.
#[wasm_bindgen(js_name = strip)]
pub fn strip(text: &str, start: usize, length: usize) -> Result<String, JsError> {
    crate::wrapper::strip(text, start..start + length).map_err(js_err)
}

/// Compute the `c2pa.hash.data` binding. The wrapper bytes are removed first
/// and the remainder normalized to NFC, in that order: offsets are into the
/// text as stored, so normalizing first would shift every one of them.
///
/// Returns `{ alg, hash, exclusions }`.
#[wasm_bindgen(js_name = computeDataHash)]
pub fn compute_data_hash(text: &str, alg: &str) -> Result<JsValue, JsError> {
    let dh = hardbinding::compute_data_hash(text, algorithm(alg)?, &RustCrypto, &UnicodeNfc)
        .map_err(js_err)?;
    let out = js_sys::Object::new();
    let _ = js_sys::Reflect::set(&out, &"alg".into(), &dh.alg.as_str().into());
    let _ = js_sys::Reflect::set(
        &out,
        &"hash".into(),
        &js_sys::Uint8Array::from(&dh.hash[..]).into(),
    );
    let ranges = js_sys::Array::new();
    for e in &dh.exclusions {
        let r = js_sys::Object::new();
        let _ = js_sys::Reflect::set(&r, &"start".into(), &(e.start as u32).into());
        let _ = js_sys::Reflect::set(&r, &"length".into(), &(e.length as u32).into());
        ranges.push(&r);
    }
    let _ = js_sys::Reflect::set(&out, &"exclusions".into(), &ranges);
    Ok(out.into())
}

/// Verify a `c2pa.hash.data` binding. Throws on mismatch; returns nothing on
/// success.
#[wasm_bindgen(js_name = verifyDataHash)]
pub fn verify_data_hash(
    text: &str,
    hash: &[u8],
    exclusion_starts: Vec<u32>,
    exclusion_lengths: Vec<u32>,
    alg: &str,
) -> Result<(), JsError> {
    if exclusion_starts.len() != exclusion_lengths.len() {
        return Err(JsError::new(
            "exclusion_starts and exclusion_lengths must be the same length",
        ));
    }
    let dh = DataHash {
        exclusions: exclusion_starts
            .iter()
            .zip(&exclusion_lengths)
            .map(|(&start, &length)| Exclusion {
                start: start as usize,
                length: length as usize,
            })
            .collect(),
        alg: algorithm(alg)?.id().to_string(),
        hash: hash.to_vec(),
        pad: Vec::new(),
        name: None,
    };
    hardbinding::verify_data_hash(text, &dh, &RustCrypto, &UnicodeNfc).map_err(js_err)
}
