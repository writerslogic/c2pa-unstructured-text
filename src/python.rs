//! Python bindings, built with [maturin]/[PyO3] behind the `python` feature and
//! published to PyPI as `c2pa-unstructured-text`.
//!
//! Text maps to and from Python `str` and payloads to `bytes`, matching the
//! Rust API: A.8 carries the wrapper inside a Unicode text stream, so the
//! natural unit is text rather than bytes.
//!
//! Text that simply carries no wrapper returns `None` from
//! [`extract`](fn.extract.html) rather than raising, because absence of
//! provenance is not an error. A corrupted or duplicated wrapper *is* a
//! reportable failure and raises `ValueError` carrying its C2PA status code.
//!
//! The `python` feature implies `hard-binding`, since a Python caller cannot
//! implement the Rust `Hasher`/`Normalizer` traits; the bundled SHA-2 and NFC
//! implementations are used.
//!
//! [maturin]: https://www.maturin.rs/
//! [PyO3]: https://pyo3.rs/

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};

use crate::hardbinding::{self, Algorithm, DataHash, Exclusion, RustCrypto, UnicodeNfc};

/// Map a crate error to `ValueError`, naming the C2PA status code when the
/// specification defines one so a caller can branch on it.
fn map_err(e: crate::Error) -> PyErr {
    match e.code() {
        Some(code) => PyValueError::new_err(format!("{e} [{code}]")),
        None => PyValueError::new_err(e.to_string()),
    }
}

fn algorithm(alg: &str) -> PyResult<Algorithm> {
    Algorithm::from_id(alg).map_err(map_err)
}

/// Embed a Manifest Store into `text` as an invisible variation-selector run.
#[pyfunction]
fn embed(text: &str, payload: &[u8]) -> PyResult<String> {
    crate::wrapper::embed(text, payload).map_err(map_err)
}

/// Encode a wrapper on its own, without a host text.
#[pyfunction]
fn encode(payload: &[u8]) -> PyResult<String> {
    crate::wrapper::encode(payload).map_err(map_err)
}

/// Encode a wrapper padded to the deterministic target length, so two
/// generators produce byte-identical output for the same manifest.
#[pyfunction]
fn encode_padded(payload: &[u8]) -> PyResult<String> {
    crate::wrapper::encode_padded(payload).map_err(map_err)
}

/// The deterministic wrapper length for a manifest of `manifest_len` bytes.
#[pyfunction]
fn target_length(manifest_len: usize) -> usize {
    crate::wrapper::target_length(manifest_len)
}

/// The single valid wrapper in `text`, or `None` when it carries none.
///
/// Returns a dict with `payload` (bytes), `version`, `start`, and `length`.
#[pyfunction]
fn extract<'py>(py: Python<'py>, text: &str) -> PyResult<Option<Bound<'py, PyDict>>> {
    let w = match crate::wrapper::extract(text) {
        Ok(w) => w,
        // No wrapper at all is unsigned text, not a failure. A corrupted or
        // duplicated wrapper is a failure and propagates.
        Err(crate::Error::NotFound) => return Ok(None),
        Err(e) => return Err(map_err(e)),
    };
    let out = PyDict::new(py);
    out.set_item("payload", PyBytes::new(py, &w.payload))?;
    out.set_item("version", w.version)?;
    out.set_item("start", w.start)?;
    out.set_item("length", w.length)?;
    Ok(Some(out))
}

/// The `(start, length)` byte ranges of every valid wrapper in `text`.
#[pyfunction]
fn locate_all(text: &str) -> Vec<(usize, usize)> {
    crate::wrapper::locate_all(text)
        .into_iter()
        .map(|w| (w.start, w.length))
        .collect()
}

/// Remove the wrapper occupying `[start, start + length)`, leaving the visible
/// text.
#[pyfunction]
fn strip(text: &str, start: usize, length: usize) -> PyResult<String> {
    crate::wrapper::strip(text, start..start + length).map_err(map_err)
}

/// Compute the `c2pa.hash.data` binding for text that already carries a wrapper.
///
/// `alg` is one of `sha256`, `sha384`, `sha512`. Returns a dict with `alg`,
/// `hash` (bytes), and `exclusions` (a list of `(start, length)`).
///
/// The wrapper bytes are removed first and the remainder normalized to NFC, in
/// that order: offsets are into the text as stored, so normalizing first would
/// shift every one of them.
#[pyfunction]
#[pyo3(signature = (text, alg = "sha256"))]
fn compute_data_hash<'py>(py: Python<'py>, text: &str, alg: &str) -> PyResult<Bound<'py, PyDict>> {
    let dh = hardbinding::compute_data_hash(text, algorithm(alg)?, &RustCrypto, &UnicodeNfc)
        .map_err(map_err)?;
    let out = PyDict::new(py);
    out.set_item("alg", dh.alg.as_str())?;
    out.set_item("hash", PyBytes::new(py, &dh.hash))?;
    out.set_item(
        "exclusions",
        dh.exclusions
            .iter()
            .map(|e| (e.start, e.length))
            .collect::<Vec<_>>(),
    )?;
    Ok(out)
}

/// Verify a `c2pa.hash.data` binding against `text`.
///
/// Raises `ValueError` carrying the status code on mismatch or a malformed
/// exclusion; returns `None` on success.
#[pyfunction]
#[pyo3(signature = (text, hash, exclusions, alg = "sha256"))]
fn verify_data_hash(
    text: &str,
    hash: &[u8],
    exclusions: Vec<(usize, usize)>,
    alg: &str,
) -> PyResult<()> {
    let dh = DataHash {
        exclusions: exclusions
            .into_iter()
            .map(|(start, length)| Exclusion { start, length })
            .collect(),
        alg: algorithm(alg)?.id().to_string(),
        hash: hash.to_vec(),
        name: None,
    };
    hardbinding::verify_data_hash(text, &dh, &RustCrypto, &UnicodeNfc).map_err(map_err)
}

#[pymodule]
fn c2pa_unstructured_text(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(embed, m)?)?;
    m.add_function(wrap_pyfunction!(encode, m)?)?;
    m.add_function(wrap_pyfunction!(encode_padded, m)?)?;
    m.add_function(wrap_pyfunction!(target_length, m)?)?;
    m.add_function(wrap_pyfunction!(extract, m)?)?;
    m.add_function(wrap_pyfunction!(locate_all, m)?)?;
    m.add_function(wrap_pyfunction!(strip, m)?)?;
    m.add_function(wrap_pyfunction!(compute_data_hash, m)?)?;
    m.add_function(wrap_pyfunction!(verify_data_hash, m)?)?;
    m.add("MARKER", crate::wrapper::MARKER.to_string())?;
    m.add("VERSION", crate::wrapper::VERSION)?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
