# Contributing to c2pa-unstructured-text

Thank you for your interest in contributing. This document covers how to report issues, set up a development environment, and submit changes.

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). By participating, you are expected to uphold it.

## How to Contribute

### Reporting Issues

- Use the issue templates for bugs and feature requests.
- Do not report security vulnerabilities in public issues -- see [SECURITY.md](SECURITY.md).

### Development Setup

Prerequisites: Rust (stable, 1.75+).

```bash
git clone https://github.com/writerslogic/c2pa-unstructured-text.git
cd c2pa-unstructured-text
cargo build
cargo test
```

### Submitting Changes

1. Fork the repository and create a branch from `main`.
2. Make changes, add tests, run `cargo test --all-features`.
3. Run `cargo clippy --all-features -- -D warnings` and fix warnings.
4. Run `cargo fmt --all -- --check`.
5. Open a pull request with a clear description.

### Commit Style

Use Conventional Commits: `fix:`, `feat:`, `docs:`, `refactor:`, `test:`, `chore:`. Single-line, imperative, no trailing period.
