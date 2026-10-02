# Fuzzing

Install `cargo-fuzz`, then run:

```sh
cargo fuzz run parse_untrusted
```

Targets must remain deterministic and bound the input they hand to the parser.
