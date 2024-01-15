# JSON Web Token performance tests – Rust

This project contains a trivial create/verify benchmarks for JWTs using the `jsonwebtoken` crate and several popular
signing algorithms:

- `RS256`
- `EdDSA`
- `HS256`

Note that `HS256` uses a symmetric block cipher and has very different security tradeoffs than the other two options.
