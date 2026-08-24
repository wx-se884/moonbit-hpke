# moonbit-hpke

Pure MoonBit implementations of RFC 9180 HPKE and the JOSE security standards: JWK, JWS, JWE, and JWT.

## Project positioning

`moonbit-hpke` provides package-level cryptographic building blocks for MoonBit applications without external C or FFI dependencies. The packages are independently importable under `wx-se884/hpke/src/*`.

## Core capabilities

- HPKE KEMs: X25519 and P-256; KDFs: HKDF-SHA256/384/512; AEADs: AES-GCM, ChaCha20-Poly1305, and Export-Only.
- HPKE Base, Auth, PSK, and AuthPSK modes with deterministic fixtures, contexts, sequence ratcheting, and exporters.
- JOSE JWK/JWKS, JWS, JWE, and JWT APIs with validation and replay-cache support.
- Pure MoonBit core utilities, BigNat arithmetic, SHA-2, HMAC, HKDF, symmetric ciphers, elliptic-curve primitives, and RSA support.

## Quick start

```bash
moon --version
moon fmt --check
moon check --deny-warn
moon test --target native --deny-warn --no-parallelize
moon run cmd/hpke-cli
```

## CLI

`moon run cmd/hpke-cli` runs a reproducible HPKE/JWK/JWS/JWE/JWT demonstration with fixed fixture keys. It is not a production key generator.

## Architecture

```text
cmd/hpke-cli/  src/core/  src/crypto/  src/hpke/
src/jwk/       src/jws/   src/jwe/     src/jwt/
```

## Benchmarks

Run the checked-in MoonBit `@bench.T` suites with:

```bash
moon bench --package src/crypto --target native --release --deny-warn --no-parallelize
moon bench --package src/hpke --target native --release --deny-warn --no-parallelize
```

The measured reference table and protocol are in [`docs/benchmarks.md`](docs/benchmarks.md).

## Testing and CI

Boundary tests cover empty/short inputs, malformed encodings, tampering, wrong keys and metadata, context sequence progression, exporters, JOSE serialization, JWT claim validation, and replay identifiers. GitHub Actions validates formatting, warnings, interfaces, coverage-enabled tests, supported backends, the CLI, and executable source statistics.

## License

Apache License 2.0. See [`LICENSE`](LICENSE).
