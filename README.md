# moonbit-hpke

[![MoonBit](https://img.shields.io/badge/Language-MoonBit-purple.svg)](https://www.moonbitlang.com/)
[![CI](https://github.com/wx-se884/moonbit-hpke/actions/workflows/ci.yml/badge.svg)](https://github.com/wx-se884/moonbit-hpke/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

Pure MoonBit implementations of RFC 9180 Hybrid Public Key Encryption (HPKE) and the JOSE security standards: JWK, JWS, JWE, and JWT.

## Project positioning

`moonbit-hpke` is a dependency-light security building block for MoonBit applications that need interoperable encryption, signing, key representation, or token validation. The implementation is written in MoonBit and does not require external C libraries or FFI bindings.

The repository is organized as independent packages:

- `wx-se884/hpke/src/core` — byte utilities, Base64URL, Hex, PKCS#7, constant-time comparison, and `BigNat`.
- `wx-se884/hpke/src/crypto` — SHA-2, HMAC, HKDF, AES/AES-GCM, AES-KW, ChaCha20-Poly1305, X25519, Ed25519, P-256, and RSA primitives.
- `wx-se884/hpke/src/hpke` — RFC 9180 suites, Base/Auth/PSK/AuthPSK modes, contexts, sequence ratcheting, and exporters.
- `wx-se884/hpke/src/jwk` — JWK/JWKS values and RFC 7638 SHA-256 thumbprints.
- `wx-se884/hpke/src/jws` — compact JWS signing and verification.
- `wx-se884/hpke/src/jwe` — compact JWE encryption/decryption with AES-KW, direct AES-GCM, and HPKE integration.
- `wx-se884/hpke/src/jwt` — JWT claims validation and replay-cache support.

The deterministic key inputs exposed by the current API are intended for reproducible tests and protocol fixtures. Applications should supply keys from an appropriate secure key-management or randomness layer.

## Core capabilities

### HPKE (RFC 9180)

- KEM: DHKEM(X25519, HKDF-SHA256) and DHKEM(P-256, HKDF-SHA256).
- KDF: HKDF-SHA256, HKDF-SHA384, and HKDF-SHA512.
- AEAD: AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305, and Export-Only.
- Modes: Base, Auth, PSK, and AuthPSK.
- APIs: deterministic single-shot seal/open, stateful `HpkeContext`, sequence-number nonce derivation, and exporter keys.

### JOSE

- JWK/JWKS: `oct`, `OKP`, `EC`, and RSA-oriented key structures, public-key conversion, and thumbprints.
- JWS: compact HS256/HS384/HS512 and EdDSA signing/verification with `alg: none` rejection.
- JWE: five-part compact serialization for direct AES-GCM, AES-KW, ChaCha20-Poly1305, and HPKE-based key agreement.
- JWT: compact signing, expiration/not-before/issuer/audience checks, clock-skew tolerance, and replay cache.

## Quick start

Install MoonBit stable and verify the compiler version:

```bash
moon --version
```

The repository is validated with MoonBit `moonc v0.10.9` or newer.

```bash
moon fmt --check
moon check --deny-warn
moon test --target native --deny-warn --no-parallelize
moon run cmd/hpke-cli
```

Repeatable PowerShell checks are also available:

```powershell
pwsh -File scripts/acceptance_check.ps1
pwsh -File scripts/source_stats.ps1
```

## CLI demonstration

`moon run cmd/hpke-cli` executes an end-to-end demonstration of HPKE, JWK thumbprints, JWS, JWE, and JWT. It uses fixed fixture keys so output is reproducible; it is not a production key generator.

## Architecture

```text
moonbit-hpke/
├── moon.mod
├── cmd/hpke-cli/          # runnable end-to-end demonstration
├── src/core/              # encoding, byte safety, BigNat
├── src/crypto/            # cryptographic primitives
├── src/hpke/              # RFC 9180 protocol and contexts
├── src/jwk/               # RFC 7517 / RFC 7638
├── src/jws/               # RFC 7515
├── src/jwe/               # RFC 7516
├── src/jwt/               # RFC 7519 and replay cache
├── scripts/               # repeatable local acceptance checks
└── .github/workflows/     # multi-platform CI
```

Each directory is a MoonBit package described by its local `moon.pkg`. Public interfaces are generated with `moon info` into `pkg.generated.mbti` files for API review.

## Standards and test vectors

The tests include interoperability and regression coverage for RFC 9180, FIPS 197, NIST SP 800-38D, RFC 3394, RFC 5869, RFC 7748, RFC 8032, RFC 8439, RFC 7638, and JOSE compact serialization.

Boundary tests cover empty and short inputs, malformed encodings, tampering, incorrect keys, wrong metadata, sequence progression, exporter lengths, and replay identifiers.

## Benchmarks

Benchmarks use MoonBit's `@bench.T` harness with deterministic inputs and `b.keep(...)` to prevent dead-code elimination:

```bash
moon bench --package src/crypto --target native --release --deny-warn --no-parallelize
moon bench --package src/hpke --target native --release --deny-warn --no-parallelize
```

Reference measurement on 2026-08-24 (Windows, Intel Core i9-14900HX, 24 cores / 32 logical processors, MoonBit `moonc v0.10.9+6e6c44045`, native release build):

| Benchmark | Mean |
| --- | ---: |
| SHA-256, 32 B | 551.62 ns |
| SHA-256, 1 KiB | 4.92 µs |
| SHA-256, 16 KiB | 73.06 µs |
| HMAC-SHA256, 1 KiB | 7.33 µs |
| Base64URL encode, 1 KiB | 4.56 µs |
| AES-128 block | 521.84 ns |
| AES-GCM seal, 1 KiB | 54.16 µs |
| ChaCha20-Poly1305 seal, 1 KiB | 13.69 µs |
| X25519 base multiplication | 561.24 ms |
| HPKE Base seal, 1 KiB | 1.12 s |
| HPKE Base open, 1 KiB | 1.07 s |

Full output, fixtures, run counts, and protocol are in [`docs/benchmarks.md`](docs/benchmarks.md). These are local reference measurements, not cross-machine performance guarantees or security claims.

## Testing and CI

GitHub Actions runs on Ubuntu, macOS, and Windows. The workflow checks formatting, denies compiler warnings, regenerates and reviews public interfaces, runs coverage-enabled tests, executes supported native/JavaScript/WebAssembly targets, runs the CLI, and enforces the executable `.mbt` source threshold.

The current snapshot contains 47 executable `.mbt` files and 6,606 `.mbt` lines, counted by `scripts/source_stats.ps1`; generated `.mbti` files and build artifacts are excluded.

## License

Apache License 2.0. See [`LICENSE`](LICENSE).
