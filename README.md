# moonbit-hpke

[![MoonBit](https://img.shields.io/badge/Language-MoonBit-purple.svg)](https://www.moonbitlang.com/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![RFC 9180](https://img.shields.io/badge/RFC-9180%20(HPKE)-brightgreen.svg)](https://www.rfc-editor.org/rfc/rfc9180.html)
[![RFC 7515/7516/7517/7519](https://img.shields.io/badge/RFC-JOSE%20Suite-orange.svg)](https://datatracker.ietf.org/doc/html/rfc7515)
[![CI](https://github.com/wx-se884/moonbit-hpke/actions/workflows/ci.yml/badge.svg)](https://github.com/wx-se884/moonbit-hpke/actions)

A pure **MoonBit** production-grade cryptographic security suite implementing **RFC 9180 Hybrid Public Key Encryption (HPKE)** and the complete **JOSE (Javascript Object Signing and Encryption)** standard ecosystem (JWK, JWS, JWE, JWT).

Zero external C/FFI dependencies. Fully portable across native binaries, WebAssembly (Wasm), and JavaScript runtimes.

---

## Key Features

- **RFC 9180 Hybrid Public Key Encryption (HPKE)**:
  - **KEMs**: `DHKEM(X25519, HKDF-SHA256)` and `DHKEM(P-256, HKDF-SHA256)`.
  - **KDFs**: `HKDF-SHA256`, `HKDF-SHA384`, `HKDF-SHA512`.
  - **AEADs**: `AES-128-GCM`, `AES-256-GCM`, `ChaCha20-Poly1305`, `Export-Only`.
  - **Modes Supported**: Base (mode 0), PSK (mode 1), Auth (mode 2), AuthPSK (mode 3).
  - Single-shot (`seal` / `open`) and stateful streaming Context with sequence counter ratcheting and secret exporting.

- **JOSE Suite (RFC 7515 / 7516 / 7517 / 7519 / 7638)**:
  - **JWK / JWKS (RFC 7517)**: Key representation (`oct`, `OKP`, `EC`, `RSA`) and RFC 7638 SHA-256 Thumbprint calculation.
  - **JWS (RFC 7515)**: Compact signing & verification (`HS256`, `HS384`, `HS512`, `EdDSA`) with algorithm confusion prevention and strict rejection of `alg: none`.
  - **JWE (RFC 7516)**: 5-part compact encryption (`dir`, `A128KW`, `A256KW`, `HPKE-Base-X25519-SHA256-ChaCha20Poly1305`) with `A128GCM`, `A256GCM`, and `ChaCha20-Poly1305`.
  - **JWT (RFC 7519)**: Token issuance and verification with clock-skew tolerance, expiration/not-before validation, audience checks, and replay cache.

- **High-Assurance Cryptographic Core**:
  - Constant-time memory equality and timing-attack resistant primitives.
  - Pure MoonBit arbitrary-precision arithmetic (`BigNat`) with Jacobian projective coordinate curve acceleration.
  - Comprehensive test suites validated against official NIST CAVP, FIPS 197, RFC 7748, RFC 8439, and RFC 9180 test vectors.

---

## Architecture & Module Layout

```
moonbit-hpke/
├── moon.mod.json              # Root module definition
├── cmd/
│   └── hpke-cli/              # CLI demonstration tool
├── src/
│   ├── core/                  # BigNat, Base64URL, Hex, PKCS#7, Constant-time utilities
│   ├── crypto/                # SHA-2, HMAC, HKDF, AES-GCM, AES-KW, ChaCha20Poly1305, X25519, P-256, Ed25519
│   ├── hpke/                  # RFC 9180 DHKEM, KDF, AEAD, Setup modes, Context, Single-shot APIs
│   ├── jwk/                   # RFC 7517 JSON Web Key & Sets, RFC 7638 Thumbprints
│   ├── jws/                   # RFC 7515 JSON Web Signature
│   ├── jwe/                   # RFC 7516 JSON Web Encryption + HPKE in JWE
│   └── jwt/                   # RFC 7519 JSON Web Token & Replay Cache
└── .github/workflows/         # Cross-platform CI workflow
```

---

## Quickstart

### Prerequisites

Install the official [MoonBit](https://www.moonbitlang.com/) toolchain:

```bash
# Unix / macOS / Linux
curl -fsSL https://cli.moonbitlang.com/install/unix.sh | bash

# Windows (PowerShell)
irm https://cli.moonbitlang.com/install/powershell.ps1 | iex
```

### Build & Run Tests

```bash
# Format check
moon fmt

# Typecheck and lint check with 0 warnings
moon check --deny-warn

# Run all test suites
moon test

# Run the CLI demonstration tool
moon run cmd/hpke-cli
```

---

## Usage Examples

### 1. RFC 9180 HPKE (Single-Shot Seal & Open)

```moonbit
let suite : @hpke.HpkeSuite = {
  kem: DHKEM_X25519_HKDF_SHA256,
  kdf: HKDF_SHA256,
  aead: CHACHA20_POLY1305,
}

// Recipient key generation
let sk_r = @core.hex_decode("6db9e242b206557d33a214e1315073b4e162de1e8e1e7d6a443109ce644f195e")
let pk_r = @hpke.kem_derive_public_key(suite.kem, sk_r)

// Ephemeral sender key & message
let sk_e = @core.hex_decode("52c4a75f0640e347dec662450978797361bc419b904a4da8e18229a7e7ffcc7b")
let info = @core.string_to_utf8_bytes("HPKE Session Info")
let aad = @core.string_to_utf8_bytes("Authenticated metadata")
let pt = @core.string_to_utf8_bytes("Secret payload to encrypt")

// Sender seals
let (enc, ct) = @hpke.hpke_seal_base_deterministic(suite, pk_r, info, aad, pt, sk_e)

// Recipient opens
let decrypted = @hpke.hpke_open_base(suite, enc, sk_r, info, aad, ct)
```

### 2. RFC 7638 JWK Thumbprint

```moonbit
let key_bytes = @core.hex_decode("000102030405060708090a0b0c0d0e0f")
let jwk = @jwk.Jwk::new_oct(key_bytes, kid="auth-key-01")

let thumbprint = jwk.thumbprint_sha256()
// Outputs canonical SHA-256 Base64URL JWK thumbprint
```

### 3. RFC 7515 JSON Web Signature (JWS)

```moonbit
let secret = @core.string_to_utf8_bytes("my-256-bit-secret-key-for-hmac")
let payload = @core.string_to_utf8_bytes("{\"sub\":\"alice\",\"admin\":true}")

// Sign
let token = @jws.jws_sign("HS256", payload, secret, typ="JWT")

// Verify
let (header, verified_payload) = @jws.jws_verify(token, secret)
```

### 4. RFC 7516 JSON Web Encryption (JWE)

```moonbit
let kek = @core.hex_decode("000102030405060708090a0b0c0d0e0f")
let iv = @core.hex_decode("000000000000000000000001")
let pt = @core.string_to_utf8_bytes("Sensitive financial transactions")

// Encrypt with A128KW + A128GCM
let compact_jwe = @jwe.jwe_encrypt("A128KW", "A128GCM", pt, kek, iv)

// Decrypt
let (header, decrypted) = @jwe.jwe_decrypt(compact_jwe, kek)
```

### 5. RFC 7519 JSON Web Token (JWT)

```moonbit
let claims = @jwt.Claims::new(
  iss="https://auth.example.com",
  sub="user-999",
  aud="https://api.example.com",
  exp=2000000000L,
  jti="uuid-nonce-001"
)

let token = @jwt.jwt_sign(claims, "HS256", secret)

// Verify with timestamp validation and audience assertion
let verified = @jwt.jwt_verify(
  token,
  secret,
  now=1710000000L,
  expected_iss="https://auth.example.com",
  expected_aud="https://api.example.com"
)
```

---

## Test Vectors & Standards Compliance

The library has been thoroughly tested against official specification test vectors:
- **RFC 9180**: Hybrid Public Key Encryption (HPKE) Section 10 vectors.
- **NIST SP 800-38D**: AES Galois/Counter Mode (GCM) test cases.
- **FIPS 197**: AES-128 and AES-256 block encryption standard vectors.
- **RFC 7748**: X25519 Diffie-Hellman Key Exchange vectors.
- **RFC 8032**: Ed25519 Signature system test vectors.
- **RFC 8439**: ChaCha20 and Poly1305 AEAD test vectors.
- **RFC 7638**: JSON Web Key (JWK) Thumbprint standard vectors.
- **RFC 3394**: AES Key Wrap Specification test cases.

---

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
