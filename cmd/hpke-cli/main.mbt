// Copyright 2026 wx-se884
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

///|
fn main {
  println("================================================================")
  println("  moonbit-hpke & JOSE Cryptographic Security Suite (v0.2.0)")
  println(
    "  RFC 9180 HPKE | RFC 7515 JWS | RFC 7516 JWE | RFC 7517/7638 JWK | RFC 7519 JWT",
  )
  println("================================================================")

  // 1. HPKE Demo
  println("\n--- [1] RFC 9180 HPKE (Hybrid Public Key Encryption) ---")
  let suite : @hpke.HpkeSuite = {
    kem: DHKEM_X25519_HKDF_SHA256,
    kdf: HKDF_SHA256,
    aead: CHACHA20_POLY1305,
  }
  let sk_r = try! @core.hex_decode(
    "6db9e242b206557d33a214e1315073b4e162de1e8e1e7d6a443109ce644f195e",
  )
  let pk_r = try! @hpke.kem_derive_public_key(suite.kem, sk_r)
  let sk_e = try! @core.hex_decode(
    "52c4a75f0640e347dec662450978797361bc419b904a4da8e18229a7e7ffcc7b",
  )

  let info = @core.string_to_utf8_bytes("HPKE demo info")
  let aad = @core.string_to_utf8_bytes("HPKE authenticated data")
  let pt = @core.string_to_utf8_bytes(
    "Top Secret Payload encrypted with RFC 9180 HPKE",
  )

  let (enc, ct) = try! @hpke.hpke_seal_base_deterministic(
    suite, pk_r, info, aad, pt, sk_e,
  )
  let decrypted_pt = try! @hpke.hpke_open_base(suite, enc, sk_r, info, aad, ct)
  let decrypted_str = try! @core.utf8_bytes_to_string(decrypted_pt)

  println("KEM:       DHKEM(X25519, HKDF-SHA256)")
  println("KDF:       HKDF-SHA256")
  println("AEAD:      ChaCha20-Poly1305")
  println("Plaintext: " + (try! @core.utf8_bytes_to_string(pt)))
  println("Enc (PKe): " + @core.hex_encode(enc))
  println("Ciphertext:" + @core.hex_encode(ct))
  println("Decrypted: " + decrypted_str)

  // 2. JWK Thumbprint Demo
  println("\n--- [2] RFC 7517 & RFC 7638 JWK Thumbprint ---")
  let jwk = @jwk.Jwk::new_okp_x25519(
    pk_r,
    priv_key=sk_r,
    kid="x25519-demo-key-1",
  )
  let thumbprint = try! jwk.thumbprint_sha256()
  println("Key ID:     " + jwk.kid.unwrap())
  println("Thumbprint: " + thumbprint)

  // 3. JWS Demo
  println("\n--- [3] RFC 7515 JSON Web Signature (JWS) ---")
  let hmac_secret = @core.string_to_utf8_bytes(
    "my-super-secret-hmac-key-for-jws",
  )
  let jws_payload = @core.string_to_utf8_bytes(
    "{\"user\":\"alice\",\"role\":\"admin\"}",
  )
  let compact_jws = try! @jws.jws_sign(
    "HS256",
    jws_payload,
    hmac_secret,
    typ="JWT",
  )
  println("Compact JWS: " + compact_jws)

  let (_, verified_jws_payload) = try! @jws.jws_verify(compact_jws, hmac_secret)
  println(
    "Verified:    " + (try! @core.utf8_bytes_to_string(verified_jws_payload)),
  )

  // 4. JWE Demo
  println("\n--- [4] RFC 7516 JSON Web Encryption (JWE) ---")
  let jwe_kek = try! @core.hex_decode("000102030405060708090a0b0c0d0e0f")
  let jwe_iv = try! @core.hex_decode("000000000000000000000001")
  let jwe_pt = @core.string_to_utf8_bytes(
    "Sensitive encrypted credit card data: 4000-1234-5678-9010",
  )
  let compact_jwe = try! @jwe.jwe_encrypt(
    "A128KW", "A128GCM", jwe_pt, jwe_kek, jwe_iv,
  )
  println("Compact JWE: " + compact_jwe)

  let (_, decrypted_jwe) = try! @jwe.jwe_decrypt(compact_jwe, jwe_kek)
  println("Decrypted:   " + (try! @core.utf8_bytes_to_string(decrypted_jwe)))

  // 5. JWT Demo
  println("\n--- [5] RFC 7519 JSON Web Token (JWT) ---")
  let jwt_claims = @jwt.Claims::new(
    iss="https://auth.moonbit.org",
    sub="developer-100",
    aud="https://api.moonbit.org",
    exp=2500000000L,
    jti="token-uuid-999",
  )
  let token = try! @jwt.jwt_sign(jwt_claims, "HS256", hmac_secret)
  println("JWT:         " + token)
  let verified_claims = try! @jwt.jwt_verify(
    token,
    hmac_secret,
    now=1750000000L,
  )
  println("Issuer:      " + verified_claims.iss.unwrap())
  println("Subject:     " + verified_claims.sub.unwrap())

  println("\nAll cryptographic operations executed and verified successfully.")
}
