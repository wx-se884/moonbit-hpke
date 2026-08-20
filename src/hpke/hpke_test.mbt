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
test "hpke x25519 hkdf_sha256 chacha20poly1305 base mode roundtrip" {
  let suite : HpkeSuite = {
    kem: DHKEM_X25519_HKDF_SHA256,
    kdf: HKDF_SHA256,
    aead: CHACHA20_POLY1305,
  }
  let sk_r = @core.hex_decode(
    "6db9e242b206557d33a214e1315073b4e162de1e8e1e7d6a443109ce644f195e",
  )
  let pk_r = kem_derive_public_key(suite.kem, sk_r)

  let sk_e = @core.hex_decode(
    "52c4a75f0640e347dec662450978797361bc419b904a4da8e18229a7e7ffcc7b",
  )
  let info = @core.string_to_utf8_bytes("HPKE Test Info")
  let aad = @core.string_to_utf8_bytes("HPKE Additional Data")
  let pt = @core.string_to_utf8_bytes(
    "Beauty is truth, truth beauty,-that is all / Ye know on earth, and all ye need to know.",
  )

  let (enc, ct) = hpke_seal_base_deterministic(suite, pk_r, info, aad, pt, sk_e)
  let decrypted = hpke_open_base(suite, enc, sk_r, info, aad, ct)

  assert_true(@core.bytes_equal(decrypted, pt))
}

///|
test "hpke p256 hkdf_sha256 aes128gcm base mode roundtrip" {
  let suite : HpkeSuite = {
    kem: DHKEM_P256_HKDF_SHA256,
    kdf: HKDF_SHA256,
    aead: AES_128_GCM,
  }
  let sk_r = @core.hex_decode(
    "0202020202020202020202020202020202020202020202020202020202020202",
  )
  let pk_r = kem_derive_public_key(suite.kem, sk_r)

  let sk_e = @core.hex_decode(
    "0101010101010101010101010101010101010101010101010101010101010101",
  )
  let info = @core.string_to_utf8_bytes("P256 HPKE Info")
  let aad = @core.string_to_utf8_bytes("P256 AAD")
  let pt = @core.string_to_utf8_bytes("Secret HPKE payload over NIST P-256")

  let (enc, ct) = hpke_seal_base_deterministic(suite, pk_r, info, aad, pt, sk_e)
  let decrypted = hpke_open_base(suite, enc, sk_r, info, aad, ct)

  assert_true(@core.bytes_equal(decrypted, pt))
}

///|
test "hpke auth mode roundtrip" {
  let suite : HpkeSuite = {
    kem: DHKEM_X25519_HKDF_SHA256,
    kdf: HKDF_SHA256,
    aead: AES_256_GCM,
  }
  let sk_r = @core.hex_decode(
    "6db9e242b206557d33a214e1315073b4e162de1e8e1e7d6a443109ce644f195e",
  )
  let pk_r = kem_derive_public_key(suite.kem, sk_r)

  let sk_s = @core.hex_decode(
    "7d1538f4682838a3799c4780f78353955c73bc44ac91cb24354662223de8b87c",
  )
  let pk_s = kem_derive_public_key(suite.kem, sk_s)

  let sk_e = @core.hex_decode(
    "52c4a75f0640e347dec662450978797361bc419b904a4da8e18229a7e7ffcc7b",
  )
  let info = @core.string_to_utf8_bytes("Auth mode info")
  let aad = @core.string_to_utf8_bytes("Auth mode aad")
  let pt = @core.string_to_utf8_bytes(
    "Authenticated message from sender S to recipient R",
  )

  let (enc, ct) = hpke_seal_auth_deterministic(
    suite, pk_r, info, aad, pt, sk_s, sk_e,
  )
  let decrypted = hpke_open_auth(suite, enc, sk_r, info, aad, ct, pk_s)

  assert_true(@core.bytes_equal(decrypted, pt))
}

///|
test "hpke psk mode roundtrip" {
  let suite : HpkeSuite = {
    kem: DHKEM_X25519_HKDF_SHA256,
    kdf: HKDF_SHA256,
    aead: CHACHA20_POLY1305,
  }
  let sk_r = @core.hex_decode(
    "6db9e242b206557d33a214e1315073b4e162de1e8e1e7d6a443109ce644f195e",
  )
  let pk_r = kem_derive_public_key(suite.kem, sk_r)

  let sk_e = @core.hex_decode(
    "52c4a75f0640e347dec662450978797361bc419b904a4da8e18229a7e7ffcc7b",
  )
  let psk = @core.hex_decode(
    "0202020202020202020202020202020202020202020202020202020202020202",
  )
  let psk_id = @core.string_to_utf8_bytes("psk-key-identifier-12345")
  let info = @core.string_to_utf8_bytes("PSK mode info")
  let aad = @core.string_to_utf8_bytes("PSK aad")
  let pt = @core.string_to_utf8_bytes("Pre-shared key protected HPKE secret")

  let (enc, ct) = hpke_seal_psk_deterministic(
    suite, pk_r, info, aad, pt, psk, psk_id, sk_e,
  )
  let decrypted = hpke_open_psk(suite, enc, sk_r, info, aad, ct, psk, psk_id)

  assert_true(@core.bytes_equal(decrypted, pt))
}

///|
test "hpke secret export" {
  let suite : HpkeSuite = {
    kem: DHKEM_X25519_HKDF_SHA256,
    kdf: HKDF_SHA256,
    aead: EXPORT_ONLY,
  }
  let sk_r = @core.hex_decode(
    "6db9e242b206557d33a214e1315073b4e162de1e8e1e7d6a443109ce644f195e",
  )
  let pk_r = kem_derive_public_key(suite.kem, sk_r)
  let sk_e = @core.hex_decode(
    "52c4a75f0640e347dec662450978797361bc419b904a4da8e18229a7e7ffcc7b",
  )

  let (enc, ctx_s) = hpke_setup_base_s_deterministic(
    suite,
    pk_r,
    @core.string_to_utf8_bytes("export"),
    sk_e,
  )
  let ctx_r = hpke_setup_base_r(
    suite,
    enc,
    sk_r,
    @core.string_to_utf8_bytes("export"),
  )

  let export_ctx = @core.string_to_utf8_bytes("custom-export-channel-id")
  let sec_s = ctx_s.export_key(export_ctx, 32)
  let sec_r = ctx_r.export_key(export_ctx, 32)

  assert_true(@core.bytes_equal(sec_s, sec_r))
  assert_eq(sec_s.length(), 32)
}
