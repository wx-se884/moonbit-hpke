// Copyright 2026 wx-se884
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

///|
fn boundary_suite() -> HpkeSuite {
  { kem: DHKEM_X25519_HKDF_SHA256, kdf: HKDF_SHA256, aead: CHACHA20_POLY1305 }
}

///|
fn boundary_keys() -> (Bytes, Bytes, Bytes, Bytes) raise @core.CoreError {
  let sk_r = @core.hex_decode(
    "6db9e242b206557d33a214e1315073b4e162de1e8e1e7d6a443109ce644f195e",
  )
  let pk_r = kem_derive_public_key(boundary_suite().kem, sk_r)
  let sk_e = @core.hex_decode(
    "52c4a75f0640e347dec662450978797361bc419b904a4da8e18229a7e7ffcc7b",
  )
  (sk_r, pk_r, sk_e, @core.string_to_utf8_bytes("context"))
}

///|
test "hpke base mode preserves empty payloads and empty aad" {
  let suite = boundary_suite()
  let (sk_r, pk_r, sk_e, info) = boundary_keys()
  let (enc, payload) = hpke_seal_base_deterministic(
    suite, pk_r, info, b"", b"", sk_e,
  )
  assert_eq(enc.length(), suite.kem.n_enc())
  assert_eq(payload.length(), suite.aead.n_t())
  let opened = hpke_open_base(suite, enc, sk_r, info, b"", payload)
  assert_true(@core.bytes_equal(opened, b""))
}

///|
test "hpke rejects altered aad and ciphertext" {
  let suite = boundary_suite()
  let (sk_r, pk_r, sk_e, info) = boundary_keys()
  let aad = @core.string_to_utf8_bytes("authenticated header")
  let pt = @core.string_to_utf8_bytes("protected message")
  let (enc, payload) = hpke_seal_base_deterministic(
    suite, pk_r, info, aad, pt, sk_e,
  )
  let wrong_aad = try {
    let _ = hpke_open_base(suite, enc, sk_r, info, b"wrong", payload)
    false
  } catch {
    CryptoError(_) => true
    _ => false
  }
  let changed = @core.bytes_concat(
    @core.bytes_xor(@core.bytes_slice(payload, 0, 1), b"\x01"),
    @core.bytes_slice(payload, 1, payload.length() - 1),
  )
  let wrong_ct = try {
    let _ = hpke_open_base(suite, enc, sk_r, info, aad, changed)
    false
  } catch {
    CryptoError(_) => true
    _ => false
  }
  assert_true(wrong_aad)
  assert_true(wrong_ct)
}

///|
test "hpke contexts ratchet sequence numbers and share exporters" {
  let suite = boundary_suite()
  let (sk_r, pk_r, sk_e, info) = boundary_keys()
  let (enc, sender) = hpke_setup_base_s_deterministic(suite, pk_r, info, sk_e)
  let receiver = hpke_setup_base_r(suite, enc, sk_r, info)
  let first = sender.seal(b"first", b"")
  let second = sender.seal(b"second", b"")
  assert_true(@core.bytes_equal(receiver.open(first, b""), b"first"))
  assert_true(@core.bytes_equal(receiver.open(second, b""), b"second"))
  assert_true(
    @core.bytes_equal(
      sender.export_key(b"exporter", 48),
      receiver.export_key(b"exporter", 48),
    ),
  )
  assert_eq(sender.export_key(b"zero", 0).length(), 0)
}

///|
test "hpke validates wrong recipient key and malformed encapsulation" {
  let suite = boundary_suite()
  let (sk_r, pk_r, sk_e, info) = boundary_keys()
  let (enc, payload) = hpke_seal_base_deterministic(
    suite, pk_r, info, b"", b"x", sk_e,
  )
  let wrong_sk = @core.hex_decode(
    "7d1538f4682838a3799c4780f78353955c73bc44ac91cb24354662223de8b87c",
  )
  let wrong_key = try {
    let _ = hpke_open_base(suite, enc, wrong_sk, info, b"", payload)
    false
  } catch {
    CryptoError(_) => true
    _ => false
  }
  let malformed = try {
    let _ = hpke_open_base(suite, b"short", sk_r, info, b"", payload)
    false
  } catch {
    CryptoError(_) => true
    _ => false
  }
  assert_true(wrong_key)
  assert_true(malformed)
}

///|
test "hpke authpsk mode binds sender identity and psk" {
  let suite = boundary_suite()
  let (sk_r, pk_r, sk_e, info) = boundary_keys()
  let sk_s = @core.hex_decode(
    "7d1538f4682838a3799c4780f78353955c73bc44ac91cb24354662223de8b87c",
  )
  let pk_s = kem_derive_public_key(suite.kem, sk_s)
  let psk = @core.hex_decode(
    "0202020202020202020202020202020202020202020202020202020202020202",
  )
  let psk_id = @core.string_to_utf8_bytes("authpsk-id")
  let aad = @core.string_to_utf8_bytes("authpsk-aad")
  let pt = @core.string_to_utf8_bytes("authpsk payload")
  let (enc, payload) = hpke_seal_auth_psk_deterministic(
    suite, pk_r, info, aad, pt, sk_s, sk_e, psk, psk_id,
  )
  let opened = hpke_open_auth_psk(
    suite, enc, sk_r, info, aad, payload, pk_s, psk, psk_id,
  )
  assert_true(@core.bytes_equal(opened, pt))
  let wrong_psk = try {
    let _ = hpke_open_auth_psk(
      suite, enc, sk_r, info, aad, payload, pk_s, b"wrong", psk_id,
    )
    false
  } catch {
    CryptoError(_) => true
    _ => false
  }
  assert_true(wrong_psk)
}
