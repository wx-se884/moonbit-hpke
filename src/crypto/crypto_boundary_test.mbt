// Copyright 2026 wx-se884
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

///|
test "hash and mac functions handle empty and multi-block messages" {
  let empty = Bytes::make(0, b'\x00')
  assert_true(
    @core.bytes_equal(
      sha256(empty),
      @core.hex_decode(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      ),
    ),
  )
  let block = Bytes::make(1024, b'a')
  assert_eq(sha256(block).length(), 32)
  assert_eq(sha384(block).length(), 48)
  assert_eq(sha512(block).length(), 64)
  assert_eq(hmac_sha256(empty, empty).length(), 32)
  assert_eq(hmac_sha384(empty, empty).length(), 48)
  assert_eq(hmac_sha512(empty, empty).length(), 64)
}

///|
test "hkdf supports zero output and all sha2 variants" {
  let salt = @core.hex_decode("000102030405060708090a0b0c")
  let ikm = @core.hex_decode("0b0b0b0b0b0b0b0b")
  let info = @core.string_to_utf8_bytes("boundary")
  assert_eq(hkdf_expand_sha256(hkdf_extract_sha256(salt, ikm), info, 0), b"")
  assert_eq(hkdf_expand_sha384(hkdf_extract_sha384(salt, ikm), info, 0), b"")
  assert_eq(hkdf_expand_sha512(hkdf_extract_sha512(salt, ikm), info, 0), b"")
  assert_eq(hkdf_sha256(salt, ikm, info, 42).length(), 42)
  assert_eq(hkdf_sha384(salt, ikm, info, 42).length(), 42)
  assert_eq(hkdf_sha512(salt, ikm, info, 42).length(), 42)
}

///|
test "aes rejects invalid key lengths and roundtrips empty plaintext" {
  let invalid = try {
    let _ = AesKey::new(b"short")
    false
  } catch {
    CryptoError(_) => true
    _ => false
  }
  assert_true(invalid)
  let key = @core.hex_decode("000102030405060708090a0b0c0d0e0f")
  let iv = @core.hex_decode("000000000000000000000000")
  let payload = aes_gcm_seal(key, iv, b"", b"")
  assert_eq(payload.length(), 16)
  assert_true(@core.bytes_equal(aes_gcm_open(key, iv, payload, b""), b""))
}

///|
test "authenticated encryption rejects changed ciphertext and metadata" {
  let key = @core.hex_decode("000102030405060708090a0b0c0d0e0f")
  let iv = @core.hex_decode("000000000000000000000000")
  let aad = @core.string_to_utf8_bytes("header")
  let payload = aes_gcm_seal(
    key,
    iv,
    @core.string_to_utf8_bytes("payload"),
    aad,
  )
  let changed_payload = @core.bytes_concat(
    @core.bytes_xor(@core.bytes_slice(payload, 0, 1), b"\x01"),
    @core.bytes_slice(payload, 1, payload.length() - 1),
  )
  let changed_ct = try {
    let _ = aes_gcm_open(key, iv, changed_payload, aad)
    false
  } catch {
    CryptoError(_) => true
    _ => false
  }
  let changed_aad = try {
    let _ = aes_gcm_open(key, iv, payload, b"header!")
    false
  } catch {
    CryptoError(_) => true
    _ => false
  }
  assert_true(changed_ct)
  assert_true(changed_aad)
}

///|
test "chacha and poly1305 enforce key and nonce boundaries" {
  let bad_chacha = try {
    let _ = chacha20_block(b"short", 0U, b"short")
    false
  } catch {
    CryptoError(_) => true
    _ => false
  }
  let bad_poly = try {
    let _ = poly1305_mac(b"short", b"message")
    false
  } catch {
    CryptoError(_) => true
    _ => false
  }
  assert_true(bad_chacha)
  assert_true(bad_poly)
  let key = @core.hex_decode(
    "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
  )
  let nonce = @core.hex_decode("070000004041424344454647")
  let (ct, tag) = chacha20poly1305_encrypt(key, nonce, b"", b"")
  assert_eq(ct.length(), 0)
  assert_eq(tag.length(), 16)
  assert_true(
    @core.bytes_equal(chacha20poly1305_decrypt(key, nonce, ct, tag, b""), b""),
  )
}

///|
test "public key primitives reject malformed inputs" {
  let bad_x25519 = try {
    let _ = x25519(b"short", b"short")
    false
  } catch {
    CryptoError(_) => true
    _ => false
  }
  let bad_ed25519 = try {
    let _ = ed25519_public_from_seed(b"short")
    false
  } catch {
    CryptoError(_) => true
    _ => false
  }
  assert_true(bad_x25519)
  assert_true(bad_ed25519)
}

///|
test "aes key wrap rejects malformed and tampered data" {
  let kek = @core.hex_decode("000102030405060708090a0b0c0d0e0f")
  let malformed = try {
    let _ = aes_key_unwrap(kek, b"too-short")
    false
  } catch {
    CryptoError(_) => true
    _ => false
  }
  let wrapped = aes_key_wrap(
    kek,
    @core.hex_decode("00112233445566778899aabbccddeeff"),
  )
  let tampered = @core.bytes_concat(
    @core.bytes_xor(@core.bytes_slice(wrapped, 0, 1), b"\x80"),
    @core.bytes_slice(wrapped, 1, wrapped.length() - 1),
  )
  let bad_integrity = try {
    let _ = aes_key_unwrap(kek, tampered)
    false
  } catch {
    CryptoError(_) => true
    _ => false
  }
  assert_true(malformed)
  assert_true(bad_integrity)
}
