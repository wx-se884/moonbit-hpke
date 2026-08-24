// Copyright 2026 wx-se884
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

///|
test "jwe rejects malformed compact serialization" {
  let malformed = try {
    let _ = jwe_decrypt("one.two.three", b"key")
    false
  } catch {
    @core.CryptoError(_) => true
    _ => false
  }
  let missing_alg = try {
    let _ = jwe_parse_header("{\"enc\":\"A256GCM\"}")
    false
  } catch {
    @core.CryptoError(_) => true
    _ => false
  }
  assert_true(malformed)
  assert_true(missing_alg)
}

///|
test "jwe authenticates direct mode metadata and ciphertext" {
  let key = @core.hex_decode(
    "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
  )
  let iv = @core.hex_decode("cafebabefacedbaddecaf888")
  let token = jwe_encrypt("dir", "A256GCM", b"payload", key, iv)
  let parts = @core.string_split(token, ".")
  let altered = parts[0] +
    "." +
    parts[1] +
    "." +
    parts[2] +
    "." +
    parts[3] +
    "." +
    @core.base64url_encode(b"tampered")
  let rejected = try {
    let _ = jwe_decrypt(altered, key)
    false
  } catch {
    @core.CryptoError(_) => true
    _ => false
  }
  assert_true(rejected)
}

///|
test "jwe header roundtrip keeps optional fields" {
  let header = JweHeader::{
    alg: "dir",
    enc: "A256GCM",
    kid: Some("key-1"),
    encap: Some("encap-1"),
  }
  let parsed = jwe_parse_header(header.to_json_string())
  assert_eq(parsed.alg, "dir")
  assert_eq(parsed.enc, "A256GCM")
  assert_eq(parsed.kid, Some("key-1"))
  assert_eq(parsed.encap, Some("encap-1"))
}
