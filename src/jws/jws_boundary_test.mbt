// Copyright 2026 wx-se884
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

///|
test "jws rejects malformed compact serialization and none" {
  let malformed = try {
    let _ = jws_verify("only.two", b"secret")
    false
  } catch {
    @core.CryptoError(_) => true
    _ => false
  }
  let none = try {
    let _ = jws_parse_header("{\"alg\":\"none\"}")
    false
  } catch {
    @core.CryptoError(_) => true
    _ => false
  }
  assert_true(malformed)
  assert_true(none)
}

///|
test "jws detects signature and payload mutation" {
  let secret = @core.string_to_utf8_bytes("boundary-secret")
  let token = jws_sign("HS256", b"payload", secret)
  let parts = @core.string_split(token, ".")
  let altered_payload = @core.base64url_encode(b"payload!")
  let changed_payload = parts[0] + "." + altered_payload + "." + parts[2]
  let bad_payload = try {
    let _ = jws_verify(changed_payload, secret)
    false
  } catch {
    @core.CryptoError(_) => true
    _ => false
  }
  let altered_signature = @core.base64url_encode(b"wrong-signature")
  let changed_signature = parts[0] + "." + parts[1] + "." + altered_signature
  let bad_signature = try {
    let _ = jws_verify(changed_signature, secret)
    false
  } catch {
    @core.CryptoError(_) => true
    _ => false
  }
  assert_true(bad_payload)
  assert_true(bad_signature)
}

///|
test "jws preserves optional header fields" {
  let header = JwsHeader::{
    alg: "HS256",
    typ: Some("JWT"),
    kid: Some("key-1"),
    crit: Some(["b64"]),
  }
  let parsed = jws_parse_header(header.to_json_string())
  assert_eq(parsed.alg, "HS256")
  assert_eq(parsed.typ, Some("JWT"))
  assert_eq(parsed.kid, Some("key-1"))
  assert_eq(parsed.crit, Some(["b64"]))
}
