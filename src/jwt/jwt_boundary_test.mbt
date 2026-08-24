// Copyright 2026 wx-se884
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

///|
test "claims validation handles expiry nbf issuer and audience" {
  let claims = Claims::new(iss="issuer", aud="audience", exp=100L, nbf=50L)
  assert_true(
    claims.validate(75L, 0L, expected_iss="issuer", expected_aud="audience"),
  )
  assert_true(
    !claims.validate(101L, 0L, expected_iss="issuer", expected_aud="audience"),
  )
  assert_true(
    !claims.validate(49L, 0L, expected_iss="issuer", expected_aud="audience"),
  )
  assert_true(
    !claims.validate(75L, 0L, expected_iss="other", expected_aud="audience"),
  )
  assert_true(
    !claims.validate(75L, 0L, expected_iss="issuer", expected_aud="other"),
  )
  assert_true(
    claims.validate(102L, 2L, expected_iss="issuer", expected_aud="audience"),
  )
}

///|
test "jwt rejects changed secret and forbidden algorithm" {
  let secret = @core.string_to_utf8_bytes("boundary-jwt-secret")
  let claims = Claims::new(sub="boundary", exp=200L)
  let token = jwt_sign(claims, "HS256", secret)
  let wrong_secret = try {
    let _ = jwt_verify(token, b"wrong", now=100L)
    false
  } catch {
    @core.CryptoError(_) => true
    _ => false
  }
  let none = try {
    let _ = jwt_verify("eyJhbGciOiJub25lIn0.e30.", secret, now=100L)
    false
  } catch {
    @core.CryptoError(_) => true
    _ => false
  }
  assert_true(wrong_secret)
  assert_true(none)
}

///|
test "replay cache distinguishes empty and repeated identifiers" {
  let cache = ReplayCache::new()
  assert_true(cache.check_and_add(""))
  assert_true(!cache.check_and_add(""))
  assert_true(cache.check_and_add("different"))
}
