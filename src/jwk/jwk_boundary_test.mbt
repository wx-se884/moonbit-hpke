// Copyright 2026 wx-se884
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

///|
test "jwk public conversion removes private material" {
  let private = Jwk::new_oct(b"0123456789abcdef", kid="oct-1", alg="HS256")
  let public = private.to_public()
  assert_true(!public.is_private())
  assert_eq(public.kid, Some("oct-1"))
  assert_eq(public.alg, Some("HS256"))
  let set = JwkSet::new([private])
  assert_eq(set.find_by_kid("oct-1").map(Jwk::is_private), Some(true))
  assert_eq(set.find_by_kid("missing"), None)
}

///|
test "jwk constructors validate p256 public encoding" {
  let invalid = try {
    let _ = Jwk::new_ec_p256(b"short")
    false
  } catch {
    @core.CryptoError(_) => true
    _ => false
  }
  assert_true(invalid)
  let x = @core.hex_decode(
    "7cf27b188d034f7bcf9586f14c6e285e6f48e97e2c0f34a9f3b5b8f8f8f8f8f8",
  )
  let key = Jwk::new_okp_x25519(x, kid="x-key")
  assert_eq(key.kid, Some("x-key"))
  assert_eq(key.to_public().is_private(), false)
}
