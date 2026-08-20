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
test "jwk oct thumbprint rfc7638" {
  let key_bytes = @core.hex_decode("000102030405060708090a0b0c0d0e0f")
  let jwk = Jwk::new_oct(key_bytes, kid="my-symmetric-key")
  let thumbprint = jwk.thumbprint_sha256()
  assert_true(thumbprint.length() > 0)
}

///|
test "jwk okp x25519 public stripping" {
  let priv_key = @core.hex_decode(
    "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
  )
  let pub_key = @crypto.x25519_base(priv_key)
  let jwk_priv = Jwk::new_okp_x25519(pub_key, priv_key~, kid="x25519-key-1")

  assert_true(jwk_priv.is_private())
  let jwk_pub = jwk_priv.to_public()
  assert_true(!jwk_pub.is_private())
  assert_eq(jwk_pub.d, None)
}

///|
test "jwk set lookup" {
  let key1 = Jwk::new_oct(@core.hex_decode("11223344"), kid="key-1")
  let key2 = Jwk::new_oct(@core.hex_decode("55667788"), kid="key-2")
  let jwks = JwkSet::new([key1, key2])

  let found = jwks.find_by_kid("key-2")
  assert_true(found is Some(_))
  let not_found = jwks.find_by_kid("nonexistent")
  assert_true(not_found is None)
}
