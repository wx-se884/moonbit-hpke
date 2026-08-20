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
test "jws hs256 sign and verify" {
  let secret = @core.string_to_utf8_bytes("your-256-bit-secret-key-for-hmac")
  let payload = @core.string_to_utf8_bytes(
    "{\"sub\":\"1234567890\",\"name\":\"John Doe\",\"admin\":true}",
  )

  let compact = jws_sign("HS256", payload, secret, typ="JWT")
  let (header, verified_payload) = jws_verify(compact, secret)

  assert_eq(header.alg, "HS256")
  assert_true(@core.bytes_equal(verified_payload, payload))
}

///|
test "jws eddsa sign and verify" {
  let seed = @core.hex_decode(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
  )
  let pub_key = @crypto.ed25519_public_from_seed(seed)
  let payload = @core.string_to_utf8_bytes("Authenticated EdDSA JWS payload")

  let compact = jws_sign("EdDSA", payload, seed, kid="ed25519-key-1")
  let (header, verified_payload) = jws_verify(compact, pub_key)

  assert_eq(header.alg, "EdDSA")
  assert_true(@core.bytes_equal(verified_payload, payload))
}
