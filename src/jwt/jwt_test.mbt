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
test "jwt sign and verify with validation" {
  let secret = @core.string_to_utf8_bytes("super-secret-key-32-bytes-long!!")
  let claims = Claims::new(
    iss="https://auth.example.com",
    sub="user-12345",
    aud="https://api.example.com",
    exp=2000000000L,
    nbf=1000000000L,
    iat=1700000000L,
    jti="unique-jti-uuid-001",
  )

  let token = jwt_sign(claims, "HS256", secret)
  let verified = jwt_verify(
    token,
    secret,
    now=1710000000L,
    expected_iss="https://auth.example.com",
    expected_aud="https://api.example.com",
  )

  assert_eq(verified.sub, Some("user-12345"))
  assert_eq(verified.jti, Some("unique-jti-uuid-001"))
}

///|
test "jwt replay cache" {
  let cache = ReplayCache::new()
  assert_true(cache.check_and_add("nonce-1"))
  assert_true(!cache.check_and_add("nonce-1")) // Replay rejected
  assert_true(cache.check_and_add("nonce-2"))
}
