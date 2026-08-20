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
test "jwe dir A256GCM roundtrip" {
  let key = @core.hex_decode(
    "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
  )
  let iv = @core.hex_decode("cafebabefacedbaddecaf888")
  let pt = @core.string_to_utf8_bytes(
    "Confidential payload encrypted with Direct AES-256-GCM",
  )

  let compact = jwe_encrypt("dir", "A256GCM", pt, key, iv, kid="my-dir-key")
  let (header, decrypted) = jwe_decrypt(compact, key)

  assert_eq(header.alg, "dir")
  assert_eq(header.enc, "A256GCM")
  assert_true(@core.bytes_equal(decrypted, pt))
}

///|
test "jwe A128KW A128GCM roundtrip" {
  let kek = @core.hex_decode("000102030405060708090a0b0c0d0e0f")
  let cek = @core.hex_decode("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf")
  let iv = @core.hex_decode("000000000000000000000001")
  let pt = @core.string_to_utf8_bytes("Secret data with AES Key Wrap")

  let compact = jwe_encrypt("A128KW", "A128GCM", pt, kek, iv, cek_override=cek)
  let (header, decrypted) = jwe_decrypt(compact, kek)

  assert_eq(header.alg, "A128KW")
  assert_true(@core.bytes_equal(decrypted, pt))
}

///|
test "jwe hpke x25519 roundtrip" {
  let sk_r = @core.hex_decode(
    "6db9e242b206557d33a214e1315073b4e162de1e8e1e7d6a443109ce644f195e",
  )
  let pk_r = @crypto.x25519_base(sk_r)
  let sk_e = @core.hex_decode(
    "52c4a75f0640e347dec662450978797361bc419b904a4da8e18229a7e7ffcc7b",
  )
  let iv = @core.hex_decode("070000004041424344454647")
  let pt = @core.string_to_utf8_bytes("Top Secret message via HPKE in JWE")

  let compact = jwe_encrypt(
    "HPKE-Base-X25519-SHA256-ChaCha20Poly1305",
    "ChaCha20-Poly1305",
    pt,
    pk_r,
    iv,
    ephemeral_key=sk_e,
  )
  let (header, decrypted) = jwe_decrypt(compact, sk_r)

  assert_eq(header.alg, "HPKE-Base-X25519-SHA256-ChaCha20Poly1305")
  assert_true(@core.bytes_equal(decrypted, pt))
}
