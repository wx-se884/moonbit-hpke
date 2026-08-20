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
test "sha256 standard vectors" {
  let abc = @core.hex_decode("616263")
  let digest = sha256(abc)
  let expected = @core.hex_decode(
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
  )
  assert_true(@core.bytes_equal(digest, expected))
}

///|
test "sha384 standard vectors" {
  let abc = @core.hex_decode("616263")
  let digest = sha384(abc)
  let expected = @core.hex_decode(
    "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
  )
  assert_true(@core.bytes_equal(digest, expected))
}

///|
test "sha512 standard vectors" {
  let abc = @core.hex_decode("616263")
  let digest = sha512(abc)
  let expected = @core.hex_decode(
    "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
  )
  assert_true(@core.bytes_equal(digest, expected))
}

///|
test "hmac sha256 vector" {
  let key = @core.hex_decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
  let msg = @core.hex_decode("4869205468657265")
  let mac = hmac_sha256(key, msg)
  let expected = @core.hex_decode(
    "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
  )
  assert_true(@core.bytes_equal(mac, expected))
}

///|
test "hkdf sha256 rfc5869 vectors" {
  let ikm = @core.hex_decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
  let salt = @core.hex_decode("000102030405060708090a0b0c")
  let info = @core.hex_decode("f0f1f2f3f4f5f6f7f8f9")
  let okm = hkdf_sha256(salt, ikm, info, 42)
  let expected_okm = @core.hex_decode(
    "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
  )
  assert_true(@core.bytes_equal(okm, expected_okm))
}

///|
test "chacha20poly1305 rfc8439 vectors" {
  let key = @core.hex_decode(
    "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
  )
  let nonce = @core.hex_decode("070000004041424344454647")
  let pt = @core.string_to_utf8_bytes(
    "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.",
  )
  let aad = @core.hex_decode("50515253c0c1c2c3c4c5c6c7")

  let (ct, tag) = chacha20poly1305_encrypt(key, nonce, pt, aad)
  let expected_ct = @core.hex_decode(
    "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116",
  )
  let expected_tag = @core.hex_decode("1ae10b594f09e26a7e902ecbd0600691")

  assert_true(@core.bytes_equal(ct, expected_ct))
  assert_true(@core.bytes_equal(tag, expected_tag))

  let decrypted = chacha20poly1305_decrypt(key, nonce, ct, tag, aad)
  assert_true(@core.bytes_equal(decrypted, pt))
}

///|
test "aes256 block fips197 vectors" {
  let key = @core.hex_decode(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  )
  let pt = @core.hex_decode("00112233445566778899aabbccddeeff")
  let aes = AesKey::new(key)
  let ct = aes.encrypt_block(pt, 0)
  let exp = @core.hex_decode("8ea2b7ca516745bfeafc49904b496089")
  assert_true(@core.bytes_equal(ct, exp))
}

///|
test "aes128 block fips197 vectors" {
  let key = @core.hex_decode("000102030405060708090a0b0c0d0e0f")
  let pt = @core.hex_decode("00112233445566778899aabbccddeeff")
  let aes = AesKey::new(key)
  let ct = aes.encrypt_block(pt, 0)
  let exp = @core.hex_decode("69c4e0d86a7b0430d8cdb78070b4c55a")
  assert_true(@core.bytes_equal(ct, exp))
}

///|
test "aes_gcm roundtrip" {
  let key = @core.hex_decode(
    "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
  )
  let iv = @core.hex_decode("cafebabefacedbaddecaf888")
  let pt = @core.hex_decode(
    "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
  )
  let aad = @core.hex_decode("feedfacedeadbeeffeedfacedeadbeefabaddcad")

  let (ct, tag) = aes_gcm_encrypt(key, iv, pt, aad)
  let decrypted = aes_gcm_decrypt(key, iv, ct, tag, aad)
  assert_true(@core.bytes_equal(decrypted, pt))

  let sealed_payload = aes_gcm_seal(key, iv, pt, aad)
  let opened = aes_gcm_open(key, iv, sealed_payload, aad)
  assert_true(@core.bytes_equal(opened, pt))
}

///|
test "x25519 rfc7748 vectors" {
  let alice_priv = @core.hex_decode(
    "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
  )
  let alice_pub = x25519_base(alice_priv)
  let exp_alice_pub = @core.hex_decode(
    "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
  )
  assert_true(@core.bytes_equal(alice_pub, exp_alice_pub))

  let bob_priv = @core.hex_decode(
    "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
  )
  let bob_pub = x25519_base(bob_priv)
  let exp_bob_pub = @core.hex_decode(
    "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
  )
  assert_true(@core.bytes_equal(bob_pub, exp_bob_pub))

  let ss_a = x25519(alice_priv, bob_pub)
  let ss_b = x25519(bob_priv, alice_pub)
  let exp_ss = @core.hex_decode(
    "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
  )
  assert_true(@core.bytes_equal(ss_a, exp_ss))
  assert_true(@core.bytes_equal(ss_b, exp_ss))
}

///|
test "p256 ecdh key exchange" {
  let d_a = @core.hex_decode(
    "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
  )
  let pub_a = p256_public_from_private(d_a)

  let d_b = @core.hex_decode(
    "519b423d715f8b581f4fa8ee59f40547c18c047f0ce014c5a0296e6d55e26c6f",
  )
  let pub_b = p256_public_from_private(d_b)

  let ss_a = p256_ecdh(d_a, pub_b)
  let ss_b = p256_ecdh(d_b, pub_a)

  assert_true(@core.bytes_equal(ss_a, ss_b))
  assert_eq(ss_a.length(), 32)
}

///|
test "aes key wrap rfc3394" {
  let kek = @core.hex_decode("000102030405060708090a0b0c0d0e0f")
  let key_data = @core.hex_decode("00112233445566778899aabbccddeeff")
  let wrapped = aes_key_wrap(kek, key_data)
  let unwrapped = aes_key_unwrap(kek, wrapped)
  assert_true(@core.bytes_equal(unwrapped, key_data))
}
