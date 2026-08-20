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
fn compute_poly1305_tag(
  otk : Bytes,
  aad : Bytes,
  ciphertext : Bytes,
) -> Bytes raise @core.CoreError {
  let aad_pad_len = (16 - aad.length() % 16) % 16
  let ct_pad_len = (16 - ciphertext.length() % 16) % 16

  let aad_pad = Bytes::make(aad_pad_len, b'\x00')
  let ct_pad = Bytes::make(ct_pad_len, b'\x00')

  let len_block : FixedArray[Byte] = FixedArray::make(16, b'\x00')
  let aad_len = aad.length().to_uint64()
  let ct_len = ciphertext.length().to_uint64()

  for i in 0..<8 {
    len_block[i] = ((aad_len >> (i * 8)) & 0xFFUL).to_byte()
    len_block[8 + i] = ((ct_len >> (i * 8)) & 0xFFUL).to_byte()
  }

  let mac_data = @core.bytes_concat_all([
    aad,
    aad_pad,
    ciphertext,
    ct_pad,
    Bytes::from_array(len_block[:]),
  ])
  poly1305_mac(otk, mac_data)
}

///|
pub fn chacha20poly1305_encrypt(
  key : Bytes,
  nonce : Bytes,
  plaintext : Bytes,
  aad : Bytes,
) -> (Bytes, Bytes) raise @core.CoreError {
  let otk_block = chacha20_block(key, 0U, nonce)
  let otk = @core.bytes_slice(otk_block, 0, 32)
  let ciphertext = chacha20_process(key, 1U, nonce, plaintext)
  let tag = compute_poly1305_tag(otk, aad, ciphertext)
  (ciphertext, tag)
}

///|
pub fn chacha20poly1305_decrypt(
  key : Bytes,
  nonce : Bytes,
  ciphertext : Bytes,
  tag : Bytes,
  aad : Bytes,
) -> Bytes raise @core.CoreError {
  if tag.length() != 16 {
    raise CryptoError("ChaCha20-Poly1305 tag must be 16 bytes")
  }
  let otk_block = chacha20_block(key, 0U, nonce)
  let otk = @core.bytes_slice(otk_block, 0, 32)
  let expected_tag = compute_poly1305_tag(otk, aad, ciphertext)

  if !@core.constant_time_compare(tag, expected_tag) {
    raise CryptoError("ChaCha20-Poly1305 authentication tag mismatch")
  }

  chacha20_process(key, 1U, nonce, ciphertext)
}

///|
pub fn chacha20poly1305_seal(
  key : Bytes,
  nonce : Bytes,
  plaintext : Bytes,
  aad : Bytes,
) -> Bytes raise @core.CoreError {
  let (ct, tag) = chacha20poly1305_encrypt(key, nonce, plaintext, aad)
  @core.bytes_concat(ct, tag)
}

///|
pub fn chacha20poly1305_open(
  key : Bytes,
  nonce : Bytes,
  payload : Bytes,
  aad : Bytes,
) -> Bytes raise @core.CoreError {
  if payload.length() < 16 {
    raise CryptoError("Payload too short for ChaCha20-Poly1305")
  }
  let ct_len = payload.length() - 16
  let ct = @core.bytes_slice(payload, 0, ct_len)
  let tag = @core.bytes_slice(payload, ct_len, 16)
  chacha20poly1305_decrypt(key, nonce, ct, tag, aad)
}
