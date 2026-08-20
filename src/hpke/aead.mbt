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
pub(all) enum AeadId {
  AES_128_GCM
  AES_256_GCM
  CHACHA20_POLY1305
  EXPORT_ONLY
} derive(Debug, Eq)

///|
pub fn AeadId::value(self : AeadId) -> Int {
  match self {
    AES_128_GCM => 0x0001
    AES_256_GCM => 0x0002
    CHACHA20_POLY1305 => 0x0003
    EXPORT_ONLY => 0xFFFF
  }
}

///|
pub fn AeadId::n_k(self : AeadId) -> Int {
  match self {
    AES_128_GCM => 16
    AES_256_GCM => 32
    CHACHA20_POLY1305 => 32
    EXPORT_ONLY => 0
  }
}

///|
pub fn AeadId::n_n(self : AeadId) -> Int {
  match self {
    AES_128_GCM => 12
    AES_256_GCM => 12
    CHACHA20_POLY1305 => 12
    EXPORT_ONLY => 0
  }
}

///|
pub fn AeadId::n_t(self : AeadId) -> Int {
  match self {
    AES_128_GCM => 16
    AES_256_GCM => 16
    CHACHA20_POLY1305 => 16
    EXPORT_ONLY => 0
  }
}

///|
pub fn aead_seal(
  aead_id : AeadId,
  key : Bytes,
  nonce : Bytes,
  plaintext : Bytes,
  aad : Bytes,
) -> Bytes raise @core.CoreError {
  match aead_id {
    AES_128_GCM | AES_256_GCM =>
      @crypto.aes_gcm_seal(key, nonce, plaintext, aad)
    CHACHA20_POLY1305 => {
      let (ct, tag) = @crypto.chacha20poly1305_encrypt(
        key, nonce, plaintext, aad,
      )
      @core.bytes_concat(ct, tag)
    }
    EXPORT_ONLY => raise CryptoError("Cannot seal with Export-Only AEAD")
  }
}

///|
pub fn aead_open(
  aead_id : AeadId,
  key : Bytes,
  nonce : Bytes,
  ciphertext_and_tag : Bytes,
  aad : Bytes,
) -> Bytes raise @core.CoreError {
  match aead_id {
    AES_128_GCM | AES_256_GCM =>
      @crypto.aes_gcm_open(key, nonce, ciphertext_and_tag, aad)
    CHACHA20_POLY1305 => {
      if ciphertext_and_tag.length() < 16 {
        raise CryptoError("Ciphertext too short for ChaCha20Poly1305 tag")
      }
      let ct_len = ciphertext_and_tag.length() - 16
      let ct = @core.bytes_slice(ciphertext_and_tag, 0, ct_len)
      let tag = @core.bytes_slice(ciphertext_and_tag, ct_len, 16)
      @crypto.chacha20poly1305_decrypt(key, nonce, ct, tag, aad)
    }
    EXPORT_ONLY => raise CryptoError("Cannot open with Export-Only AEAD")
  }
}
