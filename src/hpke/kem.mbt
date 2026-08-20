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
pub(all) enum KemId {
  DHKEM_P256_HKDF_SHA256
  DHKEM_X25519_HKDF_SHA256
} derive(Debug, Eq)

///|
pub fn KemId::value(self : KemId) -> Int {
  match self {
    DHKEM_P256_HKDF_SHA256 => 0x0010
    DHKEM_X25519_HKDF_SHA256 => 0x0020
  }
}

///|
pub fn KemId::n_secret(self : KemId) -> Int {
  match self {
    DHKEM_P256_HKDF_SHA256 => 32
    DHKEM_X25519_HKDF_SHA256 => 32
  }
}

///|
pub fn KemId::n_enc(self : KemId) -> Int {
  match self {
    DHKEM_P256_HKDF_SHA256 => 65
    DHKEM_X25519_HKDF_SHA256 => 32
  }
}

///|
pub fn KemId::n_pk(self : KemId) -> Int {
  match self {
    DHKEM_P256_HKDF_SHA256 => 65
    DHKEM_X25519_HKDF_SHA256 => 32
  }
}

///|
pub fn KemId::n_sk(self : KemId) -> Int {
  match self {
    DHKEM_P256_HKDF_SHA256 => 32
    DHKEM_X25519_HKDF_SHA256 => 32
  }
}

///|
fn kem_suite_id(kem_id : KemId) -> Bytes {
  let kem_tag = @core.string_to_utf8_bytes("KEM")
  let id_bytes = @core.put_u16_be(kem_id.value())
  @core.bytes_concat(kem_tag, id_bytes)
}

///|
fn kem_labeled_extract(
  kem_id : KemId,
  salt : Bytes,
  label : String,
  ikm : Bytes,
) -> Bytes {
  let suite_id = kem_suite_id(kem_id)
  let prefix = @core.string_to_utf8_bytes("HPKE-v1")
  let label_bytes = @core.string_to_utf8_bytes(label)
  let full_ikm = @core.bytes_concat_all([prefix, suite_id, label_bytes, ikm])
  @crypto.hkdf_extract_sha256(salt, full_ikm)
}

///|
fn kem_labeled_expand(
  kem_id : KemId,
  prk : Bytes,
  label : String,
  info : Bytes,
  length : Int,
) -> Bytes {
  let suite_id = kem_suite_id(kem_id)
  let prefix = @core.string_to_utf8_bytes("HPKE-v1")
  let label_bytes = @core.string_to_utf8_bytes(label)
  let len_bytes = @core.put_u16_be(length)
  let full_info = @core.bytes_concat_all([
    len_bytes, prefix, suite_id, label_bytes, info,
  ])
  @crypto.hkdf_expand_sha256(prk, full_info, length)
}

///|
fn extract_and_expand(kem_id : KemId, dh : Bytes, kem_context : Bytes) -> Bytes {
  let eae_prk = kem_labeled_extract(
    kem_id,
    Bytes::make(0, b'\x00'),
    "eae_prk",
    dh,
  )
  kem_labeled_expand(
    kem_id,
    eae_prk,
    "shared_secret",
    kem_context,
    kem_id.n_secret(),
  )
}

///|
pub fn kem_derive_public_key(
  kem_id : KemId,
  sk : Bytes,
) -> Bytes raise @core.CoreError {
  match kem_id {
    DHKEM_P256_HKDF_SHA256 => @crypto.p256_public_from_private(sk)
    DHKEM_X25519_HKDF_SHA256 => @crypto.x25519_base(sk)
  }
}

///|
pub fn kem_dh(
  kem_id : KemId,
  sk : Bytes,
  pk : Bytes,
) -> Bytes raise @core.CoreError {
  match kem_id {
    DHKEM_P256_HKDF_SHA256 => @crypto.p256_ecdh(sk, pk)
    DHKEM_X25519_HKDF_SHA256 => @crypto.x25519(sk, pk)
  }
}

///|
pub fn kem_encap_deterministic(
  kem_id : KemId,
  pk_r : Bytes,
  sk_e : Bytes,
) -> (Bytes, Bytes) raise @core.CoreError {
  let pk_e = kem_derive_public_key(kem_id, sk_e)
  let dh = kem_dh(kem_id, sk_e, pk_r)
  let kem_context = @core.bytes_concat(pk_e, pk_r)
  let shared_secret = extract_and_expand(kem_id, dh, kem_context)
  (shared_secret, pk_e)
}

///|
pub fn kem_decap(
  kem_id : KemId,
  enc : Bytes,
  sk_r : Bytes,
) -> Bytes raise @core.CoreError {
  let pk_r = kem_derive_public_key(kem_id, sk_r)
  let dh = kem_dh(kem_id, sk_r, enc)
  let kem_context = @core.bytes_concat(enc, pk_r)
  extract_and_expand(kem_id, dh, kem_context)
}

///|
pub fn kem_auth_encap_deterministic(
  kem_id : KemId,
  pk_r : Bytes,
  sk_s : Bytes,
  sk_e : Bytes,
) -> (Bytes, Bytes) raise @core.CoreError {
  let pk_e = kem_derive_public_key(kem_id, sk_e)
  let pk_s = kem_derive_public_key(kem_id, sk_s)
  let dh1 = kem_dh(kem_id, sk_e, pk_r)
  let dh2 = kem_dh(kem_id, sk_s, pk_r)
  let dh = @core.bytes_concat(dh1, dh2)
  let kem_context = @core.bytes_concat_all([pk_e, pk_r, pk_s])
  let shared_secret = extract_and_expand(kem_id, dh, kem_context)
  (shared_secret, pk_e)
}

///|
pub fn kem_auth_decap(
  kem_id : KemId,
  enc : Bytes,
  sk_r : Bytes,
  pk_s : Bytes,
) -> Bytes raise @core.CoreError {
  let pk_r = kem_derive_public_key(kem_id, sk_r)
  let dh1 = kem_dh(kem_id, sk_r, enc)
  let dh2 = kem_dh(kem_id, sk_r, pk_s)
  let dh = @core.bytes_concat(dh1, dh2)
  let kem_context = @core.bytes_concat_all([enc, pk_r, pk_s])
  extract_and_expand(kem_id, dh, kem_context)
}
