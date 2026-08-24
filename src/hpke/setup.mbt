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
fn key_schedule(
  suite : HpkeSuite,
  mode : Int,
  shared_secret : Bytes,
  info : Bytes,
  psk : Bytes,
  psk_id : Bytes,
) -> HpkeContext {
  let suite_id = hpke_suite_id(suite)
  let psk_id_hash = kdf_labeled_extract(
    suite.kdf,
    suite_id,
    Bytes::make(0, b'\x00'),
    "psk_id_hash",
    psk_id,
  )
  let info_hash = kdf_labeled_extract(
    suite.kdf,
    suite_id,
    Bytes::make(0, b'\x00'),
    "info_hash",
    info,
  )
  let mode_byte = Bytes::make(1, mode.to_byte())
  let key_schedule_context = @core.bytes_concat_all([
    mode_byte, psk_id_hash, info_hash,
  ])

  let secret = kdf_labeled_extract(
    suite.kdf,
    suite_id,
    shared_secret,
    "secret",
    psk,
  )

  let key = if suite.aead == EXPORT_ONLY {
    Bytes::make(0, b'\x00')
  } else {
    kdf_labeled_expand(
      suite.kdf,
      suite_id,
      secret,
      "key",
      key_schedule_context,
      suite.aead.n_k(),
    )
  }

  let base_nonce = if suite.aead == EXPORT_ONLY {
    Bytes::make(0, b'\x00')
  } else {
    kdf_labeled_expand(
      suite.kdf,
      suite_id,
      secret,
      "base_nonce",
      key_schedule_context,
      suite.aead.n_n(),
    )
  }

  let exporter_secret = kdf_labeled_expand(
    suite.kdf,
    suite_id,
    secret,
    "exp",
    key_schedule_context,
    suite.kdf.n_h(),
  )

  { suite, key, base_nonce, exporter_secret, seq: 0UL }
}

///|
pub fn hpke_setup_base_s_deterministic(
  suite : HpkeSuite,
  pk_r : Bytes,
  info : Bytes,
  sk_e : Bytes,
) -> (Bytes, HpkeContext) raise @core.CoreError {
  let (shared_secret, enc) = kem_encap_deterministic(suite.kem, pk_r, sk_e)
  let ctx = key_schedule(
    suite,
    0,
    shared_secret,
    info,
    Bytes::make(0, b'\x00'),
    Bytes::make(0, b'\x00'),
  )
  (enc, ctx)
}

///|
pub fn hpke_setup_base_r(
  suite : HpkeSuite,
  enc : Bytes,
  sk_r : Bytes,
  info : Bytes,
) -> HpkeContext raise @core.CoreError {
  let shared_secret = kem_decap(suite.kem, enc, sk_r)
  key_schedule(
    suite,
    0,
    shared_secret,
    info,
    Bytes::make(0, b'\x00'),
    Bytes::make(0, b'\x00'),
  )
}

///|
pub fn hpke_setup_auth_s_deterministic(
  suite : HpkeSuite,
  pk_r : Bytes,
  info : Bytes,
  sk_s : Bytes,
  sk_e : Bytes,
) -> (Bytes, HpkeContext) raise @core.CoreError {
  let (shared_secret, enc) = kem_auth_encap_deterministic(
    suite.kem,
    pk_r,
    sk_s,
    sk_e,
  )
  let ctx = key_schedule(
    suite,
    2,
    shared_secret,
    info,
    Bytes::make(0, b'\x00'),
    Bytes::make(0, b'\x00'),
  )
  (enc, ctx)
}

///|
pub fn hpke_setup_auth_r(
  suite : HpkeSuite,
  enc : Bytes,
  sk_r : Bytes,
  info : Bytes,
  pk_s : Bytes,
) -> HpkeContext raise @core.CoreError {
  let shared_secret = kem_auth_decap(suite.kem, enc, sk_r, pk_s)
  key_schedule(
    suite,
    2,
    shared_secret,
    info,
    Bytes::make(0, b'\x00'),
    Bytes::make(0, b'\x00'),
  )
}

///|
pub fn hpke_setup_psk_s_deterministic(
  suite : HpkeSuite,
  pk_r : Bytes,
  info : Bytes,
  psk : Bytes,
  psk_id : Bytes,
  sk_e : Bytes,
) -> (Bytes, HpkeContext) raise @core.CoreError {
  let (shared_secret, enc) = kem_encap_deterministic(suite.kem, pk_r, sk_e)
  let ctx = key_schedule(suite, 1, shared_secret, info, psk, psk_id)
  (enc, ctx)
}

///|
pub fn hpke_setup_psk_r(
  suite : HpkeSuite,
  enc : Bytes,
  sk_r : Bytes,
  info : Bytes,
  psk : Bytes,
  psk_id : Bytes,
) -> HpkeContext raise @core.CoreError {
  let shared_secret = kem_decap(suite.kem, enc, sk_r)
  key_schedule(suite, 1, shared_secret, info, psk, psk_id)
}

///|
pub fn hpke_setup_auth_psk_s_deterministic(
  suite : HpkeSuite,
  pk_r : Bytes,
  info : Bytes,
  sk_s : Bytes,
  sk_e : Bytes,
  psk : Bytes,
  psk_id : Bytes,
) -> (Bytes, HpkeContext) raise @core.CoreError {
  let (shared_secret, enc) = kem_auth_encap_deterministic(
    suite.kem,
    pk_r,
    sk_s,
    sk_e,
  )
  let ctx = key_schedule(suite, 3, shared_secret, info, psk, psk_id)
  (enc, ctx)
}

///|
pub fn hpke_setup_auth_psk_r(
  suite : HpkeSuite,
  enc : Bytes,
  sk_r : Bytes,
  info : Bytes,
  pk_s : Bytes,
  psk : Bytes,
  psk_id : Bytes,
) -> HpkeContext raise @core.CoreError {
  let shared_secret = kem_auth_decap(suite.kem, enc, sk_r, pk_s)
  key_schedule(suite, 3, shared_secret, info, psk, psk_id)
}
