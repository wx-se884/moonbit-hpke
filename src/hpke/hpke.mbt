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
pub fn hpke_seal_base_deterministic(
  suite : HpkeSuite,
  pk_r : Bytes,
  info : Bytes,
  aad : Bytes,
  pt : Bytes,
  sk_e : Bytes,
) -> (Bytes, Bytes) raise @core.CoreError {
  let (enc, ctx) = hpke_setup_base_s_deterministic(suite, pk_r, info, sk_e)
  let ct = ctx.seal(pt, aad)
  (enc, ct)
}

///|
pub fn hpke_open_base(
  suite : HpkeSuite,
  enc : Bytes,
  sk_r : Bytes,
  info : Bytes,
  aad : Bytes,
  ct : Bytes,
) -> Bytes raise @core.CoreError {
  let ctx = hpke_setup_base_r(suite, enc, sk_r, info)
  ctx.open(ct, aad)
}

///|
pub fn hpke_seal_auth_deterministic(
  suite : HpkeSuite,
  pk_r : Bytes,
  info : Bytes,
  aad : Bytes,
  pt : Bytes,
  sk_s : Bytes,
  sk_e : Bytes,
) -> (Bytes, Bytes) raise @core.CoreError {
  let (enc, ctx) = hpke_setup_auth_s_deterministic(
    suite, pk_r, info, sk_s, sk_e,
  )
  let ct = ctx.seal(pt, aad)
  (enc, ct)
}

///|
pub fn hpke_open_auth(
  suite : HpkeSuite,
  enc : Bytes,
  sk_r : Bytes,
  info : Bytes,
  aad : Bytes,
  ct : Bytes,
  pk_s : Bytes,
) -> Bytes raise @core.CoreError {
  let ctx = hpke_setup_auth_r(suite, enc, sk_r, info, pk_s)
  ctx.open(ct, aad)
}

///|
pub fn hpke_seal_psk_deterministic(
  suite : HpkeSuite,
  pk_r : Bytes,
  info : Bytes,
  aad : Bytes,
  pt : Bytes,
  psk : Bytes,
  psk_id : Bytes,
  sk_e : Bytes,
) -> (Bytes, Bytes) raise @core.CoreError {
  let (enc, ctx) = hpke_setup_psk_s_deterministic(
    suite, pk_r, info, psk, psk_id, sk_e,
  )
  let ct = ctx.seal(pt, aad)
  (enc, ct)
}

///|
pub fn hpke_open_psk(
  suite : HpkeSuite,
  enc : Bytes,
  sk_r : Bytes,
  info : Bytes,
  aad : Bytes,
  ct : Bytes,
  psk : Bytes,
  psk_id : Bytes,
) -> Bytes raise @core.CoreError {
  let ctx = hpke_setup_psk_r(suite, enc, sk_r, info, psk, psk_id)
  ctx.open(ct, aad)
}

///|
pub fn hpke_seal_auth_psk_deterministic(
  suite : HpkeSuite,
  pk_r : Bytes,
  info : Bytes,
  aad : Bytes,
  pt : Bytes,
  sk_s : Bytes,
  sk_e : Bytes,
  psk : Bytes,
  psk_id : Bytes,
) -> (Bytes, Bytes) raise @core.CoreError {
  let (enc, ctx) = hpke_setup_auth_psk_s_deterministic(
    suite, pk_r, info, sk_s, sk_e, psk, psk_id,
  )
  let ct = ctx.seal(pt, aad)
  (enc, ct)
}

///|
pub fn hpke_open_auth_psk(
  suite : HpkeSuite,
  enc : Bytes,
  sk_r : Bytes,
  info : Bytes,
  aad : Bytes,
  ct : Bytes,
  pk_s : Bytes,
  psk : Bytes,
  psk_id : Bytes,
) -> Bytes raise @core.CoreError {
  let ctx = hpke_setup_auth_psk_r(suite, enc, sk_r, info, pk_s, psk, psk_id)
  ctx.open(ct, aad)
}
