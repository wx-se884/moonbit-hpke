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
pub(all) struct HpkeSuite {
  kem : KemId
  kdf : KdfId
  aead : AeadId
} derive(Debug, Eq)

///|
pub fn hpke_suite_id(suite : HpkeSuite) -> Bytes {
  let hpke_tag = @core.string_to_utf8_bytes("HPKE")
  let kem_bytes = @core.put_u16_be(suite.kem.value())
  let kdf_bytes = @core.put_u16_be(suite.kdf.value())
  let aead_bytes = @core.put_u16_be(suite.aead.value())
  @core.bytes_concat_all([hpke_tag, kem_bytes, kdf_bytes, aead_bytes])
}

///|
pub(all) struct HpkeContext {
  suite : HpkeSuite
  key : Bytes
  base_nonce : Bytes
  exporter_secret : Bytes
  mut seq : UInt64
}

///|
pub fn hpke_compute_nonce(base_nonce : Bytes, seq : UInt64) -> Bytes {
  let n_n = base_nonce.length()
  let seq_bytes = @core.put_u64_be(seq)
  let fa : FixedArray[Byte] = FixedArray::make(n_n, b'\x00')

  let offset = n_n - 8
  for i in 0..<n_n {
    if i < offset {
      fa[i] = base_nonce[i]
    } else {
      let b = seq_bytes[i - offset]
      fa[i] = (base_nonce[i].to_int() ^ b.to_int()).to_byte()
    }
  }
  Bytes::from_array(fa[:])
}

///|
pub fn HpkeContext::seal(
  self : HpkeContext,
  plaintext : Bytes,
  aad : Bytes,
) -> Bytes raise @core.CoreError {
  let nonce = hpke_compute_nonce(self.base_nonce, self.seq)
  let ct = aead_seal(self.suite.aead, self.key, nonce, plaintext, aad)
  self.seq += 1UL
  ct
}

///|
pub fn HpkeContext::open(
  self : HpkeContext,
  ciphertext : Bytes,
  aad : Bytes,
) -> Bytes raise @core.CoreError {
  let nonce = hpke_compute_nonce(self.base_nonce, self.seq)
  let pt = aead_open(self.suite.aead, self.key, nonce, ciphertext, aad)
  self.seq += 1UL
  pt
}

///|
pub fn HpkeContext::export_key(
  self : HpkeContext,
  exporter_context : Bytes,
  length : Int,
) -> Bytes {
  let suite_id = hpke_suite_id(self.suite)
  kdf_labeled_expand(
    self.suite.kdf,
    suite_id,
    self.exporter_secret,
    "sec",
    exporter_context,
    length,
  )
}
