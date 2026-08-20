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
pub(all) enum KdfId {
  HKDF_SHA256
  HKDF_SHA384
  HKDF_SHA512
} derive(Debug, Eq)

///|
pub fn KdfId::value(self : KdfId) -> Int {
  match self {
    HKDF_SHA256 => 0x0001
    HKDF_SHA384 => 0x0002
    HKDF_SHA512 => 0x0003
  }
}

///|
pub fn KdfId::n_h(self : KdfId) -> Int {
  match self {
    HKDF_SHA256 => 32
    HKDF_SHA384 => 48
    HKDF_SHA512 => 64
  }
}

///|
pub fn kdf_extract(kdf_id : KdfId, salt : Bytes, ikm : Bytes) -> Bytes {
  match kdf_id {
    HKDF_SHA256 => @crypto.hkdf_extract_sha256(salt, ikm)
    HKDF_SHA384 => @crypto.hkdf_extract_sha384(salt, ikm)
    HKDF_SHA512 => @crypto.hkdf_extract_sha512(salt, ikm)
  }
}

///|
pub fn kdf_expand(
  kdf_id : KdfId,
  prk : Bytes,
  info : Bytes,
  length : Int,
) -> Bytes {
  match kdf_id {
    HKDF_SHA256 => @crypto.hkdf_expand_sha256(prk, info, length)
    HKDF_SHA384 => @crypto.hkdf_expand_sha384(prk, info, length)
    HKDF_SHA512 => @crypto.hkdf_expand_sha512(prk, info, length)
  }
}

///|
pub fn kdf_labeled_extract(
  kdf_id : KdfId,
  suite_id : Bytes,
  salt : Bytes,
  label : String,
  ikm : Bytes,
) -> Bytes {
  let prefix = @core.string_to_utf8_bytes("HPKE-v1")
  let label_bytes = @core.string_to_utf8_bytes(label)
  let full_ikm = @core.bytes_concat_all([prefix, suite_id, label_bytes, ikm])
  kdf_extract(kdf_id, salt, full_ikm)
}

///|
pub fn kdf_labeled_expand(
  kdf_id : KdfId,
  suite_id : Bytes,
  prk : Bytes,
  label : String,
  info : Bytes,
  length : Int,
) -> Bytes {
  let prefix = @core.string_to_utf8_bytes("HPKE-v1")
  let label_bytes = @core.string_to_utf8_bytes(label)
  let len_bytes = @core.put_u16_be(length)
  let full_info = @core.bytes_concat_all([
    len_bytes, prefix, suite_id, label_bytes, info,
  ])
  kdf_expand(kdf_id, prk, full_info, length)
}
