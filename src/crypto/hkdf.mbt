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
pub fn hkdf_extract_sha256(salt : Bytes, ikm : Bytes) -> Bytes {
  let s = if salt.length() == 0 { Bytes::make(32, b'\x00') } else { salt }
  hmac_sha256(s, ikm)
}

///|
pub fn hkdf_expand_sha256(prk : Bytes, info : Bytes, length : Int) -> Bytes {
  let hash_len = 32
  let n = (length + hash_len - 1) / hash_len
  let okm : FixedArray[Byte] = FixedArray::make(length, b'\x00')

  let mut prev = Bytes::make(0, b'\x00')
  let mut bytes_written = 0

  for i = 1; i <= n; i = i + 1 {
    let counter_byte = Bytes::make(1, i.to_byte())
    let msg = @core.bytes_concat_all([prev, info, counter_byte])
    let t = hmac_sha256(prk, msg)
    let to_copy = if bytes_written + hash_len <= length {
      hash_len
    } else {
      length - bytes_written
    }
    for j in 0..<to_copy {
      okm[bytes_written + j] = t[j]
    }
    bytes_written += to_copy
    prev = t
  }

  Bytes::from_array(okm[:])
}

///|
pub fn hkdf_sha256(
  salt : Bytes,
  ikm : Bytes,
  info : Bytes,
  length : Int,
) -> Bytes {
  let prk = hkdf_extract_sha256(salt, ikm)
  hkdf_expand_sha256(prk, info, length)
}

///|
pub fn hkdf_extract_sha384(salt : Bytes, ikm : Bytes) -> Bytes {
  let s = if salt.length() == 0 { Bytes::make(48, b'\x00') } else { salt }
  hmac_sha384(s, ikm)
}

///|
pub fn hkdf_expand_sha384(prk : Bytes, info : Bytes, length : Int) -> Bytes {
  let hash_len = 48
  let n = (length + hash_len - 1) / hash_len
  let okm : FixedArray[Byte] = FixedArray::make(length, b'\x00')

  let mut prev = Bytes::make(0, b'\x00')
  let mut bytes_written = 0

  for i = 1; i <= n; i = i + 1 {
    let counter_byte = Bytes::make(1, i.to_byte())
    let msg = @core.bytes_concat_all([prev, info, counter_byte])
    let t = hmac_sha384(prk, msg)
    let to_copy = if bytes_written + hash_len <= length {
      hash_len
    } else {
      length - bytes_written
    }
    for j in 0..<to_copy {
      okm[bytes_written + j] = t[j]
    }
    bytes_written += to_copy
    prev = t
  }

  Bytes::from_array(okm[:])
}

///|
pub fn hkdf_sha384(
  salt : Bytes,
  ikm : Bytes,
  info : Bytes,
  length : Int,
) -> Bytes {
  let prk = hkdf_extract_sha384(salt, ikm)
  hkdf_expand_sha384(prk, info, length)
}

///|
pub fn hkdf_extract_sha512(salt : Bytes, ikm : Bytes) -> Bytes {
  let s = if salt.length() == 0 { Bytes::make(64, b'\x00') } else { salt }
  hmac_sha512(s, ikm)
}

///|
pub fn hkdf_expand_sha512(prk : Bytes, info : Bytes, length : Int) -> Bytes {
  let hash_len = 64
  let n = (length + hash_len - 1) / hash_len
  let okm : FixedArray[Byte] = FixedArray::make(length, b'\x00')

  let mut prev = Bytes::make(0, b'\x00')
  let mut bytes_written = 0

  for i = 1; i <= n; i = i + 1 {
    let counter_byte = Bytes::make(1, i.to_byte())
    let msg = @core.bytes_concat_all([prev, info, counter_byte])
    let t = hmac_sha512(prk, msg)
    let to_copy = if bytes_written + hash_len <= length {
      hash_len
    } else {
      length - bytes_written
    }
    for j in 0..<to_copy {
      okm[bytes_written + j] = t[j]
    }
    bytes_written += to_copy
    prev = t
  }

  Bytes::from_array(okm[:])
}

///|
pub fn hkdf_sha512(
  salt : Bytes,
  ikm : Bytes,
  info : Bytes,
  length : Int,
) -> Bytes {
  let prk = hkdf_extract_sha512(salt, ikm)
  hkdf_expand_sha512(prk, info, length)
}
