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
fn hmac_generic(
  key : Bytes,
  message : Bytes,
  block_size : Int,
  hash_fn : (Bytes) -> Bytes,
) -> Bytes {
  let k : Bytes = if key.length() > block_size { hash_fn(key) } else { key }

  let k_pad_len = block_size
  let ipad : FixedArray[Byte] = FixedArray::make(k_pad_len, b'\x36')
  let opad : FixedArray[Byte] = FixedArray::make(k_pad_len, b'\x5c')

  for i in 0..<k.length() {
    ipad[i] = (k[i].to_int() ^ 0x36).to_byte()
    opad[i] = (k[i].to_int() ^ 0x5c).to_byte()
  }

  let inner_msg = @core.bytes_concat(Bytes::from_array(ipad[:]), message)
  let inner_hash = hash_fn(inner_msg)

  let outer_msg = @core.bytes_concat(Bytes::from_array(opad[:]), inner_hash)
  hash_fn(outer_msg)
}

///|
pub fn hmac_sha256(key : Bytes, message : Bytes) -> Bytes {
  hmac_generic(key, message, 64, sha256)
}

///|
pub fn hmac_sha384(key : Bytes, message : Bytes) -> Bytes {
  hmac_generic(key, message, 128, sha384)
}

///|
pub fn hmac_sha512(key : Bytes, message : Bytes) -> Bytes {
  hmac_generic(key, message, 128, sha512)
}
