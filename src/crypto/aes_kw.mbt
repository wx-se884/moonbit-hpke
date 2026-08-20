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
pub fn aes_key_wrap(
  kek : Bytes,
  plaintext_key : Bytes,
) -> Bytes raise @core.CoreError {
  let n = plaintext_key.length() / 8
  if plaintext_key.length() % 8 != 0 || n < 2 {
    raise CryptoError(
      "Plaintext key length must be multiple of 8 bytes and at least 16 bytes",
    )
  }

  let aes = AesKey::new(kek)
  let mut a = 0xa6a6a6a6a6a6a6a6UL
  let r : FixedArray[UInt64] = FixedArray::make(n, 0UL)
  for i in 0..<n {
    r[i] = @core.get_u64_be(plaintext_key, i * 8)
  }

  let mut t = 1UL
  for j = 0; j < 6; j = j + 1 {
    for i = 0; i < n; i = i + 1 {
      let b : FixedArray[Byte] = FixedArray::make(16, b'\x00')
      for k in 0..<8 {
        b[k] = ((a >> ((7 - k) * 8)) & 0xFFUL).to_byte()
        b[8 + k] = ((r[i] >> ((7 - k) * 8)) & 0xFFUL).to_byte()
      }
      let enc = aes.encrypt_block(Bytes::from_array(b[:]), 0)
      let b_hi = @core.get_u64_be(enc, 0)
      let b_lo = @core.get_u64_be(enc, 8)
      a = b_hi ^ t
      r[i] = b_lo
      t += 1UL
    }
  }

  let out : FixedArray[Byte] = FixedArray::make((n + 1) * 8, b'\x00')
  for k in 0..<8 {
    out[k] = ((a >> ((7 - k) * 8)) & 0xFFUL).to_byte()
  }
  for i in 0..<n {
    for k in 0..<8 {
      out[(i + 1) * 8 + k] = ((r[i] >> ((7 - k) * 8)) & 0xFFUL).to_byte()
    }
  }
  Bytes::from_array(out[:])
}

///|
pub fn aes_key_unwrap(
  kek : Bytes,
  ciphertext : Bytes,
) -> Bytes raise @core.CoreError {
  if ciphertext.length() % 8 != 0 || ciphertext.length() < 24 {
    raise CryptoError(
      "Ciphertext length must be a multiple of 8 bytes and at least 24 bytes",
    )
  }
  let n = ciphertext.length() / 8 - 1
  let aes = AesKey::new(kek)

  let mut a = @core.get_u64_be(ciphertext, 0)
  let r : FixedArray[UInt64] = FixedArray::make(n, 0UL)
  for i in 0..<n {
    r[i] = @core.get_u64_be(ciphertext, (i + 1) * 8)
  }

  for j = 5; j >= 0; j = j - 1 {
    for i = n - 1; i >= 0; i = i - 1 {
      let t = (n * j + (i + 1)).to_uint64()
      let b_hi = a ^ t
      let b_lo = r[i]

      let b : FixedArray[Byte] = FixedArray::make(16, b'\x00')
      for k in 0..<8 {
        b[k] = ((b_hi >> ((7 - k) * 8)) & 0xFFUL).to_byte()
        b[8 + k] = ((b_lo >> ((7 - k) * 8)) & 0xFFUL).to_byte()
      }
      let dec = aes.decrypt_block(Bytes::from_array(b[:]), 0)
      a = @core.get_u64_be(dec, 0)
      r[i] = @core.get_u64_be(dec, 8)
    }
  }

  if a != 0xa6a6a6a6a6a6a6a6UL {
    raise CryptoError("AES key unwrap integrity check failed")
  }

  let out : FixedArray[Byte] = FixedArray::make(n * 8, b'\x00')
  for i in 0..<n {
    for k in 0..<8 {
      out[i * 8 + k] = ((r[i] >> ((7 - k) * 8)) & 0xFFUL).to_byte()
    }
  }
  Bytes::from_array(out[:])
}
