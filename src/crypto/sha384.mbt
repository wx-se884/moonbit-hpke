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
pub fn sha384(data : Bytes) -> Bytes {
  let mut h0 = 0xcbbb9d5dc1059ed8UL
  let mut h1 = 0x629a292a367cd507UL
  let mut h2 = 0x9159015a3070dd17UL
  let mut h3 = 0x152fecd8f70e5939UL
  let mut h4 = 0x67332667ffc00b31UL
  let mut h5 = 0x8eb44a8768581511UL
  let mut h6 = 0xdb0c2e0d64f98fa7UL
  let mut h7 = 0x47b5481dbefa4fa4UL

  let bit_len = data.length().to_uint64() * 8UL
  let pad_len = ((112 - (data.length() + 1) % 128) % 128 + 128) % 128
  let total_len = data.length() + 1 + pad_len + 16

  let fa : FixedArray[Byte] = FixedArray::make(total_len, b'\x00')
  for i in 0..<data.length() {
    fa[i] = data[i]
  }
  fa[data.length()] = b'\x80'

  for i in 0..<8 {
    let shift = (7 - i) * 8
    fa[total_len - 8 + i] = ((bit_len >> shift) & 0xFFUL).to_byte()
  }

  let w : FixedArray[UInt64] = FixedArray::make(80, 0UL)
  let blocks = total_len / 128

  for b = 0; b < blocks; b = b + 1 {
    let offset = b * 128
    for i in 0..<16 {
      let idx = offset + i * 8
      let mut val = 0UL
      for j in 0..<8 {
        val = (val << 8) | fa[idx + j].to_uint64()
      }
      w[i] = val
    }
    for i in 16..<80 {
      let s0 = rotr64(w[i - 15], 1) ^ rotr64(w[i - 15], 8) ^ (w[i - 15] >> 7)
      let s1 = rotr64(w[i - 2], 19) ^ rotr64(w[i - 2], 61) ^ (w[i - 2] >> 6)
      w[i] = w[i - 16] + s0 + w[i - 7] + s1
    }

    let mut a = h0
    let mut b_val = h1
    let mut c = h2
    let mut d = h3
    let mut e = h4
    let mut f = h5
    let mut g = h6
    let mut h = h7

    for i in 0..<80 {
      let s1 = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41)
      let ch = (e & f) ^ (e.lnot() & g)
      let temp1 = h + s1 + ch + k512[i] + w[i]
      let s0 = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39)
      let maj = (a & b_val) ^ (a & c) ^ (b_val & c)
      let temp2 = s0 + maj

      h = g
      g = f
      f = e
      e = d + temp1
      d = c
      c = b_val
      b_val = a
      a = temp1 + temp2
    }

    h0 += a
    h1 += b_val
    h2 += c
    h3 += d
    h4 += e
    h5 += f
    h6 += g
    h7 += h
  }

  let out : FixedArray[Byte] = FixedArray::make(48, b'\x00')
  let state = [h0, h1, h2, h3, h4, h5]
  for i in 0..<6 {
    for j in 0..<8 {
      let shift = (7 - j) * 8
      out[i * 8 + j] = ((state[i] >> shift) & 0xFFUL).to_byte()
    }
  }
  Bytes::from_array(out[:])
}
