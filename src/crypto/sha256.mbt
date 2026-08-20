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
let k256 : FixedArray[UInt] = [
  0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U, 0x923f82a4U,
  0xab1c5ed5U, 0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU,
  0x9bdc06a7U, 0xc19bf174U, 0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU,
  0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU, 0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
  0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U, 0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU,
  0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U, 0xa2bfe8a1U, 0xa81a664bU,
  0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U, 0x19a4c116U,
  0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
  0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU, 0xa4506cebU, 0xbef9a3f7U,
  0xc67178f2U,
]

///|
fn rotr32(x : UInt, n : Int) -> UInt {
  (x >> n) | (x << (32 - n))
}

///|
pub fn sha256(data : Bytes) -> Bytes {
  let mut h0 = 0x6a09e667U
  let mut h1 = 0xbb67ae85U
  let mut h2 = 0x3c6ef372U
  let mut h3 = 0xa54ff53aU
  let mut h4 = 0x510e527fU
  let mut h5 = 0x9b05688cU
  let mut h6 = 0x1f83d9abU
  let mut h7 = 0x5be0cd19U

  let bit_len = data.length().to_uint64() * 8UL
  let pad_len = ((56 - (data.length() + 1) % 64) % 64 + 64) % 64
  let total_len = data.length() + 1 + pad_len + 8

  let fa : FixedArray[Byte] = FixedArray::make(total_len, b'\x00')
  for i in 0..<data.length() {
    fa[i] = data[i]
  }
  fa[data.length()] = b'\x80'

  for i in 0..<8 {
    let shift = (7 - i) * 8
    fa[total_len - 8 + i] = ((bit_len >> shift) & 0xFFUL).to_byte()
  }

  let w : FixedArray[UInt] = FixedArray::make(64, 0U)
  let blocks = total_len / 64

  for b = 0; b < blocks; b = b + 1 {
    let offset = b * 64
    for i in 0..<16 {
      let idx = offset + i * 4
      w[i] = (fa[idx].to_uint() << 24) |
        (fa[idx + 1].to_uint() << 16) |
        (fa[idx + 2].to_uint() << 8) |
        fa[idx + 3].to_uint()
    }
    for i in 16..<64 {
      let s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3)
      let s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10)
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

    for i in 0..<64 {
      let s1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25)
      let ch = (e & f) ^ ((e ^ 0xFFFFFFFFU) & g)
      let temp1 = h + s1 + ch + k256[i] + w[i]
      let s0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22)
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

  let out : FixedArray[Byte] = FixedArray::make(32, b'\x00')
  let state = [h0, h1, h2, h3, h4, h5, h6, h7]
  for i in 0..<8 {
    out[i * 4] = ((state[i] >> 24) & 0xFFU).to_byte()
    out[i * 4 + 1] = ((state[i] >> 16) & 0xFFU).to_byte()
    out[i * 4 + 2] = ((state[i] >> 8) & 0xFFU).to_byte()
    out[i * 4 + 3] = (state[i] & 0xFFU).to_byte()
  }
  Bytes::from_array(out[:])
}
