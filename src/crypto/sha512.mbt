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
let k512 : FixedArray[UInt64] = [
  0x428a2f98d728ae22UL, 0x7137449123ef65cdUL, 0xb5c0fbcfec4d3b2fUL, 0xe9b5dba58189dbbcUL,
  0x3956c25bf348b538UL, 0x59f111f1b605d019UL, 0x923f82a4af194f9bUL, 0xab1c5ed5da6d8118UL,
  0xd807aa98a3030242UL, 0x12835b0145706fbeUL, 0x243185be4ee4b28cUL, 0x550c7dc3d5ffb4e2UL,
  0x72be5d74f27b896fUL, 0x80deb1fe3b1696b1UL, 0x9bdc06a725c71235UL, 0xc19bf174cf692694UL,
  0xe49b69c19ef14ad2UL, 0xefbe4786384f25e3UL, 0x0fc19dc68b8cd5b5UL, 0x240ca1cc77ac9c65UL,
  0x2de92c6f592b0275UL, 0x4a7484aa6ea6e483UL, 0x5cb0a9dcbd41fbd4UL, 0x76f988da831153b5UL,
  0x983e5152ee66dfabUL, 0xa831c66d2db43210UL, 0xb00327c898fb213fUL, 0xbf597fc7beef0ee4UL,
  0xc6e00bf33da88fc2UL, 0xd5a79147930aa725UL, 0x06ca6351e003826fUL, 0x142929670a0e6e70UL,
  0x27b70a8546d22ffcUL, 0x2e1b21385c26c926UL, 0x4d2c6dfc5ac42aedUL, 0x53380d139d95b3dfUL,
  0x650a73548baf63deUL, 0x766a0abb3c77b2a8UL, 0x81c2c92e47edaee6UL, 0x92722c851482353bUL,
  0xa2bfe8a14cf10364UL, 0xa81a664bbc423001UL, 0xc24b8b70d0f89791UL, 0xc76c51a30654be30UL,
  0xd192e819d6ef5218UL, 0xd69906245565a910UL, 0xf40e35855771202aUL, 0x106aa07032bbd1b8UL,
  0x19a4c116b8d2d0c8UL, 0x1e376c085141ab53UL, 0x2748774cdf8eeb99UL, 0x34b0bcb5e19b48a8UL,
  0x391c0cb3c5c95a63UL, 0x4ed8aa4ae3418acbUL, 0x5b9cca4f7763e373UL, 0x682e6ff3d6b2b8a3UL,
  0x748f82ee5defb2fcUL, 0x78a5636f43172f60UL, 0x84c87814a1f0ab72UL, 0x8cc702081a6439ecUL,
  0x90befffa23631e28UL, 0xa4506cebde82bde9UL, 0xbef9a3f7b2c67915UL, 0xc67178f2e372532bUL,
  0xca273eceea26619cUL, 0xd186b8c721c0c207UL, 0xeada7dd6cde0eb1eUL, 0xf57d4f7fee6ed178UL,
  0x06f067aa72176fbaUL, 0x0a637dc5a2c898a6UL, 0x113f9804bef90daeUL, 0x1b710b35131c471bUL,
  0x28db77f523047d84UL, 0x32caab7b40c72493UL, 0x3c9ebe0a15c9bebcUL, 0x431d67c49c100d4cUL,
  0x4cc5d4becb3e42b6UL, 0x597f299cfc657e2aUL, 0x5fcb6fab3ad6faecUL, 0x6c44198c4a475817UL,
]

///|
fn rotr64(x : UInt64, n : Int) -> UInt64 {
  (x >> n) | (x << (64 - n))
}

///|
pub fn sha512(data : Bytes) -> Bytes {
  let mut h0 = 0x6a09e667f3bcc908UL
  let mut h1 = 0xbb67ae8584caa73bUL
  let mut h2 = 0x3c6ef372fe94f82bUL
  let mut h3 = 0xa54ff53a5f1d36f1UL
  let mut h4 = 0x510e527fade682d1UL
  let mut h5 = 0x9b05688c2b3e6c1fUL
  let mut h6 = 0x1f83d9abfb41bd6bUL
  let mut h7 = 0x5be0cd19137e2179UL

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

  let out : FixedArray[Byte] = FixedArray::make(64, b'\x00')
  let state = [h0, h1, h2, h3, h4, h5, h6, h7]
  for i in 0..<8 {
    for j in 0..<8 {
      let shift = (7 - j) * 8
      out[i * 8 + j] = ((state[i] >> shift) & 0xFFUL).to_byte()
    }
  }
  Bytes::from_array(out[:])
}
