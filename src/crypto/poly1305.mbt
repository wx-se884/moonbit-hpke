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
pub fn poly1305_mac(key : Bytes, msg : Bytes) -> Bytes raise @core.CoreError {
  if key.length() != 32 {
    raise CryptoError("Poly1305 key must be 32 bytes")
  }

  // Clamp r: r &= 0x0ffffffc0ffffffc0ffffffc0fffffff
  let r_fa : FixedArray[Byte] = FixedArray::make(16, b'\x00')
  for i in 0..<16 {
    r_fa[i] = key[i]
  }
  r_fa[3] = (r_fa[3].to_int() & 15).to_byte()
  r_fa[7] = (r_fa[7].to_int() & 15).to_byte()
  r_fa[11] = (r_fa[11].to_int() & 15).to_byte()
  r_fa[15] = (r_fa[15].to_int() & 15).to_byte()
  r_fa[4] = (r_fa[4].to_int() & 252).to_byte()
  r_fa[8] = (r_fa[8].to_int() & 252).to_byte()
  r_fa[12] = (r_fa[12].to_int() & 252).to_byte()

  // r limbs in 26-bit representation
  let r0 = (
      r_fa[0].to_uint64() |
      (r_fa[1].to_uint64() << 8) |
      (r_fa[2].to_uint64() << 16) |
      (r_fa[3].to_uint64() << 24)
    ) &
    0x3ffffffUL
  let r1 = (
      (r_fa[3].to_uint64() >> 2) |
      (r_fa[4].to_uint64() << 6) |
      (r_fa[5].to_uint64() << 14) |
      (r_fa[6].to_uint64() << 22)
    ) &
    0x3ffff03UL
  let r2 = (
      (r_fa[6].to_uint64() >> 4) |
      (r_fa[7].to_uint64() << 4) |
      (r_fa[8].to_uint64() << 12) |
      (r_fa[9].to_uint64() << 20)
    ) &
    0x3ffc0ffUL
  let r3 = (
      (r_fa[9].to_uint64() >> 6) |
      (r_fa[10].to_uint64() << 2) |
      (r_fa[11].to_uint64() << 10) |
      (r_fa[12].to_uint64() << 18)
    ) &
    0x3f03fffUL
  let r4 = (
      (r_fa[12].to_uint64() >> 8) |
      (r_fa[13].to_uint64() << 0) |
      (r_fa[14].to_uint64() << 8) |
      (r_fa[15].to_uint64() << 16)
    ) &
    0x00fffffUL

  let s1 = r1 * 5UL
  let s2 = r2 * 5UL
  let s3 = r3 * 5UL
  let s4 = r4 * 5UL

  let mut h0 = 0UL
  let mut h1 = 0UL
  let mut h2 = 0UL
  let mut h3 = 0UL
  let mut h4 = 0UL

  let len = msg.length()
  let mut offset = 0

  while offset < len {
    let chunk_len = if offset + 16 <= len { 16 } else { len - offset }
    let block : FixedArray[Byte] = FixedArray::make(17, b'\x00')
    for i in 0..<chunk_len {
      block[i] = msg[offset + i]
    }
    block[chunk_len] = b'\x01' // append high bit

    let w0 = (
        block[0].to_uint64() |
        (block[1].to_uint64() << 8) |
        (block[2].to_uint64() << 16) |
        (block[3].to_uint64() << 24)
      ) &
      0x3ffffffUL
    let w1 = (
        (block[3].to_uint64() >> 2) |
        (block[4].to_uint64() << 6) |
        (block[5].to_uint64() << 14) |
        (block[6].to_uint64() << 22)
      ) &
      0x3ffffffUL
    let w2 = (
        (block[6].to_uint64() >> 4) |
        (block[7].to_uint64() << 4) |
        (block[8].to_uint64() << 12) |
        (block[9].to_uint64() << 20)
      ) &
      0x3ffffffUL
    let w3 = (
        (block[9].to_uint64() >> 6) |
        (block[10].to_uint64() << 2) |
        (block[11].to_uint64() << 10) |
        (block[12].to_uint64() << 18)
      ) &
      0x3ffffffUL
    let w4 = (block[12].to_uint64() >> 8) |
      (block[13].to_uint64() << 0) |
      (block[14].to_uint64() << 8) |
      (block[15].to_uint64() << 16) |
      (block[16].to_uint64() << 24)

    h0 += w0
    h1 += w1
    h2 += w2
    h3 += w3
    h4 += w4

    let d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1
    let d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2
    let d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3
    let d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4
    let d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0

    let mut c = d0 >> 26
    h0 = d0 & 0x3ffffffUL
    let d1_carry = d1 + c
    c = d1_carry >> 26
    h1 = d1_carry & 0x3ffffffUL
    let d2_carry = d2 + c
    c = d2_carry >> 26
    h2 = d2_carry & 0x3ffffffUL
    let d3_carry = d3 + c
    c = d3_carry >> 26
    h3 = d3_carry & 0x3ffffffUL
    let d4_carry = d4 + c
    c = d4_carry >> 26
    h4 = d4_carry & 0x3ffffffUL
    h0 += c * 5UL
    c = h0 >> 26
    h0 = h0 & 0x3ffffffUL
    h1 += c

    offset += 16
  }

  // Full carry
  let mut c = h1 >> 26
  h1 = h1 & 0x3ffffffUL
  h2 += c
  c = h2 >> 26
  h2 = h2 & 0x3ffffffUL
  h3 += c
  c = h3 >> 26
  h3 = h3 & 0x3ffffffUL
  h4 += c
  c = h4 >> 26
  h4 = h4 & 0x3ffffffUL
  h0 += c * 5UL
  c = h0 >> 26
  h0 = h0 & 0x3ffffffUL
  h1 += c

  // Compute h + -p = h + 5 - 2^130
  let g0 = h0 + 5UL
  c = g0 >> 26
  let mask_g0 = g0 & 0x3ffffffUL
  let g1 = h1 + c
  c = g1 >> 26
  let mask_g1 = g1 & 0x3ffffffUL
  let g2 = h2 + c
  c = g2 >> 26
  let mask_g2 = g2 & 0x3ffffffUL
  let g3 = h3 + c
  c = g3 >> 26
  let mask_g3 = g3 & 0x3ffffffUL
  let g4 = h4 + c - (1UL << 26)

  let mask = (g4 >> 63) - 1UL
  let not_mask = mask ^ 0xFFFFFFFFFFFFFFFFUL

  h0 = (h0 & not_mask) | (mask_g0 & mask)
  h1 = (h1 & not_mask) | (mask_g1 & mask)
  h2 = (h2 & not_mask) | (mask_g2 & mask)
  h3 = (h3 & not_mask) | (mask_g3 & mask)
  h4 = (h4 & not_mask) | ((g4 + (1UL << 26)) & mask)

  // Convert to 128-bit integer
  let t0 = (h0 | (h1 << 26) | (h2 << 52)) & 0xFFFFFFFFFFFFFFFFUL
  let t1 = ((h2 >> 12) | (h3 << 14) | (h4 << 40)) & 0xFFFFFFFFFFFFFFFFUL

  // Add s (key[16..32])
  let s_lo = @core.get_u64_le(key, 16)
  let s_hi = @core.get_u64_le(key, 24)

  let final_lo = t0 + s_lo
  let carry = if final_lo < t0 { 1UL } else { 0UL }
  let final_hi = t1 + s_hi + carry

  let out : FixedArray[Byte] = FixedArray::make(16, b'\x00')
  for i in 0..<8 {
    out[i] = ((final_lo >> (i * 8)) & 0xFFUL).to_byte()
    out[8 + i] = ((final_hi >> (i * 8)) & 0xFFUL).to_byte()
  }

  Bytes::from_array(out[:])
}
