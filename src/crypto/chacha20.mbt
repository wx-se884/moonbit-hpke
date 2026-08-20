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
fn rotl32(x : UInt, n : Int) -> UInt {
  (x << n) | (x >> (32 - n))
}

///|
fn quarter_round(
  state : FixedArray[UInt],
  a : Int,
  b : Int,
  c : Int,
  d : Int,
) -> Unit {
  state[a] = state[a] + state[b]
  state[d] = rotl32(state[d] ^ state[a], 16)

  state[c] = state[c] + state[d]
  state[b] = rotl32(state[b] ^ state[c], 12)

  state[a] = state[a] + state[b]
  state[d] = rotl32(state[d] ^ state[a], 8)

  state[c] = state[c] + state[d]
  state[b] = rotl32(state[b] ^ state[c], 7)
}

///|
pub fn chacha20_block(
  key : Bytes,
  counter : UInt,
  nonce : Bytes,
) -> Bytes raise @core.CoreError {
  if key.length() != 32 {
    raise CryptoError("ChaCha20 key must be 32 bytes")
  }
  if nonce.length() != 12 {
    raise CryptoError("ChaCha20 nonce must be 12 bytes")
  }

  let state : FixedArray[UInt] = FixedArray::make(16, 0U)
  state[0] = 0x61707865U
  state[1] = 0x3320646eU
  state[2] = 0x79622d32U
  state[3] = 0x6b206574U

  for i in 0..<8 {
    state[4 + i] = @core.get_u32_le(key, i * 4)
  }
  state[12] = counter
  for i in 0..<3 {
    state[13 + i] = @core.get_u32_le(nonce, i * 4)
  }

  let working : FixedArray[UInt] = FixedArray::make(16, 0U)
  for i in 0..<16 {
    working[i] = state[i]
  }

  for r = 0; r < 10; r = r + 1 {
    quarter_round(working, 0, 4, 8, 12)
    quarter_round(working, 1, 5, 9, 13)
    quarter_round(working, 2, 6, 10, 14)
    quarter_round(working, 3, 7, 11, 15)

    quarter_round(working, 0, 5, 10, 15)
    quarter_round(working, 1, 6, 11, 12)
    quarter_round(working, 2, 7, 8, 13)
    quarter_round(working, 3, 4, 9, 14)
  }

  let fa : FixedArray[Byte] = FixedArray::make(64, b'\x00')
  for i in 0..<16 {
    let word = working[i] + state[i]
    let offset = i * 4
    fa[offset] = (word & 0xFFU).to_byte()
    fa[offset + 1] = ((word >> 8) & 0xFFU).to_byte()
    fa[offset + 2] = ((word >> 16) & 0xFFU).to_byte()
    fa[offset + 3] = ((word >> 24) & 0xFFU).to_byte()
  }
  Bytes::from_array(fa[:])
}

///|
pub fn chacha20_process(
  key : Bytes,
  counter : UInt,
  nonce : Bytes,
  data : Bytes,
) -> Bytes raise @core.CoreError {
  let len = data.length()
  let fa : FixedArray[Byte] = FixedArray::make(len, b'\x00')
  let blocks = (len + 63) / 64
  let mut cur_counter = counter

  for b = 0; b < blocks; b = b + 1 {
    let key_stream = chacha20_block(key, cur_counter, nonce)
    cur_counter += 1U
    let offset = b * 64
    let chunk_len = if offset + 64 <= len { 64 } else { len - offset }
    for i in 0..<chunk_len {
      fa[offset + i] = (data[offset + i].to_int() ^ key_stream[i].to_int()).to_byte()
    }
  }

  Bytes::from_array(fa[:])
}
