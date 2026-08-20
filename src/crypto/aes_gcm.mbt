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
fn ghash_multiply(
  x_hi : UInt64,
  x_lo : UInt64,
  y_hi : UInt64,
  y_lo : UInt64,
) -> (UInt64, UInt64) {
  let mut z_hi = 0UL
  let mut z_lo = 0UL
  let mut v_hi = y_hi
  let mut v_lo = y_lo
  let r = 0xe100000000000000UL

  for i = 0; i < 128; i = i + 1 {
    let bit = if i < 64 {
      ((x_hi >> (63 - i)) & 1UL) != 0UL
    } else {
      ((x_lo >> (127 - i)) & 1UL) != 0UL
    }

    if bit {
      z_hi = z_hi ^ v_hi
      z_lo = z_lo ^ v_lo
    }

    let lsb = (v_lo & 1UL) != 0UL
    v_lo = (v_lo >> 1) | ((v_hi & 1UL) << 63)
    v_hi = v_hi >> 1
    if lsb {
      v_hi = v_hi ^ r
    }
  }

  (z_hi, z_lo)
}

///|
fn ghash(h : Bytes, data : Bytes) -> Bytes {
  let h_hi = @core.get_u64_be(h, 0)
  let h_lo = @core.get_u64_be(h, 8)

  let mut y_hi = 0UL
  let mut y_lo = 0UL
  let len = data.length()
  let blocks = (len + 15) / 16

  for b = 0; b < blocks; b = b + 1 {
    let offset = b * 16
    let chunk_len = if offset + 16 <= len { 16 } else { len - offset }
    let blk : FixedArray[Byte] = FixedArray::make(16, b'\x00')
    for i in 0..<chunk_len {
      blk[i] = data[offset + i]
    }
    let blk_bytes = Bytes::from_array(blk[:])
    let x_hi = @core.get_u64_be(blk_bytes, 0)
    let x_lo = @core.get_u64_be(blk_bytes, 8)

    let in_hi = y_hi ^ x_hi
    let in_lo = y_lo ^ x_lo
    let (res_hi, res_lo) = ghash_multiply(in_hi, in_lo, h_hi, h_lo)
    y_hi = res_hi
    y_lo = res_lo
  }

  let out : FixedArray[Byte] = FixedArray::make(16, b'\x00')
  for i in 0..<8 {
    out[i] = ((y_hi >> ((7 - i) * 8)) & 0xFFUL).to_byte()
    out[8 + i] = ((y_lo >> ((7 - i) * 8)) & 0xFFUL).to_byte()
  }
  Bytes::from_array(out[:])
}

///|
pub fn aes_gcm_encrypt(
  key : Bytes,
  iv : Bytes,
  plaintext : Bytes,
  aad : Bytes,
) -> (Bytes, Bytes) raise @core.CoreError {
  let aes = AesKey::new(key)
  let h = aes.encrypt_block(Bytes::make(16, b'\x00'), 0)

  let j0 : Bytes = if iv.length() == 12 {
    let fa : FixedArray[Byte] = FixedArray::make(16, b'\x00')
    for i in 0..<12 {
      fa[i] = iv[i]
    }
    fa[15] = b'\x01'
    Bytes::from_array(fa[:])
  } else {
    let iv_pad_len = (16 - iv.length() % 16) % 16
    let len_block : FixedArray[Byte] = FixedArray::make(16, b'\x00')
    let iv_bit_len = iv.length().to_uint64() * 8UL
    for i in 0..<8 {
      len_block[8 + i] = ((iv_bit_len >> ((7 - i) * 8)) & 0xFFUL).to_byte()
    }
    let ghash_in = @core.bytes_concat_all([
      iv,
      Bytes::make(iv_pad_len, b'\x00'),
      Bytes::from_array(len_block[:]),
    ])
    ghash(h, ghash_in)
  }

  // Encryption with CTR mode starting at inc_32(J0)
  let pt_len = plaintext.length()
  let ct_fa : FixedArray[Byte] = FixedArray::make(pt_len, b'\x00')
  let blocks = (pt_len + 15) / 16

  let mut ctr = @core.get_u32_be(j0, 12) + 1U
  let ctr_block : FixedArray[Byte] = FixedArray::make(16, b'\x00')
  for i in 0..<12 {
    ctr_block[i] = j0[i]
  }

  for b = 0; b < blocks; b = b + 1 {
    ctr_block[12] = ((ctr >> 24) & 0xFFU).to_byte()
    ctr_block[13] = ((ctr >> 16) & 0xFFU).to_byte()
    ctr_block[14] = ((ctr >> 8) & 0xFFU).to_byte()
    ctr_block[15] = (ctr & 0xFFU).to_byte()
    ctr += 1U

    let enc_ctr = aes.encrypt_block(Bytes::from_array(ctr_block[:]), 0)
    let offset = b * 16
    let chunk_len = if offset + 16 <= pt_len { 16 } else { pt_len - offset }
    for i in 0..<chunk_len {
      ct_fa[offset + i] = (plaintext[offset + i].to_int() ^ enc_ctr[i].to_int()).to_byte()
    }
  }

  let ciphertext = Bytes::from_array(ct_fa[:])

  // Compute Tag
  let aad_pad_len = (16 - aad.length() % 16) % 16
  let ct_pad_len = (16 - ciphertext.length() % 16) % 16
  let len_block : FixedArray[Byte] = FixedArray::make(16, b'\x00')
  let aad_bit_len = aad.length().to_uint64() * 8UL
  let ct_bit_len = ciphertext.length().to_uint64() * 8UL
  for i in 0..<8 {
    len_block[i] = ((aad_bit_len >> ((7 - i) * 8)) & 0xFFUL).to_byte()
    len_block[8 + i] = ((ct_bit_len >> ((7 - i) * 8)) & 0xFFUL).to_byte()
  }

  let ghash_in = @core.bytes_concat_all([
    aad,
    Bytes::make(aad_pad_len, b'\x00'),
    ciphertext,
    Bytes::make(ct_pad_len, b'\x00'),
    Bytes::from_array(len_block[:]),
  ])

  let s = ghash(h, ghash_in)
  let enc_j0 = aes.encrypt_block(j0, 0)
  let tag = @core.bytes_xor(s, enc_j0)

  (ciphertext, tag)
}

///|
pub fn aes_gcm_decrypt(
  key : Bytes,
  iv : Bytes,
  ciphertext : Bytes,
  tag : Bytes,
  aad : Bytes,
) -> Bytes raise @core.CoreError {
  if tag.length() != 16 {
    raise CryptoError("AES-GCM tag must be 16 bytes")
  }
  let aes = AesKey::new(key)
  let h = aes.encrypt_block(Bytes::make(16, b'\x00'), 0)

  let j0 : Bytes = if iv.length() == 12 {
    let fa : FixedArray[Byte] = FixedArray::make(16, b'\x00')
    for i in 0..<12 {
      fa[i] = iv[i]
    }
    fa[15] = b'\x01'
    Bytes::from_array(fa[:])
  } else {
    let iv_pad_len = (16 - iv.length() % 16) % 16
    let len_block : FixedArray[Byte] = FixedArray::make(16, b'\x00')
    let iv_bit_len = iv.length().to_uint64() * 8UL
    for i in 0..<8 {
      len_block[8 + i] = ((iv_bit_len >> ((7 - i) * 8)) & 0xFFUL).to_byte()
    }
    let ghash_in = @core.bytes_concat_all([
      iv,
      Bytes::make(iv_pad_len, b'\x00'),
      Bytes::from_array(len_block[:]),
    ])
    ghash(h, ghash_in)
  }

  // Compute expected Tag
  let aad_pad_len = (16 - aad.length() % 16) % 16
  let ct_pad_len = (16 - ciphertext.length() % 16) % 16
  let len_block : FixedArray[Byte] = FixedArray::make(16, b'\x00')
  let aad_bit_len = aad.length().to_uint64() * 8UL
  let ct_bit_len = ciphertext.length().to_uint64() * 8UL
  for i in 0..<8 {
    len_block[i] = ((aad_bit_len >> ((7 - i) * 8)) & 0xFFUL).to_byte()
    len_block[8 + i] = ((ct_bit_len >> ((7 - i) * 8)) & 0xFFUL).to_byte()
  }

  let ghash_in = @core.bytes_concat_all([
    aad,
    Bytes::make(aad_pad_len, b'\x00'),
    ciphertext,
    Bytes::make(ct_pad_len, b'\x00'),
    Bytes::from_array(len_block[:]),
  ])

  let s = ghash(h, ghash_in)
  let enc_j0 = aes.encrypt_block(j0, 0)
  let expected_tag = @core.bytes_xor(s, enc_j0)

  if !@core.constant_time_compare(tag, expected_tag) {
    raise CryptoError("AES-GCM authentication tag mismatch")
  }

  // Decryption with CTR mode
  let ct_len = ciphertext.length()
  let pt_fa : FixedArray[Byte] = FixedArray::make(ct_len, b'\x00')
  let blocks = (ct_len + 15) / 16

  let mut ctr = @core.get_u32_be(j0, 12) + 1U
  let ctr_block : FixedArray[Byte] = FixedArray::make(16, b'\x00')
  for i in 0..<12 {
    ctr_block[i] = j0[i]
  }

  for b = 0; b < blocks; b = b + 1 {
    ctr_block[12] = ((ctr >> 24) & 0xFFU).to_byte()
    ctr_block[13] = ((ctr >> 16) & 0xFFU).to_byte()
    ctr_block[14] = ((ctr >> 8) & 0xFFU).to_byte()
    ctr_block[15] = (ctr & 0xFFU).to_byte()
    ctr += 1U

    let enc_ctr = aes.encrypt_block(Bytes::from_array(ctr_block[:]), 0)
    let offset = b * 16
    let chunk_len = if offset + 16 <= ct_len { 16 } else { ct_len - offset }
    for i in 0..<chunk_len {
      pt_fa[offset + i] = (ciphertext[offset + i].to_int() ^ enc_ctr[i].to_int()).to_byte()
    }
  }

  Bytes::from_array(pt_fa[:])
}

///|
pub fn aes_gcm_seal(
  key : Bytes,
  iv : Bytes,
  plaintext : Bytes,
  aad : Bytes,
) -> Bytes raise @core.CoreError {
  let (ct, tag) = aes_gcm_encrypt(key, iv, plaintext, aad)
  @core.bytes_concat(ct, tag)
}

///|
pub fn aes_gcm_open(
  key : Bytes,
  iv : Bytes,
  payload : Bytes,
  aad : Bytes,
) -> Bytes raise @core.CoreError {
  if payload.length() < 16 {
    raise CryptoError("Payload too short for AES-GCM")
  }
  let ct_len = payload.length() - 16
  let ct = @core.bytes_slice(payload, 0, ct_len)
  let tag = @core.bytes_slice(payload, ct_len, 16)
  aes_gcm_decrypt(key, iv, ct, tag, aad)
}
