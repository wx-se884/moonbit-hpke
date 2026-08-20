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
pub(all) suberror CoreError {
  InvalidPadding(String)
  BufferUnderflow(String)
  InvalidLength(String)
  InvalidEncoding(String)
  CryptoError(String)
} derive(Debug, Eq)

///|
pub fn bytes_equal(a : Bytes, b : Bytes) -> Bool {
  if a.length() != b.length() {
    return false
  }
  for i in 0..<a.length() {
    if a[i] != b[i] {
      return false
    }
  }
  true
}

///|
pub fn bytes_concat(a : Bytes, b : Bytes) -> Bytes {
  let len_a = a.length()
  let len_b = b.length()
  Bytes::makei(len_a + len_b, fn(i) {
    if i < len_a {
      a[i]
    } else {
      b[i - len_a]
    }
  })
}

///|
pub fn bytes_concat_all(list : Array[Bytes]) -> Bytes {
  let mut total = 0
  for b in list {
    total += b.length()
  }
  let fa : FixedArray[Byte] = FixedArray::make(total, b'\x00')
  let mut offset = 0
  for b in list {
    let len = b.length()
    for i in 0..<len {
      fa[offset + i] = b[i]
    }
    offset += len
  }
  Bytes::from_array(fa[:])
}

///|
pub fn bytes_slice(b : Bytes, start : Int, len : Int) -> Bytes {
  Bytes::makei(len, fn(i) { b[start + i] })
}

///|
pub fn bytes_copy_to_fixed(
  src : Bytes,
  src_offset : Int,
  dst : FixedArray[Byte],
  dst_offset : Int,
  len : Int,
) -> Unit {
  for i in 0..<len {
    dst[dst_offset + i] = src[src_offset + i]
  }
}

///|
pub fn bytes_from_array(arr : Array[Byte]) -> Bytes {
  Bytes::makei(arr.length(), fn(i) { arr[i] })
}

///|
pub fn bytes_to_array(b : Bytes) -> Array[Byte] {
  let res : Array[Byte] = Array::new(capacity=b.length())
  for i in 0..<b.length() {
    res.push(b[i])
  }
  res
}

///|
pub fn bytes_xor(a : Bytes, b : Bytes) -> Bytes {
  let len = if a.length() < b.length() { a.length() } else { b.length() }
  Bytes::makei(len, fn(i) { (a[i].to_int() ^ b[i].to_int()).to_byte() })
}

///|
pub fn bytes_zero(len : Int) -> Bytes {
  Bytes::make(len, b'\x00')
}

///|
pub fn put_u16_be(val : Int) -> Bytes {
  let fa : FixedArray[Byte] = FixedArray::make(2, b'\x00')
  fa[0] = ((val >> 8) & 0xFF).to_byte()
  fa[1] = (val & 0xFF).to_byte()
  Bytes::from_array(fa[:])
}

///|
pub fn put_u32_be(val : UInt) -> Bytes {
  let fa : FixedArray[Byte] = FixedArray::make(4, b'\x00')
  fa[0] = ((val >> 24) & 0xFF).to_byte()
  fa[1] = ((val >> 16) & 0xFF).to_byte()
  fa[2] = ((val >> 8) & 0xFF).to_byte()
  fa[3] = (val & 0xFF).to_byte()
  Bytes::from_array(fa[:])
}

///|
pub fn put_u64_be(val : UInt64) -> Bytes {
  let fa : FixedArray[Byte] = FixedArray::make(8, b'\x00')
  fa[0] = ((val >> 56) & 0xFF).to_byte()
  fa[1] = ((val >> 48) & 0xFF).to_byte()
  fa[2] = ((val >> 40) & 0xFF).to_byte()
  fa[3] = ((val >> 32) & 0xFF).to_byte()
  fa[4] = ((val >> 24) & 0xFF).to_byte()
  fa[5] = ((val >> 16) & 0xFF).to_byte()
  fa[6] = ((val >> 8) & 0xFF).to_byte()
  fa[7] = (val & 0xFF).to_byte()
  Bytes::from_array(fa[:])
}

///|
pub fn get_u16_be(b : Bytes, offset : Int) -> Int {
  (b[offset].to_int() << 8) | b[offset + 1].to_int()
}

///|
pub fn get_u32_be(b : Bytes, offset : Int) -> UInt {
  (b[offset].to_uint() << 24) |
  (b[offset + 1].to_uint() << 16) |
  (b[offset + 2].to_uint() << 8) |
  b[offset + 3].to_uint()
}

///|
pub fn get_u64_be(b : Bytes, offset : Int) -> UInt64 {
  (b[offset].to_uint64() << 56) |
  (b[offset + 1].to_uint64() << 48) |
  (b[offset + 2].to_uint64() << 40) |
  (b[offset + 3].to_uint64() << 32) |
  (b[offset + 4].to_uint64() << 24) |
  (b[offset + 5].to_uint64() << 16) |
  (b[offset + 6].to_uint64() << 8) |
  b[offset + 7].to_uint64()
}

///|
pub fn put_u32_le(val : UInt) -> Bytes {
  let fa : FixedArray[Byte] = FixedArray::make(4, b'\x00')
  fa[0] = (val & 0xFF).to_byte()
  fa[1] = ((val >> 8) & 0xFF).to_byte()
  fa[2] = ((val >> 16) & 0xFF).to_byte()
  fa[3] = ((val >> 24) & 0xFF).to_byte()
  Bytes::from_array(fa[:])
}

///|
pub fn put_u64_le(val : UInt64) -> Bytes {
  let fa : FixedArray[Byte] = FixedArray::make(8, b'\x00')
  fa[0] = (val & 0xFF).to_byte()
  fa[1] = ((val >> 8) & 0xFF).to_byte()
  fa[2] = ((val >> 16) & 0xFF).to_byte()
  fa[3] = ((val >> 24) & 0xFF).to_byte()
  fa[4] = ((val >> 32) & 0xFF).to_byte()
  fa[5] = ((val >> 40) & 0xFF).to_byte()
  fa[6] = ((val >> 48) & 0xFF).to_byte()
  fa[7] = ((val >> 56) & 0xFF).to_byte()
  Bytes::from_array(fa[:])
}

///|
pub fn get_u32_le(b : Bytes, offset : Int) -> UInt {
  b[offset].to_uint() |
  (b[offset + 1].to_uint() << 8) |
  (b[offset + 2].to_uint() << 16) |
  (b[offset + 3].to_uint() << 24)
}

///|
pub fn get_u64_le(b : Bytes, offset : Int) -> UInt64 {
  b[offset].to_uint64() |
  (b[offset + 1].to_uint64() << 8) |
  (b[offset + 2].to_uint64() << 16) |
  (b[offset + 3].to_uint64() << 24) |
  (b[offset + 4].to_uint64() << 32) |
  (b[offset + 5].to_uint64() << 40) |
  (b[offset + 6].to_uint64() << 48) |
  (b[offset + 7].to_uint64() << 56)
}

///|
pub fn pkcs7_pad(b : Bytes, block_size : Int) -> Bytes {
  let padding_len = block_size - b.length() % block_size
  let pad_byte = padding_len.to_byte()
  let fa : FixedArray[Byte] = FixedArray::make(
    b.length() + padding_len,
    pad_byte,
  )
  for i in 0..<b.length() {
    fa[i] = b[i]
  }
  Bytes::from_array(fa[:])
}

///|
pub fn pkcs7_unpad(b : Bytes) -> Bytes raise CoreError {
  let len = b.length()
  if len == 0 {
    raise InvalidPadding("Empty ciphertext for PKCS#7 unpadding")
  }
  let pad_len = b[len - 1].to_int()
  if pad_len == 0 || pad_len > len {
    raise InvalidPadding("Invalid PKCS#7 pad length")
  }
  for i in (len - pad_len)..<len {
    if b[i].to_int() != pad_len {
      raise InvalidPadding("Corrupted PKCS#7 padding bytes")
    }
  }
  bytes_slice(b, 0, len - pad_len)
}

///|
pub fn string_to_utf8_bytes(str : String) -> Bytes {
  let out : Array[Byte] = []
  for i in 0..<str.length() {
    match str.get(i) {
      Some(code) => {
        let cp = code.to_int()
        if cp < 0x80 {
          out.push(cp.to_byte())
        } else if cp < 0x800 {
          out.push(((cp >> 6) | 0xC0).to_byte())
          out.push(((cp & 0x3F) | 0x80).to_byte())
        } else {
          out.push(((cp >> 12) | 0xE0).to_byte())
          out.push((((cp >> 6) & 0x3F) | 0x80).to_byte())
          out.push(((cp & 0x3F) | 0x80).to_byte())
        }
      }
      None => ()
    }
  }
  bytes_from_array(out)
}

///|
pub fn utf8_bytes_to_string(b : Bytes) -> String raise CoreError {
  let buf = StringBuilder::new()
  let mut i = 0
  let len = b.length()
  while i < len {
    let b0 = b[i].to_int() & 0xFF
    if b0 < 0x80 {
      buf.write_char(b0.unsafe_to_char())
      i += 1
    } else if (b0 & 0xE0) == 0xC0 {
      if i + 1 >= len {
        raise InvalidEncoding("Truncated UTF-8 sequence")
      }
      let b1 = b[i + 1].to_int() & 0x3F
      let cp = ((b0 & 0x1F) << 6) | b1
      buf.write_char(cp.unsafe_to_char())
      i += 2
    } else if (b0 & 0xF0) == 0xE0 {
      if i + 2 >= len {
        raise InvalidEncoding("Truncated UTF-8 sequence")
      }
      let b1 = b[i + 1].to_int() & 0x3F
      let b2 = b[i + 2].to_int() & 0x3F
      let cp = ((b0 & 0x0F) << 12) | (b1 << 6) | b2
      buf.write_char(cp.unsafe_to_char())
      i += 3
    } else {
      i += 1
    }
  }
  buf.to_string()
}

///|
pub fn string_slice(str : String, start : Int, len : Int) -> String {
  let buf = StringBuilder::new()
  for i in 0..<len {
    if start + i < str.length() {
      buf.write_char(str[start + i].to_int().unsafe_to_char())
    }
  }
  buf.to_string()
}

///|
pub fn string_index_of(str : String, pattern : String, start? : Int) -> Int {
  let p_len = pattern.length()
  if p_len == 0 {
    return 0
  }
  let s_len = str.length()
  let from_idx = match start {
    Some(s) => if s < 0 { 0 } else { s }
    None => 0
  }
  if from_idx + p_len > s_len {
    return -1
  }

  for i in from_idx..<=(s_len - p_len) {
    let mut matched = true
    for j in 0..<p_len {
      if str[i + j] != pattern[j] {
        matched = false
        break
      }
    }
    if matched {
      return i
    }
  }
  -1
}

///|
pub fn string_split(str : String, sep : String) -> Array[String] {
  let res : Array[String] = []
  let mut start = 0
  let sep_len = sep.length()
  if sep_len == 0 {
    res.push(str)
    return res
  }
  let mut idx = string_index_of(str, sep, start~)
  while idx >= 0 {
    res.push(string_slice(str, start, idx - start))
    start = idx + sep_len
    idx = string_index_of(str, sep, start~)
  }
  res.push(string_slice(str, start, str.length() - start))
  res
}

///|
pub fn parse_int64(str : String) -> Int64? {
  if str.length() == 0 {
    return None
  }
  let mut val : Int64 = 0L
  for i in 0..<str.length() {
    let c = str[i].to_int()
    if c >= 48 && c <= 57 {
      val = val * 10L + (c - 48).to_int64()
    } else {
      return None
    }
  }
  Some(val)
}
