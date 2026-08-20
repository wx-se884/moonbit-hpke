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
let b64_std_chars : String = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

///|
let b64_url_chars : String = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

///|
fn get_b64_char(chars : String, idx : Int) -> Char {
  match chars.get(idx) {
    Some(u) => u.to_int().unsafe_to_char()
    None => 'A'
  }
}

///|
pub fn base64_encode(
  data : Bytes,
  url_safe? : Bool = false,
  padding? : Bool = true,
) -> String {
  let chars = if url_safe { b64_url_chars } else { b64_std_chars }
  let len = data.length()
  let buf = StringBuilder::new()
  let mut i = 0
  while i < len {
    let b0 = data[i].to_int()
    let b1 = if i + 1 < len { data[i + 1].to_int() } else { 0 }
    let b2 = if i + 2 < len { data[i + 2].to_int() } else { 0 }

    let c0 = (b0 >> 2) & 0x3F
    let c1 = ((b0 & 0x03) << 4) | ((b1 >> 4) & 0x0F)
    let c2 = ((b1 & 0x0F) << 2) | ((b2 >> 6) & 0x03)
    let c3 = b2 & 0x3F

    buf.write_char(get_b64_char(chars, c0))
    buf.write_char(get_b64_char(chars, c1))

    if i + 1 < len {
      buf.write_char(get_b64_char(chars, c2))
    } else if padding {
      buf.write_char('=')
    }

    if i + 2 < len {
      buf.write_char(get_b64_char(chars, c3))
    } else if padding {
      buf.write_char('=')
    }

    i += 3
  }
  buf.to_string()
}

///|
pub fn base64url_encode(data : Bytes) -> String {
  base64_encode(data, url_safe=true, padding=false)
}

///|
fn decode_char(c : Char) -> Int {
  let val = c.to_int()
  if val >= 'A'.to_int() && val <= 'Z'.to_int() {
    val - 'A'.to_int()
  } else if val >= 'a'.to_int() && val <= 'z'.to_int() {
    val - 'a'.to_int() + 26
  } else if val >= '0'.to_int() && val <= '9'.to_int() {
    val - '0'.to_int() + 52
  } else if val == '+'.to_int() || val == '-'.to_int() {
    62
  } else if val == '/'.to_int() || val == '_'.to_int() {
    63
  } else {
    -1
  }
}

///|
pub fn base64_decode(input : String) -> Bytes raise CoreError {
  let chars : Array[Int] = Array::new()
  for c in input {
    if c == '=' || c == ' ' || c == '\r' || c == '\n' || c == '\t' {
      continue
    }
    let v = decode_char(c)
    if v < 0 {
      raise InvalidEncoding("Invalid base64 character")
    }
    chars.push(v)
  }

  let total_chars = chars.length()
  if total_chars == 0 {
    return Bytes::make(0, b'\x00')
  }
  let rem = total_chars % 4
  if rem == 1 {
    raise InvalidEncoding("Invalid base64 length (remainder 1)")
  }

  let full_quads = total_chars / 4
  let extra_bytes = if rem == 2 { 1 } else if rem == 3 { 2 } else { 0 }
  let out_len = full_quads * 3 + extra_bytes
  let fa : FixedArray[Byte] = FixedArray::make(out_len, b'\x00')

  let mut in_idx = 0
  let mut out_idx = 0
  for q = 0; q < full_quads; q = q + 1 {
    let c0 = chars[in_idx]
    let c1 = chars[in_idx + 1]
    let c2 = chars[in_idx + 2]
    let c3 = chars[in_idx + 3]
    in_idx += 4

    let b0 = (c0 << 2) | (c1 >> 4)
    let b1 = ((c1 & 0x0F) << 4) | (c2 >> 2)
    let b2 = ((c2 & 0x03) << 6) | c3

    fa[out_idx] = b0.to_byte()
    fa[out_idx + 1] = b1.to_byte()
    fa[out_idx + 2] = b2.to_byte()
    out_idx += 3
  }

  if rem == 2 {
    let c0 = chars[in_idx]
    let c1 = chars[in_idx + 1]
    let b0 = (c0 << 2) | (c1 >> 4)
    fa[out_idx] = b0.to_byte()
  } else if rem == 3 {
    let c0 = chars[in_idx]
    let c1 = chars[in_idx + 1]
    let c2 = chars[in_idx + 2]
    let b0 = (c0 << 2) | (c1 >> 4)
    let b1 = ((c1 & 0x0F) << 4) | (c2 >> 2)
    fa[out_idx] = b0.to_byte()
    fa[out_idx + 1] = b1.to_byte()
  }

  Bytes::from_array(fa[:])
}

///|
pub fn base64url_decode(input : String) -> Bytes raise CoreError {
  base64_decode(input)
}
