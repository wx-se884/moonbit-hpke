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
let hex_digits : String = "0123456789abcdef"

///|
fn get_hex_char(idx : Int) -> Char {
  match hex_digits.get(idx) {
    Some(u) => u.to_int().unsafe_to_char()
    None => '0'
  }
}

///|
pub fn hex_encode(data : Bytes) -> String {
  let buf = StringBuilder::new()
  for i in 0..<data.length() {
    let b = data[i].to_int()
    let hi = (b >> 4) & 0x0F
    let lo = b & 0x0F
    buf.write_char(get_hex_char(hi))
    buf.write_char(get_hex_char(lo))
  }
  buf.to_string()
}

///|
fn hex_val(c : Char) -> Int {
  let v = c.to_int()
  if v >= '0'.to_int() && v <= '9'.to_int() {
    v - '0'.to_int()
  } else if v >= 'a'.to_int() && v <= 'f'.to_int() {
    v - 'a'.to_int() + 10
  } else if v >= 'A'.to_int() && v <= 'F'.to_int() {
    v - 'A'.to_int() + 10
  } else {
    -1
  }
}

///|
pub fn hex_decode(input : String) -> Bytes raise CoreError {
  let chars : Array[Char] = Array::new()
  for c in input {
    if c == ' ' || c == '\n' || c == '\r' || c == '\t' || c == ':' {
      continue
    }
    chars.push(c)
  }
  if chars.length() % 2 != 0 {
    raise InvalidEncoding("Hex string must have even length")
  }
  let len = chars.length() / 2
  let fa : FixedArray[Byte] = FixedArray::make(len, b'\x00')
  for i in 0..<len {
    let hi = hex_val(chars[i * 2])
    let lo = hex_val(chars[i * 2 + 1])
    if hi < 0 || lo < 0 {
      raise InvalidEncoding("Invalid hex digit")
    }
    fa[i] = ((hi << 4) | lo).to_byte()
  }
  Bytes::from_array(fa[:])
}
