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
test "base64 handles empty and every short input length" {
  let empty = Bytes::make(0, b'\x00')
  assert_eq(base64_encode(empty), "")
  assert_eq(base64_decode(""), empty)
  assert_eq(base64_encode(b"f"), "Zg==")
  assert_eq(base64_encode(b"fo"), "Zm8=")
  assert_eq(base64_encode(b"foo"), "Zm9v")
  assert_eq(base64_encode(b"fo", padding=false), "Zm8")
  assert_true(bytes_equal(base64_decode("Zm8"), b"fo"))
  assert_true(bytes_equal(base64url_decode("Zm8"), b"fo"))
}

///|
test "base64 rejects impossible lengths and characters" {
  let bad_length = try {
    let _ = base64_decode("A")
    false
  } catch {
    InvalidEncoding(_) => true
    _ => false
  }
  let bad_character = try {
    let _ = base64_decode("Zm$=")
    false
  } catch {
    InvalidEncoding(_) => true
    _ => false
  }
  assert_true(bad_length)
  assert_true(bad_character)
}

///|
test "hex handles empty input and rejects malformed input" {
  assert_true(bytes_equal(hex_decode(""), Bytes::make(0, b'\x00')))
  assert_eq(hex_encode(hex_decode("00ff10")), "00ff10")
  let odd = try {
    let _ = hex_decode("abc")
    false
  } catch {
    InvalidEncoding(_) => true
    _ => false
  }
  let invalid = try {
    let _ = hex_decode("gg")
    false
  } catch {
    InvalidEncoding(_) => true
    _ => false
  }
  assert_true(odd)
  assert_true(invalid)
}

///|
test "byte helpers preserve boundaries" {
  let parts = [b"", b"left", b"-", b"right"]
  let joined = bytes_concat_all(parts)
  assert_true(bytes_equal(joined, b"left-right"))
  assert_true(bytes_equal(bytes_slice(joined, 0, 0), b""))
  assert_true(bytes_equal(bytes_slice(joined, 4, 1), b"-"))
  assert_true(bytes_equal(bytes_xor(b"\x00\xff", b"\xff\x0f"), b"\xff\xf0"))
  assert_true(bytes_equal(bytes_zero(4), b"\x00\x00\x00\x00"))
  assert_true(constant_time_compare(b"same", b"same"))
  assert_true(!constant_time_compare(b"same", b"same!"))
  assert_true(!constant_time_compare(b"same", b"SAME"))
}

///|
test "integer and string helpers cover empty and offset cases" {
  assert_eq(put_u16_be(0x1234), b"\x12\x34")
  assert_eq(get_u16_be(b"\x12\x34", 0), 0x1234)
  assert_eq(put_u32_be(0x12345678U), b"\x12\x34\x56\x78")
  assert_eq(get_u32_be(b"\x12\x34\x56\x78", 0), 0x12345678U)
  assert_eq(string_index_of("moonbit-hpke", "hpke"), 8)
  assert_eq(string_index_of("moonbit-hpke", "hpke", start=9), -1)
  assert_eq(string_split("a::b::c", "::"), ["a", "b", "c"])
  assert_eq(parse_int64(""), None)
  assert_eq(parse_int64("-1"), None)
  assert_eq(parse_int64("123456"), Some(123456L))
  let text = "你好，MoonBit"
  assert_eq(utf8_bytes_to_string(string_to_utf8_bytes(text)), text)
}

///|
test "pkcs7 accepts full blocks and rejects corrupted padding" {
  let full = pkcs7_pad(b"1234567890abcdef", 16)
  assert_eq(full.length(), 32)
  assert_true(bytes_equal(pkcs7_unpad(full), b"1234567890abcdef"))
  let empty = pkcs7_pad(b"", 8)
  assert_eq(empty.length(), 8)
  assert_true(bytes_equal(pkcs7_unpad(empty), b""))
  let zero = try {
    let _ = pkcs7_unpad(b"\x00")
    false
  } catch {
    InvalidPadding(_) => true
    _ => false
  }
  let corrupted = try {
    let _ = pkcs7_unpad(b"abc\x02")
    false
  } catch {
    InvalidPadding(_) => true
    _ => false
  }
  assert_true(zero)
  assert_true(corrupted)
}

///|
test "bignat identities and arithmetic errors are explicit" {
  let zero = BigNat::zero()
  let one = BigNat::one()
  let large = BigNat::from_bytes_be(b"\x01\x00\x00\x00\x01")
  assert_true(zero.is_zero())
  assert_true(one.is_one())
  assert_true(!large.is_even())
  assert_eq(large.bit_length(), 33)
  assert_true(large.test_bit(32))
  assert_true(!large.test_bit(31))
  assert_true(large.add(one).sub(one).compare(large) == 0)
  assert_true(large.mul(one).compare(large) == 0)
  let underflow = try {
    let _ = zero.sub(one)
    false
  } catch {
    CryptoError(_) => true
    _ => false
  }
  let divide_zero = try {
    let _ = large.div(zero)
    false
  } catch {
    CryptoError(_) => true
    _ => false
  }
  assert_true(underflow)
  assert_true(divide_zero)
}
