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
test "bytes basic operations" {
  let b1 = Bytes::make(3, b'\x01')
  let b2 = Bytes::make(2, b'\x02')
  let concat = bytes_concat(b1, b2)
  assert_eq(concat.length(), 5)
  assert_eq(concat[0], b'\x01')
  assert_eq(concat[3], b'\x02')

  let sl = bytes_slice(concat, 2, 2)
  assert_eq(sl.length(), 2)
  assert_eq(sl[0], b'\x01')
  assert_eq(sl[1], b'\x02')
}

///|
test "base64 and base64url encode and decode" {
  let test_str = "MoonBit HPKE JOSE Cryptographic Library 2026"
  let fa : FixedArray[Byte] = FixedArray::make(test_str.length(), b'\x00')
  for i in 0..<test_str.length() {
    match test_str.get(i) {
      Some(u) => fa[i] = u.to_int().to_byte()
      None => ()
    }
  }
  let bytes = Bytes::from_array(fa[:])

  let b64 = base64_encode(bytes)
  let decoded = base64_decode(b64)
  assert_true(bytes_equal(bytes, decoded))

  let b64url = base64url_encode(bytes)
  let decoded_url = base64url_decode(b64url)
  assert_true(bytes_equal(bytes, decoded_url))
}

///|
test "hex encode and decode" {
  let fa : FixedArray[Byte] = FixedArray::make(4, b'\x00')
  fa[0] = b'\xde'
  fa[1] = b'\xad'
  fa[2] = b'\xbe'
  fa[3] = b'\xef'
  let raw = Bytes::from_array(fa[:])

  let encoded = hex_encode(raw)
  assert_eq(encoded, "deadbeef")

  let decoded = hex_decode(encoded)
  assert_true(bytes_equal(raw, decoded))
}

///|
test "bignat arithmetic operations" {
  let n1 = BigNat::from_uint(12345678U)
  let n2 = BigNat::from_uint(87654321U)
  let sum = n1.add(n2)
  assert_true(sum.compare(BigNat::from_uint(100000000U)) - 1 < 0)
  let diff = n2.sub(n1)
  assert_true(diff.compare(BigNat::zero()) > 0)
  let prod = n1.mul(n2)

  let (q, r) = prod.div_rem(n1)
  assert_true(q.compare(n2) == 0)
  assert_true(r.is_zero())

  // Modular exponentiation test
  let base = BigNat::from_uint(3U)
  let exp = BigNat::from_uint(7U)
  let mod_val = BigNat::from_uint(100U)
  let pow_res = base.pow_mod(exp, mod_val)
  // 3^7 = 2187, 2187 % 100 = 87
  assert_true(pow_res.compare(BigNat::from_uint(87U)) == 0)
}
