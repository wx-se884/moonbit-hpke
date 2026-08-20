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
let c25519_p_hex : String = "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed"

///|
let c25519_a24_hex : String = "01db41" // 121665

///|
pub fn x25519(scalar : Bytes, point : Bytes) -> Bytes raise @core.CoreError {
  if scalar.length() != 32 || point.length() != 32 {
    raise CryptoError("X25519 scalar and point must be 32 bytes")
  }

  // Clamping
  let k : FixedArray[Byte] = FixedArray::make(32, b'\x00')
  for i in 0..<32 {
    k[i] = scalar[i]
  }
  k[0] = (k[0].to_int() & 248).to_byte()
  k[31] = ((k[31].to_int() & 127) | 64).to_byte()

  let p = @core.BigNat::from_bytes_be(@core.hex_decode(c25519_p_hex))
  let a24 = @core.BigNat::from_bytes_be(@core.hex_decode(c25519_a24_hex))

  // Read point as little-endian BigNat
  let x1 = @core.BigNat::from_bytes_le(point).rem(p)

  let mut x2 = @core.BigNat::one()
  let mut z2 = @core.BigNat::zero()
  let mut x3 = x1
  let mut z3 = @core.BigNat::one()

  let k_nat = @core.BigNat::from_bytes_le(Bytes::from_array(k[:]))

  for pos = 254; pos >= 0; pos = pos - 1 {
    let b = k_nat.test_bit(pos)

    if b {
      let tx = x2
      x2 = x3
      x3 = tx
      let tz = z2
      z2 = z3
      z3 = tz
    }

    let a = x2.add(z2).rem(p)
    let aa = a.mul(a).rem(p)
    let b_fe = x2.add(p).sub(z2.rem(p)).rem(p)
    let bb = b_fe.mul(b_fe).rem(p)
    let e = aa.add(p).sub(bb).rem(p)

    let c = x3.add(z3).rem(p)
    let d = x3.add(p).sub(z3.rem(p)).rem(p)
    let da = d.mul(a).rem(p)
    let cb = c.mul(b_fe).rem(p)

    let da_plus_cb = da.add(cb).rem(p)
    x3 = da_plus_cb.mul(da_plus_cb).rem(p)

    let da_minus_cb = da.add(p).sub(cb.rem(p)).rem(p)
    z3 = x1.mul(da_minus_cb.mul(da_minus_cb).rem(p)).rem(p)

    x2 = aa.mul(bb).rem(p)
    let ea24 = aa.add(a24.mul(e).rem(p)).rem(p)
    z2 = e.mul(ea24).rem(p)

    if b {
      let tx = x2
      x2 = x3
      x3 = tx
      let tz = z2
      z2 = z3
      z3 = tz
    }
  }

  let p_minus_2 = p.sub(@core.BigNat::from_uint(2U))
  let z2_inv = z2.pow_mod(p_minus_2, p)
  let res = x2.mul(z2_inv).rem(p)

  res.to_bytes_le(size=32)
}

///|
pub fn x25519_base(scalar : Bytes) -> Bytes raise @core.CoreError {
  let base : FixedArray[Byte] = FixedArray::make(32, b'\x00')
  base[0] = b'\x09'
  x25519(scalar, Bytes::from_array(base[:]))
}
