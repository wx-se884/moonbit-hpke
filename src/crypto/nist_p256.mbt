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
let p256_p_hex : String = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"

///|
let p256_n_hex : String = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"

///|
let p256_gx_hex : String = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"

///|
let p256_gy_hex : String = "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"

///|
priv struct JacobPoint {
  x : @core.BigNat
  y : @core.BigNat
  z : @core.BigNat
}

///|
fn jacob_infinity() -> JacobPoint {
  { x: @core.BigNat::one(), y: @core.BigNat::one(), z: @core.BigNat::zero() }
}

///|
fn jacob_double(
  pt : JacobPoint,
  p : @core.BigNat,
) -> JacobPoint raise @core.CoreError {
  if pt.z.is_zero() || pt.y.is_zero() {
    return jacob_infinity()
  }
  let two = @core.BigNat::from_uint(2U)
  let three = @core.BigNat::from_uint(3U)
  let four = @core.BigNat::from_uint(4U)
  let eight = @core.BigNat::from_uint(8U)

  let z_sq = pt.z.mul_mod(pt.z, p)
  let a = pt.x.sub_mod(z_sq, p)
  let b = pt.x.add(z_sq).rem(p)
  let m = three.mul_mod(a.mul_mod(b, p), p)

  let y_sq = pt.y.mul_mod(pt.y, p)
  let s = four.mul_mod(pt.x.mul_mod(y_sq, p), p)

  let m_sq = m.mul_mod(m, p)
  let two_s = two.mul_mod(s, p)
  let x3 = m_sq.sub_mod(two_s, p)

  let y_sq_sq = y_sq.mul_mod(y_sq, p)
  let eight_c = eight.mul_mod(y_sq_sq, p)
  let s_minus_x3 = s.sub_mod(x3, p)
  let y3 = m.mul_mod(s_minus_x3, p).sub_mod(eight_c, p)

  let z3 = two.mul_mod(pt.y.mul_mod(pt.z, p), p)

  { x: x3, y: y3, z: z3 }
}

///|
fn jacob_add(
  p1 : JacobPoint,
  p2 : JacobPoint,
  p : @core.BigNat,
) -> JacobPoint raise @core.CoreError {
  if p1.z.is_zero() {
    return p2
  }
  if p2.z.is_zero() {
    return p1
  }

  let z1_sq = p1.z.mul_mod(p1.z, p)
  let z2_sq = p2.z.mul_mod(p2.z, p)

  let u1 = p1.x.mul_mod(z2_sq, p)
  let u2 = p2.x.mul_mod(z1_sq, p)

  let s1 = p1.y.mul_mod(p2.z.mul_mod(z2_sq, p), p)
  let s2 = p2.y.mul_mod(p1.z.mul_mod(z1_sq, p), p)

  if u1.compare(u2) == 0 {
    if s1.compare(s2) == 0 {
      return jacob_double(p1, p)
    } else {
      return jacob_infinity()
    }
  }

  let h = u2.sub_mod(u1, p)
  let r = s2.sub_mod(s1, p)

  let h_sq = h.mul_mod(h, p)
  let h_cu = h.mul_mod(h_sq, p)
  let v = u1.mul_mod(h_sq, p)

  let two = @core.BigNat::from_uint(2U)
  let two_v = two.mul_mod(v, p)
  let r_sq = r.mul_mod(r, p)
  let x3 = r_sq.sub_mod(h_cu, p).sub_mod(two_v, p)

  let v_minus_x3 = v.sub_mod(x3, p)
  let y3 = r.mul_mod(v_minus_x3, p).sub_mod(s1.mul_mod(h_cu, p), p)

  let z3 = p1.z.mul_mod(p2.z.mul_mod(h, p), p)

  { x: x3, y: y3, z: z3 }
}

///|
fn jacob_to_affine(
  pt : JacobPoint,
  p : @core.BigNat,
) -> (@core.BigNat, @core.BigNat) raise @core.CoreError {
  if pt.z.is_zero() {
    raise CryptoError("Cannot convert infinity point to affine")
  }
  let p_minus_2 = p.sub(@core.BigNat::from_uint(2U))
  let z_inv = pt.z.pow_mod(p_minus_2, p)
  let z_inv_sq = z_inv.mul_mod(z_inv, p)
  let z_inv_cu = z_inv.mul_mod(z_inv_sq, p)

  let x = pt.x.mul_mod(z_inv_sq, p)
  let y = pt.y.mul_mod(z_inv_cu, p)
  (x, y)
}

///|
pub fn p256_scalar_mult_affine(
  k : @core.BigNat,
  x : @core.BigNat,
  y : @core.BigNat,
) -> (@core.BigNat, @core.BigNat) raise @core.CoreError {
  let p = @core.BigNat::from_bytes_be(@core.hex_decode(p256_p_hex))
  let mut res = jacob_infinity()
  let mut addend : JacobPoint = { x, y, z: @core.BigNat::one() }
  let bits = k.bit_length()

  for i = 0; i < bits; i = i + 1 {
    if k.test_bit(i) {
      res = jacob_add(res, addend, p)
    }
    addend = jacob_double(addend, p)
  }

  jacob_to_affine(res, p)
}

///|
pub fn p256_public_from_private(
  priv_key : Bytes,
) -> Bytes raise @core.CoreError {
  let k = @core.BigNat::from_bytes_be(priv_key)
  let gx = @core.BigNat::from_bytes_be(@core.hex_decode(p256_gx_hex))
  let gy = @core.BigNat::from_bytes_be(@core.hex_decode(p256_gy_hex))

  let (x, y) = p256_scalar_mult_affine(k, gx, gy)
  let x_bytes = x.to_bytes_be(size=32)
  let y_bytes = y.to_bytes_be(size=32)

  let fa : FixedArray[Byte] = FixedArray::make(65, b'\x00')
  fa[0] = b'\x04'
  for i in 0..<32 {
    fa[1 + i] = x_bytes[i]
    fa[33 + i] = y_bytes[i]
  }
  Bytes::from_array(fa[:])
}

///|
pub fn p256_ecdh(
  priv_key : Bytes,
  pub_key_uncompressed : Bytes,
) -> Bytes raise @core.CoreError {
  if pub_key_uncompressed.length() != 65 || pub_key_uncompressed[0] != b'\x04' {
    raise CryptoError("Invalid P-256 uncompressed public key format")
  }
  let k = @core.BigNat::from_bytes_be(priv_key)
  let x_bytes = @core.bytes_slice(pub_key_uncompressed, 1, 32)
  let y_bytes = @core.bytes_slice(pub_key_uncompressed, 33, 32)
  let qx = @core.BigNat::from_bytes_be(x_bytes)
  let qy = @core.BigNat::from_bytes_be(y_bytes)

  let (sx, _) = p256_scalar_mult_affine(k, qx, qy)
  sx.to_bytes_be(size=32)
}

///|
pub fn p256_ecdsa_verify(
  pub_key_uncompressed : Bytes,
  digest : Bytes,
  r_bytes : Bytes,
  s_bytes : Bytes,
) -> Bool raise @core.CoreError {
  if pub_key_uncompressed.length() != 65 || pub_key_uncompressed[0] != b'\x04' {
    return false
  }
  let p = @core.BigNat::from_bytes_be(@core.hex_decode(p256_p_hex))
  let n = @core.BigNat::from_bytes_be(@core.hex_decode(p256_n_hex))
  let gx = @core.BigNat::from_bytes_be(@core.hex_decode(p256_gx_hex))
  let gy = @core.BigNat::from_bytes_be(@core.hex_decode(p256_gy_hex))

  let r = @core.BigNat::from_bytes_be(r_bytes)
  let s = @core.BigNat::from_bytes_be(s_bytes)

  if r.is_zero() || r.compare(n) >= 0 || s.is_zero() || s.compare(n) >= 0 {
    return false
  }

  let z = @core.BigNat::from_bytes_be(digest)
  let w = s.inv_mod(n)
  let u1 = z.mul_mod(w, n)
  let u2 = r.mul_mod(w, n)

  let qx = @core.BigNat::from_bytes_be(
    @core.bytes_slice(pub_key_uncompressed, 1, 32),
  )
  let qy = @core.BigNat::from_bytes_be(
    @core.bytes_slice(pub_key_uncompressed, 33, 32),
  )

  let (u1_gx, u1_gy) = p256_scalar_mult_affine(u1, gx, gy)
  let (u2_qx, u2_qy) = p256_scalar_mult_affine(u2, qx, qy)

  let pt1 : JacobPoint = { x: u1_gx, y: u1_gy, z: @core.BigNat::one() }
  let pt2 : JacobPoint = { x: u2_qx, y: u2_qy, z: @core.BigNat::one() }
  let pt_res = jacob_add(pt1, pt2, p)
  if pt_res.z.is_zero() {
    return false
  }
  let (rx, _) = jacob_to_affine(pt_res, p)
  rx.rem(n).compare(r) == 0
}
