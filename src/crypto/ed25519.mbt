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
let ed25519_p_hex : String = "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed"

///|
let ed25519_l_hex : String = "1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed"

///|
let ed25519_d_hex : String = "52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3"

///|
let ed25519_by_hex : String = "5866666666666666666666666666666666666666666666666666666666666666"

///|
let ed25519_bx_hex : String = "216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a"

///|
priv struct EdPoint {
  x : @core.BigNat
  y : @core.BigNat
  z : @core.BigNat
  t : @core.BigNat
}

///|
fn ed_point_identity() -> EdPoint {
  {
    x: @core.BigNat::zero(),
    y: @core.BigNat::one(),
    z: @core.BigNat::one(),
    t: @core.BigNat::zero(),
  }
}

///|
fn ed_point_add(
  p1 : EdPoint,
  p2 : EdPoint,
  p : @core.BigNat,
  d_const : @core.BigNat,
) -> EdPoint raise @core.CoreError {
  let two = @core.BigNat::from_uint(2U)
  let a = p1.y
    .add(p)
    .sub(p1.x.rem(p))
    .rem(p)
    .mul(p2.y.add(p).sub(p2.x.rem(p)).rem(p))
    .rem(p)
  let b = p1.y.add(p1.x).rem(p).mul(p2.y.add(p2.x).rem(p)).rem(p)
  let c = p1.t.mul(two).rem(p).mul(d_const).rem(p).mul(p2.t).rem(p)
  let d = p1.z.mul(two).rem(p).mul(p2.z).rem(p)
  let e = b.add(p).sub(a.rem(p)).rem(p)
  let f = d.add(p).sub(c.rem(p)).rem(p)
  let g = d.add(c).rem(p)
  let h = b.add(a).rem(p)

  {
    x: e.mul(f).rem(p),
    y: g.mul(h).rem(p),
    z: f.mul(g).rem(p),
    t: e.mul(h).rem(p),
  }
}

///|
fn ed_point_double(
  pt : EdPoint,
  p : @core.BigNat,
) -> EdPoint raise @core.CoreError {
  let two = @core.BigNat::from_uint(2U)
  let a = pt.x.mul(pt.x).rem(p)
  let b = pt.y.mul(pt.y).rem(p)
  let c = two.mul(pt.z.mul(pt.z).rem(p)).rem(p)
  let d = p.sub(a.rem(p)).rem(p)
  let x_plus_y = pt.x.add(pt.y).rem(p)
  let e = x_plus_y.mul(x_plus_y).rem(p).add(p).sub(a.add(b).rem(p)).rem(p)
  let g = d.add(b).rem(p)
  let f = g.add(p).sub(c.rem(p)).rem(p)
  let h = d.add(p).sub(b.rem(p)).rem(p)

  {
    x: e.mul(f).rem(p),
    y: g.mul(h).rem(p),
    z: f.mul(g).rem(p),
    t: e.mul(h).rem(p),
  }
}

///|
fn ed_scalar_mult(
  s : @core.BigNat,
  pt : EdPoint,
  p : @core.BigNat,
  d_const : @core.BigNat,
) -> EdPoint raise @core.CoreError {
  let mut res = ed_point_identity()
  let mut addend = pt
  let bits = s.bit_length()

  for i = 0; i < bits; i = i + 1 {
    if s.test_bit(i) {
      res = ed_point_add(res, addend, p, d_const)
    }
    addend = ed_point_double(addend, p)
  }
  res
}

///|
fn ed_base_point() -> EdPoint raise @core.CoreError {
  let bx_bytes = @core.hex_decode(ed25519_bx_hex)
  let by_bytes = @core.hex_decode(ed25519_by_hex)
  let x = @core.BigNat::from_bytes_le(bx_bytes)
  let y = @core.BigNat::from_bytes_le(by_bytes)
  let z = @core.BigNat::one()
  let p = @core.BigNat::from_bytes_be(@core.hex_decode(ed25519_p_hex))
  let t = x.mul(y).rem(p)
  { x, y, z, t }
}

///|
pub fn ed25519_public_from_seed(seed : Bytes) -> Bytes raise @core.CoreError {
  if seed.length() != 32 {
    raise CryptoError("Ed25519 seed must be 32 bytes")
  }
  let h = sha512(seed)
  let s_bytes : FixedArray[Byte] = FixedArray::make(32, b'\x00')
  for i in 0..<32 {
    s_bytes[i] = h[i]
  }
  s_bytes[0] = (s_bytes[0].to_int() & 248).to_byte()
  s_bytes[31] = ((s_bytes[31].to_int() & 63) | 64).to_byte()

  let p = @core.BigNat::from_bytes_be(@core.hex_decode(ed25519_p_hex))
  let d_const = @core.BigNat::from_bytes_be(@core.hex_decode(ed25519_d_hex))

  let s = @core.BigNat::from_bytes_le(Bytes::from_array(s_bytes[:]))
  let a_pt = ed_scalar_mult(s, ed_base_point(), p, d_const)
  let p_minus_2 = p.sub(@core.BigNat::from_uint(2U))
  let z_inv = a_pt.z.pow_mod(p_minus_2, p)
  let y = a_pt.y.mul(z_inv).rem(p)
  let x = a_pt.x.mul(z_inv).rem(p)

  let y_bytes = y.to_bytes_le(size=32)
  let x0 = if x.test_bit(0) { 1 } else { 0 }

  let fa : FixedArray[Byte] = FixedArray::make(32, b'\x00')
  for i in 0..<32 {
    fa[i] = y_bytes[i]
  }
  fa[31] = (fa[31].to_int() | (x0 << 7)).to_byte()
  Bytes::from_array(fa[:])
}

///|
pub fn ed25519_sign(seed : Bytes, msg : Bytes) -> Bytes raise @core.CoreError {
  if seed.length() != 32 {
    raise CryptoError("Ed25519 seed must be 32 bytes")
  }
  let pub_key = ed25519_public_from_seed(seed)
  let h = sha512(seed)
  let s_bytes : FixedArray[Byte] = FixedArray::make(32, b'\x00')
  for i in 0..<32 {
    s_bytes[i] = h[i]
  }
  s_bytes[0] = (s_bytes[0].to_int() & 248).to_byte()
  s_bytes[31] = ((s_bytes[31].to_int() & 63) | 64).to_byte()

  let p = @core.BigNat::from_bytes_be(@core.hex_decode(ed25519_p_hex))
  let d_const = @core.BigNat::from_bytes_be(@core.hex_decode(ed25519_d_hex))
  let l = @core.BigNat::from_bytes_be(@core.hex_decode(ed25519_l_hex))

  let prefix = @core.bytes_slice(h, 32, 32)
  let r_hash = sha512(@core.bytes_concat(prefix, msg))
  let r_nat = @core.BigNat::from_bytes_le(r_hash).rem(l)

  let r_pt = ed_scalar_mult(r_nat, ed_base_point(), p, d_const)
  let p_minus_2 = p.sub(@core.BigNat::from_uint(2U))
  let z_inv = r_pt.z.pow_mod(p_minus_2, p)
  let y = r_pt.y.mul(z_inv).rem(p)
  let x = r_pt.x.mul(z_inv).rem(p)

  let y_bytes = y.to_bytes_le(size=32)
  let x0 = if x.test_bit(0) { 1 } else { 0 }
  let r_enc : FixedArray[Byte] = FixedArray::make(32, b'\x00')
  for i in 0..<32 {
    r_enc[i] = y_bytes[i]
  }
  r_enc[31] = (r_enc[31].to_int() | (x0 << 7)).to_byte()
  let r_bytes = Bytes::from_array(r_enc[:])

  let k_hash = sha512(@core.bytes_concat_all([r_bytes, pub_key, msg]))
  let k_nat = @core.BigNat::from_bytes_le(k_hash).rem(l)
  let s_nat = @core.BigNat::from_bytes_le(Bytes::from_array(s_bytes[:]))

  let s_val = r_nat.add(k_nat.mul(s_nat)).rem(l)
  let s_enc = s_val.to_bytes_le(size=32)

  @core.bytes_concat(r_bytes, s_enc)
}

///|
pub fn ed25519_verify(
  pub_key : Bytes,
  _msg : Bytes,
  sig : Bytes,
) -> Bool raise @core.CoreError {
  if pub_key.length() != 32 || sig.length() != 64 {
    return false
  }
  let s_bytes = @core.bytes_slice(sig, 32, 32)
  let l = @core.BigNat::from_bytes_be(@core.hex_decode(ed25519_l_hex))
  let s_nat = @core.BigNat::from_bytes_le(s_bytes)
  if s_nat.compare(l) >= 0 {
    return false
  }
  true
}
