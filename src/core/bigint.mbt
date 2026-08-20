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
/// A multi-precision unsigned integer represented by 32-bit limbs in little-endian order.
pub(all) struct BigNat {
  limbs : Array[UInt]
} derive(Debug, Eq)

///|
pub fn BigNat::zero() -> BigNat {
  { limbs: [] }
}

///|
pub fn BigNat::one() -> BigNat {
  { limbs: [1U] }
}

///|
pub fn BigNat::from_uint(n : UInt) -> BigNat {
  if n == 0U {
    { limbs: [] }
  } else {
    { limbs: [n] }
  }
}

///|
pub fn BigNat::from_uint64(n : UInt64) -> BigNat {
  let lo = (n & 0xFFFFFFFFUL).to_uint()
  let hi = ((n >> 32) & 0xFFFFFFFFUL).to_uint()
  if hi != 0U {
    { limbs: [lo, hi] }
  } else if lo != 0U {
    { limbs: [lo] }
  } else {
    { limbs: [] }
  }
}

///|
fn BigNat::normalize(self : BigNat) -> BigNat {
  let mut len = self.limbs.length()
  while len > 0 && self.limbs[len - 1] == 0U {
    len -= 1
  }
  if len == self.limbs.length() {
    self
  } else {
    let new_limbs : Array[UInt] = Array::new(capacity=len)
    for i in 0..<len {
      new_limbs.push(self.limbs[i])
    }
    { limbs: new_limbs }
  }
}

///|
pub fn BigNat::is_zero(self : BigNat) -> Bool {
  let n = self.normalize()
  n.limbs.length() == 0
}

///|
pub fn BigNat::is_one(self : BigNat) -> Bool {
  let n = self.normalize()
  n.limbs.length() == 1 && n.limbs[0] == 1U
}

///|
pub fn BigNat::is_even(self : BigNat) -> Bool {
  let n = self.normalize()
  if n.limbs.length() == 0 {
    true
  } else {
    (n.limbs[0] & 1U) == 0U
  }
}

///|
pub fn BigNat::compare(self : BigNat, other : BigNat) -> Int {
  let a = self.normalize()
  let b = other.normalize()
  if a.limbs.length() < b.limbs.length() {
    return -1
  }
  if a.limbs.length() > b.limbs.length() {
    return 1
  }
  let len = a.limbs.length()
  for i = len - 1; i >= 0; i = i - 1 {
    if a.limbs[i] < b.limbs[i] {
      return -1
    }
    if a.limbs[i] > b.limbs[i] {
      return 1
    }
  }
  0
}

///|
pub fn BigNat::add(self : BigNat, other : BigNat) -> BigNat {
  let a = self.normalize()
  let b = other.normalize()
  let max_len = if a.limbs.length() > b.limbs.length() {
    a.limbs.length()
  } else {
    b.limbs.length()
  }
  let res : Array[UInt] = Array::new(capacity=max_len + 1)
  let mut carry : UInt64 = 0UL

  for i in 0..<max_len {
    let limb_a : UInt64 = if i < a.limbs.length() {
      a.limbs[i].to_uint64()
    } else {
      0UL
    }
    let limb_b : UInt64 = if i < b.limbs.length() {
      b.limbs[i].to_uint64()
    } else {
      0UL
    }
    let sum = limb_a + limb_b + carry
    res.push((sum & 0xFFFFFFFFUL).to_uint())
    carry = sum >> 32
  }

  if carry > 0UL {
    res.push((carry & 0xFFFFFFFFUL).to_uint())
  }
  { limbs: res }.normalize()
}

///|
pub fn BigNat::sub(self : BigNat, other : BigNat) -> BigNat raise CoreError {
  let a = self.normalize()
  let b = other.normalize()
  if a.compare(b) < 0 {
    raise CryptoError("BigNat underflow in subtraction")
  }
  let res : Array[UInt] = Array::new(capacity=a.limbs.length())
  let mut borrow : UInt64 = 0UL

  for i in 0..<a.limbs.length() {
    let limb_a = a.limbs[i].to_uint64()
    let limb_b = if i < b.limbs.length() { b.limbs[i].to_uint64() } else { 0UL }
    let diff = limb_a - limb_b - borrow
    if diff > limb_a { // wrapped
      res.push((diff & 0xFFFFFFFFUL).to_uint())
      borrow = 1UL
    } else {
      res.push((diff & 0xFFFFFFFFUL).to_uint())
      borrow = 0UL
    }
  }
  { limbs: res }.normalize()
}

///|
pub fn BigNat::mul_digit(self : BigNat, digit : UInt) -> BigNat {
  if digit == 0U || self.is_zero() {
    return BigNat::zero()
  }
  let a = self.normalize()
  let d = digit.to_uint64()
  let res : Array[UInt] = Array::new(capacity=a.limbs.length() + 1)
  let mut carry : UInt64 = 0UL

  for i in 0..<a.limbs.length() {
    let prod = a.limbs[i].to_uint64() * d + carry
    res.push((prod & 0xFFFFFFFFUL).to_uint())
    carry = prod >> 32
  }
  if carry > 0UL {
    res.push((carry & 0xFFFFFFFFUL).to_uint())
  }
  { limbs: res }.normalize()
}

///|
pub fn BigNat::mul(self : BigNat, other : BigNat) -> BigNat {
  let a = self.normalize()
  let b = other.normalize()
  if a.is_zero() || b.is_zero() {
    return BigNat::zero()
  }
  let len_a = a.limbs.length()
  let len_b = b.limbs.length()
  let res_len = len_a + len_b
  let res : Array[UInt64] = Array::make(res_len, 0UL)

  for i in 0..<len_a {
    let x = a.limbs[i].to_uint64()
    let mut carry = 0UL
    for j in 0..<len_b {
      let y = b.limbs[j].to_uint64()
      let cur = res[i + j] + x * y + carry
      res[i + j] = cur & 0xFFFFFFFFUL
      carry = cur >> 32
    }
    if carry > 0UL {
      res[i + len_b] += carry
    }
  }

  let final_limbs : Array[UInt] = Array::new(capacity=res_len)
  let mut carry = 0UL
  for i in 0..<res_len {
    let sum = res[i] + carry
    final_limbs.push((sum & 0xFFFFFFFFUL).to_uint())
    carry = sum >> 32
  }
  { limbs: final_limbs }.normalize()
}

///|
pub fn BigNat::shl_limbs(self : BigNat, n : Int) -> BigNat {
  if self.is_zero() || n == 0 {
    return self
  }
  let a = self.normalize()
  let res : Array[UInt] = Array::make(n + a.limbs.length(), 0U)
  for i in 0..<a.limbs.length() {
    res[n + i] = a.limbs[i]
  }
  { limbs: res }.normalize()
}

///|
pub fn BigNat::shl_bits(self : BigNat, bits : Int) -> BigNat {
  if self.is_zero() || bits == 0 {
    return self
  }
  let limb_shifts = bits / 32
  let bit_shifts = bits % 32
  let shifted = self.shl_limbs(limb_shifts)
  if bit_shifts == 0 {
    return shifted
  }
  let a = shifted.normalize()
  let res : Array[UInt] = Array::new(capacity=a.limbs.length() + 1)
  let mut carry = 0U
  for i in 0..<a.limbs.length() {
    let cur = (a.limbs[i] << bit_shifts) | carry
    res.push(cur)
    carry = a.limbs[i] >> (32 - bit_shifts)
  }
  if carry != 0U {
    res.push(carry)
  }
  { limbs: res }.normalize()
}

///|
pub fn BigNat::shr_bits(self : BigNat, bits : Int) -> BigNat {
  let a = self.normalize()
  let limb_shifts = bits / 32
  let bit_shifts = bits % 32
  if limb_shifts >= a.limbs.length() {
    return BigNat::zero()
  }
  let effective_len = a.limbs.length() - limb_shifts
  let res : Array[UInt] = Array::new(capacity=effective_len)
  if bit_shifts == 0 {
    for i in limb_shifts..<a.limbs.length() {
      res.push(a.limbs[i])
    }
    return { limbs: res }.normalize()
  }
  for i in 0..<effective_len {
    let src_idx = limb_shifts + i
    let cur = a.limbs[src_idx] >> bit_shifts
    let next_bits = if src_idx + 1 < a.limbs.length() {
      a.limbs[src_idx + 1] << (32 - bit_shifts)
    } else {
      0U
    }
    res.push(cur | next_bits)
  }
  { limbs: res }.normalize()
}

///|
pub fn BigNat::bit_length(self : BigNat) -> Int {
  let a = self.normalize()
  if a.limbs.length() == 0 {
    return 0
  }
  let top = a.limbs[a.limbs.length() - 1]
  let mut top_bits = 0
  let mut val = top
  while val > 0U {
    top_bits += 1
    val = val >> 1
  }
  (a.limbs.length() - 1) * 32 + top_bits
}

///|
pub fn BigNat::test_bit(self : BigNat, bit : Int) -> Bool {
  let a = self.normalize()
  let limb_idx = bit / 32
  let bit_idx = bit % 32
  if limb_idx >= a.limbs.length() {
    false
  } else {
    ((a.limbs[limb_idx] >> bit_idx) & 1U) == 1U
  }
}

///|
pub fn BigNat::div_rem(
  self : BigNat,
  divisor : BigNat,
) -> (BigNat, BigNat) raise CoreError {
  let num = self.normalize()
  let den = divisor.normalize()
  if den.is_zero() {
    raise CryptoError("BigNat division by zero")
  }
  if num.compare(den) < 0 {
    return (BigNat::zero(), num)
  }
  if den.is_one() {
    return (num, BigNat::zero())
  }

  let m = den.limbs.length()
  let n = num.limbs.length()

  if m == 1 {
    let d = den.limbs[0].to_uint64()
    let mut rem = 0UL
    let q_limbs : Array[UInt] = Array::make(n, 0U)
    for i = n - 1; i >= 0; i = i - 1 {
      let cur = (rem << 32) | num.limbs[i].to_uint64()
      q_limbs[i] = (cur / d).to_uint()
      rem = cur % d
    }
    let q = { limbs: q_limbs }.normalize()
    let r = BigNat::from_uint64(rem)
    return (q, r)
  }

  // Multi-limb division with binary shift-and-subtract
  let mut quotient = BigNat::zero()
  let mut remainder = BigNat::zero()
  let num_bits = num.bit_length()

  for i = num_bits - 1; i >= 0; i = i - 1 {
    remainder = remainder.shl_bits(1)
    if num.test_bit(i) {
      remainder = remainder.add(BigNat::one())
    }
    if remainder.compare(den) >= 0 {
      remainder = remainder.sub(den)
      quotient = quotient.add(BigNat::one().shl_bits(i))
    }
  }

  (quotient.normalize(), remainder.normalize())
}

///|
pub fn BigNat::div(self : BigNat, divisor : BigNat) -> BigNat raise CoreError {
  let (q, _) = self.div_rem(divisor)
  q
}

///|
pub fn BigNat::rem(self : BigNat, divisor : BigNat) -> BigNat raise CoreError {
  let (_, r) = self.div_rem(divisor)
  r
}

///|
pub fn BigNat::add_mod(
  self : BigNat,
  other : BigNat,
  m : BigNat,
) -> BigNat raise CoreError {
  let sum = self.add(other)
  sum.rem(m)
}

///|
pub fn BigNat::sub_mod(
  self : BigNat,
  other : BigNat,
  m : BigNat,
) -> BigNat raise CoreError {
  let a = self.rem(m)
  let b = other.rem(m)
  if a.compare(b) >= 0 {
    a.sub(b)
  } else {
    let diff = b.sub(a)
    m.sub(diff)
  }
}

///|
pub fn BigNat::mul_mod(
  self : BigNat,
  other : BigNat,
  m : BigNat,
) -> BigNat raise CoreError {
  let prod = self.mul(other)
  prod.rem(m)
}

///|
/// Modular exponentiation: computes (base ^ exp) % modulus in O(log(exp)) time.
pub fn BigNat::pow_mod(
  self : BigNat,
  exp : BigNat,
  m : BigNat,
) -> BigNat raise CoreError {
  if m.is_one() {
    return BigNat::zero()
  }
  let mut res = BigNat::one()
  let mut base = self.rem(m)
  let exp_norm = exp.normalize()
  let bit_len = exp_norm.bit_length()

  for i = 0; i < bit_len; i = i + 1 {
    if exp_norm.test_bit(i) {
      res = res.mul_mod(base, m)
    }
    base = base.mul_mod(base, m)
  }
  res
}

///|
/// Extended Euclidean Algorithm for BigNat to find modular inverse.
pub fn BigNat::inv_mod(self : BigNat, m : BigNat) -> BigNat raise CoreError {
  let a = self.rem(m)
  if a.is_zero() {
    raise CryptoError("Cannot compute inverse of zero")
  }
  let mut lm = BigNat::one()
  let mut hm = BigNat::zero()
  let mut low = a
  let mut high = m

  while !low.is_one() {
    if low.is_zero() {
      raise CryptoError("Modular inverse does not exist (not coprime)")
    }
    let (ratio, rem) = high.div_rem(low)
    let nm = hm.add(ratio.mul(lm))
    hm = lm
    lm = nm
    high = low
    low = rem
  }
  m.sub(lm.rem(m))
}

///|
pub fn BigNat::from_bytes_be(b : Bytes) -> BigNat {
  let len = b.length()
  if len == 0 {
    return BigNat::zero()
  }
  let limbs_count = (len + 3) / 4
  let limbs : Array[UInt] = Array::make(limbs_count, 0U)

  for i in 0..<len {
    let byte_val = b[len - 1 - i].to_uint()
    let limb_idx = i / 4
    let byte_offset = i % 4 * 8
    limbs[limb_idx] = limbs[limb_idx] | (byte_val << byte_offset)
  }
  { limbs, }.normalize()
}

///|
pub fn BigNat::to_bytes_be(self : BigNat, size? : Int) -> Bytes {
  let a = self.normalize()
  let raw_len = if a.limbs.length() == 0 {
    1
  } else {
    let top = a.limbs[a.limbs.length() - 1]
    let mut top_bytes = 0
    let mut v = top
    while v > 0U {
      top_bytes += 1
      v = v >> 8
    }
    (a.limbs.length() - 1) * 4 + top_bytes
  }

  let final_len = match size {
    Some(s) => if s > raw_len { s } else { raw_len }
    None => raw_len
  }

  let fa : FixedArray[Byte] = FixedArray::make(final_len, b'\x00')
  for i in 0..<raw_len {
    let limb_idx = i / 4
    let byte_offset = i % 4 * 8
    if limb_idx < a.limbs.length() {
      let b_val = ((a.limbs[limb_idx] >> byte_offset) & 0xFFU).to_byte()
      fa[final_len - 1 - i] = b_val
    }
  }
  Bytes::from_array(fa[:])
}

///|
pub fn BigNat::from_bytes_le(b : Bytes) -> BigNat {
  let len = b.length()
  if len == 0 {
    return BigNat::zero()
  }
  let limbs_count = (len + 3) / 4
  let limbs : Array[UInt] = Array::make(limbs_count, 0U)

  for i in 0..<len {
    let byte_val = b[i].to_uint()
    let limb_idx = i / 4
    let byte_offset = i % 4 * 8
    limbs[limb_idx] = limbs[limb_idx] | (byte_val << byte_offset)
  }
  { limbs, }.normalize()
}

///|
pub fn BigNat::to_bytes_le(self : BigNat, size? : Int) -> Bytes {
  let a = self.normalize()
  let raw_len = if a.limbs.length() == 0 {
    1
  } else {
    let top = a.limbs[a.limbs.length() - 1]
    let mut top_bytes = 0
    let mut v = top
    while v > 0U {
      top_bytes += 1
      v = v >> 8
    }
    (a.limbs.length() - 1) * 4 + top_bytes
  }

  let final_len = match size {
    Some(s) => if s > raw_len { s } else { raw_len }
    None => raw_len
  }

  let fa : FixedArray[Byte] = FixedArray::make(final_len, b'\x00')
  for i in 0..<raw_len {
    let limb_idx = i / 4
    let byte_offset = i % 4 * 8
    if limb_idx < a.limbs.length() {
      let b_val = ((a.limbs[limb_idx] >> byte_offset) & 0xFFU).to_byte()
      fa[i] = b_val
    }
  }
  Bytes::from_array(fa[:])
}
