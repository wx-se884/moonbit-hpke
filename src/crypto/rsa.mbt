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
pub(all) struct RsaPublicKey {
  n : @core.BigNat
  e : @core.BigNat
} derive(Debug, Eq)

///|
pub(all) struct RsaPrivateKey {
  n : @core.BigNat
  e : @core.BigNat
  d : @core.BigNat
  p : @core.BigNat?
  q : @core.BigNat?
  dp : @core.BigNat?
  dq : @core.BigNat?
  qi : @core.BigNat?
} derive(Debug, Eq)

///|
pub fn RsaPublicKey::encrypt_raw(
  self : RsaPublicKey,
  m : @core.BigNat,
) -> @core.BigNat raise @core.CoreError {
  m.pow_mod(self.e, self.n)
}

///|
pub fn RsaPrivateKey::decrypt_raw(
  self : RsaPrivateKey,
  c : @core.BigNat,
) -> @core.BigNat raise @core.CoreError {
  c.pow_mod(self.d, self.n)
}

///|
// SHA-256 DigestInfo prefix for PKCS#1 v1.5
let sha256_digest_info_prefix_hex : String = "3031300d060960864801650304020105000420"

///|
pub fn pkcs1_v15_sign_sha256(
  priv_key : RsaPrivateKey,
  digest : Bytes,
) -> Bytes raise @core.CoreError {
  let k = (priv_key.n.bit_length() + 7) / 8
  let prefix = @core.hex_decode(sha256_digest_info_prefix_hex)
  let t = @core.bytes_concat(prefix, digest)
  let t_len = t.length()
  if k < t_len + 11 {
    raise CryptoError("RSA modulus too short for PKCS#1 v1.5 signature")
  }
  let ps_len = k - t_len - 3
  let em : FixedArray[Byte] = FixedArray::make(k, b'\x00')
  em[0] = b'\x00'
  em[1] = b'\x01'
  for i in 0..<ps_len {
    em[2 + i] = b'\xff'
  }
  em[2 + ps_len] = b'\x00'
  for i in 0..<t_len {
    em[3 + ps_len + i] = t[i]
  }

  let m = @core.BigNat::from_bytes_be(Bytes::from_array(em[:]))
  let s = priv_key.decrypt_raw(m)
  s.to_bytes_be(size=k)
}

///|
pub fn pkcs1_v15_verify_sha256(
  pub_key : RsaPublicKey,
  digest : Bytes,
  sig : Bytes,
) -> Bool raise @core.CoreError {
  let k = (pub_key.n.bit_length() + 7) / 8
  if sig.length() != k {
    return false
  }
  let s = @core.BigNat::from_bytes_be(sig)
  if s.compare(pub_key.n) >= 0 {
    return false
  }
  let m = pub_key.encrypt_raw(s)
  let em = m.to_bytes_be(size=k)

  let prefix = @core.hex_decode(sha256_digest_info_prefix_hex)
  let t = @core.bytes_concat(prefix, digest)
  let t_len = t.length()
  if k < t_len + 11 {
    return false
  }
  let ps_len = k - t_len - 3

  if em[0] != b'\x00' || em[1] != b'\x01' || em[2 + ps_len] != b'\x00' {
    return false
  }
  for i in 0..<ps_len {
    if em[2 + i] != b'\xff' {
      return false
    }
  }
  let recovered_t = @core.bytes_slice(em, 3 + ps_len, t_len)
  @core.constant_time_compare(recovered_t, t)
}

///|
fn mgf1_sha256(seed : Bytes, length : Int) -> Bytes {
  let hash_len = 32
  let n = (length + hash_len - 1) / hash_len
  let out : FixedArray[Byte] = FixedArray::make(length, b'\x00')
  let mut bytes_written = 0

  for c = 0; c < n; c = c + 1 {
    let c_bytes = @core.put_u32_be(c.reinterpret_as_uint())
    let h = sha256(@core.bytes_concat(seed, c_bytes))
    let to_copy = if bytes_written + hash_len <= length {
      hash_len
    } else {
      length - bytes_written
    }
    for i in 0..<to_copy {
      out[bytes_written + i] = h[i]
    }
    bytes_written += to_copy
  }

  Bytes::from_array(out[:])
}

///|
pub fn rsa_oaep_encrypt(
  pub_key : RsaPublicKey,
  m : Bytes,
  label? : Bytes = Bytes::make(0, b'\x00'),
  seed~ : Bytes,
) -> Bytes raise @core.CoreError {
  let k = (pub_key.n.bit_length() + 7) / 8
  let h_len = 32
  let m_len = m.length()
  if m_len > k - 2 * h_len - 2 {
    raise CryptoError("Message too long for RSA-OAEP")
  }
  let l_hash = sha256(label)
  let ps_len = k - m_len - 2 * h_len - 2
  let db_len = k - h_len - 1
  let db : FixedArray[Byte] = FixedArray::make(db_len, b'\x00')

  for i in 0..<h_len {
    db[i] = l_hash[i]
  }
  for i in 0..<ps_len {
    db[h_len + i] = b'\x00'
  }
  db[h_len + ps_len] = b'\x01'
  for i in 0..<m_len {
    db[h_len + ps_len + 1 + i] = m[i]
  }

  let db_mask = mgf1_sha256(seed, db_len)
  let masked_db = @core.bytes_xor(Bytes::from_array(db[:]), db_mask)
  let seed_mask = mgf1_sha256(masked_db, h_len)
  let masked_seed = @core.bytes_xor(seed, seed_mask)

  let em : FixedArray[Byte] = FixedArray::make(k, b'\x00')
  em[0] = b'\x00'
  for i in 0..<h_len {
    em[1 + i] = masked_seed[i]
  }
  for i in 0..<db_len {
    em[1 + h_len + i] = masked_db[i]
  }

  let m_nat = @core.BigNat::from_bytes_be(Bytes::from_array(em[:]))
  let c = pub_key.encrypt_raw(m_nat)
  c.to_bytes_be(size=k)
}

///|
pub fn rsa_oaep_decrypt(
  priv_key : RsaPrivateKey,
  c_bytes : Bytes,
  label? : Bytes = Bytes::make(0, b'\x00'),
) -> Bytes raise @core.CoreError {
  let k = (priv_key.n.bit_length() + 7) / 8
  let h_len = 32
  if c_bytes.length() != k || k < 2 * h_len + 2 {
    raise CryptoError("Decryption error: invalid ciphertext length")
  }
  let c = @core.BigNat::from_bytes_be(c_bytes)
  if c.compare(priv_key.n) >= 0 {
    raise CryptoError("Decryption error: ciphertext out of range")
  }
  let m_nat = priv_key.decrypt_raw(c)
  let em = m_nat.to_bytes_be(size=k)

  let l_hash = sha256(label)
  let masked_seed = @core.bytes_slice(em, 1, h_len)
  let masked_db = @core.bytes_slice(em, 1 + h_len, k - h_len - 1)

  let seed_mask = mgf1_sha256(masked_db, h_len)
  let seed = @core.bytes_xor(masked_seed, seed_mask)
  let db_mask = mgf1_sha256(seed, k - h_len - 1)
  let db = @core.bytes_xor(masked_db, db_mask)

  let recovered_l_hash = @core.bytes_slice(db, 0, h_len)
  if !@core.constant_time_compare(recovered_l_hash, l_hash) || em[0] != b'\x00' {
    raise CryptoError("Decryption error: OAEP decoding failed")
  }

  let mut idx = h_len
  while idx < db.length() && db[idx] == b'\x00' {
    idx += 1
  }
  if idx >= db.length() || db[idx] != b'\x01' {
    raise CryptoError("Decryption error: OAEP delimiter not found")
  }

  @core.bytes_slice(db, idx + 1, db.length() - (idx + 1))
}
