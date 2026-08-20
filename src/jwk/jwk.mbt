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
pub(all) enum KeyType {
  OCT
  OKP
  EC
  RSA
} derive(Debug, Eq)

///|
pub(all) struct Jwk {
  kty : String
  crv : String?
  x : String?
  y : String?
  d : String?
  k : String?
  n : String?
  e : String?
  kid : String?
  use_opt : String?
  alg : String?
} derive(Debug, Eq)

///|
pub fn Jwk::new_oct(key_bytes : Bytes, kid? : String, alg? : String) -> Jwk {
  {
    kty: "oct",
    crv: None,
    x: None,
    y: None,
    d: None,
    k: Some(@core.base64url_encode(key_bytes)),
    n: None,
    e: None,
    kid,
    use_opt: Some("enc"),
    alg,
  }
}

///|
pub fn Jwk::new_okp_x25519(
  pub_key : Bytes,
  priv_key? : Bytes,
  kid? : String,
) -> Jwk {
  {
    kty: "OKP",
    crv: Some("X25519"),
    x: Some(@core.base64url_encode(pub_key)),
    y: None,
    d: match priv_key {
      Some(d_bytes) => Some(@core.base64url_encode(d_bytes))
      None => None
    },
    k: None,
    n: None,
    e: None,
    kid,
    use_opt: Some("enc"),
    alg: Some("ECDH-ES"),
  }
}

///|
pub fn Jwk::new_okp_ed25519(
  pub_key : Bytes,
  priv_key? : Bytes,
  kid? : String,
) -> Jwk {
  {
    kty: "OKP",
    crv: Some("Ed25519"),
    x: Some(@core.base64url_encode(pub_key)),
    y: None,
    d: match priv_key {
      Some(d_bytes) => Some(@core.base64url_encode(d_bytes))
      None => None
    },
    k: None,
    n: None,
    e: None,
    kid,
    use_opt: Some("sig"),
    alg: Some("EdDSA"),
  }
}

///|
pub fn Jwk::new_ec_p256(
  pub_key_uncompressed : Bytes,
  priv_key? : Bytes,
  kid? : String,
  alg? : String,
) -> Jwk raise @core.CoreError {
  if pub_key_uncompressed.length() != 65 || pub_key_uncompressed[0] != b'\x04' {
    raise CryptoError("P-256 public key must be 65-byte uncompressed format")
  }
  let x_bytes = @core.bytes_slice(pub_key_uncompressed, 1, 32)
  let y_bytes = @core.bytes_slice(pub_key_uncompressed, 33, 32)

  {
    kty: "EC",
    crv: Some("P-256"),
    x: Some(@core.base64url_encode(x_bytes)),
    y: Some(@core.base64url_encode(y_bytes)),
    d: match priv_key {
      Some(d_bytes) => Some(@core.base64url_encode(d_bytes))
      None => None
    },
    k: None,
    n: None,
    e: None,
    kid,
    use_opt: Some("sig"),
    alg,
  }
}

///|
pub fn Jwk::to_public(self : Jwk) -> Jwk {
  {
    kty: self.kty,
    crv: self.crv,
    x: self.x,
    y: self.y,
    d: None,
    k: None,
    n: self.n,
    e: self.e,
    kid: self.kid,
    use_opt: self.use_opt,
    alg: self.alg,
  }
}

///|
pub fn Jwk::is_private(self : Jwk) -> Bool {
  match self.d {
    Some(_) => true
    None =>
      match self.k {
        Some(_) => true
        None => false
      }
  }
}

///|
pub fn Jwk::thumbprint_sha256(self : Jwk) -> String raise @core.CoreError {
  let canonical_json = match self.kty {
    "oct" => {
      let k_val = match self.k {
        Some(v) => v
        None =>
          raise CryptoError("Missing required parameter 'k' for oct thumbprint")
      }
      "{\"k\":\"" + k_val + "\",\"kty\":\"oct\"}"
    }
    "OKP" => {
      let crv_val = match self.crv {
        Some(v) => v
        None => raise CryptoError("Missing 'crv' in OKP thumbprint")
      }
      let x_val = match self.x {
        Some(v) => v
        None => raise CryptoError("Missing 'x' in OKP thumbprint")
      }
      "{\"crv\":\"" + crv_val + "\",\"kty\":\"OKP\",\"x\":\"" + x_val + "\"}"
    }
    "EC" => {
      let crv_val = match self.crv {
        Some(v) => v
        None => raise CryptoError("Missing 'crv' in EC thumbprint")
      }
      let x_val = match self.x {
        Some(v) => v
        None => raise CryptoError("Missing 'x' in EC thumbprint")
      }
      let y_val = match self.y {
        Some(v) => v
        None => raise CryptoError("Missing 'y' in EC thumbprint")
      }
      "{\"crv\":\"" +
      crv_val +
      "\",\"kty\":\"EC\",\"x\":\"" +
      x_val +
      "\",\"y\":\"" +
      y_val +
      "\"}"
    }
    "RSA" => {
      let e_val = match self.e {
        Some(v) => v
        None => raise CryptoError("Missing 'e' in RSA thumbprint")
      }
      let n_val = match self.n {
        Some(v) => v
        None => raise CryptoError("Missing 'n' in RSA thumbprint")
      }
      "{\"e\":\"" + e_val + "\",\"kty\":\"RSA\",\"n\":\"" + n_val + "\"}"
    }
    _ => raise CryptoError("Unsupported kty for thumbprint: " + self.kty)
  }

  let utf8 = @core.string_to_utf8_bytes(canonical_json)
  let digest = @crypto.sha256(utf8)
  @core.base64url_encode(digest)
}

///|
pub(all) struct JwkSet {
  keys : Array[Jwk]
} derive(Debug, Eq)

///|
pub fn JwkSet::new(keys : Array[Jwk]) -> JwkSet {
  { keys, }
}

///|
pub fn JwkSet::find_by_kid(self : JwkSet, kid : String) -> Jwk? {
  for key in self.keys {
    match key.kid {
      Some(k) => if k == kid { return Some(key) }
      None => ()
    }
  }
  None
}

///|
pub fn JwkSet::to_public(self : JwkSet) -> JwkSet {
  let pub_keys = self.keys.map(fn(k) { k.to_public() })
  { keys: pub_keys }
}
