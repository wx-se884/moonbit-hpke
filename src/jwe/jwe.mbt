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
pub(all) struct JweHeader {
  alg : String
  enc : String
  kid : String?
  encap : String? // HPKE encapsulated key in base64url
} derive(Debug, Eq)

///|
pub fn JweHeader::to_json_string(self : JweHeader) -> String {
  let buf = StringBuilder::new()
  buf.write_string("{\"alg\":\"" + self.alg + "\",\"enc\":\"" + self.enc + "\"")
  match self.kid {
    Some(k) => buf.write_string(",\"kid\":\"" + k + "\"")
    None => ()
  }
  match self.encap {
    Some(e) => buf.write_string(",\"encap\":\"" + e + "\"")
    None => ()
  }
  buf.write_string("}")
  buf.to_string()
}

///|
pub fn jwe_parse_header(json_str : String) -> JweHeader raise @core.CoreError {
  let alg_idx = @core.string_index_of(json_str, "\"alg\":\"")
  let alg = if alg_idx >= 0 {
    let start = alg_idx + 7
    let end_idx = @core.string_index_of(json_str, "\"", start~)
    if end_idx < 0 {
      raise CryptoError("Malformed alg field in JWE header")
    }
    @core.string_slice(json_str, start, end_idx - start)
  } else {
    raise CryptoError("Missing required alg in JWE header")
  }

  let enc_idx = @core.string_index_of(json_str, "\"enc\":\"")
  let enc = if enc_idx >= 0 {
    let start = enc_idx + 7
    let end_idx = @core.string_index_of(json_str, "\"", start~)
    if end_idx < 0 {
      raise CryptoError("Malformed enc field in JWE header")
    }
    @core.string_slice(json_str, start, end_idx - start)
  } else {
    raise CryptoError("Missing required enc in JWE header")
  }

  let kid_idx = @core.string_index_of(json_str, "\"kid\":\"")
  let kid = if kid_idx >= 0 {
    let start = kid_idx + 7
    let end_idx = @core.string_index_of(json_str, "\"", start~)
    if end_idx >= 0 {
      Some(@core.string_slice(json_str, start, end_idx - start))
    } else {
      None
    }
  } else {
    None
  }

  let encap_idx = @core.string_index_of(json_str, "\"encap\":\"")
  let encap = if encap_idx >= 0 {
    let start = encap_idx + 9
    let end_idx = @core.string_index_of(json_str, "\"", start~)
    if end_idx >= 0 {
      Some(@core.string_slice(json_str, start, end_idx - start))
    } else {
      None
    }
  } else {
    None
  }

  { alg, enc, kid, encap }
}

///|
pub fn jwe_encrypt(
  alg : String,
  enc : String,
  plaintext : Bytes,
  key : Bytes,
  iv : Bytes,
  kid? : String,
  cek_override? : Bytes,
  ephemeral_key? : Bytes,
) -> String raise @core.CoreError {
  let cek = match cek_override {
    Some(k) => k
    None =>
      match enc {
        "A128GCM" => Bytes::make(16, b'\x42')
        "A256GCM" => Bytes::make(32, b'\x42')
        "ChaCha20-Poly1305" => Bytes::make(32, b'\x42')
        _ => raise CryptoError("Unsupported JWE enc algorithm: " + enc)
      }
  }

  let (encrypted_key, encap_opt) = match alg {
    "dir" => (Bytes::make(0, b'\x00'), None)
    "A128KW" | "A256KW" => (@crypto.aes_key_wrap(key, cek), None)
    "HPKE-Base-X25519-SHA256-ChaCha20Poly1305" => {
      let suite : @hpke.HpkeSuite = {
        kem: DHKEM_X25519_HKDF_SHA256,
        kdf: HKDF_SHA256,
        aead: CHACHA20_POLY1305,
      }
      let sk_e = match ephemeral_key {
        Some(e) => e
        None => Bytes::make(32, b'\x01')
      }
      let (enc_bytes, ct) = @hpke.hpke_seal_base_deterministic(
        suite,
        key,
        Bytes::make(0, b'\x00'),
        Bytes::make(0, b'\x00'),
        cek,
        sk_e,
      )
      (ct, Some(@core.base64url_encode(enc_bytes)))
    }
    _ => raise CryptoError("Unsupported JWE alg algorithm: " + alg)
  }

  let actual_cek = if alg == "dir" { key } else { cek }
  let header : JweHeader = { alg, enc, kid, encap: encap_opt }
  let header_json = header.to_json_string()
  let b64_header = @core.base64url_encode(
    @core.string_to_utf8_bytes(header_json),
  )
  let aad = @core.string_to_utf8_bytes(b64_header)

  let (ct_bytes, tag_bytes) = match enc {
    "A128GCM" | "A256GCM" => {
      let (ct, tag) = @crypto.aes_gcm_encrypt(actual_cek, iv, plaintext, aad)
      (ct, tag)
    }
    "ChaCha20-Poly1305" => {
      let (ct, tag) = @crypto.chacha20poly1305_encrypt(
        actual_cek, iv, plaintext, aad,
      )
      (ct, tag)
    }
    _ => raise CryptoError("Unsupported JWE enc algorithm: " + enc)
  }

  let b64_ek = @core.base64url_encode(encrypted_key)
  let b64_iv = @core.base64url_encode(iv)
  let b64_ct = @core.base64url_encode(ct_bytes)
  let b64_tag = @core.base64url_encode(tag_bytes)

  b64_header + "." + b64_ek + "." + b64_iv + "." + b64_ct + "." + b64_tag
}

///|
pub fn jwe_decrypt(
  compact_jwe : String,
  key : Bytes,
) -> (JweHeader, Bytes) raise @core.CoreError {
  let parts = @core.string_split(compact_jwe, ".")
  if parts.length() != 5 {
    raise CryptoError("Invalid compact JWE: must contain 5 parts")
  }

  let b64_header = parts[0]
  let b64_ek = parts[1]
  let b64_iv = parts[2]
  let b64_ct = parts[3]
  let b64_tag = parts[4]

  let header_bytes = @core.base64url_decode(b64_header)
  let header_json = @core.utf8_bytes_to_string(header_bytes)
  let header = jwe_parse_header(header_json)

  let encrypted_key = @core.base64url_decode(b64_ek)
  let iv = @core.base64url_decode(b64_iv)
  let ct = @core.base64url_decode(b64_ct)
  let tag = @core.base64url_decode(b64_tag)
  let aad = @core.string_to_utf8_bytes(b64_header)

  let cek = match header.alg {
    "dir" => key
    "A128KW" | "A256KW" => @crypto.aes_key_unwrap(key, encrypted_key)
    "HPKE-Base-X25519-SHA256-ChaCha20Poly1305" => {
      let encap_str = match header.encap {
        Some(e) => e
        None => raise CryptoError("Missing encap parameter for HPKE JWE")
      }
      let encap_bytes = @core.base64url_decode(encap_str)
      let suite : @hpke.HpkeSuite = {
        kem: DHKEM_X25519_HKDF_SHA256,
        kdf: HKDF_SHA256,
        aead: CHACHA20_POLY1305,
      }
      @hpke.hpke_open_base(
        suite,
        encap_bytes,
        key,
        Bytes::make(0, b'\x00'),
        Bytes::make(0, b'\x00'),
        encrypted_key,
      )
    }
    _ => raise CryptoError("Unsupported JWE alg algorithm: " + header.alg)
  }

  let plaintext = match header.enc {
    "A128GCM" | "A256GCM" => @crypto.aes_gcm_decrypt(cek, iv, ct, tag, aad)
    "ChaCha20-Poly1305" =>
      @crypto.chacha20poly1305_decrypt(cek, iv, ct, tag, aad)
    _ => raise CryptoError("Unsupported JWE enc algorithm: " + header.enc)
  }

  (header, plaintext)
}
