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
pub(all) struct JwsHeader {
  alg : String
  typ : String?
  kid : String?
  crit : Array[String]?
} derive(Debug, Eq)

///|
pub fn JwsHeader::to_json_string(self : JwsHeader) -> String {
  let buf = StringBuilder::new()
  buf.write_string("{\"alg\":\"" + self.alg + "\"")
  match self.typ {
    Some(t) => buf.write_string(",\"typ\":\"" + t + "\"")
    None => ()
  }
  match self.kid {
    Some(k) => buf.write_string(",\"kid\":\"" + k + "\"")
    None => ()
  }
  match self.crit {
    Some(items) => {
      buf.write_string(",\"crit\":[")
      let mut first = true
      for item in items {
        if !first {
          buf.write_string(",")
        }
        buf.write_string("\"" + item + "\"")
        first = false
      }
      buf.write_string("]")
    }
    None => ()
  }
  buf.write_string("}")
  buf.to_string()
}

///|
pub fn jws_parse_header(json_str : String) -> JwsHeader raise @core.CoreError {
  // Extract alg
  let alg_idx = @core.string_index_of(json_str, "\"alg\":\"")
  let alg = if alg_idx >= 0 {
    let start = alg_idx + 7
    let end_idx = @core.string_index_of(json_str, "\"", start~)
    if end_idx < 0 {
      raise CryptoError("Malformed alg field in JWS header")
    }
    @core.string_slice(json_str, start, end_idx - start)
  } else {
    raise CryptoError("Missing required alg in JWS header")
  }

  if alg == "none" || alg == "NONE" {
    raise CryptoError("Algorithm 'none' is strictly prohibited")
  }

  // Extract typ
  let typ_idx = @core.string_index_of(json_str, "\"typ\":\"")
  let typ = if typ_idx >= 0 {
    let start = typ_idx + 7
    let end_idx = @core.string_index_of(json_str, "\"", start~)
    if end_idx >= 0 {
      Some(@core.string_slice(json_str, start, end_idx - start))
    } else {
      None
    }
  } else {
    None
  }

  // Extract kid
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

  let crit_idx = @core.string_index_of(json_str, "\"crit\":[")
  let crit = if crit_idx >= 0 {
    let start = crit_idx + 8
    let end_idx = @core.string_index_of(json_str, "]", start~)
    if end_idx < 0 {
      None
    } else {
      let content = @core.string_slice(json_str, start, end_idx - start)
      if content == "" {
        Some([])
      } else {
        let items : Array[String] = []
        for raw in @core.string_split(content, "\",\"") {
          let item = if raw.length() >= 2 {
            @core.string_slice(raw, 1, raw.length() - 2)
          } else {
            raw
          }
          items.push(item)
        }
        Some(items)
      }
    }
  } else {
    None
  }

  { alg, typ, kid, crit }
}

///|
pub fn jws_sign(
  alg : String,
  payload : Bytes,
  key : Bytes,
  typ? : String,
  kid? : String,
) -> String raise @core.CoreError {
  let header : JwsHeader = { alg, typ, kid, crit: None }
  let header_json = header.to_json_string()
  let b64_header = @core.base64url_encode(
    @core.string_to_utf8_bytes(header_json),
  )
  let b64_payload = @core.base64url_encode(payload)
  let signing_input = @core.string_to_utf8_bytes(b64_header + "." + b64_payload)

  let sig_bytes = match alg {
    "HS256" => @crypto.hmac_sha256(key, signing_input)
    "HS384" => @crypto.hmac_sha384(key, signing_input)
    "HS512" => @crypto.hmac_sha512(key, signing_input)
    "EdDSA" => @crypto.ed25519_sign(key, signing_input)
    _ => raise CryptoError("Unsupported JWS algorithm for signing: " + alg)
  }

  let b64_sig = @core.base64url_encode(sig_bytes)
  b64_header + "." + b64_payload + "." + b64_sig
}

///|
pub fn jws_verify(
  compact_jws : String,
  key : Bytes,
) -> (JwsHeader, Bytes) raise @core.CoreError {
  let parts = @core.string_split(compact_jws, ".")
  if parts.length() != 3 {
    raise CryptoError("Invalid compact JWS serialization: must contain 3 parts")
  }

  let b64_header = parts[0]
  let b64_payload = parts[1]
  let b64_sig = parts[2]

  let header_bytes = @core.base64url_decode(b64_header)
  let header_json = @core.utf8_bytes_to_string(header_bytes)
  let header = jws_parse_header(header_json)

  let payload = @core.base64url_decode(b64_payload)
  let sig = @core.base64url_decode(b64_sig)
  let signing_input = @core.string_to_utf8_bytes(b64_header + "." + b64_payload)

  let valid = match header.alg {
    "HS256" => {
      let expected = @crypto.hmac_sha256(key, signing_input)
      @core.bytes_equal(sig, expected)
    }
    "HS384" => {
      let expected = @crypto.hmac_sha384(key, signing_input)
      @core.bytes_equal(sig, expected)
    }
    "HS512" => {
      let expected = @crypto.hmac_sha512(key, signing_input)
      @core.bytes_equal(sig, expected)
    }
    "EdDSA" => @crypto.ed25519_verify(key, signing_input, sig)
    _ =>
      raise CryptoError(
        "Unsupported JWS algorithm for verification: " + header.alg,
      )
  }

  if !valid {
    raise CryptoError("JWS signature verification failed")
  }

  (header, payload)
}
