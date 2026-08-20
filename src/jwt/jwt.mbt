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
pub(all) struct Claims {
  iss : String?
  sub : String?
  aud : String?
  exp : Int64?
  nbf : Int64?
  iat : Int64?
  jti : String?
} derive(Debug, Eq)

///|
pub fn Claims::new(
  iss? : String,
  sub? : String,
  aud? : String,
  exp? : Int64,
  nbf? : Int64,
  iat? : Int64,
  jti? : String,
) -> Claims {
  { iss, sub, aud, exp, nbf, iat, jti }
}

///|
pub fn Claims::to_json_string(self : Claims) -> String {
  let buf = StringBuilder::new()
  buf.write_string("{")
  let mut first = true

  match self.iss {
    Some(i) => {
      if !first {
        buf.write_string(",")
      }
      buf.write_string("\"iss\":\"" + i + "\"")
      first = false
    }
    None => ()
  }
  match self.sub {
    Some(s) => {
      if !first {
        buf.write_string(",")
      }
      buf.write_string("\"sub\":\"" + s + "\"")
      first = false
    }
    None => ()
  }
  match self.aud {
    Some(a) => {
      if !first {
        buf.write_string(",")
      }
      buf.write_string("\"aud\":\"" + a + "\"")
      first = false
    }
    None => ()
  }
  match self.exp {
    Some(e) => {
      if !first {
        buf.write_string(",")
      }
      buf.write_string("\"exp\":" + e.to_string())
      first = false
    }
    None => ()
  }
  match self.nbf {
    Some(n) => {
      if !first {
        buf.write_string(",")
      }
      buf.write_string("\"nbf\":" + n.to_string())
      first = false
    }
    None => ()
  }
  match self.iat {
    Some(ia) => {
      if !first {
        buf.write_string(",")
      }
      buf.write_string("\"iat\":" + ia.to_string())
      first = false
    }
    None => ()
  }
  match self.jti {
    Some(j) => {
      if !first {
        buf.write_string(",")
      }
      buf.write_string("\"jti\":\"" + j + "\"")
    }
    None => ()
  }

  buf.write_string("}")
  buf.to_string()
}

///|
pub fn parse_claims(json_str : String) -> Claims {
  let iss_idx = @core.string_index_of(json_str, "\"iss\":\"")
  let iss = if iss_idx >= 0 {
    let start = iss_idx + 7
    let end_idx = @core.string_index_of(json_str, "\"", start~)
    if end_idx >= 0 {
      Some(@core.string_slice(json_str, start, end_idx - start))
    } else {
      None
    }
  } else {
    None
  }

  let sub_idx = @core.string_index_of(json_str, "\"sub\":\"")
  let sub = if sub_idx >= 0 {
    let start = sub_idx + 7
    let end_idx = @core.string_index_of(json_str, "\"", start~)
    if end_idx >= 0 {
      Some(@core.string_slice(json_str, start, end_idx - start))
    } else {
      None
    }
  } else {
    None
  }

  let aud_idx = @core.string_index_of(json_str, "\"aud\":\"")
  let aud = if aud_idx >= 0 {
    let start = aud_idx + 7
    let end_idx = @core.string_index_of(json_str, "\"", start~)
    if end_idx >= 0 {
      Some(@core.string_slice(json_str, start, end_idx - start))
    } else {
      None
    }
  } else {
    None
  }

  let jti_idx = @core.string_index_of(json_str, "\"jti\":\"")
  let jti = if jti_idx >= 0 {
    let start = jti_idx + 7
    let end_idx = @core.string_index_of(json_str, "\"", start~)
    if end_idx >= 0 {
      Some(@core.string_slice(json_str, start, end_idx - start))
    } else {
      None
    }
  } else {
    None
  }

  // Parse numeric exp, nbf, iat if present
  let exp_idx = @core.string_index_of(json_str, "\"exp\":")
  let exp = if exp_idx >= 0 {
    let start = exp_idx + 6
    let mut end_idx = start
    while end_idx < json_str.length() &&
          json_str[end_idx].to_int() >= 48 &&
          json_str[end_idx].to_int() <= 57 {
      end_idx += 1
    }
    let num_str = @core.string_slice(json_str, start, end_idx - start)
    match @core.parse_int64(num_str) {
      Some(v) => Some(v)
      None => None
    }
  } else {
    None
  }

  let nbf_idx = @core.string_index_of(json_str, "\"nbf\":")
  let nbf = if nbf_idx >= 0 {
    let start = nbf_idx + 6
    let mut end_idx = start
    while end_idx < json_str.length() &&
          json_str[end_idx].to_int() >= 48 &&
          json_str[end_idx].to_int() <= 57 {
      end_idx += 1
    }
    let num_str = @core.string_slice(json_str, start, end_idx - start)
    match @core.parse_int64(num_str) {
      Some(v) => Some(v)
      None => None
    }
  } else {
    None
  }

  let iat_idx = @core.string_index_of(json_str, "\"iat\":")
  let iat = if iat_idx >= 0 {
    let start = iat_idx + 6
    let mut end_idx = start
    while end_idx < json_str.length() &&
          json_str[end_idx].to_int() >= 48 &&
          json_str[end_idx].to_int() <= 57 {
      end_idx += 1
    }
    let num_str = @core.string_slice(json_str, start, end_idx - start)
    match @core.parse_int64(num_str) {
      Some(v) => Some(v)
      None => None
    }
  } else {
    None
  }

  { iss, sub, aud, exp, nbf, iat, jti }
}

///|
pub fn Claims::validate(
  self : Claims,
  now : Int64,
  clock_skew : Int64,
  expected_iss? : String,
  expected_aud? : String,
) -> Bool {
  match self.exp {
    Some(e) => if now - clock_skew > e { return false }
    None => ()
  }
  match self.nbf {
    Some(n) => if now + clock_skew < n { return false }
    None => ()
  }
  match expected_iss {
    Some(exp_iss) =>
      match self.iss {
        Some(iss) => if iss != exp_iss { return false }
        None => return false
      }
    None => ()
  }
  match expected_aud {
    Some(exp_aud) =>
      match self.aud {
        Some(aud) => if aud != exp_aud { return false }
        None => return false
      }
    None => ()
  }
  true
}

///|
pub fn jwt_sign(
  claims : Claims,
  alg : String,
  key : Bytes,
  kid? : String,
) -> String raise @core.CoreError {
  let claims_json = claims.to_json_string()
  let payload = @core.string_to_utf8_bytes(claims_json)
  @jws.jws_sign(alg, payload, key, typ="JWT", kid?)
}

///|
pub fn jwt_verify(
  token : String,
  key : Bytes,
  now? : Int64,
  clock_skew? : Int64,
  expected_iss? : String,
  expected_aud? : String,
) -> Claims raise @core.CoreError {
  let (header, payload_bytes) = @jws.jws_verify(token, key)
  if header.alg == "none" {
    raise CryptoError("JWT signed with algorithm none is disallowed")
  }
  let payload_json = @core.utf8_bytes_to_string(payload_bytes)
  let claims = parse_claims(payload_json)

  let skew = match clock_skew {
    Some(s) => s
    None => 60L
  }

  match now {
    Some(current_time) => {
      let is_valid = claims.validate(
        current_time,
        skew,
        expected_iss?,
        expected_aud?,
      )
      if !is_valid {
        raise CryptoError(
          "JWT claims validation failed (expired, not active, or issuer/audience mismatch)",
        )
      }
    }
    None => ()
  }

  claims
}

///|
pub(all) struct ReplayCache {
  seen : Array[String]
}

///|
pub fn ReplayCache::new() -> ReplayCache {
  { seen: [] }
}

///|
pub fn ReplayCache::check_and_add(self : ReplayCache, jti : String) -> Bool {
  for item in self.seen {
    if item == jti {
      return false
    }
  }
  self.seen.push(jti)
  true
}
