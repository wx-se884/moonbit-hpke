// Copyright 2026 wx-se884
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

///|
test "hpke base seal and open reference benchmarks" (b : @bench.T) {
  let suite : HpkeSuite = {
    kem: DHKEM_X25519_HKDF_SHA256,
    kdf: HKDF_SHA256,
    aead: CHACHA20_POLY1305,
  }
  let sk_r = @core.hex_decode(
    "6db9e242b206557d33a214e1315073b4e162de1e8e1e7d6a443109ce644f195e",
  )
  let pk_r = kem_derive_public_key(suite.kem, sk_r)
  let sk_e = @core.hex_decode(
    "52c4a75f0640e347dec662450978797361bc419b904a4da8e18229a7e7ffcc7b",
  )
  let info = @core.string_to_utf8_bytes("benchmark-info")
  let aad = @core.string_to_utf8_bytes("benchmark-aad")
  let payload = Bytes::make(1024, b'a')
  let (enc, ciphertext) = hpke_seal_base_deterministic(
    suite, pk_r, info, aad, payload, sk_e,
  )

  b.bench(name="hpke_seal_base_1KiB", fn() {
    let result = hpke_seal_base_deterministic(
      suite, pk_r, info, aad, payload, sk_e,
    ) catch {
      _ => (b"", b"")
    }
    b.keep(result.1.length())
  })
  b.bench(name="hpke_open_base_1KiB", fn() {
    let result = hpke_open_base(suite, enc, sk_r, info, aad, ciphertext) catch {
      _ => b""
    }
    b.keep(result.length())
  })
}
