// Copyright 2026 wx-se884
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

///|
test "crypto throughput reference benchmarks" (b : @bench.T) {
  let small = @core.string_to_utf8_bytes("MoonBit HPKE benchmark input")
  let medium = Bytes::make(1024, b'a')
  let key_128 = @core.hex_decode("000102030405060708090a0b0c0d0e0f")
  let key_256 = @core.hex_decode(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  )
  let iv = @core.hex_decode("000000000000000000000000")
  let nonce = @core.hex_decode("070000004041424344454647")
  let block = @core.hex_decode("00112233445566778899aabbccddeeff")
  let scalar = @core.hex_decode(
    "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
  )
  let aes = AesKey::new(key_128)
  let chacha_key = key_256

  b.bench(name="sha256_32B", fn() { b.keep(sha256(small).length()) })
  b.bench(name="sha256_1KiB", fn() { b.keep(sha256(medium).length()) })
  b.bench(name="sha256_16KiB", fn() {
    b.keep(sha256(Bytes::make(16384, b'a')).length())
  })
  b.bench(name="hmac_sha256_1KiB", fn() {
    b.keep(hmac_sha256(key_256, medium).length())
  })
  b.bench(name="base64url_1KiB", fn() {
    b.keep(@core.base64url_encode(medium).length())
  })
  b.bench(name="aes128_block", fn() {
    b.keep(aes.encrypt_block(block, 0).length())
  })
  b.bench(name="aes_gcm_seal_1KiB", fn() {
    let payload = aes_gcm_seal(key_128, iv, medium, small) catch { _ => b"" }
    b.keep(payload.length())
  })
  b.bench(name="chacha20poly1305_seal_1KiB", fn() {
    let payload = chacha20poly1305_seal(chacha_key, nonce, medium, small) catch {
      _ => b""
    }
    b.keep(payload.length())
  })
  b.bench(name="x25519_base", fn() { b.keep(try! x25519_base(scalar).length()) })
}
