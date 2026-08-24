# Benchmark protocol

These measurements come from the checked-in MoonBit benchmark tests using `@bench.T`, deterministic inputs, named cases, and `b.keep(...)` around observable output lengths.

## Reproduction

```bash
moon --version
moon bench --package src/crypto --target native --release --deny-warn --no-parallelize
moon bench --package src/hpke --target native --release --deny-warn --no-parallelize
```

## Reference environment

- Date: 2026-08-24 (Asia/Shanghai)
- OS: Windows
- CPU: Intel(R) Core(TM) i9-14900HX, 24 cores / 32 logical processors
- Toolchain: `moon 0.1.20260819`, `moonc v0.10.9+6e6c44045`
- Target: native, release

## Measured output

### `src/crypto`

| Name | Mean | Range | Runs |
| --- | ---: | ---: | ---: |
| `sha256_32B` | 551.62 ns | 524.81–571.27 ns | 10 × 100000 |
| `sha256_1KiB` | 4.92 µs | 4.72–5.17 µs | 10 × 18706 |
| `sha256_16KiB` | 73.06 µs | 70.78–75.69 µs | 10 × 1386 |
| `hmac_sha256_1KiB` | 7.33 µs | 6.99–8.08 µs | 10 × 14081 |
| `base64url_1KiB` | 4.56 µs | 3.67–5.57 µs | 10 × 28903 |
| `aes128_block` | 521.84 ns | 460.51–645.87 ns | 10 × 100000 |
| `aes_gcm_seal_1KiB` | 54.16 µs | 51.77–56.82 µs | 10 × 1823 |
| `chacha20poly1305_seal_1KiB` | 13.69 µs | 12.65–14.88 µs | 10 × 7630 |
| `x25519_base` | 561.24 ms | 540.33–605.48 ms | 10 × 1 |

### `src/hpke`

| Name | Mean | Range | Runs |
| --- | ---: | ---: | ---: |
| `hpke_seal_base_1KiB` | 1.12 s | 1.04–1.23 s | 10 × 1 |
| `hpke_open_base_1KiB` | 1.07 s | 1.03–1.15 s | 10 × 1 |

These values are local reference points, not cross-machine promises, side-channel evidence, or a replacement for a security review.
