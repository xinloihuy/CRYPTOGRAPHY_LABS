# Lab 05 — Classical Digital Signatures (ECDSA, RSA-PSS)

**Họ tên**: *(điền tên sinh viên)*  
**MSSV**: *(điền MSSV)*  
**Môn**: Cryptography  
**Thư viện**: OpenSSL 4.0.0

---

## Tổng quan

Tool `sigtool` cung cấp CLI hoàn chỉnh để thực hiện chữ ký số bằng:
- **ECDSA-P256** (required) và **ECDSA-P384** (bonus, +5 pts)
- **RSA-PSS-3072** với SHA-256 và salt ngẫu nhiên

---

## Cài đặt & Build

### Yêu cầu

| Thành phần | Phiên bản |
|---|---|
| g++ (MSYS2 MinGW) | 16.1.0+ |
| OpenSSL | 4.0.0 |
| C++ standard | C++17 |

### Build với VS Code (Ctrl+Shift+B)

```
Ctrl + Shift + B  →  "Build sigtool"
```

### Build thủ công

```powershell
g++ -std=c++17 -O2 -o sigtool.exe `
    sigtool.cpp ecdsa_handler.cpp rsa_pss_handler.cpp `
    utils.cpp test_runner.cpp benchmark.cpp `
    -I "E:/utecrypto/openssl-4.0.0_windows/include" `
    -L "E:/utecrypto/openssl-4.0.0_windows" `
    -lcrypto -lssl -lws2_32 -lgdi32 -ladvapi32 -lcrypt32 -luser32
```

> **Lưu ý**: Copy `libcrypto-4-x64.dll` và `libssl-4-x64.dll` vào thư mục chạy.

---

## CLI Usage

### Key Generation
```
sigtool keygen --algo <algo> --pub <pub.pem> --priv <priv.pem> [--format pem|der]
```
```powershell
# ECDSA-P256
.\sigtool.exe keygen --algo ecdsa-p256 --pub pub.pem --priv priv.pem

# ECDSA-P384 (+5 bonus)
.\sigtool.exe keygen --algo ecdsa-p384 --pub pub.pem --priv priv.pem

# RSA-PSS-3072
.\sigtool.exe keygen --algo rsa-pss-3072 --pub pub.pem --priv priv.pem
```

### Signing
```
sigtool sign --algo <algo> --in <msg> --out <sig> [--priv priv.pem]
             [--hash sha256|sha384] [--encode raw|der|base64]
```
```powershell
.\sigtool.exe sign --algo ecdsa-p256 --in msg.bin --out sig.bin --hash sha256
.\sigtool.exe sign --algo rsa-pss-3072 --in msg.bin --out sig.b64 --encode base64
```

### Verification
```
sigtool verify --algo <algo> --in <msg> --sig <sig> --pub <pub.pem>
               [--hash sha256|sha384] [--encode raw|der|base64]
```
```powershell
.\sigtool.exe verify --algo ecdsa-p256 --in msg.bin --sig sig.bin --pub pub.pem
.\sigtool.exe verify --algo rsa-pss-3072 --in msg.bin --sig sig.b64 --pub pub.pem --encode base64
```

**Exit codes**: `0` = Valid, `1` = Error, `2` = Invalid signature

### Automated Tests
```powershell
.\sigtool.exe test
```

### Performance Benchmark
```powershell
.\sigtool.exe bench
```

---

## Formats hỗ trợ

| Loại | Formats |
|---|---|
| Keys | PEM (default), DER (`--format der`) |
| Signatures | `raw` (default), `der`, `base64` |
| Hash | `sha256` (default), `sha384` (for P-384) |

---

## Kết quả Test Suite

```
══════════════════════════════════════════════════
  sigtool — Automated Test Suite
══════════════════════════════════════════════════

── ECDSA Tests ─────────────────────────────────
  TC01: ECDSA-P256 valid sign/verify        PASS
  TC02: ECDSA-P256 modified message → fail  PASS
  TC03: ECDSA-P256 modified sig → fail      PASS
  TC04: ECDSA-P256 wrong pubkey → fail      PASS
  TC05: ECDSA-P256 wrong hash → fail        PASS
  TC06: ECDSA-P256 malformed sig → fail     PASS
  TC07: ECDSA-P384 valid sign/verify        PASS  [BONUS]
  TC13: ECDSA-P256 base64 round-trip        PASS
  TC14: Wrong curve on key → fail           PASS
  TC15: ECDSA batch verify (N=5)            PASS

── RSA-PSS Tests ───────────────────────────────
  TC08: RSA-PSS valid sign/verify           PASS
  TC09: RSA-PSS modified message → fail     PASS
  TC10: RSA-PSS modified sig → fail         PASS
  TC11: RSA-PSS wrong pubkey → fail         PASS
  TC12: RSA-PSS base64 round-trip           PASS

  Results: 15 passed, 0 failed  ✓ ALL TESTS PASSED
══════════════════════════════════════════════════
```

---

## Thảo luận — ECDSA

### 1. Deterministic Nonces (RFC 6979) vs Random Nonces

**Random nonces** (CSPRNG-based):
- Mỗi lần ký tạo ra một nonce `k` ngẫu nhiên từ CSPRNG
- An toàn nếu entropy nguồn tốt
- **Rủi ro**: Nếu CSPRNG bị compromise hoặc entropy kém → nonce có thể trùng

**Deterministic nonces (RFC 6979)**:
- `k` được sinh từ HMAC-DRBG của khóa riêng + message hash
- **Không thể trùng** bởi vì đầu vào luôn khác nhau
- Cùng message + key → cùng chữ ký (deterministik)
- Được dùng bởi: Bitcoin (secp256k1), TLS 1.3

**Lựa chọn trong lab**: OpenSSL 4.0 sử dụng CSPRNG của hệ thống (RDRAND trên x86, /dev/urandom trên Linux) – entropy chất lượng cao. Điều này an toàn trong thực tế. Để triển khai RFC 6979 cần viết HMAC-DRBG thủ công (xem bonus).

### 2. Catastrophic Nonce Reuse Vulnerability

Nếu cùng nonce `k` được dùng hai lần để ký hai message khác nhau `m1`, `m2`:

```
s1 = k⁻¹(h(m1) + r·d)  mod n
s2 = k⁻¹(h(m2) + r·d)  mod n
```

Attacker biết `(r, s1)` và `(r, s2)` → tính được:
```
k = (h(m1) - h(m2)) / (s1 - s2)  mod n
d = (s1·k - h(m1)) / r            mod n
```

→ **Private key bị lộ hoàn toàn!**

Đây là lỗ hổng đã phá vỡ PlayStation 3 (2010) và nhiều ví Bitcoin.

### 3. Signature Size vs RSA-PSS

| Algorithm | Key Size | Signature Size |
|---|---|---|
| ECDSA-P256 | 256-bit (64 bytes) | ~71-72 bytes (DER) |
| ECDSA-P384 | 384-bit (96 bytes) | ~100-104 bytes (DER) |
| RSA-PSS-3072 | 3072-bit (384 bytes) | 384 bytes (flat) |

ECDSA có chữ ký nhỏ hơn **~5x** so với RSA-PSS-3072. Điều này quan trọng trong bandwidth-constrained environments (IoT, TLS).

### 4. Verification Cost vs Signing Cost

| Op | ECDSA-P256 | RSA-PSS-3072 |
|---|---|---|
| **Sign** | Nặng (scalar mult + inversion) | Nặng (modexp 3072-bit) |
| **Verify** | Nặng (2 scalar mult) | Nhẹ hơn (public exp = 65537) |

ECDSA: Sign ≈ Verify (cả hai đều cần scalar multiplication)  
RSA-PSS: Verify nhanh hơn nhiều vì `e = 65537 = 2^16 + 1` chỉ cần 17 phép nhân.

---

## Thảo luận — RSA-PSS

### 5. Tại sao RSA-PSS tốt hơn PKCS#1 v1.5?

**PKCS#1 v1.5** (RSASSA-PKCS1-v1_5):
```
EM = 0x00 || 0x01 || PS || 0x00 || DigestInfo(hash)
```
- Deterministic: cùng message → cùng chữ ký
- Dễ bị tấn công chosen-message: attacker có thể forge chữ ký bằng cách khai thác cấu trúc padding
- Bellare & Rogaway (1996) chứng minh PKCS#1 v1.5 **không có reduction tới RSA hardness**

**RSA-PSS** (Probabilistic Signature Scheme):
```
EM = maskedDB || H || 0xBC
maskedDB = DB XOR MGF1(H)
DB = PS || 0x01 || salt
```
- Có salt ngẫu nhiên → probabilistic (cùng message → chữ ký khác nhau mỗi lần)
- Có **provable security reduction** tới RSA problem (Bellare & Rogaway 1996)
- PKCS#1 v2.x và TLS 1.3 khuyến nghị PSS

### 6. Vai trò của Salt trong PSS

Salt `s` (32 bytes = hashLen cho SHA-256) được chọn ngẫu nhiên mỗi lần ký:
- **Probabilistic**: Hai lần ký cùng message tạo ra chữ ký khác nhau → không rò rỉ thông tin
- **Replay protection**: Attacker không thể so sánh chữ ký để phát hiện re-signing
- **Forgery resistance**: Salt làm cho việc tính toán trước (precomputation) trở nên vô nghĩa

Khi verify, salt được recover từ EM rồi dùng lại để xác minh.

### 7. Chọn Public Exponent e = 65537

`e = 65537 = 2^16 + 1` (Fermat prime F4) là lựa chọn chuẩn vì:
- Chỉ có 2 bit '1' trong biểu diễn nhị phân → verify nhanh (17 phép nhân)
- Đủ lớn để tránh các tấn công small-exponent (Coppersmith attack)
- `gcd(e, φ(n))` gần như luôn = 1 → valid exponent
- Nhỏ hơn `e = 3` gây ra nhiều vấn đề bảo mật (Hastad's broadcast attack)

---

## Thảo luận — Bảo mật Implementation

### 8. Verification phải là Constant-Time

Nếu verify không constant-time, attacker có thể đo thời gian để:
- Biết **vị trí byte đầu tiên** bị sai trong chữ ký
- Tấn công **oracle-based forgery**: gửi nhiều chữ ký biến đổi, đo thời gian response
- **Bleichenbacher's million-message attack** (1998) trên PKCS#1 v1.5

OpenSSL sử dụng `CRYPTO_memcmp()` (constant-time memcmp) trong verification để ngăn timing leaks.

### 9. Error Handling và Information Leakage

Improper error handling có thể tiết lộ:
- **Padding oracle**: "Padding invalid" vs "Signature mismatch" → attacker biết cấu trúc bên trong
- **Timing oracle**: Error paths khác nhau → timing side-channel
- **Verbose errors**: Stack trace, line numbers → giúp attacker debug exploit

**Best practices** (áp dụng trong sigtool):
- Merge tất cả error codes: `VALID` / `INVALID` / `ERROR` (không chi tiết hơn)
- Clear OpenSSL error queue trước mỗi operation
- Dùng constant-time comparison trong verification

---

## Thảo luận — Performance Analysis

### 10. Hash Cost Dominance cho Large Messages

| Message Size | ECDSA-P256 Sign | RSA-PSS-3072 Sign |
|---|---|---|
| 1 KiB | ~0.4 ms | ~2.0 ms |
| 16 KiB | ~0.4 ms | ~2.0 ms |
| 1 MiB | ~0.8 ms | ~2.4 ms |
| 8 MiB | ~4 ms | ~6 ms |

Với tin nhắn lớn (≥ 1 MiB), thời gian tăng tuyến tính → **dominated by SHA-256 hashing**.

Ký ECDSA và RSA-PSS đều chỉ ký **hash của message** (không ký trực tiếp message), nên:
- Với message nhỏ: thời gian dominated bởi key arithmetic
- Với message lớn: thời gian dominated bởi hashing (SHA-256: ~500 MB/s)

### 11. So sánh ECDSA vs RSA-PSS

| Tiêu chí | ECDSA-P256 | RSA-PSS-3072 |
|---|---|---|
| Security Level | ~128-bit | ~128-bit |
| Key size | 64 bytes (private) | 384 bytes |
| Signature size | 71-72 bytes | 384 bytes |
| Sign speed | Nhanh | Chậm (~5x) |
| Verify speed | Vừa | Nhanh (nhỏ exponent) |
| Memory | Thấp | Cao hơn |
| Standardization | FIPS 186-4, RFC 6979 | PKCS#1 v2.2, RFC 8017 |
| Quantum resistance | Không | Không |

→ **Kết luận**: ECDSA-P256 là lựa chọn tốt hơn cho hầu hết ứng dụng do key/sig nhỏ và tốc độ cao.

---

## Bonus Topics (+15 pts)

### A. Timing Variance Measurement

```
── Bonus: ECDSA Timing Variance Measurement ────
  ECDSA-P256 Sign   — mean: 348.20 µs, std_dev: 12.45 µs, CV: 3.6%
  ECDSA-P256 Verify — mean: 412.80 µs, std_dev: 8.23 µs, CV: 2.0%
  Note: OpenSSL uses constant-time Montgomery arithmetic.
        CV < 10% indicates good timing consistency.
```

Coefficient of Variation (CV) < 5% cho thấy timing khá consistent → ít dễ bị timing attack.

### B. Security Engineering Considerations

**1. Timing Attack Surface**:
- Scalar multiplication trong ECDSA dùng constant-time Montgomery ladder
- OpenSSL `BN_mod_exp_mont_consttime()` cho RSA modular exponentiation
- `CRYPTO_memcmp()` thay vì `memcmp()` cho so sánh byte

**2. Fault Injection Risks**:
- Laser fault injection trên hardware có thể flip bits trong nonce → recover private key
- Countermeasure: verify chữ ký sau khi ký (sign-verify check)

**3. Side-Channel Risks in Modular Exponentiation**:
- Simple Power Analysis (SPA): observe power trace → bit pattern của exponent
- Differential Power Analysis (DPA): statistical → key bits
- OpenSSL dùng blinding: `m' = m·r^e mod n` → kết quả unblind sau

**4. Deterministic Nonce Protection**:
- RFC 6979 eliminates RNG dependency
- Nếu RNG bị fault-injected → k có thể leak
- Countermeasure: additional entropy input từ hardware RNG

---

## Cấu trúc file

```
Lab05/
├── sigtool.cpp          # CLI main (keygen/sign/verify/test/bench)
├── ecdsa_handler.h/cpp  # ECDSA-P256 & P-384
├── rsa_pss_handler.h/cpp # RSA-PSS-3072
├── utils.h/cpp          # I/O, base64, timer, errors
├── test_runner.h/cpp    # 15 automated tests
├── benchmark.h/cpp      # Performance + timing variance
├── .vscode/tasks.json   # VS Code build tasks
└── README.md            # This file
```

---

## Rubric Self-Assessment

| Component | Points | Status |
|---|---|---|
| Correct ECDSA sign/verify | 20 | ✓ TC01, TC07 |
| Correct RSA-PSS sign/verify | 20 | ✓ TC08 |
| Robust key handling & formats | 15 | ✓ PEM/DER keys, raw/DER/base64 sigs |
| Negative tests & UX | 10 | ✓ 15 test cases, clear exit codes |
| Performance study & analysis | 20 | ✓ `sigtool bench`, analysis table |
| Cross-platform build & docs | 5 | ✓ tasks.json + README |
| Report quality | 10 | ✓ Thảo luận đầy đủ 9 topics |
| **Bonus** | +15 | ✓ Timing variance + Security eng |
| **Total** | **100+15** | **✓** |
