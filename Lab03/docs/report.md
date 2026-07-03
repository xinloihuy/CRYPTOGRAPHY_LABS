# Lab 03 Report — RSA-OAEP & Hybrid Encryption

**Student:** [Your Name]
**Course:** Cryptography
**Date:** 2026-06-14
**Implementation:** C++ + OpenSSL 4.0

---

## 1. Algorithms & Parameters

### A. RSA-OAEP Configuration

| Parameter | Value |
|-----------|-------|
| Modulus sizes | 3072-bit (primary), 4096-bit (comparison) |
| Hash function | SHA-256 |
| Padding | OAEP |
| MGF | MGF1(SHA-256) |
| Max plaintext (3072) | 318 bytes (= 384 - 2×32 - 2) |
| Max plaintext (4096) | 446 bytes (= 512 - 2×32 - 2) |

### B. Hybrid Encryption Configuration

| Component | Algorithm |
|-----------|-----------|
| Symmetric cipher | AES-256-GCM |
| IV size | 96-bit (12 bytes) |
| Auth tag | 128-bit (16 bytes) |
| Key wrapping | RSA-OAEP (SHA-256) |

---

## 2. Why OAEP is Secure (IND-CCA2)

RSA-OAEP achieves **IND-CCA2** (Indistinguishability under Chosen Ciphertext Attack) security through the following design:

### OAEP Structure (RFC 8017 §7.1)

```
EM = 0x00 || maskedSeed || maskedDB
     where:
       maskedDB   = DB XOR MGF1(seed, k-hLen-1)
       maskedSeed = seed XOR MGF1(maskedDB, hLen)
       DB         = lHash || PS || 0x01 || M
```

**Why IND-CCA2:**
1. **Randomized encoding**: Each encryption uses a fresh random `seed`, so the same plaintext produces different ciphertexts → prevents chosen-plaintext attacks
2. **Hash interleaving**: The double masking (seed masks DB, DB masks seed) creates a tight two-way dependency, making it computationally infeasible to recover either component without both
3. **Label binding**: The label hash `lHash` is embedded in `DB`, so any OAEP ciphertext is bound to a specific context
4. **Provable security**: Under the ROM (Random Oracle Model), OAEP reduces to the RSA one-wayness problem — breaking OAEP requires inverting RSA
5. **CCA2 resilience**: The padding structure means a random modification of the ciphertext will produce an invalid padding with overwhelming probability, preventing decryption oracle attacks

**Plaintext size limit formula:**
$$m_{Len} \leq k - 2h_{Len} - 2$$
For RSA-3072 with SHA-256: $m_{Len} \leq 384 - 64 - 2 = 318$ bytes

---

## 3. Why PKCS#1 v1.5 Encryption is Insecure

PKCS#1 v1.5 padding: `EM = 0x00 || 0x02 || PS || 0x00 || M`

**Bleichenbacher's 1998 Attack (Million-Message Attack):**
- An attacker intercepts a ciphertext `C`
- Sends crafted variants `C' = (s^e × C) mod n` to a decryption oracle
- Observes if padding starts with `0x00 0x02` (valid) or fails
- This 1-bit oracle leaks information about the plaintext
- With ~1 million queries, the full plaintext can be recovered

**Why this is critical:**
- SSL 3.0/TLS 1.0 RSA key exchange was vulnerable
- ROBOT attack (2017) showed 19-year-old vulnerability still active in major servers
- No amount of engineering fixes can rescue PKCS#1 v1.5's fundamental insecurity

**OAEP's defense:** Any ciphertext corruption causes OAEP decode to fail in a way that reveals no information (constant-time check), so no oracle is possible.

---

## 4. Why RSA Cannot Encrypt Large Files Directly

1. **Size constraint**: RSA can only encrypt up to $k - 2h_{Len} - 2$ bytes
   - RSA-3072: only 318 bytes max
   - A 1 MB file would require splitting into ~3,145 RSA operations

2. **Performance**: RSA-3072 decrypt takes ~0.76 ms per block
   - 1 MB file → ~3,145 blocks × 0.76 ms = **2.4 seconds** just for RSA operations
   - AES-GCM encrypts 1 MB in **~1 ms** (1000× faster)

3. **Determinism risk**: Without fresh randomness per block, patterns emerge

4. **Real-world analogy**: TLS, PGP, and S/MIME all use hybrid encryption for this reason

---

## 5. Hybrid Encryption — Envelope Format

### JSON Header Example:
```json
{
  "mode": "RSA-OAEP-AES-GCM",
  "rsa_modulus": 3072,
  "hash": "SHA-256",
  "wrapped_key": "<base64-encoded RSA-OAEP ciphertext of AES key>",
  "iv": "<base64-encoded 96-bit IV>",
  "tag": "<base64-encoded 128-bit GCM tag>"
}
```

### Binary Layout:
```
[4 bytes: JSON length LE][JSON header bytes][AES-GCM ciphertext]
```

### Security Properties:
- **AES-256-GCM**: Authenticated encryption — confidentiality + integrity in one operation
- **96-bit IV**: Recommended by NIST SP 800-38D; freshly generated per encryption
- **128-bit tag**: Constant-time verification (library-backed via OpenSSL)
- **Key isolation**: AES key is ephemeral, never stored, zeroed after use
- **Fail closed**: Any parse/decryption error throws immediately without partial output

---

## 6. Negative Tests Results

All 6 required negative tests pass:

| Test | Result | Error Message |
|------|--------|---------------|
| Altered RSA ciphertext | PASS | `rsa routines::oaep decoding error` |
| Altered AES-GCM ciphertext | PASS | `AES-GCM authentication failed` |
| Wrong private key | PASS | `rsa routines::oaep decoding error` |
| Wrong OAEP label | PASS | `rsa routines::oaep decoding error` |
| Tampered envelope header | PASS | `Tampered or malformed envelope header` |
| Malformed ciphertext | PASS | `Malformed envelope: declared JSON length...` |

Additional tests:
- Empty ciphertext → fail
- Plaintext too large → clear error message
- Key < 3072 bits → rejected
- Key size mismatch → clear error

---

## 7. Performance Results

### RSA Key Generation (3 runs average):

| Key Size | Time |
|----------|------|
| RSA-3072 | 182 ms |
| RSA-4096 | 509 ms |
| Ratio | 2.80× slower |

**Analysis:** Key generation time grows super-linearly with key size because RSA keygen involves primality testing and modular arithmetic operations that scale as O(k³).

### RSA-OAEP Encrypt/Decrypt (20 runs average):

| Operation | Time |
|-----------|------|
| RSA-3072 Encrypt | 0.043 ms |
| RSA-3072 Decrypt | 0.757 ms |
| Decrypt/Encrypt ratio | **17.8×** |
| RSA-4096 Encrypt | 0.064 ms |
| RSA-4096 Decrypt | 1.468 ms |

**Analysis:**
- **Encrypt** uses public exponent e=65537 (small, fast modular exponentiation)
- **Decrypt** uses the large private exponent d, even with CRT optimization it's ~18× slower
- RSA-4096 decrypt is ~2× slower than RSA-3072 (key size ratio effect on modular exponentiation)

### Hybrid Encryption Throughput:

| Payload | Encrypt | Decrypt | Throughput |
|---------|---------|---------|------------|
| 1 KiB | 0.06 ms | 0.80 ms | 17.2 MB/s |
| 1 MiB | 0.97 ms | 1.54 ms | 1,033.5 MB/s |
| 100 MiB | 92.87 ms | 59.38 ms | 1,076.8 MB/s |

**Analysis:**
- For 1 KiB: RSA dominates (most time in RSA decrypt ~0.76 ms)
- For 1 MiB+: AES-GCM dominates at ~1 GB/s throughput
- **Hybrid efficiency advantage**: AES-GCM at 1 GB/s vs pure RSA at ~0.4 MB/s for same data
- Memory: AES-GCM processes data in streaming fashion; no large buffer needed
- CPU: AES-NI hardware instructions accelerate AES by 10-20×

---

## 8. Bonus A: Manual OAEP Implementation (+5)

### Implementation Details

**MGF1 (RFC 8017 §B.2.1):**
```cpp
MGF1(seed, maskLen):
  for counter = 0, 1, 2, ... until maskLen bytes:
    T += SHA-256(seed || counter-as-4-byte-BE)
  return T[0..maskLen-1]
```

**OAEP Encode:**
1. `lHash = SHA-256(label)`
2. `DB = lHash || PS (zeros) || 0x01 || message`
3. `seed = random(32 bytes)`
4. `dbMask = MGF1(seed, k-hLen-1)`
5. `maskedDB = DB XOR dbMask`
6. `seedMask = MGF1(maskedDB, hLen)`
7. `maskedSeed = seed XOR seedMask`
8. `EM = 0x00 || maskedSeed || maskedDB`

**Constant-time Decode:**
- Uses `CRYPTO_memcmp()` for label hash comparison → **no timing side-channel**
- Accumulates `bad` flag through ALL checks before throwing
- Scans entire PS region before identifying 0x01 separator
- Clears sensitive buffers on error

**Why constant-time is critical:** A timing oracle on OAEP padding validation would enable a Bleichenbacher-style attack. Even 1 CPU cycle difference between "valid" and "invalid" padding can leak information after millions of queries.

---

## 9. Bonus B: Hybrid Security Analysis (+10)

### Envelope vs Direct RSA

| Property | Direct RSA | Hybrid (RSA+AES) |
|----------|-----------|-----------------|
| Max plaintext | 318 bytes (3072-bit) | Unlimited |
| Throughput (1 MB) | ~2.4 seconds | ~1 ms |
| Forward secrecy | No | Partial (per-session AES key) |
| Security model | RSA-OAEP IND-CCA2 | Composite |

### How TLS Handshake Uses Hybrid Design

In TLS 1.2 RSA key exchange:
```
1. Server sends RSA public key certificate
2. Client generates random 48-byte pre-master secret
3. Client encrypts pre-master secret with RSA-OAEP
4. Both sides derive symmetric session keys via PRF(pre-master, nonces)
5. All actual data encrypted with AES-GCM (symmetric)
```

This is exactly our hybrid model: RSA encrypts a small symmetric key, AES handles bulk data.

**TLS 1.3 improvement:** Replaced RSA key exchange with ECDHE, providing forward secrecy — if the server's private key is compromised later, past sessions remain confidential.

### Forward Secrecy Limitations of Pure RSA

**Problem:** In RSA key exchange, the server's long-term private key is used to decrypt the session key. If the private key is ever exposed:
- All past recorded sessions can be decrypted (retroactive attack)
- Session keys are tied to the long-term key

**Why this matters:** Nation-state adversaries may record TLS traffic today and wait for the private key to be exposed (e.g., through server compromise, legal process, or cryptanalysis).

**Our hybrid scheme:** Uses ephemeral AES keys per encryption, but the AES key is still wrapped with a static RSA key. This gives per-session confidentiality from passive attackers but not forward secrecy against an adversary who later compromises the RSA private key.

### Upgrade Path: ECDHE and ML-KEM

**ECDHE (Elliptic Curve Diffie-Hellman Ephemeral):**
- Replaces RSA key exchange in TLS 1.3
- Each session uses a fresh EC key pair
- True forward secrecy: past sessions safe even if server key compromised
- 256-bit ECDHE ≈ security of 3072-bit RSA, but 100× faster key exchange

**ML-KEM (Module Lattice Key Encapsulation Mechanism, formerly CRYSTALS-Kyber):**
- NIST FIPS 203 post-quantum standard
- Replaces ECDHE for quantum-resistant key exchange
- Security based on Module Learning With Errors (MLWE) hardness
- Immune to Shor's algorithm (which breaks RSA and ECC on quantum computers)
- Expected deployment in TLS 1.3 via hybrid ECDHE+ML-KEM (IETF RFC draft)

### AES-CTR + HMAC vs AES-GCM

| Property | AES-CTR + HMAC-SHA256 | AES-256-GCM |
|----------|----------------------|-------------|
| Confidentiality | AES-CTR | AES-CTR internally |
| Integrity | HMAC-SHA256 (separate) | GHASH (built-in) |
| Authentication failure timing | Variable (HMAC comparison) | Constant-time (OpenSSL) |
| Overhead | HMAC adds 32 bytes + computation | 16-byte tag only |
| Performance | Similar | Slightly faster (AES-NI + CLMUL) |
| Security | Provably secure (encrypt-then-MAC) | Nonce reuse catastrophic |
| Nonce reuse | CTR keystream reuse → XOR attack | Tag forgery possible |

**Recommendation:** AES-GCM for performance and simplicity; AES-CTR+HMAC for environments without AEAD support or when AES-NI unavailable.

---

## 10. CLI Usage Reference

```bash
# Key generation
rsatool keygen --bits 3072 --pub pub.pem --priv priv.pem
# → Creates: pub.pem, priv.pem, pub.der, priv.der, key_meta.json

# Encrypt (auto hybrid for large files)
rsatool encrypt --in message.txt --pub pub.pem --out ciphertext.bin
rsatool encrypt --in bigfile.bin --pub pub.pem --out big.enc --label myapp

# Decrypt
rsatool decrypt --in ciphertext.bin --priv priv.pem --out plaintext.txt
rsatool decrypt --in big.enc --priv priv.pem --out bigfile_dec.bin --label myapp

# Benchmark
rsatool benchmark

# Tests
rsatool test

# Manual OAEP (Bonus)
rsatool manual-oaep --in msg.txt --pub pub.pem --out manual.bin
rsatool manual-oaep-dec --in manual.bin --priv priv.pem --out manual_dec.txt
```

---

## 11. Key Management

- **PEM format**: Human-readable Base64, compatible with OpenSSL CLI and most libraries
- **DER format**: Binary ASN.1, used in X.509 certificates, Android/Java keystores
- **Metadata JSON**: Tracks creation time, key size, and hash algorithm for audit purposes

```json
{
  "creation_time": "2026-06-14T07:43:36Z",
  "modulus_bits": 3072,
  "hash": "SHA-256"
}
```

---

## 12. Build Instructions

```bash
# Using VSCode: Ctrl+Shift+B (runs default build task)
# Or manually:
g++ -std=c++17 -O2 -I "E:/utecrypto/openssl-4.0.0_windows/include" \
    src/*.cpp \
    -L "E:/utecrypto/openssl-4.0.0_windows" \
    -l:libcrypto.dll.a -l:libssl.dll.a \
    -o rsatool.exe
```

**VSCode Tasks available (`Ctrl+Shift+B`):**
- **Build rsatool** — Release build (default)
- **Build rsatool (Debug)** — Debug symbols
- **Run Tests** — Build + copy DLLs + run test suite
- **Run Benchmark** — Build + run performance benchmarks
- **Quick Demo** — Full keygen → encrypt → decrypt demo

---

*Report generated as part of Lab 03 — Cryptography Course*
