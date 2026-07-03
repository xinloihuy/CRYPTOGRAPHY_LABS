# Lab 06 — Post-Quantum Signatures & Certificates (ML-DSA, ML-KEM)

A complete C++ command-line tool (`pqtool`) demonstrating post-quantum cryptography using [liboqs](https://github.com/open-quantum-safe/liboqs).

## Algorithms Implemented

| Algorithm | Type | Security Level | Key Points |
|---|---|---|---|
| ML-DSA-44 | Signature | Level 2 (~128-bit) | 2420-byte sig, deterministic |
| ML-DSA-65 | Signature | Level 3 (~192-bit) | 3309-byte sig, +5 pts bonus |
| ML-KEM-512 | KEM | Level 1 (~128-bit) | IND-CCA2, F-O transform |

## Build

### Prerequisites

- **Compiler**: g++ (MinGW64/MSYS2) or MSVC
- **liboqs**: Built at `E:\utecrypto\liboqs\build`

### VSCode (Recommended)

Press `Ctrl+Shift+B` in VSCode — uses the **Build pqtool (MinGW g++)** task.

### Manual (PowerShell)

```powershell
mkdir build
g++ -std=c++17 -O2 -o build/pqtool.exe `
    src/main.cpp src/utils.cpp src/keygen.cpp src/sign.cpp src/verify.cpp `
    src/encaps.cpp src/decaps.cpp src/cert.cpp src/bench.cpp src/tests.cpp `
    -I "E:/utecrypto/liboqs/build/include" `
    -L "E:/utecrypto/liboqs/build/lib/Debug" `
    -loqs -lws2_32 -ladvapi32
```

### CMake

```powershell
cmake -B cmake_build -G "MinGW Makefiles"
cmake --build cmake_build
```

## Usage

```
pqtool <command> [options]
```

### Key Generation

```powershell
# ML-DSA-44 keypair
pqtool keygen --algo mldsa-44 --pub pub44.pem --priv priv44.pem

# ML-DSA-65 keypair
pqtool keygen --algo mldsa-65 --pub pub65.pem --priv priv65.pem

# ML-KEM-512 keypair
pqtool keygen --algo mlkem-512 --pub kem_pub.pem --priv kem_priv.pem
```

### Signing & Verification (ML-DSA)

```powershell
# Sign
pqtool sign --algo mldsa-44 --priv priv44.pem --in msg.bin --out sig.bin

# Verify
pqtool verify --algo mldsa-44 --pub pub44.pem --in msg.bin --sig sig.bin

# Base64 format
pqtool sign   --algo mldsa-44 --priv priv44.pem --in msg.bin --out sig.b64 --format base64
pqtool verify --algo mldsa-44 --pub pub44.pem --in msg.bin --sig sig.b64 --format base64
```

### KEM (ML-KEM)

```powershell
# Encapsulate (sender side)
pqtool encaps --algo mlkem-512 --pub kem_pub.pem --ct ct.bin --ss ss_enc.bin

# Decapsulate (receiver side) + verify match
pqtool decaps --algo mlkem-512 --priv kem_priv.pem --ct ct.bin --ss ss_dec.bin --verify-ss ss_enc.bin
```

### PQ Certificate

```powershell
# Create certificate (generates CA + subject keypairs, signs cert)
pqtool cert --action create --subject "Alice" --cert cert.json

# Verify certificate
pqtool cert --action verify --cert cert.json --ca-pub ca_pub.pem

# Tamper detection tests
pqtool cert --action tamper-test --cert cert.json --ca-pub ca_pub.pem
```

Certificate format (JSON):
```json
{
  "subject": "Alice",
  "algo": "ML-DSA-44",
  "issuer": "PQ-CA",
  "public_key": "<base64-encoded ML-DSA-44 public key>",
  "signature": "<base64-encoded ML-DSA-44 signature by CA>"
}
```

### Automated Tests

```powershell
pqtool test
```

Runs:
- ✅ Correct sign + verify (ML-DSA-44, ML-DSA-65)
- ✅ Modified message → fail
- ✅ Modified signature → fail
- ✅ Wrong public key → fail
- ✅ Truncated signature → fail
- ✅ Empty message sign/verify
- ✅ Large message (1 MiB)
- ✅ Batch verification (N=50)
- ✅ Cross-key signing failure
- ✅ Signature size bounds check
- ✅ ML-KEM encaps/decaps match
- ✅ Modified ciphertext (implicit rejection)
- ✅ Wrong private key rejection
- ✅ Batch decapsulation timing

### Performance Benchmark

```powershell
# Benchmark all algorithms (200 rounds for speed)
pqtool bench --algo all --rounds 200

# Individual benchmark
pqtool bench --algo mldsa-44 --rounds 1000
pqtool bench --algo mlkem-512 --rounds 1000
```

Output includes: mean, median, σ, ±95% CI, ops/sec for:
- KeyGen latency
- Sign/Verify latency (msg sizes: 1KiB, 16KiB, 1MiB, 8MiB)
- Encaps/Decaps latency

### Algorithm Information

```powershell
pqtool info
```

### Demo Script

```powershell
.\demo.ps1
```

## File Formats

| Type | Format | Description |
|---|---|---|
| Public key | PEM | Base64 with `-----BEGIN ML-DSA-44 PUBLIC KEY-----` |
| Private key | PEM | Base64 with `-----BEGIN ML-DSA-44 PRIVATE KEY-----` |
| Signature | Raw binary | Default output of `sign` |
| Signature | Base64 text | With `--format base64` |
| Ciphertext | Raw binary | ML-KEM ciphertext |
| Shared secret | Raw binary | 32-byte (256-bit) secret |
| Certificate | JSON | Human-readable PQ cert |

## Project Structure

```
Lab06/
├── src/
│   ├── main.cpp      # CLI dispatcher + banner + info
│   ├── utils.cpp/h   # PEM, base64, hex, file I/O
│   ├── keygen.cpp/h  # ML-DSA + ML-KEM key generation
│   ├── sign.cpp/h    # ML-DSA signing
│   ├── verify.cpp/h  # ML-DSA verification
│   ├── encaps.cpp/h  # ML-KEM encapsulation
│   ├── decaps.cpp/h  # ML-KEM decapsulation
│   ├── cert.cpp/h    # PQ Certificate (create/verify/tamper)
│   ├── bench.cpp/h   # Performance benchmarks with statistics
│   └── tests.cpp/h   # Automated unit & negative tests
├── .vscode/
│   └── tasks.json    # VSCode build tasks
├── CMakeLists.txt    # CMake build (Windows/Linux)
├── demo.ps1          # Full workflow demo script
└── README.md
```

## Security Discussion

### Why ML-KEM is NOT used for signing
ML-KEM is a Key Encapsulation Mechanism (KEM), not a signature scheme.
Signing requires a trapdoor one-way function where the **private key allows computing signatures** that anyone with the public key can verify. ML-KEM's trapdoor allows **decapsulation (decryption) only**, not signing.

### Hybrid Certificates (ECDSA + ML-DSA)
During PQ migration, certificates can include both:
1. Classical ECDSA signature (backward compatibility with non-PQ systems)
2. ML-DSA signature (quantum resistance for post-quantum verifiers)

### ML-DSA vs ECDSA
| Property | ECDSA | ML-DSA-44 |
|---|---|---|
| Security basis | ECDLP | Module LWE (lattice) |
| Quantum safe | ❌ | ✅ |
| Signature size | 64 bytes | ~2420 bytes |
| Deterministic | No (RFC6979) | Yes |
| Nonce reuse risk | Yes | No |

### IND-CCA2 and Fujisaki-Okamoto Transform
ML-KEM achieves IND-CCA2 security by wrapping ML-KEM-IND-CPA (the base scheme) with the Fujisaki-Okamoto (FO) transform. The FO transform re-encrypts during decapsulation and compares against the received ciphertext — any modification causes implicit rejection (returns a pseudorandom shared secret instead of failing).

## Rubric Coverage

| Component | Points | Implemented |
|---|---|---|
| Correct ML-DSA sign/verify | 25 | ✅ ML-DSA-44 + ML-DSA-65 |
| Correct ML-KEM encaps/decaps | 20 | ✅ ML-KEM-512 |
| Robust key handling & formats | 15 | ✅ PEM/DER/raw/base64 |
| Certificate implementation | 10 | ✅ JSON cert + tamper tests |
| Negative tests & UX | 10 | ✅ 14+ automated tests |
| Performance study | 15 | ✅ stats + message sizes |
| Cross-platform build & docs | 5 | ✅ CMake + tasks.json |
| ML-DSA-65 bonus | +5 | ✅ |

## Academic Integrity
Work uses liboqs library (Open Quantum Safe project, MIT license).
Test keys are generated fresh for each run and are for educational use only.
