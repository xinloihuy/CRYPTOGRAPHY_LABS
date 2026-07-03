#pragma once
// ============================================================
//  ecdsa_handler.h  —  ECDSA-P256 / P-384 key gen, sign, verify
//  Lab 05: Classical Digital Signatures
// ============================================================
#include "utils.h"
#include <string>

// Supported curves
enum class ECCurve { P256, P384 };

ECCurve parse_curve(const std::string& algo);   // "ecdsa-p256" -> P256
std::string curve_name(ECCurve c);              // P256 -> "P-256"
int  curve_nid(ECCurve c);                      // P256 -> NID_X9_62_prime256v1

// ── Key Generation ────────────────────────────────────────────
// Generates EC keypair and writes to PEM or DER files.
// Returns true on success.
bool ecdsa_keygen(ECCurve curve,
                  const std::string& pub_path,
                  const std::string& priv_path,
                  KeyFormat fmt = KeyFormat::PEM);

// ── Sign ──────────────────────────────────────────────────────
// Signs msg_path with private key at priv_path.
// Output signature written to sig_path (encoding selectable).
// hash_algo: "sha256" or "sha384"
// Returns true on success.
bool ecdsa_sign(ECCurve curve,
                const std::string& priv_path,
                const std::string& msg_path,
                const std::string& sig_path,
                const std::string& hash_algo,
                SigEncoding enc,
                KeyFormat fmt = KeyFormat::PEM);

// ── Verify ────────────────────────────────────────────────────
// Verifies sig_path against msg_path using public key.
// Returns true if valid, false if invalid.
// Throws std::runtime_error on structural errors.
bool ecdsa_verify(ECCurve curve,
                  const std::string& pub_path,
                  const std::string& msg_path,
                  const std::string& sig_path,
                  const std::string& hash_algo,
                  SigEncoding enc,
                  KeyFormat fmt = KeyFormat::PEM);
