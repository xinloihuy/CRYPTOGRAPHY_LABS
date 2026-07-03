#pragma once
// ============================================================
//  rsa_pss_handler.h  —  RSA-PSS-3072 key gen, sign, verify
//  Lab 05: Classical Digital Signatures
// ============================================================
#include "utils.h"
#include <string>

// ── Key Generation ────────────────────────────────────────────
// Generates RSA keypair (bits=3072) and writes PEM/DER files.
bool rsa_pss_keygen(int bits,
                    const std::string& pub_path,
                    const std::string& priv_path,
                    KeyFormat fmt = KeyFormat::PEM);

// ── Sign ──────────────────────────────────────────────────────
// Signs msg_path with RSA-PSS.
// salt_len = -1 → use hashLen (RSA_PSS_SALTLEN_DIGEST)
bool rsa_pss_sign(const std::string& priv_path,
                  const std::string& msg_path,
                  const std::string& sig_path,
                  const std::string& hash_algo,
                  int salt_len,
                  SigEncoding enc,
                  KeyFormat fmt = KeyFormat::PEM);

// ── Verify ────────────────────────────────────────────────────
// Verifies sig_path against msg_path using RSA-PSS public key.
bool rsa_pss_verify(const std::string& pub_path,
                    const std::string& msg_path,
                    const std::string& sig_path,
                    const std::string& hash_algo,
                    int salt_len,
                    SigEncoding enc,
                    KeyFormat fmt = KeyFormat::PEM);
