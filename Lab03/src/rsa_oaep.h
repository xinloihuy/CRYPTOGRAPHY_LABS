#pragma once
#include <vector>
#include <string>
#include <openssl/evp.h>

// ─── RSA-OAEP Encrypt ─────────────────────────────────────────────────────────
// Encrypts plaintext using RSA-OAEP (SHA-256/MGF1-SHA-256)
// label: optional OAEP label (can be empty)
// Throws std::runtime_error on failure
std::vector<unsigned char> rsa_oaep_encrypt(
    EVP_PKEY* pub_key,
    const std::vector<unsigned char>& plaintext,
    const std::string& label = ""
);

// ─── RSA-OAEP Decrypt ─────────────────────────────────────────────────────────
// Decrypts RSA-OAEP ciphertext
// Throws std::runtime_error on failure (malformed, wrong key, wrong label)
std::vector<unsigned char> rsa_oaep_decrypt(
    EVP_PKEY* priv_key,
    const std::vector<unsigned char>& ciphertext,
    const std::string& label = ""
);

// ─── Max plaintext size for RSA-OAEP ─────────────────────────────────────────
// mLen <= k - 2*hLen - 2
// For SHA-256: hLen = 32, so mLen <= k - 66
size_t rsa_oaep_max_plaintext(EVP_PKEY* pkey);
