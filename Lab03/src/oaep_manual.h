#pragma once
#include <vector>
#include <string>

// ─── Bonus: Manual OAEP Implementation (+5 points) ────────────────────────────
//
// Implements OAEP encoding/decoding manually per RFC 8017 §7.1
// Uses SHA-256 as hash and MGF1(SHA-256) as mask generation function
// MGF1 and XOR masking are implemented from scratch
// Constant-time padding validation via OpenSSL CRYPTO_memcmp

static constexpr int OAEP_HASH_LEN = 32; // SHA-256

// MGF1 mask generation function (RFC 8017 §B.2.1)
// seed: seed bytes
// mask_len: desired output length
std::vector<unsigned char> mgf1_sha256(
    const std::vector<unsigned char>& seed,
    size_t mask_len
);

// OAEP Encode (RFC 8017 §7.1.1)
// message: plaintext M
// label:   optional label L (default empty)
// k:       RSA modulus byte length
// Returns: encoded message EM of length k
std::vector<unsigned char> oaep_encode(
    const std::vector<unsigned char>& message,
    const std::string& label,
    size_t k
);

// OAEP Decode (RFC 8017 §7.1.2)
// em: encoded message EM of length k
// label: optional label L
// k: RSA modulus byte length
// Returns: plaintext M
// Throws on padding error (constant-time check)
std::vector<unsigned char> oaep_decode(
    const std::vector<unsigned char>& em,
    const std::string& label,
    size_t k
);

// Manual RSA-OAEP Encrypt using manual OAEP encoding + raw RSA
// pub_key: RSA public key (EVP_PKEY*)
// Returns ciphertext
std::vector<unsigned char> manual_oaep_encrypt(
    void* pub_key,  // EVP_PKEY*
    const std::vector<unsigned char>& plaintext,
    const std::string& label = ""
);

// Manual RSA-OAEP Decrypt using manual OAEP decoding + raw RSA
std::vector<unsigned char> manual_oaep_decrypt(
    void* priv_key,  // EVP_PKEY*
    const std::vector<unsigned char>& ciphertext,
    const std::string& label = ""
);
