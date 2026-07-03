#pragma once
#include <vector>
#include <string>
#include <openssl/evp.h>

// ─── Hybrid Envelope ──────────────────────────────────────────────────────────
// Format: [4-byte JSON length LE][JSON header][AES-GCM ciphertext]
//
// JSON header:
// {
//   "mode": "RSA-OAEP-AES-GCM",
//   "rsa_modulus": 3072,
//   "hash": "SHA-256",
//   "wrapped_key": "<base64>",
//   "iv": "<base64>",
//   "tag": "<base64>"
// }

struct HybridEnvelope {
    std::string mode;        // "RSA-OAEP-AES-GCM"
    int rsa_modulus;
    std::string hash;        // "SHA-256"
    std::string wrapped_key; // base64
    std::string iv;          // base64
    std::string tag;         // base64
    std::vector<unsigned char> ciphertext;
};

// Serialize envelope to binary blob
std::vector<unsigned char> envelope_serialize(const HybridEnvelope& env);

// Deserialize binary blob to envelope
// Throws if malformed
HybridEnvelope envelope_deserialize(const std::vector<unsigned char>& data);

// ─── Hybrid Encrypt ───────────────────────────────────────────────────────────
// Works for any plaintext size
// If plaintext <= RSA-OAEP limit → uses pure RSA-OAEP (wrapped as hybrid envelope)
// Otherwise → generates AES-256 key, encrypts data, wraps key with RSA-OAEP
std::vector<unsigned char> hybrid_encrypt(
    EVP_PKEY* pub_key,
    const std::vector<unsigned char>& plaintext,
    const std::string& label = ""
);

// ─── Hybrid Decrypt ───────────────────────────────────────────────────────────
// Decrypts a hybrid envelope
// Throws on any failure (tampered data, wrong key, wrong label)
std::vector<unsigned char> hybrid_decrypt(
    EVP_PKEY* priv_key,
    const std::vector<unsigned char>& envelope_data,
    const std::string& label = ""
);
