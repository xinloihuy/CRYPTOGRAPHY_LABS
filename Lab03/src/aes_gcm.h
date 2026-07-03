#pragma once
#include <vector>
#include <string>
#include <openssl/evp.h>

// AES-256-GCM parameters
static constexpr int AES_GCM_KEY_SIZE = 32;  // 256-bit
static constexpr int AES_GCM_IV_SIZE  = 12;  // 96-bit
static constexpr int AES_GCM_TAG_SIZE = 16;  // 128-bit

struct AesGcmResult {
    std::vector<unsigned char> ciphertext;
    std::vector<unsigned char> iv;
    std::vector<unsigned char> tag;
};

// Encrypt plaintext with AES-256-GCM
// key must be 32 bytes
// Returns ciphertext + iv + tag
AesGcmResult aes_gcm_encrypt(
    const std::vector<unsigned char>& key,
    const std::vector<unsigned char>& plaintext,
    const std::vector<unsigned char>& aad = {}
);

// Decrypt AES-256-GCM ciphertext
// Throws on authentication failure (tampered ciphertext/tag)
std::vector<unsigned char> aes_gcm_decrypt(
    const std::vector<unsigned char>& key,
    const std::vector<unsigned char>& iv,
    const std::vector<unsigned char>& ciphertext,
    const std::vector<unsigned char>& tag,
    const std::vector<unsigned char>& aad = {}
);
