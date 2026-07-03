#include "aes_gcm.h"
#include "utils.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdexcept>

// ─── AES-256-GCM Encrypt ──────────────────────────────────────────────────────
AesGcmResult aes_gcm_encrypt(
    const std::vector<unsigned char>& key,
    const std::vector<unsigned char>& plaintext,
    const std::vector<unsigned char>& aad)
{
    if (key.size() != AES_GCM_KEY_SIZE)
        throw std::runtime_error("aes_gcm_encrypt: key must be 32 bytes");

    AesGcmResult result;
    result.iv = random_bytes(AES_GCM_IV_SIZE);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) openssl_die("EVP_CIPHER_CTX_new");

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        openssl_die("EVP_EncryptInit_ex AES-256-GCM");
    }

    // Set IV length (96-bit)
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_GCM_IV_SIZE, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        openssl_die("EVP_CTRL_GCM_SET_IVLEN");
    }

    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), result.iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        openssl_die("EVP_EncryptInit_ex (key+iv)");
    }

    // Set AAD if provided
    if (!aad.empty()) {
        int dummy = 0;
        if (EVP_EncryptUpdate(ctx, nullptr, &dummy, aad.data(), (int)aad.size()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            openssl_die("EVP_EncryptUpdate AAD");
        }
    }

    result.ciphertext.resize(plaintext.size());
    int outl = 0;

    if (!plaintext.empty()) {
        if (EVP_EncryptUpdate(ctx, result.ciphertext.data(), &outl,
                              plaintext.data(), (int)plaintext.size()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            openssl_die("EVP_EncryptUpdate");
        }
        result.ciphertext.resize(outl);
    }

    int final_outl = 0;
    std::vector<unsigned char> final_buf(16);
    if (EVP_EncryptFinal_ex(ctx, final_buf.data(), &final_outl) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        openssl_die("EVP_EncryptFinal_ex");
    }
    if (final_outl > 0)
        result.ciphertext.insert(result.ciphertext.end(),
                                  final_buf.begin(), final_buf.begin() + final_outl);

    // Get authentication tag
    result.tag.resize(AES_GCM_TAG_SIZE);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                             AES_GCM_TAG_SIZE, result.tag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        openssl_die("EVP_CTRL_GCM_GET_TAG");
    }

    EVP_CIPHER_CTX_free(ctx);
    return result;
}

// ─── AES-256-GCM Decrypt ──────────────────────────────────────────────────────
std::vector<unsigned char> aes_gcm_decrypt(
    const std::vector<unsigned char>& key,
    const std::vector<unsigned char>& iv,
    const std::vector<unsigned char>& ciphertext,
    const std::vector<unsigned char>& tag,
    const std::vector<unsigned char>& aad)
{
    if (key.size() != AES_GCM_KEY_SIZE)
        throw std::runtime_error("aes_gcm_decrypt: key must be 32 bytes");
    if (iv.size() != AES_GCM_IV_SIZE)
        throw std::runtime_error("aes_gcm_decrypt: IV must be 12 bytes");
    if (tag.size() != AES_GCM_TAG_SIZE)
        throw std::runtime_error("aes_gcm_decrypt: tag must be 16 bytes");

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) openssl_die("EVP_CIPHER_CTX_new");

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        openssl_die("EVP_DecryptInit_ex AES-256-GCM");
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_GCM_IV_SIZE, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        openssl_die("EVP_CTRL_GCM_SET_IVLEN");
    }

    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        openssl_die("EVP_DecryptInit_ex (key+iv)");
    }

    // Set expected tag BEFORE decryption
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                             AES_GCM_TAG_SIZE,
                             (void*)tag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        openssl_die("EVP_CTRL_GCM_SET_TAG");
    }

    // Set AAD
    if (!aad.empty()) {
        int dummy = 0;
        if (EVP_DecryptUpdate(ctx, nullptr, &dummy, aad.data(), (int)aad.size()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            openssl_die("EVP_DecryptUpdate AAD");
        }
    }

    std::vector<unsigned char> plaintext;
    if (!ciphertext.empty()) {
        plaintext.resize(ciphertext.size());
        int outl = 0;
        if (EVP_DecryptUpdate(ctx, plaintext.data(), &outl,
                              ciphertext.data(), (int)ciphertext.size()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            openssl_die("EVP_DecryptUpdate");
        }
        plaintext.resize(outl);
    }

    int final_outl = 0;
    // EVP_DecryptFinal_ex returns 0 if tag verification fails
    int rc = EVP_DecryptFinal_ex(ctx, nullptr, &final_outl);
    EVP_CIPHER_CTX_free(ctx);

    if (rc <= 0) {
        // Clear output to avoid partial data leakage
        std::fill(plaintext.begin(), plaintext.end(), 0);
        throw std::runtime_error(
            "AES-GCM authentication failed: ciphertext or tag has been tampered"
        );
    }

    return plaintext;
}
