#include "rsa_oaep.h"
#include "utils.h"
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <stdexcept>
#include <cstring>

// ─── RSA-OAEP Max Plaintext ───────────────────────────────────────────────────
size_t rsa_oaep_max_plaintext(EVP_PKEY* pkey) {
    // k = modulus byte size
    int k = EVP_PKEY_get_size(pkey);
    // hLen = 32 for SHA-256
    const int hLen = 32;
    if (k < 2 * hLen + 2) return 0;
    return (size_t)(k - 2 * hLen - 2);
}

// ─── RSA-OAEP Encrypt ─────────────────────────────────────────────────────────
std::vector<unsigned char> rsa_oaep_encrypt(
    EVP_PKEY* pub_key,
    const std::vector<unsigned char>& plaintext,
    const std::string& label)
{
    size_t maxlen = rsa_oaep_max_plaintext(pub_key);
    if (plaintext.size() > maxlen) {
        throw std::runtime_error(
            "rsa_oaep_encrypt: plaintext too large (" +
            std::to_string(plaintext.size()) + " bytes, max " +
            std::to_string(maxlen) + " bytes). Use hybrid encryption."
        );
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pub_key, nullptr);
    if (!ctx) openssl_die("EVP_PKEY_CTX_new");

    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        openssl_die("EVP_PKEY_encrypt_init");
    }

    // Set OAEP padding
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        openssl_die("EVP_PKEY_CTX_set_rsa_padding OAEP");
    }

    // Set hash: SHA-256
    if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        openssl_die("EVP_PKEY_CTX_set_rsa_oaep_md SHA-256");
    }

    // Set MGF1 hash: SHA-256
    if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        openssl_die("EVP_PKEY_CTX_set_rsa_mgf1_md SHA-256");
    }

    // Set label if provided
    if (!label.empty()) {
        // OpenSSL takes ownership of label buffer, must be heap-allocated
        unsigned char* lbuf = (unsigned char*)OPENSSL_malloc(label.size());
        if (!lbuf) {
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("OPENSSL_malloc failed for label");
        }
        std::memcpy(lbuf, label.data(), label.size());
        if (EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, lbuf, (int)label.size()) <= 0) {
            OPENSSL_free(lbuf);
            EVP_PKEY_CTX_free(ctx);
            openssl_die("EVP_PKEY_CTX_set0_rsa_oaep_label");
        }
    }

    // Determine output size
    size_t outlen = 0;
    if (EVP_PKEY_encrypt(ctx, nullptr, &outlen, plaintext.data(), plaintext.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        openssl_die("EVP_PKEY_encrypt (size query)");
    }

    std::vector<unsigned char> ct(outlen);
    if (EVP_PKEY_encrypt(ctx, ct.data(), &outlen, plaintext.data(), plaintext.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        openssl_die("EVP_PKEY_encrypt");
    }
    ct.resize(outlen);

    EVP_PKEY_CTX_free(ctx);
    return ct;
}

// ─── RSA-OAEP Decrypt ─────────────────────────────────────────────────────────
std::vector<unsigned char> rsa_oaep_decrypt(
    EVP_PKEY* priv_key,
    const std::vector<unsigned char>& ciphertext,
    const std::string& label)
{
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(priv_key, nullptr);
    if (!ctx) openssl_die("EVP_PKEY_CTX_new");

    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        openssl_die("EVP_PKEY_decrypt_init");
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        openssl_die("EVP_PKEY_CTX_set_rsa_padding OAEP");
    }

    if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        openssl_die("EVP_PKEY_CTX_set_rsa_oaep_md SHA-256");
    }

    if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        openssl_die("EVP_PKEY_CTX_set_rsa_mgf1_md SHA-256");
    }

    if (!label.empty()) {
        unsigned char* lbuf = (unsigned char*)OPENSSL_malloc(label.size());
        if (!lbuf) {
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("OPENSSL_malloc failed for label");
        }
        std::memcpy(lbuf, label.data(), label.size());
        if (EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, lbuf, (int)label.size()) <= 0) {
            OPENSSL_free(lbuf);
            EVP_PKEY_CTX_free(ctx);
            openssl_die("EVP_PKEY_CTX_set0_rsa_oaep_label");
        }
    }

    size_t outlen = 0;
    if (EVP_PKEY_decrypt(ctx, nullptr, &outlen, ciphertext.data(), ciphertext.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        openssl_die("EVP_PKEY_decrypt (size query)");
    }

    std::vector<unsigned char> pt(outlen);
    if (EVP_PKEY_decrypt(ctx, pt.data(), &outlen, ciphertext.data(), ciphertext.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        openssl_die("RSA-OAEP decryption failed (wrong key, wrong label, or tampered ciphertext)");
    }
    pt.resize(outlen);

    EVP_PKEY_CTX_free(ctx);
    return pt;
}
