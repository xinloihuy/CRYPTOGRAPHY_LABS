#include "oaep_manual.h"
#include "utils.h"
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <stdexcept>
#include <cstring>

// ─── SHA-256 Helper ───────────────────────────────────────────────────────────
static std::vector<unsigned char> sha256(const std::vector<unsigned char>& data) {
    std::vector<unsigned char> digest(SHA256_DIGEST_LENGTH);
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) openssl_die("EVP_MD_CTX_new");
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx, data.data(), data.size());
    unsigned int dlen = SHA256_DIGEST_LENGTH;
    EVP_DigestFinal_ex(ctx, digest.data(), &dlen);
    EVP_MD_CTX_free(ctx);
    return digest;
}

// ─── MGF1-SHA256 ─────────────────────────────────────────────────────────────
// RFC 8017 §B.2.1: MGF1(mgfSeed, maskLen)
std::vector<unsigned char> mgf1_sha256(
    const std::vector<unsigned char>& seed,
    size_t mask_len)
{
    // hLen = 32 for SHA-256
    const size_t hLen = OAEP_HASH_LEN;
    if (mask_len > (uint64_t)0xFFFFFFFF * hLen)
        throw std::runtime_error("MGF1: mask too long");

    std::vector<unsigned char> T;
    uint32_t counter = 0;
    while (T.size() < mask_len) {
        // C = counter as 4-byte big-endian
        std::vector<unsigned char> input = seed;
        input.push_back((unsigned char)((counter >> 24) & 0xFF));
        input.push_back((unsigned char)((counter >> 16) & 0xFF));
        input.push_back((unsigned char)((counter >> 8)  & 0xFF));
        input.push_back((unsigned char)((counter)       & 0xFF));
        auto h = sha256(input);
        T.insert(T.end(), h.begin(), h.end());
        counter++;
    }
    T.resize(mask_len);
    return T;
}

// ─── XOR helper ──────────────────────────────────────────────────────────────
static void xor_inplace(std::vector<unsigned char>& a,
                         const std::vector<unsigned char>& b) {
    if (a.size() != b.size())
        throw std::runtime_error("XOR size mismatch");
    for (size_t i = 0; i < a.size(); i++)
        a[i] ^= b[i];
}

// ─── OAEP Encode ─────────────────────────────────────────────────────────────
// RFC 8017 §7.1.1 EME-OAEP-Encode
std::vector<unsigned char> oaep_encode(
    const std::vector<unsigned char>& message,
    const std::string& label,
    size_t k)
{
    const size_t hLen = OAEP_HASH_LEN;
    size_t mLen = message.size();

    if (mLen > k - 2 * hLen - 2)
        throw std::runtime_error(
            "OAEP encode: message too long (" + std::to_string(mLen) +
            " > " + std::to_string(k - 2*hLen - 2) + ")"
        );

    // lHash = SHA-256(label)
    std::vector<unsigned char> label_bytes(label.begin(), label.end());
    std::vector<unsigned char> lHash = sha256(label_bytes);

    // DB = lHash || PS || 0x01 || M
    // PS = k - mLen - 2*hLen - 2 zero bytes
    size_t psLen = k - mLen - 2 * hLen - 2;
    std::vector<unsigned char> DB;
    DB.insert(DB.end(), lHash.begin(), lHash.end());       // lHash (32 bytes)
    DB.insert(DB.end(), psLen, 0x00);                      // PS (zero padding)
    DB.push_back(0x01);                                    // 0x01 separator
    DB.insert(DB.end(), message.begin(), message.end());   // M

    // seed = random hLen bytes
    std::vector<unsigned char> seed = random_bytes(hLen);

    // dbMask = MGF1(seed, k - hLen - 1)
    std::vector<unsigned char> dbMask = mgf1_sha256(seed, k - hLen - 1);

    // maskedDB = DB XOR dbMask
    std::vector<unsigned char> maskedDB = DB;
    xor_inplace(maskedDB, dbMask);

    // seedMask = MGF1(maskedDB, hLen)
    std::vector<unsigned char> seedMask = mgf1_sha256(maskedDB, hLen);

    // maskedSeed = seed XOR seedMask
    std::vector<unsigned char> maskedSeed = seed;
    xor_inplace(maskedSeed, seedMask);

    // EM = 0x00 || maskedSeed || maskedDB
    std::vector<unsigned char> EM;
    EM.push_back(0x00);
    EM.insert(EM.end(), maskedSeed.begin(), maskedSeed.end());
    EM.insert(EM.end(), maskedDB.begin(), maskedDB.end());

    if (EM.size() != k)
        throw std::runtime_error("OAEP encode: internal error, EM size mismatch");

    // Zero sensitive data
    std::fill(seed.begin(), seed.end(), 0);
    std::fill(DB.begin(), DB.end(), 0);

    return EM;
}

// ─── OAEP Decode ─────────────────────────────────────────────────────────────
// RFC 8017 §7.1.2 EME-OAEP-Decode
// IMPORTANT: Constant-time comparison via CRYPTO_memcmp to prevent oracle attacks
std::vector<unsigned char> oaep_decode(
    const std::vector<unsigned char>& em,
    const std::string& label,
    size_t k)
{
    const size_t hLen = OAEP_HASH_LEN;

    if (em.size() != k || k < 2 * hLen + 2)
        throw std::runtime_error("OAEP decode: invalid encoded message length");

    // lHash = SHA-256(label)
    std::vector<unsigned char> label_bytes(label.begin(), label.end());
    std::vector<unsigned char> lHash = sha256(label_bytes);

    // Split EM = Y || maskedSeed || maskedDB
    unsigned char Y = em[0];
    std::vector<unsigned char> maskedSeed(em.begin() + 1, em.begin() + 1 + hLen);
    std::vector<unsigned char> maskedDB(em.begin() + 1 + hLen, em.end());

    // seedMask = MGF1(maskedDB, hLen)
    std::vector<unsigned char> seedMask = mgf1_sha256(maskedDB, hLen);

    // seed = maskedSeed XOR seedMask
    std::vector<unsigned char> seed = maskedSeed;
    xor_inplace(seed, seedMask);

    // dbMask = MGF1(seed, k - hLen - 1)
    std::vector<unsigned char> dbMask = mgf1_sha256(seed, k - hLen - 1);

    // DB = maskedDB XOR dbMask
    std::vector<unsigned char> DB = maskedDB;
    xor_inplace(DB, dbMask);

    // DB = lHash' || PS || 0x01 || M
    // Check lHash' == lHash using CONSTANT-TIME comparison (prevents timing oracle)
    if (DB.size() < hLen)
        throw std::runtime_error("OAEP decode: DB too short");

    int bad = 0;
    // Constant-time: Y must be 0x00
    bad |= (int)Y;
    // Constant-time: lHash check
    bad |= CRYPTO_memcmp(DB.data(), lHash.data(), hLen);

    // Find 0x01 separator after PS (must scan all PS bytes to avoid timing leak)
    size_t msg_start = std::string::npos;
    // Scan DB[hLen..] for 0x01
    for (size_t i = hLen; i < DB.size(); i++) {
        if (DB[i] == 0x01 && msg_start == std::string::npos) {
            msg_start = i + 1;
        } else if (DB[i] != 0x00 && msg_start == std::string::npos) {
            // Non-zero, non-0x01 byte in PS region
            bad |= 1;
        }
    }

    if (msg_start == std::string::npos) bad |= 1; // no 0x01 found

    if (bad != 0) {
        // Zero sensitive data before throwing
        std::fill(seed.begin(), seed.end(), 0);
        std::fill(DB.begin(), DB.end(), 0);
        throw std::runtime_error(
            "OAEP decode: padding validation failed (wrong label or corrupted data)"
        );
    }

    std::vector<unsigned char> message(DB.begin() + msg_start, DB.end());

    // Zero sensitive data
    std::fill(seed.begin(), seed.end(), 0);
    std::fill(DB.begin(), DB.end(), 0);

    return message;
}

// ─── Manual RSA-OAEP Encrypt ─────────────────────────────────────────────────
std::vector<unsigned char> manual_oaep_encrypt(
    void* pub_key_void,
    const std::vector<unsigned char>& plaintext,
    const std::string& label)
{
    EVP_PKEY* pub_key = (EVP_PKEY*)pub_key_void;
    int k = EVP_PKEY_get_size(pub_key);

    // Manual OAEP encode
    std::vector<unsigned char> EM = oaep_encode(plaintext, label, (size_t)k);

    // Raw RSA encryption (no padding, we supply the padded block)
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pub_key, nullptr);
    if (!ctx) openssl_die("EVP_PKEY_CTX_new");

    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        openssl_die("EVP_PKEY_encrypt_init");
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_NO_PADDING) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        openssl_die("EVP_PKEY_CTX_set_rsa_padding NO_PADDING");
    }

    size_t outlen = 0;
    if (EVP_PKEY_encrypt(ctx, nullptr, &outlen, EM.data(), EM.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        openssl_die("EVP_PKEY_encrypt size query");
    }

    std::vector<unsigned char> ct(outlen);
    if (EVP_PKEY_encrypt(ctx, ct.data(), &outlen, EM.data(), EM.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        openssl_die("EVP_PKEY_encrypt");
    }
    ct.resize(outlen);
    EVP_PKEY_CTX_free(ctx);
    return ct;
}

// ─── Manual RSA-OAEP Decrypt ─────────────────────────────────────────────────
std::vector<unsigned char> manual_oaep_decrypt(
    void* priv_key_void,
    const std::vector<unsigned char>& ciphertext,
    const std::string& label)
{
    EVP_PKEY* priv_key = (EVP_PKEY*)priv_key_void;
    int k = EVP_PKEY_get_size(priv_key);

    // Raw RSA decryption (no padding)
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(priv_key, nullptr);
    if (!ctx) openssl_die("EVP_PKEY_CTX_new");

    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        openssl_die("EVP_PKEY_decrypt_init");
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_NO_PADDING) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        openssl_die("EVP_PKEY_CTX_set_rsa_padding NO_PADDING");
    }

    size_t outlen = 0;
    if (EVP_PKEY_decrypt(ctx, nullptr, &outlen, ciphertext.data(), ciphertext.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        openssl_die("EVP_PKEY_decrypt size query");
    }

    std::vector<unsigned char> EM(outlen);
    if (EVP_PKEY_decrypt(ctx, EM.data(), &outlen, ciphertext.data(), ciphertext.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        openssl_die("EVP_PKEY_decrypt (raw)");
    }
    EM.resize(outlen);
    EVP_PKEY_CTX_free(ctx);

    // Pad EM to exactly k bytes (RSA may strip leading zeros)
    while ((int)EM.size() < k) {
        EM.insert(EM.begin(), 0x00);
    }

    // Manual OAEP decode (constant-time validation)
    return oaep_decode(EM, label, (size_t)k);
}
