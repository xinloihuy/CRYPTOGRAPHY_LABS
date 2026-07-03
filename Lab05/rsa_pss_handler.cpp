// ============================================================
//  rsa_pss_handler.cpp  —  RSA-PSS-3072 implementation
//  Lab 05: Classical Digital Signatures
//
//  Parameters:
//    Modulus: 3072 bits
//    Hash:    SHA-256 (required), SHA-384/512 (optional)
//    Salt:    hashLen (32 bytes for SHA-256) — randomized each time
//    Padding: PKCS1_PSS via EVP
//    Exponent: 65537 (F4)
// ============================================================
#include "rsa_pss_handler.h"

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>

#include <memory>
#include <stdexcept>
#include <iostream>

// ── RAII helpers ─────────────────────────────────────────────
using EVP_PKEY_ptr     = std::unique_ptr<EVP_PKEY,     decltype(&EVP_PKEY_free)>;
using EVP_PKEY_CTX_ptr = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
using EVP_MD_CTX_ptr   = std::unique_ptr<EVP_MD_CTX,   decltype(&EVP_MD_CTX_free)>;
using BIO_ptr          = std::unique_ptr<BIO,          decltype(&BIO_free_all)>;

// ── Internal helpers ─────────────────────────────────────────

static const EVP_MD* resolve_md_rsa(const std::string& hash_algo) {
    if (hash_algo == "sha256") return EVP_sha256();
    if (hash_algo == "sha384") return EVP_sha384();
    if (hash_algo == "sha512") return EVP_sha512();
    throw std::invalid_argument("Unsupported hash: '" + hash_algo +
                                "'. Valid: sha256, sha384, sha512");
}

static EVP_PKEY* load_private_key_rsa(const std::string& path, KeyFormat fmt) {
    BIO_ptr bio(BIO_new_file(path.c_str(), "rb"), BIO_free_all);
    if (!bio)
        throw std::runtime_error("Cannot open private key file: " + path);

    EVP_PKEY* pkey = nullptr;
    if (fmt == KeyFormat::PEM) {
        pkey = PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr);
    } else {
        pkey = d2i_PrivateKey_bio(bio.get(), nullptr);
    }
    if (!pkey)
        throw std::runtime_error("Failed to read RSA private key: " + path +
                                 " — " + openssl_error_string());
    // Validate it's RSA
    if (EVP_PKEY_base_id(pkey) != EVP_PKEY_RSA)
        throw std::runtime_error("Key is not an RSA key: " + path);
    return pkey;
}

static EVP_PKEY* load_public_key_rsa(const std::string& path, KeyFormat fmt) {
    BIO_ptr bio(BIO_new_file(path.c_str(), "rb"), BIO_free_all);
    if (!bio)
        throw std::runtime_error("Cannot open public key file: " + path);

    EVP_PKEY* pkey = nullptr;
    if (fmt == KeyFormat::PEM) {
        pkey = PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr);
    } else {
        pkey = d2i_PUBKEY_bio(bio.get(), nullptr);
    }
    if (!pkey)
        throw std::runtime_error("Failed to read RSA public key: " + path +
                                 " — " + openssl_error_string());
    if (EVP_PKEY_base_id(pkey) != EVP_PKEY_RSA)
        throw std::runtime_error("Key is not an RSA key: " + path);
    return pkey;
}

// Encode/decode signature (RSA-PSS is just raw bytes)
static std::vector<uint8_t> encode_sig_rsa(const std::vector<uint8_t>& sig,
                                             SigEncoding enc) {
    switch (enc) {
        case SigEncoding::RAW:
        case SigEncoding::DER:
            return sig; // RSA sig is already opaque bytes
        case SigEncoding::BASE64: {
            std::string b64 = base64_encode(sig);
            return std::vector<uint8_t>(b64.begin(), b64.end());
        }
    }
    return sig;
}

static std::vector<uint8_t> decode_sig_rsa(const std::vector<uint8_t>& raw,
                                             SigEncoding enc) {
    switch (enc) {
        case SigEncoding::RAW:
        case SigEncoding::DER:
            return raw;
        case SigEncoding::BASE64: {
            std::string b64(raw.begin(), raw.end());
            return base64_decode(b64);
        }
    }
    return raw;
}

// ── Key Generation ────────────────────────────────────────────

bool rsa_pss_keygen(int bits,
                    const std::string& pub_path,
                    const std::string& priv_path,
                    KeyFormat fmt) {
    ERR_clear_error();

    // Build params: key bits and exponent = 65537
    OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
    if (!bld) throw std::runtime_error("OSSL_PARAM_BLD_new failed");

    OSSL_PARAM_BLD_push_uint(bld, OSSL_PKEY_PARAM_RSA_BITS,
                             static_cast<unsigned int>(bits));
    OSSL_PARAM_BLD_push_uint(bld, OSSL_PKEY_PARAM_RSA_E, 65537U);
    OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(bld);
    OSSL_PARAM_BLD_free(bld);
    if (!params) throw std::runtime_error("OSSL_PARAM_BLD_to_param failed");

    EVP_PKEY_CTX_ptr ctx(EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr),
                         EVP_PKEY_CTX_free);
    if (!ctx) {
        OSSL_PARAM_free(params);
        throw std::runtime_error("EVP_PKEY_CTX_new_from_name(RSA) failed");
    }
    if (EVP_PKEY_keygen_init(ctx.get()) <= 0) {
        OSSL_PARAM_free(params);
        throw std::runtime_error("EVP_PKEY_keygen_init failed: " +
                                 openssl_error_string());
    }
    if (EVP_PKEY_CTX_set_params(ctx.get(), params) <= 0) {
        OSSL_PARAM_free(params);
        throw std::runtime_error("EVP_PKEY_CTX_set_params failed: " +
                                 openssl_error_string());
    }
    OSSL_PARAM_free(params);

    EVP_PKEY* raw_key = nullptr;
    if (!g_quiet)
    std::cout << "[RSA-PSS] Generating " << bits << "-bit RSA key (may take a moment)...\n";
    if (EVP_PKEY_generate(ctx.get(), &raw_key) <= 0)
        throw std::runtime_error("EVP_PKEY_generate failed: " +
                                 openssl_error_string());
    EVP_PKEY_ptr pkey(raw_key, EVP_PKEY_free);

    // Write private key
    {
        BIO_ptr bio(BIO_new_file(priv_path.c_str(), "wb"), BIO_free_all);
        if (!bio) throw std::runtime_error("Cannot create: " + priv_path);
        int rc = (fmt == KeyFormat::PEM)
            ? PEM_write_bio_PrivateKey(bio.get(), pkey.get(),
                                       nullptr, nullptr, 0, nullptr, nullptr)
            : i2d_PrivateKey_bio(bio.get(), pkey.get());
        if (rc <= 0)
            throw std::runtime_error("Failed to write private key: " +
                                     openssl_error_string());
    }

    // Write public key
    {
        BIO_ptr bio(BIO_new_file(pub_path.c_str(), "wb"), BIO_free_all);
        if (!bio) throw std::runtime_error("Cannot create: " + pub_path);
        int rc = (fmt == KeyFormat::PEM)
            ? PEM_write_bio_PUBKEY(bio.get(), pkey.get())
            : i2d_PUBKEY_bio(bio.get(), pkey.get());
        if (rc <= 0)
            throw std::runtime_error("Failed to write public key: " +
                                     openssl_error_string());
    }

    if (!g_quiet)
    std::cout << "[RSA-PSS] Key pair generated (" << bits << " bits, e=65537)\n"
              << "  Private key -> " << priv_path << "\n"
              << "  Public  key -> " << pub_path  << "\n";
    return true;
}

// ── Sign ──────────────────────────────────────────────────────

bool rsa_pss_sign(const std::string& priv_path,
                  const std::string& msg_path,
                  const std::string& sig_path,
                  const std::string& hash_algo,
                  int salt_len,
                  SigEncoding enc,
                  KeyFormat fmt) {
    ERR_clear_error();
    const EVP_MD* md = resolve_md_rsa(hash_algo);

    EVP_PKEY_ptr pkey(load_private_key_rsa(priv_path, fmt), EVP_PKEY_free);
    std::vector<uint8_t> msg = read_file(msg_path);

    EVP_MD_CTX_ptr mdctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!mdctx) throw std::runtime_error("EVP_MD_CTX_new failed");

    EVP_PKEY_CTX* pctx = nullptr;
    if (EVP_DigestSignInit(mdctx.get(), &pctx, md, nullptr, pkey.get()) <= 0)
        throw std::runtime_error("EVP_DigestSignInit failed: " +
                                 openssl_error_string());

    // Set RSA-PSS padding
    if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0)
        throw std::runtime_error("set_rsa_padding failed: " +
                                 openssl_error_string());

    // Salt length: -1 = hashLen (RSA_PSS_SALTLEN_DIGEST = -1)
    int actual_salt = (salt_len < 0) ? RSA_PSS_SALTLEN_DIGEST : salt_len;
    if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, actual_salt) <= 0)
        throw std::runtime_error("set_rsa_pss_saltlen failed: " +
                                 openssl_error_string());

    if (EVP_DigestSignUpdate(mdctx.get(), msg.data(), msg.size()) <= 0)
        throw std::runtime_error("EVP_DigestSignUpdate failed: " +
                                 openssl_error_string());

    size_t sig_len = 0;
    if (EVP_DigestSignFinal(mdctx.get(), nullptr, &sig_len) <= 0)
        throw std::runtime_error("EVP_DigestSignFinal (len) failed: " +
                                 openssl_error_string());

    std::vector<uint8_t> sig(sig_len);
    if (EVP_DigestSignFinal(mdctx.get(), sig.data(), &sig_len) <= 0)
        throw std::runtime_error("EVP_DigestSignFinal failed: " +
                                 openssl_error_string());
    sig.resize(sig_len);

    std::vector<uint8_t> out = encode_sig_rsa(sig, enc);
    write_file(sig_path, out);

    if (!g_quiet)
    std::cout << "[RSA-PSS] Sign OK\n"
              << "  Hash     : " << hash_algo  << "\n"
              << "  Salt len : " << (salt_len < 0 ? "hashLen" : std::to_string(salt_len)) << "\n"
              << "  Message  : " << msg_path   << " (" << msg.size() << " bytes)\n"
              << "  Signature: " << sig_path   << " (" << out.size() << " bytes)\n";
    return true;
}

// ── Verify ────────────────────────────────────────────────────

bool rsa_pss_verify(const std::string& pub_path,
                    const std::string& msg_path,
                    const std::string& sig_path,
                    const std::string& hash_algo,
                    int /*salt_len*/,
                    SigEncoding enc,
                    KeyFormat fmt) {
    ERR_clear_error();
    const EVP_MD* md = resolve_md_rsa(hash_algo);

    EVP_PKEY_ptr pkey(load_public_key_rsa(pub_path, fmt), EVP_PKEY_free);
    std::vector<uint8_t> msg     = read_file(msg_path);
    std::vector<uint8_t> sig_raw = read_file(sig_path);
    std::vector<uint8_t> sig     = decode_sig_rsa(sig_raw, enc);

    EVP_MD_CTX_ptr mdctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!mdctx) throw std::runtime_error("EVP_MD_CTX_new failed");

    EVP_PKEY_CTX* pctx = nullptr;
    if (EVP_DigestVerifyInit(mdctx.get(), &pctx, md, nullptr, pkey.get()) <= 0)
        throw std::runtime_error("EVP_DigestVerifyInit failed: " +
                                 openssl_error_string());

    if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0)
        throw std::runtime_error("set_rsa_padding failed: " +
                                 openssl_error_string());

    // Use RSA_PSS_SALTLEN_AUTO for verification (auto-detect salt length)
    if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_AUTO) <= 0)
        throw std::runtime_error("set_rsa_pss_saltlen failed: " +
                                 openssl_error_string());

    if (EVP_DigestVerifyUpdate(mdctx.get(), msg.data(), msg.size()) <= 0)
        throw std::runtime_error("EVP_DigestVerifyUpdate failed: " +
                                 openssl_error_string());

    int rc = EVP_DigestVerifyFinal(mdctx.get(), sig.data(), sig.size());
    if (rc == 1) {
        if (!g_quiet) std::cout << "[RSA-PSS] Verify: VALID\n";
        return true;
    } else if (rc == 0) {
        if (!g_quiet) std::cout << "[RSA-PSS] Verify: INVALID (signature mismatch)\n";
        ERR_clear_error();
        return false;
    } else {
        throw std::runtime_error("EVP_DigestVerifyFinal error: " +
                                 openssl_error_string());
    }
}
