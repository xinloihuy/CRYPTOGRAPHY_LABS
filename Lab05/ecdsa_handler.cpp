// ============================================================
//  ecdsa_handler.cpp  —  ECDSA-P256 / P-384 implementation
//  Lab 05: Classical Digital Signatures
//
//  OpenSSL EVP high-level API is used throughout.
//  Nonce generation: OpenSSL uses its CSPRNG (OpenSSL ≥ 3.x).
//  RFC 6979 deterministic nonces are discussed in README.md.
// ============================================================
#include "ecdsa_handler.h"

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>

#include <memory>
#include <stdexcept>
#include <iostream>
#include <cstring>

// ── RAII helpers ─────────────────────────────────────────────
using EVP_PKEY_ptr     = std::unique_ptr<EVP_PKEY,     decltype(&EVP_PKEY_free)>;
using EVP_PKEY_CTX_ptr = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
using EVP_MD_CTX_ptr   = std::unique_ptr<EVP_MD_CTX,   decltype(&EVP_MD_CTX_free)>;
using BIO_ptr          = std::unique_ptr<BIO,          decltype(&BIO_free_all)>;

// ── Curve info ────────────────────────────────────────────────

ECCurve parse_curve(const std::string& algo) {
    if (algo == "ecdsa-p256") return ECCurve::P256;
    if (algo == "ecdsa-p384") return ECCurve::P384;
    throw std::invalid_argument("Unknown ECDSA algorithm: '" + algo +
                                "'. Valid: ecdsa-p256, ecdsa-p384");
}

std::string curve_name(ECCurve c) {
    return (c == ECCurve::P256) ? "P-256" : "P-384";
}

int curve_nid(ECCurve c) {
    return (c == ECCurve::P256) ? NID_X9_62_prime256v1 : NID_secp384r1;
}

// Returns the OpenSSL group name string (for OSSL_PARAM)
static const char* curve_group_name(ECCurve c) {
    return (c == ECCurve::P256) ? "prime256v1" : "secp384r1";
}

// ── Load key from file ────────────────────────────────────────

static EVP_PKEY* load_private_key(const std::string& path, KeyFormat fmt) {
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
        throw std::runtime_error("Failed to read private key: " + path +
                                 " — " + openssl_error_string());
    return pkey;
}

static EVP_PKEY* load_public_key(const std::string& path, KeyFormat fmt) {
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
        throw std::runtime_error("Failed to read public key: " + path +
                                 " — " + openssl_error_string());
    return pkey;
}

// ── Validate that loaded key matches expected curve ───────────

static void validate_ec_key_curve(EVP_PKEY* pkey, ECCurve expected) {
    // Get the group name from the key
    char group_buf[64] = {};
    size_t group_len = 0;
    if (EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_GROUP_NAME,
                                       group_buf, sizeof(group_buf),
                                       &group_len) != 1) {
        // Fallback: check key type only
        if (EVP_PKEY_base_id(pkey) != EVP_PKEY_EC)
            throw std::runtime_error("Key is not an EC key");
        return;
    }
    const char* expected_name = curve_group_name(expected);
    // Accept both short name and long name (prime256v1 / secp256r1)
    int expected_nid = curve_nid(expected);
    int got_nid = OBJ_sn2nid(group_buf);
    if (got_nid == NID_undef) got_nid = OBJ_ln2nid(group_buf);
    if (got_nid == NID_undef) got_nid = OBJ_txt2nid(group_buf);
    if (got_nid != expected_nid)
        throw std::runtime_error(std::string("Curve mismatch: key uses '") +
                                 group_buf + "' but algorithm expects '" +
                                 expected_name + "'");
}

// ── Resolve MD from hash_algo string ─────────────────────────

static const EVP_MD* resolve_md(const std::string& hash_algo) {
    if (hash_algo == "sha256") return EVP_sha256();
    if (hash_algo == "sha384") return EVP_sha384();
    if (hash_algo == "sha512") return EVP_sha512();
    throw std::invalid_argument("Unsupported hash algorithm: '" + hash_algo +
                                "'. Valid: sha256, sha384, sha512");
}

// ── Signature encode/decode helpers ──────────────────────────

static std::vector<uint8_t> encode_sig(const std::vector<uint8_t>& der_sig,
                                        SigEncoding enc) {
    // OpenSSL EVP_DigestSign produces DER-encoded ECDSA signature natively
    switch (enc) {
        case SigEncoding::DER:    return der_sig;
        case SigEncoding::BASE64: {
            std::string b64 = base64_encode(der_sig);
            return std::vector<uint8_t>(b64.begin(), b64.end());
        }
        case SigEncoding::RAW:    return der_sig; // raw = DER for ECDSA
    }
    return der_sig;
}

static std::vector<uint8_t> decode_sig(const std::vector<uint8_t>& raw,
                                        SigEncoding enc) {
    switch (enc) {
        case SigEncoding::DER:    return raw;
        case SigEncoding::BASE64: {
            std::string b64(raw.begin(), raw.end());
            return base64_decode(b64);
        }
        case SigEncoding::RAW:    return raw;
    }
    return raw;
}

// ── Key Generation ────────────────────────────────────────────

bool ecdsa_keygen(ECCurve curve,
                  const std::string& pub_path,
                  const std::string& priv_path,
                  KeyFormat fmt) {
    ERR_clear_error();

    // Build OSSL_PARAM with curve group name
    OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
    if (!bld) throw std::runtime_error("OSSL_PARAM_BLD_new failed");
    OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME,
                                    curve_group_name(curve), 0);
    OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(bld);
    OSSL_PARAM_BLD_free(bld);
    if (!params) throw std::runtime_error("OSSL_PARAM_BLD_to_param failed");

    // Create context and generate
    EVP_PKEY_CTX_ptr ctx(EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr),
                         EVP_PKEY_CTX_free);
    if (!ctx) {
        OSSL_PARAM_free(params);
        throw std::runtime_error("EVP_PKEY_CTX_new_from_name failed");
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
    if (EVP_PKEY_generate(ctx.get(), &raw_key) <= 0)
        throw std::runtime_error("EVP_PKEY_generate failed: " +
                                 openssl_error_string());
    EVP_PKEY_ptr pkey(raw_key, EVP_PKEY_free);

    // Write private key
    {
        BIO_ptr bio(BIO_new_file(priv_path.c_str(), "wb"), BIO_free_all);
        if (!bio) throw std::runtime_error("Cannot create private key file: " +
                                           priv_path);
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
        if (!bio) throw std::runtime_error("Cannot create public key file: " +
                                           pub_path);
        int rc = (fmt == KeyFormat::PEM)
            ? PEM_write_bio_PUBKEY(bio.get(), pkey.get())
            : i2d_PUBKEY_bio(bio.get(), pkey.get());
        if (rc <= 0)
            throw std::runtime_error("Failed to write public key: " +
                                     openssl_error_string());
    }

    if (!g_quiet)
    std::cout << "[ECDSA] Key pair generated (" << curve_name(curve) << ")\n"
              << "  Private key -> " << priv_path << "\n"
              << "  Public  key -> " << pub_path  << "\n";
    return true;
}

// ── Sign ──────────────────────────────────────────────────────

bool ecdsa_sign(ECCurve curve,
                const std::string& priv_path,
                const std::string& msg_path,
                const std::string& sig_path,
                const std::string& hash_algo,
                SigEncoding enc,
                KeyFormat fmt) {
    ERR_clear_error();
    const EVP_MD* md = resolve_md(hash_algo);

    // Load and validate key
    EVP_PKEY_ptr pkey(load_private_key(priv_path, fmt), EVP_PKEY_free);
    validate_ec_key_curve(pkey.get(), curve);

    // Read message
    std::vector<uint8_t> msg = read_file(msg_path);

    // Create signing context
    EVP_MD_CTX_ptr mdctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!mdctx) throw std::runtime_error("EVP_MD_CTX_new failed");

    if (EVP_DigestSignInit(mdctx.get(), nullptr, md, nullptr, pkey.get()) <= 0)
        throw std::runtime_error("EVP_DigestSignInit failed: " +
                                 openssl_error_string());

    if (EVP_DigestSignUpdate(mdctx.get(), msg.data(), msg.size()) <= 0)
        throw std::runtime_error("EVP_DigestSignUpdate failed: " +
                                 openssl_error_string());

    // Get signature length
    size_t sig_len = 0;
    if (EVP_DigestSignFinal(mdctx.get(), nullptr, &sig_len) <= 0)
        throw std::runtime_error("EVP_DigestSignFinal (len) failed: " +
                                 openssl_error_string());

    std::vector<uint8_t> sig(sig_len);
    if (EVP_DigestSignFinal(mdctx.get(), sig.data(), &sig_len) <= 0)
        throw std::runtime_error("EVP_DigestSignFinal failed: " +
                                 openssl_error_string());
    sig.resize(sig_len);

    // Encode and write
    std::vector<uint8_t> out = encode_sig(sig, enc);
    write_file(sig_path, out);

    if (!g_quiet)
    std::cout << "[ECDSA] Sign OK\n"
              << "  Algo     : " << "ecdsa-" << curve_name(curve) << " / " << hash_algo << "\n"
              << "  Message  : " << msg_path  << " (" << msg.size()  << " bytes)\n"
              << "  Signature: " << sig_path  << " (" << out.size()  << " bytes, "
              << (enc == SigEncoding::BASE64 ? "base64" :
                  enc == SigEncoding::DER    ? "DER"    : "raw")      << ")\n";
    return true;
}

// ── Verify ────────────────────────────────────────────────────

bool ecdsa_verify(ECCurve curve,
                  const std::string& pub_path,
                  const std::string& msg_path,
                  const std::string& sig_path,
                  const std::string& hash_algo,
                  SigEncoding enc,
                  KeyFormat fmt) {
    ERR_clear_error();
    const EVP_MD* md = resolve_md(hash_algo);

    // Load and validate key
    EVP_PKEY_ptr pkey(load_public_key(pub_path, fmt), EVP_PKEY_free);
    validate_ec_key_curve(pkey.get(), curve);

    // Read message and signature
    std::vector<uint8_t> msg = read_file(msg_path);
    std::vector<uint8_t> sig_raw = read_file(sig_path);
    std::vector<uint8_t> sig = decode_sig(sig_raw, enc);

    // Create verify context
    EVP_MD_CTX_ptr mdctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!mdctx) throw std::runtime_error("EVP_MD_CTX_new failed");

    if (EVP_DigestVerifyInit(mdctx.get(), nullptr, md, nullptr, pkey.get()) <= 0)
        throw std::runtime_error("EVP_DigestVerifyInit failed: " +
                                 openssl_error_string());

    if (EVP_DigestVerifyUpdate(mdctx.get(), msg.data(), msg.size()) <= 0)
        throw std::runtime_error("EVP_DigestVerifyUpdate failed: " +
                                 openssl_error_string());

    int rc = EVP_DigestVerifyFinal(mdctx.get(), sig.data(), sig.size());
    if (rc == 1) {
        if (!g_quiet) std::cout << "[ECDSA] Verify: VALID\n";
        return true;
    } else if (rc == 0) {
        if (!g_quiet) std::cout << "[ECDSA] Verify: INVALID (signature mismatch)\n";
        ERR_clear_error();
        return false;
    } else {
        throw std::runtime_error("EVP_DigestVerifyFinal error: " +
                                 openssl_error_string());
    }
}
