#include "key_mgmt.h"
#include "utils.h"
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <stdexcept>
#include <fstream>
#include <ctime>
#include <iomanip>
#include <sstream>

// ─── Key Generation ───────────────────────────────────────────────────────────
RsaKeyPair keygen(int bits) {
    if (bits < 3072)
        throw std::runtime_error("keygen: RSA modulus must be >= 3072 bits");

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr);
    if (!ctx) openssl_die("EVP_PKEY_CTX_new_from_name");

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        openssl_die("EVP_PKEY_keygen_init");
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        openssl_die("EVP_PKEY_CTX_set_rsa_keygen_bits");
    }

    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_generate(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        openssl_die("EVP_PKEY_generate");
    }
    EVP_PKEY_CTX_free(ctx);

    RsaKeyPair kp;
    kp.pkey = pkey;
    kp.bits = bits;
    return kp;
}

// ─── Save/Load PEM ────────────────────────────────────────────────────────────
void save_private_key_pem(EVP_PKEY* pkey, const std::string& path) {
    FILE* f = fopen(path.c_str(), "wb");
    if (!f) throw std::runtime_error("Cannot open " + path + " for writing");
    int rc = PEM_write_PrivateKey(f, pkey, nullptr, nullptr, 0, nullptr, nullptr);
    fclose(f);
    if (!rc) openssl_die("PEM_write_PrivateKey");
}

void save_public_key_pem(EVP_PKEY* pkey, const std::string& path) {
    FILE* f = fopen(path.c_str(), "wb");
    if (!f) throw std::runtime_error("Cannot open " + path + " for writing");
    int rc = PEM_write_PUBKEY(f, pkey);
    fclose(f);
    if (!rc) openssl_die("PEM_write_PUBKEY");
}

// ─── Save/Load DER ────────────────────────────────────────────────────────────
void save_private_key_der(EVP_PKEY* pkey, const std::string& path) {
    FILE* f = fopen(path.c_str(), "wb");
    if (!f) throw std::runtime_error("Cannot open " + path + " for writing");
    int rc = i2d_PrivateKey_fp(f, pkey);
    fclose(f);
    if (!rc) openssl_die("i2d_PrivateKey_fp");
}

void save_public_key_der(EVP_PKEY* pkey, const std::string& path) {
    FILE* f = fopen(path.c_str(), "wb");
    if (!f) throw std::runtime_error("Cannot open " + path + " for writing");
    int rc = i2d_PUBKEY_fp(f, pkey);
    fclose(f);
    if (!rc) openssl_die("i2d_PUBKEY_fp");
}

// ─── Metadata JSON ────────────────────────────────────────────────────────────
void save_key_metadata(const std::string& path, int bits, const std::string& hash_alg) {
    // Get current UTC time
    std::time_t t = std::time(nullptr);
    std::tm* tm_utc = std::gmtime(&t);
    std::ostringstream ts;
    ts << std::put_time(tm_utc, "%Y-%m-%dT%H:%M:%SZ");

    std::string json = "{\n";
    json += "  \"creation_time\": \"" + ts.str() + "\",\n";
    json += "  \"modulus_bits\": " + std::to_string(bits) + ",\n";
    json += "  \"hash\": \"" + hash_alg + "\"\n";
    json += "}\n";

    write_file_text(path, json);
}

// ─── Load keys ────────────────────────────────────────────────────────────────
EVP_PKEY* load_public_key_pem(const std::string& path) {
    FILE* f = fopen(path.c_str(), "rb");
    if (!f) throw std::runtime_error("Cannot open public key: " + path);
    EVP_PKEY* pkey = PEM_read_PUBKEY(f, nullptr, nullptr, nullptr);
    fclose(f);
    if (!pkey) openssl_die("PEM_read_PUBKEY from " + path);
    return pkey;
}

EVP_PKEY* load_private_key_pem(const std::string& path) {
    FILE* f = fopen(path.c_str(), "rb");
    if (!f) throw std::runtime_error("Cannot open private key: " + path);
    EVP_PKEY* pkey = PEM_read_PrivateKey(f, nullptr, nullptr, nullptr);
    fclose(f);
    if (!pkey) openssl_die("PEM_read_PrivateKey from " + path);
    return pkey;
}

// ─── Get RSA bits ─────────────────────────────────────────────────────────────
int get_rsa_bits(EVP_PKEY* pkey) {
    return EVP_PKEY_get_bits(pkey);
}
