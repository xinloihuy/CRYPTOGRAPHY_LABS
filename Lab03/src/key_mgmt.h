#pragma once
#include <string>
#include <vector>
#include <openssl/evp.h>

// RSA key pair management
struct RsaKeyPair {
    EVP_PKEY* pkey = nullptr;
    int bits = 3072;
    ~RsaKeyPair() { if (pkey) EVP_PKEY_free(pkey); }
    // Non-copyable
    RsaKeyPair() = default;
    RsaKeyPair(const RsaKeyPair&) = delete;
    RsaKeyPair& operator=(const RsaKeyPair&) = delete;
    RsaKeyPair(RsaKeyPair&& o) : pkey(o.pkey), bits(o.bits) { o.pkey = nullptr; }
};

// Generate RSA key pair of given bit size
RsaKeyPair keygen(int bits);

// Save private key to PEM file
void save_private_key_pem(EVP_PKEY* pkey, const std::string& path);
// Save public key to PEM file
void save_public_key_pem(EVP_PKEY* pkey, const std::string& path);

// Save private key to DER file
void save_private_key_der(EVP_PKEY* pkey, const std::string& path);
// Save public key to DER file
void save_public_key_der(EVP_PKEY* pkey, const std::string& path);

// Save metadata JSON
void save_key_metadata(const std::string& path, int bits, const std::string& hash_alg);

// Load public key from PEM
EVP_PKEY* load_public_key_pem(const std::string& path);
// Load private key from PEM
EVP_PKEY* load_private_key_pem(const std::string& path);

// Get RSA modulus bit size
int get_rsa_bits(EVP_PKEY* pkey);
