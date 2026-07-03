#include "keygen.h"
#include "utils.h"
#include <oqs/oqs.h>
#include <iostream>
#include <stdexcept>
#include <cstring>

SigAlgo parse_sig_algo(const std::string& name) {
    if (name == "mldsa-44" || name == "ml-dsa-44") return SigAlgo::ML_DSA_44;
    if (name == "mldsa-65" || name == "ml-dsa-65") return SigAlgo::ML_DSA_65;
    throw std::invalid_argument("Unknown signature algorithm: " + name);
}

KemAlgo parse_kem_algo(const std::string& name) {
    if (name == "mlkem-512" || name == "ml-kem-512") return KemAlgo::ML_KEM_512;
    throw std::invalid_argument("Unknown KEM algorithm: " + name);
}

const char* sig_algo_name(SigAlgo a) {
    switch (a) {
        case SigAlgo::ML_DSA_44: return "ML-DSA-44";
        case SigAlgo::ML_DSA_65: return "ML-DSA-65";
    }
    return "Unknown";
}

const char* kem_algo_name(KemAlgo a) {
    switch (a) {
        case KemAlgo::ML_KEM_512: return "ML-KEM-512";
    }
    return "Unknown";
}

// ── OQS algorithm name mapping ───────────────────────────────────────────────
static const char* oqs_sig_name(SigAlgo a) {
    switch (a) {
        case SigAlgo::ML_DSA_44: return OQS_SIG_alg_ml_dsa_44;
        case SigAlgo::ML_DSA_65: return OQS_SIG_alg_ml_dsa_65;
    }
    return nullptr;
}

static const char* oqs_kem_name(KemAlgo a) {
    switch (a) {
        case KemAlgo::ML_KEM_512: return OQS_KEM_alg_ml_kem_512;
    }
    return nullptr;
}

// ── keygen for signature algorithms ─────────────────────────────────────────
static int keygen_sig(SigAlgo algo, const std::string& pub_file,
                      const std::string& priv_file) {
    OQS_SIG* sig = OQS_SIG_new(oqs_sig_name(algo));
    if (!sig) {
        std::cerr << "[ERROR] OQS_SIG_new failed for " << sig_algo_name(algo) << "\n";
        return 1;
    }

    std::vector<uint8_t> pub(sig->length_public_key);
    std::vector<uint8_t> priv(sig->length_secret_key);

    OQS_STATUS rc = OQS_SIG_keypair(sig, pub.data(), priv.data());
    OQS_SIG_free(sig);

    if (rc != OQS_SUCCESS) {
        std::cerr << "[ERROR] Key generation failed\n";
        return 1;
    }

    // Write public key as PEM
    std::string label = std::string(sig_algo_name(algo)) + " PUBLIC KEY";
    if (!pem_write(pub_file, label, pub.data(), pub.size())) {
        std::cerr << "[ERROR] Cannot write public key to " << pub_file << "\n";
        return 1;
    }

    // Write private key as PEM
    label = std::string(sig_algo_name(algo)) + " PRIVATE KEY";
    if (!pem_write(priv_file, label, priv.data(), priv.size())) {
        std::cerr << "[ERROR] Cannot write private key to " << priv_file << "\n";
        // zero-out on failure too
        std::fill(priv.begin(), priv.end(), 0);
        return 1;
    }

    // Zero-out private key from memory
    std::fill(priv.begin(), priv.end(), 0);

    std::cout << "[OK] " << sig_algo_name(algo) << " keypair generated\n";
    std::cout << "     Public key : " << pub_file  << " (" << pub.size()  << " bytes)\n";
    std::cout << "     Private key: " << priv_file << "\n";
    return 0;
}

// ── keygen for KEM algorithms ────────────────────────────────────────────────
static int keygen_kem(KemAlgo algo, const std::string& pub_file,
                      const std::string& priv_file) {
    OQS_KEM* kem = OQS_KEM_new(oqs_kem_name(algo));
    if (!kem) {
        std::cerr << "[ERROR] OQS_KEM_new failed for " << kem_algo_name(algo) << "\n";
        return 1;
    }

    std::vector<uint8_t> pub(kem->length_public_key);
    std::vector<uint8_t> priv(kem->length_secret_key);

    OQS_STATUS rc = OQS_KEM_keypair(kem, pub.data(), priv.data());
    OQS_KEM_free(kem);

    if (rc != OQS_SUCCESS) {
        std::cerr << "[ERROR] KEM key generation failed\n";
        return 1;
    }

    std::string label = std::string(kem_algo_name(algo)) + " PUBLIC KEY";
    if (!pem_write(pub_file, label, pub.data(), pub.size())) {
        std::cerr << "[ERROR] Cannot write public key to " << pub_file << "\n";
        return 1;
    }

    label = std::string(kem_algo_name(algo)) + " PRIVATE KEY";
    if (!pem_write(priv_file, label, priv.data(), priv.size())) {
        std::cerr << "[ERROR] Cannot write private key to " << priv_file << "\n";
        std::fill(priv.begin(), priv.end(), 0);
        return 1;
    }

    std::fill(priv.begin(), priv.end(), 0);

    std::cout << "[OK] " << kem_algo_name(algo) << " keypair generated\n";
    std::cout << "     Public key : " << pub_file  << " (" << pub.size()  << " bytes)\n";
    std::cout << "     Private key: " << priv_file << "\n";
    return 0;
}

// ── CLI entry point ──────────────────────────────────────────────────────────
int cmd_keygen(int argc, char* argv[]) {
    std::string algo_str, pub_file = "pub.pem", priv_file = "priv.pem";

    for (int i = 0; i < argc - 1; ++i) {
        std::string a = argv[i];
        if (a == "--algo")  algo_str  = argv[++i];
        else if (a == "--pub")   pub_file  = argv[++i];
        else if (a == "--priv")  priv_file = argv[++i];
    }

    if (algo_str.empty()) {
        std::cerr << "[ERROR] --algo required\n"
                  << "  Usage: pqtool keygen --algo <mldsa-44|mldsa-65|mlkem-512> "
                     "--pub <pub.pem> --priv <priv.pem>\n";
        return 1;
    }

    // Detect sig vs kem
    try {
        if (algo_str.find("dsa") != std::string::npos) {
            return keygen_sig(parse_sig_algo(algo_str), pub_file, priv_file);
        } else {
            return keygen_kem(parse_kem_algo(algo_str), pub_file, priv_file);
        }
    } catch (const std::exception& e) {
        std::cerr << "[ERROR] " << e.what() << "\n";
        return 1;
    }
}
