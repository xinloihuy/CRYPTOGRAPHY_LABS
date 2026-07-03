#include "decaps.h"
#include "keygen.h"
#include "utils.h"
#include <oqs/oqs.h>
#include <iostream>
#include <stdexcept>
#include <cstring>

static const char* oqs_kem_name_for_decaps(KemAlgo a) {
    switch (a) {
        case KemAlgo::ML_KEM_512: return OQS_KEM_alg_ml_kem_512;
    }
    return nullptr;
}

int cmd_decaps(int argc, char* argv[]) {
    std::string algo_str, priv_file = "priv.pem", ct_file = "ct.bin", ss_file = "ss.bin";
    // Optional: file to verify against encaps shared secret
    std::string verify_ss;

    for (int i = 0; i < argc - 1; ++i) {
        std::string a = argv[i];
        if      (a == "--algo")      algo_str  = argv[++i];
        else if (a == "--priv")      priv_file = argv[++i];
        else if (a == "--ct")        ct_file   = argv[++i];
        else if (a == "--ss")        ss_file   = argv[++i];
        else if (a == "--verify-ss") verify_ss = argv[++i];
    }

    if (algo_str.empty()) {
        std::cerr << "[ERROR] Usage: pqtool decaps --algo <mlkem-512> "
                     "--priv priv.pem --ct ct.bin --ss ss.bin [--verify-ss encaps_ss.bin]\n";
        return 1;
    }

    try {
        KemAlgo algo = parse_kem_algo(algo_str);
        OQS_KEM* kem = OQS_KEM_new(oqs_kem_name_for_decaps(algo));
        if (!kem) {
            std::cerr << "[ERROR] Failed to initialize " << kem_algo_name(algo) << "\n";
            return 1;
        }

        // Load private key
        std::vector<uint8_t> sk = pem_read(priv_file);
        if (sk.size() != kem->length_secret_key) {
            std::cerr << "[ERROR] Private key size mismatch: got " << sk.size()
                      << " expected " << kem->length_secret_key << "\n";
            OQS_KEM_free(kem);
            return 1;
        }

        // Load ciphertext
        std::vector<uint8_t> ct = file_read(ct_file);
        if (ct.size() != kem->length_ciphertext) {
            std::cerr << "[ERROR] Ciphertext size mismatch: got " << ct.size()
                      << " expected " << kem->length_ciphertext << "\n";
            std::fill(sk.begin(), sk.end(), 0);
            OQS_KEM_free(kem);
            return 1;
        }

        // Decapsulate
        std::vector<uint8_t> ss(kem->length_shared_secret);
        OQS_STATUS rc = OQS_KEM_decaps(kem, ss.data(), ct.data(), sk.data());

        // Zero private key
        std::fill(sk.begin(), sk.end(), 0);
        OQS_KEM_free(kem);

        if (rc != OQS_SUCCESS) {
            std::cerr << "[FAIL] Decapsulation failed (likely bad ciphertext or wrong key)\n";
            return 2;
        }

        // Write shared secret
        if (!file_write(ss_file, ss.data(), ss.size())) {
            std::cerr << "[ERROR] Cannot write shared secret to " << ss_file << "\n";
            return 1;
        }

        std::cout << "[OK] " << kem_algo_name(algo) << " decapsulation done\n";
        std::cout << "     Shared secret: " << ss_file << " (" << ss.size() << " bytes)\n";
        print_hex("     Shared secret", ss.data(), ss.size());

        // Optional: verify against encaps shared secret
        if (!verify_ss.empty()) {
            try {
                std::vector<uint8_t> ref = file_read(verify_ss);
                if (ref.size() == ss.size() && bytes_equal(ss.data(), ref.data(), ss.size())) {
                    std::cout << "[OK] Shared secrets MATCH ✓ (encaps == decaps)\n";
                } else {
                    std::cout << "[FAIL] Shared secrets DO NOT MATCH ✗\n";
                    return 2;
                }
            } catch (...) {
                std::cerr << "[WARN] Could not read verify-ss file: " << verify_ss << "\n";
            }
        }

        return 0;

    } catch (const std::exception& e) {
        std::cerr << "[ERROR] " << e.what() << "\n";
        return 1;
    }
}
