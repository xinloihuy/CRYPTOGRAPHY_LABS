#include "encaps.h"
#include "keygen.h"
#include "utils.h"
#include <oqs/oqs.h>
#include <iostream>
#include <stdexcept>

static const char* oqs_kem_name_for_encaps(KemAlgo a) {
    switch (a) {
        case KemAlgo::ML_KEM_512: return OQS_KEM_alg_ml_kem_512;
    }
    return nullptr;
}

int cmd_encaps(int argc, char* argv[]) {
    std::string algo_str, pub_file = "pub.pem", ct_file = "ct.bin", ss_file = "ss.bin";

    for (int i = 0; i < argc - 1; ++i) {
        std::string a = argv[i];
        if      (a == "--algo") algo_str = argv[++i];
        else if (a == "--pub")  pub_file = argv[++i];
        else if (a == "--ct")   ct_file  = argv[++i];
        else if (a == "--ss")   ss_file  = argv[++i];
    }

    if (algo_str.empty()) {
        std::cerr << "[ERROR] Usage: pqtool encaps --algo <mlkem-512> "
                     "--pub pub.pem --ct ct.bin --ss ss.bin\n";
        return 1;
    }

    try {
        KemAlgo algo = parse_kem_algo(algo_str);
        OQS_KEM* kem = OQS_KEM_new(oqs_kem_name_for_encaps(algo));
        if (!kem) {
            std::cerr << "[ERROR] Failed to initialize " << kem_algo_name(algo) << "\n";
            return 1;
        }

        // Load public key
        std::vector<uint8_t> pk = pem_read(pub_file);
        if (pk.size() != kem->length_public_key) {
            std::cerr << "[ERROR] Public key size mismatch: got " << pk.size()
                      << " expected " << kem->length_public_key << "\n";
            OQS_KEM_free(kem);
            return 1;
        }

        // Allocate buffers
        std::vector<uint8_t> ct(kem->length_ciphertext);
        std::vector<uint8_t> ss(kem->length_shared_secret);

        // Encapsulate
        OQS_STATUS rc = OQS_KEM_encaps(kem, ct.data(), ss.data(), pk.data());
        OQS_KEM_free(kem);

        if (rc != OQS_SUCCESS) {
            std::cerr << "[ERROR] Encapsulation failed\n";
            return 1;
        }

        if (!file_write(ct_file, ct.data(), ct.size())) {
            std::cerr << "[ERROR] Cannot write ciphertext to " << ct_file << "\n";
            return 1;
        }
        if (!file_write(ss_file, ss.data(), ss.size())) {
            std::cerr << "[ERROR] Cannot write shared secret to " << ss_file << "\n";
            return 1;
        }

        std::cout << "[OK] " << kem_algo_name(algo) << " encapsulation done\n";
        std::cout << "     Ciphertext   : " << ct_file << " (" << ct.size() << " bytes)\n";
        std::cout << "     Shared secret: " << ss_file << " (" << ss.size() << " bytes)\n";
        print_hex("     Shared secret", ss.data(), ss.size());
        return 0;

    } catch (const std::exception& e) {
        std::cerr << "[ERROR] " << e.what() << "\n";
        return 1;
    }
}
