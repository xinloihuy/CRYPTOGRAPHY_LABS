#include "verify.h"
#include "keygen.h"
#include "utils.h"
#include <oqs/oqs.h>
#include <iostream>
#include <stdexcept>

static const char* oqs_sig_name_for_verify(SigAlgo a) {
    switch (a) {
        case SigAlgo::ML_DSA_44: return OQS_SIG_alg_ml_dsa_44;
        case SigAlgo::ML_DSA_65: return OQS_SIG_alg_ml_dsa_65;
    }
    return nullptr;
}

int cmd_verify(int argc, char* argv[]) {
    std::string algo_str, pub_file = "pub.pem", in_file, sig_file;
    std::string format = "raw";

    for (int i = 0; i < argc - 1; ++i) {
        std::string a = argv[i];
        if      (a == "--algo")   algo_str = argv[++i];
        else if (a == "--pub")    pub_file = argv[++i];
        else if (a == "--in")     in_file  = argv[++i];
        else if (a == "--sig")    sig_file = argv[++i];
        else if (a == "--format") format   = argv[++i];
    }

    if (algo_str.empty() || in_file.empty() || sig_file.empty()) {
        std::cerr << "[ERROR] Usage: pqtool verify --algo <mldsa-44|mldsa-65> "
                     "--pub pub.pem --in msg.bin --sig sig.bin [--format raw|base64]\n";
        return 1;
    }

    try {
        SigAlgo algo = parse_sig_algo(algo_str);
        OQS_SIG* sig = OQS_SIG_new(oqs_sig_name_for_verify(algo));
        if (!sig) {
            std::cerr << "[ERROR] Failed to initialize " << sig_algo_name(algo) << "\n";
            return 1;
        }

        // Load public key
        std::vector<uint8_t> pk = pem_read(pub_file);
        if (pk.size() != sig->length_public_key) {
            std::cerr << "[ERROR] Public key size mismatch: got " << pk.size()
                      << " expected " << sig->length_public_key << "\n";
            OQS_SIG_free(sig);
            return 1;
        }

        // Load message
        std::vector<uint8_t> msg = file_read(in_file);

        // Load signature
        std::vector<uint8_t> signature;
        if (format == "base64") {
            signature = b64file_read(sig_file);
        } else {
            signature = file_read(sig_file);
        }

        // Verify
        OQS_STATUS rc = OQS_SIG_verify(sig, msg.data(), msg.size(),
                                        signature.data(), signature.size(), pk.data());
        OQS_SIG_free(sig);

        if (rc == OQS_SUCCESS) {
            std::cout << "[OK] Signature VALID ✓\n";
            std::cout << "     Algorithm : " << sig_algo_name(algo) << "\n";
            std::cout << "     Message   : " << in_file  << " (" << msg.size()       << " bytes)\n";
            std::cout << "     Signature : " << sig_file << " (" << signature.size() << " bytes)\n";
            return 0;
        } else {
            std::cout << "[FAIL] Signature INVALID ✗\n";
            return 2; // exit code 2 = verification failed (not an error, just invalid)
        }

    } catch (const std::exception& e) {
        std::cerr << "[ERROR] " << e.what() << "\n";
        return 1;
    }
}
