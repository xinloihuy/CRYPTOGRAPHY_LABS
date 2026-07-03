#include "sign.h"
#include "keygen.h"
#include "utils.h"
#include <oqs/oqs.h>
#include <iostream>
#include <stdexcept>
#include <cstring>

// Returns OQS algorithm name string for a SigAlgo
static const char* oqs_sig_name_for_sign(SigAlgo a) {
    switch (a) {
        case SigAlgo::ML_DSA_44: return OQS_SIG_alg_ml_dsa_44;
        case SigAlgo::ML_DSA_65: return OQS_SIG_alg_ml_dsa_65;
    }
    return nullptr;
}

int cmd_sign(int argc, char* argv[]) {
    std::string algo_str, priv_file = "priv.pem", in_file, out_file = "sig.bin";
    std::string format = "raw"; // raw | base64

    for (int i = 0; i < argc - 1; ++i) {
        std::string a = argv[i];
        if      (a == "--algo")   algo_str  = argv[++i];
        else if (a == "--priv")   priv_file = argv[++i];
        else if (a == "--in")     in_file   = argv[++i];
        else if (a == "--out")    out_file  = argv[++i];
        else if (a == "--format") format    = argv[++i];
    }

    if (algo_str.empty() || in_file.empty()) {
        std::cerr << "[ERROR] Usage: pqtool sign --algo <mldsa-44|mldsa-65> "
                     "--priv priv.pem --in msg.bin --out sig.bin [--format raw|base64]\n";
        return 1;
    }

    try {
        SigAlgo algo = parse_sig_algo(algo_str);
        OQS_SIG* sig = OQS_SIG_new(oqs_sig_name_for_sign(algo));
        if (!sig) {
            std::cerr << "[ERROR] Failed to initialize " << sig_algo_name(algo) << "\n";
            return 1;
        }

        // Load private key
        std::vector<uint8_t> sk = pem_read(priv_file);
        if (sk.size() != sig->length_secret_key) {
            std::cerr << "[ERROR] Private key size mismatch: got " << sk.size()
                      << " expected " << sig->length_secret_key << "\n";
            OQS_SIG_free(sig);
            return 1;
        }

        // Load message
        std::vector<uint8_t> msg = file_read(in_file);

        // Sign
        std::vector<uint8_t> signature(sig->length_signature);
        size_t sig_len = 0;
        OQS_STATUS rc = OQS_SIG_sign(sig, signature.data(), &sig_len,
                                      msg.data(), msg.size(), sk.data());
        // Zero sk
        std::fill(sk.begin(), sk.end(), 0);
        OQS_SIG_free(sig);

        if (rc != OQS_SUCCESS) {
            std::cerr << "[ERROR] Signing failed\n";
            return 1;
        }

        signature.resize(sig_len);

        // Write output
        bool ok = false;
        if (format == "base64") {
            ok = b64file_write(out_file, signature.data(), signature.size());
        } else {
            ok = file_write(out_file, signature.data(), signature.size());
        }

        if (!ok) {
            std::cerr << "[ERROR] Cannot write signature to " << out_file << "\n";
            return 1;
        }

        std::cout << "[OK] Signed with " << sig_algo_name(algo) << "\n";
        std::cout << "     Message   : " << in_file   << " (" << msg.size() << " bytes)\n";
        std::cout << "     Signature : " << out_file  << " (" << sig_len    << " bytes)\n";
        std::cout << "     Format    : " << format    << "\n";
        print_hex("     Sig (first 32B)", signature.data(), signature.size());
        return 0;

    } catch (const std::exception& e) {
        std::cerr << "[ERROR] " << e.what() << "\n";
        return 1;
    }
}
