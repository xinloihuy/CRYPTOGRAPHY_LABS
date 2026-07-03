/*
 * rsatool — RSA-OAEP & Hybrid Encryption CLI
 * Lab 03 — Cryptography, C++ + OpenSSL
 *
 * Commands:
 *   rsatool keygen    --bits <n> --pub <pub.pem> --priv <priv.pem>
 *   rsatool encrypt   --in <file> --pub <pub.pem> --out <file> [--label <l>] [--mode hybrid|auto]
 *   rsatool decrypt   --in <file> --priv <priv.pem> --out <file> [--label <l>]
 *   rsatool benchmark [--bits <n>]
 *   rsatool test
 *   rsatool manual-oaep --in <file> --pub <pub.pem> --out <file> [--label <l>]
 *   rsatool manual-oaep-dec --in <file> --priv <priv.pem> --out <file> [--label <l>]
 */

#include "key_mgmt.h"
#include "rsa_oaep.h"
#include "hybrid.h"
#include "aes_gcm.h"
#include "oaep_manual.h"
#include "benchmark.h"
#include "tests.h"
#include "utils.h"

#include <openssl/evp.h>
#include <openssl/err.h>
#include <iostream>
#include <string>
#include <map>
#include <vector>
#include <stdexcept>
#include <algorithm>
#include <filesystem>

namespace fs = std::filesystem;

// ─── Argument parsing ─────────────────────────────────────────────────────────
std::map<std::string, std::string> parse_args(int argc, char** argv, int start = 2) {
    std::map<std::string, std::string> args;
    for (int i = start; i < argc; i++) {
        std::string key = argv[i];
        if (key.substr(0, 2) == "--") {
            key = key.substr(2);
            if (i + 1 < argc && std::string(argv[i+1]).substr(0, 2) != "--") {
                args[key] = argv[++i];
            } else {
                args[key] = "true"; // flag
            }
        }
    }
    return args;
}

std::string require_arg(const std::map<std::string, std::string>& args,
                        const std::string& key) {
    auto it = args.find(key);
    if (it == args.end() || it->second.empty())
        throw std::runtime_error("Missing required argument: --" + key);
    return it->second;
}

std::string get_arg(const std::map<std::string, std::string>& args,
                    const std::string& key,
                    const std::string& def = "") {
    auto it = args.find(key);
    if (it == args.end()) return def;
    return it->second;
}

// ─── Print usage ──────────────────────────────────────────────────────────────
void print_usage(const char* prog) {
    std::cout << R"(
rsatool — RSA-OAEP & Hybrid Encryption (OpenSSL C++, Lab 03)

COMMANDS:

  keygen        Generate RSA key pair
    --bits      Key size in bits (default: 3072, min: 3072)
    --pub       Output public key PEM file
    --priv      Output private key PEM file
    Also saves: pub.der, priv.der, key_meta.json

  encrypt       Encrypt a file
    --in        Input plaintext file
    --pub       Public key PEM file
    --out       Output ciphertext file (binary envelope)
    --label     Optional OAEP label (default: empty)
    --mode      'auto' (default) or 'hybrid' (force hybrid)
    Auto-switches to hybrid if plaintext exceeds RSA-OAEP limit

  decrypt       Decrypt a file
    --in        Input ciphertext envelope file
    --priv      Private key PEM file
    --out       Output plaintext file
    --label     Optional OAEP label (default: empty)

  benchmark     Run performance benchmarks
    --bits      Key size (default: runs both 3072 and 4096)

  test          Run automated test suite (positive + negative tests)

  manual-oaep   Encrypt using manually implemented OAEP (Bonus +5)
    --in        Input plaintext file
    --pub       Public key PEM file
    --out       Output ciphertext file

  manual-oaep-dec  Decrypt using manually implemented OAEP
    --in        Input ciphertext file
    --priv      Private key PEM file
    --out       Output plaintext file

EXAMPLES:
  rsatool keygen --bits 3072 --pub pub.pem --priv priv.pem
  rsatool encrypt --in message.txt --pub pub.pem --out ciphertext.bin
  rsatool decrypt --in ciphertext.bin --priv priv.pem --out decrypted.txt
  rsatool encrypt --in bigfile.bin --pub pub.pem --out big.enc --mode hybrid
  rsatool benchmark
  rsatool test
)" << std::endl;
}

// ─── Commands ─────────────────────────────────────────────────────────────────
int cmd_keygen(const std::map<std::string, std::string>& args) {
    int bits = std::stoi(get_arg(args, "bits", "3072"));
    std::string pub_path  = require_arg(args, "pub");
    std::string priv_path = require_arg(args, "priv");

    std::cout << "[keygen] Generating RSA-" << bits << " key pair...\n";
    auto kp = keygen(bits);

    // Save PEM
    save_public_key_pem(kp.pkey, pub_path);
    save_private_key_pem(kp.pkey, priv_path);
    std::cout << "[keygen] PEM public key  → " << pub_path << "\n";
    std::cout << "[keygen] PEM private key → " << priv_path << "\n";

    // Save DER
    std::string pub_der  = pub_path.substr(0, pub_path.rfind('.')) + ".der";
    std::string priv_der = priv_path.substr(0, priv_path.rfind('.')) + ".der";
    save_public_key_der(kp.pkey, pub_der);
    save_private_key_der(kp.pkey, priv_der);
    std::cout << "[keygen] DER public key  → " << pub_der << "\n";
    std::cout << "[keygen] DER private key → " << priv_der << "\n";

    // Save metadata JSON
    std::string meta_path = "key_meta.json";
    save_key_metadata(meta_path, bits, "SHA-256");
    std::cout << "[keygen] Metadata JSON   → " << meta_path << "\n";
    std::cout << "[keygen] Done!\n";
    return 0;
}

int cmd_encrypt(const std::map<std::string, std::string>& args) {
    std::string in_path  = require_arg(args, "in");
    std::string pub_path = require_arg(args, "pub");
    std::string out_path = require_arg(args, "out");
    std::string label    = get_arg(args, "label", "");
    std::string mode     = get_arg(args, "mode", "auto");

    auto plaintext = read_file(in_path);
    auto pub_key   = load_public_key_pem(pub_path);

    size_t maxlen = rsa_oaep_max_plaintext(pub_key);
    int rsa_bits  = get_rsa_bits(pub_key);

    std::cout << "[encrypt] Input: " << in_path << " (" << plaintext.size() << " bytes)\n";
    std::cout << "[encrypt] Public key: RSA-" << rsa_bits << "\n";
    std::cout << "[encrypt] RSA-OAEP max plaintext: " << maxlen << " bytes\n";

    std::vector<unsigned char> ciphertext;

    bool use_hybrid = (mode == "hybrid") || (plaintext.size() > maxlen);
    if (use_hybrid) {
        std::cout << "[encrypt] Mode: HYBRID (RSA-OAEP + AES-256-GCM)\n";
        if (!label.empty())
            std::cout << "[encrypt] OAEP label: \"" << label << "\"\n";
        ciphertext = hybrid_encrypt(pub_key, plaintext, label);
    } else {
        std::cout << "[encrypt] Mode: RSA-OAEP only\n";
        if (!label.empty())
            std::cout << "[encrypt] OAEP label: \"" << label << "\"\n";
        // Wrap in hybrid envelope anyway for consistent format
        ciphertext = hybrid_encrypt(pub_key, plaintext, label);
    }

    write_file(out_path, ciphertext);
    std::cout << "[encrypt] Output: " << out_path << " (" << ciphertext.size() << " bytes)\n";
    std::cout << "[encrypt] Done!\n";

    EVP_PKEY_free(pub_key);
    return 0;
}

int cmd_decrypt(const std::map<std::string, std::string>& args) {
    std::string in_path   = require_arg(args, "in");
    std::string priv_path = require_arg(args, "priv");
    std::string out_path  = require_arg(args, "out");
    std::string label     = get_arg(args, "label", "");

    auto ciphertext = read_file(in_path);
    auto priv_key   = load_private_key_pem(priv_path);

    std::cout << "[decrypt] Input: " << in_path << " (" << ciphertext.size() << " bytes)\n";
    std::cout << "[decrypt] Private key loaded\n";
    if (!label.empty())
        std::cout << "[decrypt] OAEP label: \"" << label << "\"\n";

    auto plaintext = hybrid_decrypt(priv_key, ciphertext, label);

    write_file(out_path, plaintext);
    std::cout << "[decrypt] Output: " << out_path << " (" << plaintext.size() << " bytes)\n";
    std::cout << "[decrypt] Done!\n";

    EVP_PKEY_free(priv_key);
    return 0;
}

int cmd_benchmark(const std::map<std::string, std::string>& args) {
    (void)args;
    std::cout << "[benchmark] Starting RSA-OAEP benchmark...\n";
    run_benchmark(3072, 4096);
    run_hybrid_benchmark();
    return 0;
}

int cmd_test() {
    return run_tests();
}

int cmd_manual_oaep_enc(const std::map<std::string, std::string>& args) {
    std::string in_path  = require_arg(args, "in");
    std::string pub_path = require_arg(args, "pub");
    std::string out_path = require_arg(args, "out");
    std::string label    = get_arg(args, "label", "");

    auto plaintext = read_file(in_path);
    auto pub_key   = load_public_key_pem(pub_path);

    std::cout << "[manual-oaep] Encrypting with manually implemented OAEP...\n";
    auto ct = manual_oaep_encrypt(pub_key, plaintext, label);
    write_file(out_path, ct);
    std::cout << "[manual-oaep] Output: " << out_path << " (" << ct.size() << " bytes)\n";

    EVP_PKEY_free(pub_key);
    return 0;
}

int cmd_manual_oaep_dec(const std::map<std::string, std::string>& args) {
    std::string in_path   = require_arg(args, "in");
    std::string priv_path = require_arg(args, "priv");
    std::string out_path  = require_arg(args, "out");
    std::string label     = get_arg(args, "label", "");

    auto ct       = read_file(in_path);
    auto priv_key = load_private_key_pem(priv_path);

    std::cout << "[manual-oaep-dec] Decrypting with manually implemented OAEP...\n";
    auto pt = manual_oaep_decrypt(priv_key, ct, label);
    write_file(out_path, pt);
    std::cout << "[manual-oaep-dec] Output: " << out_path << " (" << pt.size() << " bytes)\n";

    EVP_PKEY_free(priv_key);
    return 0;
}

// ─── Main ─────────────────────────────────────────────────────────────────────
int main(int argc, char** argv) {
    // Initialize OpenSSL
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS |
                        OPENSSL_INIT_ADD_ALL_CIPHERS     |
                        OPENSSL_INIT_ADD_ALL_DIGESTS, nullptr);

    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    std::string cmd = argv[1];

    try {
        if (cmd == "keygen") {
            auto args = parse_args(argc, argv);
            return cmd_keygen(args);
        } else if (cmd == "encrypt") {
            auto args = parse_args(argc, argv);
            return cmd_encrypt(args);
        } else if (cmd == "decrypt") {
            auto args = parse_args(argc, argv);
            return cmd_decrypt(args);
        } else if (cmd == "benchmark") {
            auto args = parse_args(argc, argv);
            return cmd_benchmark(args);
        } else if (cmd == "test") {
            return cmd_test();
        } else if (cmd == "manual-oaep") {
            auto args = parse_args(argc, argv);
            return cmd_manual_oaep_enc(args);
        } else if (cmd == "manual-oaep-dec") {
            auto args = parse_args(argc, argv);
            return cmd_manual_oaep_dec(args);
        } else if (cmd == "--help" || cmd == "-h" || cmd == "help") {
            print_usage(argv[0]);
            return 0;
        } else {
            std::cerr << "[ERROR] Unknown command: " << cmd << "\n";
            print_usage(argv[0]);
            return 1;
        }
    } catch (const std::exception& e) {
        std::cerr << "\n[ERROR] " << e.what() << "\n";
        return 2;
    }
}
