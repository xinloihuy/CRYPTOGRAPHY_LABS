/**
 * pqtool — Post-Quantum Cryptography CLI Tool
 * Lab 06: ML-DSA Signatures & ML-KEM Key Encapsulation
 *
 * Usage:
 *   pqtool keygen  --algo <mldsa-44|mldsa-65|mlkem-512> --pub pub.pem --priv priv.pem
 *   pqtool sign    --algo <mldsa-44|mldsa-65> --priv priv.pem --in msg.bin --out sig.bin
 *   pqtool verify  --algo <mldsa-44|mldsa-65> --pub pub.pem --in msg.bin --sig sig.bin
 *   pqtool encaps  --algo mlkem-512 --pub pub.pem --ct ct.bin --ss ss.bin
 *   pqtool decaps  --algo mlkem-512 --priv priv.pem --ct ct.bin --ss ss.bin
 *   pqtool cert    --action <create|verify|tamper-test> [options]
 *   pqtool bench   --algo <mldsa-44|mldsa-65|mlkem-512|all> [--rounds N]
 *   pqtool test
 *   pqtool info
 */

#include "keygen.h"
#include "sign.h"
#include "verify.h"
#include "encaps.h"
#include "decaps.h"
#include "cert.h"
#include "bench.h"
#include "tests.h"

#include <oqs/oqs.h>
#include <iostream>
#include <string>
#include <cstring>

static void print_banner() {
    std::cout << R"(
  ██████╗  ██████╗ ████████╗ ██████╗  ██████╗ ██╗
  ██╔══██╗██╔═══██╗╚══██╔══╝██╔═══██╗██╔═══██╗██║
  ██████╔╝██║   ██║   ██║   ██║   ██║██║   ██║██║
  ██╔═══╝ ██║▄▄ ██║   ██║   ██║   ██║██║   ██║██║
  ██║     ╚██████╔╝   ██║   ╚██████╔╝╚██████╔╝███████╗
  ╚═╝      ╚══▀▀═╝    ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝
  Post-Quantum Cryptography Tool — Lab 06
  Algorithms: ML-DSA-44, ML-DSA-65, ML-KEM-512
  Library: liboqs (Open Quantum Safe)
)" << '\n';
}

static void print_usage() {
    std::cout <<
        "Usage: pqtool <command> [options]\n\n"
        "Commands:\n"
        "  keygen   Generate a key pair\n"
        "  sign     Sign a message (ML-DSA)\n"
        "  verify   Verify a signature (ML-DSA)\n"
        "  encaps   KEM encapsulation (ML-KEM)\n"
        "  decaps   KEM decapsulation (ML-KEM)\n"
        "  cert     PQ Certificate operations\n"
        "  bench    Performance benchmark\n"
        "  test     Run all automated tests\n"
        "  info     Show algorithm information\n\n"
        "Examples:\n"
        "  pqtool keygen  --algo mldsa-44 --pub pub.pem --priv priv.pem\n"
        "  pqtool sign    --algo mldsa-44 --priv priv.pem --in msg.bin --out sig.bin\n"
        "  pqtool verify  --algo mldsa-44 --pub pub.pem --in msg.bin --sig sig.bin\n"
        "  pqtool encaps  --algo mlkem-512 --pub pub.pem --ct ct.bin --ss ss.bin\n"
        "  pqtool decaps  --algo mlkem-512 --priv priv.pem --ct ct.bin --ss ss.bin\n"
        "  pqtool cert    --action create --subject \"Alice\" --cert cert.json\n"
        "  pqtool cert    --action verify --cert cert.json --ca-pub ca_pub.pem\n"
        "  pqtool cert    --action tamper-test --cert cert.json --ca-pub ca_pub.pem\n"
        "  pqtool bench   --algo all --rounds 1000\n"
        "  pqtool test\n";
}

static void print_info() {
    std::cout << "=== Algorithm Information ===\n\n";

    // ML-DSA-44
    OQS_SIG* s44 = OQS_SIG_new(OQS_SIG_alg_ml_dsa_44);
    if (s44) {
        std::cout << "ML-DSA-44 (NIST Level 2, ~128-bit classical security)\n";
        std::cout << "  Public key size : " << s44->length_public_key  << " bytes\n";
        std::cout << "  Private key size: " << s44->length_secret_key  << " bytes\n";
        std::cout << "  Max signature   : " << s44->length_signature   << " bytes\n";
        std::cout << "  Comparison      : ECDSA-P256 sig = 64 bytes (ML-DSA-44 = "
                  << s44->length_signature << " bytes, " << s44->length_signature / 64
                  << "x larger)\n\n";
        OQS_SIG_free(s44);
    }

    // ML-DSA-65
    OQS_SIG* s65 = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    if (s65) {
        std::cout << "ML-DSA-65 (NIST Level 3, ~192-bit classical security)\n";
        std::cout << "  Public key size : " << s65->length_public_key  << " bytes\n";
        std::cout << "  Private key size: " << s65->length_secret_key  << " bytes\n";
        std::cout << "  Max signature   : " << s65->length_signature   << " bytes\n";
        std::cout << "  vs ML-DSA-44    : " << (double)s65->length_signature / s44->length_signature
                  << "x larger signature\n\n";
        OQS_SIG_free(s65);
    }

    // ML-KEM-512
    OQS_KEM* k512 = OQS_KEM_new(OQS_KEM_alg_ml_kem_512);
    if (k512) {
        std::cout << "ML-KEM-512 (NIST Level 1, ~128-bit classical security)\n";
        std::cout << "  Public key size   : " << k512->length_public_key    << " bytes\n";
        std::cout << "  Private key size  : " << k512->length_secret_key    << " bytes\n";
        std::cout << "  Ciphertext size   : " << k512->length_ciphertext     << " bytes\n";
        std::cout << "  Shared secret size: " << k512->length_shared_secret  << " bytes (256 bits)\n";
        std::cout << "  Comparison        : RSA-2048 ciphertext = 256 bytes, ML-KEM-512 = "
                  << k512->length_ciphertext << " bytes\n";
        std::cout << "  Security model    : IND-CCA2 (via Fujisaki-Okamoto transform)\n";
        std::cout << "  Note              : ML-KEM is NOT a signature scheme.\n";
        std::cout << "                     It provides key encapsulation only.\n\n";
        OQS_KEM_free(k512);
    }

    std::cout << "=== Security Discussion ===\n\n";
    std::cout << "Why ML-KEM is NOT used for signing:\n";
    std::cout << "  ML-KEM is a Key Encapsulation Mechanism (KEM), not a signature scheme.\n";
    std::cout << "  Signing requires a trapdoor one-way function where the private key\n";
    std::cout << "  allows computing signatures that anyone with the public key can verify.\n";
    std::cout << "  ML-KEM's trapdoor allows decapsulation (decryption) only, not signing.\n\n";

    std::cout << "Hybrid certificates (ECDSA + ML-DSA):\n";
    std::cout << "  During PQ migration, certificates can include both:\n";
    std::cout << "  1. Classical ECDSA signature (for backward compatibility)\n";
    std::cout << "  2. ML-DSA signature (for quantum resistance)\n";
    std::cout << "  Both must verify for the certificate to be valid.\n\n";

    std::cout << "ML-DSA deterministic signing:\n";
    std::cout << "  Unlike ECDSA (requires random nonce, RFC6979), ML-DSA\n";
    std::cout << "  uses deterministic signing based on rejection sampling.\n";
    std::cout << "  This eliminates the nonce reuse vulnerability of ECDSA.\n";

    std::cout << "\nliboqs version: " << OQS_version() << "\n";
}

// ── main ─────────────────────────────────────────────────────────────────────
int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_banner();
        print_usage();
        return 0;
    }

    std::string cmd = argv[1];

    // Pass remaining args (argv+2) to subcommand handlers
    // Each handler receives (argc-2, argv+2)
    int sub_argc = argc - 2;
    char** sub_argv = argv + 2;

    if (cmd == "keygen") {
        return cmd_keygen(sub_argc, sub_argv);
    } else if (cmd == "sign") {
        return cmd_sign(sub_argc, sub_argv);
    } else if (cmd == "verify") {
        return cmd_verify(sub_argc, sub_argv);
    } else if (cmd == "encaps") {
        return cmd_encaps(sub_argc, sub_argv);
    } else if (cmd == "decaps") {
        return cmd_decaps(sub_argc, sub_argv);
    } else if (cmd == "cert") {
        return cmd_cert(sub_argc, sub_argv);
    } else if (cmd == "bench") {
        return cmd_bench(sub_argc, sub_argv);
    } else if (cmd == "test") {
        return cmd_test(sub_argc, sub_argv);
    } else if (cmd == "info") {
        print_info();
        return 0;
    } else if (cmd == "--help" || cmd == "-h" || cmd == "help") {
        print_banner();
        print_usage();
        return 0;
    } else {
        std::cerr << "[ERROR] Unknown command: " << cmd << "\n\n";
        print_usage();
        return 1;
    }
}
