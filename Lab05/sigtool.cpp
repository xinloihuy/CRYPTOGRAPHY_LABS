// ============================================================
//  sigtool.cpp  —  Main CLI entry point
//  Lab 05: Classical Digital Signatures (ECDSA, RSA-PSS)
//
//  Usage:
//    sigtool keygen --algo <algo> --pub <pub.pem> --priv <priv.pem> [--format pem|der]
//    sigtool sign   --algo <algo> --in <msg> --out <sig> --hash sha256 [--encode raw|der|base64] [--priv priv.pem]
//    sigtool verify --algo <algo> --in <msg> --sig <sig> --pub <pub.pem> [--encode raw|der|base64]
//    sigtool test
//    sigtool bench
//
//  Supported algos: ecdsa-p256, ecdsa-p384, rsa-pss-3072
// ============================================================
#include "ecdsa_handler.h"
#include "rsa_pss_handler.h"
#include "test_runner.h"
#include "benchmark.h"
#include "utils.h"

#include <openssl/err.h>
#include <openssl/evp.h>

#include <iostream>
#include <string>
#include <map>
#include <stdexcept>
#include <cstring>

// ── Argument parsing ──────────────────────────────────────────

struct Args {
    std::string command;
    std::string algo;
    std::string pub_path;
    std::string priv_path;
    std::string in_path;
    std::string out_path;
    std::string sig_path;
    std::string hash_algo  = "sha256";
    std::string encoding   = "raw";
    std::string key_format = "pem";
    int         salt_len   = -1;    // -1 = hashLen
};

static void usage(const char* /*prog*/) {
    std::cerr <<
R"(sigtool — Digital Signature Tool (ECDSA + RSA-PSS)
Lab 05: Classical Digital Signatures

USAGE:
  sigtool keygen --algo <algo> --pub <pub.pem> --priv <priv.pem> [--format pem|der]
  sigtool sign   --algo <algo> --in <msg> --out <sig> [--priv <priv.pem>]
                 [--hash sha256|sha384] [--encode raw|der|base64]
  sigtool verify --algo <algo> --in <msg> --sig <sig> --pub <pub.pem>
                 [--hash sha256|sha384] [--encode raw|der|base64]
  sigtool test   (run all automated tests)
  sigtool bench  (run performance benchmarks)

SUPPORTED ALGORITHMS:
  ecdsa-p256    ECDSA with NIST P-256 curve (~128-bit security)
  ecdsa-p384    ECDSA with NIST P-384 curve (~192-bit security) [bonus]
  rsa-pss-3072  RSA-PSS with 3072-bit modulus, SHA-256, salt=hashLen

EXAMPLES:
  sigtool keygen --algo ecdsa-p256 --pub pub.pem --priv priv.pem
  sigtool sign   --algo ecdsa-p256 --in msg.bin --out sig.bin --hash sha256
  sigtool verify --algo ecdsa-p256 --in msg.bin --sig sig.bin --pub pub.pem
  sigtool keygen --algo rsa-pss-3072 --pub pub.pem --priv priv.pem
  sigtool sign   --algo rsa-pss-3072 --in msg.bin --out sig.bin --encode base64
  sigtool verify --algo rsa-pss-3072 --in msg.bin --sig sig.bin --pub pub.pem --encode base64
  sigtool test
  sigtool bench
)" << "\n";
}

static Args parse_args(int argc, char* argv[]) {
    Args a;
    if (argc < 2) {
        usage(argv[0]);
        std::exit(1);
    }
    a.command = argv[1];

    for (int i = 2; i < argc; ++i) {
        std::string key = argv[i];
        auto next = [&]() -> std::string {
            if (i + 1 >= argc)
                throw std::invalid_argument("Missing value for " + key);
            return argv[++i];
        };
        if      (key == "--algo")   a.algo       = next();
        else if (key == "--pub")    a.pub_path   = next();
        else if (key == "--priv")   a.priv_path  = next();
        else if (key == "--in")     a.in_path    = next();
        else if (key == "--out")    a.out_path   = next();
        else if (key == "--sig")    a.sig_path   = next();
        else if (key == "--hash")   a.hash_algo  = next();
        else if (key == "--encode") a.encoding   = next();
        else if (key == "--format") a.key_format = next();
        else if (key == "--salt")   a.salt_len   = std::stoi(next());
        else if (key == "--help" || key == "-h") {
            usage(argv[0]);
            std::exit(0);
        }
        else {
            throw std::invalid_argument("Unknown option: " + key);
        }
    }
    return a;
}

// ── Command handlers ──────────────────────────────────────────

static int cmd_keygen(const Args& a) {
    if (a.algo.empty())     throw std::invalid_argument("--algo required");
    if (a.pub_path.empty()) throw std::invalid_argument("--pub required");
    if (a.priv_path.empty())throw std::invalid_argument("--priv required");

    KeyFormat fmt = parse_key_format(a.key_format);

    if (a.algo == "ecdsa-p256" || a.algo == "ecdsa-p384") {
        ECCurve curve = parse_curve(a.algo);
        return ecdsa_keygen(curve, a.pub_path, a.priv_path, fmt) ? 0 : 1;
    } else if (a.algo == "rsa-pss-3072") {
        return rsa_pss_keygen(3072, a.pub_path, a.priv_path, fmt) ? 0 : 1;
    } else {
        throw std::invalid_argument("Unknown algorithm: '" + a.algo +
                                    "'. Valid: ecdsa-p256, ecdsa-p384, rsa-pss-3072");
    }
}

static int cmd_sign(const Args& a) {
    if (a.algo.empty())   throw std::invalid_argument("--algo required");
    if (a.in_path.empty())throw std::invalid_argument("--in required");
    if (a.out_path.empty())throw std::invalid_argument("--out required");

    SigEncoding enc = parse_encoding(a.encoding);
    KeyFormat   fmt = parse_key_format(a.key_format);

    // Default private key path
    std::string priv = a.priv_path.empty() ? "priv.pem" : a.priv_path;

    if (a.algo == "ecdsa-p256" || a.algo == "ecdsa-p384") {
        ECCurve curve = parse_curve(a.algo);
        return ecdsa_sign(curve, priv, a.in_path, a.out_path,
                          a.hash_algo, enc, fmt) ? 0 : 1;
    } else if (a.algo == "rsa-pss-3072") {
        return rsa_pss_sign(priv, a.in_path, a.out_path,
                            a.hash_algo, a.salt_len, enc, fmt) ? 0 : 1;
    } else {
        throw std::invalid_argument("Unknown algorithm: " + a.algo);
    }
}

static int cmd_verify(const Args& a) {
    if (a.algo.empty())    throw std::invalid_argument("--algo required");
    if (a.in_path.empty()) throw std::invalid_argument("--in required");
    if (a.sig_path.empty())throw std::invalid_argument("--sig required");
    if (a.pub_path.empty())throw std::invalid_argument("--pub required");

    SigEncoding enc = parse_encoding(a.encoding);
    KeyFormat   fmt = parse_key_format(a.key_format);

    bool valid = false;
    if (a.algo == "ecdsa-p256" || a.algo == "ecdsa-p384") {
        ECCurve curve = parse_curve(a.algo);
        valid = ecdsa_verify(curve, a.pub_path, a.in_path, a.sig_path,
                             a.hash_algo, enc, fmt);
    } else if (a.algo == "rsa-pss-3072") {
        valid = rsa_pss_verify(a.pub_path, a.in_path, a.sig_path,
                               a.hash_algo, a.salt_len, enc, fmt);
    } else {
        throw std::invalid_argument("Unknown algorithm: " + a.algo);
    }

    // Exit code: 0 = valid, 2 = invalid signature (not error)
    return valid ? 0 : 2;
}

// ── Main ──────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    // Initialize OpenSSL
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS |
                        OPENSSL_INIT_ADD_ALL_CIPHERS     |
                        OPENSSL_INIT_ADD_ALL_DIGESTS, nullptr);

    try {
        Args a = parse_args(argc, argv);

        if (a.command == "keygen") return cmd_keygen(a);
        if (a.command == "sign")   return cmd_sign(a);
        if (a.command == "verify") return cmd_verify(a);
        if (a.command == "test") {
            int failures = run_all_tests();
            return (failures == 0) ? 0 : 1;
        }
        if (a.command == "bench") {
            run_benchmarks();
            return 0;
        }
        if (a.command == "--help" || a.command == "-h") {
            usage(argv[0]);
            return 0;
        }
        std::cerr << "[ERROR] Unknown command: '" << a.command << "'\n";
        usage(argv[0]);
        return 1;

    } catch (const std::invalid_argument& e) {
        std::cerr << "[ERROR] " << e.what() << "\n";
        return 1;
    } catch (const std::runtime_error& e) {
        std::cerr << "[ERROR] " << e.what() << "\n";
        print_openssl_errors();
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "[ERROR] Unexpected: " << e.what() << "\n";
        return 1;
    }
}
