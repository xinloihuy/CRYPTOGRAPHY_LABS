// ============================================================
//  test_runner.cpp  —  Automated positive & negative tests
//  Lab 05: Classical Digital Signatures
//
//  Tests:
//    TC01: ECDSA-P256  valid sign → verify passes
//    TC02: ECDSA-P256  modified message → verify fails
//    TC03: ECDSA-P256  modified signature → verify fails
//    TC04: ECDSA-P256  wrong public key → verify fails
//    TC05: ECDSA-P256  wrong hash (sha384 vs sha256) → error
//    TC06: ECDSA-P256  malformed signature → error/fail
//    TC07: ECDSA-P384  valid sign → verify passes (bonus)
//    TC08: RSA-PSS     valid sign → verify passes
//    TC09: RSA-PSS     modified message → verify fails
//    TC10: RSA-PSS     modified signature → verify fails
//    TC11: RSA-PSS     wrong public key → verify fails
//    TC12: RSA-PSS     base64 round-trip sign/verify
//    TC13: ECDSA-P256  base64 encoding round-trip
//    TC14: Wrong algo (P256 key used for P384) → error
//    TC15: Batch verify N signatures
// ============================================================
#include "test_runner.h"
#include "ecdsa_handler.h"
#include "rsa_pss_handler.h"
#include "utils.h"

#include <iostream>
#include <string>
#include <vector>
#include <functional>
#include <filesystem>
#include <cstring>

namespace fs = std::filesystem;

// ── Test framework ────────────────────────────────────────────

struct TestResult {
    std::string name;
    bool        passed;
    std::string message;
};

static std::vector<TestResult> g_results;

static void run_test(const std::string& name,
                     std::function<bool()> fn) {
    std::cout << "  [TEST] " << name << " ... ";
    try {
        bool ok = fn();
        g_results.push_back({name, ok, ok ? "PASS" : "FAIL"});
        std::cout << (ok ? "\033[32mPASS\033[0m" : "\033[31mFAIL\033[0m") << "\n";
    } catch (const std::exception& e) {
        // Expected-exception tests will catch before here
        g_results.push_back({name, false, std::string("EXCEPTION: ") + e.what()});
        std::cout << "\033[31mFAIL\033[0m (" << e.what() << ")\n";
    }
}

// Expect a test to throw OR return false (either = pass for negative tests)
static bool expect_fail(std::function<bool()> fn) {
    try {
        bool r = fn();
        return !r; // negative test passes if fn returned false
    } catch (const std::exception&) {
        return true; // exception also counts as expected failure
    }
}

// ── Temp file helpers ─────────────────────────────────────────

static std::string tmp(const std::string& name) {
    return (fs::temp_directory_path() / ("sigtool_test_" + name)).string();
}

static void write_tmp(const std::string& name, const std::vector<uint8_t>& data) {
    write_file(tmp(name), data);
}

static void cleanup_tmp(std::initializer_list<std::string> names) {
    for (auto& n : names) {
        fs::remove(tmp(n));
    }
}

// ── Individual Tests ──────────────────────────────────────────

static bool tc01_ecdsa_p256_valid() {
    // Keygen
    ecdsa_keygen(ECCurve::P256, tmp("tc01_pub.pem"), tmp("tc01_priv.pem"));
    // Create a test message
    std::vector<uint8_t> msg(1024, 0xAB);
    write_tmp("tc01_msg.bin", msg);
    // Sign
    ecdsa_sign(ECCurve::P256, tmp("tc01_priv.pem"), tmp("tc01_msg.bin"),
               tmp("tc01_sig.bin"), "sha256", SigEncoding::DER);
    // Verify
    bool ok = ecdsa_verify(ECCurve::P256, tmp("tc01_pub.pem"),
                           tmp("tc01_msg.bin"), tmp("tc01_sig.bin"),
                           "sha256", SigEncoding::DER);
    cleanup_tmp({"tc01_pub.pem","tc01_priv.pem","tc01_msg.bin","tc01_sig.bin"});
    return ok;
}

static bool tc02_ecdsa_p256_modified_message() {
    ecdsa_keygen(ECCurve::P256, tmp("tc02_pub.pem"), tmp("tc02_priv.pem"));
    std::vector<uint8_t> msg(512, 0x12);
    write_tmp("tc02_msg.bin", msg);
    ecdsa_sign(ECCurve::P256, tmp("tc02_priv.pem"), tmp("tc02_msg.bin"),
               tmp("tc02_sig.bin"), "sha256", SigEncoding::DER);
    // Modify message
    msg[10] ^= 0xFF;
    write_tmp("tc02_msg_bad.bin", msg);
    bool fails = expect_fail([&]{
        return ecdsa_verify(ECCurve::P256, tmp("tc02_pub.pem"),
                            tmp("tc02_msg_bad.bin"), tmp("tc02_sig.bin"),
                            "sha256", SigEncoding::DER);
    });
    cleanup_tmp({"tc02_pub.pem","tc02_priv.pem","tc02_msg.bin",
                 "tc02_msg_bad.bin","tc02_sig.bin"});
    return fails;
}

static bool tc03_ecdsa_p256_modified_signature() {
    ecdsa_keygen(ECCurve::P256, tmp("tc03_pub.pem"), tmp("tc03_priv.pem"));
    std::vector<uint8_t> msg(256, 0x34);
    write_tmp("tc03_msg.bin", msg);
    ecdsa_sign(ECCurve::P256, tmp("tc03_priv.pem"), tmp("tc03_msg.bin"),
               tmp("tc03_sig.bin"), "sha256", SigEncoding::DER);
    // Modify signature
    std::vector<uint8_t> sig = read_file(tmp("tc03_sig.bin"));
    if (sig.size() > 5) sig[5] ^= 0xFF;
    write_tmp("tc03_sig_bad.bin", sig);
    bool fails = expect_fail([&]{
        return ecdsa_verify(ECCurve::P256, tmp("tc03_pub.pem"),
                            tmp("tc03_msg.bin"), tmp("tc03_sig_bad.bin"),
                            "sha256", SigEncoding::DER);
    });
    cleanup_tmp({"tc03_pub.pem","tc03_priv.pem","tc03_msg.bin",
                 "tc03_sig.bin","tc03_sig_bad.bin"});
    return fails;
}

static bool tc04_ecdsa_p256_wrong_pubkey() {
    // Generate two different keypairs
    ecdsa_keygen(ECCurve::P256, tmp("tc04a_pub.pem"), tmp("tc04a_priv.pem"));
    ecdsa_keygen(ECCurve::P256, tmp("tc04b_pub.pem"), tmp("tc04b_priv.pem"));
    std::vector<uint8_t> msg(256, 0x56);
    write_tmp("tc04_msg.bin", msg);
    // Sign with key A, verify with key B
    ecdsa_sign(ECCurve::P256, tmp("tc04a_priv.pem"), tmp("tc04_msg.bin"),
               tmp("tc04_sig.bin"), "sha256", SigEncoding::DER);
    bool fails = expect_fail([&]{
        return ecdsa_verify(ECCurve::P256, tmp("tc04b_pub.pem"),
                            tmp("tc04_msg.bin"), tmp("tc04_sig.bin"),
                            "sha256", SigEncoding::DER);
    });
    cleanup_tmp({"tc04a_pub.pem","tc04a_priv.pem","tc04b_pub.pem",
                 "tc04b_priv.pem","tc04_msg.bin","tc04_sig.bin"});
    return fails;
}

static bool tc05_ecdsa_wrong_hash() {
    ecdsa_keygen(ECCurve::P256, tmp("tc05_pub.pem"), tmp("tc05_priv.pem"));
    std::vector<uint8_t> msg(256, 0x78);
    write_tmp("tc05_msg.bin", msg);
    // Sign with sha256, verify with sha384 → should fail/throw
    ecdsa_sign(ECCurve::P256, tmp("tc05_priv.pem"), tmp("tc05_msg.bin"),
               tmp("tc05_sig.bin"), "sha256", SigEncoding::DER);
    bool fails = expect_fail([&]{
        return ecdsa_verify(ECCurve::P256, tmp("tc05_pub.pem"),
                            tmp("tc05_msg.bin"), tmp("tc05_sig.bin"),
                            "sha384", SigEncoding::DER);
    });
    cleanup_tmp({"tc05_pub.pem","tc05_priv.pem","tc05_msg.bin","tc05_sig.bin"});
    return fails;
}

static bool tc06_ecdsa_malformed_signature() {
    ecdsa_keygen(ECCurve::P256, tmp("tc06_pub.pem"), tmp("tc06_priv.pem"));
    std::vector<uint8_t> msg(256, 0x9A);
    write_tmp("tc06_msg.bin", msg);
    // Write garbage as signature
    std::vector<uint8_t> garbage = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01};
    write_tmp("tc06_sig_bad.bin", garbage);
    bool fails = expect_fail([&]{
        return ecdsa_verify(ECCurve::P256, tmp("tc06_pub.pem"),
                            tmp("tc06_msg.bin"), tmp("tc06_sig_bad.bin"),
                            "sha256", SigEncoding::DER);
    });
    cleanup_tmp({"tc06_pub.pem","tc06_priv.pem","tc06_msg.bin","tc06_sig_bad.bin"});
    return fails;
}

static bool tc07_ecdsa_p384_valid() {
    ecdsa_keygen(ECCurve::P384, tmp("tc07_pub.pem"), tmp("tc07_priv.pem"));
    std::vector<uint8_t> msg(1024, 0xBC);
    write_tmp("tc07_msg.bin", msg);
    ecdsa_sign(ECCurve::P384, tmp("tc07_priv.pem"), tmp("tc07_msg.bin"),
               tmp("tc07_sig.bin"), "sha384", SigEncoding::DER);
    bool ok = ecdsa_verify(ECCurve::P384, tmp("tc07_pub.pem"),
                           tmp("tc07_msg.bin"), tmp("tc07_sig.bin"),
                           "sha384", SigEncoding::DER);
    cleanup_tmp({"tc07_pub.pem","tc07_priv.pem","tc07_msg.bin","tc07_sig.bin"});
    return ok;
}

static bool tc08_rsa_pss_valid() {
    rsa_pss_keygen(3072, tmp("tc08_pub.pem"), tmp("tc08_priv.pem"));
    std::vector<uint8_t> msg(1024, 0xCD);
    write_tmp("tc08_msg.bin", msg);
    rsa_pss_sign(tmp("tc08_priv.pem"), tmp("tc08_msg.bin"),
                 tmp("tc08_sig.bin"), "sha256", -1, SigEncoding::RAW);
    bool ok = rsa_pss_verify(tmp("tc08_pub.pem"), tmp("tc08_msg.bin"),
                              tmp("tc08_sig.bin"), "sha256", -1, SigEncoding::RAW);
    cleanup_tmp({"tc08_pub.pem","tc08_priv.pem","tc08_msg.bin","tc08_sig.bin"});
    return ok;
}

static bool tc09_rsa_pss_modified_message() {
    rsa_pss_keygen(3072, tmp("tc09_pub.pem"), tmp("tc09_priv.pem"));
    std::vector<uint8_t> msg(512, 0xDE);
    write_tmp("tc09_msg.bin", msg);
    rsa_pss_sign(tmp("tc09_priv.pem"), tmp("tc09_msg.bin"),
                 tmp("tc09_sig.bin"), "sha256", -1, SigEncoding::RAW);
    msg[20] ^= 0xFF;
    write_tmp("tc09_msg_bad.bin", msg);
    bool fails = expect_fail([&]{
        return rsa_pss_verify(tmp("tc09_pub.pem"), tmp("tc09_msg_bad.bin"),
                               tmp("tc09_sig.bin"), "sha256", -1, SigEncoding::RAW);
    });
    cleanup_tmp({"tc09_pub.pem","tc09_priv.pem","tc09_msg.bin",
                 "tc09_msg_bad.bin","tc09_sig.bin"});
    return fails;
}

static bool tc10_rsa_pss_modified_signature() {
    rsa_pss_keygen(3072, tmp("tc10_pub.pem"), tmp("tc10_priv.pem"));
    std::vector<uint8_t> msg(256, 0xEF);
    write_tmp("tc10_msg.bin", msg);
    rsa_pss_sign(tmp("tc10_priv.pem"), tmp("tc10_msg.bin"),
                 tmp("tc10_sig.bin"), "sha256", -1, SigEncoding::RAW);
    std::vector<uint8_t> sig = read_file(tmp("tc10_sig.bin"));
    if (sig.size() > 10) sig[10] ^= 0x01;
    write_tmp("tc10_sig_bad.bin", sig);
    bool fails = expect_fail([&]{
        return rsa_pss_verify(tmp("tc10_pub.pem"), tmp("tc10_msg.bin"),
                               tmp("tc10_sig_bad.bin"), "sha256", -1, SigEncoding::RAW);
    });
    cleanup_tmp({"tc10_pub.pem","tc10_priv.pem","tc10_msg.bin",
                 "tc10_sig.bin","tc10_sig_bad.bin"});
    return fails;
}

static bool tc11_rsa_pss_wrong_pubkey() {
    rsa_pss_keygen(3072, tmp("tc11a_pub.pem"), tmp("tc11a_priv.pem"));
    rsa_pss_keygen(3072, tmp("tc11b_pub.pem"), tmp("tc11b_priv.pem"));
    std::vector<uint8_t> msg(256, 0xF0);
    write_tmp("tc11_msg.bin", msg);
    rsa_pss_sign(tmp("tc11a_priv.pem"), tmp("tc11_msg.bin"),
                 tmp("tc11_sig.bin"), "sha256", -1, SigEncoding::RAW);
    bool fails = expect_fail([&]{
        return rsa_pss_verify(tmp("tc11b_pub.pem"), tmp("tc11_msg.bin"),
                               tmp("tc11_sig.bin"), "sha256", -1, SigEncoding::RAW);
    });
    cleanup_tmp({"tc11a_pub.pem","tc11a_priv.pem","tc11b_pub.pem","tc11b_priv.pem",
                 "tc11_msg.bin","tc11_sig.bin"});
    return fails;
}

static bool tc12_rsa_pss_base64_roundtrip() {
    rsa_pss_keygen(3072, tmp("tc12_pub.pem"), tmp("tc12_priv.pem"));
    std::vector<uint8_t> msg(512, 0x42);
    write_tmp("tc12_msg.bin", msg);
    rsa_pss_sign(tmp("tc12_priv.pem"), tmp("tc12_msg.bin"),
                 tmp("tc12_sig.b64"), "sha256", -1, SigEncoding::BASE64);
    bool ok = rsa_pss_verify(tmp("tc12_pub.pem"), tmp("tc12_msg.bin"),
                              tmp("tc12_sig.b64"), "sha256", -1, SigEncoding::BASE64);
    cleanup_tmp({"tc12_pub.pem","tc12_priv.pem","tc12_msg.bin","tc12_sig.b64"});
    return ok;
}

static bool tc13_ecdsa_base64_roundtrip() {
    ecdsa_keygen(ECCurve::P256, tmp("tc13_pub.pem"), tmp("tc13_priv.pem"));
    std::vector<uint8_t> msg(256, 0x33);
    write_tmp("tc13_msg.bin", msg);
    ecdsa_sign(ECCurve::P256, tmp("tc13_priv.pem"), tmp("tc13_msg.bin"),
               tmp("tc13_sig.b64"), "sha256", SigEncoding::BASE64);
    bool ok = ecdsa_verify(ECCurve::P256, tmp("tc13_pub.pem"),
                           tmp("tc13_msg.bin"), tmp("tc13_sig.b64"),
                           "sha256", SigEncoding::BASE64);
    cleanup_tmp({"tc13_pub.pem","tc13_priv.pem","tc13_msg.bin","tc13_sig.b64"});
    return ok;
}

static bool tc14_wrong_curve_on_key() {
    // Generate P256 key, try to use it as P384
    ecdsa_keygen(ECCurve::P256, tmp("tc14_pub.pem"), tmp("tc14_priv.pem"));
    std::vector<uint8_t> msg(256, 0x11);
    write_tmp("tc14_msg.bin", msg);
    bool fails = expect_fail([&]{
        return ecdsa_sign(ECCurve::P384,     // WRONG curve
                          tmp("tc14_priv.pem"),
                          tmp("tc14_msg.bin"),
                          tmp("tc14_sig.bin"),
                          "sha384", SigEncoding::DER);
    });
    cleanup_tmp({"tc14_pub.pem","tc14_priv.pem","tc14_msg.bin","tc14_sig.bin"});
    return fails;
}

static bool tc15_batch_verify() {
    const int N = 5;
    ecdsa_keygen(ECCurve::P256, tmp("tc15_pub.pem"), tmp("tc15_priv.pem"));
    int ok_count = 0;
    for (int i = 0; i < N; ++i) {
        std::vector<uint8_t> msg(256 + i * 64, static_cast<uint8_t>(i));
        std::string msg_f = tmp("tc15_msg_" + std::to_string(i) + ".bin");
        std::string sig_f = tmp("tc15_sig_" + std::to_string(i) + ".bin");
        write_file(msg_f, msg);
        ecdsa_sign(ECCurve::P256, tmp("tc15_priv.pem"), msg_f, sig_f,
                   "sha256", SigEncoding::DER);
        if (ecdsa_verify(ECCurve::P256, tmp("tc15_pub.pem"), msg_f, sig_f,
                         "sha256", SigEncoding::DER))
            ok_count++;
        fs::remove(msg_f);
        fs::remove(sig_f);
    }
    cleanup_tmp({"tc15_pub.pem","tc15_priv.pem"});
    std::cout << "    Batch verified " << ok_count << "/" << N << " signatures\n";
    return ok_count == N;
}

// ── Main runner ───────────────────────────────────────────────

int run_all_tests() {
    std::cout << "\n";
    std::cout << "══════════════════════════════════════════════════\n";
    std::cout << "  sigtool — Automated Test Suite\n";
    std::cout << "══════════════════════════════════════════════════\n\n";

    std::cout << "── ECDSA Tests ─────────────────────────────────\n";
    run_test("TC01: ECDSA-P256 valid sign/verify",       tc01_ecdsa_p256_valid);
    run_test("TC02: ECDSA-P256 modified message → fail", tc02_ecdsa_p256_modified_message);
    run_test("TC03: ECDSA-P256 modified sig → fail",     tc03_ecdsa_p256_modified_signature);
    run_test("TC04: ECDSA-P256 wrong pubkey → fail",     tc04_ecdsa_p256_wrong_pubkey);
    run_test("TC05: ECDSA-P256 wrong hash → fail",       tc05_ecdsa_wrong_hash);
    run_test("TC06: ECDSA-P256 malformed sig → fail",    tc06_ecdsa_malformed_signature);
    run_test("TC07: ECDSA-P384 valid sign/verify",       tc07_ecdsa_p384_valid);
    run_test("TC13: ECDSA-P256 base64 round-trip",       tc13_ecdsa_base64_roundtrip);
    run_test("TC14: Wrong curve on key → fail",          tc14_wrong_curve_on_key);
    run_test("TC15: ECDSA batch verify (N=5)",           tc15_batch_verify);

    std::cout << "\n── RSA-PSS Tests ───────────────────────────────\n";
    std::cout << "  (RSA-3072 keygen is slow — please wait...)\n";
    run_test("TC08: RSA-PSS valid sign/verify",          tc08_rsa_pss_valid);
    run_test("TC09: RSA-PSS modified message → fail",    tc09_rsa_pss_modified_message);
    run_test("TC10: RSA-PSS modified sig → fail",        tc10_rsa_pss_modified_signature);
    run_test("TC11: RSA-PSS wrong pubkey → fail",        tc11_rsa_pss_wrong_pubkey);
    run_test("TC12: RSA-PSS base64 round-trip",          tc12_rsa_pss_base64_roundtrip);

    // Summary
    int passed = 0, failed = 0;
    for (auto& r : g_results) {
        if (r.passed) passed++; else failed++;
    }

    std::cout << "\n══════════════════════════════════════════════════\n";
    std::cout << "  Results: " << passed << " passed, " << failed << " failed";
    if (failed == 0)
        std::cout << "  ✓ ALL TESTS PASSED\n";
    else {
        std::cout << "\n  FAILED TESTS:\n";
        for (auto& r : g_results)
            if (!r.passed)
                std::cout << "    ✗ " << r.name << " — " << r.message << "\n";
    }
    std::cout << "══════════════════════════════════════════════════\n\n";
    return failed;
}
