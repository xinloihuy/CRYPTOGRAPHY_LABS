#include "tests.h"
#include "key_mgmt.h"
#include "rsa_oaep.h"
#include "hybrid.h"
#include "aes_gcm.h"
#include "oaep_manual.h"
#include "utils.h"
#include <iostream>
#include <vector>
#include <string>
#include <stdexcept>
#include <functional>
#include <iomanip>

static int g_passed = 0;
static int g_failed = 0;

static void run_test(const std::string& name, std::function<void()> fn) {
    try {
        fn();
        std::cout << "  [PASS] " << name << "\n";
        g_passed++;
    } catch (const std::exception& e) {
        std::cout << "  [FAIL] " << name << "\n";
        std::cout << "         Error: " << e.what() << "\n";
        g_failed++;
    }
}

static void run_test_throws(const std::string& name, std::function<void()> fn) {
    bool threw = false;
    std::string what;
    try {
        fn();
    } catch (const std::exception& e) {
        threw = true;
        what = e.what();
    }
    if (threw) {
        std::cout << "  [PASS] " << name << "\n";
        std::cout << "         (Threw: " << what << ")\n";
        g_passed++;
    } else {
        std::cout << "  [FAIL] " << name << " -- expected exception, got none\n";
        g_failed++;
    }
}

static void print_section(const std::string& s) {
    std::cout << "\n[TEST] " << s << "\n" << std::string(50, '-') << "\n";
}

int run_tests() {
    g_passed = 0;
    g_failed = 0;

    std::cout << "\n" << std::string(60, '=') << "\n";
    std::cout << "  RSA-OAEP & Hybrid Encryption -- Automated Test Suite\n";
    std::cout << std::string(60, '=') << "\n";

    // ── Generate test keys ─────────────────────────────────────────────────
    print_section("Setup: Generate RSA-3072 and RSA-4096 key pairs");
    auto kp3072 = keygen(3072);
    auto kp4096 = keygen(4096);
    auto kp_alt = keygen(3072);
    std::cout << "  [INFO] RSA-3072 key generated\n";
    std::cout << "  [INFO] RSA-4096 key generated\n";
    std::cout << "  [INFO] RSA-3072 alternate key generated\n";

    // ── Positive tests: RSA-OAEP ──────────────────────────────────────────
    print_section("1. Correct RSA-OAEP Encrypt/Decrypt (SHA-256)");

    run_test("RSA-3072 encrypt/decrypt roundtrip", [&]() {
        std::vector<unsigned char> msg = {'H','e','l','l','o',' ','C','r','y','p','t','o','!'};
        auto ct = rsa_oaep_encrypt(kp3072.pkey, msg);
        auto pt = rsa_oaep_decrypt(kp3072.pkey, ct);
        if (pt != msg) throw std::runtime_error("Plaintext mismatch");
    });

    run_test("RSA-4096 encrypt/decrypt roundtrip", [&]() {
        std::vector<unsigned char> msg = {'H','e','l','l','o',' ','C','r','y','p','t','o','!'};
        auto ct = rsa_oaep_encrypt(kp4096.pkey, msg);
        auto pt = rsa_oaep_decrypt(kp4096.pkey, ct);
        if (pt != msg) throw std::runtime_error("Plaintext mismatch");
    });

    run_test("RSA-OAEP with optional label", [&]() {
        std::vector<unsigned char> msg = {'L','a','b','e','l','T','e','s','t'};
        std::string label = "test-label-2024";
        auto ct = rsa_oaep_encrypt(kp3072.pkey, msg, label);
        auto pt = rsa_oaep_decrypt(kp3072.pkey, ct, label);
        if (pt != msg) throw std::runtime_error("Plaintext mismatch");
    });

    run_test("Max-size plaintext for RSA-3072 OAEP", [&]() {
        size_t maxLen = rsa_oaep_max_plaintext(kp3072.pkey);
        auto big_msg = random_bytes(maxLen);
        auto ct = rsa_oaep_encrypt(kp3072.pkey, big_msg);
        auto pt = rsa_oaep_decrypt(kp3072.pkey, ct);
        if (pt != big_msg) throw std::runtime_error("Plaintext mismatch");
    });

    // ── Negative tests: RSA-OAEP ──────────────────────────────────────────
    print_section("2. RSA-OAEP Negative Tests");

    run_test_throws("Altered RSA ciphertext => decryption fails", [&]() {
        std::vector<unsigned char> msg = {'T','e','s','t'};
        auto ct = rsa_oaep_encrypt(kp3072.pkey, msg);
        ct[ct.size()/2] ^= 0xFF;
        rsa_oaep_decrypt(kp3072.pkey, ct);
    });

    run_test_throws("Wrong private key => decryption fails", [&]() {
        std::vector<unsigned char> msg = {'T','e','s','t'};
        auto ct = rsa_oaep_encrypt(kp3072.pkey, msg);
        rsa_oaep_decrypt(kp_alt.pkey, ct);
    });

    run_test_throws("Wrong OAEP label => decryption fails", [&]() {
        std::vector<unsigned char> msg = {'T','e','s','t'};
        auto ct = rsa_oaep_encrypt(kp3072.pkey, msg, "correct-label");
        rsa_oaep_decrypt(kp3072.pkey, ct, "wrong-label");
    });

    run_test_throws("Empty ciphertext => decryption fails", [&]() {
        std::vector<unsigned char> empty;
        rsa_oaep_decrypt(kp3072.pkey, empty);
    });

    run_test_throws("Plaintext exceeds RSA-OAEP limit => encrypt fails", [&]() {
        size_t maxLen = rsa_oaep_max_plaintext(kp3072.pkey);
        auto too_big = random_bytes(maxLen + 1);
        rsa_oaep_encrypt(kp3072.pkey, too_big);
    });

    run_test_throws("RSA key < 3072 bits => keygen fails", [&]() {
        keygen(2048);
    });

    // ── Positive tests: Hybrid ────────────────────────────────────────────
    print_section("3. Hybrid Encryption Roundtrip Tests");

    run_test("Hybrid encrypt/decrypt: small message (32 bytes)", [&]() {
        auto msg = random_bytes(32);
        auto env = hybrid_encrypt(kp3072.pkey, msg);
        auto pt  = hybrid_decrypt(kp3072.pkey, env);
        if (pt != msg) throw std::runtime_error("Plaintext mismatch");
    });

    run_test("Hybrid encrypt/decrypt: 1 MiB message", [&]() {
        auto msg = random_bytes(1024*1024);
        auto env = hybrid_encrypt(kp3072.pkey, msg);
        auto pt  = hybrid_decrypt(kp3072.pkey, env);
        if (pt != msg) throw std::runtime_error("Plaintext mismatch");
    });

    run_test("Hybrid encrypt/decrypt with label", [&]() {
        auto msg = random_bytes(1000);
        std::string label = "hybrid-test-label";
        auto env = hybrid_encrypt(kp3072.pkey, msg, label);
        auto pt  = hybrid_decrypt(kp3072.pkey, env, label);
        if (pt != msg) throw std::runtime_error("Plaintext mismatch");
    });

    run_test("Hybrid encrypt/decrypt: empty message", [&]() {
        std::vector<unsigned char> msg;
        auto env = hybrid_encrypt(kp3072.pkey, msg);
        auto pt  = hybrid_decrypt(kp3072.pkey, env);
        if (pt != msg) throw std::runtime_error("Plaintext mismatch");
    });

    // ── Negative tests: Hybrid ────────────────────────────────────────────
    print_section("4. Hybrid Encryption Negative Tests");

    run_test_throws("Altered AES-GCM ciphertext => tag authentication fails", [&]() {
        auto msg = random_bytes(500);
        auto env = hybrid_encrypt(kp3072.pkey, msg);
        if (env.size() > 50) {
            env[env.size() - 1] ^= 0x42;
        }
        hybrid_decrypt(kp3072.pkey, env);
    });

    run_test_throws("Wrong private key in hybrid => RSA unwrap fails", [&]() {
        auto msg = random_bytes(500);
        auto env = hybrid_encrypt(kp3072.pkey, msg);
        hybrid_decrypt(kp_alt.pkey, env);
    });

    run_test_throws("Wrong OAEP label in hybrid => RSA unwrap fails", [&]() {
        auto msg = random_bytes(500);
        auto env = hybrid_encrypt(kp3072.pkey, msg, "label-A");
        hybrid_decrypt(kp3072.pkey, env, "label-B");
    });

    run_test_throws("Tampered envelope header => parse/validation fails", [&]() {
        auto msg = random_bytes(500);
        auto env = hybrid_encrypt(kp3072.pkey, msg);
        // Corrupt JSON in the header area (after 4-byte length prefix)
        if (env.size() > 15) {
            env[10] = 'X';
            env[11] = 'X';
            env[12] = 'X';
        }
        hybrid_decrypt(kp3072.pkey, env);
    });

    run_test_throws("Malformed ciphertext (too short) => fail closed", [&]() {
        std::vector<unsigned char> bad = {0x01, 0x00, 0x00, 0x00};
        hybrid_decrypt(kp3072.pkey, bad);
    });

    run_test_throws("Key size mismatch => fails", [&]() {
        auto msg = random_bytes(500);
        auto env = hybrid_encrypt(kp3072.pkey, msg);
        hybrid_decrypt(kp4096.pkey, env);
    });

    // ── AES-GCM tests ─────────────────────────────────────────────────────
    print_section("5. AES-256-GCM Tests");

    run_test("AES-GCM encrypt/decrypt roundtrip", [&]() {
        auto key = random_bytes(32);
        auto pt  = random_bytes(256);
        auto res = aes_gcm_encrypt(key, pt);
        auto dec = aes_gcm_decrypt(key, res.iv, res.ciphertext, res.tag);
        if (dec != pt) throw std::runtime_error("Plaintext mismatch");
    });

    run_test_throws("AES-GCM tampered ciphertext => auth fails", [&]() {
        auto key = random_bytes(32);
        auto pt  = random_bytes(256);
        auto res = aes_gcm_encrypt(key, pt);
        res.ciphertext[0] ^= 0xFF;
        aes_gcm_decrypt(key, res.iv, res.ciphertext, res.tag);
    });

    run_test_throws("AES-GCM tampered tag => auth fails", [&]() {
        auto key = random_bytes(32);
        auto pt  = random_bytes(256);
        auto res = aes_gcm_encrypt(key, pt);
        res.tag[0] ^= 0xFF;
        aes_gcm_decrypt(key, res.iv, res.ciphertext, res.tag);
    });

    run_test_throws("AES-GCM wrong key => auth fails", [&]() {
        auto key  = random_bytes(32);
        auto key2 = random_bytes(32);
        auto pt   = random_bytes(256);
        auto res  = aes_gcm_encrypt(key, pt);
        aes_gcm_decrypt(key2, res.iv, res.ciphertext, res.tag);
    });

    // ── Manual OAEP tests ─────────────────────────────────────────────────
    print_section("6. Manual OAEP Implementation Tests (Bonus +5)");

    run_test("MGF1-SHA256 output length correct", [&]() {
        auto seed = random_bytes(32);
        auto mask = mgf1_sha256(seed, 100);
        if (mask.size() != 100)
            throw std::runtime_error("MGF1 output length mismatch");
    });

    run_test("Manual OAEP encode/decode roundtrip (no label)", [&]() {
        std::vector<unsigned char> msg = {'M','a','n','u','a','l','O','A','E','P'};
        size_t k = 3072 / 8;
        auto em  = oaep_encode(msg, "", k);
        auto dec = oaep_decode(em, "", k);
        if (dec != msg) throw std::runtime_error("Roundtrip mismatch");
    });

    run_test("Manual OAEP encode/decode with label", [&]() {
        auto msg = random_bytes(50);
        size_t k = 3072 / 8;
        auto em  = oaep_encode(msg, "test-label", k);
        auto dec = oaep_decode(em, "test-label", k);
        if (dec != msg) throw std::runtime_error("Roundtrip mismatch");
    });

    run_test("Manual RSA-OAEP full encrypt/decrypt roundtrip", [&]() {
        std::vector<unsigned char> msg = {'M','a','n','u','a','l',' ','R','S','A'};
        auto ct = manual_oaep_encrypt(kp3072.pkey, msg);
        auto pt = manual_oaep_decrypt(kp3072.pkey, ct);
        if (pt != msg) throw std::runtime_error("Plaintext mismatch");
    });

    run_test_throws("Manual OAEP wrong label => decode fails", [&]() {
        auto msg = random_bytes(20);
        size_t k = 3072 / 8;
        auto em  = oaep_encode(msg, "label-X", k);
        oaep_decode(em, "label-Y", k);
    });

    run_test_throws("Manual OAEP tampered EM => decode fails", [&]() {
        auto msg = random_bytes(20);
        size_t k = 3072 / 8;
        auto em  = oaep_encode(msg, "", k);
        em[50] ^= 0xFF;
        oaep_decode(em, "", k);
    });

    // ── Summary ───────────────────────────────────────────────────────────
    std::cout << "\n" << std::string(60, '=') << "\n";
    std::cout << "  Test Results: "
              << g_passed << " PASSED, "
              << g_failed << " FAILED\n";
    std::cout << std::string(60, '=') << "\n";

    return (g_failed == 0) ? 0 : 1;
}
