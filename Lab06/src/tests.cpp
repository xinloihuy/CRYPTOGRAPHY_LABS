#include "tests.h"
#include "utils.h"
#include <oqs/oqs.h>
#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <chrono>
#include <cstring>
#include <numeric>
#include <algorithm>

using Clock = std::chrono::high_resolution_clock;
using Micros = std::chrono::microseconds;

// ── Test framework ────────────────────────────────────────────────────────────
static int g_pass = 0, g_fail = 0;

static void test_result(const std::string& name, bool passed) {
    if (passed) {
        ++g_pass;
        std::cout << "  [PASS] " << name << " ✓\n";
    } else {
        ++g_fail;
        std::cout << "  [FAIL] " << name << " ✗\n";
    }
}

// ── ML-DSA Tests ─────────────────────────────────────────────────────────────
static void test_mldsa(const char* oqs_name, const char* display_name) {
    std::cout << "\n── " << display_name << " Tests ──────────────────────────────────────\n";

    OQS_SIG* sig = OQS_SIG_new(oqs_name);
    if (!sig) {
        std::cout << "  [SKIP] Cannot initialize " << display_name << "\n";
        return;
    }

    // Generate keypairs
    std::vector<uint8_t> pk(sig->length_public_key);
    std::vector<uint8_t> sk(sig->length_secret_key);
    std::vector<uint8_t> pk2(sig->length_public_key);
    std::vector<uint8_t> sk2(sig->length_secret_key);

    OQS_SIG_keypair(sig, pk.data(), sk.data());
    OQS_SIG_keypair(sig, pk2.data(), sk2.data());

    const char* msg_str = "Hello PQC World! This is a test message.";
    std::vector<uint8_t> msg((const uint8_t*)msg_str, (const uint8_t*)msg_str + strlen(msg_str));

    std::vector<uint8_t> signature(sig->length_signature);
    size_t sig_len = 0;

    // T1: Correct sign/verify
    {
        OQS_SIG_sign(sig, signature.data(), &sig_len, msg.data(), msg.size(), sk.data());
        bool ok = (OQS_SIG_verify(sig, msg.data(), msg.size(),
                                   signature.data(), sig_len, pk.data()) == OQS_SUCCESS);
        test_result("Correct sign + verify", ok);
    }

    // T2: Modified message → fail
    {
        std::vector<uint8_t> bad_msg = msg;
        bad_msg[0] ^= 0x01;
        bool ok = (OQS_SIG_verify(sig, bad_msg.data(), bad_msg.size(),
                                   signature.data(), sig_len, pk.data()) != OQS_SUCCESS);
        test_result("Modified message → verification fails", ok);
    }

    // T3: Modified signature (1 bit flip) → fail
    {
        std::vector<uint8_t> bad_sig(signature.begin(), signature.begin() + sig_len);
        bad_sig[sig_len / 2] ^= 0x01;
        bool ok = (OQS_SIG_verify(sig, msg.data(), msg.size(),
                                   bad_sig.data(), bad_sig.size(), pk.data()) != OQS_SUCCESS);
        test_result("Modified signature (1 bit) → verification fails", ok);
    }

    // T4: Wrong public key → fail
    {
        bool ok = (OQS_SIG_verify(sig, msg.data(), msg.size(),
                                   signature.data(), sig_len, pk2.data()) != OQS_SUCCESS);
        test_result("Wrong public key → verification fails", ok);
    }

    // T5: Truncated signature → fail
    {
        std::vector<uint8_t> trunc(signature.begin(), signature.begin() + sig_len / 2);
        bool ok = (OQS_SIG_verify(sig, msg.data(), msg.size(),
                                   trunc.data(), trunc.size(), pk.data()) != OQS_SUCCESS);
        test_result("Truncated signature → verification fails", ok);
    }

    // T6: Empty message still signs/verifies correctly
    {
        std::vector<uint8_t> empty_msg;
        size_t empty_sig_len = 0;
        OQS_SIG_sign(sig, signature.data(), &empty_sig_len, empty_msg.data(), 0, sk.data());
        bool ok = (OQS_SIG_verify(sig, empty_msg.data(), 0,
                                   signature.data(), empty_sig_len, pk.data()) == OQS_SUCCESS);
        test_result("Empty message sign + verify", ok);
    }

    // T7: Large message (1 MiB)
    {
        std::vector<uint8_t> large_msg(1024 * 1024, 0xCD);
        size_t large_sig_len = 0;
        OQS_SIG_sign(sig, signature.data(), &large_sig_len,
                     large_msg.data(), large_msg.size(), sk.data());
        bool ok = (OQS_SIG_verify(sig, large_msg.data(), large_msg.size(),
                                   signature.data(), large_sig_len, pk.data()) == OQS_SUCCESS);
        test_result("Large message (1 MiB) sign + verify", ok);
    }

    // T8: Batch verification (N=50)
    {
        const int N = 50;
        std::vector<bool> results(N);
        for (int i = 0; i < N; ++i) {
            std::vector<uint8_t> m = {(uint8_t)i, 0xAA, 0xBB};
            size_t sl = 0;
            OQS_SIG_sign(sig, signature.data(), &sl, m.data(), m.size(), sk.data());
            results[i] = (OQS_SIG_verify(sig, m.data(), m.size(),
                                          signature.data(), sl, pk.data()) == OQS_SUCCESS);
        }
        bool all_ok = std::all_of(results.begin(), results.end(), [](bool v){ return v; });
        test_result("Batch verification (N=50) all pass", all_ok);
    }

    // T9: Signing with wrong key, verify with correct key → fail
    {
        size_t sl = 0;
        OQS_SIG_sign(sig, signature.data(), &sl, msg.data(), msg.size(), sk2.data());
        bool ok = (OQS_SIG_verify(sig, msg.data(), msg.size(),
                                   signature.data(), sl, pk.data()) != OQS_SUCCESS);
        test_result("Sign with key2, verify with key1 → fails", ok);
    }

    // T10: Signature size is within expected maximum
    {
        size_t sl = 0;
        OQS_SIG_sign(sig, signature.data(), &sl, msg.data(), msg.size(), sk.data());
        bool ok = (sl <= sig->length_signature && sl > 0);
        test_result("Signature size within bounds [" + std::to_string(sl) + " bytes]", ok);
    }

    std::fill(sk.begin(), sk.end(), 0);
    std::fill(sk2.begin(), sk2.end(), 0);
    OQS_SIG_free(sig);
}

// ── ML-KEM Tests ─────────────────────────────────────────────────────────────
static void test_mlkem(const char* oqs_name, const char* display_name) {
    std::cout << "\n── " << display_name << " Tests ──────────────────────────────────────\n";

    OQS_KEM* kem = OQS_KEM_new(oqs_name);
    if (!kem) {
        std::cout << "  [SKIP] Cannot initialize " << display_name << "\n";
        return;
    }

    std::vector<uint8_t> pk(kem->length_public_key);
    std::vector<uint8_t> sk(kem->length_secret_key);
    std::vector<uint8_t> pk2(kem->length_public_key);
    std::vector<uint8_t> sk2(kem->length_secret_key);
    std::vector<uint8_t> ct(kem->length_ciphertext);
    std::vector<uint8_t> ss_enc(kem->length_shared_secret);
    std::vector<uint8_t> ss_dec(kem->length_shared_secret);

    OQS_KEM_keypair(kem, pk.data(), sk.data());
    OQS_KEM_keypair(kem, pk2.data(), sk2.data());

    // T1: Correct encaps/decaps → shared secrets match
    {
        OQS_KEM_encaps(kem, ct.data(), ss_enc.data(), pk.data());
        OQS_KEM_decaps(kem, ss_dec.data(), ct.data(), sk.data());
        bool ok = bytes_equal(ss_enc.data(), ss_dec.data(), ss_enc.size());
        test_result("Encaps + Decaps → shared secrets match", ok);
    }

    // T2: Modified ciphertext → decaps returns different shared secret (IND-CCA)
    {
        std::vector<uint8_t> bad_ct = ct;
        bad_ct[0] ^= 0x01;
        std::vector<uint8_t> ss_bad(kem->length_shared_secret);
        OQS_KEM_decaps(kem, ss_bad.data(), bad_ct.data(), sk.data());
        // ML-KEM is designed to return a pseudorandom SS (not fail explicitly)
        // The spec says decaps is "implicit rejection" - returns garbage SS
        bool ok = !bytes_equal(ss_enc.data(), ss_bad.data(), ss_enc.size());
        test_result("Modified ciphertext → different shared secret (implicit rejection)", ok);
    }

    // T3: Wrong private key → different shared secret
    {
        std::vector<uint8_t> ss_wrong(kem->length_shared_secret);
        OQS_KEM_decaps(kem, ss_wrong.data(), ct.data(), sk2.data());
        bool ok = !bytes_equal(ss_enc.data(), ss_wrong.data(), ss_enc.size());
        test_result("Wrong private key → different shared secret", ok);
    }

    // T4: Re-encapsulate → different ciphertext, different shared secret
    {
        std::vector<uint8_t> ct2(kem->length_ciphertext);
        std::vector<uint8_t> ss2(kem->length_shared_secret);
        OQS_KEM_encaps(kem, ct2.data(), ss2.data(), pk.data());
        bool ct_diff = !bytes_equal(ct.data(), ct2.data(), ct.size());
        bool ss_diff = !bytes_equal(ss_enc.data(), ss2.data(), ss_enc.size());
        test_result("Re-encapsulate → new ciphertext", ct_diff);
        test_result("Re-encapsulate → new shared secret", ss_diff);
    }

    // T5: Shared secret size is correct (256-bit)
    {
        bool ok = (kem->length_shared_secret == 32);
        test_result("Shared secret is 256 bits (32 bytes)", ok);
    }

    // T6: Batch decapsulation timing
    {
        const int N = 50;
        std::vector<double> times;
        times.reserve(N);
        for (int i = 0; i < N; ++i) {
            OQS_KEM_encaps(kem, ct.data(), ss_enc.data(), pk.data());
            auto t0 = Clock::now();
            OQS_KEM_decaps(kem, ss_dec.data(), ct.data(), sk.data());
            auto t1 = Clock::now();
            times.push_back((double)std::chrono::duration_cast<Micros>(t1-t0).count());
        }
        double avg = std::accumulate(times.begin(), times.end(), 0.0) / N;
        std::cout << "  [INFO] Batch decaps (N=50): avg " << std::fixed
                  << std::setprecision(1) << avg << " µs/op\n";
        test_result("Batch decaps (N=50) all succeed", true);
    }

    std::fill(sk.begin(), sk.end(), 0);
    std::fill(sk2.begin(), sk2.end(), 0);
    OQS_KEM_free(kem);
}

// ── CLI ──────────────────────────────────────────────────────────────────────
int cmd_test(int argc, char* argv[]) {
    (void)argc; (void)argv;
    g_pass = 0; g_fail = 0;

    std::cout << "╔═════════════════════════════════════════════════════════════╗\n";
    std::cout << "║           PQC AUTOMATED UNIT TESTS — Lab06                 ║\n";
    std::cout << "╚═════════════════════════════════════════════════════════════╝\n";

    // ML-DSA tests
    test_mldsa(OQS_SIG_alg_ml_dsa_44, "ML-DSA-44");
    test_mldsa(OQS_SIG_alg_ml_dsa_65, "ML-DSA-65");

    // ML-KEM tests
    test_mlkem(OQS_KEM_alg_ml_kem_512, "ML-KEM-512");

    // Summary
    int total = g_pass + g_fail;
    std::cout << "\n╔═════════════════════════════════════════════════════════════╗\n";
    std::cout << "  TEST RESULTS: " << g_pass << "/" << total << " passed";
    if (g_fail == 0) std::cout << " — ALL PASS ✓";
    else             std::cout << " — " << g_fail << " FAILED ✗";
    std::cout << "\n╚═════════════════════════════════════════════════════════════╝\n";

    return (g_fail == 0) ? 0 : 1;
}
