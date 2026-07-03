// ============================================================
//  benchmark.cpp  —  Performance evaluation
//  Lab 05: Classical Digital Signatures
//
//  Measures:
//    - Key generation latency (ms)
//    - Sign latency (ms) per message size
//    - Verify latency (ms) per message size
//    - Throughput (ops/sec)
//  Message sizes: 1 KiB, 16 KiB, 1 MiB, 8 MiB
// ============================================================
#include "benchmark.h"
#include "ecdsa_handler.h"
#include "rsa_pss_handler.h"
#include "utils.h"

#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <filesystem>
#include <cmath>

namespace fs = std::filesystem;

static const std::vector<size_t> MSG_SIZES = {
    1024,           // 1 KiB
    16 * 1024,      // 16 KiB
    1024 * 1024,    // 1 MiB
    8 * 1024 * 1024 // 8 MiB
};

static std::string size_label(size_t sz) {
    if (sz < 1024)       return std::to_string(sz) + " B";
    if (sz < 1024*1024)  return std::to_string(sz/1024) + " KiB";
    return std::to_string(sz/(1024*1024)) + " MiB";
}

static std::string tmp_b(const std::string& n) {
    return (fs::temp_directory_path() / ("bench_" + n)).string();
}

// ── Print header row ──────────────────────────────────────────

static void print_header() {
    std::cout << std::left
              << std::setw(14) << "Algo"
              << std::setw(10) << "Msg Size"
              << std::setw(14) << "Sign (ms)"
              << std::setw(16) << "Verify (ms)"
              << std::setw(16) << "Sign ops/s"
              << std::setw(16) << "Verify ops/s"
              << "\n";
    std::cout << std::string(86, '-') << "\n";
}

static void print_row(const std::string& algo,
                      const std::string& msg_label,
                      double sign_ms,
                      double verify_ms) {
    double sign_ops  = (sign_ms  > 0) ? 1000.0 / sign_ms  : 0;
    double verify_ops = (verify_ms > 0) ? 1000.0 / verify_ms : 0;
    std::cout << std::left
              << std::setw(14) << algo
              << std::setw(10) << msg_label
              << std::fixed << std::setprecision(3)
              << std::setw(14) << sign_ms
              << std::setw(16) << verify_ms
              << std::setprecision(1)
              << std::setw(16) << sign_ops
              << std::setw(16) << verify_ops
              << "\n";
}

// ── ECDSA Benchmark ───────────────────────────────────────────

static void bench_ecdsa(ECCurve curve,
                         const std::string& algo_label,
                         const std::string& hash) {
    g_quiet = true;  // suppress per-op verbose output
    // Keygen timing
    Timer t;
    t.start();
    ecdsa_keygen(curve, tmp_b("pub.pem"), tmp_b("priv.pem"), KeyFormat::PEM);
    double keygen_ms = t.elapsed_ms();
    std::cout << "  Keygen (" << algo_label << "): " << std::fixed
              << std::setprecision(2) << keygen_ms << " ms\n";

    for (size_t sz : MSG_SIZES) {
        std::string lbl  = size_label(sz);
        std::string mf   = tmp_b("msg_" + lbl + ".bin");
        std::string sf   = tmp_b("sig_" + lbl + ".bin");

        // Generate random message
        std::vector<uint8_t> msg = random_bytes(sz);
        write_file(mf, msg);

        // Warm-up run
        ecdsa_sign(curve, tmp_b("priv.pem"), mf, sf, hash, SigEncoding::DER);

        // Sign timing (average of 3 runs)
        const int REPS = 3;
        double sign_total = 0, verify_total = 0;
        for (int i = 0; i < REPS; ++i) {
            t.start();
            ecdsa_sign(curve, tmp_b("priv.pem"), mf, sf, hash, SigEncoding::DER);
            sign_total += t.elapsed_ms();

            t.start();
            ecdsa_verify(curve, tmp_b("pub.pem"), mf, sf, hash, SigEncoding::DER);
            verify_total += t.elapsed_ms();
        }

        print_row(algo_label, lbl,
                  sign_total / REPS, verify_total / REPS);

        fs::remove(mf);
        fs::remove(sf);
    }
    fs::remove(tmp_b("pub.pem"));
    fs::remove(tmp_b("priv.pem"));
}

// ── RSA-PSS Benchmark ─────────────────────────────────────────

static void bench_rsa_pss(const std::string& algo_label) {
    g_quiet = true;  // suppress per-op verbose output
    Timer t;
    t.start();
    rsa_pss_keygen(3072, tmp_b("rsa_pub.pem"), tmp_b("rsa_priv.pem"), KeyFormat::PEM);
    double keygen_ms = t.elapsed_ms();
    std::cout << "  Keygen (" << algo_label << "): " << std::fixed
              << std::setprecision(2) << keygen_ms << " ms\n";

    for (size_t sz : MSG_SIZES) {
        std::string lbl  = size_label(sz);
        std::string mf   = tmp_b("rsa_msg_" + lbl + ".bin");
        std::string sf   = tmp_b("rsa_sig_" + lbl + ".bin");

        std::vector<uint8_t> msg = random_bytes(sz);
        write_file(mf, msg);

        // Warm-up
        rsa_pss_sign(tmp_b("rsa_priv.pem"), mf, sf, "sha256", -1, SigEncoding::RAW);

        const int REPS = 3;
        double sign_total = 0, verify_total = 0;
        for (int i = 0; i < REPS; ++i) {
            t.start();
            rsa_pss_sign(tmp_b("rsa_priv.pem"), mf, sf, "sha256", -1, SigEncoding::RAW);
            sign_total += t.elapsed_ms();

            t.start();
            rsa_pss_verify(tmp_b("rsa_pub.pem"), mf, sf, "sha256", -1, SigEncoding::RAW);
            verify_total += t.elapsed_ms();
        }

        print_row(algo_label, lbl,
                  sign_total / REPS, verify_total / REPS);

        fs::remove(mf);
        fs::remove(sf);
    }
    fs::remove(tmp_b("rsa_pub.pem"));
    fs::remove(tmp_b("rsa_priv.pem"));
}

// ── Bonus: Timing variance measurement ───────────────────────
// (Security Engineering: measure nonce/sign time variance)

static void bench_timing_variance() {
    g_quiet = true;  // suppress per-iteration output
    std::cout << "\n── Bonus: ECDSA Timing Variance Measurement ────\n";
    std::cout << "  (Analyzing timing consistency for side-channel assessment)\n";

    ecdsa_keygen(ECCurve::P256, tmp_b("var_pub.pem"), tmp_b("var_priv.pem"));
    std::vector<uint8_t> msg = random_bytes(256);
    write_file(tmp_b("var_msg.bin"), msg);

    const int N = 20;
    std::vector<double> sign_times, verify_times;

    for (int i = 0; i < N; ++i) {
        Timer t;
        t.start();
        ecdsa_sign(ECCurve::P256, tmp_b("var_priv.pem"), tmp_b("var_msg.bin"),
                   tmp_b("var_sig.bin"), "sha256", SigEncoding::DER);
        sign_times.push_back(t.elapsed_us());

        t.start();
        ecdsa_verify(ECCurve::P256, tmp_b("var_pub.pem"), tmp_b("var_msg.bin"),
                     tmp_b("var_sig.bin"), "sha256", SigEncoding::DER);
        verify_times.push_back(t.elapsed_us());
    }

    // Compute mean and std dev
    auto stats = [](const std::vector<double>& v) -> std::pair<double,double> {
        double sum = 0;
        for (double x : v) sum += x;
        double mean = sum / v.size();
        double var = 0;
        for (double x : v) var += (x - mean) * (x - mean);
        return {mean, std::sqrt(var / v.size())};
    };

    auto [sign_mean, sign_std]   = stats(sign_times);
    auto [verify_mean, verify_std] = stats(verify_times);

    std::cout << std::fixed << std::setprecision(2);
    std::cout << "  ECDSA-P256 Sign   — mean: " << sign_mean   << " µs"
              << ", std_dev: " << sign_std   << " µs"
              << ", CV: " << (100.0*sign_std/sign_mean) << "%\n";
    std::cout << "  ECDSA-P256 Verify — mean: " << verify_mean << " µs"
              << ", std_dev: " << verify_std << " µs"
              << ", CV: " << (100.0*verify_std/verify_mean) << "%\n";
    std::cout << "  Note: OpenSSL uses constant-time Montgomery arithmetic.\n"
              << "        Small timing variance is expected from OS scheduling.\n"
              << "        CV < 10% indicates good timing consistency.\n";

    fs::remove(tmp_b("var_pub.pem"));
    fs::remove(tmp_b("var_priv.pem"));
    fs::remove(tmp_b("var_msg.bin"));
    fs::remove(tmp_b("var_sig.bin"));
}

// ── Signature size comparison ─────────────────────────────────

static void print_sig_sizes() {
    g_quiet = true;
    std::cout << "\n── Signature Size Comparison ───────────────────\n";
    ecdsa_keygen(ECCurve::P256, tmp_b("sz_p256_pub.pem"), tmp_b("sz_p256_priv.pem"));
    ecdsa_keygen(ECCurve::P384, tmp_b("sz_p384_pub.pem"), tmp_b("sz_p384_priv.pem"));
    rsa_pss_keygen(3072, tmp_b("sz_rsa_pub.pem"), tmp_b("sz_rsa_priv.pem"));

    std::vector<uint8_t> msg(256, 0xAB);
    write_file(tmp_b("sz_msg.bin"), msg);

    ecdsa_sign(ECCurve::P256, tmp_b("sz_p256_priv.pem"), tmp_b("sz_msg.bin"),
               tmp_b("sz_p256.sig"), "sha256", SigEncoding::DER);
    ecdsa_sign(ECCurve::P384, tmp_b("sz_p384_priv.pem"), tmp_b("sz_msg.bin"),
               tmp_b("sz_p384.sig"), "sha384", SigEncoding::DER);
    rsa_pss_sign(tmp_b("sz_rsa_priv.pem"), tmp_b("sz_msg.bin"),
                 tmp_b("sz_rsa.sig"), "sha256", -1, SigEncoding::RAW);

    auto p256_sz = read_file(tmp_b("sz_p256.sig")).size();
    auto p384_sz = read_file(tmp_b("sz_p384.sig")).size();
    auto rsa_sz  = read_file(tmp_b("sz_rsa.sig")).size();

    std::cout << "  ECDSA-P256  signature: " << p256_sz << " bytes\n";
    std::cout << "  ECDSA-P384  signature: " << p384_sz << " bytes\n";
    std::cout << "  RSA-PSS-3072 signature: " << rsa_sz << " bytes\n";

    for (const auto& f : {"sz_p256_pub.pem","sz_p256_priv.pem",
                           "sz_p384_pub.pem","sz_p384_priv.pem",
                           "sz_rsa_pub.pem","sz_rsa_priv.pem",
                           "sz_msg.bin","sz_p256.sig","sz_p384.sig","sz_rsa.sig"})
        fs::remove(tmp_b(f));
}

// ── Main entry ────────────────────────────────────────────────

void run_benchmarks() {
    std::cout << "\n";
    std::cout << "══════════════════════════════════════════════════════════════════════════════════════\n";
    std::cout << "  sigtool — Performance Benchmark\n";
    std::cout << "  Signing/Verifying random messages (averaged over 3 runs)\n";
    std::cout << "══════════════════════════════════════════════════════════════════════════════════════\n\n";

    std::cout << "── Key Generation Latency ──────────────────────\n";
    std::cout << "  (RSA-3072 keygen is CPU-intensive, ~1-5 seconds expected)\n\n";

    print_header();

    std::cout << "\n>> ECDSA-P256:\n";
    bench_ecdsa(ECCurve::P256, "ECDSA-P256", "sha256");

    std::cout << "\n>> ECDSA-P384:\n";
    bench_ecdsa(ECCurve::P384, "ECDSA-P384", "sha384");

    std::cout << "\n>> RSA-PSS-3072 (key reused across message sizes):\n";
    bench_rsa_pss("RSA-PSS-3072");

    print_sig_sizes();
    bench_timing_variance();

    std::cout << "\n══════════════════════════════════════════════════════════════════════════════════════\n";
    std::cout << "  Analysis:\n";
    std::cout << "  • Sign/Verify time grows linearly with message size (dominated by hashing)\n";
    std::cout << "  • ECDSA sign is faster than RSA-PSS sign (smaller key arithmetic)\n";
    std::cout << "  • ECDSA verify is faster than RSA-PSS verify for large messages\n";
    std::cout << "  • RSA-PSS signature is ~384 bytes vs ~71-103 bytes for ECDSA\n";
    std::cout << "  • Hash cost dominates for messages ≥ 1 MiB regardless of algorithm\n";
    std::cout << "══════════════════════════════════════════════════════════════════════════════════════\n\n";
}
