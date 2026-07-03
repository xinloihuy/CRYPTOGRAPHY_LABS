#include "bench.h"
#include "utils.h"
#include <oqs/oqs.h>
#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <chrono>
#include <cmath>
#include <algorithm>
#include <numeric>
#include <stdexcept>
#include <cstring>

using Clock = std::chrono::high_resolution_clock;
using Micros = std::chrono::microseconds;

// ── Statistics ────────────────────────────────────────────────────────────────
struct Stats {
    double mean_us;
    double median_us;
    double stddev_us;
    double ci95_us;   // ±
    double ops_per_sec;
};

static Stats compute_stats(const std::vector<double>& times_us) {
    size_t n = times_us.size();
    Stats s{};
    if (n == 0) return s;

    // Mean
    double sum = std::accumulate(times_us.begin(), times_us.end(), 0.0);
    s.mean_us = sum / n;

    // Variance / stddev
    double var = 0;
    for (auto t : times_us) var += (t - s.mean_us) * (t - s.mean_us);
    var /= (n > 1 ? n - 1 : 1);
    s.stddev_us = std::sqrt(var);

    // Median
    std::vector<double> sorted = times_us;
    std::sort(sorted.begin(), sorted.end());
    s.median_us = (n % 2 == 0)
        ? (sorted[n/2-1] + sorted[n/2]) / 2.0
        : sorted[n/2];

    // 95% CI = 1.96 * stddev / sqrt(n)
    s.ci95_us = 1.96 * s.stddev_us / std::sqrt((double)n);

    // ops/sec
    s.ops_per_sec = (s.mean_us > 0) ? 1e6 / s.mean_us : 0;

    return s;
}

static void print_stats(const std::string& label, const Stats& s) {
    std::cout << std::fixed << std::setprecision(3);
    std::cout << "  " << std::setw(22) << std::left << label
              << "  mean=" << std::setw(9) << s.mean_us  << " µs"
              << "  median=" << std::setw(9) << s.median_us << " µs"
              << "  σ=" << std::setw(8) << s.stddev_us << " µs"
              << "  ±95%=" << std::setw(7) << s.ci95_us << " µs"
              << "  " << std::setw(9) << std::setprecision(1) << s.ops_per_sec << " ops/s\n";
}

// ── ML-DSA benchmark ─────────────────────────────────────────────────────────
static void bench_mldsa(const char* oqs_name, const char* display_name,
                         int rounds, const std::vector<size_t>& msg_sizes) {
    OQS_SIG* sig = OQS_SIG_new(oqs_name);
    if (!sig) {
        std::cerr << "[ERROR] Cannot init " << display_name << "\n";
        return;
    }

    std::cout << "\n╔══ " << display_name << " ══════════════════════════════════════╗\n";
    std::cout << "  Public key : " << sig->length_public_key  << " bytes\n";
    std::cout << "  Private key: " << sig->length_secret_key  << " bytes\n";
    std::cout << "  Signature  : " << sig->length_signature   << " bytes (max)\n";
    std::cout << "  Rounds     : " << rounds << "\n\n";

    // ── Keygen ────────────────────────────────────────────────────────────────
    std::vector<uint8_t> pk(sig->length_public_key);
    std::vector<uint8_t> sk(sig->length_secret_key);
    {
        // Warm-up
        for (int w = 0; w < 3; ++w) OQS_SIG_keypair(sig, pk.data(), sk.data());

        std::vector<double> times;
        times.reserve(rounds);
        for (int r = 0; r < rounds; ++r) {
            auto t0 = Clock::now();
            OQS_SIG_keypair(sig, pk.data(), sk.data());
            auto t1 = Clock::now();
            times.push_back(
                (double)std::chrono::duration_cast<Micros>(t1 - t0).count());
        }
        print_stats("KeyGen", compute_stats(times));
    }

    // ── Sign / Verify for each message size ──────────────────────────────────
    for (size_t msg_size : msg_sizes) {
        std::vector<uint8_t> msg(msg_size, 0xAB);
        std::vector<uint8_t> signature(sig->length_signature);
        size_t sig_len = 0;

        // Generate one signature for verify timing
        OQS_SIG_sign(sig, signature.data(), &sig_len, msg.data(), msg.size(), sk.data());

        std::string size_label;
        if (msg_size < 1024)           size_label = std::to_string(msg_size) + "B";
        else if (msg_size < 1024*1024) size_label = std::to_string(msg_size/1024) + "KiB";
        else                           size_label = std::to_string(msg_size/(1024*1024)) + "MiB";

        // Sign timing
        {
            std::vector<double> times;
            times.reserve(rounds);
            // fewer rounds for large messages
            int r_count = (msg_size > 1024*1024) ? std::max(30, rounds/10) : rounds;
            for (int r = 0; r < r_count; ++r) {
                auto t0 = Clock::now();
                OQS_SIG_sign(sig, signature.data(), &sig_len,
                             msg.data(), msg.size(), sk.data());
                auto t1 = Clock::now();
                times.push_back(
                    (double)std::chrono::duration_cast<Micros>(t1 - t0).count());
            }
            signature.resize(sig_len);
            print_stats("Sign [" + size_label + "]", compute_stats(times));
        }

        // Verify timing
        {
            std::vector<double> times;
            times.reserve(rounds);
            int r_count = (msg_size > 1024*1024) ? std::max(30, rounds/10) : rounds;
            for (int r = 0; r < r_count; ++r) {
                auto t0 = Clock::now();
                OQS_SIG_verify(sig, msg.data(), msg.size(),
                               signature.data(), sig_len, pk.data());
                auto t1 = Clock::now();
                times.push_back(
                    (double)std::chrono::duration_cast<Micros>(t1 - t0).count());
            }
            print_stats("Verify [" + size_label + "]", compute_stats(times));
        }
    }

    std::fill(sk.begin(), sk.end(), 0);
    OQS_SIG_free(sig);
    std::cout << "╚═══════════════════════════════════════════════════════════╝\n";
}

// ── ML-KEM benchmark ─────────────────────────────────────────────────────────
static void bench_mlkem(const char* oqs_name, const char* display_name, int rounds) {
    OQS_KEM* kem = OQS_KEM_new(oqs_name);
    if (!kem) {
        std::cerr << "[ERROR] Cannot init " << display_name << "\n";
        return;
    }

    std::cout << "\n╔══ " << display_name << " ═══════════════════════════════════════════╗\n";
    std::cout << "  Public key    : " << kem->length_public_key   << " bytes\n";
    std::cout << "  Private key   : " << kem->length_secret_key   << " bytes\n";
    std::cout << "  Ciphertext    : " << kem->length_ciphertext    << " bytes\n";
    std::cout << "  Shared secret : " << kem->length_shared_secret << " bytes\n";
    std::cout << "  Rounds        : " << rounds << "\n\n";

    std::vector<uint8_t> pk(kem->length_public_key);
    std::vector<uint8_t> sk(kem->length_secret_key);
    std::vector<uint8_t> ct(kem->length_ciphertext);
    std::vector<uint8_t> ss_enc(kem->length_shared_secret);
    std::vector<uint8_t> ss_dec(kem->length_shared_secret);

    // Warm-up
    OQS_KEM_keypair(kem, pk.data(), sk.data());

    // KeyGen
    {
        std::vector<double> times;
        times.reserve(rounds);
        for (int r = 0; r < rounds; ++r) {
            auto t0 = Clock::now();
            OQS_KEM_keypair(kem, pk.data(), sk.data());
            auto t1 = Clock::now();
            times.push_back((double)std::chrono::duration_cast<Micros>(t1-t0).count());
        }
        print_stats("KeyGen", compute_stats(times));
    }

    // Generate fresh keypair for encaps/decaps
    OQS_KEM_keypair(kem, pk.data(), sk.data());

    // Encaps
    {
        std::vector<double> times;
        times.reserve(rounds);
        for (int r = 0; r < rounds; ++r) {
            auto t0 = Clock::now();
            OQS_KEM_encaps(kem, ct.data(), ss_enc.data(), pk.data());
            auto t1 = Clock::now();
            times.push_back((double)std::chrono::duration_cast<Micros>(t1-t0).count());
        }
        print_stats("Encaps", compute_stats(times));
    }

    // One encaps for decaps
    OQS_KEM_encaps(kem, ct.data(), ss_enc.data(), pk.data());

    // Decaps
    {
        std::vector<double> times;
        times.reserve(rounds);
        for (int r = 0; r < rounds; ++r) {
            auto t0 = Clock::now();
            OQS_KEM_decaps(kem, ss_dec.data(), ct.data(), sk.data());
            auto t1 = Clock::now();
            times.push_back((double)std::chrono::duration_cast<Micros>(t1-t0).count());
        }
        print_stats("Decaps", compute_stats(times));
    }

    // Verify shared secrets match
    bool match = bytes_equal(ss_enc.data(), ss_dec.data(), ss_enc.size());
    std::cout << "\n  Shared secret match: " << (match ? "YES ✓" : "NO ✗") << "\n";

    // Throughput: shared secrets per second
    std::cout << "  (Shared secret size: " << ss_enc.size() << " bytes = "
              << (ss_enc.size() * 8) << " bits)\n";

    std::fill(sk.begin(), sk.end(), 0);
    OQS_KEM_free(kem);
    std::cout << "╚═══════════════════════════════════════════════════════════════╝\n";
}

// ── CLI ──────────────────────────────────────────────────────────────────────
int cmd_bench(int argc, char* argv[]) {
    std::string algo_str = "all";
    int rounds = 1000;

    for (int i = 0; i < argc - 1; ++i) {
        std::string a = argv[i];
        if      (a == "--algo")   algo_str = argv[++i];
        else if (a == "--rounds") rounds   = std::stoi(argv[++i]);
    }

    // Message sizes: 1KiB, 16KiB, 1MiB, 8MiB
    std::vector<size_t> msg_sizes = {1024, 16*1024, 1*1024*1024, 8*1024*1024};

    std::cout << "╔═════════════════════════════════════════════════════════════╗\n";
    std::cout << "║           PQC PERFORMANCE BENCHMARK — Lab06                ║\n";
    std::cout << "╚═════════════════════════════════════════════════════════════╝\n";
    std::cout << "  Platform : Windows (MSYS2/MinGW64 g++ 16)\n";
    std::cout << "  Rounds   : " << rounds << " per operation\n";
    std::cout << "  Warm-up  : 3 rounds before each measurement\n";
    std::cout << "  Metrics  : mean, median, σ (stddev), ±95% CI, ops/s\n\n";
    std::cout << "  Note: Hash cost is message-size independent for ML-DSA\n";
    std::cout << "        (message is hashed internally by SHAKE-256)\n";

    bool do_dsa44  = (algo_str == "all" || algo_str == "mldsa-44"  || algo_str == "ml-dsa-44");
    bool do_dsa65  = (algo_str == "all" || algo_str == "mldsa-65"  || algo_str == "ml-dsa-65");
    bool do_kem512 = (algo_str == "all" || algo_str == "mlkem-512" || algo_str == "ml-kem-512");

    if (do_dsa44)  bench_mldsa(OQS_SIG_alg_ml_dsa_44, "ML-DSA-44", rounds, msg_sizes);
    if (do_dsa65)  bench_mldsa(OQS_SIG_alg_ml_dsa_65, "ML-DSA-65", rounds, msg_sizes);
    if (do_kem512) bench_mlkem(OQS_KEM_alg_ml_kem_512, "ML-KEM-512", rounds);

    std::cout << "\n=== Benchmark complete ===\n";
    return 0;
}
