#include "benchmark.h"
#include "key_mgmt.h"
#include "rsa_oaep.h"
#include "hybrid.h"
#include "aes_gcm.h"
#include "utils.h"
#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <numeric>
#include <algorithm>

static void print_separator(const std::string& title) {
    std::cout << "\n" << std::string(60, '=') << "\n";
    std::cout << "  " << title << "\n";
    std::cout << std::string(60, '=') << "\n";
}

static void print_row(const std::string& label, double ms, const std::string& unit = "ms") {
    std::cout << std::left << std::setw(38) << label
              << std::right << std::setw(10) << std::fixed << std::setprecision(3)
              << ms << " " << unit << "\n";
}

static double bench_keygen(int bits, int reps = 3) {
    std::vector<double> times;
    for (int i = 0; i < reps; i++) {
        double t0 = now_ms();
        auto kp = keygen(bits);
        double t1 = now_ms();
        times.push_back(t1 - t0);
        (void)kp;
    }
    return std::accumulate(times.begin(), times.end(), 0.0) / reps;
}

static double bench_rsa_encrypt(EVP_PKEY* pub, const std::vector<unsigned char>& msg, int reps = 20) {
    std::vector<double> times;
    for (int i = 0; i < reps; i++) {
        double t0 = now_ms();
        auto ct = rsa_oaep_encrypt(pub, msg);
        double t1 = now_ms();
        times.push_back(t1 - t0);
        (void)ct;
    }
    return std::accumulate(times.begin(), times.end(), 0.0) / reps;
}

static double bench_rsa_decrypt(EVP_PKEY* priv, const std::vector<unsigned char>& ct, int reps = 20) {
    std::vector<double> times;
    for (int i = 0; i < reps; i++) {
        double t0 = now_ms();
        auto pt = rsa_oaep_decrypt(priv, ct);
        double t1 = now_ms();
        times.push_back(t1 - t0);
        (void)pt;
    }
    return std::accumulate(times.begin(), times.end(), 0.0) / reps;
}

void run_benchmark(int bits_3072, int bits_4096) {
    print_separator("RSA Key Generation Benchmark");
    std::cout << std::left << std::setw(38) << "Key Size"
              << std::right << std::setw(10) << "Avg Time" << " (3 runs each)\n";
    std::cout << std::string(60, '-') << "\n";

    double kg3072 = bench_keygen(bits_3072, 3);
    print_row("RSA-3072 keygen", kg3072);
    double kg4096 = bench_keygen(bits_4096, 3);
    print_row("RSA-4096 keygen", kg4096);
    std::cout << "  → 4096 is " << std::fixed << std::setprecision(2)
              << (kg4096 / kg3072) << "x slower than 3072\n";

    print_separator("RSA-OAEP Encrypt/Decrypt Benchmark");
    std::cout << std::left << std::setw(38) << "Operation"
              << std::right << std::setw(10) << "Avg (ms)" << " (20 runs)\n";
    std::cout << std::string(60, '-') << "\n";

    // Test message: 64 bytes (small, fits RSA-OAEP)
    std::vector<unsigned char> msg = random_bytes(64);

    // 3072
    {
        auto kp = keygen(bits_3072);
        auto ct = rsa_oaep_encrypt(kp.pkey, msg);
        double enc3 = bench_rsa_encrypt(kp.pkey, msg, 20);
        double dec3 = bench_rsa_decrypt(kp.pkey, ct, 20);
        print_row("RSA-3072 encrypt", enc3);
        print_row("RSA-3072 decrypt", dec3);
        std::cout << "  → RSA-3072 decrypt/encrypt ratio: "
                  << std::fixed << std::setprecision(2)
                  << (dec3 / enc3) << "x (decrypt is slower - CRT)\n";
    }

    // 4096
    {
        auto kp = keygen(bits_4096);
        auto ct = rsa_oaep_encrypt(kp.pkey, msg);
        double enc4 = bench_rsa_encrypt(kp.pkey, msg, 20);
        double dec4 = bench_rsa_decrypt(kp.pkey, ct, 20);
        print_row("RSA-4096 encrypt", enc4);
        print_row("RSA-4096 decrypt", dec4);
    }
}

void run_hybrid_benchmark() {
    print_separator("Hybrid Encryption Benchmark (RSA-3072 + AES-256-GCM)");

    auto kp = keygen(3072);
    EVP_PKEY* pub  = kp.pkey;
    EVP_PKEY* priv = kp.pkey;

    // Payload sizes: 1 KiB, 1 MiB, 100 MiB
    struct TestCase { const char* name; size_t size; int reps; };
    std::vector<TestCase> cases = {
        {"1 KiB    (1,024 bytes)",        1024ULL,               50},
        {"1 MiB    (1,048,576 bytes)",    1024ULL*1024,          10},
        {"100 MiB  (104,857,600 bytes)",  100ULL*1024*1024,       3},
    };

    std::cout << std::left << std::setw(36) << "Payload"
              << std::right << std::setw(12) << "Enc (ms)"
              << std::setw(12) << "Dec (ms)"
              << std::setw(16) << "Throughput\n";
    std::cout << std::string(76, '-') << "\n";

    for (auto& tc : cases) {
        std::vector<unsigned char> payload = random_bytes(tc.size);

        // Warm up
        auto env = hybrid_encrypt(pub, payload);
        hybrid_decrypt(priv, env);

        // Encrypt
        std::vector<double> enc_times, dec_times;
        for (int i = 0; i < tc.reps; i++) {
            double t0 = now_ms();
            auto e = hybrid_encrypt(pub, payload);
            double t1 = now_ms();
            enc_times.push_back(t1 - t0);

            double t2 = now_ms();
            hybrid_decrypt(priv, e);
            double t3 = now_ms();
            dec_times.push_back(t3 - t2);
        }

        double avg_enc = std::accumulate(enc_times.begin(), enc_times.end(), 0.0) / tc.reps;
        double avg_dec = std::accumulate(dec_times.begin(), dec_times.end(), 0.0) / tc.reps;
        double throughput_mbps = (tc.size / 1024.0 / 1024.0) / (avg_enc / 1000.0);

        std::cout << std::left << std::setw(36) << tc.name
                  << std::right << std::setw(10) << std::fixed << std::setprecision(2) << avg_enc << "ms"
                  << std::setw(10) << avg_dec << "ms"
                  << std::setw(10) << std::setprecision(1) << throughput_mbps << " MB/s\n";
    }

    std::cout << "\nAnalysis:\n";
    std::cout << "  • AES-GCM dominates throughput for large data\n";
    std::cout << "  • RSA overhead is amortized across payload size\n";
    std::cout << "  • Symmetric crypto is orders of magnitude faster than RSA\n";
    std::cout << "  • Hybrid encryption enables secure large-file encryption\n";
    std::cout << "  • RSA key size has minimal impact on AES throughput\n";
}
