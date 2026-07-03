/*
 * benchmark.cpp — Lab 04 Task 6
 * Performance Evaluation of Hash Functions
 *
 * Benchmarks SHA-256, SHA-512, SHA3-256, SHA3-512
 * on 1 MiB, 100 MiB data blocks.
 * Measures throughput (MB/s) and reports results in a table.
 *
 * Two modes:
 *   Streaming: reads data in 64 KiB chunks (simulates large file I/O)
 *   In-memory: hashes a pre-allocated buffer (memory-mapped equivalent)
 *
 * Also discusses SHA-2 vs SHA-3 performance differences.
 */

#include <openssl/evp.h>
#include <openssl/err.h>

#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <map>
#include <chrono>
#include <numeric>
#include <sstream>
#include <cstring>
#include <algorithm>
#include <stdexcept>

// ─── Constants ────────────────────────────────────────────────────────────────
static constexpr size_t KiB = 1024;
static constexpr size_t MiB = 1024 * KiB;

static const std::vector<std::pair<std::string, size_t>> FILE_SIZES = {
    {"1 MiB",   1   * MiB},
    {"100 MiB", 100 * MiB},
};

static const std::vector<std::pair<std::string, const char*>> ALGORITHMS = {
    {"SHA-256",   "SHA2-256"},
    {"SHA-512",   "SHA2-512"},
    {"SHA3-256",  "SHA3-256"},
    {"SHA3-512",  "SHA3-512"},
};

// ─── Timer ───────────────────────────────────────────────────────────────────
using Clock = std::chrono::high_resolution_clock;
using Ms    = std::chrono::duration<double, std::milli>;

// ─── Hash a buffer in memory (in-memory mode) ────────────────────────────────
static double bench_memory(const char* algo_name,
                            const unsigned char* data,
                            size_t data_len,
                            int iterations = 3) {
    const EVP_MD* md = EVP_MD_fetch(nullptr, algo_name, nullptr);
    if (!md) {
        std::cerr << "  Cannot fetch: " << algo_name << "\n";
        return 0.0;
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    unsigned char digest[64];
    unsigned int dlen = 0;

    double total_ms = 0.0;
    for (int iter = 0; iter < iterations; ++iter) {
        auto t0 = Clock::now();
        EVP_DigestInit_ex(ctx, md, nullptr);
        EVP_DigestUpdate(ctx, data, data_len);
        EVP_DigestFinal_ex(ctx, digest, &dlen);
        auto t1 = Clock::now();
        total_ms += Ms(t1 - t0).count();
    }

    EVP_MD_CTX_free(ctx);
    EVP_MD_free((EVP_MD*)md);

    double avg_ms = total_ms / iterations;
    double mb = data_len / (double)MiB;
    return mb / (avg_ms / 1000.0); // MB/s
}

// ─── Hash via streaming (64 KiB chunks) ──────────────────────────────────────
static double bench_streaming(const char* algo_name,
                               const unsigned char* data,
                               size_t data_len,
                               int iterations = 3) {
    const EVP_MD* md = EVP_MD_fetch(nullptr, algo_name, nullptr);
    if (!md) return 0.0;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    unsigned char digest[64];
    unsigned int dlen = 0;
    const size_t CHUNK = 64 * KiB;

    double total_ms = 0.0;
    for (int iter = 0; iter < iterations; ++iter) {
        auto t0 = Clock::now();
        EVP_DigestInit_ex(ctx, md, nullptr);
        size_t offset = 0;
        while (offset < data_len) {
            size_t n = std::min(CHUNK, data_len - offset);
            EVP_DigestUpdate(ctx, data + offset, n);
            offset += n;
        }
        EVP_DigestFinal_ex(ctx, digest, &dlen);
        auto t1 = Clock::now();
        total_ms += Ms(t1 - t0).count();
    }

    EVP_MD_CTX_free(ctx);
    EVP_MD_free((EVP_MD*)md);

    double avg_ms = total_ms / iterations;
    double mb = data_len / (double)MiB;
    return mb / (avg_ms / 1000.0);
}

// ─── ASCII bar chart ─────────────────────────────────────────────────────────
static void print_bar(double value, double max_value, int bar_width = 40) {
    int filled = (int)(value / max_value * bar_width);
    std::cout << "  [";
    for (int i = 0; i < bar_width; ++i)
        std::cout << (i < filled ? '=' : '.');
    std::cout << "] " << std::fixed << std::setprecision(1) << value << " MB/s\n";
}

// ─── Generate pseudo-random test data ────────────────────────────────────────
static std::vector<unsigned char> generate_data(size_t len) {
    std::vector<unsigned char> data(len);
    // Simple LCG PRNG for reproducible "random" data
    uint64_t state = 0xDEADBEEFCAFEBABEULL;
    for (size_t i = 0; i < len; ++i) {
        state = state * 6364136223846793005ULL + 1442695040888963407ULL;
        data[i] = (unsigned char)(state >> 56);
    }
    return data;
}

// ─── Results table ────────────────────────────────────────────────────────────
struct BenchResult {
    std::string algo;
    std::string size_label;
    double      mem_mbps;
    double      stream_mbps;
};

// ─── Main ─────────────────────────────────────────────────────────────────────
int main() {
    std::cout << "\n╔══════════════════════════════════════════════════════════════╗\n";
    std::cout << "║     Performance Benchmark — Lab 04 Task 6                    ║\n";
    std::cout << "║     SHA-256, SHA-512, SHA3-256, SHA3-512                     ║\n";
    std::cout << "╚══════════════════════════════════════════════════════════════╝\n\n";
    std::cout << "  Platform: Windows x64\n";
    std::cout << "  OpenSSL: " << OPENSSL_VERSION_TEXT << "\n";
    std::cout << "  Compiler: GCC " << __VERSION__ << "\n";
    std::cout << "  Iterations per test: 3 (averaged)\n\n";

    std::vector<BenchResult> results;

    for (const auto& sz : FILE_SIZES) {
        std::cout << "─── Generating " << sz.first << " test data... ";
        std::cout.flush();
        auto data = generate_data(sz.second);
        std::cout << "done ─────────────────────────────────────────\n\n";

        for (const auto& algo : ALGORITHMS) {
            std::cout << "  Testing " << std::left << std::setw(10) << algo.first
                      << " on " << sz.first << "...\n";

            double mem    = bench_memory(algo.second, data.data(), data.size());
            double stream = bench_streaming(algo.second, data.data(), data.size());

            results.push_back({algo.first, sz.first, mem, stream});

            std::cout << "    In-memory:  " << std::fixed << std::setprecision(2)
                      << std::setw(8) << mem << " MB/s\n";
            std::cout << "    Streaming:  " << std::fixed << std::setprecision(2)
                      << std::setw(8) << stream << " MB/s\n\n";
        }
    }

    // ─── Summary Table ────────────────────────────────────────────────────────
    std::cout << "\n╔══════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                    BENCHMARK RESULTS TABLE                  ║\n";
    std::cout << "╚══════════════════════════════════════════════════════════════╝\n\n";

    std::cout << std::left
              << std::setw(12) << "Algorithm"
              << std::setw(12) << "Data Size"
              << std::setw(18) << "In-Memory (MB/s)"
              << std::setw(18) << "Streaming (MB/s)"
              << "\n";
    std::cout << std::string(60, '-') << "\n";

    for (const auto& r : results) {
        std::cout << std::left
                  << std::setw(12) << r.algo
                  << std::setw(12) << r.size_label
                  << std::setw(18) << std::fixed << std::setprecision(2) << r.mem_mbps
                  << std::setw(18) << std::fixed << std::setprecision(2) << r.stream_mbps
                  << "\n";
    }

    // ─── ASCII bar chart for 100 MiB, in-memory ───────────────────────────────
    std::cout << "\n╔══ Performance Chart: 100 MiB, In-Memory ════════════════════╗\n\n";

    double max_mbps = 0.0;
    for (const auto& r : results)
        if (r.size_label == "100 MiB")
            max_mbps = std::max(max_mbps, r.mem_mbps);

    for (const auto& r : results) {
        if (r.size_label != "100 MiB") continue;
        std::cout << "  " << std::left << std::setw(10) << r.algo;
        print_bar(r.mem_mbps, max_mbps);
    }

    // ─── Analysis Discussion ──────────────────────────────────────────────────
    std::cout << R"(
╔══════════════════════════════════════════════════════════════════╗
║  Performance Analysis                                            ║
╚══════════════════════════════════════════════════════════════════╝

SHA-2 vs SHA-3 PERFORMANCE:
────────────────────────────
SHA-256 and SHA-512 are typically faster on modern x86-64 CPUs because:

1. Hardware acceleration: Intel SHA extensions (SHA-NI, since ~2016)
   directly accelerate SHA-256 and SHA-1 using dedicated opcodes.
   SHA-NI provides ~4x speedup over pure software SHA-256.

2. Word size optimization:
   • SHA-256 uses 32-bit operations → efficient on all CPUs
   • SHA-512 uses 64-bit operations → faster than SHA-256 on 64-bit CPUs
     due to wider registers (fewer rounds relative to output size)

3. SHA-3 (Keccak sponge) uses a 5×5×64-bit state matrix (1600 bits).
   Operations include XOR, AND, NOT, rotations over 64-bit lanes.
   No dedicated hardware acceleration exists yet in most CPUs.
   Performance gap: SHA-256 typically 2-4x faster than SHA3-256.

STREAMING vs MEMORY-MAPPED I/O:
────────────────────────────────
• In-memory: All data in L2/L3 cache → minimal memory latency
  Highest achievable throughput for pure computation
• Streaming (64 KiB chunks): Simulates disk I/O with buffering
  For very large files, throughput is limited by disk bandwidth
  (~500 MB/s SSD, ~3000 MB/s NVMe), not the hash function itself

Observation: For most hash functions on modern hardware:
  Computation throughput >> typical disk read speeds
  So streaming is disk-bound, not CPU-bound for large files.

CPU UTILIZATION:
────────────────
Single-threaded: All benchmark runs use 1 CPU core.
SHA-256 with SHA-NI: ~100% single-core utilization during computation
SHA-3: Also ~100% single-core, but lower absolute throughput

CACHE EFFECTS:
────────────────
• 1 MiB: Fits in L2 cache (typically 256 KiB - 4 MiB)
  → Very cache-friendly, minimal DRAM accesses
• 100 MiB: Exceeds L3 cache (typically 8-32 MiB)
  → Causes cache thrashing, lower throughput than 1 MiB
  This explains why 100 MiB throughput may be lower than 1 MiB

Note: 1 GiB benchmark was omitted (requires ~1 GiB RAM allocation)
but can be enabled by adding {"1 GiB", 1024 * MiB} to FILE_SIZES.

RECOMMENDATION:
────────────────
• SHA-256: Best for high-throughput applications with SHA-NI hardware
• SHA-512: Better than SHA-256 on 64-bit without SHA-NI
• SHA3-256: Preferred for new applications (sponge, no length extension)
• SHA3-512: Maximum security, acceptable performance
• SHAKE256: For variable-length output (KDF, PRF use cases)
)";

    return 0;
}
