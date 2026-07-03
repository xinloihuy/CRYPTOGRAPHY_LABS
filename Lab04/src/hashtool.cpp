/*
 * hashtool.cpp — Lab 04 Task 1+2+6
 * Hash Suite CLI Tool using OpenSSL 4.0.0
 *
 * Supports: SHA-224, SHA-256, SHA-384, SHA-512
 *           SHA3-224, SHA3-256, SHA3-384, SHA3-512
 *           SHAKE128, SHAKE256 (variable output)
 *
 * Usage:
 *   hashtool --algo sha256 --in file.bin
 *   hashtool --algo shake256 --outlen 64 --in file.bin
 *   hashtool --algo sha512 --in large.iso --stream
 *   hashtool --kat
 *   hashtool --algo sha256 --text "Hello World"
 */

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/provider.h>

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <chrono>
#include <iomanip>
#include <cstring>
#include <algorithm>
#include <stdexcept>

// ─── Constants ────────────────────────────────────────────────────────────────
static constexpr size_t CHUNK_SIZE = 64 * 1024; // 64 KiB streaming chunk

// ─── Hex helpers ──────────────────────────────────────────────────────────────
static std::string bytes_to_hex(const unsigned char* buf, size_t len) {
    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i)
        ss << std::setw(2) << (unsigned int)buf[i];
    return ss.str();
}

static std::vector<unsigned char> hex_to_bytes(const std::string& hex) {
    std::vector<unsigned char> bytes;
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        unsigned int b;
        std::istringstream ss(hex.substr(i, 2));
        ss >> std::hex >> b;
        bytes.push_back((unsigned char)b);
    }
    return bytes;
}

// ─── OpenSSL error handling ────────────────────────────────────────────────────
static void throw_openssl_error(const std::string& ctx) {
    char buf[256];
    ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
    throw std::runtime_error(ctx + ": " + buf);
}

// ─── Algorithm info ───────────────────────────────────────────────────────────
struct AlgoInfo {
    const char* openssl_name; // EVP digest name
    size_t      digest_bits;  // 0 = XOF (SHAKE)
    bool        is_xof;
};

static const std::map<std::string, AlgoInfo> ALGO_MAP = {
    // SHA-2
    {"sha224",   {"SHA2-224",  224, false}},
    {"sha256",   {"SHA2-256",  256, false}},
    {"sha384",   {"SHA2-384",  384, false}},
    {"sha512",   {"SHA2-512",  512, false}},
    // SHA-3
    {"sha3-224", {"SHA3-224",  224, false}},
    {"sha3-256", {"SHA3-256",  256, false}},
    {"sha3-384", {"SHA3-384",  384, false}},
    {"sha3-512", {"SHA3-512",  512, false}},
    // SHAKE (XOF)
    {"shake128", {"SHAKE-128", 0,   true}},
    {"shake256", {"SHAKE-256", 0,   true}},
};

// ─── Hash computation ─────────────────────────────────────────────────────────
struct HashResult {
    std::vector<unsigned char> digest;
    double                     elapsed_ms;
    size_t                     bytes_processed;
};

static HashResult hash_stream(const AlgoInfo& algo,
                               std::istream&   in,
                               size_t          outlen_bytes) {
    const EVP_MD* md = EVP_get_digestbyname(algo.openssl_name);
    if (!md) {
        // Try fetching via new-style provider API
        md = EVP_MD_fetch(nullptr, algo.openssl_name, nullptr);
        if (!md) throw_openssl_error("EVP_MD_fetch(" + std::string(algo.openssl_name) + ")");
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) throw_openssl_error("EVP_MD_CTX_new");

    // For XOF we need EVP_DigestInit with xoflen parameter
    if (algo.is_xof) {
        OSSL_PARAM params[2];
        params[0] = OSSL_PARAM_construct_size_t("xoflen", &outlen_bytes);
        params[1] = OSSL_PARAM_construct_end();
        if (!EVP_DigestInit_ex2(ctx, md, params))
            throw_openssl_error("EVP_DigestInit_ex2 (XOF)");
    } else {
        if (!EVP_DigestInit_ex(ctx, md, nullptr))
            throw_openssl_error("EVP_DigestInit_ex");
    }

    auto t0 = std::chrono::high_resolution_clock::now();

    std::vector<char> buf(CHUNK_SIZE);
    size_t total = 0;
    while (in.read(buf.data(), buf.size()) || in.gcount() > 0) {
        size_t n = (size_t)in.gcount();
        if (!EVP_DigestUpdate(ctx, buf.data(), n))
            throw_openssl_error("EVP_DigestUpdate");
        total += n;
    }

    std::vector<unsigned char> digest;
    if (algo.is_xof) {
        digest.resize(outlen_bytes);
        if (!EVP_DigestFinalXOF(ctx, digest.data(), outlen_bytes))
            throw_openssl_error("EVP_DigestFinalXOF");
    } else {
        digest.resize(EVP_MD_size(md));
        unsigned int dlen = 0;
        if (!EVP_DigestFinal_ex(ctx, digest.data(), &dlen))
            throw_openssl_error("EVP_DigestFinal_ex");
        digest.resize(dlen);
    }

    auto t1 = std::chrono::high_resolution_clock::now();
    double elapsed = std::chrono::duration<double, std::milli>(t1 - t0).count();

    EVP_MD_CTX_free(ctx);

    return {digest, elapsed, total};
}

// ─── Known Answer Tests ───────────────────────────────────────────────────────
// NIST test vectors: empty string digests
struct KATEntry {
    std::string algo;
    size_t      outlen; // for XOF
    std::string input;  // hex-encoded input ("" = empty string)
    std::string expected_hex;
};

// NIST FIPS 180/202 vectors for empty ("") input
static const std::vector<KATEntry> KAT_VECTORS = {
    // SHA-2 family (empty string)
    {"sha224",   0,  "",
     "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"},
    {"sha256",   0,  "",
     "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
    {"sha384",   0,  "",
     "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"},
    {"sha512",   0,  "",
     "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"},
    // SHA-3 family (empty string) — NIST FIPS 202
    {"sha3-224", 0,  "",
     "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"},
    {"sha3-256", 0,  "",
     "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"},
    {"sha3-384", 0,  "",
     "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"},
    {"sha3-512", 0,  "",
     "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"},
    // SHAKE with empty input (outlen=32 bytes for shake128, 64 for shake256)
    {"shake128", 32, "",
     "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"},
    {"shake256", 64, "",
     "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be"},
    // SHA-256 of "abc" — NIST FIPS 180-4 vector
    {"sha256",   0,  "616263",
     "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
    // SHA-512 of "abc"
    {"sha512",   0,  "616263",
     "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"},
};

static bool run_kat() {
    std::cout << "\n╔══════════════════════════════════════════════════╗\n";
    std::cout << "║        Known Answer Tests (KAT) — NIST Vectors  ║\n";
    std::cout << "╚══════════════════════════════════════════════════╝\n\n";

    int passed = 0, failed = 0;

    for (const auto& v : KAT_VECTORS) {
        auto it = ALGO_MAP.find(v.algo);
        if (it == ALGO_MAP.end()) {
            std::cerr << "[SKIP] Unknown algo: " << v.algo << "\n";
            continue;
        }
        const AlgoInfo& ai = it->second;

        // Build input bytes from hex
        std::vector<unsigned char> input_bytes;
        if (!v.input.empty()) {
            input_bytes = hex_to_bytes(v.input);
        }

        // Hash it
        std::string label = v.algo;
        if (ai.is_xof) label += "(outlen=" + std::to_string(v.outlen) + ")";

        try {
            std::string input_str(input_bytes.begin(), input_bytes.end());
            std::istringstream ss(input_str);
            size_t outlen = (ai.is_xof) ? v.outlen : (ai.digest_bits / 8);
            HashResult hr = hash_stream(ai, ss, outlen);

            std::string got = bytes_to_hex(hr.digest.data(), hr.digest.size());

            // Compare (case-insensitive)
            std::string exp = v.expected_hex;
            std::transform(got.begin(), got.end(), got.begin(), ::tolower);
            std::transform(exp.begin(), exp.end(), exp.begin(), ::tolower);

            if (got == exp) {
                std::cout << "  [PASS] " << std::left << std::setw(22) << label << "\n";
                ++passed;
            } else {
                std::cout << "  [FAIL] " << label << "\n";
                std::cout << "         Expected: " << exp << "\n";
                std::cout << "         Got:      " << got << "\n";
                ++failed;
            }
        } catch (const std::exception& e) {
            std::cout << "  [ERR]  " << label << " — " << e.what() << "\n";
            ++failed;
        }
    }

    std::cout << "\n  Result: " << passed << " passed, " << failed << " failed\n";
    return (failed == 0);
}

// ─── Help ─────────────────────────────────────────────────────────────────────
static void print_help(const char* prog) {
    std::cout << R"(
┌──────────────────────────────────────────────────────────────┐
│  hashtool — Hash Suite CLI  (Lab 04, Task 1+2+6)             │
│  Using OpenSSL 4.0.0                                         │
└──────────────────────────────────────────────────────────────┘

Usage:
  hashtool --algo <algo> --in <file>  [options]
  hashtool --algo <algo> --text <str> [options]
  hashtool --kat

Algorithms:
  SHA-2:  sha224  sha256  sha384  sha512
  SHA-3:  sha3-224  sha3-256  sha3-384  sha3-512
  XOF:    shake128  shake256  (requires --outlen)

Options:
  --algo   <name>   Hash algorithm (required)
  --in     <file>   Input file
  --text   <str>    Input string (alternative to --in)
  --outlen <n>      Output length in bytes (XOF only, default 32)
  --raw    <file>   Write raw binary digest to file
  --stream          Force streaming mode (auto for large files)
  --kat             Run all Known Answer Tests
  --help            Show this help

Examples:
  hashtool --algo sha256 --in file.bin
  hashtool --algo sha512 --in large.iso --stream
  hashtool --algo shake256 --outlen 64 --in file.bin
  hashtool --algo sha3-256 --text "Hello World"
  hashtool --kat
)";
}

// ─── main ─────────────────────────────────────────────────────────────────────
int main(int argc, char* argv[]) {
    if (argc < 2) { print_help(argv[0]); return 1; }

    // Parse args
    std::string algo_name, in_file, text_input, raw_out;
    size_t outlen = 32;
    bool do_kat = false, do_stream = false;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--kat")    { do_kat = true; }
        else if (a == "--stream") { do_stream = true; }
        else if (a == "--help")   { print_help(argv[0]); return 0; }
        else if (a == "--algo"   && i+1 < argc) { algo_name  = argv[++i]; }
        else if (a == "--in"     && i+1 < argc) { in_file    = argv[++i]; }
        else if (a == "--text"   && i+1 < argc) { text_input = argv[++i]; }
        else if (a == "--raw"    && i+1 < argc) { raw_out    = argv[++i]; }
        else if (a == "--outlen" && i+1 < argc) { outlen     = std::stoull(argv[++i]); }
        else {
            std::cerr << "[!] Unknown argument: " << a << "\n";
            return 1;
        }
    }

    if (do_kat) {
        bool ok = run_kat();
        return ok ? 0 : 1;
    }

    // Validate algorithm
    if (algo_name.empty()) {
        std::cerr << "[!] --algo is required\n"; return 1;
    }
    // Normalize to lowercase
    std::transform(algo_name.begin(), algo_name.end(), algo_name.begin(), ::tolower);

    auto it = ALGO_MAP.find(algo_name);
    if (it == ALGO_MAP.end()) {
        std::cerr << "[!] Unsupported algorithm: " << algo_name << "\n";
        std::cerr << "    Supported: sha224 sha256 sha384 sha512 sha3-224 sha3-256 sha3-384 sha3-512 shake128 shake256\n";
        return 1;
    }
    const AlgoInfo& ai = it->second;

    // Validate XOF outlen
    if (ai.is_xof && outlen == 0) {
        std::cerr << "[!] --outlen must be > 0 for XOF algorithms\n"; return 1;
    }
    if (!ai.is_xof) {
        outlen = ai.digest_bits / 8;
    }

    // Validate input
    if (in_file.empty() && text_input.empty()) {
        std::cerr << "[!] Provide --in <file> or --text <string>\n"; return 1;
    }

    // Compute hash
    HashResult hr;
    try {
        if (!in_file.empty()) {
            std::ifstream fin(in_file, std::ios::binary);
            if (!fin) { std::cerr << "[!] Cannot open: " << in_file << "\n"; return 1; }
            hr = hash_stream(ai, fin, outlen);
        } else {
            std::istringstream ss(text_input);
            hr = hash_stream(ai, ss, outlen);
        }
    } catch (const std::exception& e) {
        std::cerr << "[!] Error: " << e.what() << "\n"; return 1;
    }

    // Print result
    std::string hex = bytes_to_hex(hr.digest.data(), hr.digest.size());
    double mbps = (hr.bytes_processed > 0 && hr.elapsed_ms > 0)
                  ? (hr.bytes_processed / 1048576.0) / (hr.elapsed_ms / 1000.0)
                  : 0.0;

    std::cout << algo_name << "(" << (!in_file.empty() ? in_file : "(stdin)") << ") = " << hex << "\n";

    if (hr.bytes_processed > 0) {
        std::cout << std::fixed << std::setprecision(2)
                  << "  Processed: " << hr.bytes_processed << " bytes"
                  << "  Time: " << hr.elapsed_ms << " ms"
                  << "  Speed: " << mbps << " MB/s\n";
    }

    // Write raw output
    if (!raw_out.empty()) {
        std::ofstream fout(raw_out, std::ios::binary);
        if (!fout) { std::cerr << "[!] Cannot write: " << raw_out << "\n"; return 1; }
        fout.write(reinterpret_cast<const char*>(hr.digest.data()), hr.digest.size());
        std::cout << "  Raw digest written to: " << raw_out << "\n";
    }

    return 0;
}
