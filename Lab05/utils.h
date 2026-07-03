#pragma once
// ============================================================
//  utils.h  —  Shared helpers for sigtool
//  Lab 05: Classical Digital Signatures
// ============================================================
#include <string>

// Global quiet flag: when true, sign/verify handlers suppress verbose output
extern bool g_quiet;
#include <vector>
#include <chrono>
#include <cstdint>
#include <stdexcept>

// ── Encoding types ──────────────────────────────────────────
enum class SigEncoding { RAW, DER, BASE64 };
enum class KeyFormat   { PEM, DER };

SigEncoding parse_encoding(const std::string& s);
KeyFormat   parse_key_format(const std::string& s);

// ── File I/O ─────────────────────────────────────────────────
std::vector<uint8_t> read_file(const std::string& path);
void write_file(const std::string& path, const std::vector<uint8_t>& data);

// ── Base64 ───────────────────────────────────────────────────
std::string          base64_encode(const std::vector<uint8_t>& data);
std::vector<uint8_t> base64_decode(const std::string& b64);

// ── OpenSSL error helpers ─────────────────────────────────────
std::string openssl_error_string();   // Returns last error as string
void        print_openssl_errors();   // Prints all pending OpenSSL errors

// ── High-resolution timer ─────────────────────────────────────
class Timer {
public:
    void   start();
    double elapsed_ms() const;  // milliseconds
    double elapsed_us() const;  // microseconds
    double elapsed_s()  const;  // seconds
private:
    std::chrono::high_resolution_clock::time_point m_start;
};

// ── Random bytes generator ────────────────────────────────────
std::vector<uint8_t> random_bytes(size_t n);

// ── Hex helpers (for debug output) ───────────────────────────
std::string bytes_to_hex(const std::vector<uint8_t>& data);
