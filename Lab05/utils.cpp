#include "utils.h"

#include <fstream>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <iostream>
#include <algorithm>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

// Global quiet flag (set true during benchmarks)
bool g_quiet = false;

// ── Enum parsers ─────────────────────────────────────────────

SigEncoding parse_encoding(const std::string& s) {
    if (s == "raw")    return SigEncoding::RAW;
    if (s == "der")    return SigEncoding::DER;
    if (s == "base64") return SigEncoding::BASE64;
    throw std::invalid_argument("Unsupported encoding '" + s +
                                "'. Valid: raw, der, base64");
}

KeyFormat parse_key_format(const std::string& s) {
    if (s == "pem") return KeyFormat::PEM;
    if (s == "der") return KeyFormat::DER;
    throw std::invalid_argument("Unsupported key format '" + s +
                                "'. Valid: pem, der");
}

// ── File I/O ─────────────────────────────────────────────────

std::vector<uint8_t> read_file(const std::string& path) {
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs.is_open())
        throw std::runtime_error("Cannot open file for reading: " + path);
    return std::vector<uint8_t>(std::istreambuf_iterator<char>(ifs),
                                std::istreambuf_iterator<char>());
}

void write_file(const std::string& path, const std::vector<uint8_t>& data) {
    std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
    if (!ofs.is_open())
        throw std::runtime_error("Cannot open file for writing: " + path);
    ofs.write(reinterpret_cast<const char*>(data.data()),
              static_cast<std::streamsize>(data.size()));
    if (!ofs.good())
        throw std::runtime_error("Write error for file: " + path);
}

// ── Base64 ───────────────────────────────────────────────────

std::string base64_encode(const std::vector<uint8_t>& data) {
    BIO* b64  = BIO_new(BIO_f_base64());
    BIO* bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    // No newlines
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(b64, data.data(), static_cast<int>(data.size()));
    BIO_flush(b64);

    BUF_MEM* bptr = nullptr;
    BIO_get_mem_ptr(b64, &bptr);

    std::string result(bptr->data, bptr->length);
    BIO_free_all(b64);
    return result;
}

std::vector<uint8_t> base64_decode(const std::string& b64) {
    BIO* bio = BIO_new_mem_buf(b64.data(), static_cast<int>(b64.size()));
    BIO* b64f = BIO_new(BIO_f_base64());
    bio = BIO_push(b64f, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    std::vector<uint8_t> result(b64.size()); // upper bound
    int decoded_len = BIO_read(bio, result.data(),
                               static_cast<int>(result.size()));
    BIO_free_all(bio);

    if (decoded_len < 0)
        throw std::runtime_error("Base64 decode failed");
    result.resize(static_cast<size_t>(decoded_len));
    return result;
}

// ── OpenSSL error helpers ─────────────────────────────────────

std::string openssl_error_string() {
    unsigned long err = ERR_get_error();
    if (err == 0) return "(no OpenSSL error)";
    char buf[256];
    ERR_error_string_n(err, buf, sizeof(buf));
    return std::string(buf);
}

void print_openssl_errors() {
    unsigned long err;
    while ((err = ERR_get_error()) != 0) {
        char buf[256];
        ERR_error_string_n(err, buf, sizeof(buf));
        std::cerr << "[OpenSSL] " << buf << "\n";
    }
}

// ── Timer ─────────────────────────────────────────────────────

void Timer::start() {
    m_start = std::chrono::high_resolution_clock::now();
}

double Timer::elapsed_ms() const {
    auto now = std::chrono::high_resolution_clock::now();
    return std::chrono::duration<double, std::milli>(now - m_start).count();
}

double Timer::elapsed_us() const {
    auto now = std::chrono::high_resolution_clock::now();
    return std::chrono::duration<double, std::micro>(now - m_start).count();
}

double Timer::elapsed_s() const {
    auto now = std::chrono::high_resolution_clock::now();
    return std::chrono::duration<double>(now - m_start).count();
}

// ── Random bytes ──────────────────────────────────────────────

std::vector<uint8_t> random_bytes(size_t n) {
    std::vector<uint8_t> buf(n);
    if (RAND_bytes(buf.data(), static_cast<int>(n)) != 1)
        throw std::runtime_error("RAND_bytes failed: " + openssl_error_string());
    return buf;
}

// ── Hex dump ─────────────────────────────────────────────────

std::string bytes_to_hex(const std::vector<uint8_t>& data) {
    std::ostringstream oss;
    for (uint8_t b : data)
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    return oss.str();
}
