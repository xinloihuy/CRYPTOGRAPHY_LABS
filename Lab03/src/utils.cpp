#include "utils.h"
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <chrono>
#include <cstring>

// ─── Error handling ───────────────────────────────────────────────────────────
std::string openssl_error_string() {
    std::string result;
    unsigned long err;
    while ((err = ERR_get_error()) != 0) {
        char buf[256];
        ERR_error_string_n(err, buf, sizeof(buf));
        if (!result.empty()) result += "; ";
        result += buf;
    }
    if (result.empty()) result = "(no OpenSSL error)";
    return result;
}

void openssl_die(const std::string& msg) {
    throw std::runtime_error(msg + ": " + openssl_error_string());
}

// ─── Base64 ───────────────────────────────────────────────────────────────────
std::string base64_encode(const std::vector<unsigned char>& data) {
    if (data.empty()) return "";
    EVP_ENCODE_CTX* ctx = EVP_ENCODE_CTX_new();
    if (!ctx) openssl_die("EVP_ENCODE_CTX_new");

    // Calculate output size: ceil(n/3)*4 + newlines + null
    size_t outlen_max = ((data.size() + 2) / 3) * 4 + 16;
    std::vector<unsigned char> out(outlen_max + 64);

    EVP_EncodeInit(ctx);
    int outl = 0, total = 0;
    EVP_EncodeUpdate(ctx, out.data(), &outl,
                     data.data(), (int)data.size());
    total += outl;
    EVP_EncodeFinal(ctx, out.data() + total, &outl);
    total += outl;
    EVP_ENCODE_CTX_free(ctx);

    // Remove newlines for compact base64
    std::string result;
    result.reserve(total);
    for (int i = 0; i < total; i++) {
        char c = (char)out[i];
        if (c != '\n' && c != '\r') result += c;
    }
    return result;
}

std::vector<unsigned char> base64_decode(const std::string& b64) {
    if (b64.empty()) return {};
    EVP_ENCODE_CTX* ctx = EVP_ENCODE_CTX_new();
    if (!ctx) openssl_die("EVP_ENCODE_CTX_new");

    size_t outlen_max = b64.size();
    std::vector<unsigned char> out(outlen_max + 16);

    EVP_DecodeInit(ctx);
    int outl = 0, total = 0;
    int rc = EVP_DecodeUpdate(ctx, out.data(), &outl,
                              (const unsigned char*)b64.c_str(), (int)b64.size());
    if (rc < 0) {
        EVP_ENCODE_CTX_free(ctx);
        throw std::runtime_error("base64_decode: invalid base64 input");
    }
    total += outl;
    rc = EVP_DecodeFinal(ctx, out.data() + total, &outl);
    EVP_ENCODE_CTX_free(ctx);
    if (rc < 0) {
        throw std::runtime_error("base64_decode: invalid base64 padding");
    }
    total += outl;
    out.resize(total);
    return out;
}

// ─── Hex ─────────────────────────────────────────────────────────────────────
std::string hex_encode(const std::vector<unsigned char>& data) {
    std::ostringstream oss;
    for (unsigned char c : data)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)c;
    return oss.str();
}

std::vector<unsigned char> hex_decode(const std::string& hex) {
    if (hex.size() % 2 != 0)
        throw std::runtime_error("hex_decode: odd length hex string");
    std::vector<unsigned char> out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        unsigned int byte;
        std::istringstream ss(hex.substr(i, 2));
        ss >> std::hex >> byte;
        if (ss.fail()) throw std::runtime_error("hex_decode: invalid hex character");
        out.push_back((unsigned char)byte);
    }
    return out;
}

// ─── File I/O ─────────────────────────────────────────────────────────────────
std::vector<unsigned char> read_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f.is_open())
        throw std::runtime_error("Cannot open file: " + path);
    return std::vector<unsigned char>(
        (std::istreambuf_iterator<char>(f)),
        std::istreambuf_iterator<char>()
    );
}

void write_file(const std::string& path, const std::vector<unsigned char>& data) {
    std::ofstream f(path, std::ios::binary);
    if (!f.is_open())
        throw std::runtime_error("Cannot write file: " + path);
    f.write((const char*)data.data(), data.size());
}

std::string read_file_text(const std::string& path) {
    std::ifstream f(path);
    if (!f.is_open())
        throw std::runtime_error("Cannot open file: " + path);
    return std::string(
        (std::istreambuf_iterator<char>(f)),
        std::istreambuf_iterator<char>()
    );
}

void write_file_text(const std::string& path, const std::string& text) {
    std::ofstream f(path);
    if (!f.is_open())
        throw std::runtime_error("Cannot write file: " + path);
    f << text;
}

// ─── Random bytes ─────────────────────────────────────────────────────────────
std::vector<unsigned char> random_bytes(size_t n) {
    std::vector<unsigned char> buf(n);
    if (RAND_bytes(buf.data(), (int)n) != 1)
        openssl_die("RAND_bytes");
    return buf;
}

// ─── Timing ──────────────────────────────────────────────────────────────────
double now_ms() {
    using namespace std::chrono;
    return (double)duration_cast<microseconds>(
        high_resolution_clock::now().time_since_epoch()
    ).count() / 1000.0;
}
