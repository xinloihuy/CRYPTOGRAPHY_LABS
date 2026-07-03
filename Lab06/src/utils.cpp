#include "utils.h"
#include <fstream>
#include <sstream>
#include <iostream>
#include <cstring>
#include <stdexcept>

// ── Base64 lookup tables ─────────────────────────────────────────────────────
static const char B64_CHARS[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int b64_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1; // invalid / padding
}

std::string base64_encode(const uint8_t* data, size_t len) {
    std::string out;
    out.reserve(((len + 2) / 3) * 4);
    for (size_t i = 0; i < len; i += 3) {
        uint32_t val = (uint32_t)data[i] << 16;
        if (i + 1 < len) val |= (uint32_t)data[i + 1] << 8;
        if (i + 2 < len) val |= (uint32_t)data[i + 2];
        out += B64_CHARS[(val >> 18) & 0x3F];
        out += B64_CHARS[(val >> 12) & 0x3F];
        out += (i + 1 < len) ? B64_CHARS[(val >> 6) & 0x3F] : '=';
        out += (i + 2 < len) ? B64_CHARS[val & 0x3F] : '=';
    }
    return out;
}

std::vector<uint8_t> base64_decode(const std::string& s) {
    std::vector<uint8_t> out;
    // strip whitespace
    std::string clean;
    for (char c : s) if (!isspace((unsigned char)c)) clean += c;
    size_t n = clean.size();
    if (n % 4 != 0) throw std::runtime_error("base64_decode: bad length");
    out.reserve(n / 4 * 3);
    for (size_t i = 0; i < n; i += 4) {
        int v0 = b64_val(clean[i]);
        int v1 = b64_val(clean[i+1]);
        int v2 = b64_val(clean[i+2]);
        int v3 = b64_val(clean[i+3]);
        if (v0 < 0 || v1 < 0) throw std::runtime_error("base64_decode: invalid char");
        uint32_t val = ((uint32_t)v0 << 18) | ((uint32_t)v1 << 12);
        out.push_back((uint8_t)(val >> 16));
        if (clean[i+2] != '=') {
            val |= ((uint32_t)v2 << 6);
            out.push_back((uint8_t)((val >> 8) & 0xFF));
        }
        if (clean[i+3] != '=') {
            val |= (uint32_t)v3;
            out.push_back((uint8_t)(val & 0xFF));
        }
    }
    return out;
}

// ── Hex ─────────────────────────────────────────────────────────────────────
std::string hex_encode(const uint8_t* data, size_t len) {
    static const char HEX[] = "0123456789abcdef";
    std::string s;
    s.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        s += HEX[data[i] >> 4];
        s += HEX[data[i] & 0xF];
    }
    return s;
}

// ── PEM ─────────────────────────────────────────────────────────────────────
bool pem_write(const std::string& filename, const std::string& label,
               const uint8_t* data, size_t len) {
    std::ofstream f(filename, std::ios::binary);
    if (!f) return false;
    f << "-----BEGIN " << label << "-----\n";
    // write base64 with line breaks at 64 chars
    std::string b64 = base64_encode(data, len);
    for (size_t i = 0; i < b64.size(); i += 64) {
        f << b64.substr(i, 64) << '\n';
    }
    f << "-----END " << label << "-----\n";
    return f.good();
}

std::vector<uint8_t> pem_read(const std::string& filename, const std::string& label) {
    std::ifstream f(filename);
    if (!f) throw std::runtime_error("pem_read: cannot open " + filename);
    std::string line, b64;
    bool in_block = false;
    while (std::getline(f, line)) {
        // trim CR
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.substr(0, 5) == "-----") {
            if (line.find("BEGIN") != std::string::npos) {
                if (!label.empty() && line.find(label) == std::string::npos)
                    continue; // wrong label
                in_block = true;
            } else if (line.find("END") != std::string::npos) {
                in_block = false;
            }
            continue;
        }
        if (in_block) b64 += line;
    }
    if (b64.empty()) throw std::runtime_error("pem_read: no data found in " + filename);
    return base64_decode(b64);
}

// ── Raw binary I/O ───────────────────────────────────────────────────────────
bool file_write(const std::string& filename, const uint8_t* data, size_t len) {
    std::ofstream f(filename, std::ios::binary);
    if (!f) return false;
    f.write(reinterpret_cast<const char*>(data), len);
    return f.good();
}

std::vector<uint8_t> file_read(const std::string& filename) {
    std::ifstream f(filename, std::ios::binary | std::ios::ate);
    if (!f) throw std::runtime_error("file_read: cannot open " + filename);
    size_t sz = (size_t)f.tellg();
    f.seekg(0);
    std::vector<uint8_t> buf(sz);
    f.read(reinterpret_cast<char*>(buf.data()), sz);
    return buf;
}

// ── Base64 file I/O ──────────────────────────────────────────────────────────
bool b64file_write(const std::string& filename, const uint8_t* data, size_t len) {
    std::ofstream f(filename);
    if (!f) return false;
    f << base64_encode(data, len) << '\n';
    return f.good();
}

std::vector<uint8_t> b64file_read(const std::string& filename) {
    std::ifstream f(filename);
    if (!f) throw std::runtime_error("b64file_read: cannot open " + filename);
    std::string s((std::istreambuf_iterator<char>(f)), {});
    return base64_decode(s);
}

// ── Misc ─────────────────────────────────────────────────────────────────────
void print_hex(const char* label, const uint8_t* data, size_t len, size_t maxBytes) {
    size_t show = std::min(len, maxBytes);
    std::cout << label << " [" << len << " bytes]: " << hex_encode(data, show);
    if (len > show) std::cout << "...";
    std::cout << '\n';
}

bool bytes_equal(const uint8_t* a, const uint8_t* b, size_t len) {
    // Constant-time comparison
    uint8_t diff = 0;
    for (size_t i = 0; i < len; ++i) diff |= a[i] ^ b[i];
    return diff == 0;
}
