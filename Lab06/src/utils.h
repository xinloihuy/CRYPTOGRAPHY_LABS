#pragma once
#include <string>
#include <vector>
#include <cstdint>

// ── Base64 ──────────────────────────────────────────────────────────────────
std::string base64_encode(const uint8_t* data, size_t len);
std::vector<uint8_t> base64_decode(const std::string& s);

// ── Hex ─────────────────────────────────────────────────────────────────────
std::string hex_encode(const uint8_t* data, size_t len);

// ── PEM I/O ─────────────────────────────────────────────────────────────────
// Write raw bytes as PEM (base64 between header/footer lines)
bool pem_write(const std::string& filename,
               const std::string& label,       // e.g. "PUBLIC KEY"
               const uint8_t* data, size_t len);

// Read PEM → raw bytes; label is checked if non-empty
std::vector<uint8_t> pem_read(const std::string& filename,
                               const std::string& label = "");

// ── Raw binary I/O ───────────────────────────────────────────────────────────
bool file_write(const std::string& filename, const uint8_t* data, size_t len);
std::vector<uint8_t> file_read(const std::string& filename);

// ── Base64 file I/O ──────────────────────────────────────────────────────────
bool b64file_write(const std::string& filename, const uint8_t* data, size_t len);
std::vector<uint8_t> b64file_read(const std::string& filename);

// ── Misc ─────────────────────────────────────────────────────────────────────
void print_hex(const char* label, const uint8_t* data, size_t len, size_t maxBytes = 32);
bool bytes_equal(const uint8_t* a, const uint8_t* b, size_t len);
