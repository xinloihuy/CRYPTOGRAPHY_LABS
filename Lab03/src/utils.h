#pragma once
#include <string>
#include <vector>
#include <stdexcept>
#include <openssl/evp.h>

// ─── Error handling ───────────────────────────────────────────────────────────
void openssl_die(const std::string& msg);
std::string openssl_error_string();

// ─── Base64 ───────────────────────────────────────────────────────────────────
std::string base64_encode(const std::vector<unsigned char>& data);
std::vector<unsigned char> base64_decode(const std::string& b64);

// ─── Hex ─────────────────────────────────────────────────────────────────────
std::string hex_encode(const std::vector<unsigned char>& data);
std::vector<unsigned char> hex_decode(const std::string& hex);

// ─── File I/O ─────────────────────────────────────────────────────────────────
std::vector<unsigned char> read_file(const std::string& path);
void write_file(const std::string& path, const std::vector<unsigned char>& data);
std::string read_file_text(const std::string& path);
void write_file_text(const std::string& path, const std::string& text);

// ─── Random bytes ─────────────────────────────────────────────────────────────
std::vector<unsigned char> random_bytes(size_t n);

// ─── Timing ──────────────────────────────────────────────────────────────────
double now_ms();
