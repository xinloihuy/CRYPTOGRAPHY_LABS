/*
 * length_extension.cpp — Lab 04 Task 5 + Bonus Task A (+5 pts)
 *
 * Demonstrates Length-Extension Attack on naïve MAC = H(key || message)
 * AND implements the attack manually for SHA-256 (Bonus +5).
 *
 * Attack: Given MAC = SHA256(k || m), length of k, and m (but NOT k),
 * we can compute MAC' = SHA256(k || m || pad || m') for any extension m'.
 * This is done WITHOUT knowing k.
 *
 * Part 1: Naïve MAC demonstration (victim side)
 * Part 2: Length-extension attack (attacker side)
 *   a) Using OpenSSL's SHA-256 with state injection
 *   b) Manual SHA-256 state reconstruction (Bonus +5)
 * Part 3: HMAC defense demonstration
 *
 * Why Merkle-Damgård enables length extension:
 *   SHA-256 uses MD construction: state = compress(prev_state, block)
 *   The final hash output IS the internal state after processing all blocks.
 *   An attacker who sees the hash can "continue" hashing more data from
 *   exactly that state, without knowing the prefix (the key).
 */

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/err.h>

#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdint>
#include <stdexcept>

// ─── Hex helpers ──────────────────────────────────────────────────────────────
static std::string to_hex(const unsigned char* buf, size_t len) {
    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i)
        ss << std::setw(2) << (unsigned)buf[i];
    return ss.str();
}

static std::vector<unsigned char> from_hex(const std::string& hex) {
    std::vector<unsigned char> v;
    for (size_t i = 0; i+1 < hex.size(); i += 2) {
        unsigned b;
        std::istringstream ss(hex.substr(i,2));
        ss >> std::hex >> b;
        v.push_back((unsigned char)b);
    }
    return v;
}

// ─── SHA-256 using OpenSSL ────────────────────────────────────────────────────
static std::vector<unsigned char> sha256(const unsigned char* data, size_t len) {
    std::vector<unsigned char> out(32);
    unsigned int olen = 32;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, out.data(), &olen);
    EVP_MD_CTX_free(ctx);
    return out;
}

// ─── HMAC-SHA256 ──────────────────────────────────────────────────────────────
static std::vector<unsigned char> hmac_sha256(const unsigned char* key, size_t klen,
                                               const unsigned char* msg, size_t mlen) {
    std::vector<unsigned char> out(32);
    unsigned int olen = 32;
    HMAC(EVP_sha256(), key, (int)klen, msg, mlen, out.data(), &olen);
    return out;
}

// ─── SHA-256 Padding computation ─────────────────────────────────────────────
// Computes the Merkle-Damgård padding appended to a message of `msg_len` bytes
// Total padded length is always a multiple of 64 bytes (SHA-256 block size)
static std::vector<unsigned char> sha256_padding(size_t msg_len) {
    std::vector<unsigned char> pad;
    pad.push_back(0x80); // Append 1-bit (as 0x80 byte)
    size_t padded_len = msg_len + 1;
    // Pad with zeros until padded_len ≡ 56 (mod 64)
    while ((padded_len % 64) != 56) {
        pad.push_back(0x00);
        padded_len++;
    }
    // Append original message length in BITS as 64-bit big-endian
    uint64_t bit_len = (uint64_t)msg_len * 8;
    for (int i = 7; i >= 0; --i)
        pad.push_back((unsigned char)((bit_len >> (i * 8)) & 0xFF));
    return pad;
}

// ─── Manual SHA-256 constants ─────────────────────────────────────────────────
// Round constants K
static const uint32_t SHA256_K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static inline uint32_t ROTR32(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
static inline uint32_t Ch(uint32_t x, uint32_t y, uint32_t z)  { return (x & y) ^ (~x & z); }
static inline uint32_t Maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }
static inline uint32_t Sigma0(uint32_t x) { return ROTR32(x,2) ^ ROTR32(x,13) ^ ROTR32(x,22); }
static inline uint32_t Sigma1(uint32_t x) { return ROTR32(x,6) ^ ROTR32(x,11) ^ ROTR32(x,25); }
static inline uint32_t sigma0(uint32_t x) { return ROTR32(x,7) ^ ROTR32(x,18) ^ (x >> 3); }
static inline uint32_t sigma1(uint32_t x) { return ROTR32(x,17) ^ ROTR32(x,19) ^ (x >> 10); }

// Manual SHA-256 block compression — processes one 64-byte block
// starting from state [H0..H7], updates state in place
static void sha256_compress_block(uint32_t state[8], const unsigned char block[64]) {
    uint32_t W[64];
    for (int i = 0; i < 16; ++i)
        W[i] = ((uint32_t)block[4*i] << 24) | ((uint32_t)block[4*i+1] << 16) |
               ((uint32_t)block[4*i+2] << 8) | (uint32_t)block[4*i+3];
    for (int i = 16; i < 64; ++i)
        W[i] = sigma1(W[i-2]) + W[i-7] + sigma0(W[i-15]) + W[i-16];

    uint32_t a=state[0], b=state[1], c=state[2], d=state[3];
    uint32_t e=state[4], f=state[5], g=state[6], h=state[7];

    for (int i = 0; i < 64; ++i) {
        uint32_t T1 = h + Sigma1(e) + Ch(e,f,g) + SHA256_K[i] + W[i];
        uint32_t T2 = Sigma0(a) + Maj(a,b,c);
        h=g; g=f; f=e; e=d+T1;
        d=c; c=b; b=a; a=T1+T2;
    }
    state[0]+=a; state[1]+=b; state[2]+=c; state[3]+=d;
    state[4]+=e; state[5]+=f; state[6]+=g; state[7]+=h;
}

// ─── Extract SHA-256 internal state from a digest ─────────────────────────────
// SHA-256 output is big-endian serialization of [H0..H7]
static void digest_to_state(const unsigned char digest[32], uint32_t state[8]) {
    for (int i = 0; i < 8; ++i) {
        state[i] = ((uint32_t)digest[4*i]   << 24) |
                   ((uint32_t)digest[4*i+1] << 16) |
                   ((uint32_t)digest[4*i+2] << 8)  |
                   ((uint32_t)digest[4*i+3]);
    }
}

// ─── Manual length-extension for SHA-256 (Bonus +5) ──────────────────────────
// Given:
//   known_hash: MAC = SHA256(key || message)  [32 bytes]
//   key_len:    len(key)
//   message:    original message (known to attacker)
//   extension:  additional data m' to append
// Computes: SHA256(key || message || padding || extension)  WITHOUT knowing key
static std::vector<unsigned char> manual_length_extension(
    const unsigned char known_hash[32],
    size_t              key_len,
    const std::string&  message,
    const std::string&  extension)
{
    // Step 1: Reconstruct the internal state from the known hash
    uint32_t state[8];
    digest_to_state(known_hash, state);

    // Step 2: Determine the total length that was hashed to produce known_hash
    // That is: key_len + message.size() + len(padding for key||message)
    size_t inner_len = key_len + message.size();
    std::vector<unsigned char> inner_pad = sha256_padding(inner_len);
    size_t padded_inner_len = inner_len + inner_pad.size(); // multiple of 64

    // Step 3: Prepare the extension block(s) and process through manual compression
    // We're continuing from state after SHA256 processed (key || message || padding)
    // The "total" length for the new padding is padded_inner_len + extension.size()
    std::string ext_with_pad = extension;
    std::vector<unsigned char> new_pad = sha256_padding(padded_inner_len + extension.size());
    // Build the extension message
    std::vector<unsigned char> ext_bytes(extension.begin(), extension.end());
    ext_bytes.insert(ext_bytes.end(), new_pad.begin(), new_pad.end());

    // Step 4: Process extension blocks through SHA-256 compression
    // Total length passed to SHA-256 at end = padded_inner_len + ext_bytes.size()
    size_t total_len = padded_inner_len + ext_bytes.size();

    // Process each 64-byte block of ext_bytes
    for (size_t offset = 0; offset < ext_bytes.size(); offset += 64) {
        sha256_compress_block(state, ext_bytes.data() + offset);
    }

    // Step 5: Serialize final state as big-endian → this is our forged MAC
    std::vector<unsigned char> forged(32);
    for (int i = 0; i < 8; ++i) {
        forged[4*i]   = (state[i] >> 24) & 0xFF;
        forged[4*i+1] = (state[i] >> 16) & 0xFF;
        forged[4*i+2] = (state[i] >> 8)  & 0xFF;
        forged[4*i+3] = state[i]          & 0xFF;
    }

    (void)total_len;
    return forged;
}

// ─── Build the forged message ─────────────────────────────────────────────────
// The attacker sends: message || padding || extension
// The server will compute: SHA256(key || message || padding || extension)
// which equals our forged MAC
static std::vector<unsigned char> build_forged_message(
    size_t             key_len,
    const std::string& message,
    const std::string& extension)
{
    size_t inner_len = key_len + message.size();
    std::vector<unsigned char> padding = sha256_padding(inner_len);

    std::vector<unsigned char> forged_msg;
    forged_msg.insert(forged_msg.end(), message.begin(), message.end());
    forged_msg.insert(forged_msg.end(), padding.begin(), padding.end());
    forged_msg.insert(forged_msg.end(), extension.begin(), extension.end());
    return forged_msg;
}

// ─── Print padding diagram ───────────────────────────────────────────────────
static void print_padding_diagram(size_t key_len, const std::string& msg) {
    size_t inner_len = key_len + msg.size();
    std::vector<unsigned char> pad = sha256_padding(inner_len);
    size_t total = inner_len + pad.size();

    std::cout << "\n  SHA-256 Merkle-Damgård Padding Diagram:\n\n";
    std::cout << "  Original hashed input = key (" << key_len << " B) || message (" << msg.size() << " B)\n";
    std::cout << "  Total inner length = " << inner_len << " bytes\n\n";
    std::cout << "  ┌─────────────────────────────────────────────────────────────┐\n";
    std::cout << "  │  key (" << key_len << "B)  │  msg (" << msg.size() << "B)  │  0x80  │  zeros...  │  len(64b big-endian)  │\n";
    std::cout << "  └─────────────────────────────────────────────────────────────┘\n";
    std::cout << "  ◄──────────── " << inner_len << " bytes ────────────► ◄──── " << pad.size() << " bytes padding ────►\n";
    std::cout << "  Total padded: " << total << " bytes (" << (total/64) << " × 64-byte SHA-256 blocks)\n\n";
    std::cout << "  Padding bytes (hex): 80";
    for (size_t i = 1; i < pad.size() && i < 10; ++i)
        std::cout << " " << std::hex << std::setw(2) << std::setfill('0') << (unsigned)pad[i];
    if (pad.size() > 10) std::cout << " ... (zeros) ...";
    // Last 8 bytes = big-endian bit length
    uint64_t bits = (uint64_t)inner_len * 8;
    std::cout << "\n  Length field (bits): " << std::dec << bits
              << " = 0x" << std::hex << std::setw(16) << std::setfill('0') << bits << std::dec << "\n";
}

// ─── Main ─────────────────────────────────────────────────────────────────────
int main() {
    std::cout << "\n╔══════════════════════════════════════════════════════════════╗\n";
    std::cout << "║  Length-Extension Attack Demo — Lab 04 Task 5 + Bonus (+5)  ║\n";
    std::cout << "╚══════════════════════════════════════════════════════════════╝\n\n";

    // ─── Setup ────────────────────────────────────────────────────────────────
    // Secret key (unknown to attacker)
    const std::string SECRET_KEY = "supersecretkey16";  // 16 bytes
    const std::string MESSAGE    = "amount=100&user=alice";
    const std::string EXTENSION  = "&admin=true";

    size_t key_len = SECRET_KEY.size();
    size_t msg_len = MESSAGE.size();

    // ─── VICTIM: Compute genuine MAC ──────────────────────────────────────────
    std::cout << "╔── VICTIM SIDE ─────────────────────────────────────────────╗\n";
    std::cout << "  Construction: MAC = SHA256(key || message)\n";
    std::cout << "  Secret key:   \"" << SECRET_KEY << "\" (" << key_len << " bytes)\n";
    std::cout << "  Message:      \"" << MESSAGE << "\"\n\n";

    std::vector<unsigned char> inner;
    inner.insert(inner.end(), SECRET_KEY.begin(), SECRET_KEY.end());
    inner.insert(inner.end(), MESSAGE.begin(), MESSAGE.end());
    auto genuine_mac = sha256(inner.data(), inner.size());

    std::cout << "  Genuine MAC (SHA256(k||m)):\n";
    std::cout << "  " << to_hex(genuine_mac.data(), 32) << "\n\n";

    // ─── ATTACKER: What they know ─────────────────────────────────────────────
    std::cout << "╔── ATTACKER SIDE ───────────────────────────────────────────╗\n";
    std::cout << "  Attacker knows:\n";
    std::cout << "    - genuine_mac = " << to_hex(genuine_mac.data(), 32) << "\n";
    std::cout << "    - message     = \"" << MESSAGE << "\"\n";
    std::cout << "    - key_len     = " << key_len << " (assumed/guessed)\n";
    std::cout << "    - extension   = \"" << EXTENSION << "\"\n";
    std::cout << "  Attacker does NOT know the key!\n\n";

    // ─── Padding diagram ──────────────────────────────────────────────────────
    print_padding_diagram(key_len, MESSAGE);

    // ─── ATTACK: Manual length extension (Bonus +5) ───────────────────────────
    std::cout << "\n╔── ATTACK: Manual SHA-256 Length Extension (Bonus +5) ──────╗\n";
    std::cout << "  Reconstructing SHA-256 internal state from genuine_mac...\n";

    uint32_t reconstructed_state[8];
    digest_to_state(genuine_mac.data(), reconstructed_state);

    std::cout << "  Internal state [H0..H7]:\n";
    for (int i = 0; i < 8; ++i)
        std::cout << "    H" << i << " = 0x" << std::hex << std::setw(8)
                  << std::setfill('0') << reconstructed_state[i] << "\n";
    std::cout << std::dec;

    // Perform manual extension
    auto forged_mac = manual_length_extension(
        genuine_mac.data(), key_len, MESSAGE, EXTENSION);

    // Build the forged message that attacker sends
    auto forged_msg = build_forged_message(key_len, MESSAGE, EXTENSION);

    std::cout << "\n  Forged message (what attacker sends to server):\n";
    std::cout << "  \"" << MESSAGE;
    // Show padding bytes symbolically
    std::vector<unsigned char> padding = sha256_padding(key_len + MESSAGE.size());
    std::cout << "\" + [padding: ";
    std::cout << std::hex;
    for (size_t i = 0; i < padding.size() && i < 4; ++i)
        std::cout << std::setw(2) << std::setfill('0') << (unsigned)padding[i] << " ";
    std::cout << "...] + \"" << EXTENSION << "\"\n";
    std::cout << std::dec;
    std::cout << "  Total forged message length: " << forged_msg.size() << " bytes\n\n";

    std::cout << "  Forged MAC (computed by attacker WITHOUT key):\n";
    std::cout << "  " << to_hex(forged_mac.data(), 32) << "\n\n";

    // ─── VERIFICATION: Does server accept the forged MAC? ─────────────────────
    std::cout << "╔── VERIFICATION: Server checks forged message ───────────────╗\n";
    std::cout << "  Server computes: SHA256(key || forged_message)\n";

    // Simulate server receiving (key || forged_msg)
    std::vector<unsigned char> server_input;
    server_input.insert(server_input.end(), SECRET_KEY.begin(), SECRET_KEY.end());
    server_input.insert(server_input.end(), forged_msg.begin(), forged_msg.end());
    auto server_mac = sha256(server_input.data(), server_input.size());

    std::cout << "  Server computed MAC: " << to_hex(server_mac.data(), 32) << "\n";
    std::cout << "  Forged MAC:          " << to_hex(forged_mac.data(), 32) << "\n\n";

    if (server_mac == forged_mac) {
        std::cout << "  ★ ATTACK SUCCESSFUL! Server MAC matches forged MAC!\n";
        std::cout << "  ★ Attacker successfully appended \"" << EXTENSION << "\"\n";
        std::cout << "    to the authenticated message WITHOUT knowing the key!\n";
    } else {
        std::cout << "  [!] MACs differ — check implementation\n";
    }

    // ─── HMAC defense ─────────────────────────────────────────────────────────
    std::cout << "\n╔── DEFENSE: HMAC vs Naïve MAC ──────────────────────────────╗\n";

    // Genuine HMAC
    const unsigned char* k = (const unsigned char*)SECRET_KEY.data();
    const unsigned char* m = (const unsigned char*)MESSAGE.data();
    auto genuine_hmac = hmac_sha256(k, key_len, m, msg_len);

    // Forged message with HMAC check
    auto forged_hmac_check = hmac_sha256(k, key_len, forged_msg.data(), forged_msg.size());

    std::cout << "  Genuine HMAC(k, m)           = " << to_hex(genuine_hmac.data(), 32) << "\n";
    std::cout << "  HMAC(k, forged_message)      = " << to_hex(forged_hmac_check.data(), 32) << "\n";

    if (genuine_hmac != forged_hmac_check) {
        std::cout << "  ✓ HMAC detects the forgery — attack FAILED against HMAC!\n";
        std::cout << "  ✓ Length-extension attack is IMPOSSIBLE against HMAC\n";
    }

    // ─── Explanation ──────────────────────────────────────────────────────────
    std::cout << R"(
╔══════════════════════════════════════════════════════════════════╗
║  Discussion & Mitigation Analysis                                ║
╚══════════════════════════════════════════════════════════════════╝

WHY MERKLE-DAMGÅRD ENABLES LENGTH EXTENSION:
────────────────────────────────────────────
SHA-256 uses the Merkle-Damgård (MD) construction:
  H₀ = IV (fixed initial value)
  Hᵢ = compress(Hᵢ₋₁, blockᵢ)
  Output = Hₙ  (final state, serialized)

The KEY problem: the hash output IS the internal state.
Anyone who sees SHA256(data) can "continue" the computation
by injecting more blocks, as if they were in the middle of hashing.

Attack primitive:
  Given SHA256(k || m) = H
  Attacker reconstructs internal state from H
  Attacker continues from that state with extension data m'
  Result = SHA256(k || m || padding || m') — VALID under the naive MAC

WHY HMAC PREVENTS IT:
─────────────────────
HMAC(k, m) = H((k ⊕ opad) || H((k ⊕ ipad) || m))

The outer hash wraps the inner hash result. Even if attacker
computes the inner hash extension, they cannot extend the outer
hash without knowing k (needed for k ⊕ opad).

HMAC is specifically designed to defeat:
  • Length-extension attacks
  • Related-key attacks
  • Generic composition attacks

SECURE ALTERNATIVES:
────────────────────
1. HMAC-SHA256: RFC 2104 — the standard secure MAC
2. SHA-3 / SHAKE: Sponge construction — NOT vulnerable to
   length extension (absorb/squeeze model, output is NOT state)
3. Prefix-free encoding: H(len(k) || k || m) prevents
   ambiguous parsing but doesn't fix the state problem
4. BLAKE2/BLAKE3: Built-in keying support, immune to extension

REAL-WORLD IMPACT:
──────────────────
• Flickr API (2009): Used SHA1(secret || params) — exploited
• Amazon AWS v1 signatures: Used HMAC but older SDKs had bugs
• Many web APIs (2008-2012) used naive H(key || data) MACs
• Length-extension attacks allow privilege escalation in APIs
  that sign requests: add &admin=true without knowing the secret
)";

    return 0;
}
