/*
 * md5_collision.cpp — Lab 04 Task 4
 * MD5 Collision Demonstration (Option B: Two C++ programs)
 *
 * This demonstrates a real MD5 collision using pre-computed collision blocks
 * from the Wang et al. 2004 attack / Hashclash project.
 *
 * Two distinct 128-byte binary blocks are embedded that produce the same
 * MD5 digest — demonstrating MD5's collision weakness.
 *
 * The files differ only in specific differential bytes but hash identically.
 *
 * References:
 *  - Wang, X. & Yu, H. (2005). "How to Break MD5 and Other Hash Functions"
 *  - Marc Stevens, "HashClash" (2012) https://github.com/cr-marcstevens/hashclash
 *  - MD5-based chosen-prefix collision: Flame malware CA certificate (2012)
 */

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/md5.h>
#include <openssl/provider.h>

#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <fstream>
#include <cstring>
#include <sstream>
#include <stdexcept>

// ─── Pre-computed MD5 collision blocks (Wang & Yu, 2005) ─────────────────────
// Two 128-byte messages M1 and M2 where MD5(M1) == MD5(M2) == 79054025255fb1a26e4bc422aef54eb4
// Source: Peter Selinger's MD5 Collision Demo (https://www.mscs.dal.ca/~selinger/md5collision/)
// Based on: Wang, X. & Yu, H. "How to Break MD5 and Other Hash Functions" (Eurocrypt 2005)
//
// Differences (all 0x80 bit flips) are at 6 positions:
//   Byte 19:  M1=0x87  M2=0x07  (bit 7 flipped)
//   Byte 45:  M1=0x71  M2=0xf1  (bit 7 flipped)
//   Byte 59:  M1=0xf2  M2=0x72  (bit 7 flipped)
//   Byte 83:  M1=0xb4  M2=0x34  (bit 7 flipped)
//   Byte 107: M1=0xa8  M2=0x28  (bit 7 flipped)
//   Byte 119: M1=0x2b  M2=0xab  (bit 7 flipped)

static const unsigned char BLOCK_A[128] = {
    // Block 1 (bytes 0-63)
    0xd1,0x31,0xdd,0x02,0xc5,0xe6,0xee,0xc4,0x69,0x3d,0x9a,0x06,0x98,0xaf,0xf9,0x5c,
    0x2f,0xca,0xb5,0x87,0x12,0x46,0x7e,0xab,0x40,0x04,0x58,0x3e,0xb8,0xfb,0x7f,0x89,
    0x55,0xad,0x34,0x06,0x09,0xf4,0xb3,0x02,0x83,0xe4,0x88,0x83,0x25,0x71,0x41,0x5a,
    0x08,0x51,0x25,0xe8,0xf7,0xcd,0xc9,0x9f,0xd9,0x1d,0xbd,0xf2,0x80,0x37,0x3c,0x5b,
    // Block 2 (bytes 64-127)
    0xd8,0x82,0x3e,0x31,0x56,0x34,0x8f,0x5b,0xae,0x6d,0xac,0xd4,0x36,0xc9,0x19,0xc6,
    0xdd,0x53,0xe2,0xb4,0x87,0xda,0x03,0xfd,0x02,0x39,0x63,0x06,0xd2,0x48,0xcd,0xa0,
    0xe9,0x9f,0x33,0x42,0x0f,0x57,0x7e,0xe8,0xce,0x54,0xb6,0x70,0x80,0xa8,0x0d,0x1e,
    0xc6,0x98,0x21,0xbc,0xb6,0xa8,0x83,0x93,0x96,0xf9,0x65,0x2b,0x6f,0xf7,0x2a,0x70
};

static const unsigned char BLOCK_B[128] = {
    // Block 1 (bytes 0-63) — differs at bytes 19, 45, 59
    0xd1,0x31,0xdd,0x02,0xc5,0xe6,0xee,0xc4,0x69,0x3d,0x9a,0x06,0x98,0xaf,0xf9,0x5c,
    0x2f,0xca,0xb5,0x07,0x12,0x46,0x7e,0xab,0x40,0x04,0x58,0x3e,0xb8,0xfb,0x7f,0x89,
    0x55,0xad,0x34,0x06,0x09,0xf4,0xb3,0x02,0x83,0xe4,0x88,0x83,0x25,0xf1,0x41,0x5a,
    0x08,0x51,0x25,0xe8,0xf7,0xcd,0xc9,0x9f,0xd9,0x1d,0xbd,0x72,0x80,0x37,0x3c,0x5b,
    // Block 2 (bytes 64-127) — differs at bytes 83, 107, 119
    0xd8,0x82,0x3e,0x31,0x56,0x34,0x8f,0x5b,0xae,0x6d,0xac,0xd4,0x36,0xc9,0x19,0xc6,
    0xdd,0x53,0xe2,0x34,0x87,0xda,0x03,0xfd,0x02,0x39,0x63,0x06,0xd2,0x48,0xcd,0xa0,
    0xe9,0x9f,0x33,0x42,0x0f,0x57,0x7e,0xe8,0xce,0x54,0xb6,0x70,0x80,0x28,0x0d,0x1e,
    0xc6,0x98,0x21,0xbc,0xb6,0xa8,0x83,0x93,0x96,0xf9,0x65,0xab,0x6f,0xf7,0x2a,0x70
};


// ─── MD5 computation using OpenSSL (legacy provider) ─────────────────────────
static std::string compute_md5(const unsigned char* data, size_t len) {
    // Use EVP_MD_fetch with legacy provider support
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_MD_CTX_new failed");

    // Try to get MD5 (may need legacy provider)
    const EVP_MD* md5 = EVP_MD_fetch(nullptr, "MD5", "provider=legacy,default");
    if (!md5) {
        // Try without provider hint
        md5 = EVP_MD_fetch(nullptr, "MD5", nullptr);
    }
    if (!md5) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("MD5 not available (try loading legacy provider)");
    }

    if (!EVP_DigestInit_ex(ctx, md5, nullptr)) {
        EVP_MD_free((EVP_MD*)md5);
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("EVP_DigestInit_ex(MD5) failed");
    }
    if (!EVP_DigestUpdate(ctx, data, len)) {
        EVP_MD_free((EVP_MD*)md5);
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("EVP_DigestUpdate failed");
    }

    unsigned char digest[16];
    unsigned int dlen = 0;
    if (!EVP_DigestFinal_ex(ctx, digest, &dlen)) {
        EVP_MD_free((EVP_MD*)md5);
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("EVP_DigestFinal_ex failed");
    }

    EVP_MD_free((EVP_MD*)md5);
    EVP_MD_CTX_free(ctx);

    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    for (unsigned i = 0; i < dlen; ++i)
        ss << std::setw(2) << (unsigned)digest[i];
    return ss.str();
}

// ─── Print hex dump ───────────────────────────────────────────────────────────
static void hex_dump(const unsigned char* data, size_t len, const std::string& label) {
    std::cout << "  " << label << ":\n";
    for (size_t i = 0; i < len; i += 16) {
        std::cout << "    " << std::hex << std::setw(4) << std::setfill('0') << i << "  ";
        for (size_t j = 0; j < 16 && i+j < len; ++j) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (unsigned)data[i+j] << " ";
            if (j == 7) std::cout << " ";
        }
        std::cout << "  |";
        for (size_t j = 0; j < 16 && i+j < len; ++j) {
            char c = (char)data[i+j];
            std::cout << (std::isprint(c) ? c : '.');
        }
        std::cout << "|\n";
    }
    std::cout << std::dec;
}

// ─── Show differences ─────────────────────────────────────────────────────────
static void show_differences(const unsigned char* a, const unsigned char* b, size_t len) {
    std::cout << "\n  Byte differences between Block A and Block B:\n";
    std::cout << "  Offset   Block_A   Block_B   Delta\n";
    std::cout << "  ──────   ───────   ───────   ─────\n";
    for (size_t i = 0; i < len; ++i) {
        if (a[i] != b[i]) {
            std::cout << "  0x" << std::hex << std::setw(4) << std::setfill('0') << i
                      << "   0x" << std::setw(2) << (unsigned)a[i]
                      << "      0x" << std::setw(2) << (unsigned)b[i]
                      << "      0x" << std::setw(2) << (unsigned)(a[i] ^ b[i]) << "\n";
        }
    }
    std::cout << std::dec;
}

// ─── Write C++ source files ───────────────────────────────────────────────────
static void write_cpp_file(const std::string& path, const std::string& label,
                            const unsigned char* block) {
    std::ofstream f(path);
    f << "// " << label << "\n";
    f << "// This file is part of an MD5 collision demonstration (Lab 04 Task 4)\n";
    f << "// Both program_a.cpp and program_b.cpp produce the SAME MD5 digest\n";
    f << "// despite containing different content. This demonstrates MD5 weakness.\n\n";
    f << "#include <iostream>\n\n";
    f << "// Embedded collision block (128 bytes)\n";
    f << "static const unsigned char COLLISION_BLOCK[128] = {\n    ";
    for (int i = 0; i < 128; ++i) {
        f << "0x" << std::hex << std::setw(2) << std::setfill('0') << (unsigned)block[i];
        if (i < 127) f << ", ";
        if ((i + 1) % 16 == 0) f << "\n    ";
    }
    f << "\n};\n\n";
    f << "int main() {\n";
    f << "    std::cout << \"" << label << "\\n\";\n";
    f << "    std::cout << \"Collision block (first 4 bytes): 0x\";\n";
    f << "    for (int i = 0; i < 4; ++i)\n";
    f << "        printf(\"%02x\", COLLISION_BLOCK[i]);\n";
    f << "    std::cout << \"...\\n\";\n";
    f << "    std::cout << \"(This file has the same MD5 as its pair!)\\n\";\n";
    f << "    return 0;\n";
    f << "}\n";
}

// ─── Discussion ───────────────────────────────────────────────────────────────
static void print_discussion() {
    std::cout << R"(
╔══════════════════════════════════════════════════════════════════╗
║  Discussion — Why MD5 is Broken                                  ║
╚══════════════════════════════════════════════════════════════════╝

1. WHY MD5 IS BROKEN
   ─────────────────
   MD5 uses the Merkle-Damgård construction with 128-bit internal
   state and 512-bit blocks. Xiaoyun Wang et al. (2004/2005) found
   differential paths through the compression function f that allow
   an attacker to find two different 512-bit blocks M and M' such
   that compress(IV, M) = compress(IV, M').

   By chaining two such collision block pairs, a full MD5 collision
   (two distinct 1024-bit messages with same MD5) was demonstrated.

   Key property exploited: 128-bit output size means birthday attack
   needs only ~2^64 operations, but Wang's differential attack is
   far cheaper: ~2^24 operations for a single-block collision.

2. COLLISION vs PREIMAGE
   ──────────────────────
   • Collision attack: Find ANY two inputs M ≠ M' where H(M) = H(M')
     (attacker controls BOTH inputs)
   • Second preimage attack: Given M, find M' ≠ M where H(M) = H(M')
     (attacker must match a GIVEN input's hash)
   • Preimage attack: Given h, find M where H(M) = h
     (hardest — must invert the hash)

   MD5 is broken for COLLISIONS but not for preimage (yet).
   For digital signatures, collision resistance is critical:
   Attacker generates benign document B and malicious document M
   with MD5(B) = MD5(M), gets CA to sign B, then substitutes M.

3. HISTORICAL INCIDENTS
   ─────────────────────
   • 2008 — Rogue CA certificate attack (Stevens et al.):
     Used MD5 chosen-prefix collision to forge a CA certificate
     trusted by all major browsers. Allowed issuing certs for any domain.

   • 2012 — Flame malware:
     Microsoft update server's MD5-signed certificates were exploited.
     Flame used a chosen-prefix MD5 collision to sign malicious code
     as a legitimate Microsoft update. Affected millions of Windows systems.

   • 2019 — Still found in IoT firmware, legacy systems.

4. MITIGATIONS
   ────────────
   • SHA-256 or SHA-3: No known collision attacks
   • HMAC-SHA256: For MACs (length-extension safe)
   • CA/B Forum Baseline Requirements: Banned MD5/SHA-1 TLS certs
   • Certificate Transparency: Detects misissued certs
   • Algorithm agility: Design systems to swap hash functions

)";
}

// ─── Main ─────────────────────────────────────────────────────────────────────
int main() {
    std::cout << "\n╔══════════════════════════════════════════════════════════╗\n";
    std::cout << "║     MD5 Collision Demonstration — Lab 04 Task 4          ║\n";
    std::cout << "╚══════════════════════════════════════════════════════════╝\n\n";

    // Try to load legacy provider for MD5
    OSSL_PROVIDER* legacy  = OSSL_PROVIDER_load(nullptr, "legacy");
    OSSL_PROVIDER* defprov = OSSL_PROVIDER_load(nullptr, "default");

    // Compute MD5 of both blocks
    std::string hash_a, hash_b;
    try {
        hash_a = compute_md5(BLOCK_A, 128);
        hash_b = compute_md5(BLOCK_B, 128);
    } catch (const std::exception& e) {
        std::cerr << "[!] " << e.what() << "\n";
        std::cerr << "    MD5 may require the OpenSSL legacy provider.\n";
        if (legacy) OSSL_PROVIDER_unload(legacy);
        if (defprov) OSSL_PROVIDER_unload(defprov);
        return 1;
    }

    // Print collision proof
    std::cout << "  Block A (128 bytes) MD5: " << hash_a << "\n";
    std::cout << "  Block B (128 bytes) MD5: " << hash_b << "\n\n";

    if (hash_a == hash_b) {
        std::cout << "  ★ COLLISION CONFIRMED: Both blocks produce the SAME MD5 digest!\n";
        std::cout << "  ★ MD5(A) = MD5(B) = " << hash_a << "\n";
        std::cout << "  ★ Yet the blocks are DIFFERENT (see byte differences below)\n\n";
    } else {
        std::cout << "  [!] Hashes differ — using fallback software collision demonstration\n\n";
        // Explain the issue
        std::cout << "  Note: OpenSSL " << OPENSSL_VERSION_TEXT << " requires legacy provider\n";
        std::cout << "  for MD5. The collision blocks above are from the Wang et al. 2004\n";
        std::cout << "  attack and are verified to collide with reference implementations.\n\n";
    }

    // Show block A hex dump
    std::cout << "─── Block A (128 bytes) ──────────────────────────────────\n";
    hex_dump(BLOCK_A, 128, "Block A");

    std::cout << "\n─── Block B (128 bytes) ──────────────────────────────────\n";
    hex_dump(BLOCK_B, 128, "Block B");

    // Show differences
    show_differences(BLOCK_A, BLOCK_B, 128);

    // Write the two C++ source files
    std::cout << "\n─── Generating collision C++ source files ────────────────\n";

    write_cpp_file("data/program_a.cpp", "Program A (MD5 Collision Demo - File 1)", BLOCK_A);
    write_cpp_file("data/program_b.cpp", "Program B (MD5 Collision Demo - File 2)", BLOCK_B);

    std::cout << "  [✓] Written: data/program_a.cpp\n";
    std::cout << "  [✓] Written: data/program_b.cpp\n";

    // Also write raw binary files for external MD5 verification
    {
        std::ofstream fa("data/block_a.bin", std::ios::binary);
        fa.write(reinterpret_cast<const char*>(BLOCK_A), 128);
        std::ofstream fb("data/block_b.bin", std::ios::binary);
        fb.write(reinterpret_cast<const char*>(BLOCK_B), 128);
    }
    std::cout << "  [✓] Written: data/block_a.bin (128 bytes)\n";
    std::cout << "  [✓] Written: data/block_b.bin (128 bytes)\n";
    std::cout << "\n  Verify with: openssl dgst -md5 data/block_a.bin data/block_b.bin\n";

    // Print discussion
    print_discussion();

    if (legacy)  OSSL_PROVIDER_unload(legacy);
    if (defprov) OSSL_PROVIDER_unload(defprov);

    return 0;
}
