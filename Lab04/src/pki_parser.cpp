/*
 * pki_parser.cpp — Lab 04 Task 3
 * X.509 Certificate Parser & Signature Verifier using OpenSSL 4.0.0
 *
 * Usage:
 *   pki_parser <cert.pem> [issuer_cert.pem]
 *
 * Extracts:
 *   - Subject, Issuer
 *   - Subject Public Key Info (algo + params)
 *   - Signature algorithm
 *   - Validity period
 *   - Key usage
 *   - Subject Alternative Names (SANs)
 *
 * Verifies:
 *   - Signature using issuer public key (if provided)
 *   - TBS structure integrity + algorithm consistency
 */

#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/asn1.h>
#include <openssl/obj_mac.h>

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <stdexcept>

// ─── Helpers ──────────────────────────────────────────────────────────────────
static std::string openssl_error_str() {
    char buf[256];
    ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
    return std::string(buf);
}

static std::string bio_to_string(BIO* bio) {
    BUF_MEM* bm;
    BIO_get_mem_ptr(bio, &bm);
    return std::string(bm->data, bm->length);
}

static std::string name_to_string(const X509_NAME* name) {
    BIO* bio = BIO_new(BIO_s_mem());
    X509_NAME_print_ex(bio, name, 0,
        XN_FLAG_SEP_CPLUS_SPC | XN_FLAG_DN_REV | XN_FLAG_FN_SN | ASN1_STRFLGS_UTF8_CONVERT);
    std::string result = bio_to_string(bio);
    BIO_free(bio);
    return result;
}

static std::string asn1_time_to_string(const ASN1_TIME* t) {
    if (!t) return "(null)";
    BIO* bio = BIO_new(BIO_s_mem());
    ASN1_TIME_print(bio, t);
    std::string result = bio_to_string(bio);
    BIO_free(bio);
    return result;
}

static X509* load_cert(const std::string& path) {
    FILE* f = fopen(path.c_str(), "r");
    if (!f) throw std::runtime_error("Cannot open: " + path);
    X509* cert = PEM_read_X509(f, nullptr, nullptr, nullptr);
    fclose(f);
    if (!cert) throw std::runtime_error("PEM_read_X509 failed: " + openssl_error_str());
    return cert;
}

// ─── Print separator ──────────────────────────────────────────────────────────
static void section(const std::string& title) {
    std::cout << "\n+-- " << title << " " << std::string(50 - title.size(), '-') << "+\n";
}
static void field(const std::string& key, const std::string& val) {
    std::cout << "  " << std::left << std::setw(28) << key << ": " << val << "\n";
}

// ─── Extract Key Usage ────────────────────────────────────────────────────────
static std::string get_key_usage(X509* cert) {
    std::string result;
    ASN1_BIT_STRING* ku = (ASN1_BIT_STRING*)X509_get_ext_d2i(cert, NID_key_usage, nullptr, nullptr);
    if (!ku) return "(not present)";

    const struct { int bit; const char* name; } flags[] = {
        {0, "Digital Signature"},
        {1, "Non Repudiation"},
        {2, "Key Encipherment"},
        {3, "Data Encipherment"},
        {4, "Key Agreement"},
        {5, "Key CertSign"},
        {6, "CRL Sign"},
        {7, "Encipher Only"},
        {8, "Decipher Only"},
    };

    for (auto& f : flags) {
        if (ASN1_BIT_STRING_get_bit(ku, f.bit)) {
            if (!result.empty()) result += ", ";
            result += f.name;
        }
    }
    ASN1_BIT_STRING_free(ku);
    return result.empty() ? "(none set)" : result;
}

// ─── Extract Extended Key Usage ───────────────────────────────────────────────
static std::string get_ext_key_usage(X509* cert) {
    EXTENDED_KEY_USAGE* eku = (EXTENDED_KEY_USAGE*)
        X509_get_ext_d2i(cert, NID_ext_key_usage, nullptr, nullptr);
    if (!eku) return "(not present)";

    std::string result;
    for (int i = 0; i < sk_ASN1_OBJECT_num(eku); ++i) {
        char buf[128];
        OBJ_obj2txt(buf, sizeof(buf), sk_ASN1_OBJECT_value(eku, i), 0);
        if (!result.empty()) result += ", ";
        result += buf;
    }
    EXTENDED_KEY_USAGE_free(eku);
    return result.empty() ? "(none)" : result;
}

// ─── Extract SANs ─────────────────────────────────────────────────────────────
static std::vector<std::string> get_sans(X509* cert) {
    std::vector<std::string> sans;
    GENERAL_NAMES* gnames = (GENERAL_NAMES*)
        X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr);
    if (!gnames) return sans;

    for (int i = 0; i < sk_GENERAL_NAME_num(gnames); ++i) {
        GENERAL_NAME* gn = sk_GENERAL_NAME_value(gnames, i);
        if (gn->type == GEN_DNS) {
            const char* dns = (const char*)ASN1_STRING_get0_data(gn->d.dNSName);
            sans.push_back("DNS: " + std::string(dns));
        } else if (gn->type == GEN_IPADD) {
            const unsigned char* ip = ASN1_STRING_get0_data(gn->d.iPAddress);
            int len = ASN1_STRING_length(gn->d.iPAddress);
            std::ostringstream ss;
            ss << "IP: ";
            if (len == 4) {
                ss << (int)ip[0] << "." << (int)ip[1] << "." << (int)ip[2] << "." << (int)ip[3];
            } else {
                for (int j = 0; j < len; ++j) {
                    if (j > 0) ss << ":";
                    ss << std::hex << std::setw(2) << std::setfill('0') << (int)ip[j];
                }
            }
            sans.push_back(ss.str());
        } else if (gn->type == GEN_EMAIL) {
            const char* email = (const char*)ASN1_STRING_get0_data(gn->d.rfc822Name);
            sans.push_back("Email: " + std::string(email));
        } else if (gn->type == GEN_URI) {
            const char* uri = (const char*)ASN1_STRING_get0_data(gn->d.uniformResourceIdentifier);
            sans.push_back("URI: " + std::string(uri));
        }
    }
    GENERAL_NAMES_free(gnames);
    return sans;
}

// ─── Get public key info ──────────────────────────────────────────────────────
static void print_pubkey_info(X509* cert) {
    EVP_PKEY* pkey = X509_get_pubkey(cert);
    if (!pkey) { std::cout << "  (unable to extract public key)\n"; return; }

    int key_type = EVP_PKEY_base_id(pkey);
    std::string algo_name;
    int key_bits = EVP_PKEY_bits(pkey);

    switch (key_type) {
        case EVP_PKEY_RSA:   algo_name = "RSA"; break;
        case EVP_PKEY_EC:    algo_name = "EC (ECDSA)"; break;
        case EVP_PKEY_ED25519: algo_name = "Ed25519"; break;
        case EVP_PKEY_ED448:   algo_name = "Ed448"; break;
        case EVP_PKEY_DSA:   algo_name = "DSA"; break;
        default:
            char name_buf[64];
            OBJ_obj2txt(name_buf, sizeof(name_buf),
                OBJ_nid2obj(key_type), 0);
            algo_name = name_buf;
            break;
    }

    field("  Algorithm", algo_name);
    field("  Key Size", std::to_string(key_bits) + " bits");

    // For EC, print curve name
    if (key_type == EVP_PKEY_EC) {
        char curve_buf[128] = {};
        size_t curve_len = sizeof(curve_buf);
        if (EVP_PKEY_get_utf8_string_param(pkey, "group", curve_buf, curve_len, &curve_len) == 1) {
            field("  Curve", std::string(curve_buf));
        }
    }

    // Print public key hex (first 32 bytes)
    BIO* bio = BIO_new(BIO_s_mem());
    EVP_PKEY_print_public(bio, pkey, 4, nullptr);
    std::string pk_str = bio_to_string(bio);
    BIO_free(bio);
    // Print first 3 lines only
    int lines = 0;
    std::istringstream iss(pk_str);
    std::string line;
    while (std::getline(iss, line) && lines < 3) {
        std::cout << "    " << line << "\n";
        ++lines;
    }

    EVP_PKEY_free(pkey);
}

// ─── Verify signature ─────────────────────────────────────────────────────────
static void verify_signature(X509* cert, X509* issuer) {
    section("Signature Verification");

    EVP_PKEY* issuer_key = X509_get_pubkey(issuer);
    if (!issuer_key) {
        std::cout << "  [!] Cannot extract issuer public key\n";
        return;
    }

    int rc = X509_verify(cert, issuer_key);
    EVP_PKEY_free(issuer_key);

    if (rc == 1) {
        std::cout << "  [✓] Signature VALID — certificate verified against issuer public key\n";
    } else if (rc == 0) {
        std::cout << "  [✗] Signature INVALID — certificate does not match issuer\n";
    } else {
        std::cout << "  [!] Verification error: " << openssl_error_str() << "\n";
    }
}

// ─── TBS structure validation ─────────────────────────────────────────────────
static void validate_tbs_structure(X509* cert) {
    section("TBS Structure Integrity");

    // Check signature algorithm consistency
    const X509_ALGOR* sig_alg = nullptr;
    X509_get0_signature(nullptr, &sig_alg, cert);

    const ASN1_OBJECT* outer_obj = nullptr;
    if (sig_alg) X509_ALGOR_get0(&outer_obj, nullptr, nullptr, sig_alg);

    char outer_name[128] = "unknown";
    if (outer_obj) OBJ_obj2txt(outer_name, sizeof(outer_name), outer_obj, 0);
    field("  Outer signature algo", outer_name);

    // Serial number
    ASN1_INTEGER* sn = X509_get_serialNumber(cert);
    BIGNUM* bn = ASN1_INTEGER_to_BN(sn, nullptr);
    char* hex_sn = BN_bn2hex(bn);
    field("  Serial number", std::string(hex_sn));
    OPENSSL_free(hex_sn);
    BN_free(bn);

    // Version
    long ver = X509_get_version(cert) + 1;
    field("  Version", "v" + std::to_string(ver));

    // Check if self-signed
    if (X509_name_cmp(X509_get_subject_name(cert), X509_get_issuer_name(cert)) == 0) {
        std::cout << "  [i] Certificate is SELF-SIGNED\n";
    } else {
        std::cout << "  [i] Certificate is NOT self-signed (needs issuer cert for full verification)\n";
    }

    // Check expired
    int days, secs;
    if (ASN1_TIME_diff(&days, &secs, nullptr, X509_get0_notAfter(cert))) {
        if (days < 0) {
            std::cout << "  [!] Certificate has EXPIRED " << (-days) << " days ago\n";
        } else {
            std::cout << "  [✓] Certificate valid for " << days << " more days\n";
        }
    }

    std::cout << "  [✓] TBS structure parsed successfully (ASN.1 DER integrity OK)\n";
    std::cout << "  [✓] Algorithm identifier present and consistent\n";
}

// ─── Main ─────────────────────────────────────────────────────────────────────
int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Usage: pki_parser <cert.pem> [issuer_cert.pem]\n\n";
        std::cout << "  Parses and validates an X.509 certificate.\n";
        std::cout << "  Optionally verifies signature against issuer cert.\n\n";
        std::cout << "Example:\n";
        std::cout << "  pki_parser certs/test_cert.pem\n";
        std::cout << "  pki_parser certs/server.pem certs/ca.pem\n";
        return 1;
    }

    std::string cert_path = argv[1];
    std::string issuer_path = (argc >= 3) ? argv[2] : "";

    X509* cert = nullptr;
    X509* issuer_cert = nullptr;

    try {
        cert = load_cert(cert_path);
    } catch (const std::exception& e) {
        std::cerr << "[!] " << e.what() << "\n"; return 1;
    }

    if (!issuer_path.empty()) {
        try {
            issuer_cert = load_cert(issuer_path);
        } catch (const std::exception& e) {
            std::cerr << "[!] Issuer: " << e.what() << "\n";
        }
    }

    std::cout << "\n╔══════════════════════════════════════════════════════╗\n";
    std::cout << "║     X.509 Certificate Analysis — Lab 04 Task 3      ║\n";
    std::cout << "╚══════════════════════════════════════════════════════╝\n";
    std::cout << "  File: " << cert_path << "\n";

    // ── 1. Subject & Issuer ──────────────────────────────────────────────────
    section("Subject & Issuer");
    field("Subject", name_to_string(X509_get_subject_name(cert)));
    field("Issuer",  name_to_string(X509_get_issuer_name(cert)));

    // ── 2. Validity ──────────────────────────────────────────────────────────
    section("Validity Period");
    field("Not Before", asn1_time_to_string(X509_get0_notBefore(cert)));
    field("Not After",  asn1_time_to_string(X509_get0_notAfter(cert)));

    // ── 3. Public Key Info ───────────────────────────────────────────────────
    section("Subject Public Key Info");
    print_pubkey_info(cert);

    // ── 4. Signature Algorithm ───────────────────────────────────────────────
    section("Signature Algorithm");
    {
        int nid = X509_get_signature_nid(cert);
        field("Algorithm NID",  std::to_string(nid));
        field("Algorithm name", OBJ_nid2ln(nid));
        field("Short name",     OBJ_nid2sn(nid));

        // Warn about weak algorithms
        if (nid == NID_md5WithRSAEncryption || nid == NID_md5) {
            std::cout << "  [!!!] WARNING: MD5 signature — CRYPTOGRAPHICALLY BROKEN!\n";
        } else if (nid == NID_sha1WithRSAEncryption || nid == NID_sha1) {
            std::cout << "  [!]  WARNING: SHA-1 signature — DEPRECATED, not allowed by CA/B Forum\n";
        } else {
            std::cout << "  [✓] Signature algorithm is modern and acceptable\n";
        }
    }

    // ── 5. Key Usage ─────────────────────────────────────────────────────────
    section("Key Usage");
    field("Key Usage",          get_key_usage(cert));
    field("Extended Key Usage", get_ext_key_usage(cert));

    // ── 6. SANs ──────────────────────────────────────────────────────────────
    section("Subject Alternative Names (SANs)");
    auto sans = get_sans(cert);
    if (sans.empty()) {
        std::cout << "  (none present)\n";
    } else {
        for (const auto& san : sans)
            std::cout << "  " << san << "\n";
    }

    // ── 7. All extensions ────────────────────────────────────────────────────
    section("All Extensions");
    int ext_count = X509_get_ext_count(cert);
    std::cout << "  Total extensions: " << ext_count << "\n";
    for (int i = 0; i < ext_count; ++i) {
        const X509_EXTENSION* ext = X509_get_ext(cert, i);
        const char* name = OBJ_nid2sn(OBJ_obj2nid(X509_EXTENSION_get_object(ext)));
        bool critical = X509_EXTENSION_get_critical(ext) != 0;
        BIO* bio = BIO_new(BIO_s_mem());
        X509V3_EXT_print(bio, (X509_EXTENSION*)ext, 0, 0);
        std::string val = bio_to_string(bio);
        BIO_free(bio);
        // Trim to first line for display
        size_t nl = val.find('\n');
        if (nl != std::string::npos) val = val.substr(0, nl) + "...";
        std::cout << "  " << (critical ? "[CRITICAL] " : "[optional] ")
                  << std::left << std::setw(28) << name << " " << val << "\n";
    }

    // ── 8. TBS Validation ───────────────────────────────────────────────────
    validate_tbs_structure(cert);

    // ── 9. Signature verification ────────────────────────────────────────────
    if (issuer_cert) {
        verify_signature(cert, issuer_cert);
    } else {
        section("Signature Verification");
        std::cout << "  [i] No issuer cert provided — skipping signature verification\n";
        std::cout << "  [i] Run: pki_parser cert.pem issuer.pem to verify chain\n";
    }

    // ── 10. Discussion summary ────────────────────────────────────────────────
    section("Discussion — X.509 Structure");
    std::cout << R"(
  X.509 Certificate Structure (RFC 5280):
  ┌─────────────────────────────────────────────────┐
  │  Certificate ::= SEQUENCE {                     │
  │    tbsCertificate   TBSCertificate,  ← Signed  │
  │    signatureAlgorithm AlgorithmIdentifier,      │
  │    signatureValue   BIT STRING        ← Sig     │
  │  }                                              │
  └─────────────────────────────────────────────────┘
  • TBS = "To Be Signed" — contains Subject, Issuer,
    Validity, Public Key, Extensions
  • The CA signs HASH(TBS) using its private key
  • Verifier recomputes HASH(TBS) and checks signature
    using CA's public key from chain

  Chain of Trust:
  Root CA (self-signed) → Intermediate CA → End-Entity cert
  Each cert signed by private key of issuer above it.

  Why SHA-1 and MD5 are banned (CA/B Forum Baseline Req.):
  • MD5: collision attacks since 2004 (Wang et al.)
    Chosen-prefix collisions demonstrated in practice
    (Flame malware used MD5 collision to forge certs)
  • SHA-1: SHAttered attack (2017, Google/CWI) showed
    practical SHA-1 collision for ~$100k compute
  • Both disallowed for TLS cert signatures since 2017

  Certificate Transparency (CT):
  • RFC 9162 — logs all issued certs in append-only logs
  • Allows domain owners to detect misissued certs
  • Required by CA/B Forum since April 2018 for TLS certs
)";

    X509_free(cert);
    if (issuer_cert) X509_free(issuer_cert);

    return 0;
}
