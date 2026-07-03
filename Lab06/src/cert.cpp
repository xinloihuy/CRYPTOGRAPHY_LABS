#include "cert.h"
#include "utils.h"
#include <oqs/oqs.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <cstring>
#include <vector>
#include <string>

// ── Minimal JSON builder ─────────────────────────────────────────────────────
// We implement a tiny JSON writer/reader to avoid external dependencies.

struct PQCert {
    std::string subject;
    std::string public_key_b64;   // subject's ML-DSA public key
    std::string algo;             // e.g. "ML-DSA-44"
    std::string issuer;
    std::string signature_b64;    // CA's ML-DSA signature over the TBS blob
};

// TBS = to-be-signed data: subject + algo + public_key_b64 concatenated
static std::string make_tbs(const PQCert& c) {
    return c.subject + "|" + c.algo + "|" + c.issuer + "|" + c.public_key_b64;
}

static std::string cert_to_json(const PQCert& c) {
    // Simple hand-rolled JSON (no special chars in our data)
    std::ostringstream os;
    os << "{\n";
    os << "  \"subject\": \""    << c.subject        << "\",\n";
    os << "  \"algo\": \""       << c.algo           << "\",\n";
    os << "  \"issuer\": \""     << c.issuer         << "\",\n";
    os << "  \"public_key\": \"" << c.public_key_b64 << "\",\n";
    os << "  \"signature\": \""  << c.signature_b64  << "\"\n";
    os << "}\n";
    return os.str();
}

// Minimal JSON field extractor (handles simple string values)
static std::string json_get(const std::string& json, const std::string& key) {
    std::string search = "\"" + key + "\"";
    size_t pos = json.find(search);
    if (pos == std::string::npos) throw std::runtime_error("JSON key not found: " + key);
    pos = json.find(':', pos);
    if (pos == std::string::npos) throw std::runtime_error("JSON parse error at key: " + key);
    pos = json.find('"', pos);
    if (pos == std::string::npos) throw std::runtime_error("JSON value not string: " + key);
    ++pos;
    size_t end = json.find('"', pos);
    if (end == std::string::npos) throw std::runtime_error("JSON unterminated string: " + key);
    return json.substr(pos, end - pos);
}

static PQCert cert_from_json(const std::string& json) {
    PQCert c;
    c.subject        = json_get(json, "subject");
    c.algo           = json_get(json, "algo");
    c.issuer         = json_get(json, "issuer");
    c.public_key_b64 = json_get(json, "public_key");
    c.signature_b64  = json_get(json, "signature");
    return c;
}

// ── OQS helpers ──────────────────────────────────────────────────────────────
static const char* ML_DSA_44_NAME = OQS_SIG_alg_ml_dsa_44;

// Create a new ML-DSA-44 keypair
static bool dsa44_keygen(std::vector<uint8_t>& pk, std::vector<uint8_t>& sk) {
    OQS_SIG* sig = OQS_SIG_new(ML_DSA_44_NAME);
    if (!sig) return false;
    pk.resize(sig->length_public_key);
    sk.resize(sig->length_secret_key);
    bool ok = (OQS_SIG_keypair(sig, pk.data(), sk.data()) == OQS_SUCCESS);
    OQS_SIG_free(sig);
    return ok;
}

static bool dsa44_sign(const std::string& tbs,
                        const std::vector<uint8_t>& sk,
                        std::vector<uint8_t>& signature) {
    OQS_SIG* sig = OQS_SIG_new(ML_DSA_44_NAME);
    if (!sig) return false;
    signature.resize(sig->length_signature);
    size_t sig_len = 0;
    bool ok = (OQS_SIG_sign(sig,
                             signature.data(), &sig_len,
                             (const uint8_t*)tbs.data(), tbs.size(),
                             sk.data()) == OQS_SUCCESS);
    OQS_SIG_free(sig);
    if (ok) signature.resize(sig_len);
    return ok;
}

static bool dsa44_verify(const std::string& tbs,
                          const std::vector<uint8_t>& signature,
                          const std::vector<uint8_t>& pk) {
    OQS_SIG* sig = OQS_SIG_new(ML_DSA_44_NAME);
    if (!sig) return false;
    bool ok = (OQS_SIG_verify(sig,
                               (const uint8_t*)tbs.data(), tbs.size(),
                               signature.data(), signature.size(),
                               pk.data()) == OQS_SUCCESS);
    OQS_SIG_free(sig);
    return ok;
}

// ── Actions ──────────────────────────────────────────────────────────────────

// Create: Generate CA keypair + subject keypair, sign subject pubkey → cert.json
static int action_create(const std::string& subject, const std::string& issuer,
                          const std::string& ca_pub_file,  const std::string& ca_priv_file,
                          const std::string& sub_pub_file, const std::string& cert_file) {
    std::cout << "=== Creating PQ Certificate ===\n\n";

    // Step 1: Generate CA keypair
    std::cout << "[1/4] Generating CA keypair (ML-DSA-44)...\n";
    std::vector<uint8_t> ca_pk, ca_sk;
    if (!dsa44_keygen(ca_pk, ca_sk)) {
        std::cerr << "[ERROR] CA keygen failed\n"; return 1;
    }
    pem_write(ca_pub_file,  "ML-DSA-44 PUBLIC KEY",  ca_pk.data(), ca_pk.size());
    pem_write(ca_priv_file, "ML-DSA-44 PRIVATE KEY", ca_sk.data(), ca_sk.size());
    std::cout << "       CA public key : " << ca_pub_file  << " (" << ca_pk.size() << " bytes)\n";
    std::cout << "       CA private key: " << ca_priv_file << "\n";

    // Step 2: Generate subject keypair
    std::cout << "[2/4] Generating subject keypair (ML-DSA-44)...\n";
    std::vector<uint8_t> sub_pk, sub_sk;
    if (!dsa44_keygen(sub_pk, sub_sk)) {
        std::cerr << "[ERROR] Subject keygen failed\n"; return 1;
    }
    pem_write(sub_pub_file, "ML-DSA-44 PUBLIC KEY", sub_pk.data(), sub_pk.size());
    std::cout << "       Subject pub key: " << sub_pub_file << " (" << sub_pk.size() << " bytes)\n";

    // Step 3: Build TBS and sign
    std::cout << "[3/4] Signing subject public key with CA private key...\n";
    PQCert cert;
    cert.subject        = subject;
    cert.algo           = "ML-DSA-44";
    cert.issuer         = issuer;
    cert.public_key_b64 = base64_encode(sub_pk.data(), sub_pk.size());

    std::string tbs = make_tbs(cert);
    std::vector<uint8_t> sig_bytes;
    if (!dsa44_sign(tbs, ca_sk, sig_bytes)) {
        std::cerr << "[ERROR] CA signing failed\n";
        std::fill(ca_sk.begin(), ca_sk.end(), 0);
        return 1;
    }
    // Zero CA private key from memory
    std::fill(ca_sk.begin(), ca_sk.end(), 0);
    std::fill(sub_sk.begin(), sub_sk.end(), 0);

    cert.signature_b64 = base64_encode(sig_bytes.data(), sig_bytes.size());

    // Step 4: Write JSON cert
    std::cout << "[4/4] Writing certificate...\n";
    std::string json = cert_to_json(cert);
    std::ofstream f(cert_file);
    if (!f) { std::cerr << "[ERROR] Cannot write " << cert_file << "\n"; return 1; }
    f << json;

    std::cout << "\n[OK] Certificate created: " << cert_file << "\n";
    std::cout << "     Subject  : " << cert.subject << "\n";
    std::cout << "     Issuer   : " << cert.issuer  << "\n";
    std::cout << "     Algorithm: " << cert.algo    << "\n";
    std::cout << "     Signature: " << sig_bytes.size() << " bytes\n";
    return 0;
}

// Verify: Load cert.json + CA public key, check signature
static int action_verify(const std::string& cert_file, const std::string& ca_pub_file) {
    std::cout << "=== Verifying PQ Certificate ===\n\n";

    // Load cert JSON
    std::ifstream f(cert_file);
    if (!f) { std::cerr << "[ERROR] Cannot open " << cert_file << "\n"; return 1; }
    std::string json((std::istreambuf_iterator<char>(f)), {});
    PQCert cert = cert_from_json(json);

    // Load CA public key
    std::vector<uint8_t> ca_pk = pem_read(ca_pub_file);

    // Rebuild TBS
    std::string tbs = make_tbs(cert);

    // Decode signature
    std::vector<uint8_t> sig_bytes = base64_decode(cert.signature_b64);

    // Verify
    std::cout << "     Subject  : " << cert.subject << "\n";
    std::cout << "     Issuer   : " << cert.issuer  << "\n";
    std::cout << "     Algorithm: " << cert.algo    << "\n";
    std::cout << "     Sig size : " << sig_bytes.size() << " bytes\n\n";

    if (dsa44_verify(tbs, sig_bytes, ca_pk)) {
        std::cout << "[OK] Certificate signature VALID ✓\n";
        return 0;
    } else {
        std::cout << "[FAIL] Certificate signature INVALID ✗\n";
        return 2;
    }
}

// Tamper test: demonstrate various tampering scenarios
static int action_tamper_test(const std::string& cert_file, const std::string& ca_pub_file) {
    std::cout << "=== PQ Certificate Tamper Tests ===\n\n";

    // Load original cert
    std::ifstream f(cert_file);
    if (!f) { std::cerr << "[ERROR] Cannot open " << cert_file << "\n"; return 1; }
    std::string json((std::istreambuf_iterator<char>(f)), {});
    PQCert orig = cert_from_json(json);
    std::vector<uint8_t> ca_pk = pem_read(ca_pub_file);

    int pass = 0, total = 0;
    auto check_fail = [&](const std::string& name, bool should_fail) {
        std::cout << "  [" << ++total << "] " << name << ": ";
        std::cout << (should_fail ? "PASSED (correctly rejected) ✓" : "FAILED (should have been rejected) ✗") << "\n";
        if (should_fail) ++pass;
    };

    std::string tbs;
    std::vector<uint8_t> sig_bytes = base64_decode(orig.signature_b64);
    bool ok;

    // Test 1: Tampered subject
    {
        PQCert c = orig;
        c.subject = "TAMPERED_SUBJECT";
        tbs = make_tbs(c);
        ok = !dsa44_verify(tbs, sig_bytes, ca_pk);
        check_fail("Tampered subject", ok);
    }

    // Test 2: Tampered public key (flip one byte)
    {
        PQCert c = orig;
        std::vector<uint8_t> pk_bytes = base64_decode(c.public_key_b64);
        pk_bytes[0] ^= 0xFF;
        c.public_key_b64 = base64_encode(pk_bytes.data(), pk_bytes.size());
        tbs = make_tbs(c);
        ok = !dsa44_verify(tbs, sig_bytes, ca_pk);
        check_fail("Tampered public key", ok);
    }

    // Test 3: Tampered signature (flip one byte)
    {
        std::vector<uint8_t> bad_sig = sig_bytes;
        bad_sig[42] ^= 0x01;
        tbs = make_tbs(orig);
        ok = !dsa44_verify(tbs, bad_sig, ca_pk);
        check_fail("Tampered signature (1 bit flip)", ok);
    }

    // Test 4: Wrong CA public key (generate fresh keypair)
    {
        std::vector<uint8_t> wrong_pk, wrong_sk;
        dsa44_keygen(wrong_pk, wrong_sk);
        std::fill(wrong_sk.begin(), wrong_sk.end(), 0);
        tbs = make_tbs(orig);
        ok = !dsa44_verify(tbs, sig_bytes, wrong_pk);
        check_fail("Wrong CA public key", ok);
    }

    // Test 5: Tampered issuer
    {
        PQCert c = orig;
        c.issuer = "EVIL-CA";
        tbs = make_tbs(c);
        ok = !dsa44_verify(tbs, sig_bytes, ca_pk);
        check_fail("Tampered issuer", ok);
    }

    // Test 6: Empty signature
    {
        std::vector<uint8_t> empty_sig(10, 0);
        tbs = make_tbs(orig);
        ok = !dsa44_verify(tbs, empty_sig, ca_pk);
        check_fail("Empty/zeroed signature", ok);
    }

    std::cout << "\n=== Results: " << pass << "/" << total << " tamper tests passed ===\n";
    return (pass == total) ? 0 : 1;
}

// ── CLI entry point ──────────────────────────────────────────────────────────
int cmd_cert(int argc, char* argv[]) {
    std::string action, subject = "Student-Lab06", issuer = "PQ-CA";
    std::string ca_pub  = "ca_pub.pem",  ca_priv = "ca_priv.pem";
    std::string sub_pub = "sub_pub.pem", cert_file = "cert.json";

    for (int i = 0; i < argc - 1; ++i) {
        std::string a = argv[i];
        if      (a == "--action")   action    = argv[++i];
        else if (a == "--subject")  subject   = argv[++i];
        else if (a == "--issuer")   issuer    = argv[++i];
        else if (a == "--ca-pub")   ca_pub    = argv[++i];
        else if (a == "--ca-priv")  ca_priv   = argv[++i];
        else if (a == "--sub-pub")  sub_pub   = argv[++i];
        else if (a == "--cert")     cert_file = argv[++i];
    }

    if (action.empty()) {
        std::cerr << "[ERROR] Usage: pqtool cert --action <create|verify|tamper-test> [...]\n";
        return 1;
    }

    if (action == "create") {
        return action_create(subject, issuer, ca_pub, ca_priv, sub_pub, cert_file);
    } else if (action == "verify") {
        return action_verify(cert_file, ca_pub);
    } else if (action == "tamper-test") {
        return action_tamper_test(cert_file, ca_pub);
    } else {
        std::cerr << "[ERROR] Unknown action: " << action << "\n";
        return 1;
    }
}
