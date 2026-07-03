#include "hybrid.h"
#include "rsa_oaep.h"
#include "aes_gcm.h"
#include "utils.h"
#include <stdexcept>
#include <sstream>
#include <cstring>
#include <cstdint>

// ─── Minimal JSON helpers (no external deps) ──────────────────────────────────
static std::string json_escape(const std::string& s) {
    // Simple escaping for ASCII strings
    std::string out;
    for (char c : s) {
        if (c == '"') out += "\\\"";
        else if (c == '\\') out += "\\\\";
        else out += c;
    }
    return out;
}

// Extract value of "key": "value" from JSON string
static std::string json_get_string(const std::string& json, const std::string& key) {
    std::string search = "\"" + key + "\"";
    size_t kpos = json.find(search);
    if (kpos == std::string::npos)
        throw std::runtime_error("JSON parse error: key '" + key + "' not found");
    size_t colon = json.find(':', kpos + search.size());
    if (colon == std::string::npos)
        throw std::runtime_error("JSON parse error: no colon after key '" + key + "'");
    size_t q1 = json.find('"', colon + 1);
    if (q1 == std::string::npos)
        throw std::runtime_error("JSON parse error: no opening quote for value of '" + key + "'");
    size_t q2 = json.find('"', q1 + 1);
    if (q2 == std::string::npos)
        throw std::runtime_error("JSON parse error: no closing quote for value of '" + key + "'");
    return json.substr(q1 + 1, q2 - q1 - 1);
}

static int json_get_int(const std::string& json, const std::string& key) {
    std::string search = "\"" + key + "\"";
    size_t kpos = json.find(search);
    if (kpos == std::string::npos)
        throw std::runtime_error("JSON parse error: key '" + key + "' not found");
    size_t colon = json.find(':', kpos + search.size());
    if (colon == std::string::npos)
        throw std::runtime_error("JSON parse error: no colon after key '" + key + "'");
    // Skip whitespace
    size_t vpos = colon + 1;
    while (vpos < json.size() && (json[vpos] == ' ' || json[vpos] == '\t' || json[vpos] == '\n')) vpos++;
    // Read integer
    size_t end = vpos;
    while (end < json.size() && (json[end] >= '0' && json[end] <= '9')) end++;
    if (end == vpos) throw std::runtime_error("JSON parse error: no integer value for '" + key + "'");
    return std::stoi(json.substr(vpos, end - vpos));
}

// ─── Serialize / Deserialize ──────────────────────────────────────────────────
std::vector<unsigned char> envelope_serialize(const HybridEnvelope& env) {
    // Build JSON header
    std::string json = "{\n";
    json += "  \"mode\": \"" + json_escape(env.mode) + "\",\n";
    json += "  \"rsa_modulus\": " + std::to_string(env.rsa_modulus) + ",\n";
    json += "  \"hash\": \"" + json_escape(env.hash) + "\",\n";
    json += "  \"wrapped_key\": \"" + json_escape(env.wrapped_key) + "\",\n";
    json += "  \"iv\": \"" + json_escape(env.iv) + "\",\n";
    json += "  \"tag\": \"" + json_escape(env.tag) + "\"\n";
    json += "}";

    // 4-byte LE header length + JSON + ciphertext
    uint32_t jlen = (uint32_t)json.size();
    std::vector<unsigned char> out;
    out.push_back((unsigned char)(jlen & 0xFF));
    out.push_back((unsigned char)((jlen >> 8) & 0xFF));
    out.push_back((unsigned char)((jlen >> 16) & 0xFF));
    out.push_back((unsigned char)((jlen >> 24) & 0xFF));
    out.insert(out.end(), json.begin(), json.end());
    out.insert(out.end(), env.ciphertext.begin(), env.ciphertext.end());
    return out;
}

HybridEnvelope envelope_deserialize(const std::vector<unsigned char>& data) {
    if (data.size() < 4)
        throw std::runtime_error("Malformed envelope: too short (< 4 bytes)");

    uint32_t jlen = (uint32_t)data[0]
                  | ((uint32_t)data[1] << 8)
                  | ((uint32_t)data[2] << 16)
                  | ((uint32_t)data[3] << 24);

    if (data.size() < 4 + jlen)
        throw std::runtime_error(
            "Malformed envelope: declared JSON length " + std::to_string(jlen) +
            " but only " + std::to_string((int)data.size() - 4) + " bytes remain"
        );

    std::string json(data.begin() + 4, data.begin() + 4 + jlen);

    HybridEnvelope env;
    try {
        env.mode        = json_get_string(json, "mode");
        env.rsa_modulus = json_get_int(json, "rsa_modulus");
        env.hash        = json_get_string(json, "hash");
        env.wrapped_key = json_get_string(json, "wrapped_key");
        env.iv          = json_get_string(json, "iv");
        env.tag         = json_get_string(json, "tag");
    } catch (const std::exception& e) {
        throw std::runtime_error(std::string("Tampered or malformed envelope header: ") + e.what());
    }

    // Validate fields
    if (env.mode != "RSA-OAEP-AES-GCM")
        throw std::runtime_error("Unsupported envelope mode: " + env.mode);
    if (env.hash != "SHA-256")
        throw std::runtime_error("Unsupported hash in envelope: " + env.hash);
    if (env.rsa_modulus < 3072)
        throw std::runtime_error("Unsupported RSA modulus in envelope: " + std::to_string(env.rsa_modulus));

    env.ciphertext = std::vector<unsigned char>(
        data.begin() + 4 + jlen, data.end()
    );
    return env;
}

// ─── Hybrid Encrypt ───────────────────────────────────────────────────────────
std::vector<unsigned char> hybrid_encrypt(
    EVP_PKEY* pub_key,
    const std::vector<unsigned char>& plaintext,
    const std::string& label)
{
    int rsa_bits = EVP_PKEY_get_bits(pub_key);

    // Generate random 256-bit AES key
    std::vector<unsigned char> aes_key = random_bytes(AES_GCM_KEY_SIZE);

    // Encrypt plaintext with AES-256-GCM
    AesGcmResult gcm = aes_gcm_encrypt(aes_key, plaintext);

    // Wrap AES key with RSA-OAEP
    std::vector<unsigned char> wrapped_key = rsa_oaep_encrypt(pub_key, aes_key, label);

    HybridEnvelope env;
    env.mode        = "RSA-OAEP-AES-GCM";
    env.rsa_modulus = rsa_bits;
    env.hash        = "SHA-256";
    env.wrapped_key = base64_encode(wrapped_key);
    env.iv          = base64_encode(gcm.iv);
    env.tag         = base64_encode(gcm.tag);
    env.ciphertext  = gcm.ciphertext;

    // Zero out key from memory
    std::fill(aes_key.begin(), aes_key.end(), 0);

    return envelope_serialize(env);
}

// ─── Hybrid Decrypt ───────────────────────────────────────────────────────────
std::vector<unsigned char> hybrid_decrypt(
    EVP_PKEY* priv_key,
    const std::vector<unsigned char>& envelope_data,
    const std::string& label)
{
    HybridEnvelope env = envelope_deserialize(envelope_data);

    // Decode base64 fields
    std::vector<unsigned char> wrapped_key, iv, tag;
    try {
        wrapped_key = base64_decode(env.wrapped_key);
        iv          = base64_decode(env.iv);
        tag         = base64_decode(env.tag);
    } catch (const std::exception& e) {
        throw std::runtime_error(std::string("Envelope base64 decode error: ") + e.what());
    }

    // Validate sizes
    if (iv.size() != AES_GCM_IV_SIZE)
        throw std::runtime_error("Envelope IV size mismatch: expected 12 bytes");
    if (tag.size() != AES_GCM_TAG_SIZE)
        throw std::runtime_error("Envelope tag size mismatch: expected 16 bytes");

    // Verify RSA key size matches envelope
    int key_bits = EVP_PKEY_get_bits(priv_key);
    if (key_bits != env.rsa_modulus) {
        throw std::runtime_error(
            "Key size mismatch: envelope uses " + std::to_string(env.rsa_modulus) +
            "-bit RSA but provided key is " + std::to_string(key_bits) + "-bit"
        );
    }

    // Unwrap AES key with RSA-OAEP
    std::vector<unsigned char> aes_key;
    try {
        aes_key = rsa_oaep_decrypt(priv_key, wrapped_key, label);
    } catch (const std::exception& e) {
        throw std::runtime_error(
            std::string("RSA-OAEP key unwrap failed (wrong private key or wrong label): ") + e.what()
        );
    }

    if (aes_key.size() != AES_GCM_KEY_SIZE)
        throw std::runtime_error("Unwrapped AES key has wrong size");

    // Decrypt AES-GCM (throws on tag mismatch)
    std::vector<unsigned char> plaintext;
    try {
        plaintext = aes_gcm_decrypt(aes_key, iv, env.ciphertext, tag);
    } catch (const std::exception& e) {
        // Zero key on error
        std::fill(aes_key.begin(), aes_key.end(), 0);
        throw;
    }

    std::fill(aes_key.begin(), aes_key.end(), 0);
    return plaintext;
}
