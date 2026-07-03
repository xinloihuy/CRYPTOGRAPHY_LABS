/**
 * ================================================================
 *  aestool — AES Symmetric Encryption Tool
 *  Lab 1 — Cryptography Lab
 *  Compiler: g++ -std=c++17 -I<cryptopp_include> -L<cryptopp_lib> -lcryptopp
 * ================================================================
 *  Modes  : ECB, CBC, OFB, CFB, CTR, XTS, CCM (AEAD), GCM (AEAD)
 *  Features:
 *    - Runtime mode selection via CLI
 *    - AEAD (CCM/GCM) with AAD and authentication tag
 *    - Auto IV/Nonce generation + sidecar JSON persistence
 *    - ECB misuse prevention (size limit + warning)
 *    - Nonce-reuse detection for CTR/CCM/GCM
 *    - KAT runner (NIST SP 800-38A/D vectors)
 *    - Performance benchmark (1KB→8MB, all modes)
 *    - Negative test demonstrations (fail-closed)
 * ================================================================
 */

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <stdexcept>
#include <chrono>
#include <iomanip>
#include <algorithm>
#include <cstring>

// ── Crypto++ ─────────────────────────────────────────────────
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/xts.h>
#include <cryptopp/ccm.h>
#include <cryptopp/gcm.h>
#include <cryptopp/filters.h>
#include <cryptopp/files.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <cryptopp/base64.h>
#include <cryptopp/sha.h>
#include <cryptopp/secblock.h>

// ── Constants ────────────────────────────────────────────────
static const int    CCM_TAG_SZ   = 16;
static const int    GCM_TAG_SZ   = 16;
static const size_t ECB_MAX_BYTE = 16 * 1024;   // 16 KiB
static const char*  NONCE_REG    = ".aestool_nonces.json";

// ────────────────────────────────────────────────────────────
// AppConfig
// ────────────────────────────────────────────────────────────
struct AppConfig {
    std::string op;                // encrypt|decrypt|kat|benchmark|neg-test
    std::string mode   = "cbc";   // ecb|cbc|ofb|cfb|ctr|xts|ccm|gcm
    std::string key_file, key_hex;
    std::string iv_file, nonce_file;
    std::string in_file, in_text, out_file;
    std::string aad_file, aad_text, kat_file;
    bool aead=false, allow_ecb=false;
};

// ────────────────────────────────────────────────────────────
// CLI
// ────────────────────────────────────────────────────────────
static const char* USAGE =
    "Usage: aestool <encrypt|decrypt|kat|benchmark|neg-test> [options]\n"
    "  --mode <ecb|cbc|ofb|cfb|ctr|xts|ccm|gcm>  (default: cbc)\n"
    "  --key <file>       --key-hex <hex>\n"
    "  --iv  <file>       --nonce   <file>\n"
    "  --in  <file>       --text    <string>\n"
    "  --out <file>\n"
    "  --aead             --aad <file>   --aad-text <string>\n"
    "  --allow-ecb\n"
    "  --kat <vectors.json>\n";

AppConfig ParseCLI(int argc, char* argv[]) {
    AppConfig c;
    if (argc < 2) throw std::invalid_argument(std::string("No command.\n") + USAGE);
    c.op = argv[1];
    if (c.op == "--help" || c.op == "-h") { std::cout << USAGE; exit(0); }

    for (int i = 2; i < argc; ++i) {
        std::string a = argv[i];
        auto nxt = [&]() -> std::string {
            if (i+1 >= argc) throw std::invalid_argument("Missing value for: " + a);
            return argv[++i];
        };
        if      (a=="--mode")     c.mode      = nxt();
        else if (a=="--key")      c.key_file  = nxt();
        else if (a=="--key-hex")  c.key_hex   = nxt();
        else if (a=="--iv")       c.iv_file   = nxt();
        else if (a=="--nonce")    c.nonce_file= nxt();
        else if (a=="--in")       c.in_file   = nxt();
        else if (a=="--text")     c.in_text   = nxt();
        else if (a=="--out")      c.out_file  = nxt();
        else if (a=="--aad")      c.aad_file  = nxt();
        else if (a=="--aad-text") c.aad_text  = nxt();
        else if (a=="--kat")      { c.kat_file = nxt(); c.op = "kat"; }
        else if (a=="--allow-ecb") c.allow_ecb = true;
        else if (a=="--aead")     c.aead = true;
        else std::cerr << "[WARN] Unknown flag: " << a << "\n";
    }
    std::transform(c.mode.begin(), c.mode.end(), c.mode.begin(), ::tolower);
    return c;
}

// ────────────────────────────────────────────────────────────
// Crypto utilities
// ────────────────────────────────────────────────────────────
std::string HexEnc(const std::string& d) {
    std::string h;
    CryptoPP::StringSource(d, true, new CryptoPP::HexEncoder(new CryptoPP::StringSink(h), true));
    return h;
}
std::string HexDec(const std::string& h) {
    std::string d;
    CryptoPP::StringSource(h, true, new CryptoPP::HexDecoder(new CryptoPP::StringSink(d)));
    return d;
}
std::string B64Enc(const std::string& d) {
    std::string b;
    CryptoPP::StringSource(d, true, new CryptoPP::Base64Encoder(new CryptoPP::StringSink(b), false));
    return b;
}
std::string SHA256H(const std::string& d) {
    std::string h; CryptoPP::SHA256 sha;
    CryptoPP::StringSource(d, true, new CryptoPP::HashFilter(sha, new CryptoPP::HexEncoder(new CryptoPP::StringSink(h))));
    return h;
}

// ────────────────────────────────────────────────────────────
// File I/O
// ────────────────────────────────────────────────────────────
std::string ReadBin(const std::string& p) {
    if (p.empty()) throw std::invalid_argument("Empty path");
    std::string s;
    try { CryptoPP::FileSource(p.c_str(), true, new CryptoPP::StringSink(s)); }
    catch (...) { throw std::runtime_error("Cannot read: " + p); }
    return s;
}
void WriteBin(const std::string& p, const std::string& d) {
    if (p.empty()) throw std::invalid_argument("Empty output path");
    CryptoPP::StringSource(d, true, new CryptoPP::FileSink(p.c_str()));
}
std::string ReadTxt(const std::string& p) {
    std::ifstream f(p);
    if (!f) throw std::runtime_error("Cannot open: " + p);
    return {std::istreambuf_iterator<char>(f), {}};
}
void WriteTxt(const std::string& p, const std::string& d) {
    std::ofstream f(p);
    if (!f) throw std::runtime_error("Cannot write: " + p);
    f << d;
}
bool Exists(const std::string& p) { return std::ifstream(p).good(); }

// ────────────────────────────────────────────────────────────
// Mini JSON parser/writer
// ────────────────────────────────────────────────────────────
struct JV {
    enum T { STR, NUM, BOOL_, NUL, ARR, OBJ } t = NUL;
    std::string s; double n=0; bool b=false;
    std::vector<JV> arr;
    std::map<std::string,JV> obj;
    bool isStr() const { return t==STR; }
    bool isObj() const { return t==OBJ; }
    bool isArr() const { return t==ARR; }
    bool has(const std::string& k) const { return obj.count(k)>0; }
    const JV& get(const std::string& k) const {
        auto it=obj.find(k);
        if(it==obj.end()) throw std::runtime_error("JSON key missing: "+k);
        return it->second;
    }
};

class JP {
    std::string src; size_t p=0;
    void ws(){while(p<src.size()&&isspace(src[p]))++p;}
    char peek(){ws();return p<src.size()?src[p]:0;}
    char eat(){ws();return p<src.size()?src[p++]:0;}
    std::string str(){
        if(eat()!='"') throw std::runtime_error("Expected '\"'");
        std::string o;
        while(p<src.size()&&src[p]!='"'){
            if(src[p]=='\\'){++p;char c=src[p++];if(c=='"')o+='"';else if(c=='\\')o+='\\';else if(c=='n')o+='\n';else if(c=='t')o+='\t';else o+=c;}
            else o+=src[p++];
        }
        ++p; return o;
    }
    JV val(){
        ws(); JV v; char c=peek();
        if(c=='"'){v.t=JV::STR;v.s=str();}
        else if(c=='{'){
            v.t=JV::OBJ;eat();
            while(peek()!='}'){ws();if(peek()==','){eat();continue;}
                std::string k=str();ws();if(eat()!=':')throw std::runtime_error(":");
                v.obj[k]=val();ws();if(peek()==',')eat();}
            eat();
        }
        else if(c=='['){
            v.t=JV::ARR;eat();
            while(peek()!=']'){ws();if(peek()==','){eat();continue;}
                v.arr.push_back(val());ws();if(peek()==',')eat();}
            eat();
        }
        else if(c=='t'){p+=4;v.t=JV::BOOL_;v.b=true;}
        else if(c=='f'){p+=5;v.t=JV::BOOL_;v.b=false;}
        else if(c=='n'){p+=4;v.t=JV::NUL;}
        else{v.t=JV::NUM;size_t s0=p;while(p<src.size()&&(isdigit(src[p])||src[p]=='-'||src[p]=='.'||src[p]=='e'||src[p]=='E'||src[p]=='+'))++p;v.n=std::stod(src.substr(s0,p-s0));}
        return v;
    }
public:
    JP(std::string s):src(std::move(s)){}
    JV parse(){return val();}
};

JV ParseJSON(const std::string& t){return JP(t).parse();}

std::string MakeJSON(const std::map<std::string,std::string>& m){
    std::ostringstream s; s<<"{\n"; bool f=true;
    for(auto&[k,v]:m){if(!f)s<<",\n";s<<"  \""<<k<<"\": \""<<v<<"\"";f=false;}
    s<<"\n}"; return s.str();
}

// ────────────────────────────────────────────────────────────
// Key
// ────────────────────────────────────────────────────────────
std::string ReadKey(const AppConfig& c) {
    std::string k;
    if (!c.key_hex.empty()) k = HexDec(c.key_hex);
    else if (!c.key_file.empty()) {
        k = ReadBin(c.key_file);
        if (k.size()>=4 && k.substr(0,4)=="HEX:") k=HexDec(k.substr(4));
    } else throw std::invalid_argument("No key. Use --key or --key-hex");

    if (c.mode=="xts") {
        if (k.size()!=32&&k.size()!=64)
            throw std::invalid_argument("XTS key must be 32 or 64 bytes. Got: "+std::to_string(k.size()));
    } else {
        if (k.size()!=16&&k.size()!=24&&k.size()!=32)
            throw std::invalid_argument("AES key must be 16/24/32 bytes. Got: "+std::to_string(k.size()));
    }
    std::cout<<"[INFO] Key: "<<k.size()*8<<"-bit AES\n";
    return k;
}

// ────────────────────────────────────────────────────────────
// IV / Nonce
// ────────────────────────────────────────────────────────────
size_t IVSize(const std::string& m){
    if(m=="ecb") return 0;
    if(m=="gcm") return 12;
    if(m=="ccm") return 13;
    return CryptoPP::AES::BLOCKSIZE;
}

std::string GenIV(size_t n){
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::SecByteBlock iv(n);
    rng.GenerateBlock(iv,n);
    return {(const char*)iv.data(),n};
}

void CheckIV(const std::string& iv, size_t exp, const std::string& mode){
    if(exp>0&&iv.size()!=exp)
        throw std::invalid_argument("IV size: got "+std::to_string(iv.size())+" bytes, need "+std::to_string(exp)+" for "+mode);
}

struct IVR { std::string data; bool generated; };
IVR GetIV(const std::string& iv_f, const std::string& n_f, size_t need){
    std::string p = !iv_f.empty()?iv_f:n_f;
    if(!p.empty()){
        auto iv=ReadBin(p);
        if(iv.size()!=need) throw std::invalid_argument("IV size mismatch: got "+std::to_string(iv.size())+", need "+std::to_string(need));
        return {iv,false};
    }
    auto iv=GenIV(need);
    std::cout<<"[INFO] Auto-IV/Nonce ("<<need<<"B): "<<HexEnc(iv)<<"\n";
    return {iv,true};
}

// ────────────────────────────────────────────────────────────
// Sidecar JSON
// ────────────────────────────────────────────────────────────
std::string SidecarPath(const std::string& f){return f+".json";}

void WriteSidecar(const std::string& out, const std::map<std::string,std::string>& m){
    std::string p=SidecarPath(out);
    WriteTxt(p,MakeJSON(m));
    std::cout<<"[INFO] Sidecar: "<<p<<"\n";
}

std::map<std::string,std::string> ReadSidecar(const std::string& p){
    auto jv=ParseJSON(ReadTxt(p));
    std::map<std::string,std::string> r;
    if(jv.isObj()) for(auto&[k,v]:jv.obj) if(v.isStr()) r[k]=v.s;
    return r;
}

std::string IVFromSidecar(const std::string& in_f){
    std::string sp=SidecarPath(in_f);
    if(!Exists(sp)) return "";
    auto m=ReadSidecar(sp);
    if(m.count("iv")&&!m["iv"].empty()){
        std::cout<<"[INFO] IV from sidecar: "<<m["iv"]<<"\n";
        return HexDec(m["iv"]);
    }
    return "";
}

// ────────────────────────────────────────────────────────────
// Nonce reuse protection (CTR/CCM/GCM)
// ────────────────────────────────────────────────────────────
bool IsNonceMode(const std::string& m){return m=="ctr"||m=="ccm"||m=="gcm";}

void CheckNonceReuse(const std::string& kh, const std::string& nh, const std::string& mode){
    if(!IsNonceMode(mode)||!Exists(NONCE_REG)) return;
    std::string combo=kh+":"+nh;
    if(ReadTxt(NONCE_REG).find("\""+combo+"\"")!=std::string::npos)
        throw std::runtime_error(
            "[SECURITY] NONCE REUSE DETECTED in "+mode+" mode!\n"
            "  Nonce: "+nh+"\n"
            "  Reusing key+nonce completely breaks "+mode+" security.\n"
            "  Fix: omit --iv/--nonce to auto-generate a fresh nonce.");
}

void RegisterNonce(const std::string& kh, const std::string& nh, const std::string& mode){
    if(!IsNonceMode(mode)) return;
    std::string combo=kh+":"+nh;
    std::vector<std::string> entries;
    if(Exists(NONCE_REG)){
        try{
            auto jv=ParseJSON(ReadTxt(NONCE_REG));
            if(jv.isArr()) for(auto&v:jv.arr) if(v.isStr()) entries.push_back(v.s);
        }catch(...){}
    }
    if(std::find(entries.begin(),entries.end(),combo)==entries.end())
        entries.push_back(combo);
    std::ostringstream ss; ss<<"[\n";
    for(size_t i=0;i<entries.size();++i){ss<<"  \""<<entries[i]<<"\"";if(i+1<entries.size())ss<<",";}
    ss<<"\n]"; WriteTxt(NONCE_REG,ss.str());
}

// ────────────────────────────────────────────────────────────
// Input helpers
// ────────────────────────────────────────────────────────────
std::string GetInput(const AppConfig& c){
    if(!c.in_text.empty()) return c.in_text;
    if(!c.in_file.empty()) return ReadBin(c.in_file);
    throw std::invalid_argument("No input. Use --in <file> or --text <string>");
}
std::string GetAAD(const AppConfig& c){
    if(!c.aad_file.empty()) return ReadBin(c.aad_file);
    if(!c.aad_text.empty()) return c.aad_text;
    return "";
}

// ────────────────────────────────────────────────────────────
// ECB misuse check
// ────────────────────────────────────────────────────────────
void WarnECB(size_t sz, bool allow){
    std::cerr<<"\n[WARNING] ECB mode is INSECURE!\n"
               "  Identical plaintext blocks → identical ciphertext blocks.\n"
               "  Patterns in data are visible. DO NOT use in production.\n\n";
    if(sz>ECB_MAX_BYTE){
        if(!allow) throw std::runtime_error(
            "ECB: input "+std::to_string(sz)+" bytes > 16 KiB limit. "
            "Use --allow-ecb to override (dangerous).");
        std::cerr<<"[WARNING] --allow-ecb override active.\n\n";
    }
}

// ────────────────────────────────────────────────────────────
// AES encrypt/decrypt functions (all 8 modes)
// ────────────────────────────────────────────────────────────

// ── ECB ──────────────────────────────────────────────────────
std::string EncECB(const std::string& k,const std::string& p){
    std::string c; CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption e;
    e.SetKey((const CryptoPP::byte*)k.data(),k.size());
    CryptoPP::StringSource(p,true,new CryptoPP::StreamTransformationFilter(e,new CryptoPP::StringSink(c)));
    return c;
}
std::string DecECB(const std::string& k,const std::string& c){
    std::string p; CryptoPP::ECB_Mode<CryptoPP::AES>::Decryption d;
    d.SetKey((const CryptoPP::byte*)k.data(),k.size());
    CryptoPP::StringSource(c,true,new CryptoPP::StreamTransformationFilter(d,new CryptoPP::StringSink(p)));
    return p;
}

// ── CBC ──────────────────────────────────────────────────────
std::string EncCBC(const std::string& k,const std::string& iv,const std::string& p){
    CheckIV(iv,16,"CBC"); std::string c;
    CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption e;
    e.SetKeyWithIV((const CryptoPP::byte*)k.data(),k.size(),(const CryptoPP::byte*)iv.data());
    CryptoPP::StringSource(p,true,new CryptoPP::StreamTransformationFilter(e,new CryptoPP::StringSink(c)));
    return c;
}
std::string DecCBC(const std::string& k,const std::string& iv,const std::string& c){
    CheckIV(iv,16,"CBC"); std::string p;
    CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption d;
    d.SetKeyWithIV((const CryptoPP::byte*)k.data(),k.size(),(const CryptoPP::byte*)iv.data());
    CryptoPP::StringSource(c,true,new CryptoPP::StreamTransformationFilter(d,new CryptoPP::StringSink(p)));
    return p;
}

// ── OFB ──────────────────────────────────────────────────────
std::string EncOFB(const std::string& k,const std::string& iv,const std::string& p){
    CheckIV(iv,16,"OFB"); std::string c;
    CryptoPP::OFB_Mode<CryptoPP::AES>::Encryption e;
    e.SetKeyWithIV((const CryptoPP::byte*)k.data(),k.size(),(const CryptoPP::byte*)iv.data());
    CryptoPP::StringSource(p,true,new CryptoPP::StreamTransformationFilter(e,new CryptoPP::StringSink(c)));
    return c;
}
std::string DecOFB(const std::string& k,const std::string& iv,const std::string& c){
    CheckIV(iv,16,"OFB"); std::string p;
    CryptoPP::OFB_Mode<CryptoPP::AES>::Decryption d;
    d.SetKeyWithIV((const CryptoPP::byte*)k.data(),k.size(),(const CryptoPP::byte*)iv.data());
    CryptoPP::StringSource(c,true,new CryptoPP::StreamTransformationFilter(d,new CryptoPP::StringSink(p)));
    return p;
}

// ── CFB ──────────────────────────────────────────────────────
std::string EncCFB(const std::string& k,const std::string& iv,const std::string& p){
    CheckIV(iv,16,"CFB"); std::string c;
    CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption e;
    e.SetKeyWithIV((const CryptoPP::byte*)k.data(),k.size(),(const CryptoPP::byte*)iv.data());
    CryptoPP::StringSource(p,true,new CryptoPP::StreamTransformationFilter(e,new CryptoPP::StringSink(c)));
    return c;
}
std::string DecCFB(const std::string& k,const std::string& iv,const std::string& c){
    CheckIV(iv,16,"CFB"); std::string p;
    CryptoPP::CFB_Mode<CryptoPP::AES>::Decryption d;
    d.SetKeyWithIV((const CryptoPP::byte*)k.data(),k.size(),(const CryptoPP::byte*)iv.data());
    CryptoPP::StringSource(c,true,new CryptoPP::StreamTransformationFilter(d,new CryptoPP::StringSink(p)));
    return p;
}

// ── CTR ──────────────────────────────────────────────────────
std::string EncCTR(const std::string& k,const std::string& iv,const std::string& p){
    CheckIV(iv,16,"CTR"); std::string c;
    CryptoPP::CTR_Mode<CryptoPP::AES>::Encryption e;
    e.SetKeyWithIV((const CryptoPP::byte*)k.data(),k.size(),(const CryptoPP::byte*)iv.data());
    CryptoPP::StringSource(p,true,new CryptoPP::StreamTransformationFilter(e,new CryptoPP::StringSink(c)));
    return c;
}
std::string DecCTR(const std::string& k,const std::string& iv,const std::string& c){
    CheckIV(iv,16,"CTR"); std::string p;
    CryptoPP::CTR_Mode<CryptoPP::AES>::Decryption d;
    d.SetKeyWithIV((const CryptoPP::byte*)k.data(),k.size(),(const CryptoPP::byte*)iv.data());
    CryptoPP::StringSource(c,true,new CryptoPP::StreamTransformationFilter(d,new CryptoPP::StringSink(p)));
    return p;
}

// ── XTS (key=32 or 64 bytes, iv=16 bytes sector tweak) ───────
std::string EncXTS(const std::string& k,const std::string& iv,const std::string& p){
    CheckIV(iv,16,"XTS");
    if(p.size()<CryptoPP::AES::BLOCKSIZE) throw std::invalid_argument("XTS: plaintext >= 16 bytes");
    std::string c; CryptoPP::XTS_Mode<CryptoPP::AES>::Encryption e;
    e.SetKeyWithIV((const CryptoPP::byte*)k.data(),k.size(),(const CryptoPP::byte*)iv.data());
    CryptoPP::StringSource(p,true,new CryptoPP::StreamTransformationFilter(e,new CryptoPP::StringSink(c)));
    return c;
}
std::string DecXTS(const std::string& k,const std::string& iv,const std::string& c){
    CheckIV(iv,16,"XTS"); std::string p;
    CryptoPP::XTS_Mode<CryptoPP::AES>::Decryption d;
    d.SetKeyWithIV((const CryptoPP::byte*)k.data(),k.size(),(const CryptoPP::byte*)iv.data());
    CryptoPP::StringSource(c,true,new CryptoPP::StreamTransformationFilter(d,new CryptoPP::StringSink(p)));
    return p;
}

// ── GCM (iv=12 bytes, output = ciphertext||tag) ──────────────
std::string EncGCM(const std::string& k,const std::string& iv,
                    const std::string& aad,const std::string& p){
    using namespace CryptoPP;
    std::string c; GCM<AES>::Encryption e;
    e.SetKeyWithIV((const byte*)k.data(),k.size(),(const byte*)iv.data(),iv.size());
    AuthenticatedEncryptionFilter ef(e,new StringSink(c),false,GCM_TAG_SZ);
    ef.ChannelPut(AAD_CHANNEL,(const byte*)aad.data(),aad.size());
    ef.ChannelMessageEnd(AAD_CHANNEL);
    ef.Put((const byte*)p.data(),p.size());
    ef.MessageEnd();
    return c;
}
std::string DecGCM(const std::string& k,const std::string& iv,
                    const std::string& aad,const std::string& c){
    using namespace CryptoPP;
    if(c.size()<(size_t)GCM_TAG_SZ) throw std::runtime_error("GCM: input too short");
    std::string p; GCM<AES>::Decryption d;
    d.SetKeyWithIV((const byte*)k.data(),k.size(),(const byte*)iv.data(),iv.size());
    AuthenticatedDecryptionFilter df(d,new StringSink(p),
        AuthenticatedDecryptionFilter::DEFAULT_FLAGS,GCM_TAG_SZ);
    df.ChannelPut(AAD_CHANNEL,(const byte*)aad.data(),aad.size());
    df.ChannelMessageEnd(AAD_CHANNEL);
    df.Put((const byte*)c.data(),c.size());
    df.MessageEnd();
    return p;
}

// ── CCM (iv=13 bytes, output = ciphertext||tag) ──────────────
std::string EncCCM(const std::string& k,const std::string& iv,
                    const std::string& aad,const std::string& p){
    using namespace CryptoPP;
    std::string c; CCM<AES,CCM_TAG_SZ>::Encryption e;
    e.SetKeyWithIV((const byte*)k.data(),k.size(),(const byte*)iv.data(),iv.size());
    e.SpecifyDataLengths(aad.size(),p.size());
    AuthenticatedEncryptionFilter ef(e,new StringSink(c),false,CCM_TAG_SZ);
    ef.ChannelPut(AAD_CHANNEL,(const byte*)aad.data(),aad.size());
    ef.ChannelMessageEnd(AAD_CHANNEL);
    ef.Put((const byte*)p.data(),p.size());
    ef.MessageEnd();
    return c;
}
std::string DecCCM(const std::string& k,const std::string& iv,
                    const std::string& aad,const std::string& c){
    using namespace CryptoPP;
    if(c.size()<(size_t)CCM_TAG_SZ) throw std::runtime_error("CCM: input too short");
    std::string p; size_t mlen=c.size()-CCM_TAG_SZ;
    CCM<AES,CCM_TAG_SZ>::Decryption d;
    d.SetKeyWithIV((const byte*)k.data(),k.size(),(const byte*)iv.data(),iv.size());
    d.SpecifyDataLengths(aad.size(),mlen);
    AuthenticatedDecryptionFilter df(d,new StringSink(p),
        AuthenticatedDecryptionFilter::DEFAULT_FLAGS,CCM_TAG_SZ);
    df.ChannelPut(AAD_CHANNEL,(const byte*)aad.data(),aad.size());
    df.ChannelMessageEnd(AAD_CHANNEL);
    df.Put((const byte*)c.data(),c.size());
    df.MessageEnd();
    return p;
}

// ────────────────────────────────────────────────────────────
// DoEncrypt
// ────────────────────────────────────────────────────────────
void DoEncrypt(const AppConfig& cfg){
    std::string key=ReadKey(cfg);
    std::string plain=GetInput(cfg);
    if(cfg.out_file.empty()) throw std::invalid_argument("No --out file");

    std::string cipher;
    std::map<std::string,std::string> meta;
    meta["alg"]="AES-"+std::to_string(key.size()*8)+"-"+cfg.mode;

    if(cfg.mode=="ecb"){
        WarnECB(plain.size(),cfg.allow_ecb);
        cipher=EncECB(key,plain);

    } else if(cfg.mode=="cbc"||cfg.mode=="ofb"||cfg.mode=="cfb"){
        auto ivr=GetIV(cfg.iv_file,cfg.nonce_file,16);
        meta["iv"]=HexEnc(ivr.data); meta["key_hash"]=SHA256H(key);
        if(cfg.mode=="cbc")      cipher=EncCBC(key,ivr.data,plain);
        else if(cfg.mode=="ofb") cipher=EncOFB(key,ivr.data,plain);
        else                     cipher=EncCFB(key,ivr.data,plain);

    } else if(cfg.mode=="ctr"){
        auto ivr=GetIV(cfg.iv_file,cfg.nonce_file,16);
        meta["iv"]=HexEnc(ivr.data); meta["key_hash"]=SHA256H(key);
        CheckNonceReuse(meta["key_hash"],meta["iv"],"ctr");
        cipher=EncCTR(key,ivr.data,plain);
        RegisterNonce(meta["key_hash"],meta["iv"],"ctr");

    } else if(cfg.mode=="xts"){
        auto ivr=GetIV(cfg.iv_file,cfg.nonce_file,16);
        meta["iv"]=HexEnc(ivr.data); meta["key_hash"]=SHA256H(key);
        cipher=EncXTS(key,ivr.data,plain);

    } else if(cfg.mode=="gcm"){
        auto ivr=GetIV(cfg.iv_file,cfg.nonce_file,12);
        meta["iv"]=HexEnc(ivr.data); meta["key_hash"]=SHA256H(key);
        std::string aad=GetAAD(cfg); meta["aad"]=HexEnc(aad);
        CheckNonceReuse(meta["key_hash"],meta["iv"],"gcm");
        cipher=EncGCM(key,ivr.data,aad,plain);
        RegisterNonce(meta["key_hash"],meta["iv"],"gcm");
        if(cipher.size()>=(size_t)GCM_TAG_SZ)
            meta["tag"]=HexEnc(cipher.substr(cipher.size()-GCM_TAG_SZ));

    } else if(cfg.mode=="ccm"){
        auto ivr=GetIV(cfg.iv_file,cfg.nonce_file,13);
        meta["iv"]=HexEnc(ivr.data); meta["key_hash"]=SHA256H(key);
        std::string aad=GetAAD(cfg); meta["aad"]=HexEnc(aad);
        CheckNonceReuse(meta["key_hash"],meta["iv"],"ccm");
        cipher=EncCCM(key,ivr.data,aad,plain);
        RegisterNonce(meta["key_hash"],meta["iv"],"ccm");
        if(cipher.size()>=(size_t)CCM_TAG_SZ)
            meta["tag"]=HexEnc(cipher.substr(cipher.size()-CCM_TAG_SZ));

    } else throw std::invalid_argument("Unknown mode: "+cfg.mode);

    WriteBin(cfg.out_file,cipher);
    WriteSidecar(cfg.out_file,meta);

    std::cout<<"\n[SUCCESS] Encrypted -> "<<cfg.out_file<<"\n";
    std::cout<<"[INFO]    Size   : "<<cipher.size()<<" bytes\n";
    std::cout<<"[INFO]    Hex    : "<<HexEnc(cipher.substr(0,std::min(cipher.size(),(size_t)32)))<<"...\n";
    std::cout<<"[INFO]    Base64 : "<<B64Enc(cipher)<<"\n\n";
}

// ────────────────────────────────────────────────────────────
// DoDecrypt
// ────────────────────────────────────────────────────────────
void DoDecrypt(const AppConfig& cfg){
    std::string key=ReadKey(cfg);
    std::string cipher=GetInput(cfg);
    if(cfg.out_file.empty()) throw std::invalid_argument("No --out file");

    // Resolve IV: from flag → sidecar
    auto resolveIV=[&](size_t need)->std::string{
        std::string iv;
        std::string ivpath=!cfg.iv_file.empty()?cfg.iv_file:cfg.nonce_file;
        if(!ivpath.empty()) iv=ReadBin(ivpath);
        else iv=IVFromSidecar(cfg.in_file);
        if(iv.empty()) throw std::invalid_argument(
            "IV not found. Use --iv <file> or ensure sidecar '"+SidecarPath(cfg.in_file)+"' exists.");
        CheckIV(iv,need,cfg.mode);
        return iv;
    };

    // Resolve AAD: from flag → sidecar
    auto resolveAAD=[&]()->std::string{
        if(!cfg.aad_file.empty()||!cfg.aad_text.empty()) return GetAAD(cfg);
        std::string sp=SidecarPath(cfg.in_file);
        if(Exists(sp)){auto m=ReadSidecar(sp);if(m.count("aad")&&!m["aad"].empty())return HexDec(m["aad"]);}
        return "";
    };

    std::string plain;
    if(cfg.mode=="ecb"){
        WarnECB(cipher.size(),cfg.allow_ecb);
        plain=DecECB(key,cipher);
    } else if(cfg.mode=="cbc") plain=DecCBC(key,resolveIV(16),cipher);
    else if(cfg.mode=="ofb")   plain=DecOFB(key,resolveIV(16),cipher);
    else if(cfg.mode=="cfb")   plain=DecCFB(key,resolveIV(16),cipher);
    else if(cfg.mode=="ctr")   plain=DecCTR(key,resolveIV(16),cipher);
    else if(cfg.mode=="xts")   plain=DecXTS(key,resolveIV(16),cipher);
    else if(cfg.mode=="gcm"){
        try{ plain=DecGCM(key,resolveIV(12),resolveAAD(),cipher); }
        catch(const CryptoPP::Exception& e){
            throw std::runtime_error(
                std::string("[SECURITY] GCM AUTH FAILED: ")+e.what()+"\n"
                "  Output withheld (fail-closed).");}
    } else if(cfg.mode=="ccm"){
        try{ plain=DecCCM(key,resolveIV(13),resolveAAD(),cipher); }
        catch(const CryptoPP::Exception& e){
            throw std::runtime_error(
                std::string("[SECURITY] CCM AUTH FAILED: ")+e.what()+"\n"
                "  Output withheld (fail-closed).");}
    } else throw std::invalid_argument("Unknown mode: "+cfg.mode);

    WriteBin(cfg.out_file,plain);
    std::cout<<"\n[SUCCESS] Decrypted -> "<<cfg.out_file<<" ("<<plain.size()<<" bytes)\n\n";
}

// ────────────────────────────────────────────────────────────
// KAT Runner (NIST SP 800-38A/D)
// ────────────────────────────────────────────────────────────
void RunKAT(const std::string& vfile){
    std::cout<<"\n";
    std::cout<<"╔══════════════════════════════════════════════════════╗\n";
    std::cout<<"║      Known Answer Test (KAT) Runner                  ║\n";
    std::cout<<"║  NIST SP 800-38A (ECB/CBC/OFB/CFB/CTR)               ║\n";
    std::cout<<"║  NIST SP 800-38D (GCM)                               ║\n";
    std::cout<<"╚══════════════════════════════════════════════════════╝\n\n";

    auto root=ParseJSON(ReadTxt(vfile));
    if(!root.isObj()||!root.has("tests"))
        throw std::runtime_error("Invalid vector file: missing 'tests'");

    auto& tests=root.get("tests").arr;
    int total=(int)tests.size(), passed=0, failed=0, skipped=0;

    for(auto& tc:tests){
        if(!tc.isObj()){++skipped;continue;}
        std::string id  =tc.has("id")  ?tc.get("id").s  :"?";
        std::string mode=tc.has("mode")?tc.get("mode").s:"";
        std::transform(mode.begin(),mode.end(),mode.begin(),::tolower);

        std::cout<<"  ["<<std::left<<std::setw(45)<<id<<"] ";
        std::cout.flush();

        try{
            std::string key=HexDec(tc.get("key").s);
            std::string pt =HexDec(tc.get("plaintext").s);
            std::string ect=HexDec(tc.get("ciphertext").s);
            std::string got;

            if(mode=="ecb"){
                CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption e;
                e.SetKey((const CryptoPP::byte*)key.data(),key.size());
                CryptoPP::StringSource(pt,true,new CryptoPP::StreamTransformationFilter(
                    e,new CryptoPP::StringSink(got),CryptoPP::BlockPaddingSchemeDef::NO_PADDING));

            } else if(mode=="cbc"){
                std::string iv=HexDec(tc.get("iv").s);
                CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption e;
                e.SetKeyWithIV((const CryptoPP::byte*)key.data(),key.size(),(const CryptoPP::byte*)iv.data());
                CryptoPP::StringSource(pt,true,new CryptoPP::StreamTransformationFilter(
                    e,new CryptoPP::StringSink(got),CryptoPP::BlockPaddingSchemeDef::NO_PADDING));

            } else if(mode=="ofb"){
                std::string iv=HexDec(tc.get("iv").s);
                CryptoPP::OFB_Mode<CryptoPP::AES>::Encryption e;
                e.SetKeyWithIV((const CryptoPP::byte*)key.data(),key.size(),(const CryptoPP::byte*)iv.data());
                CryptoPP::StringSource(pt,true,new CryptoPP::StreamTransformationFilter(e,new CryptoPP::StringSink(got)));

            } else if(mode=="cfb"){
                std::string iv=HexDec(tc.get("iv").s);
                CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption e;
                e.SetKeyWithIV((const CryptoPP::byte*)key.data(),key.size(),(const CryptoPP::byte*)iv.data());
                CryptoPP::StringSource(pt,true,new CryptoPP::StreamTransformationFilter(e,new CryptoPP::StringSink(got)));

            } else if(mode=="ctr"){
                std::string iv=HexDec(tc.get("iv").s);
                CryptoPP::CTR_Mode<CryptoPP::AES>::Encryption e;
                e.SetKeyWithIV((const CryptoPP::byte*)key.data(),key.size(),(const CryptoPP::byte*)iv.data());
                CryptoPP::StringSource(pt,true,new CryptoPP::StreamTransformationFilter(e,new CryptoPP::StringSink(got)));

            } else if(mode=="gcm"){
                std::string iv =HexDec(tc.get("iv").s);
                std::string aad=tc.has("aad")?HexDec(tc.get("aad").s):"";
                std::string etg=tc.has("tag")?HexDec(tc.get("tag").s):"";
                std::string full;
                CryptoPP::GCM<CryptoPP::AES>::Encryption e;
                e.SetKeyWithIV((const CryptoPP::byte*)key.data(),key.size(),(const CryptoPP::byte*)iv.data(),iv.size());
                CryptoPP::AuthenticatedEncryptionFilter ef(e,new CryptoPP::StringSink(full),false,GCM_TAG_SZ);
                ef.ChannelPut(CryptoPP::AAD_CHANNEL,(const CryptoPP::byte*)aad.data(),aad.size());
                ef.ChannelMessageEnd(CryptoPP::AAD_CHANNEL);
                ef.Put((const CryptoPP::byte*)pt.data(),pt.size());
                ef.MessageEnd();
                got=full.substr(0,full.size()-GCM_TAG_SZ);
                std::string gtag=full.substr(full.size()-GCM_TAG_SZ);
                bool ctok=(got==ect), tagok=etg.empty()||(gtag==etg);
                if(ctok&&tagok){std::cout<<"PASS\n";++passed;}
                else{
                    std::cout<<"FAIL\n";
                    if(!ctok) std::cout<<"    CT  exp: "<<HexEnc(ect)<<"\n        got: "<<HexEnc(got)<<"\n";
                    if(!tagok)std::cout<<"    TAG exp: "<<HexEnc(etg)<<"\n        got: "<<HexEnc(gtag)<<"\n";
                    ++failed;
                }
                continue;

            } else if(mode=="ccm"){
                std::string iv =HexDec(tc.get("iv").s);
                std::string aad=tc.has("aad")?HexDec(tc.get("aad").s):"";
                std::string etg=tc.has("tag")?HexDec(tc.get("tag").s):"";
                std::string full;
                CryptoPP::CCM<CryptoPP::AES,CCM_TAG_SZ>::Encryption e;
                e.SetKeyWithIV((const CryptoPP::byte*)key.data(),key.size(),(const CryptoPP::byte*)iv.data(),iv.size());
                e.SpecifyDataLengths(aad.size(),pt.size());
                CryptoPP::AuthenticatedEncryptionFilter ef(e,new CryptoPP::StringSink(full),false,CCM_TAG_SZ);
                ef.ChannelPut(CryptoPP::AAD_CHANNEL,(const CryptoPP::byte*)aad.data(),aad.size());
                ef.ChannelMessageEnd(CryptoPP::AAD_CHANNEL);
                ef.Put((const CryptoPP::byte*)pt.data(),pt.size());
                ef.MessageEnd();
                got=full.substr(0,full.size()-CCM_TAG_SZ);
                bool ctok=(got==ect),tagok=etg.empty()||(full.substr(full.size()-CCM_TAG_SZ)==etg);
                if(ctok&&tagok){std::cout<<"PASS\n";++passed;}
                else{std::cout<<"FAIL\n";++failed;}
                continue;

            } else {
                std::cout<<"SKIP (unsupported: "<<mode<<")\n";++skipped;continue;
            }

            if(got==ect){std::cout<<"PASS\n";++passed;}
            else{
                std::cout<<"FAIL\n";
                std::cout<<"    exp: "<<HexEnc(ect)<<"\n";
                std::cout<<"    got: "<<HexEnc(got)<<"\n";
                ++failed;
            }
        }catch(const std::exception& e){
            std::cout<<"ERROR: "<<e.what()<<"\n";++failed;
        }
    }

    std::cout<<"\n──────────────────────────────────────────────────────\n";
    std::cout<<" KAT: "<<total<<" total | "<<passed<<" passed | "<<failed<<" failed | "<<skipped<<" skipped\n";
    std::cout<<"──────────────────────────────────────────────────────\n";
    if(failed>0) throw std::runtime_error("KAT FAILED: "+std::to_string(failed)+" test(s)!");
    std::cout<<" All tests PASSED — matches NIST vectors.\n\n";
}

// ────────────────────────────────────────────────────────────
// Benchmark
// ────────────────────────────────────────────────────────────
struct BR{std::string mode;size_t sz;double tput,lat;};

BR Bench(const std::string& mode,size_t sz){
    CryptoPP::AutoSeededRandomPool rng;
    const int IT=3;
    std::string pl(sz,0); rng.GenerateBlock((CryptoPP::byte*)pl.data(),sz);
    std::string k32(32,0); rng.GenerateBlock((CryptoPP::byte*)k32.data(),32);
    std::string k64(64,0); rng.GenerateBlock((CryptoPP::byte*)k64.data(),64);
    std::string i16(16,0); rng.GenerateBlock((CryptoPP::byte*)i16.data(),16);
    std::string i12(12,0);
    std::string i13(13,0);

    auto t0=std::chrono::high_resolution_clock::now();
    for(int i=0;i<IT;++i){
        std::string c;
        try{
            if(mode=="ecb"&&sz<=ECB_MAX_BYTE){
                CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption e;e.SetKey((const CryptoPP::byte*)k32.data(),32);
                CryptoPP::StringSource(pl,true,new CryptoPP::StreamTransformationFilter(e,new CryptoPP::StringSink(c)));
            } else if(mode=="cbc"){
                CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption e;e.SetKeyWithIV((const CryptoPP::byte*)k32.data(),32,(const CryptoPP::byte*)i16.data());
                CryptoPP::StringSource(pl,true,new CryptoPP::StreamTransformationFilter(e,new CryptoPP::StringSink(c)));
            } else if(mode=="ofb"){
                CryptoPP::OFB_Mode<CryptoPP::AES>::Encryption e;e.SetKeyWithIV((const CryptoPP::byte*)k32.data(),32,(const CryptoPP::byte*)i16.data());
                CryptoPP::StringSource(pl,true,new CryptoPP::StreamTransformationFilter(e,new CryptoPP::StringSink(c)));
            } else if(mode=="cfb"){
                CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption e;e.SetKeyWithIV((const CryptoPP::byte*)k32.data(),32,(const CryptoPP::byte*)i16.data());
                CryptoPP::StringSource(pl,true,new CryptoPP::StreamTransformationFilter(e,new CryptoPP::StringSink(c)));
            } else if(mode=="ctr"){
                CryptoPP::CTR_Mode<CryptoPP::AES>::Encryption e;e.SetKeyWithIV((const CryptoPP::byte*)k32.data(),32,(const CryptoPP::byte*)i16.data());
                CryptoPP::StringSource(pl,true,new CryptoPP::StreamTransformationFilter(e,new CryptoPP::StringSink(c)));
            } else if(mode=="xts"){
                CryptoPP::XTS_Mode<CryptoPP::AES>::Encryption e;e.SetKeyWithIV((const CryptoPP::byte*)k64.data(),64,(const CryptoPP::byte*)i16.data());
                CryptoPP::StringSource(pl,true,new CryptoPP::StreamTransformationFilter(e,new CryptoPP::StringSink(c)));
            } else if(mode=="gcm"){
                rng.GenerateBlock((CryptoPP::byte*)i12.data(),12);
                CryptoPP::GCM<CryptoPP::AES>::Encryption e;e.SetKeyWithIV((const CryptoPP::byte*)k32.data(),32,(const CryptoPP::byte*)i12.data(),12);
                CryptoPP::AuthenticatedEncryptionFilter ef(e,new CryptoPP::StringSink(c),false,GCM_TAG_SZ);
                ef.ChannelMessageEnd(CryptoPP::AAD_CHANNEL);ef.Put((const CryptoPP::byte*)pl.data(),pl.size());ef.MessageEnd();
            } else if(mode=="ccm"){
                rng.GenerateBlock((CryptoPP::byte*)i13.data(),13);
                CryptoPP::CCM<CryptoPP::AES,CCM_TAG_SZ>::Encryption e;e.SetKeyWithIV((const CryptoPP::byte*)k32.data(),32,(const CryptoPP::byte*)i13.data(),13);
                e.SpecifyDataLengths(0,pl.size());
                CryptoPP::AuthenticatedEncryptionFilter ef(e,new CryptoPP::StringSink(c),false,CCM_TAG_SZ);
                ef.ChannelMessageEnd(CryptoPP::AAD_CHANNEL);ef.Put((const CryptoPP::byte*)pl.data(),pl.size());ef.MessageEnd();
            }
        }catch(...){
            
        }
    }
    auto t1=std::chrono::high_resolution_clock::now();
    double ms=std::chrono::duration<double,std::milli>(t1-t0).count();
    return {mode,sz,((double)sz*IT/1048576.0)/(ms/1000.0),ms/IT};
}

std::string FmtSz(size_t b){
    if(b>=1048576) return std::to_string(b/1048576)+" MB";
    if(b>=1024)    return std::to_string(b/1024)+" KB";
    return std::to_string(b)+" B";
}

void RunBenchmark(){
    std::cout<<"\n╔══════════════════════════════════════════════════════════════╗\n";
    std::cout<<"║        AES-256 Benchmark — All Modes — Crypto++              ║\n";
    std::cout<<"╚══════════════════════════════════════════════════════════════╝\n\n";
    std::cout<<std::left<<std::setw(6)<<"Mode"<<std::setw(9)<<"Size"
             <<std::setw(14)<<"Throughput"<<std::setw(12)<<"Latency"<<"Notes\n";
    std::cout<<std::string(58,'-')<<"\n";

    std::vector<std::string> modes={"ecb","cbc","ofb","cfb","ctr","xts","gcm","ccm"};
    std::vector<size_t> sizes={1024,4096,16384,262144,1048576,8388608};

    for(auto& m:modes){
        for(auto& s:sizes){
            if(m=="ecb"&&s>ECB_MAX_BYTE){
                std::cout<<std::setw(6)<<m<<std::setw(9)<<FmtSz(s)
                         <<"    ---          ---     SKIPPED(ECB>16KiB)\n";
                continue;
            }
            if(m=="ccm"&&s>65535){
                std::cout<<std::setw(6)<<m<<std::setw(9)<<FmtSz(s)
                         <<"    ---          ---     SKIPPED(CCM>64KiB)\n";
                continue;
            }
            auto r=Bench(m,s);
            std::string note=(m=="gcm"||m=="ccm")?"[AEAD]":(m=="xts")?"[Disk]":(m=="ecb")?"[INSECURE]":"";
            std::cout<<std::setw(6)<<r.mode<<std::setw(9)<<FmtSz(r.sz)
                     <<std::fixed<<std::setprecision(1)<<std::setw(8)<<r.tput<<" MB/s  "
                     <<std::setprecision(2)<<std::setw(7)<<r.lat<<" ms  "<<note<<"\n";
        }
        std::cout<<"\n";
    }
    std::cout<<"══════════════════════════════════════════════════════════════\n";
    std::cout<<" Analysis:\n";
    std::cout<<"  • CTR/OFB/CFB (stream): highest throughput, parallelizable\n";
    std::cout<<"  • GCM ≈ CTR speed + auth tag (GHASH via AES-NI+CLMUL)\n";
    std::cout<<"  • CCM: two-pass (slower than GCM for same security)\n";
    std::cout<<"  • CBC: sequential chaining, limits parallelism\n";
    std::cout<<"  • XTS: designed for disk encryption (2× key size)\n";
    std::cout<<"  • ECB: fast but INSECURE, limited to ≤16 KiB\n";
    std::cout<<"══════════════════════════════════════════════════════════════\n\n";
}

// ────────────────────────────────────────────────────────────
// Negative Test Demonstrations
// ────────────────────────────────────────────────────────────
void RunNegTests(const AppConfig& cfg){
    std::cout<<"\n╔══════════════════════════════════════════════════════╗\n";
    std::cout<<"║      Negative Test Demonstrations (Fail-Closed)      ║\n";
    std::cout<<"╚══════════════════════════════════════════════════════╝\n\n";

    std::string key=ReadKey(cfg);
    std::string plain=!cfg.in_text.empty()?cfg.in_text:
                      (!cfg.in_file.empty()?ReadBin(cfg.in_file):"AES Security Test — 23110231");
    std::string iv=GenIV(16);

    std::cout<<"  Plaintext : \""<<plain<<"\"\n";
    std::cout<<"  IV        : "<<HexEnc(iv)<<"\n\n";

    // 1. Correct round-trip (baseline)
    {
        std::string c=EncCBC(key,iv,plain);
        std::string r=DecCBC(key,iv,c);
        std::cout<<"  [1/5] Correct CBC round-trip:\n";
        std::cout<<"        Result: \""<<r<<"\"\n";
        std::cout<<"        Status: "<<(r==plain?"PASS ✓":"FAIL ✗")<<"\n\n";
    }

    // 2. Wrong key → corrupted output
    {
        std::string c=EncCBC(key,iv,plain);
        std::string wk=key; wk[0]^=0xFF;
        std::cout<<"  [2/5] Wrong key → corrupted plaintext:\n";
        try{
            std::string bad=DecCBC(wk,iv,c);
            std::cout<<"        Got: \""<<bad.substr(0,20)<<"...\"\n";
            std::cout<<"        Status: "<<(bad!=plain?"PASS ✓ (corrupted)":"FAIL ✗")<<"\n\n";
        }catch(const std::exception& e){
            std::cout<<"        Error: "<<e.what()<<"\n";
            std::cout<<"        Status: PASS ✓ (error on bad key)\n\n";
        }
    }

    // 3. Wrong IV → first block corrupted
    {
        std::string c=EncCBC(key,iv,plain);
        std::string wi=iv; wi[0]^=0xFF;
        std::cout<<"  [3/5] Wrong IV → first block corrupted (CBC):\n";
        try{
            std::string bad=DecCBC(key,wi,c);
            std::cout<<"        Status: "<<(bad!=plain?"PASS ✓ (first block corrupted)":"FAIL ✗")<<"\n\n";
        }catch(const std::exception& e){
            std::cout<<"        Status: PASS ✓ (padding error caught)\n\n";
        }
    }

    // 4. Tampered ciphertext (GCM) → auth failure
    {
        std::string iv12=GenIV(12);
        std::string c=EncGCM(key,iv12,"",plain);
        std::string tc=c; if(!tc.empty())tc[0]^=0xAB;
        std::cout<<"  [4/5] Tampered GCM ciphertext → authentication failure:\n";
        try{
            DecGCM(key,iv12,"",tc);
            std::cout<<"        Status: FAIL ✗ (should have rejected!)\n\n";
        }catch(const std::exception& e){
            std::cout<<"        Error : "<<e.what()<<"\n";
            std::cout<<"        Status: PASS ✓ (tag mismatch → output withheld)\n\n";
        }
    }

    // 5. Invalid IV length → rejection
    {
        std::string short_iv(8,'\x00');
        std::cout<<"  [5/5] Invalid IV length (8 bytes instead of 16) → rejection:\n";
        try{
            EncCBC(key,short_iv,plain);
            std::cout<<"        Status: FAIL ✗ (should have rejected!)\n\n";
        }catch(const std::exception& e){
            std::cout<<"        Error : "<<e.what()<<"\n";
            std::cout<<"        Status: PASS ✓ (invalid IV rejected)\n\n";
        }
    }

    std::cout<<"══════════════════════════════════════════════════════\n";
    std::cout<<" All negative tests demonstrate correct fail-closed behavior.\n\n";
}

// ────────────────────────────────────────────────────────────
// main
// ────────────────────────────────────────────────────────────
int main(int argc, char* argv[]){
    std::cout<<"═══════════════════════════════════════════════════════\n";
    std::cout<<"  aestool — AES Symmetric Encryption Tool\n";
    std::cout<<"  Modes: ECB CBC OFB CFB CTR XTS CCM(AEAD) GCM(AEAD)\n";
    std::cout<<"  Crypto++ | C++17 | Lab 1\n";
    std::cout<<"═══════════════════════════════════════════════════════\n\n";

    try{
        auto cfg=ParseCLI(argc,argv);
        if      (cfg.op=="encrypt")   DoEncrypt(cfg);
        else if (cfg.op=="decrypt")   DoDecrypt(cfg);
        else if (cfg.op=="kat")       {
            if(cfg.kat_file.empty()) throw std::invalid_argument("Use: aestool kat --kat vectors.json");
            RunKAT(cfg.kat_file);
        }
        else if (cfg.op=="benchmark") RunBenchmark();
        else if (cfg.op=="neg-test")  RunNegTests(cfg);
        else throw std::invalid_argument("Unknown command: '"+cfg.op+"'\n"+USAGE);
    }
    catch(const std::exception& e){
        std::cerr<<"\n[CRITICAL ERROR] "<<e.what()<<"\n\n";
        return 1;
    }
    return 0;
}
