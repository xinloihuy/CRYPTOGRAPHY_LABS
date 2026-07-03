#pragma once
#include <string>

// Supported algorithms
enum class SigAlgo { ML_DSA_44, ML_DSA_65 };
enum class KemAlgo { ML_KEM_512 };

SigAlgo parse_sig_algo(const std::string& name);
KemAlgo parse_kem_algo(const std::string& name);
const char* sig_algo_name(SigAlgo a);
const char* kem_algo_name(KemAlgo a);

// pqtool keygen --algo <algo> --pub <pub.pem> --priv <priv.pem>
int cmd_keygen(int argc, char* argv[]);
