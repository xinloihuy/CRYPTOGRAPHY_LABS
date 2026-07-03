#pragma once
// ============================================================
//  test_runner.h  —  Automated correctness & negative tests
//  Lab 05: Classical Digital Signatures
// ============================================================
#include <string>

// Run all automated tests for both ECDSA and RSA-PSS.
// Prints results and returns number of failures (0 = all pass).
int run_all_tests();
