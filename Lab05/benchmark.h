#pragma once
// ============================================================
//  benchmark.h  —  Performance evaluation
//  Lab 05: Classical Digital Signatures
// ============================================================

// Run performance benchmarks for ECDSA and RSA-PSS.
// Tests message sizes: 1 KiB, 16 KiB, 1 MiB, 8 MiB
// Prints table with: keygen, sign, verify latency & throughput
void run_benchmarks();
