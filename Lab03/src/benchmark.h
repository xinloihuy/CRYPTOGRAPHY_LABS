#pragma once
#include <string>

// Run all performance benchmarks and print results
void run_benchmark(int bits_3072 = 3072, int bits_4096 = 4096);

// Run hybrid benchmarks for given payload sizes
void run_hybrid_benchmark();
