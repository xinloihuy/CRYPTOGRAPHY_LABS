#pragma once
// pqtool verify --algo <mldsa-44|mldsa-65> --pub pub.pem --in msg.bin --sig sig.bin [--format raw|base64]
int cmd_verify(int argc, char* argv[]);
