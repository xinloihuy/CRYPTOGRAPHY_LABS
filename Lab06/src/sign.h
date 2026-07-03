#pragma once
// pqtool sign --algo <mldsa-44|mldsa-65> --priv priv.pem --in msg.bin --out sig.bin [--format raw|base64]
int cmd_sign(int argc, char* argv[]);
