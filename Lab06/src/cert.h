#pragma once
// pqtool cert --action <create|verify|tamper-test>
//             [--subject <name>] [--ca-pub ca_pub.pem] [--ca-priv ca_priv.pem]
//             [--sub-pub sub_pub.pem] [--cert cert.json]
int cmd_cert(int argc, char* argv[]);
