═══════════════════════════════════════════════════════
  aestool — AES Symmetric Encryption Tool
  Modes: ECB CBC OFB CFB CTR XTS CCM(AEAD) GCM(AEAD)
  Crypto++ | C++17 | Lab 1
═══════════════════════════════════════════════════════


╔══════════════════════════════════════════════════════════════╗
║        AES-256 Benchmark — All Modes — Crypto++              ║
╚══════════════════════════════════════════════════════════════╝

Mode  Size     Throughput    Latency     Notes
----------------------------------------------------------
ecb   1 KB     31.1     MB/s  0.03    ms  [INSECURE]
ecb   4 KB     658.4    MB/s  0.01    ms  [INSECURE]
ecb   16 KB    507.9    MB/s  0.03    ms  [INSECURE]
ecb   256 KB       ---          ---     SKIPPED(ECB>16KiB)
ecb   1 MB         ---          ---     SKIPPED(ECB>16KiB)
ecb   8 MB         ---          ---     SKIPPED(ECB>16KiB)

cbc   1 KB     74.5     MB/s  0.01    ms  
cbc   4 KB     253.7    MB/s  0.02    ms  
cbc   16 KB    432.0    MB/s  0.04    ms  
cbc   256 KB   580.5    MB/s  0.43    ms  
cbc   1 MB     610.9    MB/s  1.64    ms  
cbc   8 MB     687.6    MB/s  11.63   ms  

ofb   1 KB     51.7     MB/s  0.02    ms  
ofb   4 KB     336.7    MB/s  0.01    ms  
ofb   16 KB    533.9    MB/s  0.03    ms  
ofb   256 KB   672.6    MB/s  0.37    ms  
ofb   1 MB     770.9    MB/s  1.30    ms  
ofb   8 MB     746.1    MB/s  10.72   ms  

cfb   1 KB     60.4     MB/s  0.02    ms  
cfb   4 KB     355.1    MB/s  0.01    ms  
cfb   16 KB    248.8    MB/s  0.06    ms  
cfb   256 KB   510.1    MB/s  0.49    ms  
cfb   1 MB     705.1    MB/s  1.42    ms  
cfb   8 MB     809.3    MB/s  9.89    ms  

ctr   1 KB     82.1     MB/s  0.01    ms  
ctr   4 KB     849.2    MB/s  0.00    ms  
ctr   16 KB    400.3    MB/s  0.04    ms  
ctr   256 KB   1609.1   MB/s  0.16    ms  
ctr   1 MB     1581.1   MB/s  0.63    ms  
ctr   8 MB     1724.1   MB/s  4.64    ms  

xts   1 KB     69.3     MB/s  0.01    ms  [Disk]
xts   4 KB     121.4    MB/s  0.03    ms  [Disk]
xts   16 KB    599.4    MB/s  0.03    ms  [Disk]
xts   256 KB   743.5    MB/s  0.34    ms  [Disk]
xts   1 MB     968.5    MB/s  1.03    ms  [Disk]
xts   8 MB     981.8    MB/s  8.15    ms  [Disk]

gcm   1 KB     60.0     MB/s  0.02    ms  [AEAD]
gcm   4 KB     116.8    MB/s  0.03    ms  [AEAD]
gcm   16 KB    517.4    MB/s  0.03    ms  [AEAD]
gcm   256 KB   938.6    MB/s  0.27    ms  [AEAD]
gcm   1 MB     1138.9   MB/s  0.88    ms  [AEAD]
gcm   8 MB     1166.5   MB/s  6.86    ms  [AEAD]

ccm   1 KB     71.3     MB/s  0.01    ms  [AEAD]
ccm   4 KB     102.1    MB/s  0.04    ms  [AEAD]
ccm   16 KB    395.6    MB/s  0.04    ms  [AEAD]
ccm   256 KB   889.5  MB/s  0.32    ms  [AEAD]
ccm   1 MB     918.1 MB/s  0.94    ms  [AEAD]
ccm   8 MB     950.9 MB/s  7.01    ms  [AEAD]

══════════════════════════════════════════════════════════════
 Analysis:
  • CTR/OFB/CFB (stream): highest throughput, parallelizable
  • GCM ≈ CTR speed + auth tag (GHASH via AES-NI+CLMUL)
  • CCM: two-pass (slower than GCM for same security)
  • CBC: sequential chaining, limits parallelism
  • XTS: designed for disk encryption (2× key size)
  • ECB: fast but INSECURE, limited to ≤16 KiB
══════════════════════════════════════════════════════════════

