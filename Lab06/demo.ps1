# Demo script: Full pqtool workflow
# Run from: E:\HK6_Year3\Crypto\Lab06\

$tool = ".\build\pqtool.exe"
$d = ".\build\demo_files"

Write-Host "`n=== pqtool Full Workflow Demo ===" -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path $d | Out-Null

# ── Step 1: Generate ML-DSA-44 keypair
Write-Host "`n[1] Generating ML-DSA-44 keypair..." -ForegroundColor Yellow
& $tool keygen --algo mldsa-44 --pub "$d\pub44.pem" --priv "$d\priv44.pem"

# ── Step 2: Generate ML-DSA-65 keypair
Write-Host "`n[2] Generating ML-DSA-65 keypair..." -ForegroundColor Yellow
& $tool keygen --algo mldsa-65 --pub "$d\pub65.pem" --priv "$d\priv65.pem"

# ── Step 3: Generate ML-KEM-512 keypair
Write-Host "`n[3] Generating ML-KEM-512 keypair..." -ForegroundColor Yellow
& $tool keygen --algo mlkem-512 --pub "$d\kem_pub.pem" --priv "$d\kem_priv.pem"

# ── Step 4: Create test message
Write-Host "`n[4] Creating test message..." -ForegroundColor Yellow
$msg = "Hello PQC World! This is Lab 06 test message."
[System.IO.File]::WriteAllBytes("$d\msg.bin", [System.Text.Encoding]::UTF8.GetBytes($msg))
Write-Host "    Message: $msg"

# ── Step 5: Sign with ML-DSA-44
Write-Host "`n[5] Signing with ML-DSA-44..." -ForegroundColor Yellow
& $tool sign --algo mldsa-44 --priv "$d\priv44.pem" --in "$d\msg.bin" --out "$d\sig44.bin"

# ── Step 6: Verify signature
Write-Host "`n[6] Verifying ML-DSA-44 signature..." -ForegroundColor Yellow
& $tool verify --algo mldsa-44 --pub "$d\pub44.pem" --in "$d\msg.bin" --sig "$d\sig44.bin"

# ── Step 7: Sign with ML-DSA-65
Write-Host "`n[7] Signing with ML-DSA-65..." -ForegroundColor Yellow
& $tool sign --algo mldsa-65 --priv "$d\priv65.pem" --in "$d\msg.bin" --out "$d\sig65.bin"

# ── Step 8: Verify ML-DSA-65
Write-Host "`n[8] Verifying ML-DSA-65 signature..." -ForegroundColor Yellow
& $tool verify --algo mldsa-65 --pub "$d\pub65.pem" --in "$d\msg.bin" --sig "$d\sig65.bin"

# ── Step 9: ML-KEM encapsulation
Write-Host "`n[9] ML-KEM-512 encapsulation..." -ForegroundColor Yellow
& $tool encaps --algo mlkem-512 --pub "$d\kem_pub.pem" --ct "$d\ct.bin" --ss "$d\ss_enc.bin"

# ── Step 10: ML-KEM decapsulation
Write-Host "`n[10] ML-KEM-512 decapsulation..." -ForegroundColor Yellow
& $tool decaps --algo mlkem-512 --priv "$d\kem_priv.pem" --ct "$d\ct.bin" --ss "$d\ss_dec.bin" --verify-ss "$d\ss_enc.bin"

# ── Step 11: Certificate workflow
Write-Host "`n[11] Creating PQ Certificate..." -ForegroundColor Yellow
& $tool cert --action create --subject "Alice (Lab06)" --cert "$d\cert.json" `
    --ca-pub "$d\ca_pub.pem" --ca-priv "$d\ca_priv.pem" --sub-pub "$d\sub_pub.pem"

Write-Host "`n[12] Verifying PQ Certificate..." -ForegroundColor Yellow
& $tool cert --action verify --cert "$d\cert.json" --ca-pub "$d\ca_pub.pem"

Write-Host "`n[13] Certificate tamper tests..." -ForegroundColor Yellow
& $tool cert --action tamper-test --cert "$d\cert.json" --ca-pub "$d\ca_pub.pem"

# ── Step 14: Negative test: verify with wrong key
Write-Host "`n[14] Negative test: verify with wrong public key..." -ForegroundColor Yellow
& $tool verify --algo mldsa-44 --pub "$d\pub65.pem" --in "$d\msg.bin" --sig "$d\sig44.bin"

# ── Step 15: Algorithm info
Write-Host "`n[15] Algorithm information..." -ForegroundColor Yellow
& $tool info

Write-Host "`n=== Demo Complete ===" -ForegroundColor Green
