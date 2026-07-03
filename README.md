# CRYPTOGRAPHY_LABS

Bộ lab và công cụ minh họa các chủ đề môn Cryptography (C++ + OpenSSL).

Mục tiêu của repository:
- Lưu các bài lab, mã nguồn, và báo cáo liên quan đến các chủ đề: mã hóa bất đối xứng (RSA-OAEP), mã hóa lai (hybrid), chữ ký số (ECDSA, RSA-PSS), và các bài kiểm tra/benchmark.
- Cung cấp công cụ CLI ví dụ (rsatool, sigtool) để build, chạy test, và đo hiệu năng.

Nội dung chính
- Lab03: rsatool — RSA-OAEP & Hybrid Encryption (C++ + OpenSSL 4.0)
  - RSA-OAEP (SHA-256), AES-256-GCM envelope, PEM/DER/JSON key formats, benchmark, 30 tests.
- Lab05: sigtool — Classical Digital Signatures (ECDSA, RSA-PSS)
  - ECDSA-P256 (bắt buộc) và RSA-PSS-3072, test suite, benchmark, thảo luận bảo mật.

Yêu cầu
- Trình biên dịch: g++ (MSYS2 MinGW hoặc tương đương), hỗ trợ C++17
- OpenSSL 4.0.0 (thư viện phát triển và DLL trên Windows nếu cần)
- Hệ điều hành: Cross-platform (Linux, Windows via MSYS2)

Cách build (tổng quát)
1. Cài đặt OpenSSL 4.0 và thiết lập include/lib tương ứng.
2. Vào thư mục lab tương ứng, dùng tasks của VSCode hoặc dòng lệnh để build.

Ví dụ (Lab03 - Windows, tham khảo Lab03/README.md):
```bash
# Build (g++)
g++ -std=c++17 -O2 -I "/path/to/openssl/include" \
    src/*.cpp \
    -L "/path/to/openssl/lib" \
    -l:libcrypto.dll.a -l:libssl.dll.a \
    -o rsatool.exe
```

Ví dụ (Lab05 - Windows, tham khảo Lab05/README.md):
```powershell
g++ -std=c++17 -O2 -o sigtool.exe `
    sigtool.cpp ecdsa_handler.cpp rsa_pss_handler.cpp `
    utils.cpp test_runner.cpp benchmark.cpp `
    -I "E:/utecrypto/openssl-4.0.0_windows/include" `
    -L "E:/utecrypto/openssl-4.0.0_windows" `
    -lcrypto -lssl -lws2_32 -lgdi32 -ladvapi32 -lcrypt32 -luser32
```

Các lệnh CLI chính (tổng quan)
- rsatool (Lab03):
  - keygen, encrypt, decrypt, test, benchmark, manual-oaep
- sigtool (Lab05):
  - keygen, sign, verify, test, bench

Cấu trúc repository (tóm tắt)
```
CRYPTOGRAPHY_LABS/
├── Lab03/           # rsatool: RSA-OAEP + Hybrid + tests + benchmark
├── Lab05/           # sigtool: ECDSA, RSA-PSS + tests + benchmark
├── README.md        # Tập tin này
└── docs/            # (nếu có) báo cáo và tài liệu bổ sung
```

Hướng dẫn kiểm tra & benchmark
- Mỗi lab có target `test` để chạy bộ test tự động (positive + negative cases).
- Có các target `benchmark`/`bench` để chạy đo hiệu năng trên các kích thước payload khác nhau.
- Tham khảo README riêng trong mỗi Lab để biết lệnh chi tiết, tập tin ví dụ, và kết quả mẫu.

Ghi chú về bảo mật và triển khai
- Mã sử dụng OpenSSL — đảm bảo dùng OpenSSL 4.x như đã chỉ định.
- Tránh rò rỉ thông tin qua lỗi (normalize error codes), sử dụng so sánh constant-time khi cần.
- Với ECDSA, cân nhắc RFC 6979 (deterministic nonce) nếu muốn loại bỏ dependency vào RNG cho nonce.

Đóng góp
- Nếu bạn muốn đóng góp: fork repository → tạo branch riêng → mở PR mô tả thay đổi.
- Ghi rõ lab nào, chức năng mới, và kèm bài test nếu thêm logic.

License & Liên hệ
- Thêm thông tin license ở root nếu muốn (MIT/BSD/GPL).
- Nếu cần trợ giúp, mở Issue hoặc liên hệ tác giả/giảng viên trong metadata của lab.

---

Tài liệu chi tiết cho từng lab nằm trong thư mục Lab03/ và Lab05/ — xem các README bên trong để biết hướng dẫn build và CLI cụ thể.
