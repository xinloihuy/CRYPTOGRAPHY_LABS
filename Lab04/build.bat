@echo off
setlocal

set OPENSSL_DIR=E:\utecrypto\openssl-4.0.0_windows
set OPENSSL=E:\utecrypto\openssl-4.0.0_windows\apps\openssl.exe
set INC=-I%OPENSSL_DIR%\include
set LIB_DIR=-L%OPENSSL_DIR%
set LIBS=-lcrypto -lssl -lws2_32 -lgdi32 -lcrypt32
set FLAGS=-std=c++17 -O2 -Wall

echo [*] Building Lab 04 — All programs
echo ==========================================

echo [1/5] Building hashtool...
g++ %FLAGS% %INC% %LIB_DIR% src\hashtool.cpp -o bin\hashtool.exe %LIBS%
if %ERRORLEVEL% NEQ 0 ( echo [FAIL] hashtool & exit /b 1 )
echo [OK] bin\hashtool.exe

echo [2/5] Building pki_parser...
g++ %FLAGS% %INC% %LIB_DIR% src\pki_parser.cpp -o bin\pki_parser.exe %LIBS%
if %ERRORLEVEL% NEQ 0 ( echo [FAIL] pki_parser & exit /b 1 )
echo [OK] bin\pki_parser.exe

echo [3/5] Building md5_collision...
g++ %FLAGS% %INC% %LIB_DIR% src\md5_collision.cpp -o bin\md5_collision.exe %LIBS%
if %ERRORLEVEL% NEQ 0 ( echo [FAIL] md5_collision & exit /b 1 )
echo [OK] bin\md5_collision.exe

echo [4/5] Building length_extension...
g++ %FLAGS% %INC% %LIB_DIR% src\length_extension.cpp -o bin\length_extension.exe %LIBS%
if %ERRORLEVEL% NEQ 0 ( echo [FAIL] length_extension & exit /b 1 )
echo [OK] bin\length_extension.exe

echo [5/5] Building benchmark...
g++ %FLAGS% %INC% %LIB_DIR% src\benchmark.cpp -o bin\benchmark.exe %LIBS%
if %ERRORLEVEL% NEQ 0 ( echo [FAIL] benchmark & exit /b 1 )
echo [OK] bin\benchmark.exe

echo.
echo ==========================================
echo [*] All programs built successfully!
echo.
echo [*] Generating test certificate...
%OPENSSL% req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 ^
  -keyout certs\test_key.pem -out certs\test_cert.pem ^
  -days 365 -nodes ^
  -subj "/C=VN/ST=HoChiMinh/L=HCM/O=UTE/OU=CryptoLab/CN=lab04.test" ^
  -addext "subjectAltName=DNS:lab04.test,DNS:www.lab04.test,IP:127.0.0.1" ^
  -addext "keyUsage=digitalSignature,keyEncipherment" ^
  -addext "extendedKeyUsage=serverAuth,clientAuth" 2>NUL
echo [OK] certs\test_cert.pem generated

echo.
echo ==========================================
echo [*] Running Known Answer Tests (KATs)...
echo.
copy /Y %OPENSSL_DIR%\libcrypto-4-x64.dll bin\ >NUL 2>&1
copy /Y %OPENSSL_DIR%\libssl-4-x64.dll   bin\ >NUL 2>&1
copy /Y %OPENSSL_DIR%\providers\*.dll    bin\ >NUL 2>&1

cd bin
hashtool.exe --kat
cd ..

echo.
echo [*] All done! Run individual programs:
echo   bin\hashtool.exe --kat
echo   bin\hashtool.exe --algo sha256 --text "Hello World"
echo   bin\pki_parser.exe certs\test_cert.pem
echo   bin\md5_collision.exe
echo   bin\length_extension.exe
echo   bin\benchmark.exe

endlocal
