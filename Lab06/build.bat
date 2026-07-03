@echo off
:: Build script for pqtool using MSVC
:: liboqs was compiled with MSVC, so we must use cl.exe

set VCVARS=C:\Program Files\Microsoft Visual Studio\18\Insiders\VC\Auxiliary\Build\vcvars64.bat
set LIBOQS_INC=E:\utecrypto\liboqs\build\include
set LIBOQS_LIB=E:\utecrypto\liboqs\build\lib\Debug
set SRC=E:\HK6_Year3\Crypto\Lab06\src
set OUT=E:\HK6_Year3\Crypto\Lab06\build\pqtool.exe

echo [BUILD] Setting up MSVC environment...
call "%VCVARS%"
if errorlevel 1 (
    echo [ERROR] Could not initialize MSVC environment.
    exit /b 1
)

echo [BUILD] Compiling pqtool...
cl /std:c++17 /O2 /EHsc /W3 ^
    /Fe:"%OUT%" ^
    "%SRC%\main.cpp" ^
    "%SRC%\utils.cpp" ^
    "%SRC%\keygen.cpp" ^
    "%SRC%\sign.cpp" ^
    "%SRC%\verify.cpp" ^
    "%SRC%\encaps.cpp" ^
    "%SRC%\decaps.cpp" ^
    "%SRC%\cert.cpp" ^
    "%SRC%\bench.cpp" ^
    "%SRC%\tests.cpp" ^
    /I "%LIBOQS_INC%" ^
    /link ^
    /LIBPATH:"%LIBOQS_LIB%" ^
    oqs.lib ws2_32.lib advapi32.lib

if errorlevel 1 (
    echo [ERROR] Build failed.
    exit /b 1
)

echo [OK] Build successful: %OUT%
