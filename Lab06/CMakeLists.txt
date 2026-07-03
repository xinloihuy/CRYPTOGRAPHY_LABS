cmake_minimum_required(VERSION 3.16)
project(pqtool CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ── liboqs paths ─────────────────────────────────────────────────────────────
set(LIBOQS_ROOT "E:/utecrypto/liboqs/build" CACHE PATH "Path to liboqs build directory")
set(LIBOQS_INCLUDE "${LIBOQS_ROOT}/include")
# liboqs was built with MSVC Debug config → lib is in lib/Debug
set(LIBOQS_LIB_DIR "${LIBOQS_ROOT}/lib/Debug")

# ── Sources ───────────────────────────────────────────────────────────────────
set(SOURCES
    src/main.cpp
    src/utils.cpp
    src/keygen.cpp
    src/sign.cpp
    src/verify.cpp
    src/encaps.cpp
    src/decaps.cpp
    src/cert.cpp
    src/bench.cpp
    src/tests.cpp
)

add_executable(pqtool ${SOURCES})

target_include_directories(pqtool PRIVATE ${LIBOQS_INCLUDE})
target_link_directories(pqtool PRIVATE ${LIBOQS_LIB_DIR})

if(WIN32)
    target_link_libraries(pqtool oqs ws2_32 advapi32)
else()
    target_link_libraries(pqtool oqs m)
endif()

# Compiler flags
if(MSVC)
    target_compile_options(pqtool PRIVATE /O2 /W3)
else()
    target_compile_options(pqtool PRIVATE -O2 -Wall -Wextra)
endif()

# ── Build output in ./build ────────────────────────────────────────────────────
set_target_properties(pqtool PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/build"
)

message(STATUS "liboqs include : ${LIBOQS_INCLUDE}")
message(STATUS "liboqs lib dir : ${LIBOQS_LIB_DIR}")
