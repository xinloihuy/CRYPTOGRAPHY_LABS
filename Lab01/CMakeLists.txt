cmake_minimum_required(VERSION 3.16)
project(AESTool VERSION 1.0 DESCRIPTION "AES Encryption Tool - Lab 1" LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ── Source ────────────────────────────────────────────────────
set(SOURCES main.cpp)

# ── Executables (build both 'aestool' and 'main' for compatibility) ──
add_executable(aestool ${SOURCES})
add_executable(main    ${SOURCES})

# ── Crypto++ ─────────────────────────────────────────────────
if(WIN32)
    # Windows path (matches .vscode/tasks.json)
    set(CRYPTOPP_INC "E:/HK6_Year3/Crypto/cryptopp_win/include")
    set(CRYPTOPP_LIB "E:/HK6_Year3/Crypto/cryptopp_win")

    foreach(TGT aestool main)
        target_include_directories(${TGT} PRIVATE ${CRYPTOPP_INC})
        target_link_directories(${TGT}    PRIVATE ${CRYPTOPP_LIB})
        target_link_libraries(${TGT}      cryptopp)
    endforeach()

    message(STATUS "[WIN] Crypto++ include: ${CRYPTOPP_INC}")
    message(STATUS "[WIN] Crypto++ lib dir: ${CRYPTOPP_LIB}")

else()
    # Linux: try pkg-config first, then system fallback
    find_package(PkgConfig QUIET)
    if(PkgConfig_FOUND)
        pkg_check_modules(CRYPTOPP libcryptopp)
    endif()

    foreach(TGT aestool main)
        if(CRYPTOPP_FOUND)
            target_include_directories(${TGT} PRIVATE ${CRYPTOPP_INCLUDE_DIRS})
            target_link_directories(${TGT}    PRIVATE ${CRYPTOPP_LIBRARY_DIRS})
            target_link_libraries(${TGT}      ${CRYPTOPP_LIBRARIES})
        else()
            # Fallback: assume system-installed libcryptopp
            target_link_libraries(${TGT} cryptopp)
        endif()
    endforeach()

    message(STATUS "[LINUX] Crypto++ configured via pkg-config or system")
endif()

# ── Compiler flags ─────────────────────────────────────────────
foreach(TGT aestool main)
    target_compile_options(${TGT} PRIVATE
        $<$<CXX_COMPILER_ID:GNU,Clang>:-Wall -Wextra -O2>
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /O2>
    )
endforeach()

# ── Copy vectors.json to build output ─────────────────────────
configure_file(vectors.json ${CMAKE_CURRENT_BINARY_DIR}/vectors.json COPYONLY)

# ── Summary ───────────────────────────────────────────────────
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "Compiler  : ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "Targets   : aestool, main")
message(STATUS "")
message(STATUS "Build commands:")
message(STATUS "  Windows (MinGW): cmake -G \"MinGW Makefiles\" .. && mingw32-make")
message(STATUS "  Linux          : cmake .. && make")
message(STATUS "")
message(STATUS "Quick test:")
message(STATUS "  ./aestool encrypt --mode cbc --key key.bin --in input.txt --out ct.bin")
message(STATUS "  ./aestool decrypt --mode cbc --key key.bin --in ct.bin   --out out.txt")
message(STATUS "  ./aestool kat --kat vectors.json")
message(STATUS "  ./aestool benchmark")
message(STATUS "  ./aestool neg-test --key key.bin")
