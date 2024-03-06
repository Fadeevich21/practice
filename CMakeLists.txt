cmake_minimum_required(VERSION 3.11)

project(RSA VERSION 1.0 LANGUAGES C)

set(CMAKE_EXPORT_COMPILE_COMMANDS True)
set(CMAKE_BUILD_TYPE Debug)

add_compile_options(-O3)
add_compile_options(-ffast-math)
add_compile_options(-flto)
add_compile_options(-march=native)

add_executable(rsa_test)

target_sources(rsa_test PRIVATE
    src/main.c
    src/bignum.c
    src/rsa.c
    src/asn1.c
    src/base64.c
    src/montgomery.c
    src/utils.c
)

target_include_directories(rsa_test PRIVATE include)