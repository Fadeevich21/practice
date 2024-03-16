cmake_minimum_required(VERSION 3.14)

project(RSA VERSION 1.0)

set(CMAKE_EXPORT_COMPILE_COMMANDS True)
set(CMAKE_BUILD_TYPE Debug)

add_compile_options(-O3)
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

target_include_directories(rsa_test PRIVATE ${PROJECT_SOURCE_DIR}/include)

add_subdirectory(tests)
