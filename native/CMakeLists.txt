cmake_minimum_required(VERSION 3.16)
project(hsm_kms_tnr_native C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_executable(pkcs11_campaign src/pkcs11_campaign.c)
target_include_directories(pkcs11_campaign PRIVATE include)
target_compile_options(pkcs11_campaign PRIVATE -Wall -Wextra -Werror)

find_library(SOFTHSM2_LIB softhsm2
    PATHS
        /usr/lib/softhsm
        /usr/lib/x86_64-linux-gnu/softhsm
        /usr/lib/aarch64-linux-gnu/softhsm
        /usr/lib64/softhsm
    REQUIRED)
target_link_libraries(pkcs11_campaign PRIVATE ${SOFTHSM2_LIB})
set_target_properties(pkcs11_campaign PROPERTIES
    BUILD_RPATH "/usr/lib/softhsm;/usr/lib/x86_64-linux-gnu/softhsm;/usr/lib/aarch64-linux-gnu/softhsm")
