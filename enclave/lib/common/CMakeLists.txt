# Common library
file(GLOB E_COMMON_SRCS *.cpp)
add_trusted_library(enclave_common_t SRCS ${E_COMMON_SRCS})
