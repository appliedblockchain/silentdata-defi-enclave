# Crypto library
file(GLOB E_CRYPTO_SRCS *.cpp)
add_trusted_library(enclave_crypto_t SRCS ${E_CRYPTO_SRCS})
