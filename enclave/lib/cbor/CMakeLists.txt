# Concise binary object representation library
file(GLOB E_CBOR_SRCS *.c)
add_trusted_library(enclave_cbor_t SRCS ${E_CBOR_SRCS})
set_target_properties(enclave_cbor_t PROPERTIES COMPILE_FLAGS ${ENCLAVE_C_FLAGS})
