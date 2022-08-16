# Proof library
file(GLOB E_PROOF_SRCS *.cpp)
add_trusted_library(enclave_proof_t SRCS ${E_PROOF_SRCS})
add_dependencies(enclave_client_t messages_proto_t requests_proto_t)