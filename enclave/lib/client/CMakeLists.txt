# Client library
file(GLOB E_CLIENT_SRCS *.cpp)
add_trusted_library(enclave_client_t SRCS ${E_CLIENT_SRCS})
add_dependencies(enclave_client_t messages_proto_t)
