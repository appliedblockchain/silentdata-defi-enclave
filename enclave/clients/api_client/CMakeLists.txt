# Open API client library
file(GLOB E_API_CLIENT_SRCS *.cpp)
add_trusted_library(enclave_api_client_t SRCS ${E_API_CLIENT_SRCS})
