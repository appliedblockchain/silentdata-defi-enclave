# Company identity API library
file(GLOB E_IDENTITY_SRCS *.cpp)
add_trusted_library(enclave_identity_t SRCS ${E_IDENTITY_SRCS})
target_link_libraries(enclave_identity_t enclave_api_client_t)
