# Company registry API library
file(GLOB E_REGISTRY_SRCS *.cpp)
add_trusted_library(enclave_registry_t SRCS ${E_REGISTRY_SRCS})
target_link_libraries(enclave_registry_t enclave_api_client_t)
