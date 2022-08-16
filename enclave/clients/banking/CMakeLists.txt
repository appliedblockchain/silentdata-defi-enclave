# Open banking API library
file(GLOB E_BANKING_SRCS *.cpp)
add_trusted_library(enclave_banking_t SRCS ${E_BANKING_SRCS})
target_link_libraries(enclave_banking_t enclave_api_client_t)
