# Open banking API library
file(GLOB E_ACCOUNTING_SRCS *.cpp)
add_trusted_library(enclave_accounting_t SRCS ${E_ACCOUNTING_SRCS})
target_link_libraries(enclave_accounting_t enclave_api_client_t)
