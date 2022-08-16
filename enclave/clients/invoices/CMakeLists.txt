# Invoice source API library
file(GLOB E_INVOICES_SRCS *.cpp)
add_trusted_library(enclave_invoices_t SRCS ${E_INVOICES_SRCS})
target_link_libraries(enclave_invoices_t enclave_api_client_t)
