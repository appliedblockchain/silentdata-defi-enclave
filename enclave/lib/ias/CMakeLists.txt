# IAS library
file(GLOB E_IAS_SRCS *.cpp)
add_trusted_library(enclave_ias_t SRCS ${E_IAS_SRCS})
