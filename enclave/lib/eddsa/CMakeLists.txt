# EDDSA library
file(GLOB E_EDDSA_SRCS *.c)
add_trusted_library(enclave_eddsa_t SRCS ${E_EDDSA_SRCS})
set(EDDSA_FLAGS "${SGX_COMMON_CFLAGS} -nostdinc -fvisibility=hidden -fpie -fstack-protector-strong -ffunction-sections -fdata-sections")
set_target_properties(enclave_eddsa_t PROPERTIES COMPILE_FLAGS ${EDDSA_FLAGS})
