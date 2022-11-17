cmake_minimum_required(VERSION 3.0)
project(silentdata-defi-core C CXX)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/bin)
set(CMAKE_INSTALL_PREFIX ${PROJECT_BINARY_DIR}/install)

list(APPEND CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)
find_package(SGX REQUIRED)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

set(MBED_DIR Default CACHE STRING "Path to mbedtls-compat-sgx lib and include")
if(MBED_DIR STREQUAL "Default")
    message(STATUS "MBED_DIR not set, using default of ${PROJECT_SOURCE_DIR}/../mbedtls-compat-sgx/build/mbedtls_SGX-2.28.1")
    set(MBED_DIR ${PROJECT_SOURCE_DIR}/../mbedtls-compat-sgx/build/mbedtls_SGX-2.28.1)
else()
    message(STATUS "MBED_DIR set to ${MBED_DIR}")
endif()
set(MBEDTLS_LIB_PATH ${MBED_DIR}/lib)
set(MBEDTLS_INCLUDE_DIR ${MBED_DIR}/include)

# Find protobuf
find_package(Protobuf REQUIRED)
find_package(ProtoGen REQUIRED)
message(STATUS "Using protobuf ${Protobuf_VERSION}")
set(PROTOBUF_IMPORT_DIRS "${CMAKE_SOURCE_DIR}/proto")
message(STATUS "${PROTOBUF_IMPORT_DIRS}")

set_property(
    DIRECTORY
    APPEND
    PROPERTY ADDITIONAL_CLEAN_FILES worker_enclave.signed.so
)

include_directories(SYSTEM ${SGX_INCLUDE_DIR}
    ${MBEDTLS_INCLUDE_DIR})
include_directories(${PROJECT_SOURCE_DIR}
    ${PROJECT_BINARY_DIR}
    ${CMAKE_CURRENT_BINARY_DIR})

set(PROJECT_ENCLAVE_DIR ${PROJECT_SOURCE_DIR}/enclave)

set(EDL_SEARCH_PATHS ${PROJECT_ENCLAVE_DIR}/worker
    ${MBEDTLS_LIB_PATH})

set(WORKER_EDL_FILE ${PROJECT_ENCLAVE_DIR}/worker/worker_enclave.edl)

set(WORKER_LDS worker_enclave.lds)

set(ENCLAVE_TEST_KEY ${PROJECT_SOURCE_DIR}/enclave_private_test.pem)

add_subdirectory(lib)
add_subdirectory(proto)
add_subdirectory(enclave)
add_subdirectory(clients)
