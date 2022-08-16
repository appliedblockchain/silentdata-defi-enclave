########## WORKER ENCLAVE ##########

set(WORKER_ENCLAVE_SRCS worker_enclave.cpp)

set(WORKER_ENCLAVE_TRUSTED_LIBS enclave_common_t
                                 enclave_eddsa_t
                                 enclave_crypto_t
                                 enclave_cbor_t
                                 enclave_client_t
                                 enclave_ias_t
                                 enclave_api_client_t
                                 enclave_banking_t
                                 enclave_accounting_t
                                 enclave_identity_t
                                 enclave_invoices_t
                                 enclave_proof_t
                                 messages_proto_t
                                 requests_proto_t)

set(WORKER_ENCLAVE_LIB_PATHS ${MBEDTLS_LIB_PATH})

set(WORKER_ENCLAVE_LIBS mbedtls_SGX_t)

add_enclave_library(worker_enclave
                    SRCS ${WORKER_ENCLAVE_SRCS}
                    TRUSTED_LIBS ${WORKER_ENCLAVE_TRUSTED_LIBS}
                    EDL ${WORKER_EDL_FILE}
                    EDL_SEARCH_PATHS ${EDL_SEARCH_PATHS}
                    LDSCRIPT ${WORKER_LDS}
                    LIB_PATHS ${WORKER_ENCLAVE_LIB_PATHS}
                    LIBS ${WORKER_ENCLAVE_LIBS})

sign_and_install(worker_enclave)
