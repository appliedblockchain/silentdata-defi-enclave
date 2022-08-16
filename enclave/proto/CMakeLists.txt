# Invoice proto library

sgx_protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS messages.proto)

set_source_files_properties(${PROTO_SRCS}
                            PROPERTIES
                            COMPILE_FLAGS "-w")

add_trusted_library(messages_proto_t
                    SRCS ${PROTO_SRCS})

sgx_protobuf_generate_cpp(REQ_PROTO_SRCS REQ_PROTO_HDRS requests.proto)

set_source_files_properties(${REQ_PROTO_SRCS}
                            PROPERTIES
                            COMPILE_FLAGS "-w")

add_trusted_library(requests_proto_t
                    SRCS ${REQ_PROTO_SRCS})

install(TARGETS messages_proto_t
    DESTINATION lib
    PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)

install(TARGETS requests_proto_t
    DESTINATION lib
    PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
