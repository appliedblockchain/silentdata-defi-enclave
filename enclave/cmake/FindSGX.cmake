# FindPackage cmake file for Intel SGX SDK

cmake_minimum_required(VERSION 2.8.11) # target_include_directories
include(CMakeParseArguments)

set(SGX_FOUND "NO")

if(EXISTS SGX_DIR)
    set(SGX_PATH ${SGX_DIR})
elseif(EXISTS SGX_ROOT)
    set(SGX_PATH ${SGX_ROOT})
elseif(EXISTS $ENV{SGX_SDK})
    set(SGX_PATH $ENV{SGX_SDK})
elseif(EXISTS $ENV{SGX_DIR})
    set(SGX_PATH $ENV{SGX_DIR})
elseif(EXISTS $ENV{SGX_ROOT})
    set(SGX_PATH $ENV{SGX_ROOT})
else()
    set(SGX_PATH "/opt/intel/sgxsdk")
endif()

set(SGX_COMMON_CFLAGS -m64)
set(SGX_LIBRARY_PATH ${SGX_PATH}/lib64)
set(SGX_ENCLAVE_SIGNER ${SGX_PATH}/bin/x64/sgx_sign)
set(SGX_EDGER8R ${SGX_PATH}/bin/x64/sgx_edger8r)
set(SGX_PROTOC ${SGX_PATH}/bin/x64/sgx_protoc)

find_path(SGX_INCLUDE_DIR sgx.h "${SGX_PATH}/include" NO_DEFAULT_PATH)
find_path(SGX_LIBRARY_DIR libsgx_urts.so "${SGX_LIBRARY_PATH}" NO_DEFAULT_PATH)

if(SGX_INCLUDE_DIR AND SGX_LIBRARY_DIR)
    set(SGX_FOUND "YES")
    set(SGX_INCLUDE_DIR "${SGX_PATH}/include" CACHE PATH "Intel SGX include directory" FORCE)
    set(SGX_TLIBC_INCLUDE_DIR "${SGX_INCLUDE_DIR}/tlibc" CACHE PATH "Intel SGX tlibc include directory" FORCE)
    set(SGX_LIBCXX_INCLUDE_DIR "${SGX_INCLUDE_DIR}/libcxx" CACHE PATH "Intel SGX libcxx include directory" FORCE)
    set(SGX_INCLUDE_DIRS ${SGX_INCLUDE_DIR} ${SGX_TLIBC_INCLUDE_DIR} ${SGX_LIBCXX_INCLUDE_DIR})
    mark_as_advanced(SGX_INCLUDE_DIR SGX_TLIBC_INCLUDE_DIR SGX_LIBCXX_INCLUDE_DIR SGX_LIBRARY_DIR)
    message(STATUS "Found Intel SGX SDK.")
endif()

if(SGX_FOUND)
    # Use the build type to set the defaults for SGX_HW and SGX_MODE
    set(BUILD_TYPE Develop CACHE STRING "Develop = Simulation + Debug; Deploy = Hardware + release.")
    if(BUILD_TYPE STREQUAL "Deploy")
        message(STATUS "BUILD_TYPE=Deploy. Deploy mode: SGX_HW=ON, SGX_MODE=Release, BUILD_TESTS=OFF")
        set(SGX_HW ON)
        set(SGX_MODE "Release")
        set(BUILD_TESTS OFF)
    else()
        message(STATUS "BUILD_TYPE=Develop. Develop mode: SGX_HW=OFF, SGX_MODE=Debug, BUILD_TESTS=ON")
        set(SGX_HW OFF)
        set(SGX_MODE "Debug")
        set(BUILD_TESTS ON)
    endif()

    # The SGX_HW and SGX_MODE flags can be overwritten
    set(SGX_HW ${SGX_HW} CACHE BOOL "ON to run SGX on hardware, OFF for simulation.")
    set(SGX_MODE ${SGX_MODE} CACHE STRING "SGX build mode: Debug; PreRelease; Release.")
    set(BUILD_TESTS ${BUILD_TESTS} CACHE BOOL "ON to build the test suite, OFF to not.")
    if(BUILD_TESTS)
        message(STATUS "BUILD_TESTS=ON. Building unit and integration test suite")
    else()
        message(STATUS "BUILD_TESTS=OFF. Not building unit and integration test suite, use BUILD_TESTS=ON to build")
    endif()

    if(SGX_HW)
        message(STATUS "SGX_HW=ON. Building in hardware mode (requires SGX PSW and drivers)")
        set(SGX_URTS_LIB sgx_urts)
        set(SGX_USVC_LIB sgx_uae_service)
        set(SGX_EPID_LIB sgx_epid)
        set(SGX_QUOTE_LIB sgx_quote_ex)
        set(SGX_TRTS_LIB sgx_trts)
        set(SGX_TSVC_LIB sgx_tservice)
    else()
        message(STATUS "SGX_HW=OFF. Building in simulation mode")
        set(SGX_URTS_LIB sgx_urts_sim)
        set(SGX_USVC_LIB sgx_uae_service_sim)
        set(SGX_EPID_LIB sgx_epid_sim)
        set(SGX_QUOTE_LIB sgx_quote_ex_sim)
        set(SGX_TRTS_LIB sgx_trts_sim)
        set(SGX_TSVC_LIB sgx_tservice_sim)
        set(SGX_COMMON_CFLAGS "${SGX_COMMON_CFLAGS} -DSGX_SIM_MODE")
    endif()

    if(SGX_MODE STREQUAL "Debug")
        message(STATUS "SGX_MODE=Debug. Building in debug mode")
        set(SGX_COMMON_CFLAGS "${SGX_COMMON_CFLAGS} -O0 -g -DDEBUG -UNDEBUG -UEDEBUG")
    elseif(SGX_MODE STREQUAL "PreRelease")
        message(STATUS "SGX_MODE=PreRelease. Building in pre-release mode")
        set(SGX_COMMON_CFLAGS "${SGX_COMMON_CFLAGS} -O2 -UDEBUG -DNDEBUG -DEDEBUG")
    elseif(SGX_MODE STREQUAL "Release")
        message(STATUS "SGX_MODE=Release. Building in release mode")
        set(SGX_COMMON_CFLAGS "${SGX_COMMON_CFLAGS} -O2 -UDEBUG -DNDEBUG -UEDEBUG -DPRODUCTION_IAS")
    else()
        message(FATAL_ERROR "SGX_MODE ${SGX_MODE} is not Debug, PreRelease or Release.")
    endif()

    # Set the warning flags
    set(SGX_WARNING_FLAGS "-Wall -Wextra -Winit-self -Wpointer-arith -Wreturn-type \
					       -Waddress -Wsequence-point -Wformat-security \
					       -Wmissing-include-dirs -Wfloat-equal -Wshadow \
                           -Wcast-align -Wconversion -Wredundant-decls")
    # Warnings specific to C and C++
    set(SGX_WARNING_CFLAGS "-Wjump-misses-init -Wstrict-prototypes -Wunsuffixed-float-constants")
    set(SGX_WARNING_CXXFLAGS "-Wnon-virtual-dtor -std=c++11")

    set(SGX_SECURITY_FLAGS "-Wl,-z,relro,-z,now,-z,noexecstack")

    # Enclave compilation flags
    set(ENCLAVE_INC_DIRS "${SGX_INCLUDE_DIR}" "${SGX_TLIBC_INCLUDE_DIR}" "${SGX_LIBCXX_INCLUDE_DIR}" "${SGX_INCLUDE_DIR}/tprotobuf")
    set(ENCLAVE_COMMON_FLAGS "${SGX_COMMON_CFLAGS} ${SGX_WARNING_FLAGS} -nostdinc -fvisibility=hidden -fpie -fstack-protector-strong -ffunction-sections -fdata-sections -DPB_ENABLE_SGX")
    set(ENCLAVE_C_FLAGS "${ENCLAVE_COMMON_FLAGS} ${SGX_WARNING_CFLAGS}")
    set(ENCLAVE_CXX_FLAGS "${ENCLAVE_COMMON_FLAGS} ${SGX_WARNING_CXXFLAGS} -nostdinc++")

    # Untrusted executable compilation flags
    set(APP_INC_DIRS "${SGX_PATH}/include")
    set(APP_COMMON_FLAGS "${SGX_COMMON_CFLAGS} ${SGX_WARNING_FLAGS} -fPIC -Wno-attributes ${APP_INC_FLAGS}")
    set(APP_C_FLAGS "${APP_COMMON_FLAGS} ${SGX_WARNING_CFLAGS}")
    set(APP_CXX_FLAGS "${APP_COMMON_FLAGS} ${SGX_WARNING_CXX_FLAGS}")

    function(_build_edl_obj edl edl_search_paths use_prefix)
        get_filename_component(EDL_NAME ${edl} NAME_WE)
        get_filename_component(EDL_ABSPATH ${edl} ABSOLUTE)
        set(EDL_T_C "${CMAKE_CURRENT_BINARY_DIR}/${EDL_NAME}_t.c")
        set(SEARCH_PATHS "")
        foreach(path ${edl_search_paths})
            get_filename_component(ABSPATH ${path} ABSOLUTE)
            list(APPEND SEARCH_PATHS "${ABSPATH}")
        endforeach()
        list(APPEND SEARCH_PATHS "${SGX_PATH}/include")
        string(REPLACE ";" ":" SEARCH_PATHS "${SEARCH_PATHS}")
        if(${use_prefix})
            set(USE_PREFIX "--use-prefix")
        endif()
        add_custom_command(OUTPUT ${EDL_T_C}
                           COMMAND ${SGX_EDGER8R} ${USE_PREFIX} --trusted ${EDL_ABSPATH} --search-path ${SEARCH_PATHS}
                           MAIN_DEPENDENCY ${EDL_ABSPATH}
                           WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

        add_library(${target}-edlobj OBJECT ${EDL_T_C})
        set_target_properties(${target}-edlobj PROPERTIES COMPILE_FLAGS ${ENCLAVE_C_FLAGS})
        target_include_directories(${target}-edlobj PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${ENCLAVE_INC_DIRS})

        set_property(DIRECTORY APPEND PROPERTY ADDITIONAL_MAKE_CLEAN_FILES "${CMAKE_CURRENT_BINARY_DIR}/${EDL_NAME}_t.h")
    endfunction()

    # build trusted static library to be linked into enclave library
    function(add_trusted_library target)
        set(optionArgs USE_PREFIX)
        set(oneValueArgs EDL LDSCRIPT)
        set(multiValueArgs SRCS EDL_SEARCH_PATHS LIBS LIB_PATHS)
        cmake_parse_arguments("SGX" "${optionArgs}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})
        if(NOT "${SGX_LDSCRIPT}" STREQUAL "")
            get_filename_component(LDS_ABSPATH ${SGX_LDSCRIPT} ABSOLUTE)
            set(LDSCRIPT_FLAG "-Wl,--version-script=${LDS_ABSPATH}")
        endif()
        if("${SGX_EDL}" STREQUAL "")
            message("${target}: SGX enclave edl file is not provided; skipping edger8r")
            add_library(${target} STATIC ${SGX_SRCS})
        else()
            if("${SGX_EDL_SEARCH_PATHS}" STREQUAL "")
                message("${target}: SGX enclave edl file search paths are not provided!")
            endif()
            _build_edl_obj(${SGX_EDL} "${SGX_EDL_SEARCH_PATHS}" ${SGX_USE_PREFIX})
            add_library(${target} STATIC ${SGX_SRCS} $<TARGET_OBJECTS:${target}-edlobj>)
        endif()
        
        set_target_properties(${target} PROPERTIES COMPILE_FLAGS ${ENCLAVE_CXX_FLAGS})
        target_include_directories(${target} PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${ENCLAVE_INC_DIRS})

        set(EXTRA_LIB_PATHS "")
        foreach(EXLIBPATH ${SGX_LIB_PATHS})
            list(APPEND EXTRA_LIB_PATHS "-L${EXLIBPATH}")
        endforeach()

        set(EXTRA_LIBS "")
        foreach(EXLIB ${SGX_LIBS})
            list(APPEND EXTRA_LIBS "-l${EXLIB}")
        endforeach()

        target_link_libraries(${target} "${SGX_COMMON_CFLAGS} ${SGX_SECURITY_FLAGS} \
            -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L${SGX_LIBRARY_PATH} ${EXTRA_LIB_PATHS} \
            -Wl,--start-group ${EXTRA_LIBS} -lsgx_tstdc -lsgx_tcxx -lsgx_tkey_exchange -lsgx_tcrypto -lsgx_protobuf -l${SGX_TSVC_LIB} -Wl,--end-group \
            -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
            -Wl,-pie,-eenclave_entry -Wl,--export-dynamic \
            ${LDSCRIPT_FLAG} \
            -Wl,--defsym,__ImageBase=0")
    endfunction()

    # build enclave shared library
    function(add_enclave_library target)
        set(optionArgs USE_PREFIX)
        set(oneValueArgs EDL LDSCRIPT)
        set(multiValueArgs SRCS TRUSTED_LIBS EDL_SEARCH_PATHS LIB_PATHS LIBS)
        cmake_parse_arguments("SGX" "${optionArgs}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})
        if("${SGX_EDL}" STREQUAL "")
            message(FATAL_ERROR "${target}: SGX enclave edl file is not provided!")
        endif()
        if("${SGX_EDL_SEARCH_PATHS}" STREQUAL "")
            message("${target}: SGX enclave edl file search paths are not provided!")
        endif()
        if(NOT "${SGX_LDSCRIPT}" STREQUAL "")
            get_filename_component(LDS_ABSPATH ${SGX_LDSCRIPT} ABSOLUTE)
            set(LDSCRIPT_FLAG "-Wl,--version-script=${LDS_ABSPATH}")
        endif()

        _build_edl_obj(${SGX_EDL} "${SGX_EDL_SEARCH_PATHS}" ${SGX_USE_PREFIX})

        add_library(${target} SHARED ${SGX_SRCS} $<TARGET_OBJECTS:${target}-edlobj>)
        set_target_properties(${target} PROPERTIES COMPILE_FLAGS ${ENCLAVE_CXX_FLAGS})
        target_include_directories(${target} PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${ENCLAVE_INC_DIRS})

        set(TLIB_LIST "")
        foreach(TLIB ${SGX_TRUSTED_LIBS})
            string(APPEND TLIB_LIST "$<TARGET_FILE:${TLIB}> ")
            add_dependencies(${target} ${TLIB})
        endforeach()

        set(EXTRA_LIB_PATHS "")
        foreach(EXLIBPATH ${SGX_LIB_PATHS})
            list(APPEND EXTRA_LIB_PATHS "-L${EXLIBPATH}")
        endforeach()

        set(EXTRA_LIBS "")
        foreach(EXLIB ${SGX_LIBS})
            list(APPEND EXTRA_LIBS "-l${EXLIB}")
        endforeach()

        target_link_libraries(${target} "${SGX_COMMON_CFLAGS} ${SGX_SECURITY_FLAGS}\
            -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L${SGX_LIBRARY_PATH} ${EXTRA_LIB_PATHS}\
            -Wl,--whole-archive -l${SGX_TRTS_LIB} -Wl,--no-whole-archive \
            -Wl,--start-group ${TLIB_LIST} ${EXTRA_LIBS} -lsgx_tstdc -lsgx_tcxx -lsgx_tkey_exchange -lsgx_tcrypto -lsgx_protobuf -l${SGX_TSVC_LIB} -Wl,--end-group \
            -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
            -Wl,-pie,-eenclave_entry -Wl,--export-dynamic \
            ${LDSCRIPT_FLAG} \
            -Wl,--defsym,__ImageBase=0")
    endfunction()

    # sign the enclave, according to configurations one-step or two-step signing will be performed.
    # default one-step signing output enclave name is target.signed.so, change it with OUTPUT option.
    function(enclave_sign target)
        set(optionArgs IGNORE_INIT IGNORE_REL)
        set(oneValueArgs KEY CONFIG OUTPUT)
        cmake_parse_arguments("SGX" "${optionArgs}" "${oneValueArgs}" "" ${ARGN})
        if("${SGX_CONFIG}" STREQUAL "")
            message("${target}: SGX enclave config is not provided!")
        else()
            get_filename_component(CONFIG_ABSPATH ${SGX_CONFIG} ABSOLUTE)
        endif()
        if("${SGX_KEY}" STREQUAL "")
            if (NOT SGX_HW OR NOT SGX_MODE STREQUAL "Release")
                message(FATAL_ERROR "${target}: Private key used to sign enclave is not provided!")
            endif()
        else()
            get_filename_component(KEY_ABSPATH ${SGX_KEY} ABSOLUTE)
        endif()
        if("${SGX_OUTPUT}" STREQUAL "")
            set(OUTPUT_NAME "${target}.signed.so")
        else()
            set(OUTPUT_NAME ${SGX_OUTPUT})
        endif()
	if(${SGX_IGNORE_INIT})
	    set(IGN_INIT "-ignore-init-sec-error")
	endif()
	if(${SGX_IGNORE_REL})
	    set(IGN_REL "-ignore-rel-error")
	endif()

        if(SGX_HW AND SGX_MODE STREQUAL "Release")
            add_custom_target(${target}-sign ALL
                              COMMAND ${SGX_ENCLAVE_SIGNER} gendata
                                      $<$<NOT:$<STREQUAL:${SGX_CONFIG},>>:-config> $<$<NOT:$<STREQUAL:${SGX_CONFIG},>>:${CONFIG_ABSPATH}>
                                      -enclave $<TARGET_FILE:${target}> -out $<TARGET_FILE_DIR:${target}>/${target}_hash.hex ${IGN_INIT} ${IGN_REL}
                              COMMAND ${CMAKE_COMMAND} -E cmake_echo_color
                                  --cyan "SGX production enclave first step signing finished, \
    use ${CMAKE_CURRENT_BINARY_DIR}/${target}_hash.hex for second step"
                              WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
        else()
            add_custom_target(${target}-sign ALL ${SGX_ENCLAVE_SIGNER} sign -key ${KEY_ABSPATH}
                              $<$<NOT:$<STREQUAL:${SGX_CONFIG},>>:-config> $<$<NOT:$<STREQUAL:${SGX_CONFIG},>>:${CONFIG_ABSPATH}>
                              -enclave $<TARGET_FILE:${target}>
                              -out $<TARGET_FILE_DIR:${target}>/${OUTPUT_NAME}
			      ${IGN_INIT} ${IGN_REL}
                              WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
        endif()

        set(CLEAN_FILES "$<TARGET_FILE_DIR:${target}>/${OUTPUT_NAME};$<TARGET_FILE_DIR:${target}>/${target}_hash.hex")
        set_property(DIRECTORY APPEND PROPERTY ADDITIONAL_MAKE_CLEAN_FILES "${CLEAN_FILES}")
    endfunction()

    function(add_untrusted_library target mode)
        set(optionArgs USE_PREFIX)
        set(multiValueArgs SRCS EDL EDL_SEARCH_PATHS)
        cmake_parse_arguments("SGX" "${optionArgs}" "" "${multiValueArgs}" ${ARGN})
        if("${SGX_EDL}" STREQUAL "")
            message(FATAL_ERROR "${target}: SGX enclave edl file is not provided!")
        endif()
        if("${SGX_EDL_SEARCH_PATHS}" STREQUAL "")
            message("${target}: SGX enclave edl file search paths are not provided!")
        endif()

        set(EDL_U_SRCS "")
        foreach(EDL ${SGX_EDL})
            get_filename_component(EDL_NAME ${EDL} NAME_WE)
            get_filename_component(EDL_ABSPATH ${EDL} ABSOLUTE)
            set(EDL_U_C "${CMAKE_CURRENT_BINARY_DIR}/${EDL_NAME}_u.c")
            set(SEARCH_PATHS "")
            foreach(path ${SGX_EDL_SEARCH_PATHS})
                get_filename_component(ABSPATH ${path} ABSOLUTE)
                list(APPEND SEARCH_PATHS "${ABSPATH}")
            endforeach()
            list(APPEND SEARCH_PATHS "${SGX_PATH}/include")
            string(REPLACE ";" ":" SEARCH_PATHS "${SEARCH_PATHS}")
            if(${SGX_USE_PREFIX})
                set(USE_PREFIX "--use-prefix")
            endif()
            add_custom_command(OUTPUT ${EDL_U_C}
                               COMMAND ${SGX_EDGER8R} ${USE_PREFIX} --untrusted ${EDL_ABSPATH} --search-path ${SEARCH_PATHS}
                               MAIN_DEPENDENCY ${EDL_ABSPATH}
                               WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
            add_library(${target}-edluobj OBJECT ${EDL_U_C})
            set_target_properties(${target}-edluobj PROPERTIES COMPILE_FLAGS ${APP_C_FLAGS})

            list(APPEND EDL_U_SRCS $<TARGET_OBJECTS:${target}-edluobj>)
        endforeach()

        add_library(${target} ${mode} ${SGX_SRCS} ${EDL_U_SRCS})
        set_target_properties(${target} PROPERTIES COMPILE_FLAGS ${APP_CXX_FLAGS})
        target_include_directories(${target} PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${APP_INC_DIRS})
        target_link_libraries(${target} "${SGX_COMMON_CFLAGS} \
                                         -L${SGX_LIBRARY_PATH} \
                                         -l${SGX_URTS_LIB} \
                                         -l${SGX_EPID_LIB} \
                                         -l${SGX_QUOTE_LIB} \
                                         -lsgx_ukey_exchange \
                                         -lcrypto \
                                         -lssl \
                                         -lpthread")

        set_property(DIRECTORY APPEND PROPERTY ADDITIONAL_MAKE_CLEAN_FILES "${CMAKE_CURRENT_BINARY_DIR}/${EDL_NAME}_u.h")
    endfunction()

    function(add_untrusted_executable target)
        set(optionArgs USE_PREFIX)
        set(multiValueArgs SRCS EDL EDL_SEARCH_PATHS LIB_PATHS LIBS)
        cmake_parse_arguments("SGX" "${optionArgs}" "" "${multiValueArgs}" ${ARGN})
        if("${SGX_EDL}" STREQUAL "")
            message(FATAL_ERROR "${target}: SGX enclave edl file is not provided!")
        endif()
        if("${SGX_EDL_SEARCH_PATHS}" STREQUAL "")
            message("${target}: SGX enclave edl file search paths are not provided!")
        endif()

        set(EDL_U_SRCS "")
        foreach(EDL ${SGX_EDL})
            get_filename_component(EDL_NAME ${EDL} NAME_WE)
            get_filename_component(EDL_ABSPATH ${EDL} ABSOLUTE)
            set(EDL_U_C "${CMAKE_CURRENT_BINARY_DIR}/${EDL_NAME}_u.c")
            set(EDL_U_H "${CMAKE_CURRENT_BINARY_DIR}/${EDL_NAME}_u.h")
            set(SEARCH_PATHS "")
            foreach(path ${SGX_EDL_SEARCH_PATHS})
                get_filename_component(ABSPATH ${path} ABSOLUTE)
                list(APPEND SEARCH_PATHS "${ABSPATH}")
            endforeach()
            list(APPEND SEARCH_PATHS "${SGX_PATH}/include")
            string(REPLACE ";" ":" SEARCH_PATHS "${SEARCH_PATHS}")
            if(${SGX_USE_PREFIX})
                set(USE_PREFIX "--use-prefix")
            endif()
            add_custom_command(OUTPUT ${EDL_U_C}
                               COMMAND ${SGX_EDGER8R} ${USE_PREFIX} --untrusted ${EDL_ABSPATH} --search-path ${SEARCH_PATHS}
                               MAIN_DEPENDENCY ${EDL_ABSPATH}
                               WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
            add_library(${target}-${EDL_NAME}-edluobj OBJECT ${EDL_U_C})
            set_target_properties(${target}-${EDL_NAME}-edluobj PROPERTIES COMPILE_FLAGS ${APP_C_FLAGS})

            list(APPEND EDL_U_SRCS $<TARGET_OBJECTS:${target}-${EDL_NAME}-edluobj>)
            list(APPEND EDL_U_HDRS ${EDL_U_H})
        endforeach()

        set(EXTRA_LIB_PATHS "")
        foreach(EXLIBPATH ${SGX_LIB_PATHS})
            list(APPEND EXTRA_LIB_PATHS "-L${EXLIBPATH}")
        endforeach()

        set(EXTRA_LIBS "")
        foreach(EXLIB ${SGX_LIBS})
            list(APPEND EXTRA_LIBS "-l${EXLIB}")
        endforeach()

        add_executable(${target} ${SGX_SRCS} ${EDL_U_SRCS})
        set_target_properties(${target} PROPERTIES COMPILE_FLAGS ${APP_CXX_FLAGS})
        target_include_directories(${target} PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${APP_INC_DIRS})
        target_link_libraries(${target} "${SGX_COMMON_CFLAGS} \
                                         -L${SGX_LIBRARY_PATH} \
                                         ${EXTRA_LIB_PATHS} \
                                         ${EXTRA_LIBS} \
                                         -l${SGX_URTS_LIB} \
                                         -l${SGX_EPID_LIB} \
                                         -l${SGX_QUOTE_LIB} \
                                         -lsgx_ukey_exchange \
                                         -lcrypto \
                                         -lssl \
                                         -lpthread")
        set_property(DIRECTORY APPEND PROPERTY ADDITIONAL_MAKE_CLEAN_FILES ${EDL_U_HDRS})
    endfunction()

    function(sign_and_install target)
        if(SGX_HW AND SGX_MODE STREQUAL "Release")
        message(STATUS "${target} DisableDebug = 1")
        enclave_sign(${target}
                     KEY ${ENCLAVE_TEST_KEY}
                     CONFIG "${target}.config.xml"
                     OUTPUT "${target}.signed.so")
        else()
        message(STATUS "${target} DisableDebug = 0")
        enclave_sign(${target}
                     KEY ${ENCLAVE_TEST_KEY}
                     CONFIG "${target}_debug.config.xml"
                     OUTPUT "${target}.signed.so")
        endif()

        install(TARGETS ${target}
                DESTINATION ${target}
                PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)

        # In release mode the hash of the enclave code needs to be signed before producing the signed
        # enclave object
        if(SGX_HW AND SGX_MODE STREQUAL "Release")
            install(FILES "$<TARGET_FILE_DIR:${target}>/${target}_hash.hex"
                    DESTINATION worker_enclave
                    PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
        else()
            install(FILES "$<TARGET_FILE_DIR:${target}>/${target}.signed.so"
                DESTINATION worker_enclave
                PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)

            install(FILES "$<TARGET_FILE_DIR:${target}>/${target}.signed.so"
                DESTINATION ../
                PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
        endif()
    endfunction()

    function(SGX_PROTOBUF_GENERATE_CPP SRCS HDRS)
        if(NOT ARGN)
            message(SEND_ERROR "Error: SGX_PROTOBUF_GENERATE_CPP() called without any proto files")
            return()
        endif()

        set(${SRCS})
        set(${HDRS})
        foreach(FIL ${ARGN})
            get_filename_component(ABS_FIL ${FIL} ABSOLUTE)
            get_filename_component(FIL_WE ${FIL} NAME_WE)

            list(APPEND ${SRCS} "${CMAKE_CURRENT_BINARY_DIR}/${FIL_WE}.pb.cc")
            list(APPEND ${HDRS} "${CMAKE_CURRENT_BINARY_DIR}/${FIL_WE}.pb.h")

            add_custom_command(
            OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/${FIL_WE}.pb.cc"
                    "${CMAKE_CURRENT_BINARY_DIR}/${FIL_WE}.pb.h"
            COMMAND ${SGX_PROTOC}
            ARGS --cpp_out ${CMAKE_CURRENT_BINARY_DIR} -I ${CMAKE_CURRENT_SOURCE_DIR} ${ABS_FIL}
            DEPENDS ${ABS_FIL} ${SGX_PROTOC}
            COMMENT "Running sgx C++ protocol buffer compiler on ${FIL}"
            VERBATIM )
        endforeach()

        set_source_files_properties(${${SRCS}} ${${HDRS}} PROPERTIES GENERATED TRUE)
        set(${SRCS} ${${SRCS}} PARENT_SCOPE)
        set(${HDRS} ${${HDRS}} PARENT_SCOPE)
    endfunction()

else(SGX_FOUND)
    message(WARNING "Intel SGX SDK not found!")
    if(SGX_FIND_REQUIRED)
        message(FATAL_ERROR "Could NOT find Intel SGX SDK!")
    endif()
endif(SGX_FOUND)
