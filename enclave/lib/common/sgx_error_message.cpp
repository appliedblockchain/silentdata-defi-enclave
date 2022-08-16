#include "lib/common/sgx_error_message.hpp"

#include <mbusafecrt.h>

std::string sgx_error_message(const std::string &method, const sgx_status_t &status)
{
    char hex[5];
    sprintf_s(hex, 5, "%x", status);
    std::string error_message = method + " SGX call failed with error 0x" + std::string(hex);
    if (sgx_status_map.find(status) != sgx_status_map.end())
    {
        error_message +=
            ": (" + sgx_status_map.at(status).name + ") " + sgx_status_map.at(status).message;
    }
    return error_message;
}
