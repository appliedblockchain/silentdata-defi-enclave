#pragma once

#include <map>
#include <stdexcept>
#include <string>

#include "include/core_status_codes.h"
#include "include/core_status_message.h"

namespace silentdata
{
namespace enclave
{

class EnclaveException : public std::runtime_error
{
    std::string message_;
    CoreStatusCode code_;

public:
    EnclaveException(
        CoreStatusCode code, const std::string &info, const char *file, const char *func, int line)
        : std::runtime_error(info), code_(code)
    {
        const char *file_name = strrchr(file, '/');
        if (file_name == nullptr)
            file_name = file;
        else
            file_name = file_name + 1;
        message_ = std::string(file_name) + ":" + std::string(func) + ":" + std::to_string(line) +
                   ": " + "(" + core_status_name(code) + "-" +
                   std::to_string(static_cast<int>(code)) + ") " + std::string(info);
    }

    EnclaveException(CoreStatusCode code, const char *file, const char *func, int line)
        : std::runtime_error(""), code_(code)
    {
        const char *file_name = strrchr(file, '/');
        if (file_name == nullptr)
            file_name = file;
        else
            file_name = file_name + 1;
        message_ = std::string(file_name) + ":" + std::string(func) + ":" + std::to_string(line) +
                   ": " + core_status_message(code);
    }

    const char *what() const throw() { return message_.c_str(); }

    CoreStatusCode get_code() const { return code_; }
    void set_code(CoreStatusCode code) { code_ = code; }
};
#define THROW_EXCEPTION(code, arg) throw EnclaveException(code, arg, __FILE__, __func__, __LINE__);
#define THROW_ERROR_CODE(code) throw EnclaveException(code, __FILE__, __func__, __LINE__);

} // namespace enclave
} // namespace silentdata
