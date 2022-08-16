#pragma once

#include <array>
#include <ctype.h>
#include <string>
#include <vector>

#include "include/core_constants.h"

#include "lib/common/enclave_exception.hpp"
#include "lib/common/enclave_logger.hpp"

namespace silentdata
{
namespace enclave
{

std::string url_encode(const std::string &str);
std::string hex_encode(const std::string &str);
std::string b64_encode(const std::string &str);
std::vector<uint8_t> unicode_utf8_bytes_encode(const std::string &str);

} // namespace enclave
} // namespace silentdata
