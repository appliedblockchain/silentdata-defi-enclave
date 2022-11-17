#pragma once

#include <array>
#include <ctype.h>
#include <string>
#include <vector>

namespace silentdata
{
namespace enclave
{

std::string url_encode(const std::string &str);
std::string hex_encode(const std::string &str);
std::string b64_encode(const std::string &str);

} // namespace enclave
} // namespace silentdata
