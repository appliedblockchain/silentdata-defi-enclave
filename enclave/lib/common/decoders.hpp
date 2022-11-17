#pragma once

#include <array>
#include <string>
#include <vector>

#include "include/core_constants.h"

#include "lib/common/enclave_exception.hpp"

namespace silentdata
{
namespace enclave
{

std::string url_decode(const std::string &url_string);
std::string b64_decode(const std::string &b64_string);
std::string hex_decode(const std::string &hex_string);

std::array<uint8_t, CORE_SHA_512_256_LEN>
hash_from_msgpack_transaction(const std::vector<uint8_t> &encoded_transaction);

std::vector<uint8_t> hex_utf8_decode(const std::vector<uint8_t> &utf8_hex_message);

} // namespace enclave
} // namespace silentdata
