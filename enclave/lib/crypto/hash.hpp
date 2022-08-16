#pragma once

#include <array>
#include <vector>

#include <sgx_tcrypto.h>

#include "include/core_constants.h"

#include "lib/eddsa/sha512-256.h"
#include "lib/eddsa/sha512.h"

namespace silentdata
{
namespace enclave
{

class Hash
{
public:
    enum Algorithm
    {
        SHA512,
        SHA512_256,
        SHA256
    };

    static std::vector<uint8_t> get_digest(const Algorithm &algorithm,
                                           const std::vector<uint8_t> &message);
    static std::array<uint8_t, CORE_SHA_512_LEN>
    get_SHA_512_digest(const std::vector<uint8_t> &message);
    static std::array<uint8_t, CORE_SHA_512_256_LEN>
    get_SHA_512_256_digest(const std::vector<uint8_t> &message);
    static std::array<uint8_t, CORE_SHA_256_LEN>
    get_SHA_256_digest(const std::vector<uint8_t> &message);
};

} // namespace enclave
} // namespace silentdata
