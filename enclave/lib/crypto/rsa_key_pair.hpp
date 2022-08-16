#pragma once

#include <array>
#include <vector>

#include "sgx_tcrypto.h"

#include "include/core_constants.h"

#include "lib/common/enclave_exception.hpp"
#include "lib/common/enclave_logger.hpp"
#include "lib/common/sgx_error_message.hpp"

namespace silentdata
{
namespace enclave
{

class RSAKeyPair
{
public:
    sgx_rsa3072_key_t private_key;
    sgx_rsa3072_public_key_t public_key;
    RSAKeyPair();

    // Create an RSA signature
    std::array<uint8_t, CORE_RSA_SIG_LEN> sign(const std::vector<uint8_t> &data) const;
};

} // namespace enclave
} // namespace silentdata
