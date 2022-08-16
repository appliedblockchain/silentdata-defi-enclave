#pragma once

#include <array>
#include <vector>

#include "sgx_tcrypto.h"
#include "sgx_trts.h"

#include "include/core_constants.h"

#include "lib/common/enclave_exception.hpp"
#include "lib/common/enclave_logger.hpp"
#include "lib/common/sgx_error_message.hpp"

namespace silentdata
{
namespace enclave
{

class AESGCMKey
{
public:
    sgx_aes_gcm_128bit_key_t symmetric_key;
    AESGCMKey() {}
    AESGCMKey(const sgx_aes_gcm_128bit_key_t *shared_secret)
    {
        memcpy(symmetric_key, shared_secret, sizeof(sgx_aes_gcm_128bit_key_t));
    }

    // Encrypt data using AES-GCM
    std::vector<uint8_t> encrypt(const std::vector<uint8_t> &input,
                                 const std::vector<uint8_t> &aad = {}) const;

    // Decrypt data using AES-GCM and or check additional authenticated data
    std::vector<uint8_t> decrypt(const std::vector<uint8_t> &input,
                                 const std::vector<uint8_t> &aad = {}) const;
};

} // namespace enclave
} // namespace silentdata
