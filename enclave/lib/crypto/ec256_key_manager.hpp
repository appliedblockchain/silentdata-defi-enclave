#pragma once

#include <sgx_tcrypto.h>

#include "include/core_constants.h"
#include "include/fifo_map.hpp"

#include "lib/common/sgx_error_message.hpp"
#include "lib/crypto/ec256_key_pair.hpp"

namespace silentdata
{
namespace enclave
{

class EC256KeyManager
{
private:
    nlohmann::fifo_map<std::string, EC256KeyPair> keys_;
    size_t max_size_;

public:
    EC256KeyManager(int max_size) : max_size_(max_size) {}

    bool has_key_pair(const std::string &public_key) const;
    bool has_key_pair(const std::array<uint8_t, CORE_ECC_KEY_LEN> &public_key) const;

    const EC256KeyPair &get_key_pair(const std::string &public_key) const;
    const EC256KeyPair &get_key_pair(const std::array<uint8_t, CORE_ECC_KEY_LEN> &public_key) const;

    const EC256KeyPair &generate_key();

    void remove_key_pair(const std::array<uint8_t, CORE_ECC_KEY_LEN> &public_key);
    void remove_key_pair(const std::string &public_key);
};

} // namespace enclave
} // namespace silentdata
