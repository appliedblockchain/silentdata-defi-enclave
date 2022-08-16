#pragma once

#include <sgx_tcrypto.h>

#include "include/core_constants.h"

#include "lib/common/sgx_error_message.hpp"
#include "lib/crypto/aes_gcm_key.hpp"

namespace silentdata
{
namespace enclave
{

class EC256KeyPair
{
private:
    sgx_ec256_private_t private_key_;
    sgx_ec256_public_t public_key_;

public:
    EC256KeyPair();

    const sgx_ec256_private_t &private_key() const { return private_key_; }
    const sgx_ec256_public_t &public_key() const { return public_key_; }

    std::array<uint8_t, CORE_ECC_PRIVATE_KEY_LEN> private_key_bytes() const;
    std::array<uint8_t, CORE_ECC_KEY_LEN> public_key_bytes() const;

    void generate_keys();
    void set_private_key(const sgx_ec256_private_t &private_key);
    void set_private_key(const std::array<uint8_t, CORE_ECC_PRIVATE_KEY_LEN> &private_key_bytes);
    void set_private_key(const std::vector<uint8_t> &private_key_bytes);

    // Perform an elliptic-curve Diffie-Hellman key exchange and derive a key usable for AES
    // encryption
    AESGCMKey ecdh(const uint8_t *peer_public_key_bytes) const;
};

} // namespace enclave
} // namespace silentdata
