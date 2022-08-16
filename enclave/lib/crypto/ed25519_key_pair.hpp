#pragma once

#include <array>
#include <vector>

#include "sgx_tcrypto.h"
#include "sgx_trts.h"

#include "include/core_constants.h"

#include "lib/common/sgx_error_message.hpp"
#include "lib/eddsa/eddsa.h"

namespace silentdata
{
namespace enclave
{

class ED25519KeyPair
{
private:
    std::array<uint8_t, ED25519_KEY_LEN> private_key_;
    std::array<uint8_t, ED25519_KEY_LEN> public_key_;

public:
    ED25519KeyPair();

    void generate_keys();
    void set_private_key(const std::array<uint8_t, ED25519_KEY_LEN> &private_key);
    void set_private_key(const std::vector<uint8_t> &private_key);

    const std::array<uint8_t, ED25519_KEY_LEN> &private_key() const { return private_key_; }
    const std::array<uint8_t, ED25519_KEY_LEN> &public_key() const { return public_key_; }

    // Create an ED25519 signature
    std::array<uint8_t, ED25519_SIG_LEN> sign(const std::vector<uint8_t> &data) const;
    // Create an algorand contract compatible ED25519 signature
    std::array<uint8_t, ED25519_SIG_LEN>
    algorand_sign(const std::vector<uint8_t> &data,
                  const std::array<uint8_t, CORE_SHA_512_256_LEN> &program_hash) const;

    bool verify(const std::vector<uint8_t> &data,
                const std::array<uint8_t, ED25519_SIG_LEN> &signature) const;
};

} // namespace enclave
} // namespace silentdata
