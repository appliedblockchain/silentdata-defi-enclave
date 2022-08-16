#include "ed25519_key_pair.hpp"
#include <ipp/ippcp.h>

#include "lib/common/enclave_exception.hpp"

namespace silentdata
{
namespace enclave
{

ED25519KeyPair::ED25519KeyPair() { this->generate_keys(); }

void ED25519KeyPair::generate_keys()
{
    // Generate random bytes for the private key
    const sgx_status_t sgx_status = sgx_read_rand(private_key_.data(), ED25519_KEY_LEN);
    if (sgx_status != SGX_SUCCESS)
        THROW_EXCEPTION(sgx_error_status(sgx_status),
                        sgx_error_message("sgx_read_rand", sgx_status).c_str());

    // Generate a public key from the private key
    ed25519_genpub(public_key_.data(), private_key_.data());
}

void ED25519KeyPair::set_private_key(const std::vector<uint8_t> &private_key)
{
    if (private_key.size() != ED25519_KEY_LEN)
        THROW_EXCEPTION(kInvalidInput, "Supplied private key has incorrect size");

    std::array<uint8_t, ED25519_KEY_LEN> private_key_array;
    std::copy(private_key.begin(), private_key.end(), private_key_array.begin());

    this->set_private_key(private_key_array);
}

void ED25519KeyPair::set_private_key(const std::array<uint8_t, ED25519_KEY_LEN> &private_key)
{
    std::memcpy(private_key_.data(), private_key.data(), private_key.size());
    ed25519_genpub(public_key_.data(), private_key_.data());
}

std::array<uint8_t, ED25519_SIG_LEN> ED25519KeyPair::sign(const std::vector<uint8_t> &data) const
{
    std::array<uint8_t, ED25519_SIG_LEN> signature{};
    ed25519_sign(
        signature.data(), private_key_.data(), public_key_.data(), data.data(), data.size());
    return signature;
}

std::array<uint8_t, ED25519_SIG_LEN>
ED25519KeyPair::algorand_sign(const std::vector<uint8_t> &data,
                              const std::array<uint8_t, CORE_SHA_512_256_LEN> &program_hash) const
{
    std::vector<uint8_t> to_sign;
    const std::string prefix = "ProgData";
    to_sign.insert(to_sign.end(), prefix.begin(), prefix.end());
    to_sign.insert(to_sign.end(), program_hash.begin(), program_hash.end());
    to_sign.insert(to_sign.end(), data.begin(), data.end());

    return sign(to_sign);
}

bool ED25519KeyPair::verify(const std::vector<uint8_t> &data,
                            const std::array<uint8_t, ED25519_SIG_LEN> &signature) const
{
    return ed25519_verify(signature.data(), public_key_.data(), data.data(), data.size());
}

} // namespace enclave
} // namespace silentdata
