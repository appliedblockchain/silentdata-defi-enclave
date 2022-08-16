#include "lib/crypto/hash.hpp"

#include "lib/common/enclave_exception.hpp"

namespace silentdata
{
namespace enclave
{

std::vector<uint8_t> Hash::get_digest(const Algorithm &algorithm,
                                      const std::vector<uint8_t> &message)
{
    switch (algorithm)
    {
    case SHA512:
    {
        const auto hash = Hash::get_SHA_512_digest(message);
        return std::vector<uint8_t>(hash.begin(), hash.end());
    }
    case SHA512_256:
    {
        const auto hash = Hash::get_SHA_512_256_digest(message);
        return std::vector<uint8_t>(hash.begin(), hash.end());
    }
    case SHA256:
    {
        const auto hash = Hash::get_SHA_256_digest(message);
        return std::vector<uint8_t>(hash.begin(), hash.end());
    }
    default:
        THROW_EXCEPTION(kInvalidInput, "Input hashing algorithm not supported");
    }
}

std::array<uint8_t, CORE_SHA_512_LEN> Hash::get_SHA_512_digest(const std::vector<uint8_t> &message)
{
    std::array<uint8_t, CORE_SHA_512_LEN> output;

    struct sha512 hash;
    sha512_init(&hash);
    sha512_add(&hash, message.data(), message.size());
    sha512_final(&hash, output.begin());

    return output;
}

std::array<uint8_t, CORE_SHA_512_256_LEN>
Hash::get_SHA_512_256_digest(const std::vector<uint8_t> &message)
{
    std::array<uint8_t, CORE_SHA_512_256_LEN> output;

    struct sha512_256 hash;
    sha512_256_init(&hash);
    sha512_256_add(&hash, message.data(), message.size());
    sha512_256_final(&hash, output.begin());

    return output;
}

std::array<uint8_t, CORE_SHA_256_LEN> Hash::get_SHA_256_digest(const std::vector<uint8_t> &message)
{
    std::array<uint8_t, CORE_SHA_256_LEN> output;

    sgx_sha256_hash_t hash;
    sgx_status_t sgx_status =
        sgx_sha256_msg(message.data(), static_cast<uint32_t>(message.size()), &hash);

    if (sgx_status != SGX_SUCCESS)
        THROW_EXCEPTION(kSGXCryptoError, "Failed to create hash of proof type");

    std::copy(hash, hash + CORE_SHA_256_LEN, output.begin());

    return output;
}

} // namespace enclave
} // namespace silentdata
