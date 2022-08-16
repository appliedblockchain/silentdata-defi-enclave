#include "lib/ias/report.hpp"

using json::JSON;

namespace silentdata
{
namespace enclave
{

std::array<uint8_t, CORE_SHA_256_LEN>
get_public_keys_hash(const std::array<uint8_t, CORE_ECC_KEY_LEN> &encryption_public_key,
                     const std::array<uint8_t, CORE_ED25519_KEY_LEN> &ed25519_signing_public_key)
{
    // Concatenate the public key data
    std::array<uint8_t, CORE_ECC_KEY_LEN + CORE_ED25519_KEY_LEN> public_keys;
    std::copy(encryption_public_key.begin(), encryption_public_key.end(), public_keys.begin());
    std::copy(ed25519_signing_public_key.begin(),
              ed25519_signing_public_key.end(),
              std::next(public_keys.begin(), encryption_public_key.size()));

    // Get the hash digest of the key data
    sgx_sha256_hash_t hash;
    const sgx_status_t sgx_status =
        sgx_sha256_msg(public_keys.data(), static_cast<uint32_t>(public_keys.size()), &hash);
    if (sgx_status != SGX_SUCCESS)
        THROW_EXCEPTION(sgx_error_status(sgx_status),
                        sgx_error_message("sgx_sha256_msg", sgx_status));

    std::array<uint8_t, CORE_SHA_256_LEN> result;
    memcpy(result.data(), hash, CORE_SHA_256_LEN);

    return result;
}

sgx_report_t get_report(const sgx_target_info_t &quoting_enclave_target_info,
                        const std::array<uint8_t, CORE_ECC_KEY_LEN> &encryption_public_key,
                        const std::array<uint8_t, CORE_ED25519_KEY_LEN> &ed25519_signing_public_key)
{
    // Hash the public keys & add it to the report data
    DEBUG_LOG("Creating hash of public keys");
    const std::array<uint8_t, CORE_SHA_256_LEN> hash =
        get_public_keys_hash(encryption_public_key, ed25519_signing_public_key);

    sgx_report_data_t report_data = {{0}};
    memcpy(&report_data, hash.data(), CORE_SHA_256_LEN);

    DEBUG_LOG("Creating report");
    sgx_report_t report;
    const sgx_status_t status =
        sgx_create_report(&quoting_enclave_target_info, &report_data, &report);
    if (status != SGX_SUCCESS)
        THROW_ERROR_CODE(sgx_error_status(status));

    return report;
}

} // namespace enclave
} // namespace silentdata
