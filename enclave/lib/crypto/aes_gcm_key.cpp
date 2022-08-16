#include "lib/crypto/aes_gcm_key.hpp"

namespace silentdata
{
namespace enclave
{

std::vector<uint8_t> AESGCMKey::encrypt(const std::vector<uint8_t> &input,
                                        const std::vector<uint8_t> &aad) const
{
    // Set the initialisation vector
    std::array<uint8_t, CORE_IV_LEN> iv{};
    sgx_status_t sgx_status;
    sgx_status = sgx_read_rand(iv.data(), iv.size());
    if (sgx_status != SGX_SUCCESS)
        THROW_EXCEPTION(sgx_error_status(sgx_status),
                        sgx_error_message("sgx_read_rand", sgx_status).c_str());

    std::vector<uint8_t> output(CORE_MAC_LEN + CORE_IV_LEN + input.size(), '\0');
    sgx_aes_gcm_128bit_tag_t mac;
    // Encrypt the information with the symmetric key
    sgx_status = sgx_rijndael128GCM_encrypt(&symmetric_key,
                                            input.data(),
                                            static_cast<uint32_t>(input.size()),
                                            output.data() + CORE_MAC_LEN + CORE_IV_LEN,
                                            const_cast<const uint8_t *>(iv.data()),
                                            CORE_IV_LEN,
                                            aad.data(),
                                            static_cast<uint32_t>(aad.size()),
                                            &mac);
    if (sgx_status != SGX_SUCCESS)
        THROW_EXCEPTION(sgx_error_status(sgx_status),
                        sgx_error_message("sgx_rijndael128GCM_encrypt", sgx_status).c_str());

    // Put the MAC and IV at the start of the output
    std::copy(std::begin(mac), std::end(mac), output.data());
    std::copy(iv.begin(), iv.end(), output.data() + CORE_MAC_LEN);

    return output;
}

std::vector<uint8_t> AESGCMKey::decrypt(const std::vector<uint8_t> &input,
                                        const std::vector<uint8_t> &aad) const
{
    if (input.size() < CORE_IV_LEN + CORE_MAC_LEN)
        THROW_EXCEPTION(kDecryptionError, "Encrypted input not long enough to contain MAC and IV");
    const size_t ciphertext_len = input.size() - CORE_IV_LEN - CORE_MAC_LEN;
    std::vector<uint8_t> output(ciphertext_len, '\0');
    const sgx_status_t sgx_status = sgx_rijndael128GCM_decrypt(
        &symmetric_key,
        input.size() == 0 ? nullptr : input.data() + CORE_MAC_LEN + CORE_IV_LEN,
        static_cast<uint32_t>(ciphertext_len),
        output.data(),
        input.data() + CORE_MAC_LEN,
        CORE_IV_LEN,
        aad.data(),
        static_cast<uint32_t>(aad.size()),
        reinterpret_cast<const sgx_aes_gcm_128bit_tag_t *>(input.data()));
    if (sgx_status != SGX_SUCCESS)
        THROW_EXCEPTION(sgx_error_status(sgx_status),
                        sgx_error_message("sgx_rijndael128GCM_decrypt", sgx_status).c_str());

    return output;
}

} // namespace enclave
} // namespace silentdata
