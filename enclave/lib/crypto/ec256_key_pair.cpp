#include "ec256_key_pair.hpp"
#include <ipp/ippcp.h>

#include "lib/common/enclave_exception.hpp"

namespace silentdata
{
namespace enclave
{

EC256KeyPair::EC256KeyPair() { this->generate_keys(); }

void EC256KeyPair::generate_keys()
{
    sgx_ecc_state_handle_t handle;

    auto ret = sgx_ecc256_open_context(&handle);
    if (ret != SGX_SUCCESS)
        THROW_EXCEPTION(sgx_error_status(ret), sgx_error_message("sgx_ecc256_open_context", ret));

    ret = sgx_ecc256_create_key_pair(&private_key_, &public_key_, handle);
    if (ret != SGX_SUCCESS)
    {
        sgx_ecc256_close_context(handle);
        THROW_EXCEPTION(sgx_error_status(ret),
                        sgx_error_message("sgx_ecc256_create_key_pair", ret));
    }

    ret = sgx_ecc256_close_context(handle);
    if (ret != SGX_SUCCESS)
        THROW_EXCEPTION(sgx_error_status(ret), sgx_error_message("sgx_ecc256_close_context", ret));
}

std::array<uint8_t, CORE_ECC_PRIVATE_KEY_LEN> EC256KeyPair::private_key_bytes() const
{
    std::array<uint8_t, CORE_ECC_PRIVATE_KEY_LEN> bytes;
    memcpy(bytes.data(), private_key_.r, CORE_ECC_PRIVATE_KEY_LEN);

    return bytes;
}

std::array<uint8_t, CORE_ECC_KEY_LEN> EC256KeyPair::public_key_bytes() const
{
    std::array<uint8_t, CORE_ECC_KEY_LEN> bytes;
    memcpy(bytes.data(), public_key_.gx, CORE_ECC_GXY_LEN);
    memcpy(bytes.data() + CORE_ECC_GXY_LEN, public_key_.gy, CORE_ECC_GXY_LEN);

    return bytes;
}

void EC256KeyPair::set_private_key(const sgx_ec256_private_t &private_key)
{
    sgx_ec256_public_t new_public_key;
    const auto status = sgx_ecc256_calculate_pub_from_priv(&private_key, &new_public_key);
    if (status != SGX_SUCCESS)
    {
        THROW_EXCEPTION(sgx_error_status(status),
                        sgx_error_message("sgx_ecc256_calculate_pub_from_priv", status));
    }

    private_key_ = private_key;
    public_key_ = new_public_key;
}

void EC256KeyPair::set_private_key(
    const std::array<uint8_t, CORE_ECC_PRIVATE_KEY_LEN> &private_key_bytes)
{
    sgx_ec256_private_t private_key;
    memcpy(private_key.r, private_key_bytes.data(), CORE_ECC_PRIVATE_KEY_LEN);
    this->set_private_key(private_key);
}

void EC256KeyPair::set_private_key(const std::vector<uint8_t> &private_key_bytes)
{
    if (private_key_bytes.size() != CORE_ECC_PRIVATE_KEY_LEN)
        THROW_EXCEPTION(kInvalidInput, "Input private key bytes has the wrong size");

    sgx_ec256_private_t private_key;
    memcpy(private_key.r, private_key_bytes.data(), CORE_ECC_PRIVATE_KEY_LEN);
    this->set_private_key(private_key);
}

AESGCMKey EC256KeyPair::ecdh(const uint8_t *peer_public_key_bytes) const
{

    sgx_ec256_public_t peer_public_key;
    memcpy(peer_public_key.gx, peer_public_key_bytes, CORE_ECC_GXY_LEN);
    memcpy(peer_public_key.gy, peer_public_key_bytes + CORE_ECC_GXY_LEN, CORE_ECC_GXY_LEN);

    sgx_ecc_state_handle_t handle;
    sgx_status_t sgx_status = sgx_ecc256_open_context(&handle);
    if (sgx_status != SGX_SUCCESS)
        THROW_EXCEPTION(kECDHError, sgx_error_message("sgx_ecc256_open_context", sgx_status));

    sgx_ec256_dh_shared_t shared_secret_full{};

    // This will generate a little-endian x coordinate of a point on the elliptic curve (256 bit)
    sgx_status = sgx_ecc256_compute_shared_dhkey(
        &private_key_, &peer_public_key, &shared_secret_full, handle);
    if (sgx_status != SGX_SUCCESS)
    {
        sgx_ecc256_close_context(handle);
        THROW_EXCEPTION(kECDHError,
                        sgx_error_message("sgx_ecc256_compute_shared_dhkey", sgx_status));
    }

    sgx_status = sgx_ecc256_close_context(handle);
    if (sgx_status != SGX_SUCCESS)
        THROW_EXCEPTION(kECDHError, sgx_error_message("sgx_ecc256_close_context", sgx_status));

    // "Key derivation": Take the first 16 bits of the big-endian representation
    // to replicate what the JS code does
    sgx_aes_gcm_128bit_key_t shared_secret;
    for (size_t i = 0; i < CORE_SHARED_SECRET_BITS; i++)
    {
        shared_secret[i] = shared_secret_full.s[31 - i];
    }

    return AESGCMKey(&shared_secret);
}

} // namespace enclave
} // namespace silentdata
