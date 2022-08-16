#include "lib/crypto/rsa_key_pair.hpp"

namespace silentdata
{
namespace enclave
{

RSAKeyPair::RSAKeyPair()
{
    // modulus
    unsigned char n[SGX_RSA3072_KEY_SIZE]{};
    // public exponent, we set this to 65537
    unsigned char e[SGX_RSA3072_PUB_EXP_SIZE] = {0x01, 0x00, 0x01, 0x00};
    // private exponent
    unsigned char d[SGX_RSA3072_PRI_EXP_SIZE]{};
    // prime factor
    unsigned char p[SGX_RSA3072_KEY_SIZE / 2]{};
    // prime factor
    unsigned char q[SGX_RSA3072_KEY_SIZE / 2]{};
    // d mod (p-1)
    unsigned char dmp1[SGX_RSA3072_KEY_SIZE / 2]{};
    // d mod (q-1)
    unsigned char dmq1[SGX_RSA3072_KEY_SIZE / 2]{};
    // q^-1 mod p
    unsigned char iqmp[SGX_RSA3072_KEY_SIZE / 2]{};

    const sgx_status_t result = sgx_create_rsa_key_pair(
        SGX_RSA3072_KEY_SIZE, SGX_RSA3072_PUB_EXP_SIZE, n, d, e, p, q, dmp1, dmq1, iqmp);
    if (result != SGX_SUCCESS)
        THROW_EXCEPTION(kKeyCreationError, sgx_error_message("sgx_create_rsa_key_pair", result));

    memcpy(private_key.mod, n, sizeof(n));
    memcpy(private_key.e, e, sizeof(e));
    memcpy(private_key.d, d, sizeof(d));
    memcpy(public_key.mod, n, sizeof(n));
    memcpy(public_key.exp, e, sizeof(e));
}

std::array<uint8_t, CORE_RSA_SIG_LEN> RSAKeyPair::sign(const std::vector<uint8_t> &data) const
{
    std::array<uint8_t, CORE_RSA_SIG_LEN> signature;
    DEBUG_LOG("Signing with enclaves private key");

    const sgx_status_t sgx_status =
        sgx_rsa3072_sign(data.data(),
                         static_cast<uint32_t>(data.size()),
                         &private_key,
                         reinterpret_cast<sgx_rsa3072_signature_t *>(signature.data()));
    if (sgx_status != SGX_SUCCESS)
        THROW_EXCEPTION(sgx_error_status(sgx_status),
                        sgx_error_message("sgx_rsa3072_sign", sgx_status));

    DEBUG_HEX_LOG("Signature:", signature.data(), 384);
    return signature;
}

} // namespace enclave
} // namespace silentdata
