#include <array>
#include <cmath>
#include <cstring>
#include <functional>
#include <map>
#include <string>

#include "sgx_tcrypto.h"
#include "sgx_trts.h"
#include "sgx_utils.h"

#include "include/core_constants.h"
#include "include/core_status_codes.h"

#include "lib/common/cbor_map.hpp"
#include "lib/common/date_time.hpp"
#include "lib/common/enclave_exception.hpp"
#include "lib/common/enclave_logger.hpp"
#include "lib/common/sgx_error_message.hpp"
#include "lib/common/types.hpp"
#include "lib/crypto/ec256_key_manager.hpp"
#include "lib/crypto/ec256_key_pair.hpp"
#include "lib/crypto/ed25519_key_pair.hpp"
#include "lib/ias/report.hpp"
#include "lib/ias/verify.hpp"

#include "lib/proof/api_requests.hpp"
#include "lib/proof/proof_data.hpp"
#include "lib/proof/proof_handlers.hpp"
#include "lib/proof/proof_utils.hpp"
#include "lib/proof/wallet_requests.hpp"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wbuiltin-declaration-mismatch"
#include "enclave/worker/global.hpp"
#pragma GCC diagnostic pop

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wconversion"
#pragma GCC diagnostic ignored "-Wredundant-decls"
#pragma GCC diagnostic ignored "-Wunused-parameter"
#include "proto/messages.pb.h"
#include "proto/requests.pb.h"
#pragma GCC diagnostic pop

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wtype-limits"
#include "worker_enclave_t.h"
#pragma GCC diagnostic pop

using namespace silentdata::enclave;

EC256KeyManager ec256_key_manager(CORE_MAX_ENCRYPTION_KEYS);
EC256KeyPair provision_key_pair;
ED25519KeyPair ed25519_key_pair;

void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
}

CoreStatusCode capture_exceptions(const std::function<void()> &logic)
{
    try
    {
        logic();
    }
    catch (const EnclaveException &e)
    {
        EXCEPTION_LOG(e);
        return e.get_code();
    }
    catch (const std::exception &e)
    {
        ERROR_LOG("%s", e.what());
        return kUnknownError;
    }
    catch (...)
    {
        return kUnknownError;
    }

    return kSuccess;
}

void raise_sgx_error(const std::function<sgx_status_t()> &logic)
{
    const sgx_status_t status = logic();
    if (status != SGX_SUCCESS)
        THROW_ERROR_CODE(sgx_error_status(status));
}

std::vector<uint8_t> get_private_key_data()
{
    CBORMap cbor;
    cbor.insert("ed25519_signing_skey", ed25519_key_pair.private_key());
    cbor.insert("encryption_skey", provision_key_pair.private_key_bytes());

    return cbor.encode_cbor();
}

void set_keys_from_private_key_data(const std::vector<uint8_t> &private_key_data)
{
    // Parse as CBOR
    const CBORMap cbor(private_key_data, {"ed25519_signing_skey", "encryption_skey"});

    // Get the signing key pair
    const std::vector<uint8_t> ed25519_signing_skey =
        cbor.get("ed25519_signing_skey").get_byte_string_value();
    ED25519KeyPair new_ed25519_signing_key_pair;
    new_ed25519_signing_key_pair.set_private_key(ed25519_signing_skey);

    // Get the encryption key pair
    const std::vector<uint8_t> encryption_skey =
        cbor.get("encryption_skey").get_byte_string_value();
    EC256KeyPair new_provision_key_pair;
    new_provision_key_pair.set_private_key(encryption_skey);

    // Store these key pairs in memory
    ed25519_key_pair = new_ed25519_signing_key_pair;
    provision_key_pair = new_provision_key_pair;
}

/**
 * @brief Unseal encryption and signing private keys and store them in memory
 *
 * @param sealed_key_data the sealed key data (stored as a CBOR encoded map)
 * @param sealed_size the number of bytes in the sealed_key_data
 *
 * @return status code
 */
CoreStatusCode ecall_set_keys_from_sealed(uint8_t *sealed_key_data, size_t sealed_size)
{
    return capture_exceptions([&]() {
        // Validate function argument pointers
        if (sealed_key_data == nullptr)
            THROW_EXCEPTION(kInvalidInput, "Input pointer is null");

        // Determine the length of the data once unsealed
        if (sealed_size <= sizeof(sgx_sealed_data_t))
            THROW_EXCEPTION(kInvalidInput, "The input sealed_size is too small");

        const uint32_t unsealed_size = sealed_size - sizeof(sgx_sealed_data_t);

        // Unseal the data
        std::vector<uint8_t> unsealed_bytes(unsealed_size, 0);
        uint32_t unsealed_size_copy = unsealed_size; // SGX API requires this to be non-const
        raise_sgx_error([&]() {
            return sgx_unseal_data(reinterpret_cast<sgx_sealed_data_t *>(sealed_key_data),
                                   NULL,
                                   NULL,
                                   unsealed_bytes.data(),
                                   &unsealed_size_copy);
        });

        // Set the keys
        set_keys_from_private_key_data(unsealed_bytes);
    });
}

/**
 * @brief Seal the private encryption and signing keys, and return the result
 *
 * @param max_bytes the number of bytes allocated to sealed_key_data (buffer size)
 * @param sealed_key_data the output sealed key data buffer
 * @param used_bytes the output number of bytes used
 *
 * @return status code
 */
CoreStatusCode
ecall_get_sealed_keys(uint32_t max_bytes, uint8_t *sealed_key_data, uint32_t *used_bytes)
{
    return capture_exceptions([&]() {
        // Validate function argument pointers
        if (sealed_key_data == nullptr || used_bytes == nullptr)
            THROW_EXCEPTION(kInvalidInput, "One or more input pointers are null");

        // Get the private key data, to be sealed
        const std::vector<uint8_t> unsealed_bytes = get_private_key_data();

        // Seal the data
        const uint32_t sealed_size = sizeof(sgx_sealed_data_t) + unsealed_bytes.size();
        if (sealed_size > max_bytes)
            THROW_EXCEPTION(kInvalidInput,
                            "Input buffer isn't large enough to accept the sealed key data");

        std::vector<uint8_t> sealed_bytes(sealed_size, 0);

        const uint16_t key_policy = SGX_KEYPOLICY_MRENCLAVE;
        sgx_attributes_t attribute_mask;
        attribute_mask.flags = 0xFF0000000000000B;
        attribute_mask.xfrm = 0x0;
        const sgx_misc_select_t misc_mask = 0xF0000000;

        raise_sgx_error([&]() {
            return sgx_seal_data_ex(key_policy,
                                    attribute_mask,
                                    misc_mask,
                                    0,
                                    NULL,
                                    unsealed_bytes.size(),
                                    unsealed_bytes.data(),
                                    sealed_bytes.size(),
                                    reinterpret_cast<sgx_sealed_data_t *>(sealed_bytes.data()));
        });

        // Copy the sealed data to the output pointer
        memcpy(sealed_key_data, sealed_bytes.data(), sealed_bytes.size());
        *used_bytes = sealed_bytes.size();
    });
}

/**
 * @brief Return the enclave's public encryption & signing keys
 *
 * @param encryption_public_key the EC256 public key used for one time encryption
 * @param provision_public_key the EC256 public key used for encryption in provisioning step
 * @param ed25519_signing_public_key the ED25519 public key used for signing
 * @param encryption_public_key_signature signature of the encryption_public_key by the signing key
 *
 * @return status code
 */
CoreStatusCode ecall_get_public_keys(uint8_t *encryption_public_key,
                                     uint8_t *provision_public_key,
                                     uint8_t *ed25519_signing_public_key,
                                     uint8_t *encryption_public_key_signature)
{
    return capture_exceptions([&]() {
        // Validate function argument pointers
        if (encryption_public_key == nullptr || ed25519_signing_public_key == nullptr ||
            provision_public_key == nullptr || encryption_public_key_signature == nullptr)
            THROW_EXCEPTION(kInvalidInput, "One or more input pointers are null");

        // Generate a new encryption key pair and sign it
        const EC256KeyPair &ec256_key_pair = ec256_key_manager.generate_key();
        const std::array<uint8_t, CORE_ECC_KEY_LEN> encryption_public_key_bytes =
            ec256_key_pair.public_key_bytes();
        memcpy(encryption_public_key, encryption_public_key_bytes.data(), CORE_ECC_KEY_LEN);

        const std::array<uint8_t, CORE_ED25519_SIG_LEN> signature =
            ed25519_key_pair.sign(std::vector<uint8_t>(std::begin(encryption_public_key_bytes),
                                                       std::end(encryption_public_key_bytes)));
        memcpy(encryption_public_key_signature, signature.data(), CORE_ED25519_SIG_LEN);

        // Copy the signing and provision public keys to output pointers
        const std::array<uint8_t, ED25519_KEY_LEN> ed25519_signing_public_key_bytes =
            ed25519_key_pair.public_key();
        memcpy(
            ed25519_signing_public_key, ed25519_signing_public_key_bytes.data(), ED25519_KEY_LEN);
        const std::array<uint8_t, CORE_ECC_KEY_LEN> provision_public_key_bytes =
            provision_key_pair.public_key_bytes();
        memcpy(provision_public_key, provision_public_key_bytes.data(), CORE_ECC_KEY_LEN);
    });
}

/**
 * @brief Get the report required for verifying the enclave
 *
 * @param p_qe_target struct containing information about the target (quoting) enclave, used to
 * generate a local proof report which can then be verified by the target and converted to a quote
 * @param p_report Struct containing the report information for the enclave
 *
 * @return status code
 */
CoreStatusCode ecall_get_report(sgx_target_info_t *p_qe_target, sgx_report_t *p_report)
{
    return capture_exceptions([&]() {
        // Validate function argument pointers
        if (p_qe_target == nullptr || p_report == nullptr)
            THROW_EXCEPTION(kInvalidInput, "One or more input pointers are null");

        const sgx_report_t report = get_report(
            *p_qe_target, provision_key_pair.public_key_bytes(), ed25519_key_pair.public_key());
        *p_report = report;
    });
}

void verify_enclaves_are_clones(sgx_target_info_t *p_qe_target,
                                const char *ias_report_body,
                                const char *ias_report_cert_chain,
                                const uint8_t *ias_report_signature,
                                const uint8_t *provision_public_key,
                                const uint8_t *ed25519_signing_public_key)
{
    // Validate function argument pointers
    if (p_qe_target == nullptr || ias_report_body == nullptr || ias_report_cert_chain == nullptr ||
        ias_report_signature == nullptr || provision_public_key == nullptr ||
        ed25519_signing_public_key == nullptr)
        THROW_EXCEPTION(kInvalidInput, "One or more input pointers are null");

    // Copy the data in the input arrays
    std::array<uint8_t, CORE_IAS_SIG_LEN> signature;
    memcpy(signature.data(), ias_report_signature, CORE_IAS_SIG_LEN);

    std::array<uint8_t, CORE_ECC_KEY_LEN> provision_public_key_bytes;
    memcpy(provision_public_key_bytes.data(), provision_public_key, CORE_ECC_KEY_LEN);

    std::array<uint8_t, CORE_ED25519_KEY_LEN> ed25519_signing_public_key_bytes;
    memcpy(
        ed25519_signing_public_key_bytes.data(), ed25519_signing_public_key, CORE_ED25519_KEY_LEN);

    // Verify the IAS report signature
    verify_signature(ias_report_cert_chain, ias_report_body, signature);

    // Verify the contents of the IAS report & that the enclave about which the attestation
    // relates is a clone of this enclave
    const sgx_report_t verifier_report = get_report(
        *p_qe_target, provision_key_pair.public_key_bytes(), ed25519_key_pair.public_key());
    verify_quote(ias_report_body,
                 provision_public_key_bytes,
                 ed25519_signing_public_key_bytes,
                 verifier_report);
}

/**
 * @brief Verify the IAS report from a peer enclave, and encrypt the private keys for the peer
 * enclave to decrypt
 *
 * @param p_qe_target struct containing information about the target (quoting) enclave
 * @param ias_report_body JSON body of IAS response
 * @param ias_report_cert_chain signing certificate chain of IAS
 * @param ias_report_signature signature of report body
 * @param provision_public_key public encryption key of peer enclave
 * @param ed25519_signing_public_key public signing key of peer enclave
 * @param max_bytes the number of bytes allocated to encrypted_key_data (buffer size)
 * @param encrypted_key_data the output encrypted private key data (CBOR encoded)
 * @param used_bytes the output number of bytes used
 *
 * @return status code
 */
CoreStatusCode ecall_get_encrypted_keys(sgx_target_info_t *p_qe_target,
                                        const char *ias_report_body,
                                        const char *ias_report_cert_chain,
                                        const uint8_t *ias_report_signature,
                                        const uint8_t *provision_public_key,
                                        const uint8_t *ed25519_signing_public_key,
                                        uint32_t max_bytes,
                                        uint8_t *encrypted_key_data,
                                        uint32_t *used_bytes)
{
    return capture_exceptions([&]() {
        // Validate function argument pointers
        if (p_qe_target == nullptr || ias_report_body == nullptr ||
            ias_report_cert_chain == nullptr || ias_report_signature == nullptr ||
            provision_public_key == nullptr || ed25519_signing_public_key == nullptr ||
            encrypted_key_data == nullptr || used_bytes == nullptr)
            THROW_EXCEPTION(kInvalidInput, "One or more input pointers are null");

        // Verify the enclave requesting the private keys is a clone of this enclave
        verify_enclaves_are_clones(p_qe_target,
                                   ias_report_body,
                                   ias_report_cert_chain,
                                   ias_report_signature,
                                   provision_public_key,
                                   ed25519_signing_public_key);

        // Get the private key data, to be encrypted
        const std::vector<uint8_t> to_encrypt = get_private_key_data();

        // Encrypt the private key data (to be decrypted by the peer enclave)
        const AESGCMKey symmetric_key = provision_key_pair.ecdh(provision_public_key);
        const std::vector<uint8_t> encrypted_bytes = symmetric_key.encrypt(to_encrypt);

        // Copy the encrypted data to the output pointer
        if (encrypted_bytes.size() > max_bytes)
            THROW_EXCEPTION(kInvalidInput,
                            "Input buffer isn't large enough to accept the encrypted key data");

        memcpy(encrypted_key_data, encrypted_bytes.data(), encrypted_bytes.size());
        *used_bytes = encrypted_bytes.size();
    });
}

/**
 * @brief Verify the IAS report from a peer enclave, and store the private keys from the encrypted
 * data
 *
 * @param p_qe_target struct containing information about the target (quoting) enclave
 * @param ias_report_body JSON body of IAS response
 * @param ias_report_cert_chain signing certificate chain of IAS
 * @param ias_report_signature signature of report body
 * @param provision_public_key public encryption key of peer enclave
 * @param ed25519_signing_public_key public signing key of peer enclave
 * @param encrypted_key_data the output encrypted private key data (CBOR encoded)
 * @param encrypted_size the size of the encrypted_key_data
 *
 * @return status code
 */
CoreStatusCode ecall_set_keys_from_encrypted(sgx_target_info_t *p_qe_target,
                                             const char *ias_report_body,
                                             const char *ias_report_cert_chain,
                                             const uint8_t *ias_report_signature,
                                             const uint8_t *provision_public_key,
                                             const uint8_t *ed25519_signing_public_key,
                                             uint8_t *encrypted_key_data,
                                             uint32_t encrypted_size)
{
    return capture_exceptions([&]() {
        // Validate function argument pointers
        if (p_qe_target == nullptr || ias_report_body == nullptr ||
            ias_report_cert_chain == nullptr || ias_report_signature == nullptr ||
            provision_public_key == nullptr || ed25519_signing_public_key == nullptr ||
            encrypted_key_data == nullptr)
            THROW_EXCEPTION(kInvalidInput, "One or more input pointers are null");

        // Verify the enclave sending the private keys is a clone of this enclave
        verify_enclaves_are_clones(p_qe_target,
                                   ias_report_body,
                                   ias_report_cert_chain,
                                   ias_report_signature,
                                   provision_public_key,
                                   ed25519_signing_public_key);

        // Decrypt the secret key data
        std::vector<uint8_t> encrypted_key_data_bytes(encrypted_size, 0);
        memcpy(encrypted_key_data_bytes.data(), encrypted_key_data, encrypted_size);

        const AESGCMKey symmetric_key = provision_key_pair.ecdh(provision_public_key);
        const std::vector<uint8_t> decrypted_key_data =
            symmetric_key.decrypt(encrypted_key_data_bytes);

        // Set the keys
        set_keys_from_private_key_data(decrypted_key_data);
    });
}

// -------------------------------------------

void initialize_request_buffers(const uint8_t *request_bytes, ProofResult *proof_result)
{
    // Validate function argument output pointers
    if (request_bytes == nullptr || proof_result == nullptr)
        THROW_EXCEPTION(kInvalidInput, "One or more of the function argument pointers is NULL");

    std::memset(proof_result->data, 0, CORE_MAX_PROOF_LEN);
    proof_result->data_size = 0;

    std::memset(proof_result->signature, 0, ED25519_SIG_LEN);

    std::memset(proof_result->certificate_data, 0, CORE_MAX_CERTIFICATE_LEN);
    proof_result->certificate_data_size = 0;
}

CoreStatusCode ecall_plaid_get_link_token(const uint8_t *request_bytes,
                                          size_t request_size,
                                          ProofResult *proof_result)
{
    std::vector<uint8_t> encrypted_link;
    try
    {
        initialize_request_buffers(request_bytes, proof_result);

        PlaidLinkTokenRequest req;
        if (!req.ParseFromArray(request_bytes, static_cast<int>(request_size)))
            THROW_EXCEPTION(kInvalidInput, "Cannot parse protobuf message");
        const std::string &public_key = req.client_info().enclave_encryption_public_key();
        const PlaidLinkRequestWrapper request(req, ec256_key_manager.get_key_pair(public_key));
        encrypted_link = get_encrypted_link_token(request);
        ec256_key_manager.remove_key_pair(public_key);
    }
    catch (const EnclaveException &e)
    {
        EXCEPTION_LOG(e);
        return e.get_code();
    }
    catch (...)
    {
        return kUnknownError;
    }

    if (encrypted_link.size() > CORE_MAX_PROOF_LEN)
        return kOutputOverflow;
    std::copy(encrypted_link.begin(), encrypted_link.end(), proof_result->data);
    proof_result->data_size = encrypted_link.size();

    return kSuccess;
}

CoreStatusCode ecall_check_crossflow_invoice(const uint8_t *request_bytes,
                                             size_t request_size,
                                             ProofResult *proof_result)
{
    // Initialize return pointers
    CheckResult result;
    try
    {
        initialize_request_buffers(request_bytes, proof_result);

        CrossflowInvoiceCheckRequest req;
        if (!req.ParseFromArray(request_bytes, static_cast<int>(request_size)))
            THROW_EXCEPTION(kInvalidInput, "Cannot parse protobuf message");
        EC256KeyPair dummy_key_pair;
        const CrossflowInvoiceCheckRequestWrapper request(req, dummy_key_pair);
        result = process_crossflow_invoice_proof(request, ed25519_key_pair);
    }
    catch (const EnclaveException &e)
    {
        EXCEPTION_LOG(e);
        return e.get_code();
    }
    catch (...)
    {
        return kUnknownError;
    }
    if (result.status != kSuccess)
        return result.status;

    // Write proof data to the output pointers
    if (result.binary_proof_data.size() > CORE_MAX_PROOF_LEN)
        return kOutputOverflow;
    std::copy(result.binary_proof_data.begin(), result.binary_proof_data.end(), proof_result->data);
    proof_result->data_size = result.binary_proof_data.size();
    memcpy(proof_result->signature, result.signature.data(), ED25519_SIG_LEN);

    return kSuccess;
}

// Exchange a public token for an access token and obtain the users total bank
// balance from an open banking API and compare it against a given value
// Input:  - api_config = Configuration for open banking API to use (name, client ID, secret,
// environment)
//         - client_info = Input info from the app (timestamp, proof id, public key, encrypted
//         input)
//         - currency_code = ISO 4217 code
//         - minimum_balance = The value to check the balance against
//         - contract = Include wallet signature in signed data rather than names
// Output: - proof_result = A struct containing proof data and signature
CoreStatusCode ecall_minimum_balance_proof(const uint8_t *request_bytes,
                                           size_t request_size,
                                           ProofResult *proof_result)
{
    // Initialize return pointers
    CheckResult result;
    try
    {
        initialize_request_buffers(request_bytes, proof_result);

        MinimumBalanceCheckRequest req;
        if (!req.ParseFromArray(request_bytes, static_cast<int>(request_size)))
            THROW_EXCEPTION(kInvalidInput, "Cannot parse protobuf message");
        const std::string &public_key = req.client_info().enclave_encryption_public_key();
        const BalanceCheckRequestWrapper request(req, ec256_key_manager.get_key_pair(public_key));
        result = process_balance_proof(request, ed25519_key_pair);
        ec256_key_manager.remove_key_pair(public_key);
    }
    catch (const EnclaveException &e)
    {
        EXCEPTION_LOG(e);
        return e.get_code();
    }
    catch (...)
    {
        return kUnknownError;
    }
    if (result.status != kSuccess)
        return result.status;

    // Write proof data to the output pointers
    if (result.binary_proof_data.size() > CORE_MAX_PROOF_LEN)
        return kOutputOverflow;
    std::copy(result.binary_proof_data.begin(), result.binary_proof_data.end(), proof_result->data);
    proof_result->data_size = result.binary_proof_data.size();
    memcpy(proof_result->signature, result.signature.data(), ED25519_SIG_LEN);
    if (result.certificate_data.size() > CORE_MAX_CERTIFICATE_LEN)
        return kOutputOverflow;
    std::copy(result.certificate_data.begin(),
              result.certificate_data.end(),
              proof_result->certificate_data);
    proof_result->certificate_data_size = result.certificate_data.size();

    return kSuccess;
}

// Exchange a public token for an access token and obtain the users transaction data for the last 3
// months and compare the incoming total for each month against a given value
// Input:  - api_config = Configuration for open banking API to use (name, client ID, secret,
// environment)
//         - client_info = Input info from the app (timestamp, proof id, public key, encrypted
//         input)
//         - currency_code = ISO 4217 code
//         - consistent_income = The value to check the income against
//         - stable = Only include income from same source around the same time each month
//         - contract = Include wallet signature in signed data rather than names
// Output: - proof_result = A struct containing proof data and signature
CoreStatusCode ecall_consistent_income_proof(const uint8_t *request_bytes,
                                             size_t request_size,
                                             ProofResult *proof_result)
{
    // Initialise padded struct
    CheckResult result;
    try
    {
        initialize_request_buffers(request_bytes, proof_result);

        ConsistentIncomeCheckRequest req;
        if (!req.ParseFromArray(request_bytes, static_cast<int>(request_size)))
            THROW_EXCEPTION(kInvalidInput, "Cannot parse protobuf message");
        const std::string &public_key = req.client_info().enclave_encryption_public_key();
        const IncomeCheckRequestWrapper request(req, ec256_key_manager.get_key_pair(public_key));
        result = process_income_proof(request, ed25519_key_pair);
        ec256_key_manager.remove_key_pair(public_key);
    }
    catch (const EnclaveException &e)
    {
        EXCEPTION_LOG(e);
        return e.get_code();
    }
    catch (...)
    {
        return kUnknownError;
    }
    if (result.status != kSuccess)
        return result.status;

    // Write proof data to the output pointers
    if (result.binary_proof_data.size() > CORE_MAX_PROOF_LEN)
        return kOutputOverflow;
    std::copy(result.binary_proof_data.begin(), result.binary_proof_data.end(), proof_result->data);
    proof_result->data_size = result.binary_proof_data.size();
    memcpy(proof_result->signature, result.signature.data(), ED25519_SIG_LEN);
    if (result.certificate_data.size() > CORE_MAX_CERTIFICATE_LEN)
        return kOutputOverflow;
    std::copy(result.certificate_data.begin(),
              result.certificate_data.end(),
              proof_result->certificate_data);
    proof_result->certificate_data_size = result.certificate_data.size();

    return kSuccess;
}

CoreStatusCode
ecall_onfido_kyc_proof(const uint8_t *request_bytes, size_t request_size, ProofResult *proof_result)
{
    // Initialize return pointers
    CheckResult result;
    try
    {
        initialize_request_buffers(request_bytes, proof_result);

        OnfidoKYCCheckRequest req;
        if (!req.ParseFromArray(request_bytes, static_cast<int>(request_size)))
            THROW_EXCEPTION(kInvalidInput, "Cannot parse protobuf message");
        const std::string &public_key = req.client_info().enclave_encryption_public_key();
        const OnfidoKYCCheckRequestWrapper request(req, ec256_key_manager.get_key_pair(public_key));
        result = process_onfido_kyc_proof(request, ed25519_key_pair);
        ec256_key_manager.remove_key_pair(public_key);
    }
    catch (const EnclaveException &e)
    {
        EXCEPTION_LOG(e);
        return e.get_code();
    }
    catch (...)
    {
        return kUnknownError;
    }
    if (result.status != kSuccess)
        return result.status;

    // Write proof data to the output pointers
    if (result.binary_proof_data.size() > CORE_MAX_PROOF_LEN)
        return kOutputOverflow;
    std::copy(result.binary_proof_data.begin(), result.binary_proof_data.end(), proof_result->data);
    proof_result->data_size = result.binary_proof_data.size();
    memcpy(proof_result->signature, result.signature.data(), ED25519_SIG_LEN);
    if (result.certificate_data.size() > CORE_MAX_CERTIFICATE_LEN)
        return kOutputOverflow;
    std::copy(result.certificate_data.begin(),
              result.certificate_data.end(),
              proof_result->certificate_data);
    proof_result->certificate_data_size = result.certificate_data.size();

    return kSuccess;
}

CoreStatusCode
ecall_instagram_proof(const uint8_t *request_bytes, size_t request_size, ProofResult *proof_result)
{
    // Initialize return pointers
    CheckResult result;
    try
    {
        initialize_request_buffers(request_bytes, proof_result);

        InstagramCheckRequest req;
        if (!req.ParseFromArray(request_bytes, static_cast<int>(request_size)))
            THROW_EXCEPTION(kInvalidInput, "Cannot parse protobuf message");
        const std::string &public_key = req.client_info().enclave_encryption_public_key();
        const InstagramCheckRequestWrapper request(req, ec256_key_manager.get_key_pair(public_key));
        result = process_instagram_proof(request, ed25519_key_pair);
        ec256_key_manager.remove_key_pair(public_key);
    }
    catch (const EnclaveException &e)
    {
        EXCEPTION_LOG(e);
        return e.get_code();
    }
    catch (...)
    {
        return kUnknownError;
    }
    if (result.status != kSuccess)
        return result.status;

    // Write proof data to the output pointers
    if (result.binary_proof_data.size() > CORE_MAX_PROOF_LEN)
        return kOutputOverflow;
    std::copy(result.binary_proof_data.begin(), result.binary_proof_data.end(), proof_result->data);
    proof_result->data_size = result.binary_proof_data.size();
    memcpy(proof_result->signature, result.signature.data(), ED25519_SIG_LEN);
    if (result.certificate_data.size() > CORE_MAX_CERTIFICATE_LEN)
        return kOutputOverflow;
    std::copy(result.certificate_data.begin(),
              result.certificate_data.end(),
              proof_result->certificate_data);
    proof_result->certificate_data_size = result.certificate_data.size();

    return kSuccess;
}
