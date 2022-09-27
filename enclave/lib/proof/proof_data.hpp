/*
 * Functions for serialising proof data to be signed
 */

#pragma once

#include <array>
#include <string>
#include <vector>

#include <sgx_tcrypto.h>
#include <sgx_trts.h>

#include "include/core_constants.h"
#include "include/core_status_codes.h"
#include "include/proof_types.h"

#include "lib/cbor/cbor.h"
#include "lib/common/cbor_map.hpp"
#include "lib/common/enclave_exception.hpp"
#include "lib/common/enclave_logger.hpp"
#include "lib/common/logicsig.hpp"
#include "lib/crypto/hash.hpp"

namespace silentdata
{
namespace enclave
{

std::vector<uint8_t> generate_crossflow_invoice_proof_data(
    const std::string &proof_id,
    int32_t timestamp,
    const std::array<uint8_t, CORE_ED25519_KEY_LEN> &initiator_pkey,
    const std::vector<uint8_t> &certificate_hash,
    const std::array<uint8_t, CORE_SHA_256_LEN> &invoice_id,
    uint64_t minting_app_id,
    uint8_t risk_score,
    uint64_t value,
    const std::string &currency_code,
    uint64_t interest_rate,
    int32_t funding_date,
    int32_t due_date);

std::vector<uint8_t> generate_kyc_proof_data(
    const std::string &proof_id,
    int32_t timestamp, // The time the request was made to produce the proof certificate
    const std::array<uint8_t, CORE_ED25519_KEY_LEN> &initiator_pkey,
    const std::vector<uint8_t> &certificate_hash,
    int32_t check_timestamp, // The time the checks were performed
    const std::array<uint8_t, CORE_SHA_256_LEN> &subject_id);

std::vector<uint8_t>
generate_instagram_proof_data(const std::string &proof_id,
                              int32_t timestamp,
                              const std::array<uint8_t, CORE_ED25519_KEY_LEN> &initiator_pkey,
                              const std::vector<uint8_t> &certificate_hash,
                              const std::string &username,
                              const std::string &account_type);

std::vector<uint8_t>
generate_bank_proof_data(ProofType type,
                         const std::string &proof_id,
                         int32_t timestamp,
                         const std::array<uint8_t, CORE_ED25519_KEY_LEN> &initiator_pkey,
                         const std::vector<uint8_t> &certificate_hash,
                         const std::string &currency_code,
                         uint32_t comparison_value,
                         const std::string &server_timestamp,
                         const std::string &server_common_name);

} // namespace enclave
} // namespace silentdata
