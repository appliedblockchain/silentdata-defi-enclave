#pragma once

#include <array>
#include <string>

#include "include/core_constants.h"

#include "lib/common/enclave_logger.hpp"

namespace silentdata
{
namespace enclave
{

// Get the the public key of an algorand logicsig, based on it's compiled contract code
//
// The template_compiled_contract should be a hex-encoded string
// which can also include the substrings <SILENTDATA_ASSET_ID> and <MINTING_APP_ID_BYTES>
// at the positions where the invoice ID and minting app id should be injected
std::array<uint8_t, CORE_SHA_512_256_LEN>
get_logicsig_public_key(const std::string &template_compiled_contract,
                        const std::array<uint8_t, CORE_SHA_256_LEN> &invoice_id,
                        uint64_t minting_app_id);

} // namespace enclave
} // namespace silentdata
