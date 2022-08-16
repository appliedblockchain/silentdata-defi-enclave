/*
 * Utility functions for processing proofs
 */

#pragma once

#include <string>
#include <vector>

#include "include/core_constants.h"
#include "include/core_status_codes.h"

#include "lib/common/cbor_map.hpp"
#include "lib/common/enclave_exception.hpp"
#include "lib/common/enclave_logger.hpp"

#include "clients/banking/plaid_client.hpp"

#include "lib/proof/api_requests.hpp"
#include "lib/proof/comparison_functions.hpp"

namespace silentdata
{
namespace enclave
{

std::vector<uint8_t> get_encrypted_link_token(const PlaidLinkRequestWrapper &request);

} // namespace enclave
} // namespace silentdata
