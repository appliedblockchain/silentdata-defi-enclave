/*
 * Utility functions for processing proofs
 */

#pragma once

#include <string>
#include <vector>

#include "clients/banking/plaid_client.hpp"

#include "lib/proof/api_requests.hpp"

namespace silentdata
{
namespace enclave
{

std::vector<uint8_t> get_encrypted_link_token(const PlaidLinkRequestWrapper &request);

} // namespace enclave
} // namespace silentdata
