/*
 * Functions for processing proofs
 */

#pragma once

#include <string>
#include <vector>

#include "include/core_constants.h"
#include "include/core_status_codes.h"

#include "lib/common/cbor_map.hpp"
#include "lib/common/credit_rating.hpp"
#include "lib/common/date_time.hpp"
#include "lib/common/decoders.hpp"
#include "lib/common/enclave_exception.hpp"
#include "lib/common/enclave_logger.hpp"
#include "lib/common/encoders.hpp"
#include "lib/common/json.hpp"
#include "lib/crypto/ed25519_key_pair.hpp"
#include "lib/crypto/hash.hpp"

#include "clients/banking/plaid_client.hpp"
#include "clients/banking/truelayer_client.hpp"
#include "clients/identity/instagram_client.hpp"
#include "clients/identity/onfido_client.hpp"
#include "clients/invoices/crossflow_client.hpp"

#include "lib/proof/api_requests.hpp"
#include "lib/proof/comparison_functions.hpp"
#include "lib/proof/proof_data.hpp"
#include "lib/proof/wallet_requests.hpp"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wconversion"
#pragma GCC diagnostic ignored "-Wredundant-decls"
#pragma GCC diagnostic ignored "-Wunused-parameter"
#include "proto/messages.pb.h"
#pragma GCC diagnostic pop

namespace silentdata
{
namespace enclave
{

class CheckResult
{
public:
    CoreStatusCode status;
    std::array<uint8_t, ED25519_SIG_LEN> signature;
    std::vector<uint8_t> binary_proof_data;
    std::vector<uint8_t> certificate_data;
};

CheckResult process_crossflow_invoice_proof(const CrossflowInvoiceCheckRequestWrapper &request,
                                            const ED25519KeyPair &ed25519_signing_keys);

CheckResult process_balance_proof(const BalanceCheckRequestWrapper &request,
                                  const ED25519KeyPair &ed25519_signing_keys);

CheckResult process_income_proof(const IncomeCheckRequestWrapper &request,
                                 const ED25519KeyPair &ed25519_signing_keys);

CheckResult process_onfido_kyc_proof(const OnfidoKYCCheckRequestWrapper &request,
                                     const ED25519KeyPair &ed25519_signing_keys);

CheckResult process_instagram_proof(const InstagramCheckRequestWrapper &request,
                                    const ED25519KeyPair &ed25519_signing_keys);

} // namespace enclave
} // namespace silentdata
