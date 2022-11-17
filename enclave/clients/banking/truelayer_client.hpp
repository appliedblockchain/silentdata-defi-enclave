/*
 * Calls to truelayer API
 */

#pragma once

#include <array>
#include <map>
#include <string>
#include <time.h>
#include <vector>

#include "sgx_tcrypto.h"

#include "include/core_status_codes.h"

#include "lib/client/https_response.hpp"
#include "lib/common/json.hpp"
#include "lib/common/types.hpp"

#include "clients/banking/bank_client.hpp"

namespace silentdata
{
namespace enclave
{

class TrueLayerClient : public BankClient
{
private:
    std::string code_;
    std::string code_verifier_;
    std::string redirect_uri_;

    std::vector<std::string> get_accounts();
    std::vector<BankTransaction> get_account_transactions(const std::string &account_id,
                                                          struct tm start_date,
                                                          struct tm end_date);

    std::vector<std::string> default_headers(bool post = false) const;
    json::JSON default_request_body() const;

public:
    TrueLayerClient(const std::string &hostname,
                    const std::string &client_id,
                    const std::string &secret,
                    uint32_t timestamp,
                    const std::string &code,
                    const std::string &code_verifier,
                    const std::string &redirect_uri,
                    const std::vector<std::string> &allowed_certificates = {});
    TrueLayerClient(const std::string &hostname,
                    const APIConfig &config,
                    const std::string &code,
                    const std::string &code_verifier,
                    const std::vector<std::string> &allowed_certificates = {});
    ~TrueLayerClient();

    CoreStatusCode parse_error(const HTTPSResponse &response) const;

    // Send a request to the TrueLayer API to obtain an access token from a link token
    void get_access();

    // Send a request to the TrueLayer API to destroy a given access token
    void destroy_access();

    // Send a request to the TrueLayer API to return the total bank balance for all connected
    // accounts
    BankBalance get_total_balance(const std::string &currency_code,
                                  const std::string &account_id = "");

    // Send a request to the TrueLayer API to return all transactions as amount-date pairs in a
    // given time period
    std::vector<BankTransaction> get_all_transactions(struct tm start_date,
                                                      struct tm end_date,
                                                      const std::string &account_id = "");

    // Get account information for all associated accounts
    std::map<std::string, AccountNumbers> get_account_details();
};

} // namespace enclave
} // namespace silentdata
