/*
 * Calls to plaid API
 */

#pragma once

#include <map>
#include <string>
#include <time.h>
#include <vector>

#include "include/core_status_codes.h"

#include "lib/client/https_response.hpp"
#include "lib/common/json.hpp"
#include "lib/common/types.hpp"

#include "clients/banking/bank_client.hpp"

namespace silentdata
{
namespace enclave
{

struct PlaidLink
{
    std::string token;
    std::string expiration;
    std::string request_id;
};

class PlaidClient : public BankClient
{
private:
    std::string public_token_;
    std::string redirect_uri_;

    std::vector<BankTransaction>
    get_transactions(const json::JSON &body, CoreStatusCode &error_code, int &total);

    std::vector<std::string> default_headers(bool post = false) const;
    json::JSON default_request_body() const;

public:
    PlaidClient(const std::string &hostname,
                const std::string &client_id,
                const std::string &secret,
                uint32_t timestamp,
                const std::string &public_token,
                const std::string &redirect_uri,
                const std::vector<std::string> &allowed_certificates = {});
    PlaidClient(const std::string &hostname,
                const APIConfig &config,
                const std::string &public_token = "",
                const std::vector<std::string> &allowed_certificates = {});
    ~PlaidClient();

    // Parse an error response from Plaid
    CoreStatusCode parse_error(const HTTPSResponse &response) const;

    // Send a request to the Plaid API to create a link token for a user
    PlaidLink create_link_token(const std::string &client_user_id, const std::string &country);

    // Send a request to the Plaid API to obtain an access token from a link token
    void get_access();

    // Send a request to the Plaid API to destroy a given access token
    void destroy_access();

    // Send a request to the Plaid API to return the total bank balance for all connected accounts
    BankBalance get_total_balance(const std::string &currency_code,
                                  const std::string &account_id = "");

    // Send a request to the Plaid API to return all transactions as amount-date pairs in a given
    // time period
    std::vector<BankTransaction> get_all_transactions(struct tm start_date,
                                                      struct tm end_date,
                                                      const std::string &account_id = "");

    // Get account information for all associated accounts
    std::map<std::string, AccountNumbers> get_account_details();
};

} // namespace enclave
} // namespace silentdata
