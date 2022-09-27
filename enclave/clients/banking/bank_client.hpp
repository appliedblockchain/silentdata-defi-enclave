/*
 *  Abstract class for open banking API clients
 */

#pragma once

#include <string>
#include <vector>

#include "clients/api_client/oauth_api_client.hpp"
#include "lib/client/client_opt.h"
#include "lib/client/https_response.hpp"
#include "lib/common/json.hpp"
#include "lib/common/types.hpp"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wconversion"
#pragma GCC diagnostic ignored "-Wredundant-decls"
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wshadow"
#include "proto/messages.pb.h"
#pragma GCC diagnostic pop

namespace silentdata
{
namespace enclave
{

class BankClient : public OAuthAPIClient
{
public:
    BankClient(const std::string &host,
               const std::string &client_id,
               const std::string &secret,
               uint32_t timestamp,
               const std::vector<std::string> &allowed_certificates)
        : OAuthAPIClient(host, client_id, secret, timestamp, allowed_certificates)
    {
    }
    virtual ~BankClient() {}

    virtual BankBalance get_total_balance(const std::string &currency_code,
                                          const std::string &account_id = "") = 0;

    virtual std::vector<BankTransaction> get_all_transactions(
        struct tm start_date, struct tm end_date, const std::string &account_id = "") = 0;

    virtual std::string get_account_holder_name(const std::string &account_id = "") = 0;

    virtual std::string get_business_name(const std::string &account_id = "") = 0;

    virtual std::string get_institution_name() = 0;

    virtual std::map<std::string, AccountNumbers> get_account_details() = 0;
};

} // namespace enclave
} // namespace silentdata
