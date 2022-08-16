/*
 *  Crossflow client
 */

#pragma once

#include <string>

#include "lib/common/optional.hpp"

#include "clients/api_client/oauth_api_client.hpp"

namespace silentdata
{
namespace enclave
{

class CrossflowClient : public APIClient
{
private:
    std::vector<std::string> default_headers(bool post = false) const;
    json::JSON default_request_body() const;

    std::string api_prefix_;

public:
    struct CrossflowInvoice
    {
        std::string buyer;
        int buyer_id;
        std::string currency;
        double financeable_total;
        std::string credit_rating;
        double interest_rate;
        int tenor;
        int timestamp;
    };

    CrossflowClient(const std::string &hostname, const uint32_t timestamp);

    ~CrossflowClient(){};

    CoreStatusCode parse_error(const HTTPSResponse &response) const;

    void get_access(const std::string &email, const std::string &password);
    Optional<CrossflowInvoice> get_invoice(const std::string &cf_request_id);
    void set_api_prefix(const std::string &api_prefix);
};

} // namespace enclave
} // namespace silentdata
