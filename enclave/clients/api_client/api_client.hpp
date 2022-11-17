/*
 *  Abstract base class for API clients
 */

#pragma once

#include <string>
#include <vector>

#include "lib/client/https_client.hpp"
#include "lib/client/https_response.hpp"
#include "lib/common/json.hpp"

namespace silentdata
{
namespace enclave
{

class APIClient : public HTTPSClient
{
protected:
    std::string host_;
    std::string secret_;
    std::string last_timestamp_;
    std::string last_certificate_chain_;

    virtual std::vector<std::string> default_headers(bool post = false) const = 0;
    virtual json::JSON default_request_body() const = 0;

    HTTPSResponse get(const std::string &endpoint);
    HTTPSResponse get(const std::string &endpoint, const std::vector<std::string> &headers);
    HTTPSResponse post(const std::string &endpoint);
    HTTPSResponse post(const std::string &endpoint, const std::string &body);
    HTTPSResponse post(const std::string &endpoint,
                       const std::string &body,
                       const std::vector<std::string> &headers);
    void del(const std::string &endpoint);
    void del(const std::string &endpoint, const std::vector<std::string> &headers);

    CoreStatusCode get_HTTP_status(const int status_code) const;
    json::JSON parse_json(const HTTPSResponse &response) const;

public:
    APIClient(const std::string &host,
              const std::string &secret,
              uint32_t timestamp,
              const std::vector<std::string> &allowed_certificates);
    virtual ~APIClient() {}

    virtual CoreStatusCode parse_error(const HTTPSResponse &response) const = 0;

    const std::string &get_timestamp() const { return last_timestamp_; }
    const std::string &get_certificate_chain() const { return last_certificate_chain_; }
    void set_host(const std::string &host) { host_ = host; }
    std::string json_to_form_encoding(const json::JSON &data) const;
};

} // namespace enclave
} // namespace silentdata
