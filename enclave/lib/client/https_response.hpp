/*
 * Return type of GET and POST requests from HTTPSClient
 */

#pragma once

#include <string>
#include <vector>

#include "lib/client/response.h"

namespace silentdata
{
namespace enclave
{

class HTTPSResponse
{
public:
    HTTPSResponse() : valid_(false) {}
    HTTPSResponse(httpparser::Response response, std::string cert_chain, bool valid)
        : http_response_(response), certificate_chain_(cert_chain), valid_(valid)
    {
    }

    unsigned int get_status_code() const { return http_response_.statusCode; }
    std::string get_body() const;
    const std::vector<httpparser::Response::HeaderItem> &get_headers() const
    {
        return http_response_.headers;
    }
    const std::string &get_certificate_chain() const { return certificate_chain_; }
    std::string get_timestamp() const;
    bool is_valid() const { return valid_; }

private:
    httpparser::Response http_response_;
    std::string certificate_chain_;
    bool valid_;
};

} // namespace enclave
} // namespace silentdata
