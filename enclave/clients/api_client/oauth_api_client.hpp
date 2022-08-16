/*
 *  Abstract base class for API clients
 */

#pragma once

#include <string>
#include <vector>

#include "clients/api_client/api_client.hpp"

#include "lib/client/client_opt.h"
#include "lib/client/https_client.hpp"
#include "lib/client/https_response.hpp"
#include "lib/common/json.hpp"
#include "lib/common/types.hpp"

namespace silentdata
{
namespace enclave
{

class OAuthAPIClient : public APIClient
{
protected:
    std::string client_id_;
    std::string access_token_;

public:
    OAuthAPIClient(const std::string &host,
                   const std::string &client_id,
                   const std::string &secret,
                   uint32_t timestamp,
                   const std::vector<std::string> &allowed_certificates)
        : APIClient(host, secret, timestamp, allowed_certificates), client_id_(client_id)
    {
    }
    virtual ~OAuthAPIClient() {}

    virtual void get_access() = 0;

    virtual void destroy_access() = 0;
};

} // namespace enclave
} // namespace silentdata
