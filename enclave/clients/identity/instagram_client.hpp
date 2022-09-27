/*
 * Calls to Instagram API
 */

#pragma once

#include <array>
#include <map>
#include <string>
#include <time.h>
#include <vector>

#include "sgx_tcrypto.h"

#include "include/core_status_codes.h"

#include "lib/client/client_opt.h"
#include "lib/client/https_client.hpp"
#include "lib/client/https_response.hpp"
#include "lib/common/date_time.hpp"
#include "lib/common/enclave_exception.hpp"
#include "lib/common/enclave_logger.hpp"
#include "lib/common/json.hpp"
#include "lib/common/optional.hpp"
#include "lib/common/sgx_error_message.hpp"
#include "lib/common/types.hpp"

#include "clients/api_client/oauth_api_client.hpp"

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

class InstagramClient : public OAuthAPIClient
{
private:
    std::string code_;
    std::string redirect_uri_;
    std::string access_token_;
    std::string user_id_;

    std::vector<std::string> default_headers(bool post = false) const;
    json::JSON default_request_body() const;

    Optional<std::string> parse_error_type(const HTTPSResponse &response) const;
    std::string get_user_field(const std::string &field);

public:
    InstagramClient(const std::string &hostname,
                    const std::string &client_id,
                    const std::string &secret,
                    uint32_t timestamp,
                    const std::string &code,
                    const std::string &redirect_uri);
    InstagramClient(const std::string &hostname, const APIConfig &config, const std::string &code);

    CoreStatusCode parse_error(const HTTPSResponse &response) const;

    // Send a request to the Instagram API to obtain an access token from a authorization code
    void get_access();
    void destroy_access();

    // Send a request to the Instagram API to get the username
    std::string get_username();
    // Send a request to the Instagram API to get the account type
    std::string get_account_type();
};

} // namespace enclave
} // namespace silentdata
