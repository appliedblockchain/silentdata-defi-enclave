/*
 *  Xero accounting software client
 */

#pragma once

#include <string>
#include <vector>

#include "lib/client/https_response.hpp"
#include "lib/common/encoders.hpp"
#include "lib/common/json.hpp"
#include "lib/common/types.hpp"

#include "clients/api_client/oauth_api_client.hpp"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wconversion"
#pragma GCC diagnostic ignored "-Wshadow"
#pragma GCC diagnostic ignored "-Wredundant-decls"
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wshadow"
#include "proto/messages.pb.h"
#pragma GCC diagnostic pop

namespace silentdata
{
namespace enclave
{

class XeroClient : public OAuthAPIClient
{
private:
    std::string code_;
    std::string code_verifier_;
    std::string redirect_uri_;
    std::string refresh_token_;
    std::string tenant_id_;

    std::vector<std::string> default_headers(bool post = false) const;
    json::JSON default_request_body() const;
    void post_connect_token(const std::string &body);
    Invoice parse_invoice(const json::JSON &data) const;

public:
    XeroClient(const std::string &hostname,
               const std::string &client_id,
               const std::string &secret,
               uint32_t timestamp,
               const std::string &code,
               const std::string &code_verifier,
               const std::string &redirect_uri,
               const std::string &refresh_token,
               const std::vector<std::string> &allowed_certificates = {});
    XeroClient(const std::string &hostname,
               const APIConfig &config,
               const std::string &code,
               const std::string &code_verifier,
               const std::vector<std::string> &allowed_certificates = {});
    XeroClient(const std::string &hostname,
               const APIConfig &config,
               const std::string &refresh_token);
    ~XeroClient();

    CoreStatusCode parse_error(const HTTPSResponse &response) const;

    void get_access();

    void destroy_access();

    void refresh_access();

    std::vector<std::string> get_tenant_ids();

    Invoice get_invoice(const std::string &invoice_id);

    std::vector<Invoice> get_invoices();

    const std::string &get_refresh_token() const { return refresh_token_; }
};

} // namespace enclave
} // namespace silentdata
