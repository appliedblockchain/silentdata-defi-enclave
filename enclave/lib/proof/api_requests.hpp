/*
 * Common proof request/response types
 */

#pragma once

#include <array>
#include <string>
#include <vector>

#include "include/core_constants.h"
#include "include/core_status_codes.h"

#include "clients/banking/plaid_client.hpp"

#include "lib/common/cbor_map.hpp"
#include "lib/common/types.hpp"
#include "lib/crypto/aes_gcm_key.hpp"
#include "lib/crypto/ec256_key_pair.hpp"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wconversion"
#pragma GCC diagnostic ignored "-Wredundant-decls"
#pragma GCC diagnostic ignored "-Wunused-parameter"
#include "proto/messages.pb.h"
#include "proto/requests.pb.h"
#pragma GCC diagnostic pop

namespace silentdata
{
namespace enclave
{

class APIRequest
{
public:
    APIRequest(const std::vector<APIConfig> &api_configs,
               const ClientInfo &client_info,
               const EC256KeyPair &key_pair);
    virtual ~APIRequest() {}

    const APIConfig &get_api_config(const size_t i) const
    {
        if (i >= api_configs_.size())
            THROW_EXCEPTION(kInvalidInput, "API config index out of range");
        return api_configs_.at(i);
    }
    const std::string get_api_client(const size_t i) const
    {
        if (i >= api_clients_.size())
            THROW_EXCEPTION(kInvalidInput, "API client index out of range");
        return api_clients_.at(i);
    }
    int32_t get_client_timestamp() const { return client_info_.client_timestamp(); }
    int32_t get_server_timestamp() const { return api_configs_.at(0).server_timestamp(); }
    const AESGCMKey &get_symmetric_key() const;
    std::vector<uint8_t> get_decrypted_input() const;
    const std::string &get_proof_id() const { return client_info_.proof_id(); }
    const std::vector<uint8_t> &get_allowed_certificates() const { return allowed_certificates_; }
    std::string get_allowed_certificate(const std::string &hostname) const
    {
        CBORMap certificate_map(allowed_certificates_, {hostname});
        return certificate_map.get(hostname).get_text_string_value();
    }

private:
    const std::vector<APIConfig> api_configs_;

protected:
    const ClientInfo client_info_;
    std::vector<std::string> api_clients_;
    std::vector<uint8_t> encrypted_input_;
    bool has_symmetric_key_;
    AESGCMKey symmetric_key_;
    std::vector<uint8_t> allowed_certificates_;
};

class PlaidLinkRequestWrapper : public APIRequest
{
public:
    PlaidLinkRequestWrapper(const PlaidLinkTokenRequest &request, const EC256KeyPair &key_pair);
    ~PlaidLinkRequestWrapper() {}

    const std::string &get_client_user_id() const { return request_.client_user_id(); }
    const std::string &get_country() const { return request_.country(); }

private:
    PlaidLinkTokenRequest request_;
};

class CrossflowInvoiceCheckRequestWrapper : public APIRequest
{
public:
    CrossflowInvoiceCheckRequestWrapper(const CrossflowInvoiceCheckRequest &request,
                                        const EC256KeyPair &key_pair);
    ~CrossflowInvoiceCheckRequestWrapper() {}

    std::vector<uint8_t> get_decrypted_input() const
    {
        // ATTN no encrypted data is used, but function definition is required by APIRequest
        return {};
    }

    const std::array<uint8_t, CORE_SHA_512_256_LEN> &get_program_hash() const
    {
        return program_hash_;
    }
    std::string get_cf_request_id() const { return request_.cf_request_id(); }
    uint64_t get_minting_app_id() const { return request_.minting_app_id(); }

private:
    CrossflowInvoiceCheckRequest request_;
    std::array<uint8_t, CORE_SHA_512_256_LEN> program_hash_;
};

} // namespace enclave
} // namespace silentdata
