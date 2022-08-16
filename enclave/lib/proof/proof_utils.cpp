#include "lib/proof/proof_utils.hpp"

namespace silentdata
{
namespace enclave
{

std::vector<uint8_t> get_encrypted_link_token(const PlaidLinkRequestWrapper &request)
{
    // Checks that the key is ok
    request.get_decrypted_input();

    // Configure the Plaid options
    const std::string hostname = request.get_api_config(0).environment() + ".plaid.com";
    PlaidClient plaid(
        hostname, request.get_api_config(0), {request.get_allowed_certificate(hostname)});

    const PlaidLink plaid_link =
        plaid.create_link_token(request.get_client_user_id(), request.get_country());

    const uint32_t timestamp = request.get_server_timestamp();

    CBORMap map;
    map.insert("timestamp", timestamp);
    map.insert("token", plaid_link.token);
    map.insert("expiration", plaid_link.expiration);
    map.insert("request_id", plaid_link.request_id);

    const std::vector<uint8_t> link = map.encode_cbor();

    return request.get_symmetric_key().encrypt(link);
}

} // namespace enclave
} // namespace silentdata
