#include "lib/proof/api_requests.hpp"

namespace silentdata
{
namespace enclave
{

APIRequest::APIRequest(const std::vector<APIConfig> &api_configs,
                       const ClientInfo &client_info,
                       const EC256KeyPair &key_pair)
    : api_configs_(api_configs), client_info_(client_info), has_symmetric_key_(false)
{
    if (client_info.proof_id().size() != CORE_UUID_LEN)
        THROW_EXCEPTION(kInvalidInput, "Proof ID is incorrect size");

    for (const auto &api_config : api_configs)
        api_clients_.push_back(api_config.client());

    encrypted_input_.insert(encrypted_input_.end(),
                            client_info.encrypted_input().begin(),
                            client_info.encrypted_input().end());

    // Verify that the client and server timestamps match within some limit
    if (std::abs(client_info.client_timestamp() - api_configs.at(0).server_timestamp()) >
        CORE_TIMESTAMP_AGREEMENT)
    {
        THROW_EXCEPTION(kInvalidInput, "Server and client timestamps do not match");
    }

    // ATTN for some use cases, the client public key isn't required and so can be passed as empty
    if (!client_info.encryption_public_key().empty())
    {
        symmetric_key_ = key_pair.ecdh(
            reinterpret_cast<const uint8_t *>(client_info.encryption_public_key().data()));
        has_symmetric_key_ = true;
    }

    if (!client_info.allowed_certificates().empty())
    {
        allowed_certificates_ = std::vector<uint8_t>(client_info.allowed_certificates().begin(),
                                                     client_info.allowed_certificates().end());
    }
}

const AESGCMKey &APIRequest::get_symmetric_key() const
{
    if (!has_symmetric_key_)
        THROW_EXCEPTION(kInvalidInput, "Symmetric key not available");

    return symmetric_key_;
}

std::vector<uint8_t> APIRequest::get_decrypted_input() const
{
    // Construct additional authenticated data
    const uint32_t timestamp = get_client_timestamp();
    std::vector<uint8_t> aad = std::vector<uint8_t>(CORE_UUID_LEN + CORE_TIMESTAMP_LEN);
    std::memcpy(aad.data(), get_proof_id().data(), CORE_UUID_LEN);
    std::memcpy(aad.data() + CORE_UUID_LEN, &timestamp, CORE_TIMESTAMP_LEN);
    return get_symmetric_key().decrypt(encrypted_input_, aad);
}

PlaidLinkRequestWrapper::PlaidLinkRequestWrapper(const PlaidLinkTokenRequest &request,
                                                 const EC256KeyPair &key_pair)
    : APIRequest({request.api_config()}, request.client_info(), key_pair), request_(request)
{
    api_clients_ = {"plaid"};
}

CrossflowInvoiceCheckRequestWrapper::CrossflowInvoiceCheckRequestWrapper(
    const CrossflowInvoiceCheckRequest &request, const EC256KeyPair &key_pair)
    : APIRequest({request.crossflow_api_config()}, request.client_info(), key_pair),
      request_(request)
{
    if (request.wallet_info().blockchain() != WalletInfo_Blockchain_ALGORAND)
        THROW_EXCEPTION(kInvalidInput, "Only algorand supported for crossflow invoice proofs");

    const std::string &program_hash = request.wallet_info().program_hash();
    if (program_hash.size() != CORE_SHA_512_256_LEN)
        THROW_EXCEPTION(kInvalidInput, "Smart contract program hash wrong size");
    std::copy(program_hash.begin(), program_hash.end(), program_hash_.begin());
}

} // namespace enclave
} // namespace silentdata
