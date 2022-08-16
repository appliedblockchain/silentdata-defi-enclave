#include "lib/proof/wallet_requests.hpp"

namespace silentdata
{
namespace enclave
{

WalletRequest::WalletRequest(const std::vector<APIConfig> &api_configs,
                             const ClientInfo &client_info,
                             const WalletInfo &wallet_info,
                             const EC256KeyPair &key_pair)
    : APIRequest(api_configs, client_info, key_pair),
      wallet_signed_data_encoding_(wallet_info.encoding()),
      wallet_blockchain_(wallet_info.blockchain())
{
    if (api_configs.empty())
        THROW_EXCEPTION(kClientConfigurationError, "No API configuration provided");

    const std::string &program_hash = wallet_info.program_hash();
    if (wallet_blockchain_ == WalletInfo_Blockchain_ALGORAND &&
        program_hash.size() != CORE_SHA_512_256_LEN)
        THROW_EXCEPTION(kInvalidInput, "Smart contract program hash wrong size");
    std::copy(program_hash.begin(), program_hash.end(), program_hash_.begin());

    const std::string &wallet_public_key = wallet_info.wallet_public_key();
    if (wallet_public_key.size() != CORE_ED25519_KEY_LEN)
        THROW_EXCEPTION(kInvalidInput, "Wallet public key wrong size");
    std::copy(wallet_public_key.begin(), wallet_public_key.end(), wallet_public_key_.begin());

    const std::string &wallet_signature = wallet_info.signature();
    if (wallet_signature.size() != CORE_ED25519_SIG_LEN)
        THROW_EXCEPTION(kInvalidInput, "Wallet signature wrong size");
    std::copy(wallet_signature.begin(), wallet_signature.end(), wallet_signature_.begin());

    const std::string &encrypted_signed_data = wallet_info.encrypted_signed_data();
    encrypted_signed_data_.insert(
        encrypted_signed_data_.end(), encrypted_signed_data.begin(), encrypted_signed_data.end());
}

std::array<uint8_t, CORE_SHA_512_256_LEN>
WalletRequest::get_decrypted_data_hash_from_signed_data() const
{
    const std::vector<uint8_t> signed_data = get_signed_data();
    std::array<uint8_t, CORE_SHA_512_256_LEN> signed_hash;
    if (wallet_blockchain_ == WalletInfo_Blockchain_ALGORAND)
    {
        // The signed_data is an algorand transaction (encoded via msgpack)
        // The "note" field of the transaction should be the hash of the decrypted_data
        signed_hash = hash_from_msgpack_transaction(signed_data);
    }
    else
    {
        // Otherwise the data that was signed may have been encoded in hex and needs
        // to be decoded back into bytes to get the hash
        const std::vector<uint8_t> decoded_signed_data =
            (wallet_signed_data_encoding_ == WalletInfo_Encoding_HEX_UTF8)
                ? hex_utf8_decode(signed_data)
                : signed_data;
        if (decoded_signed_data.size() != CORE_SHA_512_256_LEN)
            THROW_EXCEPTION(kInvalidInput, "Signed data has the wrong length");
        std::copy(decoded_signed_data.begin(), decoded_signed_data.end(), signed_hash.begin());
    }
    return signed_hash;
}

std::vector<uint8_t> WalletRequest::get_signed_data_for_verification() const
{
    const std::vector<uint8_t> signed_data = get_signed_data();
    std::vector<uint8_t> data_to_verify;
    if (wallet_blockchain_ == WalletInfo_Blockchain_ALGORAND)
    {
        // That signature, should be for the signed_data (prefixed with "TX")
        const std::string prefix = "TX";
        data_to_verify.insert(data_to_verify.end(), prefix.begin(), prefix.end());
        data_to_verify.insert(data_to_verify.end(), signed_data.begin(), signed_data.end());
    }
    else
    {
        data_to_verify = signed_data;
    }
    return data_to_verify;
}

void WalletRequest::verify_wallet_signature() const
{
    // Hash the decrypted_data
    const std::vector<uint8_t> decrypted_data = get_decrypted_input();
    std::array<uint8_t, CORE_SHA_256_LEN> hash = Hash::get_SHA_256_digest(decrypted_data);

    // Verify the signed_data includes the hash of the decrypted_data
    std::array<uint8_t, CORE_SHA_256_LEN> signed_hash = get_decrypted_data_hash_from_signed_data();
    if (std::memcmp(hash.data(), signed_hash.data(), CORE_SHA_256_LEN) != 0)
        THROW_EXCEPTION(kInvalidInput, "Signed data does not match hash of private data");

    // Verify that the signature matches the signed_with_prefix and the wallet public key supplied
    std::vector<uint8_t> signed_data = get_signed_data_for_verification();
    if (!ed25519_verify(get_wallet_signature().data(),
                        get_wallet_public_key().data(),
                        signed_data.data(),
                        signed_data.size()))
        THROW_EXCEPTION(kSignatureVerificationError, "Failed to verify wallet signature");

    verify_allowed_certificates();
    return;
}

void WalletRequest::verify_allowed_certificates() const
{
    DEBUG_LOG("Verifying allowed certificates");
    if (allowed_certificates_.size() > 0)
    {
        const std::vector<uint8_t> decrypted_data = get_decrypted_input();
        CBORMap input_map(decrypted_data, {"certificate_hash"});
        std::vector<uint8_t> signed_hash =
            input_map.get("certificate_hash").get_byte_string_value();

        const std::vector<uint8_t> certificates(client_info_.allowed_certificates().begin(),
                                                client_info_.allowed_certificates().end());
        std::array<uint8_t, CORE_SHA_256_LEN> certificate_hash =
            Hash::get_SHA_256_digest(certificates);

        if (std::memcmp(signed_hash.data(), certificate_hash.data(), CORE_SHA_256_LEN) != 0)
            THROW_EXCEPTION(kInvalidInput,
                            "Signed certificate hash does not match input certificates");
    }
    return;
}

BalanceCheckRequestWrapper::BalanceCheckRequestWrapper(const MinimumBalanceCheckRequest &request,
                                                       const EC256KeyPair &key_pair)
    : WalletRequest({request.api_config()}, request.client_info(), request.wallet_info(), key_pair),
      request_(request)
{
}

IncomeCheckRequestWrapper::IncomeCheckRequestWrapper(const ConsistentIncomeCheckRequest &request,
                                                     const EC256KeyPair &key_pair)
    : WalletRequest({request.api_config()}, request.client_info(), request.wallet_info(), key_pair),
      request_(request)
{
}

OnfidoKYCCheckRequestWrapper::OnfidoKYCCheckRequestWrapper(const OnfidoKYCCheckRequest &request,
                                                           const EC256KeyPair &key_pair)
    : WalletRequest({request.api_config()}, request.client_info(), request.wallet_info(), key_pair),
      request_(request)
{
}

InstagramCheckRequestWrapper::InstagramCheckRequestWrapper(const InstagramCheckRequest &request,
                                                           const EC256KeyPair &key_pair)
    : WalletRequest({request.api_config()}, request.client_info(), request.wallet_info(), key_pair),
      request_(request)
{
}

} // namespace enclave
} // namespace silentdata
