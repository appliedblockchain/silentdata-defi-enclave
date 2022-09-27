/*
 * Common proof request/response types
 */

#pragma once

#include <array>
#include <string>
#include <vector>

#include "include/core_constants.h"
#include "include/core_status_codes.h"

#include "lib/common/decoders.hpp"
#include "lib/common/types.hpp"
#include "lib/crypto/aes_gcm_key.hpp"
#include "lib/crypto/ec256_key_pair.hpp"
#include "lib/crypto/hash.hpp"
#include "lib/eddsa/eddsa.h"

#include "lib/proof/api_requests.hpp"

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

enum Blockchain
{
    kAlgorand = 0,
    kSolana = 1
};

class WalletRequest : public APIRequest
{
public:
    WalletRequest(const std::vector<APIConfig> &api_configs,
                  const ClientInfo &client_info,
                  const WalletInfo &wallet_info,
                  const EC256KeyPair &key_pair);
    ~WalletRequest() {}

    const std::array<uint8_t, CORE_SHA_512_256_LEN> &get_program_hash() const
    {
        return program_hash_;
    }
    const std::array<uint8_t, CORE_ED25519_KEY_LEN> &get_wallet_public_key() const
    {
        return wallet_public_key_;
    }
    const std::array<uint8_t, CORE_ED25519_SIG_LEN> &get_wallet_signature() const
    {
        return wallet_signature_;
    }
    Blockchain get_blockchain() const
    {
        if (wallet_blockchain_ == WalletInfo_Blockchain_ALGORAND)
            return kAlgorand;
        else if (wallet_blockchain_ == WalletInfo_Blockchain_SOLANA)
            return kSolana;
        else
            THROW_EXCEPTION(kInvalidInput, "Unknown wallet blockchain")
    }
    std::vector<uint8_t> get_signed_data() const
    {
        return get_symmetric_key().decrypt(encrypted_signed_data_);
    }
    void verify_wallet_signature() const;
    void verify_allowed_certificates() const;

private:
    std::array<uint8_t, CORE_SHA_512_256_LEN> get_decrypted_data_hash_from_signed_data() const;
    std::vector<uint8_t> get_signed_data_for_verification() const;

    std::array<uint8_t, CORE_SHA_512_256_LEN> program_hash_;
    std::array<uint8_t, CORE_ED25519_KEY_LEN> wallet_public_key_;
    std::array<uint8_t, CORE_ED25519_SIG_LEN> wallet_signature_;
    WalletInfo_Encoding wallet_signed_data_encoding_;
    WalletInfo_Blockchain wallet_blockchain_;
    std::vector<uint8_t> encrypted_signed_data_;
};

class BalanceCheckRequestWrapper : public WalletRequest
{
public:
    BalanceCheckRequestWrapper(const MinimumBalanceCheckRequest &request,
                               const EC256KeyPair &key_pair);
    ~BalanceCheckRequestWrapper() {}

    const AccountNumbers &get_account_numbers() const { return request_.account_numbers(); }
    bool match_account_numbers() const { return !(request_.account_numbers().ByteSizeLong() == 0); }
    const std::string &get_currency_code() const { return request_.currency_code(); }
    uint32_t get_minimum_balance() const { return request_.minimum_balance(); }

private:
    MinimumBalanceCheckRequest request_;
};

class IncomeCheckRequestWrapper : public WalletRequest
{
public:
    IncomeCheckRequestWrapper(const ConsistentIncomeCheckRequest &request,
                              const EC256KeyPair &key_pair);
    ~IncomeCheckRequestWrapper() {}

    const AccountNumbers &get_account_numbers() const { return request_.account_numbers(); }
    bool match_account_numbers() const { return !(request_.account_numbers().ByteSizeLong() == 0); }
    const std::string &get_currency_code() const { return request_.currency_code(); }
    uint32_t get_consistent_income() const { return request_.consistent_income(); }
    bool is_stable() const { return request_.stable(); }

private:
    ConsistentIncomeCheckRequest request_;
};

class OnfidoKYCCheckRequestWrapper : public WalletRequest
{
public:
    OnfidoKYCCheckRequestWrapper(const OnfidoKYCCheckRequest &request,
                                 const EC256KeyPair &key_pair);
    ~OnfidoKYCCheckRequestWrapper() {}

private:
    OnfidoKYCCheckRequest request_;
};

class InstagramCheckRequestWrapper : public WalletRequest
{
public:
    InstagramCheckRequestWrapper(const InstagramCheckRequest &request,
                                 const EC256KeyPair &key_pair);
    ~InstagramCheckRequestWrapper() {}

private:
    InstagramCheckRequest request_;
};

} // namespace enclave
} // namespace silentdata
