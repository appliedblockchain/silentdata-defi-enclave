#include "lib/proof/proof_data.hpp"

namespace silentdata
{
namespace enclave
{

std::array<uint8_t, CORE_SHA_256_LEN> type_to_check_hash(ProofType type)
{
    std::vector<uint8_t> message_bytes(4);
    for (int i = 0; i < 4; i++)
        message_bytes[3 - i] = static_cast<uint8_t>(type >> (i * 8));

    return Hash::get_SHA_256_digest(message_bytes);
}

std::vector<uint8_t>
generate_proof_data(CBORMap &map,
                    const std::array<uint8_t, CORE_SHA_256_LEN> &check_hash,
                    std::string proof_id,
                    int32_t timestamp,
                    const std::array<uint8_t, CORE_ED25519_KEY_LEN> &initiator_pkey,
                    const std::vector<uint8_t> &certificate_hash)
{
    map.insert("check_hash", check_hash);
    map.insert("id", proof_id);
    map.insert("timestamp", timestamp);
    map.insert("initiator_pkey", initiator_pkey);
    if (certificate_hash.size() == CORE_SHA_256_LEN)
    {
        map.insert("certificate_hash", certificate_hash);
    }

    return map.encode_cbor();
}

std::vector<uint8_t>
generate_asset_proof_data(CBORMap &map,
                          const std::array<uint8_t, CORE_SHA_256_LEN> &check_hash,
                          std::string proof_id,
                          int32_t timestamp,
                          const std::array<uint8_t, CORE_ED25519_KEY_LEN> &initiator_pkey,
                          const std::vector<uint8_t> &certificate_hash,
                          const std::array<uint8_t, CORE_SHA_256_LEN> &asset_id,
                          const std::array<uint8_t, CORE_ED25519_KEY_LEN> &lsig_pkey)
{
    map.insert("asset_id", asset_id);
    map.insert("lsig_pkey", lsig_pkey);

    return generate_proof_data(
        map, check_hash, proof_id, timestamp, initiator_pkey, certificate_hash);
}

std::vector<uint8_t> generate_crossflow_invoice_proof_data(
    const std::string &proof_id,
    int32_t timestamp,
    const std::array<uint8_t, CORE_ED25519_KEY_LEN> &initiator_pkey,
    const std::vector<uint8_t> &certificate_hash,
    const std::array<uint8_t, CORE_SHA_256_LEN> &invoice_id,
    uint64_t minting_app_id,
    uint8_t risk_score,
    uint64_t value,
    const std::string &currency_code,
    uint64_t interest_rate,
    int32_t funding_date,
    int32_t due_date)
{
    const std::array<uint8_t, CORE_ID_HASH_LEN> check_hash =
        type_to_check_hash(kCrossflowInvoiceProof);
    DEBUG_HEX_LOG("Crossflow invoice check hash", check_hash.data(), check_hash.size());

    CBORMap map;
    map.insert("risk_score", risk_score);
    map.insert("value", value);
    map.insert("currency_code", currency_code);
    map.insert("interest_rate", interest_rate);
    map.insert("funding_date", funding_date);
    map.insert("due_date", due_date);

    const std::string asset_lsig_template =
        "052004000601048020<SILENTDATA_ASSET_ID>"
        "800130134431093203124431153203124431203203124431133203124431082212443112221244310122124431"
        "188800921240004732048103124433001023124433001888007c124433001922124437001a00800a7065726d69"
        "7373696f6e12443301102412443116810212443110251240003a3110231240003c003110231244311924124432"
        "04250f4433031023124433031888002c124433031922124437031a0080046d696e741244420011311431001244"
        "4200083119241244420000244322438008<MINTING_APP_ID_BYTES>1789";
    std::array<uint8_t, CORE_ED25519_KEY_LEN> lsig_pkey =
        get_logicsig_public_key(asset_lsig_template, invoice_id, minting_app_id);
    DEBUG_HEX_LOG("Crossflow invoice lsig public key", lsig_pkey.data(), lsig_pkey.size());

    return generate_asset_proof_data(map,
                                     check_hash,
                                     proof_id,
                                     timestamp,
                                     initiator_pkey,
                                     certificate_hash,
                                     invoice_id,
                                     lsig_pkey);
}

std::vector<uint8_t>
generate_kyc_proof_data(const std::string &proof_id,
                        int32_t timestamp,
                        const std::array<uint8_t, CORE_ED25519_KEY_LEN> &initiator_pkey,
                        const std::vector<uint8_t> &certificate_hash,
                        int32_t check_timestamp,
                        const std::array<uint8_t, CORE_SHA_256_LEN> &subject_id)
{
    const std::array<uint8_t, CORE_ID_HASH_LEN> check_hash = type_to_check_hash(kKYCCheckProof);
    DEBUG_HEX_LOG("KYC check hash", check_hash.data(), check_hash.size());

    CBORMap map;
    map.insert("check_timestamp", check_timestamp);
    map.insert("subject_id", subject_id);

    return generate_proof_data(
        map, check_hash, proof_id, timestamp, initiator_pkey, certificate_hash);
}

std::vector<uint8_t>
generate_instagram_proof_data(const std::string &proof_id,
                              int32_t timestamp,
                              const std::array<uint8_t, CORE_ED25519_KEY_LEN> &initiator_pkey,
                              const std::vector<uint8_t> &certificate_hash,
                              const std::string &username)
{
    const std::array<uint8_t, CORE_ID_HASH_LEN> check_hash = type_to_check_hash(kInstagramProof);
    DEBUG_HEX_LOG("Instagram check hash", check_hash.data(), check_hash.size());

    CBORMap map;
    map.insert("ig_username", username);

    return generate_proof_data(
        map, check_hash, proof_id, timestamp, initiator_pkey, certificate_hash);
}

std::vector<uint8_t>
generate_bank_proof_data(ProofType type,
                         const std::string &proof_id,
                         int32_t timestamp,
                         const std::array<uint8_t, CORE_ED25519_KEY_LEN> &initiator_pkey,
                         const std::vector<uint8_t> &certificate_hash,
                         const std::string &account_holder_name,
                         const std::string &institution_name,
                         const std::string &currency_code,
                         uint32_t comparison_value,
                         const std::string &server_timestamp,
                         const std::string &server_common_name)
{
    if (type == kMinimumBalanceProof)
        DEBUG_LOG("Serializing minimum balance proof data.");
    else if (type == kConsistentIncomeProof)
        DEBUG_LOG("Serializing consistent income proof data.");
    else if (type == kStableIncomeProof)
        DEBUG_LOG("Serializing stable income proof data.");
    else
        THROW_EXCEPTION(kSigningError, "Invalid proof type");

    const std::array<uint8_t, CORE_ID_HASH_LEN> check_hash = type_to_check_hash(type);

    CBORMap map;
    map.insert("account_holder_name", account_holder_name);
    map.insert("institution_name", institution_name);
    map.insert("currency_code", currency_code);
    map.insert("comparison_value", comparison_value);
    map.insert("server_timestamp", server_timestamp);
    map.insert("server_common_name", server_common_name);

    return generate_proof_data(
        map, check_hash, proof_id, timestamp, initiator_pkey, certificate_hash);
}

} // namespace enclave
} // namespace silentdata
