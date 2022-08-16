#include "lib/common/logicsig.hpp"

#include <unordered_map>

#include "lib/common/enclave_exception.hpp"
#include "lib/crypto/hash.hpp"

namespace silentdata
{
namespace enclave
{

const std::unordered_map<char, uint8_t> hex_char_to_number = {{'0', 0},
                                                              {'1', 1},
                                                              {'2', 2},
                                                              {'3', 3},
                                                              {'4', 4},
                                                              {'5', 5},
                                                              {'6', 6},
                                                              {'7', 7},
                                                              {'8', 8},
                                                              {'9', 9},
                                                              {'a', 10},
                                                              {'b', 11},
                                                              {'c', 12},
                                                              {'d', 13},
                                                              {'e', 14},
                                                              {'f', 15}};

std::vector<uint8_t> parse_contract_string(const std::string &template_compiled_contract,
                                           const std::array<uint8_t, CORE_SHA_256_LEN> &invoice_id,
                                           uint64_t minting_app_id)
{
    std::vector<uint8_t> output;
    const std::string invoice_id_template = "<SILENTDATA_ASSET_ID>";
    const std::string minting_id_template = "<MINTING_APP_ID_BYTES>";

    size_t i = 0;
    while (i < template_compiled_contract.length())
    {
        const char c1 = template_compiled_contract.at(i);

        const bool is_hex_char = (hex_char_to_number.count(c1) != 0);
        if (!is_hex_char && c1 != '<')
            THROW_EXCEPTION(
                kDecodingError,
                "Couldn't parse input template_compiled_contract. Unexpected character '" +
                    std::string(1, c1) + "' at index " + std::to_string(i));

        if (is_hex_char)
        {
            // Expect the next character to be hex too!
            if (i == template_compiled_contract.length() - 1)
                THROW_EXCEPTION(kDecodingError,
                                "Couldn't parse input template_compiled_contract. Expected hex "
                                "character, but reached end of string");

            const char c2 = template_compiled_contract.at(i + 1);
            if (hex_char_to_number.count(c2) == 0)
                THROW_EXCEPTION(kDecodingError,
                                "Couldn't parse input template_compiled_contract. Expected hex "
                                "character, but found '" +
                                    std::string(1, c1) + "' at index " + std::to_string(i));

            // Take the two hex characters as a byte
            const uint8_t byte =
                static_cast<uint8_t>((16 * hex_char_to_number.at(c1)) + hex_char_to_number.at(c2));
            output.emplace_back(byte);
            i += 2;
            continue;
        }

        // Otherwise the next characters should be <SILENTDATA_ASSET_ID> or <MINTING_APP_ID_BYTES>
        std::size_t found = template_compiled_contract.find(invoice_id_template, i);
        if (found != std::string::npos && found == i)
        {
            // Inject the invoice ID to the output
            output.insert(output.end(), invoice_id.begin(), invoice_id.end());
            i += invoice_id_template.length();
            continue;
        }
        found = template_compiled_contract.find(minting_id_template, i);
        if (found != std::string::npos && found == i)
        {
            // Inject the minting app ID to the output as bytes
            std::vector<uint8_t> minting_app_id_bytes(8);
            for (int b_i = 0; b_i < 8; b_i++)
                minting_app_id_bytes[7 - b_i] = static_cast<uint8_t>(minting_app_id >> (b_i * 8));
            DEBUG_LOG("MINTING APP ID %i", minting_app_id);
            DEBUG_HEX_LOG("Minting app bytes", minting_app_id_bytes.data(), 8);
            output.insert(output.end(), minting_app_id_bytes.begin(), minting_app_id_bytes.end());
            i += minting_id_template.length();
            continue;
        }
        else
        {
            THROW_EXCEPTION(kDecodingError, "Expected template after finding '<'");
        }
    }
    DEBUG_HEX_LOG("Compiled lsig code", output.data(), static_cast<int>(output.size()));

    return output;
}

std::array<uint8_t, CORE_SHA_512_256_LEN>
get_logicsig_public_key(const std::string &template_compiled_contract,
                        const std::array<uint8_t, CORE_SHA_256_LEN> &invoice_id,
                        uint64_t minting_app_id)
{
    // Parse the input template_compiled_contract and inject the invoice ID
    const auto injected_contract =
        parse_contract_string(template_compiled_contract, invoice_id, minting_app_id);

    // The tag "Program" is added as a prefix to the compiled contract
    std::vector<uint8_t> message = {80, 114, 111, 103, 114, 97, 109};
    message.insert(message.end(), injected_contract.begin(), injected_contract.end());

    // Hash the compiled contract
    const std::vector<uint8_t> hash = Hash::get_digest(Hash::SHA512_256, message);
    if (hash.size() != CORE_SHA_512_256_LEN)
        THROW_EXCEPTION(kDecodingError, "Hash has the wrong size!");

    // Copy into the output array
    std::array<uint8_t, CORE_SHA_512_256_LEN> output;
    std::copy_n(hash.begin(), CORE_SHA_512_256_LEN, output.begin());
    return output;
}

} // namespace enclave
} // namespace silentdata
