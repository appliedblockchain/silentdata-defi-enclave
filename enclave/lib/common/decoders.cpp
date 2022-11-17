#include "lib/common/decoders.hpp"

namespace silentdata
{
namespace enclave
{

std::string url_decode(const std::string &url_string)
{
    std::string decoded;
    size_t i;
    size_t len = url_string.length();

    for (i = 0; i < len; ++i)
    {
        if (url_string[i] == '+')
            decoded += ' ';
        else if (url_string[i] == '%')
        {
            char *e = NULL;
            unsigned long int v;

            // Have a % but run out of characters in the string
            if (i + 3 > len)
                THROW_EXCEPTION(kDecodingError, "Premature end of string");

            v = strtoul(url_string.substr(i + 1, 2).c_str(), &e, 16);

            // Have %hh but hh is not a valid hex code.
            if (*e)
                THROW_EXCEPTION(kDecodingError, "Invalid URL encoding");

            decoded += static_cast<char>(v);
            i += 2;
        }
        else
            decoded += url_string[i];
    }

    return decoded;
}

static const std::vector<int> B64index = {
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  62, 63, 62, 62, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 0,  0,  0,  0,  0,
    0,  0,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15, 16, 17, 18,
    19, 20, 21, 22, 23, 24, 25, 0,  0,  0,  0,  63, 0,  26, 27, 28, 29, 30, 31, 32, 33,
    34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51};

std::string b64_decode(const std::string &b64_string)
{
    const unsigned char *p = reinterpret_cast<const unsigned char *>(b64_string.data());
    const size_t len = b64_string.length();
    const int pad = len > 0 && (len % 4 || p[len - 1] == '=');
    const size_t L = ((len + 3) / 4 - pad) * 4;
    std::string str(L / 4 * 3 + pad, '\0');

    for (size_t i = 0, j = 0; i < L; i += 4)
    {
        try
        {
            const int n = B64index.at(p[i]) << 18 | B64index.at(p[i + 1]) << 12 |
                          B64index.at(p[i + 2]) << 6 | B64index.at(p[i + 3]);
            str[j++] = static_cast<char>(n >> 16);
            str[j++] = static_cast<char>(n >> 8 & 0xFF);
            str[j++] = static_cast<char>(n & 0xFF);
        }
        catch (const std::exception &e)
        {
            THROW_EXCEPTION(kDecodingError, "Not base64 encoded");
        }
    }
    if (pad)
    {
        try
        {
            int n = B64index.at(p[L]) << 18 | B64index.at(p[L + 1]) << 12;
            str[str.size() - 1] = static_cast<char>(n >> 16);

            if (len > L + 2 && p[L + 2] != '=')
            {
                n |= B64index.at(p[L + 2]) << 6;
                str.push_back(static_cast<char>(n >> 8 & 0xFF));
            }
        }
        catch (const std::exception &e)
        {
            THROW_EXCEPTION(kDecodingError, "Not base64 encoded");
        }
    }
    return str;
}

int hex_decode_char(char input)
{
    if (input >= '0' && input <= '9')
        return input - '0';
    if (input >= 'A' && input <= 'F')
        return input - 'A' + 10;
    if (input >= 'a' && input <= 'f')
        return input - 'a' + 10;
    THROW_EXCEPTION(kDecodingError, "Invalid hex input");
}

std::string hex_decode(const std::string &hex_string)
{
    if (hex_string.length() % 2)
        THROW_EXCEPTION(kDecodingError, "Invalid hex string length");
    std::string str(hex_string.length() / 2, '\0');
    for (size_t i = 0, j = 0; i < hex_string.size(); i += 2)
    {
        str[j++] = static_cast<char>(hex_decode_char(hex_string[i]) * 16 +
                                     hex_decode_char(hex_string[i + 1]));
    }
    return str;
}

std::array<uint8_t, CORE_SHA_512_256_LEN>
hash_from_msgpack_transaction(const std::vector<uint8_t> &encoded_transaction)
{
    // Check first byte corresponds to map with 7 elements (0x87)
    if (encoded_transaction.at(0) != 0x87)
        THROW_EXCEPTION(kDecodingError, "Signed data not msgpack encoded dummy transaction");
    std::array<uint8_t, CORE_SHA_512_256_LEN> hash = {0};

    bool found_note = false;
    size_t i = 1;
    while (i < encoded_transaction.size() - 38)
    {
        const int key_size = encoded_transaction.at(i) - 0xa0;
        i += 1;
        if (encoded_transaction.size() < i + key_size)
            THROW_EXCEPTION(kDecodingError, "Key longer than buffer");
        const std::string key(encoded_transaction.begin() + i,
                              encoded_transaction.begin() + i + key_size);
        i += key_size;
        if (key == "note")
        {
            if (encoded_transaction.at(i) != 0xc4)
                THROW_EXCEPTION(kDecodingError, "Invalid array tag");
            i += 1;
            const int byte_size = encoded_transaction.at(i);
            if (byte_size != CORE_SHA_512_256_LEN || encoded_transaction.size() < i + byte_size)
                THROW_EXCEPTION(kDecodingError, "Invalid byte array size");
            i += 1;
            std::copy(encoded_transaction.begin() + i,
                      encoded_transaction.begin() + i + CORE_SHA_512_256_LEN,
                      hash.begin());

            found_note = true;
            break;
        }
        const uint8_t value_id = encoded_transaction.at(i);
        if (value_id <= 0x7f) // Positive fixint
            i += 1;
        else if (value_id >= 0xa0 && value_id <= 0xbf) // fixstr (<32 bytes)
            i += 1 + (value_id - 0xa0);
        else if (value_id == 0xc0) // null
            i += 1;
        else if (value_id == 0xc2 || value_id == 0xc3) // true/false
            i += 1;
        else if (value_id == 0xcc) // uint8
            i += 2;
        else if (value_id == 0xcd) // uint16
            i += 3;
        else if (value_id == 0xce) // uint32
            i += 5;
        else if (value_id == 0xc4) // binary (<256 bytes)
            i += 2 + encoded_transaction.at(i + 1);
        else if (value_id == 0xd9) // string (<256 bytes)
            i += 2 + encoded_transaction.at(i + 1);
        else
            THROW_EXCEPTION(kDecodingError, "Unexpected value type");
    }

    if (!found_note)
        THROW_EXCEPTION(kDecodingError, "note field not found");

    return hash;
}

std::vector<uint8_t> hex_utf8_decode(const std::vector<uint8_t> &utf8_hex_message)
{
    // Decode hex characters from UTF-8
    const uint8_t utf8_0 = 0x30;
    const uint8_t utf8_A = 0x41;
    const uint8_t utf8_a = 0x61;

    std::string hex;
    for (const uint8_t byte : utf8_hex_message)
    {
        // Handle digits 0-9
        if (byte >= utf8_0 && byte <= utf8_0 + 9)
        {
            hex.push_back(static_cast<char>(static_cast<uint8_t>('0') + byte - utf8_0));
            continue;
        }

        // Handle uppercase A-F
        if (byte >= utf8_A && byte <= utf8_A + 5)
        {
            hex.push_back(static_cast<char>(static_cast<uint8_t>('A') + byte - utf8_A));
            continue;
        }

        // Handle lowercase a-f
        if (byte >= utf8_a && byte <= utf8_a + 5)
        {
            hex.push_back(static_cast<char>(static_cast<uint8_t>('a') + byte - utf8_a));
            continue;
        }

        THROW_EXCEPTION(kDecodingError,
                        "Unexpected UTF-8 character code: " + std::to_string(unsigned(byte)));
    }

    // Decode from hex
    const std::string decoded_str = hex_decode(hex);
    return std::vector<uint8_t>(decoded_str.begin(), decoded_str.end());
}

} // namespace enclave
} // namespace silentdata
