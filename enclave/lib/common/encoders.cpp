#include "lib/common/encoders.hpp"

#include <unordered_map>

namespace silentdata
{
namespace enclave
{

char to_hex(char code)
{
    static char hex[] = "0123456789ABCDEF";
    return hex[code & 15];
}

std::string url_encode(const std::string &str)
{
    std::string encoded;

    for (const char &c : str)
    {

        // Keep alphanumeric and other accepted characters intact
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~')
        {
            encoded += c;
            continue;
        }

        // Any other characters are percent-encoded
        encoded += '%';
        encoded += to_hex(static_cast<char>(c >> 4));
        encoded += to_hex(c & 15);
    }

    return encoded;
}

std::string hex_encode(const std::string &str)
{
    static const char hex_digits[] = "0123456789abcdef";

    std::string output;
    output.reserve(str.length() * 2);
    for (unsigned char c : str)
    {
        output.push_back(hex_digits[c >> 4]);
        output.push_back(hex_digits[c & 15]);
    }
    return output;
}

static const unsigned char base64_table[65] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string b64_encode(const std::string &str)
{
    const unsigned char *src = reinterpret_cast<const unsigned char *>(str.data());
    const size_t len = str.size();
    unsigned char *out, *pos;
    const unsigned char *end, *in;

    const size_t olen = 4 * ((len + 2) / 3); /* 3-byte blocks to 4-byte */

    if (olen < len)
        return std::string(); /* integer overflow */

    std::string outStr;
    outStr.resize(olen);
    out = reinterpret_cast<unsigned char *>(&outStr[0]);

    end = src + len;
    in = src;
    pos = out;
    while (end - in >= 3)
    {
        *pos++ = base64_table[in[0] >> 2];
        *pos++ = base64_table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
        *pos++ = base64_table[((in[1] & 0x0f) << 2) | (in[2] >> 6)];
        *pos++ = base64_table[in[2] & 0x3f];
        in += 3;
    }

    if (end - in)
    {
        *pos++ = base64_table[in[0] >> 2];
        if (end - in == 1)
        {
            *pos++ = base64_table[(in[0] & 0x03) << 4];
            *pos++ = '=';
        }
        else
        {
            *pos++ = base64_table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
            *pos++ = base64_table[(in[1] & 0x0f) << 2];
        }
        *pos++ = '=';
    }

    return outStr;
}

} // namespace enclave
} // namespace silentdata
