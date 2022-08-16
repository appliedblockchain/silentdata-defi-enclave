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

static const std::unordered_map<char, uint8_t> utf8_table = {
    {0x20, ' '},  {0x21, '!'}, {0x22, '"'}, {0x23, '#'}, {0x24, '$'},  {0x25, '%'}, {0x26, '&'},
    {0x27, '\''}, {0x28, '('}, {0x29, ')'}, {0x2A, '*'}, {0x2B, '+'},  {0x2C, ','}, {0x2D, '-'},
    {0x2E, '.'},  {0x2F, '/'}, {0x30, '0'}, {0x31, '1'}, {0x32, '2'},  {0x33, '3'}, {0x34, '4'},
    {0x35, '5'},  {0x36, '6'}, {0x37, '7'}, {0x38, '8'}, {0x39, '9'},  {0x3A, ':'}, {0x3B, ';'},
    {0x3C, '<'},  {0x3D, '='}, {0x3E, '>'}, {0x3F, '?'}, {0x40, '@'},  {0x41, 'A'}, {0x42, 'B'},
    {0x43, 'C'},  {0x44, 'D'}, {0x45, 'E'}, {0x46, 'F'}, {0x47, 'G'},  {0x48, 'H'}, {0x49, 'I'},
    {0x4A, 'J'},  {0x4B, 'K'}, {0x4C, 'L'}, {0x4D, 'M'}, {0x4E, 'N'},  {0x4F, 'O'}, {0x50, 'P'},
    {0x51, 'Q'},  {0x52, 'R'}, {0x53, 'S'}, {0x54, 'T'}, {0x55, 'U'},  {0x56, 'V'}, {0x57, 'W'},
    {0x58, 'X'},  {0x59, 'Y'}, {0x5A, 'Z'}, {0x5B, '['}, {0x5C, '\\'}, {0x5D, ']'}, {0x5E, '^'},
    {0x5F, '_'},  {0x60, '`'}, {0x61, 'a'}, {0x62, 'b'}, {0x63, 'c'},  {0x64, 'd'}, {0x65, 'e'},
    {0x66, 'f'},  {0x67, 'g'}, {0x68, 'h'}, {0x69, 'i'}, {0x6A, 'j'},  {0x6B, 'k'}, {0x6C, 'l'},
    {0x6D, 'm'},  {0x6E, 'n'}, {0x6F, 'o'}, {0x70, 'p'}, {0x71, 'q'},  {0x72, 'r'}, {0x73, 's'},
    {0x74, 't'},  {0x75, 'u'}, {0x76, 'v'}, {0x77, 'w'}, {0x78, 'x'},  {0x79, 'y'}, {0x7A, 'z'},
    {0x7B, '{'},  {0x7C, '|'}, {0x7D, '}'}, {0x7E, '~'}};

std::vector<uint8_t> unicode_utf8_bytes_encode(const std::string &str)
{
    std::vector<uint8_t> bytes;
    for (const auto c : str)
    {
        const auto iter = utf8_table.find(c);
        if (iter == utf8_table.end())
            THROW_EXCEPTION(kInvalidInput, "Unsupported character: '" + std::string(1, c) + "'");

        bytes.push_back(iter->second);
    }

    return bytes;
}

} // namespace enclave
} // namespace silentdata
