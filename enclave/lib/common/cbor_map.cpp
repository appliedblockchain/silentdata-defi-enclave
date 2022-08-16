#include "lib/common/cbor_map.hpp"

namespace silentdata
{
namespace enclave
{

CBORMapValue::CBORMapValue(const std::vector<uint8_t> &value)
    : type_(kCBORByteString), uint_value_(std::numeric_limits<uint64_t>::max()),
      int_value_(std::numeric_limits<int64_t>::max()), byte_value_(value)
{
}

CBORMapValue::CBORMapValue(const char *value)
    : type_(kCBORTextString), uint_value_(std::numeric_limits<uint64_t>::max()),
      int_value_(std::numeric_limits<int64_t>::max()), text_value_(value)
{
}

CBORMapValue::CBORMapValue(const std::string &value)
    : type_(kCBORTextString), uint_value_(std::numeric_limits<uint64_t>::max()),
      int_value_(std::numeric_limits<int64_t>::max()), text_value_(value)
{
}

CBORType CBORMapValue::get_type() const { return type_; }

uint64_t CBORMapValue::get_uint_value() const
{
    if (type_ != kCBORUInt)
        THROW_EXCEPTION(kInvalidInput, "Can't get CBOR map element as type isn't uint");

    return uint_value_;
}

int64_t CBORMapValue::get_int_value() const
{
    if (type_ != kCBORInt)
        THROW_EXCEPTION(kInvalidInput, "Can't get CBOR map element as type isn't int");

    return int_value_;
}

const std::vector<uint8_t> &CBORMapValue::get_byte_string_value() const
{
    if (type_ != kCBORByteString)
        THROW_EXCEPTION(kInvalidInput, "Can't get CBOR map element as type isn't byte string");

    return byte_value_;
}

const std::string &CBORMapValue::get_text_string_value() const
{
    if (type_ != kCBORTextString)
        THROW_EXCEPTION(kInvalidInput, "Can't get CBOR map element as type isn't text string");

    return text_value_;
}

// ----

CBORMap::CBORMap(const std::vector<uint8_t> &cbor, const std::vector<std::string> &keys)
{
    CborParser parser;
    CborValue map;
    if (cbor_parser_init(cbor.data(), cbor.size(), 0, &parser, &map) != CborNoError)
        THROW_EXCEPTION(kInvalidInput, "Error initializing CBOR parser");

    if (!cbor_value_is_map(&map))
        THROW_EXCEPTION(kInvalidInput, "Input CBOR is not a map");

    for (const std::string &key : keys)
    {
        CborValue cbor_value;
        if (cbor_value_map_find_value(&map, key.c_str(), &cbor_value) != CborNoError)
            THROW_EXCEPTION(kInvalidInput, "Error extracting key \"" + key + "\"");

        if (cbor_value_get_type(&cbor_value) == CborInvalidType)
            THROW_EXCEPTION(kInvalidInput, "Key \"" + key + "\" not found in map");

        if (cbor_value_is_tag(&cbor_value))
        {
            if (cbor_value_skip_tag(&cbor_value) != CborNoError)
                THROW_EXCEPTION(kInvalidInput, "Error skipping tag");
        }

        if (cbor_value_is_unsigned_integer(&cbor_value))
        {
            uint64_t value;
            if (cbor_value_get_uint64(&cbor_value, &value) != CborNoError)
                THROW_EXCEPTION(kInvalidInput,
                                "Error extracting unsigned int value for key \"" + key + "\"");

            this->insert(key, value);
            continue;
        }

        if (cbor_value_is_negative_integer(&cbor_value) || cbor_value_is_integer(&cbor_value))
        {
            int64_t value;
            if (cbor_value_get_int64(&cbor_value, &value) != CborNoError)
                THROW_EXCEPTION(kInvalidInput,
                                "Error extracting int value for key \"" + key + "\"");

            this->insert(key, value);
            continue;
        }

        const bool is_byte_string = cbor_value_is_byte_string(&cbor_value);
        const bool is_text_string = cbor_value_is_text_string(&cbor_value);
        if (is_byte_string || is_text_string)
        {
            size_t length;
            if (cbor_value_calculate_string_length(&cbor_value, &length) != CborNoError)
                THROW_EXCEPTION(kInvalidInput,
                                "Error extracting length of string for key \"" + key + "\"");

            if (is_byte_string)
            {
                std::vector<uint8_t> bytes;
                bytes.resize(length, 0);

                CborValue next;
                size_t buflen = length;
                if (cbor_value_copy_byte_string(&cbor_value, bytes.data(), &buflen, &next) !=
                    CborNoError)
                    THROW_EXCEPTION(kInvalidInput,
                                    "Error extracting byte string value for key \"" + key + "\"");

                this->insert(key, bytes);
                continue;
            }

            std::vector<char> text;
            text.resize(length, 0);

            CborValue next;
            size_t buflen = length;
            if (cbor_value_copy_text_string(&cbor_value, text.data(), &buflen, &next) !=
                CborNoError)
                THROW_EXCEPTION(kInvalidInput,
                                "Error extracting text string value for key \"" + key + "\"");

            this->insert(key, std::string(text.begin(), text.end()));
            continue;
        }

        THROW_EXCEPTION(kInvalidInput, "Type found for key \"" + key + "\" not handled");
    }
}

bool CBORMap::has(const std::string &key) const { return map_.count(key) == 1; }

const CBORMapValue &CBORMap::get(const std::string &key) const
{
    if (!this->has(key))
        THROW_EXCEPTION(kInvalidInput, "Key \"" + key + "\" not found");

    return map_.at(key);
}

std::vector<std::string> CBORMap::get_keys() const
{
    std::vector<std::string> keys;
    std::transform(map_.begin(),
                   map_.end(),
                   std::back_inserter(keys),
                   [](const std::pair<std::string, CBORMapValue> &entry) { return entry.first; });
    std::sort(keys.begin(), keys.end());

    return keys;
}

std::vector<uint8_t> CBORMap::encode_cbor(int max_size) const
{
    const std::vector<std::string> keys = this->get_keys();

    if (max_size == 0)
        max_size = CORE_MAX_PROOF_LEN;
    std::vector<uint8_t> encoded_data(max_size, 0);
    CborEncoder encoder, map_encoder;
    cbor_encoder_init(&encoder, encoded_data.data(), encoded_data.size(), 0);
    cbor_encoder_create_map(&encoder, &map_encoder, keys.size());

    for (const auto &key : keys)
    {
        const auto &cbor_value = this->get(key);

        cbor_encode_text_stringz(&map_encoder, key.c_str());
        switch (cbor_value.get_type())
        {
        case kCBORUInt:
            cbor_encode_uint(&map_encoder, cbor_value.get_uint_value());
            break;
        case kCBORInt:
            cbor_encode_int(&map_encoder, cbor_value.get_int_value());
            break;
        case kCBORTextString:
            cbor_encode_text_stringz(&map_encoder, cbor_value.get_text_string_value().c_str());
            break;
        case kCBORByteString:
        {
            const auto &bytes = cbor_value.get_byte_string_value();
            cbor_encode_byte_string(&map_encoder, bytes.data(), bytes.size());
            break;
        }
        default:
            THROW_EXCEPTION(kInvalidInput, "Incompatible CBOR type");
        }
    }

    cbor_encoder_close_container(&encoder, &map_encoder);

    const size_t overrun = cbor_encoder_get_extra_bytes_needed(&encoder);
    if (overrun != 0)
        THROW_ERROR_CODE(kSigningDataFieldTooLong);

    const size_t buffer_size = cbor_encoder_get_buffer_size(&encoder, encoded_data.data());
    encoded_data.resize(buffer_size);

    return encoded_data;
}

} // namespace enclave
} // namespace silentdata
