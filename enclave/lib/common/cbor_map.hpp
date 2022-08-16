/*
 * CBOR map
 */

#pragma once

#include <array>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "include/core_constants.h"
#include "include/core_status_codes.h"

#include "lib/cbor/cbor.h"
#include "lib/common/enclave_exception.hpp"
#include "lib/common/enclave_logger.hpp"

namespace silentdata
{
namespace enclave
{

enum CBORType
{
    kCBORUInt,
    kCBORInt,
    kCBORTextString,
    kCBORByteString
};

class CBORMapValue
{
public:
    template <typename T> CBORMapValue(const T value);

    CBORMapValue(const std::vector<uint8_t> &value);

    template <std::size_t N> CBORMapValue(const std::array<uint8_t, N> &value);

    CBORMapValue(const char *value);
    CBORMapValue(const std::string &value);

    CBORType get_type() const;

    uint64_t get_uint_value() const;
    int64_t get_int_value() const;
    const std::vector<uint8_t> &get_byte_string_value() const;
    const std::string &get_text_string_value() const;

private:
    CBORType type_;

    uint64_t uint_value_;
    int64_t int_value_;
    std::vector<uint8_t> byte_value_;
    std::string text_value_;
};

class CBORMap
{
public:
    CBORMap() {}
    CBORMap(const std::vector<uint8_t> &cbor, const std::vector<std::string> &keys);

    template <typename T> void insert(const std::string &key, const T &value);

    bool has(const std::string &key) const;
    const CBORMapValue &get(const std::string &key) const;
    std::vector<std::string> get_keys() const;

    std::vector<uint8_t> encode_cbor(int max_size = 0) const;

private:
    std::unordered_map<std::string, CBORMapValue> map_;
};

// ----

template <typename T>
CBORMapValue::CBORMapValue(const T value)
    : type_(std::numeric_limits<T>::lowest() == 0 ? kCBORUInt : kCBORInt),
      uint_value_(std::numeric_limits<uint64_t>::max()),
      int_value_(std::numeric_limits<int64_t>::max())
{
    switch (type_)
    {
    case kCBORUInt:
        uint_value_ = value;
        break;
    case kCBORInt:
        int_value_ = value;
        break;
    default:
        THROW_EXCEPTION(kInvalidInput, "Unexpected CBOR value type");
    }
}

template <std::size_t N>
CBORMapValue::CBORMapValue(const std::array<uint8_t, N> &value)
    : type_(kCBORByteString), uint_value_(std::numeric_limits<uint64_t>::max()),
      int_value_(std::numeric_limits<int64_t>::max()), byte_value_(value.begin(), value.end())
{
}

template <typename T> void CBORMap::insert(const std::string &key, const T &value)
{
    if (!map_.emplace(key, CBORMapValue(value)).second)
        THROW_EXCEPTION(kInvalidInput, "Failed to insert key \"" + key + "\" into CBOR map");
}

} // namespace enclave
} // namespace silentdata
