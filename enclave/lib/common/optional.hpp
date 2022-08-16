/*
 * Optional value
 */

#pragma once

namespace silentdata
{
namespace enclave
{

template <typename T> class Optional
{
public:
    // Construct without a value
    Optional();

    // Construct with a value (by calling one of T's constructors)
    template <typename... Args> Optional(Args &&... args);

    bool has_value() const;
    const T &value() const;
    T &value();

private:
    T value_;
    bool has_value_;
};

template <typename T> Optional<T>::Optional() : value_(), has_value_(false) {}

template <typename T>
template <typename... Args>
Optional<T>::Optional(Args &&... args) : value_(args...), has_value_(true)
{
}

template <typename T> bool Optional<T>::has_value() const { return has_value_; }

template <typename T> const T &Optional<T>::value() const
{
    if (!has_value_)
        throw std::logic_error(
            "Trying to access non-existent value of Optional by const reference");

    return value_;
}

template <typename T> T &Optional<T>::value()
{
    if (!has_value_)
        throw std::logic_error(
            "Trying to access non-existent value of Optional by non-const reference");

    return value_;
}

} // namespace enclave
} // namespace silentdata
