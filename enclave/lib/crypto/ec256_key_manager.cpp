#include "ec256_key_manager.hpp"

#include "lib/common/enclave_exception.hpp"

namespace silentdata
{
namespace enclave
{

bool EC256KeyManager::has_key_pair(const std::string &public_key) const
{
    if (keys_.find(public_key) == keys_.end())
        return false;
    return true;
}

bool EC256KeyManager::has_key_pair(const std::array<uint8_t, CORE_ECC_KEY_LEN> &public_key) const
{
    std::string public_key_str(std::begin(public_key), std::end(public_key));
    return has_key_pair(public_key_str);
}

const EC256KeyPair &EC256KeyManager::get_key_pair(const std::string &public_key) const
{
    if (!has_key_pair(public_key))
        THROW_EXCEPTION(kInvalidInput, "Cannot find corresponding encryption private key");
    return keys_.at(public_key);
}

const EC256KeyPair &
EC256KeyManager::get_key_pair(const std::array<uint8_t, CORE_ECC_KEY_LEN> &public_key) const
{
    std::string public_key_str(std::begin(public_key), std::end(public_key));
    return get_key_pair(public_key_str);
}

const EC256KeyPair &EC256KeyManager::generate_key()
{
    EC256KeyPair new_key;
    // Convert public key to string
    const std::array<uint8_t, CORE_ECC_KEY_LEN> public_key = new_key.public_key_bytes();
    std::string public_key_str(std::begin(public_key), std::end(public_key));
    // Check map size and remove oldest entry if size is max
    if (keys_.size() >= max_size_)
        keys_.erase(keys_.begin());
    // Add new key to map
    keys_[public_key_str] = new_key;
    return keys_.at(public_key_str);
}

void EC256KeyManager::remove_key_pair(const std::string &public_key)
{
    if (!has_key_pair(public_key))
        THROW_EXCEPTION(kInvalidInput, "Cannot find corresponding encryption private key");
    keys_.erase(public_key);
}

void EC256KeyManager::remove_key_pair(const std::array<uint8_t, CORE_ECC_KEY_LEN> &public_key)
{
    std::string public_key_str(std::begin(public_key), std::end(public_key));
    return remove_key_pair(public_key_str);
}

} // namespace enclave
} // namespace silentdata
