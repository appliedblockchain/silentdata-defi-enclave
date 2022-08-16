#pragma once

#include <array>
#include <string>
#include <vector>

#include "mbedtls/certs.h"
#include "mbedtls/error.h"
#include "mbedtls/md.h"
#include "mbedtls/md_internal.h"
#include "mbedtls/pem.h"
#include "mbedtls/x509.h"

#include "sgx_quote.h"
#include "sgx_tcrypto.h"
#include "sgx_utils.h"

#include "include/core_constants.h"
#include "include/ias_root_ca_cert.hpp"

#include "lib/common/decoders.hpp"
#include "lib/common/enclave_exception.hpp"
#include "lib/common/enclave_logger.hpp"
#include "lib/common/json.hpp"
#include "lib/common/sgx_error_message.hpp"

#include "lib/crypto/ec256_key_pair.hpp"
#include "lib/crypto/ed25519_key_pair.hpp"

namespace silentdata
{
namespace enclave
{

std::array<uint8_t, CORE_SHA_256_LEN>
get_public_keys_hash(const std::array<uint8_t, CORE_ECC_KEY_LEN> &encryption_public_key,
                     const std::array<uint8_t, CORE_ED25519_KEY_LEN> &ed25519_signing_public_key);

sgx_report_t
get_report(const sgx_target_info_t &quoting_enclave_target_info,
           const std::array<uint8_t, CORE_ECC_KEY_LEN> &encryption_public_key,
           const std::array<uint8_t, CORE_ED25519_KEY_LEN> &ed25519_signing_public_key);

} // namespace enclave
} // namespace silentdata
