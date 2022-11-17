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

#include "include/ias_root_ca_cert.hpp"

#include "lib/common/decoders.hpp"

#include "lib/ias/report.hpp"

namespace silentdata
{
namespace enclave
{

bool verify_signature(const std::string &cert_chain_string,
                      const std::string &content,
                      const std::array<uint8_t, CORE_IAS_SIG_LEN> &signature);

bool verify_quote(const std::string &peer_ias_report_body,
                  const std::array<uint8_t, CORE_ECC_KEY_LEN> &peer_provision_public_key,
                  const std::array<uint8_t, CORE_ED25519_KEY_LEN> &peer_ed25519_signing_public_key,
                  const sgx_report_t &verifier_report);

} // namespace enclave
} // namespace silentdata
