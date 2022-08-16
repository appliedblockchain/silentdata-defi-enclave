#pragma once

#include "include/core_constants.h"

namespace silentdata
{
namespace enclave
{

constexpr const std::array<uint8_t, CORE_ED25519_KEY_LEN> CROSSFLOW_WALLET_PUBLIC_KEY = {
    132, 67,  27, 217, 79, 22,  35, 169, 66,  155, 91,  191, 38,  214, 232, 193,
    145, 111, 30, 112, 11, 136, 32, 218, 118, 48,  250, 188, 160, 254, 1,   159};

} // namespace enclave
} // namespace silentdata
