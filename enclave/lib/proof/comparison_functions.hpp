/*
 * Functions for comparing outputs of Plaid calls to attestation inputs
 */

#pragma once

#include <time.h>

#include "lib/common/date_time.hpp"
#include "lib/common/enclave_logger.hpp"
#include "lib/common/types.hpp"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wconversion"
#pragma GCC diagnostic ignored "-Wshadow"
#pragma GCC diagnostic ignored "-Wredundant-decls"
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wshadow"
#include "proto/messages.pb.h"
#pragma GCC diagnostic pop

namespace silentdata
{
namespace enclave
{

// Check if balance is above a given amount
bool check_minimum_balance(const BankBalance &balance,
                           const std::string &currency_code,
                           uint32_t minimum_balance);

// Check income is above a given amount each month between two dates
bool check_consistent_income(const std::vector<BankTransaction> &transactions,
                             const struct tm &start_date,
                             const struct tm &end_date,
                             const std::string &currency_code,
                             uint32_t consistent_income);

// Check stable income (same date, same name) is above a given amount each month between two dates
bool check_stable_income(const std::vector<BankTransaction> &transactions,
                         const struct tm &start_date,
                         const struct tm &end_date,
                         const std::string &currency_code,
                         const int tolerance_days,
                         const uint32_t consistent_income);

std::string find_account(const std::map<std::string, AccountNumbers> &account_details,
                         const AccountNumbers &account_numbers);

bool check_minimum_age(const int now_timestamp,
                       const int date_of_birth_timestamp,
                       const int min_years);

} // namespace enclave
} // namespace silentdata
