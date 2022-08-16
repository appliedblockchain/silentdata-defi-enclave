/*
 * Helper functions for date and time manipulations
 */

#pragma once

#include <map>
#include <numeric>
#include <stdexcept>
#include <string>
#include <time.h>
#include <vector>

#include "lib/common/enclave_exception.hpp"
#include "lib/common/types.hpp"

namespace silentdata
{
namespace enclave
{

// Is the year a leap year
bool is_leap_year(const int year);

// Convert HTTP Date header to a struct tm
struct tm http_date_to_tm(const std::string &date_string);

// Subtract a given number of months from a struct tm date containing year, month and day
struct tm subtract_tm_months(const struct tm &date, int months);

// Add a given number of months from a struct tm date containing year, month and day
struct tm add_tm_months(const struct tm &date, int months);

// Convert a struct tm to a ISO 8601 format string "YYYY-MM-DD"
std::string tm_to_iso8601(const struct tm &date);

// Convert date string in ISO 860 format to struct tm
struct tm iso8601_to_tm(const std::string &date_str);

// Convert date string in ISO 8601 format (including time)"YYYY-MM-DDTHH:MM:SS.sss+hh:mm"
int iso8601_to_timestamp(const std::string &date_str);

// Calculate the time in seconds from Jan 01 1970 (UTC)
int tm_to_timestamp(const struct tm &date);

// Convert a timestamp in seconds from Jan 01 1970 (UTC) to a struct tm
struct tm timestamp_to_tm(const int timestamp);

// Calculate the difference between two struct tm's in days
int tm_day_difference(const struct tm &date1, const struct tm &date2);

// Calculate the difference between two struct tm's in floor(months)
int tm_month_difference(const struct tm &date1, const struct tm &date2);

// Find the first date in a list of transactions
struct tm get_earliest_date(const std::vector<BankTransaction> &transactions);

} // namespace enclave
} // namespace silentdata
