#include "lib/common/date_time.hpp"
#include "lib/common/optional.hpp"

#include <cmath>
#include <unordered_map>
#include <unordered_set>

namespace
{

bool check_tm_limits(const struct tm &date)
{
    if (date.tm_mon < 0 || date.tm_mon > 11)
        return false;
    if (date.tm_mday < 1 || date.tm_mday > 31)
        return false;
    if (date.tm_hour < 0 || date.tm_hour > 23)
        return false;
    if (date.tm_min < 0 || date.tm_min > 59)
        return false;
    if (date.tm_sec < 0 || date.tm_sec > 59)
        return false;
    return true;
}

std::vector<int> days_in_month = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};

} // namespace

namespace silentdata
{
namespace enclave
{

bool is_leap_year(const int year)
{
    return ((year % 4 == 0) && (year % 100 != 0)) || (year % 400 == 0);
}

struct tm http_date_to_tm(const std::string &date_string)
{
    struct tm output_date = {};

    // Tokenise the date string
    std::vector<std::string> date_tokens;
    // HTTP Date header has the format "Wed, 21 Oct 2015 07:28:00 GMT"
    size_t pos = date_string.find(" ");
    size_t init_pos = 0;
    while (pos != std::string::npos)
    {
        date_tokens.push_back(date_string.substr(init_pos, pos - init_pos));
        init_pos = pos + 1;
        pos = date_string.find(" ", init_pos);
    }
    if (date_tokens.size() != 5)
        THROW_EXCEPTION(kHTTPResponseParseError, "Incorrect number of tokens in HTTP Date header");

    // tm_year defined as years since 1900
    size_t int_size;
    try
    {
        output_date.tm_year = std::stoi(date_tokens[3], &int_size) - 1900;
    }
    catch (...)
    {
        THROW_EXCEPTION(kHTTPResponseParseError, "Could not convert year string to an integer");
    }
    if (int_size != date_tokens[3].size())
        THROW_EXCEPTION(kHTTPResponseParseError,
                        "Could not convert entire year string to an integer");

    // tm_mon defined as months since January
    const std::map<std::string, int> month_number = {{"Jan", 0},
                                                     {"Feb", 1},
                                                     {"Mar", 2},
                                                     {"Apr", 3},
                                                     {"May", 4},
                                                     {"Jun", 5},
                                                     {"Jul", 6},
                                                     {"Aug", 7},
                                                     {"Sep", 8},
                                                     {"Oct", 9},
                                                     {"Nov", 10},
                                                     {"Dec", 11}};
    if (month_number.find(date_tokens[2]) == month_number.end())
    {
        THROW_EXCEPTION(kHTTPResponseParseError, "Unexpected month string");
    }
    output_date.tm_mon = month_number.at(date_tokens[2]);

    // tm_mday defined as days of the month
    try
    {
        output_date.tm_mday = std::stoi(date_tokens[1], &int_size);
    }
    catch (...)
    {
        THROW_EXCEPTION(kHTTPResponseParseError, "Could not convert day string to an integer");
    }
    if (int_size != date_tokens[1].size())
        THROW_EXCEPTION(kHTTPResponseParseError,
                        "Could not convert entire date string to an integer");

    if (!check_tm_limits(output_date))
        THROW_EXCEPTION(kHTTPResponseParseError,
                        "Invalid struct tm date outside of limits mon(0-11), mday(1-31)");
    return output_date;
}

struct tm subtract_tm_months(const struct tm &date, int months)
{
    if (!check_tm_limits(date))
        THROW_EXCEPTION(kDateTimeError,
                        "Invalid struct tm date outside of limits mon(0-11), mday(1-31)");

    struct tm output_date = {};
    // If the number of months is greater than a year, subtract years
    int year = date.tm_year;
    while (months > 12)
    {
        months -= 12;
        year -= 1;
    }
    // If the remaining number of months is greater than the current month subtract
    // a year
    if (date.tm_mon < months)
        year -= 1;
    output_date.tm_year = year;
    // Subtract number of months using modular arithmatic (months are 0-11)
    // Extra +12)%12 to handle negative numbers
    output_date.tm_mon = ((date.tm_mon - months) % 12 + 12) % 12;
    // If the current day is greater than the number of days in the new month, correct for this
    output_date.tm_mday = std::min(date.tm_mday, days_in_month[output_date.tm_mon]);
    return output_date;
}

struct tm add_tm_months(const struct tm &date, int months)
{
    if (!check_tm_limits(date))
        THROW_EXCEPTION(kDateTimeError,
                        "Invalid struct tm date outside of limits mon(0-11), mday(1-31)");

    struct tm output_date = {};
    // If the number of months is greater than a year, add years
    int year = date.tm_year;
    while (months > 12)
    {
        months -= 12;
        year += 1;
    }
    // If the current month is greater that 11 - the months to add, add a year
    if (date.tm_mon > (11 - months))
        year += 1;
    output_date.tm_year = year;
    // Subtract number of months using modular arithmatic (months are 0-11)
    // Extra +12)%12 to handle negative numbers
    output_date.tm_mon = ((date.tm_mon + months) % 12 + 12) % 12;
    // If the current day is greater than the number of days in the new month, correct for this
    output_date.tm_mday = std::min(date.tm_mday, days_in_month[output_date.tm_mon]);
    return output_date;
}

std::string tm_to_iso8601(const struct tm &date)
{
    if (!check_tm_limits(date))
        THROW_EXCEPTION(kDateTimeError,
                        "Invalid struct tm date outside of limits mon(0-11), mday(1-31)");

    std::string day_str = std::to_string(date.tm_mday);
    if (date.tm_mday < 10)
        day_str = "0" + day_str;
    std::string month_str = std::to_string(date.tm_mon + 1);
    if ((date.tm_mon + 1) < 10)
        month_str = "0" + month_str;
    std::string output = std::to_string(date.tm_year + 1900) + "-" + month_str + "-" + day_str;
    return output;
}

struct tm iso8601_to_tm(const std::string &date_str)
{
    struct tm date = {};
    try
    {
        // tm_year is year since 1900
        date.tm_year = std::stoi(date_str.substr(0, 4)) - 1900;
        // tm_mon is month since January
        date.tm_mon = std::stoi(date_str.substr(5, 2)) - 1;
        date.tm_mday = std::stoi(date_str.substr(8, 2));
    }
    catch (...)
    {
        THROW_EXCEPTION(kJSONParseError, "Could not convert date to integer");
    }

    if (!check_tm_limits(date))
        THROW_EXCEPTION(kDateTimeError,
                        "Invalid struct tm date outside of limits mon(0-11), mday(1-31)");
    return date;
}

int iso8601_to_timestamp(const std::string &date_str)
{
    // Need at least 4 characters for the year YYYY
    if (date_str.length() < 4)
        THROW_EXCEPTION(kDateTimeError, "Input \"" + date_str + "\" is not in iso8601 format");

    const auto consume_char = [](const char c, std::string &s) -> Optional<char> {
        if (s.length() < 1)
            return Optional<char>();

        if (s.at(0) == c)
        {
            s.erase(0, 1);
            return c;
        }

        return Optional<char>();
    };

    const auto consume_digit = [](std::string &s) -> Optional<int> {
        if (s.length() < 1)
            return Optional<int>();

        try
        {
            const auto digit = std::stoi(s.substr(0, 1));
            s.erase(0, 1);
            return digit;
        }
        catch (...)
        {
            return Optional<int>();
        }
    };

    const auto consume_n_digits = [&](const size_t n, std::string &s) -> Optional<int> {
        if (n == 0)
            THROW_EXCEPTION(kInvalidInput, "Can't consume 0 digits");

        if (s.length() < n)
            return Optional<int>();

        int val = 0;
        int power = 1;
        for (size_t i = 0; i < n - 1; ++i)
            power *= 10;

        std::string consumed = "";
        while (power != 0)
        {
            const auto front_char = s.substr(0, 1);
            const auto digit_opt = consume_digit(s);
            if (!digit_opt.has_value())
            {
                // Restore the digits consumed
                s = consumed + s;
                return Optional<int>();
            }

            consumed += front_char;
            val += power * digit_opt.value();
            power /= 10;
        }

        return val;
    };

    const auto consume_n_digits_in_range =
        [&](const size_t n, const int min, const int max, std::string &s) -> Optional<int> {
        if (s.length() < n)
            return Optional<int>();

        std::string front_chars = s.substr(0, n);
        const auto digits_opt = consume_n_digits(n, s);
        if (!digits_opt.has_value())
            return Optional<int>();

        if (digits_opt.value() < min || digits_opt.value() > max)
        {
            // Restore the digits consumed
            s = front_chars + s;
            return Optional<int>();
        }

        return digits_opt.value();
    };

    const auto consume_n_digits_in_range_with_prefix = [&](const size_t n,
                                                           const int min,
                                                           const int max,
                                                           const char prefix,
                                                           std::string &s) -> Optional<int> {
        if (!consume_char(prefix, s).has_value())
            return Optional<int>();

        const auto value_opt = consume_n_digits_in_range(n, min, max, s);
        if (!value_opt.has_value())
        {
            // Restore the char consumed
            s = std::string(1, prefix) + s;
            return Optional<int>();
        }

        return value_opt.value();
    };

    int current_year = 1970;
    const auto consume_year = [&](std::string &s) -> Optional<int> {
        const auto opt = consume_n_digits(4, s);
        if (!opt.has_value())
            return Optional<int>();

        const auto year = opt.value();
        if (year < 1970)
            THROW_EXCEPTION(kDateTimeError, "Cannot convert dates before 1970 to timestamps");

        int days = 0;
        for (int y = 1970; y < year; y++)
        {
            days += is_leap_year(y) ? 366 : 365;
        }

        current_year = year;
        return days * 24 * 60 * 60;
    };

    int current_month = 0;
    const auto consume_month = [&](std::string &s) -> Optional<int> {
        const auto opt = consume_n_digits_in_range_with_prefix(2, 1, 12, '-', s);
        if (!opt.has_value())
            return Optional<int>();

        const auto month = opt.value() - 1;

        int days = std::accumulate(days_in_month.begin(), days_in_month.begin() + month, 0);
        if (month > 1 && is_leap_year(current_year))
            days += 1;

        current_month = month;
        return days * 24 * 60 * 60;
    };

    const auto consume_day = [&](std::string &s) -> Optional<int> {
        const auto max_days = days_in_month.at(current_month) +
                              ((is_leap_year(current_year) && current_month == 1) ? 1 : 0);

        const auto opt = consume_n_digits_in_range_with_prefix(2, 1, max_days, '-', s);
        if (!opt.has_value())
            return Optional<int>();

        return (opt.value() - 1) * 24 * 60 * 60;
    };

    const auto consume_hour = [&](std::string &s) -> Optional<int> {
        const auto opt = consume_n_digits_in_range_with_prefix(2, 0, 23, 'T', s);
        if (!opt.has_value())
            return Optional<int>();

        return opt.value() * 60 * 60;
    };

    const auto consume_min = [&](std::string &s) -> Optional<int> {
        const auto opt = consume_n_digits_in_range_with_prefix(2, 0, 59, ':', s);

        if (!opt.has_value())
            return Optional<int>();

        return opt.value() * 60;
    };

    const auto consume_sec = [&](std::string &s) -> Optional<int> {
        const auto opt = consume_n_digits_in_range_with_prefix(2, 0, 59, ':', s);

        if (!opt.has_value())
            return Optional<int>();

        return opt.value();
    };

    // The sec fraction is any number of digits e.g: 123 -> 0.123 seconds -> 0 second (rounded)
    const auto consume_sec_fraction = [&](std::string &s) -> Optional<int> {
        // The first digit is prefixed by '.'
        const auto first_digit_opt = consume_n_digits_in_range_with_prefix(1, 0, 9, '.', s);
        if (!first_digit_opt.has_value())
            return Optional<int>();

        const auto return_value = (first_digit_opt.value() >= 5 ? 1 : 0);

        // All remaining digits have no prefix
        while (true)
        {
            const auto digit_opt = consume_digit(s);
            if (!digit_opt.has_value())
                break;
        }

        return return_value;
    };

    const auto consume_utc = [&](std::string &s) -> Optional<int> {
        const auto opt = consume_char('Z', s);

        if (!opt.has_value())
            return Optional<int>();

        return 0;
    };

    // ATTN a timezone starting with '+' is ahead of UTC and '-' is behind
    // E.g. YYYY-MM-DDT09:00+01:00 (9am in timezone 1hr ahead of UTC) == YYYY-MM-DDT08:00Z (8am in
    // UTC)

    bool is_timezone_ahead = false;
    const auto consume_timezone_ahead_hour = [&](std::string &s) -> Optional<int> {
        const auto opt = consume_n_digits_in_range_with_prefix(2, 0, 23, '+', s);

        if (!opt.has_value())
            return Optional<int>();

        is_timezone_ahead = true;
        return -opt.value() * 60 * 60;
    };

    const auto consume_timezone_behind_hour = [&](std::string &s) -> Optional<int> {
        const auto opt = consume_n_digits_in_range_with_prefix(2, 0, 23, '-', s);

        if (!opt.has_value())
            return Optional<int>();

        is_timezone_ahead = false;
        return +opt.value() * 60 * 60;
    };

    const auto consume_timezone_min = [&](std::string &s) -> Optional<int> {
        const auto opt = consume_n_digits_in_range_with_prefix(2, 0, 59, ':', s);

        if (!opt.has_value())
            return Optional<int>();

        return (is_timezone_ahead ? -1 : 1) * opt.value() * 60;
    };

    // Setup the syntax as a mapping from the last item consumed to the next allowed items
    const std::unordered_map<std::string, std::vector<std::string>> syntax = {
        {"", {"year"}},
        {"year", {"month", "end"}},
        {"month", {"day", "end"}},
        {"day", {"hour", "end"}},
        {"hour", {"min", "utc", "timezone_ahead_hour", "timezone_behind_hour", "end"}},
        {"min", {"sec", "utc", "timezone_ahead_hour", "timezone_behind_hour", "end"}},
        {"sec", {"sec_fraction", "utc", "timezone_ahead_hour", "timezone_behind_hour", "end"}},
        {"sec_fraction", {"utc", "timezone_ahead_hour", "timezone_behind_hour", "end"}},
        {"utc", {"end"}},
        {"timezone_ahead_hour", {"timezone_min", "end"}},
        {"timezone_behind_hour", {"timezone_min", "end"}},
        {"timezone_min", {"end"}},
    };

    const std::unordered_map<std::string, std::function<Optional<int>(std::string &)>> logic = {
        {"year", consume_year},
        {"month", consume_month},
        {"day", consume_day},
        {"hour", consume_hour},
        {"min", consume_min},
        {"sec", consume_sec},
        {"sec_fraction", consume_sec_fraction},
        {"utc", consume_utc},
        {"timezone_ahead_hour", consume_timezone_ahead_hour},
        {"timezone_behind_hour", consume_timezone_behind_hour},
        {"timezone_min", consume_timezone_min},
    };

    // Parse the string
    int timestamp = 0;
    std::string remaining_str = date_str;
    std::string current_step = "";
    while (!remaining_str.empty())
    {
        bool success = false;
        for (const auto &next_step : syntax.at(current_step))
        {
            if (next_step == "end")
            {
                if (!remaining_str.empty())
                    THROW_EXCEPTION(kDateTimeError,
                                    "Unexpected characters at end of input string \"" + date_str +
                                        "\"");

                success = true;
                current_step = next_step;
                break;
            }

            const auto seconds_opt = logic.at(next_step)(remaining_str);
            if (!seconds_opt.has_value())
                continue;

            timestamp += seconds_opt.value();
            success = true;
            current_step = next_step;
            break;
        }

        if (!success)
            THROW_EXCEPTION(kDateTimeError, "Input \"" + date_str + "\" is not in iso8601 format");
    }

    return timestamp;
}

int tm_to_timestamp(const struct tm &date)
{
    // Some input checking
    if (date.tm_year < 70)
        THROW_EXCEPTION(kDateTimeError, "Cannot convert dates before 1970 to timestamps");
    if (date.tm_year >= 138 && (date.tm_mon >= 1 || date.tm_mday > 19))
        THROW_EXCEPTION(kDateTimeError, "Cannot convert dates after 2038 to int32 timestamps");
    if (!check_tm_limits(date))
        THROW_EXCEPTION(kDateTimeError,
                        "Invalid struct tm date outside of limits mon(0-11), mday(1-31)");

    const int tm_year = date.tm_year + 1900;
    int days = 0;
    for (int year = 1970; year < tm_year; year++)
    {
        if (((year % 4 == 0) && (year % 100 != 0)) || (year % 400 == 0))
            days += 366;
        else
            days += 365;
    }
    // Calculate the number of days from Jan 01 to the current day,
    // correcting for leap years
    days += std::accumulate(days_in_month.begin(), days_in_month.begin() + date.tm_mon, 0);
    if (date.tm_mon > 1 && (((tm_year % 4 == 0) && (tm_year % 100 != 0)) || (tm_year % 400 == 0)))
        days += 1;
    days += date.tm_mday - 1;
    // Calculate the number of seconds since Jan 01 1970
    int timestamp = days * 60 * 60 * 24;
    timestamp += date.tm_hour * 60 * 60;
    timestamp += date.tm_min * 60;
    timestamp += date.tm_sec;
    return timestamp;
}

struct tm timestamp_to_tm(const int timestamp)
{
    if (timestamp < 0)
        THROW_EXCEPTION(kDateTimeError, "The input timestamp is negative");

    struct tm date;
    const int seconds_in_day = 24 * 60 * 60;
    int remaining_seconds = timestamp;

    // Determine the year
    int year = 1970;
    while (true)
    {
        const auto days_in_year = is_leap_year(year) ? 366 : 365;
        const auto seconds_in_year = days_in_year * seconds_in_day;
        if (seconds_in_year > remaining_seconds)
            break;

        remaining_seconds -= seconds_in_year;
        year++;
    }
    date.tm_year = year - 1900; // Years since 1900

    // Determine the month
    int month = 0;
    for (const int days : days_in_month)
    {
        const auto leap_days = (month == 1 && is_leap_year(year)) ? 1 : 0;
        const auto seconds_in_month = (days + leap_days) * seconds_in_day;
        if (seconds_in_month > remaining_seconds)
            break;

        remaining_seconds -= seconds_in_month;
        month++;
    }
    date.tm_mon = month; // Months since January

    // Determine the day
    date.tm_mday = 1 + (remaining_seconds / seconds_in_day); // Day of the month
    if (date.tm_mday > 31)
        THROW_EXCEPTION(kDateTimeError, "Logical error - determined more than 31 days in a month!");

    remaining_seconds -= (date.tm_mday - 1) * seconds_in_day;

    // Determine the hour
    const auto seconds_in_hour = 60 * 60;
    date.tm_hour = remaining_seconds / seconds_in_hour;
    if (date.tm_hour > 23)
        THROW_EXCEPTION(kDateTimeError, "Logical error - determined more than 24 hours in a day!");

    remaining_seconds -= date.tm_hour * seconds_in_hour;

    // Determine the minute
    const auto seconds_in_minute = 60;
    date.tm_min = remaining_seconds / seconds_in_minute;
    if (date.tm_min > 59)
        THROW_EXCEPTION(kDateTimeError,
                        "Logical error - determined more than 60 minutes in an hour!");

    remaining_seconds -= date.tm_min * seconds_in_minute;

    // Determine the seconds
    date.tm_sec = remaining_seconds;
    if (date.tm_sec > 59)
        THROW_EXCEPTION(kDateTimeError,
                        "Logical error - determined more than 60 seconds in a minute!");

    return date;
}

int tm_day_difference(const struct tm &date1, const struct tm &date2)
{
    const int timestamp1 = tm_to_timestamp(date1);
    const int timestamp2 = tm_to_timestamp(date2);
    const int difference_sec = std::abs(timestamp1 - timestamp2);
    const int difference_day = difference_sec / (60 * 60 * 24);
    return difference_day;
}

int tm_month_difference(const struct tm &date1, const struct tm &date2)
{
    return (date2.tm_year - date1.tm_year) * 12 + date2.tm_mon - date1.tm_mon;
}

struct tm get_earliest_date(const std::vector<BankTransaction> &transactions)
{
    if (transactions.size() < 1)
        THROW_EXCEPTION(kJSONParseError, "No transactions available");
    struct tm first_date = transactions[0].date;
    for (const auto &transaction : transactions)
    {
        const struct tm &date = transaction.date;
        if (date.tm_year < first_date.tm_year)
        {
            first_date = date;
        }
        else if (date.tm_year == first_date.tm_year)
        {
            if (date.tm_mon < first_date.tm_mon)
            {
                first_date = date;
            }
            else if (date.tm_mon == first_date.tm_mon && date.tm_mday < first_date.tm_mday)
            {
                first_date = date;
            }
        }
    }
    return first_date;
}

} // namespace enclave
} // namespace silentdata
