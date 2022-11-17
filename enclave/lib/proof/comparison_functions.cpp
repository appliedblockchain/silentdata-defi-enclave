#include "lib/proof/comparison_functions.hpp"

namespace
{

using namespace silentdata::enclave;

// Check monthly income against a total over a range of months, index of income should be the number
// of months from the first checked month
bool check_income(const std::map<int, double> &income, uint32_t consistent_income, int num_months)
{
    // Do the attestation
    int months_checked = 0;
    for (const auto &kv : income)
    {
        DEBUG_LOG("Comparing month %i", kv.first);
        if (kv.first == num_months)
        {
            DEBUG_LOG("Skip current month");
            continue;
        }
        if (kv.second < static_cast<double>(consistent_income))
        {
            DEBUG_LOG("Monthly income < %f", static_cast<double>(consistent_income));
            return false;
        }
        DEBUG_LOG("Monthly income >= %f", static_cast<double>(consistent_income));
        months_checked++;
    }
    DEBUG_LOG("Number of months checked = %i", months_checked);
    if (months_checked != num_months)
        return false;

    return true;
}
} // namespace

namespace silentdata
{
namespace enclave
{

bool check_minimum_balance(const BankBalance &balance,
                           const std::string &currency_code,
                           uint32_t minimum_balance)
{
    if (balance.currency_code != currency_code)
    {
        WARNING_LOG("Balance in unexpected currency code: %s", balance.currency_code.c_str());
        return false;
    }
    if (balance.available < static_cast<double>(minimum_balance))
    {
        WARNING_LOG("Minimum account balance requirements not met");
        return false;
    }
    return true;
}

bool check_consistent_income(const std::vector<BankTransaction> &transactions,
                             const struct tm &start_date,
                             const struct tm &end_date,
                             const std::string &currency_code,
                             uint32_t consistent_income)
{
    const int num_months = tm_month_difference(start_date, end_date);
    DEBUG_LOG("Start date = %s", tm_to_iso8601(start_date).c_str());
    DEBUG_LOG("End date = %s", tm_to_iso8601(end_date).c_str());
    DEBUG_LOG("Month range = %i", num_months);

    const auto min_timestamp = tm_to_timestamp(start_date);
    const auto max_timestamp = tm_to_timestamp(end_date);

    std::map<int, double> income;
    // Initialise in case there are no transactions in a month
    for (int i = 0; i < num_months; i++)
        income[i] = 0;

    for (const auto &transaction : transactions)
    {
        // Ignore outgoing (negative) transactions for now
        if (transaction.amount < 0)
            continue;
        // Ignore any transactions in a different currency
        if (transaction.currency_code != currency_code)
        {
            WARNING_LOG("Unexpected transaction currency code: %s",
                        transaction.currency_code.c_str());
            continue;
        }

        // Only count transactions in the specified range
        const auto timestamp = tm_to_timestamp(transaction.date);
        if (timestamp < min_timestamp)
            continue;

        if (timestamp > max_timestamp)
            continue;

        const int index = tm_month_difference(start_date, transaction.date);
        // Ignore anything outside of the date range we're considering
        if (income.find(index) == income.end())
            continue;

        income[index] += transaction.amount;
    }

    return check_income(income, consistent_income, num_months);
}

// Gets the month offsets that are consecutive around zero
std::vector<int> get_consecutive_month_offsets(
    const std::unordered_map<int, std::vector<size_t>> &related_transactions)
{
    // Require a month offet of zero
    std::vector<int> consecutive_month_offsets;
    const auto iter_zero = related_transactions.find(0);
    if (iter_zero == related_transactions.end() || iter_zero->second.empty())
        THROW_EXCEPTION(kInvalidInput, "Supplied month offsets don't include zero");

    consecutive_month_offsets.push_back(0);

    // Collect the consecutive month offsets above & below zero
    for (const int d_offset : std::vector<int>({1, -1}))
    {
        int offset = 0;
        while (true)
        {
            offset += d_offset;

            const auto iter = related_transactions.find(offset);
            if (iter == related_transactions.end() || iter->second.empty())
                break;

            consecutive_month_offsets.push_back(offset);
        }
    }

    std::sort(consecutive_month_offsets.begin(), consecutive_month_offsets.end());
    return consecutive_month_offsets;
}

// Gets the transactions that occured within or around the same day of the month as the seed
// transaction (to within the tolerance). Only the transactions with the input `ids` are considered
//
// Organises these related transactions by the "month offset" from the seed transaction
std::unordered_map<int, std::vector<size_t>>
get_related_transactions(const std::vector<BankTransaction> &transactions,
                         const std::vector<size_t> &ids,
                         const size_t seed_id,
                         const int tolerance_days)
{
    const auto &seed_transaction = transactions.at(seed_id);

    // Mapping from month offset, to the related transactions IDs
    std::unordered_map<int, std::vector<size_t>> related_transactions;
    for (const auto id : ids)
    {
        const auto &transaction = transactions.at(id);

        // Require that the transaction has the same name & currency code as the seed transaction
        if (transaction.currency_code != seed_transaction.currency_code)
            THROW_EXCEPTION(kInvalidInput, "All transactions should have the same currency_code");

        if (transaction.name != transaction.name)
            THROW_EXCEPTION(kInvalidInput, "All transactions should have the same name")

        // Check if the transaction occured at or around the same day of the month as the seed
        // transaction ATTN. also check the months surrounding the month in which the transaction
        // occured to allow for the case where the range of dates within the tolerance of +-3 days
        // spans the boundary between two months
        const int months_diff = tm_month_difference(seed_transaction.date, transaction.date);
        for (int d_month = months_diff - 1; d_month <= months_diff + 1; ++d_month)
        {
            auto central_date = seed_transaction.date;
            if (d_month < 0)
                central_date = subtract_tm_months(central_date, -d_month);
            else if (d_month > 0)
                central_date = add_tm_months(central_date, d_month);

            const auto day_diff = std::abs(tm_day_difference(central_date, transaction.date));
            if (day_diff > tolerance_days)
                continue;

            related_transactions[d_month].push_back(id);
            break;
        }
    }

    return related_transactions;
}

// Gets the minimum total value of all transactions in a month, over a period of a specified number
// of consecutive months
double get_stable_value(const std::vector<BankTransaction> &transactions,
                        const std::unordered_map<int, std::vector<size_t>> &related_transactions,
                        const size_t num_months)
{
    if (num_months == 0)
        THROW_EXCEPTION(kInvalidInput, "The expected number of months can't be zero");

    const auto consecutive_month_offsets = get_consecutive_month_offsets(related_transactions);

    // To be stable, the income source has to occur over at least the desired number of consecutive
    // months
    if (consecutive_month_offsets.size() < num_months)
        return 0.;

    // Otherwise the stable value is the minimum total in any given month
    double stable_value = std::numeric_limits<double>::max();
    for (const auto month_offset : consecutive_month_offsets)
    {
        double value = 0.;
        for (const auto id : related_transactions.at(month_offset))
        {
            const auto transaction = transactions.at(id);
            value += transaction.amount;
        }

        stable_value = std::min(stable_value, value);
    }

    return stable_value;
}

// Extracts the transaction IDs from the supplied collection of transactions, ordered by month
// offset
std::unordered_set<size_t>
get_transaction_ids(const std::unordered_map<int, std::vector<size_t>> &related_transactions)
{
    std::unordered_set<size_t> used_transaction_ids;
    for (const auto &entry : related_transactions)
    {
        for (const auto id : entry.second)
            used_transaction_ids.insert(id);
    }

    return used_transaction_ids;
}

// Recursively gets the stable value of a given set of transactions, using the specified seed
// transaction
double get_stable_value(const std::vector<BankTransaction> &transactions,
                        const std::vector<size_t> &ids,
                        const size_t seed_id,
                        const int tolerance_days,
                        const size_t num_months)
{
    // Get the stable value of the transactions relating to this seed
    const auto related_transactions =
        get_related_transactions(transactions, ids, seed_id, tolerance_days);
    const auto stable_value = get_stable_value(transactions, related_transactions, num_months);

    if (stable_value <= std::numeric_limits<double>::epsilon())
        return 0.;

    // Remove the used transactions from the list of ids
    const auto used_ids = get_transaction_ids(related_transactions);
    std::vector<size_t> unused_ids;
    for (const auto id : ids)
    {
        if (used_ids.count(id) == 0)
            unused_ids.push_back(id);
    }

    // Find the maximal stable value of the remaining transactions when treating each unused ID as
    // the seed
    double max_remaining_stable_value = 0.;
    for (const auto new_seed_id : unused_ids)
    {
        const auto remaining_stable_value =
            get_stable_value(transactions, unused_ids, new_seed_id, tolerance_days, num_months);
        max_remaining_stable_value = std::max(max_remaining_stable_value, remaining_stable_value);
    }

    return stable_value + max_remaining_stable_value;
}

struct NameSortedTransactions
{
    std::vector<std::string> names;
    std::unordered_map<std::string, std::vector<size_t>> name_to_transaction_ids;
};

// Filters the input transactions and only keeps those that:
// - are incoming
// - have the desired currency_code
// - are within the start_date-tolerance -> end_date+tolerance range
//
// Organises the filted transactions by their name
NameSortedTransactions prepare_transactions(const std::vector<BankTransaction> &transactions,
                                            const struct tm &start_date,
                                            const struct tm &end_date,
                                            const int tolerance_days,
                                            const std::string &currency_code)
{
    NameSortedTransactions result;
    auto &names = result.names;
    auto &name_to_transaction_ids = result.name_to_transaction_ids;

    const int num_months = tm_month_difference(start_date, end_date);

    const int tolerance_sec = tolerance_days * 24 * 60 * 60;
    const auto start_timestamp = tm_to_timestamp(start_date) - tolerance_sec;
    const auto end_timestamp = tm_to_timestamp(end_date) + tolerance_sec;

    std::unordered_map<std::string, double> name_to_total_value;
    for (size_t i = 0; i < transactions.size(); ++i)
    {
        const auto transaction = transactions.at(i);

        // Ignore outgoing (negative) transactions for now
        if (transaction.amount < 0)
            continue;

        // Ignore any transactions in a different currency
        if (transaction.currency_code != currency_code)
        {
            WARNING_LOG("Unexpected transaction currency code: %s",
                        transaction.currency_code.c_str());
            continue;
        }

        // Only allow transactions within the specified range
        const auto timestamp = tm_to_timestamp(transaction.date);
        if (timestamp < start_timestamp)
            continue;

        if (timestamp > end_timestamp)
            continue;

        // Select this transaction
        name_to_transaction_ids[transaction.name].push_back(i);

        // Keep track of the total value for each name, used for sorting
        if (name_to_total_value.find(transaction.name) == name_to_total_value.end())
            name_to_total_value.emplace(transaction.name, 0.);

        name_to_total_value.at(transaction.name) += transaction.amount;
    }

    // Require at least num_months of transactions to have one per month
    std::vector<std::string> unused_names;
    for (const auto &entry : name_to_transaction_ids)
    {
        if (entry.second.size() < static_cast<size_t>(num_months))
        {
            unused_names.push_back(entry.first);
            continue;
        }

        names.push_back(entry.first);
    }

    // Remove any entries for unused names
    for (const auto &name : unused_names)
        name_to_transaction_ids.erase(name);

    // Sort the names by the total value of the transactions
    std::sort(names.begin(), names.end(), [&](const std::string &a, const std::string &b) {
        double value_a = name_to_total_value.at(a);
        double value_b = name_to_total_value.at(b);

        // Most valuable names first
        if (std::abs(value_a - value_b) > std::numeric_limits<double>::epsilon())
            return value_a > value_b;

        // Alphabetic for equally valuable names
        return a < b;
    });

    return result;
}

bool check_stable_income(const std::vector<BankTransaction> &transactions,
                         const struct tm &start_date,
                         const struct tm &end_date,
                         const std::string &currency_code,
                         const int tolerance_days,
                         const uint32_t consistent_income)
{
    const int num_months = tm_month_difference(start_date, end_date);
    DEBUG_LOG("Start date = %s", tm_to_iso8601(start_date).c_str());
    DEBUG_LOG("End date = %s", tm_to_iso8601(end_date).c_str());
    DEBUG_LOG("Month range = %i", num_months);

    // Select the relevant transactions
    const auto name_sorted_transactions =
        prepare_transactions(transactions, start_date, end_date, tolerance_days, currency_code);

    const auto &names = name_sorted_transactions.names;
    const auto &name_to_transaction_ids = name_sorted_transactions.name_to_transaction_ids;

    // Accumulate the total stable value over all transaction sources
    double total_stable_value = 0.;
    for (const auto &name : names)
    {
        const auto ids = name_to_transaction_ids.at(name);

        // Try each transaction as the seed and find the one that maximises the stable value for
        // this name
        double max_stable_value = 0.;
        for (const auto seed_id : ids)
        {
            const auto stable_value =
                get_stable_value(transactions, ids, seed_id, tolerance_days, num_months);

            max_stable_value = std::max(max_stable_value, stable_value);
        }

        total_stable_value += max_stable_value;

        // If the current total exceeds the required minimum then there's no need to process the
        // remaining income sources
        if (total_stable_value >= static_cast<double>(consistent_income))
            return true;
    }

    return false;
}

std::string find_account(const std::map<std::string, AccountNumbers> &account_details,
                         const AccountNumbers &account_numbers)
{
    std::string matched_account_id = "";
    // Determine if bank provides the info
    for (const auto &kv : account_details)
    {
        const std::string &account_id = kv.first;
        const AccountNumbers &account = kv.second;
        if (!account_numbers.ach_account_number().empty())
        {
            if (account.ach_account_number().empty())
                THROW_ERROR_CODE(kBankInfoNotProvided);
            if (account_numbers.ach_account_number() != account.ach_account_number())
                continue;
        }
        if (!account_numbers.ach_routing().empty())
        {
            if (account.ach_routing().empty() && account.ach_wire_routing().empty())
                THROW_ERROR_CODE(kBankInfoNotProvided);
            if (account_numbers.ach_routing() != account.ach_routing() &&
                account_numbers.ach_routing() != account.ach_wire_routing())
                continue;
        }
        if (!account_numbers.ach_wire_routing().empty())
        {
            if (account.ach_routing().empty() && account.ach_wire_routing().empty())
                THROW_ERROR_CODE(kBankInfoNotProvided);
            if (account_numbers.ach_wire_routing() != account.ach_routing() &&
                account_numbers.ach_wire_routing() != account.ach_wire_routing())
                continue;
        }
        if (!account_numbers.iban().empty())
        {
            if (account.iban().empty())
                THROW_ERROR_CODE(kBankInfoNotProvided);
            if (account_numbers.iban() != account.iban())
                continue;
        }
        if (!account_numbers.uk_account_number().empty())
        {
            if (account.uk_account_number().empty())
                THROW_ERROR_CODE(kBankInfoNotProvided);
            if (account_numbers.uk_account_number() != account.uk_account_number())
                continue;
        }
        if (!account_numbers.uk_sort_code().empty())
        {
            if (account.uk_sort_code().empty())
                THROW_ERROR_CODE(kBankInfoNotProvided);
            if (account_numbers.uk_sort_code() != account.uk_sort_code())
                continue;
        }
        if (!account_numbers.eft_account_number().empty())
        {
            if (account.eft_account_number().empty())
                THROW_ERROR_CODE(kBankInfoNotProvided);
            if (account_numbers.eft_account_number() != account.eft_account_number())
                continue;
        }
        if (!account_numbers.eft_institution().empty())
        {
            if (account.eft_institution().empty())
                THROW_ERROR_CODE(kBankInfoNotProvided);
            if (account_numbers.eft_institution() != account.eft_institution())
                continue;
        }
        if (!account_numbers.eft_branch().empty())
        {
            if (account.eft_branch().empty())
                THROW_ERROR_CODE(kBankInfoNotProvided);
            if (account_numbers.eft_branch() != account.eft_branch())
                continue;
        }
        if (!account_numbers.bic().empty())
        {
            if (account.bic().empty())
                THROW_ERROR_CODE(kBankInfoNotProvided);
            if (account_numbers.bic() != account.bic())
                continue;
        }
        matched_account_id = account_id;
    }
    if (matched_account_id.empty())
        THROW_ERROR_CODE(kNoMatchingAccount);
    return matched_account_id;
}

bool check_minimum_age(const int now_timestamp,
                       const int date_of_birth_timestamp,
                       const int min_years)
{
    const auto now = timestamp_to_tm(now_timestamp);
    const auto dob = timestamp_to_tm(date_of_birth_timestamp);

    const int years = now.tm_year - dob.tm_year;
    const int months = now.tm_mon - dob.tm_mon;
    const int days = now.tm_mday - dob.tm_mday;

    return !(years < min_years || (years == min_years && months < 0) ||
             (years == min_years && months == 0 && days < 0));
}

} // namespace enclave
} // namespace silentdata
