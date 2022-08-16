#include "lib/proof/comparison_functions.hpp"

namespace
{

using namespace silentdata::enclave;

// Match transactions by same name and day of the month
int find_matching_transaction(const BankTransaction &transaction,
                              const std::vector<BankTransaction> &other_transactions,
                              int tolerance)
{
    int matched_index = -1;
    for (size_t i = 0; i < other_transactions.size(); i++)
    {
        const BankTransaction &other_transaction = other_transactions[i];
        // Must be from the same source
        if (other_transaction.name != transaction.name)
            continue;
        // Must be on the same day if the day <= 28
        const int day = transaction.date.tm_mday;
        const int next_day = other_transaction.date.tm_mday;
        if (next_day <= 28 && day <= 28 && std::abs(next_day - day) > tolerance)
            continue;
        // Must be in the range 28 - 31 if day >= 28
        if (next_day >= 28 && day < (28 - tolerance))
            continue;
        if (day >= 28 && next_day < (28 - tolerance))
            continue;
        matched_index = static_cast<int>(i);
    }
    return matched_index;
}

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
    DEBUG_LOG("Start date = %i-%i-%i", start_date.tm_year, start_date.tm_mon, start_date.tm_mday);
    DEBUG_LOG("End date = %i-%i-%i", end_date.tm_year, end_date.tm_mon, end_date.tm_mday);
    DEBUG_LOG("Month range = %i", num_months);

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
        const int index = tm_month_difference(start_date, transaction.date);
        // Ignore anything outside of the date range we're considering
        if (income.find(index) == income.end())
            continue;
        income[index] += transaction.amount;
    }

    return check_income(income, consistent_income, num_months);
}

bool check_stable_income(const std::vector<BankTransaction> &transactions,
                         const struct tm &start_date,
                         const struct tm &end_date,
                         const std::string &currency_code,
                         uint32_t consistent_income)
{
    const int num_months = tm_month_difference(start_date, end_date);
    DEBUG_LOG("Start date = %i-%i-%i", start_date.tm_year, start_date.tm_mon, start_date.tm_mday);
    DEBUG_LOG("End date = %i-%i-%i", end_date.tm_year, end_date.tm_mon, end_date.tm_mday);
    DEBUG_LOG("Month range = %i", num_months);

    // Create map of incoming transactions by month
    std::map<int, std::vector<BankTransaction>> month_transactions_map;
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
        const int index = tm_month_difference(start_date, transaction.date);
        month_transactions_map[index].push_back(transaction);
    }

    std::map<int, double> income;
    // Initialise in case there are no transactions in a month
    for (int i = 0; i < num_months; i++)
        income[i] = 0;

    if (month_transactions_map.find(0) == month_transactions_map.end())
        return false;

    // For each transaction in the first month, check there is a corresponding transaction in all
    // subsequent months before adding to the total income
    const std::vector<BankTransaction> &first_month_transactions = month_transactions_map[0];
    for (const auto &transaction : first_month_transactions)
    {
        std::vector<BankTransaction> stable_transactions = {transaction};
        bool is_stable = true;
        // Check there is a transaction from the same entity at around the same time each month
        for (const auto &kv : month_transactions_map)
        {
            if (kv.first == 0)
                continue;
            const std::vector<BankTransaction> &other_transactions = kv.second;
            const int matched_index = find_matching_transaction(transaction, other_transactions, 3);
            if (matched_index < 0 || matched_index >= static_cast<int>(other_transactions.size()))
            {
                DEBUG_LOG("No match found for transaction");
                is_stable = false;
                break;
            }
            stable_transactions.push_back(other_transactions[matched_index]);
        }
        // Add any stable transactions to the total
        if (is_stable)
        {
            for (const auto &stable_transaction : stable_transactions)
            {
                const int index = tm_month_difference(start_date, stable_transaction.date);
                income[index] += stable_transaction.amount;
            }
        }
    }

    return check_income(income, consistent_income, num_months);
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

} // namespace enclave
} // namespace silentdata
