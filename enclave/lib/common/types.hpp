/*
 * Common data types
 */

#pragma once

#include "time.h"
#include <string>
#include <vector>

namespace silentdata
{
namespace enclave
{

struct BankBalance
{
    BankBalance(const std::string &cc, double a, double c)
        : currency_code(cc), available(a), current(c)
    {
    }
    BankBalance() {}
    std::string currency_code;
    double available;
    double current;
};

struct BankTransaction
{
    BankTransaction(const std::string &cc, double a, struct tm d, const std::string &n)
        : currency_code(cc), amount(a), date(d), name(n)
    {
    }
    std::string currency_code;
    double amount;
    struct tm date;
    std::string name;
};

struct Invoice
{
    struct tm date;
    struct tm due_date;
    // ATTN amount is the value of invoice in units of currency_code/100 (i.e. cents for USD, pence
    // for GBP) e.g. amount = 69420 and currency_code = USD -> value of invoice is $694.20
    uint64_t amount;
    std::string currency_code;
    std::string payer;
    std::string id;
};

struct CompanyProfile
{
    CompanyProfile() {}

    CompanyProfile(const bool a, const struct tm d) : is_active(a), creation_date(d) {}

    bool is_active;
    struct tm creation_date;
};

struct SubjectDetails
{
    SubjectDetails() {}
    SubjectDetails(const std::string &fn,
                   const std::string &ln,
                   const std::string &di,
                   const int dob)
        : first_name(fn), last_name(ln), document_id(di), date_of_birth(dob)
    {
    }

    std::string first_name;
    std::string last_name;
    std::string document_id;
    int date_of_birth;
};

struct KYCCheck
{
    KYCCheck() {}
    KYCCheck(const bool p, const int t) : passed(p), timestamp(t) {}

    bool passed;
    int timestamp; ///< The creation date of the oldest report that was considered by the check as a
                   ///< timestamp
};

} // namespace enclave
} // namespace silentdata
