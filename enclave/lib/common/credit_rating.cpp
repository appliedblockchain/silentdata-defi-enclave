#include "lib/common/credit_rating.hpp"

#include "lib/common/enclave_exception.hpp"
#include "lib/common/enclave_logger.hpp"

#include <unordered_map>

namespace silentdata
{
namespace enclave
{

const std::unordered_map<std::string, int> credit_rating_to_risk_score = {
    {"AAA+", 2},  {"AAA", 5},  {"AAA-", 8},  {"AA+", 12},  {"AA", 15},  {"AA-", 18},
    {"A+", 22},   {"A", 25},   {"A-", 28},   {"BBB+", 32}, {"BBB", 35}, {"BBB-", 38},
    {"BB+", 42},  {"BB", 45},  {"BB-", 48},  {"B+", 52},   {"B", 55},   {"B-", 58},
    {"CCC+", 62}, {"CCC", 65}, {"CCC-", 68}, {"CC+", 72},  {"CC", 75},  {"CC-", 78},
    {"C+", 82},   {"C", 85},   {"C-", 88},   {"RD", 92},   {"SD", 95},  {"D", 98}};

int get_risk_score(const std::string &credit_rating)
{
    const auto iter = credit_rating_to_risk_score.find(credit_rating);
    if (iter == credit_rating_to_risk_score.end())
        THROW_EXCEPTION(kDecodingError, "Input credit_rating \"" + credit_rating + "\" not known");

    return iter->second;
}

} // namespace enclave
} // namespace silentdata
