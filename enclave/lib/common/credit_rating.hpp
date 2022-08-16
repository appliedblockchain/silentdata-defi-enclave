#pragma once

#include <string>

namespace silentdata
{
namespace enclave
{

// Converts an input credit rating to a risk score from 1-100
//
// The credit_rating should be one of the following:
//    { X, RD, SD, D }
//    where X in { Y+, Y, Y- }
//    where Y in { Z, ZZ, ZZZ }
//    where Z in { A, B, C}
//
// E.g. BB+, CCC-, RD, A are all valid credit ratings.
// In total 30 different ratings are possible, so not all values from 1-100 are used.
//
// The risk scores are ordered such that:
//    - D > SD > RD > X (as defined above)
//    - Y- > Y > Y+
//    - Z > ZZ > ZZZ
//    - C > B > A
//
// AAA+ has the least risk and is assigned a score of 2
//    - The difference in risk between A <-> B and B <-> C is 30
//    - The difference in risk between A <-> AA, AA <-> AAA, B <-> BB, etc. is 10
//    - The difference in risk between A- <-> A, A <-> A+, etc. is 3
//
// D, SD and RD have the most risk and are assigned scores of 98, 95 and 92 respectively
int get_risk_score(const std::string &credit_rating);

} // namespace enclave
} // namespace silentdata
