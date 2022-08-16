/*
 *  Onfido identity client
 */

#pragma once

#include <string>

#include "lib/common/optional.hpp"
#include "lib/common/types.hpp"

#include "clients/api_client/api_client.hpp"

namespace silentdata
{
namespace enclave
{

class OnfidoClient : public APIClient
{
private:
    typedef std::pair<int, std::string> TimedId;
    typedef std::vector<TimedId> TimedIdVector;

    // Pairs of expected keys and their expected values on a report
    //   - first = vector of nested keys (e.g. "foo.bar.baz" -> { "foo", "bar", "baz" }
    //   - second = expected value at that key
    typedef std::vector<std::pair<std::vector<std::string>, std::string>> ReportValidationRequest;

    // Pairs of (nested) keys and a boolean, true if the key exists and has it's expected value
    //   - first = vector of nested keys
    //   - second = true if all keys exist and value is as expected
    typedef std::vector<std::pair<std::vector<std::string>, bool>> ReportValidation;

    std::vector<std::string> default_headers(bool post = false) const;
    json::JSON default_request_body() const;

    HTTPSResponse
    get_with_rate_limit(const std::string &endpoint, bool retry = false, int retries = 0);

    Optional<std::string> parse_error_string(const HTTPSResponse &response) const;

    // Make a GET request to obtain the checks associated with an applicant
    // and extract the report IDs ordered by their timestamp (newest first)
    TimedIdVector get_report_ids(const std::string &applicant_id);

    // Parse the report IDs from a HTTPSResponse from Onfido for a GET check request
    TimedIdVector parse_report_ids(const HTTPSResponse &response) const;

    // Make a GET request to retrieve a report with a given ID
    json::JSON get_report(const std::string &report_id);

    // Use a nested key to access a value on an input JSON object
    Optional<json::JSON> get_value_with_nested_key(const json::JSON &object,
                                                   const std::vector<std::string> &keys) const;

    // Find the report with the specified type that is first in the input vector of report_ids
    Optional<json::JSON> get_most_recent_report_with_type(const TimedIdVector &report_ids,
                                                          const std::string &type);

    ReportValidation
    verify_applicant_report(const json::JSON &report,
                            const ReportValidationRequest &validation_request) const;

    std::string get_first_name(const json::JSON &report) const;
    std::string get_last_name(const json::JSON &report) const;
    std::string get_document_id(const json::JSON &report) const;
    int get_date_of_birth(const json::JSON &report) const;

    int max_retries_;

public:
    OnfidoClient(const std::string &hostname,
                 const std::string &api_key,
                 const uint32_t timestamp,
                 const std::vector<std::string> &allowed_certificates = {});

    ~OnfidoClient() {}

    CoreStatusCode parse_error(const HTTPSResponse &response) const;

    KYCCheck verify_applicant_reports(const std::string &applicant_id);
    SubjectDetails fetch_subject_details(const std::string &applicant_id);
};

} // namespace enclave
} // namespace silentdata
