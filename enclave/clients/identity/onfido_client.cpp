#include "clients/identity/onfido_client.hpp"

#include <string>
#include <utility>
#include <vector>

#include "lib/common/date_time.hpp"

using json::JSON;

namespace silentdata
{
namespace enclave
{

OnfidoClient::OnfidoClient(const std::string &hostname,
                           const std::string &api_key,
                           const uint32_t timestamp,
                           const std::vector<std::string> &allowed_certificates)
    : APIClient(hostname, api_key, timestamp, allowed_certificates), max_retries_(5)
{
}

Optional<std::string> OnfidoClient::parse_error_string(const HTTPSResponse &response) const
{
    const std::string error_key = "error";
    const std::string type_key = "type";

    const auto error_data = parse_json(response);
    if (!error_data.hasKey(error_key))
    {
        return Optional<std::string>();
    }

    const auto error = error_data.get(error_key);
    if (!error.hasKey(type_key))
    {
        return Optional<std::string>();
    }

    return error.get(type_key).String();
}

CoreStatusCode OnfidoClient::parse_error(const HTTPSResponse &response) const
{
    if (response.get_status_code() == 200)
        return kSuccess;

    try
    {
        ERROR_LOG(
            "Onfido Error (%i):\n%s", response.get_status_code(), response.get_body().c_str());

        const auto error_type_opt = parse_error_string(response);

        if (!error_type_opt.has_value())
            return get_HTTP_status(response.get_status_code());

        const auto &error_type = error_type_opt.value();

        // Error codes taken from:
        // https://documentation.onfido.com/#error-codes-and-what-to-do

        if (error_type == "bad_request")
            return kOnfidoBadRequest;

        if (error_type == "incorrect_base_url")
            return kOnfidoIncorrectBaseUrl;

        if (error_type == "authorization_error")
            return kOnfidoAuthorizationError;

        if (error_type == "user_authorization_error")
            return kOnfidoUserAuthorizationError;

        if (error_type == "bad_referrer")
            return kOnfidoBadReferrer;

        if (error_type == "expired_token")
            return kOnfidoExpiredToken;

        if (error_type == "account_disabled")
            return kOnfidoAccountDisabled;

        if (error_type == "trial_limits_reached")
            return kOnfidoTrialLimitsReached;

        if (error_type == "resource_not_found")
            return kOnfidoResourceNotFound;

        if (error_type == "gone")
            return kOnfidoGone;

        if (error_type == "validation_error")
            return kOnfidoValidationError;

        if (error_type == "missing_billing_info")
            return kOnfidoMissingBillingInfo;

        if (error_type == "missing_documents")
            return kOnfidoMissingDocuments;

        if (error_type == "invalid_reports_names")
            return kOnfidoInvalidReportsNames;

        if (error_type == "missing_id_numbers")
            return kOnfidoMissingIdNumbers;

        if (error_type == "report_names_blank")
            return kOnfidoReportNamesBlank;

        if (error_type == "report_names_format")
            return kOnfidoReportNamesFormat;

        if (error_type == "check_type_deprecated")
            return kOnfidoCheckTypeDeprecated;

        if (error_type == "document_ids_with_unsupported_report")
            return kOnfidoDocumentIdsWithUnsupportedReport;

        if (error_type == "facial_similarity_photo_without_document")
            return kOnfidoFacialSimilarityPhotoWithoutDocument;

        if (error_type == "facial_similarity_video_not_supported")
            return kOnfidoFacialSimilarityVideoNotSupported;

        if (error_type == "failed_check_requirements")
            return kOnfidoFailedCheckRequirements;

        if (error_type == "incomplete_checks")
            return kOnfidoIncompleteChecks;

        if (error_type == "rate_limit")
            return kOnfidoRateLimit;

        if (error_type == "internal_server_error")
            return kOnfidoInternalServerError;

        return kOnfidoOtherError;
    }
    catch (...)
    {
        const auto status_code = response.get_status_code();
        return get_HTTP_status(status_code);
    }

    return kHTTPStatusNot200;
}

std::vector<std::string> OnfidoClient::default_headers(bool post) const
{
    std::vector<std::string> headers;
    headers.push_back("Host: " + server_address());
    if (post)
        headers.push_back("Content-Type: application/json");

    headers.push_back("Authorization: Token token=" + secret_);

    return headers;
}

json::JSON OnfidoClient::default_request_body() const { return json::Object(); }

HTTPSResponse
OnfidoClient::get_with_rate_limit(const std::string &endpoint, bool retry, int retries)
{
    try
    {
        return get(endpoint);
    }
    catch (const EnclaveException &e)
    {
        if (e.get_code() != kOnfidoRateLimit || retries >= max_retries_)
            throw e;

        DEBUG_LOG(
            "Onfido returned a rate limit error sleeping for 30s and retrying. Attempt %i / %i.",
            retries + 1,
            max_retries_);
        mbedtls_net_usleep(30000000);
        return get_with_rate_limit(endpoint, retry, retries + 1);
    }
}

OnfidoClient::TimedIdVector OnfidoClient::get_report_ids(const std::string &applicant_id)
{
    const std::string endpoint = "/v3.2/checks";
    const std::string payload = "applicant_id=" + applicant_id;

    const auto retry = true;
    const std::string error_message = "An error occured during GET request to Onfido server:\n"
                                      "  - Endpoint: " +
                                      endpoint +
                                      "\n"
                                      "  - Query: " +
                                      payload;

    DEBUG_LOG("Sending get request with payload: %s", payload.c_str());
    try
    {
        return parse_report_ids(get_with_rate_limit(endpoint + "?" + payload, retry));
    }
    catch (const std::exception &e)
    {
        THROW_EXCEPTION(kHTTPRequestError, error_message + "\n  - Error: " + std::string(e.what()));
    }
    catch (...)
    {
        THROW_EXCEPTION(kHTTPRequestError, error_message);
    }
}

OnfidoClient::TimedIdVector OnfidoClient::parse_report_ids(const HTTPSResponse &response) const
{
    const std::string checks_key = "checks";
    const std::string created_at_key = "created_at";
    const std::string report_ids_key = "report_ids";

    // Ensure the server didn't respond with an error
    const auto error = parse_error(response);
    if (error != kSuccess)
        THROW_ERROR_CODE(error);

    // Ensure that there are checks in the response and they are iterable
    const auto data = parse_json(response);
    if (!data.hasKey(checks_key))
        THROW_EXCEPTION(kJSONKeyError, "Response from Onfido missing key: \"" + checks_key + "\"");

    const auto &checks = data.get(checks_key);
    if (checks.length() < 0)
        THROW_EXCEPTION(kJSONIteratorError,
                        "Response from Onfido has \"" + checks_key + "\" that aren't iterable");

    // Iterate through the checks and pull out the report ids along with their time of creation
    TimedIdVector report_data;
    for (const auto &check : checks.ArrayRange())
    {
        // Get the creation date-time
        if (!check.hasKey(created_at_key))
            THROW_EXCEPTION(kJSONKeyError,
                            "Response from Onfido missing key: \"" + created_at_key + "\"");

        const auto &created_at_str = check.get(created_at_key).String();

        // Get the report ids if they exist
        if (!check.hasKey(report_ids_key))
            continue;

        const auto &report_ids = check.get(report_ids_key);
        if (report_ids.length() < 0)
            continue;

        const auto created_at = iso8601_to_timestamp(created_at_str);
        for (const auto &report_id : report_ids.ArrayRange())
        {
            report_data.emplace_back(created_at, report_id.String());
        }
    }

    // Sort the reports by their time of creation (newest first)
    std::sort(report_data.begin(), report_data.end(), [](const TimedId &a, const TimedId &b) {
        // If reports have the same timestamp, sort alphabetically
        if (a.first == b.first)
            return a.second < b.second;

        return a.first > b.first;
    });

    return report_data;
}

JSON OnfidoClient::get_report(const std::string &report_id)
{
    const std::string endpoint = "/v3.2/reports/" + report_id;

    const auto retry = true;
    const std::string error_message = "An error occured during GET request to Onfido server:\n"
                                      "  - Endpoint: " +
                                      endpoint;

    try
    {
        const auto response = get_with_rate_limit(endpoint, retry);
        const auto error = parse_error(response);
        if (error != kSuccess)
            THROW_ERROR_CODE(error);

        return parse_json(response);
    }
    catch (const std::exception &e)
    {
        THROW_EXCEPTION(kHTTPRequestError, error_message + "\n  - Error: " + std::string(e.what()));
    }
    catch (...)
    {
        THROW_EXCEPTION(kHTTPRequestError, error_message);
    }
}

Optional<JSON> OnfidoClient::get_most_recent_report_with_type(const TimedIdVector &report_ids,
                                                              const std::string &type)
{
    // ATTN this function assumes that the input TimedIdVector is already sorted

    const std::string name_key = "name";

    for (const auto &report : report_ids)
    {
        const auto id = report.second;

        const auto json = get_report(id);
        if (!json.hasKey(name_key))
            THROW_EXCEPTION(kJSONKeyError, "Report from Onfido missing key: \"" + name_key + "\"");

        const auto name = json.get(name_key).String();
        if (name != type)
            continue;

        return json;
    }

    return Optional<JSON>();
}

Optional<JSON> OnfidoClient::get_value_with_nested_key(const JSON &object,
                                                       const std::vector<std::string> &keys) const
{
    JSON current_object = object;
    for (const auto &nested_key : keys)
    {
        if (!current_object.hasKey(nested_key))
            return Optional<JSON>();

        const auto next_object = current_object.get(nested_key);
        current_object = next_object;
    }

    return current_object;
}

OnfidoClient::ReportValidation
OnfidoClient::verify_applicant_report(const JSON &report,
                                      const ReportValidationRequest &validation_request) const
{
    ReportValidation validation;

    for (const auto &entry : validation_request)
    {
        const auto &keys = entry.first;
        const auto &expected_value = entry.second;

        const auto value_opt = get_value_with_nested_key(report, keys);
        if (!value_opt.has_value())
        {
            validation.emplace_back(keys, false);
            continue;
        }

        const auto value = value_opt.value().String();
        validation.emplace_back(keys, value == expected_value);
    }

    return validation;
}

KYCCheck OnfidoClient::verify_applicant_reports(const std::string &applicant_id)
{
    const auto report_ids = get_report_ids(applicant_id);

    bool all_reports_passed = true;
    int timestamp = 0;
    for (const auto &validation_data : std::vector<std::pair<std::string, ReportValidationRequest>>{

             // The checks we want to validate
             // ATTN the specific keys that we want to validate are still to be decided
             {"document",
              {
                  {{"result"}, "clear"},
                  {{"sub_result"}, "clear"},
              }},
             {"facial_similarity_photo",
              {
                  {{"result"}, "clear"},
                  {{"breakdown", "face_comparison", "result"}, "clear"},
                  {{"breakdown", "image_integrity", "result"}, "clear"},
                  {{"breakdown", "visual_authenticity", "result"}, "clear"},
              }},
             {"watchlist_standard",
              {
                  {{"result"}, "clear"},
                  {{"breakdown", "legal_and_regulatory_warnings", "result"}, "clear"},
                  {{"breakdown", "politically_exposed_person", "result"}, "clear"},
                  {{"breakdown", "sanction", "result"}, "clear"},
              }},
         })
    {
        // Get the report with this type
        const auto &report_type = validation_data.first;
        const auto report_opt = get_most_recent_report_with_type(report_ids, report_type);
        if (!report_opt.has_value())
        {
            DEBUG_LOG("Failed to find Onfido report with type \"%s\" with applicant_id: %s",
                      report_type.c_str(),
                      applicant_id.c_str());
            all_reports_passed = false;
            continue;
        }

        const auto &report = report_opt.value();

        // Set the KYC timestamp to be the most recent report seen
        const std::string created_at_key = "created_at";
        const auto created_at_opt = get_value_with_nested_key(report, {created_at_key});
        if (!created_at_opt.has_value())
            THROW_EXCEPTION(kJSONKeyError,
                            "Failed to find \"" + created_at_key +
                                "\" key in Onfido report with type \"" + report_type +
                                "\" with applicant_id: " + applicant_id);

        const auto created_at = created_at_opt.value().String();
        const auto report_timestamp = iso8601_to_timestamp(created_at);
        if (report_timestamp > timestamp)
            timestamp = report_timestamp;

        // Perform the validation checks
        const auto &validation_request = validation_data.second;
        const auto &validation = verify_applicant_report(report, validation_request);
        for (const auto &item : validation)
        {
            const auto passed = item.second;
            if (passed)
                continue;

            const auto &keys = item.first;
            std::string nested_key = "";
            for (const auto &key : keys)
                nested_key += (nested_key.empty() ? "" : ".") + key;

            DEBUG_LOG("Key \"%s\" not found, or has value not equal to expected value, in \"%s\" "
                      "report for Onfido applicant_id: %s",
                      nested_key.c_str(),
                      report_type.c_str(),
                      applicant_id.c_str());
            all_reports_passed = false;
        }
    }

    return KYCCheck(all_reports_passed, timestamp);
}

std::string OnfidoClient::get_first_name(const json::JSON &report) const
{
    const auto first_name_opt = get_value_with_nested_key(report, {"properties", "first_name"});
    if (!first_name_opt.has_value())
        THROW_EXCEPTION(kJSONKeyError,
                        "Failed to find key \"properties.first_name\" in \"document\" report");

    return first_name_opt.value().String();
}

std::string OnfidoClient::get_last_name(const json::JSON &report) const
{
    const auto last_name_opt = get_value_with_nested_key(report, {"properties", "last_name"});
    if (!last_name_opt.has_value())
        THROW_EXCEPTION(kJSONKeyError,
                        "Failed to find key \"properties.last_name\" in \"document\" report");

    return last_name_opt.value().String();
}

std::string OnfidoClient::get_document_id(const json::JSON &report) const
{
    const auto document_numbers_opt =
        get_value_with_nested_key(report, {"properties", "document_numbers"});
    if (!document_numbers_opt.has_value())
        THROW_EXCEPTION(
            kJSONKeyError,
            "Failed to find key \"properties.document_numbers\" in \"document\" report");

    const auto &document_numbers = document_numbers_opt.value();

    if (document_numbers.length() < 0)
        THROW_EXCEPTION(
            kJSONTypeError,
            "Value of \"properties.document_numbers\" in \"document\" report is not iterable");

    if (document_numbers.length() == 0)
        THROW_EXCEPTION(
            kJSONOutOfRangeError,
            "Value of \"properties.document_numbers\" in \"document\" report is empty list");

    // Grab the docment number values
    std::vector<std::string> document_number_values;
    for (const auto &document_number : document_numbers.ArrayRange())
    {
        // Get the value of the
        if (!document_number.hasKey("value"))
            THROW_EXCEPTION(kJSONKeyError, "Found a document number without a \"value\"");

        const auto value = document_number.get("value").String();
        document_number_values.push_back(value);
    }

    // Sort the document number values for reproducibility
    std::sort(document_number_values.begin(), document_number_values.end());

    // Concatenate the document number values as a document ID
    std::string document_id;
    for (const auto &value : document_number_values)
        document_id += value;

    return document_id;
}

int OnfidoClient::get_date_of_birth(const json::JSON &report) const
{
    const auto date_of_birth_opt =
        get_value_with_nested_key(report, {"properties", "date_of_birth"});
    if (!date_of_birth_opt.has_value())
        THROW_EXCEPTION(kJSONKeyError,
                        "Failed to find key \"properties.date_of_birth\" in \"document\" report");

    const auto dob = date_of_birth_opt.value().String();
    return iso8601_to_timestamp(dob);
}

SubjectDetails OnfidoClient::fetch_subject_details(const std::string &applicant_id)
{
    // Get the most recent document report
    const auto report_ids = get_report_ids(applicant_id);
    const auto report_opt = get_most_recent_report_with_type(report_ids, "document");
    if (!report_opt.has_value())
        THROW_EXCEPTION(kHTTPRequestError,
                        "Failed to find Onfido report with type \"document\" with applicant_id: " +
                            applicant_id);

    const auto &report = report_opt.value();
    return SubjectDetails(get_first_name(report),
                          get_last_name(report),
                          get_document_id(report),
                          get_date_of_birth(report));
}

} // namespace enclave
} // namespace silentdata
