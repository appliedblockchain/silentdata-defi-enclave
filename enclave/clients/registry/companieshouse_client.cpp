#include "clients/registry/companieshouse_client.hpp"

#include "lib/common/date_time.hpp"
#include "lib/common/encoders.hpp"

#include <algorithm>

using json::JSON;

namespace silentdata
{
namespace enclave
{

CompaniesHouseClient::CompaniesHouseClient(const std::string &hostname,
                                           const std::string &api_key,
                                           const uint32_t timestamp,
                                           const std::vector<std::string> &allowed_certificates)
    : APIClient(hostname, api_key, timestamp, allowed_certificates)
{
}

Optional<std::string> CompaniesHouseClient::get_error_string(const json::JSON &error_data) const
{
    // ATTN HTTP response from Companies House API is in an inconsistent format!
    // Supposed error enumerations and descriptions are given here:
    // https://github.com/companieshouse/api-enumerations/blob/master/errors.yml
    //
    // curl --user <VALID_API_KEY>: -i "https://api.company-information.service.gov.uk/company/0"
    //     status: 404 (Not Found)
    //     response: {"errors":[{"error":"company-profile-not-found","type":"ch:service"}]}
    //     note: "error" is one of those listed in the api-enumerations
    //
    // curl --user <INVALID_API_KEY>: -i
    // "https://api.company-information.service.gov.uk/company/09686276"
    //     status: 401 (Unauthorized)
    //     response: {"error":"Invalid Authorization","type":"ch:service"}
    //     note: Response is a single error (instead of list of "errors" as above), and "error" is
    //     now a description instead of type listed in api-enumerations
    //
    // curl --user <VALID_API_KEY>: -i
    // "https://api.company-information.service.gov.uk/dissolved-search/companies?q=&search_type=alphabetical&size=0"
    //     status: 422 (Unprocessable Entity)
    //     response: Invalid size parameter, size must be greater than zero and not greater than 100
    //     note: Response is just text, not a JSON object.
    //
    // Other cases may be possible.

    // Handle cases with a single error
    const std::string singleErrorKey = "error";
    if (error_data.hasKey(singleErrorKey))
    {
        return error_data.at(singleErrorKey).ToString();
    }

    // Handle multiple errors
    const std::string multiErrorKey = "errors";
    if (error_data.hasKey(multiErrorKey))
    {
        // Use the first error, if it exists
        const auto &errors = error_data.at(multiErrorKey);
        if (errors.length() >= 1)
        {
            return get_error_string(errors.at(0));
        }
    }

    return Optional<std::string>();
}

CoreStatusCode CompaniesHouseClient::parse_error(const HTTPSResponse &response) const
{
    if (response.get_status_code() == 200)
        return kSuccess;

    try
    {
        ERROR_LOG("Companies House Error (%i):\n%s",
                  response.get_status_code(),
                  response.get_body().c_str());

        const auto error_data = json::JSON::Load(response.get_body());
        const auto error_type_opt = get_error_string(error_data);

        if (!error_type_opt.has_value())
            return get_HTTP_status(response.get_status_code());

        const auto &error_type = error_type_opt.value();

        // Access denied
        if (error_type == "access-denied")
            return kCompaniesHouseAccessDenied;

        // Company profile not found
        if (error_type == "company-profile-not-found")
            return kCompaniesHouseCompanyProfileNotFound;

        // Company insolvencies not found
        if (error_type == "company-insolvencies-not-found")
            return kCompaniesHouseCompanyInsolvenciesNotFound;

        // An update was made to the {object} by another user during your session. Select the
        // back button to see the updated version and to make further changes
        if (error_type == "etag-mismatch")
            return kCompaniesHouseEtagMismatch;

        // Invalid authorization header
        if (error_type == "invalid-authorization-header")
            return kCompaniesHouseInvalidAuthorizationHeader;

        // Access denied for HTTP method {method}
        if (error_type == "invalid-http-method")
            return kCompaniesHouseInvalidHttpMethod;

        // Invalid client ID
        if (error_type == "invalid-client-id")
            return kCompaniesHouseInvalidClientId;

        // No JSON payload provided
        if (error_type == "no-json-provided")
            return kCompaniesHouseNoJsonProvided;

        // Not authorised to file for this company
        if (error_type == "not-authorised-for-company")
            return kCompaniesHouseNotAuthorisedForCompany;

        // Transaction is not open
        if (error_type == "transaction-not-open")
            return kCompaniesHouseTransactionNotOpen;

        // Transaction does not exist
        if (error_type == "transaction-does-not-exist")
            return kCompaniesHouseTransactionDoesNotExist;

        // No transactions found for this user
        if (error_type == "user-transactions-not-found")
            return kCompaniesHouseUserTransactionsNotFound;

        // Unauthorised
        if (error_type == "unauthorised")
            return kCompaniesHouseUnauthorised;

        return kCompaniesHouseOtherError;
    }
    catch (...)
    {
        const auto status_code = response.get_status_code();
        return get_HTTP_status(status_code);
    }

    return kHTTPStatusNot200;
}

std::vector<std::string> CompaniesHouseClient::default_headers(bool post) const
{
    std::vector<std::string> headers;
    headers.push_back("Host: " + server_address());
    if (post)
        headers.push_back("Content-Type: application/json");

    // Comanpies House API uses HTTP basic access authentication with the API key as the userid and
    // an empty password field Need to pass "api_key:" in Base64 encoding where the ':' separates
    // the userid and password.
    headers.push_back("Authorization: Basic " + b64_encode(secret_ + ":"));

    return headers;
}

json::JSON CompaniesHouseClient::default_request_body() const { return json::Object(); }

Optional<CompanyProfile> CompaniesHouseClient::get_company_by_name(const std::string &name)
{
    CompanyProfile profile;
    const auto sanitized_name = get_sanitized_name(name);

    for (size_t page = 0; page < max_pages_; ++page)
    {
        const auto response = get_search_response(sanitized_name, page);

        const auto status = parse_error(response);
        if (status != kSuccess)
            THROW_ERROR_CODE(status);

        ensure_json_content_type(response);
        const auto response_data = parse_json(response);

        if (!response_data.hasKey(items_key_))
            THROW_EXCEPTION(kJSONKeyError,
                            "Response from Companies House missing key \"" +
                                std::string(items_key_) + "\"");

        const auto &items = response_data.at(items_key_);
        if (items.length() < 0)
            THROW_EXCEPTION(kJSONIteratorError,
                            "Response from Companies House has \"" + std::string(items_key_) +
                                "\" that aren't iterable");

        // Not found
        if (items.length() == 0)
            return Optional<CompanyProfile>();

        // Iterate through the search results on this page
        for (const auto &item : items.ArrayRange())
        {
            if (!item.hasKey(title_key_))
            {
                ERROR_LOG("Companies House responded with a search item without a \"%s\" key",
                          title_key_);
                continue;
            }

            // Check if this is the company we are looking for
            const auto &name_result = item.at(title_key_).ToString();
            const auto sanitized_name_result = get_sanitized_name(name_result);
            if (sanitized_name_result != sanitized_name)
                continue;

            if (!item.hasKey(creation_date_key_))
                THROW_EXCEPTION(kJSONKeyError,
                                "Response from Companies House missing key \"" +
                                    std::string(creation_date_key_) + "\"");

            if (!item.hasKey(company_status_key_))
                THROW_EXCEPTION(kJSONKeyError,
                                "Response from Companies House missing key \"" +
                                    std::string(company_status_key_) + "\"");

            const auto &creation_date = item.at(creation_date_key_).ToString();
            set_date_from_string(creation_date, profile.creation_date);

            const auto &company_status = item.at(company_status_key_).ToString();
            profile.is_active = (company_status == "active");

            // Found
            return Optional<CompanyProfile>(profile);
        }
    }

    // Not found
    return Optional<CompanyProfile>();
}

void CompaniesHouseClient::set_date_from_string(const std::string &date_string,
                                                struct tm &date) const
{
    const std::string error_message =
        "Response from Companies House has date \"" + date_string + "\" which is invalid.";
    try
    {
        date = iso8601_to_tm(date_string);
    }
    catch (const std::exception &e)
    {
        THROW_EXCEPTION(kDateTimeError, error_message + "\nError: " + std::string(e.what()));
    }
    catch (...)
    {
        THROW_EXCEPTION(kDateTimeError, error_message);
    }
}

std::string CompaniesHouseClient::get_sanitized_name(const std::string &name) const
{
    auto sanitized_name = name;
    std::for_each(sanitized_name.begin(), sanitized_name.end(), [](char &c) {
        c = static_cast<char>(::toupper(static_cast<int>(c)));
    });

    return sanitized_name;
}

HTTPSResponse CompaniesHouseClient::get_search_response(const std::string &query,
                                                        const size_t page_number)
{
    const auto start_index = page_number * items_per_page_;

    const std::string payload = "q=" + url_encode(query) +
                                "&items_per_page=" + std::to_string(items_per_page_) +
                                "&start_index=" + std::to_string(start_index);

    const std::string error_message =
        "An error occured during GET request to Companies House server:\n"
        "  - Endpoint: /search/companies\n"
        "  - Query: " +
        payload;

    DEBUG_LOG("Sending get request with payload: %s", payload.c_str());
    try
    {
        return get("/search/companies?" + payload);
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

void CompaniesHouseClient::ensure_json_content_type(const HTTPSResponse &response) const
{
    for (const auto &header : response.get_headers())
    {
        if (header.name == "Content-Type" && header.value == "application/json")
            return;
    }

    THROW_EXCEPTION(kHTTPResponseParseError,
                    "Missing \"Content-Type\" header, or type is not \"application/json\"");
}

} // namespace enclave
} // namespace silentdata
