#include "clients/banking/truelayer_client.hpp"

using json::JSON;

namespace silentdata
{
namespace enclave
{

TrueLayerClient::TrueLayerClient(const std::string &hostname,
                                 const std::string &client_id,
                                 const std::string &secret,
                                 uint32_t timestamp,
                                 const std::string &code,
                                 const std::string &code_verifier,
                                 const std::string &redirect_uri,
                                 const std::vector<std::string> &allowed_certificates)
    : BankClient(hostname, client_id, secret, timestamp, allowed_certificates), code_(code),
      code_verifier_(code_verifier), redirect_uri_(redirect_uri)
{
}

TrueLayerClient::TrueLayerClient(const std::string &hostname,
                                 const APIConfig &config,
                                 const std::string &code,
                                 const std::string &code_verifier,
                                 const std::vector<std::string> &allowed_certificates)
    : TrueLayerClient(hostname,
                      config.client_id(),
                      config.secret(),
                      config.server_timestamp(),
                      code,
                      code_verifier,
                      config.redirect_uri(),
                      allowed_certificates)
{
}

TrueLayerClient::~TrueLayerClient()
{
    // Destroy access token if it exists
    if (access_token_.size() != 0)
    {
        try
        {
            destroy_access();
        }
        catch (...)
        {
            ERROR_LOG("Unable to destroy access");
        }
    }
}

std::vector<std::string> TrueLayerClient::default_headers(bool post) const
{
    std::vector<std::string> headers;
    headers.push_back("Host: " + server_address());
    if (post)
        headers.push_back("Content-Type: application/json");
    if (access_token_.length() != 0)
        headers.push_back("Authorization: Bearer " + access_token_);
    return headers;
}

JSON TrueLayerClient::default_request_body() const
{
    JSON request = json::Object();
    request["client_id"] = client_id_;
    request["client_secret"] = secret_;
    return request;
}

CoreStatusCode TrueLayerClient::parse_error(const HTTPSResponse &response) const
{
    // Just in case a valid response was passed to the function
    if (response.get_status_code() == 200)
        return kSuccess;

    // Try to parse the error response
    // Details of TrueLayer error codes: https://docs.truelayer.com/#data-api-errors
    try
    {
        ERROR_LOG("TrueLayer Error:\n%s", response.get_body().c_str());
        const JSON error_data = json::JSON::Load(response.get_body());
        const std::string error_code = error_data.get("error").String();
        if (error_code == "validation_error" || error_code == "invalid_grant" ||
            error_code == "invalid_client")
            return kTrueLayerValidationError;
        if (error_code == "invalid_date_range")
            return kTrueLayerDateRangeError;
        if (error_code == "deprecated_provider")
            return kTrueLayerDeprecatedProvider;
        if (error_code == "unauthorized" || error_code == "invalid_token")
            return kTrueLayerInvalidToken;
        if (error_code == "access_denied")
            return kTrueLayerAccessDenied;
        if (error_code == "sca_exceeded")
            return kTrueLayerSCAExceeded;
        if (error_code == "account_not_found")
            return kTrueLayerAccountNotFound;
        if (error_code == "provider_too_many_requests" ||
            error_code == "provider_request_limit_exceeded")
            return kTrueLayerRateLimitExceeded;
        if (error_code == "endpoint_not_supported")
            return kTrueLayerInvalidEndpoint;
        if (error_code == "internal_server_error" || error_code == "connector_overload")
            return kTrueLayerInternalServerError;
        if (error_code == "provider_error" || error_code == "temporarily_unavailable" ||
            error_code == "provider_timeout" || error_code == "connector_timeout")
            return kTrueLayerProviderError;
        return kTrueLayerOtherError;
    }
    // If that fails just set the error by the HTTP status code
    catch (...)
    {
        const auto status_code = response.get_status_code();
        return get_HTTP_status(status_code);
    }

    return kHTTPStatusNot200;
}

void TrueLayerClient::get_access()
{
    set_subdomain("auth");

    JSON request = default_request_body();
    request["grant_type"] = "authorization_code";
    request["redirect_uri"] = redirect_uri_;
    request["code"] = code_;
    request["code_verifier"] = code_verifier_;

    DEBUG_LOG("Sending /connect/token POST request to TrueLayer");
    const HTTPSResponse response = post("/connect/token", request.dump());

    const JSON data = JSON::Load(response.get_body());

    access_token_ = data.get("access_token").String();

    // Parse the response to get the timestamp
    last_timestamp_ = response.get_timestamp();

    // Check that a certificate chain was obtained
    last_certificate_chain_ = response.get_certificate_chain();
    if (last_certificate_chain_.length() == 0)
        THROW_EXCEPTION(kCertificateWriteError,
                        "Could not obtain the certificate chain from the HTTPS client");
}

void TrueLayerClient::destroy_access()
{
    set_subdomain("auth");
    set_close_session(true);

    DEBUG_LOG("Sending /api/delete DELETE request to TrueLayer");
    del("/api/delete");

    access_token_.clear();
}

std::vector<std::string> TrueLayerClient::get_accounts()
{
    set_subdomain("api");

    DEBUG_LOG("Sending /data/v1/accounts GET request to TrueLayer");
    const HTTPSResponse response = get("/data/v1/accounts");

    // Sum up all of the available balances
    const JSON data = JSON::Load(response.get_body());
    if (data.get("results").length() <= 0)
        THROW_EXCEPTION(kJSONParseError, "Could not find any bank accounts");

    std::vector<std::string> account_ids;
    for (const auto &account : data.get("results").ArrayRange())
    {
        account_ids.push_back(account.get("account_id").String());
    }
    return account_ids;
}

BankBalance TrueLayerClient::get_total_balance(const std::string &currency_code,
                                               const std::string &account_id)
{
    set_subdomain("api");

    const std::vector<std::string> account_ids = get_accounts();
    std::string code;
    double available = 0;
    double current = 0;
    for (const auto &id : account_ids)
    {
        if (!account_id.empty() && account_id != id)
            continue;
        DEBUG_LOG("Sending /data/v1/accounts/%s/balance GET request to TrueLayer", id.c_str());
        const HTTPSResponse response = get("/data/v1/accounts/" + id + "/balance");

        // Sum up all of the available balances
        const JSON data = JSON::Load(response.get_body());
        if (data.get("results").length() != 1)
            THROW_EXCEPTION(kJSONParseError, "Balance result for account did not have one entry");

        const JSON &balance = data.get("results").at(0);
        code = balance.get("currency").ToString();
        if (code != currency_code)
        {
            WARNING_LOG("Currency code for this account doesn't match input, skipping...");
            continue;
        }
        available += balance.get("available").Number();
        current += balance.get("current").Number();
    }

    return BankBalance(code, available, current);
}

std::vector<BankTransaction> TrueLayerClient::get_account_transactions(
    const std::string &account_id, struct tm start_date, struct tm end_date)
{
    set_subdomain("api");

    start_date.tm_mday = 1;
    end_date.tm_mday = 1;
    const int n_months = tm_month_difference(start_date, end_date);

    DEBUG_LOG("Sending /data/v1/accounts/%s/transactions GET request to TrueLayer",
              account_id.c_str());
    std::vector<BankTransaction> transactions;
    // Go month by month to reduce the number of transactions fetched in one go
    for (int month = 0; month < n_months; month++)
    {
        const struct tm first_date = add_tm_months(start_date, month);
        const std::string first_date_str = tm_to_iso8601(first_date) + "T00:00:00";
        const struct tm last_date = add_tm_months(start_date, month + 1);
        const std::string last_date_str = tm_to_iso8601(last_date) + "T00:00:00";
        const std::string query = "from=" + first_date_str + "&to=" + last_date_str;

        const HTTPSResponse response =
            get("/data/v1/accounts/" + account_id + "/transactions?" + query);

        const JSON data = JSON::Load(response.get_body());
        for (const auto &transaction : data.get("results").ArrayRange())
        {
            const std::string code = transaction.get("currency").String();
            const std::string date_str = transaction.get("timestamp").String();
            const struct tm date = iso8601_to_tm(date_str);

            const double amount = transaction.get("amount").Number();
            const std::string name = transaction.get("description").ToString();
            // Positive transactions mean money coming in to the account
            transactions.push_back(BankTransaction(code, amount, date, name));
        }
    }

    return transactions;
}

std::vector<BankTransaction> TrueLayerClient::get_all_transactions(struct tm start_date,
                                                                   struct tm end_date,
                                                                   const std::string &account_id)
{
    const std::vector<std::string> account_ids = get_accounts();
    std::vector<BankTransaction> transactions;
    for (const auto &id : account_ids)
    {
        if (!account_id.empty() && account_id != id)
            continue;
        const std::vector<BankTransaction> account_transactions =
            get_account_transactions(id, start_date, end_date);
        transactions.insert(
            transactions.end(), account_transactions.begin(), account_transactions.end());
    }

    return transactions;
}

std::string TrueLayerClient::get_account_holder_name(const std::string &account_id)
{
    set_subdomain("api");

    if (account_id != "")
        WARNING_LOG("Cannot select account holder name with account ID in TrueLayer");

    DEBUG_LOG("Sending /data/v1/info GET request to TrueLayer");
    const HTTPSResponse response = get("/data/v1/info");

    const JSON data = JSON::Load(response.get_body());
    if (data.get("results").length() != 1)
        THROW_EXCEPTION(kJSONParseError, "Could not find one result for account holder name");

    return data.get("results").at(0).get("full_name").String();
}

std::string TrueLayerClient::get_business_name(const std::string &account_id)
{
    set_subdomain("api");

    DEBUG_LOG("Sending /data/v1/info GET request to TrueLayer");
    const HTTPSResponse response = get("/data/v1/info");

    const JSON data = JSON::Load(response.get_body());
    if (data.get("results").length() != 1)
        THROW_EXCEPTION(kJSONParseError, "Could not find one result for account holder name");

    const std::string full_name = data.get("results").at(0).get("full_name").String();

    DEBUG_LOG("Sending /data/v1/accounts GET request to TrueLayer");
    const HTTPSResponse accounts_response = get("/data/v1/accounts");

    const JSON accounts_data = JSON::Load(accounts_response.get_body());
    if (accounts_data.get("results").length() <= 0)
        THROW_EXCEPTION(kJSONParseError, "Could not find any bank accounts");

    std::vector<std::string> account_names;
    for (const auto &account : accounts_data.get("results").ArrayRange())
    {
        std::string id = account.get("account_id").String();
        if (account_id != "" && account_id != id)
            continue;
        account_names.push_back(account.get("display_name").String());
    }

    // Use the name that appears the most if there's more than one
    std::map<std::string, int> name_occurrence;
    for (const auto &name : account_names)
        name_occurrence[name]++;
    std::string display_name = account_names[0];
    for (const auto &kv : name_occurrence)
        if (kv.second > name_occurrence[display_name])
            display_name = kv.first;

    // TODO mapping to decide which of full_name or display_name to use
    const std::string business_name = full_name + ": " + display_name;

    return business_name;
}

std::string TrueLayerClient::get_institution_name()
{
    set_subdomain("api");

    DEBUG_LOG("Sending /data/v1/me GET request to TrueLayer");
    const HTTPSResponse response = get("/data/v1/me");

    const JSON data = JSON::Load(response.get_body());
    if (data.get("results").length() != 1)
        THROW_EXCEPTION(kJSONParseError, "Could not find one result for access_token metadata");

    return data.get("results").at(0).get("provider").get("display_name").String();
}

std::map<std::string, AccountNumbers> TrueLayerClient::get_account_details()
{
    set_subdomain("api");

    DEBUG_LOG("Sending /data/v1/accounts GET request to TrueLayer");
    const HTTPSResponse response = get("/data/v1/accounts");

    const JSON data = JSON::Load(response.get_body());
    if (data.get("results").length() <= 0)
        THROW_EXCEPTION(kJSONParseError, "Could not find any bank accounts");

    std::map<std::string, AccountNumbers> account_details;
    for (const auto &account : data.get("results").ArrayRange())
    {
        const std::string id = account.get("account_id").String();
        const JSON &numbers = account.get("account_number");

        std::string account_number;
        if (numbers.hasKey("number"))
            account_number = numbers.get("number").ToString();
        if (account_number.empty())
            WARNING_LOG("Account number not provided");
        account_details[id].set_uk_account_number(account_number);

        std::string sort_code;
        if (numbers.hasKey("sort_code"))
            sort_code = numbers.get("sort_code").ToString();
        if (sort_code.empty())
        {
            WARNING_LOG("Sort code not provided");
        }
        else
        {
            sort_code.erase(2, 1);
            sort_code.erase(4, 1);
        }
        account_details[id].set_uk_sort_code(sort_code);

        std::string iban;
        if (numbers.hasKey("iban"))
            iban = numbers.get("iban").ToString();
        if (iban.empty())
            WARNING_LOG("IBAN not provided");
        account_details[id].set_iban(iban);

        std::string bic;
        if (numbers.hasKey("swift_bic"))
            bic = numbers.get("swift_bic").ToString();
        if (bic.empty())
            WARNING_LOG("BIC not provided");
        account_details[id].set_bic(bic);

        std::string routing;
        if (numbers.hasKey("routing_number"))
            routing = numbers.get("routing_number").ToString();
        if (routing.empty())
            WARNING_LOG("Routing number is null");
        account_details[id].set_ach_routing(routing);
    }

    return account_details;
}

} // namespace enclave
} // namespace silentdata
