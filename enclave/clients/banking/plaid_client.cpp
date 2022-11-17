#include "clients/banking/plaid_client.hpp"

using json::JSON;

namespace silentdata
{
namespace enclave
{

PlaidClient::PlaidClient(const std::string &hostname,
                         const std::string &client_id,
                         const std::string &secret,
                         uint32_t timestamp,
                         const std::string &public_token,
                         const std::string &redirect_uri,
                         const std::vector<std::string> &allowed_certificates)
    : BankClient(hostname, client_id, secret, timestamp, allowed_certificates),
      public_token_(public_token), redirect_uri_(redirect_uri)
{
}

PlaidClient::PlaidClient(const std::string &hostname,
                         const APIConfig &config,
                         const std::string &public_token,
                         const std::vector<std::string> &allowed_certificates)
    : PlaidClient(hostname,
                  config.client_id(),
                  config.secret(),
                  config.server_timestamp(),
                  public_token,
                  config.redirect_uri(),
                  allowed_certificates)
{
}

PlaidClient::~PlaidClient()
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
            ERROR_LOG("Unable to destroy access token");
        }
    }
}

std::vector<std::string> PlaidClient::default_headers(bool post) const
{
    std::vector<std::string> headers;
    headers.push_back("Host: " + host_);
    if (post)
        headers.push_back("Content-Type: application/json");
    return headers;
}

JSON PlaidClient::default_request_body() const
{
    JSON request = json::Object();
    request["client_id"] = client_id_;
    request["secret"] = secret_;
    if (access_token_.length() != 0)
        request["access_token"] = access_token_;
    return request;
}

CoreStatusCode PlaidClient::parse_error(const HTTPSResponse &response) const
{
    // Just in case a valid response was passed to the function
    if (response.get_status_code() == 200)
        return kSuccess;

    // Try to parse the error response
    // Details of Plaid error codes: https://plaid.com/docs/errors/
    try
    {
        ERROR_LOG("Plaid Error:\n%s", response.get_body().c_str());
        const JSON error_data = JSON::Load(response.get_body());
        const std::string error_type = error_data.get("error_type").String();
        std::string error_code;
        if (error_data.hasKey("error_code"))
            error_code = error_data.get("error_code").String();
        if (error_type == "API_ERROR")
            return kPlaidApiError;
        if (error_type == "INSTITUTION_ERROR")
        {
            if (error_code == "INSTITUTION_NO_LONGER_SUPPORTED")
                return kPlaidInstitutionNotSupported;
            return kPlaidInstitutionError;
        }
        if (error_type == "INVALID_INPUT")
            return kPlaidInvalidInput;
        if (error_type == "INVALID_REQUEST")
            return kPlaidInvalidRequest;
        if (error_type == "INVALID_RESULT")
            return kPlaidInvalidResult;
        if (error_type == "ITEM_ERROR")
        {
            if (error_code == "PRODUCT_NOT_READY" || error_code == "ITEM_PRODUCT_NOT_READY")
                return kPlaidProductNotReady;
            return kPlaidItemError;
        }
        if (error_type == "OAUTH_ERROR")
            return kPlaidOAuthError;
        if (error_type == "RATE_LIMIT_EXCEEDED")
            return kPlaidRateLimitExceeded;
        return kPlaidOtherError;
    }
    // If that fails just set the error by the HTTP status code
    catch (...)
    {
        const auto status_code = response.get_status_code();
        return get_HTTP_status(status_code);
    }

    return kHTTPStatusNot200;
}

PlaidLink PlaidClient::create_link_token(const std::string &client_user_id,
                                         const std::string &country)
{
    JSON request = default_request_body();
    request["client_name"] = "SILENTDATA";
    request["country_codes"] = json::Array(country);
    request["language"] = "en";
    JSON user = json::Object();
    user["client_user_id"] = client_user_id;
    request["user"] = user;
    request["products"] = json::Array("identity", "transactions");
    request["redirect_uri"] = redirect_uri_;

    // Make the HTTPS request
    DEBUG_LOG("Sending /link/token/create POST request to Plaid");
    const HTTPSResponse response = post("/link/token/create", request.dump());

    const JSON data = JSON::Load(response.get_body());

    PlaidLink link;
    link.token = data.get("link_token").String();
    link.expiration = data.get("expiration").String();
    link.request_id = data.get("request_id").String();
    return link;
}

void PlaidClient::get_access()
{
    JSON request = default_request_body();
    request["public_token"] = public_token_;

    DEBUG_LOG("Sending /item/public_token/exchange POST request to Plaid");
    const HTTPSResponse response = post("/item/public_token/exchange", request.dump());

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

void PlaidClient::destroy_access()
{
    set_close_session(true);

    DEBUG_LOG("Sending /item/remove POST request to Plaid");
    const HTTPSResponse response = post("/item/remove");

    const JSON data = JSON::Load(response.get_body());
    if (!data.hasKey("removed") || !data.get("removed").Bool())
        THROW_ERROR_CODE(kPlaidTokenDestructionError);

    access_token_.clear();
}

BankBalance PlaidClient::get_total_balance(const std::string &currency_code,
                                           const std::string &account_id)
{
    JSON request = default_request_body();
    // If we're matching a specific account
    if (account_id != "")
    {
        JSON options = json::Object();
        options["account_ids"] = json::Array(account_id);
        request["options"] = options;
    }

    DEBUG_LOG("Sending /accounts/balance/get POST request to Plaid");
    const HTTPSResponse response = post("/accounts/balance/get", request.dump());

    // Sum up all of the available balances
    const JSON data = JSON::Load(response.get_body());
    if (data.get("accounts").length() <= 0)
        THROW_EXCEPTION(kJSONParseError, "Could not find any bank accounts");

    std::string code;
    double available = 0;
    double current = 0;
    for (const auto &account : data.get("accounts").ArrayRange())
    {
        code = account.get("balances").get("iso_currency_code").ToString();
        if (code != currency_code)
        {
            WARNING_LOG("Currency code for this account doesn't match input, skipping...");
            continue;
        }
        available += account.get("balances").get("available").Number();
        current += account.get("balances").get("current").Number();
    }

    return BankBalance(currency_code, available, current);
}

std::vector<BankTransaction>
PlaidClient::get_transactions(const JSON &body, CoreStatusCode &error_code, int &total)
{
    error_code = kSuccess;

    DEBUG_LOG("Sending /transactions/get POST request to Plaid");
    std::vector<BankTransaction> transactions;
    HTTPSResponse response =
        HTTPSClient::post("/transactions/get", default_headers(true), body.dump());

    if (!response.is_valid())
        THROW_ERROR_CODE(kHTTPResponseParseError);
    if (response.get_status_code() != 200)
    {
        error_code = parse_error(response);
        WARNING_LOG("Error code %i returned by Plaid", error_code);
        if (error_code != kPlaidProductNotReady)
            THROW_ERROR_CODE(error_code);
        return transactions;
    }

    const JSON data = JSON::Load(response.get_body());

    // It's possible for there to be no transactions in the first 30 days (as we ignore the current
    // month), check if this is the case and return an empty vector if so
    total = static_cast<int>(data.get("total_transactions").Int());
    if (total == 0)
    {
        WARNING_LOG("No transactions in first 30 days");
        return transactions;
    }

    // Get the transactions of all associated accounts
    for (const auto &transaction : data.get("transactions").ArrayRange())
    {
        const std::string currency_code = transaction.get("iso_currency_code").ToString();
        if (currency_code.empty())
        {
            WARNING_LOG("Currency code for this transaction is missing, skipping...");
            continue;
        }

        const std::string date_str = transaction.get("date").String();
        const struct tm date = iso8601_to_tm(date_str);

        const double amount = transaction.get("amount").Number();
        const std::string name = transaction.get("name").String();
        // Negative transactions mean money coming in to the account
        transactions.push_back(BankTransaction(currency_code, -amount, date, name));
    }
    return transactions;
}

std::vector<BankTransaction> PlaidClient::get_all_transactions(struct tm start_date,
                                                               struct tm end_date,
                                                               const std::string &account_id)
{
    const std::string start_date_str = tm_to_iso8601(start_date);
    const std::string end_date_str = tm_to_iso8601(end_date);

    // Close the client after each connection because we might be waiting a while and that can
    // cause the peer to close the connection
    set_close_session(true);

    JSON request = default_request_body();
    JSON options = json::Object();
    int count = 50; // Number of transactions to get in one go
    int offset = 0;
    options["count"] = count;
    options["offset"] = offset;
    if (account_id != "")
        options["account_ids"] = json::Array(account_id);
    request["options"] = options;
    request["start_date"] = start_date_str;
    request["end_date"] = end_date_str;

    CoreStatusCode error_code = kSuccess;
    int total_transactions = 0;
    DEBUG_LOG("Getting the first page of transactions");
    std::vector<BankTransaction> transactions =
        get_transactions(request, error_code, total_transactions);
    // If the product isn't ready keep trying until it is
    while (error_code == kPlaidProductNotReady)
    {
        DEBUG_LOG("Product not ready, waiting 5 seconds and trying again");
        // Sleep for 5 seconds
        mbedtls_net_usleep(5000000);
        transactions = get_transactions(request, error_code, total_transactions);
    }

    // Now we're able to get transactions, but if all transactions aren't ready we'll only get the
    // first 30 days and plaid won't tell us about the rest
    // Two possible situations:
    // 1. We have all historical transactions and can continue
    // 2. We only have the first 30 days and need to wait until the historical transactions are
    // ready
    int days_fetched;
    try
    {
        const struct tm first_date = get_earliest_date(transactions);
        days_fetched = tm_day_difference(first_date, end_date);
    }
    catch (...)
    {
        WARNING_LOG(
            "Failed to calculate the difference in days between the first and last transaction");
        // An error here means that no transactions have been fetched
        days_fetched = 0;
    }
    DEBUG_LOG("Number of days fetched = %i", days_fetched);

    // Get the earliest available transaction (only if there are any transactions and we don't
    // already have three months worth)
    if (total_transactions > 0 && days_fetched <= 30)
    {
        DEBUG_LOG("Getting the first available transaction");
        request["options"]["count"] = 1;
        request["options"]["offset"] = total_transactions - 1;
        int temp_total;
        const std::vector<BankTransaction> first_transaction =
            get_transactions(request, error_code, temp_total);
        if (first_transaction.size() != 1)
            THROW_EXCEPTION(kJSONParseError, "Couldn't retrieve the first available transaction");
        days_fetched = tm_day_difference(first_transaction[0].date, end_date);
    }

    // If it looks like we've only got the first 30 days, wait 30 seconds and then request again
    // Check if the number of transactions has increased to signal that the historical data
    // has been fetched, try this up to a maximum of 10 times
    const int prev_total_transactions = total_transactions;
    int times_waited = 0;
    // Reset the request body count and offset
    request["options"]["count"] = count;
    request["options"]["offset"] = offset;
    while (total_transactions == prev_total_transactions && times_waited < 10 && days_fetched <= 30)
    {
        DEBUG_LOG("Historical transactions not available, waiting 30 seconds and trying again");
        mbedtls_net_usleep(30000000);
        transactions = get_transactions(request, error_code, total_transactions);
        times_waited++;
    }

    // If there are more transactions than "count", page through the transaction data until all
    // the transactions have been saved
    set_close_session(false);
    while (transactions.size() < static_cast<size_t>(total_transactions))
    {
        DEBUG_LOG("Not all transactions obtained, getting next page");
        const int current_offset = static_cast<int>(request["options"]["offset"].ToInt());
        request["options"]["offset"] = current_offset + count;
        const std::vector<BankTransaction> next_transactions =
            get_transactions(request, error_code, total_transactions);
        transactions.insert(transactions.end(), next_transactions.begin(), next_transactions.end());
    }

    return transactions;
}

std::map<std::string, AccountNumbers> PlaidClient::get_account_details()
{
    std::map<std::string, AccountNumbers> account_details;

    DEBUG_LOG("Sending /auth/get POST request to Plaid");
    const HTTPSResponse response = post("/auth/get");

    // Parse the response to get the account details of all associated accounts
    const JSON data = JSON::Load(response.get_body());
    const JSON &numbers = data.get("numbers");

    // Create objects containing account details
    if (numbers.hasKey("bacs") && numbers.get("bacs").length() > 0)
    {
        for (const auto &bacs : numbers.get("bacs").ArrayRange())
        {
            const std::string id = bacs.get("account_id").String();

            std::string account_number;
            if (bacs.hasKey("account"))
                account_number = bacs.get("account").ToString();
            if (account_number.empty())
                WARNING_LOG("Account number not provided");
            account_details[id].set_uk_account_number(account_number);

            std::string sort_code;
            if (bacs.hasKey("sort_code"))
                sort_code = bacs.get("sort_code").ToString();
            if (sort_code.empty())
                WARNING_LOG("Sort code not provided");
            account_details[id].set_uk_sort_code(sort_code);
        }
    }
    else
    {
        WARNING_LOG("No BACS bank number information present");
    }

    if (numbers.hasKey("international") && numbers.get("international").length() > 0)
    {
        for (const auto &international : numbers.get("international").ArrayRange())
        {
            const std::string id = international.get("account_id").String();

            std::string iban;
            if (international.hasKey("iban"))
                iban = international.get("iban").ToString();
            if (iban.empty())
                WARNING_LOG("IBAN not provided");
            account_details[id].set_iban(iban);

            std::string bic;
            if (international.hasKey("bic"))
                bic = international.get("bic").ToString();
            if (bic.empty())
                WARNING_LOG("BIC not provided");
            account_details[id].set_bic(bic);
        }
    }
    else
    {
        WARNING_LOG("No international bank number information present");
    }

    if (numbers.hasKey("ach") && numbers.get("ach").length() > 0)
    {
        for (const auto &ach : numbers.get("ach").ArrayRange())
        {
            const std::string id = ach.get("account_id").String();

            std::string account_number;
            if (ach.hasKey("account"))
                account_number = ach.get("account").ToString();
            if (account_number.empty())
                WARNING_LOG("Account number not provided");
            account_details[id].set_ach_account_number(account_number);

            std::string routing;
            if (ach.hasKey("routing"))
                routing = ach.get("routing").ToString();
            if (routing.empty())
                WARNING_LOG("Routing number is null");
            account_details[id].set_ach_routing(routing);

            std::string wire_routing;
            if (ach.hasKey("wire_routing"))
                wire_routing = ach.get("wire_routing").ToString();
            if (wire_routing.empty())
                WARNING_LOG("Wire routing number is null");
            account_details[id].set_ach_wire_routing(wire_routing);
        }
    }
    else
    {
        WARNING_LOG("No ACH bank number information present");
    }

    if (numbers.hasKey("eft") && numbers.get("eft").length() > 0)
    {
        for (const auto &eft : numbers.get("eft").ArrayRange())
        {
            std::string id = eft.get("account_id").String();
            std::string account_number;
            if (eft.hasKey("account"))
                account_number = eft.get("account").ToString();
            if (account_number.empty())
                WARNING_LOG("Account number is null");
            account_details[id].set_eft_account_number(account_number);

            std::string institution;
            if (eft.hasKey("institution"))
                institution = eft.get("institution").ToString();
            if (institution.empty())
                WARNING_LOG("Insitution number is null");
            account_details[id].set_eft_institution(institution);

            std::string branch;
            if (eft.hasKey("branch"))
                branch = eft.get("branch").ToString();
            if (branch.empty())
                WARNING_LOG("Branch number is null");
            account_details[id].set_eft_branch(branch);
        }
    }
    else
    {
        WARNING_LOG("No EFT bank number information present");
    }

    return account_details;
}

} // namespace enclave
} // namespace silentdata
