#include "clients/invoices/crossflow_client.hpp"
#include "clients/invoices/crossflow_certificate.h"

#include "lib/common/date_time.hpp"
#include "lib/common/decoders.hpp"

using json::JSON;

namespace silentdata
{
namespace enclave
{

CrossflowClient::CrossflowClient(const std::string &hostname, const uint32_t timestamp)
    : APIClient(hostname, "", timestamp, {crossflow_certificate}),
      api_prefix_("/api/v1/crossflow-mock")
{
}

void CrossflowClient::set_api_prefix(const std::string &api_prefix) { api_prefix_ = api_prefix; }

void CrossflowClient::get_access(const std::string &email, const std::string &password)
{
    const std::string token_key = "token";

    const std::string error_message = "An error occured during POST request to Crossflow server:\n"
                                      "  - Endpoint: /auth/login";

    auto body = json::Object();
    body["email"] = email;
    body["password"] = password;

    DEBUG_LOG("Sending POST request to %s", (api_prefix_ + "/auth/login").c_str());
    try
    {
        const auto response = post(api_prefix_ + "/auth/login", body.dump());
        const auto response_json = parse_json(response);

        if (!response_json.hasKey(token_key))
            THROW_EXCEPTION(kJSONKeyError,
                            "Response from Crossflow missing key \"" + token_key + "\"");

        secret_ = response_json.get(token_key).String();
    }
    catch (const EnclaveException &e)
    {
        THROW_EXCEPTION(e.get_code(), error_message + "\n  - Error: " + std::string(e.what()));
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

CoreStatusCode CrossflowClient::parse_error(const HTTPSResponse &response) const
{
    if (response.get_status_code() == 200)
        return kSuccess;

    // Crossflow doesn't give a custom error code, default to generic HTTP status
    const auto status_code = response.get_status_code();
    return get_HTTP_status(status_code);
}

std::vector<std::string> CrossflowClient::default_headers(bool post) const
{
    std::vector<std::string> headers;

    headers.push_back("Host: " + server_address());
    headers.push_back("Accept: application/json");
    if (post)
        headers.push_back("Content-Type: application/json");

    if (!secret_.empty())
        headers.push_back("Authorization: Bearer " + secret_);

    return headers;
}

json::JSON CrossflowClient::default_request_body() const { return json::Object(); }

Optional<CrossflowClient::CrossflowInvoice>
CrossflowClient::get_invoice(const std::string &cf_request_id)
{
    if (secret_.empty())
        THROW_EXCEPTION(kInvalidInput,
                        "Can't get invoice from Crossflow as no acccess token is set. Please first "
                        "call `get_access(email, password)`");

    const std::string buyer_key = "buyer";
    const std::string buyer_id_key = "buyerId";
    const std::string currency_key = "currency";
    const std::string financeable_total_key = "financeableTotal";
    const std::string credit_rating_key = "creditRating";
    const std::string interest_rate_key = "interestRate";
    const std::string tenor_key = "tenor";
    const std::string destination_pubkey_key = "destinationPublicKey";

    const std::vector<std::string> keys = {buyer_key,
                                           buyer_id_key,
                                           currency_key,
                                           financeable_total_key,
                                           credit_rating_key,
                                           interest_rate_key,
                                           tenor_key,
                                           destination_pubkey_key};

    const std::string error_message = "An error occured during GET request to Crossflow server:\n"
                                      "  - Endpoint: /invoices/" +
                                      cf_request_id;

    CrossflowInvoice invoice;

    DEBUG_LOG("Sending GET request to %s", (api_prefix_ + "/invoices/" + cf_request_id).c_str());
    try
    {
        const auto response = get(api_prefix_ + "/invoices/" + cf_request_id);
        const auto response_json = parse_json(response);

        for (const auto &key : keys)
        {
            if (!response_json.hasKey(key))
                THROW_EXCEPTION(kJSONKeyError,
                                "Response from Crossflow missing key \"" + key + "\"");
        }

        invoice.buyer = response_json.get(buyer_key).String();
        invoice.buyer_id = static_cast<int>(response_json.get(buyer_id_key).Int());
        invoice.currency = response_json.get(currency_key).String();
        invoice.financeable_total = response_json.get(financeable_total_key).Number();
        invoice.credit_rating = response_json.get(credit_rating_key).String();
        invoice.interest_rate = response_json.get(interest_rate_key).Number();
        invoice.tenor = static_cast<int>(response_json.get(tenor_key).Int());
        invoice.timestamp = tm_to_timestamp(http_date_to_tm(response.get_timestamp()));
        const std::string destination_pubkey_str =
            hex_decode(response_json.get(destination_pubkey_key).String());
        if (destination_pubkey_str.size() != invoice.destination_pubkey.size())
            THROW_EXCEPTION(kOutputOverflow, "Destination public key is the wrong size");
        std::copy(destination_pubkey_str.begin(),
                  destination_pubkey_str.end(),
                  invoice.destination_pubkey.data());
    }
    catch (const EnclaveException &e)
    {
        if (e.get_code() == kHTTPStatus404)
            return Optional<CrossflowClient::CrossflowInvoice>();

        THROW_EXCEPTION(e.get_code(), error_message + "\n  - Error: " + std::string(e.what()));
    }
    catch (const std::exception &e)
    {
        THROW_EXCEPTION(kHTTPRequestError, error_message + "\n  - Error: " + std::string(e.what()));
    }
    catch (...)
    {
        THROW_EXCEPTION(kHTTPRequestError, error_message);
    }

    return invoice;
}

} // namespace enclave
} // namespace silentdata
