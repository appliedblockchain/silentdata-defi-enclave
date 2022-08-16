#include "clients/accounting/xero_client.hpp"

using json::JSON;

namespace silentdata
{
namespace enclave
{

XeroClient::XeroClient(const std::string &hostname,
                       const std::string &client_id,
                       const std::string &secret,
                       uint32_t timestamp,
                       const std::string &code,
                       const std::string &code_verifier,
                       const std::string &redirect_uri,
                       const std::string &refresh_token,
                       const std::vector<std::string> &allowed_certificates)
    : OAuthAPIClient(hostname, client_id, secret, timestamp, allowed_certificates), code_(code),
      code_verifier_(code_verifier), redirect_uri_(redirect_uri), refresh_token_(refresh_token)
{
}

XeroClient::XeroClient(const std::string &hostname,
                       const APIConfig &config,
                       const std::string &code,
                       const std::string &code_verifier,
                       const std::vector<std::string> &input_certificates)
    : XeroClient(hostname,
                 config.client_id(),
                 config.secret(),
                 config.server_timestamp(),
                 code,
                 code_verifier,
                 config.redirect_uri(),
                 "",
                 input_certificates)
{
}

XeroClient::XeroClient(const std::string &hostname,
                       const APIConfig &config,
                       const std::string &refresh_token)
    : XeroClient(hostname,
                 config.client_id(),
                 config.secret(),
                 config.server_timestamp(),
                 "",
                 "",
                 "",
                 refresh_token)
{
}

XeroClient::~XeroClient()
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

std::vector<std::string> XeroClient::default_headers(bool post) const
{
    std::vector<std::string> headers;
    headers.push_back("Host: " + server_address());
    if (post)
        headers.push_back("Content-Type: application/x-www-form-urlencoded");
    if (access_token_.length() != 0)
        headers.push_back("Authorization: Bearer " + access_token_);
    if (tenant_id_.length() != 0)
        headers.push_back("xero-tenant-id: " + tenant_id_);
    return headers;
}

JSON XeroClient::default_request_body() const
{
    JSON request = json::Object();
    request["client_id"] = client_id_;
    if (access_token_.length() != 0)
        request["access_token"] = access_token_;
    return request;
}

CoreStatusCode XeroClient::parse_error(const HTTPSResponse &response) const
{
    // Just in case a valid response was passed to the function
    if (response.get_status_code() == 200)
        return kSuccess;

    // Try to parse the error response
    // Details of Xero error codes:
    // https://developer.xero.com/documentation/guides/oauth2/troubleshooting/
    try
    {
        ERROR_LOG("Xero Error:\n%s", response.get_body().c_str());
        const JSON error_data = json::JSON::Load(response.get_body());
        const std::string error_code = error_data.at("error").ToString();
        if (error_code == "invalid_grant")
            return kXeroInvalidCode;
        if (error_code == "invalid_client")
            return kXeroInvalidClientId;
        if (error_code == "unauthorized_client")
            return kXeroInvalidRedirectUri;
        if (error_code == "unsupported_grant_type")
            return kXeroInvalidGrantType;
        return kXeroOtherError;
    }
    // If that fails just set the error by the HTTP status code
    catch (...)
    {
        const auto status_code = response.get_status_code();
        return get_HTTP_status(status_code);
    }

    return kHTTPStatusNot200;
}

void XeroClient::post_connect_token(const std::string &body)
{
    set_subdomain("identity");

    DEBUG_LOG("Sending /connect/token POST request to Xero");
    const HTTPSResponse response = post("/connect/token", body);

    const JSON data = JSON::Load(response.get_body());

    access_token_ = data.get("access_token").String();
    refresh_token_ = data.get("refresh_token").String();

    // Parse the response to get the timestamp
    last_timestamp_ = response.get_timestamp();

    // Check that a certificate chain was obtained
    last_certificate_chain_ = response.get_certificate_chain();
    if (last_certificate_chain_.length() == 0)
        THROW_EXCEPTION(kCertificateWriteError,
                        "Could not obtain the certificate chain from the HTTPS client");

    // Get the tenant ID
    const std::vector<std::string> tenant_ids = get_tenant_ids();
    if (tenant_ids.size() != 1)
        THROW_EXCEPTION(kClientConnectionError,
                        "Invalid number of tenants connected (should be 1)");
    tenant_id_ = tenant_ids.at(0);
}

void XeroClient::get_access()
{
    const std::string request =
        "grant_type=authorization_code&client_id=" + url_encode(client_id_) +
        "&code=" + url_encode(code_) + "&redirect_uri=" + url_encode(redirect_uri_) +
        "&code_verifier=" + url_encode(code_verifier_);
    post_connect_token(request);
}

void XeroClient::refresh_access()
{
    const std::string request = "grant_type=refresh_token&client_id=" + url_encode(client_id_) +
                                "&refresh_token=" + url_encode(refresh_token_);
    post_connect_token(request);
}

void XeroClient::destroy_access()
{
    set_subdomain("identity");
    set_close_session(true);

    const std::string request = "token=" + url_encode(refresh_token_);

    std::vector<std::string> headers;
    headers.push_back("Host: " + server_address());
    headers.push_back("Content-Type: application/x-www-form-urlencoded");
    headers.push_back("Authorization: Basic " + b64_encode(client_id_ + ":"));

    DEBUG_LOG("Sending /connect/revocation POST request to Xero");
    post("/connect/revocation", request, headers);

    access_token_.clear();
    refresh_token_.clear();
    tenant_id_.clear();
}

std::vector<std::string> XeroClient::get_tenant_ids()
{
    set_subdomain("api");

    DEBUG_LOG("Sending /connections GET request to Xero");
    const HTTPSResponse response = get("/connections");

    const JSON data = JSON::Load("{\"tenants\": " + response.get_body() + "}");
    std::vector<std::string> tenant_ids;
    for (const auto &tenant : data.get("tenants").ArrayRange())
    {
        tenant_ids.push_back(tenant.get("tenantId").String());
    }

    return tenant_ids;
}

Invoice XeroClient::parse_invoice(const json::JSON &data) const
{
    Invoice invoice;

    const std::string date = data.get("DateString").String();
    invoice.date = iso8601_to_tm(date);
    const std::string due_date = data.get("DueDateString").String();
    invoice.due_date = iso8601_to_tm(due_date);

    // ATTN multiplication by 100 to convert from units of currency_code (e.g. USD) to ->
    // currency_code / 100 (e.g. cents)
    const double amount = std::floor(100 * data.get("Total").Float());
    if (amount < 0)
        THROW_EXCEPTION(kUIntUnderflow, "Invoice amount is negative");
    if (amount > CORE_MAX_SAFE_INTEGER)
        THROW_EXCEPTION(kIntegerOverflow, "Invoice amount larger than MAX_SAFE_INTEGER");
    invoice.amount = static_cast<uint64_t>(amount);

    invoice.currency_code = data.get("CurrencyCode").String();
    invoice.payer = data.get("Contact").at("Name").String();
    invoice.id = data.get("InvoiceID").String();

    return invoice;
}

Invoice XeroClient::get_invoice(const std::string &invoice_id)
{
    set_subdomain("api");

    DEBUG_LOG("Sending /Invoices/{invoice_id} GET request to Xero");
    const HTTPSResponse response = get("/api.xro/2.0/Invoices/" + invoice_id);

    const JSON data = JSON::Load(response.get_body());
    if (!data.hasKey("Invoices") || data.get("Invoices").length() != 1)
        THROW_EXCEPTION(kJSONParseError, "No invoice (or too many) found");

    return parse_invoice(data.get("Invoices").at(0));
}

std::vector<Invoice> XeroClient::get_invoices()
{
    set_subdomain("api");

    DEBUG_LOG("Sending /Invoices GET request to Xero");
    const HTTPSResponse response = get("/api.xro/2.0/Invoices?summaryOnly=True&page=1");

    const JSON data = JSON::Load(response.get_body());

    std::vector<Invoice> invoices;
    for (const auto &invoice : data.get("Invoices").ArrayRange())
    {
        const double amount_paid = invoice.get("AmountPaid").Float();
        if (amount_paid > 0)
            continue;
        const std::string due_date = invoice.get("DueDateString").String();
        const uint32_t due_date_timestamp = tm_to_timestamp(iso8601_to_tm(due_date));
        const std::string current_time = get_timestamp();
        const uint32_t current_timestamp = tm_to_timestamp(http_date_to_tm(current_time));
        if (due_date_timestamp < current_timestamp)
            continue;

        invoices.push_back(parse_invoice(invoice));
    }

    return invoices;
}

} // namespace enclave
} // namespace silentdata
