#include "clients/api_client/api_client.hpp"

using json::JSON;

namespace silentdata
{
namespace enclave
{

APIClient::APIClient(const std::string &host,
                     const std::string &secret,
                     uint32_t timestamp,
                     const std::vector<std::string> &allowed_certificates)
    : host_(host), secret_(secret)
{
    set_server(host_);
    ClientOptions opt;
    opt.server_port = "443";
    opt.timestamp = timestamp;
    set_options(opt);
    if (allowed_certificates.size() != 0)
        set_certificates(allowed_certificates);
}

HTTPSResponse APIClient::get(const std::string &endpoint)
{
    return get(endpoint, default_headers());
}

HTTPSResponse APIClient::get(const std::string &endpoint, const std::vector<std::string> &headers)
{
    HTTPSResponse response = HTTPSClient::get(endpoint, headers);
    if (!response.is_valid())
        THROW_ERROR_CODE(kHTTPResponseParseError);
    if (response.get_status_code() != 200)
    {
        THROW_ERROR_CODE(parse_error(response));
    }
    return response;
}

HTTPSResponse APIClient::post(const std::string &endpoint)
{
    const JSON body = default_request_body();
    return post(endpoint, body.dump(), default_headers(true));
}

HTTPSResponse APIClient::post(const std::string &endpoint, const std::string &body)
{
    return post(endpoint, body, default_headers(true));
}

HTTPSResponse APIClient::post(const std::string &endpoint,
                              const std::string &body,
                              const std::vector<std::string> &headers)
{
    HTTPSResponse response = HTTPSClient::post(endpoint, headers, body);
    if (!response.is_valid())
    {
        THROW_ERROR_CODE(kHTTPResponseParseError);
    }
    if (response.get_status_code() != 200)
        THROW_ERROR_CODE(parse_error(response));
    return response;
}

void APIClient::del(const std::string &endpoint) { return del(endpoint, default_headers()); }

void APIClient::del(const std::string &endpoint, const std::vector<std::string> &headers)
{
    HTTPSResponse response = HTTPSClient::del(endpoint, headers);
    if (!response.is_valid())
        THROW_ERROR_CODE(kHTTPResponseParseError);
    if (response.get_status_code() != 200)
        THROW_ERROR_CODE(parse_error(response));
}

CoreStatusCode APIClient::get_HTTP_status(const int status_code) const
{
    switch (status_code)
    {
    case 400:
        return kHTTPStatus400;
    case 401:
        return kHTTPStatus401;
    case 403:
        return kHTTPStatus403;
    case 404:
        return kHTTPStatus404;
    case 405:
        return kHTTPStatus405;
    case 408:
        return kHTTPStatus408;
    case 500:
        return kHTTPStatus500;
    case 503:
        return kHTTPStatus503;
    default:
        break;
    }

    if (status_code >= 400 && status_code <= 499)
        return kHTTPStatus4xx;

    if (status_code >= 500 && status_code <= 599)
        return kHTTPStatus5xx;

    return kHTTPStatusNot200;
}

JSON APIClient::parse_json(const HTTPSResponse &response) const
{
    const std::string error_message =
        "Issue parsing response from server as JSON. Response:\n" + response.get_body();
    try
    {
        const auto output = JSON::Load(response.get_body());

        if (output.IsNull())
            THROW_EXCEPTION(kJSONParseError, error_message + "\nParsed response is null");

        return output;
    }
    catch (const std::exception &e)
    {
        THROW_EXCEPTION(kJSONParseError, error_message + "\nError: " + std::string(e.what()));
    }
    catch (...)
    {
    }
    THROW_EXCEPTION(kJSONParseError, error_message);
}

std::string APIClient::json_to_form_encoding(const JSON &data) const
{
    std::string output = "";

    for (const auto &entry : data.ObjectRange())
    {
        const std::string key = entry.first;
        const JSON value = entry.second;

        const auto value_type = value.JSONType();
        if (value_type == JSON::Class::Object || value_type == JSON::Class::Array)
            THROW_EXCEPTION(kInvalidInput, "Form encoding of Object and Array types not supported");

        std::string value_string = value.dump(0, "");

        // Remove the quotes from the string
        if (value_type == JSON::Class::String)
        {
            if (value_string.length() < 2)
                THROW_EXCEPTION(kInvalidInput, "JSON dumped string has fewer than 2 characters");

            if (value_string.front() != '"')
                THROW_EXCEPTION(kInvalidInput,
                                "JSON dumped string has character at front isn't \"");

            if (value_string.back() != '"')
                THROW_EXCEPTION(kInvalidInput, "JSON dumped string has character at back isn't \"");

            value_string = value_string.substr(1, value_string.length() - 2);
        }

        if (!output.empty())
            output += "&";

        output += key + "=" + value_string;
    }

    return output;
}

} // namespace enclave
} // namespace silentdata
