#include "clients/identity/instagram_client.hpp"

using json::JSON;

namespace silentdata
{
namespace enclave
{

InstagramClient::InstagramClient(const std::string &hostname,
                                 const std::string &client_id,
                                 const std::string &secret,
                                 uint32_t timestamp,
                                 const std::string &code,
                                 const std::string &redirect_uri)
    : OAuthAPIClient(hostname, client_id, secret, timestamp, {}), code_(code),
      redirect_uri_(redirect_uri)
{
}

InstagramClient::InstagramClient(const std::string &hostname,
                                 const APIConfig &config,
                                 const std::string &code)
    : InstagramClient(hostname,
                      config.client_id(),
                      config.secret(),
                      config.server_timestamp(),
                      code,
                      config.redirect_uri())
{
}

std::vector<std::string> InstagramClient::default_headers(bool post) const
{
    std::vector<std::string> headers;
    headers.push_back("Host: " + server_address());
    if (post)
        headers.push_back("Content-Type: application/x-www-form-urlencoded");
    return headers;
}

JSON InstagramClient::default_request_body() const { return json::Object(); }

Optional<std::string> InstagramClient::parse_error_type(const HTTPSResponse &response) const
{
    const auto error_data = parse_json(response);

    // Sometimes error type is under the "error_type" key
    if (error_data.hasKey("error_type"))
        return error_data.get("error_type").String();

    // Other times its under "error.type"
    if (error_data.hasKey("error"))
    {
        const auto error_data_error = error_data.get("error");
        if (error_data_error.hasKey("type"))
            return error_data_error.get("type").String();
    }

    return Optional<std::string>();
}

CoreStatusCode InstagramClient::parse_error(const HTTPSResponse &response) const
{
    // Just in case a valid response was passed to the function
    if (response.get_status_code() == 200)
        return kSuccess;

    try
    {
        ERROR_LOG(
            "Instagram Error (%i):\n%s", response.get_status_code(), response.get_body().c_str());

        const auto error_type_opt = parse_error_type(response);

        if (!error_type_opt.has_value())
            return get_HTTP_status(response.get_status_code());

        const auto &error_type = error_type_opt.value();
        if (error_type == "OAuthException")
            return kInstagramOAuthException;

        if (error_type == "IGApiException")
            return kInstagramIGApiException;

        return kInstagramOtherError;
    }
    catch (...)
    {
        const auto status_code = response.get_status_code();
        return get_HTTP_status(status_code);
    }

    return kHTTPStatusNot200;
}

void InstagramClient::get_access()
{
    set_subdomain("api");

    JSON request = default_request_body();
    request["client_id"] = client_id_;
    request["client_secret"] = secret_;
    request["grant_type"] = "authorization_code";
    request["redirect_uri"] = redirect_uri_;
    request["code"] = code_;

    DEBUG_LOG("Sending /oauth/access_token POST request to Instagram");
    const std::string request_form = json_to_form_encoding(request);
    const HTTPSResponse response = post("/oauth/access_token", request_form);

    const JSON data = parse_json(response);
    access_token_ = data.get("access_token").String();
    user_id_ = std::to_string(data.get("user_id").Int());
}

void InstagramClient::destroy_access()
{
    access_token_.clear();
    user_id_.clear();
}

std::string InstagramClient::get_username()
{
    if (access_token_.empty() || user_id_.empty())
        THROW_EXCEPTION(kInvalidInput,
                        "Can't get username from Instagram as no acccess token is set. Please "
                        "first call `get_access()`");

    set_subdomain("graph");

    const std::string url = "/" + user_id_ + "?access_token=" + access_token_ + "&fields=username";
    DEBUG_LOG("Sending GET request to Instagram");
    const HTTPSResponse response = get(url);

    const JSON data = parse_json(response);
    return data.get("username").String();
}

} // namespace enclave
} // namespace silentdata
