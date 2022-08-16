#include "lib/client/https_response.hpp"

namespace silentdata
{
namespace enclave
{

std::string HTTPSResponse::get_body() const
{
    std::string body = "";
    if (http_response_.content.size() > 0)
    {
        body = std::string(http_response_.content.data(), http_response_.content.size());
    }
    return body;
}

// Parse a HTTP response to get the timestamp from the header
std::string HTTPSResponse::get_timestamp() const
{
    std::string timestamp;
    for (const auto &header : http_response_.headers)
    {
        if (header.name == "Date")
            timestamp = header.value;
    }
    return timestamp;
}

} // namespace enclave
} // namespace silentdata
