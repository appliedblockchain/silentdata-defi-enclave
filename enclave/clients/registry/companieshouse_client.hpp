/*
 *  Companies house registry client
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

class CompaniesHouseClient : public APIClient
{
private:
    std::vector<std::string> default_headers(bool post = false) const;
    json::JSON default_request_body() const;

    Optional<std::string> get_error_string(const json::JSON &error_data) const;

    void set_date_from_string(const std::string &date_string, struct tm &date) const;

    std::string get_sanitized_name(const std::string &name) const;

    void ensure_json_content_type(const HTTPSResponse &response) const;

    HTTPSResponse get_search_response(const std::string &query, const size_t page_number);

    static constexpr size_t items_per_page_ = 20u;
    static constexpr size_t max_pages_ = 5u;

    static constexpr const char *items_key_ = "items";
    static constexpr const char *title_key_ = "title";
    static constexpr const char *company_status_key_ = "company_status";
    static constexpr const char *creation_date_key_ = "date_of_creation";

public:
    CompaniesHouseClient(const std::string &hostname,
                         const std::string &api_key,
                         const uint32_t timestamp,
                         const std::vector<std::string> &allowed_certificates = {});

    ~CompaniesHouseClient() {}

    CoreStatusCode parse_error(const HTTPSResponse &response) const;

    Optional<CompanyProfile> get_company_by_name(const std::string &name);
};

} // namespace enclave
} // namespace silentdata
