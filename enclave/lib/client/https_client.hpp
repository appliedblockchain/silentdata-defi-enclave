/*
 *  SSL client with certificate authentication
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

/*
 * Modified 2020-11-30 tgrbrooks
 */

#pragma once

#include <cstring>
#include <math.h>
#include <numeric>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <vector>

#include "mbedtls/certs.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/net.h"
#include "mbedtls/pem.h"
#include "mbedtls/ssl.h"
#include "mbedtls/x509.h"

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_printf printf
#define mbedtls_fprintf fprintf
#define mbedtls_snprintf snprintf
#endif

#include "include/core_constants.h"

#include "lib/client/cacert.hpp"
#include "lib/client/client_opt.h"
#include "lib/client/httpresponseparser.h"
#include "lib/client/https_response.hpp"
#include "lib/client/response.h"
#include "lib/common/date_time.hpp"
#include "lib/common/enclave_logger.hpp"

namespace silentdata
{
namespace enclave
{

// Wraps up the MBED TLS SSL client functionality so the memory is cleaned up
// automatically when it goes out of scope.
// The get() and post() methods are used to send GET and POST HTTPS requests
// Example:
//    client_options opt;
//    opt.server_port = "443";
//    HTTPSClient client("hostname", opt);
//    std::vector<char *> headers = {"Host: hostname"};
//    HTTPSResponse response = client.get("/endpoint/name", headers, opt);
class HTTPSClient
{
public:
    HTTPSClient(HTTPSClient &&) = delete;
    HTTPSClient &operator=(HTTPSClient &&) = delete;

    // Constructor
    explicit HTTPSClient(const std::string &server,
                         const ClientOptions &opt,
                         const std::vector<std::string> &certificates = {});
    // Destructor
    ~HTTPSClient();

    // Send a GET request and parse the response
    HTTPSResponse
    get(const std::string &endpoint, const std::vector<std::string> &headers, ClientOptions opt);
    HTTPSResponse get(const std::string &endpoint, const std::vector<std::string> &headers);
    // Send a POST request and parse the response
    HTTPSResponse post(const std::string &endpoint,
                       const std::vector<std::string> &headers,
                       const std::string &body,
                       ClientOptions opt);
    HTTPSResponse post(const std::string &endpoint,
                       const std::vector<std::string> &headers,
                       const std::string &body);
    // Send a DELETE request and parse the response
    HTTPSResponse
    del(const std::string &endpoint, const std::vector<std::string> &headers, ClientOptions opt);
    HTTPSResponse del(const std::string &endpoint, const std::vector<std::string> &headers);

    // Obtain a copy of the client configuration options
    const ClientOptions &get_client_options() const { return opt_; }

    // Public setters
    void set_server(const std::string &server);
    void set_subdomain(const std::string &subdomain);
    void set_server_port(const char *port) { opt_.server_port = port; }
    void set_read_timeout(uint32_t timeout);
    void set_certificates(const std::vector<std::string> &certificates);
    void set_close_session(bool close) { opt_.close_session = close; }

    std::string server_address() const;
    const std::string &get_api_common_name() const { return api_common_name_; }
    std::string get_leaf_certificate() const;

protected:
    HTTPSClient();
    void set_options(const ClientOptions &opt) { opt_ = opt; }

private:
    bool config_changed_;
    // Name of the remote server
    std::string server_;
    std::string subdomain_;
    // Configuration options (allowed options in client_opt.h)
    ClientOptions opt_;
    // Pinned leaf certificates that this client will connect to
    std::string pinned_certificates_;
    // HTTP headers
    std::vector<std::string> headers_;
    // HTTP request body
    const char *request_body_;
    // Output buffer with maximum size
    unsigned char *output_;
    unsigned char *output_start_;
    // The remote server certificate chain in PEM format;
    std::string certificate_chain_str_;
    // The common name for the leaf certificate
    std::string api_common_name_;
    // Has a SSL session been saved
    bool session_saved_;
    // Has the SSL session been closed
    bool session_closed_;
    // Has the initial setup been completed
    bool initial_setup_;
    // Has the memory been initialised;
    bool mbedtls_initialised_;

    // MBED TLS objects
    mbedtls_net_context server_fd_;
    mbedtls_entropy_context entropy_;
    mbedtls_ctr_drbg_context ctr_drbg_;
    mbedtls_ssl_context ssl_;
    mbedtls_ssl_config conf_;
    mbedtls_ssl_session saved_session_;
    mbedtls_x509_crt cacert_;

    // Initialise mbedtls objects
    void mbedtls_init();
    // Free the memory of mbedtls objects
    void mbedtls_free();
    // Reset the member variables so a new request can be made
    void configure_and_send(const ClientOptions &opt,
                            const std::vector<std::string> &headers,
                            const char *request_body);
    // Call all of the member functions required to run the client
    void run_client();
    // Perform all set up and configuration steps required to make request
    void setup_for_request();
    //  Initialize the random number generator (CRT-DRBG) with a source of
    //  entropy
    void initialise_random_generator();
    //  Load the trusted CA certificates
    void load_certificates();
    //  Start the connection to the server in the specified transport mode
    void start_connection();
    //  Setup the SSL client configurations
    void configure_ssl();
    //  Perform SSL handshake and save the session if reconnecting
    void perform_handshake();
    // Return the certificate chain of the server
    std::string get_certificate_chain() const;
    // Get the result of the certificate verification and print the peer
    // certificate contents if debugging
    void verify_certificate() const;
    // Write the GET request and read the HTTP response
    void send_request();
    // Close the connection if not already done
    void close_notify();
    //  Reconnect if allowed by configuration, otherwise exit
    void reconnect();

    const char *request_start() const;
    const char *request_end() const;

    // Check the certificate chain expiration dates against a provided timestamp
    bool check_certificate_expiration(const mbedtls_x509_crt *cert) const;
    // Check the certificate chain expiration dates against a provided timestamp
    std::string get_certificate_subject_cn(const mbedtls_x509_crt *cert) const;
    // Parse a HTTP response from a HTTPS client to obtain the body
    struct HTTPParseResult
    {
        httpparser::HttpResponseParser::ParseResult status;
        httpparser::Response response;
        HTTPParseResult(httpparser::HttpResponseParser::ParseResult s, httpparser::Response r)
            : status(s), response(r)
        {
        }
    };
    HTTPParseResult parse_http(unsigned char *buffer) const;
    // Compare server certificate to allowed pinned certificates
    static int pinned_verify(void *pinned_chain, mbedtls_x509_crt *crt, int depth, uint32_t *flags);
};

} // namespace enclave
} // namespace silentdata
