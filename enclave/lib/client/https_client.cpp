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

#include "lib/client/https_client.hpp"

namespace
{

// Calculate the time in seconds from Jan 01 1970 (UTC)
int utc_unix_timestamp(const mbedtls_x509_time &time)
{
    struct tm date = {};
    date.tm_year = time.year - 1900;
    date.tm_mon = time.mon - 1;
    date.tm_mday = time.day;
    date.tm_hour = time.hour;
    date.tm_min = time.min;
    date.tm_sec = time.sec;
    return silentdata::enclave::tm_to_timestamp(date);
}

void print_mbedtls_error(const char *name, int ret)
{
    if (ret != 0)
    {
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, 100);
        ERROR_LOG("%s returned with error: -0x%X - %s", name, -ret, error_buf);
    }
}

static void
mbedtls_debug(void * /*unused_ctx*/, int level, const char *file, int line, const char *str)
{
    const char *p, *basename;

    /* Extract basename from file */
    for (p = basename = file; *p != '\0'; p++)
    {
        if (*p == '/' || *p == '\\')
        {
            basename = p + 1;
        }
    }

    DEBUG_LOG("%s:%04d: |%d| %s", basename, line, level, str);
}

} // namespace

namespace silentdata
{
namespace enclave
{

// Constructor
HTTPSClient::HTTPSClient(const std::string &server,
                         const ClientOptions &opt,
                         const std::vector<std::string> &certificates)
    : server_(server), opt_(opt)
{
    config_changed_ = false;
    request_body_ = NULL;
    output_ = static_cast<unsigned char *>(malloc(MBEDTLS_SSL_MAX_CONTENT_LEN));
    output_start_ = output_;
    session_saved_ = false;
    session_closed_ = true;
    initial_setup_ = false;
    mbedtls_initialised_ = false;
    for (const auto &cert : certificates)
        pinned_certificates_ += cert;

    // Make sure memory references of MBED TLS objects are valid.
    mbedtls_init();

    // Set the debugging information level if MBEDTLS debugging available
#if defined(MBEDTLS_DEBUG_C)
    ERROR_LOG("MBEDTLS_DEBUG_C defined");
    mbedtls_debug_set_threshold(opt_.debug_level);
#endif
}

// Constructor
HTTPSClient::HTTPSClient()
{
    config_changed_ = false;
    request_body_ = NULL;
    output_ = static_cast<unsigned char *>(malloc(MBEDTLS_SSL_MAX_CONTENT_LEN));
    output_start_ = output_;
    session_saved_ = false;
    session_closed_ = true;
    initial_setup_ = false;
    mbedtls_initialised_ = false;

    // Make sure memory references of MBED TLS objects are valid.
    mbedtls_init();

    // Set the debugging information level if MBEDTLS debugging available
#if defined(MBEDTLS_DEBUG_C)
    mbedtls_debug_set_threshold(opt_.debug_level);
#endif
}

// Destructor
HTTPSClient::~HTTPSClient()
{
    // Make sure the TLS connection has been closed without trying to reconnect
    if (!session_closed_)
    {
        opt_.reconnect = 0;
        close_notify();
    }
    // Clean up the MBED TLS object memory
    mbedtls_free();

    std::free(output_start_);
}

// Send a GET request and parse the response
HTTPSResponse HTTPSClient::get(const std::string &endpoint,
                               const std::vector<std::string> &headers,
                               ClientOptions opt)
{
    opt.request_type = GET_REQUEST_TYPE;
    opt.request_page = endpoint.c_str();
    const char *body = "";
    try
    {
        configure_and_send(opt, headers, body);
    }
    catch (const EnclaveException &e)
    {
        if (mbedtls_initialised_)
            mbedtls_free();
        EXCEPTION_LOG(e);
        THROW_EXCEPTION(e.get_code(), "Sending GET request failed");
    }

    bool parse_valid = true;
    const HTTPParseResult parse_result = parse_http(output_start_);
    if (parse_result.status != httpparser::HttpResponseParser::ParsingCompleted)
        parse_valid = false;
    // Return the response and certificate_chain from the server
    return HTTPSResponse(parse_result.response, certificate_chain_str_, parse_valid);
}

HTTPSResponse HTTPSClient::get(const std::string &endpoint, const std::vector<std::string> &headers)
{
    return get(endpoint, headers, opt_);
}

// Send a POST request and parse the response
HTTPSResponse HTTPSClient::post(const std::string &endpoint,
                                const std::vector<std::string> &headers,
                                const std::string &body,
                                ClientOptions opt)
{
    opt.request_type = POST_REQUEST_TYPE;
    opt.request_page = endpoint.c_str();
    try
    {
        configure_and_send(opt, headers, body.c_str());
    }
    catch (const EnclaveException &e)
    {
        if (mbedtls_initialised_)
            mbedtls_free();
        EXCEPTION_LOG(e);
        THROW_EXCEPTION(e.get_code(), "Sending POST request failed");
    }

    bool parse_valid = true;
    const HTTPParseResult parse_result = parse_http(output_start_);
    if (parse_result.status != httpparser::HttpResponseParser::ParsingCompleted)
        parse_valid = false;
    // Return the response and certificate_chain from the server
    return HTTPSResponse(parse_result.response, certificate_chain_str_, parse_valid);
}

HTTPSResponse HTTPSClient::post(const std::string &endpoint,
                                const std::vector<std::string> &headers,
                                const std::string &body)
{
    return post(endpoint, headers, body, opt_);
}

void HTTPSClient::set_certificates(const std::vector<std::string> &certificates)
{
    pinned_certificates_.clear();
    for (const auto &cert : certificates)
        pinned_certificates_ += cert;
}

// Send a DELETE request and parse the response
HTTPSResponse HTTPSClient::del(const std::string &endpoint,
                               const std::vector<std::string> &headers,
                               ClientOptions opt)
{
    opt.request_type = DELETE_REQUEST_TYPE;
    opt.request_page = endpoint.c_str();
    const char *body = "";
    try
    {
        configure_and_send(opt, headers, body);
    }
    catch (const EnclaveException &e)
    {
        if (mbedtls_initialised_)
            mbedtls_free();
        EXCEPTION_LOG(e);
        THROW_EXCEPTION(e.get_code(), "Sending DELETE request failed");
    }

    bool parse_valid = true;
    const HTTPParseResult parse_result = parse_http(output_start_);
    if (parse_result.status != httpparser::HttpResponseParser::ParsingCompleted)
        parse_valid = false;
    // Return the response and certificate_chain from the server
    return HTTPSResponse(parse_result.response, certificate_chain_str_, parse_valid);
}

HTTPSResponse HTTPSClient::del(const std::string &endpoint, const std::vector<std::string> &headers)
{
    return del(endpoint, headers, opt_);
}

void HTTPSClient::set_server(const std::string &server)
{
    if (server_ != server)
        config_changed_ = true;
    server_ = server;
}

void HTTPSClient::set_subdomain(const std::string &subdomain)
{
    if (subdomain_ != subdomain)
        config_changed_ = true;
    subdomain_ = subdomain;
}

std::string HTTPSClient::server_address() const
{
    if (server_ != "localhost" && subdomain_ != "")
        return subdomain_ + "." + server_;
    else
        return server_;
}

void HTTPSClient::set_read_timeout(uint32_t timeout)
{
    if (opt_.read_timeout != timeout)
        config_changed_ = true;
    opt_.read_timeout = timeout;
}

// Initialise mbedtls objects
void HTTPSClient::mbedtls_init()
{
    mbedtls_initialised_ = true;
    mbedtls_net_init(&server_fd_);
    mbedtls_ssl_init(&ssl_);
    mbedtls_ssl_config_init(&conf_);
    memset(&saved_session_, 0, sizeof(mbedtls_ssl_session));
    mbedtls_ctr_drbg_init(&ctr_drbg_);
    mbedtls_x509_crt_init(&cacert_);
    mbedtls_entropy_init(&entropy_);
}

// Free the memory of mbedtls objects
void HTTPSClient::mbedtls_free()
{
    // Reset the flags
    session_saved_ = false;
    session_closed_ = true;
    initial_setup_ = false;
    mbedtls_initialised_ = false;
    // Free the memory of mbedtls objects
    mbedtls_net_free(&server_fd_);
    mbedtls_x509_crt_free(&cacert_);
    mbedtls_ssl_session_free(&saved_session_);
    mbedtls_ssl_free(&ssl_);
    mbedtls_ssl_config_free(&conf_);
    mbedtls_ctr_drbg_free(&ctr_drbg_);
    mbedtls_entropy_free(&entropy_);
}

// Reset the member variables so a new request can be made
void HTTPSClient::configure_and_send(const ClientOptions &opt,
                                     const std::vector<std::string> &headers,
                                     const char *request_body)
{
    // Compare old and new configurations to determine if the client needs to be reconfigured
    if (opt_.transport != opt.transport || opt_.read_timeout != opt.read_timeout ||
        opt_.tickets != opt.tickets || opt_.nbio != opt.nbio)
        config_changed_ = true;

    // Reassign the member variables
    opt_ = opt;
    headers_ = headers;
    request_body_ = const_cast<char *>(request_body);

    // If the client hasn't been previously run before
    if (mbedtls_initialised_ && !initial_setup_)
    {
        DEBUG_LOG("First time running client");
        return run_client();
    }
    // If the client still has a connection open send another request
    if (mbedtls_initialised_ && !session_closed_ && !config_changed_)
    {
        DEBUG_LOG("Session still open, sending a new request");
        return send_request();
    }
    // If the client has been run before and a session has been saved try to reconnect
    if (mbedtls_initialised_ && session_saved_ && !config_changed_)
    {
        DEBUG_LOG("Session was previously saved, trying to reconnect");
        return reconnect();
    }
    DEBUG_LOG("Resetting the client");
    config_changed_ = false;
    // Otherwise we need to reset everything and start again
    // Clean up the MBED TLS object memory
    mbedtls_free();
    // Make sure memory references of MBED TLS objects are valid.
    mbedtls_init();

    return run_client();
}

// Call all of the member functions required to run the client
void HTTPSClient::run_client()
{
    setup_for_request();
    send_request();
    return;
}

// Perform all set up and configuration steps required to make request
void HTTPSClient::setup_for_request()
{
    initialise_random_generator();
    load_certificates();
    start_connection();
    configure_ssl();
    perform_handshake();
    verify_certificate();
    initial_setup_ = true;
    return;
}

//  Initialize the random number generator (CRT-DRBG) with a source of entropy
void HTTPSClient::initialise_random_generator()
{
    INFO_LOG("Seeding the random number generator");
    const char *pers = "ssl_client2";
    int ret;
    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg_,
                                     mbedtls_entropy_func,
                                     &entropy_,
                                     reinterpret_cast<const unsigned char *>(pers),
                                     strlen(pers))) != 0)
    {
        print_mbedtls_error("mbedtls_crt_drbg_seed", ret);
        THROW_EXCEPTION(kClientConfigurationError, "Initialising random number generator failed");
    }

    return;
}

//  Load the trusted CA certificates
void HTTPSClient::load_certificates()
{
    INFO_LOG("Loading the pinned leaf certificate(s)");

    int ret;
    // load trusted crts
    if (pinned_certificates_.size() > 0)
        ret = mbedtls_x509_crt_parse(
            &cacert_,
            reinterpret_cast<const unsigned char *>(pinned_certificates_.c_str()),
            pinned_certificates_.size() + 1);
    else
        ret = mbedtls_x509_crt_parse(
            &cacert_, reinterpret_cast<const unsigned char *>(cacert), sizeof cacert);

    if (ret != 0)
    {
        print_mbedtls_error("mbedtls_x509_crt_parse", ret);
        THROW_EXCEPTION(kClientCertificateParseError, "Parsing the CA certificates failed");
    }

    return;
}

//  Start the connection to the server in the specified transport mode
void HTTPSClient::start_connection()
{
    INFO_LOG("Connecting to %s:%s:%s...",
             opt_.transport == MBEDTLS_SSL_TRANSPORT_STREAM ? "TCP" : "UDP",
             server_address().c_str(),
             opt_.server_port);

    int ret;
    if ((ret = mbedtls_net_connect(&server_fd_,
                                   server_address().c_str(),
                                   opt_.server_port,
                                   opt_.transport == MBEDTLS_SSL_TRANSPORT_STREAM
                                       ? MBEDTLS_NET_PROTO_TCP
                                       : MBEDTLS_NET_PROTO_UDP)) != 0)
    {
        print_mbedtls_error("mbedtls_net_connect", ret);
        THROW_EXCEPTION(kClientConnectionError, "Initial connection to server failed");
    }

    // Set blocking or non-blocking I/O
    if (opt_.nbio > 0)
    {
        DEBUG_LOG("Setting non-blocking I/O");
        ret = mbedtls_net_set_nonblock(&server_fd_);
    }
    else
    {
        DEBUG_LOG("Setting blocking I/O");
        ret = mbedtls_net_set_block(&server_fd_);
    }
    if (ret != 0)
    {
        print_mbedtls_error("mbedtls_net_set_(non)block", ret);
        THROW_EXCEPTION(kClientConfigurationError, "Setting blocking or non-blocking I/O failed");
    }

    session_closed_ = false;
    return;
}

//  Set up the SSL client configurations
void HTTPSClient::configure_ssl()
{
    INFO_LOG("Setting up the SSL/TLS structure...");
    // Load the default SSL configuration values
    int ret;
    if ((ret = mbedtls_ssl_config_defaults(
             &conf_, MBEDTLS_SSL_IS_CLIENT, opt_.transport, MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
    {
        print_mbedtls_error("mbedtls_ssl_config_defaults", ret);
        THROW_EXCEPTION(kClientConfigurationError, "Loading default configuration values failed");
    }

    // Set the random number generator callback
    mbedtls_ssl_conf_rng(&conf_, mbedtls_ctr_drbg_random, &ctr_drbg_);

    // Set the certificate verification mode top optional as verification performed by the
    // pinned_verify function
    if (pinned_certificates_.size() > 0)
    {
        mbedtls_ssl_conf_authmode(&conf_, MBEDTLS_SSL_VERIFY_OPTIONAL);
        mbedtls_ssl_conf_verify(&conf_, pinned_verify, &cacert_);
    }
    else
    {
        mbedtls_ssl_conf_ca_chain(&conf_, &cacert_, NULL);
    }
    mbedtls_ssl_conf_dbg(&conf_, mbedtls_debug, NULL);
    // Set the timeout period for mbed_tls_ssl_read()
    DEBUG_LOG("Setting read timeout to %i", opt_.read_timeout);
    mbedtls_ssl_conf_read_timeout(&conf_, opt_.read_timeout);
    // Enable/disable session tickets
    mbedtls_ssl_conf_session_tickets(&conf_, opt_.tickets);

    // Set the data required to verify peer certificate
    mbedtls_ssl_conf_ca_chain(&conf_, &cacert_, NULL);

    // Set up an SSL context for use
    if ((ret = mbedtls_ssl_setup(&ssl_, &conf_)) != 0)
    {
        print_mbedtls_error("mbedtls_ssl_setup", ret);
        THROW_EXCEPTION(kClientConfigurationError, "Setting up SSL context failed");
    }

    // Set or reset the hostname to check against the received server
    // certificate
    if ((ret = mbedtls_ssl_set_hostname(&ssl_, server_address().c_str())) != 0)
    {
        print_mbedtls_error("mbedtls_ssl_set_hostname", ret);
        THROW_EXCEPTION(kClientConfigurationError, "Checking server hostname failed");
    }

    // Set the underlying blocking/non-blocking I/O callbacks for write, read
    // and read-with-timeout
    mbedtls_ssl_set_bio(&ssl_,
                        &server_fd_,
                        mbedtls_net_send,
                        mbedtls_net_recv,
                        opt_.nbio == 0 ? mbedtls_net_recv_timeout : NULL);

    return;
}

//  Perform SSL handshake and save the session if reconnecting
void HTTPSClient::perform_handshake()
{
    INFO_LOG("Performing the SSL/TLS handshake");
    if (pinned_certificates_.size() > 0)
        DEBUG_LOG("Verifying peer X.509 certificate with pinned certificates");
    else
        DEBUG_LOG("Verifying peer X.509 certificate with CA certificates");
    int ret;
    while ((ret = mbedtls_ssl_handshake(&ssl_)) != 0)
    {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            print_mbedtls_error("mbedtls_ssl_handshake", ret);
            if (ret == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED)
                ERROR_LOG("Unable to verify the server's certificate. Either it is invalid, or you "
                          "didn't set ca_file or ca_path to an appropriate value.");
            THROW_EXCEPTION(kClientHandshakeError, "TLS handshake with server failed");
        }
    }
    DEBUG_LOG("X.509 Verifies");

    INFO_LOG("Hand shake succeeds: [%s, %s]",
             mbedtls_ssl_get_version(&ssl_),
             mbedtls_ssl_get_ciphersuite(&ssl_));

    if ((ret = mbedtls_ssl_get_record_expansion(&ssl_)) >= 0)
        DEBUG_LOG("Record expansion is [%d]", ret);
    else
        DEBUG_LOG("Record expansion is [unknown (compression)]");

    DEBUG_LOG("Maximum fragment length is [%u]", (unsigned int)mbedtls_ssl_get_max_frag_len(&ssl_));

    // Save the server certificate chain in PEM format
    certificate_chain_str_ = get_certificate_chain();

    // Check if any of the certificate chain is expired
    const mbedtls_x509_crt *certificate = mbedtls_ssl_get_peer_cert(&ssl_);
    if (check_certificate_expiration(certificate) == false)
    {
        THROW_EXCEPTION(kClientExpiredCertificate, "Server certificates are expired");
    }
    api_common_name_ = get_certificate_subject_cn(certificate);

    // If there are reconnect attempts left and the session hasn't already been saved, copy the
    // session data to a session structure
    if ((opt_.reconnect != 0 || opt_.save_session || !opt_.close_session) && !session_saved_)
    {
        INFO_LOG("Saving session for reuse...");

        if ((ret = mbedtls_ssl_get_session(&ssl_, &saved_session_)) != 0)
        {
            print_mbedtls_error("mbedtls_ssl_get_session", ret);
            THROW_EXCEPTION(kClientReconnectionError, "Saving session for reuse failed");
        }

        session_saved_ = true;
    }

    return;
}

// Get the result of the certificate verification and print the peer certificate contents if
// debugging
void HTTPSClient::verify_certificate() const
{
    if (mbedtls_ssl_get_peer_cert(&ssl_) != NULL)
    {
        if (opt_.debug_level > 0)
        {
            DEBUG_LOG("Peer certificate information");
            char cert_buffer[MBEDTLS_SSL_MAX_CONTENT_LEN + 1];
            mbedtls_x509_crt_info(
                cert_buffer, sizeof(cert_buffer) - 1, "|-", mbedtls_ssl_get_peer_cert(&ssl_));
            DEBUG_LOG("%s\n", cert_buffer);
        }
    }

    return;
}

// Write the GET/POST request and read the HTTP response
void HTTPSClient::send_request()
{
    unsigned char buffer[MBEDTLS_SSL_MAX_CONTENT_LEN + 1];
    int len = mbedtls_snprintf(
        reinterpret_cast<char *>(buffer), sizeof(buffer) - 1, request_start(), opt_.request_page);
    if (len > MBEDTLS_SSL_MAX_CONTENT_LEN)
        THROW_EXCEPTION(kOutputOverflow, "Request buffer too long");

    for (size_t i = 0; i < headers_.size(); i++)
    {
        len += mbedtls_snprintf(reinterpret_cast<char *>(buffer) + len,
                                sizeof(buffer) - 1 - len,
                                "%s\r\n",
                                headers_[i].c_str());
        if (len > MBEDTLS_SSL_MAX_CONTENT_LEN)
            THROW_EXCEPTION(kOutputOverflow, "Request buffer too long");
    }

    // Add body to request if there is one (assumes only POST requests have bodies)
    if ((strlen(request_body_) + len) > (MBEDTLS_SSL_MAX_CONTENT_LEN - 30))
    {
        THROW_EXCEPTION(kClientWriteError,
                        "Request body length is longer than the maximum content length");
        if (len > MBEDTLS_SSL_MAX_CONTENT_LEN)
            THROW_EXCEPTION(kOutputOverflow, "Request buffer too long");
    }
    if (strlen(request_body_) > 0)
    {
        len += mbedtls_snprintf(reinterpret_cast<char *>(buffer) + len,
                                sizeof(buffer) - 1 - len,
                                "Content-Length: %zu\r\n\r\n",
                                strlen(request_body_));
        if (len > MBEDTLS_SSL_MAX_CONTENT_LEN)
            THROW_EXCEPTION(kOutputOverflow, "Request buffer too long");
        len += mbedtls_snprintf(
            reinterpret_cast<char *>(buffer) + len, sizeof(buffer) - 1 - len, "%s", request_body_);
        if (len > MBEDTLS_SSL_MAX_CONTENT_LEN)
            THROW_EXCEPTION(kOutputOverflow, "Request buffer too long");
    }

    const int tail_len = static_cast<int>(strlen(request_end()));

    // Add padding to request to reach opt.request_size in length
    if (opt_.request_size != DFL_REQUEST_SIZE && len + tail_len < opt_.request_size)
    {
        memset(buffer + len, 'A', opt_.request_size - len - tail_len);
        len += opt_.request_size - len - tail_len;
    }

    strncpy(reinterpret_cast<char *>(buffer) + len, request_end(), sizeof(buffer) - len - 1);
    len += tail_len;

    // Truncate if request size is smaller than the "natural" size
    if (opt_.request_size != DFL_REQUEST_SIZE && len > opt_.request_size)
    {
        len = opt_.request_size;

        // Still end with \r\n unless that's really not possible
        if (len >= 2)
            buffer[len - 2] = '\r';
        if (len >= 1)
            buffer[len - 1] = '\n';
    }

    // Try to write exactly (len - written) application data bytes
    int written, frags;
    int ret = 0;
    for (written = 0, frags = 0; written < len; written += ret, frags++)
    {
        while ((ret = mbedtls_ssl_write(&ssl_, buffer + written, len - written)) <= 0)
        {
            if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
            {
                print_mbedtls_error("mbedtls_ssl_write", ret);
                THROW_EXCEPTION(kClientWriteError, "Writing HTTPS request failed");
            }
        }
    }

    buffer[written] = '\0';
    DEBUG_LOG("%d bytes written in %d fragments", written, frags);

    int total_read = 0;
    auto length = MBEDTLS_SSL_MAX_CONTENT_LEN;

    // Make sure allocation is at the original start address
    output_ = output_start_;

    output_ = static_cast<unsigned char *>(realloc(output_, length));

    // Reload start address, in case realloc needed to move the memory
    output_start_ = output_;

    //  Read the HTTP response from the stream
    do
    {
        memset(output_, 0, length);

        // Read at most length - 1 application data bytes
        ret = mbedtls_ssl_read(&ssl_, output_, length - 1);

        if (ret < 0)
        {
            switch (ret)
            {
            case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
                INFO_LOG("Connection was closed by peer");
                // Waiting too long with the session open can cause the server to close it, in this
                // case try to reconnect with a saved session
                if (!opt_.close_session && session_saved_)
                {
                    opt_.close_session = true;
                    return reconnect();
                }
                opt_.close_session = true;
                return close_notify();

            case MBEDTLS_ERR_NET_CONN_RESET:
                WARNING_LOG("Connection was reset by peer");
                //  Reconnect if option selected, otherwise exit
                if (opt_.reconnect != 0 && session_saved_)
                {
                    --opt_.reconnect;
                    return reconnect();
                }
                opt_.close_session = true;
                return close_notify();

            case MBEDTLS_ERR_SSL_WANT_READ:
            case MBEDTLS_ERR_SSL_WANT_WRITE:
                continue;

            default:
                print_mbedtls_error("mbedtls_ssl_read", ret);
                THROW_EXCEPTION(kClientReadError, "Reading HTTPS response failed");
            }
        }

        total_read += ret;
        DEBUG_LOG("Get %d bytes ending with %x", ret, output_start_[total_read - 1]);

        // Parse the HTTP response to determine if the server has finished sending
        const HTTPParseResult parse_result = parse_http(output_start_);
        if (parse_result.status == httpparser::HttpResponseParser::ParsingCompleted)
        {
            output_ = output_start_;
            output_ = static_cast<unsigned char *>(realloc(output_, total_read + 1));

            if (output_)
            {
                // Reload start address, in case realloc needed to move the memory
                output_start_ = output_;
                length = 0;
            }
            // Raise an exception if there wasn't any more free memory to allocate
            else
            {
                WARNING_LOG("It was not possible to decrease buffer size");
            }
            break;
        }

        else if (parse_result.status == httpparser::HttpResponseParser::ParsingError)
            THROW_EXCEPTION(kClientReadError, "Parsing HTTP response failed");

        output_ += ret;
        length -= ret;

        // Allocate more memory if there is still some data to process
        if (length == 1 &&
            parse_result.status == httpparser::HttpResponseParser::ParsingIncompleted)
        {
            DEBUG_LOG("Needed to realloc more memory.");

            // Make sure allocation is performed at the original start address
            output_ = output_start_;

            // Increase the memory in one time the original amount
            output_ = static_cast<unsigned char *>(
                realloc(output_, total_read + MBEDTLS_SSL_MAX_CONTENT_LEN));

            if (output_)
            {
                // Reload start address, in case realloc needed to move the memory
                output_start_ = output_;
                // Point back to the previous address within the array
                output_ += total_read;
                // Since the length increased, there is the same original amount of memory free
                length = MBEDTLS_SSL_MAX_CONTENT_LEN;
            }
            // Raise an exception if there wasn't any more free memory to allocate
            else
            {
                THROW_EXCEPTION(kClientReadError,
                                "Parsing HTTP response failed - Memory allocation limit exceeded.");
            }
        }

    } while (true);

    //  Continue doing data exchanges?
    if (--opt_.exchanges > 0)
        return send_request();

    return close_notify();
}

// Close the connection if not already done
void HTTPSClient::close_notify()
{
    if (opt_.close_session)
    {
        // No error checking, the connection might be closed already
        int ret;
        do
            ret = mbedtls_ssl_close_notify(&ssl_);
        while (ret == MBEDTLS_ERR_SSL_WANT_WRITE);

        INFO_LOG("Closed %s:%s", server_address().c_str(), opt_.server_port);
        session_closed_ = true;

        // Reconnect if option selected, otherwise exit
        if (opt_.reconnect != 0 && session_saved_)
        {
            --opt_.reconnect;
            return reconnect();
        }
    }
    return;
}

//  Reconnect to a saved session
void HTTPSClient::reconnect()
{

    mbedtls_net_free(&server_fd_);
    INFO_LOG("Reconnecting with saved session...");

    int ret;
    if ((ret = mbedtls_ssl_session_reset(&ssl_)) != 0)
    {
        print_mbedtls_error("mbedtls_ssl_session_reset", ret);
        THROW_EXCEPTION(kClientReconnectionError, "Resetting SSL session failed");
    }
    if ((ret = mbedtls_ssl_set_session(&ssl_, &saved_session_)) != 0)
    {
        print_mbedtls_error("mbedtls_ssl_set_session", ret);
        THROW_EXCEPTION(kClientReconnectionError, "Setting SSL session from saved session failed");
    }

    try
    {
        start_connection();
        perform_handshake();
    }
    catch (const EnclaveException &e)
    {
        EXCEPTION_LOG(e);
        ERROR_LOG("Failed to restart session, closing");
        return close_notify();
    }
    return send_request();
}

const char *HTTPSClient::request_start() const
{
    if (opt_.request_type == GET_REQUEST_TYPE)
        return "GET %s HTTP/1.1\r\n";
    if (opt_.request_type == POST_REQUEST_TYPE)
        return "POST %s HTTP/1.1\r\n";
    if (opt_.request_type == DELETE_REQUEST_TYPE)
        return "DELETE %s HTTP/1.1\r\n";
    return "";
}

const char *HTTPSClient::request_end() const
{
    if (opt_.request_type == GET_REQUEST_TYPE)
        return "\r\n";
    if (opt_.request_type == POST_REQUEST_TYPE)
        return "";
    if (opt_.request_type == DELETE_REQUEST_TYPE)
        return "\r\n";
    return "";
}

bool HTTPSClient::check_certificate_expiration(const mbedtls_x509_crt *certificate) const
{
    while (certificate != NULL)
    {
        // Get the Leaf certificate and its period of validity
        const mbedtls_x509_time valid_from = certificate->valid_from;
        int valid_from_unix_time = utc_unix_timestamp(valid_from);
        if (opt_.timestamp < valid_from_unix_time)
            return false;

        const mbedtls_x509_time valid_to = certificate->valid_to;
        int valid_to_unix_time = utc_unix_timestamp(valid_to);
        if (opt_.timestamp > valid_to_unix_time)
            return false;

        certificate = certificate->next;
    }

    return true;
}

std::string HTTPSClient::get_certificate_subject_cn(const mbedtls_x509_crt *certificate) const
{
    if (certificate == NULL)
        return "";
    const size_t buffer_size = 500;
    char name_buffer[buffer_size];
    mbedtls_x509_dn_gets(name_buffer, buffer_size, &(certificate->subject));

    const std::string subject = std::string(name_buffer);
    const size_t start = subject.find("CN=", 0);
    if (start == std::string::npos)
        return "";
    const size_t end = subject.find(",", start);
    if (end == std::string::npos)
        return subject.substr(start + 3);
    return subject.substr(start + 3, end);
}

std::string get_certificate_pem_string(const mbedtls_x509_crt *certificate)
{
    size_t buffer_length = CORE_MAX_CERTIFICATE_LEN;
    unsigned char *buffer = static_cast<unsigned char *>(malloc(buffer_length));

    // Get the certificate in DER format (binary)
    const mbedtls_x509_buf der_buffer = certificate->raw;
    // Convert to PEM (base64 with header and footer)
    size_t pem_len;
    int ret = mbedtls_pem_write_buffer("-----BEGIN CERTIFICATE-----\n",
                                       "-----END CERTIFICATE-----\n",
                                       der_buffer.p,
                                       der_buffer.len,
                                       buffer,
                                       buffer_length,
                                       &pem_len);

    // Certificate writing failed, buffer not long enough
    if (ret > 0 && pem_len > buffer_length)
    {
        // Increase buffer size
        buffer_length = pem_len;
        buffer = static_cast<unsigned char *>(realloc(buffer, buffer_length));

        if (buffer)
        {
            // Now the buffer will have enough size to process the whole certificate
            ret = mbedtls_pem_write_buffer("-----BEGIN CERTIFICATE-----\n",
                                           "-----END CERTIFICATE-----\n",
                                           der_buffer.p,
                                           der_buffer.len,
                                           buffer,
                                           buffer_length,
                                           &pem_len);
        }
        // Raise exception if there wasn't enough memory for reallocation
        else
        {
            std::free(buffer);
            THROW_EXCEPTION(kClientCertificateParseError,
                            "Certificate writing failed, memory limit reached");
        }
    }

    if (ret != 0)
    {
        std::free(buffer);
        print_mbedtls_error("mbedtls_pem_write_buffer", ret);
        THROW_EXCEPTION(kClientCertificateParseError, "Failed to write certificate as PEM");
    }

    const std::string pem_string = std::string(reinterpret_cast<char *>(buffer));
    std::free(buffer);
    return pem_string;
}

// Return the leaf certificate of the server
std::string HTTPSClient::get_leaf_certificate() const
{
    // Get the current certificate
    const mbedtls_x509_crt *certificate = mbedtls_ssl_get_peer_cert(&ssl_);
    std::string pem_certificate = get_certificate_pem_string(certificate);
    pem_certificate.erase(std::remove(pem_certificate.begin(), pem_certificate.end(), '\r'),
                          pem_certificate.end());
    return pem_certificate;
}

// Return the certificate chain of the server
std::string HTTPSClient::get_certificate_chain() const
{
    std::string certificate_chain;
    // Get the current certificate
    const mbedtls_x509_crt *certificate = mbedtls_ssl_get_peer_cert(&ssl_);

    while (certificate != NULL)
    {
        certificate_chain += get_certificate_pem_string(certificate);
        certificate = certificate->next;
    }
    return certificate_chain;
}

// Parse a HTTP response from a HTTPS client to obtain the body
HTTPSClient::HTTPParseResult HTTPSClient::parse_http(unsigned char *buffer) const
{
    const char *begin = reinterpret_cast<char *>(buffer);
    const size_t buf_len = strlen(begin);

    httpparser::Response response;
    httpparser::HttpResponseParser parser;
    const httpparser::HttpResponseParser::ParseResult res =
        parser.parse(response, begin, begin + buf_len);
    return HTTPParseResult(res, response);
}

// https://github.com/Intevation/mxe/blob/trustbridge/src/curl-2-curlopt-peercert.patch
int HTTPSClient::pinned_verify(void *pinned_chain,
                               mbedtls_x509_crt *crt,
                               int depth,
                               uint32_t *flags)
{
    DEBUG_LOG("Certificate pinning: Verify requested for (Depth %d):", depth);
    // Only allow pinning for leaf (depth 0) certificates
    if (depth != 0)
    {
        DEBUG_LOG("Certificate pinning: Nothing to do here");
        return 0;
    }

    mbedtls_x509_crt *pinned = static_cast<mbedtls_x509_crt *>(pinned_chain);
    const mbedtls_x509_crt *leaf = crt;
    int ret;

    if (pinned_chain == NULL || crt == NULL)
    {
        ERROR_LOG("Certificate pinning: Certificates are NULL");
        *flags |= MBEDTLS_X509_BADCERT_NOT_TRUSTED;
        return *flags;
    }

    bool found_match = false;
    while (pinned != NULL)
    {
        ret = memcmp(pinned->raw.p, leaf->raw.p, pinned->raw.len);
        if (ret == 0)
            found_match = true;
        pinned = pinned->next;
    }
    if (found_match)
    {
        DEBUG_LOG("Certificate pinning: Found matching certificate");
        *flags = 0;
        return 0;
    }

    ERROR_LOG("Certificate pinning: Didn't find match");
    *flags |= MBEDTLS_X509_BADCERT_NOT_TRUSTED;
    return *flags;
}

} // namespace enclave
} // namespace silentdata
