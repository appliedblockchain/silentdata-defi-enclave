#pragma once

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <string>
#include <vector>

#include "mbedtls/ssl.h"

#define DFL_SERVER_PORT "443"
#define DFL_REQUEST_PAGE "/"
#define DFL_REQUEST_SIZE -1
#define DFL_DEBUG_LEVEL 0
#define DFL_NBIO 0
#define DFL_READ_TIMEOUT 300000
#define DFL_MAX_RESEND 0
#define DFL_EXCHANGES 1
#define DFL_RECONNECT 0
#define DFL_TICKETS MBEDTLS_SSL_SESSION_TICKETS_ENABLED
#define DFL_TRANSPORT MBEDTLS_SSL_TRANSPORT_STREAM
#define DFL_SAVE_SESSION 0
#define DFL_CLOSE_SESSION 0

#define GET_REQUEST_TYPE 0
#define POST_REQUEST_TYPE 1
#define DELETE_REQUEST_TYPE 2

namespace silentdata
{
namespace enclave
{

struct ClientOptions
{
    ClientOptions()
        : server_port(DFL_SERVER_PORT), debug_level(DFL_DEBUG_LEVEL), nbio(DFL_NBIO),
          read_timeout(DFL_READ_TIMEOUT), max_resend(DFL_MAX_RESEND),
          request_page(DFL_REQUEST_PAGE), request_size(DFL_REQUEST_SIZE), exchanges(DFL_EXCHANGES),
          reconnect(DFL_RECONNECT), tickets(DFL_TICKETS), transport(DFL_TRANSPORT),
          request_type(GET_REQUEST_TYPE), save_session(DFL_SAVE_SESSION),
          close_session(DFL_CLOSE_SESSION), timestamp(0)
    {
    }

    const char *server_port;  /* port on which the ssl service runs       */
    int debug_level;          /* level of debugging                       */
    int nbio;                 /* should I/O be blocking?                  */
    uint32_t read_timeout;    /* timeout on mbedtls_ssl_read() in
                                 milliseconds (default is 5 min)          */
    int max_resend;           /* DTLS times to resend on read timeout     */
    const char *request_page; /* page on server to request                */
    int request_size;         /* pad request with header to requested size*/
    int exchanges;            /* number of data exchanges                 */
    int reconnect;            /* number of attempts to resume session     */
    int tickets;              /* enable / disable session tickets         */
    int transport;            /* TLS or DTLS?                             */
    int request_type;         /* 0 (default) = GET, 1 = POST              */
    bool save_session;        /* false (default) = don't save session for
                                 future reconnects, true = save session   */
    bool close_session;       /* false (default) = don't close the session,
                                 true = close the session                                */
    int64_t timestamp;        /* The current UNIX timestamp passed in to
                                 the enclave for certificate expiration
                                 checking                                 */
};

} // namespace enclave
} // namespace silentdata
