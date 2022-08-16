#ifndef SILENTDATA_ENCLAVE_ENCLAVE_LOGGER_H
#define SILENTDATA_ENCLAVE_ENCLAVE_LOGGER_H

#include <cstring>
#include <stdexcept>

#include "mbedtls/ssl.h"

enum EnclaveLogLevel
{
    kEnclaveLogLevelNone = 0,
    kEnclaveLogLevelCritical = 1,
    kEnclaveLogLevelError = 2,
    kEnclaveLogLevelWarning = 3,
    kEnclaveLogLevelInfo = 4,
    kEnclaveLogLevelDebug = 5
};

void hexdump(const char *title,
             void const *data,
             unsigned int hex_length,
             const char *level,
             const char *file_name,
             const char *function,
             int line);

#ifndef LOG_BUILD_LEVEL
#ifdef NDEBUG
#define LOG_BUILD_LEVEL kEnclaveLogLevelNone
#else
#define LOG_BUILD_LEVEL kEnclaveLogLevelDebug
#endif
#endif

extern const char *log_level_strings[];

// The BUILD_LOG_LEVEL defines what will be compiled in the executable, in production
// it should be set to kEnclaveLogLevelNONE

#define LOG_SHOULD_I(level) (level <= LOG_BUILD_LEVEL)

#define ENCLAVE_LOG(level, fmt, arg...)                                                            \
    do                                                                                             \
    {                                                                                              \
        if (LOG_SHOULD_I(level))                                                                   \
        {                                                                                          \
            const char *file_name = strrchr(__FILE__, '/') + 1;                                    \
            mbedtls_compat_sgx_printf("%s: %s:%s:%d: " fmt "\n",                                   \
                                      log_level_strings[level],                                    \
                                      file_name,                                                   \
                                      __FUNCTION__,                                                \
                                      __LINE__,                                                    \
                                      ##arg);                                                      \
        }                                                                                          \
    } while (0)

#define ENCLAVE_HEX_LOG(level, name, dat, len)                                                     \
    do                                                                                             \
    {                                                                                              \
        if (LOG_SHOULD_I(level))                                                                   \
        {                                                                                          \
            const char *file_name = strrchr(__FILE__, '/') + 1;                                    \
            hexdump(name, dat, len, log_level_strings[level], file_name, __FUNCTION__, __LINE__);  \
        }                                                                                          \
    } while (0)

#define DEBUG_LOG(fmt, arg...) ENCLAVE_LOG(kEnclaveLogLevelDebug, fmt, ##arg)
#define INFO_LOG(fmt, arg...) ENCLAVE_LOG(kEnclaveLogLevelInfo, fmt, ##arg)
#define WARNING_LOG(fmt, arg...) ENCLAVE_LOG(kEnclaveLogLevelWarning, fmt, ##arg)
#define ERROR_LOG(fmt, arg...) ENCLAVE_LOG(kEnclaveLogLevelError, fmt, ##arg)
#define CRITICAL_LOG(fmt, arg...) ENCLAVE_LOG(kEnclaveLogLevelCritical, fmt, ##arg)
#define DEBUG_HEX_LOG(name, dat, len) ENCLAVE_HEX_LOG(kEnclaveLogLevelDebug, name, dat, len)
// Not a macro but named like one for consistency
void EXCEPTION_LOG(const std::runtime_error &e);

#endif
