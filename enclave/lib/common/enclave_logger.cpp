#include "lib/common/enclave_logger.hpp"

const char *log_level_strings[] = {
    "NONE",     // 0
    "critical", // 1
    "error",    // 2
    "warn",     // 3
    "info",     // 4
    "debug"     // 5
};

void EXCEPTION_LOG(const std::runtime_error &e)
{
    if (LOG_SHOULD_I(kEnclaveLogLevelError))
    {
        mbedtls_compat_sgx_printf("error: %s\n", e.what());
    }
}

void hexdump(const char *title,
             void const *data,
             unsigned int hex_length,
             const char *level,
             const char *file_name,
             const char *function,
             int line)
{
    unsigned int i;
    size_t row, col;
    const size_t rows = (hex_length / 16 + (hex_length % 16 != 0));
    const size_t max_buffer_length = 100 * rows + 200;
    char buffer[max_buffer_length];

    if (!data)
        return;

    int len = snprintf(
        buffer, sizeof(buffer) - 1, "%s: %s:%s:%d: %s\n", level, file_name, function, line, title);

    for (row = 0, i = 0; row < rows; row++, i += 16)
    {
        // location of first byte in line
        len += snprintf(buffer + len, sizeof(buffer) - 1 - len, "0x%04X:   ", i);

        // left half of hex dump
        for (col = i; col < i + 8; col++)
        {
            if (col < hex_length)
                len += snprintf(buffer + len,
                                sizeof(buffer) - 1 - len,
                                "%02X ",
                                (static_cast<unsigned char const *>(data))[col]);
            else
                len += snprintf(buffer + len, sizeof(buffer) - 1 - len, "   "); // pad if short line
        }

        len += snprintf(buffer + len, sizeof(buffer) - 1 - len, "  ");

        // right half of hex dump
        for (col = i + 8; col < i + 16; col++)
        {
            if (col < hex_length)
                len += snprintf(buffer + len,
                                sizeof(buffer) - 1 - len,
                                "%02X ",
                                (static_cast<unsigned char const *>(data))[col]);
            else
                len += snprintf(buffer + len, sizeof(buffer) - 1 - len, "   "); // pad if short line
        }

        len += snprintf(buffer + len, sizeof(buffer) - 1 - len, "   ");

        // ASCII dump
        for (col = i; col < i + 16; col++)
        {
            if (col < hex_length)
                if ((static_cast<unsigned char const *>(data))[col] >= 32 &&
                    (static_cast<unsigned char const *>(data))[col] < 127)
                    len += snprintf(buffer + len,
                                    sizeof(buffer) - 1 - len,
                                    "%c",
                                    (static_cast<char const *>(data))[col]);
                else
                    len += snprintf(
                        buffer + len, sizeof(buffer) - 1 - len, "."); // put this for non-printables
            else
                len += snprintf(buffer + len, sizeof(buffer) - 1 - len, " "); // pad if short line
        }

        len += snprintf(buffer + len, sizeof(buffer) - 1 - len, "\n");
    }
    // mbedtls_compat_sgx_printf will only print BUFSIZ chars at once
    for (int chunk = 0; chunk < (len / BUFSIZ + (len % BUFSIZ != 0)); chunk++)
        mbedtls_compat_sgx_printf("%s", buffer + (chunk * (BUFSIZ - 1)));
}
