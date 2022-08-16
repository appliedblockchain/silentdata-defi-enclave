#ifndef SHA512_256_H
#define SHA512_256_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define SHA512_256_BLOCK_SIZE 128
#define SHA512_256_HASH_LENGTH 32

    struct sha512_256
    {
        uint64_t state[8];
        uint64_t count;

        uint8_t buffer[SHA512_256_BLOCK_SIZE];
        size_t fill;
    };

    void sha512_256_init(struct sha512_256 *ctx);
    void sha512_256_add(struct sha512_256 *ctx, const uint8_t *data, size_t len);
    void sha512_256_final(struct sha512_256 *ctx, uint8_t out[SHA512_256_HASH_LENGTH]);

#ifdef __cplusplus
}
#endif

#endif
