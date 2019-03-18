#ifndef __HMAC_H__
#define __HMAC_H__

/* Import libecc for hash functions */
#include "libsig.h"
#include "api/stdio.h"
#include "api/nostd.h"

/* The HMAC structure is made of two hash contexts */
typedef struct {
        const hash_mapping *hash;
        hash_context in_ctx;
        hash_context out_ctx;
} hmac_context;

int hmac_init(hmac_context *ctx, const uint8_t *hmackey, uint32_t hmackey_len, hash_alg_type hash_type);
void hmac_update(hmac_context *ctx, const uint8_t *input, uint32_t ilen);
int hmac_finalize(hmac_context *ctx, uint8_t *output, uint32_t *outlen);
int hmac_pbkdf2(hash_alg_type hash_type, const uint8_t *password, uint32_t password_len, const uint8_t *salt, uint32_t salt_len, uint32_t c, uint32_t dklen, uint8_t *output, uint32_t *outlen);

#ifdef HMAC_TEST_VECTORS
int do_hmac_test_vectors(void);
#endif
#ifdef HMAC_TEST_PERF
int do_hmac_test_perf(void);
#endif

#endif /* __HMAC_H__ */
