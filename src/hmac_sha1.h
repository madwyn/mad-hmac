#ifndef __HMAC_SHA1_INCLUDED__
#define __HMAC_SHA1_INCLUDED__

#include "sha1.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SHA1_BLOCK_SIZE  64
#define SHA1_DIGEST_SIZE SHA1_HASH_SIZE

typedef struct {
    Sha1Context ctx_inside;
    Sha1Context ctx_outside;

    /* for hmac_reinit */
    Sha1Context ctx_inside_reinit;
    Sha1Context ctx_outside_reinit;

    unsigned char block_ipad[SHA1_BLOCK_SIZE];
    unsigned char block_opad[SHA1_BLOCK_SIZE];
} hmac_sha1_ctx;

void hmac_sha1_init(  hmac_sha1_ctx *ctx, const unsigned char *key,
                                                unsigned int   key_size);

void hmac_sha1_reinit(hmac_sha1_ctx *ctx);

void hmac_sha1_update(hmac_sha1_ctx *ctx, const unsigned char *message,
                                                unsigned int   message_len);

void hmac_sha1_final( hmac_sha1_ctx *ctx,       unsigned char *mac,
                                                unsigned int mac_size);

void hmac_sha1(const unsigned char *key,     unsigned int key_size,
               const unsigned char *message, unsigned int message_len,
                     unsigned char *mac,     unsigned int mac_size);

#ifdef __cplusplus
}
#endif


#endif
