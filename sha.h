#ifndef NCATOOL_SHA_H
#define NCATOOL_SHA_H

#define GCRYPT_NO_DEPRECATED
#include <gcrypt.h>

/* Define structs. */
typedef struct {
    gcry_md_hd_t digest; /* gcrypt context for this hasher. */
} sha_ctx_t;


/* Function prototypes. */
sha_ctx_t *new_sha_ctx(void);
void sha_update(sha_ctx_t *ctx, const void *data, size_t l);
void sha_get_hash(sha_ctx_t *ctx, unsigned char *hash);
void sha_free(sha_ctx_t *ctx);

void sha_hash_buffer(unsigned char *hash, const void *data, size_t l);

#endif