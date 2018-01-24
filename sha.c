#include <stdlib.h>
#include <stdio.h>
#include "sha.h"
#include "types.h"
#include "utils.h"

/* Allocate new context. */
sha_ctx_t *new_sha_ctx(void) {
    sha_ctx_t *ctx;
    if ((ctx = malloc(sizeof(*ctx))) == NULL) {
        FATAL_ERROR("Failed to allocate sha_ctx_t!");
    }

    if (gcry_md_open(&ctx->digest, GCRY_MD_SHA256, 0) != 0) {
        FATAL_ERROR("Failed to open sha_ctx_t!");
    }

    return ctx;

}

/* Update digest with new data. */
void sha_update(sha_ctx_t *ctx, const void *data, size_t l) {
    gcry_md_write(ctx->digest, data, l);
}

/* Read hash from context. */
void sha_get_hash(sha_ctx_t *ctx, unsigned char *hash) {
    memcpy(hash, gcry_md_read(ctx->digest, 0), 0x20);
}

/* Free context object. */
void sha_free(sha_ctx_t *ctx) {
    gcry_md_close(ctx->digest);
    free(ctx);
}

void sha_hash_buffer(unsigned char *digest, const void *data, size_t l) {
    gcry_md_hash_buffer(GCRY_MD_SHA256, digest, data, l);
}
