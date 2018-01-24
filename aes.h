#ifndef NCATOOL_AES_H
#define NCATOOL_AES_H

#define GCRYPT_NO_DEPRECATED
#include <gcrypt.h>

typedef struct {
    gcry_cipher_hd_t cipher; /* gcrypt context for this cryptor. */
    int mode;
} aes_ctx_t;


void aes_init(void);
aes_ctx_t *new_aes_ctx(const void *key, unsigned int key_size, int mode);
void free_aes_ctx(aes_ctx_t *ctx);
void aes_setiv(aes_ctx_t *ctx, const void *iv, size_t l);

void aes_encrypt(aes_ctx_t *ctx, void *dst, void *src, size_t l);
void aes_decrypt(aes_ctx_t *ctx, void *dst, void *src, size_t l);

void aes_xts_encrypt(aes_ctx_t *ctx, void *dst, void *src, size_t l, size_t sector, size_t sector_size);
void aes_xts_decrypt(aes_ctx_t *ctx, void *dst, void *src, size_t l, size_t sector, size_t sector_size);

#endif
