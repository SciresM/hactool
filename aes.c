#include <stdlib.h>
#include <stdio.h>
#include "aes.h"
#include "types.h"
#include "utils.h"

/* Initialize the wrapper library. */
void aes_init(void) {
    if (!gcry_check_version("1.8.0")) {
        FATAL_ERROR("Error: gcrypt version is less than 1.8.0");
    }

    gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
}

/* Allocate a new context. */
aes_ctx_t *new_aes_ctx(const void *key, unsigned int key_size, int mode) {
    aes_ctx_t *ctx;
    if ((ctx = malloc(sizeof(*ctx))) == NULL) {
        FATAL_ERROR("Failed to allocate aes_ctx_t!");
    }

    ctx->mode = mode;

    if (gcry_cipher_open(&ctx->cipher, GCRY_CIPHER_AES128, mode, 0) != 0) {
        FATAL_ERROR("Failed to open aes_ctx_t!");
    }

    if (gcry_cipher_setkey(ctx->cipher, key, key_size) != 0) {
        FATAL_ERROR("Failed to set key!");
    }

    return ctx;
}

/* Free an allocated context. */
void free_aes_ctx(aes_ctx_t *ctx) {
    /* Explicitly allow NULL. */
    if (ctx == NULL) {
        return;
    }
    
    gcry_cipher_close(ctx->cipher);
    free(ctx);
}

/* Set AES CTR or IV for a context. */
void aes_setiv(aes_ctx_t *ctx, const void *iv, size_t l) {
    if (ctx->mode == GCRY_CIPHER_MODE_CTR) {
        if (gcry_cipher_setctr(ctx->cipher, iv, l) != 0) {
            FATAL_ERROR("Failed to set ctr!");
        }
    } else {
        if (gcry_cipher_setiv(ctx->cipher, iv, l) != 0) {
            FATAL_ERROR("Failed to set iv!");
        }
    }
}

/* Encrypt with context. */
void aes_encrypt(aes_ctx_t *ctx, void *dst, void *src, size_t l) {   
    if (gcry_cipher_encrypt(ctx->cipher, dst, l, src, (src == NULL) ? 0 : l) != 0) {
        FATAL_ERROR("Failed to encrypt!");
    }
}

/* Decrypt with context. */
void aes_decrypt(aes_ctx_t *ctx, void *dst, void *src, size_t l) {
    if (gcry_cipher_decrypt(ctx->cipher, dst, l, src, (src == NULL) ? 0 : l) != 0) {
        FATAL_ERROR("Failed to decrypt!");
    } 
}

void get_tweak(unsigned char *tweak, size_t sector) {
    for (int i = 0xF; i >= 0; i--) { /* Nintendo LE custom tweak... */
        tweak[i] = (unsigned char)(sector & 0xFF);
        sector >>= 8;
    }
}

/* Encrypt with context. */
void aes_xts_encrypt(aes_ctx_t *ctx, void *dst, void *src, size_t l, size_t sector, size_t sector_size) {
    unsigned char tweak[0x10];

    if (l % sector_size != 0) {
        FATAL_ERROR("Length must be multiple of sectors!");
    }

    for (size_t i = 0; i < l; i += sector_size) {
        /* Workaround for Nintendo's custom sector...manually generate the tweak. */
        get_tweak(tweak, sector++);
        aes_setiv(ctx, tweak, 16);  
        aes_encrypt(ctx, ((char *)dst) + i, (src == NULL) ? NULL : ((char *)src) + i, sector_size);
    }
}

/* Decrypt with context. */
void aes_xts_decrypt(aes_ctx_t *ctx, void *dst, void *src, size_t l, size_t sector, size_t sector_size) {
    unsigned char tweak[0x10];

    if (l % sector_size != 0) {
        FATAL_ERROR("Length must be multiple of sectors!");
    }

    for (size_t i = 0; i < l; i += sector_size) {
        /* Workaround for Nintendo's custom sector...manually generate the tweak. */
        get_tweak(tweak, sector++);
        aes_setiv(ctx, tweak, 16);  
        aes_decrypt(ctx, ((char *)dst) + i, (src == NULL) ? NULL : ((char *)src) + i, sector_size);
    }
}
