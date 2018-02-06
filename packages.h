#ifndef HACTOOL_PACKAGES_H
#define HACTOOL_PACKAGES_H

#include "types.h"
#include "utils.h"
#include "settings.h"

#define MAGIC_PK11 0x31314B50
#define MAGIC_PK21 0x31324B50

typedef struct {
    unsigned char build_hash[0x10];
    unsigned char build_date[0x10];
    unsigned char stage1[0x3FC0];
    uint32_t pk11_size;
    unsigned char _0x3FE4[0xC];
    unsigned char ctr[0x10];
} pk11_stage1_t;

typedef struct {
    uint32_t magic;
    uint32_t warmboot_size;
    uint32_t _0x8;
    uint32_t _0xC;
    uint32_t nx_bootloader_size;
    uint32_t _0x14;
    uint32_t secmon_size;
    uint32_t _0x1C;
    unsigned char data[];
} pk11_t;

typedef struct {
    FILE *file;
    hactool_ctx_t *tool_ctx;
    int is_pilot;
    unsigned int key_rev;
    pk11_stage1_t stage1;
    pk11_t *pk11;
} pk11_ctx_t;


static inline unsigned char *pk11_get_warmboot_bin(pk11_ctx_t *ctx) {
    return ctx->is_pilot ? &ctx->pk11->data[ctx->pk11->secmon_size + ctx->pk11->nx_bootloader_size] : &ctx->pk11->data[0];
}

static inline unsigned char *pk11_get_secmon(pk11_ctx_t *ctx) {
    return ctx->is_pilot ? &ctx->pk11->data[0] : &ctx->pk11->data[ctx->pk11->warmboot_size + ctx->pk11->nx_bootloader_size];
}

static inline unsigned char *pk11_get_nx_bootloader(pk11_ctx_t *ctx) {
    return ctx->is_pilot ? &ctx->pk11->data[ctx->pk11->secmon_size] : &ctx->pk11->data[ctx->pk11->warmboot_size];
}


void pk11_process(pk11_ctx_t *ctx);
void pk11_print(pk11_ctx_t *ctx);
void pk11_save(pk11_ctx_t *ctx);

#endif