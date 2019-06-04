#include <string.h>
#include <time.h>
#include "save.h"
#include "aes.h"

void save_process(save_ctx_t *ctx) {
    /* Read *just* safe amount. */
    fseeko64(ctx->file, 0, SEEK_SET);
    if (fread(&ctx->header, 1, sizeof(ctx->header), ctx->file) != sizeof(ctx->header)) {
        fprintf(stderr, "Failed to read save header!\n");
        exit(EXIT_FAILURE);
    }

    if ((ctx->tool_ctx->action & ACTION_VERIFY)) {
        ctx->hash_validity = check_memory_hash_table(ctx->file, ctx->header.layout.hash, 0x300, 0x3D00, 0x3D00, 0);

        unsigned char cmac[0x10];
        memset(cmac, 0, 0x10);
        aes_calculate_cmac(cmac, &ctx->header.layout, sizeof(ctx->header.layout), ctx->tool_ctx->settings.keyset.save_mac_key);
        if (memcmp(cmac, &ctx->header.cmac, 0x10) == 0) {
            ctx->disf_cmac_validity = VALIDITY_VALID;
        } else {
            ctx->disf_cmac_validity = VALIDITY_INVALID;
        }
    }

    if (ctx->tool_ctx->action & ACTION_INFO) {
        save_print(ctx);
    }

    if (ctx->tool_ctx->action & ACTION_EXTRACT) {
        save_save(ctx);
    }
}

void save_save(save_ctx_t *ctx) {

}

void save_print_ivfc_section(save_ctx_t *ctx) {
    print_magic("    Magic:                          ", ctx->header.ivfc_header.magic);
    printf("    ID:                             %08"PRIx32"\n", ctx->header.ivfc_header.id);
    memdump(stdout, "    Salt Seed:                      ", &ctx->header.ivfc_header.salt_source, 0x20);
    for (unsigned int i = 0; i < 4; i++) {
        printf("    Level %"PRId32":\n", i);
        printf("        Data Offset:                0x%016"PRIx64"\n", ctx->header.ivfc_header.level_headers[i].logical_offset);
        printf("        Data Size:                  0x%016"PRIx64"\n", ctx->header.ivfc_header.level_headers[i].hash_data_size);
        if (i != 0) {
            printf("        Hash Offset:                0x%016"PRIx64"\n", ctx->header.ivfc_header.level_headers[i-1].logical_offset);
        } else {
            printf("        Hash Offset:                0x%016"PRIx64"\n", 0);
        }
        printf("        Hash Block Size:            0x%08"PRIx32"\n", 1 << ctx->header.ivfc_header.level_headers[i].block_size);
    }
}

static const char *save_get_save_type(save_ctx_t *ctx) {
    switch (ctx->header.extra_data.save_data_type) {
        case 0:
            return "SystemSaveData";
        case 1:
            return "SaveData";
        case 2:
            return "BcatDeliveryCacheStorage";
        case 3:
            return "DeviceSaveData";
        case 4:
            return "TemporaryStorage";
        case 5:
            return "CacheStorage";
        default:
            return "Unknown";
    }
}

void save_print(save_ctx_t *ctx) {
    printf("\nSave:\n");

    if (ctx->tool_ctx->action & ACTION_VERIFY) {
        if (ctx->disf_cmac_validity == VALIDITY_VALID) {
            memdump(stdout, "Header CMAC (GOOD):                 ", &ctx->header.cmac, 0x10);
        } else {
            memdump(stdout, "Header CMAC (FAIL):                 ", &ctx->header.cmac, 0x10);
        }
    } else {
        memdump(stdout, "Header CMAC:                        ", &ctx->header.cmac, 0x10);
    }

    printf("Title ID:                           %016"PRIx64"\n", ctx->header.extra_data.title_id);
    memdump(stdout, "User ID:                            ", &ctx->header.extra_data.user_id, 0x10);
    printf("Save ID:                            %016"PRIx64"\n", ctx->header.extra_data.save_id);
    printf("Save Type:                          %s\n", save_get_save_type(ctx));
    printf("Owner ID:                           %016"PRIx64"\n", ctx->header.extra_data.save_owner_id);
    char timestamp[70];
    if (strftime(timestamp, sizeof(timestamp), "%F %T UTC", gmtime((time_t *)&ctx->header.extra_data.timestamp)))
        printf("Timestamp:                          %s\n", timestamp);
    printf("Save Data Size:                     %016"PRIx64"\n", ctx->header.extra_data.data_size);
    printf("Journal Size:                       %016"PRIx64"\n", ctx->header.extra_data.journal_size);

    if (ctx->tool_ctx->action & ACTION_VERIFY) {
        if (ctx->hash_validity == VALIDITY_VALID) {
            memdump(stdout, "Header Hash (GOOD):                 ", &ctx->header.layout.hash, 0x20);
        } else {
            memdump(stdout, "Header Hash (FAIL):                 ", &ctx->header.layout.hash, 0x20);
        }
    } else {
        memdump(stdout, "Header Hash:                        ", &ctx->header.layout.hash, 0x20);
    }

    save_print_ivfc_section(ctx);
}
