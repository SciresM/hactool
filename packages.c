#include <string.h>
#include <stdio.h>
#include "packages.h"
#include "aes.h"

void pk11_process(pk11_ctx_t *ctx) {
    fseeko64(ctx->file, 0, SEEK_SET);
    if (fread(&ctx->stage1, 1, sizeof(ctx->stage1), ctx->file) != sizeof(ctx->stage1)) {
        fprintf(stderr, "Failed to read PK11 Stage 1!\n");
        exit(EXIT_FAILURE);
    }
    
    /* Check if PK11 was built in 2016. */
    /* This is a heuristic to detect an older layout for the PK11 binary. */
    if (ctx->stage1.build_date[0] == '2' && ctx->stage1.build_date[1] == '0' && ctx->stage1.build_date[2] == '1' && ctx->stage1.build_date[3] == '6') {
        ctx->is_pilot = 1;
    } else {
        ctx->is_pilot = 0;
    }
    
    ctx->pk11 = malloc(ctx->stage1.pk11_size);
    if (ctx->pk11 == NULL) {
        fprintf(stderr, "Failed to allocate PK11!\n");
        exit(EXIT_FAILURE);
    }
    
    if (fread(ctx->pk11, 1, ctx->stage1.pk11_size, ctx->file) != ctx->stage1.pk11_size) {
        fprintf(stderr, "Failed to read PK11!\n");
        exit(EXIT_FAILURE);
    }
    
    aes_ctx_t *crypt_ctx = NULL;
    pk11_t dec_header;
    for (unsigned int i = 0; i < 0x20; i++) {
        ctx->key_rev = i;
        crypt_ctx = new_aes_ctx(&ctx->tool_ctx->settings.keyset.package1_keys[i], 0x10, AES_MODE_CTR);
        aes_setiv(crypt_ctx, ctx->stage1.ctr, 0x10);
        aes_decrypt(crypt_ctx, &dec_header, ctx->pk11, sizeof(dec_header));
        if (dec_header.magic == MAGIC_PK11) {
            break;
        }
        free_aes_ctx(crypt_ctx);
        crypt_ctx = NULL;
    }
    
    if (crypt_ctx == NULL) {
        fprintf(stderr, "Failed to decrypt PK11! Is correct key present?\n");
        exit(EXIT_FAILURE);
    }
    
    aes_setiv(crypt_ctx, ctx->stage1.ctr, 0x10);
    aes_decrypt(crypt_ctx, ctx->pk11, ctx->pk11, ctx->stage1.pk11_size);
    
    uint64_t pk11_size = 0x20 + ctx->pk11->warmboot_size + ctx->pk11->nx_bootloader_size + ctx->pk11->secmon_size;
    pk11_size = align64(pk11_size, 0x10);
    if (pk11_size != ctx->stage1.pk11_size) {
        fprintf(stderr, "PK11 seems corrupt!\n");
        exit(EXIT_FAILURE);
    }
    
    if (ctx->tool_ctx->action & ACTION_INFO) {
        pk11_print(ctx);
    }
    
    if (ctx->tool_ctx->action & ACTION_EXTRACT) {
        pk11_save(ctx);
    }
}

void pk11_print(pk11_ctx_t *ctx) {
    printf("PK11:\n");
    printf("    Build Date:                     %s\n", ctx->stage1.build_date);
    memdump(stdout, "    Build Hash:                     ", ctx->stage1.build_hash, 0x10);
    printf("    Key Revision:                   %02"PRIx32" (%s)\n", ctx->key_rev, get_key_revision_summary((uint8_t)ctx->key_rev));
    printf("    PK11 Size:                      %08"PRIx32"\n", ctx->stage1.pk11_size);
    printf("    Warmboot.bin Size:              %08"PRIx32"\n", ctx->pk11->warmboot_size);
    printf("    NX_Bootloader.bin Size          %08"PRIx32"\n", ctx->pk11->nx_bootloader_size);
    printf("    Secure_Monitor.bin Size:        %08"PRIx32"\n", ctx->pk11->secmon_size);
    printf("\n");
}

void pk11_save(pk11_ctx_t *ctx) {
    /* Extract to directory. */
    filepath_t *dirpath = NULL;
    if (ctx->tool_ctx->file_type == FILETYPE_PACKAGE1 && ctx->tool_ctx->settings.out_dir_path.enabled) {
        dirpath = &ctx->tool_ctx->settings.out_dir_path.path;
    }
    if (dirpath == NULL || dirpath->valid != VALIDITY_VALID) {
        dirpath = &ctx->tool_ctx->settings.pk11_dir_path;
    }
    if (dirpath != NULL && dirpath->valid == VALIDITY_VALID) {
        os_makedir(dirpath->os_path);
        
        /* Save Decrypted.bin */
        printf("Saving decrypted binary to %s/Decrypted.bin\n", dirpath->char_path);
        char *decrypted_bin = malloc(sizeof(ctx->stage1) + ctx->stage1.pk11_size);
        if (decrypted_bin == NULL) {
            fprintf(stderr, "Failed to allocate buffer!\n");
            exit(EXIT_FAILURE);
        }
        memcpy(decrypted_bin, &ctx->stage1, sizeof(ctx->stage1));
        memcpy(decrypted_bin + sizeof(ctx->stage1), ctx->pk11, ctx->stage1.pk11_size);
        save_buffer_to_directory_file(decrypted_bin, sizeof(ctx->stage1) + ctx->stage1.pk11_size, dirpath, "Decrypted.bin");
        free(decrypted_bin);
        
        /* Save Warmboot.bin */
        printf("Saving Warmboot.bin to %s/Warmboot.bin...\n", dirpath->char_path);
        save_buffer_to_directory_file(pk11_get_warmboot_bin(ctx), ctx->pk11->warmboot_size, dirpath, "Warmboot.bin");
        
        /* Save NX_Bootloader.bin */
        printf("Saving NX_Bootloader.bin to %s/NX_Bootloader.bin...\n", dirpath->char_path);
        save_buffer_to_directory_file(pk11_get_nx_bootloader(ctx), ctx->pk11->nx_bootloader_size, dirpath, "NX_Bootloader.bin");
        
        /* Save Secure_Monitor.bin */
        printf("Saving Secure_Monitor.bin to %s/Secure_Monitor.bin...\n", dirpath->char_path);
        save_buffer_to_directory_file(pk11_get_secmon(ctx), ctx->pk11->secmon_size, dirpath, "Secure_Monitor.bin");
    }
}