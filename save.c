#include <string.h>
#include <time.h>
#include "save.h"
#include "aes.h"
#include "sha.h"

#define REMAP_ENTRY_LENGTH 0x20

remap_segment_ctx_t *save_remap_init_segments(remap_header_t *header, remap_entry_ctx_t *map_entries, uint32_t num_map_entries) {
    remap_segment_ctx_t *segments =  malloc(sizeof(remap_segment_ctx_t) * header->map_segment_count);
    unsigned int entry_idx = 0;

    for (unsigned int i = 0; i < header->map_segment_count; i++) {
        remap_segment_ctx_t seg;
        seg.entries = malloc(sizeof(remap_entry_ctx_t));
        memcpy(seg.entries, &map_entries[entry_idx], sizeof(remap_entry_ctx_t));
        seg.offset = map_entries[entry_idx].virtual_offset;
        map_entries[entry_idx].segment = &seg;
        seg.entry_count = 1;
        entry_idx++;

        while (entry_idx < num_map_entries && map_entries[entry_idx - 1].virtual_offset_end == map_entries[entry_idx].virtual_offset) {
            map_entries[entry_idx].segment = &seg;
            map_entries[entry_idx - 1].next = &map_entries[entry_idx];
            seg.entries = malloc(sizeof(remap_entry_ctx_t));
            memcpy(seg.entries, &map_entries[entry_idx], sizeof(remap_entry_ctx_t));
            seg.entry_count++;
            entry_idx++;
        }
        seg.length = seg.entries[seg.entry_count - 1].virtual_offset_end - seg.entries[0].virtual_offset;
        memcpy(&segments[i], &seg, sizeof(remap_segment_ctx_t));
    }
    return segments;
}

remap_entry_ctx_t *save_remap_get_map_entry(remap_storage_ctx_t *ctx, uint64_t offset) {
    uint32_t segment_idx = (uint32_t)(offset >> (64 - ctx->header->segment_bits));
    if (segment_idx < ctx->header->map_segment_count) {
        for (unsigned int i = 0; i < ctx->segments[segment_idx].entry_count; i++)
            if (ctx->segments[segment_idx].entries[i].virtual_offset_end > offset)
                return &ctx->segments[segment_idx].entries[i];
    }
    fprintf(stderr, "Remap offset %"PRIx64" out of range!\n", offset);
    exit(EXIT_FAILURE);
}

void save_remap_read(remap_storage_ctx_t *ctx, void *buffer, uint64_t offset, size_t count) {
    remap_entry_ctx_t *entry = save_remap_get_map_entry(ctx, offset);
    uint64_t in_pos = offset;
    uint32_t out_pos = 0;
    uint32_t remaining = count;

    while (remaining) {
        uint64_t entry_pos = in_pos - entry->virtual_offset;
        uint32_t bytes_to_read = entry->virtual_offset_end - in_pos < remaining ? (uint32_t)(entry->virtual_offset_end - in_pos) : remaining;

        switch (ctx->type) {
            case STORAGE_BYTES:
                fseeko64(ctx->file, ctx->base_storage_offset + entry->physical_offset + entry_pos, SEEK_SET);
                fread((uint8_t *)buffer + out_pos, 1, bytes_to_read, ctx->file);
                break;
            case STORAGE_DUPLEX:
                save_duplex_storage_read(ctx->duplex, (uint8_t *)buffer + out_pos, ctx->base_storage_offset + entry->physical_offset + entry_pos, bytes_to_read);
                break;
            default:
                break;
        }
        
        out_pos += bytes_to_read;
        in_pos += bytes_to_read;
        remaining -= bytes_to_read;

        if (in_pos >= entry->virtual_offset_end)
            entry = entry->next;
    }
}

void save_bitmap_set_bit(void *buffer, size_t bit_offset) {
    *((uint8_t *)buffer + (bit_offset >> 3)) |= 1 << (bit_offset & 7);
}

void save_bitmap_clear_bit(void *buffer, size_t bit_offset) {
    *((uint8_t *)buffer + (bit_offset >> 3)) &= ~(uint8_t)(1 << (bit_offset & 7));
}

uint8_t save_bitmap_check_bit(void *buffer, size_t bit_offset) {
    return *((uint8_t *)buffer + (bit_offset >> 3)) & (1 << (bit_offset & 7));
}

void save_duplex_storage_init(duplex_storage_ctx_t *ctx, duplex_fs_layer_info_t *layer, void *bitmap, uint64_t bitmap_size) {
    ctx->data_a = layer->data_a;
    ctx->data_b = layer->data_b;
    ctx->bitmap_storage = (uint8_t *)bitmap;
    ctx->block_size = 1 << layer->info.block_size_power;

    ctx->bitmap.data = ctx->bitmap_storage;
    ctx->bitmap.bitmap = malloc(bitmap_size >> 3);

    uint32_t bits_remaining = bitmap_size;
    uint32_t bitmap_pos = 0;
    uint32_t *buffer_pos = (uint32_t *)bitmap;
    while (bits_remaining) {
        uint32_t bits_to_read = bits_remaining < 32 ? bits_remaining : 32;
        uint32_t val = *buffer_pos;
        for (uint32_t i = 0; i < bits_to_read; i++) {
            if (val & 0x80000000U)
                save_bitmap_set_bit(ctx->bitmap.bitmap, bitmap_pos);
            else
                save_bitmap_clear_bit(ctx->bitmap.bitmap, bitmap_pos);
            bitmap_pos++;
            bits_remaining--;
            val <<= 1;
        }
        buffer_pos++;
    }
}

void save_duplex_storage_read(duplex_storage_ctx_t *ctx, void *buffer, uint64_t offset, size_t count) {
    uint64_t in_pos = offset;
    uint32_t out_pos = 0;
    uint32_t remaining = count;

    while (remaining) {
        uint32_t block_num = (uint32_t)(in_pos / ctx->block_size);
        uint32_t block_pos = (uint32_t)(in_pos % ctx->block_size);
        uint32_t bytes_to_read = ctx->block_size - block_pos < remaining ? ctx->block_size - block_pos : remaining;

        uint8_t *data = save_bitmap_check_bit(ctx->bitmap.bitmap, block_num) ? ctx->data_b : ctx->data_a;
        memcpy((uint8_t *)buffer + out_pos, data + in_pos, bytes_to_read);

        out_pos += bytes_to_read;
        in_pos += bytes_to_read;
        remaining -= bytes_to_read;
    }
}

void save_process(save_ctx_t *ctx) {
    // lh: SaveDataFileSystem ctor
    /* Try to parse Header A. */
    fseeko64(ctx->file, 0, SEEK_SET);
    if (fread(&ctx->header, 1, sizeof(ctx->header), ctx->file) != sizeof(ctx->header)) {
        fprintf(stderr, "Failed to read save header!\n");
        exit(EXIT_FAILURE);
    }

    save_process_header(ctx);

    if (ctx->header_hash_validity == VALIDITY_INVALID) {
        /* Try to parse Header B. */
        fseeko64(ctx->file, 0x4000, SEEK_SET);
        if (fread(&ctx->header, 1, sizeof(ctx->header), ctx->file) != sizeof(ctx->header)) {
            fprintf(stderr, "Failed to read save header!\n");
            exit(EXIT_FAILURE);
        }

        save_process_header(ctx);

        if (ctx->header_hash_validity == VALIDITY_INVALID) {
            fprintf(stderr, "Error: Save header is invalid!\n");
            exit(EXIT_FAILURE);
        }
    }

    unsigned char cmac[0x10];
    memset(cmac, 0, 0x10);
    aes_calculate_cmac(cmac, &ctx->header.layout, sizeof(ctx->header.layout), ctx->tool_ctx->settings.keyset.save_mac_key);
    if (memcmp(cmac, &ctx->header.cmac, 0x10) == 0) {
        ctx->header_cmac_validity = VALIDITY_VALID;
    } else {
        ctx->header_cmac_validity = VALIDITY_INVALID;
        memdump(stdout, "bad hash ", cmac, 0x10);
    }

    /* Initialize remap storages. */
    // lh: RemapStorage ctor for DataRemapStorage
    ctx->data_remap_storage.type = STORAGE_BYTES;
    ctx->data_remap_storage.base_storage_offset = ctx->header.layout.file_map_data_offset;
    ctx->data_remap_storage.header = &ctx->header.main_remap_header;
    ctx->data_remap_storage.map_entries = malloc(sizeof(remap_entry_ctx_t) * ctx->data_remap_storage.header->map_entry_count);
    ctx->data_remap_storage.file = ctx->file;
    fseeko64(ctx->file, ctx->header.layout.file_map_entry_offset, SEEK_SET);
    for (unsigned int i = 0; i < ctx->data_remap_storage.header->map_entry_count; i++) {
        fread(&ctx->data_remap_storage.map_entries[i], 0x20, 1, ctx->file);
        ctx->data_remap_storage.map_entries[i].physical_offset_end = ctx->data_remap_storage.map_entries[i].physical_offset + ctx->data_remap_storage.map_entries[i].size;
        ctx->data_remap_storage.map_entries[i].virtual_offset_end = ctx->data_remap_storage.map_entries[i].virtual_offset + ctx->data_remap_storage.map_entries[i].size;
    }

    // lh: InitSegments for DataRemapStorage
    ctx->data_remap_storage.segments = save_remap_init_segments(ctx->data_remap_storage.header, ctx->data_remap_storage.map_entries, ctx->data_remap_storage.header->map_entry_count);

    // lh: InitDuplexStorage for DuplexStorage using DataRemapStorage
    ctx->duplex_layers[0].data_a = (uint8_t *)&ctx->header + ctx->header.layout.duplex_master_offset_a;
    ctx->duplex_layers[0].data_b = (uint8_t *)&ctx->header + ctx->header.layout.duplex_master_offset_b;
    memcpy(&ctx->duplex_layers[0].info, &ctx->header.duplex_header.layers[0], sizeof(duplex_info_t));

    ctx->duplex_layers[1].data_a = malloc(ctx->header.layout.duplex_l1_size);
    save_remap_read(&ctx->data_remap_storage, ctx->duplex_layers[1].data_a, ctx->header.layout.duplex_l1_offset_a, ctx->header.layout.duplex_l1_size);
    ctx->duplex_layers[1].data_b = malloc(ctx->header.layout.duplex_l1_size);
    save_remap_read(&ctx->data_remap_storage, ctx->duplex_layers[1].data_b, ctx->header.layout.duplex_l1_offset_b, ctx->header.layout.duplex_l1_size);
    memcpy(&ctx->duplex_layers[1].info, &ctx->header.duplex_header.layers[1], sizeof(duplex_info_t));

    ctx->duplex_layers[2].data_a = malloc(ctx->header.layout.duplex_data_size);
    save_remap_read(&ctx->data_remap_storage, ctx->duplex_layers[2].data_a, ctx->header.layout.duplex_data_offset_a, ctx->header.layout.duplex_data_size);
    ctx->duplex_layers[2].data_b = malloc(ctx->header.layout.duplex_data_size);
    save_remap_read(&ctx->data_remap_storage, ctx->duplex_layers[2].data_b, ctx->header.layout.duplex_data_offset_b, ctx->header.layout.duplex_data_size);
    memcpy(&ctx->duplex_layers[2].info, &ctx->header.duplex_header.layers[2], sizeof(duplex_info_t));

    // lh: HierarchicalDuplexStorage ctor for InitDuplexStorage
    uint8_t *bitmap = ctx->header.layout.duplex_index == 1 ? ctx->duplex_layers[0].data_b : ctx->duplex_layers[0].data_a;
    save_duplex_storage_init(&ctx->duplex_storage.layers[0], &ctx->duplex_layers[1], bitmap, ctx->header.layout.duplex_master_size);
    ctx->duplex_storage.layers[0]._length = ctx->header.layout.duplex_l1_size;

    bitmap = malloc(ctx->duplex_storage.layers[0]._length);
    save_duplex_storage_read(&ctx->duplex_storage.layers[0], bitmap, 0, ctx->duplex_storage.layers[0]._length);
    save_duplex_storage_init(&ctx->duplex_storage.layers[1], &ctx->duplex_layers[2], bitmap, ctx->duplex_storage.layers[0]._length);
    ctx->duplex_storage.layers[1]._length = ctx->header.layout.duplex_data_size;

    ctx->duplex_storage.data_layer = ctx->duplex_storage.layers[1];

    // lh: RemapStorage ctor for MetaRemapStorage using DuplexStorage
    ctx->meta_remap_storage.type = STORAGE_DUPLEX;
    ctx->meta_remap_storage.duplex = &ctx->duplex_storage.data_layer;
    ctx->meta_remap_storage.header = &ctx->header.meta_remap_header;
    ctx->meta_remap_storage.map_entries = malloc(sizeof(remap_entry_ctx_t) * ctx->meta_remap_storage.header->map_entry_count);
    fseeko64(ctx->file, ctx->header.layout.meta_map_entry_offset, SEEK_SET);
    for (unsigned int i = 0; i < ctx->meta_remap_storage.header->map_entry_count; i++) {
        fread(&ctx->meta_remap_storage.map_entries[i], 0x20, 1, ctx->file);
        ctx->meta_remap_storage.map_entries[i].physical_offset_end = ctx->meta_remap_storage.map_entries[i].physical_offset + ctx->meta_remap_storage.map_entries[i].size;
        ctx->meta_remap_storage.map_entries[i].virtual_offset_end = ctx->meta_remap_storage.map_entries[i].virtual_offset + ctx->meta_remap_storage.map_entries[i].size;
    }

    // lh: InitSegments for MetaRemapStorage
    ctx->meta_remap_storage.segments = save_remap_init_segments(ctx->meta_remap_storage.header, ctx->meta_remap_storage.map_entries, ctx->meta_remap_storage.header->map_entry_count);

    // lh: JournalMapParams ctor for local journalMapInfo using MetaRemapStorage
    journal_map_params_t journal_map_info;
    journal_map_info.map_storage = malloc(ctx->header.layout.journal_map_table_size);
    save_remap_read(&ctx->meta_remap_storage, journal_map_info.map_storage, ctx->header.layout.journal_map_table_offset, ctx->header.layout.journal_map_table_size);
    free(journal_map_info.map_storage);
    // memdump(stdout, "", journal_map_info.map_storage, ctx->header.layout.journal_map_table_size);

    // journal_map_info.physical_block_bitmap = malloc(ctx->header.layout.journal_physical_bitmap_size);
    // save_remap_read(&ctx->meta_remap_storage, journal_map_info.physical_block_bitmap, ctx->header.layout.journal_physical_bitmap_offset, ctx->header.layout.journal_physical_bitmap_size);
    // memdump(stdout, "", journal_map_info.physical_block_bitmap, ctx->header.layout.journal_physical_bitmap_size);

    // journal_map_info.virtual_block_bitmap = malloc(ctx->header.layout.journal_virtual_bitmap_size);
    // save_remap_read(&ctx->meta_remap_storage, journal_map_info.virtual_block_bitmap, ctx->header.layout.journal_virtual_bitmap_offset, ctx->header.layout.journal_virtual_bitmap_size);
    // memdump(stdout, "", journal_map_info.virtual_block_bitmap, ctx->header.layout.journal_virtual_bitmap_size);

    // journal_map_info.free_block_bitmap = malloc(ctx->header.layout.journal_free_bitmap_size);
    // save_remap_read(&ctx->meta_remap_storage, journal_map_info.free_block_bitmap, ctx->header.layout.journal_free_bitmap_offset, ctx->header.layout.journal_free_bitmap_size);
    // memdump(stdout, "", journal_map_info.free_block_bitmap, ctx->header.layout.journal_free_bitmap_size);

    // lh: local journalData from DataRemapStorage
    // can't malloc, it's most of the file size
    ctx->data_remap_storage.base_storage_offset = ctx->header.layout.journal_data_offset;

    // lh: JournalStorage ctor for JournalStorage from journalData, journalMapInfo
    ctx->journal_storage.header = &ctx->header.journal_header;
    ctx->journal_storage.map.header = &ctx->header.map_header;
    ctx->journal_storage.map.map_storage = journal_map_info.map_storage;
    ctx->journal_storage.map.entries = malloc(sizeof(journal_map_entry_t) * ctx->journal_storage.map.header->main_data_block_count);
    uint32_t *pos = (uint32_t *)ctx->journal_storage.map.map_storage;
    for (unsigned int i = 0; i < ctx->journal_storage.map.header->main_data_block_count; i++) {
        ctx->journal_storage.map.entries[i].virtual_index = i;
        ctx->journal_storage.map.entries[i].physical_index = *pos & 0x7FFFFFFF;
        pos += 2;
    }
    ctx->journal_storage.block_size = ctx->journal_storage.header->block_size;
    ctx->journal_storage._length = ctx->journal_storage.header->total_size - ctx->journal_storage.header->journal_size;

    // lh: InitJournalIvfcStorage for CoreDataIvfcStorage
    ivfc_save_hdr_t *ivfc = &ctx->header.data_ivfc_header;
    ivfc_level_save_ctx_t levels[ivfc->num_levels]; // 5
    memset(&levels, 0, sizeof(ivfc_level_save_ctx_t) * ivfc->num_levels);
    levels[0].type = STORAGE_BYTES;
    levels[0].hash_offset = ctx->header.layout.ivfc_master_hash_offset_a;
    for (unsigned int i = 1; i < ivfc->num_levels - 1; i++) {
        ivfc_level_hdr_t *level = &ivfc->level_headers[i - 1];
        levels[i].type = STORAGE_REMAP;
        levels[i].data_offset = level->logical_offset;
        levels[i].data_size = level->hash_data_size;
    }
    ivfc_level_hdr_t *data_level = &ivfc->level_headers[ivfc->num_levels - 2];
    levels[ivfc->num_levels - 1].type = STORAGE_JOURNAL;
    levels[ivfc->num_levels - 1].data_offset = data_level->logical_offset;
    levels[ivfc->num_levels - 1].data_size = data_level->hash_data_size;

    // lh: HierarchicalIntegrityVerificationStorage ctor for CoreDataIvfcStorage
    // lh: GetIvfcInfo ctor from local ivfc, levels
    typedef struct {
        char string[50];
        uint32_t length;
    } salt_source_t;

    static salt_source_t salt_sources[6] = {
        {"HierarchicalIntegrityVerificationStorage::Master", 48},
        {"HierarchicalIntegrityVerificationStorage::L1", 44},
        {"HierarchicalIntegrityVerificationStorage::L2", 44},
        {"HierarchicalIntegrityVerificationStorage::L3", 44},
        {"HierarchicalIntegrityVerificationStorage::L4", 44},
        {"HierarchicalIntegrityVerificationStorage::L5", 44}
    };
    integrity_verification_info_ctx_t init_info[ivfc->num_levels]; // 5

    init_info[0].data = &levels[0];
    init_info[0].block_size = 0;
    for (unsigned int i = 1; i < ivfc->num_levels; i++) {
        init_info[i].data = &levels[i];
        init_info[i].block_size = 1 << ivfc->level_headers[i - 1].block_size;
        sha256_get_buffer_hmac(init_info[i].salt, salt_sources[i - 1].string, salt_sources[i - 1].length, ivfc->salt_source, 0x20);
    }

    ctx->core_data_ivfc_storage.levels[0] = init_info[0].data;
    ctx->core_data_ivfc_storage.level_validities = malloc(sizeof(validity_t *) * (ivfc->num_levels - 1));
    for (unsigned int i = 1; i < ivfc->num_levels; i++) {
        integrity_verification_storage_ctx_t *level_data = &ctx->core_data_ivfc_storage.integrity_storages[i - 1];
        level_data->hash_storage = ctx->core_data_ivfc_storage.levels[i - 1];
        level_data->sector_size = init_info[i].block_size;
        level_data->_length = init_info[i].data->data_size;
        level_data->sector_count = (level_data->_length + level_data->sector_size - 1) / level_data->sector_size;
        memcpy(level_data->salt, init_info[i].salt, 0x20);
        ctx->core_data_ivfc_storage.levels[i] = init_info[i].data;
        level_data->block_validities = calloc(1, sizeof(validity_t) * level_data->sector_count);
        ctx->core_data_ivfc_storage.level_validities[i - 1] = level_data->block_validities;
    }
    ctx->core_data_ivfc_storage.data_level = ctx->core_data_ivfc_storage.levels[ivfc->num_levels - 1];
    ctx->core_data_ivfc_storage._length = ctx->core_data_ivfc_storage.integrity_storages[ivfc->num_levels - 2]._length;

    // lh: local fatStorage from MetaRemapStorage
    uint8_t *fat_storage = malloc(ctx->header.layout.fat_size);
    save_remap_read(&ctx->meta_remap_storage, fat_storage, ctx->header.layout.fat_offset, ctx->header.layout.fat_size);
    free(fat_storage);

    // lh: InitFatIvfcStorage for FatIvfcStorage

    // lh: SaveDataFileSystemCore ctor for SaveDataFileSystemCore from CoreDataIvfcStorage, fatStorage

    if (ctx->tool_ctx->action & ACTION_INFO) {
        save_print(ctx);
    }

    if (ctx->tool_ctx->action & ACTION_EXTRACT) {
        save_save(ctx);
    }
}

void save_process_header(save_ctx_t *ctx) {
    if (ctx->header.layout.magic != MAGIC_DISF || ctx->header.duplex_header.magic != MAGIC_DPFS ||
        ctx->header.data_ivfc_header.magic != MAGIC_IVFC || ctx->header.journal_header.magic != MAGIC_JNGL ||
        ctx->header.save_header.magic != MAGIC_SAVE || ctx->header.main_remap_header.magic != MAGIC_RMAP ||
        ctx->header.meta_remap_header.magic != MAGIC_RMAP) {
        fprintf(stderr, "Error: Save header is corrupt!\n");
        exit(EXIT_FAILURE);
    }

    ctx->data_ivfc_master = (uint8_t *)&ctx->header + ctx->header.layout.ivfc_master_hash_offset_a;
    ctx->fat_ivfc_master = (uint8_t *)&ctx->header + ctx->header.layout.fat_ivfc_master_hash_a;

    ctx->header.data_ivfc_header.num_levels = 5;

    if (ctx->header.layout.version >= 0x50000) {
        ctx->header.fat_ivfc_header.num_levels = 4;
    }

    ctx->header_hash_validity = check_memory_hash_table(ctx->file, ctx->header.layout.hash, 0x300, 0x3D00, 0x3D00, 0);
}

void save_free_contexts(save_ctx_t *ctx) {
    for (unsigned int i = 0; i < ctx->data_remap_storage.header->map_segment_count; i++) {
        for (unsigned int j = 0; j < ctx->data_remap_storage.segments[i].entry_count; j++) {
            free(&ctx->data_remap_storage.segments[i].entries[j]);
        }
    }
    free(ctx->data_remap_storage.segments);
    for (unsigned int i = 0; i < ctx->meta_remap_storage.header->map_segment_count; i++) {
        for (unsigned int j = 0; j < ctx->meta_remap_storage.segments[i].entry_count; j++) {
            free(&ctx->meta_remap_storage.segments[i].entries[j]);
        }
    }
    free(ctx->meta_remap_storage.segments);
    free(ctx->data_remap_storage.map_entries);
    free(ctx->meta_remap_storage.map_entries);
    free(ctx->duplex_storage.layers[0].bitmap.bitmap);
    free(ctx->duplex_storage.layers[1].bitmap.bitmap);
    free(ctx->duplex_storage.layers[1].bitmap_storage);
    for (unsigned int i = 1; i < 3; i++) {
        free(ctx->duplex_layers[i].data_a);
        free(ctx->duplex_layers[i].data_b);
    }
    free(ctx->journal_storage.map.entries);
    for (unsigned int i = 1; i < ctx->header.data_ivfc_header.num_levels; i++) {
        free(ctx->core_data_ivfc_storage.integrity_storages[i].block_validities);
    }
    free(ctx->core_data_ivfc_storage.level_validities);
}

void save_save(save_ctx_t *ctx) {
    filepath_t *dirpath = NULL;
    if (ctx->tool_ctx->file_type == FILETYPE_SAVE && ctx->tool_ctx->settings.out_dir_path.enabled) {
        dirpath = &ctx->tool_ctx->settings.out_dir_path.path;
    }
    if (dirpath != NULL && dirpath->valid == VALIDITY_VALID) {
        os_makedir(dirpath->os_path);
    }
}

void save_print_ivfc_section(save_ctx_t *ctx) {
    print_magic("    Magic:                          ", ctx->header.data_ivfc_header.magic);
    printf("    ID:                             %08"PRIx32"\n", ctx->header.data_ivfc_header.id);
    memdump(stdout, "    Salt Seed:                      ", &ctx->header.data_ivfc_header.salt_source, 0x20);
    for (unsigned int i = 0; i < 4; i++) {
        printf("    Level %"PRId32":\n", i);
        printf("        Data Offset:                0x%016"PRIx64"\n", ctx->header.data_ivfc_header.level_headers[i].logical_offset);
        printf("        Data Size:                  0x%016"PRIx64"\n", ctx->header.data_ivfc_header.level_headers[i].hash_data_size);
        if (i != 0) {
            printf("        Hash Offset:                0x%016"PRIx64"\n", ctx->header.data_ivfc_header.level_headers[i-1].logical_offset);
        } else {
            printf("        Hash Offset:                0x%016"PRIx64"\n", 0x0UL);
        }
        printf("        Hash Block Size:            0x%08"PRIx32"\n", 1 << ctx->header.data_ivfc_header.level_headers[i].block_size);
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
        if (ctx->header_cmac_validity == VALIDITY_VALID) {
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
        if (ctx->header_hash_validity == VALIDITY_VALID) {
            memdump(stdout, "Header Hash (GOOD):                 ", &ctx->header.layout.hash, 0x20);
        } else {
            memdump(stdout, "Header Hash (FAIL):                 ", &ctx->header.layout.hash, 0x20);
        }
    } else {
        memdump(stdout, "Header Hash:                        ", &ctx->header.layout.hash, 0x20);
    }

    save_print_ivfc_section(ctx);
}
