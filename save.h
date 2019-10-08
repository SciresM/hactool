#ifndef HACTOOL_SAVE_H
#define HACTOOL_SAVE_H
#include "types.h"
#include "settings.h"
#include "ivfc.h"

#define SAVE_HEADER_SIZE 0x4000

#define MAGIC_DISF 0x46534944
#define MAGIC_DPFS 0x53465044
#define MAGIC_JNGL 0x4C474E4A
#define MAGIC_SAVE 0x45564153
#define MAGIC_RMAP 0x50414D52
#define MAGIC_IVFC 0x43465649

typedef struct {
    uint32_t magic; /* DISF */
    uint32_t version;
    uint8_t hash[0x20];
    uint64_t file_map_entry_offset;
    uint64_t file_map_entry_size;
    uint64_t meta_map_entry_offset;
    uint64_t meta_map_entry_size;
    uint64_t file_map_data_offset;
    uint64_t file_map_data_size;
    uint64_t duplex_l1_offset_a;
    uint64_t duplex_l1_offset_b;
    uint64_t duplex_l1_size;
    uint64_t duplex_data_offset_a;
    uint64_t duplex_data_offset_b;
    uint64_t duplex_data_size;
    uint64_t journal_data_offset;
    uint64_t journal_data_size_a;
    uint64_t journal_data_size_b;
    uint64_t journal_size;
    uint64_t duplex_master_offset_a;
    uint64_t duplex_master_offset_b;
    uint64_t duplex_master_size;
    uint64_t ivfc_master_hash_offset_a;
    uint64_t ivfc_master_hash_offset_b;
    uint64_t ivfc_master_hash_size;
    uint64_t journal_map_table_offset;
    uint64_t journal_map_table_size;
    uint64_t journal_physical_bitmap_offset;
    uint64_t journal_physical_bitmap_size;
    uint64_t journal_virtual_bitmap_offset;
    uint64_t journal_virtual_bitmap_size;
    uint64_t journal_free_bitmap_offset;
    uint64_t journal_free_bitmap_size;
    uint64_t ivfc_l1_offset;
    uint64_t ivfc_l1_size;
    uint64_t ivfc_l2_offset;
    uint64_t ivfc_l2_size;
    uint64_t ivfc_l3_offset;
    uint64_t ivfc_l3_size;
    uint64_t fat_offset;
    uint64_t fat_size;
    uint64_t duplex_index;
    uint64_t fat_ivfc_master_hash_a;
    uint64_t fat_ivfc_master_hash_b;
    uint64_t fat_ivfc_l1_offset;
    uint64_t fat_ivfc_l1_size;
    uint64_t fat_ivfc_l2_offset;
    uint64_t fat_ivfc_l2_size;
    uint8_t _0x190[0x70];
} fs_layout_t;

#pragma pack(push, 1)
typedef struct {
    uint64_t offset;
    uint64_t length;
    uint32_t block_size_power;
} duplex_info_t;
#pragma pack(pop)

typedef struct {
    uint32_t magic; /* DPFS */
    uint32_t version;
    duplex_info_t layers[3];
} duplex_header_t;

typedef struct {
    uint32_t version;
    uint32_t main_data_block_count;
    uint32_t journal_block_count;
    uint32_t _0x0C;
} journal_map_header_t;

typedef struct {
    uint32_t magic; /* JNGL */
    uint32_t version;
    uint64_t total_size;
    uint64_t journal_size;
    uint64_t block_size;
} journal_header_t;

typedef struct {
    uint32_t magic; /* SAVE */
    uint32_t version;
    uint64_t block_count;
    uint64_t block_size;
} save_fs_header_t;

typedef struct {
    uint64_t block_size;
    uint64_t fat_offset;
    uint32_t fat_block_count;
    uint32_t _0x14;
    uint64_t data_offset;
    uint32_t data_block_count;
    uint32_t _0x24;
    uint32_t directory_table_block;
    uint32_t file_table_block;
} fat_header_t;

typedef struct {
    uint32_t magic; /* RMAP */
    uint32_t version;
    uint32_t map_entry_count;
    uint32_t map_segment_count;
    uint32_t segment_bits;
    uint8_t _0x14[0x2C];
} remap_header_t;

typedef struct remap_segment_ctx_t remap_segment_ctx_t;
typedef struct remap_entry_ctx_t remap_entry_ctx_t;

#pragma pack(push, 1)
struct remap_entry_ctx_t {
    uint64_t virtual_offset;
    uint64_t physical_offset;
    uint64_t size;
    uint32_t alignment;
    uint32_t _0x1C;
    uint64_t virtual_offset_end;
    uint64_t physical_offset_end;
    remap_segment_ctx_t *segment;
    remap_entry_ctx_t *next;
};
#pragma pack(pop)

struct remap_segment_ctx_t{
    uint64_t offset;
    uint64_t length;
    remap_entry_ctx_t *entries;
    uint64_t entry_count;
};

typedef struct {
    uint64_t base_storage_offset;
    remap_header_t *header;
    remap_entry_ctx_t *map_entries;
    remap_segment_ctx_t *segments;
    FILE *file;
} remap_storage_ctx_t;

typedef struct {
    uint64_t title_id;
    uint8_t user_id[0x10];
    uint64_t save_id;
    uint8_t save_data_type;
    uint8_t _0x21[0x1F];
    uint64_t save_owner_id;
    uint64_t timestamp;
    uint64_t _0x50;
    uint64_t data_size;
    uint64_t journal_size;
    uint64_t commit_id;
} extra_data_t;

#pragma pack(push, 1)
typedef struct {
    uint8_t cmac[0x10];
    uint8_t _0x10[0xF0];
    fs_layout_t layout;
    duplex_header_t duplex_header;
    ivfc_save_hdr_t data_ivfc_header;
    uint32_t _0x404;
    journal_header_t journal_header;
    journal_map_header_t map_header;
    uint8_t _0x438[0x1D0];
    save_fs_header_t save_header;
    fat_header_t fat_header;
    remap_header_t main_remap_header, meta_remap_header;
    uint64_t _0x6D0;
    extra_data_t extra_data;
    uint8_t _0x748[0x390];
    ivfc_save_hdr_t fat_ivfc_header;
    uint8_t _0xB98[0x3468];
} save_header_t;
#pragma pack(pop)

typedef struct {
    uint8_t *data;
    uint8_t *bitmap;
} duplex_bitmap_t;

typedef struct {
    uint32_t block_size;
    uint8_t *bitmap_storage;
    uint8_t *data_a;
    uint8_t *data_b;
    duplex_bitmap_t bitmap;
    uint64_t _length;
} duplex_storage_ctx_t;

typedef struct {
    duplex_storage_ctx_t layers[2];
    duplex_storage_ctx_t data_layer;
    uint64_t _length;
} hierarchical_duplex_storage_ctx_t;

typedef struct {
    uint8_t *data_a;
    uint8_t *data_b;
    duplex_info_t info;
} duplex_fs_layer_info_t;

typedef struct {
    FILE *file;
    hactool_ctx_t *tool_ctx;
    save_header_t header;
    validity_t header_cmac_validity;
    validity_t header_hash_validity;
    uint8_t *duplex_master_bitmap_a;
    uint8_t *duplex_master_bitmap_b;
    uint8_t *data_ivfc_master;
    uint8_t *fat_ivfc_master;
    remap_storage_ctx_t data_remap_storage;
    remap_storage_ctx_t meta_remap_storage;
    hierarchical_duplex_storage_ctx_t duplex_storage;
    duplex_fs_layer_info_t duplex_layers[3];
    ivfc_level_ctx_t ivfc_levels[IVFC_MAX_LEVEL];
} save_ctx_t;

void save_process(save_ctx_t *ctx);
void save_process_header(save_ctx_t *ctx);
void save_save(save_ctx_t *ctx);
void save_print(save_ctx_t *ctx);

void save_free_contexts(save_ctx_t *ctx);

#endif
