#ifndef HACTOOL_BKTR_H
#define HACTOOL_BKTR_H

#include "types.h"

#define MAGIC_BKTR 0x52544B42

typedef struct {
    uint64_t offset;
    uint64_t size;
    uint32_t magic; /* "BKTR" */
    uint32_t _0x14; /* Version? */
    uint32_t num_entries;
    uint32_t _0x1C; /* Reserved? */
} bktr_header_t;

#pragma pack(push, 1)
typedef struct {
    uint64_t virt_offset;
    uint64_t phys_offset;
    uint32_t is_patch;
} bktr_relocation_entry_t;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct {
    uint8_t _0x0[0x4004]; /* lol. */
    uint32_t num_entries;
    uint64_t patch_romfs_size;
    bktr_relocation_entry_t entries[];
} bktr_relocation_block_t;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct {
    uint64_t  offset;
    uint32_t _0x8;
    uint32_t ctr_val;
} bktr_subsection_entry_t;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct {
    uint8_t _0x0[0x4004]; /* lol. */
    uint32_t num_entries;
    uint64_t bktr_entry_offset;
    bktr_subsection_entry_t entries[];
} bktr_subsection_block_t;
#pragma pack(pop)

bktr_relocation_entry_t *bktr_get_relocation(bktr_relocation_block_t *block, uint64_t offset);
bktr_subsection_entry_t *bktr_get_subsection(bktr_subsection_block_t *block, uint64_t offset);

#endif