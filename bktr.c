#include "bktr.h"
#include "utils.h"

/* Get a relocation entry from offset and relocation block. */
bktr_relocation_entry_t *bktr_get_relocation(bktr_relocation_block_t *block, uint64_t offset) {
    /* Weak check for invalid offset. */
    if (offset > block->patch_romfs_size) {
        fprintf(stderr, "Too big offset looked up in BKTR relocation table!\n");
        exit(EXIT_FAILURE);
    }
    if (block->num_entries == 1) { /* Check for edge case, short circuit. */
        return &block->entries[0];
    }
    /* Binary search. */
    uint32_t low = 0, high = block->num_entries - 1;
    while (low <= high) {
        uint32_t mid = (low + high) / 2;
        if (block->entries[mid].virt_offset > offset) { /* Too high. */
            high = mid - 1;
        } else { /* block->entries[mid].offset <= offset. */
            /* Check for success. */
            if (mid == block->num_entries - 1 || block->entries[mid+1].virt_offset > offset) {
                return &block->entries[mid];
            }
            low = mid + 1;
        }
    }
    fprintf(stderr, "Failed to find offset %012"PRIx64" in BKTR relocation table!\n", offset);
    exit(EXIT_FAILURE);
}

/* Get a subsection entry from offset and subsection block .*/
bktr_subsection_entry_t *bktr_get_subsection(bktr_subsection_block_t *block, uint64_t offset) {
    /* If offset is past the virtual, we're reading from the BKTR_HEADER subsection. */
    if (offset >= block->entries[block->num_entries].offset) {
        return &block->entries[block->num_entries];
    }
    if (block->num_entries == 1) { /* Check for edge case, short circuit. */
        return &block->entries[0];
    }
    /* Binary search. */
    uint32_t low = 0, high = block->num_entries - 1;
    while (low <= high) {
        uint32_t mid = (low + high) / 2;
        if (block->entries[mid].offset > offset) { /* Too high. */
            high = mid - 1;
        } else { /* block->entries[mid].offset <= offset. */
            /* Check for success. */
            if (mid == block->num_entries - 1 || block->entries[mid+1].offset > offset) {
                return &block->entries[mid];
            }
            low = mid + 1;
        }
    }
    fprintf(stderr, "Failed to find offset %012"PRIx64" in BKTR subsection table!\n", offset);
    exit(EXIT_FAILURE);
}
