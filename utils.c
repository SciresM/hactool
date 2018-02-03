#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#ifdef _WIN32
#include <direct.h>
#endif
#include "utils.h"

uint32_t align(uint32_t offset, uint32_t alignment) {
    uint32_t mask = ~(alignment-1);

    return (offset + (alignment-1)) & mask;
}

uint64_t align64(uint64_t offset, uint64_t alignment) {
    uint64_t mask = ~(uint64_t)(alignment-1);

    return (offset + (alignment-1)) & mask;
}

/* Print a magic number. */
void print_magic(const char *prefix, uint32_t magic) {
    printf("%s%c%c%c%c\n", prefix, (char)((magic >> 0) & 0xFF), (char)((magic >> 8) & 0xFF), (char)((magic >> 16) & 0xFF), (char)((magic >> 24) & 0xFF));
}


/* Taken mostly from ctrtool. */
void memdump(FILE *f, const char *prefix, const void *data, size_t size) {
    uint8_t *p = (uint8_t *)data;

    unsigned int prefix_len = strlen(prefix);
    size_t offset = 0;
    int first = 1;

    while (size) {
        unsigned int max = 32;

        if (max > size) {
            max = size;
        }

        if (first) {
            fprintf(f, "%s", prefix);
            first = 0;
        } else {
            fprintf(f, "%*s", prefix_len, "");
        }

        for (unsigned int i = 0; i < max; i++) {
            fprintf(f, "%02X", p[offset++]);
        }

        fprintf(f, "\n");

        size -= max;
    }
}

void save_file_section(FILE *f_in, uint64_t ofs, uint64_t total_size, filepath_t *filepath) {
    FILE *f_out = os_fopen(filepath->os_path, OS_MODE_WRITE);

    if (f_out == NULL) {
        fprintf(stderr, "Failed to open %s!\n", filepath->char_path);
        return;
    }

    uint64_t read_size = 0x400000; /* 4 MB buffer. */
    unsigned char *buf = malloc(read_size);
    if (buf == NULL) {
        fprintf(stderr, "Failed to allocate file-save buffer!\n");
        exit(EXIT_FAILURE);
    }
    memset(buf, 0xCC, read_size); /* Debug in case I fuck this up somehow... */
    uint64_t end_ofs = ofs + total_size;
    fseek(f_in, ofs, SEEK_SET);
    while (ofs < end_ofs) {       
        if (ofs + read_size >= end_ofs) read_size = end_ofs - ofs;
        if (fread(buf, 1, read_size, f_in) != read_size) {
            fprintf(stderr, "Failed to read file!\n");
            exit(EXIT_FAILURE);
        }
        fwrite(buf, 1, read_size, f_out);
        ofs += read_size;
    }

    fclose(f_out);

    free(buf);
}
