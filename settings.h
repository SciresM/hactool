#ifndef NCATOOL_SETTINGS_H
#define NCATOOL_SETTINGS_H
#include <stdio.h>
#include "types.h"
#include "filepath.h"

typedef enum {
    KEYSET_DEV,
    KEYSET_RETAIL
} keyset_variant_t;

typedef struct {
    unsigned char header_key[0x20];
    unsigned char titlekeks[0x20][0x10];
    unsigned char key_area_keys[0x20][3][0x10];
    unsigned char nca_hdr_fixed_key_modulus[0x100];
    unsigned char acid_fixed_key_modulus[0x100];
} nca_keyset_t;

typedef struct {
    int enabled;
    filepath_t path;
} override_filepath_t;

typedef struct {
    nca_keyset_t keyset;
    int has_titlekey;
    unsigned char titlekey[0x10];
    unsigned char dec_titlekey[0x10];
    int has_contentkey;
    unsigned char contentkey[0x10];
    filepath_t section_paths[4];
    filepath_t section_dir_paths[4];
    override_filepath_t exefs_path;
    override_filepath_t exefs_dir_path;
    override_filepath_t romfs_path;
    override_filepath_t romfs_dir_path;
} ncatool_settings_t;

enum ncatool_file_type
{
    NCA
};

#define ACTION_INFO (1<<0)
#define ACTION_EXTRACT (1<<1)
#define ACTION_VERIFY (1<<2)
#define ACTION_RAW (1<<3)
#define ACTION_LISTROMFS (1<<4)

typedef struct {
    enum ncatool_file_type file_type;
    FILE *file;
    ncatool_settings_t settings;
    uint32_t action;
} ncatool_ctx_t;


#endif