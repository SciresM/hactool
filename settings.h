#ifndef HACTOOL_SETTINGS_H
#define HACTOOL_SETTINGS_H
#include <stdio.h>
#include "types.h"
#include "filepath.h"

typedef enum {
    KEYSET_DEV,
    KEYSET_RETAIL
} keyset_variant_t;

typedef enum {
    BASEFILE_ROMFS,
    BASEFILE_NCA
} hactool_basefile_t;

typedef struct {
    unsigned char master_keys[0x20][0x10];               /* Firmware master keys. */
    unsigned char aes_kek_generation_source[0x10];       /* Seed for GenerateAesKek, usecase + generation 0. */
    unsigned char aes_key_generation_source[0x10];       /* Seed for GenerateAesKey. */
    unsigned char key_area_key_application_source[0x10]; /* Seed for kaek 0. */
    unsigned char key_area_key_ocean_source[0x10];       /* Seed for kaek 1. */
    unsigned char key_area_key_system_source[0x10];      /* Seed for kaek 2. */
    unsigned char titlekek_source[0x10];                 /* Seed for titlekeks. */
    unsigned char header_kek_source[0x10];               /* Seed for header kek. */
    unsigned char encrypted_header_key[0x20];            /* Actual encrypted header key. */
    unsigned char header_key[0x20];                      /* NCA header key. */
    unsigned char titlekeks[0x20][0x10];                 /* Title key encryption keys. */
    unsigned char key_area_keys[0x20][3][0x10];          /* Key area encryption keys. */
    unsigned char nca_hdr_fixed_key_modulus[0x100];      /* NCA header fixed key RSA pubk. */
    unsigned char acid_fixed_key_modulus[0x100];         /* ACID fixed key RSA pubk. */
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
    override_filepath_t out_dir_path;
    filepath_t pfs0_dir_path;
    filepath_t hfs0_dir_path;
    filepath_t dec_nca_path;
    filepath_t header_path;
} hactool_settings_t;

enum hactool_file_type
{
    FILETYPE_NCA,
    FILETYPE_PFS0,
    FILETYPE_ROMFS,
    FILETYPE_HFS0,
    /* FILETYPE_XCI, */
    /* FILETYPE_PACKAGE2, */
    /* FILETYPE_PACKAGE1, */
};

#define ACTION_INFO (1<<0)
#define ACTION_EXTRACT (1<<1)
#define ACTION_VERIFY (1<<2)
#define ACTION_RAW (1<<3)
#define ACTION_LISTROMFS (1<<4)

struct nca_ctx; /* This will get re-defined by nca.h. */

typedef struct {
    enum hactool_file_type file_type;
    FILE *file;
    FILE *base_file;
    hactool_basefile_t base_file_type;
    struct nca_ctx *base_nca_ctx;
    hactool_settings_t settings;
    uint32_t action;
} hactool_ctx_t;


#endif
