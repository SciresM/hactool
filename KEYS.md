hactool currently recognizes the following keys (## represents a hexadecimal number between 00 and 1F):

```
secure_boot_key                 : Secure boot key for use in key derivation. NOTE: CONSOLE UNIQUE
tsec_key                        : TSEC key for use in key derivation. NOTE: CONSOLE UNIQUE.
keyblob_mac_key_source          : Seed for keyblob MAC key derivation.
keyblob_mac_key_##              : The ##th Keys used to validate keyblobs. NOTE: CONSOLE UNIQUE.
keyblob_key_source_##           : The ##th Seeds for keyblob keys.
keyblob_key_##                  : The ##th Actual keys used to decrypt keyblobs. NOTE: CONSOLE UNIQUE.
encrypted_keyblob_##            : The ##th Actual encrypted keyblobs (EKS). NOTE: CONSOLE UNIQUE.
keyblob_##                      : The ##th Actual decrypted keyblobs (EKS).
master_key_source               : Seed for master key derivation.
master_key_##                   : The ##th Firmware Master Key. Obtainable with TrustZone code execution.
package1_key_##                 : The ##th Package1 key. Obtainable with Package1ldr code execution.
package2_key_source             : Found in TrustZone .rodata.
package2_key_##                 : The ##th Package2 key. Derivable from master_key_## and package2_key_source.
aes_kek_generation_source       : Found in TrustZone .rodata.
aes_key_generation_source       : Found in TrustZone .rodata.
titlekek_source                 : Found in TrustZone .rodata.
titlekek_##                     : The ##th Titlekek. Derivable from master_key_## and titlekek_source.
key_area_key_application_source : Found in FS .rodata.
key_area_key_ocean_source       : Found in FS .rodata.
key_area_key_system_source      : Found in FS .rodata.
key_area_key_application_##     : Derivable from master_key_##, aes generation sources, and key_area_key_application_source.
key_area_key_ocean_##           : Derivable from master_key_##, aes generation sources, and key_area_key_ocean_source.
key_area_key_system_##          : Derivable from master_key_##, aes generation sources, and key_area_key_system_source.
sd_card_kek_source              : Seed for SD card kek.
sd_card_nca_key_source          : Seed for SD card encryption NCA key.
sd_card_save_key_source         : Seed for SD card encryption save key.
header_kek_source               : Found in FS .rodata.
header_key_source               : Found in FS .rodata.
header_key                      : Derivable from master_key_##, aes generation sources, and header sources.
```