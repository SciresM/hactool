#include <stdlib.h>
#include "rsa.h"
#include "sha.h"
#include "utils.h"
#include "types.h"

#define RSA_2048_BYTES 0x100
#define RSA_2048_BITS (RSA_2048_BYTES*8)

void init_mpi_from_buffer(gcry_mpi_t *mpi, const void *data, size_t len) {
    /* Create new mpi, len * 8 bits. */
    *mpi = gcry_mpi_new(len * 8);
    if (gcry_mpi_scan(mpi, GCRYMPI_FMT_USG, data, len, NULL) != 0) {
        FATAL_ERROR("Unable to load mpi!");
    }
}

/* Perform an RSA-PSS verify operation on data, with signature and N. */
int rsa2048_pss_verify(const void *data, size_t len, const unsigned char *signature, const unsigned char *modulus) {
    /* Do gcrypt exponentiation. */    
    gcry_mpi_t signature_mpi;
    gcry_mpi_t modulus_mpi;
    gcry_mpi_t e_mpi;
    gcry_mpi_t message_mpi = gcry_mpi_new(RSA_2048_BITS);
    unsigned char m_buf[RSA_2048_BYTES];
    unsigned char h_buf[0x24];

    const unsigned char E[3] = {1, 0, 1};
    init_mpi_from_buffer(&e_mpi, E, 3);
    init_mpi_from_buffer(&signature_mpi, signature, RSA_2048_BYTES);
    init_mpi_from_buffer(&modulus_mpi, modulus, RSA_2048_BYTES);
    gcry_mpi_powm(message_mpi, signature_mpi, e_mpi, modulus_mpi);

    size_t sz;
    if (gcry_mpi_print(GCRYMPI_FMT_USG, m_buf, RSA_2048_BYTES, &sz, message_mpi) != 0) {
        FATAL_ERROR("Failed to export exponentiated RSA message!");
    }

    if (sz != RSA_2048_BYTES) { /* Ensure message is correct length. */
        return false;
    }

    gcry_mpi_release(signature_mpi);
    gcry_mpi_release(modulus_mpi);
    gcry_mpi_release(e_mpi);
    gcry_mpi_release(message_mpi);

    /* libgcrypt requires knowledge of the salt to do automated PSS verification as far as I can tell. */
    /* This is not an option in our case... */
    if (m_buf[RSA_2048_BYTES-1] != 0xBC) {
        return false;
    }

    memset(h_buf, 0, 0x24);
    memcpy(h_buf, m_buf + RSA_2048_BYTES - 0x20 - 0x1, 0x20);

    /* Decrypt maskedDB. Should MGF1 be its own function? */
    unsigned char seed = 0;
    unsigned char mgf1_buf[0x20];
    for (unsigned int ofs = 0; ofs < RSA_2048_BYTES - 0x20 - 1; ofs += 0x20) {
        h_buf[0x23] = seed++;
        sha_hash_buffer(mgf1_buf, h_buf, 0x24);
        for (unsigned int i = ofs; i < ofs + 0x20 && i < RSA_2048_BYTES - 0x20 - 1; i++) {
            m_buf[i] ^= mgf1_buf[i - ofs];
        }
    }

    m_buf[0] &= 0x7F; /* Constant lmask for rsa-2048-pss. */

    /* Validate DB. */
    for (unsigned int i = 0; i < RSA_2048_BYTES - 0x20 - 0x20 - 1 - 1; i++) {
        if (m_buf[i] != 0) {
            return false;
        }
    }   
    if (m_buf[RSA_2048_BYTES - 0x20 - 0x20 - 1 - 1] != 1) {
        return false;
    }

    /* Check hash correctness. */
    unsigned char validate_buf[8 + 0x20 + 0x20];
    unsigned char validate_hash[0x20];
    memset(validate_buf, 0, 0x48);
    sha_hash_buffer(&validate_buf[8], data, len);
    memcpy(&validate_buf[0x28], &m_buf[RSA_2048_BYTES - 0x20 - 0x20 - 1], 0x20);
    sha_hash_buffer(validate_hash, validate_buf, 0x48);
    return memcmp(h_buf, validate_hash, 0x20) == 0;

}
