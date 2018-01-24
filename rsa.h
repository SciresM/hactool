#ifndef NCATOOL_RSA_H
#define NCATOOL_RSA_H

#define GCRYPT_NO_DEPRECATED
#include <gcrypt.h>

int rsa2048_pss_verify(const void *data, size_t len, const unsigned char *signature, const unsigned char *modulus);

#endif