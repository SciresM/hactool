#ifndef NCATOOL_RSA_H
#define NCATOOL_RSA_H

#include "mbedtls/rsa.h"

int rsa2048_pss_verify(const void *data, size_t len, const unsigned char *signature, const unsigned char *modulus);

#endif
