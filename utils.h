#ifndef NCATOOL_UTILS_H
#define NCATOOL_UTILS_H

#include <stdio.h>
#include <stdlib.h>
#include "types.h"

#ifdef _WIN32
#define PATH_SEPERATOR '\\'
#else
#define PATH_SEPERATOR '/'
#endif

#define MEDIA_SIZE 0x200

/* On the switch, paths are limited to 0x300. Limit them to 0x400 - 1 on PC. */
/* MAX_PATH is previously defined in "windef.h" on WIN32. */
#ifndef MAX_PATH
#define MAX_PATH 1023
#endif

#define FATAL_ERROR(msg) do {\
    fprintf(stderr, "Error: %s\n", msg);\
    exit(EXIT_FAILURE);\
} while (0)

uint32_t align(uint32_t offset, uint32_t alignment);
uint64_t align64(uint64_t offset, uint64_t alignment);

void print_magic(const char *prefix, uint32_t magic);

void memdump(FILE *f, const char *prefix, const void *data, size_t size);

uint64_t _fsize(const char *filename);

#ifdef _MSC_VER
inline int fseeko64(FILE *__stream, long long __off, int __whence)
{
    return _fseeki64(__stream, __off, __whence);
}
#elif __APPLE__ || __CYGWIN__ 
    // OS X file I/O is 64bit
    #define fseeko64 fseek
#elif __linux__ || __WIN32
    extern int fseeko64 (FILE *__stream, __off64_t __off, int __whence);
#else
    /* fseeko is guaranteed by POSIX, hopefully the OS made their off_t definition 64-bit;
     * known sane on FreeBSD and OpenBSD.
     */
    #define fseeko64 fseeko
#endif

static inline uint64_t media_to_real(uint64_t media) {
    return MEDIA_SIZE * media;
}

#endif
