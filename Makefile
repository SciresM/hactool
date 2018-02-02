include config.mk

ifeq ($(OS),Windows_NT)
LDFLAGS += -liconv
endif

.PHONY: clean

INCLUDE = -I ./mbedtls/include
LIBDIR = ./mbedtls/library
CFLAGS += -D_BSD_SOURCE -D_POSIX_SOURCE -D_POSIX_C_SOURCE=200112L -D_DEFAULT_SOURCE -D__USE_MINGW_ANSI_STDIO=1 -D_FILE_OFFSET_BITS=64

all:
	cd mbedtls && $(MAKE)
	$(MAKE) ncatool

.c.o:
	$(CC) $(INCLUDE) -c $(CFLAGS) -o $@ $<

ncatool: sha.o aes.o rsa.o npdm.o bktr.o utils.o nca.o main.o filepath.o
	$(CC) -o $@ $^ $(LDFLAGS) -L $(LIBDIR)

aes.o: aes.h types.h

bktr.o: bktr.h types.h

filepath.o: filepath.c types.h

main.o: main.c pki.h types.h

nca.o: nca.h aes.h sha.h rsa.h bktr.h filepath.h types.h

npdm.o: npdm.c types.h

rsa.o: rsa.h sha.h types.h

sha.o: sha.h types.h

utils.o: utils.h types.h

clean:
	rm -f *.o ncatool ncatool.exe
	cd mbedtls && $(MAKE) clean

dist:
	$(eval NCATOOLVER = $(shell grep '\bNCATOOL_VERSION\b' version.h \
		| cut -d'	' -f2 \
		| sed -e 's/"//g'))
	mkdir ncatool-$(NCATOOLVER)
	cp *.c *.h config.mk.template Makefile README.md LICENSE ncatool-$(NCATOOLVER)
	tar czf ncatool-$(NCATOOLVER).tar.gz ncatool-$(NCATOOLVER)
	rm -r ncatool-$(NCATOOLVER)
