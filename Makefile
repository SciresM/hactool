include config.mk

ifeq ($(OS),Windows_NT)
LDFLAGS += -liconv
endif

.PHONY: clean

INCLUDE = -I ./mbedtls/include
LIBDIR = ./mbedtls/library
CFLAGS += -D_BSD_SOURCE -D_POSIX_SOURCE -D_POSIX_C_SOURCE=200112L -D_DEFAULT_SOURCE -D__USE_MINGW_ANSI_STDIO=1 -D_FILE_OFFSET_BITS=64

all:
	cd mbedtls && $(MAKE) lib
	$(MAKE) hactool

.c.o:
	$(CC) $(INCLUDE) -c $(CFLAGS) -o $@ $<

hactool: sha.o aes.o rsa.o npdm.o bktr.o pki.o pfs0.o hfs0.o romfs.o utils.o nca.o main.o filepath.o
	$(CC) -o $@ $^ $(LDFLAGS) -L $(LIBDIR)

aes.o: aes.h types.h

bktr.o: bktr.h types.h

filepath.o: filepath.c types.h

hfs0.o: hfs0.h types.h

main.o: main.c pki.h types.h

pfs0.o: pfs0.h types.h

pki.o: pki.h aes.h types.h

nca.o: nca.h aes.h sha.h rsa.h bktr.h filepath.h types.h

npdm.o: npdm.c types.h

romfs.o: ivfc.h types.h

rsa.o: rsa.h sha.h types.h

sha.o: sha.h types.h

utils.o: utils.h types.h

clean:
	rm -f *.o hactool hactool.exe
	cd mbedtls && $(MAKE) clean

dist:
	$(eval HACTOOLVER = $(shell grep '\bHACTOOL_VERSION\b' version.h \
		| cut -d'	' -f2 \
		| sed -e 's/"//g'))
	mkdir hactool-$(HACTOOLVER)
	cp *.c *.h config.mk.template Makefile README.md LICENSE hactool-$(HACTOOLVER)
	tar czf hactool-$(HACTOOLVER).tar.gz hactool-$(HACTOOLVER)
	rm -r hactool-$(HACTOOLVER)
