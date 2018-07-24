include config.mk

.PHONY: clean

INCLUDE = -I ./mbedtls/include
LIBDIR = ./mbedtls/library
CFLAGS += -D_BSD_SOURCE -D_POSIX_SOURCE -D_POSIX_C_SOURCE=200112L -D_DEFAULT_SOURCE -D__USE_MINGW_ANSI_STDIO=1 -D_FILE_OFFSET_BITS=64

all:
	cd mbedtls && $(MAKE) lib
	$(MAKE) hactool

.c.o:
	$(CC) $(INCLUDE) -c $(CFLAGS) -o $@ $<

hactool: sha.o aes.o extkeys.o rsa.o npdm.o bktr.o kip.o packages.o pki.o pfs0.o hfs0.o nca0_romfs.o romfs.o utils.o nax0.o nso.o lz4.o nca.o xci.o main.o filepath.o ConvertUTF.o cJSON.o
	$(CC) -o $@ $^ $(LDFLAGS) -L $(LIBDIR)

aes.o: aes.h types.h

bktr.o: bktr.h types.h

extkeys.o: extkeys.h types.h settings.h

filepath.o: filepath.c types.h

hfs0.o: hfs0.h types.h

kip.o: kip.h types.h

lz4.o: lz4.h

main.o: main.c pki.h types.h

packages.o: packages.h aes.h kip.h types.h

pfs0.o: pfs0.h types.h

pki.o: pki.h aes.h types.h

nax0.o: nax0.h aes.h sha.h types.h

nca.o: nca.h aes.h sha.h rsa.h bktr.h filepath.h types.h

npdm.o: npdm.c cJSON.h types.h

nso.o: nso.h types.h

romfs.o: ivfc.h types.h

nca0_romfs.o: nca0_romfs.h ivfc.h types.h

rsa.o: rsa.h sha.h types.h

sha.o: sha.h types.h

utils.o: utils.h types.h

xci.o: xci.h types.h hfs0.h

ConvertUTF.o: ConvertUTF.h

cJSON.o: cJSON.h

clean:
	rm -f *.o hactool hactool.exe
    
clean_full:
	rm -f *.o hactool hactool.exe
	cd mbedtls && $(MAKE) clean

dist: clean_full
	$(eval HACTOOLVER = $(shell grep '\bHACTOOL_VERSION\b' version.h \
		| cut -d' ' -f3 \
		| sed -e 's/"//g'))
	mkdir hactool-$(HACTOOLVER)
	cp -R *.c *.h config.mk.template Makefile README.md LICENSE mbedtls hactool-$(HACTOOLVER)
	tar czf hactool-$(HACTOOLVER).tar.gz hactool-$(HACTOOLVER)
	rm -r hactool-$(HACTOOLVER)
