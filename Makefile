include config.mk

.PHONY: clean

CFLAGS += -D_BSD_SOURCE -D_POSIX_SOURCE -D_POSIX_C_SOURCE=200112L -D_DEFAULT_SOURCE -D__USE_MINGW_ANSI_STDIO=1 -D_FILE_OFFSET_BITS=64

all:
	cd mbedtls && $(MAKE) lib
	$(MAKE) hactool
	$(MAKE) lib

.c.o:
	$(CC) $(INCLUDE) -c $(CFLAGS) -o $@ $<

hactool: save.o sha.o aes.o extkeys.o rsa.o npdm.o bktr.o kip.o packages.o pki.o pfs0.o hfs0.o nca0_romfs.o romfs.o utils.o nax0.o nso.o lz4.o nca.o xci.o main.o filepath.o ConvertUTF.o cJSON.o
	$(CC) -o $@ $^ $(LDFLAGS) -L $(LIBDIR)

lib: save.o sha.o aes.o extkeys.o rsa.o npdm.o bktr.o kip.o packages.o pki.o pfs0.o hfs0.o nca0_romfs.o romfs.o utils.o nax0.o nso.o lz4.o nca.o xci.o filepath.o ConvertUTF.o cJSON.o
	rm -rf dist
	$(AR) -rc $@hactool.a $^
	mkdir dist
	mkdir dist/include
	mkdir dist/lib
	cp *.h dist/include
	cp libhactool.a dist/lib

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

save.o: save.h ivfc.h aes.h sha.h filepath.h types.h

sha.o: sha.h types.h

utils.o: utils.h types.h

xci.o: xci.h types.h hfs0.h

ConvertUTF.o: ConvertUTF.h

cJSON.o: cJSON.h

clean:
	rm -f *.o *.d hactool hactool.exe libhactool.a
    
clean_full: clean
	cd mbedtls && $(MAKE) clean

dist: clean_full
	$(eval HACTOOLVER = $(shell grep '\bHACTOOL_VERSION\b' version.h \
		| cut -d' ' -f3 \
		| sed -e 's/"//g'))
	mkdir hactool-$(HACTOOLVER)
	cp -R *.c *.h config.mk.template Makefile README.md LICENSE mbedtls hactool-$(HACTOOLVER)
	tar czf hactool-$(HACTOOLVER).tar.gz hactool-$(HACTOOLVER)
	rm -r hactool-$(HACTOOLVER)
