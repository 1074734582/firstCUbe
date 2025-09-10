
GMSSL_DIR := ../../common/gmssl/gmssl
INC_GMSSL = $(GMSSL_DIR)/include
LIB_GMSSL = -L$(GMSSL_DIR)/lib -l:libcrypto.a -ldl -lpthread

CC := gcc 
CFLAGS += -O2 -march=native -fomit-frame-pointer -std=c99

SOURCES += address.c rng.c wots.c utils.c fors.c sign.c hash_shake256.c thash_shake256_simple.c fips202.c crypto_sphinc.c
HEADERS = params.h address.h rng.h wots.h utils.h fors.h api.h hash.h thash.h fips202.h crypto_sphinc.h

.PHONY: shake256 sha256 clean

shake256: libpqc_sphinc.so

libpqc_sphinc.so: $(SOURCES) $(HEADERS) 
	$(CC) -shared -fPIC $(CFLAGS) -fvisibility=hidden -DSPHINC_K=7 -o $@ $(SOURCES) $(LIB_GMSSL) -I$(INC_GMSSL)

clean:
	rm -f *.so *.o
