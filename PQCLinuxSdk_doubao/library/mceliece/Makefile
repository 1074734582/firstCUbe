# kat_kem.rsp: kat
# 	./run

# kat: Makefile nist/kat_kem.c nist/rng.c nist/rng.h randombytes.h benes.c bm.c controlbits.c decrypt.c encrypt.c gf.c operations.c pk_gen.c root.c sk_gen.c synd.c transpose.c util.c    
# 	./build

GMSSL_DIR := ../../common/gmssl/gmssl
INC_GMSSL = $(GMSSL_DIR)/include
LIB_GMSSL = -L$(GMSSL_DIR)/lib -l:libcrypto.a -ldl -lpthread

CC := gcc 
CFLAGS += -O2 -march=native -fomit-frame-pointer -std=c99

LDFLAGS=-lcrypto -I/usr/local/openssl/include/ 
SOURCES := benes.c bm.c controlbits.c decrypt.c encrypt.c gf.c operations.c pk_gen.c root.c sk_gen.c synd.c transpose.c util.c crypto_mceliece.c fips202.c rng.c
HEADERS= api.h benes.h bm.h controlbits.h crypto_hash.h crypto_kem_mceliece348864.h crypto_kem.h decrypt.h encrypt.h int32_sort.h \
		 uint64_sort.h gf.h operations.h params.h randombytes.h pk_gen.h root.h sk_gen.h synd.h transpose.h util.h fips202.h rng.h

.PHONY: all clean

all: \
	libpqc_mceliece.so \

libpqc_mceliece.so: $(SOURCES) $(HEADERS) 
	$(CC) -shared -fPIC $(CFLAGS) -fvisibility=hidden \
	 -o $@ $(SOURCES) $(LIB_GMSSL) -I$(INC_GMSSL)

clean:
	rm -f *.so
