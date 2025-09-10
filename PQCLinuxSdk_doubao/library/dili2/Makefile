
GMSSL_DIR := ../../common/gmssl/gmssl
INC_GMSSL = $(GMSSL_DIR)/include
LIB_GMSSL = -L$(GMSSL_DIR)/lib -l:libcrypto.a -ldl -lpthread

CC ?= /usr/bin/cc
CFLAGS += -Wall -Wextra -Wpedantic -Wmissing-prototypes -Wredundant-decls \
  -Wshadow -Wvla -Wpointer-arith -O3 -march=native -mtune=native -std=c99 -I/usr/openssl/include/

SOURCES = sign.c packing.c polyvec.c poly.c ntt.c reduce.c rounding.c crypto_dili.c fips202.c symmetric-shake.c  rng.c
HEADERS = config.h params.h api.h sign.h packing.h polyvec.h poly.h ntt.h \
  reduce.h rounding.h symmetric.h randombytes.h crypto_dili.h


.PHONY: all clean

all: libpqc_dili2.so

libpqc_dili2.so: $(SOURCES) $(HEADERS) 
	$(CC) -shared -fPIC $(CFLAGS) -fvisibility=hidden -DDILITHIUM_MODE=2 \
	  -o $@ $(SOURCES) $(LIB_GMSSL) -I$(INC_GMSSL)

clean:
	rm -f *.so
