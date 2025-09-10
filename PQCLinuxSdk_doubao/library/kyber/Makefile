# CC=/usr/bin/gcc
# CFLAGS += -O3 -march=native -fomit-frame-pointer
# LDFLAGS=-lcrypto

# SOURCES= cbd.c fips202.c indcpa.c kem.c ntt.c poly.c polyvec.c PQCgenKAT_kem.c reduce.c rng.c verify.c symmetric-shake.c
# HEADERS= api.h cbd.h fips202.h indcpa.h ntt.h params.h poly.h polyvec.h reduce.h rng.h verify.h symmetric.h

# PQCgenKAT_kem: $(HEADERS) $(SOURCES)
# 	$(CC) $(CFLAGS) -o $@ $(SOURCES) $(LDFLAGS)

# .PHONY: clean

# clean:
# 	-rm PQCgenKAT_kem
#############################################

# CC := gcc 
# CFLAGS += -O2 -march=native -fomit-frame-pointer -std=c99 -fPIC -shared 
# LDFLAGS=-lcrypto -I/usr/openssl/include/ 

# TARGET := libmylib.so

# SOURCES := cbd.c fips202.c indcpa.c kem.c ntt.c poly.c polyvec.c PQCgenKAT_kem.c reduce.c rng.c verify.c symmetric-shake.c crypto_kyper.c
# OBJECTS := $(patsubst %.c, %.o, $(SOURCES))
 
# $(TARGET): $(OBJECTS)
# 	$(CC) $(LDFLAGS) $(CFLAGS) $^ -o $@ 
 
# %.o: %.c
# 	$(CC) -c $(CFLAGS) -DKYBER_K=2 $(LDFLAGS) $< 

# .PHONY: clean

# clean:
# 	rm -f $(TARGET) $(OBJECTS)
######################################################################################

GMSSL_DIR := ../../common/gmssl/gmssl
INC_GMSSL = $(GMSSL_DIR)/include
LIB_GMSSL = -L$(GMSSL_DIR)/lib -l:libcrypto.a -ldl -lpthread

CC := gcc 
CFLAGS += -O2 -march=native -fomit-frame-pointer -std=gnu99

SOURCES := cbd.c fips202.c indcpa.c kem.c ntt.c poly.c polyvec.c reduce.c rng.c verify.c symmetric-shake.c crypto_kyber.c
HEADERS= api.h cbd.h fips202.h indcpa.h ntt.h params.h poly.h polyvec.h reduce.h rng.h verify.h symmetric.h crypto_kyber.h

.PHONY: all clean

all: libpqc_kyber.so

libpqc_kyber.so: $(SOURCES) $(HEADERS) 
	$(CC) -shared -fPIC $(CFLAGS) -fvisibility=hidden -DKYBER_K=2 \
	  -o $@ $(SOURCES) $(LIB_GMSSL) -I$(INC_GMSSL) 

clean:
	rm -f *.so



