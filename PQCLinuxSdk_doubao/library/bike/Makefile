# BIKE reference and optimized implementations assume that OpenSSL and NTL libraries are available in the platform.

# To compile this code for NIST KAT routine use: make bike-nist-kat
# To compile this code for demo tests use: make bike-demo-test

# TO EDIT PARAMETERS AND SELECT THE BIKE VARIANT: please edit defs.h file in the indicated sections.

# The file measurements.h controls how the cycles are counted. Note that #define REPEAT is initially set to 100,
# which means that every keygen, encaps and decaps is repeated 100 times and the number of cycles is averaged.

# Verbose levels: 0, 1, 2 or 3
# VERBOSE=0

# CC:=g++
# CFLAGS:=-m64 -O3

# SRC:=*.c ntl.cpp FromNIST/rng.c
# INCLUDE:=-I. -I$(OpenSSL)/include -L$(OpenSSL)/lib -std=c++11 -lcrypto -lssl -lm -ldl -lntl -lgmp -lgf2x -lpthread

# all: bike-nist-kat

# bike-demo-test: $(SRC) *.h tests/test.c
# 	$(CC) $(CFLAGS) tests/test.c $(SRC) $(INCLUDE) -DVERBOSE=$(VERBOSE) -DNIST_RAND=1 -o $@

# bike-nist-kat: $(SRC) *.h FromNIST/*.h FromNIST/PQCgenKAT_kem.c
# 	$(CC) $(CFLAGS) FromNIST/PQCgenKAT_kem.c $(SRC) $(INCLUDE) -DVERBOSE=$(VERBOSE) -DNIST_RAND=1 -o $@

# clean:
# 	rm -f PQCkemKAT_*
# 	rm -f bike*

GMSSL_DIR := ../../common/gmssl/gmssl
INC_GMSSL = $(GMSSL_DIR)/include
LIB_GMSSL = -L$(GMSSL_DIR)/lib -l:libcrypto.a -ldl -lpthread

INC_NTL = NTL
LIB_NTL = -L$(INC_NTL) -l:libpqc_ntl.so -Wl,-rpath,./library/bike/NTL -ldl -lpthread

CC := gcc 
CFLAGS += -O2 -march=native -fomit-frame-pointer -std=c99 -lpthread

SOURCES := conversions.c decode.c sha3.c kem.c ring_buffer.c rng.c sampling.c shake_prng.c threshold.c utilities.c
HEADERS= api.h conversions.h decode.h defs.h hash_wrapper.h sha3.h kem.h ring_buffer.h rng.h  sampling.h shake_prng.h threshold.h utilities.h types.h
.PHONY: all clean

all: \
	libpqc_bike.so 

libpqc_bike.so: $(SOURCES) $(HEADERS) 
	$(CC) -shared -fPIC $(CFLAGS) -fvisibility=hidden -o $@ $(SOURCES) $(LIB_GMSSL) -I$(INC_GMSSL) $(LIB_NTL) -I$(INC_NTL)

clean:
	rm -f *.so *.o
