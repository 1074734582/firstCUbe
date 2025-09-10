
# GCC = gcc
# AR = ar
# USE_SHAKE = 1

# CFLAGS += -fPIC -std=c99 -Wall -Wextra -Wpedantic -Wmissing-prototypes -Wredundant-decls \
#   -Wshadow -Wvla -Wpointer-arith -Wa,--noexecstack -fomit-frame-pointer -O3 -mtune=native

# PROJECT_HOME=../../..
# SM3_HOME=$(PROJECT_HOME)/hash/sm3
# FIPS202_HOME=$(PROJECT_HOME)/hash/keccak
# INCLUDE_PATH=-I$(PROJECT_HOME) -I$(PROJECT_HOME)/include -I$(PROJECT_HOME)/utils -I$(PROJECT_HOME)/kem/aigis-enc/std

# CFLAGS += $(INCLUDE_PATH)

# SOURCES= cbd.o owcpa.o genmatrix.o kem_aigis.o ntt.o poly.o polyvec.o reduce.o verify.o hashkdf.o \
# 		 $(PROJECT_HOME)/utils/randombytes.o
# HEADERS= api.h cbd.h owcpa.h genmatrix.h ntt.h params.h poly.h polyvec.h reduce.h verify.h hashkdf.h \
# 		 $(PROJECT_HOME)/utils/randombytes.h

# ifeq ($(SANITIZER), 1)
# CFLAGS += -fsanitize=leak
# endif

# ifeq ($(USE_SHAKE), 1)
# 	HASH_HEADER += $(FIPS202_HOME)/fips202.h
# 	HASH_SOURCE += $(FIPS202_HOME)/fips202.o
# 	CFLAGS += -march=native -DUSE_SHAKE
# 	CFLAGS += -I$(FIPS202_HOME)
# else

# 	ifeq ($(TARGET_HYGON), 1)
# 		CFLAGS += -mavx2
# 	else
# 		CFLAGS += -march=native
# 	endif
# 	HASH_SOURCE = $(SM3_HOME)/x86-64/sm3.o
# 	HASH_HEADER = $(SM3_HOME)/x86-64/include/sm3.h

# 	HASH_HEADER += sm3kdf.h $(PROJECT_HOME)/include/sm3_extended.h
# 	HASH_SOURCE += sm3kdf.o $(SM3_HOME)/sm3_extended.o

# endif

# HEADERS += $(HASH_HEADER)
# SOURCES += $(HASH_SOURCE)


# .PHONY : all
# all: tsr

# tsr:$(SOURCES)
# 	$(GCC) -fPIC -shared -o libaigis.so $(SOURCES) -DAIGIS_ENC_MODE=1
# 	${AR} -rc libaigis.a $(SOURCES)

# %.o:%.c
# 	$(GCC) $(CFLAGS) -o $@ -c $<

# .PHONY : clean

# clean:
# 	@clear;
# 	@echo
# 	@echo Delete: Intermediate build files...
# 	@rm -f *.o *.so *.a
# 	@echo Delete: ....finished!
# 	@echo



CC := gcc 
CFLAGS += -O2 -march=native -fomit-frame-pointer -std=c99

SOURCES := cbd.c owcpa.c genmatrix.c crypto_aigis.c ntt.c poly.c polyvec.c reduce.c verify.c hashkdf.c randombytes.c fips202.c 
HEADERS= api.h cbd.h owcpa.h genmatrix.h ntt.h params.h poly.h polyvec.h reduce.h verify.h hashkdf.h  randombytes.h fips202.h

.PHONY: all clean

all: \
	libpqc_aigis.so 

libpqc_aigis.so: $(SOURCES) $(HEADERS) 
	$(CC) -shared -fPIC $(CFLAGS) -fvisibility=hidden -o $@ $(SOURCES) 

clean:
	rm -f *.so *.o
