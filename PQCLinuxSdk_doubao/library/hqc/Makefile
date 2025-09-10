# ifeq ($(ROOT),)
# ROOT:=.
# endif

# CPP=g++

# CPP_FLAGS:=-O3 -Wall -Wextra -Wpedantic -Wvla -Wredundant-decls 

# SHA3_SRC:=$(ROOT)/lib/fips202/fips202.c
# SHA3_INCLUDE:=-I $(ROOT)/lib/fips202

# SRC:=$(ROOT)/src/
# INCLUDE:=-I $(ROOT)/src -lntl -lgf2x -lgmp -pthread
# LIB:=$(SHA3_INCLUDE)

# MAIN_HQC:=$(ROOT)/src/main_hqc.cpp
# MAIN_KAT:=$(ROOT)/src/main_kat.c

# HQC_OBJS:=vector.o reed_muller.o reed_solomon.o fft.o gf.o gf2x.o code.o parsing.o hqc.o kem.o shake_ds.o shake_prng.o
# HQC_OBJS_VERBOSE:=vector.o reed_muller.o reed_solomon-verbose.o fft.o gf.o gf2x.o code-verbose.o parsing.o hqc-verbose.o kem-verbose.o shake_ds.o shake_prng.o
# LIB_OBJS:= fips202.o

# BIN:=bin
# BUILD:=bin/build


# folders:
# 	@echo -e "\n### Creating folders\n"
# 	mkdir -p $(BUILD)

# fips202.o: | folders
# 	@/bin/echo -e "\n### Compiling fips202"
# 	$(CPP) $(CFLAGS) -c $(SHA3_SRC) $(SHA3_INCLUDE) -o $(BUILD)/$@

# %.o: $(SRC)/%.cpp | folders
# 	@/bin/echo -e "\n### Compiling $@"
# 	$(CPP) $(CPP_FLAGS) -c $< $(INCLUDE) $(LIB) -o $(BUILD)/$@

# %-verbose.o: $(SRC)/%.cpp | folders
# 	@echo -e "\n### Compiling $@ (verbose mode)\n"
# 	$(CPP) $(CPP_FLAGS) -c $< $(INCLUDE) $(LIB) -D VERBOSE -o $(BUILD)/$@

# hqc-128: $(HQC_OBJS) $(LIB_OBJS) | folders
# 	@echo -e "\n### Compiling hqc-128\n"
# 	$(CPP) $(CPP_FLAGS) $(MAIN_HQC) $(addprefix $(BUILD)/, $^) $(INCLUDE) $(LIB) -o $(BIN)/$@

# hqc-128-kat: $(HQC_OBJS) $(LIB_OBJS) | folders
# 	@echo -e "\n### Compiling hqc-128 KAT\n"
# 	$(CPP) $(CPP_FLAGS) $(MAIN_KAT) $(addprefix $(BUILD)/, $^) $(INCLUDE) $(LIB) -o $(BIN)/$@

# hqc-128-verbose: $(HQC_OBJS_VERBOSE) $(LIB_OBJS) | folders
# 	@echo -e "\n### Compiling hqc-128 (verbose mode)\n"
# 	$(CPP) $(CPP_FLAGS) $(MAIN_HQC) $(addprefix $(BUILD)/, $^) $(INCLUDE) $(LIB) -D VERBOSE -o $(BIN)/$@


# clean:
# 	rm -f PQCkemKAT_*
# 	rm -f vgcore.*
# 	rm -rf ./bin



-std=c++11
#g++ -I../include -I.  -g -O2 -std=c++11 -pthread -march=native  -o ZZ_pXTest ZZ_pXTest.cpp ntl.a  -lgmp    -lm 


CC := gcc
CFLAGS +=-O3 -std=c99 -funroll-all-loops -flto -mavx -mavx2 -mbmi -mpclmul -pedantic -Wall -Wextra -pthread

SOURCES := code.c vector.c reed_muller.c reed_solomon.c fft.c gf.c gf2x.c  parsing.c   shake_ds.c shake_prng.c fips202.c crypto_hqc.c kem.c hqc.c
HEADERS= vector.h reed_muller.h reed_solomon.h fft.h gf.h gf2x.h parsing.h   shake_ds.h shake_prng.h domains.h fips202.h

.PHONY: all clean

all: \
	libpqc_hqc.so 

libpqc_hqc.so: $(SOURCES) $(HEADERS) 
	$(CC) -shared -fPIC $(CFLAGS) -fvisibility=hidden -o $@ $(SOURCES) 

clean:
	rm -f *.so *.o
