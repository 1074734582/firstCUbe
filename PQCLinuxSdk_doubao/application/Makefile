# library and include dir
GMSSL_DIR := ../common/gmssl/gmssl
INC_GMSSL = $(GMSSL_DIR)/include 

INC_CRYPTO = ../library
INC_SDK = ../sdk/api

LIB_SDK = -L$(INC_SDK) -l:librsp.a -ldl -lpthread
LIB_CRYPTO = -L$(INC_CRYPTO) -l:libcrypto_api.a -ldl -lpthread
LIB_GMSSL = -L$(GMSSL_DIR)/lib -l:libcrypto.a -ldl -lpthread

	#gcc -g -Wall -O0 -o ../algotest algotest/benchmark.c $(LIB_SDK) $(LIB_BIKE) $(LIB_NTL) -I$(INC_SDK) -I$(INC_BIKE) -I$(INC_BIKE)/NTL -I$(INC_BIKE)/FromNIST -std=gnu99 -lstdc++ -ldl -lntl -lgmp -lgf2x -lm -lcrypto -lssl
	
all :
	gcc -g -Wall -O0 -o ../algotest algotest/benchmark.c \
	  $(LIB_CRYPTO) $(LIB_GMSSL) $(LIB_SDK) \
	-I$(INC_CRYPTO) -I$(INC_GMSSL) -I$(INC_SDK) \
	-std=gnu99 -lstdc++ -ldl
	
clean:
	rm -f ../algotest

