GCC = gcc
LD = ld
AR = ar

CFLAGS = -g -O0 -Wall -fpic -std=gnu99  -ldl -lpthread 

INC = -I./  -I../SafeAuthModule/

SDK_SRC = $(wildcard *.c)

SDK_OBJ = $(patsubst %.c,%.o,$(SDK_SRC))

# lib
INC_SAFEAUTHMODULE = ../SafeAuthModule/
LIB_SAFEAUTHMODULE = -L$(SAFEAUTHMODULE) -l:libsafeauth.a  
SAFEAUTHMODULE_LIB =  ../SafeAuthModule/libsafeauth.a


GMSSL_DIR := ./../common/gmssl/gmssl
INC_GMSSL = $(GMSSL_DIR)/include 
LIB_GMSSL = -L$(GMSSL_DIR)/lib -l:libcrypto.a -ldl -lpthread

.PHONY : all
all: aaus

aaus:$(SDK_OBJ)
	$(LD) -shared -o libsafeauth.so $(SDK_OBJ)
	${AR} -crsT libsafeauth.a  $(SDK_OBJ)

	gcc -g -Wall -O0 -o test main.c rsa.c safeauth.c uart.c  $(LIB_GMSSL)  -I$(INC_GMSSL) -std=gnu99



%.o:%.c
	$(GCC) $(CFLAGS) -o $@ -c $< ${INC}  

.PHONY : clean

clean:
	@echo
	@echo Delete: Intermediate build files...
	@rm -f *.o *.so *.a
	@echo Delete: ....finished!
	@echo


	
