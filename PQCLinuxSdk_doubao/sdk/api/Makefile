GCC = gcc
LD = ld
AR = ar

CFLAGS = -g -O0 -Wall -fpic -std=gnu99 -ldl -lpthread

SDK_SRC = $(wildcard *.c)

SDK_OBJ = $(patsubst %.c,%.o,$(SDK_SRC))

.PHONY : all
all: rsp

rsp:$(SDK_OBJ)
	$(LD) -shared -o librsp.so $(SDK_OBJ)
	${AR} -rc librsp.a $(SDK_OBJ)

%.o:%.c
	$(GCC) $(CFLAGS) -o $@ -c $< ${INC}

.PHONY : clean

clean:
	@echo
	@echo Delete: Intermediate build files...
	@rm -f *.o *.a *.so 
	@echo Delete: ....finished!
	@echo
