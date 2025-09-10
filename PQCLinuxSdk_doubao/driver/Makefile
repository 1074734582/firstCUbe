ifneq ($(CONFIG_BASIC),)
	ccflags-y += -DDRIVER_BASIC
endif
ccflags-y += -std=gnu9x -Wall -Wno-unused-function -Wno-unused-variable -Wno-format 
ifneq ($(KERNELRELEASE),)
	obj-m := hx_ctrl_drv.o
	hx_ctrl_drv-objs := chrdev.o ring.o common.o algo.o dev.o dev_mgr.o performance_hard.o

else
	KERNELDIR ?= /lib/modules/$(shell uname -r)/build
	PWD := $(shell pwd)

default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules
endif

clean:
	rm -f *.o *.ko Module.symvers modules.order *.mod.c .*.cmd  .*.o.d  .tmp_versions  ./../../hx_ctrl_drv.ko -rf 
