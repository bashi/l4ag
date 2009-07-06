ifneq ($(KERNELRELEASE),)
	DEBUG = y
	obj-m := l4ag.o
	#l4ag-objs := l4ag.o
else
	KERNELDIR ?= /lib/modules/$(shell uname -r)/build
  PWD := $(shell pwd)
	#CFLAGS += -DDEBUG
	CFLAGS += -I$(PWD)/../include

default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

clean:
	rm -rf *.o *.ko *.mod.c *.mod.o Module.markers Module.symvers modules.order .*.cmd .*.d
endif
