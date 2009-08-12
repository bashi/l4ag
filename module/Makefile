ifneq ($(KERNELRELEASE),)
	obj-m := l4ag.o
	l4ag-objs := if_l4ag.o l4ag_cubic.o
else
	KERNELDIR ?= /lib/modules/$(shell uname -r)/build
  PWD := $(shell pwd)

default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

clean:
	rm -rf *.o *.ko *.mod.c *.mod.o Module.markers Module.symvers modules.order .*.cmd .*.d
endif
