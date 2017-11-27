obj-m += csa.o

csa-y := csa_core.o

KERNEL_DIR ?= /lib/modules/$(shell uname -r)/build

.PHONY: modules
.PHONY: clean

all:	modules

modules:
	make -C $(KERNEL_DIR) M=`pwd` modules

clean:
	make -C $(KERNEL_DIR) M=`pwd` clean

