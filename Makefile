obj-m += csa.o
obj-m += csad.o

csa-y := csa_core.o
csad-y := csa_dev.o

KERNEL_DIR ?= /lib/modules/$(shell uname -r)/build

.PHONY: modules
.PHONY: tests
.PHONY: clean
.PHONY: clean_tests

all:	modules tests

modules:
	make -C $(KERNEL_DIR) M=`pwd` modules

clean:	clean_tests
	make -C $(KERNEL_DIR) M=`pwd` clean

# USER SPACE TESTS
tests:	csa_test

csa_test:	csa_test.c
	gcc -o $@ $?

clean_tests:
	@rm -f csa_test csa_test.o
