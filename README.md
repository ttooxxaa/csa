# csa
# continuous physical space allocator module
#
# make
# sudo insmod csa.ko
#	The module API (csa.h) is now usable
# sudo insmod csad.ko
# 	This creates a /dev/csa misc device that
#	enables user space allocation requests, see
#	csa_test.c
# sudo chmod 666 /dev/csa
# csa_test 0x40000000
# gets 1GB, free's on process exit
