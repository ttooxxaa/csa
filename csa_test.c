/*
 * User space test for csa.ko using /dev/csa (csad.ko)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

static int dev;
static const char *dev_name = "/dev/csa";

static int init_map(void)
{
	dev = open(dev_name, O_RDWR);
	if (dev < 0) {
		fprintf(stderr, "Failed to open %s (%d)\n", dev_name, dev);
		return 1;
	}
	return 0;
}

static int test_map(size_t size)
{
	int ret;
	void *p;
	unsigned long phys;

	p = mmap(0, size, PROT_READ | PROT_WRITE, MAP_SHARED, dev, 0);
	if (!p) {
		fprintf(stderr, "Failed to allocate 0x%lx\n", size);
		return 1;
	}
	phys = (unsigned long)p;
	ret = ioctl(dev, 0, &phys);
	if (ret) {
		fprintf(stderr,
			"Failed to get physical address for 0x%p size 0x%lx\n",
			p, size);
		return 1;
	}
	fprintf(stdout, "Allocated 0x%lx at physical 0x%lx\n", size, phys);
	return 0;
}

int main(int argc, char *argv[])
{
	size_t size;
	if ((argc < 2) || !strcmp(argv[1], "-?") || !strcmp(argv[1], "--help"))  {
		fprintf(stderr, "USAGE: %s size-bytes-hex\n", argv[0]);
		exit(1);
	}
	if (sscanf(argv[1], "%lx", &size) != 1) {
		fprintf(stderr, "Bad size: %s\n", argv[1]);
		exit(1);
	}

	if (init_map())
		exit(1);
	test_map(size);
	return 0;
}
