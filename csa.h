#ifndef __CSA_H__
#define __CSA_H__

#include <linux/mm.h>
#include <linux/topology.h> /* numa */

/*
 * Allocate (size) bytes of continuous physical memory on (nid).
 * You can request physical address aligned to (align),
 * or use align=0 for default.
 * Returns the kernel virtual address of the beginning of the block.
 */
extern void *csa_alloc_node(int nid, size_t size, size_t align);

/*
 * Same on current node of the running the calling process
 */
static inline void *csa_alloc(size_t size, size_t align)
{
	return csa_alloc_node(numa_node_id(), size, align);
}

/*
 * Deallocate: kernel virtual (addr), (size) bytes.
 * Careful: no book-keeping and checks done.
 */
void csa_free(void *addr, size_t size);

#endif
