#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/io.h>

#include <linux/uaccess.h>
#include <linux/mman.h>
#include <linux/fs.h>

#include "csa.h"

#define DRIVER_VERSION "v1.0"
#define DRIVER_AUTHOR "Anton Eidelman"
#define DRIVER_DESC "csa device for user space allocations"

#define dev_name "csa"

/*
 * Misc device for user space access to continuous memory allocation
 * implemented in csa.ko.
 */

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Anton Eidelman");
MODULE_DESCRIPTION("Continuous Space Allocation Device");

/* If set, this amount of memory is allocated during module init */
static ulong size;
module_param(size, ulong, S_IRUGO | S_IWUSR);

struct pfn_block {
	void *addr; /* kernel virtual address */
	unsigned long pfn;
	unsigned long uaddr; /* vma start in the owner process */
	size_t size;
	struct list_head list;
};

static struct pfn_block a; /* tracks options allocation on insmod */

/* Helpers for test allocation on insmod and free on rmmod */
static inline int t_alloc(struct pfn_block *b, size_t size)
{
	if (!size)
		return 0;
	b->addr = csa_alloc(size, 0x10000000);
	b->size = size;
	pr_info("Requested %lx got %p\n", b->size, b->addr);
	return 0;
}

static inline void t_free(struct pfn_block *b)
{
	pr_info("CSAT: cleanup: 0x%lx at  %p\n", b->size, b->addr);
	if (b->addr)
		csa_free(b->addr, b->size);
}

/*
 * Block tracking: blocks allocated are currently owned by the process that
 * mmaps it, which triggers allocation.
 * The memory is retained as long as the process keep /dev/csa open,
 * so on process exit all memory it owned is released.
 */
struct track {
	struct list_head head;
	spinlock_t lock;
};

/* Initialize a tracker for caller */
static int track_init(struct file *f)
{
	struct track *t = kzalloc(sizeof(*t), GFP_KERNEL);

	if (!t)
		return -ENOMEM;
	spin_lock_init(&t->lock);
	INIT_LIST_HEAD(&t->head);
	f->private_data = t;
	return 0;
}

/* Get caller's tracker */
static inline struct track *track_get(struct file *f)
{
	return (struct track *)f->private_data;
}

/* Add block to tracker t */
static struct pfn_block *track_add(struct track *t, void *p,
				   unsigned long uaddr, size_t size)
{
	struct pfn_block *b = kzalloc(sizeof(*b), GFP_KERNEL);
	unsigned long flags;

	if (b) {
		b->addr = p;
		b->uaddr = uaddr;
		b->size = size;
		b->pfn = page_to_pfn(virt_to_page(p));
		spin_lock_irqsave(&t->lock, flags);
		list_add_tail(&b->list, &t->head);
		spin_unlock_irqrestore(&t->lock, flags);
	}
	return b;
}

/* Remove tracker (but keep the memory) */
static void track_del(struct track *t, struct pfn_block *b)
{
	unsigned long flags;

	spin_lock_irqsave(&t->lock, flags);
	list_del(&b->list);
	spin_unlock_irqrestore(&t->lock, flags);
	kfree(b);
}

/*
 * Lookup block by user address (does not have to be the block start address).
 * This is a slow operation, liner lookup in a list expected to be short.
 */
static struct pfn_block *track_lookup(struct track *t, unsigned long uaddr)
{
	struct pfn_block *b;
	struct pfn_block *match = 0;
	unsigned long flags;

	spin_lock_irqsave(&t->lock, flags);
	list_for_each_entry(b, &t->head, list)
		if ((uaddr >= b->uaddr) && (uaddr < (b->uaddr + b->size))) {
			match = b;
			break;
		}
	spin_unlock_irqrestore(&t->lock, flags);
	return match;
}

static void track_release(struct track *t)
{
	struct pfn_block *b, *n;

	list_for_each_entry_safe(b, n, &t->head, list) {
		csa_free(b->addr, b->size);
		pr_info("Released 0x%lx bytes at %p owned by pid %d\n",
			b->size, b->addr, current->pid);
		kfree(b);
	}
	kfree(t);
}

/*
 * /dev/csa system calls
 */
static int csa_open(struct inode *inode, struct file *f)
{
	return track_init(f);
}

static int csa_release(struct inode *inode, struct file *f)
{
	track_release(track_get(f));
	return 0;
}

static int csa_mmap(struct file *file, struct vm_area_struct *vma)
{
	unsigned long size = round_up(vma->vm_end - vma->vm_start, PAGE_SIZE);
	int ret = -ENOMEM;
	void *p;
	struct pfn_block *b;

	vma->vm_pgoff = 0;
	p = csa_alloc(size, 0);
	if (p) {
		b = track_add(track_get(file), p, vma->vm_start, size);
		if (!b) {
			pr_info("Failed to add tracker\n");
			goto out_mem;
		}

		ret = remap_pfn_range(vma, vma->vm_start, b->pfn,
				size, vma->vm_page_prot);
		if (ret) {
			pr_info("Remap failed (%d): 0x%lx size 0x%lx\n",
				ret, b->pfn << PAGE_SHIFT, size);
			goto out_tracked;
		}
	}
	return 0;

out_tracked:
	track_del(track_get(file), b);
out_mem:
	csa_free(p, size);
	return ret;
}

long csa_ioctl(struct file *file, unsigned int ioctl_num,
		 unsigned long param)
{
	int ret = 0;
	unsigned long uaddr;
	phys_addr_t pa;

	switch (ioctl_num) {
	case 0: /* v2p */
		ret = copy_from_user(&uaddr, (void *)param, sizeof(uaddr));
		if (!ret) {
			struct pfn_block *b = track_lookup(track_get(file),
							   uaddr);

			if (!b)
				return -EINVAL;
			pa = b->pfn << PAGE_SHIFT;
			ret = copy_to_user((void *)param, &pa, sizeof(pa));
		}
		break;
	default:
		return -EINVAL;
	}

	return ret;
}

static const struct file_operations csa_fops = {
	.owner =	THIS_MODULE,
	.open =		csa_open,
	.release =	csa_release,
	.mmap =		csa_mmap,
	.unlocked_ioctl = csa_ioctl,
};

static struct miscdevice csa_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = dev_name,
	.fops = &csa_fops,
};

static int __init csat_init(void)
{
	if (size) {
		/* This is optional: allows allocation with no user space */
		pr_info("CSAT: allocate size = 0x%lx\n", size);
		t_alloc(&a, size);
	}
	misc_register(&csa_dev);
	return 0;
}

static void __exit csat_cleanup(void)
{
	misc_deregister(&csa_dev);
	t_free(&a);
}

module_init(csat_init);
module_exit(csat_cleanup);
