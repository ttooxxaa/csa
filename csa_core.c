/*
 * Continuous <physical> space allocation module
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/init.h>

#include "csa.h" /* API */

/* Only use these to verify build on older kernels e.g. on 4.4.x */
#if (0)
static inline void set_page_count(struct page *page, int n) {}
static inline void *page_to_virt(struct page *page) { return 0; }
#endif

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Anton Eidelman");
MODULE_DESCRIPTION("Continuous Space Allocation");

/* This is the maximal page order MM supports: we allocate from this order */
#define TOP_ORDER (MAX_ORDER - 1)
#define TOP_NR_PAGES BIT(TOP_ORDER)

/*
 * Use this with kernel exporting alloc_contig_range() and free_contig_range().
 * Otherwise, the implementation will scan zone free-lists to locate suitable
 * continuous pfn ranges.
 */
#define USE_CONTIG_ALLOC

/* Allocation context passed around internally */
struct csa {
	size_t size; /* requested size bytes */
	size_t align; /* start alignment in TOP_ORDER pages */
	unsigned long count; /* requested size in TOP_ORDER pages */
	unsigned long pfn; /* range start pfn */
	int nid; /* node ID */
};
/*
 * Not an EXPORT_SYMBOL.
 * This is used in mm_zone.h:next_zones_zonelist() to for traversing
 * multiple nodes in *nodes.
 * Returning NULL terminates the traversal once a node is done.
 */
struct zoneref *__next_zones_zonelist(struct zoneref *z, enum zone_type hz,
				      nodemask_t *nodes)
{
	return NULL;
}

static inline int page_ok(unsigned long pfn)
{
	struct page *page;

	if (!pfn_valid(pfn))
		return 0;
	page = pfn_to_page(pfn);
	if (PageReserved(page) || (page_count(page) > 0) || PageHuge(page))
		return 0;
	return 1;
}

/*
 * Returns 0 if the given TOP_ORDER PFN range matches the request (csa):
 * size and alignment.
 * Otherwise returns a non-0.
 */
static inline int check_range(unsigned long start_pfn, unsigned long end_pfn,
			      struct csa *csa)
{
	start_pfn = round_up(start_pfn, csa->align);

	if ((end_pfn > start_pfn) && ((end_pfn - start_pfn) >= csa->count))
		return 0;
	return -ENOMEM;
}

/* Prapare pfn range for use */
static void prep_pfn_range(unsigned long start_pfn, unsigned long end_pfn)
{
	unsigned long pfn = start_pfn;
	struct page *page = pfn_to_page(start_pfn);

	for (; pfn < end_pfn; pfn++, page++) {
		__ClearPageBuddy(page);
		set_page_private(page, 0);
		SetPageReserved(page);
	}
	/* We reserved a range: take them off the managed set accounting */
	adjust_managed_page_count(pfn_to_page(start_pfn), start_pfn - end_pfn);
}

/* Prepare a pfn range for free */
static void unprep_pfn_range(unsigned long start_pfn, unsigned long end_pfn)
{
	unsigned long pfn = start_pfn;
	struct page *page = pfn_to_page(start_pfn);

	for (; pfn < end_pfn; pfn++, page++) {
		set_page_count(page, 1);
		ClearPageReserved(page);
	}
	/* We unreserved a range: put them back into managed set */
	adjust_managed_page_count(pfn_to_page(start_pfn), end_pfn - start_pfn);
}

#ifndef USE_CONTIG_ALLOC
/*
 * Remove (count) pages at (page) from the free_list.
 * Caller must hold the zone lock.
 */
static int grab_pages(struct zone *zone, struct page *frompage,
		      unsigned long count)
{
	struct page *page, *n;

	list_for_each_entry_safe(page, n, &frompage->lru, lru) {
		list_del(&page->lru);
		count--;
		if (!count)
			break;
	}
	return 0;
}

static unsigned long try_free_area(struct zone *zone, int mt, struct csa *csa)
{
	struct page *page;
	int ret = -ENOMEM;
	unsigned long count = 0;
	unsigned long start_pfn = 0, end_pfn = 0;
	unsigned long flags;
	struct free_area *fa = &(zone->free_area[TOP_ORDER]);
	/*
	 * The mess happens a the head of free list since page_alloc.c
	 * allocates from the head and frees to the head.
	 * The best chances we have are at the tail of the free list.
	 */
	spin_lock_irqsave(&zone->lock, flags);
	list_for_each_entry_reverse(page, &fa->free_list[mt], lru) {
		unsigned long pfn = page_to_pfn(page) >> TOP_ORDER;

		if (count) {
			if (pfn == end_pfn)
				end_pfn++;
			else if (pfn == (start_pfn - 1))
				start_pfn = pfn;
			else {
				pr_debug("Fragment: 0x%lx-0x%lx: 0x%lx\n",
				     start_pfn, end_pfn, end_pfn - start_pfn);
				count = 0;
			}
		}
		if (!count) {
			start_pfn = pfn;
			end_pfn = pfn + 1;
		}
		count++;
		if (!check_range(start_pfn, end_pfn, csa)) {
			ret = 0;
			break;
		}
	}
	if (!ret) {
		start_pfn = round_up(start_pfn, csa->align);
		end_pfn = start_pfn + csa->count - 1; /* LAST page in range */
		page = pfn_to_page(end_pfn << TOP_ORDER);
		pr_debug("AREA [0x%lx-0x%lx]\n", start_pfn, end_pfn);
		grab_pages(zone, list_prev_entry(page, lru), csa->count);
		csa->pfn = start_pfn << TOP_ORDER;
		__mod_zone_page_state(zone, NR_FREE_PAGES,
				      -(count << TOP_ORDER));
	} else {
		pr_debug("Fragment: [0x%lx-0x%lx): 0x%lx\n",
			 start_pfn, end_pfn, end_pfn - start_pfn);
	}
	spin_unlock_irqrestore(&zone->lock, flags);
	return ret;
}

static int check_freelists(struct zone *zone, struct csa *csa)
{
	struct free_area *fa = &(zone->free_area[TOP_ORDER]);
	int mt;

	if (fa->nr_free < csa->count)
		return -ENOMEM;
	for (mt = 0; mt < MIGRATE_TYPES; mt++) {
		if (!list_empty(&fa->free_list[mt])) {
			if (!try_free_area(zone, mt, csa))
				return 0;
		}
	}
	return -ENOMEM;
}

static void free_pfn_range(unsigned long pfn, unsigned long npages)
{
	unsigned long pages = TOP_NR_PAGES;
	unsigned long count;
	struct page *page = NULL;

	for (count = 0; count < npages; count += pages, pfn += pages) {
		page = pfn_to_page(pfn);
		__free_pages(page, TOP_ORDER);
	}
}

#else /* USE_CONTIG_ALLOC */
/* Scan zone pfns to locate a suitable candidate range of free pages */
static int check_zone(struct zone *zone, struct csa *csa)
{
	int ret = -ENOMEM;
	unsigned long flags;
	unsigned long pfn;
	/* pfn=0 is not valid, no use 0 value for unset objects */
	unsigned long start_pfn, end_pfn;
	unsigned long last_start_pfn = 0;
	unsigned long align = csa->align << TOP_ORDER; /* single pages */

	pfn = round_up(zone->zone_start_pfn, align);
again:
	start_pfn = 0;
	spin_lock_irqsave(&zone->lock, flags);

	for (; pfn < zone_end_pfn(zone); pfn++) {
		if (page_ok(pfn)) {
			if (!start_pfn)
				start_pfn = pfn;
			if (!((pfn + 1) & (align - 1))) {
				end_pfn = pfn + 1;
				if (!check_range(start_pfn >> TOP_ORDER,
						 end_pfn >> TOP_ORDER, csa)) {
					ret = 0;
					break;
				}
			}
		} else {
			/* no current valid range */
			start_pfn = 0;
			/* next properly aligned candidate */
			pfn = round_up(pfn + 1, align) - 1;
		}
	}
	spin_unlock_irqrestore(&zone->lock, flags);
	if (!ret) {
		pr_info("RANGE [0x%lx-0x%lx)\n", start_pfn, end_pfn);
		ret = alloc_contig_range(start_pfn, end_pfn, MIGRATE_MOVABLE);
		if (ret) {
			/*
			 * We dropped the lock, so thing might have changed.
			 */
			pr_info("alloc_contig_range returned %d\n", ret);
			/*
			 * Keep scanning from the start_pfn: if the problematic
			 * page is close to the start, we can still use most
			 * of the remaining range.
			 * But if we get the same range again, skip it and
			 * keep scanning from the current page (pfn).
			 */
			if (start_pfn != last_start_pfn) {
				/* New range, restart scan from its start */
				pfn = start_pfn;
			}
			last_start_pfn = start_pfn;
			goto again;
		}
		csa->pfn = start_pfn;
	}
	return ret; /* DO not allocate for now */
}
#endif

static int check_zones(struct csa *csa, gfp_t gfp)
{
	struct zonelist *zl = node_zonelist(csa->nid, gfp);
	struct zone *zone;
	struct zoneref *z;
	nodemask_t *nm = NULL;
	int zhigh = gfp_zone(gfp);

	for_each_zone_zonelist_nodemask(zone, z, zl, zhigh, nm) {
		pr_info("Zone %s [0x%lx-0x%lx] nr_free=0x%lx",
			zone->name, zone->zone_start_pfn, zone_end_pfn(zone),
			zone->free_area[TOP_ORDER].nr_free);
#ifndef USE_CONTIG_ALLOC
		if (!check_freelists(zone, csa))
			return 0;
#else
		if (!check_zone(zone, csa))
			return 0;
#endif
	}
	return -ENOMEM;
}

void *csa_alloc_node(int nid, size_t size, size_t align)
{
	int sorder = PAGE_SHIFT + TOP_ORDER; /* log2(pagesize) */
	size_t pagesize = BIT(sorder);
	size_t tsize = round_up(size, BIT(sorder));
	struct csa csa = {
		.size = tsize,
		.count = tsize >> sorder,
		.pfn = 0,
		.nid = nid,
		.align = align ? align >> sorder : 1,
	};

	if (!align) /* default alignment */
		align = pagesize;
	if (!size || (align & (align - 1)))
		return NULL; /* invalid request */
	csa.align = align >> sorder;

	if (check_zones(&csa, GFP_USER))
		return NULL;
	prep_pfn_range(csa.pfn, csa.pfn + (tsize >> PAGE_SHIFT));
	return page_to_virt(pfn_to_page(csa.pfn));
}
EXPORT_SYMBOL(csa_alloc_node);

void csa_free(void *addr, size_t size)
{
	int sorder = PAGE_SHIFT + TOP_ORDER; /* log2(page size) */
	unsigned long npages = round_up(size, BIT(sorder)) >> PAGE_SHIFT;
	unsigned long pfn = page_to_pfn(virt_to_page(addr));

	unprep_pfn_range(pfn, pfn + npages);
#ifndef USE_CONTIG_ALLOC
	free_pfn_range(pfn, npages);
#else
	free_contig_range(pfn, npages);
#endif
}
EXPORT_SYMBOL(csa_free);

static int __init csa_init(void)
{
	pr_info("CSA: entering\n");
	return 0;
}

static void __exit csa_cleanup(void)
{
	/* We do not maintain records: callers should have freed their stuff */
	pr_info("CSA: cleanup\n");
}

module_init(csa_init);
module_exit(csa_cleanup);
