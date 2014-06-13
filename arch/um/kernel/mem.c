/* 
 * Copyright (C) 2000 - 2003 Jeff Dike (jdike@addtoit.com)
 * Licensed under the GPL
 */

#include "linux/stddef.h"
#include "linux/kernel.h"
#include "linux/mm.h"
#include "linux/bootmem.h"
#include "linux/highmem.h"
#include "asm/page.h"
#include "asm/fixmap.h"
#include "asm/pgalloc.h"
#include "user_util.h"
#include "kern_util.h"
#include "kern.h"
#include "mem_user.h"
#include "uml_uaccess.h"
#include "os.h"

extern char __binary_start;

/* Changed during early boot */
unsigned long *empty_zero_page = NULL;
unsigned long *empty_bad_page = NULL;
pgd_t swapper_pg_dir[1024];
unsigned long highmem;
int kmalloc_ok = 0;

static unsigned long brk_end;
static unsigned long totalram_pages = 0;

void unmap_physmem(void)
{
	os_unmap_memory((void *) brk_end, uml_reserved - brk_end);
}

static void map_cb(void *unused)
{
	map_memory(brk_end, __pa(brk_end), uml_reserved - brk_end, 1, 1, 0);
}

#ifdef CONFIG_HIGHMEM
static void setup_highmem(unsigned long highmem_start, 
			  unsigned long highmem_len)
{
	struct page *page;
	unsigned long highmem_pfn;
	int i;

	highmem_start_page = virt_to_page(highmem_start);

	highmem_pfn = __pa(highmem_start) >> PAGE_SHIFT;
	for(i = 0; i < highmem_len >> PAGE_SHIFT; i++){
		page = &mem_map[highmem_pfn + i];
		ClearPageReserved(page);
		set_bit(PG_highmem, &page->flags);
		atomic_set(&page->count, 1);
		__free_page(page);
	}
}
#endif

void mem_init(void)
{
	unsigned long start;

        /* clear the zero-page */
        memset((void *) empty_zero_page, 0, PAGE_SIZE);

	/* Map in the area just after the brk now that kmalloc is about
	 * to be turned on.
	 */
	brk_end = (unsigned long) UML_ROUND_UP(sbrk(0));
	map_cb(NULL);
	initial_thread_cb(map_cb, NULL);
	free_bootmem(__pa(brk_end), uml_reserved - brk_end);
	uml_reserved = brk_end;

	/* Fill in any hole at the start of the binary */
	start = (unsigned long) &__binary_start;
	if(uml_physmem != start){
		map_memory(uml_physmem, __pa(uml_physmem), start - uml_physmem,
			   1, 1, 0);
	}

	/* this will put all low memory onto the freelists */
	totalram_pages = free_all_bootmem();
	totalram_pages += highmem >> PAGE_SHIFT;
	num_physpages = totalram_pages;
	printk(KERN_INFO "Memory: %luk available\n", 
	       (unsigned long) nr_free_pages() << (PAGE_SHIFT-10));
	kmalloc_ok = 1;

#ifdef CONFIG_HIGHMEM
	setup_highmem(end_iomem, highmem);
#endif
}

static void __init fixrange_init(unsigned long start, unsigned long end, 
				 pgd_t *pgd_base)
{
	pgd_t *pgd;
	pmd_t *pmd;
	pte_t *pte;
	int i, j;
	unsigned long vaddr;

	vaddr = start;
	i = __pgd_offset(vaddr);
	j = __pmd_offset(vaddr);
	pgd = pgd_base + i;

	for ( ; (i < PTRS_PER_PGD) && (vaddr < end); pgd++, i++) {
		pmd = (pmd_t *)pgd;
		for (; (j < PTRS_PER_PMD) && (vaddr != end); pmd++, j++) {
			if (pmd_none(*pmd)) {
				pte = (pte_t *) alloc_bootmem_low_pages(PAGE_SIZE);
				set_pmd(pmd, __pmd(_KERNPG_TABLE + 
						   (unsigned long) __pa(pte)));
				if (pte != pte_offset(pmd, 0))
					BUG();
			}
			vaddr += PMD_SIZE;
		}
		j = 0;
	}
}

#ifdef CONFIG_HIGHMEM
pte_t *kmap_pte;
pgprot_t kmap_prot;

#define kmap_get_fixmap_pte(vaddr)					\
	pte_offset(pmd_offset(pgd_offset_k(vaddr), (vaddr)), (vaddr))

void __init kmap_init(void)
{
	unsigned long kmap_vstart;

	/* cache the first kmap pte */
	kmap_vstart = __fix_to_virt(FIX_KMAP_BEGIN);
	kmap_pte = kmap_get_fixmap_pte(kmap_vstart);

	kmap_prot = PAGE_KERNEL;
}

static void init_highmem(void)
{
	pgd_t *pgd;
	pmd_t *pmd;
	pte_t *pte;
	unsigned long vaddr;

	/*
	 * Permanent kmaps:
	 */
	vaddr = PKMAP_BASE;
	fixrange_init(vaddr, vaddr + PAGE_SIZE*LAST_PKMAP, swapper_pg_dir);

	pgd = swapper_pg_dir + __pgd_offset(vaddr);
	pmd = pmd_offset(pgd, vaddr);
	pte = pte_offset(pmd, vaddr);
	pkmap_page_table = pte;

	kmap_init();
}

#endif /* CONFIG_HIGHMEM */

void paging_init(void)
{
	unsigned long zones_size[MAX_NR_ZONES], vaddr;
	int i;

	empty_zero_page = (unsigned long *) alloc_bootmem_low_pages(PAGE_SIZE);
	empty_bad_page = (unsigned long *) alloc_bootmem_low_pages(PAGE_SIZE);
	for(i=0;i<sizeof(zones_size)/sizeof(zones_size[0]);i++) 
		zones_size[i] = 0;
	zones_size[0] = (end_iomem >> PAGE_SHIFT) - (uml_physmem >> PAGE_SHIFT);
	zones_size[2] = highmem >> PAGE_SHIFT;
	free_area_init(zones_size);

	/*
	 * Fixed mappings, only the page table structure has to be
	 * created - mappings will be set by set_fixmap():
	 */
	vaddr = __fix_to_virt(__end_of_fixed_addresses - 1) & PMD_MASK;
	fixrange_init(vaddr, FIXADDR_TOP, swapper_pg_dir);

#if CONFIG_HIGHMEM
	init_highmem();
#endif
}

struct page *arch_validate(struct page *page, int mask, int order)
{
	unsigned long addr, zero = 0;
	int i;

 again:
	if(page == NULL) return(page);
	if(PageHighMem(page)) return(page);

	addr = (unsigned long) page_address(page);
	for(i = 0; i < (1 << order); i++){
		current->thread.fault_addr = (void *) addr;
		if(__do_copy_to_user((void *) addr, &zero, 
				     sizeof(zero),
				     &current->thread.fault_addr,
				     &current->thread.fault_catcher)){
			if(!(mask & __GFP_WAIT)) return(NULL);
			else break;
		}
		addr += PAGE_SIZE;
	}
	if(i == (1 << order)) return(page);
	page = _alloc_pages(mask, order);
	goto again;
}

/* This can't do anything because nothing in the kernel image can be freed
 * since it's not in kernel physical memory.
 */

void free_initmem(void)
{
}

#ifdef CONFIG_BLK_DEV_INITRD

void free_initrd_mem(unsigned long start, unsigned long end)
{
	if (start < end)
		printk ("Freeing initrd memory: %ldk freed\n", 
			(end - start) >> 10);
	for (; start < end; start += PAGE_SIZE) {
		ClearPageReserved(virt_to_page(start));
		set_page_count(virt_to_page(start), 1);
		free_page(start);
		totalram_pages++;
	}
}
	
#endif

int do_check_pgt_cache(int low, int high)
{
        int freed = 0;
        if(pgtable_cache_size > high) {
                do {
                        if (pgd_quicklist) {
                                free_pgd_slow(get_pgd_fast());
                                freed++;
                        }
                        if (pmd_quicklist) {
                                pmd_free_slow(pmd_alloc_one_fast(NULL, 0));
                                freed++;
                        }
                        if (pte_quicklist) {
                                pte_free_slow(pte_alloc_one_fast(NULL, 0));
                                freed++;
                        }
                } while(pgtable_cache_size > low);
        }
        return freed;
}

void show_mem(void)
{
        int i, total = 0, reserved = 0;
        int shared = 0, cached = 0;
        int highmem = 0;

        printk("Mem-info:\n");
        show_free_areas();
        printk("Free swap:       %6dkB\n", nr_swap_pages<<(PAGE_SHIFT-10));
        i = max_mapnr;
        while(i-- > 0) {
                total++;
                if(PageHighMem(mem_map + i))
                        highmem++;
                if(PageReserved(mem_map + i))
                        reserved++;
                else if(PageSwapCache(mem_map + i))
                        cached++;
                else if(page_count(mem_map + i))
                        shared += page_count(mem_map + i) - 1;
        }
        printk("%d pages of RAM\n", total);
        printk("%d pages of HIGHMEM\n", highmem);
        printk("%d reserved pages\n", reserved);
        printk("%d pages shared\n", shared);
        printk("%d pages swap cached\n", cached);
        printk("%ld pages in page table cache\n", pgtable_cache_size);
        show_buffers();
}

/* Changed by meminfo_compat, which is a setup */
static int meminfo_22 = 0;

static int meminfo_compat(char *str)
{
	meminfo_22 = 1;
	return(1);
}

__setup("22_meminfo", meminfo_compat);

void si_meminfo(struct sysinfo *val)
{
	val->totalram = totalram_pages;
	val->sharedram = 0;
	val->freeram = nr_free_pages();
	val->bufferram = atomic_read(&buffermem_pages);
	val->totalhigh = highmem >> PAGE_SHIFT;
	val->freehigh = nr_free_highpages();
	val->mem_unit = PAGE_SIZE;
	if(meminfo_22){
		val->freeram <<= PAGE_SHIFT;
		val->bufferram <<= PAGE_SHIFT;
		val->totalram <<= PAGE_SHIFT;
		val->sharedram <<= PAGE_SHIFT;
	}
}

/*
 * Overrides for Emacs so that we follow Linus's tabbing style.
 * Emacs will notice this stuff at the end of the file and automatically
 * adjust the settings for this buffer only.  This must remain at the end
 * of the file.
 * ---------------------------------------------------------------------------
 * Local variables:
 * c-file-style: "linux"
 * End:
 */
