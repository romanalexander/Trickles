/* 
 * Copyright (C) 2000 - 2003 Jeff Dike (jdike@addtoit.com)
 * Licensed under the GPL
 */

#ifndef __UM_PAGE_H
#define __UM_PAGE_H

struct page;

#include "asm/arch/page.h"

#undef BUG
#undef PAGE_BUG
#undef __pa
#undef __va
#undef virt_to_page
#undef VALID_PAGE
#undef PAGE_OFFSET
#undef KERNELBASE

extern unsigned long uml_physmem;

#define PAGE_OFFSET (uml_physmem)
#define KERNELBASE PAGE_OFFSET

#ifndef __ASSEMBLY__

extern void stop(void);

#define BUG() do { \
	panic("kernel BUG at %s:%d!\n", __FILE__, __LINE__); \
} while (0)

#define PAGE_BUG(page) do { \
	BUG(); \
} while (0)

#endif /* __ASSEMBLY__ */

#define __va_space (8*1024*1024)

extern unsigned long to_phys(void *virt);
extern void *to_virt(unsigned long phys);

#define __pa(virt) to_phys((void *) virt)
#define __va(phys) to_virt((unsigned long) phys)

#define VALID_PAGE(page) ((page - mem_map) < max_mapnr)

extern struct page *arch_validate(struct page *page, int mask, int order);
#define HAVE_ARCH_VALIDATE

extern void arch_free_page(struct page *page, int order);
#define HAVE_ARCH_FREE_PAGE

#endif

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
