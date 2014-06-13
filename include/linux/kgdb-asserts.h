#ifndef _GDB_ASSERTS_H_
#define _GDB_ASSERTS_H_

/*
 * Copyright (C) 2001 Amit S. Kale
 */

void show_stack(unsigned long * esp);
#define KGDB_ASSERT(message, condition)	do {			\
	if (!(condition)) {					\
		printk("kgdb assertion failed: %s\n", message); \
		show_stack(NULL);				\
breakpoint();							\
	}							\
} while (0)

#define KA_VALID_ERRNO(errno) ((errno) > 0 && (errno) <= EMEDIUMTYPE)

#define KA_VALID_PTR_ERR(ptr) KA_VALID_ERRNO(-PTR_ERR(ptr))

#define KA_VALID_KPTR(ptr)  (!(ptr) ||	\
	       ((void *)(ptr) >= (void *)PAGE_OFFSET &&  \
	       (void *)(ptr) < ERR_PTR(-EMEDIUMTYPE)))

#define KA_VALID_PTRORERR(errptr) (KA_VALID_KPTR(errptr) || KA_VALID_PTR_ERR(errptr))

#ifndef CONFIG_SMP
#define KA_HELD_GKL()	1
#else
#define KA_HELD_GKL()	(current->lock_depth >= 0)
#endif

#endif /* _GDB_ASSERTS_H_ */
