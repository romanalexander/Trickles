#include "linux/module.h"
#include "linux/in6.h"
#include "linux/rwsem.h"
#include "asm/byteorder.h"
#include "asm/semaphore.h"
#include "asm/uaccess.h"
#include "asm/checksum.h"
#include "asm/errno.h"

EXPORT_SYMBOL(__down_failed);
EXPORT_SYMBOL(__down_failed_interruptible);
EXPORT_SYMBOL(__down_failed_trylock);
EXPORT_SYMBOL(__up_wakeup);

unsigned int csum_partial_copy_generic (const char *src, char *dst,
	int len, int sum, int *src_err_ptr, int *dst_err_ptr);

/* Networking helper routines. */
EXPORT_SYMBOL(csum_partial_copy_from);
EXPORT_SYMBOL(csum_partial_copy_to);
EXPORT_SYMBOL(csum_partial_copy_generic);
