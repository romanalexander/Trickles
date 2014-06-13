#ifndef __UM_TIMEX_H
#define __UM_TIMEX_H

#include "linux/time.h"

typedef unsigned long cycles_t;

#define cacheflush_time (0)

static inline cycles_t get_cycles (void)
{
	return 0;
}

#define vxtime_lock()		do ; while (0)
#define vxtime_unlock()		do ; while (0)

#endif
