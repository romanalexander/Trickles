#ifndef _UM_PARAM_H
#define _UM_PARAM_H

#define HZ 100

#define EXEC_PAGESIZE   4096

#ifndef NGROUPS
#define NGROUPS         32
#endif

#ifndef NOGROUP
#define NOGROUP         (-1)
#endif

#define MAXHOSTNAMELEN  64      /* max length of hostname */

#ifdef __KERNEL__
# define CLOCKS_PER_SEC 100    /* frequency at which times() counts */
#endif

#endif
