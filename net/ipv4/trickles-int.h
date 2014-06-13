#ifndef TRICKLES_INT_H
#define TRICKELS_INT_H

#ifndef USERTEST
#include <linux/skbuff.h>
#include <net/trickles.h>

#include <linux/slab.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/module.h>
#include <linux/compile.h>
#include <linux/vmalloc.h>
#include <linux/mman.h>
#include <linux/file.h>

#include <linux/random.h>

//#define DEBUG_TRICKLES_ALLOCATION
#include <net/trickles_packet_helpers.h>
#include <net/tmalloc.h>
#include <linux/ctype.h>

#include <linux/udp.h>

/* Workqueue / task queue backwards compatibility stuff */
/* Copied from orinoco.h */

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,5,41)
#include <linux/workqueue.h>
#else
#include <linux/tqueue.h>
#define work_struct tq_struct
#define INIT_WORK INIT_TQUEUE
#define schedule_work schedule_task
#endif

#include "timing.h"

double sqrt(double x);
float sqrtf(float x);
// Hacks to make libm.a link properly (necessary if not using -ffastmath
//int fputs, stderr, __errno_location, fwrite, __assert_fail;

#else // USERTEST

#include <stdio.h>
#include <malloc.h>
#include <string.h>

#include <assert.h>
#include "compat.h"
#include "skbuff.h"
#include <time.h>

#include "timing.h"

#include "trickles_packet_helpers.h"
#include "tmalloc.h"

#include <ctype.h>

#endif // USERTEST

extern int packetTraceLevel;
extern int packetTraceLogged;
extern int packetTraceCounter;
extern int packetTraceTotal;

#define PACKET_TRACE_OFO 		(0)
#define PACKET_TRACE_FRAGMENTS 	(0)

#define START_PACKET() do { packetTraceLogged = 0; } while (0)
#define TRACE_K_PACKETS(K) do { packetTraceLevel = 1; packetTraceCounter = 0; packetTraceTotal = (K); } while(0)
#define TRACE_THIS_PACKET() TRACE_K_PACKETS(1)
#define TRACE_K_PACKETS_ONCE(K) if(packetTraceTotal == 0) TRACE_K_PACKETS(K)

#define PACKET_TRACE_LOG_DO(ACTION)				\
	if(packetTraceLevel && packetTraceTotal > 0) {		\
		if((packetTraceCounter < packetTraceTotal) &&		\
		   !packetTraceLogged) {				\
			printk("packet[%d] = {", packetTraceCounter++);	\
			packetTraceLogged = 1;	\
		}				\
		ACTION;				\
	}

#define PACKET_TRACE_LOG(S,...)			\
	PACKET_TRACE_LOG_DO(printk(S,##__VA_ARGS__));

#define PACKET_TRACE_FINISH()						\
	do {								\
		if(packetTraceLogged) {printk("}\n");			\
			if(packetTraceCounter == packetTraceTotal) { packetTraceCounter = 0; packetTraceTotal = 0; } \
		}							\
	} while(0);

#endif // TRICKLES_INT_H
