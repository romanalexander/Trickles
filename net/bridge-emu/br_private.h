/*
 *	Linux ethernet bridge
 *
 *	Authors:
 *	Lennert Buytenhek		<buytenh@gnu.org>
 *
 *	$Id: br_private.h,v 1.1.1.1 2004/06/19 05:03:04 ashieh Exp $
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */

#ifndef _BR_PRIVATE_H
#define _BR_PRIVATE_H

#include <linux/netdevice.h>
#include <linux/miscdevice.h>
#include <linux/if_bridge.h>
#include "br_private_timer.h"

#define BR_HASH_BITS 8
#define BR_HASH_SIZE (1 << BR_HASH_BITS)

#define BR_HOLD_TIME (1*HZ)

typedef struct bridge_id bridge_id;
typedef struct mac_addr mac_addr;
typedef __u16 port_id;

struct bridge_id
{
	unsigned char	prio[2];
	unsigned char	addr[6];
};

struct mac_addr
{
	unsigned char	addr[6];
	unsigned char	pad[2];
};

struct net_bridge_fdb_entry
{
	struct net_bridge_fdb_entry	*next_hash;
	struct net_bridge_fdb_entry	**pprev_hash;
	atomic_t			use_count;
	mac_addr			addr;
	struct net_bridge_port		*dst;
	unsigned long			ageing_timer;
	unsigned			is_local:1;
	unsigned			is_static:1;
};


#ifdef CONFIG_EMUSWITCH_MODULE

#if 0
#define FRAME_LEN (1500)
static inline __u64 nextTxTime(struct net_bridge_throttle_state *state) {
	return state->lastTxTime + 
	       (state->lastPacketLen * state->frameTxDuration) / 
		    FRAME_LEN;
}


// Jiffies to "ns2"
#define JIFFIES_TO_NS2(J) (((J) * HZ) << 30ULL)
#define NS2_TO_JIFFIES(N) (((N) >> 30ULL) * HZ)
#endif
#if 0
struct jiffie_offset {
	// Note that this must be a proper fraction!!!  
	int jiffie;
	int offset;
};
#endif

struct net_bridge_throttle_state {
	/* Configuration parameters */
	int useThrottle; // 1 = throttle on. 0 = throttle off
	int maxQueueLen;
	int bytesPerSecond; // number of packets to accept in this direction per jiffie
	struct timeval lastTV;

	// End of configuration parameters
#if 0
	int rateNumerator; // numerator of packets/s
	int rateDenominator; // denominator of packets/s
	int frameTxDuration; // (ns2) Time to transmit a FRAME_LEN byte Ethernet frame

	// xxx Implement special queue drop flavors ???

	// Dynamic state


	int state; // 0 = quiescent. 
	           // 1 = packet potentially in progress (check lastTxTime)
#define QUIESCENT(S,NT) ((S)->state == 0 || JIFFIES_TO_NS2(jiffies) >= NT)
	struct jiffie_offset lastTxEndTime;
	// ^^ This is derived from realJiffie + realOffset + computed
	// TxTime (simulation). XXX Should we explicitly sync
	// lastTxEnd with actual NIC behavior?
	int lastPacketLen;
#endif
	int bytesSentInInterval; // number of packets sent in current jiffie
	struct sk_buff_head queue;
	int timeout;
	struct timer_list queue_timer;
};
#define INIT_NB_THROTTLE_STATE(S) init_nb_throttle_state(S)
#else
#define INIT_NB_THROTTLE_STATE(S) /* Do nothing */
#endif // CONFIG_EMUSWITCH_MODULE

struct net_bridge_port
{
	struct net_bridge_port		*next;
	struct net_bridge		*br;
	struct net_device		*dev;
	int				port_no;

	/* STP */
	port_id				port_id;
	int				state;
	int				path_cost;
	bridge_id			designated_root;
	int				designated_cost;
	bridge_id			designated_bridge;
	port_id				designated_port;
	unsigned			topology_change_ack:1;
	unsigned			config_pending:1;
	int				priority;

	struct br_timer			forward_delay_timer;
	struct br_timer			hold_timer;
	struct br_timer			message_age_timer;

#ifdef CONFIG_EMUSWITCH_MODULE
	struct net_bridge_throttle_state input_state;
	struct net_bridge_throttle_state output_state;
#endif
};

#ifdef CONFIG_EMUSWITCH_MODULE
typedef void (*emuswitch_thunk_t)(void *);
typedef void *emuswitch_thunkstate_t;
struct emuswitch_skb_cb {
	struct net_bridge_port *from;
	struct net_bridge_port *to;
#if 0
	struct jiffie_offset predictedTxTime;
#endif

	emuswitch_thunk_t thunk;
	emuswitch_thunkstate_t thunkstate;
};

#define EMUSWITCH_SKB_CB(SKB) ((struct emuswitch_skb_cb*)&(SKB)->cb[0])
#endif

struct net_bridge
{
	struct net_bridge		*next;
	rwlock_t			lock;
	struct net_bridge_port		*port_list;
	struct net_device		dev;
	struct net_device_stats		statistics;
	rwlock_t			hash_lock;
	struct net_bridge_fdb_entry	*hash[BR_HASH_SIZE];
	struct timer_list		tick;

	/* STP */
	bridge_id			designated_root;
	int				root_path_cost;
	int				root_port;
	int				max_age;
	int				hello_time;
	int				forward_delay;
	bridge_id			bridge_id;
	int				bridge_max_age;
	int				bridge_hello_time;
	int				bridge_forward_delay;
	unsigned			stp_enabled:1;
	unsigned			topology_change:1;
	unsigned			topology_change_detected:1;

	struct br_timer			hello_timer;
	struct br_timer			tcn_timer;
	struct br_timer			topology_change_timer;
	struct br_timer			gc_timer;

	int				ageing_time;
	int				gc_interval;
};

extern struct notifier_block br_device_notifier;
extern unsigned char bridge_ula[6];

/* br.c */
extern void br_dec_use_count(void);
extern void br_inc_use_count(void);

/* br_device.c */
extern void br_dev_setup(struct net_device *dev);
extern int br_dev_xmit(struct sk_buff *skb, struct net_device *dev);

/* br_fdb.c */
extern void br_fdb_changeaddr(struct net_bridge_port *p,
		       unsigned char *newaddr);
extern void br_fdb_cleanup(struct net_bridge *br);
extern void br_fdb_delete_by_port(struct net_bridge *br,
			   struct net_bridge_port *p);
extern struct net_bridge_fdb_entry *br_fdb_get(struct net_bridge *br,
					unsigned char *addr);
extern void br_fdb_put(struct net_bridge_fdb_entry *ent);
extern int  br_fdb_get_entries(struct net_bridge *br,
			unsigned char *_buf,
			int maxnum,
			int offset);
extern void br_fdb_insert(struct net_bridge *br,
		   struct net_bridge_port *source,
		   unsigned char *addr,
		   int is_local);

/* br_forward.c */
extern void br_deliver(struct net_bridge_port *to,
		struct sk_buff *skb);
extern void br_forward(struct net_bridge_port *to,
		struct sk_buff *skb);
extern void br_flood_deliver(struct net_bridge *br,
		      struct sk_buff *skb,
		      int clone);
extern void br_flood_forward(struct net_bridge *br,
		      struct sk_buff *skb,
		      int clone);

/* br_if.c */
extern int br_add_bridge(char *name);
extern int br_del_bridge(char *name);
extern int br_add_if(struct net_bridge *br,
	      struct net_device *dev);
extern int br_del_if(struct net_bridge *br,
	      struct net_device *dev);
extern int br_get_bridge_ifindices(int *indices,
			    int num);
extern void br_get_port_ifindices(struct net_bridge *br,
			   int *ifindices);

/* br_input.c */
extern void br_handle_frame(struct sk_buff *skb);

/* br_ioctl.c */
extern void br_call_ioctl_atomic(void (*fn)(void));
extern int br_ioctl(struct net_bridge *br,
	     unsigned int cmd,
	     unsigned long arg0,
	     unsigned long arg1,
	     unsigned long arg2);
extern int br_ioctl_deviceless_stub(unsigned long arg);

extern struct net_bridge_port *br_get_port(struct net_bridge *br,
				    int port_no);
extern void br_init_port(struct net_bridge_port *p);
extern port_id br_make_port_id(struct net_bridge_port *p);
extern int br_is_root_bridge(struct net_bridge *br);

#ifdef CONFIG_BRIDGESTEP
/* br_stp.c */
extern void br_become_designated_port(struct net_bridge_port *p);

/* br_stp_bpdu.c */
extern int br_stp_handle_bpdu(struct sk_buff *skb);
#else
#define br_become_designated_port(X)
static inline int br_stp_handle_bpdu(struct sk_buff *skb) { __kfree_skb(skb); return 0;}
#endif

/* br_stp_if.c */
extern void br_stp_enable_bridge(struct net_bridge *br);
extern void br_stp_disable_bridge(struct net_bridge *br);
extern void br_stp_enable_port(struct net_bridge_port *p);
extern void br_stp_disable_port(struct net_bridge_port *p);
extern void br_stp_recalculate_bridge_id(struct net_bridge *br);
extern void br_stp_set_bridge_priority(struct net_bridge *br,
				int newprio);
extern void br_stp_set_port_priority(struct net_bridge_port *p,
			      int newprio);
extern void br_stp_set_path_cost(struct net_bridge_port *p,
			  int path_cost);


#ifdef CONFIG_EMUSWITCH_MODULE
/* br_emuswitch.c */
extern int br_port_set_emuswitch(struct net_bridge_port *p, 
				 struct __emuswitch_info *info);
extern int br_port_get_emuswitch(struct net_bridge_port *p, 
				 struct __emuswitch_info *info);
#define EMUSWITCH_SET_PORT_DIR(SKB, TO, DIR)	\
   do {						\
	   EMUSWITCH_SKB_CB(SKB)->DIR = (TO);	\
   } while(0);
#define EMUSWITCH_SET_TOPORT(SKB, TO)	\
	EMUSWITCH_SET_PORT_DIR(SKB, TO, to)
#define EMUSWITCH_SET_FROMPORT(SKB, FROM) \
	EMUSWITCH_SET_PORT_DIR(SKB, FROM, from);

/* Process returns 0 if packet can be sent immediately, 1 otherwise */
extern int emuswitch_process(struct net_bridge_throttle_state *state, 
			     struct sk_buff *skb);
extern void init_nb_throttle_state(struct net_bridge_throttle_state *state);

#define EMUSWITCH_DIR(SKB, THUNK, THUNKSTATE, NORMAL, SKIP, STATE)	\
	if(EMUSWITCH_SKB_CB(SKB)->STATE.useThrottle) {			\
	   EMUSWITCH_SKB_CB(SKB)->thunk = THUNK;			\
	   EMUSWITCH_SKB_CB(SKB)->thunkstate = THUNKSTATE;		\
	   emuswitch_process(&EMUSWITCH_SKB_CB(SKB)->STATE, SKB);	\
		   { NORMAL; }						\
		   /* else { SKIP; } */					\
	} while(0)

#define EMUSWITCH_IN(SKB, THUNK, THUNKSTATE, NORMAL, SKIP)		\
	EMUSWITCH_DIR(SKB, THUNK, THUNKSTATE, NORMAL, SKIP, from->input_state);

#define EMUSWITCH_OUT(SKB, THUNK, THUNKSTATE, NORMAL, SKIP)		\
	EMUSWITCH_DIR(SKB, THUNK, THUNKSTATE, NORMAL, SKIP, from->output_state);
#else

/* Ops below preprocessed away */
#define EMUSWITCH_SET_TOPORT(SKB,TO)
#define EMUSWITCH_SET_FROMPORT(SKB,FROM)
#define EMUSWITCH_IN(SKB, THUNK, THUNKSTATE, SKIP)
#define EMUSWITCH_OUT(SKB, THUNK, THUNKSTATE, SKIP)

#endif // CONFIG_EMUSWITCH_MODULE

#endif
