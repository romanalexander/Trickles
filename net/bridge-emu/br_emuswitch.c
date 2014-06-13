/* Emuswitch functions */

#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/skbuff.h>
#include <linux/if_bridge.h>
#include <linux/netfilter_bridge.h>
#include <linux/rtnetlink.h>
#include "br_private.h"

/* Timer used to pace port queue */

#ifdef CONFIG_SMP
#error "Not SMP safe"
#endif


#define INTERVAL 1000000

static void drain_port_timer(struct net_bridge_throttle_state *state) {
	struct timeval tv;
#if 0 // microoptimization
	if(state->queue.qlen == 0) {
		del_timer(&state->queue_timer);
		return;
	}
#endif

	/* compute number of bytes we're allowed to send out
	   XXX Need to do filtering to calculate average time
	 */
	do_gettimeofday(&tv);
	// approximate divide by 1000000
	int sdelta = tv.tv_sec - state->lastTV.tv_sec;
#define SDELTA_CLAMP (10)
	if(sdelta > SDELTA_CLAMP) sdelta = SDELTA_CLAMP;
	__u64 usDelta = (__u64)(sdelta << 20ULL) + 
		(__u64)((int)tv.tv_usec - (int)state->lastTV.tv_usec);
	int byteLimit = (usDelta * state->bytesPerSecond) >> 20ULL;
#if 0
	if(byteLimit > 1500 && net_ratelimit()) {
		printk("elapsed us: %lld, limit: %d\n", usDelta, byteLimit);
	}
#endif

	int sent = 0, brokeLimit = 0;

	//printk("Queue length: %d\n", state->queue.qlen);
	while(state->queue.qlen > 0) {
		struct sk_buff *skb = skb_peek(&state->queue);
		if(state->bytesSentInInterval + skb->len < byteLimit) {
			__skb_unlink(skb, &state->queue);
			if(skb->dev == NULL) {
				printk("warning: skb->dev == NULL\n");
			}
			//printk("thunking\n");
			state->bytesSentInInterval += skb->len; // need to read len before possible deallocation
			EMUSWITCH_SKB_CB(skb)->thunk(EMUSWITCH_SKB_CB(skb)->thunkstate);
			sent = 1;
		} else {
			break;
		}
	}
	if(state->bytesSentInInterval > INTERVAL) {
		brokeLimit = 1;
	}
	if(brokeLimit) {
#if 1
		printk("bytes in interval %d bytelimit: %d qlen: %d\n", 
		       state->bytesSentInInterval, byteLimit, state->queue.qlen);
#endif
		state->bytesSentInInterval = 0;
		state->lastTV = tv;
	}
	//printk("timer2\n");

	BUG_TRAP(!timer_pending(&state->queue_timer));
	if(!timer_pending(&state->queue_timer)) {
		state->timeout = jiffies + 1;
		mod_timer(&state->queue_timer, state->timeout);
	}
}

void restartTimer(struct net_bridge_throttle_state *state) {
	//state->bytesSentInInterval = 0;
	state->timeout = jiffies + 1;

	//BUG_TRAP(!timer_pending(&state->queue_timer));
	mod_timer(&state->queue_timer, state->timeout);
}


int emuswitch_process(struct net_bridge_throttle_state *state, 
		      struct sk_buff *skb) {
	static int maxqlen = 0;
	//emuswitch_thunk_t thunk = EMUSWITCH_SKB_CB(skb)->thunk;
	//emuswitch_thunkstate_t thunkState = EMUSWITCH_SKB_CB(skb)->thunkstate;
	maxqlen = max(maxqlen, state->maxQueueLen);

	if(state->queue.qlen < state->maxQueueLen) {
		int oldQlen = state->queue.qlen;
		__skb_queue_tail(&state->queue, skb);
#if 0 // microoptimization
		if(oldQlen == 0) {
			restartTimer(state);
		}
#endif
		//printk("queue length %d\n", state->queue.qlen);
	} else {
		// Drop packet
		printk("dropped packet\n");
		__kfree_skb(skb);
	}
	if(state->queue.qlen > 200) {
		printk("queue length: %d/%d\n", state->queue.qlen, state->maxQueueLen);
	}
	return 1;
}

void init_nb_throttle_state(struct net_bridge_throttle_state *state) {
	state->useThrottle = 0;
        skb_queue_head_init(&state->queue);
	init_timer(&state->queue_timer);
	state->queue_timer.function = (void(*)(unsigned long))drain_port_timer;
	state->queue_timer.data = (unsigned long)state;
}

static inline void 
enable_nb_throttle_state(struct net_bridge_throttle_state *state) {
	if(!state->useThrottle) {
		state->useThrottle = 1;
		BUG_TRAP(state->maxQueueLen > 0);
		BUG_TRAP(state->bytesPerSecond > 0);

		BUG_TRAP(!timer_pending(&state->queue_timer));
		restartTimer(state);
		printk("timer set\n");

		do_gettimeofday(&state->lastTV);
	}
}

static inline void 
disable_nb_throttle_state(struct net_bridge_throttle_state *state) {
	if(state->useThrottle) {
		state->useThrottle = 0;

		BUG_TRAP(state->maxQueueLen > 0);
		BUG_TRAP(state->bytesPerSecond > 0);

		state->bytesSentInInterval = 0;
		state->timeout = 0;

		del_timer(&state->queue_timer);
		while(state->queue.qlen > 0) {
			struct sk_buff *skb = __skb_dequeue(&state->queue);
			__kfree_skb(skb);
		}
	}
}

int br_port_set_emuswitch(struct net_bridge_port *p, 
			   struct __emuswitch_info *info) {
	local_bh_disable();
#define INIT(DIR,OFFS)							\
	do {								\
		p->DIR##_state.maxQueueLen =				\
			info->direction[OFFS].maxQueueLen;		\
		p->DIR##_state.bytesPerSecond =				\
			info->direction[OFFS].bytesPerSecond;		\
		if(info->direction[OFFS].useThrottle) {			\
			enable_nb_throttle_state(&p->DIR##_state);	\
		} else {						\
			disable_nb_throttle_state(&p->DIR##_state);	\
		}							\
	} while(0);

	if(info->directions & EMU_INPUT) {
		INIT(input,0);
	}
	if(info->directions & EMU_OUTPUT) {
		INIT(output,1);
	}
#undef INIT
	local_bh_enable();
	return 0;
}

int br_port_get_emuswitch(struct net_bridge_port *p, 
			   struct __emuswitch_info *info) {
	local_bh_disable();
#define READINFO(DIR,OFFS)					\
	do {						\
		info->direction[OFFS].maxQueueLen =	\
			p->DIR##_state.maxQueueLen;	\
		info->direction[OFFS].bytesPerSecond =	\
			p->DIR##_state.bytesPerSecond;	\
		info->direction[OFFS].useThrottle =	\
			p->DIR##_state.useThrottle;	\
	} while(0);

	if(info->directions & EMU_INPUT) {
		READINFO(input,0);
	}
	if(info->directions & EMU_OUTPUT) {
		READINFO(output,1);
	}
#undef READINFO
	local_bh_enable();
	printk("get emuswitch enabled %d = %d\n", p->input_state.useThrottle, info->direction[0].useThrottle);
	return 0;
}
