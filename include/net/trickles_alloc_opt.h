#ifndef _IN_TRICKLES_H
	#error "File can only be included from trickles.h"
#endif // _IN_TRICKLES_H 

// Recycling allocation optimizations

#define RECYCLE_LIMIT (1000)
// Helper functions for recycling old skb
#define TRICKLES_TX_SKB_LEN (MAX_TCP_HEADER + MAX_TRICKLES_SERVER_HDR_LEN + TRICKLES_MSS)

static inline void recycle_headerinit(void *p)
{
	struct sk_buff *skb = p;

	skb->next = NULL;
	skb->prev = NULL;
	skb->list = NULL;
	skb->sk = NULL;
	skb->stamp.tv_sec=0;	/* No idea about time */
	skb->dev = NULL;
	skb->real_dev = NULL;
	skb->dst = NULL;
	memset(skb->cb, 0, sizeof(skb->cb));
	skb->pkt_type = PACKET_HOST;	/* Default type */
	skb->ip_summed = 0;
	skb->priority = 0;
	skb->security = 0;	/* By default packets are insecure */
	skb->destructor = NULL;

#ifdef CONFIG_NETFILTER
	skb->nfmark = skb->nfcache = 0;
	skb->nfct = NULL;
#ifdef CONFIG_NETFILTER_DEBUG
	skb->nf_debug = 0;
#endif
#endif
#ifdef CONFIG_NET_SCHED
	skb->tc_index = 0;
#endif
}

#ifdef ENABLE_RECYCLING
static inline void save_for_recycle(struct sock *sk, struct sk_buff *skb) {
	struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;
	int r0 = skb_shinfo(skb)->nr_frags != 0,
		r1 = tp->t.recycleList.qlen >= RECYCLE_LIMIT,
		r2 = skb->truesize - sizeof(struct sk_buff) < TRICKLES_TX_SKB_LEN;
	if(r0 || r1 || r2) {
		if(r0 || r2) {
			if(trickles_ratelimit())
				printk("Unsuitable for recycling %d %d %d truesize = %d skblen = %d\n", r0, r1, r2, skb->truesize, TRICKLES_TX_SKB_LEN);
		}
		__kfree_skb(skb);
		return;
	}
	// initialization copied from alloc_skb
	recycle_headerinit(skb);

	skb->tail = skb->data = skb->head;
	skb->len = 0;
	skb->cloned = 0;
	skb->data_len =0;

	atomic_set(&skb->users, 1);
	atomic_set(&(skb_shinfo(skb)->dataref), 1);
	skb_shinfo(skb)->nr_frags = 0;
	skb_shinfo(skb)->frag_list = NULL;

	__skb_queue_tail(&tp->t.recycleList, skb);
}
#else
static inline void save_for_recycle(struct sock *sk, struct sk_buff *skb) {
	kfree_skb(skb);
}
#endif

static inline struct sk_buff *recycle(struct sock *sk) {
	struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;
	// Attempt to improve cache performance by using most recently enqueued packets first
	struct sk_buff *skb = __skb_dequeue_tail(&tp->t.recycleList);
#if 0
	if(skb) {
		if(trickles_ratelimit()) {
			printk("recycle successful\n");
		}
	} else {
		if(trickles_ratelimit()) {
			printk("recycle unsuccessful\n");
		}
	}
#endif
	return skb;
}

