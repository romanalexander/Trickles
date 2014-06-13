#ifndef _IN_TRICKLES_H
	#error "File can only be included from trickles.h"
#endif // _IN_TRICKLES_H 

#include <net/trickles_dlist.h>

static void init_minisock(struct cminisock *msk) {
	msk->num_packets = 0;
	msk->ucont_len = 0;
	msk->ucont_data = NULL;
	msk->input_len = 0;
	msk->input = NULL;
	msk->packets = NULL;

	msk->refCnt = 1;
#define HAS_VALID_CACHERECYCLEINDEX(MSK) ((MSK)->cacheRecycleIndex >= 0)
	msk->cacheRecycleIndex = -1; // invalid index
	msk->serverSK = NULL;
	msk->pmsk = NULL;
	msk->isStatic = 0;
}

static void msk_initStatic(struct cminisock *msk) {
	init_minisock(msk);
	msk->isStatic = 1;
	msk->prev = msk->next = NULL;
	msk->ctl = ALLOC_PENDING;
}

static void init_pminisock(struct pminisock *pmsk) {
	pmsk->num_packets = 0;
	pmsk->ucont_len = 0;
	pmsk->ucont_data = NULL;
	pmsk->input_len = 0;
	pmsk->input = NULL;
	pmsk->packets = NULL;
	pmsk->refCnt = 1;
	pmsk->cacheRecycleIndex = -1; // invalid index
}

static void free_msk(struct sock *sk, struct cminisock *msk);

static inline void msk_free_fields(struct sock *sk, struct cminisock *msk) {
	free_msk(sk, msk);
}

#ifndef USERTEST

static inline int alloc_msk_packets(struct cminisock *msk, int numPackets) {
	if(msk->num_packets > 0) {
		printk("msk packets is %d\n", msk->num_packets);
	}
	BUG_TRAP(msk->num_packets == 0);
	BUG_TRAP(numPackets >= 0);
#define MAX_NUM_SIMULATION_PACKETS (8000)
	static struct cminisock_packet packets[NR_CPUS][MAX_NUM_SIMULATION_PACKETS];
	if(!SIMULATION_MODE(msk->sk)) {
		msk->packets = tmalloc(msk->sk, sizeof(struct cminisock_packet) * numPackets);

		// printk("allocated packets to %p\n", msk->packets);

		if(msk->packets == NULL) {
			if(trickles_ratelimit()) {
				printk("out of memory while tmalloc()'ing space for packets\n");
			}
			return 0;
		}
	} else {
		// avoid malloc
		if(numPackets <= MAX_NUM_SIMULATION_PACKETS) {
			msk->packets = packets[smp_processor_id()];
		} else {
			msk->packets = NULL;
			if(trickles_ratelimit()) {
				printk("Too many packets requested during simulation\n");
			}
			return 0;
		}
	}
	msk->num_packets = numPackets;
	return 1;
}

static inline
int can_alloc_trickles_msk(struct sock *sk) {
	struct tcp_opt *tp = &(sk->tp_pinfo.af_tcp);
	struct alloc_head_list *head = &tp->cminisock_api_config.msk_freelist;
	struct cminisock *curr =
		(struct cminisock *)head->next;
	while((struct alloc_head_list*)curr != head && curr->ctl == ALLOC_PROCESSING) {
		//printk("alloc_head loop\n");
		curr = curr->next;
	}
	return (struct alloc_head_list*)curr != head;
}

static struct pminisock *alloc_trickles_pmsk(struct sock *sk) {
	struct tcp_opt *tp = &(sk->tp_pinfo.af_tcp);
	struct list_link *phead = (struct  list_link *)&tp->cminisock_api_config.pmsk_freelist;
	struct pminisock *rval = NULL, *pcurr = (struct pminisock *)
		tp->cminisock_api_config.pmsk_freelist.next;

	if(!SIMULATION_MODE(sk)) {
		while((struct list_link *)pcurr != phead &&
		      pcurr->ctl == ALLOC_PROCESSING) {
			//printk("alloc_head loop\n");
			pcurr = pcurr->next;
		}

		if((struct list_link *)pcurr == phead) {
			printk("no list_link\n");
			return NULL;
		}
		dlist_unlink((struct list_link*)pcurr);
	} else {
		// pmsk is useless during simulation
		static struct pminisock pmsk;
		pcurr = &pmsk;
	}

	rval = pcurr;
	rval->ctl = ALLOC_PENDING;

	init_pminisock(rval);

	return rval;
}

static inline struct cminisock *alloc_trickles_msk(struct sock *sk) {
	struct tcp_opt *tp = &(sk->tp_pinfo.af_tcp);
	struct alloc_head_list *head = &tp->cminisock_api_config.msk_freelist;
	struct cminisock *rval = NULL, *curr = (struct cminisock *)
		tp->cminisock_api_config.msk_freelist.next;

	if(!SIMULATION_MODE(sk)) {
		while((struct alloc_head_list*)curr != head &&
		      curr->ctl == ALLOC_PROCESSING) {
			//printk("alloc_head loop\n");
			curr = curr->next;
		}
		//printk("out of alloc_head loop\n");

		if((struct alloc_head_list *)curr == head) {
			printk("no alloc_head\n");
			return NULL;
		}

		rval = curr;
		unlink((struct alloc_head*)rval);
		rval->ctl = ALLOC_PENDING;
	} else {
		if(tp->t.responseCount == 0) {
			rval = tp->t.responseMSK;
			rval->list = NULL;
			rval->next = rval->prev = NULL;
		} else {
			rval = kmalloc(sizeof (struct cminisock), GFP_ATOMIC);
			if(rval == NULL) {
				printk("out of memory during compatibility mode\n");
				return NULL;
			}
			rval->next = rval->prev = NULL;
			rval->list = NULL;
			insert_tail(&tp->t.responseList, (struct alloc_head*)rval);
		}
		tp->t.responseCount++;

		rval->sk = sk;
		rval->ctl = ALLOC_PENDING;
	}

	init_minisock(rval);

	return rval;
}

#endif // USERTEST

static void free_trickles_msk(struct sock *sk, struct cminisock *msk);
static void free_trickles_msk_finish(struct sock *sk, struct cminisock *msk);

static void free_trickles_pmsk(struct sock *sk, struct pminisock *msk);
static void free_trickles_pmsk_finish(struct sock *sk, struct pminisock *msk);

/* Two phase free: first phase disconnects socket from event list,
   sets to ALLOC_PROCESSING; second phase adds the socket to free
   list, sets to ALLOC_FREE and ready for reuse */
#ifndef USERTEST

#ifdef MODULE

extern int gIsServer;

#define FREE_FUNCTIONS(SUFFIX,TYPE, HEAD, STATIC_CHECK, SIMULATION_RELEASE, POST_RELEASE,	LINK_TYPE, INSERT_HEAD, UNLINK)	\
									\
static inline void SUFFIX##_hold(TYPE *msk) {				\
	msk->refCnt++;							\
}									\
									\
static TYPE *shallow_copy_##SUFFIX(struct sock *sk, TYPE *pmsk) {	\
	TYPE *rval = alloc_trickles_##SUFFIX(sk);			\
	LINK_TYPE head;							\
									\
	if(rval == NULL) {						\
		struct tcp_opt *tp = &(sk->tp_pinfo.af_tcp);		\
		printk("out of memory while shallow copying msk\n");	\
		MSKONLY(printk("list len is %d\n",			\
			       tp->cminisock_api_config.msk_freelist.len)); \
		return NULL;						\
	}								\
	/* save & restore alloc head */					\
	head = *(LINK_TYPE *)rval;					\
	*rval = *pmsk;							\
	*(LINK_TYPE *)rval = head;					\
									\
	rval->refCnt = 1; MSKONLY(rval->isStatic = 0;)			\
									\
	return rval;							\
}									\
									\
									\
static TYPE *copy_##SUFFIX(struct sock *sk, TYPE *pmsk) {			\
	/* Copy everything except for per-packet information. */ \
										/* printk("CopyMSK (%s)\n", #SUFFIX); */  \
	TYPE *rval = shallow_copy_##SUFFIX(sk, pmsk);			\
	if(rval == NULL) {						\
		printk("out of memory while copying msk\n");		\
		return NULL;						\
	}								\
									\
	rval->num_packets = 0;						\
	rval->packets = NULL;  MSKONLY(rval->pmsk = NULL;)		\
									\
	if(rval->ucont_len > 0) {					\
		rval->ucont_data = tmalloc(sk,rval->ucont_len);		\
		/* printk("copymsk: tmalloc ucontdata\n"); */		\
		if(rval->ucont_data == NULL) {				\
			printk("out of tmalloc memory while copying msk (len = %d)\n", rval->ucont_len); \
			free_trickles_##SUFFIX(sk,rval);		\
			free_trickles_##SUFFIX##_finish(sk,rval);	\
			return NULL;					\
		}							\
	} else {							\
		rval->ucont_data = NULL;				\
	}								\
	if(rval->input_len > 0) {					\
		rval->input = tmalloc(sk,rval->input_len);		\
		/* printk("copymsk: tmalloc inputlen\n"); */		\
		if(rval->input == NULL) {				\
			printk("out of tmalloc memory while copying msk (%s len = %d)\n", #SUFFIX, rval->input_len); \
			tfree(sk,rval->ucont_data);			\
			free_trickles_##SUFFIX(sk,rval);		\
			free_trickles_##SUFFIX##_finish(sk,rval);	\
			return NULL;					\
		}							\
	} else {							\
		rval->input = NULL;					\
	}								\
	if(rval->ucont_data)						\
		memcpy(rval->ucont_data,pmsk->ucont_data,rval->ucont_len); \
	if(rval->input)							\
		memcpy(rval->input,pmsk->input,rval->input_len);	\
	return rval;							\
}									\
									\
static void free_trickles_##SUFFIX(struct sock *sk, TYPE *msk) {	\
	if(!SIMULATION_MODE(sk)) {					\
		if(msk->ctl == ALLOC_FREE || msk->ctl == ALLOC_PROCESSING) { \
			printk("double free\n");			\
			BUG();						\
		}							\
		if(msk->ctl == ALLOC_READY && msk->prev != NULL) {	\
			UNLINK(msk);					\
		}							\
		msk->ctl = ALLOC_PROCESSING;				\
	}								\
}									\
									\
static void free_##SUFFIX(struct sock *sk, TYPE *msk) {			\
	int i;								\
	/*								\
	printk("msk summary (%p [%d]) (%p [%d]) (%p [%d])\n",		\
	       msk->packets, msk->num_packets,				\
	       msk->ucont_data, msk->ucont_len,				\
	       msk->input, msk->input_len);				\
	*/								\
	for(i=0; i < msk->num_packets; i++) {				\
		if(msk->packets[i].ucontData != NULL) {			\
			/* if(gIsServer) printk("server ucont kfree\n"); */ kfree(msk->packets[i].ucontData); \
		}							\
	}								\
	/* printk("done with packet data\n"); */			\
	if(!SIMULATION_MODE(sk) && msk->packets) {			\
		tfree(sk,msk->packets);					\
		msk->packets = NULL;					\
	}								\
	/* printk("done with packet array\n"); */			\
	msk->num_packets = 0;						\
									\
	if(msk->ucont_data != NULL) {					\
		tfree(sk,msk->ucont_data);				\
		msk->ucont_data = NULL;					\
	}								\
	/* printk("done with ucont data\n"); */				\
	msk->ucont_len = 0;						\
	if(msk->input != NULL) {					\
		tfree(sk,msk->input);					\
		msk->input = NULL;					\
	}								\
	/* printk("done with input len\n"); */				\
	msk->input_len = 0;						\
}									\
									\
static void SUFFIX##_release(struct sock *sk, TYPE *msk) {		\
	/* Perform actual deallocation. This function is common to */ \
	/* state cache and event queue */ \
	msk->refCnt--;							\
	BUG_TRAP(msk->refCnt <= 3);					\
	if(msk->refCnt == 0) {						\
		/* printk("release: refcnt %p\n", msk); */		\
		struct tcp_opt *tp = &(sk->tp_pinfo.af_tcp);		\
		HEAD;							\
									\
		free_##SUFFIX(sk,msk);					\
		if(!STATIC_CHECK) {					\
			if(!SIMULATION_MODE(sk)) {			\
				INSERT_HEAD(head, msk);			\
				msk->ctl = ALLOC_FREE;			\
			} else {					\
				SIMULATION_RELEASE;			\
			}						\
		}							\
	} else {							\
		/*printk("release: refcnt == %d\n", msk->refCnt);*/	\
	}								\
	POST_RELEASE;							\
}									\
									\
static void free_trickles_##SUFFIX##_finish(struct sock *sk, TYPE *msk) { \
	if(!SIMULATION_MODE(sk)) {					\
		if(msk->ctl != ALLOC_PROCESSING && msk->ctl != ALLOC_HALFFREE) { \
			printk("(free_trickles_msk_finish %s) without corresponding free_trickles_msk: msk->ctl = %d\n", #SUFFIX, msk->ctl); \
			BUG();						\
		}							\
	}								\
	SUFFIX##_release(sk,msk);					\
}									\
static inline void SUFFIX##_clear_fields(TYPE *msk) {			\
	msk->num_packets = 0;						\
	msk->packets = NULL;						\
									\
	msk->ucont_len = 0;						\
	msk->ucont_data = NULL;						\
									\
	msk->input_len = 0;						\
	msk->input = NULL;						\
}



// whew

#define LIST_INSERT_HEAD(H,M) insert_head((H), (struct alloc_head *)(M))
#define LIST_UNLINK(M) unlink((struct alloc_head*)msk)
#define DLIST_INSERT_HEAD(H,M) dlist_insert_head(H, (struct list_link*)(M))
#define DLIST_UNLINK(M) dlist_unlink((struct list_link*)(M))

#define MSKONLY(X) X
FREE_FUNCTIONS(msk,struct cminisock, 
	       struct alloc_head_list *head = &tp->cminisock_api_config.msk_freelist,
	       msk->isStatic, 
	       if(msk != tp->t.responseMSK) {
		       /* overflow */
		       LIST_UNLINK(msk);
		       if(gIsServer) printk("server msk kfree\n"); kfree(msk);
	       }
	       tp->t.responseCount--,
	       if(msk->pmsk != NULL) {
		       struct pminisock *pmsk = msk->pmsk;
		       free_trickles_pmsk(sk, pmsk);
		       free_trickles_pmsk_finish(sk, pmsk);
	       },
	       struct alloc_head_list, LIST_INSERT_HEAD, LIST_UNLINK);
#undef MSKONLY
#define MSKONLY(X)
FREE_FUNCTIONS(pmsk,struct pminisock, 
	       struct dlist *head = &tp->cminisock_api_config.pmsk_freelist,
	       /* XXX static check and simulation check are really poorly conceived for pmsk */
	       (SIMULATION_MODE(sk) ||  !(msk >= (struct pminisock *)tp->cminisock_api_config.cfg.ctl->pminisock_base && 
					  (msk+1) <= (struct pminisock *)tp->cminisock_api_config.cfg.ctl->pminisock_limit)),
		 // do nothing on simulation check
	       ,
	       /* no additional deallocation */ ,
	       struct list_link, DLIST_INSERT_HEAD, DLIST_UNLINK);
#undef MSKONLY

#undef LIST_INSERT_HEAD
#undef LIST_UNLINK
#undef DLIST_INSERT_HEAD
#undef DLIST_UNLINK

#define CACHE_CHILD_COPY (0x1)
#define CACHE_CHILD_CLEAR (0x2)
void pminisock_cache_child(struct sock *sk, struct cminisock *msk, 
		   struct pminisock *pmsk, int packet_number,int flags);
#endif // MODULE
#endif // USERTEST
