#define BREAKOUT() 	printk("returning prematurely at %d\n",__LINE__); return 0;
#define COMPATIBILITY(X) X

#include "trickles-int.h"
#include "memdump-util.h"

#ifndef USERTEST

#define ALWAYS_INLINE __attribute__((always_inline))

#define IS_TRICKLES_SERVER(SK)						\
	(((SK)->tp_pinfo.af_tcp.trickles_opt & TCP_TRICKLES_ENABLE) &&	\
	 ((SK)->state == TCP_LISTEN))

#define FREE_MSK(SK,MSK)					\
		COMPATIBILITY(					\
			      (MSK)->pmsk = NULL;		\
			      msk_clear_fields((MSK));		\
			      free_trickles_msk_finish((SK),(MSK));	\
		);

static inline int analyze_msk_list_helper(struct sock *sk, int print);

static struct cminisock *allocate_api_msk(struct sock *sk) {
	struct tcp_opt *tp = &(sk->tp_pinfo.af_tcp);
	struct cminisock *rval = &tp->t.api_msk;
	msk_initStatic(rval);
	return rval;
}

inline
void dump_socket_stats(struct sock *sk) {
	struct tcp_opt *tp = &(sk->tp_pinfo.af_tcp);
	printk("   tp->rcv_nxt = %d\n", tp->rcv_nxt);
	printk("   tp->t.byteRcvNxt = %d\n", tp->t.byteRcvNxt);
	printk("   Recv queue len = %d\n", sk->receive_queue.qlen);
	printk("   Trickles state = %d\n", tp->t.state);
	DUMP_RTO(sk);
	printk("   Ofo_queue len = %d\n", tp->t.ofo_queue.qlen);
	printk("   data_ofo_queue len = %d\n", tp->t.data_ofo_queue.qlen);
	printk("   request_ofo_queue len = %d\n", tp->t.request_ofo_queue.len);
}

static inline
void dump_datachunks(char *ptr, int len) {
	int chunknum = 0;
	struct DataChunk *chunk = (struct DataChunk *)ptr;
	printk("Total dump len = %d ", len);
	while((char*)(chunk+1) - ptr < len && chunknum < 5) {
		printk("Chunk %d(%d) - %d @ %d\n", chunknum,
#ifdef CHUNK_ID
		       chunk->chunkID,
#else
		       -1,
#endif
		       DATA_LEN(chunk),
		       (char*)chunk->data - ptr);
		chunk = NEXT_CHUNK_ADDR(chunk);
		chunknum++;
	}
}

/* begin functions copied from tcp.c */

static inline void
fill_page_desc(struct sk_buff *skb, int i, struct page *page, int off, int size)
{
	skb_frag_t *frag = &skb_shinfo(skb)->frags[i];
	frag->page = page;
	frag->page_offset = off;
	frag->size = size;
	skb_shinfo(skb)->nr_frags = i+1;
}

extern int total_csum_bytes;

static ALWAYS_INLINE int
skb_add_data(struct sk_buff *skb, char *from, int copy)
{
	int err = 0;
	unsigned int csum;
	int off = skb->len;
	char *dest = skb_put(skb, copy);

	total_csum_bytes += copy;
	csum = csum_and_copy_from_user(from, dest, copy, 0, &err);
	if (!err) {
		skb->csum = csum_block_add(skb->csum, csum, off);
#ifdef GREP_FOR_RANGEHEADER
		//printk("Grepping for range header (e.g., non-zero bytes)\n");
		int i;
#if 0
		for(i=0; i < copy; i++) {
			if(dest[i] != 0) {
				printk("Non zero byte at %d\n",
				       dest - (char*)skb->head);
				break;
			}
		}
#endif
		int count;
		if((count = validateDataChunks(dest, copy)) < 0) {
			printk("Data chunk validation failed at %d, count = %d\n",
			       dest - (char*)skb->head, count);
			return -EFAULT;
		}
#endif
		return 0;
	}

	__skb_trim(skb, off);
	return -EFAULT;
}

/* end functions copied from tcp.c */

static inline void init_sock(struct cminisock *msk, struct sock *sk) {
	msk->sk = sk;
	msk->sk->dst_cache = NULL;
	msk->sk->protinfo.af_inet.opt = NULL;
	msk->sk->protinfo.af_inet.ttl = 255;
	msk->sk->protocol = IPPROTO_TCP;
	msk->sk->protinfo.af_inet.tos = 0;
	msk->sk->tp_pinfo.af_tcp.trickles_opt = 0;
	msk->sk->localroute = 0;
        if (ipv4_config.no_pmtu_disc)
                msk->sk->protinfo.af_inet.pmtudisc = IP_PMTUDISC_DONT;
        else
                msk->sk->protinfo.af_inet.pmtudisc = IP_PMTUDISC_WANT;
	/* following hack won't work correctly for complex socket binding config on the master socket */
	msk->sk->bound_dev_if = 0;

	msk->sk->saddr = msk->saddr;
	msk->sk->sport = msk->source;
	msk->sk->daddr = msk->daddr;
	msk->sk->dport = msk->dest;
}


static int upcall_seqnum = 0;

static volatile void *virt_to_kseg(volatile void *address)
{
        pgd_t *pgd; pmd_t *pmd; pte_t *ptep, pte;
	unsigned long va, ret = 0UL;

	va=VMALLOC_VMADDR((unsigned long)address);

	/* get the page directory. Use the kernel memory map. */
	pgd = pgd_offset_k(va);

	/* check whether we found an entry */
	if (!pgd_none(*pgd))
        {
	      /* get the page middle directory */
	      pmd = pmd_offset(pgd, va);
	      /* check whether we found an entry */
	      if (!pmd_none(*pmd))
              {
		  /* get a pointer to the page table entry */
	          ptep = pte_offset(pmd, va);
	          pte = *ptep;
		  /* check for a valid page */
	          if (pte_present(pte))
                  {
		        /* get the address the page is refering to */
		        ret = (unsigned long)page_address(pte_page(pte));
			/* add the offset within the page to the page address */
			ret |= (va & (PAGE_SIZE -1));
		  }
	      }
	}
	return((volatile void *)ret);
}

#define QUEUE_UPCALL(SUFFIX, TYPE, INSERT_H)				\
inline void queue_upcall_##SUFFIX##_prealloc(struct sock *sk,	\
			     enum cminisock_event_tag tag, TYPE *msk) {	\
	struct tcp_opt *tp = &(sk->tp_pinfo.af_tcp);			\
	switch(tag) {							\
	case SYN:							\
	case RST:							\
	case FIN:							\
	case ACK:							\
		/* enqueue at the end */				\
		INSERT_H;						\
		break;							\
	default:							\
		printk("Unsupported tag for preallocation\n");		\
	}								\
}									\
									\
inline void queue_upcall_##SUFFIX(enum cminisock_event_tag tag, TYPE *msk) { \
										/* printk("Queuing %p : input_len %d\n", msk, msk->input_len); */  \
	msk->tag = tag;							\
	switch(tag) {							\
	case SYN:							\
	case RST:							\
	case FIN:							\
	case ACK:							\
		msk->ctl = ALLOC_READY;					\
		if(userapi_pkt_spew) {					\
			int i;						\
			for(i=0; i < msk->num_packets; i++) {		\
				printk("upcall pkts[%d]: %u-%u\n", i, msk->packets[i].seq, msk->packets[i].seq + msk->packets[i].len); \
			}						\
		}							\
									\
		break;							\
	default:							\
		printk("queue_upcall_msk (%s): invalid tag\n", #SUFFIX); \
	}								\
}

QUEUE_UPCALL(msk, struct cminisock, 
	     insert_tail_mb(&tp->cminisock_api_config.cfg.ctl->msk_eventlist, (struct alloc_head *)msk););
QUEUE_UPCALL(pmsk, struct pminisock, 
	     dlist_insert_tail_mb(&tp->cminisock_api_config.cfg.ctl->pmsk_eventlist, (struct list_link *)msk););

static inline
void new_event(struct sock *sk) {
	wake_up_interruptible(sk->sleep);
	if (!sk->dead) {
		/* clear select and other blocking operations */
		sk->data_ready(sk, 0);
	}
	atomic_inc(&sk->tp_pinfo.af_tcp.cminisock_api_config.cfg.ctl->update_since_poll);
 }

inline void queue_upcall_deliver(struct sock *sk) {
	//DO_SANITY_CHECK_MSK(msk);
	// printk("new event notification\n");
	new_event(sk);
}

///////////////////////////////////////

static void tcp_prequeue_process(struct sock *sk)
{
	struct sk_buff *skb;
	struct tcp_opt *tp = &(sk->tp_pinfo.af_tcp);

	net_statistics[smp_processor_id()*2+1].TCPPrequeued += skb_queue_len(&tp->ucopy.prequeue);

	/* RX process wants to run with disabled BHs, though it is not necessary */
	local_bh_disable();
	while ((skb = __skb_dequeue(&tp->ucopy.prequeue)) != NULL)
		sk->backlog_rcv(sk, skb);
	local_bh_enable();

	/* Clear memory counter. */
	tp->ucopy.memory = 0;
}

static int trickles_poll(struct sock *sk);

/* precondition: msk already 1/2 freed, and address verified */
#define SENDMSG_INSTANCE(SUFF, HANDLER)					\
static inline int trickles_do_sendmsg_ ## SUFF				\
		(struct sock *sk, struct cminisock *msk, void *vec, int veclen) { \
	if(!msk->isStatic) {					\
		printk("msk must be static\n");			\
		BUG();						\
	}							\
	/* printk("downcall %d\n", msk->seq); */		\
								\
	int rval = 0;						\
	struct sock dummysk;						\
	struct tcp_opt *tp = &(sk->tp_pinfo.af_tcp),			\
	  *dummy_tp = &(dummysk.tp_pinfo.af_tcp);			\
	struct sk_buff *skb;						\
									\
	/* dummysk = kmalloc(sizeof(struct sock), GFP_KERNEL); */	\
	dummy_tp->trickles_opt = tp->trickles_opt;			\
	dummy_tp->t.hmacCTX = tp->t.hmacCTX;				\
	dummy_tp->t.nonceCTX = tp->t.nonceCTX;				\
									\
	init_sock(msk, &dummysk);					\
	msk->serverSK = sk;						\
									\
	{								\
		static int last;					\
		if(msk->seqnum != last+1) {				\
			/* printk("missing downcall: out of sequence\n"); */ \
		}							\
		last = msk->seqnum;					\
	}								\
									\
	if(msk->tag == SYN || msk->tag == ACK || msk->tag == FIN) { \
		HANDLER(sk,msk,vec,veclen);				\
	} else {							\
		struct tcp_skb_cb *tcb;					\
		skb = recycle(sk);					\
		if(skb == NULL) {					\
			skb = alloc_skb(TRICKLES_TX_SKB_LEN, GFP_KERNEL); \
		}							\
		if(skb == NULL) {					\
			printk("could not allocate skb\n");		\
			goto out;					\
		}							\
		tcb = TCP_SKB_CB(skb);					\
		skb->csum = 0;						\
		skb->ip_summed = CHECKSUM_HW;				\
		skb_reserve(skb, MAX_TCP_HEADER + MAX_TRICKLES_SERVER_HDR_LEN + TRICKLES_MSS); \
									\
		switch(msk->tag) {					\
		case SYN:						\
			BUG(); break;					\
		case RST:						\
			/* todo: find out what the proper semantics in response to rst are */ \
			kfree_skb(skb);					\
			goto out;					\
		default:						\
			kfree_skb(skb);					\
			BUG_TRAP(0);					\
			goto out;					\
		}							\
		int i;							\
		for(i=0; i < msk->num_packets; i++) {			\
			struct sk_buff *skb1 = skb_clone(skb, GFP_ATOMIC); \
			skb1->csum = 0;					\
			skb1->ip_summed = CHECKSUM_HW;			\
			msk_transmit_skb(msk, skb1, i);			\
			msk->tag = ACK;					\
			/* printk("SYN %d\n", i); */			\
		}							\
		kfree_skb(skb);						\
	}								\
 out:;									\
	struct pminisock *pmsk = msk->pmsk;				\
	if(sysctl_trickles_Continuation_enable && HAS_VALID_CACHERECYCLEINDEX(msk)) { \
		/* must cache before deallocating, since we still need the packet field */ \
		pmsk_hold(pmsk);						\
		pminisock_cache_child(sk, msk, pmsk, pmsk->cacheRecycleIndex, 0); \
		free_trickles_pmsk_finish(sk,pmsk);			\
		msk_free_fields(sk, msk);				\
	} else {							\
		free_trickles_pmsk_finish(sk,pmsk);			\
	}								\
	return rval;							\
}

static inline int tiov_handler(struct sock *origSK, struct cminisock *msk, struct tiovec *tiov, int tiovlen);
SENDMSG_INSTANCE(tiov,tiov_handler);
static inline int fiov_handler(struct sock *origSK, struct cminisock *msk, struct fiovec *fiov, int fiovlen);
SENDMSG_INSTANCE(fiov,fiov_handler);

#ifdef SETUCONT_COMMAND
static inline
int containsUContDesc(struct cminisock_packet *cpkt) {
	return cpkt->ucontLen < 0;
}

static inline
void extractUContDesc(struct cminisock_packet *cpkt, int *ucontLen, char **user_src) {
	*ucontLen = cpkt->ucontLen = -cpkt->ucontLen;
	*user_src = cpkt->ucontData;
	cpkt->ucontData = NULL;
}

static inline
void insertUContDesc(struct cminisock_packet *cpkt, int ucontLen, char *user_src) {
	BUG_TRAP(cpkt->ucontLen == 0);
	cpkt->ucontLen = -ucontLen;
	cpkt->ucontData = user_src;
}

static inline
int setupUCont(struct cminisock *msk, struct ucontdesc *udesc, int udesclen,
		int udescstride) {
	int i;
	struct cminisock_packet *pkts = msk->packets;
	int packetNum = 0;

	for(i=0; i < udesclen; i++) {
		struct ucontdesc *curr_tiov =
			(struct ucontdesc *) ((char*)udesc + udescstride * i);
		int ucontLen = curr_tiov->ucont_len;
		if(ucontLen > 0) {
			if(packetNum >= msk->num_packets) {
				printk("Too many uconts specified in list\n");
				return 0;
			}
			if(pkts[packetNum].ucontLen > 0) {
				printk("UContLen > 0!!!, ptr = %p\n", pkts[packetNum].ucontData);
				return -1;
			}
			insertUContDesc(&pkts[packetNum], ucontLen, curr_tiov->ucont_base);
			packetNum++;
		}
	}
	return 0;
}

static inline
int copyUCont(struct sk_buff *skb, struct cminisock_packet *cpkt) {
	if(containsUContDesc(cpkt) < 0) {
		int error = 0;
		int ucontLen;
		char *user_src;
		extractUContDesc(cpkt, &ucontLen, &user_src);
		skb->csum =
			csum_and_copy_from_user(user_src, skb_push(skb, ucontLen),
						ucontLen, skb->csum, &error);
		if(error) {
			printk("csum error on ucont\n");
			return error;
		}
	}
	return 0;
}
#else

#define containsUContDesc(X) (0)

#define extractUContDesc(X,Y,Z) do { BUG_TRAP(0); } while(0)

#define insertUContDesc(X,Y,Z) do { BUG_TRAP(0); } while(0)

#define setupUCont(A,B,C,D) (0)

#define copyUCont(X,Y) (0)

#endif // SETUCONT_COMMAND

static inline
void free_remaining(struct sk_buff **skbs, int offset, int total) {
	for(; offset < total; offset++) {
		kfree_skb(skbs[offset]);
	}
}

#ifdef SETUCONT_COMMAND
#define FINISH_TRANSMIT(MSK,SKBS,NUM_DATA_PACKETS,UDESC,UDESCLEN,UDESCSTRIDE) \
	finishTransmitHelper(MSK,SKBS,NUM_DATA_PACKETS,UDESC,UDESCLEN,UDESCSTRIDE)
#else
#define FINISH_TRANSMIT(MSK,SKBS,NUM_DATA_PACKETS,UDESC,UDESCLEN,UDESCSTRIDE) \
	finishTransmitHelper(MSK,SKBS,NUM_DATA_PACKETS,NULL,0,0)
#endif

static
void finishTransmitHelper(struct cminisock *msk, struct sk_buff *skbs[],
		    int numDataPackets, struct ucontdesc *udesc,
		    int udesclen, int udescstride) {
#define REALCHILD(PKT) ((PKT).ucontLen != 0)
	struct cminisock_packet *pkts = msk->packets;
	int numUCChildPackets = numDataPackets;
	int i, j, UCposition;
	struct sk_buff *skb;

	if(setupUCont(msk, udesc, udesclen, udescstride)) {
		free_remaining(skbs, 0, numDataPackets);
		// failure
		return;
	}
	for(i=numUCChildPackets; i < msk->num_packets; i++) {
		// find more child packets (e.g., ucont_len > 0)
		if(REALCHILD(pkts[i])) {
			numUCChildPackets++;
		}
	}
	for(i=0; i < msk->num_packets; i++) {
		pkts[i].numSiblings = numUCChildPackets;
	}
	UCposition = 0;
	for(j=0; j < numDataPackets; j++) {
		pkts[j].position = UCposition++;
		if(copyUCont(skbs[j], &pkts[j]) != 0) {
			free_remaining(skbs, j, numDataPackets);
			return;
		}
#if 0
		// Analyze headers of data packets
		dump_datachunks(skbs[j]->data, skbs[j]->len);
#endif
		msk_transmit_skb(msk, skbs[j], j);
	}
	for(i = numDataPackets; i < msk->num_packets; i++) {
		if(REALCHILD(pkts[i])) {
			pkts[i].position = UCposition++;
		} else {
			pkts[i].position = INVALID_POSITION;
		}
		/* Send out all remaining packets to placate transport level */
		// XXX Should piggyback all of these packets into a single packet

		int ucontLen;
#ifdef SETUCONT_COMMAND
		ucontLen = abs(pkts[i].ucontLen);
#else
		ucontLen = pkts[i].ucontLen;
#endif // SETUCONT_COMMAND
		skb = alloc_skb(MAX_TCP_HEADER + MAX_TRICKLES_SERVER_HDR_LEN + ucontLen, GFP_KERNEL);
		if(skb == NULL) {
			printk("out of memory during finishTransmit\n");
			return;
		}
		skb_reserve(skb, MAX_TCP_HEADER + MAX_TRICKLES_SERVER_HDR_LEN + ucontLen);
		skb->csum = 0;
		if(copyUCont(skb, &pkts[i])) {
			return;
		}
		msk_transmit_skb(msk, skb, i);
	}
#undef  REALCHILD
}

static inline int tiov_handler(struct sock *origSK, struct cminisock *msk, struct tiovec *tiov, int tiovlen) {
	//BREAKOUT();
	int i, numDataPackets = 0, totallen = 0, tiov_pos = 0, tiov_offs = 0;
	struct cminisock_packet *pkts;
	int rval = 0;
#define MAX_SKBS (4)
	struct sk_buff *skb_body[MAX_SKBS];
	struct sk_buff **skbs, *skb;
	if(msk->num_packets > MAX_SKBS) {
		skbs = kmalloc(sizeof(struct sk_buff *) * msk->num_packets, GFP_USER);
	} else {
		BUG_TRAP(msk->num_packets >= 0);
		skbs = skb_body;
	}
	int maxLen = 0;

	if(skbs == NULL)
		goto out;

	pkts = msk->packets;

	for(i=0; i < tiovlen; i++) {
		totallen += tiov[i].iov_len;
	}
	for(i=0; i < msk->num_packets; i++) {
		maxLen += msk->packets[i].len;
	}
	if(totallen < maxLen) {
		static int shortCount = 0;
		static int maxCount = 0;
		shortCount++;
		if(msk->dbg_mark == MAX_NUM_DATACHUNKS) {
			maxCount++;
		}
		if(trickles_ratelimit()) {
			printk("%lud:mark(%d) Short by %d (%d - %d) count=(%d,%d)\n", jiffies, msk->dbg_mark, maxLen - totallen,
			       maxLen, totallen, shortCount, maxCount);
			printk("%p short by input_len = %d\n", msk, msk->input_len);
		}
		static int zerocount = 0;
		if(totallen == 0) {
			zerocount++;
			if(trickles_ratelimit()) {
				printk("%lud: zero request count: %d\n", jiffies, zerocount);
			}
		}
	}
	//BREAKOUT();
	for(i=0; i < msk->num_packets; i++) {
		int pkt_remain;
		int short_pkt = 0;

		if(pkts[i].len > totallen) {
			short_pkt = 1;
		}
		pkt_remain = pkts[i].len = MIN(pkts[i].len, totallen);
		skb = skbs[i] = recycle(origSK);
		if(skb == NULL) {
			skb = skbs[i] = alloc_skb(MAX_TCP_HEADER + MAX_TRICKLES_SERVER_HDR_LEN + pkts[i].ucontLen + pkts[i].len, GFP_KERNEL);
		}
		numDataPackets = i+1;
		if(skb == NULL) {
			printk("could not allocate skb\n");
			goto out;
		}
		skb_reserve(skb, MAX_TCP_HEADER + MAX_TRICKLES_SERVER_HDR_LEN + pkts[i].ucontLen);

		skb->csum = 0;
		skb->ip_summed = CHECKSUM_HW;
		while(tiov_pos < tiovlen) {
			int amt = MIN(pkt_remain, tiov[tiov_pos].iov_len - tiov_offs);
			int err = 0;
			char *src = tiov[tiov_pos].iov_base + tiov_offs;
			//printk("tiov copy loop, copying %d\n", amt);

			err = skb_add_data(skb,src,amt);
			//printk("tiov[%d].tiov_base (%p) + tiov_offs (%u) = %p, data = %p, amt = %d, skb->csum = %x, tail = %p, tailroom = %u, tiov_len = %u, &err=%p\n", tiov_pos, tiov[tiov_pos].tiov_base, tiov_offs, tiov[tiov_pos].tiov_base + tiov_offs, data, amt, skb->csum, skb->tail, skb_tailroom(skb), tiov[tiov_pos].iov_len, &err);
			if(err) {
				printk("error while csum/copy, base = %p amt = %d, msk state = %d, (seq,base,delta) = (%d,%d,%d)\n", 
				       src, amt, msk->state, msk->seq, msk->TCPBase, msk->seq - msk->TCPBase);

				kfree_skb(skb);
				goto out;
			}

			totallen -= amt;
			pkt_remain -= amt;
			tiov_offs += amt;
			if(tiov_offs == tiov[tiov_pos].iov_len) {
				tiov_offs = 0;
				tiov_pos++;
			}
			if(pkt_remain == 0) break;
		}
		BUG_TRAP(pkt_remain == 0);

		if(userapi_pkt_spew) {
			printk("sending pkts[%d] %u-%u\n", i, pkts[i].seq, pkts[i].seq + pkts[i].len);
		}

		// on last packet, set the tag to FIN
		if(totallen == 0 &&
		   tiov[tiovlen-1].iov_base == (void*)-1 && tiov[tiovlen-1].iov_len == 0) {
			printk("Fin, iovlen = %d\n", tiovlen);
			msk->tag = FIN;
		}

		rval += pkts[i].len; // check how much data actually sent?
		if(totallen == 0) {
			break;
		}
	}

	FINISH_TRANSMIT(msk, skbs, numDataPackets,
		       (struct ucontdesc *)&tiov[0].ucont_base, tiovlen,
		       sizeof(*tiov));
	//BREAKOUT();
	if(totallen > 0) {
		if(trickles_ratelimit()) {
			int i;
			printk("too much data for downcall: %d left, trace = %d\n",
			       totallen, msk->executionTrace);
			for(i=0; i < tiovlen; i++) {
				printk("tiov[%d] = {base = %p, len = %d}\n", i,
				       tiov[i].iov_base, tiov[i].iov_len);
			}
		}
#if 0
		printk("pre showing stack\n");
		show_stack(NULL);
		printk("done showing stack\n");
#endif
	}
 out:
	if(skbs != skb_body) {
		//printk("pre disabled kfree %d\n", msk->num_packets);
		kfree(skbs);
	}
	return rval;
}

void trickles_close(struct sock *sk, long timeout) {
	/* Based on TCP_CLOSE.
	   Zap connections as fast as possible
	*/
	struct sk_buff *skb;
	int data_was_unread = 0;
#if 1 // 0502 - moving receive queue drain inside bh-safe portion
	// orig
	lock_sock(sk);
	sk->shutdown = SHUTDOWN_MASK;

	/* drain receive queue */
	while((skb=__skb_dequeue(&sk->receive_queue))!=NULL) {
		u32 len = TCP_SKB_CB(skb)->end_seq - TCP_SKB_CB(skb)->seq - skb->h.th->fin;
		data_was_unread += len;
		__kfree_skb(skb);
	}
	// printk("%u bytes unread\n", data_was_unread); // 0418

	tcp_mem_reclaim(sk);
	tcp_set_state(sk, TCP_CLOSE);

	release_sock(sk);

	local_bh_disable();
	bh_lock_sock(sk);

	sock_hold(sk);
	sock_orphan(sk);
	tcp_destroy_sock(sk);

	bh_unlock_sock(sk);
	local_bh_enable();
	sock_put(sk);
#else
	local_bh_disable();
	bh_lock_sock(sk);

	sock_hold(sk);
	sock_orphan(sk);

	sk->shutdown = SHUTDOWN_MASK;

	/* drain receive queue */
	while((skb=__skb_dequeue(&sk->receive_queue))!=NULL) {
		u32 len = TCP_SKB_CB(skb)->end_seq - TCP_SKB_CB(skb)->seq - skb->h.th->fin;
		data_was_unread += len;
		__kfree_skb(skb);
	}
	// printk("%u bytes unread\n", data_was_unread); // 0418

	tcp_mem_reclaim(sk);
	tcp_set_state(sk, TCP_CLOSE);

	tcp_destroy_sock(sk);

	bh_unlock_sock(sk);
	local_bh_enable();
	sock_put(sk);
#endif
}

void trickles_init_sock_impl(struct sock *sk, int val) {
	struct tcp_opt *tp = &(sk->tp_pinfo.af_tcp);
	local_bh_disable();
	release_sock(sk);
	bh_lock_sock(sk);
	if(!(tp->trickles_opt & TCP_TRICKLES_ENABLE) &&
	   val & TCP_TRICKLES_ENABLE) {
		if(val & TCP_TRICKLES_RSERVER) {
			tp->t.testseq = 1;
			sk->prot = &trickles_prot;

		} else {
			sk->prot = &trickles_client_prot;
#if 0
			if(val & TCP_TRICKLES_BUFFERDISCARD) {
				sk->rcvbuf = 100000000;
			}
#endif
			/* remember clients so that we can clear timers */
			trickles_add_clientsock(sk);

#ifdef RECORD_LOSS_EVENTS
#define EVENT_RECORD_LEN (8192)
			tp->t.events = kmalloc(EVENT_RECORD_LEN, GFP_ATOMIC);
			tp->t.eventsPos = 0;
			tp->t.eventsSize = EVENT_RECORD_LEN /
				sizeof(struct TricklesLossEvent);
			int i;
			for(i=0; i < tp->t.eventsSize; i++) {
				tp->t.events[i].valid = 0;
			}
#undef EVENT_RECORD_LEN
#endif // RECORD_LOSS_EVENTS

			tp->t.slowstart_timer.function = &slow_start_timer;
			tp->t.slowstart_timer.data = (long)sk;
		}
	}
	tp->trickles_opt = val;
	bh_unlock_sock(sk);
	lock_sock(sk);
	local_bh_enable();
}

#define IS_VALID_MSK(SK, MSK)						\
	({								\
		struct tcp_opt *_tp = 	&((SK)->tp_pinfo.af_tcp);	\
		IS_TRICKLES_SOCK_ADDR(_tp,(MSK)) && VALID_MSK_CTL((MSK)); \
	})

int trickles_sendmsg(struct sock *sk, struct msghdr *msg, int size) {
	printk("sendmsg\n");
	struct tcp_opt *tp = &(sk->tp_pinfo.af_tcp);
	struct cminisock *msk;
	struct pminisock *pmsk;
	int tiovlen = msg->msg_iovlen;
	int rval = -EINVAL;

	struct tiovec *tiov = (struct tiovec *)msg->msg_iov;
	struct cminisock_cmd *cmd = msg->msg_name;

	if(sizeof(*cmd) != msg->msg_namelen || (int)cmd->magic != TRICKLES_MAGIC) {
		return -EINVAL;
	}

	if(cmd->cmd == STARTRCV) {
		printk(" StartRcv functionality deprecated\n");
		return -EINVAL;
	}
	if(!TRICKLES_USERAPI_CONFIGURED_TP(tp)) {
		return -EINVAL;
	}
	if(cmd->cmd == POLL) {
		int res;
		lock_sock(sk);
		if (skb_queue_len(&tp->ucopy.prequeue)) {
			tcp_prequeue_process(sk);
		}
		res = trickles_poll(sk);
		release_sock(sk);
		return res;
	}

	/* XXX: perhaps allow multiple sockets to be passed down at a time */
	msk = cmd->socket;

	/* TODO: try to get rid of this silly lock ? */
	lock_sock(sk);
	if(!TRICKLES_USERAPI_CONFIGURED_TP(tp)) {
		printk("Socket not configured\n");
		rval = -EINVAL;
		release_sock(sk);
		goto out;
	}

	COMPATIBILITY(
	if(!IS_VALID_MSK(sk,msk)) {
		printk("%d: bad minisocket %d %d\n", __LINE__, !IS_TRICKLES_SOCK_ADDR(tp,msk), !(VALID_MSK_CTL(msk)));
		rval = -EINVAL;
		release_sock(sk);
		goto out;
	}
	)
	pmsk = msk->pmsk;

	free_trickles_pmsk(sk,pmsk);
	COMPATIBILITY(free_trickles_msk(sk,msk));
	FREE_MSK(sk,msk); // unlink msk, since this is the last reference

	if(cmd->cmd == DROP) {
		rval = 0;
		free_trickles_pmsk_finish(sk, pmsk);
		FREE_MSK(sk,msk);

		goto out_put;
	}

	if(cmd->cmd != PROCESS) {
		if(trickles_ratelimit()) 
			printk("warning: command was not process\n");

		free_trickles_pmsk_finish(sk, pmsk);
		FREE_MSK(sk, msk);
		goto out_put;
	}

	struct cminisock *api_msk = allocate_api_msk(sk);
	unmarshallContinuationServerPMSK2MSK(sk, api_msk, pmsk);

	rval = trickles_do_sendmsg_tiov(sk,api_msk,tiov,tiovlen);

 out_put:
	release_sock(sk);
 out:
	return rval;
}

static int trickles_poll(struct sock *sk) {
	int err = 0;
	/* Algorithm: perform sleep, then return when done */
	//struct tcp_opt *tp = &(sk->tp_pinfo.af_tcp);

	/* don't cache a pointer, since the configuration could change
	   under us */

#define NO_EVENT()  (trickles_sock_poll_impl(NULL, &sock, NULL) == 0)

	struct socket sock;
	sock.sk = sk;
	if(NO_EVENT()) {
#define MAX_TIMEOUT (100*HZ)
		int timeout = MAX_TIMEOUT;
		int in_time = jiffies;
		release_sock(sk);
		interruptible_sleep_on_timeout(sk->sleep, timeout);
		lock_sock(sk);
		if(!NO_EVENT()) {
			if(userapi_time_spew)
				printk("wakeup time (user): %lu\n", jiffies);
		} else {
			printk("timeout expired %d\n", jiffies - in_time);
			err = -EAGAIN;
		}
	}

	goto out; // suppress warning
 out:
	return err;
#undef NO_EVENT
}

int trickles_sock_poll_impl(struct file * file, struct socket *sock, poll_table *wait) {
    struct sock *sk = sock->sk;
    struct tcp_opt *tp = &(sk->tp_pinfo.af_tcp);
    extern int gUpdateSincePollTotal;
    extern int gUpdateSincePollCount;
    int mask = 0;
    if(TRICKLES_USERAPI_CONFIGURED_TP(tp)) {
	    int poll_value = atomic_read(&tp->cminisock_api_config.cfg.ctl->update_since_poll);
	    if((!(tp->trickles_opt & TCP_TRICKLES_EDGE)  && !dlist_empty(&tp->cminisock_api_config.cfg.ctl->pmsk_eventlist)) ||
	       ((tp->trickles_opt & TCP_TRICKLES_EDGE) &&
		poll_value > 0 &&
		!dlist_empty(&tp->cminisock_api_config.cfg.ctl->pmsk_eventlist))) {
		    mask = POLLIN;
		    gUpdateSincePollTotal += poll_value;
		    gUpdateSincePollCount++;
		    atomic_sub(poll_value, &tp->cminisock_api_config.cfg.ctl->update_since_poll);
	    }
    }
    return mask;
}

/*
 *
 * MMAP support
 *
 */

void vfree_helper(void *ptr) {
	printk("Delayed deallocation\n");
	vfree(ptr);
}

static struct page * trickles_vma_nopage(struct vm_area_struct * area, unsigned long address, int unused) {
	unsigned long offset;
	struct page *page;
	struct trickles_kconfig *api_config = (struct trickles_kconfig*)area->vm_private_data;
	if(api_config == NULL) return NULL;

	void *base = api_config->cfg.ctl->ro_base;
	offset = address - (unsigned long)area->vm_start;
	if(offset >= api_config->cfg.ctl->ro_len) {
		printk("error, vm_nopage offset >= ro_len\n");
		return NULL;
	}
	page = virt_to_page(virt_to_kseg((char *)base + offset));
	if(page)
		get_page(page);
	return page;
}

struct vm_operations_struct trickles_vm_ops = {
	nopage: trickles_vma_nopage,
	open:  NULL,
	close: NULL
};

int cminisock_config_pipe_impl(struct sock *sk, char *optdata, int optlen, int direction) {
	printk("configuring pipe\n");
	struct tcp_opt *tp = &(sk->tp_pinfo.af_tcp);
	struct trickles_config new_config;
	struct trickles_mmap_ctl *ctl;
	struct alloc_head_list *head;
	unsigned int mmap_len;
	int error;
	struct cminisock *msk;

	if(direction == CMINISOCK_IN) {
		unsigned minisock_len;
		/* big socket lock already acquired; however, we might need to sleep & hold off if a transaction is pending */
		/* 1) Sleep until transaction complete
		   2) Perform a vmalloc
		   3) Split the new area into read-only and read-write sections */
		while(tp->cminisock_api_config.pending_delivery) {
			int timeout = HZ/4;
			printk("config loop\n");
			__set_task_state(current, TASK_INTERRUPTIBLE);

			release_sock(sk);
			timeout = schedule_timeout(timeout);
			lock_sock(sk);

		}
		__set_task_state(current, TASK_RUNNING);

		if(optlen != sizeof(new_config)) {
			printk("optlen != sizeof(new_config)\n");
			error = -EINVAL;
			goto out;
		}
		error = copy_from_user(&new_config,optdata,sizeof(new_config));
		if(error) {
		  printk("copy from user error\n");
			error = -EFAULT;
			goto out;
		}

		if((mmap_len = new_config.mmap_len) > MAX_TRICKLES_SHMEM_SIZE) {
			printk("requested mmap area too large\n");
			error = -EINVAL;
			goto out;
		}
		new_config.mmap_base = vmalloc(mmap_len);
		printk("mmap_base: %p\n", new_config.mmap_base);
		if(new_config.mmap_base == NULL) {
			printk("could not mmap enough memory\n");
			error = -ENOMEM;
			goto out;
		}

		/* Split the area */
		ctl = new_config.mmap_base;
		new_config.ctl = ctl;
		BUG_TRAP(sizeof(*ctl) + sizeof(struct work_struct) < PAGE_SIZE);
		ctl->ro_base = new_config.mmap_base;
		ctl->ro_len = PAGE_ALIGN(mmap_len / 4);
		ctl->ro_offs = (char*)ctl->ro_base - (char*)new_config.mmap_base;
		ctl->rw_base = (__u8*)ctl->ro_base + ctl->ro_len;
		ctl->rw_len = PAGE_ALIGN(mmap_len - ((char*)ctl->rw_base - (char*)new_config.mmap_base)) - PAGE_SIZE;
		ctl->rw_offs = (char*)ctl->rw_base - (char*)new_config.mmap_base;
		atomic_set(&ctl->update_since_poll, 0);
		INIT_WORK((struct work_struct *)(ctl+1), vfree_helper, new_config.mmap_base);
		BUG_TRAP(ctl->rw_len > 0);
		BUG_TRAP(ctl->ro_len > 0);
		BUG_TRAP((char*)ctl->ro_base < (char*)new_config.mmap_base + mmap_len);

		init_head(&ctl->msk_eventlist);

		tp->cminisock_api_config.cfg = new_config;
		new_config.ctl = NULL;
		printk("newConfig page ctl is %p\n", tp->cminisock_api_config.cfg.ctl);

		/* Initialize minisockets */
		head = &tp->cminisock_api_config.msk_freelist;
		init_head(head);

		msk = (struct cminisock *)((char*)ctl->ro_base + PAGE_SIZE);
		ctl->minisock_base = msk;
		ctl->minisock_offs = (char*)ctl->minisock_base - (char*)new_config.mmap_base;

		minisock_len = MINISOCK_LEN(ctl->ro_len);
		ctl->minisock_limit = (char*)ctl->minisock_base + minisock_len;
		BUG_TRAP(minisock_len > 0);

		int count = 0;
		int maxMSKCount = new_config.maxMSKCount;
		StateCache_resize(maxMSKCount / 2);

		printk("inserting msk: ");
		while((char*)(msk + 1) <= (char*)ctl->minisock_limit && 
		      count < maxMSKCount) {
			memset(msk, 0x3a, sizeof(*msk));
			msk->ctl = ALLOC_FREE;
			msk->prev = msk->next = NULL;
			msk->list = NULL;
			init_minisock(msk);
			insert_tail(head, (struct alloc_head*)msk);
			msk++;
			count++;
			//printk("%p  ", msk);
		}
		printk("\n");

		/* Initialize pminisock */
		int pminisock_len = PMINISOCK_LEN(ctl->ro_len);
		ctl->pminisock_base = ALIGN(ctl->minisock_limit, 1);
		struct pminisock *pmsk = ctl->pminisock_base;
		struct dlist *phead = &tp->cminisock_api_config.pmsk_freelist;
		dlist_init(phead);
		dlist_init(&ctl->pmsk_eventlist);

		printk("checking minisock alignment: %p\n", pmsk);
		ctl->pminisock_limit = (char*)ctl->pminisock_base + pminisock_len;
		count = 0;
		printk("inserting pmsk: ");
		while((char*)(pmsk+1) <= (char*)ctl->pminisock_limit && 
		      count < maxMSKCount) {
			memset(pmsk, 0x3a, sizeof(*pmsk));
			pmsk->prev = pmsk->next = NULL;
			pmsk->ctl = ALLOC_FREE;
			init_pminisock(pmsk);
			dlist_insert_tail(phead, 
					  (struct list_link*)pmsk);
			pmsk++;
			count++;
			//printk("%p  ", pmsk);
		}
		printk("\n");

		/* Initialize heap */
		ctl->heap_base = ALIGN(ctl->pminisock_limit, 1);
		tp->t.heapbytesize = ctl->ro_len - pminisock_len;

		error = copy_to_user(optdata,&new_config,sizeof(new_config));
		if(error) {
			printk("copy to user error\n");
			error = -EINVAL;
			goto out_dealloc;
		}

		// Set up Crypto
		if(generateHMAC) {
#ifndef FIXED_CRYPTO_KEYS
			__u8 hmac_key[HMAC_KEYLEN];
			get_random_bytes(hmac_key, HMAC_KEYLEN);
#else
#warning "Fixed hmac key"
			__u8 hmac_key[HMAC_KEYLEN+1] = "\00\01\02\03\04\05\06\07\010\011\012\013\014\015\016\017\020\021\022\023\024";
#endif
#if OPENSSL_HMAC
#warning "OpenSSL HMAC"
			tp->t.hmacCTX = kmalloc(sizeof(*tp->t.hmacCTX), GFP_KERNEL);
			if(tp->t.hmacCTX == NULL) {
				printk("hmac kmalloc error\n");
				error = -ENOMEM;
				goto out_dealloc;
			}
			hmac_setup(tp->t.hmacCTX, hmac_key, HMAC_KEYLEN);
#else
			BUG_TRAP(HMAC_KEYLEN <= HMACLEN);
			memcpy(tp->t.hmacKey, hmac_key, HMAC_KEYLEN);
#endif
		}
		if(generateNonces) {
#ifndef FIXED_CRYPTO_KEYS
			__u8 nonce_key[NONCE_KEYLEN];
			get_random_bytes(nonce_key, NONCE_KEYLEN);
#else
			__u8 nonce_key[NONCE_KEYLEN+1] = "\00\01\02\03\04\05\06\07\010\011\012\013\014\015\016\017\020\021\022\023\024";
#endif
			tp->t.nonceCTX = kmalloc(sizeof(*tp->t.nonceCTX), GFP_KERNEL);
			if(tp->t.nonceCTX == NULL) {
				printk("nonce kmalloc error\n");
				error = -ENOMEM;
				goto out_dealloc;
			}
			aes_encrypt_key(nonce_key, NONCE_KEYLEN, tp->t.nonceCTX);
		}

		return 0;
	} else {
		int len;
		if(get_user(len, (int*)optlen)) {
			printk("pipe parameter readout: get optlen fault\n");
			return -EFAULT;
		}
		error = copy_to_user(optdata,&tp->cminisock_api_config.cfg,sizeof(tp->cminisock_api_config.cfg));
		if(error) {
			printk("pipe parameter readout: copy out fault\n");
			return -EINVAL;
		}
		if(put_user(len, (int*)optlen)) {
			printk("pipe parameter readout: set optlen fault\n");
			return -EFAULT;
		}
		printk("socket %p configured\n", sk);
		return 0;
	}

 out:
	return error;
 out_dealloc:
	vfree(new_config.mmap_base);
	new_config.mmap_base = NULL;
	return error;
}

int trickles_setsockopt_impl(struct sock *sk, int optname, int optval) {
	extern int gIsServer;
	struct tcp_opt *tp = &(sk->tp_pinfo.af_tcp);
	switch(optname) {
	case TCP_TRICKLES_ADDSERVER: {
		int currPos;
		if(tp->t.numServers >= MAX_TRICKLES_SERVERS) {
			printk("out of space for servers\n");
			return -ENOMEM;
		}
		currPos = tp->t.numServers++;
		struct trickles_server *server = &tp->t.servers[currPos];
		trickles_server_init(server);
		server->address = optval;
		printk("serverAddrs[%d] = %X\n", currPos, server->address);
		gIsServer = 0;
		break;
	}
	case TCP_TRICKLES_PROBERATE: {
		tp->t.probeRate = optval;
		printk("setting probe rate to %d\n", tp->t.probeRate);
		break;
	}
	default:
		printk("Invalid sockopt\n");
		return -EINVAL;
	}
	return 0;
}

int trickles_getsockopt_impl(struct sock *sk, int level, int optname, char *optval, int *optlen) {
	extern void analyze_msk_list(struct sock *sk);

	struct tcp_opt *tp = &(sk->tp_pinfo.af_tcp);
	int outputLen, len, rval;
	if(level != SOL_TCP) {
		return -EINVAL;
	}
	switch(optname) {
	case TCP_TRICKLES_CWND:
		outputLen = sizeof(int);
		rval = tp->snd_wnd;
		break;
	case TCP_TRICKLES_SSTHRESH:
		outputLen = sizeof(int);
		rval = tp->snd_ssthresh;
		break;
	case TCP_TRICKLES_DUMP:
		// dump stats
		//printk("Dumping socket stats for %p\n", sk);
		//dump_socket_stats(sk);
		analyze_msk_list(sk);
		outputLen = sizeof(int);
		rval = 0;
		break;
	default:
		return -ENOPROTOOPT;
	}
	if(get_user(len,optlen)) {
		return -EFAULT;
	}
	if(len < sizeof(int)) {
		return -EFAULT;
	}
	if(put_user(outputLen,optlen)) {
		return -EFAULT;
	}
	if(put_user(rval,optval)) {
		return -EFAULT;
	}
	return 0;
}

static __inline__ void sockfd_put(struct socket *sock)
{
        fput(sock->file);
}

/* syscall */
int trickles_sendv_impl(int fd, struct cminisock *msk, struct tiovec *user_tiov, int tiovlen) {
	printk("sendv_impl\n");
	struct socket *sock;
	struct sock *sk;
	struct tcp_opt *tp;
	int err;

	struct tiovec *tiov;
	int tiov_size;

	COMPATIBILITY(struct pminisock *pmsk);

	extern int gNumSendv;
	gNumSendv++;

	err = -EINVAL;
	if (tiovlen < 0 || tiovlen > UIO_MAXIOV) {
		goto out;
	}
	err = -ENOMEM;
	tiov_size = sizeof(struct tiovec) * tiovlen;
	if(tiov_size > 0) {
		tiov = kmalloc(tiov_size, GFP_KERNEL);
		if(tiov == NULL) {
			goto out;
		}
		err = -EFAULT;
		if(copy_from_user(tiov, user_tiov, tiov_size)) {
			goto out_freeiov;
		}
	} else {
		tiov = NULL;
	}

	sock = sockfd_lookup(fd, &err);
	if (!sock)
		goto out_freeiov;

	sk = sock->sk;
	tp = &(sk->tp_pinfo.af_tcp);

	lock_sock(sk);
	if(!TRICKLES_USERAPI_CONFIGURED_TP(tp)) {
		printk("Socket not configured\n");
		err = -EINVAL;
		release_sock(sk);
		goto out_put;
	}
	COMPATIBILITY(
	if(!IS_VALID_MSK(sk,msk)) {
		printk("%d: bad minisocket %d %d\n", __LINE__, !IS_TRICKLES_SOCK_ADDR(tp,msk), !(VALID_MSK_CTL(msk)));
		err = -EINVAL;
		release_sock(sk);
		goto out_put;
	}
	)

	COMPATIBILITY(pmsk = msk->pmsk);

	free_trickles_pmsk(sk, pmsk);
	COMPATIBILITY(free_trickles_msk(sk,msk));
	FREE_MSK(sk,msk); // unlink msk, since this is the last reference

	struct cminisock *api_msk = allocate_api_msk(sk);
	unmarshallContinuationServerPMSK2MSK(sk, api_msk, pmsk);

	err = trickles_do_sendmsg_tiov(sk,api_msk,tiov,tiovlen);

	release_sock(sk);
out_put:
	sockfd_put(sock);
 out_freeiov:
	if(tiov_size > 0)
		kfree(tiov);
 out:
	return err;
}

// copied from filemap.c
static int skb_fillpage_actor(read_descriptor_t * desc, struct page *page, unsigned long offset , unsigned long size)
{
	ssize_t written;
	unsigned long count = desc->count;
	struct sk_buff *skb = (struct sk_buff *) desc->buf;
	int i = skb_shinfo(skb)->nr_frags;

	if (size > count)
		size = count;

	if(i >= MAX_SKB_FRAGS) {
		printk("too many fragments\n");
		written = -EINVAL;
	} else {
		get_page(page);
		fill_page_desc(skb,i,page,offset,size);
		written = size;
		skb->len += size;
		skb->data_len += size;
	}
	if (written < 0) {
		desc->error = written;
		written = 0;
	}
	desc->count = count - written;
	desc->written += written;
	return written;
}

/* Insert file pages into sk_buff */
static ssize_t file_insertpages(struct sk_buff *skb, int in_fd, loff_t offset, size_t count)
{
	ssize_t retval;
	struct file * in_file;
	struct inode * in_inode;

	/*
	 * Get input file, and verify that it is ok..
	 */
	retval = -EBADF;
	in_file = fget(in_fd);
	if (!in_file)
		goto out;
	if (!(in_file->f_mode & FMODE_READ))
		goto fput_in;
	retval = -EINVAL;
	in_inode = in_file->f_dentry->d_inode;
	if (!in_inode)
		goto fput_in;
	if (!in_inode->i_mapping->a_ops->readpage)
		goto fput_in;
	retval = locks_verify_area(FLOCK_VERIFY_READ, in_inode, in_file, in_file->f_pos, count);
	if (retval)
		goto fput_in;

	retval = 0;
	if (count) {
		read_descriptor_t desc;

		desc.written = 0;
		desc.count = count;
		desc.buf = (char *) skb;
		desc.error = 0;
		do_generic_file_read(in_file, &offset, &desc, skb_fillpage_actor);

		retval = desc.written;
		if (!retval)
			retval = desc.error;
	}

fput_in:
	fput(in_file);
out:
	return retval;
}

/* same structure as iov_handler */
static inline int fiov_handler(struct sock *origSK, struct cminisock *msk, struct fiovec *fiov, int fiovlen) {
	printk("returning prematurely\n");
	return 0;
	int numDataPackets = 0;
	int i, totallen = 0, fiov_pos = 0, fiov_offs = 0;
	struct cminisock_packet *pkts;
	int rval = 0;
	struct sk_buff **skbs =
		kmalloc(sizeof(struct sk_buff *) * msk->num_packets, GFP_USER),
		*skb;

	if(skbs == NULL) {
		goto out;
	}
	pkts = msk->packets;

	for(i=0; i < fiovlen; i++) {
		totallen += fiov[i].len;
	}
	for(i=0; i < msk->num_packets; i++) {
		int pkt_remain;
		int short_pkt = 0;
		int copying = 1; /* initial state: allow copies. After first sendfile() request, can no longer copy */

		if(pkts[i].len > totallen) {
			short_pkt = 1;
		}
		pkt_remain = pkts[i].len = MIN(pkts[i].len, totallen);
		skb = skbs[i] = recycle(origSK);
		if(skb == NULL) {
			skb = skbs[i] = alloc_skb(MAX_TCP_HEADER + MAX_TRICKLES_SERVER_HDR_LEN + pkts[i].ucontLen + pkts[i].len, GFP_KERNEL);
		}
		numDataPackets = i+1;
		if(skb == NULL) {
			printk("could not allocate skb\n");
			goto out;
		}
		skb_reserve(skb, MAX_TCP_HEADER + MAX_TRICKLES_SERVER_HDR_LEN + pkts[i].ucontLen);

		skb->csum = 0;
		skb->ip_summed = CHECKSUM_HW;
		while(fiov_pos < fiovlen) {
			int amt = MIN(pkt_remain, fiov[fiov_pos].len - fiov_offs);
			int err = 0;
			//printk("iov copy loop, copying %d\n", amt);

			if(fiov[fiov_pos].fd == -2) {
				if(!copying) {
					printk("cannot copy; after first page fragment of packet\n");
					kfree_skb(skb);
					goto out;
				}
				/* not 64 bit safe */
				if(fiov[fiov_pos].offset + fiov_offs >= (0x1ULL << 32ULL)) {
					printk("trickles does not handle file offsets > 32 bits\n");
				}
				char *src = (char*)fiov[fiov_pos].offset + fiov_offs;
				err = skb_add_data(skb,src,amt);
				if(err) {
					printk("error while csum/copy, base = %p amt = %d pkt_type = %d\n", src, amt, msk->packets[i].type);
					kfree_skb(skb);
					rval = -EINVAL;
					goto out;
				}
			} else {
				int res;
				copying = 0;
				res = file_insertpages(skb,fiov[fiov_pos].fd, fiov[fiov_pos].offset + fiov_offs, amt);
				if(res < 0) {
					rval = res;
					printk("could not insert pages\n");
					goto out;
				}
				if(res != amt) {
					rval = res;
					printk("insufficient file data for insertion\n");
					goto out;
				}
			}
			//printk("iov[%d].iov_base (%p) + iov_offs (%u) = %p, data = %p, amt = %d, skb->csum = %x, tail = %p, tailroom = %u, iov_len = %u, &err=%p\n", iov_pos, iov[iov_pos].iov_base, iov_offs, iov[iov_pos].iov_base + iov_offs, data, amt, skb->csum, skb->tail, skb_tailroom(skb), iov[iov_pos].iov_len, &err);
			if(err) {
				printk("error while csum/copy\n");
				kfree_skb(skb);
				goto out;
			}

			totallen -= amt;
			pkt_remain -= amt;
			fiov_offs += amt;
			if(fiov_offs == fiov[fiov_pos].len) {
				fiov_offs = 0;
				fiov_pos++;
			}
			if(pkt_remain == 0) break;
		}
		BUG_TRAP(pkt_remain == 0);

		if(userapi_pkt_spew) {
			printk("sending pkts[%d] %u-%u\n", i, pkts[i].seq, pkts[i].seq + pkts[i].len);
		}
		// on last packet, set the tag to FIN
		if(totallen == 0 &&
		   fiov[fiovlen-1].offset == 0 && fiov[fiovlen-1].len == 0) {
			msk->tag = FIN;
		}

		rval += pkts[i].len; // check how much data actually sent?
		if(totallen == 0) break;
	}
	FINISH_TRANSMIT(msk, skbs, numDataPackets, NULL, 0, 0);
	// end code copied from iov_handler
	if(totallen > 0) {
		if(trickles_ratelimit())
			printk("too much data for downcall\n");
	}
 out:
	kfree(skbs);
	return rval;
}

int trickles_sendfilev_impl(int fd, struct cminisock *msk, struct fiovec *user_fiov, int fiovlen) {
	printk("sendfilev_impl\n");
	struct socket *sock;
	struct sock *sk;
	struct tcp_opt *tp;
	int err;
	struct fiovec *fiov;
	COMPATIBILITY(struct pminisock *pmsk);

	err = -EINVAL;
	if (fiovlen < 0 || fiovlen > UIO_MAXIOV) {
		goto out;
	}
	{
		int fiov_size;
		err = -ENOMEM;
		fiov_size = sizeof(struct fiovec) * fiovlen;
		if(fiov_size > 0) {
			fiov = kmalloc(fiov_size, GFP_KERNEL);
			if(fiov == NULL) {
				goto out;
			}
			err = -EFAULT;
			if(copy_from_user(fiov, user_fiov, fiov_size)) {
				goto out_freefiov;
			}
		} else {
			fiov = NULL;
		}
	}

	sock = sockfd_lookup(fd, &err);
	if (!sock)
		goto out_freefiov;

	sk = sock->sk;
	tp = &(sk->tp_pinfo.af_tcp);

	lock_sock(sk);
	if(!TRICKLES_USERAPI_CONFIGURED_TP(tp)) {
		printk("Socket not configured\n");
		release_sock(sk);
		err = -EINVAL;
		goto out_put;
	}
	COMPATIBILITY(
	if(!IS_VALID_MSK(sk,msk)) {
		printk("%d: bad minisocket %d %d\n", __LINE__, !IS_TRICKLES_SOCK_ADDR(tp,msk), !(VALID_MSK_CTL(msk)));
		err = -EINVAL;
		release_sock(sk);
		goto out_put;
	}
	)

	COMPATIBILITY(pmsk = msk->pmsk);

	free_trickles_pmsk(sk, pmsk);
	COMPATIBILITY(free_trickles_msk(sk,msk));
	FREE_MSK(sk,msk); // unlink msk, since this is the last reference

	struct cminisock *api_msk = allocate_api_msk(sk);
	unmarshallContinuationServerPMSK2MSK(sk, api_msk, pmsk);

	err = trickles_do_sendmsg_fiov(sk,api_msk,fiov,fiovlen);

	release_sock(sk);
 out_put:
	sockfd_put(sock);
 out_freefiov:
	if(fiovlen > 0)
		kfree(fiov);
 out:
	return err;
}

int trickles_send_impl(int fd, struct cminisock *msk, char *buf, int len) {
	// printk("send_impl\n");
	struct socket *sock;
	struct sock *sk;
	struct tcp_opt *tp;
	int err;
	struct tiovec iov = {iov_base: buf, iov_len: len,
#ifdef SETUCONT_COMMAND
			     ucont_base: NULL,
			     ucont_len: 0
#endif // SETUCONT_COMMAND
	};
	COMPATIBILITY(struct pminisock *pmsk);

	sock = sockfd_lookup(fd, &err);
	if (!sock)
		goto out;

	sk = sock->sk;
	tp = &(sk->tp_pinfo.af_tcp);

	lock_sock(sk);
	if(!TRICKLES_USERAPI_CONFIGURED_TP(tp)) {
		printk("Socket not configured\n");
		release_sock(sk);
		err = -EINVAL;
		goto out_put;
	}
	COMPATIBILITY(
	if(!IS_VALID_MSK(sk,msk)) {
		printk("%d: bad minisocket %d\n", __LINE__, !IS_TRICKLES_SOCK_ADDR(tp,msk));
		err = -EINVAL;
		release_sock(sk);
		goto out_put;
	}
	)

	COMPATIBILITY(pmsk = msk->pmsk);

	free_trickles_pmsk(sk, pmsk);
	COMPATIBILITY(free_trickles_msk(sk,msk));

	if(iov.iov_len == -1) {
		free_trickles_pmsk_finish(sk, pmsk);
		FREE_MSK(sk,msk);
		err = 0;
	} else if(iov.iov_len == -2) {
		if(pmsk->ctl != ALLOC_HALFFREE) {
			pmsk->ctl = ALLOC_HALFFREE;
			// Remove from list, but dont deallocate
			err = 0;
		} else {
			/* already half-freed ! */
			printk("already half freed\n");
			err = -EINVAL;
		}
		COMPATIBILITY(
		if(msk->ctl != ALLOC_HALFFREE) {
			msk->ctl = ALLOC_HALFFREE;
			// Remove from list, but dont deallocate
			err = 0;
		} else {
			/* already half-freed ! */
			printk("already half freed\n");
			err = -EINVAL;
		}
		) // compatibility
	} else if(iov.iov_len == -3) {
		pmsk->tag = FIN;
		COMPATIBILITY(msk->tag = FIN);
		iov.iov_len = 0;
		goto more;
	} else {
	more:;
		FREE_MSK(sk,msk); // unlink msk, since this is the last reference

		struct cminisock *api_msk = allocate_api_msk(sk);
		unmarshallContinuationServerPMSK2MSK(sk, api_msk, pmsk);

		err = trickles_do_sendmsg_tiov(sk,api_msk,&iov,1);
	}

	release_sock(sk);
out_put:
	sockfd_put(sock);
 out:
	return err;
}

int trickles_mmap_impl(struct file *file, struct socket *sock, struct vm_area_struct *vma) {
	printk("configuring mmap\n");
	struct sock *sk = sock->sk;
	struct tcp_opt *tp = &(sk->tp_pinfo.af_tcp);

	if(!TRICKLES_USERAPI_CONFIGURED_TP(tp)) {
		printk("mmap before configuration\n");
		return -EINVAL;
	}
	printk("trickles mmap called\n");
	vma->vm_ops = &trickles_vm_ops;
	vma->vm_private_data = &tp->cminisock_api_config;
	return 0;
}

int trickles_setucont_impl(int fd, struct cminisock *msk_compat, int pkt_num,
			   char *user_ucont, unsigned ucont_len) {
	struct socket *sock;
	struct sock *sk;
	struct tcp_opt *tp;
	int err;
	char *buf;
	COMPATIBILITY(struct pminisock *pmsk);

	extern int gNumSetUCont;
	gNumSetUCont++;

	sock = sockfd_lookup(fd, &err);
	if (!sock)
		goto out;

	sk = sock->sk;
	tp = &(sk->tp_pinfo.af_tcp);

	lock_sock(sk);

	if(!TRICKLES_USERAPI_CONFIGURED_TP(tp)) {
		printk("Socket not configured\n");
		release_sock(sk);
		err = -EINVAL;
		goto out_put;
	}
	COMPATIBILITY(
	if(!IS_VALID_MSK(sk,msk_compat)) {
		printk("%d: bad minisocket %d %d\n", __LINE__, !IS_TRICKLES_SOCK_ADDR(tp,msk_compat), !(VALID_MSK_CTL(msk_compat)));
		err = -EINVAL;
		release_sock(sk);
		goto out_put;
	}
	)

	COMPATIBILITY(pmsk = msk_compat->pmsk);

	if(pmsk->packets[pkt_num].type == CONTTYPE_MINIMAL) {
		//printk("setucont on minimal packet\n");
	} else {
		//printk("setucont on full packet\n");
	}

#if 0
	printk("pmsk num_packet = %d, msk num_packet = %d\n", 
	       pmsk->num_packets, msk_compat->num_packets);
#endif

	if(pkt_num < 0 || pkt_num >= pmsk->num_packets) {
		printk("(%p) invalid packet # %d\n", pmsk, pkt_num);
		err = -EINVAL;
		release_sock(sk);
		goto out_put;
	}
	if(ucont_len > 0) {
		buf = kmalloc(ucont_len, GFP_KERNEL);
		if(buf == NULL) {
			printk("set_ucont: out of memory\n");
			err = -ENOMEM;
			release_sock(sk);
			goto out_put;
		}
		if(copy_from_user(buf,user_ucont,ucont_len)) {
			printk("set_ucont: fault while copying\n");
			err = -EFAULT;
			release_sock(sk);
			goto out_put;
		}
	} else {
		buf = NULL;
	}
	BUG_TRAP(pkt_num < pmsk->num_packets);
	setPacketUCont(&pmsk->packets[pkt_num], buf, ucont_len);
	err = 0;
	release_sock(sk);

 out_put:
	sockfd_put(sock);
 out:
	return err;
}
#endif // USERTEST

/*
 *
 * COMPATIBILITY LAYER
 * This code is responsible for implementing the bytestream conversion protocol
 *
 */


static int trickles_write_memory_free(struct sock *sk) {
	struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;
	return tp->t.write_seq - tp->t.snd_una < sk->sndbuf;
}

#ifndef USERTEST
/*
 *	Wait for more write memory
 */
static int wait_for_write_memory(struct sock * sk, long *timeo)
{
  /* copied from standard TCP version */
	int err = 0;
	long vm_wait = 0;
	long current_timeo = *timeo;
	DECLARE_WAITQUEUE(wait, current);

	if (trickles_write_memory_free(sk))
		current_timeo = vm_wait = (net_random()%(HZ/5))+2;

	add_wait_queue(sk->sleep, &wait);
	for (;;) {
		set_bit(SOCK_ASYNC_NOSPACE, &sk->socket->flags);

		set_current_state(TASK_INTERRUPTIBLE);

		if (sk->err || (sk->shutdown & SEND_SHUTDOWN))
			goto do_error;
		if (!*timeo)
			goto do_nonblock;
		if (signal_pending(current))
			goto do_interrupted;
		clear_bit(SOCK_ASYNC_NOSPACE, &sk->socket->flags);
		if (trickles_write_memory_free(sk) && !vm_wait)
			break;

		set_bit(SOCK_NOSPACE, &sk->socket->flags);
		release_sock(sk);
		if (!trickles_write_memory_free(sk) || vm_wait)
			current_timeo = schedule_timeout(current_timeo);
		lock_sock(sk);

		if (vm_wait) {
			vm_wait -= current_timeo;
			current_timeo = *timeo;
			if (current_timeo != MAX_SCHEDULE_TIMEOUT &&
			    (current_timeo -= vm_wait) < 0)
				current_timeo = 0;
			vm_wait = 0;
		}
		*timeo = current_timeo;
	}
out:
	current->state = TASK_RUNNING;
	remove_wait_queue(sk->sleep, &wait);
	return err;

do_error:
	err = -EPIPE;
	goto out;
do_nonblock:
	err = -EAGAIN;
	goto out;
do_interrupted:
	err = sock_intr_errno(*timeo);
	goto out;
}
#else
static int wait_for_write_memory(struct sock * sk, long *timeo) {
  printk("Not implemented for userspace test\n");
  assert(0);
}
#endif // USERTEST

int trickles_client_sendmsg(struct sock *sk, struct msghdr *msg, int size) {
	//printk("%d: s\n", jiffies);
	//printk("client_sendmsg(0)\n");
	int i;
	int iovlen, totalLen = 0, skb_spaceleft = 0, result = 0, position = 0;
	// NOT tiovec: these are mapped to send()
	struct iovec *iov;
	struct sk_buff *skb = NULL;
	struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;
	iov = msg->msg_iov;
	iovlen = msg->msg_iovlen;

	for(i=0; i < iovlen; i++) {
		totalLen += iov[i].iov_len;
	}
	// Sleep if not enough space
	lock_sock(sk);

	for(i=0; i < iovlen; i++) {
		char *buf;
		int iov_position = 0;
		//printk("client_sendmsg(3)\n");
		while(iov_position < iov[i].iov_len) {
			//printk("client_sendmsg(4)\n");
			int copyLen;
			if(skb_spaceleft == 0) {
				if(skb != NULL) {
					// queue previous skb
					tp->t.write_seq += skb->len;
					TCP_SKB_CB(skb)->end_seq = tp->t.write_seq;
					__skb_queue_tail(&tp->t.requestBytes, skb);
				}
				if(!TRICKLES_HAS_SENDSPACE(sk)) {
					long timeout;
				sleep:
					timeout = HZ/10;
					wait_for_write_memory(sk, &timeout);
				}
				BUG_TRAP(tp->t.write_seq - tp->t.snd_una <= sk->sndbuf);
				skb_spaceleft = MIN(sk->sndbuf - (tp->t.write_seq - tp->t.snd_una), totalLen - position);
				//skb = alloc_skb(skb_spaceleft, GFP_KERNEL);
				skb = alloc_skb(skb_spaceleft, GFP_ATOMIC);
				if(skb == NULL) {
					printk("Trickles_client_sendmsg: out of memory\n");
					goto sleep;
				}
				TCP_SKB_CB(skb)->seq = tp->t.write_seq;
			}
			copyLen = MIN(iov[i].iov_len - iov_position, skb_spaceleft);
			buf = skb_put(skb, copyLen);
			if(copy_from_user(buf, iov[i].iov_base + iov_position, copyLen)) {
				printk("Trickles_client_sendmsg: fault while copying from client\n");
				result = -EFAULT;
				goto out_dealloc;
			}
			skb_spaceleft -= copyLen;
			position += copyLen;
			iov_position += copyLen;
		}
	}
	BUG_TRAP(skb_spaceleft == 0);
	if(skb != NULL) {
		// queue previous skb
		tp->t.write_seq += skb->len;
		TCP_SKB_CB(skb)->end_seq = tp->t.write_seq;
		__skb_queue_tail(&tp->t.requestBytes, skb);
	}

	if(tp->t.write_seq - tp->t.snd_una > 0) {
		switch(tp->t.conversionState) {
		case CONVERSION_IDLE:
			queueConversionRequests(sk);
			tp->t.conversionState = CONVERSION_WAITFORSERVER;
			pushRequests(sk);
			//printk("trickles_sendmsg(0) set conversion state to waitforserver\n");
			break;
		case CONVERSION_WAITFORUSER:
			finishIncompleteRequest(sk);
			tp->t.conversionState = CONVERSION_WAITFORSERVER;
			pushRequests(sk);
			//printk("trickles_sendmsg(1) set conversion state to waitforserver\n");
			break;
		case CONVERSION_WAITFORSERVER:
			// do nothing, since the new data may need to be appended to an existing conversion
			break;
		}
	}

#if 0
	printk("trickles_client_sendmsg (%p): iov[0] = %d@%p, snd_una = %d write_seq = %d\n",
	       sk,
	       iov[0].iov_len, iov[0].iov_base,
	       tp->t.snd_una, tp->t.write_seq);
#endif
	release_sock(sk);
	//printk("client_sendmsg(1)\n");
	return totalLen;

 out_dealloc:
	kfree_skb(skb);
	release_sock(sk);
	//printk("client_sendmsg(2)\n");
	return result;
}

void trickles_syn_piggyback_impl(struct sock *sk, struct sk_buff *skb) {
	//printk("Piggyback impl\n");
	struct tcp_opt *tp = &(sk->tp_pinfo.af_tcp);
	int sendBufLen = tp->t.write_seq - tp->t.snd_una;
	//printk("sendBufLen = %d\n", sendBufLen);
	if(sendBufLen > 0) {
		int copyLen =
			MIN(sendBufLen, TRICKLES_MSS - MAX_TCP_HEADER);
		struct sk_buff *input_skb = tp->t.requestBytes.next;
		int csum = 0;
		while(copyLen > 0) {
			BUG_TRAP((void*)input_skb != (void*)&tp->t.requestBytes);
			unsigned pieceLen = MIN(input_skb->len, copyLen);
			char *dst = skb_put(skb, pieceLen),
				*src = input_skb->data;
			int srcErr = 0, dstErr = 0;
			csum = csum_partial_copy_generic(src, dst, pieceLen, csum,
							 &srcErr, &dstErr);
			if(srcErr || dstErr) {
				printk("error while piggybacking data on SYN\n : %d %d\n",
				       srcErr, dstErr);
			}
			copyLen -= pieceLen;
			input_skb = input_skb->next;
		}
		skb->csum = csum;
	}
}

#ifndef USERTEST
/* tcp_data_wait: copied from tcp.c */

static long tcp_data_wait(struct sock *sk, long timeo)
{
	DECLARE_WAITQUEUE(wait, current);

	add_wait_queue(sk->sleep, &wait);

	__set_current_state(TASK_INTERRUPTIBLE);

	set_bit(SOCK_ASYNC_WAITDATA, &sk->socket->flags);
	release_sock(sk);

	if (skb_queue_empty(&sk->receive_queue))
		timeo = schedule_timeout(timeo);

	lock_sock(sk);
	clear_bit(SOCK_ASYNC_WAITDATA, &sk->socket->flags);

	remove_wait_queue(sk->sleep, &wait);
	__set_current_state(TASK_RUNNING);
	return timeo;
}

int trickles_client_recvmsg(struct sock *sk, struct msghdr *msg,
			    int len, int nonblock, int flags, int *addr_len) {
	/* XXX Support all socket API semantics? */
	struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;
	int result = 0;
	int target;		/* Read at least this many bytes */
	long timeo;

	lock_sock(sk);
	if(!(tp->trickles_opt & TCP_TRICKLES_RCV_START)) {
		// also needed in trickles_poll
#if 0 // 0424 - changing client program instead of hacking rcv_start functionality into client
		bh_lock_sock(sk);
		trickles_send_ack_hook(sk);
		bh_unlock_sock(sk);#
#endif
		tp->trickles_opt |= TCP_TRICKLES_RCV_START;
	}

	if(!(tp->trickles_opt & TCP_TRICKLES_BUFFERDISCARD)) {
		/* Normal case: deliver actual data to client */
		release_sock(sk);
		return tcp_recvmsg(sk,msg,len,nonblock,flags,addr_len);
	}

	// Else, generate fake data (correlated with the network: data
	// is returned from this routine only if data was received on
	// the network. However, the actual network data was discarded)

	result = -ENOTCONN;

	if(flags & (MSG_OOB | MSG_PEEK)) {
		result = -EINVAL;
		goto done;
	}

	timeo = sock_rcvtimeo(sk, nonblock);
	target = sock_rcvlowat(sk, flags & MSG_WAITALL, len);

	while(1) {
		if(tp->rcv_nxt - tp->copied_seq >= target) {
			result = MIN(len, tp->rcv_nxt - tp->copied_seq); // 0503 - changed from min to MIN to suppress compilation warning
			tp->copied_seq += result;
			cleanup_rbuf(sk, result);
			break;
		} else if(timeo == 0) {
			/* NOWAIT */
			result = MIN(target, tp->rcv_nxt - tp->copied_seq); // 0503 - changed from min to MIN to suppress compilation warning
			tp->copied_seq += result;
			cleanup_rbuf(sk, result);
			break;
		} else {
			/* wait until enough new data is available */
			printk("waiting for data\n");
			timeo = tcp_data_wait(sk, timeo);
		}
		if(tp->rcv_nxt - tp->copied_seq == 0) {
			/* check to see why tcp_data_wait returned without new data. Copied from tcp_recvmsg */
			if (sk->done)
				break;

			if (sk->err) {
				result = sock_error(sk);
				break;
			}

			if (sk->shutdown & RCV_SHUTDOWN)
				break;

			if (sk->state == TCP_CLOSE) {
				if (!sk->done) {
					/* This occurs when user tries to read
					 * from never connected socket.
					 */
					result = -ENOTCONN;
					break;
				}
				break;
			}

			if (!timeo) {
				result = -EAGAIN;
				break;
			}
		}
		cleanup_rbuf(sk, result);
	}
	done:
	release_sock(sk);
	return result;
}

static inline void dump_tiov(struct tiovec *tiov) {
	printk("tiov_base = %p\ntiov_len = %d", tiov->iov_base, tiov->iov_len);
}

static inline void dump_mskdesc(struct mskdesc *mskd) {
	printk("msk = %p, num =  %d\n", mskd->msk, mskd->tiov_num);
	dump_tiov(mskd->tiov);
}

int trickles_sendbulk_impl(int fd, struct mskdesc *user_descbuf, int descbuf_len) {
	// printk("sendbulk_impl\n");
	struct socket *sock;
	struct sock *sk;
	struct tcp_opt *tp;
	struct mskdesc *descbuf;
	int err;

	extern int gNumSendbulk;
	extern int gNumSendbulkDesc;
	gNumSendbulk++;

	if(descbuf_len <= 0) {
		err = -EINVAL;
		goto out;
	}

	sock = sockfd_lookup(fd, &err);
	if (!sock)
		goto out;

	sk = sock->sk;
	tp = &(sk->tp_pinfo.af_tcp);

	//if(copy_from_user(buf, iov[i].iov_base + iov_position, copyLen)) {
	descbuf = kmalloc(descbuf_len, GFP_KERNEL);
	if(descbuf == NULL) {
		printk("trickles_sendbulk_impl: user desc buf out of memory\n");
		goto out_put;
	}
	if((err = copy_from_user(descbuf,user_descbuf,descbuf_len))) {
		printk("trickles_sendbulk_impl: copy_from_user returned %d\n", err);
		err = -EFAULT;
		goto out_dealloc;
	}
	void *tail = (char*)descbuf + descbuf_len;
	struct mskdesc *curr_desc = descbuf;

	lock_sock(sk);
	int descnum = 0;
	while(curr_desc < (struct mskdesc *)tail) {
		struct cminisock *msk = curr_desc->msk;
		COMPATIBILITY(struct pminisock *pmsk);
		//printk("Minisocket %d = %p\n", descnum, msk);
		if(!IS_VALID_MSK(sk, msk)) {
			printk("trickles_sendbulk_impl: bad minisocket %d %d @ %d\n",
			       !IS_TRICKLES_SOCK_ADDR(tp,msk), !(VALID_MSK_CTL(msk)),
			       descnum);
			err = -EINVAL;
			goto out_release;
		}
		COMPATIBILITY(pmsk = msk->pmsk);
		free_trickles_pmsk(sk, pmsk);
		COMPATIBILITY(free_trickles_msk(sk, msk));
		FREE_MSK(sk, msk);

		msk->dbg_mark = curr_desc->dbg_mark;

		struct cminisock *api_msk = allocate_api_msk(sk);
		unmarshallContinuationServerPMSK2MSK(sk, api_msk, pmsk);

		//printk("Desc %d, len = %d\n", descnum, curr_desc->tiov[0].iov_len);
		trickles_do_sendmsg_tiov(sk, api_msk, curr_desc->tiov, curr_desc->tiov_num);
		curr_desc = NEXT_MSKDESC(curr_desc);
		descnum++;
#if 0
		// Check prequeue
		if (skb_queue_len(&tp->ucopy.prequeue)) {
			tcp_prequeue_process(sk);
		}
#endif
	}
	gNumSendbulkDesc += descnum;

	if(tp->trickles_opt & TCP_TRICKLES_BULKPOLL) {
		//printk("bulk poll %d\n", tp->trickles_opt);
		if((err = trickles_poll(sk)) >= 0) {
			//printk("err = %d\n", err);
		} else {
			printk("err = EAGAIN\n");
			err = -EAGAIN;
		}
	}
 out_release:
	release_sock(sk);
 out_dealloc:
	kfree(descbuf);
 out_put:
	sockfd_put(sock);
 out:
	return err;
}

/* Bulk debugging output interface */

struct alloc_head_list tricklesProcLogHead;

#if 0
ctl_table trickles_table[] = {
  {DEV_PM_ON, "on", &on, sizeof(on), 0644, NULL, pm_sysctl_handler},
  {0}
};

ctl_table trickles_trickles_table[] = {
  {DEV_PM, "pm", NULL, 0, 0555, pm_table},
  {0}
};

ctl_table trickles_root_table[] = {
  {CTL_DEV, "dev", NULL, 0, 0555, pm_pm_table},
  {0}
};
#endif

int trickles_read_proc(char *page, char **start, off_t offset, int count,
		       int *eof, void *data)
{
    struct TricklesProcLogEntry *logEntry;
    int i, pos = 0, done = 1;

    local_bh_disable();
    alloc_head_walk(&tricklesProcLogHead, logEntry) {
	    char tempBody[4096], *temp = tempBody;
	    int first = logEntry->returnedEvents == 0;
	    if(first) {
		    int count = 0;
		    for(i=logEntry->returnedEvents; i < logEntry->size; i++) {
			    if(logEntry->events[i].valid)
				    count++;
		    }
		    sprintf(temp, "Socket (daddr=%X port=%d) (rcv_nxt=%u,trcv_nxt=%u) [%d]\n",
			    htonl(logEntry->addr), htons(logEntry->port),
			    logEntry->rcv_nxt, logEntry->t_rcv_nxt, count);
		    temp += strlen(temp);
	    }
	    for(i=logEntry->returnedEvents; i < logEntry->size; i++) {
		    struct TricklesLossEvent *event = &logEntry->events[i];
		    char locationBuf[64];
		    char *saveLocation;
		    char *state;
		    if(!event->valid) continue;
		    done = 0;
		    switch(event->extra) {
		    case EVENT_EXTRA_SEND:
			    saveLocation = "sendStateChange";
			    break;
		    case EVENT_EXTRA_RECV:
			    saveLocation = "recv";
			    break;
		    case EVENT_EXTRA_SAMPLE0:
			    saveLocation = "contList sample0";
			    break;
		    case EVENT_EXTRA_SAMPLE1:
			    saveLocation = "contList sample1";
			    break;
		    default:
			    sprintf(locationBuf, "(bad location %d)", event->extra);
			    saveLocation = locationBuf;
		    }
		    switch(event->state) {
		    case TRICKLES_CLIENT_NORMAL:
			    state = "(normal)";
			    break;
		    case TRICKLES_CLIENT_RECOVERY:
			    state = "(recovery)";
			    break;
		    case TRICKLES_CLIENT_SLOWSTART:
			    state = "(slowstart)";
			    break;
		    case TRICKLES_CLIENT_SYNACK:
			    state = "(synack)";
			    break;
		    default:
			    state = "(bad state)";
		    }
		    sprintf(temp, "%s: cwnd=%d state=%s time=%d\n", saveLocation,
			    (int)event->cwnd, state, event->time);
		    if(first) {
			    temp = tempBody;
			    first = 0;
		    }
		    temp += logEntry->sentAmount;
		    int copyLen = MAX(MIN((int)strlen(temp), count - pos), 0);
		    if(copyLen == strlen(temp)) {
			    done = 1;
		    }
		    memcpy(page + pos, temp, copyLen);
		    pos += copyLen;
		    if(done) {
			    logEntry->returnedEvents++;
			    logEntry->sentAmount = 0;
		    } else {
			    logEntry->sentAmount += copyLen;
			    //printk("sentamount = %d\n", logEntry->sentAmount);
			    BUG_TRAP(pos == count);
			    goto done;
		    }
	    }
	    if(done && (i == logEntry->size)) {
		    struct TricklesProcLogEntry *clean = logEntry;
		    logEntry = (struct TricklesProcLogEntry *)logEntry->prev;
		    unlink((struct alloc_head*)clean);
		    kfree(clean->events);
		    kfree(clean);
	    }
    }
 done:
    if(empty(&tricklesProcLogHead)) {
	    *eof = 1;
    } else {
	    *eof = 0;
    }
    local_bh_enable();
    *start = page;
    //printk("pos=%d, count=%d\n", pos, count);
    return pos;
}

struct alloc_head_list tricklesCwndProcLogHead;

struct BoundedBuffer {
	char *dest;
	int len;
	int curPos;
};

void bb_init(struct BoundedBuffer *bb, char *buffer, int len) {
	bb->dest = buffer;
	bb->len = len;
	bb->curPos = 0;

	//printk("bbinit: %p %d %d\n", bb->dest, bb->len, bb->curPos);
}

int bb_write(struct BoundedBuffer *bb, const char *data, int len) {
	int prevPos = bb->curPos;
	int copyLen;
	bb->curPos = MIN(prevPos+len, bb->len);
	copyLen = bb->curPos - prevPos;

	memcpy(bb->dest + prevPos, data, copyLen);
	return copyLen;
}

spinlock_t cwndLogLock = SPIN_LOCK_UNLOCKED;

void trickles_logCwnd_impl(enum LogCwndType type, int addr, int port, int seq, int ack_seq,
			   int startCwnd, int effCwnd, int ssthresh,
			   int rtt, int srtt) {
#ifdef LOG_CWND_ENABLE
	struct TricklesCwndProcLogEntry *logentry =
		kmalloc(sizeof(struct TricklesCwndProcLogEntry), GFP_ATOMIC);
	if(logentry != NULL) {
		logentry->prev = logentry->next = NULL;
		logentry->list = NULL;

		logentry->type = type;

		logentry->addr = addr;
		logentry->port = port;
		logentry->seq  = seq;
		logentry->ack_seq = ack_seq;
		logentry->startCwnd= startCwnd;
		logentry->effCwnd  = effCwnd;
		logentry->ssthresh = ssthresh;
		logentry->sentAmount = 0;
#if 0
		logentry->timestamp = jiffies;
#else
		// high resolution timestamp
		struct timeval tv;
		do_gettimeofday(&tv);
		// s, us
		logentry->s = tv.tv_sec;
		logentry->us = tv.tv_usec;
#endif
		logentry->rtt = rtt;
		logentry->srtt = srtt;
		spin_lock(&cwndLogLock);
		insert_tail(&tricklesCwndProcLogHead, (struct alloc_head*)logentry);
		spin_unlock(&cwndLogLock);
	}
#endif
}

int trickles_cwnd_read_proc(char *page, char **start, off_t offset, int count,
			    int *eof, void *data)
{
    struct TricklesCwndProcLogEntry *logEntry;
    struct BoundedBuffer bb;
    bb_init(&bb, page, count);

#define TRICKLES_CWND_READ_DISABLE_BH
#ifdef TRICKLES_CWND_READ_DISABLE_BH
    local_bh_disable();
#else
    #warning "Local bh not disabled while reading from cwnd log"
#endif
    alloc_head_walk(&tricklesCwndProcLogHead, logEntry) {
	    if(1) {
		    char tempbuf[1024];
		    int wrlen, real_wrlen;
		    //sprintf(tempbuf, "%8.8X:%d:%d:%d = %d/%d/%d @ %d s %d us %d rtt0 %d rtt1\n",
		    //sprintf(tempbuf, "%8.8X:%d:%d:%d = %d/%d/%d @ %d s %d us %d TCPBase %d rtt1\n",
		    switch(logEntry->type) {
		    case PACKET_RECORD:
			    sprintf(tempbuf, "pkt - %d:%d = %d/%d/%d @ %d s %d us %d rtt0 %d rtt1\n",
				    logEntry->seq, logEntry->ack_seq,
				    logEntry->startCwnd, logEntry->effCwnd, logEntry->ssthresh,
				    logEntry->s, logEntry->us,
				    logEntry->rtt,
				    logEntry->srtt);
			    break;
		    case CONTINUATION_RECORD:
			    sprintf(tempbuf, "cont - %d:%d = %d/%d/%d TCPBase: %d @ %d s %d us rtt1: %d \n",
				    logEntry->seq, logEntry->ack_seq,
				    logEntry->startCwnd, logEntry->effCwnd, logEntry->ssthresh,
				    logEntry->rtt,
				    logEntry->s, logEntry->us,
				    logEntry->srtt);
			    break;
		    case EVENT_RECORD: {
			    int eventtype = logEntry->seq;
			    char *eventTypeStr = "(undef0)";
			    switch(eventtype) {
			    case RECOVERYEVENT:
				    eventTypeStr = "Recovery";
				    break;
			    case TIMEOUTEVENT0:
				    eventTypeStr = "Timeout0";
				    break;
			    case TIMEOUTEVENT1:
				    eventTypeStr = "Timeout1";
				    break;
			    case USERBLOCKEVENT:
				    eventTypeStr = "UserBlock";
				    break;
			    case USERUNBLOCKEVENT:
				    eventTypeStr = "UserUnblock";
				    break;
			    case USERBADUNBLOCKEVENT:
				    eventTypeStr = "UserBadUnblock";
				    break;
			    case INSEQEVENT:
				    eventTypeStr = "InSeq";
				    break;
			    default:
				    eventTypeStr = "UNKNOWN";
			    }
			    sprintf(tempbuf, "%s:%d(%d-%d) = %d/%d/%d TCPBase: %d @ %d s %d us\n", eventTypeStr, logEntry->ack_seq,
				    logEntry->addr, logEntry->port,
				    logEntry->startCwnd, logEntry->effCwnd, logEntry->ssthresh,
				    logEntry->rtt,
				    logEntry->s, logEntry->us);

			    break;
		      }
		    default:
			    sprintf(tempbuf, "unknown record type\n");
		    }
		    // , logEntry->timestamp);
		    char *src = tempbuf + logEntry->sentAmount;
		    real_wrlen = bb_write(&bb, src, wrlen = strlen(src));
		    logEntry->sentAmount = real_wrlen;

		    if(real_wrlen < wrlen) {
			    break;
		    }
		    if(real_wrlen == wrlen) {
			    struct TricklesCwndProcLogEntry *clean;
			    clean = logEntry;
			    logEntry = (struct TricklesCwndProcLogEntry*)logEntry->prev;
			    unlink((struct alloc_head*)clean);
			    kfree(clean);
		    }

	    }
    }
    if(empty(&tricklesCwndProcLogHead)) {
	    // done with all entries
	    //printk("eof\n");
	    *eof = 1;
    } else {
	    *eof = 0;
    }
#ifdef TRICKLES_CWND_READ_DISABLE_BH
    local_bh_enable();
#endif

    //printk("curpos = %d %d\n", bb.curPos, loop_count);

    *start = page;
    return bb.curPos;
}

#undef memcpy
#define memcpy __copy_to_user
#include "array.h"
#include "bounded_buffer.h"
#undef memcpy

#define PATCH_FROM_FIELD(TYPE,FIELD)		\
	{offset: OFFSET_OF(TYPE,FIELD),	\
	width: WIDTH_OF(TYPE,FIELD) }

struct patch_desc {
	int offset;
	int width;
};

#define IS_OUTPUT(DIR) (DIR == out)

#define GEN_COPY_PATCH_HMAC_UPDATE(DIR)					\
static inline void copy_patch_hmac_update_##DIR(struct HMAC_CTX *hmac_ctx, void *user_addr, void *kernel_addr, \
					  int len, void (*const generator)(const void *const context, int num, struct patch_desc *patch), \
					  const void *const gen_ctx, int numDescs) { \
	const int in=1, out=2;						\
	int i;								\
	int lastOffset = 0;						\
	if(IS_OUTPUT(DIR)) {						\
		for(i=0; i < numDescs; i++) {				\
			struct patch_desc patch;			\
			/* Generator generates descriptors in-sequence */ \
			generator(gen_ctx, i, &patch);			\
			if(patch.offset < lastOffset) {			\
				BUG();					\
			}						\
			int hmacStart = lastOffset;			\
			int hmacEnd = patch.offset;			\
			__copy_to_user(user_addr + hmacStart, kernel_addr + hmacStart, hmacEnd - hmacStart); \
			hmac_update(hmac_ctx, (char*)kernel_addr + hmacStart, hmacEnd - hmacStart); \
			int zero = 0;					\
			BUG_TRAP(patch.width <= sizeof(zero));		\
			__copy_to_user(user_addr + patch.offset, &zero, patch.width); \
			hmac_update(hmac_ctx, &zero, patch.width); \
			lastOffset = patch.offset + patch.width;	\
		}							\
	} else {							\
		__copy_from_user(kernel_addr, user_addr, len);		\
									\
		/* N.B. Input processing does not need to insert zeros */ \
		for(i=0; i < numDescs; i++) {				\
			int zero = 0;					\
			struct patch_desc patch;			\
			/* Generator generates descriptors in-sequence */ \
			generator(gen_ctx, i, &patch);			\
			if(patch.offset < lastOffset) {			\
				BUG();					\
			}						\
			BUG_TRAP(patch.offset + patch.width <= len);	\
			/* printk("checking @ %p ", user_addr + patch.offset); */ \
			BUG_TRAP(memcmp(kernel_addr + patch.offset, &zero, patch.width) == 0); \
			memset(kernel_addr + patch.offset, 0, patch.width); \
		}							\
	}								\
	/* Finish off hmac */						\
	BUG_TRAP(len >= lastOffset);					\
	__copy_to_user(user_addr + lastOffset, kernel_addr + lastOffset, len - lastOffset); \
	if(IS_OUTPUT(DIR)) {						\
		hmac_update(hmac_ctx, (char*)kernel_addr + lastOffset, len - lastOffset); \
	}								\
}

GEN_COPY_PATCH_HMAC_UPDATE(in);
GEN_COPY_PATCH_HMAC_UPDATE(out);

static inline void arrayPatchGenerator(const void * const context, int num, struct patch_desc *patch) {
	struct patch_desc *array = (struct patch_desc*) context;
	*patch = array[num];
}

static inline void packetPatchGenerator(const void * const context, int num, struct patch_desc *patch) {
	patch->offset = num * sizeof(struct cminisock_packet) +
		OFFSET_OF(struct cminisock_packet, ucontData);
	patch->width = WIDTH_OF(struct cminisock_packet, ucontData);
}

struct DeferralContext {
#define MAX_NUM_DEFERRALS_PER_CONTEXT (16)
	int numDeferrals;
	int data[MAX_NUM_DEFERRALS_PER_CONTEXT];
	struct DeferralContext *next;
};

void DeferralContext_init(struct DeferralContext *ctx) {
	ctx->numDeferrals = 0;
	ctx->next = NULL;
}

void DeferralContext_free(struct DeferralContext *ctx) {
	if(ctx->next != NULL) {
		DeferralContext_free(ctx->next);
	}
	kfree(ctx);
}

int defer(struct DeferralContext *ctx, int value) {
	while(ctx->next != NULL) {
		BUG_TRAP(ctx->numDeferrals == MAX_NUM_DEFERRALS_PER_CONTEXT);
		ctx = ctx->next;
	}
	if(ctx->numDeferrals == MAX_NUM_DEFERRALS_PER_CONTEXT) {
		ctx->next = kmalloc(sizeof(struct DeferralContext), GFP_KERNEL);
		if(ctx->next == NULL) {
			printk("Out of memory while allocating deferral spillb lock\n");
			return -1;
		}
		ctx = ctx->next;
	}
	ctx->data[ctx->numDeferrals++] = value;
	return 0;
}

// Apply deferrals updates the HMAC with actual pointer information
void apply_deferrals(struct HMAC_CTX *hmac_ctx, struct DeferralContext *deferral_ctx) {
	BUG();
#if 0
	int first = 1;
	while(deferral_ctx != NULL) {
		hmac_update(hmac_ctx, (char *) &deferral_ctx->data[0],
			    deferral_ctx->numDeferrals * sizeof(deferral_ctx->data[0]));

		struct DeferralContext *toFree = deferral_ctx;
		deferral_ctx = deferral_ctx->next;
		if(!first) {
			kfree(toFree);
		}
		first = 0;
	}
#endif
}

// Support functions

// yes, this is a hack to avoid allocating on output instance
void *(* const tmalloc_helperout)(struct sock *sk, int len) = NULL;
void *(* const kmalloc_helperout)(struct sock *sk, int len) = NULL;

static inline void *tmalloc_helperin(struct sock *sk, int len) {
	printk("tmalloc_helperin'ing %d\n", len);
	return tmalloc(sk, len);
}

static inline void *kmalloc_helperin(struct sock *sk, int len) {
	//printk("kmalloc'ing %d\n", len);
	return kmalloc(len, GFP_KERNEL);
}

#define DEFERRED_HMAC(VALUE)						\
	do { if(defer(&deferral_ctx, (VALUE)) != 0) goto convert_error; } while(0)

#define RESERVE_COPY_PATCH_HMAC(DIR, ALLOC_FUNC, 	MSKTHINGO, LEN, DESC, DESCCTX, DESCLEN, PATCH_TYPE, PATCH_FIELD) \
	({								\
		if((LEN) == 0) {					\
			/* Do nothing */				\
		} else {						\
			int _len = (LEN);				\
			char *_dest_name = "user_" #MSKTHINGO;		\
			void *_tempdest = lbb_reserve(lbb, _len);	\
			if(_tempdest == NULL) {				\
				printk("result overflow - %s\n", _dest_name); \
				err = LBB_ERROR;			\
				goto convert_error;			\
			}						\
			if(ALLOC_FUNC ## DIR != NULL) {			\
				void *alloc_ptr = ALLOC_FUNC ## DIR(sk, LEN); \
				if(alloc_ptr == NULL) {			\
					printk("Out of memory ("#ALLOC_FUNC # DIR ") during copy_patch_hmac\n"); \
					err = LBB_ERROR;		\
					goto convert_error;		\
				}					\
				/* printk(#MSKTHINGO "("#ALLOC_FUNC # DIR ")  = %p\n", alloc_ptr);*/ \
				MSKTHINGO = alloc_ptr;			\
			}						\
			copy_patch_hmac_update_##DIR(hmac_ctx, _tempdest, (MSKTHINGO), \
						     _len, DESC, DESCCTX, DESCLEN); \
			if(IS_OUTPUT(DIR)) __put_user((char*)_tempdest - currStart, &((PATCH_TYPE*)_tempdest)->PATCH_FIELD); \
			/* DEFERRED_HMAC((char*)_tempdest - currStart); */ \
		}							\
	})

#ifdef DEBUG_LENGTHS
#define DUMP_DESCLEN() do { printk("desclen[%d] = %d\n", desclen_num++, desc_len - prevDescLen); prevDescLen = desc_len; } while(0)
#define DUMP_DELTA()				\
	do { printk("Delta[%d] = %d\n", deltaNum++, lbb_get_offset(lbb) - prevDeltaLen); prevDeltaLen = lbb_get_offset(lbb);} while(0)
#else

#define DUMP_DESCLEN()
#define DUMP_DELTA()

#endif

#undef DELAY
#define DELAY(X) do { int i; int j; volatile int counter = 0; for(i=0; i < (X); i++) for(j=0;j<100000000;j++) counter++; } while(0)

#define LBB_ERROR (-1)
#define MSK_ERROR (-2)
#define GEN_CONVERTMSK(DIR)						\
static ALWAYS_INLINE int convertMSK_##DIR(struct sock *sk, struct HMAC_CTX *hmac_ctx, struct cminisock *msk, struct linear_bounded_buffer *lbb, int *count) { \
	const int in = 1, out = 2;					\
	int i, err = 0;							\
	/* int prevDeltaLen = 0, deltaNum = 0, prevDescLen = 0, desclen_num = 0; */ \
	int startLen = lbb_get_offset(lbb);				\
	struct DeferralContext deferral_ctx;				\
	DeferralContext_init(&deferral_ctx);				\
									\
	/* Precompute length */						\
	int desc_len = -1;							\
	if(IS_OUTPUT(DIR)) {						\
		/* printk("output, precomputing desc_len\n"); */	\
		desc_len = sizeof(struct extract_mskdesc_out);		\
		DUMP_DESCLEN();						\
		desc_len += msk->ucont_len;				\
		DUMP_DESCLEN();						\
		desc_len += msk->input_len;				\
		DUMP_DESCLEN();						\
		desc_len += msk->num_packets * sizeof(struct cminisock_packet);	\
		DUMP_DESCLEN();						\
		for(i=0; i < msk->num_packets; i++) {			\
			desc_len += msk->packets[i].ucontLen;		\
		DUMP_DESCLEN();						\
		}							\
	}								\
									\
	/* Shared - reserve space for descriptor length */		\
	int *len = (int*)lbb_reserve(lbb, sizeof(int));		\
	char *currStart = (char*)len;					\
	struct cminisock *user_msk = (struct cminisock *)		\
		lbb_reserve(lbb, sizeof(*msk));			\
	if(currStart == NULL || user_msk == NULL) {			\
		printk(#DIR ": Result overflow on currStart or output_msk\n");	\
		err = LBB_ERROR;					\
		goto convert_error;					\
	}								\
	if(IS_OUTPUT(DIR)) {						\
		__put_user(desc_len, len);				\
		hmac_update(hmac_ctx, &desc_len, sizeof(desc_len)); \
		/* printk("output, inserting desc_len %d @ (%d,%p)\n", desc_len, lbb_get_pos(lbb), len); */  \
	} else {							\
		__get_user(desc_len, len);				\
		/* printk("input, extracting desc_len %d @ (%p,%d)\n", desc_len, lbb_get_pos(lbb), len); */ /* DELAY(1); */ \
	}								\
									\
	const struct patch_desc const mskPatchArray[] = {			\
		PATCH_FROM_FIELD(struct cminisock, sk),		\
		PATCH_FROM_FIELD(struct cminisock, ucont_data),		\
		PATCH_FROM_FIELD(struct cminisock, input),		\
		PATCH_FROM_FIELD(struct cminisock, packets)		\
	};								\
	DUMP_DELTA();								\
	copy_patch_hmac_update_##DIR(hmac_ctx, user_msk, msk, sizeof(*msk),  \
				     arrayPatchGenerator, mskPatchArray, ARRAY_LEN(mskPatchArray)); \
									\
	/* Copy ucont_data */						\
	RESERVE_COPY_PATCH_HMAC(DIR, tmalloc_helper, msk->ucont_data, \
				msk->ucont_len,				\
				NULL, NULL, 0,				\
				struct cminisock, ucont_data);		\
									\
	DUMP_DELTA();						\
	/* Copy input */						\
	RESERVE_COPY_PATCH_HMAC(DIR, tmalloc_helper, msk->input, \
				msk->input_len,				\
				NULL, NULL, 0,				\
				struct cminisock, input);		\
									\
	DUMP_DELTA();						\
	/* copy packets */						\
	int packets_len = msk->num_packets * sizeof(struct cminisock_packet); \
	RESERVE_COPY_PATCH_HMAC(DIR, tmalloc_helper, msk->packets, \
				packets_len, \
				packetPatchGenerator, NULL,		\
				msk->num_packets,			\
				struct cminisock, packets);		\
	DUMP_DELTA();						\
	/* Copy packets[*]->ucontData */				\
	for(i=0; i < msk->num_packets; i++) {				\
		RESERVE_COPY_PATCH_HMAC(DIR, kmalloc_helper, msk->packets[i].ucontData, \
					msk->packets[i].ucontLen,	\
					NULL, NULL, 0,			\
					struct cminisock_packet, ucontData); \
	DUMP_DELTA();						\
	}								\
									\
	if(IS_OUTPUT(DIR)) {						\
		/* FINALIZE */						\
		int check_len = lbb_get_offset(lbb) - startLen;			\
		if(!(desc_len == check_len)) { BUG_TRAP(desc_len == check_len); printk("%d %d\n", desc_len, check_len); } \
		__put_user(check_len, len);				\
	} else {							\
		int actual_len = lbb_get_offset(lbb) - startLen;			\
		int desc_len1;						\
		__get_user(desc_len1, len); BUG_TRAP(desc_len1 == desc_len); \
		if(!(desc_len == actual_len)) { BUG_TRAP(desc_len == actual_len); printk("%d %d\n", desc_len, actual_len); } \
	}								\
									\
	/* Apply deferrals -- Deferrals are not needed yet */			\
	/* apply_deferrals(hmac_ctx, &deferral_ctx); */			\
	(*count)++;							\
	if(0) { /* don't execute this code block except during exceptions */ \
	convert_error:							\
		if(deferral_ctx.next != NULL)				\
			DeferralContext_free(deferral_ctx.next);	\
		return -EINVAL;						\
	}								\
	return 0;							\
}

GEN_CONVERTMSK(in);
GEN_CONVERTMSK(out);

static inline
int extract_MSKs_from_lbb(struct sock *sk, struct alloc_head_list *new_msk_list,
			   struct HMAC_CTX *hmac_ctx,
			   struct linear_bounded_buffer *lbb);


static inline void msk_force_free(struct sock *sk, struct cminisock *msk) {
	printk("msk_force_free users not updated to pmsk\n");
	BUG();
	msk->ctl = ALLOC_READY;
	free_trickles_msk(sk,msk);
	free_trickles_msk_finish(sk,msk);
 }

#ifdef CHECK_INVALID
#define CHECK_INVALID_0()					\
	int origInvalidCount = analyze_msk_list_helper(sk, 0);

#define CHECK_INVALID_1()						\
	do { int newInvalidCount = analyze_msk_list_helper(sk, 0);	\
	if(newInvalidCount > 0 || origInvalidCount > 0) {		\
		printk("Invalid counts @ %d: %d=>%d\n", __LINE__, origInvalidCount, newInvalidCount); \
	} } while(0);
#else
#define CHECK_INVALID_0()
#define CHECK_INVALID_1()
#endif


/* "Ideal" Error semantics
   If error occurs due to lack of space in output, then the output is guaranteed to be in a usable state
   E.g., hmac and msk_collection are valid for the truncated output

   - Unfortunately, this is challenging to do efficiently given the way HMAC is computed. Punt.
*/
int trickles_extract_events_impl(int fd, struct extract_mskdesc_in *descbuf, int descbuf_len, struct msk_collection *dest, int *destLen) {
	printk("Not updated to use pmsk\n");
	BUG();

	int hitFreeLoop = 0;
	/*
	   1. For each descbuf
	      a. Verify MD5
	      b. Allocate msk and tmalloc() structures
	      c. Link into event list
	*/
	struct socket *sock;
	struct sock *sk = NULL;
	struct tcp_opt *tp;
	int err;
	int hmac_input_len;

	if(descbuf_len <= 0) {
		err = -EINVAL;
		goto out;
	}

	sock = sockfd_lookup(fd, &err);
	if (!sock)
		goto out;

	sk = sock->sk;

	lock_sock(sk);

	if(!IS_TRICKLES_SERVER(sk)) {
		printk("Not trickles server\n");
		err = -EINVAL;
		goto out_put;
	}

	tp = &(sk->tp_pinfo.af_tcp);
	CHECK_INVALID_0();

	int origFreeLen = tp->cminisock_api_config.msk_freelist.len;

	if(!access_ok(VERIFY_READ, descbuf, descbuf_len)) {
		printk("descbuf not readable\n");
		err = -EFAULT;
		goto out_put;
	}
	if(!access_ok(VERIFY_WRITE, dest, *destLen)) {
		printk("destination not writable\n");
		err = -EFAULT;
		goto out_put;
	}

	struct linear_bounded_buffer lbb = {
		start : (char*)dest,
		curr : (char*)dest,
		limit : *destLen
	};


	struct extract_mskdesc_in *currentInputDesc = descbuf;
	struct msk_collection *outputCollection = dest;
	lbb_reserve(&lbb, sizeof(struct msk_collection));

	char hmac[HMACLEN];
	struct HMAC_CTX hmac_ctx = *tp->t.hmacCTX;
	hmac_init(&hmac_ctx);

	*destLen = 0;
	int numCopies = 0;
	/* N.B.
	   All embedded pointer offsets are appended to HMAC
	   Initially, pointer offsets are populated as 0
	*/
	while((char*)currentInputDesc -  (char*) descbuf < descbuf_len) {
		struct extract_mskdesc_in mskdesc;
		__copy_from_user(&mskdesc, currentInputDesc, sizeof(mskdesc));
		struct cminisock *msk = mskdesc.msk;

		//printk("Requesting msk=%p & %p\n", msk, &currentInputDesc->msk);

		if(!IS_VALID_MSK(sk,msk)) {
			printk("Invalid msk in descbuf list, %d %d\n", IS_TRICKLES_SOCK_ADDR(tp,(msk)), IS_TRICKLES_SOCK_ADDR(tp,(msk)) && VALID_MSK_CTL((msk)));
			err = -EINVAL;
			goto out_put;
		}
		if(msk->ctl != ALLOC_READY) {
			printk("Only alloc_ready packets are allowed to be extracted. alloc_halffree packets have no convenient access path on the destination\n");
			err = -EINVAL;
			goto out_put;
		}
		if(mskdesc.operation & EVENT_COPYOUT) {
			//char *start_pos = lbb_get_pos(&lbb);
			if((err = convertMSK_out(sk, &hmac_ctx, msk, &lbb, &numCopies)) != 0) {
				printk("Output conversion failed\n");
				if(err == LBB_ERROR) {
					printk("Better output error semantics (valid truncation) not implemented!\n");
#if 0
					lbb.curr = start_pos;
					goto truncated_output;
#else
					goto out_put;
#endif
				}
				BUG_TRAP(err == MSK_ERROR);
				if(err == MSK_ERROR) {
					goto out_put;
				}
			}
		}

		if(mskdesc.operation & EVENT_UNLINK) {
			free_trickles_msk(sk,msk);
			msk->ctl = ALLOC_HALFFREE;
		}
		if(mskdesc.operation & EVENT_DEALLOC) {
			if(msk->ctl != ALLOC_HALFFREE) {
				printk("Dealloc called on an msk that is not half-freed\n");
				err = -EINVAL;
				goto out_put;
			}
			free_trickles_msk_finish(sk,msk);
		}
		currentInputDesc = MSKDESC_IN_NEXT(currentInputDesc);
	}
	goto truncated_output; // suppress error
 truncated_output:

	hmac_input_len = hmac_ctx.len;
	hmac_final(&hmac_ctx, hmac);
	__copy_to_user(outputCollection->hmac, hmac, HMACLEN);
	outputCollection->len = *destLen = lbb.curr - lbb.start;

	CHECK_INVALID_1();

#if 1 // instant self-test

	printk("Starting instant self-test\n");

	int test_numIn;
	struct alloc_head_list new_msk_list;
	init_head(&new_msk_list);

	lbb.limit = lbb_get_offset(&lbb);
	lbb.curr = lbb.start;

	BUG_TRAP(lbb_get_offset(&lbb) == 0);
	struct msk_collection *inputCollection = (struct msk_collection *)lbb_reserve(&lbb, sizeof(struct msk_collection));
	EQ_TEST(inputCollection, outputCollection);

	struct HMAC_CTX test_hmac_ctx = *tp->t.hmacCTX;
	char test_hmac[HMACLEN];
	//int test_hmac_input_len0 = lbb_get_end(&lbb) - lbb_get_pos(&lbb);

	char *hmac_start = lbb_get_pos(&lbb);
	int hmac_len = lbb_get_end(&lbb) - lbb_get_pos(&lbb);
	hmac_init(&test_hmac_ctx);
	hmac_update(&test_hmac_ctx, hmac_start, hmac_len);
	//int test_hmac_input_len = test_hmac_ctx.len;
	hmac_final(&test_hmac_ctx, test_hmac);

	printk("instant Hmac computed on %d @%p\n", hmac_len, hmac_start);

	int memcmp_result = memcmp(test_hmac, hmac, HMACLEN);
	EQ_TEST(memcmp_result, 0);

#if 0
	printk("TEST_HMAC %d %d\n", test_hmac_input_len0, test_hmac_input_len);
	hexdump(test_hmac, HMACLEN);
	printk("\n");
	printk("HMAC  %d\n", hmac_input_len);
	hexdump(hmac, HMACLEN);
	printk("\n");
#endif

	if((test_numIn = extract_MSKs_from_lbb(sk, &new_msk_list, &test_hmac_ctx, &lbb)) < 0) {
		printk("test_numIn < 0: %d\n", test_numIn);
	} else {
		EQ_TEST(test_numIn, numCopies);
		EQ_TEST(new_msk_list.len, test_numIn);
	}

	hitFreeLoop = 1;
	if(new_msk_list.len > 0) {
		while(new_msk_list.len > 0) {
			struct cminisock *toFree = (struct cminisock *)new_msk_list.next;
			BUG_TRAP(toFree != (struct cminisock*)&new_msk_list);
			msk_force_free(sk, toFree);
			//printk("post free len = %d %d\n", new_msk_list.len, tp->cminisock_api_config.msk_freelist.len);
		}
	}
#endif

	err = numCopies;
 out_put:
	release_sock(sk);
	sockfd_put(sock);
 out:
	if(sk) {
		printk("FreeLoop(%d %d) After extract free list length %d=>%d\n", hitFreeLoop, err, origFreeLen, tp->cminisock_api_config.msk_freelist.len);
		CHECK_INVALID_1();
	}
	return err;
}

#define CHECK_RESERVE_SUCCESS(VAR) do {					\
	if((VAR) == NULL) {						\
		printk("install_event -- descbuf too short for " #VAR "\n"); \
		err = -EINVAL;						\
		goto out_put;						\
	}								\
} while(0)


// trickles_install_events_impl can handle multiple consecutive collections

#define MSK_IS_ON_VALID_LIST(TP,MSK)				\
	((MSK)->list == &(TP)->cminisock_api_config.msk_freelist ||		\
	 (MSK)->list == &(TP)->cminisock_api_config.cfg.ctl->msk_eventlist)

int trickles_install_events_impl(int fd, struct msk_collection *descbuf, int descbuf_len) {
	// 0228 Disabled because it was not updated during pmsk optimization
	printk("Not updated to use pmsk\n");
	BUG();
	struct socket *sock;
	struct sock *sk = NULL;
	struct tcp_opt *tp;
	int err = -1;

	struct alloc_head_list new_msk_list;
	init_head(&new_msk_list);

	if(descbuf_len <= 0) {
		err = -EINVAL;
		goto out;
	}

	sock = sockfd_lookup(fd, &err);
	if (!sock) {
		err = -EINVAL;
		goto out;
	}

	sk = sock->sk;
	lock_sock(sk);

	if(!IS_TRICKLES_SERVER(sk)) {
		printk("Not trickles server\n");
		err = -EINVAL;
		goto out_put;
	}

	tp = &(sk->tp_pinfo.af_tcp);
	int origFreeLen = tp->cminisock_api_config.msk_freelist.len;

	CHECK_INVALID_0();

	if(!access_ok(VERIFY_READ, descbuf, descbuf_len)) {
		printk("descbuf not readable\n");
		err = -EFAULT;
		goto out_put;
	}

	char *inputPosition = (char*)descbuf;
	int numCollections = 0;
	int totalNumIn = 0;
	printk("Input position = %p, length = %d\n", descbuf, descbuf_len);
	while(inputPosition < (char*)descbuf + descbuf_len) {
		int remaining = descbuf_len - (inputPosition - (char*)descbuf);
		printk("remaining = %d, %p %p\n", remaining, inputPosition, (char*)descbuf + descbuf_len);
		struct linear_bounded_buffer lbb = {
			start : (char*)inputPosition,
			curr : (char*)inputPosition,
			limit : remaining
		};
		struct msk_collection *inputCollection = (struct msk_collection *)lbb_reserve(&lbb, sizeof(struct msk_collection));
		CHECK_RESERVE_SUCCESS(inputCollection);
		//printk("passed reserve success, remaining = %d\n", remaining);
		BUG_TRAP(&inputCollection->descs[0] == lbb_get_pos(&lbb));

		int collectionLen;
		//printk("Address of input collection length = %p\n", &inputCollection->len);

		__get_user(collectionLen, &inputCollection->len);
		if(inputPosition + collectionLen > (char*)descbuf + descbuf_len) {
			printk("Not enough space for collection %d\n", numCollections);
			err = -EINVAL;
			goto out_put;
		}
		lbb.limit = collectionLen;
		//printk("collectionLen = %d\n", collectionLen);

		int numIn;

		char input_hmac[HMACLEN];
		__copy_from_user(input_hmac, inputCollection->hmac, HMACLEN);

		struct HMAC_CTX hmac_ctx = *tp->t.hmacCTX;
		char hmac[HMACLEN];
		char *hmac_start = lbb_get_pos(&lbb);
		int hmac_len = lbb_get_end(&lbb) - lbb_get_pos(&lbb);
		hmac_init(&hmac_ctx);
		hmac_update(&hmac_ctx, hmac_start, hmac_len);
		hmac_final(&hmac_ctx, hmac);

		//printk("Input hmac computed on %d @%p\n", hmac_len, hmac_start);

		if(memcmp(hmac, input_hmac, HMACLEN) != 0) {
			printk("input_events[%d]: Hmac verify failed\n", numCollections);
			err = -EINVAL;
			goto out_put;
		}
		if((numIn = extract_MSKs_from_lbb(sk, &new_msk_list, &hmac_ctx, &lbb)) < 0) {
			printk("Could not extract msks\n");
			err = -EINVAL;
			goto out_put;
		}
		numCollections++;
		inputPosition += collectionLen;
		BUG_TRAP(inputPosition == lbb_get_pos(&lbb));
		totalNumIn += numIn;
	}
	printk("%d collections processed\n", numCollections);

	// List header handling is tricky. We need to put the msk on the right list depending on its current state
	while(new_msk_list.len > 0) {
		struct cminisock *relink = (struct cminisock *)new_msk_list.next;
		BUG_TRAP(relink != (struct cminisock*)&new_msk_list);
		unlink((struct alloc_head*)relink);

		relink->sk = sk;
		BUG_TRAP(IS_VALID_MSK(sk, relink));
		switch(relink->ctl) {
		case ALLOC_READY:
			insert_tail(&tp->cminisock_api_config.cfg.ctl->msk_eventlist, (struct alloc_head *)relink);
			new_event(sk);
			break;
		case ALLOC_HALFFREE:
			printk("No reliable access path to halffree msks!!!\n");
			BUG();
			// don't re-insert on list
			break;
		default:
			printk("Unhandled ctl state %d in installed event\n", relink->ctl);
			// can't use msk_force_free because we aren't on any list
			free_trickles_msk_finish(sk,relink);
			err = -EINVAL;
			goto out_put;
		}
		if(!MSK_IS_ON_VALID_LIST(tp,relink)) {
			printk("Relink Msk %p not on valid list (list = %p)\n", relink, relink->list);
		}
	}
	err = totalNumIn;
 out_put:
	release_sock(sk);
	sockfd_put(sock);
 out:
	if(sk) {
		printk("New_msk_list = %p\n", &new_msk_list);
		if(new_msk_list.len > 0) {
			printk("Freeing msk still on new_msk_list %d\n", new_msk_list.len);
			while(new_msk_list.len > 0) {
				struct cminisock *toFree = (struct cminisock *)new_msk_list.next;
				BUG_TRAP(toFree != (struct cminisock*)&new_msk_list);

				if(toFree->list != &new_msk_list) {
					printk("toFree Msk %p not on new_msk_list\n", toFree);
				}

				msk_force_free(sk,toFree);
				//printk("post free len = %d %d\n", new_msk_list.len, tp->cminisock_api_config.msk_freelist.len);
				BUG_TRAP(toFree->list == &tp->cminisock_api_config.msk_freelist);
			}
		}
		printk("Free list length %d\n", tp->cminisock_api_config.msk_freelist.len);
		printk("After insert free list length %d=>%d\n", origFreeLen, tp->cminisock_api_config.msk_freelist.len);

		CHECK_INVALID_1();
	}
	return err;
}

int trickles_request_impl(int fd, char *buf, int buf_len, int reserved_len) {
	struct socket *sock;
	struct sock *sk;
	struct tcp_opt *tp;
	int err;

	sock = sockfd_lookup(fd, &err);
	if (!sock)
		goto out;

	sk = sock->sk;
	tp = &(sk->tp_pinfo.af_tcp);

	lock_sock(sk);
	if(!((tp->trickles_opt & TCP_TRICKLES_ENABLE) &&
	   !(tp->trickles_opt & TCP_TRICKLES_RSERVER) && 
	     (tp->trickles_opt & TCP_TRICKLES_PAR_REQUEST))) {
		printk("Socket not configured -- %d\n", tp->trickles_opt);
		err = -EINVAL;
		goto out_release;
	}


	struct sk_buff *skb = alloc_skb(buf_len, GFP_KERNEL);
	if((err = copy_from_user(skb_put(skb, buf_len), buf, buf_len))) {
		goto out_release;
	}
	TCP_SKB_CB(skb)->seq = 0;
	TCP_SKB_CB(skb)->end_seq = TCP_SKB_CB(skb)->seq + skb->len;

#if 0
{
	char transfer_buf[1024];
	memcpy(transfer_buf, skb->data, buf_len);
	transfer_buf[buf_len] = 0;
	printk("Transfered request string %s (%d)\n", transfer_buf, buf_len);
}
#endif
	 if((err = CompleteRequest_parallel_queue(sk, skb, reserved_len))) {
		 goto out_release;
	 }
	 pushRequests(sk);

 out_release:
	release_sock(sk);
	if(sk->backlog.tail) {
		printk("have backlog\n");
	}
 out_put:
	sockfd_put(sock);
 out:
	return err;
}

static inline
int extract_MSKs_from_lbb(struct sock *sk, struct alloc_head_list *new_msk_list,
			   struct HMAC_CTX *hmac_ctx,
			   struct linear_bounded_buffer *lbb) {
	int err;
	char *desc_end = lbb_get_end(lbb);
	int numIn = 0;

	while((char*)lbb_get_pos(lbb) < desc_end) {
		//printk("At %p < %p,%d:  ", lbb_get_pos(lbb), desc_end, lbb_get_offset(lbb));

		int foo;
		struct cminisock *msk = alloc_trickles_msk(sk);
		if(msk == NULL) {
			printk("could not allocate msk\n");
			err = -ENOMEM;
			goto out_put;
		}
		if(convertMSK_in(sk, NULL, msk, lbb, &foo) != 0) {
			printk("Input conversion failed\n");
			/* TRICKY! At this point msk header pointers have not yet been adjusted */
			msk->prev = NULL;
			msk->next = NULL;
			msk->list = NULL;

			// can't use msk_force_free because we aren't on any list
			free_trickles_msk_finish(sk,msk);
			err = -EINVAL;
			goto out_put;
		}
		msk->prev = NULL;
		msk->next = NULL;
		msk->list = NULL;
		insert_tail(new_msk_list, (struct alloc_head*)msk);
		numIn++;
	}

	char *actual_end = lbb_get_pos(lbb);
	BUG_TRAP(actual_end <= desc_end);
	if(actual_end != desc_end) {
		printk("actual end of descbuf does not match param passed by client: %p %p\n",
		       actual_end, desc_end);
	}
	return numIn;
 out_put:
	return err;
}

static inline int analyze_msk_list_helper(struct sock *sk, int print) {
	int numInvalid = 0;
	if(IS_TRICKLES_SERVER(sk)) {
		struct tcp_opt *tp = &(sk->tp_pinfo.af_tcp);
		struct trickles_mmap_ctl *ctl = tp->cminisock_api_config.cfg.ctl;
		struct cminisock *msk;

		void *freeList = &tp->cminisock_api_config.msk_freelist;
		void *eventList = &ctl->msk_eventlist;
		for(msk = ctl->minisock_base; (void*)(msk+1) < (void*)ctl->minisock_limit; msk++) {
			char *listName = "UnknownList";
			char *ctlName = "UnknownCtl";
			if(msk->list == freeList) {
				listName = "FreeList";
			} else if(msk->list == eventList) {
				listName = "EventList";
			} else {
				numInvalid++;
			}
#define CTL_MAP(NAME) case NAME: ctlName = #NAME; break;
			switch(msk->ctl) {
				CTL_MAP(ALLOC_FREE);
				CTL_MAP(ALLOC_READY);
				CTL_MAP(ALLOC_PENDING);
				CTL_MAP(ALLOC_PROCESSING);
				CTL_MAP(ALLOC_HALFFREE);
			}
			if(print)
				printk("MSK(%p %s) is on %s (%p)\n", msk, ctlName,
				       listName, msk->list);
		}
	}
	return numInvalid;
}

void analyze_msk_list(struct sock *sk) {
#if 0
	analyze_msk_list_helper(sk, 1);
#endif
}
#endif // USERTEST
