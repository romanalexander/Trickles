#ifndef TRICKLES_PACKET_HELPERS_H
#define TRICKLES_PACKET_HELPERS_H

#include "cminisock.h"
#include "trickles_state_cache.h"

#ifdef __KERNEL__

#define HNCONVERTLONG(X) dcont->X = htonl(scont->X)
#define CONVERSION_MAP_SIZE (3)


#define MARSHALL_PACKET_FIELDS(DCONT, SCONT, PKTNUM, BCONV)			\
({									\
	 \
    /* server side */							\
    (DCONT)->seq = BCONV((SCONT)->packets[PKTNUM].seq);			\
    /* printk("(DCONT)->seq = %d\n", ntohl((DCONT)->seq)); */		\
    (DCONT)->continuationType = (SCONT)->packets[PKTNUM].contType;	\
    if((SCONT)->packets[PKTNUM].type & PTYPE_FIRST) {			\
      (DCONT)->firstChild = 1;						\
    } else {								\
      (DCONT)->firstChild = 0;						\
    }									\
									\
    static const int stateConversionMap[] = {				\
      /* 0 */ 0,							\
      /* 1 */ 1,							\
      /* 2 */ 2 };							\
    int conversionOffset = (SCONT)->packets[PKTNUM].type & PTYPE_STATEMASK; \
    if(conversionOffset >= CONVERSION_MAP_SIZE) {			\
      BUG();								\
    }									\
    (DCONT)->state = stateConversionMap[conversionOffset];		\
})

#define MARSHALL_CONTINUATION(SUFFIX,SERVER_SIDE,COMPUTE_MAC)		\
static inline void marshallContinuation ## SUFFIX(struct sock *sk, WireContinuation *dcont, const CONTINUATION_TYPE *scont, int pktNum) { \
  dcont->clientState = scont->clientState;				\
  dcont->parent = scont->parent;					\
									\
  if(SERVER_SIDE) {							\
	  MARSHALL_PACKET_FIELDS(dcont, scont, pktNum, htonl);		\
    dcont->timestamp = htonl(scont->timestamp);				\
    dcont->clientTimestamp = scont->clientTimestamp;			\
    dcont->mrtt = htonl(scont->mrtt);					\
  } else {								\
    /* client side */							\
    HNCONVERTLONG(seq);							\
									\
    dcont->continuationType = scont->continuationType;			\
    dcont->firstChild = scont->firstChild;				\
									\
    dcont->state = scont->state;					\
									\
    dcont->timestamp = scont->rawTimestamp;				\
    dcont->clientTimestamp = scont->clientTimestamp;			\
    dcont->mrtt = scont->rawMrtt;					\
  }									\
  /* printk("marshall - firstLoss: %p\n", &dcont->firstLoss); */	\
  HNCONVERTLONG(firstLoss);						\
  HNCONVERTLONG(firstBootstrapSeq);					\
  HNCONVERTLONG(startCwnd);						\
  HNCONVERTLONG(ssthresh);						\
  HNCONVERTLONG(TCPBase);						\
									\
  dcont->tokenCounterBase = scont->tokenCounterBase;			\
									\
  /* todo: compute MAC */						\
  COMPUTE_MAC();							\
}

#define MAC_GEN_PHDR()					\
	  phdr->seq = dcont->seq;			\
	  phdr->type = dcont->continuationType;		\
	  phdr->first = dcont->firstChild ? 1 : 0;	\
	  phdr->serverAddr = scont->saddr;		\
	  phdr->serverPort = scont->source;		\
	  phdr->clientAddr = scont->daddr;		\
	  phdr->clientPort = scont->dest

#define SERVER_COMPUTE_MAC()				\
  do {							\
	  PseudoHeader hdr, *phdr = &hdr;		\
	  MAC_GEN_PHDR();				\
	  computeMAC(sk, phdr, dcont, dcont->mac);	\
} while(0)
#define CLIENT_COMPUTE_MAC()			\
  do{						\
    memcpy(dcont->mac, scont->mac, HMACLEN);	\
  } while(0)

MARSHALL_CONTINUATION(Server, 1, SERVER_COMPUTE_MAC)
MARSHALL_CONTINUATION(ServerCopyMAC, 1, CLIENT_COMPUTE_MAC)
MARSHALL_CONTINUATION(Client, 0, CLIENT_COMPUTE_MAC)
#undef SERVER_COMPUTE_MAC
#undef CLIENT_COMPUTE_MAC
#undef HNCONVERTLONG

static inline void marshallAckProof(WireAckProof *dproof, const AckProof *sproof) {
#define HNCONVERTLONG(X) dproof->X = htonl(sproof->X);
#define COPYLONG(X) dproof->X = sproof->X
  int i;
  dproof->numSacks = MIN(sproof->numSacks, MAXSACKS);
  for(i=0; i < dproof->numSacks; i++) {
    HNCONVERTLONG(sacks[i].left);
    HNCONVERTLONG(sacks[i].right);
    COPYLONG(sacks[i].nonceSummary);
  }
#undef HNCONVERTLONG
#undef COPYLONG
}

#define NHCONVERTLONG(X) dcont->X = ntohl(scont->X);
#define COPYLONG(X) dcont->X = scont->X

struct sk_buff;

/* skb is used to initialize connection endpoint variables */


#define UNMARSHALL_CONTINUATION(SUFFIX, ARGS, TIMESTAMP_H, FLOW_H, INITIALIZE_H, CONVERTLONG, COMPUTE_MAC) \
static inline int unmarshallContinuation ## SUFFIX(ARGS) { \
    COMPUTE_MAC();							\
  dcont->continuationType = scont->continuationType;			\
  CONVERTLONG(seq); /* printk("dcont->seq = %d\n", dcont->seq); */	\
									\
  dcont->clientState = scont->clientState;				\
  dcont->parent = scont->parent;					\
									\
  TIMESTAMP_H();							\
  dcont->clientTimestamp = scont->clientTimestamp;			\
  dcont->state = scont->state;						\
  dcont->firstChild = scont->firstChild;				\
									\
  /* printk("unmarshall - firstLoss: %p\n", &dcont->firstLoss); */	\
  CONVERTLONG(firstLoss);						\
  CONVERTLONG(firstBootstrapSeq);					\
  CONVERTLONG(startCwnd);						\
  CONVERTLONG(ssthresh);						\
  CONVERTLONG(TCPBase);						\
									\
  FLOW_H();								\
  dcont->tokenCounterBase = scont->tokenCounterBase;			\
									\
  INITIALIZE_H();							\
									\
  return 1;								\
}

#define MAC_VERIFY_PHDR()			\
	phdr->seq = scont->seq;					\
	phdr->type = scont->continuationType;			\
	phdr->first = scont->firstChild;			\
	phdr->serverAddr = skb->nh.iph->daddr;			\
	phdr->serverPort = skb->h.th->dest;			\
	phdr->clientAddr = skb->nh.iph->saddr;			\
	phdr->clientPort = skb->h.th->source

#define SERVER_COMPUTE_MAC()			\
do {						\
    if(unlikely(!SIMULATION_MODE(skb->sk))) {	\
	    char mac[HMACLEN];						\
	    PseudoHeader hdr, *phdr = &hdr;				\
	    MAC_VERIFY_PHDR();						\
									\
	    computeMAC(skb->sk, phdr, scont, mac);			\
	    if(memcmp(mac, scont->mac, HMACLEN)) {			\
		    printk("failed hmac comparison\n"); return 0;	\
	    }								\
    }						\
} while(0);

#define CLIENT_COMPUTE_MAC()			\
  do {					\
    memcpy(dcont->mac, scont->mac, HMACLEN);	\
  } while(0)

#define DONT_COMPUTE_MAC()

#define MSK_ARGS \
	struct sk_buff *skb, struct cminisock *dcont, const WireContinuation *scont

#define PMSK_ARGS \
	struct sk_buff *skb, struct pminisock *dcont, const WireContinuation *scont

#define PMSK2MSK_ARGS \
	struct sock *sk, struct cminisock *dcont, struct pminisock *scont

#define MSK2PMSK_ARGS \
	struct sock *sk, struct pminisock *dcont, struct cminisock *scont

#define MSK_TIMESTAMP()				\
	dcont->rawTimestamp = scont->timestamp;	\
	dcont->timestamp = ntohl(scont->timestamp);	\
	dcont->rawMrtt = scont->mrtt;			\
	dcont->mrtt = ntohl(scont->mrtt);

#define PMSK_TIMESTAMP()			\
	dcont->rawTimestamp = scont->timestamp;	\
	dcont->rawMrtt = scont->mrtt;

#define PMSK2MSK_TIMESTAMP()				\
	COPYLONG(rawTimestamp);			\
	dcont->timestamp = ntohl(scont->rawTimestamp);	\
	COPYLONG(rawMrtt);				\
	dcont->mrtt = ntohl(scont->rawMrtt);		\
	dcont->tag = scont->tag

#define MSK2PMSK_TIMESTAMP()				\
	COPYLONG(rawTimestamp);			\
	COPYLONG(rawMrtt);			\
	dcont->tag = scont->tag

// Flow unmarshall code -- wired to MSK. Still required for client-side

#define MSK_FLOW()						\
  if(unlikely(!SIMULATION_MODE(skb->sk))) {			\
	  dcont->saddr = skb->nh.iph->daddr;				\
	  dcont->daddr = skb->nh.iph->saddr;				\
	  dcont->source = skb->h.th->dest;				\
	  dcont->dest = skb->h.th->source;				\
  }

// To save space, only the remote endpoint identifiers are saved
#define PMSK_FLOW()				\
	dcont->daddr = skb->nh.iph->saddr;	\
	dcont->dest = skb->h.th->source;
	
#define PMSK2MSK_FLOW()						\
	dcont->saddr = sk->saddr;					\
	dcont->source = sk->sport;					\
	dcont->daddr = scont->daddr;					\
	dcont->dest = scont->dest;

#define MSK2PMSK_FLOW()						\
	COPYLONG(daddr);					\
	COPYLONG(dest);

#define MSK_INITIALIZE()			\
	dcont->num_packets = 0;						\
	dcont->numChildrenReceived = 0;					\
	dcont->parentMSK = NULL;

#define PMSK_INITIALIZE()			\
	dcont->num_packets = 0;
	/* no actions */

#define PMSK2MSK_INITIALIZE() PMSK_INITIALIZE() ; \
	dcont->pmsk = scont;				\
	dcont->num_packets = scont->num_packets;	\
	dcont->ucont_data = scont->ucont_data;		\
	dcont->ucont_len = scont->ucont_len;		\
	dcont->input = scont->input;			\
	dcont->input_len = scont->input_len;	\
	dcont->packets = scont->packets;

#define MSK2PMSK_INITIALIZE() PMSK_INITIALIZE() ;	\
	dcont->num_packets = scont->num_packets;	\
	dcont->ucont_data = scont->ucont_data;		\
	dcont->ucont_len = scont->ucont_len;		\
	dcont->input = scont->input;			\
	dcont->input_len = scont->input_len;	\
	dcont->packets = scont->packets;

UNMARSHALL_CONTINUATION(ServerMSK, 
			MSK_ARGS, 
			MSK_TIMESTAMP, 
			MSK_FLOW, 
			MSK_INITIALIZE, 
			NHCONVERTLONG, SERVER_COMPUTE_MAC);

UNMARSHALL_CONTINUATION(ServerPMSK, 
			PMSK_ARGS, 
			PMSK_TIMESTAMP, 
			PMSK_FLOW, 
			PMSK_INITIALIZE, 
			NHCONVERTLONG, SERVER_COMPUTE_MAC);

UNMARSHALL_CONTINUATION(ServerPMSK2MSK, 
			PMSK2MSK_ARGS, 
			PMSK2MSK_TIMESTAMP, 
			PMSK2MSK_FLOW,
			PMSK2MSK_INITIALIZE, 
			COPYLONG, DONT_COMPUTE_MAC);

UNMARSHALL_CONTINUATION(ServerMSK2PMSK, 
			MSK2PMSK_ARGS, 
			MSK2PMSK_TIMESTAMP, 
			MSK2PMSK_FLOW,
			MSK2PMSK_INITIALIZE, 
			COPYLONG, DONT_COMPUTE_MAC);

UNMARSHALL_CONTINUATION(Client, 
			MSK_ARGS, 
			MSK_TIMESTAMP, 
			MSK_FLOW, 
			MSK_INITIALIZE, 
			NHCONVERTLONG, CLIENT_COMPUTE_MAC);

// whew

#undef SERVER_COMPUTE_MAC
#undef CLIENT_COMPUTE_MAC
#undef NHCONVERTLONG
#undef COPYLONG

extern int numContinuations;

#ifndef USERTEST
extern kmem_cache_t *clientSideContinuation_cache;
#endif


// Simulation accessors
#define SIMULATION_PACKETS(CONT)  (((CONT)+1)->packets)
#define SIMULATION_NUM_PACKETS(CONT)  (((CONT)+1)->num_packets)

static inline int SIMULATION_TOTAL_LEN(struct cminisock *cont) {
	int i;
	int total = 0;

	for(i=0; i < SIMULATION_NUM_PACKETS(cont); i++) {
		total += SIMULATION_PACKETS(cont)[i].len;
	}

	return total;
}

#define ENCODE_SIMULATION_RESULT(CONT)		\
	((SIMULATION_TOTAL_LEN(CONT) & 0xffff) |	\
	 SIMULATION_NUM_PACKETS(CONT) << 16)

static inline void DECODE_SIMULATION_RESULT(__u32 value, int *pTotalLen, int *pNumPackets) {
	*pTotalLen = value & 0xffff;
	*pNumPackets = (value >> 16) & 0xffff;
}

#define USESLAB
#define INIT2

#define CLIENTSIDE_CONTINUATION_SIZE (2 * sizeof(CONTINUATION_TYPE))
static inline CONTINUATION_TYPE *newClientSide_Continuation(int flags) {
  int i;
#ifdef USERTEST
  CONTINUATION_TYPE *rval = kmalloc(CLIENTSIDE_CONTINUATION_SIZE, flags);
#else
  CONTINUATION_TYPE *rval = kmem_cache_alloc(clientSideContinuation_cache, GFP_ATOMIC);
#endif

#ifdef DEBUG_TRICKLES_ALLOCATION // 0418
  numContinuations++;
#endif

  if(rval == NULL) {
    printk("out of memory while allocating continuation\n");
    return NULL;
  }

  rval->prev = rval->next = NULL;
  rval->list = NULL;
#ifdef INIT2 // 0502 - initialize only the first one (simulation is off)
  for(i=0; i < 2; i++) {
#else
  for(i=0; i < 1; i++) {
#endif
	  (rval+i)->ucont_len = 0;
	  (rval+i)->ucont_data = NULL;
	  (rval+i)->input_len = 0;
	  (rval+i)->input = NULL;
	  // 0429 null mark
	  (rval+i)->mark = 0;
	  (rval+i)->simulated = 0;
  }
  rval->sk = NULL;
  return rval;
}

static inline void *kmalloc_dup(void *src, int len, unsigned gfp) {
	char *ptr = kmalloc(len, gfp);
	if(ptr == NULL) {
		printk("out of memory in kmalloc_dup\n");
		return NULL;
	}
	memcpy(ptr, src, len);
	return ptr;
}

static inline CONTINUATION_TYPE *
copyClientSide_Continuation(CONTINUATION_TYPE *cont, int flags) {
  int i;
#ifdef USERTEST
  CONTINUATION_TYPE *rval = kmalloc(2 * sizeof(CONTINUATION_TYPE), flags);
#else  //0426 - change kernel to slab cache
  CONTINUATION_TYPE *rval = kmem_cache_alloc(clientSideContinuation_cache, GFP_ATOMIC);
#endif

#ifdef DEBUG_TRICKLES_ALLOCATION // 0418
  numContinuations++;
#endif

  // 0501 - attempting to track down corruption bug
#ifdef DEBUG_ALLOC
#ifndef USERTEST
  if(((int)rval) & 0xfff) {
	  printk("incorrect alignment\n");
	  BUG();
  }
#endif // USERTEST
#endif // DEBUG_ALLOC

  if(rval == NULL) {
    printk("out of memory while allocating continuation to copy\n");
    return NULL;
  }
  rval->prev = rval->next = NULL;
  rval->list = NULL;

  memcpy(rval, cont, (int)((CONTINUATION_TYPE *)0)->clientside_copy_end);
  for(i=0; i < 2; i++) {
#if 0 // 0812 - copy makes the code very slow, so rewrite to avoid the copy
	  (rval+i)->ucont_len = (cont+i)->ucont_len;
	  char *src_ucont = (cont+i)->ucont_data;
	  if(src_ucont != NULL) {
		  (rval+i)->ucont_data = kmalloc_dup(src_ucont, (rval+i)->ucont_len, GFP_ATOMIC);
	  } else {
		  (rval+i)->ucont_data = NULL;
	  }
#else
	  (rval+i)->ucont_len = 0;
	  (rval+i)->ucont_data = NULL;
#endif

	  (rval+i)->simulated = 0;

	  (rval+i)->input_len = 0;
	  (rval+i)->input = NULL;
	  // 0429 null mark
	  (rval+i)->mark = 0;
	  (rval+i)->num_packets = 0;
	  (rval+i)->packets = NULL;
	  (rval+i)->refCnt = 1;
	  (rval+i)->cacheRecycleIndex = -1;
	  (rval+i)->serverSK = NULL;
	  (rval+i)->pmsk = NULL;
	  (rval+i)->isStatic = 0;
	  (rval+i)->actualCwnd = 0;
  }
  //printk("copy rval = %p, input = %p\n", rval, cont);
  return rval;
}

#ifndef TRACE_FREE
static inline void freeClientSide_Continuation(CONTINUATION_TYPE *cont) {

#if 0
}
#endif

#else
#define CONT_POISON ((void*)0x7FFFFFFF)
#warning "Paranoid freeclientside continuation"

#define freeClientSide_Continuation(CONT) freeClientSide_ContinuationHelper((CONT), __FILE__, __LINE__)
 static inline void freeClientSide_ContinuationHelper(CONTINUATION_TYPE *cont, char *file, int lineno) {

#endif
#ifdef TRACE_FREE
  printk("freeingclientside %p @ (%s:%d)\n", cont, file, lineno);
#endif

  int i;

#ifdef TRACE_FREE
  if(cont->sk == CONT_POISON) {
	  printk("Warning: Continuation poisoned\n");
	  BUG();
  }
#endif // TRACE_FREE

#ifdef DEBUG_TRICKLES_ALLOCATION // 0418
  numContinuations--;
#endif
#ifdef DEBUG_ALLOC
#ifndef USERTEST
  if((int)cont & 0xfff) {
	  BUG();
  }
#endif // USERTEST
#endif // DEBUG_ALLOC

  if(cont->list) {
	  BUG();
  }

  for(i=0; i < 2; i++) {
    if((cont+i)->ucont_data)
      kfree((cont+i)->ucont_data);
    if((cont+i)->input)
      kfree((cont+i)->input);
  }
  // poison
#ifdef TRACE_FREE
  cont->sk = CONT_POISON;
#endif // TRACE_FREE

#ifdef USERTEST
  kfree(cont);
#else  //0426 - change kernel to slab cache
#ifdef DEBUG_ALLOC
  zap_virt(cont);
  //memset(cont, 0x3e, sizeof(*cont));
#else
#ifndef USESLAB
  kfree(cont);  // 0502 maybe slab cache usage is buggy
#else
  kmem_cache_free(clientSideContinuation_cache, cont);
#endif
#endif
#endif
}

static inline
struct SkipCell *SkipCell_new(unsigned start, unsigned end) {
	struct SkipCell *cell = 
		kmalloc(sizeof(struct SkipCell), GFP_ATOMIC);
	cell->prev = cell->next = NULL;
	cell->list = NULL;

	cell->start = start;
	cell->end = end;
	return cell;
}

static inline
void SkipCell_free(struct SkipCell *cell) {
	kfree(cell);
}

 static void SkipCell_dump(struct SkipCell *cell) {
	 if((struct alloc_head_list *)cell == cell->list) {
		 printk("end");
	 } else {
		 printk("cell[%d-%d] ", cell->start, cell->end);
	 }
 }

 static int SkipCell_intersectRange(struct SkipCell *c0, unsigned start, unsigned end) {
	unsigned left = MAX(c0->start ,start);
	unsigned right = MIN(c0->end, end);
	return left < right;
 }

static int SkipCell_intersect(struct SkipCell *c0, struct SkipCell *c1) {
	return SkipCell_intersectRange(c0, c1->start, c1->end);
}

static inline int SkipCell_compare(struct SkipCell *c0, struct SkipCell *c1) {
	return c0-> start == c1->start && c0->end == c1->end;
}

static int SkipCell_insert(struct sock *sk, struct SkipCell *cell) {
	struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;
	struct alloc_head_list *list = &tp->t.skipList;
	struct SkipCell *prev = (struct SkipCell *)list;
	if(empty(list)) {
		insert_tail(list, (struct alloc_head*)cell);
		return 1;
	} else {
		int found = 0;
		struct SkipCell *next = (struct SkipCell *) list->next;
		if(cell->end <= next->start) {
			BUG_TRAP((struct alloc_head_list *)prev == list);
			// printk("skip at beginning\n");
			found = 1;
		} else {
			alloc_head_walk(list, next) {
				if((struct alloc_head_list *)prev != list && 
				   (struct alloc_head_list *)next != list) {
					if(prev->end <= cell->start && 
					   cell->end <= next->start) {
						//printk("skip found in middle\n");
						found = 1;
						break;
					}
					if(SkipCell_compare(prev,cell)) {
						// printk("skip cell is the same as next, ok\n");
						return 0;
					}
					if(cell->end <= next->start) {
						printk("no acceptable insertion point for skip\n");
						BUG();
						return 0;
					}
				}
				prev = next;
			}
		}
		if((struct alloc_head_list*)next == list) {
			if(prev->end <= cell->start) {
				if(found) BUG();
				// printk("skip found at end\n");
				found = 1;
			} else {
				//printk("not compatible with the back, not inserting\n");
				return 0;
			}
		}
		if(found) {
			if(SkipCell_intersect(prev, cell) ||
			   SkipCell_intersect(cell, next)) {
				printk("found an insertion point, but turns out to have overlap\n");
				BUG();
			} else {
#if 0
				printk("inserting ");
				SkipCell_dump(cell);
				printk(" between ");
				SkipCell_dump(prev);
				printk(" , ");
				SkipCell_dump(next);
				printk("\n");
#endif

				insert((struct alloc_head*)cell, 
				       (struct alloc_head*)prev, 
				       (struct alloc_head*)next);
				return 1;
			}
		}

		BUG_TRAP(!found);
		BUG();
		return 0;
	}
}

static inline void unmarshallAckProof(AckProof *dproof, const WireAckProof *sproof) {
#define NHCONVERTLONG(X) dproof->X = ntohl(sproof->X);
#define COPYLONG(X) dproof->X = sproof->X
  int i;
  dproof->numSacks = sproof->numSacks;
  for(i=0; i < sproof->numSacks; i++) {
    NHCONVERTLONG(sacks[i].left);
    NHCONVERTLONG(sacks[i].right);
    COPYLONG(sacks[i].nonceSummary);
  }
#undef NHCONVERTLONG
#undef COPYLONG
}

static inline struct UC_Continuation *unmarshallUC_Continuation(struct WireUC_Continuation *scont, unsigned length) {
  unsigned dataLen = length - sizeof(struct WireUC_Continuation);
  struct UC_Continuation *rval = kmalloc(sizeof(struct UC_Continuation) + dataLen, GFP_ATOMIC);

  if(rval == NULL) {
    printk("Out of memory while unmarshalling UC_Continuation\n");
    return NULL;
  }
  rval->prev = rval->next = NULL;
  rval->list = NULL;

  rval->seq = ntohl(scont->seq);
  rval->validStart = ntohl(scont->validStart);
  rval->validEnd = ntohl(scont->validEnd);

  rval->FIN_received = 0;
  rval->FINHint = 0;
  rval->FINHintPosition = 0xffffffff;

  rval->fields = scont->fields;
  rval->dataLen = dataLen;
  rval->kernel.obsoleteAt = rval->validEnd;
  memcpy(rval->kernel.data, scont->data, dataLen);
  return rval;
}

static void 
UC_Continuation_receivedFIN(struct UC_Continuation *cont, unsigned finPosition) {
	cont->FIN_received = 1;
	cont->FINHint = 1;
	cont->FINHintPosition = finPosition;
	BUG_TRAP(finPosition <= cont->kernel.obsoleteAt);
#if 0
	printk("obsolete position moved from %d to %d\n", 
	       cont->kernel.obsoleteAt, finPosition);
#endif
	cont->kernel.obsoleteAt = finPosition;
}

static void 
UC_Continuation_setFINHint(struct UC_Continuation *cont, unsigned finHintPosition) {
	if(cont->FINHint && cont->FINHintPosition != finHintPosition) {
		printk("Warning! client does not properly multiple hints in the same continuation (curr=%d, new=%d)\n",
		       cont->FINHintPosition, finHintPosition);
	}
	if(!cont->FIN_received) {
		cont->FINHint = 1;
		cont->FINHintPosition = finHintPosition;
	}
}

static unsigned UC_Continuation_virtualEnd(struct UC_Continuation *cont) {
	if(cont->FINHint) {
		BUG_TRAP(cont->FINHintPosition <= cont->validEnd);
		return cont->FINHintPosition;
	} else {
		return cont->validEnd;
	}
}

static unsigned UC_Continuation_actualEnd(struct UC_Continuation *cont) {
	if(cont->FIN_received) {
		return cont->FINHintPosition;
	} else {
		return cont->validEnd;
	}
}

static int
UC_Continuation_inSkippedRegion(struct UC_Continuation *cont, unsigned position) {
	BUG_TRAP(cont->validStart <= position && position < cont->validEnd);
	return position >= UC_Continuation_virtualEnd(cont) && 
		position < cont->validEnd;
}

static inline unsigned marshallUC_Continuation(struct WireUC_Continuation *dcont, struct UC_Continuation *scont) {
  int dataLen = scont->dataLen;
  dcont->seq = htonl(scont->seq);
  dcont->validStart = htonl(scont->validStart);
  dcont->validEnd = htonl(scont->validEnd);
  dcont->fields = scont->fields;
  memcpy(dcont->data, scont->kernel.data, dataLen);
  return sizeof(*dcont) + dataLen;
}

static inline void WireUC_addDependency(struct WireUC_Continuation *completeResp, struct UC_DependencyLink *dep) {
  printk("Dependency handling not complete\n");
  BUG();
  completeResp->fields |= (0x01);
  /* and more stuff */
  /* ... */
}

static inline struct UC_Continuation *copyUC_Continuation(struct UC_Continuation *scont) {
  /* create a separate copy */
  int dataLen = scont->dataLen;
  struct UC_Continuation *rval = kmalloc(sizeof(*rval) + dataLen, GFP_ATOMIC);
  if(rval == NULL) {
    printk("Out of memory while copying UC_Continuation\n");
    return NULL;
  }
  *rval = *scont;
  rval->prev = rval->next = NULL;
  rval->list = NULL;

  memcpy(rval->kernel.data, scont->kernel.data, dataLen);
  return rval;
}

static inline struct UC_DependencyLink *unmarshallUC_Dependency(struct sock *sk, struct WireUC_Dependency *sdep) {
#if 0
  struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;
  struct UC_Dependency *rval, *currDep;
  int i;
  /* scan through sk to see if any dependencies can be resolved */
  /* May return pointer to existing dependency */

  if(sdep->pred.start > sdep->pred.end ||
     sdep->succ.start > sdep->succ.end) { 
      printk("unmarshallUC_Dependency: bad dep\n"); 
      return NULL;
  }
  rval = kmalloc(sizeof(struct UC_Dependency), GFP_ATOMIC);
  if(rval == NULL) {
    printk("Out of memory while unmarshalling UC Dependency\n");
    return NULL;
  }
  rval->prev = rval->next = NULL;
  rval->list = NULL;
  rval->refCnt = 1;

  rval->start = ntohl(sdep->succ.start);
  rval->end = ntohl(sdep->succ.end);

  initVector(&rval->vec);
#else
  printk("Dependency management doesn't work yet\n");
  BUG();
  return NULL;
#endif
}

static inline int freeDependencyNode(struct sock *sk, struct UC_DependencyNode *dep) {
#if 0
  dep->refCnt--;
  if(dep->refCnt == 0) {
    if(dep->list) {
      unlink(dep);
    }
    kfree(dep);
    return 0;
  }
  return dep->refCnt;
#else
  printk("Dependency management doesn't work yet\n");
  BUG();
  return -1;
#endif
}

static inline struct UC_DependencyNode *copyUC_DependencyNode(struct UC_DependencyNode *sdep) {
#if 0
  int i;
  struct UC_Dependency *rval = kmalloc(sizeof(struct UC_Dependency), GFP_ATOMIC);
  if(rval == NULL) {
    printk("Out of memory while copying UC_Dependency\n");
    return NULL;
  }
  *rval = *sdep;
  rval->prev = rval->next = NULL;
  rval->list = NULL;
  rval->deps = kmalloc(sizeof(struct UC_Continuation*) * rval->maxDeps, GFP_ATOMIC);
  if(rval->deps == NULL) {
    printk("Out of memory while copying UC_Dependency\n");
    kfree(rval);
    return NULL;
  }
  for(i=0; i < rval->numDeps; i++) {
    rval->deps[i] = sdep->deps[i];
    rval->deps[i]->refCnt++;
  }
  return rval;
#else
  printk("Dependency management doesn't work yet\n");
  BUG();
  return NULL;
#endif
}

static inline 
void updateUC_ContinuationAndDependency(struct UC_Continuation *cont, struct UC_DependencyNode *dep) {
#if 0
/* called when resolving old dependency chains when new continuations
   are inserted called when inserting new dependencies */
  BUG_TRAP(dep->start >= cont->validStart && dep->end <= cont->validEnd);
  BUG_TRAP(!dep->resolved && dep->cont == NULL);
  dep->resolved = 1;
  dep->cont = cont;
  cont->kernel.obsoleteAt = MAX(cont->kernel.obsoleteAt, dep->end);
#else
  printk("Dependency management doesn't work yet\n");
  BUG();
#endif
}

static inline int addDependencyLink(struct UC_DependencyNode *changedDep, struct UC_DependencyLink *newLink) {
#if 0
  if(changedDep->numDeps < changedDep->maxDeps) {
    changedDep->deps[changedDep->numDeps++] = newDep;
  } else {
    /* Resize */
    struct UC_Dependency *resizedDeps[];
    int newSize = changedDep->maxDeps * 2;

    resizedDeps = kmalloc(newSize * sizeof(UC_Dependency*), GFP_ATOMIC);
    if(resizedDeps == NULL) {
      printk("Out of memory while adding dependency link\n");
      return -1;
    }
    memcpy(resizedDeps, changedDep->deps, changedDep->numDeps * sizeof(UC_Dependency*));
    kfree(changedDep->deps);
    changedDep->deps = resizedDeps;
    changedDep->deps[changedDep->numDeps++] = newDep;
    changedDep->maxDeps = newSize;
  }
  newDep->refCnt++;
  return 0;
#else
  printk("Dependency management doesn't work yet\n");
  BUG();
  return -1;
#endif
}
#endif // __KERNEL__

/* HELPER FUNCTIONS FOR USER SPACE CODE */

static inline 
void WireUC_clearFields(struct WireUC_Continuation *wireContinuation) {
  wireContinuation->fields = 0;
}

static inline void *WireUC_getDataStart(struct WireUC_Continuation *wireContinuation) {
  char *rval = wireContinuation->data;
  /* get start of data area, taking into account the variable header length */
  if(wireContinuation->fields & FIELD_DEPS) {
    printk("getWireUC_dataStart: no dependency support\n");
    BUG();
  }
  if(wireContinuation->fields & ~FIELD_ALL) {
    printk("getWireUC_dataStart: unknown field\n");
    BUG();
  }

  /* perform necessary adjustments on rval here */
  return rval;
}

static inline void initResponseHeader(struct WireUC_RespHeader *resp, enum UC_Type type, int error, unsigned len) {
  resp->type = type;
  resp->error = error;
  resp->len = htons((short)len);
}

static inline void initIncompleteResponse(struct WireUC_CVT_IncompleteResponse *incompleteResp, unsigned ack_seq, int error, 
			    unsigned validStart, unsigned convContLen) {
  initResponseHeader((struct WireUC_RespHeader *)incompleteResp, UC_INCOMPLETE,
		     error, 
		     sizeof(struct WireUC_CVT_IncompleteResponse) + convContLen);
  incompleteResp->ack_seq = htonl(ack_seq);
  incompleteResp->newCont.validStart = htonl(validStart);
}

static inline void initCompleteResponse(struct WireUC_CVT_CompleteResponse *completeResp, unsigned ack_seq, 
					unsigned convContLen, unsigned seq, unsigned validStart, unsigned validEnd, __u16 piggyLength) {
  initResponseHeader((struct WireUC_RespHeader *)completeResp, UC_COMPLETE,
		     0, 
		     sizeof(struct WireUC_CVT_CompleteResponse) + convContLen);
  completeResp->ack_seq = htonl(ack_seq);
  completeResp->piggyLength = htons(piggyLength);
  completeResp->newCont.seq = htonl(seq);
  completeResp->newCont.validStart = htonl(validStart);
  completeResp->newCont.validEnd = htonl(validEnd);
  completeResp->newCont.fields = 0;
}

static inline void initNewContinuationResponse(struct WireUC_NewContinuationResponse *newContinuationResp, 
					       unsigned contLen, unsigned seq, unsigned validStart, unsigned validEnd) {
	initResponseHeader((struct WireUC_RespHeader*)newContinuationResp, UC_NEWCONT,
			   0,
			   sizeof(struct WireUC_NewContinuationResponse) + contLen);
	newContinuationResp->newCont.seq = htonl(seq);
	newContinuationResp->newCont.validStart = htonl(validStart);
	newContinuationResp->newCont.validEnd = htonl(validEnd);
	newContinuationResp->newCont.fields = 0;
}

#ifdef __KERNEL__

static inline void UC_Continuation_dump_string(char *dest, struct UC_Continuation *ucont) {
	sprintf(dest, "{ seq=[%d]\nvalid=[%d-%d]\ncvalid=[%d-%d] }\n", 
		ucont->seq, 
		ucont->validStart, ucont->validEnd, 
		ucont->clientValidStart, ucont->clientValidEnd);
}

static inline void UC_Continuation_dump(struct UC_Continuation *ucont) {
	char temp[1024];
	UC_Continuation_dump_string(temp, ucont);
	printk(temp);
}
#endif // __KERNEL__

static inline struct DataChunk *
data_buildChunkHeader(struct DataChunk *chunk, int byteNum, int chunkLen) {
	BUG_TRAP(! (chunkLen & ~0xffff));
	chunk->byteNum = htonl(byteNum);
	chunk->type = RCHUNK_DATA;
	chunk->flags = 0;
	chunk->chunkLen = htons(chunkLen + sizeof(struct DataChunk));
	// return pointer to next datachunk
	return (struct DataChunk *) (chunk->data + chunkLen);
 }

static inline struct ResponseChunk *
skip_buildChunkHeader(struct ResponseChunk *chunk, __u32 byteNum, __u32 skipLen) {
	int len;
	struct SkipChunk *schunk = (struct SkipChunk *) chunk;
	schunk->type = RCHUNK_SKIP;
	chunk->flags = 0;
	schunk->chunkLen = htons(len = sizeof(struct SkipChunk));
	schunk->byteNum = htonl(byteNum);
	schunk->len = htonl(skipLen);
	return (struct ResponseChunk *)((char*)schunk + len);
}

static inline struct ResponseChunk *
finhint_buildChunkHeader(struct ResponseChunk *chunk, __u32 byteNum, __u32 skipLen) {
	int len;
	struct FINHintChunk *shchunk = (struct FINHintChunk *) chunk;
	shchunk->type = RCHUNK_FINHINT;
	chunk->flags = 0;
	shchunk->chunkLen = htons(len = sizeof(struct FINHintChunk));
	shchunk->byteNum = htonl(byteNum);
	shchunk->len = htonl(skipLen);
	return (struct ResponseChunk *)((char*)shchunk + len);
}

static inline struct ResponseChunk *
pushhint_buildChunkHeader(struct ResponseChunk *chunk, int start, int end) {
	struct PushHintChunk *phchunk = (struct PushHintChunk *) chunk;
	phchunk->type = RCHUNK_PUSH_HINT;
	chunk->flags = 0;
	phchunk->chunkLen = htons(sizeof(struct PushHintChunk));
	phchunk->start = htonl(start);
	phchunk->end = htonl(end);
	
	// return pointer to next chunk
	return (struct ResponseChunk *) (phchunk+1);
 }
//
// Helper routines for properly striping range responses across multiple packets
//
struct GenerateDataContext {
	int packetNum;
	int packetPos;
	char *outputStart;
	char *outputPos;

	struct cminisock_packet *packets;
	int numPackets;
};

static inline
void GenerateDataContext_init(struct GenerateDataContext *ctx, char *dest, 
			      struct cminisock_packet *packets, int numPackets) {
	ctx->packetNum = 0;
	ctx->packetPos = 0;
	ctx->outputPos = ctx->outputStart = dest;
	ctx->packets = packets;
	ctx->numPackets = numPackets;
}

static inline
void GenerateDataContext_describePackets(struct GenerateDataContext *ctx) {
	int i;
	for(i=0; i < ctx->numPackets; i++) {
		printk("Packet [%d] = %d\n", i, ctx->packets[i].len);
	}
}

static inline
void GenerateDataContext_dump(struct GenerateDataContext *ctx) {
	printk("\tPacketNum = %d\n"
	       "\tPacketPos = %d\n\tOutputPos = %p/%p/%d\n"
	       "\tnumPackets = %d\n\tpackets = %p\n",
	       ctx->packetNum, 
	       ctx->packetPos, ctx->outputPos, ctx->outputStart, ctx->outputPos - ctx->outputStart,
	       ctx->numPackets, ctx->packets);
}

#define PACKET_LEN(CTX) ((CTX)->packets[(CTX)->packetNum].len - (CTX)->packets[(CTX)->packetNum].ucontLen)

static inline
int GenerateDataContext_packetSpace(struct GenerateDataContext *ctx) {
	if(ctx->packetNum >= ctx->numPackets) {
		return 0;
	}
	return PACKET_LEN(ctx) - ctx->packetPos;
}

static inline
char *GenerateDataContext_put(struct GenerateDataContext *ctx, int numBytes) {
#define CHECK_OUT_OF_SPACE()				\
	do {						\
		if(ctx->packetNum >= ctx->numPackets) {	\
			/* out of space */		\
			return NULL;			\
		}					\
	} while(0)

	if(numBytes == 0) return ctx->outputPos;

	CHECK_OUT_OF_SPACE();

	if(!(ctx->packetNum <= ctx->numPackets)) {
		BUG_TRAP(ctx->packetNum <= ctx->numPackets);
		printk("%d !<= %d\n", ctx->packetNum, ctx->numPackets);
	}
	char *temp;
	if(GenerateDataContext_packetSpace(ctx) >= numBytes) {
		// no adjustments needed in normal operation
		//printk("putting %d at %d[%d]\n", numBytes, ctx->packetNum, ctx->packetPos);
	} else {
		// can't fit request into current packet
		// BUG_TRAP(PACKET_LEN(ctx));
		ctx->outputPos += PACKET_LEN(ctx) - ctx->packetPos;
		ctx->packetPos = 0;
		ctx->packetNum++;
	}
	temp = ctx->outputPos;
	ctx->packetPos += numBytes;
	ctx->outputPos += numBytes;

	CHECK_OUT_OF_SPACE();

	BUG_TRAP(ctx->packetPos <= PACKET_LEN(ctx));

	if(ctx->packetPos == PACKET_LEN(ctx)) {
		ctx->packetPos = 0;
		ctx->packetNum++;
	}
	return temp;
#undef CHECK_OUT_OF_SPACE
}

static inline 
struct ResponseChunk *GenerateDataContext_reserveChunkHeader(struct GenerateDataContext *ctx, int headerLen, int generatePadding) {
	char *currpos = ctx->outputPos;
	struct  ResponseChunk *output = (struct ResponseChunk *)
		GenerateDataContext_put(ctx, headerLen);
	if(output == NULL) {
		// printk("reserve generic header returning null\n");
		return NULL;
	} else {
		// printk("reserve generic header succeeded\n");
		if(currpos != (char*)output) {
			// we skipped over some data and need padding
			if(generatePadding) {
				// printk("generating padding for generic header\n");
				while(currpos != (char*)output) {
					*currpos++ = PADDING_CHUNK;
				}
			}
		}
	}

	return output;
}

static inline 
struct DataChunk *
GenerateDataContext_reserveHeader(struct GenerateDataContext *ctx, 
				  int generatePadding) {
	/// XXX rewrite to use _reserveChunkHeader
	char *currpos = ctx->outputPos;
	struct DataChunk *output = (struct DataChunk *) GenerateDataContext_put(ctx, sizeof(struct DataChunk));
	if(output == NULL) {
		//printk("reserve header returning null\n");
		return NULL;
	} else {
		//printk("reserve header succeeded\n");
		if(currpos != (char*)output) {
			// need padding
			if(generatePadding) {
				// printk("generating padding\n");
				while(currpos != (char*)output) {
					*currpos++ = PADDING_CHUNK;
				}
			}
		}
	}

	return output;
}

static inline 
int GenerateDataContext_simulateRequest(struct GenerateDataContext *gctx) {
	struct DataChunk *test = GenerateDataContext_reserveHeader(gctx, 0);
	if(test == NULL) {
		// printk("reserve header failed\n");
		return -1;
	}

	int maxLen = GenerateDataContext_packetSpace(gctx);
	return maxLen;
}

static inline int validateDataChunks(char *start, int len) {
#define VALIDATION_LIMIT (100)
	int chunknum = 0, dataLen = 0;
	struct DataChunk *chunk = (struct DataChunk *)start;
	int goodCount = 0, loopcount = 0, printAtReturn = 0, count = 0;
	while((char*)(chunk+1) - start < len) {
		int len = DATA_LEN(chunk);
		if(len <= 0) {
			if(trickles_ratelimit())
				printk("bad length chunk(%d) -- ", len);
			printAtReturn = 1;
		} else {
			goodCount++;
		}
		dataLen += len;
		chunknum++;

		chunk = NEXT_CHUNK_ADDR(chunk);
		//printk("offset at %d\n", (char*)chunk - start);

		loopcount++;
		if(loopcount > VALIDATION_LIMIT) {
			printk("validation limit exceeded, goodCount = %d\n", goodCount);
			return -1;
		}
	}
	if((char*)chunk - start > len) {
		printk("data chunk validation failed, %d > %d\n", (char*)chunk-start, len);
		return -chunknum - 1;
	}
	if(printAtReturn) {
		printk("returning\n");
	}
	return chunknum;
#undef  VALIDATION_LIMIT
}

static inline 
void GenerateDataContext_sanityCheck(struct GenerateDataContext *gctx) {
	// Verify  that number of packets was not exceeded
	BUG_TRAP(gctx->packetNum <= gctx->numPackets);
	// Verify that aggregate packet limit was not exceeded, and
	// that the datachunks within each packet are consistent
	int i;
	int totalLen = 0;
	int outputLen = gctx->outputPos - gctx->outputStart;
	char *buf = gctx->outputStart;
#ifndef __KERNEL__
	for(i=0; i < gctx->numPackets; i++) {

#warning "not compiling kernel version"
		assert(0); // following line was not adjusted for new packet_len definition
		int numChunks = validateDataChunks(buf, MIN(PACKET_LEN(gctx), MAX(outputLen - totalLen,0)));
		totalLen += PACKET_LEN(gctx);
		if(numChunks < 0) {
			numChunks = -numChunks;
			printk("Packet %d: chunk processing error, %d/%d\n", i, numChunks, gctx->numPackets);
		}
		buf += PACKET_LEN(gctx);
	}
	if(outputLen > totalLen) {
		BUG_TRAP(gctx->outputPos - gctx->outputStart <= totalLen);
		printk("%d !<= %d %d\n", gctx->outputPos - gctx->outputStart, totalLen, gctx->numPackets);
	}
#endif
}

static inline
void ResponseChunks_dump(char *start, int count) {
	struct ResponseChunk *buf = (struct ResponseChunk *) start;
	printk("{");
	while(count > 0) {
		int len = ntohs(buf->chunkLen);
		printk("[%d] t=%d f=%d l=%d: ", (char*)buf - start, buf->type, buf->flags, len);
		switch(buf->type) {
		case RCHUNK_PUSH_HINT:
			break;
		case RCHUNK_DATA: {
			struct DataChunk *dc = (struct DataChunk*) buf;
			printk("da[%d,%d]", ntohl(dc->byteNum), 
			       ntohl(dc->byteNum) + len - sizeof(struct DataChunk));
			break;
		}
		case RCHUNK_SKIP: {
			struct SkipChunk *sc = (struct SkipChunk *)buf;
			printk("sk[%d,%d]", ntohl(sc->byteNum),
			       ntohl(sc->byteNum) + ntohl(sc->len));
			break;
		}
		case RCHUNK_FINHINT: {
			struct FINHintChunk *fc = (struct FINHintChunk *)buf;
			printk("fh[%d,%d]", ntohl(fc->byteNum),
			       ntohl(fc->byteNum) + ntohl(fc->len));
			break;
		}
		}
		printk("\n");
		buf = (char*)buf + len;
		count--;
	}
	printk("}\n");
	
 }

static void WireContinuation_print(struct WireContinuation *wcont) {
	printk("{ type = %d, seq = %d\n", wcont->continuationType, ntohl(wcont->seq));
	printk("  tstamp = %d, mrtt = %d, state = %d, firstLoss = %d, firstBootstrapSeq = %d, startCwnd = %d, ssthresh = %d, TCPBase = %d, tokenCounterBase = %lld }\n",
	       wcont->timestamp, wcont->mrtt, wcont->state, wcont->firstLoss,
	       wcont->firstBootstrapSeq, wcont->startCwnd, wcont->ssthresh,
	       wcont->TCPBase, wcont->tokenCounterBase);
 }

#endif // TRICKLES_PACKET_HELPERS_H
