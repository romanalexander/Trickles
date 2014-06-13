#define TRICKLES_C
#ifdef USERTEST
#define inline
#endif

#ifdef USERTEST
#define usertest (1)
#else
#define usertest (0)
#endif

//#define SOFTWARE_CSUM

#ifdef USE_UDP
#define iovec iovec_other
#define sockaddr sockaddr_other
#define sockaddr_storage sockaddr_storage_other
#define msghdr msghdr_other
#define cmsghdr cmsghdr_other
#define __cmsg_nxthdr __cmsg_nxthdr_other
#define ucred ucred_other
#define in_addr in_addr_other
#define linger linger_other
#define sockaddr_in sockaddr_in_other
#include <sys/socket.h>
#include <netinet/in.h>
#undef iovec
#undef sockaddr
#undef sockaddr_storage
#undef msghdr
#undef cmsghdr
#undef __cmsg_nxthdr
#undef ucred
#undef in_addr
#undef linger
#undef sockaddr_in
#endif

#include "trickles-int.h"
#include "memdump-util.h"
#include "math-util.h"

#include "skbstat.h"
#include "histstat.h"

#ifndef USERTEST
#include "linux/proc_fs.h"
#endif

#include "msk_table.h"

extern void __tcp_v4_hash(struct sock *sk, const int listen_possible);
#if 0
#define RECORD_MISSINGDATAMAP_INSERTION_HELPER(START,END)		\
	printk("inserted [%d-%d] into missing data map at %d\n", (START), (END), __LINE__)
#else
#define RECORD_MISSINGDATAMAP_INSERTION_HELPER(START,END)
#endif
#define RECORD_MISSINGDATAMAP_INSERTION(REQ)			\
	RECORD_MISSINGDATAMAP_INSERTION_HELPER((REQ)->start, (REQ)->end)

// #define PRINT_PROBES
// #define PRINT_PROBES_TX
//#define PRINT_PROBES_RX

int packetTraceLevel = 0;
int packetTraceLogged = 0;
int packetTraceCounter = 0;
int packetTraceTotal = 0;


//#define FINDUC_DBG

#define PACKET_SPACING_DIGEST(BASE)		\
do {						\
 	static long last_send_time;		\
	long delta = jiffies - last_send_time;	\
	int log = 0;				\
	while(delta > 0) {			\
		delta >>= 1;			\
		log++;				\
	}					\
	log = MIN(log, 9);			\
	printk("%c", BASE+log);	\
	last_send_time = jiffies;		\
} while(0)

static void SK_selectAndSend(struct sock *sk, struct sk_buff *skb);
static int SK_findMatchingServer(struct sock *sk, __u32 addr) {
	struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;
	int i;
	for(i=0; i < tp->t.numServers; i++) {
		if(tp->t.servers[i].address == addr) {
			return i;
		}
	}
	return -1;
}

static void updateRTTEstimatorHelper(int *pA, int *pD, int delta) {
	int limit = trickles_ratelimit();
	if(limit) {
		printk("update rtt estimator with %d, (%d,%d) => ", delta, *pA, *pD);
	}
#if 0
	if(delta > 10<<3) {
		printk("delta was %d\n", delta);
	}
#endif
	if(*pA == 0) {
		// initial variance is initial estimate / 2
		*pA = delta << 3;
		*pD = *pA >> 1;
	} else {
		int Err = (delta << 3) - *pA; // units of jiffies/8
		// Err is in units of jiffies/8, A is in units of jiffies/8
		//effect is A = 7/8 A + 1/8 Err
		*pA += (Err >> 3);
		//effect is D += 1/4 (Err - D)
		*pD += ((iabs(Err) - *pD) >> 2);
	}
	if(limit) {
		printk("(%d,%d)\n", *pA, *pD);
	}
}

static struct {
	__u32	address;
	int	index;
} probeStat;


static void trickles_server_newPacket(struct trickles_server *server, struct sk_buff *skb) {
	CONTINUATION_TYPE *cont = TCP_SKB_CB(skb)->cont;
	int delta = jiffies - cont->clientTimestamp;
	updateRTTEstimatorHelper(&server->A, &server->D, delta);
	server->updateCount++;
	server->byteCount += skb->len;

#ifdef PRINT_PROBES_RX
	static int lastAddress;
	if(lastAddress != server->address) {
		printk("different probe received %X %X %X\n", lastAddress, server->address, probeStat.address);
	}
	lastAddress = server->address;
	if(probeStat.address == server->address) {
		static int recvProbeCount = 0;
		printk("[%d] probing recv [%d] => %X @ %d (%d - %d)\n",
		       recvProbeCount++, probeStat.index, server->address,
		       jiffies, 
		       server->A, delta);
	} else {
		static int otherProbeCount = 0;
		otherProbeCount++;
		if(otherProbeCount % 1000 == 0) {
		printk("[%d] probing recv [@] => %X @ %d (%d - %d)\n",
		       otherProbeCount++, server->address, jiffies, 
		       server->A, delta);
		}
	}
#endif
}

void SK_dump_vars(struct sock *sk) {
	struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;
	printk("t.byteRcvNxt = %d, t.byteReqNext = %d, t.rcv_nxt = %d\n", 
	       tp->t.byteRcvNxt, tp->t.byteReqNext, tp->t.rcv_nxt);
}

struct UC_Continuation gLastRemovedCont;
void SK_ucontList_dump(struct sock *sk) {
	struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;
	struct UC_Continuation *ucont;
	int index = 0;
	if(tp->t.ucontList.len > 0) {
		printk("ucontlist:\n");
		alloc_head_walk(&tp->t.ucontList, ucont) {
			printk("[%d] => ", index); UC_Continuation_dump(ucont);
			index++;
		}
	} else {
		//printk("ucontlist last removed: "); UC_Continuation_dump(&gLastRemovedCont);
	}
}

#if 0 // XXX what is this code supposed to do ?
void SK_makeVirtualRequest(struct sock *sk, struct UC_Continuation *ucont, 
			   unsigned tseq,
			   unsigned start, unsigned end) {
	struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;
	struct DataRequestMapping *dataReqMap = 
		newDataRequestMapping(ucont, tseq, tseq+1, start, end);
	// XXX temporary hack
	BUG_TRAP(start <= tp->t.byteReqNext && tp->t.byteReqNext <= end);
	tp->t.byteReqNext = end;
}
#endif

void SK_raw_ofo_queue_dump(struct sock *sk) {
	struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;
	struct sk_buff_head *ofo = &tp->t.ofo_queue;
	struct sk_buff *skb = ofo->next;

	if(ofo->qlen > 0) {
		printk("raw ofo queue = { ");
		while((struct sk_buff_head *) skb != ofo) {
			struct cminisock *cont = TCP_SKB_CB(skb)->cont;
			printk("seq=%d", 
			       cont != NULL ? cont->seq : -1);
			if(skb->next != ofo) {
				printk(", ");
			}
			skb = skb->next;
		}
		printk(" }\n");
	}
}

void SK_data_ofo_queue_dump(struct sock *sk) {
	struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;
	struct sk_buff_head *ofo = &tp->t.data_ofo_queue;
	struct sk_buff *skb = ofo->next;
	int first = 1;
	int last_end = 0;

	if(ofo->qlen > 0) {
		printk("data ofo queue = ");
		while((struct sk_buff_head *) skb != ofo) {
			if(first) {
				printk(" %d - ", TCP_SKB_CB(skb)->seq);
			} else {
				if(last_end != TCP_SKB_CB(skb)->seq) {
					printk("%d, %d - ", last_end, TCP_SKB_CB(skb)->seq);
				}
			}
			last_end = TCP_SKB_CB(skb)->end_seq;
			first = 0;
			skb = skb->next;
		}
		printk("%d\n", last_end);
	}
}

void SK_skiplist_dump(struct sock *sk) {
	struct tcp_opt *tp = &(sk)->tp_pinfo.af_tcp;
	struct alloc_head_list *skiplist = &tp->t.skipList;
	struct SkipCell *curr = (struct SkipCell *)skiplist->next;
	if(skiplist->len > 0) {
		printk("skiplist = ");
		while((struct alloc_head_list *)curr != skiplist) {
			SkipCell_dump(curr);
			curr = (struct SkipCell *)curr->next;
		}
		printk("\n");
	}
}

void SK_data_request_dump_helper(struct alloc_head_list *list, int lim) {
	struct DataRequestMapping *req;
	alloc_head_walk(list, req) {
		printk("[%d-%d] , ", req->start, req->end);
		if(lim-- == 0) break;
	}
}

void SK_data_request_dump(struct sock *sk) {
	struct tcp_opt *tp = &(sk)->tp_pinfo.af_tcp;
	struct alloc_head_list *list;
	const int lim = 10;

	list = &tp->t.dataRequestMap;
	if(list->len > 0) {
		printk("datarequestmap = ");
		SK_data_request_dump_helper(list, lim);
	}
	list = &tp->t.missingDataMap;
	if(list->len > 0) {
		printk("missing datat map = ");
		SK_data_request_dump_helper(list, lim);
	}
}

static void request_dump(struct Request *req) {
	if(req->type == MREQ_CONVERSION) {
		struct ConversionRequest *creq = (struct ConversionRequest*)
			req;
		printk("req %d ", creq->parallelStart);
		if(creq->completePred != NULL) {
			UC_Continuation_dump(creq->completePred);
		}
	} else {
		printk("req [%d] , ", req->type);
	}
}

void SK_requestList_dump_helper(struct alloc_head_list *list) {
	struct Request *req;
	int offset = 0;
	alloc_head_walk(list, req) {
		printk("[%d]: ", offset++);
		request_dump(req);
	}
}

void SK_request_dump(struct sock *sk) {
	struct tcp_opt *tp = &(sk)->tp_pinfo.af_tcp;
	struct alloc_head_list *list;
	list = &tp->t.queuedRequests;
	if(!empty(list)) {
		printk("queuedRequests = ");
		SK_requestList_dump_helper(list);
		printk("\n");
	}
	list = &tp->t.sentRequests;
	if(!empty(list)) {
		printk("sentRequests = ");
		SK_requestList_dump_helper(list);
		printk("\n");
	}
}

static void trickles_server_dump(struct trickles_server *server) {
	printk("{ lastProbeTime = %d, address = %X, A = %d, D = %d, updateCount = %d, byteCount = %d }", server->lastProbeTime, server->address, server->A, server->D, server->updateCount, server->byteCount);
}

void SK_trickles_servers_dump(struct sock *sk) {
	int i;
	struct tcp_opt *tp = &(sk)->tp_pinfo.af_tcp;
	printk("server probe period = %d\n",  tp->t.probeRate);
	for(i=0; i < tp->t.numServers; i++) {
		printk("server [%d] = ", i);
		trickles_server_dump(&tp->t.servers[i]);
		printk("\n");
	}
}

struct Range {
	unsigned start, end;
	int valid;
};

static int Range_equal(struct Range *r0, struct Range *r1) {
	return r0->start == r1->start && r0->end == r1->end;
}

static void Range_dump(struct Range *r) {
	printk("range (%s) [%d,%d]", r->valid? "y" :"n", r->start, r->end);
}

static inline int Range_valid(struct Range *r) {
	return r->valid;
}

static void Range_intersect(struct Range *r0, struct Range *r1, struct Range *result) {
	result->start = MAX(r0->start, r1->start);
	result->end = MIN(r0->end, r1->end);
	result->valid = result->start < result->end;
}

static void Range_difference(struct Range *r0, struct Range *r1, struct Range *left, struct Range *right) {
	struct Range intersection;

	Range_intersect(r0,r1,&intersection);
	
	// front and back can be zero length
	if(intersection.valid) {
		left->start = r0->start;
		left->end = intersection.start;
		left->valid = 1;
		
		right->start = intersection.end;
		right->end = r0->end;
		right->valid = 1;
	} else {
		left->start = r0->start;
		left->end = r0->end;
		left->valid = 1;
		
		right->start = r0->end;
		right->end = r0->end;
		right->valid = 1;
	}
}

static int Range_length(struct Range *r0) {
	return r0->end - r0->start;
}

static inline
int intersect_range(unsigned start0, unsigned end0,
		    unsigned start1, unsigned end1) {
	struct Range r0 = { start0, end0, 1 }, r1 = { start1, end1, 1 }, res;
	Range_intersect(&r0, &r1, &res);
	return res.valid;
}

// returns the first piece of the difference
static void SK_data_ofo_queue_difference(struct Range *r0, struct sock *sk, struct Range *first) {
	// first = r0 - ofo_queue (the first range)
	// rest = [beginning of second valid range, r0.end]
	struct tcp_opt *tp = &(sk)->tp_pinfo.af_tcp;

	BUG_TRAP(tp->t.byteRcvNxt <= r0->start);

	struct sk_buff *skb;
	// probe for first
	struct Range prev = *r0;
	for(skb = tp->t.data_ofo_queue.next; (struct sk_buff_head*)skb != &tp->t.data_ofo_queue; skb = skb->next) {
		struct Range sr = { TCP_SKB_CB(skb)->seq, TCP_SKB_CB(skb)->end_seq, 1 };
		struct Range left, right;
		if(prev.end <= sr.start) break;
		Range_difference(&prev, &sr, &left, &right);
		prev = left;

		if(Range_length(&prev) == 0) {
			prev = right;
		}
	}
	*first = prev;

	if(!Range_equal(r0,first)) {
		// printk("range changed -- "); Range_dump(r0); printk(" to orig = "); Range_dump(r0); printk(" :: first = "); Range_dump(first); printk("\n");
	}
}

void mem_dump(char *start, int len) {
	int i;
	for(i=0; i < len; i++) {
		if(i > 0 && i % 8 == 0) {
			printk(" - ");
		}
		printk("%.2x ", start[i]);
		if(i > 0 && i % 72 == 0) {
			printk("\n");
		}
	}
}

int total_csum_bytes = 0;
static int csum_complete_user_count = 0;
static int gNumNomemEvents = 0;
int gNumSetUCont = 0;
int gNumSendv = 0;
int gNumSendbulk = 0;
int gNumSendbulkDesc = 0;

int gUpdateSincePollTotal = 0;
int gUpdateSincePollCount = 0;
int gInvalidReqnum = 0;
int gNumSlowstart = 0;
int gNumRecovery = 0;

__u64 gTotalTimeoutInterval = 0;
int gTotalTimeoutCount = 0;

int gNumRecoveryStates = 0;
int gNumBootstrapStates = 0;
int gNumBootstrapResponses = 0;
int gNeedDifferentContinuationCount = 0;
static int gConversionCount = 0;
static int gNoRequestPackets = 0;
static int gSmallRequestPackets = 0;
static int gMediumRequestPackets = 0;
static int gLargeRequestPackets = 0;
static int gLargerRequestPackets = 0;
static int gLargestRequestPackets = 0;

static int gHasPendingCount = 0;
// number of times that generateDataRequests() is called
static int gGenDataRequestCount = 0;
static int gInWindowCount = 0;
static int gOutOfWindowCount = 0;
static int gGenerateRequestsFromUnrequested = 0;
static int gZeroLoopCount = 0;
static int gNumRequests = 0;

static int gInsertSeq = 0;
static int gRecvSeq = 0;
static int gContSeq = 0;

static int gSkipCount = 0;

extern int gNormalCount;
extern int gRecoveryCount;
extern int gSlowStartCount;

static int gNumProbes = 0;
static int gProbeRate;
static int gNumSwitches = 0;

int gNumSentBytes = 0;
int gNumSentPackets = 0;

int gNumFull = 0;
int gNumHash = 0;
int gNumMinimal = 0;

static void initPacketSeq(void) {
	gInsertSeq = -1;
	gRecvSeq = -1;
	gContSeq = -1;
}

static void dumpPacketSeq(void) {
#if 0
	static int oInsertSeq, oRecvSeq, oContSeq;
	printk("%d/%d/%d ", gRecvSeq, gContSeq - oContSeq, gInsertSeq - oInsertSeq);
	oInsertSeq = gInsertSeq;
	oRecvSeq = gRecvSeq;
	oContSeq = gContSeq;
#endif
}

enum Trace {
	UNSPEC
};

static enum Trace gCurrentTrace;

static inline void record_delay(int delay) {
	gTotalTimeoutInterval += delay;
	gTotalTimeoutCount++;
}

const int dbgBadChunk = 0;

struct SKBStat gOuterSKBStat, gNoDataSKBStat, gReceivedSKBStat;
struct histogram a_histogram, d_histogram, timeout_histogram, rx_histogram;

#define SAVE_ESTIMATOR_STATS(SK)				\
	({ struct tcp_opt *_tp = &(SK)->tp_pinfo.af_tcp;	\
		hist_addPoint(&a_histogram, _tp->t.A);		\
		hist_addPoint(&d_histogram, _tp->t.D);		\
	})

#define SAVE_DELAY_STATS(SK)				\
	({ struct tcp_opt *_tp = &(SK)->tp_pinfo.af_tcp;	\
		hist_addPoint(&timeout_histogram, _tp->t.RTO);		\
	})

int gNumReceivedBytes, gNumUncopiedBytes;
#define NUM_OVERLAPPED (8)
struct {
	int count;
	int total;
	int lineNum;
} gNumOverlapped[NUM_OVERLAPPED];

#define RECORD_OVERLAP(X,Y) do { gNumOverlapped[X].count++; gNumOverlapped[X].total += (Y); gNumOverlapped[X].lineNum = __LINE__; } while(0)

#define RECORD_NOMEM() do { gNumNomemEvents++; } while(0)

static inline int skb_can_put(struct sk_buff *skb, int amt) {
	return skb->tail + amt <= skb->end;
}

#ifdef USERTEST
static inline int addOfoSkb(struct sk_buff *skb) {
	return 1;
}

static inline  void delOfoSkb(struct sk_buff *skb) {
	return;
}

void zap_virt(void *address) {
}
#else

// xxx HACK TO ALLOW > 2000 clients
// The memory allocation scheme results in bursts of memory
atomic_t ofoBufSize = ATOMIC_INIT(0);

// maximum of 256 mb allowed in ofo queue
#define OFO_BUF_LIMIT (256 * 1024 * 1024)
static inline int addOfoSkb(struct sk_buff *skb) {
	if(atomic_read(&ofoBufSize) > OFO_BUF_LIMIT) {
#if 0
		if(trickles_ratelimit())
			printk("%d > ofo limit\n", atomic_read(&ofoBufSize));
#endif
		return 0;
	}
	atomic_add(skb->end - skb->head,&ofoBufSize);
	return 1;
}

static inline  void delOfoSkb(struct sk_buff *skb) {
	atomic_sub(skb->end - skb->head,&ofoBufSize);
}
#endif // USERTEST

// 0425 debug variables to determine goodput
__u64 numRxPackets = 0;
__u64 numRxBytes = 0;
__u64 numRxOverhead = 0;

// 0418 debug variables
int numDataRequestMappings;

int numContinuations;

#if 0
#define MARK_PC(CONT) (CONT)->mark |= (__LINE__) << 18
#else
#define MARK_PC(CONT)
#endif

static inline void unlinkCont(CONTINUATION_TYPE *cont) {
	unlink((struct alloc_head*)cont);
}

#if 0
#define CHECK_IF_ZEROREQUEST(REQ) CHECK_IF_ZEROREQUEST_helper(REQ, __LINE__)
void CHECK_IF_ZEROREQUEST_helper(struct Request *req, int lineno) {
	if(req->type == MREQ_CONVERSION && ) {
		xxx code not don;
	}
}
#else
#define CHECK_IF_ZEROREQUEST(REQ)
#endif

#ifdef DO_INTEGRITY_CHECK
void INTEGRITY_CHECK(struct sock *sk, struct cminisock *msk) {
	return;
	struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;
	struct cminisock *ptr;
	int found = 0;

	if(msk->list != &tp->t.cont_list) {
		BUG();
	}
	alloc_head_walk(&tp->t.cont_list, ptr) {
		if(ptr == msk) {
			found = 1;
			break;
		}
	}
	if(!found) BUG();
}
#else
#define INTEGRITY_CHECK(X,Y)
#endif // DO_INTEGRITY_CHECK

#ifdef SAVE_APHIST
#define SAVE_ACK_PREV(TP) { save_ack_prev(TP, __LINE__); }

void save_ack_prev(struct tcp_opt *tp, int lineno) {
	int pos = tp->t.aphistpos;
	if(tp->t.ack_prev != 0) {
		tp->t.aphist[pos] = *tp->t.ack_prev;
	} else {
		memset(&tp->t.aphist[pos], 0xff, sizeof(tp->t.aphist[pos]));
	}
	tp->t.aphist[pos].mark |= (lineno & 0x3fff) << 2;
	pos = (pos + 1) % ACK_PREV_HISTORY_ENTRIES;
	tp->t.aphistpos = pos;
}
#else
#define SAVE_ACK_PREV(TP)
#endif // SAVE_APHIST


static int numConversionRequests = 0;

static int sendAckHelper(struct sock *sk, CONTINUATION_TYPE *cont, enum TrickleRequestType type);

struct ConversionRequest *kmalloc_ConversionRequest(int gfp) {
	numConversionRequests++;
	return kmalloc(sizeof(struct ConversionRequest), gfp);
}

int numContinuationRequests = 0;

struct ContinuationRequest *kmalloc_ContinuationRequest(int gfp) {
	numContinuationRequests++;
	return kmalloc(sizeof(struct ContinuationRequest), gfp);
}

#ifdef USE_FLOATINGPOINT
// FSAVE/FRESTORE areas to support use of FPU in bottom half
static char fpu_user_save[NR_CPUS][512];
static char fpu_kernel_save[NR_CPUS][512];

// Based on code from asm-i386/xor.h
#define FPU_SAVE(X)							\
  do {									\
	if (!(current->flags & PF_USEDFPU)) {				\
		__asm__ __volatile__ (" clts;\n");			\
	} else 								\
  		__asm__ __volatile__ ("fsave %0; fwait": "=m"((X)[0]));	\
  } while (0)

#define FPU_RESTORE(X)							\
  do {									\
	if (!(current->flags & PF_USEDFPU)) {				\
		stts();							\
	} else 								\
		__asm__ __volatile__ ("frstor %0": : "m"((X)[0]));	\
  } while (0)
#endif // USE_FLOATINGPOINT

#ifndef USERTEST
struct proto trickles_client_prot;

spinlock_t trickles_sockets_head_lock = SPIN_LOCK_UNLOCKED;
struct sock trickles_sockets_head;

void trickles_add_clientsock(struct sock *sk) {
	struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;
	struct tcp_opt *htp = &trickles_sockets_head.tp_pinfo.af_tcp;
	spin_lock(&trickles_sockets_head_lock);
	tp->t.dnext = htp->t.dnext;
	htp->t.dnext = sk;
	tp->t.dprev = &trickles_sockets_head;
	tp->t.dnext->tp_pinfo.af_tcp.t.dprev = sk;
	spin_unlock(&trickles_sockets_head_lock);
}

void trickles_del_clientsock(struct sock *sk) {
	struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;
	if(tp->t.dprev == NULL) {
		BUG_TRAP(tp->t.dnext != NULL);
		printk("Socket not on clientsock list\n");
		return;
	}
	spin_lock(&trickles_sockets_head_lock);
	BUG_TRAP(tp->t.dprev->tp_pinfo.af_tcp.t.dnext == sk);
	BUG_TRAP(tp->t.dnext->tp_pinfo.af_tcp.t.dprev == sk);
	tp->t.dprev->tp_pinfo.af_tcp.t.dnext = tp->t.dnext;
	tp->t.dnext->tp_pinfo.af_tcp.t.dprev = tp->t.dprev;

	tp->t.dprev = tp->t.dnext = NULL;
	spin_unlock(&trickles_sockets_head_lock);
}
#endif

#define SKB_CONTAINS(SKB, SEQ) \
	((TCP_SKB_CB(SKB)->seq <= (SEQ)) && (TCP_SKB_CB(SKB)->end_seq > (SEQ)))

static inline void trickles_kfree_skb(struct sk_buff *skb) {
	if(TCP_SKB_CB(skb)->cont) {
		// 0810 - used to be a straight kfree
		freeClientSide_Continuation(TCP_SKB_CB(skb)->cont);
	}
	int i;
	for(i=0; i < TCP_SKB_CB(skb)->numDataChunks-1; i++) {
		struct sk_buff **pskb = GET_CHUNK(skb,i);
		if(*pskb != NULL) {
			trickles_kfree_skb(*pskb);
			if(0 && trickles_ratelimit())
				printk("Freeing undetached skb\n");
		}
	}
	if(TCP_SKB_CB(skb)->chunksOverflow != NULL) {
		kfree(TCP_SKB_CB(skb)->chunksOverflow);
	}
	__kfree_skb(skb);
 }

static void dump_global_stats(void) {
	printk("numRxPackets = %llu, numRxBytes = %llu, avgRxPacketSize = %d, avgRxOverhead = %d, numTxPackets = %llu, numTxBytes = %llu, avgTxPacketSize = %d\n",
	       numRxPackets, numRxBytes, (__u32)(numRxPackets >> 4) ? (__u32)(numRxBytes >> 4) / (__u32)(numRxPackets >> 4) : 0,
	       (__u32)(numRxPackets >> 4) ? (__u32)(numRxOverhead >> 4) / (__u32)(numRxPackets >> 4) : 0,
	       numTxPackets, numTxBytes, (__u32)(numTxPackets >> 4) ? (__u32)(numTxBytes >> 4) / (__u32)(numTxPackets >> 4) : 0);
	numRxPackets = numRxBytes = numTxPackets = numTxBytes = 0;

	printk("Number of no memory events: %d\n", gNumNomemEvents);
	printk("Number of csum bytes %d, ", total_csum_bytes);
	printk("TCP Complete count %d, ", csum_complete_user_count);
	printk("setucont %d, sendv %d\n", gNumSetUCont, gNumSendv);
	printk("Num of sendbulk: %d, descs: %d\n", gNumSendbulk, gNumSendbulkDesc);
	printk("Average updates per poll %d (%d/%d)\n",
	       gUpdateSincePollCount ?
	       gUpdateSincePollTotal / gUpdateSincePollCount : -1,
	       gUpdateSincePollTotal, gUpdateSincePollCount);
	printk("Invalid reqnum %d\n", gInvalidReqnum);
	printk("NumSlowstart %d\n", gNumSlowstart);
	printk("NumRecovery %d\n", gNumRecovery);

	printk("Outer skb stat: "); SKBStat_dump(&gOuterSKBStat);
	printk("NoData skb stat: "); SKBStat_dump(&gNoDataSKBStat);
	printk("Received skb stat: "); SKBStat_dump(&gReceivedSKBStat);
	printk("Num received bytes: %d\n", gNumReceivedBytes);
	printk("Num uncopied bytes: %d\n", gNumUncopiedBytes);
	//hist_dump(&a_histogram);
	//hist_dump(&d_histogram);
	//hist_dump(&timeout_histogram);

	int i;
	int overlappedTotal = 0;
	for(i=0; i < NUM_OVERLAPPED; i++) {
		printk("Overlapped[lineno=%d] = %d / %d = %d\n", gNumOverlapped[i].lineNum,
		       gNumOverlapped[i].total, gNumOverlapped[i].count,
		       SAFEAVG(gNumOverlapped[i].total, gNumOverlapped[i].count));
		overlappedTotal += gNumOverlapped[i].total;
	}
	printk("Total overlap total = %d\n", overlappedTotal);

	printk("Delay updates: avg=%d (cnt=%d)\n", SAFEAVG(gTotalTimeoutInterval, gTotalTimeoutCount),
	       gTotalTimeoutCount);
	printk("NumRecoveryStates = %d\n", gNumRecoveryStates);
	printk("NumBootstrapStates = %d\n", gNumBootstrapStates);
	printk("NumBootstrapResponses = %d\n", gNumBootstrapResponses);

	printk("neededDifferentContinuations = %d\n", gNeedDifferentContinuationCount);
	printk("conversionCount = %d\n", gConversionCount);

	printk("gNoRequestPackets = %d\n", gNoRequestPackets);
	printk("gSmallRequestPackets (1-300) = %d\n", gSmallRequestPackets);
	printk("gMediumRequestPackets (300-800) = %d\n", gMediumRequestPackets);
	printk("gLargeRequestPackets (800-1500) = %d\n", gLargeRequestPackets);
	printk("gLargerRequestPackets (1500-2500) = %d\n", gLargerRequestPackets);
	printk("gLargestRequestPackets (>2500) = %d\n", gLargestRequestPackets);

	printk("gHasPendingCount = %d\n", gHasPendingCount);
	printk("gGenDataRequestCount = %d\n", gGenDataRequestCount);
	printk("gInWindowCount = %d\n", gInWindowCount);
	printk("gOutOfWindowCount = %d\n", gOutOfWindowCount);
	printk("gGenerateRequestsFromUnrequested = %d\n", gGenerateRequestsFromUnrequested);
	printk("gZeroLoopCount = %d\n", gZeroLoopCount);
	printk("gNumRequests = %d\n", gNumRequests);

	hist_dump(&rx_histogram);
	printk("gSkipCount = %d\n", gSkipCount);

	printk("gNumProbes = %d\n", gNumProbes);
	printk("gProbeRate = %d\n", gProbeRate);
	printk("gNumSwitches = %d\n", gNumSwitches);
}

/* Simple random number generator */

static unsigned long rand;

static inline unsigned char random(void) {
  /* See "Numerical Recipes in C", second edition, p. 284 */
  rand = rand * 1664525L + 1013904223L;
  return (unsigned char) (rand >> 24);
}

/*
 * Crypto support
 */

#define generateHMAC_VAL (1)
#define generateNonces_VAL (1)

const int generateHMAC = generateHMAC_VAL;
const int generateNonces = generateNonces_VAL;

// hack to give gcc more information about constants
#define generateHMAC (generateHMAC_VAL)
#define generateNonces (generateNonces_VAL)


// Debugging control
int enableDataRecovery = 1;
int serverDebugLevel = 0;
int debugDrops = 0;
int debugTransitions = 0;

#define PRINT_TRANSITION(SK, S)						\
({ struct sock *_sk = (SK);						\
   struct tcp_opt *_tp = &_sk->tp_pinfo.af_tcp;				\
   printk("%p: %s tcp rcv_nxt = %d byteRcvNxt = %d t.rcv_nxt = %d\n", _sk, (S), _tp->rcv_nxt, _tp->t.byteRcvNxt, _tp->t.rcv_nxt); })

int debugProofDrops = 1;
int clientDebugLevel = 0;
//#define SPEW_PARTIAL
int disableSevereErrors = 1;
int printOverlap = 0;
int disableTimeout = 0;

#ifdef OPENSSL_HMAC

void hmac_setup(HMAC_CTX *ctx, char *key, int len) {
  BUG_TRAP(len <= HMAC_BLOCKSIZE);
  memset(ctx->key, 0, HMAC_BLOCKSIZE);
  memcpy(ctx->key, key, len);

  int i;
  char pad[HMAC_BLOCKSIZE];

  for (i=0; i<HMAC_BLOCKSIZE; i++)
    pad[i]=0x36^ctx->key[i];
  DIGEST_Init(&ctx->in_ctx);
  DIGEST_Update(&ctx->in_ctx, pad, HMAC_BLOCKSIZE);

  for (i=0; i<HMAC_BLOCKSIZE; i++)
    pad[i]=0x5c^ctx->key[i];
  DIGEST_Init(&ctx->out_ctx);
  DIGEST_Update(&ctx->out_ctx, pad, HMAC_BLOCKSIZE);
}

void hmac_init(HMAC_CTX *ctx) {
  ctx->digest_ctx = ctx->in_ctx;
  ctx->len = 0;
}

void hmac_update(HMAC_CTX *ctx, void *data, int len) {
  DIGEST_Update(&ctx->digest_ctx, data, len);
  ctx->len += len;
  //printk("hmac'ed %d\n", len);
}

void hmac_final(HMAC_CTX *ctx, char *output) {
  char buf[HMAC_BLOCKSIZE];
  DIGEST_Final(buf, &ctx->digest_ctx);
  ctx->digest_ctx = ctx->out_ctx;
  DIGEST_Update(&ctx->digest_ctx, buf, HMACLEN);
  DIGEST_Final(output, &ctx->digest_ctx);
}

#endif // OPENSSL_HMAC

/* NONCE uses AES */

void computeMAC(struct sock *sk, PseudoHeader *phdr, const WireContinuation *cont, char *dest) {
	struct tcp_opt *tp = &(sk->tp_pinfo.af_tcp);
	if(generateHMAC) {
#ifdef OPENSSL_HMAC
		HMAC_CTX *ctx = tp->t.hmacCTX;
#ifdef DISABLE_SADDR_HMAC
		phdr->serverAddr = 0;
#endif
		hmac_init(ctx);
		hmac_update(ctx, (char*)phdr, HMAC_PHEADER_LEN);
		hmac_update(ctx, (char*)cont->hmac_start, WIRECONT_MAC_LEN);
		hmac_final(ctx, dest);
#if 0
		printk("Hmac input\n");
		int position = hexdump((char*)phdr, HMAC_PHEADER_LEN);
		hexdump_helper((char*)cont->hmac_start,
			       WIRECONT_MAC_LEN, position);
		printk("\n");
		printk("Hmac output\n");
		hexdump((char*)dest, HMACLEN);
		printk("\n");
#endif
#else
#error "not implemented"
		// improve parallelism by making local copy
		hmac_sha(tp->t.hmacKey, HMACLEN,
			 (char*)cont->hmac_start - HMAC_PHEADER_LEN, WIRECONT_MAC_LEN,
			 dest, HMACLEN);
#endif
	} else {
		memset(dest, 0, HMACLEN);
	}
}
#define NUM_NONCES_PER_BLOCK (NONCE_BLOCKSIZE / sizeof(__u32))

static inline
__u32 generateCryptoRangeNonceHelper(aes_encrypt_ctx *ctx, __u64 seqNumLeft, __u64 seqNumRight) {
	int i;
	__u64 nums[2] = {seqNumLeft, seqNumRight+1};
	__u64 oldNum = -1;
	__u32 nonce = 0;
	char nonce_out[NONCE_BLOCKSIZE];

	for(i=0; i < 2; i++) {
		__u64 number = nums[i] / NUM_NONCES_PER_BLOCK;
		int offset = nums[i] % NUM_NONCES_PER_BLOCK;
		char nonce_in[NONCE_BLOCKSIZE];
		if(i > 0 && oldNum == number) {
			goto skip_generation;
		}
		memset(nonce_in, 0, NONCE_BLOCKSIZE);
		*((__u64*)nonce_in) = number;
		aes_encrypt(nonce_in, nonce_out, ctx);
	skip_generation:
		nonce ^= ((__u32*)nonce_out)[offset];
		oldNum = number;
	}
	return nonce;
}

__u32 generateRangeNonce(struct sock *sk, __u64 seqNumLeft, __u64 seqNumRight) {
	if(SIMULATION_MODE(sk)) {
		BUG_TRAP(!SIMULATION_MODE(sk));
	}
	struct tcp_opt *tp = &(sk->tp_pinfo.af_tcp);
	int myGenerateNonces = generateNonces && !SIMULATION_MODE(sk);
	if(myGenerateNonces) {
		return generateCryptoRangeNonceHelper(tp->t.nonceCTX, seqNumLeft, seqNumRight);
	} else {
		// fast nonce generation
		int i;
		__u64 nums[2] = {seqNumLeft, seqNumRight+1};
		__u32 nonce = 0;
		for(i=0; i < 2; i++) {
			nonce ^= nums[i];
		}
		return nonce;
	}
}

static inline
__u32 generateCryptoSingleNonceHelper(aes_encrypt_ctx *ctx, __u64 seqNum, struct NonceCtx *prevCtx) {
	__u64 number = seqNum / NUM_NONCES_PER_BLOCK;
	int offset = seqNum % NUM_NONCES_PER_BLOCK;
	char nonce_in[NONCE_BLOCKSIZE];
	char nonce_out_data[NONCE_BLOCKSIZE], *nonce_out = nonce_out_data;
	memset(nonce_in, 0, NONCE_BLOCKSIZE);
	__u32 nonce;

	if(prevCtx) {
		nonce_out = prevCtx->prevBlock;
		if(prevCtx->new) {
			prevCtx->prevNumber = number;
			prevCtx->new = 0;
		} else if(prevCtx->prevNumber == number) {
			goto skipGeneration;
		} else {
			prevCtx->prevNumber = number;
		}
	}
	*((__u64*)nonce_in) = number;

	aes_encrypt(nonce_in, nonce_out, ctx);
 skipGeneration:
	nonce = ((__u32*)nonce_out)[offset];
	if(offset == NUM_NONCES_PER_BLOCK-1) {
		number += 1;
		*((__u64*)nonce_in) = number;
		aes_encrypt(nonce_in, nonce_out, ctx);
		nonce ^= ((__u32*)nonce_out)[0];
		if(prevCtx) {
			prevCtx->prevNumber = number;
		}
	} else {
		nonce ^= ((__u32*)nonce_out)[offset + 1];
	}
	return nonce;
}

__u32 generateSingleNonce(struct sock *sk, __u64 seqNum, struct NonceCtx *prevCtx) {
	BUG_TRAP(!SIMULATION_MODE(sk));
	struct tcp_opt *tp = &(sk->tp_pinfo.af_tcp);
	int myGenerateNonces = generateNonces && !SIMULATION_MODE(sk);

	if(myGenerateNonces) {
		return generateCryptoSingleNonceHelper(tp->t.nonceCTX, seqNum, prevCtx);
	} else {
		return seqNum ^ (seqNum+1);
	}
}

#ifndef USERTEST

/* begin functions copied from tcp_input.c */
static int __tcp_checksum_complete_user(struct sock *sk, struct sk_buff *skb)
{
        int result;

	if(skb->ip_summed == CHECKSUM_HW) {
		skb->ip_summed = CHECKSUM_UNNECESSARY;
		if(!tcp_v4_check(skb->h.th, skb->len, skb->nh.iph->saddr, skb->nh.iph->daddr,
				 skb->csum))
			return 0;
		printk("hw tcp checksum failed\n");
		return -1;
	}
        if (sk->lock.users) {
                local_bh_enable();
                result = __tcp_checksum_complete(skb);
                local_bh_disable();
        } else {
                result = __tcp_checksum_complete(skb);
        }
        return result;
}

static __inline__ int
tcp_checksum_complete_user(struct sock *sk, struct sk_buff *skb)
{
	csum_complete_user_count++;
        return skb->ip_summed != CHECKSUM_UNNECESSARY &&
                __tcp_checksum_complete_user(sk, skb);
}

/* end functions copied from tcp_input.c */

#define update_rx_stats(IN_SKB) update_rx_stats_helper((IN_SKB), 0)
static void update_rx_stats_helper(struct sk_buff *in_skb, int print) {
	numRxPackets++;

	hist_addPoint(&rx_histogram, in_skb->len);

	numRxBytes += in_skb->len - TCP_SKB_CB(in_skb)->numDataChunks * sizeof(struct DataChunk);
	int overhead = TCP_SKB_CB(in_skb)->numDataChunks * sizeof(struct DataChunk) + in_skb->data - in_skb->head;
	if(0 || print) {
		printk("len = %d overhead = %d (%d)\n", in_skb->len, overhead, TCP_SKB_CB(in_skb)->numDataChunks);
	}
	numRxOverhead += overhead;
}

static inline void trickles_init_tcp_cb(struct sk_buff *skb) {
	TCP_SKB_CB(skb)->cont = NULL;
	TCP_SKB_CB(skb)->numDataChunks = 0;
	TCP_SKB_CB(skb)->chunksOverflow = NULL;
	TCP_SKB_CB(skb)->seq = -1;
	TCP_SKB_CB(skb)->end_seq = -1;
}

static int gDumpConvCont = 0;

static int trickles_rcv_impl(struct sock *sk, struct sk_buff *in_skb) {
	//printk("TricklesRcvImpl %d\n", count++);
#if 0
	if(!(sk->tp_pinfo.af_tcp.trickles_opt & TCP_TRICKLES_RSERVER))
		printk("t(%d) ", ntohl(in_skb->h.th->seq));
#endif
	gDumpConvCont = 0;

	struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;
	trickles_init_tcp_cb(in_skb);
	
#ifdef SOFTWARE_CSUM
	in_skb->ip_summed = 0;
#endif
	if (tcp_checksum_complete_user(sk, in_skb))
		goto csum_error;
	__skb_pull(in_skb, in_skb->h.th->doff * 4);

	in_skb->ip_summed = CHECKSUM_UNNECESSARY;
	in_skb->sk = sk;

	if(sk->tp_pinfo.af_tcp.trickles_opt & TCP_TRICKLES_RSERVER) {
		int result;
		// First process prequeue overflow
		struct sk_buff *pre_skb;

		LOG_PACKET(sk, -in_skb->h.th->ack_seq);
		while (can_alloc_trickles_msk(sk) &&
		       ((pre_skb = __skb_dequeue(&tp->t.prequeueOverflow))
			!= NULL)) {
			update_rx_stats(pre_skb);
			result = server_rcv_impl(sk, pre_skb);
			if(result == 0 || result == -EINVAL) {
				save_for_recycle(sk, pre_skb);
			} else {
				BUG_TRAP(result == -ENOMEM);
				RECORD_NOMEM();
				__skb_queue_head(&tp->t.prequeueOverflow, pre_skb);
				__skb_queue_tail(&tp->t.prequeueOverflow, in_skb);
				return 0;
			}
		}
		if(can_alloc_trickles_msk(sk)) {
			goto process_first;
		} else {
			// XXX should defer until later
			if(tp->t.prequeueOverflow.qlen < 20000) {
				__skb_queue_tail(&tp->t.prequeueOverflow, in_skb);
				return 0;
			} else {
				return -1;
			}
		}
		// optimization: process the rest of the prequeue before restoring FPU context
#ifndef USERTEST
		while (can_alloc_trickles_msk(sk) &&
		       ((in_skb = __skb_dequeue(&tp->ucopy.prequeue))
			!= NULL)) {
#endif
		process_first:
			update_rx_stats(in_skb);
			result = server_rcv_impl(sk, in_skb);
			if(result == 0 || result == -EINVAL) {
				save_for_recycle(sk, in_skb);
			} else {
				BUG_TRAP(result == -ENOMEM);
				RECORD_NOMEM();
				__skb_queue_tail(&tp->ucopy.prequeue, in_skb);
				break;
			}
#ifndef USERTEST
		}
#endif
		return 0;
	} else {
		int result;

		update_rx_stats(in_skb);
		//LOG_PACKET(sk, -in_skb->h.th->ack_seq);

		result = client_rcv_impl(sk, in_skb);
		if(result) {
			__kfree_skb(in_skb);
		}
		return 0;
	}
 csum_error:
	printk("CSUM error!\n");
	return -1;
}

#endif // USERTEST

/*
 *
 * Client handling
 *
 */

static int findAckables(struct sock *sk, int skip, struct sk_buff **skip_skb);
static void requestSlowStart(struct sock *sk);
static inline void client_inseq(struct sock *sk, struct sk_buff *in_skb, int noCont);

// RFC 2988 says 1 second is a good value. Linux uses 200ms
//#define MIN_SS_TIMEOUT ((HZ/5))
#define MIN_SS_TIMEOUT (HZ)

//#define MIN_SS_TIMEOUT (2 * HZ)
// RFC 2988 says 60 second is the right value
//#define MAX_SS_TIMEOUT (3*HZ)
#define MAX_SS_TIMEOUT (60*HZ)


/* slow start moderation */
void resetClientTimer(struct sock *sk) {
	struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;
	unsigned long expiration = jiffies;

	if(tp->t.state == TRICKLES_CLIENT_SYNACK) {
		expiration += 2 * HZ;
	} else {
		int timeout = MAX(RTO_IN_JIFFIES(sk), MIN_SS_TIMEOUT);
		timeout = MIN(timeout, MAX_SS_TIMEOUT);
#ifdef RANDOMIZE_SLOWSTART_TIMER
		timeout += random() % ((HZ * 30) / 1000);
#endif

		if(0 && trickles_ratelimit()) {
			printk("new timeout %d\n", timeout);
		}

		expiration += timeout;
	}
	// todo: change timeout to measured connection rtt
	if(!mod_timer(&tp->t.slowstart_timer, expiration)) {
		sock_hold(sk);
	}
}

static void enterRecoveryState(struct sock *sk, int isSlowStart);
struct UC_Continuation *
findUCContinuation(struct sock *sk, unsigned start, unsigned end);

void slow_start_timer(unsigned long data) {
	struct sock *sk = (struct sock *)data;
	struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;
	int numAcks = 0;
	int backedOff = 0;
	// TRACE_THIS_PACKET();

	static int lastRcvNxt = 0;
#if 0
	if(tp->t.rcv_nxt <= lastRcvNxt + 2) {
		TRACE_K_PACKETS(8);
	} else {
		TRACE_K_PACKETS(8);
	}
#endif
	lastRcvNxt = tp->t.rcv_nxt;

#if 0
	MSKTable_clear(tp->t.msk_table);
#endif

#if 0
	printk("slow start, rcv_nxt = %d, byteRcvNxt = %d, ", 
	       tp->t.rcv_nxt, tp->t.byteRcvNxt);
	SK_ucontList_dump(sk);
	SK_skiplist_dump(sk);
	SK_raw_ofo_queue_dump(sk);
	SK_data_ofo_queue_dump(sk);
	SK_data_request_dump(sk);
#endif

	record_delay(tp->t.RTO);
	SAVE_DELAY_STATS(sk);
	//printk("slow start timer 0\n");

	gNumSlowstart ++;
	//printk("slow start timer -2\n");
	if(0 && (clientDebugLevel >= 1 || ( 1 && gNumSlowstart % 10000 == 0) || usertest)) {
		printk("Slow start timer @ %lu, total = %d, numDataRequestMappings = %d, numContinuations = %d, numConversionRequests = %d, numContinuationRequests = %d, tp->copied_seq/rcv_nxt = %u/%u, tp->t.byteRcvNxt = %d, tp->t.rcv_nxt = %u, sk = %p", jiffies, gNumSlowstart, numDataRequestMappings, numContinuations, numConversionRequests, numContinuationRequests, tp->copied_seq, tp->rcv_nxt, tp->t.byteRcvNxt, tp->t.rcv_nxt, sk);
		DUMP_RTO(sk);
		printk("\n");
	}
	tp->t.in_flight = 0;
#ifndef USERTEST
	bh_lock_sock(sk);
	if (sk->state == TCP_CLOSE)
		goto out_unlock;
#endif // USERTEST

	int haveRequests = !empty(&tp->t.sentRequests) || !empty(&tp->t.queuedRequests);
	//printk("Slow start timer(%p), snd_una = %d, write_seq = %d\n", sk, tp->t.snd_una, tp->t.write_seq);

	//printk("slow start timer 1\n");

	// First, try to send out any pending acks
	if((numAcks = trickles_send_ack_impl(sk, 0)) == 0) {
#if 0
		printk("no acks, then %d %d %d \n",
		       tp->t.timerState & TRICKLES_ENABLE_DATA_TIMEOUT,
		       findUCContinuation(sk, tp->t.byteReqNext, tp->t.byteReqNext),
		   haveRequests);
#endif

		if((tp->t.timerState & TRICKLES_ENABLE_DATA_TIMEOUT)
		   || findUCContinuation(sk, tp->t.byteReqNext, tp->t.byteReqNext)
		   || haveRequests) {
			//#define STRICT_BUFFER_CHECK
#ifdef STRICT_BUFFER_CHECK // 0419 - fixing extraneous slowstarts with blocked client
			// NOTE!!! POSSIBLE RACE CONDITION WITH USERSPACE SINCE WE DON'T CHECK USER LOCK
			//printk("need slowstart 1\n");
			int haveRcvBuf = tp->rcv_nxt < tp->copied_seq + sk->rcvbuf;
			printk("HaveRcvBuf = %d (%d %d)\n",
			       haveRcvBuf, tp->rcv_nxt < tp->copied_seq + sk->rcvbuf);
			if(!IS_SEND_UCONTREQ_STATE(tp) ||
			   !empty(&tp->t.sentRequests) ||   // requests we can use
			   !empty(&tp->t.queuedRequests) || //  "" ""
			   (haveRcvBuf && // have space in buffer, and usable continuation
			    findUCContinuation(sk, tp->t.byteRcvNxt, tp->t.byteRcvNxt))) {
#if 0
			}
#endif
#else
			//printk("test a = %d %d %d(%d,%d)\n", !IS_SEND_UCONTREQ_STATE(tp), haveRequests, findUCContinuation(sk, tp->rcv_nxt, tp->rcv_nxt), tp->rcv_nxt, tp->rcv_nxt);

			if(IMPLIES(IS_SEND_UCONTREQ_STATE(tp), haveRequests) ||
			   findUCContinuation(sk, tp->t.byteRcvNxt, tp->t.byteRcvNxt)) {
#endif
				static int gNumSlowstart = 0;
				if(1 || (gNumSlowstart++ % 100 == 0) || clientDebugLevel >= 1) {
#if 0
					printk("Timing out @ %lu (%d times) sk = %p tp->{rcv_nxt, byteRcvNxt, window} = %u/%u/%u\n", jiffies, gNumSlowstart, sk, tp->rcv_nxt, tp->t.byteRcvNxt, tp->copied_seq- tp->rcv_nxt);
					printk("rtt = %u, total = %d, numDataRequestMappings = %d, numContinuations = %d, numConversionRequests = %d, numContinuationRequests = %d, tp->rcv_nxt = %u, tp->t.byteRcvNxt = %d tp->t.rcv_nxt = %u, sk = %p\n", tp->t.A, gNumSlowstart, numDataRequestMappings, numContinuations, numConversionRequests, numContinuationRequests, tp->rcv_nxt, tp->t.byteRcvNxt, tp->t.rcv_nxt, sk);
					DUMP_RTO(sk);
					printk("ContList Length = %d  Cont OFO queue length %d Data OFO queue length %d\n", tp->t.cont_list.len, tp->t.ofo_queue.qlen, tp->t.data_ofo_queue.qlen);
#endif
				}
				/* 1) Enter recovery mode
				   2) Initiate slow start
				*/
				backedOff = 1;
				enterRecoveryState(sk, 1);
				requestSlowStart(sk);
			} else {
				if(tp->t.conversionState == CONVERSION_IDLE) {
#ifdef STRICT_BUFFER_CHECK
					BUG_TRAP(haveRcvBuf);
#endif
					tp->t.timerState |= TRICKLES_NEED_SLOWSTART;
					//printk("need slowstart 2\n");
					tp->t.timerState &= ~TRICKLES_ENABLE_DATA_TIMEOUT;
				} else {
					if(trickles_ratelimit()) printk("no requests available for timeout ??? \n");
				}
			}
		}
	}
	if(numAcks) {
		printk("slow start num acks = %d\n", numAcks);
		SK_dump_vars(sk);
	}

	if(!disableTimeout) {
		if(haveRequests || ((tp->t.timerState & TRICKLES_ENABLE_DATA_TIMEOUT) &&
				    findUCContinuation(sk, tp->t.byteReqNext, tp->t.byteReqNext))) {
			if(!backedOff) {
				int newRTO = RTO_IN_JIFFIES(sk);
				newRTO = newRTO * 2;
				RTO_FROM_JIFFIES(sk, newRTO);
			}
			resetClientTimer(sk); // 0504 - back off timer if no progress made
		}
		// TRICKY: If !enable_data_timeout, or no continuation findUCContinuation(), we MUST reset the timer
		// when those states become true
	}
#ifndef USERTEST
out_unlock:
	PACKET_TRACE_FINISH();
	//printk("slow start timer -1\n");
	bh_unlock_sock(sk);
	sock_put(sk);
#endif // USERTEST
}

static void trickles_client_connected_impl(struct sock *sk) {
	struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;
	/* Called once client establishes connection */
	/*  1) Clear all timers
	   2) Initialize trickles timeout timer
	*/
#ifndef USERTEST
#if 1 // 10/04 -- duplicated earlier in initialization sequence to allow piggybacked data on synack
	tcp_clear_xmit_timers(sk);
	tp->t.slowstart_timer.function = &slow_start_timer;
	tp->t.slowstart_timer.data = (long)sk;
#endif
	resetClientTimer(sk);
#endif // USERTEST
}

inline int Sack_contains(Sack *sack, int seq);

#if 0
// replaced with rebuildAckProof (cleaner design)
static void advanceAckProof(AckProof *proof, __u32 seq) {
	int i, j;
	for(i=0; i < proof->numSacks; i++) {
		if(Sack_contains(&proof->sacks[i], seq)) {
			break;
		}
	}
	if(i == proof->numSacks) {
		printk("advanceAckProof Error: Could not find target seqnum\n");
		proof->numSacks = 0;
		return;
	}
	for(j=0; j < proof->numSacks - i; j++) {
		proof->sacks[j] = proof->sacks[i + j];
	}
	proof->numSacks = proof->numSacks - i;
}
#endif

//#define CURR_CONT(X) ((CONTINUATION_TYPE *)((X)->tp_pinfo.af_tcp.t.ack_curr ? (X)->tp_pinfo.af_tcp.t.ack_curr : (X)->tp_pinfo.af_tcp.t.ack_prev))

void AckProof_dump(AckProof *proof);
static void enterRecoveryState(struct sock *sk, int reqSlowStart) {
	struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;
	int newRTO = RTO_IN_JIFFIES(sk);

#ifdef SLOWSTART_ONLY
	reqSlowStart = 1;
#endif
	// enterRecoveryState may be called multiple times
	// during the same Fast Recovery, but only once per SlowStart attempt
	switch(tp->t.state) {
	case TRICKLES_CLIENT_NORMAL:
		if(reqSlowStart) {
			if(clientDebugLevel >= 1 || debugTransitions)
				printk("%p: Normal=>SlowStart\n", sk);
			tp->t.state = TRICKLES_CLIENT_SLOWSTART;
			newRTO *= 2;
			tp->t.clientStateCounter++;
			tp->t.request_snd_nxt++;
			tp->t.request_rcv_nxt = tp->t.request_snd_nxt;
		} else {
			if(clientDebugLevel >= 1 || debugTransitions) {
				printk("%p: Normal=>Recovery\n", sk);
				AckProof_dump(&tp->t.altProof);
			}
			tp->t.state = TRICKLES_CLIENT_RECOVERY;
			newRTO *= 2;
			tp->t.clientStateCounter++;
		}
		break;
	case TRICKLES_CLIENT_RECOVERY:
		if(reqSlowStart) {
			tp->t.state = TRICKLES_CLIENT_SLOWSTART;
			newRTO *= 2;
			if(clientDebugLevel >= 1 || debugTransitions)
				printk("%p: Recovery=>SlowStart\n", sk);
			tp->t.clientStateCounter++;
			tp->t.request_snd_nxt++;
			tp->t.request_rcv_nxt = tp->t.request_snd_nxt;
		} else {
			// already in recovery state; take no action
			if(clientDebugLevel >= 1 || debugTransitions) {
				printk("%p: Recovery=>Recovery\n", sk);
				AckProof_dump(&tp->t.altProof);
			}
			// DO NOT UPDATE CLIENTSTATE COUNTER (or any other state)
			return;
		}
		break;
	case TRICKLES_CLIENT_SLOWSTART:
		BUG_TRAP(reqSlowStart);
		newRTO *= 2;
		if(clientDebugLevel >= 1 || debugTransitions)
			printk("%p: SlowStart=>SlowStart\n", sk);
		// Unlike client_recovery=>client_recovery transition,
		// take action: send another slow start request
		tp->t.clientStateCounter++;
		tp->t.request_snd_nxt++;
		tp->t.request_rcv_nxt = tp->t.request_snd_nxt;
		break;
	}

	RTO_FROM_JIFFIES(sk, newRTO);
}

#define NEWER(S0,S1) ((S0)>(S1))
static void ContList_insert(struct sock *sk, CONTINUATION_TYPE *cont) {
	struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;
	CONTINUATION_TYPE *cont_curs, *currentVal = cont, *newCont;
	/* sorted insert into cont list */
	int replaced = 0;
	int replaceAckPrev = 0;
	if(tp->t.previous_base > cont->TCPBase) {
		printk("previous base > cont->TCPBase. clientstate %d clientstatecounter %d\n", cont->clientState, tp->t.clientStateCounter);
	}
	gInsertSeq = cont->seq;

	for(cont_curs = (CONTINUATION_TYPE*)tp->t.cont_list.prev;
	    cont_curs != (CONTINUATION_TYPE*)&tp->t.cont_list;
	    cont_curs=cont_curs->prev) {
		if(cont_curs->seq < cont->seq)
			break;
	}
	if(cont_curs->next != (CONTINUATION_TYPE*)&tp->t.cont_list &&
	   cont_curs->next->seq == cont->seq) {
		CONTINUATION_TYPE *dup = cont_curs->next;
		if(NEWER(cont->clientState, dup->clientState)) {
			newCont = copyClientSide_Continuation(cont, GFP_ATOMIC);
			if(newCont == NULL) {
				printk("ContList_Insert(1); out of memory\n");
				goto skip_insert;
			}

			replaced = 1;
			// get rid of old one
			if(tp->t.ack_prev == dup)
				replaceAckPrev = 1;
			if(clientDebugLevel >= 2)
				printk("Got rid of old cont %u\n", dup->seq);
			unlinkCont(dup);
			MARK_PC(dup);
			freeClientSide_Continuation(dup);
			goto skip_alloc;
		} else {
			// dont use new one
			if(tp->t.ack_prev == cont)
				printk("ContList_insert: invalid condition\n");
			if(clientDebugLevel >= 2)
				printk("Got rid of new cont %u\n", cont->seq);
			currentVal = dup;
			goto skip_insert;
		}
	}
	/* create copy for transport-level acking and processing */
	newCont = copyClientSide_Continuation(cont, GFP_ATOMIC);
	if(newCont == NULL) {
		printk("ContList_Insert: Out of memory\n");
		goto skip_insert;
	}
	skip_alloc:
	newCont->mark |= 0x2;

	// don't need user-level data while performing transport-level processing
	newCont->ucont_data = NULL;
	newCont->input = NULL;
	//printk("contlist_insert: newCont %p cont %p\n", newCont, cont);
	insert((struct alloc_head*)newCont, (struct alloc_head*)cont_curs, (struct alloc_head*)cont_curs->next);
	if(replaceAckPrev || tp->t.ack_prev == cont) {
		tp->t.ack_prev = newCont;
		INTEGRITY_CHECK(sk, tp->t.ack_prev);
		SAVE_ACK_PREV(tp);
	}
	if(!(!tp->t.ack_prev || tp->t.ack_prev->next)) {
		// 0429
		BUG_TRAP((!tp->t.ack_prev || tp->t.ack_prev->next));
		BUG();
	}
 skip_insert:
	;
}

int breakpoint_seq = -1;
int paranoia = 0;

#if 0
struct Request *copyRequest(struct Request *req) {
	struct Request *rval;
	switch(req->type) {
	case MREQ_CONTINUATION: {
		struct ContinuationRequest *contReq = (struct ContinuationRequest *)req, *newContReq;
		newContReq = kmalloc_ContinuationRequest(GFP_ATOMIC);
		if(newContReq == NULL) {
			printk("Out of memory while copying request\n");
			return NULL;
		}
		*newContReq = *contReq;
		newContReq->conts = kmalloc(sizeof(newContReq->conts[0]) * newContReq->numConts, GFP_ATOMIC);
		if(newContReq->conts == NULL) {
			printk("Out of memory while copying request\n");
			kfree(newContReq);
			return NULL;
		}
		memcpy(newContReq->conts, contReq->conts, sizeof(contReq->conts[0]) * contReq->numConts);
		rval = (struct Request *)newContReq;
		break;
	}
	case MREQ_CONVERSION: {
		struct ConversionRequest *convReq = (struct ConversionRequest *)req, *newConvReq;
		newConvReq = kmalloc_ConversionRequest(GFP_ATOMIC);
		if(newConvReq == NULL) {
			printk("Out of memory while copying request\n");
			return NULL;
		}
		*newConvReq = *convReq;
		rval = (struct Request*)newConvReq;
		break;
	}
	default:
		rval = NULL;
		BUG();
	}
	rval->prev = rval->next = NULL;
	rval->list = NULL;
	return rval;
}
#endif

void freeRequest(struct Request *req) {
	BUG_TRAP(req->allocated);
	req->allocated = 0;

	switch(req->type) {
	case MREQ_CONTINUATION: {
		struct ContinuationRequest *contReq = (struct ContinuationRequest *)req;
		/* need to deallocate continuation array */
		kfree(contReq->conts);
		numContinuationRequests--;
		break;
	}
	case MREQ_CONVERSION: {
		struct ConversionRequest *convReq = (struct ConversionRequest *)req;
		/* skb references are dropped when snd_una is advanced, so don't perform that deallocation here */
		if(convReq->incomplete) {
			kfree(convReq->incompletePred);
		} else {
			if(convReq->completePred != NULL) {
				UC_CONTINUATION_TRYFREE(convReq->completePred);
			}
		}
		numConversionRequests--;
		break;
	}
	default:
		BUG();
	}
	BUG_TRAP(!req->list);
	kfree(req);
}

inline void pushRequests(struct sock *sk) {
	/* Try to send an ack */
	trickles_send_ack_impl(sk, 0);
}

inline void cleanTxQueue(struct sock *sk) {
	struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;
	struct sk_buff *skb = NULL;
	for(skb = tp->t.requestBytes.next; skb != (struct sk_buff*)&tp->t.requestBytes; skb = skb->next) {
		if(TCP_SKB_CB(skb)->end_seq <= tp->t.snd_una) {
			struct sk_buff *clean = skb;
			skb = skb->prev;
			__skb_unlink(clean, &tp->t.requestBytes);
			kfree_skb(clean);
		}
	}
}

int gSocketConversionCount = 0;
void queueConversionRequests(struct sock *sk) {
	// E.g., if there are any overlaps with previous conversion requests, it nukes the old ones
	struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;
	struct ConversionRequest *req;
	struct sk_buff *skb = NULL;
	int found = 0;
	BUG_TRAP(tp->t.write_seq - tp->t.snd_una > 0);
	req = kmalloc_ConversionRequest(GFP_ATOMIC);
	if(req == NULL) {
		printk("queueConversionRequests: Out of memory!\n");
		BUG();
	}
	for(skb = tp->t.requestBytes.next; skb != (struct sk_buff*)&tp->t.requestBytes; skb = skb->next) {
		if(TCP_SKB_CB(skb)->end_seq <= tp->t.snd_una) {
			struct sk_buff *clean = skb;
			skb = skb->prev;
			__skb_unlink(clean, &tp->t.requestBytes);
			kfree_skb(clean);
		} else if(SKB_CONTAINS(skb, tp->t.snd_una)) {
			found = 1;
			break;
		}
	}
	if(!found) {
		printk("Could not find matching bytes to convert\n");
		kfree(req);
		BUG();
		return;
	}
	initCompleteConversionRequest(req,
				      tp->t.prevConvCont,
				      /* Data */
				      skb,
				      tp->t.snd_una);
#if 0
	printk("complete conversion @ %d, byteRcvNxt = %d\n", 
	       tp->t.snd_una, tp->t.byteRcvNxt);
#endif
	gSocketConversionCount++;
	if(gDumpConvCont || 
	   (tp->t.byteRcvNxt > 0 && tp->t.prevConvCont->validStart == 0)) {
		printk("count = %d, byteRcvNxt = %d, prevConvCont: %p = ", gSocketConversionCount, tp->t.byteRcvNxt, tp->t.prevConvCont);
		UC_Continuation_dump(tp->t.prevConvCont);
	}
#if 0
	if(tp->t.prevConvCont->validStart == 0) {
		printk("new continuation added with validStart = 0\n");
		UC_Continuation_dump(&tp->t.prevConvCont);
	}
#endif
	// printk("%p: init complete conversion request: %d-%d\n", sk, tp->t.snd_una, TCP_SKB_CB(skb)->end_seq);
	//printk("0: start = %d %d\n", tp->t.snd_una, req->start);

	{
		// XXX fast bandaid fix
		struct Request *curr;
		for(curr = (struct Request*)tp->t.queuedRequests.next; 
		    (struct alloc_head_list *) curr != &tp->t.queuedRequests;
		    ) {
			struct Request *clean = curr;
			curr = (struct Request *)curr->next;

			if(clean->type == MREQ_CONVERSION) {
				struct ConversionRequest *creq = (struct ConversionRequest *)
					clean;
				//printk("found conversion: %d-%d\n", creq->start, creq->end);
				if(intersect_range(creq->start, creq->end, 
						   req->start, req->end)) {
					BUG_TRAP(creq->start <= req->start && 
						 creq->end <= req->end);
					//printk("freeing request %d-%d\n", creq->start ,creq->end);
					unlink((struct alloc_head*)creq);
					freeRequest((struct Request *)creq);
				}
			}
		}
	}

	queueNewRequest(sk, (struct Request *)req);
}

inline void finishIncompleteRequest(struct sock *sk) {
	printk("finish incomplete request\n");
	struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;
	struct ConversionRequest *req = tp->t.newIncompleteRequest;
	struct sk_buff *skb;
	int found = 0;
	if(req == NULL) {
		printk("finishIncompleteRequest, but no pending incomplete request\n");
		BUG();
	}
	BUG_TRAP(req->incomplete);

	for(skb = tp->t.requestBytes.next; skb != (struct sk_buff*)&tp->t.requestBytes; skb = skb->next) {
		if(TCP_SKB_CB(skb)->end_seq <= tp->t.snd_una) {
			struct sk_buff *clean = skb;
			skb = skb->prev;
			__skb_unlink(clean, &tp->t.requestBytes);
			kfree_skb(clean);
		} else if(SKB_CONTAINS(skb, tp->t.snd_una)) {
			found = 1;
			break;
		}
	}
	if(!found) {
		printk("Could not find matching bytes to convert\n");
		BUG();
		return;
	}
	tp->t.newIncompleteRequest = NULL;

	req->data = skb;
	req->offset = tp->t.snd_una - TCP_SKB_CB(skb)->seq;
	req->start = TCP_SKB_CB(skb)->seq + req->offset;

	printk("1: start = %d\n", req->start);

	req->end = req->start;
	queueNewRequest(sk, (struct Request*)req);
}

static inline int processIncompleteResponse(struct sock *sk, struct WireUC_CVT_IncompleteResponse *incompleteResp, int responseLen) {
	/* Update conversion state, and use the incomplete
	   continuationn to generate and enqueue the request for the
	   next step in the parse */
	struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;
	struct ConversionRequest *newConvReq;
	struct sk_buff *skb;
	int foundNextData = 0;
	struct WireUC_CVT_IncompleteContinuation *pred;
	unsigned predLength;
	unsigned ackSeq = ntohl(incompleteResp->ack_seq);
	int bytesConsumed = tp->t.snd_una;

	/* Need to finish this conversion. So find
	   next bytestream data to send, enqueue new
	   request in request queue */

	/* XXX This code does not gracefully handle
	   parallel parse requests */
	if(ackSeq > tp->t.snd_una) {
		tp->t.snd_una = ackSeq;
		if(tp->t.snd_una > tp->t.write_seq) {
			printk("BUG! after byte position update, snd_una %d > write_seq %d !\n", tp->t.snd_una, tp->t.write_seq);
			tp->t.snd_una = tp->t.write_seq;
			return -1;
		}
	}
	bytesConsumed = tp->t.snd_una - bytesConsumed;
	// xxx Should not be TRICKLES_MSS (more like TCP_MSS)
	if(bytesConsumed == 0 &&
	   tp->t.snd_end - tp->t.snd_una >= TRICKLES_MSS) {
		printk("Error: bytesConsumed == 0, but full MSS was sent! Forward progress cannot be made\n");
		return -1;
	}
	/* Deallocate any elements in send queue that we no longer need, and find next skb to use */
	for(skb = tp->t.requestBytes.next; skb != (struct sk_buff*)&tp->t.requestBytes; skb = skb->next) {
		if(TCP_SKB_CB(skb)->end_seq <= tp->t.snd_una) {
			struct sk_buff *clean = skb;
			skb = skb->prev;
			__skb_unlink(clean, &tp->t.requestBytes);
			kfree_skb(clean);
		}
		if(SKB_CONTAINS(skb, tp->t.snd_una)) {
			foundNextData = 1;
			break;
		}
	}
	newConvReq = kmalloc_ConversionRequest(GFP_ATOMIC);
	if(newConvReq == NULL) {
		printk("Out of memory while allocating Request to continue incomplete conversion!\n");
		return -1;
	}
	predLength = responseLen - ((char*)&incompleteResp->newCont - (char*)incompleteResp);
	pred = kmalloc_dup(&incompleteResp->newCont, predLength, GFP_ATOMIC);
	if(pred == NULL) {
		kfree(newConvReq);
		printk("kmalloc_dup() returned error\n");
		return -1;
	}
	if(!foundNextData) {
		// Defer installation of new request until data arrives from userlevel
		BUG_TRAP(tp->t.newIncompleteRequest == NULL);
		tp->t.conversionState = CONVERSION_WAITFORUSER;
		tp->t.newIncompleteRequest = newConvReq;
		initIncompleteConversionRequest(newConvReq,
						pred, predLength,
						/* no data yet */
						NULL, -1);
		//printk("process_incomplete_request set conversion state to waitforuser\n");
	} else {
		BUG_TRAP(tp->t.newIncompleteRequest == NULL);
		tp->t.conversionState = CONVERSION_WAITFORSERVER;
		tp->t.newIncompleteRequest = NULL;
		initIncompleteConversionRequest(newConvReq,
						pred, predLength,
						/* data */
						skb,
						tp->t.snd_una - TCP_SKB_CB(skb)->seq);
		queueNewRequest(sk, (struct Request*)newConvReq);
		//printk("process_incomplete_request set conversion state to waitforserver\n");
	}
	return 0;
}

#define LEFT 0
#define RIGHT 1

/* insertNewDep is used to insert a dependency into a blank range where no previous dependency ever existed */
static inline int insertNewDep(struct UC_DependencyNode *left, struct UC_DependencyNode *right, struct UC_DependencyNode *newDep, int side) {
	unsigned newStart, newEnd;
	struct UC_DependencyNode *clone;
	struct alloc_head *prev, *next;

	if(left == NULL) {
		newStart = newDep->start;
	} else {
		newStart = MAX(left->end, newDep->start);
		prev = (struct alloc_head*)left;
		next = left->next;
	}
	if(right == NULL) {
		newEnd = newDep->end;
	} else {
		newEnd = MIN(newDep->end, right->start);
		prev = right->prev;
		next = (struct alloc_head*)right;
	}
	switch(side) {
	case LEFT:
		if(right) {
			if(newDep->start >= right->start) {
				printk("insertNewDep: supposed to insert on left, but newDep is not at the left\n");
				return -1;
			}
		} else {
			printk("insertNewDep: supposed to insert on left, but nothing to the right\n");
			return -1;
		}
		break;
	case RIGHT:
		if(left) {
			if(newDep->end <= left->end) {
				printk("insertNewDep: supposed to insert on right, but newDep is not at the right\n");
				return -1;
			}
		} else {
			printk("insertNewDep: supposed to insert on right, but nothing to the left\n");
			return -1;
		}
		break;
	default:
		printk("insertNewDep: unknown side\n");
		return -1;
	}
	clone = copyUC_DependencyNode(newDep);
	if(clone == NULL) {
		printk("Out of memory while creating dependency at %d side\n", side);
		return -1;
	}
	insert((struct alloc_head*)clone, prev, next);
	return 0;
}

int addNewUC_Continuation(struct sock *sk, struct UC_Continuation *newCont) {
	struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;
	struct UC_Continuation *insertPos;
	// printk("adding continuation "); UC_Continuation_dump(newCont);
	
	if(newCont->validEnd < tp->t.byteRcvNxt) {
		BUG_TRAP(newCont->validEnd >= tp->t.byteRcvNxt);
		printk("%d - %d\n", newCont->validEnd, tp->t.byteRcvNxt);
		return 1;
	}

	// find place to insert new continuation
	alloc_head_reverse_walk(&tp->t.ucontList, insertPos) {
		/* insert the new continuation in the proper location */
		if(insertPos->clientValidStart < newCont->validStart) break;
	}
	newCont->clientValidStart = newCont->validStart;
	newCont->clientValidEnd = newCont->validEnd;

	// find intersections
	// Real validStart and validEnd should NOT be touched in this block
	struct alloc_head_list *insertionList = &tp->t.ucontList;
	insert((struct alloc_head*)newCont,
	       (struct alloc_head*)insertPos, (struct alloc_head*)insertPos->next);

	// Now, resolve overlaps
	struct UC_Continuation *finger = (struct UC_Continuation *)insertPos, *nextCont;

	if((struct alloc_head_list*)finger == insertionList) {
		finger = (struct UC_Continuation*) finger->next;
	}
	unsigned lastByte = newCont->clientValidEnd;
	for(; (struct alloc_head_list*)finger->next != insertionList; finger = nextCont) {
		nextCont = (struct UC_Continuation *)finger->next;
		unsigned start = MAX(finger->clientValidStart, nextCont->clientValidStart),
			end = MIN(finger->clientValidEnd, nextCont->clientValidEnd);
		if(start < end) {
			struct UC_Continuation *left = NULL, *middle = NULL, *right = NULL,
				*older = NULL, *newer = NULL;
			struct alloc_head *iPrev = finger->prev;
			struct alloc_head *iPrev0 = iPrev;
			struct alloc_head *iNext = nextCont->next;

			// let newest continuation take intersection
			if(finger->seq > nextCont->seq) {
				older = nextCont;
				newer = finger;
			} else {
				older = finger;
				newer = nextCont;
			}
			if(older->clientValidStart < start) {
				left = older;
			}
			middle = newer;
			if(older->clientValidEnd > end) {
				if(left == older) {
					struct UC_Continuation *older1 = copyUC_Continuation(older);
					if(older1 == NULL) {
						printk("Out of memory while splitting continuation\n");
						return -1;
					}
#if 0 // 0707 -- unclear ???
					right->prev = right->next = NULL;
					right->list = NULL;
#endif
					right = older1;
				} else {
					right = older;
				}
			} else {
				if(!left) {
					BUG_TRAP(older != NULL);
					// older completely overlapped
					unlink((struct alloc_head*)older);
					UC_CONTINUATION_TRYFREE(older);
				}
			}
			if(left) {
				if(left->list)
					unlink((struct alloc_head*)left);
				left->clientValidEnd = start;
			}
			if(middle) {
				if(middle->list)
					unlink((struct alloc_head*)middle);
				// no clientValid* adjustment necessary, since middle is preserved
			}
			if(right) {
				if(right->list)
					unlink((struct alloc_head*)right);
				right->clientValidStart = end;
			}
			if(left) {
				insert((struct alloc_head*)left, iPrev, iNext);
				iPrev = (struct alloc_head *)left;
			}
			if(middle) {
				insert((struct alloc_head*)middle, iPrev, iNext);
				iPrev = (struct alloc_head*)middle;
			}
			if(right) {
				insert((struct alloc_head*)right, iPrev, iNext);
				iPrev = (struct alloc_head*)right;
			}
			/* Sanity checks */
			{
				struct UC_Continuation *finger = (struct UC_Continuation*)iPrev0;
				while((struct alloc_head*)finger->next != iNext) {
					if((struct alloc_head_list*)finger != insertionList &&
					   (struct alloc_head_list*)finger->next != insertionList) {
						BUG_TRAP(finger->clientValidEnd <=
							 ((struct UC_Continuation*)finger->next)->clientValidStart);
					}
					finger = (struct UC_Continuation*)finger->next;
				}
			}
			nextCont = (struct UC_Continuation*)iPrev0; // XXX iNext->prev is a more efficient resumption point
		}
		if(end >= lastByte) {
			// no more overlaps possible
			break;
		}
	}
	// it's possible for client timer to block because we dont have continuations
	// XXX we may wish to guard this with more stringent checks to avoid unnecessary timeouts?
	resetClientTimer(sk);
	return 0;
}

void updateParent(struct sock *sk, enum UserRequestType matchType, 
		  unsigned matchID /* the sequence number of the parent */ ,
		  unsigned numSiblings, unsigned position) {
	struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;
	if((tp->trickles_opt & TCP_TRICKLES_PAR_REQUEST) && 
	   matchType == MREQ_CONVERSION) {
		return; // MREQ_COMPLETE is cleared when UC_COMPLETE is received
	} else {
	/* Additional POSTCONDITION:
	   tp->t.request_rcv_nxt updated
	*/
	int k;
	int foundCleanable = 0;
	struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;
	struct alloc_head_list *list_heads[] = {&tp->t.sentRequests,
						&tp->t.queuedRequests};
	struct Request *parent_req;
	for(k=0; k < sizeof(list_heads)/sizeof(list_heads[0]); k++) {
		struct alloc_head_list *head = list_heads[k];
		alloc_head_walk(head, parent_req) {
			unsigned positionMask = 1 << position;
			unsigned allMask;
			if(matchID != parent_req->seq) {
				continue;
			}
			if(matchType != MREQ_WILD && parent_req->type != matchType) {
				printk("updateParent: type %d %d do not match\n", 
				       matchType, parent_req->type);
				return;
			}
			foundCleanable = 1;

			if(numSiblings > MAX_MREQ_CHILDREN) {
				printk("Too many siblings!\n");
				return;
			}
			if(position >= numSiblings) {
				printk("position >= numSiblings! %d, %d\n", 
				       position, numSiblings);
				return;
			}
			if(!(parent_req->numChildren == 0 ||
			     numSiblings == parent_req->numChildren)) {
				printk("Inconsistent number of siblings!\n");
				return;
			}
			if(parent_req->childrenMask & positionMask) {
#if 0
				printk("Already received this child, %d %d\n",
				       parent_req->childrenMask, positionMask);
#endif
				return;
			}
			parent_req->numChildren = numSiblings;
			if(parent_req->numChildren == 0) {
				printk("numChildren == 0 (not possible, because we just received a child\n");
				return;
			}
			parent_req->childrenMask |= positionMask;
			allMask = (unsigned)(1 << ((unsigned)parent_req->numChildren)) - 1;

			if((parent_req->childrenMask & allMask) == allMask) {
				/* Server may not have generated an update covering the entire continuation. If not, resubmit request */
				switch(parent_req->type) {
				case MREQ_WILD:
				case MREQ_CONTINUATION:
				case MREQ_CONVERSION: {
					// Deallocate parent
					// avoid stale pointer dereference when doing next step of alloc_head_walk
					struct Request *clean = parent_req;
					BUG_TRAP(parent_req->seq == tp->t.request_rcv_nxt);
					tp->t.request_rcv_nxt++;

					parent_req = (struct Request *)clean->prev;
					unlink((struct alloc_head*)clean);
					freeRequest(clean);
					break;
				}
				default:
					printk("updateParent: unsupported parent type\n");
					BUG();
				}
			}
		}
		/* back in outer loop */
		if(foundCleanable) {
			break;
		}
	}
	if(!foundCleanable) {
		// printk("Error: could not find matching request in reliable request queue!\n");
	}
	}
}

void removeObsoleteContinuations(struct sock *sk) {
	struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;
	struct UC_Continuation *ucont;
	int count = 0;
	alloc_head_walk(&tp->t.ucontList, ucont) {
		if(ucont->kernel.obsoleteAt <= tp->t.byteRcvNxt) {
			struct UC_Continuation *clean = ucont;
#if 0
			printk("%d: Removed continuation c=%d o=%d [%d-%d] [%d-%d]\n", jiffies,
			       count, clean->kernel.obsoleteAt,
			       clean->validStart, clean->validEnd,
			       clean->clientValidStart, clean->clientValidEnd);
#endif
			ucont = (struct UC_Continuation*)ucont->prev;
			unlink((struct alloc_head*)clean);
			count++;
			gLastRemovedCont = *clean;
			UC_CONTINUATION_TRYFREE(clean);
		}
	}
}

void removeObsoleteDependencies(struct sock *sk) {
	struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;
	struct UC_DependencyNode *depNode;
	/* Drop reference count for dependency nodes that we no longer need for requesting new data */
	alloc_head_walk(&tp->t.depNodeList, depNode) {
		struct UC_DependencyNode *prev = (struct UC_DependencyNode*)depNode->prev;
		if(freeDependencyNode(sk,depNode) == 0) {
			/* dependency was freed and unlinked, so avoid dereferencing a dangling pointer */
			depNode = prev;
		}
	}
}

static void DataRequestMapping_hintFixup(struct DataRequestMapping *map) {
	unsigned realEnd  = UC_Continuation_actualEnd(map->ucont);
	if(realEnd < map->end) {
		if(trickles_ratelimit())
			printk("fixing up %d=>%d\n", map->end, realEnd);
		map->end = realEnd;
	}
}

static inline void removeObsoleteDataRequestMaps(struct sock *sk, unsigned transportSeq) {
	/* Side effect: updates rtt estimate */
	struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;
	int i;
	struct DataRequestMapping *dataReqMap, *nextDataReqMap;
	struct alloc_head_list* dataRequestLists[] = {
		&tp->t.dataRequestMap,
		&tp->t.missingDataMap};

	TIMING_CTX_DEF0("removeObsoleteDataRequestMaps", "requestMap", "missingMap");
	TIMING_CTX_DEF1(1,1);
	reinitTimingCtx(&ctx);
	for(i=0; i < 2; i++) {
		struct alloc_head_list *currList = dataRequestLists[i];
		recordSample(&ctx, i);
		for(dataReqMap = (struct DataRequestMapping *)currList->next;
		    dataReqMap != (struct DataRequestMapping *)currList;
		    dataReqMap = nextDataReqMap) {
			int freed = 0;
			nextDataReqMap = dataReqMap->next;

			if(dataReqMap->end <= tp->t.byteRcvNxt) {
				unlink((struct alloc_head*)dataReqMap);
				/* update rtt estimate if obsolete request matches current packet */
				// XXX - with this algorithm, reordering inflates rtt (timing is updated when the packet can be delivered in-order, not when it is first received)
				// XXX should we test the sequence number?
				if(1 /* || dataReqMap->transportResponseSeqStart <= transportSeq &&
					transportSeq < dataReqMap->transportResponseSeqEnd */) {
#ifdef FIXEDRTT
					tp->t.A = (FIXEDRTT);
#else
					// code moved to trickles_client_rcv
#endif
					{
						static int rttCounter = 0;
						rttCounter++;
						if(clientDebugLevel >= 2) {
							if(rttCounter % 1000 == 0)
								printk("HZ=%d delta %lu, new rtt %d %d/8\n", HZ, jiffies - dataReqMap->timestamp, tp->t.A >> 3, tp->t.A & 0x7);
						}
					}
				}
				freeDataRequestMapping(dataReqMap);
				freed = 1;
				resetClientTimer(sk);
				continue;
			}
			// t.rcvNxt has advanced past the end of the transport sequence. That means all RPCs have either completed, or we've given up
			// First, apply any potential fixups to the dataRequest based on SKIP updates
			DataRequestMapping_hintFixup(dataReqMap);

			if(!(dataReqMap->start < dataReqMap->end)) {
				// zero- or negative length request
				unlink((struct alloc_head*) dataReqMap);
				freeDataRequestMapping(dataReqMap);
				continue;
			}

			if(!freed && dataReqMap->sent &&
			   !dataReqMap->completed && // hint
			   tp->t.rcv_nxt >= dataReqMap->transportResponseSeqEnd) {
				//printk("tp->t.rcv_nxt = %u dataReqMap->transportResponseSeqEnd = %d\n", tp->t.rcv_nxt, dataReqMap->transportResponseSeqEnd);
				// dataReqMap is still valid
				// If tp->t.rcv_nxt >= transportSeqEnd, then the server may not have sent us the full request.
				// Find missing parts of the request, and resubmit

				// save old head
				struct alloc_head *prevMap = (struct alloc_head*) dataReqMap->prev,
					*nextMap = (struct alloc_head*)dataReqMap->next;
				int inserted = 0;
				int lastEnd = MAX(dataReqMap->start, tp->t.byteRcvNxt);
				struct sk_buff *finger = tp->t.ofo_queue.next;
				unlink((struct alloc_head*)dataReqMap);

				// check whether we're closer to the left or the right
				skb_queue_walk(&tp->t.data_ofo_queue, finger) {
					// detect overlap
					int minSeq = MAX(TCP_SKB_CB(finger)->seq, dataReqMap->start);
					int maxSeq = MIN(TCP_SKB_CB(finger)->end_seq, dataReqMap->end);
					if(maxSeq >= dataReqMap->end) {
						break;
					}
					if(minSeq < maxSeq) {
						// overlap
						if(lastEnd < minSeq) {
							// void between last skb and this skb; ask server to fill it in
							RECORD_MISSINGDATAMAP_INSERTION_HELPER(lastEnd, minSeq);
							submitDerivedDataRequestMapping(sk, dataReqMap, lastEnd, minSeq);
							inserted = 1;
#ifdef SPEW_PARTIAL
							printk("Inserted %d-%d\n", lastEnd, minSeq);
#endif
						}
						lastEnd = maxSeq;
					}
				}

				if(lastEnd < dataReqMap->end) {
					int myStart = lastEnd,
						myEnd = dataReqMap->end;
					if(!inserted) {
						// common case: server omitted data at the end of the request.
						// Reuse existing mapping
						RECORD_MISSINGDATAMAP_INSERTION_HELPER(myStart, myEnd);
						submitDataRequestMapping(sk, dataReqMap, myStart, myEnd);
#ifdef SPEW_PARTIAL
						printk("Inserted %d-%d\n", myStart, myEnd);
#endif
					} else {
						RECORD_MISSINGDATAMAP_INSERTION_HELPER(myStart, myEnd);
						submitDerivedDataRequestMapping(sk, dataReqMap, myStart, myEnd);
#ifdef SPEW_PARTIAL
						printk("Inserted %d-%d\n", myStart, myEnd);
#endif
					}
				} else {
					if(!inserted) {
						// request is completely covered; put it back
						dataReqMap->completed = 1;
						insert((struct alloc_head*)dataReqMap, prevMap, nextMap);
					}
				}
			}
		}
		recordSample(&ctx, i);
	}
	printTimings(&ctx);
}

void UpdateClientTransportState(struct sock *sk, struct sk_buff *skb, CONTINUATION_TYPE *cont) {
	struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;
	// if noCont, then no available information for updating state machine
	BUG_TRAP(cont->seq <= tp->t.rcv_nxt);
#define UPTODATE(CONT) ((CONT)->clientState == tp->t.clientStateCounter)
	/* Transport level updates */
	if(cont->continuationType == CONTTYPE_MINIMAL) {
		// minimal continuation type cannot update transport state
		return;
	}
	switch(tp->t.state) {
	case TRICKLES_CLIENT_NORMAL:
		if(cont->firstChild)
			tp->t.in_flight = MAX(0, tp->t.in_flight - 1);
		break;
	case TRICKLES_CLIENT_RECOVERY:
		if(cont->state == CONT_BOOTSTRAP &&
		   UPTODATE(cont)) {
			if(clientDebugLevel >= 2)
				printk("received bootstrap continuation\n");
			/* during recovery, need to switch to bootstrap continuation */
			/* If bootstrap state, fall through to check if we should exit from recovery */
			goto exit_recovery;
		} else {
			break;
		}
	case TRICKLES_CLIENT_SLOWSTART:
	exit_recovery:
		if(UPTODATE(cont) && cont->seq == cont->TCPBase) {
			/* exit recovery */
			CONTINUATION_TYPE *cont_curs, *next;
			__u32 prev_seq = tp->t.ack_prev->TCPBase; // 0501 cleanup
			if(clientDebugLevel >= 1)
				printk("client_rcv: exit recovery or slow start : seq = %u oldBase = %u newBase = %u startCwnd = %u\n", cont->seq,
				       prev_seq, cont->TCPBase, cont->startCwnd);

			tp->t.standardProof.numSacks = 0;
			AckProof_update(sk, &tp->t.standardProof, cont);
			for(cont_curs = (CONTINUATION_TYPE*)tp->t.cont_list.next;
			    cont_curs != (CONTINUATION_TYPE*)&tp->t.cont_list;
			    cont_curs = next) {
				next = (CONTINUATION_TYPE*)cont_curs->next;

				// 0424 - tighten up conditions to detect inconsistent states
				/*
				if(((tp->t.state == TRICKLES_CLIENT_SLOWSTART && UPTODATE(cont_curs)) ||
				    ((tp->t.state == TRICKLES_CLIENT_RECOVERY) && cont_curs->seq >= cont->TCPBase))) {
				*/
				if(UPTODATE(cont_curs) && cont_curs->TCPBase >= cont->TCPBase) {
					BUG_TRAP(cont_curs->TCPBase >= cont->TCPBase);
					AckProof_update(sk, &tp->t.standardProof, cont_curs);
				} else {
					/* there should not be any older continuations in list */
					// XXX 0426 - Additional violation situations are possible if requestSlowStart fails because it cannot find a continuation that can be used for the slow start request
					if(!(cont_curs->clientState == tp->t.clientStateCounter-2 /* recovery followed by slow start */ ||
					     cont_curs->clientState == tp->t.clientStateCounter-1 /* recovery */||
					     cont_curs->clientState == tp->t.clientStateCounter)) {
						if(!disableSevereErrors)
							printk("%p: cleaning violation: cursor state %d current client state %d\n",
							       sk, cont_curs->clientState, tp->t.clientStateCounter);
					}
					BUG_TRAP(cont_curs != cont);
					unlinkCont(cont_curs);
					MARK_PC(cont_curs);
#if 1 // 0430 disabled to isolate bug (yes this reveals a bunch of memory errors)
					freeClientSide_Continuation(cont_curs);
#else
					if((int)cont_curs & 0xfff) {
						BUG();
					}
					BUG_TRAP(((int)cont_curs & 0xfff) == 0);
					zap_virt(cont_curs);
#endif
				}
			}
			/* only up-to-date continuations in cont_list now */
			tp->t.altProof = tp->t.standardProof;
#if 0
			printk("standard ");
			AckProof_dump(&tp->t.standardProof);
			printk("alt ");
			AckProof_dump(&tp->t.altProof);
#endif
			BUG_TRAP(tp->t.standardProof.sacks[0].left <= cont->TCPBase);
			BUG_TRAP(tp->t.altProof.sacks[0].left <= cont->TCPBase);

			tp->t.previous_base = cont->TCPBase;
			if(clientDebugLevel >= 1)
				printk("new cwnd: %d ssthresh: %d seq: %d base: %d\n", cont->startCwnd, cont->ssthresh, cont->seq, cont->TCPBase);
			if(clientDebugLevel >= 1 ||  debugTransitions) {
				char *oldState;
				switch(tp->t.state) {
				case TRICKLES_CLIENT_SLOWSTART:
					oldState = "SlowStart";
					break;
				case TRICKLES_CLIENT_RECOVERY:
					oldState = "Recovery";
					break;
				case TRICKLES_CLIENT_NORMAL:
					oldState = "NORMAL!!";
					BUG();
					break;
				default:
					oldState = "UNKNOWN!!";
					BUG();
					break;
				}
				printk("%p: %s=>Normal\n", sk, oldState); // 0419
			}
			appendTricklesLossEvent(sk, MIN(cont->startCwnd, EVENT_CWND_MAX),
						EVENT_EXTRA_RECV, tp->t.state);

			tp->t.state = TRICKLES_CLIENT_NORMAL;
			tp->t.oo_count = 0;
			tp->t.in_flight = 0;

			tp->t.timerState = TRICKLES_ENABLE_DATA_TIMEOUT;
			resetClientTimer(sk);

			//SAVE_ACK_PREV(tp);
			tp->t.ack_prev = NULL;
			tp->t.ack_last = cont->seq;
			//0501 - called twice when recovering
			//findAckables(sk, 0, NULL);
			break;
		}
	}
}

static void UpdateClientUCState(struct sock *sk, struct RequestOFOEntry *ofo_entry) {
	struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;
	struct WireUC_RespHeader *hdr;
	struct UC_Continuation *addedUCont = NULL;
	CONTINUATION_TYPE *cont = ofo_entry->cont;
	int ucont_position;
	int ucontNum = 0;

	/*
	 *
	 *
	 * UC-level updates
	 *
	 *
	 */

	// Examine user continuation
	//printk("%p @ ucont_len = %d\n", cont->ucont_data, cont->ucont_len);
	int hadUcont = 0;
	for(ucont_position = 0;
	    ucont_position < cont->ucont_len;
	    ucont_position += ntohs(hdr->len)) {
		hadUcont = 1;
		void *ucont_start = cont->ucont_data + ucont_position;
		hdr = (struct WireUC_RespHeader *)ucont_start;
		int ucont_len = ntohs(hdr->len);

		if(ucont_len < sizeof(struct WireUC_RespHeader)) {
			printk("User continuation %d @ %d too short\n", ucontNum, ucont_position);
			return;
		}
		ucontNum++;

		switch((enum UC_Type)hdr->type) {
		case UC_INCOMPLETE: {
			printk("received incomplete\n");
			printk("I don't work\n");
			BUG();
			struct WireUC_CVT_IncompleteResponse *incompleteResp =
				(struct WireUC_CVT_IncompleteResponse *) hdr;
			int res;
			if(ucont_len < sizeof(*incompleteResp)) {
				printk("User continuation too short for incomplete response\n");
				return;
			}
			switch(tp->t.conversionState) {
			case CONVERSION_WAITFORSERVER:
				res = processIncompleteResponse(sk,incompleteResp,ucont_len);
				if(res) {
					printk("Error while processing incompleteResponse\n");
					return;
				}
				break;
			case CONVERSION_IDLE:
			case CONVERSION_WAITFORUSER:
				printk("Invalid conversion state (supposed to be WAITFORSERVER) while processing incompleteResponse\n");
				return;
			default:
				printk("Invalid state!\n");
				BUG();
				return;
			}
			break;
		}
		case UC_COMPLETE:
			CompleteRequest_finish(sk, cont, ucont_start, ucont_len, (struct WireUC_CVT_CompleteResponse *) hdr, ofo_entry);
			break;
		case UC_UPDATE: {
			/* This code was written, but never
			   used. See UC_NCONT code path below for New
			   CONTinuation Update technique */
			struct WireUC_MGMT_UpdateResponse *updateResp =
				(struct WireUC_MGMT_UpdateResponse *) hdr;
			struct UC_Continuation *ucont;
			if(ucont_len < sizeof(*updateResp)) {
				printk("User continuation too short for update response\n");
				return;
			}
			ucont =	unmarshallUC_Continuation(&updateResp->newCont,
							  ucont_len - ((char*)&updateResp->newCont - (char*)ucont_start));
			if(ucont == NULL) {
				printk("UC_Update: out of memory while unmarshalling new continuation\n");
				return;
			}
			addedUCont = ucont;
			// printk("adding continuation from update\n");
			if(addNewUC_Continuation(sk, addedUCont)) {
				printk("UC_Update: error while adding new continuation\n");
				return;
			}
			break;
		}
		case UC_NEWCONT: {
			struct WireUC_NewContinuationResponse *newContResp =
				(struct WireUC_NewContinuationResponse *) hdr;
			struct UC_Continuation *ucont;
			if(ucont_len < sizeof(*newContResp)) {
				printk("User continuation too short for UC_NEWCONT\n");
				return;
			}
			ucont = unmarshallUC_Continuation(&newContResp->newCont,
							  ucont_len - ((char*)&newContResp->newCont - (char*)ucont_start));
			if(ucont == NULL) {
				printk("Error while unmarshalling UC Continuation for UC_NEWCONT packet\n");
			}
			addedUCont = ucont;
			// printk("adding continuation from newCont\n");
			if(addNewUC_Continuation(sk, ucont)) {
				printk("UC_NEWCONT: error while adding new continuation\n");
				kfree(ucont);
				return;
			}
			break;
		}
		default:
			printk("Invalid UC response \n");
			return;
		}
		/*
		 * Update parent, removing from reliable queues if necessary
		 */
		if(ofo_entry->isSynack) {
			// synack does not have a parent
			tp->t.request_rcv_nxt = 1;
			tp->t.request_snd_nxt = 1;
		} else {
			enum UserRequestType type;
			unsigned start, end;
			switch(hdr->type) {
			case UC_INCOMPLETE:
			case UC_COMPLETE:
				type = MREQ_CONVERSION;
				start = -1;
				end = -1;
				goto update_parent;
			case UC_UPDATE:
				BUG_TRAP(addedUCont);
				type = MREQ_CONTINUATION;
			update_parent:
				updateParent(sk, type, ofo_entry->parent, 
					     ofo_entry->numSiblings, ofo_entry->position);
				break;
			case UC_NEWCONT:
				/// do nothing
				break;
			default:
				printk("Invalid Uc response \n");
			}
		}
	}
	// printk("[%d]", ucontNum);
	if(!hadUcont && ofo_entry->position != INVALID_POSITION) {
		updateParent(sk, MREQ_WILD, ofo_entry->parent,
			     ofo_entry->numSiblings, ofo_entry->position);
	}
}


#define SYNACK_TIMEOUT (HZ)

static inline int try_queue_data_helper(struct sock *sk, struct sk_buff *skb, int linenum);
#define try_queue_data(SK,SKB)    try_queue_data_helper(SK,SKB,__LINE__)

#define DROP() do { dropline = __LINE__; goto drop; } while(0)

#if 0
#define TICK() printk("%d:client_rcv_impl(%d,%d) @%d\n", (int) jiffies, skb_seq, skb_len, __LINE__)
#else
#define TICK()
#endif

int gPacketAddedRequest = 0;

int client_rcv_impl(struct sock *sk, struct sk_buff *in_skb) {
#ifdef TRACELOSS
	printk("%d (%d,%d,%d,%d) ", ntohl(in_skb->h.th->seq), 
	       in_skb->h.th->syn, in_skb->h.th->ack, in_skb->h.th->fin, in_skb->h.th->rst);
#endif
	initPacketSeq();

	// printk("%d: r\n", jiffies);
	// #define NOREQUEST
#ifdef NOREQUEST
	printk("{ ");
#endif
	// printk("h(%d) ", ntohl(in_skb->h.th->seq));
	gRecvSeq = ntohl(in_skb->h.th->seq);

	gPacketAddedRequest = 0;
	//printk("client received packet\n");
	START_PACKET();

	int skb_len = in_skb->len;
	int skb_seq = -1;
	//printk("Enter client_rcv_impl(%p)\n", in_skb);
	int dropline = -1;
	struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;
	WireTrickleResponse *tresp_hdr;

	trickles_init_tcp_cb(in_skb);

	CONTINUATION_TYPE *cont = newClientSide_Continuation(GFP_ATOMIC);
	TCP_SKB_CB(in_skb)->cont = cont;
	if(TCP_SKB_CB(in_skb)->cont == NULL) {
		printk("could not allocate client side continuation\n");
		goto drop;
	}

#if 0
	if(IS_RECOVERY_STATE()) {
		printk("Received packet during recovery %d\n", tp->t.clientStateCounter);
	}
#endif
	short ucont_len;
	char *ucont_in;
	int progress;
	unsigned cur_seq;
	int noCont = 0;
	int synack = 0;


	TIMING_CTX_DEF0("client_rcv_impl", "top", "int0", "int1");
	TIMING_CTX_DEF1(8,7,4);
	reinitTimingCtx(&ctx);
	recordSample(&ctx,0);


	if(cont == NULL) {
		printk("client_rcv: Could not allocate continuation\n");
		DROP();
	}
	cont->mark |= 0x1;

#ifdef RCV_COPY_TO_SMALLER_SKB
	// in_skb is too big (in 4K slab for device). So copy it into a smaller skb (order 2048
	// disable for performance, enable for scalability
	{
		struct sk_buff *copy;
		int copyLen = in_skb->tail - in_skb->head;
		copy = alloc_skb(copyLen, GFP_ATOMIC);
		if(copy == NULL) {
			DROP();
		}
		memcpy(copy->head, in_skb->head, copyLen);
		skb_reserve(copy, in_skb->data - in_skb->head);
		copy->h.th = (struct tcphdr*)(copy->head + ((char*)in_skb->h.th - (char*)in_skb->head));
		copy->nh.iph = (struct iphdr*)(copy->head + ((char*)in_skb->nh.iph - (char*)in_skb->head));
		skb_put(copy, in_skb->len);
		BUG_TRAP(copy->len == in_skb->len);
		copy->sk = in_skb->sk;

		__kfree_skb(in_skb);
		in_skb = copy;
		TCP_SKB_CB(in_skb)->cont = cont;
	}
#endif

	tresp_hdr = (WireTrickleResponse *)in_skb->data;
	/* 0429 - hash compression support */
	/* XXX HASHCOMPRESSED does not work for retransmitted packets */

	int needCachedContinuation = 0;
	struct {
		int parentSeq;
		int parentSeqMask;
	} matchSpec = { 0, 0 };

	if(tresp_hdr->cont.continuationType & CONTTYPE_HASHCOMPRESSED) {
		if(!__skb_pull(in_skb, RESPONSELEN_HASHCOMPRESS)) {
			printk("could not pull hash compressed header\n");
			DROP();
		}

		TICK();
		needCachedContinuation = 1;
		
		BUG_TRAP((tresp_hdr->cont.continuationType & ~CONTTYPE_HASHCOMPRESSED) !=
			 CONTTYPE_MINIMAL);
		
		cont->seq = ntohl(tresp_hdr->cont.hash.seq);
		cont->timestamp = ntohl(tresp_hdr->cont.hash.timestamp);
		cont->mrtt = ntohl(tresp_hdr->cont.hash.mrtt);
		matchSpec.parentSeq = tresp_hdr->cont.hash.parentSeq;
		matchSpec.parentSeqMask = 0xffff;
		memcpy(cont->mac, tresp_hdr->cont.hash.mac, HMACLEN);
#if 0
		printk("hash compressed continuation: %X %X %X (%X %X)\n",
		       cont->seq, cont->timestamp, cont->mrtt, 
		       matchSpec.parentSeq, matchSpec.parentSeqMask);
#endif
	} else {
		TICK();
		if(!pskb_may_pull(in_skb, RESPONSELEN_MINIMAL)) {
			//printk("client_rcv: could not pull WireTrickleResponse\n");
			DROP();
		}

		switch(tresp_hdr->cont.continuationType) {
		case CONTTYPE_MINIMAL:
			__skb_pull(in_skb, RESPONSELEN_MINIMAL);
			//printk("minimal continuation, length = %d(%d)\n", in_skb->len, in_skb->data - in_skb->head);
			noCont = 1;
			break;
		case CONTTYPE_FULL1:
		case CONTTYPE_FULL2:
			if(!pskb_may_pull(in_skb, sizeof(WireTrickleResponse))) {
				printk("client_rcv: could not pull full WireTrickleResponse\n");
				DROP();
			}
			__skb_pull(in_skb, sizeof(WireTrickleResponse));
			//printk("full continuation, length = %d(%d)\n", in_skb->len, in_skb->data - in_skb->head);
			break;
		default:
			BUG();
		}
		if(noCont) {
			cont->continuationType = tresp_hdr->cont.continuationType;
			cont->seq = ntohl(tresp_hdr->cont.seq);
			cont->clientState = tresp_hdr->cont.clientState;
			cont->clientTimestamp = tresp_hdr->cont.clientTimestamp;
			cont->parent = tresp_hdr->cont.parent;
		} else {
			unmarshallContinuationClient(in_skb, cont, &tresp_hdr->cont);
		}
		skb_seq = cont->seq;
		LOG_PACKET_CONT(sk, in_skb->h.th->ack_seq, cont);
	}
	// TCP_SKB_CB(in_skb)->dbg_cont_seq = cont->seq;

#define VERIFY_CONT_IN_TABLE
#ifdef VERIFY_CONT_IN_TABLE
	{
		struct cminisock *lcont;
		if((lcont = MSKTable_lookup(tp->t.msk_table, cont->seq,
		    matchSpec.parentSeq, matchSpec.parentSeqMask)) != NULL) {
			cminisock_tableUnlink(lcont);
			memcpy(lcont->mac, cont->mac, sizeof(cont->mac));
			//printk("using saved continuation\n");

			if(!needCachedContinuation) {
				lcont->continuationType = cont->continuationType;
				lcont->clientState = cont->clientState;
				lcont->clientTimestamp = cont->clientTimestamp;
			} else {
				// used saved versions of above fields
			}

			lcont->parent = cont->parent;

			freeClientSide_Continuation(cont);
			cont = lcont;
			TCP_SKB_CB(in_skb)->cont = cont;
		} else {
			//printk("not using saved continuation\n");
			if(needCachedContinuation) {
				printk("Needed a cached continuation, but no such continuation found. Dropping this packet (seq = %d)\n", cont->seq);
				goto drop;
			}
		}
	}
#endif // VERIFY_CONT_IN_TABLE

	if(!noCont && (cont->seq > tp->t.rcv_nxt + 1000000 ||
		       cont->TCPBase > tp->t.rcv_nxt + 1000000)) {
		if(trickles_ratelimit())
			printk("Warning: client received bogus sequence number (%u) or TCPBase (%u)\n", cont->seq, cont->TCPBase);
	}
	int serverIndex = SK_findMatchingServer(sk, in_skb->nh.iph->saddr);
	BUG_TRAP(serverIndex >= 0);
	if(serverIndex >= 0) {
		struct trickles_server *server = &tp->t.servers[serverIndex];
		if(trickles_ratelimit())
			printk("rtt estimator %d\n",serverIndex);
		trickles_server_newPacket(server, in_skb);
	}
	PACKET_TRACE_LOG("(recv seq=%d) ", cont->seq);

	TCP_SKB_CB(in_skb)->numSiblings = tresp_hdr->numSiblings;
	TCP_SKB_CB(in_skb)->position = tresp_hdr->position;

	ucont_len = ntohs(tresp_hdr->ucont_len);
	//printk("tresp_hdr->ucont_len = %d\n", ucont_len);
	char *ucont_start = ucont_in = in_skb->data;

	cont->mark = SKBLIST;
	// printk("s(%d) ", cont->seq);
	gContSeq = cont->seq;

	recordSample(&ctx,0);

	cont->ucont_len = ucont_len;

	cont->cum_nonce = tresp_hdr->nonce;
	cont->next = cont->prev = NULL;

#define QUEUE_AND_DROP()				\
	do { dropline = __LINE__; goto queue_data_and_drop; } while(0)

	if(!pskb_may_pull(in_skb, ucont_len)) {
		printk("client_rcv: could not pull ucont (ucont_len = %d, skb_len = %d)\n", (int)ucont_len, in_skb->len);
		DROP();
	}
	if(ucont_len) {
		cont->ucont_data = kmalloc(ucont_len, GFP_ATOMIC);
		if(cont->ucont_data == NULL) {
			printk("client_rcv: out of memory while copying user continuation\n");
			__skb_pull(in_skb, ucont_len);
			QUEUE_AND_DROP();
		}
		memcpy(cont->ucont_data, ucont_in, ucont_len);
		__skb_pull(in_skb, ucont_len);
	}
	//printk("cont->ucont_data = %p, cont->ucont_len = %d\n", cont->ucont_data, cont->ucont_len);

	TCP_SKB_CB(in_skb)->trickle_seq = cont->seq;
	TCP_SKB_CB(in_skb)->clientState = cont->clientState;

#if 0
	if(IS_RECOVERY_STATE())
		printk("Recovery packet client state counter = %d, socket counter = %d\n", cont->clientState, tp->t.clientStateCounter);
#endif
	if(cont->seq < tp->t.rcv_nxt) {
		if(clientDebugLevel >= 2 || debugDrops)
			printk("Client_rcv: Useless old packet cont.seq = %u < rcv_nxt = %u; dropping\n", cont->seq, tp->t.rcv_nxt);
		QUEUE_AND_DROP();
	}

	recordSample(&ctx,0);
	if(sk->state != TCP_ESTABLISHED) {
		gSocketConversionCount = 0;
		if(!(in_skb->h.th->syn && in_skb->h.th->ack) )
			DROP();
		// printk("new client socket %p\n", sk);
		synack = 1;
		BUG_TRAP(!noCont);
		sk->state = TCP_ESTABLISHED;
		tp->rcv_nxt = 0;
		tp->rcv_wup = 0;
		tp->copied_seq = 0;
		trickles_client_connected_impl(sk);
		tp->t.rcv_nxt = cont->seq;
		tp->t.byteRcvNxt = 0;
		tp->t.byteSkipHintAmount = 0;
		tp->t.previous_base = cont->TCPBase;
		tp->t.state = TRICKLES_CLIENT_NORMAL;

		//SAVE_ACK_PREV(tp);
		tp->t.ack_prev = NULL;
		tp->t.ack_last = cont->seq + 1;
		tp->t.A = 0;
		tp->t.D = 0;
		tp->t.RTO = INITIAL_RTO;

		tp->t.timerState = TRICKLES_ENABLE_DATA_TIMEOUT;
		resetClientTimer(sk);
		/* code below copied from tcp_synsent_state_process; copy more if necessary */
		mb();
		tcp_set_state(sk, TCP_ESTABLISHED);
		if(!sk->dead) {
			sk->state_change(sk);
			sk_wake_async(sk, 0, POLL_OUT);
		}
		tp->t.clientStateCounter = cont->clientState;
		cont->parent = tp->t.request_rcv_nxt;


		// printk("establishing\n");
		if(SK_MULTIMODE(sk)) {
			// printk("multimode setting wild addr\n");
			tcp_unhash(sk);
			// insert into hash with wildcard
			sk->daddr = TRICKLES_WILDADDR;
			__tcp_v4_hash(sk, 0);
			// keep wildcard as daddr ; needed for hash table lookup
		}
	} else if(tp->t.state == TRICKLES_CLIENT_SYNACK &&
		  !in_skb->h.th->syn && in_skb->h.th->ack) {
		tp->t.state = TRICKLES_CLIENT_NORMAL;
	}
	TICK();
	// 0502 search end

	// Must initialize in_skb->parent here, since
	// cont->parent is initialized in SYN/ACK processing
	TCP_SKB_CB(in_skb)->parent = cont->parent;

	recordSample(&ctx,0);
	/*
	printk("Client received %u, rcv_nxt = %u, ack_seq = %u, ack_last = %u\n",
	       cont.seq, tp->t.rcv_nxt, tp->t.ack_seq, tp->t.ack_last);
	*/

	recordSample(&ctx,0);

	/*
	 *
	 *
	 * DATA STRUCTURE INVARIANTS
	 * ofo_queue - inserted during initial packet receipt, removed when dequeued, handed off to userspace, freed when duplicate arrives
	 * cont_list - inserted during initial packet receipt (not reordering), and freed during acking. NEVER freed during ofo_queue walk!!!
	 * In other words, continuations are treated separately from data
	 *
	 */

	recordSample(&ctx,0);
	if(!(((tp->t.state == TRICKLES_CLIENT_NORMAL || tp->t.state == TRICKLES_CLIENT_SLOWSTART) &&
	      cont->clientState == tp->t.clientStateCounter) ||
	     (tp->t.state == TRICKLES_CLIENT_RECOVERY &&
	      (cont->clientState == tp->t.clientStateCounter || cont->clientState == tp->t.clientStateCounter-1)))) {
		if(clientDebugLevel >= 2 || debugDrops)
			printk("%d %d client state did not match, packet seq = %u state = %u, clientstate = %u\n", (int) jiffies, tp->t.state, cont->seq, cont->clientState, tp->t.clientStateCounter);
		QUEUE_AND_DROP();
	}
	/* always add to alt sacks */
	if(!AckProof_update(sk, &tp->t.altProof, cont)) {
		if(clientDebugLevel >= 2 || debugDrops || debugProofDrops) {
			if(trickles_ratelimit())
				printk("altproof not updated, dropping\n");
		}
		QUEUE_AND_DROP();
	}
	if(tp->t.ack_prev == NULL || cont->seq > tp->t.ack_prev->seq) {
		//printk("  client: updating standardProof\n");
		/* have not acked yet, so add to standard sack */
		if(!AckProof_update(sk, &tp->t.standardProof, cont) &&
		   // 0419: need this test since tp->t.standardProof can be in bad states during recovery and slowstart
		   tp->t.state == TRICKLES_CLIENT_NORMAL) {
			if(clientDebugLevel >= 2 || debugDrops || debugProofDrops){
				if(trickles_ratelimit())
					printk("standardProof not updated, dropping\n");
			}
			QUEUE_AND_DROP();
		}
	}

	if(!noCont) {
		/* receiving packets, so we're making progress */
		if(!disableTimeout) {
			resetClientTimer(sk);
		}
	}
	cur_seq = cont->seq; // save value since cont might be deallocated soon

	TICK();

#ifdef FIXEDRTT
	tp->t.A = FIXEDRTT;
	tp->t.RTO = (tp->t.A >> 3) * TIMEOUT_MULTIPLIER;
#else
	if(!synack) {
		/* xxx use updateRTTestimator */
		int delta = jiffies - cont->clientTimestamp;
		if(delta > 0) {
			// protect against wraparound
			if(delta > 10000) {
				printk("warning: delta = %d\n", delta);
				goto skip;
			}
			if(tp->t.A == 0) {
				tp->t.A = (delta) << 3;
				// initial variance is initial estimate / 2
				tp->t.D = tp->t.A >> 1;
			} else {
				int Err = (delta << 3) - tp->t.A; // units of jiffies/8
				// Err is in units of jiffies/8, A is in units of jiffies/8
				//effect is A += 1/8 Err
				tp->t.A += (Err >> 3);
				//effect is D += 1/4 (Err - D)
				tp->t.D += ((iabs(Err) - tp->t.D) >> 2);
				tp->t.RTO = VJ90RTO8(sk);
			}
			SAVE_ESTIMATOR_STATS(sk);
			if(0 && trickles_ratelimit()) {
				DUMP_RTO(sk);
				printk("\n");
			}
		}
	skip:
		;
	}
#endif

	TICK();
	if(cont->seq == tp->t.rcv_nxt) {
		//printk("seq = %d, rcv_nxt = %d\n", cont->seq, tp->t.rcv_nxt);
		TICK();
		int closedGap = 0;
		struct sk_buff *skb = in_skb;
		unsigned seq = cont->seq;
		int first = 1;
		recordSample(&ctx,1);

		if(!noCont) {
			ContList_insert(sk,cont);
		}
		recordSample(&ctx,1);
		while(1) {
			/* do NOT reinsert continuations from ofo queue; they're already in the ContList */
			client_inseq(sk, skb, noCont);
			// client inseq may deallocate cont, so unlink here
			cont = NULL;
			if(first) recordSample(&ctx,1);
			if(paranoia >= 1 &&
			   AckProof_checkRange(&tp->t.altProof, tp->t.rcv_nxt, tp->t.rcv_nxt) == BADRANGE) {
				printk("Could not find rcv_nxt in altProof\n");
			}
			tp->t.rcv_nxt++;
#if 0
			if(IS_RECOVERY_STATE())
				printk("rcv nxt now %d ack_last = %d\n", tp->t.rcv_nxt, tp->t.ack_last);
#endif
			skb = skb_peek(&tp->t.ofo_queue);
			if(first) recordSample(&ctx,1);
			if(!skb || TCP_SKB_CB(skb)->trickle_seq != tp->t.rcv_nxt) {
				if(first) recordSample(&ctx,1);
				break;
			}
			closedGap++;
			__skb_dequeue(&tp->t.ofo_queue);
			delOfoSkb(skb);
			if(first) recordSample(&ctx,1);
			first = 0;
		}
		recordSample(&ctx,1);
		if(closedGap) {
			if(clientDebugLevel >= 2)
				printk("%u closed gap of %d, ack_last = %u\n", seq, closedGap, tp->t.ack_last);
		} else {
			if(clientDebugLevel >= 2)
				printk("%u in order, ack_last = %u\n", seq, tp->t.ack_last);
		}
		recordSample(&ctx,1);
	} else {
		TICK();
		// printk("seq = %d, rcv_nxt = %d\n", cont->seq, tp->t.rcv_nxt);
		/* enqueue in ofo_queue */
		if(skb_peek(&tp->t.ofo_queue) == NULL) {
			if(clientDebugLevel >= 2)
				printk("  client: %u inserted at ofo head\n", TCP_SKB_CB(in_skb)->trickle_seq);
			if(!addOfoSkb(in_skb)) {
				DROP();
			}
			__skb_queue_head(&tp->t.ofo_queue, in_skb);
			if(!noCont) {
				ContList_insert(sk,cont);
			}
		} else {
			struct sk_buff *skb = tp->t.ofo_queue.prev;
			do {
				if(TCP_SKB_CB(skb)->trickle_seq < TCP_SKB_CB(in_skb)->trickle_seq)
					break;
			} while((struct sk_buff_head*)(skb=skb->prev) != &tp->t.ofo_queue);

			if((struct sk_buff_head*)skb->next != &tp->t.ofo_queue &&
			   TCP_SKB_CB(skb->next)->trickle_seq == TCP_SKB_CB(in_skb)->trickle_seq) {
				// overlap
				struct sk_buff *next = skb->next;
				if(NEWER(TCP_SKB_CB(in_skb)->clientState, TCP_SKB_CB(next)->clientState)) {

					if(clientDebugLevel >= 2)
						printk("Got rid of old skb %u\n", TCP_SKB_CB(next)->trickle_seq);
					__skb_unlink(next, &tp->t.ofo_queue);
					trickles_kfree_skb(next);
				} else {
					if(clientDebugLevel >= 2)
						printk("Got rid of new skb %u\n", TCP_SKB_CB(in_skb)->trickle_seq);
					trickles_kfree_skb(in_skb);
					goto skip_insert;
				}
			}
			if(clientDebugLevel >= 2) {
				printk("  client: inserted %u after %u, before %u\n", TCP_SKB_CB(in_skb)->trickle_seq, TCP_SKB_CB(skb)->trickle_seq, TCP_SKB_CB(skb->next)->trickle_seq);
			}
			if(!addOfoSkb(in_skb)) {
				DROP();
			}
			__skb_insert(in_skb, skb, skb->next, &tp->t.ofo_queue);

			/* sorted insert into cont list */
			if(!noCont)
				ContList_insert(sk, cont);
		skip_insert: ;
		}
	}
	recordSample(&ctx,0);
	cont = NULL;
	in_skb = NULL;
	// After this point, never reference cont or in_skb

	switch(tp->t.state) {
	case TRICKLES_CLIENT_SYNACK:
		TICK();
	case TRICKLES_CLIENT_NORMAL:
		TICK();
	case TRICKLES_CLIENT_RECOVERY:
		TICK();
		/* Check whether we want to send an ack */
		recordSample(&ctx,2);
		progress = findAckables(sk,0,NULL);
		recordSample(&ctx,2);
		if(!progress) {
			if(clientDebugLevel >= 2)
				printk("  client: no ackable found, rcv_nxt = %u\n", tp->t.rcv_nxt);
#ifndef DISABLE_FASTRECOVERY
			if(cur_seq > tp->t.ack_last) {
				tp->t.oo_count++;
#if 1 // 0714 - try different out of order thresholds
				if(tp->t.oo_count >= OO_THRESHOLD) {
#else
				if(tp->t.oo_count >= min(OO_THRESHOLD, max(tp->t.sentRequests.len / 4, 3))) {
				}
#endif
					int old_last = tp->t.ack_last;
					unsigned first_seq, seq;
					struct sk_buff *skip_skb;
					struct Request *req;
					struct DataRequestMapping *dataReqMap;

					if(clientDebugLevel >= 2)
						printk("oo threshold exceeded\n");
					tp->t.oo_count = 0;
					gNumRecovery++;
#ifdef REPORT_RECOVERY
					printk("entering recovery @ ack_last = %d seq = %d\n", tp->t.ack_last, cur_seq);
#endif

					enterRecoveryState(sk, 0);
					findAckables(sk, 1,&skip_skb);

					BUG_TRAP(tp->t.ack_last >= old_last);
					BUG_TRAP(skip_skb != NULL);
					if(skip_skb->prev != (struct sk_buff*)&tp->t.ofo_queue) {
						first_seq = TCP_SKB_CB(skip_skb->prev)->trickle_seq + 1;
					} else {
						first_seq = tp->t.rcv_nxt;
					}
					BUG_TRAP(first_seq < TCP_SKB_CB(skip_skb)->trickle_seq);
#if 1 // 0418 [AA
					for(seq = first_seq,
						    dataReqMap = (struct DataRequestMapping*)tp->t.dataRequestMap.next,
						    req = (struct Request *)tp->t.sentRequests.next;
					    seq < TCP_SKB_CB(skip_skb)->trickle_seq;
					    seq++) {
						int foundMapping = 0, foundRequest = 0;
						while(dataReqMap != (struct DataRequestMapping*) &tp->t.dataRequestMap &&
						      dataReqMap->transportResponseSeqEnd <= seq) {
							dataReqMap = dataReqMap->next;
						}
						if(dataReqMap != (struct DataRequestMapping*)&tp->t.dataRequestMap &&
						   dataReqMap->transportResponseSeqStart <= seq &&
						   seq < dataReqMap->transportResponseSeqEnd) {
							struct DataRequestMapping *next = dataReqMap->next;
							// Missing packet overlaps a data mapping
							if(enableDataRecovery) {
								unlink((struct alloc_head*)dataReqMap);
								RECORD_MISSINGDATAMAP_INSERTION(dataReqMap);
								insert_tail(&tp->t.missingDataMap,
									    (struct alloc_head*)dataReqMap);
								foundMapping = 1;
							}
							dataReqMap = next;
						}

						while(req != (struct Request *)&tp->t.sentRequests &&
						      req->transportResponseSeqEnd <= seq) {
							req = (struct Request*)req->next;
						}
						if(req != (struct Request *)&tp->t.sentRequests &&
						   req->transportResponseSeqStart <= seq &&
						   seq < req->transportResponseSeqEnd) {
							struct Request *next = (struct Request*)req->next;

							unlink((struct alloc_head*)req);
							resetRequest(req);
							CHECK_IF_ZEROREQUEST(req);
							insert_head(&tp->t.queuedRequests, (struct alloc_head*)req);
							foundRequest = 1;
							req = next;
						}
						if(!(foundRequest ^ foundMapping)) {
#if 0 // 0418 trickles should be able to recover from these conditions
							if(foundRequest && foundMapping) {
								printk("weird, found both a request and a mapping\n");
							} else {
								printk("found neither request nor mapping\n");
							}
#endif
						}
					}
#endif // 0418 AA]
				}
			}
#endif // DISABLE_FASTRECOVERY
		} else {
			//printk("  client: after findackables: ack_seq = %d ack_last = %d\n", tp->t.ack_seq, tp->t.ack_last);
		}
		recordSample(&ctx,2);
		trickles_send_ack_impl(sk, 0);
		recordSample(&ctx,2);
		break;
	case TRICKLES_CLIENT_SLOWSTART:
		// do nothing
		break;
	default:
		BUG();
	}
	recordSample(&ctx,0);
	printTimings(&ctx);
	//printk("Exit client_rcv_impl(%p)\n", in_skb);

	PACKET_TRACE_FINISH();
#ifdef NOREQUEST
	if(!gPacketAddedRequest) {
		printk("a: ");
		SK_dump_vars(sk);
		SK_ucontList_dump(sk);
		SK_data_request_dump(sk);
		SK_skiplist_dump(sk);
		SK_data_ofo_queue_dump(sk);
		SK_request_dump(sk);
	}
	printk(" }\n");
#endif
	if(!gPacketAddedRequest) {
		gNoRequestPackets++;
	}
	dumpPacketSeq();
	return 0;

 queue_data_and_drop:
	// printk("dropline = %d ", dropline);
	TICK();

	// 0901 -- Scrape out the last bit of performane from the dropped packets

	// Always attempt to enqueue the DATA, even if the rest of the
	// protocol is b0rked
	TCP_SKB_CB(in_skb)->dbg = __LINE__;
	if(try_queue_data(sk,in_skb) >= 0) {
		//printk("try queue data returned success\n");
		trickles_kfree_skb(in_skb);
		dumpPacketSeq();
		return 0;
	} else {
		//printk("try queue data returned failure\n");
	}
 drop:
	TICK();
	// printk("drop @ %d\n", dropline);
	if(debugDrops) {
		printk("dropping @ %d ", dropline);
		printk("state = %d seq = %d ", cont->state, cont->seq);
		//update_rx_stats_helper(in_skb, 1);
	} else {
		//update_rx_stats_helper(in_skb, 0);
	}

	trickles_kfree_skb(in_skb);
	if(cont != NULL && (tp->t.ack_prev == cont)) {
		BUG();
	}
#if 0 // 0813 trickles_kfree_skb now handles deallocation
	if(cont) {
		printk("dropline = %d\n", dropline);
		MARK_PC(cont);
		freeClientSide_Continuation(cont);
	}
#endif
	//printk("Exit client_rcv_impl(%p)\n", in_skb);
	PACKET_TRACE_FINISH();

#ifdef NOREQUEST
	if(!gPacketAddedRequest) {
		printk("b: ");
		SK_dump_vars(sk);
		SK_ucontList_dump(sk);
		SK_data_request_dump(sk);
		SK_skiplist_dump(sk);
		SK_data_ofo_queue_dump(sk);
		SK_request_dump(sk);
	}
	printk(" }\n");
#endif 
	if(!gPacketAddedRequest) {
		gNoRequestPackets++;
	}
	dumpPacketSeq();
	return 0;
}
#undef DROP
#undef QUEUE_AND_DROP

int trickles_send_ack_impl(struct sock *sk, int user_ctx) {
	int num_iterations = 0;
	struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;
	CONTINUATION_TYPE *cont = tp->t.ack_prev;
	int contSource = 1;
	int caller = user_ctx ? 1 : 0; // DON'T REMOVE! Used when timing is enabled
	int numAcksSent = 0;

	TIMING_CTX_DEF0("trickles_send_ack_impl", "kernel", "user");
	TIMING_CTX_DEF1(5,5);
	reinitTimingCtx(&ctx);
	recordSample(&ctx,caller);
	if(caller)  ; // force reference to caller in all compilation environments

#if 1
#define REACHED(LABEL)
#else
#define REACHED(LABEL)						\
	if(IS_RECOVERY_STATE()) {				\
		printk("trickles_send_ack " #LABEL " - seq = %d\n", cont != NULL ? cont->seq : -1); \
	}
#endif

	if(cont == NULL) {
		contSource = 0;
		cont = (CONTINUATION_TYPE *)&tp->t.cont_list;
		REACHED(cont_list);
	}
	REACHED(top);

	while(1) {
		int is_curr = 0;
		num_iterations++;

		recordSample(&ctx,caller);
		cont = cont->next;
		/* Send ack */
		if(cont == NULL) {
			printk("trickles_send_ack_impl: cont == NULL\n");
			BUG();
			goto out;
		}
		REACHED(1);

		if(cont == (CONTINUATION_TYPE*)&tp->t.cont_list ||
		   cont->seq >= tp->t.ack_last) {
			/* advanced too far; don't update */
			if(is_curr) BUG();
			goto out;
		}
		REACHED(2);

		recordSample(&ctx,caller);

		if(!sendAckHelper(sk,cont,TREQ_NORMAL)) {
			/* some error while transmitting ack */
			goto out;
		}
		REACHED(3);
		numAcksSent++;

		if(clientDebugLevel >= 2) {
			if(cont->state == CONT_BOOTSTRAP) {
				printk("bootstrap ack: %u\n", cont->seq);
			}
		}

		recordSample(&ctx,caller);
		tp->t.ack_prev = cont;
		INTEGRITY_CHECK(sk, tp->t.ack_prev);
		SAVE_ACK_PREV(tp);
		if(!(!tp->t.ack_prev || tp->t.ack_prev->next)) {
			// 0429
			BUG_TRAP(!tp->t.ack_prev || tp->t.ack_prev->next);
			BUG();
		}

		if(tp->t.state == TRICKLES_CLIENT_NORMAL) {
			CONTINUATION_TYPE *clean = (CONTINUATION_TYPE*)tp->t.cont_list.next;
			REACHED(4);
			while(clean != (CONTINUATION_TYPE*)&tp->t.cont_list) {
				CONTINUATION_TYPE *prev = clean;
				clean = clean->next;
				// XXX  0429 hash compress changes needed
				REACHED(5);
				if(
#ifdef ENABLE_HASHCOMPRESS
				   prev->numChildrenReceived < prev->numTransportChildren ||
#endif
				   prev->seq >= tp->t.ack_prev->seq ||
				   prev->seq >= tp->t.rcv_nxt /* ||
								 prev->seq >= tp->t.previous_base */) {
#if 0
					printk("skipped continued deallocation (list len = %d): prev->seq (%d) >= tp->t.ack_prev->seq (%d), prev->seq (%d) >= tp->t.rcv_nxt (%d)\n",
					       tp->t.cont_list.len,
					       prev->seq, tp->t.ack_prev->seq,
					       prev->seq, tp->t.rcv_nxt);
#endif
					REACHED(6);
					break;
				}
				REACHED(7);
				BUG_TRAP(prev != tp->t.ack_prev);
				BUG_TRAP(prev != cont);
				unlinkCont(prev);
				MARK_PC(prev);
				if(tp->t.ack_prev == prev) {
					BUG();
				}
				if(clientDebugLevel >= 2) {
					printk("freeing %d, rcv_nxt=%d, previous_base = %d\n", prev->seq, tp->t.rcv_nxt, tp->t.previous_base);
				}
				freeClientSide_Continuation(prev);
			}
		}
		REACHED(8);
		tp->t.in_flight++;
		recordSample(&ctx,caller);
		//printTimings(&ctx);
	}
 out:
	return numAcksSent;
	//printTimings(&ctx);

#undef REACHED
}

void user_ack_impl(struct sock *sk) {
	/* Wrapper for trickles_send_ack_impl */
	struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;

	BUG_TRAP(in_softirq());


	tp->t.timerState |= TRICKLES_ENABLE_DATA_TIMEOUT;
	if((tp->t.timerState & TRICKLES_NEED_SLOWSTART)) {
		// slow start blocked by user
		enterRecoveryState(sk, 1);

		if(clientDebugLevel >= 2)
			printk("user_ack_impl requestslowstart %p state = %d\n", sk, tp->t.timerState);
		requestSlowStart(sk);
	} else if(NEED_USERACK(sk)) {
		local_bh_disable();
		//printk("pre user triggering sendackimpl = %d,%d\n", tp->t.ack_last, tp->t.rcv_nxt);
		int numAcks = trickles_send_ack_impl(sk, 1);
		//printk("user triggering sendackimpl = %d,%d,%d\n", numAcks, tp->t.ack_last, tp->t.rcv_nxt);
		if(numAcks > 0) {
			LOG_PACKET_USERUNBLOCKEVENT(NULL);
		} else {
			LOG_PACKET_USERBADUNBLOCKEVENT(NULL);
			//printk("badunblock\n");
		}
		tp->t.timerState &= ~TRICKLES_NEED_USERACK;
		local_bh_enable();
	}
	resetClientTimer(sk);
}

void tcp_data_queue(struct sock *sk, struct sk_buff *skb);
#ifndef USERTEST
void trickles_fin(struct sock *sk) {
	// based on tcp_fin()
	sk->shutdown |= RCV_SHUTDOWN;
	sk->done = 0;
	sk->err = EPIPE;
	tcp_set_state(sk, TCP_CLOSE);

	sk->state_change(sk);
	/* Do not send POLL_HUP for half duplex close. */
	if (sk->shutdown == SHUTDOWN_MASK || sk->state == TCP_CLOSE)
		sk_wake_async(sk, 1, POLL_HUP);
	else
		sk_wake_async(sk, 1, POLL_IN);
}

/* begin functions copied from tcp_input.c */
static int tcp_copy_to_iovec(struct sock *sk, struct sk_buff *skb, int hlen)
{
	struct tcp_opt *tp = &(sk->tp_pinfo.af_tcp);
	int chunk = skb->len - hlen;
	int err;

	local_bh_enable();
	if (skb->ip_summed==CHECKSUM_UNNECESSARY)
		err = skb_copy_datagram_iovec(skb, hlen, tp->ucopy.iov, chunk);
	else
		err = skb_copy_and_csum_datagram_iovec(skb, hlen, tp->ucopy.iov);

	if (!err) {
		tp->ucopy.len -= chunk;
		tp->copied_seq += chunk;
	}

	local_bh_disable();
	return err;
}

//#define SAVE_LAST_DATA_TIME
#ifdef SAVE_LAST_DATA_TIME
struct timeval last_data_time;
#endif // SAVE_LAST_DATA_TIME

static inline void tcp_fast_path_queue(struct sock *sk, struct sk_buff *skb) {
	// derived from fast path code in tcp_input.c
	int eaten = 0;
	struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;
	int len = skb->len;
	int direct_copy = tp->ucopy.task == current &&
	    tp->copied_seq == tp->rcv_nxt &&
	    len <= tp->ucopy.len &&
	    sk->lock.users;

	TIMING_CTX_DEF0("fast_path_queue", "not direct copy", "direct copy");
	TIMING_CTX_DEF1(3,3);
	reinitTimingCtx(&ctx);
	direct_copy = direct_copy ? 1 : 0;
	recordSample(&ctx,direct_copy);

	if(len == 0) goto skip;

	// 10/15 Linux tcp.c doesn't understand data on syn/ack. So we need to mask the fact that this packet was a syn. Ugly
	skb->h.th->syn = 0;
	if(!(tp->trickles_opt & TCP_TRICKLES_BUFFERDISCARD)) {
		if(TCP_SKB_CB(skb)->seq != tp->rcv_nxt) {
			printk("start sequence not at rcv nxt: %d %d\n", TCP_SKB_CB(skb)->seq, tp->rcv_nxt);
		}

		if (direct_copy) {
			printk("direct copy\n");
			__set_current_state(TASK_RUNNING);

			if (!tcp_copy_to_iovec(sk, skb, 0)) {
				tp->rcv_nxt = TCP_SKB_CB(skb)->end_seq;
				NET_INC_STATS_BH(TCPHPHitsToUser);
				eaten = 1;
			}
		}
		recordSample(&ctx,direct_copy);
		if (!eaten) {
			NET_INC_STATS_BH(TCPHPHits);

			/* Bulk data transfer: receiver */

			if(TCP_SKB_CB(skb)->cont) {
				freeClientSide_Continuation(TCP_SKB_CB(skb)->cont);
				TCP_SKB_CB(skb)->cont = NULL;
			}
			__skb_queue_tail(&sk->receive_queue, skb);
			tcp_set_owner_r(skb, sk);
#if 0
			if(atomic_read(&skb_shinfo(skb)->dataref) > 2) {
				printk("skb to send to user had refcnt > 2\n");
			}
#endif
			tp->rcv_nxt = TCP_SKB_CB(skb)->end_seq;
			// print out error if we exceed by more than 12.5%
			if(tp->rcv_nxt > (sk->rcvbuf + tp->copied_seq + (sk->rcvbuf >> 2))) {
				if(!disableSevereErrors)
					printk("exceeded constraint on rcvbuf by %d\n", tp->rcv_nxt - (sk->rcvbuf + tp->copied_seq));
			}
		}
	} else {
		// ! TCP_TRICKLES_BUFFERDISCARD
		gNumReceivedBytes += TCP_SKB_CB(skb)->end_seq - tp->rcv_nxt;
		tp->rcv_nxt = TCP_SKB_CB(skb)->end_seq;
		SKBStat_update(&gReceivedSKBStat, skb, skb->data - skb->head);
		if(atomic_read(&skb->users) > 1) {
			printk("Buffer discarding %p, refcnt = %d\n", skb, atomic_read(&skb->users));
		}
		trickles_kfree_skb(skb);
	}

	if((int)tp->rcv_nxt < 0) {
		printk("rcv_nxt = %d\n", tp->rcv_nxt);
	}
	// printk("%d: rcv_nxt = %d\n", jiffies, tp->rcv_nxt);

#if 1 // 0810 advance byteReqNext in case we have pushed data
	// XXX Should the datarequestmap also be updated?
	if(tp->t.byteReqNext < tp->t.byteRcvNxt) {
		tp->t.byteReqNext = tp->t.byteRcvNxt;
	}
#endif
	recordSample(&ctx,direct_copy);
	sk_wake_async(sk, 0, POLL_IN);
	if(skb->h.th->fin) {
		trickles_fin(sk);
	}
	printTimings(&ctx);
 skip:
	if (eaten)
		trickles_kfree_skb(skb);
	else
		sk->data_ready(sk, 0);
#ifdef SAVE_LAST_DATA_TIME
        do_gettimeofday(&last_data_time);
#endif // SAVE_LAST_DATA_TIME
	return;
}
#endif // USERTEST

#if 0
#define TRICKLES_SKB_GENERIC(SUFFIX)					\
static struct sk_buff *trickles_skb_ ##SUFFIX (struct sk_buff *skb, int flags) { \
	struct sk_buff *newSkb = skb_##SUFFIX(skb, flags);			\
	if(newSkb == NULL) {						\
		return NULL;						\
	}								\
	TCP_SKB_CB(newSkb)->cont = copyClientSide_Continuation(TCP_SKB_CB(newSkb)->cont, GFP_ATOMIC); \
	if(TCP_SKB_CB(newSkb)->cont == NULL) {				\
		__kfree_skb(newSkb);					\
		return NULL;						\
	}								\
	return newSkb;							\
}

TRICKLES_SKB_GENERIC(copy);
TRICKLES_SKB_GENERIC(clone);
#endif

static inline int process_new_ucont(struct sock *sk, struct RequestOFOEntry *ofo_entry);

static inline void client_inseq(struct sock *sk, struct sk_buff *skb, int noCont) {
	struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;
	CONTINUATION_TYPE *cont = TCP_SKB_CB(skb)->cont;
	TCP_SKB_CB(skb)->cont = NULL;
	unsigned transportSeq = cont->seq;
#ifdef LAST_CHUNK
	int is_last_chunk = IS_LAST_CHUNK(skb);
	void *origSKB = skb;
#endif

	LOG_PACKET_INSEQEVENT(cont);

	// Perform state updates before queuing packet, for otherwise skb might disappear
	/* find matching continuation in ContList */
	if(!noCont) {
		CONTINUATION_TYPE *cont;
		int found = 0;
		alloc_head_reverse_walk(&tp->t.cont_list, cont) {
			if(cont->seq == tp->t.rcv_nxt) {
				found = 1;
				UpdateClientTransportState(sk, skb, cont);
#ifdef ENABLE_HASHCOMPRESS
				if(cont->parentMSK) {
					cont->parentMSK->numChildrenReceived++;
				}
#endif
				// cannot continue looping after performing update, since list may have changed
				break;
			}
		}
		if(!found) {
			if(clientDebugLevel >= 2) {
				printk("client_inseq: could not find transport level continuation to use for state update\n");
			}
		}
	}

	int may_contain_interesting_ucont =
	  (cont->ucont_len > 0 && skb->len > 0) ||
	   TCP_SKB_CB(skb)->parent >= tp->t.request_rcv_nxt;
	struct RequestOFOEntry *ofo_entry = NULL;

	if(may_contain_interesting_ucont) {
		int isSynack = skb->h.th->syn && skb->h.th->ack;
#if 0
		if(cont->ucont_len > 0) {
			printk("probably complete len = %d\n", skb->len);
		}
#endif
		ofo_entry =
			RequestOFOEntry_new(cont, isSynack,
					    TCP_SKB_CB(skb)->parent,
					    TCP_SKB_CB(skb)->numSiblings,
					    TCP_SKB_CB(skb)->position);
		cont = NULL;
		if(ofo_entry == NULL) {
			printk("RequestOFOEntry returned null, inseq exiting prematurely\n");
			trickles_kfree_skb(skb);
			return;
		}
	}

	/* During retransmission, the association between transport
	   level sequence numbers and UC-level request numbers is
	   scrambled. Hence, client needs to perform a reordering on
	   UC requests */

	// 0810 was cont->ucont_len instead of tcp_cb->cont->ucont_len

	TCP_SKB_CB(skb)->dbg = __LINE__;

	if(may_contain_interesting_ucont) {
		process_new_ucont(sk, ofo_entry);
	}

	if(try_queue_data(sk, skb) >= 0) {
		// DO NOTHING
#undef DROP_DATA_PACKET
	} else {
		// No data
		int overhead = skb->tail - skb->head;
		//printk("%d: seq = %d\n", (int)jiffies, transportSeq);
		SKBStat_update(&gNoDataSKBStat, skb, overhead);
	}
	trickles_kfree_skb(skb);
	skb = NULL;

	goto done_processing; // suppress warning
 done_processing:
	/* Clean out stuff just rendered obsolete */
#ifdef LAST_CHUNK
	if(is_last_chunk) {
		printk("removing obsolete data request maps\n");
		removeObsoleteDataRequestMaps(sk, transportSeq);  // moved out of data-only path, so that it executes unconditionally
	} else {
		printk("%p: not last chunk\n", origSKB);
	}
#else
	removeObsoleteDataRequestMaps(sk, transportSeq);  // moved out of data-only path, so that it executes unconditionally
#endif
	removeObsoleteContinuations(sk);
	removeObsoleteDependencies(sk);
	return;
	goto drop;
 drop:
	printk("dropped\n");
	if(skb) {
		trickles_kfree_skb(skb);
	}
}

/*********************** Data management code *************************/
static inline int fragment_skb(struct sk_buff *in_skb);

static int byteRcvNxt_checkSkip(struct sock *sk) {
	struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;
	struct alloc_head_list *skiplist = &tp->t.skipList;
	unsigned rcvnxt = tp->t.byteRcvNxt;
	if(empty(skiplist)) {
		return 0;
	}
	struct SkipCell *head = (struct SkipCell *)skiplist->next;
	if(rcvnxt == head->start) {
		return 1;
	} else if(SkipCell_intersectRange(head, rcvnxt, rcvnxt+1)) {
		printk("warning: rcv nxt overlaps with a skip cell, this isn't right\n");
		// possible to recover from this failure: just do a normal skip
		return 1;
	}
	return 0;
}

static void byteRcvNxt_doSkip(struct sock *sk) {
	struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;
	struct alloc_head_list *skiplist = &tp->t.skipList;
	if(empty(skiplist)) BUG();
	struct SkipCell *head = (struct SkipCell *)skiplist->next;

	unsigned target = head->end;
	BUG_TRAP(tp->t.byteRcvNxt == head->start);
	int skippedAmount = target - tp->t.byteRcvNxt;
	// printk("doing skip, %d=>%d\n", tp->t.byteRcvNxt, target);
	tp->t.byteRcvNxt = target;
	if(skippedAmount > tp->t.byteSkipHintAmount) {
#if 0
		printk("overskipping, was %d, will - %d\n",
		       tp->t.byteSkipHintAmount, skippedAmount);
#endif
	}
	tp->t.byteSkipHintAmount = 
		MAX(tp->t.byteSkipHintAmount - skippedAmount, 0);
	BUG_TRAP(tp->t.byteSkipHintAmount >= 0);
	gSkipCount++;

	unlink((struct alloc_head*)head);
	SkipCell_free(head);
}

static void fin_break(void) {
	static volatile int x; 
	x++;
}


static inline int try_queue_data_helper(struct sock *sk, struct sk_buff *outerSKB, int linenum) {
	struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;
	// XXX This function is way too big
	// Check for non-data chunk
	struct ResponseChunk *rchunk = (struct ResponseChunk *)outerSKB->data;
	int nonzeroPacket = 0;

	if(outerSKB->len == 0) {
		//printk("%d: len == 0, rcv_nxt = %d, syn = %d ack = %d\n", (int)jiffies, tp->rcv_nxt, outerSKB->h.th->syn, outerSKB->h.th->ack);
		return -1;
	}
	if(outerSKB->len < sizeof(*rchunk)) {
		if(trickles_ratelimit()) {
			printk("try_queue_data: too short\n");
		}
		return -1;
	}
	if(!IS_VALID_CHUNKTYPE(rchunk->type)) {
		if(trickles_ratelimit()) {
			printk("Invalid chunktype %d\n", rchunk->type);
		}
		return -1;
	}
	if(rchunk->type == RCHUNK_PUSH_HINT) {
		struct PushHintChunk *phchunk =
			(struct PushHintChunk *) rchunk;
		int chunk_len = ntohs(phchunk->chunkLen);
		printk("Pulling %d ", chunk_len);
		skb_pull(outerSKB, chunk_len);

		int start = ntohl(phchunk->start),
			end = ntohl(phchunk->end);
		printk("Hint is [%d-%d]\n", start, end);
		if(start <= tp->t.byteReqNext && tp->t.byteReqNext < end) {
			printk("Adjusting byteReqNext: %d => %d\n", tp->t.byteReqNext, end);
			tp->t.byteReqNext = end;
		}
	}
	// SKB could contain data in multiple ranges. These are captured in the skb's fragments
	if(fragment_skb(outerSKB) > 0) {
		// Process all fragments
		int fragnum;

		int overhead = TCP_SKB_CB(outerSKB)->numDataChunks * sizeof(struct DataChunk) + outerSKB->data - outerSKB->head;
		SKBStat_update(&gOuterSKBStat, outerSKB, overhead);

		for(fragnum = 0; fragnum < TCP_SKB_CB(outerSKB)->numDataChunks;
		    fragnum++) {
			struct sk_buff **pskb = GET_CHUNK(outerSKB, fragnum);
			struct sk_buff *skb = *pskb;
			*pskb = NULL;
#if 0
			printk("Frag[%d/%d]=[%d,%d] ", fragnum,
			       TCP_SKB_CB(outerSKB)->numDataChunks,
			       TCP_SKB_CB(skb)->byteNum,
			       TCP_SKB_CB(skb)->byteNum + skb->len);
#endif

#if 0 // 0901 -- after factoring out thies function, this sanity check can no longer be performed
			if(!(IMPLIES(tp->t.ack_prev != NULL, tp->t.ack_prev != cont))) {
				BUG_TRAP(IMPLIES(tp->t.ack_prev != NULL, tp->t.ack_prev != cont));
				printk("tp->t.ack_prev->list = %p\n", tp->t.ack_prev->list);
			}
			MARK_PC(cont);
#endif

			if(skb->len == 0) {
				printk("skb == 0\n");
				goto bad_packet;
			}

			if(byteRcvNxt_checkSkip(sk)) {
				// handle any new skips
				byteRcvNxt_doSkip(sk);
			}
			if(TCP_SKB_CB(skb)->byteNum > tp->t.byteRcvNxt) {
				struct sk_buff *finger, *next;
				/*
				  Enqueue in ofo queue
				*/
				TCP_SKB_CB(skb)->seq = TCP_SKB_CB(skb)->byteNum;
				TCP_SKB_CB(skb)->end_seq = TCP_SKB_CB(skb)->seq + skb->len;
				if(PACKET_TRACE_OFO) {
					PACKET_TRACE_LOG("t.rcv_nxt = %d, "
						 "ofo attempt %d-%d ; ", 
						 tp->t.rcv_nxt,
						 TCP_SKB_CB(skb)->seq,
						 TCP_SKB_CB(skb)->end_seq);
				}
				if(skb_peek(&tp->t.data_ofo_queue)) {
					finger = tp->t.data_ofo_queue.prev;
					/* eliminate overlap later, when using elements from ofo queue */
					do {

						if(TCP_SKB_CB(finger)->seq < TCP_SKB_CB(skb)->seq)
							break;
					} while((struct sk_buff_head*)(finger=finger->prev) != &tp->t.data_ofo_queue);
				} else {
					finger = (struct sk_buff *)&tp->t.data_ofo_queue;
				}
				next = finger->next;
				if(finger != (struct sk_buff*)&tp->t.data_ofo_queue) {
					int slack = TCP_SKB_CB(finger)->end_seq - TCP_SKB_CB(skb)->seq;
					if(slack > 0) {
						if(slack >= skb->len) {
							RECORD_OVERLAP(0, skb->len);
							// completely covered by old packet
							trickles_kfree_skb(skb);
							skb = NULL;
							// 0717 Trying to increase efficiency
							if(0 && trickles_ratelimit()) {
								printk("New packet completely covered by old packet\n");
							}
							goto skip_ofo_insert;
						} else {
							RECORD_OVERLAP(1, slack);
							skb_pull(skb, slack);
							TCP_SKB_CB(skb)->seq += slack;
							// 0717 Trying to increase efficiency
							if(0 && trickles_ratelimit()) {
								printk("New packet overlapped old packet by %d\n", slack);
							}
						}
					}
				}
				if(next != (struct sk_buff*)&tp->t.data_ofo_queue) {
					int slack = TCP_SKB_CB(skb)->end_seq - TCP_SKB_CB(next)->seq;
					if(slack > 0) {
						if(slack >= next->len) {
							RECORD_OVERLAP(2, next->len);
							// completely covered by new packet
							__skb_unlink(next, &tp->t.data_ofo_queue);
							if(tp->t.byteReqHint == next)
								tp->t.byteReqHint = NULL;
							// 0717 Trying to increase efficiency
							if(0 && trickles_ratelimit()) {
								printk("Old packet completely covered by old packet\n");
							}
							trickles_kfree_skb(next);
						} else {
							RECORD_OVERLAP(3, slack);
							skb_pull(next, slack);
							TCP_SKB_CB(next)->seq += slack;
							// 0717 Trying to increase efficiency
							if(0 && trickles_ratelimit()) {
								printk("Old packet overlapped new packet by %d\n", slack);
							}
						}
					}
				}
				__skb_insert(skb, finger, finger->next, &tp->t.data_ofo_queue);
				if(PACKET_TRACE_OFO) {
					PACKET_TRACE_LOG("ofo attempt succeeded; ");
					PACKET_TRACE_LOG_DO(SK_data_ofo_queue_dump(sk));
				}

				skb = NULL;
			skip_ofo_insert:
				//PACKET_TRACE_LOG("\n");
				goto data_done;
			}
			if(TCP_SKB_CB(skb)->byteNum < tp->t.byteRcvNxt) {
				int slack = tp->t.byteRcvNxt - TCP_SKB_CB(skb)->byteNum;
				if(slack >= skb->len) {
					if(0 || clientDebugLevel >= 2)
						printk("byteNum = %d, byteRcvNxt = %d\n", TCP_SKB_CB(skb)->byteNum, tp->t.byteRcvNxt);
					RECORD_OVERLAP(6,skb->len);
					trickles_kfree_skb(skb);
					skb = NULL;
					goto data_done;
				} else {
					RECORD_OVERLAP(4,slack);
					__skb_pull(skb, slack);
					TCP_SKB_CB(skb)->byteNum += slack;
				}
			}
			if(skb->len == 0) {
				trickles_kfree_skb(skb);
				skb = NULL;
				goto data_done;
			}
			BUG_TRAP(TCP_SKB_CB(skb)->byteNum == tp->t.byteRcvNxt);
			TCP_SKB_CB(skb)->seq = tp->t.byteRcvNxt;
			TCP_SKB_CB(skb)->end_seq = TCP_SKB_CB(skb)->seq + skb->len;
			//printk("end_seq = %d\n", TCP_SKB_CB(skb)->end_seq);

			int firstPacket = 1;
			nonzeroPacket = 1;
			int packetCount = 0;

			if(0) {
				static long last_send_time;
				long delta = jiffies - last_send_time;
				int log = 0;
				while(delta > 0) {
					delta >>= 1;
					log++;
				}
				log = MIN(log, 9);
				printk("%c", '0'+log);
				if(0 && log >= 2) {
					printk("(%d)", TCP_SKB_CB(skb)->seq);
				}
				last_send_time = jiffies;
			}

			while(1) {
			queue_next_packet:
				/* TODO: This code trusts that only client actions generate
				   packets. Add windowsize check to prevent attackers from
				   overflowing window */

				BUG_TRAP(skb->len > 0);
				
				if(firstPacket) {
					firstPacket = 0;
				} else {
					// PACKET_TRACE_LOG("multipacket seq = %d - %d\n", TCP_SKB_CB(skb)->seq, TCP_SKB_CB(skb)->end_seq);
				}
				packetCount++;

				// after this point, tcb->seq and ->end_seq are in tp->rcv_nxt units
				TCP_SKB_CB(skb)->seq = tp->rcv_nxt;
				TCP_SKB_CB(skb)->end_seq = 
					TCP_SKB_CB(skb)->seq + skb->len;
				tcp_fast_path_queue(sk, skb);

				tp->t.byteRcvNxt += skb->len;
				if(byteRcvNxt_checkSkip(sk)) {
					byteRcvNxt_doSkip(sk);
				}

				if(tp->t.byteReqHint == skb)
					tp->t.byteReqHint = NULL;

				while((skb = skb_peek(&tp->t.data_ofo_queue))) {
					if(TCP_SKB_CB(skb)->seq > tp->t.byteRcvNxt) {
						goto data_done;
					}
					__skb_unlink(skb, &tp->t.data_ofo_queue);
					if(tp->t.byteReqHint == skb)
						tp->t.byteReqHint = NULL;

					if(TCP_SKB_CB(skb)->end_seq <= tp->t.byteRcvNxt) {
						if(printOverlap)
							printk("IN SEQUENCE WHOLE PACKET REMOVED: %d\n", skb->len);
						RECORD_OVERLAP(7,skb->len);
						trickles_kfree_skb(skb);
					} else {
						int slack = tp->t.byteRcvNxt - TCP_SKB_CB(skb)->seq;
						RECORD_OVERLAP(5, slack);
						__skb_pull(skb, slack);
						TCP_SKB_CB(skb)->seq += slack;
						BUG_TRAP(TCP_SKB_CB(skb)->seq == tp->t.byteRcvNxt &&
							 skb->len > 0);
						if(slack) {
							if(printOverlap)
								printk("IN SEQUENCE SLACK REMOVED: %d\n", slack);
						}
						goto queue_next_packet;
					}
				}
				// only reach this point if no suitable packet found
				break;
			}
		data_done:
			if(nonzeroPacket)
				//printk("(%d)", packetCount)
					;
			;
		}
		if(PACKET_TRACE_FRAGMENTS) {
			PACKET_TRACE_LOG(" byteRcvNxt = %d ", tp->t.byteRcvNxt);
		}
	}
	return 0;
 bad_packet:
	printk("bad packet\n");
	return -1;
}

#define BAD_DATA() do { if(dbgBadChunk) printk("bad data line %d\n", __LINE__); goto bad_data; } while(0)
struct sk_buff *
DataChunk_parse(struct ResponseChunk *rc, struct sk_buff *in_skb, int chunkNum) {
	struct DataChunk *currChunk = (struct DataChunk *) rc;
	int dataLen = DATA_LEN(currChunk);
	struct sk_buff *curr_skb = NULL;

	if(dataLen < 0) {
		if(dbgBadChunk)
			printk("Bad data len (%d), ignoring for data purposes @ chunkno = %d lineno = %d %d-%d\n",
			       in_skb->h.th->ack_seq, chunkNum, TCP_SKB_CB(in_skb)->dbg,
			       in_skb->data - in_skb->head, in_skb->tail - in_skb->head);
		BAD_DATA();
	}
	curr_skb = skb_clone(in_skb, GFP_ATOMIC);
	if(curr_skb == NULL) {
		printk("Out of memory while splitting skb\n");
		BAD_DATA();
	}
	trickles_init_tcp_cb(curr_skb);

	//printk("Chunk(%d) at %d, %d %d\n", ntohs(currChunk->chunkLen), (char*)curr_skb->data - ucont_start,  (char*) (currChunk+1) - ucont_start, origTail - ucont_start);
	curr_skb->data = currChunk->data;
	curr_skb->tail = curr_skb->data + dataLen;
	curr_skb->len = dataLen;
	TCP_SKB_CB(curr_skb)->byteNum =
		htonl(currChunk->byteNum);
	TCP_SKB_CB(curr_skb)->toSkip = 0;
	TCP_SKB_CB(curr_skb)->skipPosition = 0xffffffff;
	return curr_skb;
 bad_data:
	return NULL;
}

static inline int fragment_skb(struct sk_buff *in_skb) {
	struct sock *sk = in_skb->sk;
	struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;
	struct ResponseChunk *currChunk = (struct ResponseChunk *)
		in_skb->data, *prevChunk = NULL;
	char *origTail = in_skb->tail;
	char *origDataStart = in_skb->data;
	int origLen = in_skb->len;
	int traceNeedNewline = 0;

	if(!isDataSubchunk(currChunk)) {
		if(trickles_ratelimit())
			printk("currChunk->type = %d, len = %d\n", currChunk->type, ntohs(currChunk->chunkLen));
		goto bad_data;
	}

	TCP_SKB_CB(in_skb)->numDataChunks = 0;

	if((char*)currChunk == origTail) {
		printk("No chunks, origlen =  %d\n", origLen);
		in_skb->data = in_skb->tail;
		in_skb->len = 0;
		TCP_SKB_CB(in_skb)->numDataChunks = 0;
	} else {
		if(!((char*)currChunk < origTail)) {
			BUG_TRAP((char*)currChunk < origTail);
			printk("currChunk = %p origTail = %p\n", currChunk, origTail);
		}

		struct sk_buff *curr_skb = NULL;
		int chunkNum = 0;
#if 0
		printk("\nseq(%d) [%d] = { ", TCP_SKB_CB(in_skb)->dbg_cont_seq, 
		       origTail - (char *)currChunk);
		ResponseChunk_printAll(currChunk, origTail - (char *)currChunk);
		printk("}");
#endif
		while((char*) (currChunk+1) <= origTail &&
		      chunkNum < MAX_NUM_DATACHUNKS) {
			int isPaddingChunk = 0;

			switch(currChunk->type) {
			case RCHUNK_DATA: {
				struct sk_buff *curr_skb = 
					DataChunk_parse(currChunk, in_skb, chunkNum);
				if(curr_skb == NULL) {
					printk("out of memory while parsing data chunk\n");
					goto bad_data;
				}
				struct DataChunk *dc = (struct DataChunk *)
					currChunk;
				unsigned byteNum = ntohl(dc->byteNum);

				if(PACKET_TRACE_FRAGMENTS) {
					PACKET_TRACE_LOG("fragment(f=%X) [%d-%d] ",
							 dc->flags, byteNum, byteNum + curr_skb->len);
				}

				if(!findUCContinuation(sk, byteNum, byteNum+1)) {
#if 0
					printk("continuation not found for %d\n", byteNum);
					SK_request_dump(sk);
					SK_ucontList_dump(sk);
					SK_dump_vars(sk);
#endif
					// XXX this shouldn't happen, but may occur during a lsos
					// it turns out that the rest of the state machine gets screwd up if we queue the data here.
					goto bad_data;
				}

				if(dc->flags & DCHUNK_FIN) {
					unsigned finByte = byteNum + curr_skb->len;
					// we also need to perform an implicit skip to the right edge. It's more convenient to do this when the continuation is cleared, so save ContFIN position in sk

					struct UC_Continuation *cont = 
					findUCContinuation(sk, finByte - 1, finByte);
#if 0
					printk("fin chunk ; still need to zap data request mapping\n");
					SK_dump_vars(sk);
#endif
					if(cont == NULL) {
						printk("continuation not found\n");
						goto bad_data;
					} else {
						// printk("fin received, byteRcvNxt = %d\n", tp->t.byteRcvNxt);
						UC_Continuation_receivedFIN(cont, finByte);
					}
					TCP_SKB_CB(curr_skb)->toSkip = 1;
					TCP_SKB_CB(curr_skb)->skipPosition = 
						cont->validEnd;
				}
				struct sk_buff **chunk = GET_CHUNK(in_skb,chunkNum);
				// printk("pchunk is %p\n", chunk);
				*chunk = curr_skb;
				chunkNum++;
				break;
			} 
			case RCHUNK_SKIP: {
				struct SkipChunk *sc = (struct SkipChunk *)
					currChunk;
				unsigned len = ntohl(sc->len);
				unsigned byteNum = ntohl(sc->byteNum);
				struct SkipCell *cell = 
					SkipCell_new(byteNum, byteNum + len);
				if(cell == NULL) {
					printk("out of memory for skipcell\n");
					goto bad_data;
				}
				SkipCell_insert(sk, cell);
				break;
			}
			case RCHUNK_FINHINT: {
				struct FINHintChunk *shc = (struct FINHintChunk *)
					currChunk;
				unsigned hintPosition = ntohl(shc->byteNum);
				// We look for the matching continuation, and install the hint
				struct UC_Continuation *cont = findUCContinuation(sk, hintPosition, hintPosition);
				if(cont == NULL) {
					printk("continuation skip did not match a continuation\n");
#if 0
					goto bad_data;
#else
					goto non_fatal;
#endif
				}
				struct SkipCell *cell = 
					SkipCell_new(hintPosition, cont->validEnd);
				if(cell == NULL) {
					printk("out of memory for skipcell\n");
					goto bad_data;
				}
				if(!SkipCell_insert(sk, cell)) {
					// printk("could not insert cell \n");
					SkipCell_free(cell);
				}
				//TRACE_K_PACKETS(20);
				PACKET_TRACE_LOG( "hint received, hintPosition = %d, byteRcvNxt = %d ", hintPosition, tp->t.byteRcvNxt );
				PACKET_TRACE_LOG_DO(SK_data_ofo_queue_dump(sk); printk(" ;; "););
				
				UC_Continuation_setFINHint(cont, hintPosition);
				break;
			}
			default:
				if(!ResponseChunk_isPadding(currChunk)) {
					printk("invalid skiphint %x\n", (int)*(char*)currChunk);
					goto bad_data;
				}
				isPaddingChunk = 1;
			}
#if 0
			printk("%p: NumDataChunks = %d\n",
			       curr_skb, TCP_SKB_CB(curr_skb)->numDataChunks);
#endif
			// Prepare for next loop
			if(isPaddingChunk) {
				currChunk = (struct ResponseChunk *)(((char*)currChunk) + 1);
			} else{
				// normal chunk
				prevChunk = currChunk;
				currChunk = (struct ResponseChunk *)
					NEXT_CHUNK_ADDR(currChunk);
				//printk("%p => %p\n", origChunk, currChunk);
			}
		}
		BUG_TRAP(chunkNum >= 1);
		// Harmless padding
		if((char*)(currChunk-1) >= origTail) {
			int dumpLen = (char*)origTail - (char*)currChunk;
			if(dbgBadChunk)
				printk("curr chunk (prev=%d, packetID=%d) exceeds tail!, chunkNum = %d, origLen = %d, chunkOffset = %d\n",
#ifdef CHUNKID
				       prevChunk != NULL ? 0xdeadbeef : // prevChunk->chunkID :
#endif
			       -1,
			       in_skb->h.th->ack_seq, chunkNum, origLen, (char*)currChunk - origDataStart);
			mem_dump((char*)currChunk, dumpLen);
		}
		TCP_SKB_CB(in_skb)->numDataChunks = chunkNum;

		//printk("%p: NumDataChunks = %d\n", in_skb, TCP_SKB_CB(in_skb)->numDataChunks);
	}
	//update_rx_stats(in_skb);

	//printk("in_skb: byteNum = %d, len = %d\n", TCP_SKB_CB(in_skb)->byteNum, in_skb->len);
#undef BAD_DATA

 non_fatal:
	if(traceNeedNewline) printk("\n");
	return TCP_SKB_CB(in_skb)->numDataChunks;
 bad_data:
	if(traceNeedNewline) printk("\n");
	return -1;
}


/* **************** Continuation management code ***************************/

static inline int process_new_ucont(struct sock *sk, struct RequestOFOEntry *ofo_entry) {
	struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;

	BUG_TRAP(ofo_entry != NULL);
	if(ofo_entry->parent == TRANSPORT_OR_DATA_ONLY_REQNUM) {
		gInvalidReqnum++;
		RequestOFOEntry_free(ofo_entry);
		return -1;
	}
	BUG_TRAP(ofo_entry->parent != TRANSPORT_ONLY_REQNUM);

	//printk("Contains ucont1\n");
	if(ofo_entry->parent == tp->t.request_rcv_nxt) {
		for(;;) {
			// process formerly out of order continuations that are now in-order
			CONTINUATION_TYPE *cont = ofo_entry->cont;
#ifndef TEST_TRANSPORT_ONLY
			//printk("pre update\n");
			UpdateClientUCState(sk, ofo_entry);
			RequestOFOEntry_free(ofo_entry);
			//printk("post update, ucontlist = %d\n", tp->t.ucontList.len);
#endif
			// deallocation of skb->cont must occur after references in the above block
			BUG_TRAP(tp->t.ack_prev != cont); // 0429 track down corruption error
			MARK_PC(cont);
			// request_rcv_nxt is updated in updateParent
			if(empty(&tp->t.request_ofo_queue)) {
				break;
			}
			ofo_entry = (struct RequestOFOEntry *)tp->t.request_ofo_queue.next;
			if(ofo_entry->parent != tp->t.request_rcv_nxt) {
				break;
			}
			unlink((struct alloc_head*) ofo_entry);
		}
		ofo_entry = NULL;
	} else {
		//printk("ofo\n");
		/* enqueue in request_ofo_queue */
		struct RequestOFOEntry *finger;
		BUG_TRAP(ofo_entry->parent > tp->t.request_rcv_nxt);
		if(empty(&tp->t.request_ofo_queue)) {
			insert_head((struct alloc_head_list*)&tp->t.request_ofo_queue,
				    (struct alloc_head*)ofo_entry);
		} else {
			finger = (struct RequestOFOEntry *)tp->t.request_ofo_queue.prev;
			do {
				if(finger->parent < ofo_entry->parent)
					break;
			} while((struct alloc_head_list*)(finger=finger->prev) != &tp->t.request_ofo_queue);
			if(finger->next != (struct RequestOFOEntry*)&tp->t.request_ofo_queue) {
				if( ((struct RequestOFOEntry*)finger->next)->parent == ofo_entry->parent) {
					RequestOFOEntry_free(ofo_entry);
					ofo_entry = NULL;
					return 1;
				}
				BUG_TRAP(((struct RequestOFOEntry*)
					  finger->next)->parent >
					 ofo_entry->parent);
			}
			insert((struct alloc_head*)ofo_entry,
			       (struct alloc_head*)finger,
			       (struct alloc_head*)finger->next);
			ofo_entry = NULL;
		}
	}
	//BUG_TRAP(ofo_entry == NULL);
	return 0;
 }

/* TODO: Strip out sk argument */
int AckProof_update(struct sock *sk, AckProof *ackProof, CONTINUATION_TYPE *cont) {
	int i, j;
	__u32 seq = cont->seq;
	int *numSacks = &ackProof->numSacks;
	Sack *sacks = ackProof->sacks;
	for(i=0; i < *numSacks && (seq >= sacks[i].left || seq == sacks[i].left - 1); i++) {
	  /* condition not expressed as > because of overflow/underflow */
		if(seq == sacks[i].left - 1) {
			sacks[i].left = seq;
			sacks[i].nonceSummary ^= cont->cum_nonce;
			if(i > 0 && sacks[i-1].right == sacks[i].left - 1) {
				printk("Not supposed to reach this point\n");
			  /* actually, this case should never be reached */
				/* coalesce */
				sacks[i-1].right = sacks[i].right;
				sacks[i-1].nonceSummary ^= sacks[i].nonceSummary;
				for(j=i + 1; j < *numSacks; j++) {
					sacks[j - 1] = sacks[j];
				}
				(*numSacks)--;
			}
			return 1;
		} else if(seq == sacks[i].right + 1) {
			sacks[i].right = seq;
			sacks[i].nonceSummary ^= cont->cum_nonce;
			if(i + 1 < *numSacks && sacks[i].right == sacks[i+1].left - 1) {
				/* coalesce */
				sacks[i].right = sacks[i+1].right;
				sacks[i].nonceSummary ^= sacks[i+1].nonceSummary;
				for(j=i + 2; j < *numSacks; j++) {
					sacks[j - 1] = sacks[j];
				}
				(*numSacks)--;
			}
			return 1;
		} else if(Sack_contains(&sacks[i], seq)) {
			/* In the middle of an existing sack */
			return 1;
		}
	}
	if(i >= MAX_KERNEL_SACKS) {
		//printk("exceeded # of sacks while updating sack\n");
		return 0;
	}
	/* Cannot extend any sack ; create new one */
	/* seq is between i-1 and i; shift upwards all sacks i and up */
	for(j=MIN(*numSacks, MAX_KERNEL_SACKS-1); j > i; j--) {
		sacks[j] = sacks[j-1];
	}
	sacks[i].left = sacks[i].right = seq;
	sacks[i].nonceSummary = cont->cum_nonce;
	*numSacks = MIN(*numSacks+1, MAX_KERNEL_SACKS);
	/* Sanity checks */
	BUG_TRAP(i == *numSacks-1 || (sacks[i].right != sacks[i+1].left - 1 &&
				      sacks[i].right < sacks[i+1].left));
	BUG_TRAP(i == 0 || (sacks[i-1].right != sacks[i].left - 1 &&
			    sacks[i-1].right < sacks[i].left));

	return 1;
}


static int findAckables(struct sock *sk, int skip, struct sk_buff **skip_skb) {
	// skip == 1 if we are to ignore leading missing packets (loss assumed)
	struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;
	int progress = 0;
	struct sk_buff *skb = skb_peek(&tp->t.ofo_queue);
	if(skip_skb) *skip_skb = NULL;
	// 0419 special case - if ack_curr is set (due to recovery), we've already made progress in finding an ackable continuation
#if 0
	// 0501 - don't call findAckable when exiting recovery
	if(tp->t.ack_prev == NULL && tp->t.cont_list.len >= 1) {
		progress = 1;
		goto done;
	}
#endif

	if(tp->t.ack_last < tp->t.rcv_nxt) {
		tp->t.ack_last = tp->t.rcv_nxt;
		progress = 1;
	}
	if(skb) {
		if(!progress && skip) {
			while((struct sk_buff_head*)skb != &tp->t.ofo_queue &&
			      TCP_SKB_CB(skb)->trickle_seq < tp->t.ack_last) {
				skb = skb->next;
			}
			if((struct sk_buff_head*)skb == &tp->t.ofo_queue) return 0 /* no progress*/;
			if(0 || clientDebugLevel >= 2)
				printk("ack_last skipped over gap: %u - %u\n",
				       (struct sk_buff_head*)skb->prev != &tp->t.ofo_queue ?
				       TCP_SKB_CB(skb->prev)->trickle_seq :
				       tp->t.rcv_nxt - 1, TCP_SKB_CB(skb)->trickle_seq);
			tp->t.ack_last = TCP_SKB_CB(skb)->trickle_seq + 1;
			*skip_skb = skb;
			progress = 1;
		}
		while((struct sk_buff_head*)skb != &tp->t.ofo_queue &&
		      TCP_SKB_CB(skb)->trickle_seq <= tp->t.ack_last) {
			if(tp->t.ack_last == TCP_SKB_CB(skb)->trickle_seq) {
				tp->t.ack_last++;
				progress = 1;
			}
			skb = skb->next;
		}
	}
#if 0
 done:
#endif
	return progress;
}

 struct UC_Continuation *findUCContinuation(struct sock *sk, unsigned start, unsigned end) {
	 /* XXX use faster datastructure/algorithms? */

	 struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;
	 struct UC_Continuation *ucont = (struct UC_Continuation*)tp->t.ucontList.next,
		 *candidate = NULL;
	 int found = 0;
	 // return continuation with maximum overlap
	 int overlapSize = 0;
	 while(ucont != (struct UC_Continuation *)&tp->t.ucontList) {
#ifdef FINDUC_DBG
		 printk("Considering %p: [%d-%d]\n", ucont,
			ucont->validStart, ucont->validEnd);
#endif
		 int overlapStart = MAX(ucont->validStart, start);
		 int overlapEnd = MIN(ucont->validEnd, end);
		 int zerolenOK = start == end;
		 int curr_overlapSize = overlapEnd - overlapStart;
		 if(overlapStart > start || overlapStart > overlapEnd ||
		    (!zerolenOK && curr_overlapSize == 0)) {
#ifdef FINDUC_DBG
			 printk("skipped overlap = [%d=%d]\n",
				overlapStart, overlapEnd);
#endif
			 goto next;
		 }

		 if(overlapEnd == end) {
			 // done, found perfect fit
			 found = 1;
#ifdef FINDUC_DBG
			 printk("perfect fit, set to %p\n", ucont);
#endif
			 candidate = ucont;
			 break;
		 }
		 if((curr_overlapSize > 0 || zerolenOK) &&
		    (candidate == NULL || overlapSize < curr_overlapSize)) {
#ifdef FINDUC_DBG
			 printk("%d %d candidate set to %p\n", overlapSize,
				curr_overlapSize, ucont);
#endif
			 found = 1;
			 overlapSize = curr_overlapSize;
			 candidate = ucont;
		 }
	 next:
#ifdef FINDUC_DBG
		 printk("next\n");
#endif
		 ucont = (struct UC_Continuation*)ucont->next;
	 }

#ifdef FINDUC_DBG
	 printk("uc_continuation: [%d-%d] ", start, end);
#endif
	 if(!found) {
#ifdef FINDUC_DBG
		 printk("not found\n");
#endif
		 return NULL;
	 }
#ifdef FINDUC_DBG
	 printk("%p [%d-%d]\n", candidate, candidate->validStart,
		candidate->validEnd);
#endif

	 return candidate;
 }

struct sk_buff *startSimulation(struct sock *sk, CONTINUATION_TYPE *cont, struct sk_buff *skb) {
	struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;
	struct sk_buff *result = skb_copy(skb, GFP_ATOMIC);
	if(result == NULL) {
		return NULL;
	}
	tp->t.responseMSK = cont;
	tp->t.responseCount = 0;

	BUG_TRAP(tp->t.responseList.len == 0);
	init_head(&tp->t.responseList);

	result->h.th = NULL;
	result->nh.iph = NULL;
	return result;
}

void finishSimulation(struct sock *sk, CONTINUATION_TYPE *destCont, CONTINUATION_TYPE *simCont) {
	struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;
	CONTINUATION_TYPE *finger;
	if(tp->t.responseCount >= 1) {
		int totalDataLen = 0;
		int i;
		BUG_TRAP(simCont == tp->t.responseMSK);
		for(i=0; i < simCont->num_packets; i++) {
			totalDataLen += simCont->packets[i].len;
			simCont->packets[i].contType &= ~CONTTYPE_HASHCOMPRESSED;
			// printk("pktlen=%d ", simCont->packets[i].len);
		}

		destCont->firstTransportChild = simCont->packets[0].seq;
		destCont->numTransportChildren = simCont->num_packets;

		if(simCont->state == CONT_RECOVERY) {
			// TRACE_THIS_PACKET();
			// printk("recoveryStep %d: { tot=%d ", simCont->seq, totalDataLen);
			int i;
			PACKET_TRACE_LOG_DO(
			for(i=0; i < simCont->num_packets; i++) {
				printk("{%d=%d}", simCont->packets[i].seq,
				       simCont->packets[i].len);
				if(i < simCont->num_packets - 1) {
					printk(", ");
				}
			}
			printk(" }\n");
			);
		}
	} else {
		//printk("No simulation output (could be harmless, e.g. during fast recovery!!\n");
#if 0 // 0822
		destCont->minResponseLen = 0;
#endif
		destCont->firstTransportChild = 0;
		destCont->numTransportChildren = 0;
		destCont->mark = -1;
	}
	finger = (CONTINUATION_TYPE*)tp->t.responseList.next;
	while(finger != (CONTINUATION_TYPE*)&tp->t.responseList) {
		printk("responseListlen = %d\n", tp->t.responseList.len);
		printk("finger=%p (%p  %p)\n", finger, finger->prev, finger->next);
		struct cminisock *clean = finger;
		finger = finger->next;
		unlinkCont(clean);
		MARK_PC(clean);
		free_msk(sk, clean);
		kfree(clean); // not a bug! alloc_trickles_msk creates the msk w/ kmalloc()
	}
	destCont->simulated = 1;

#if 1
	// Add predicted output to prediction table
	int i;
	struct cminisock *msk;
	for(i=0; i < tp->t.responseCount; i++) {
		if(i==0) {
			msk = tp->t.responseMSK;
		} else if(i == 1) {
			msk = (struct cminisock *)tp->t.responseList.next;
		} else {
			msk = msk->next;
		}
		BUG_TRAP(msk != (struct cminisock *)&tp->t.responseList);

		int j;
		for(j=0; j < msk->num_packets; j++) {
			if((msk->packets[j].contType & ~CONTTYPE_HASHCOMPRESSED) == CONTTYPE_MINIMAL) {
#if 0
				printk("skipping minimal %d\n", 
				       msk->packets[j].seq);
#endif
				continue;
			}
			struct cminisock *n_msk = 
				copyClientSide_Continuation(msk, GFP_ATOMIC);
			if(n_msk == NULL) {
				printk("Warning: Out of memory while adding to hash compression table\n");
				break;
			}
#define IDENT_CONV(X) X
			MARSHALL_PACKET_FIELDS(n_msk, msk, j, IDENT_CONV);
#undef IDENT_CONV
			// printk("inserting %d\n", n_msk->seq);

			n_msk->localParentID = msk->seq;
			n_msk->clientTimestamp = jiffies;
			// xxx minisocket allocation is screwed up
			MSKTable_insert(tp->t.msk_table, n_msk);
		}
	}
	
	MSKTable_clean(tp->t.msk_table, tp->t.rcv_nxt);
#endif
}

static int runSimulation(struct sock *sk, CONTINUATION_TYPE *cont, struct sk_buff *skb) {
	struct sk_buff *scratchSkb = startSimulation(sk, cont + 1, skb);
	cont->source = sk->sport;
	cont->dest = sk->dport;
	//printk("%d %d\n", cont->source, cont->dest);
#if 0
	struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;
	if(IS_RECOVERY_STATE())
		printk("recovery simulation of seq = %d, rcvnxt = %d\n", cont->seq, tp->t.rcv_nxt);
#endif
	if(scratchSkb == NULL) {
		printk("Out of memory during simulation\n");
		return 0;
	}

	int rval = server_rcv_impl(sk, scratchSkb);
	// server_rcv_impl never deallocates skb
	__kfree_skb(scratchSkb);
	if(rval == -EINVAL) {
		if(!disableSevereErrors) {
			if(trickles_ratelimit()) {
				printk("simulation failure\n");
			}
		}
		finishSimulation(sk, cont, cont + 1);
		return 0;
	} else {
		if(rval != 0) {
			if(trickles_ratelimit()) {
				printk("simulation rval == %d\n", rval);
			}
		}
		// debugging
		struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;
		tp->snd_cwnd = cont->actualCwnd;
		tp->snd_ssthresh = cont->ssthresh;
	}
	finishSimulation(sk, cont, cont + 1);
	return 1;
}

#define USEFULNESS_THRESHOLD (1000) // don't use continuation unless we can receive at least this many bytes

#define PACKET_RESPONSE_LEN(CONT, P) 			\
	(( 0 <= (P) && (P) < SIMULATION_NUM_PACKETS(CONT)) ? SIMULATION_PACKETS(CONT)[(P)].len : 0)

#define OUT_FREE (-1)
#define OUT_FREE_IGNORE (-2)
#define OUT_NODATAREQUEST (-3)

// XXX XXX XXX XXX

// Out_NoDataRequest propagation is not 100% kosher. The
// implementation forces the state machine to unconditionally wait for
// the window to open. But the exception may potentially be thrown
// when the window is not empty.
// *** To save time, this is "Good Enough For Now"

#define PROPAGATE_ERR(STMT, STR, OFREE)					\
({									\
	int _rval = STMT;							\
	if(_rval != 0) {						\
		/* if(IS_RECOVERY_STATE())  printk("rval = %d\n", _rval); */ \
		/* if(( _rval == OUT_FREE_IGNORE) && trickles_ratelimit()) printk(STR, _rval);  */  \
		if(_rval == OUT_FREE) { OFREE; }  \
		if(_rval == OUT_FREE_IGNORE) { goto out_free_ignore_this_cont; }  \
		if(_rval == OUT_NODATAREQUEST) { goto no_data_request; }	\
	}								\
 })

static inline
int generateRequestsFromPending(struct sock *sk, struct sk_buff *skb,
			struct WireTrickleRequest *wreq,
			CONTINUATION_TYPE *cont);
static inline
int generateDataRequests(struct sock *sk, struct sk_buff *skb,
			struct WireTrickleRequest *wreq,
			CONTINUATION_TYPE *cont);

#if 0
#define TICK() printk("sendackhelper @%d\n", __LINE__)
#else
#define TICK()
#endif
static int sendAckHelper(struct sock *sk, CONTINUATION_TYPE *cont, enum TrickleRequestType type) {
	TICK();
	struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;
	struct sk_buff *skb;
	int res;
	static int packetID = 0;

	PACKET_TRACE_LOG("a0 ");
	while((skb=__skb_dequeue(&tp->t.sendAckOverflow))) {
		BUG_TRAP(skb->sk == sk);
		skb->sk = sk;
		if((res = tp->af_specific->queue_xmit(skb, 0)) != 0) {
			if(trickles_ratelimit()) {
				printk("dropped while sending ack from overflow\n");
			}
			// push back
			__skb_queue_head(&tp->t.sendAckOverflow, skb);
			TICK();
			return 0;
		}
	}

	PACKET_TRACE_LOG("a1 ");
#if 0 // 0420, tracking down source of order 4096 objects
	skb = alloc_skb(ETHERNET_MTU, GFP_ATOMIC);
#else
	skb = alloc_skb(MAX_TCP_HEADER + MAX_TRICKLES_CLIENT_HDR_LEN + TRICKLES_MSS, GFP_ATOMIC);
#endif
	WireTrickleRequest *wreq;
	int tcp_header_size;
	struct tcphdr *th;
	AckProof *proof;
	short windowValue = -1;

	TIMING_CTX_DEF0("sendAckHelper", "sent", "didn't send", "inner0", "inner10", "inner11");
	TIMING_CTX_DEF1(6, 4, 2, 3, 3);
	reinitTimingCtx(&ctx);
	recordSample(&ctx,0);
	recordSample(&ctx,1);

	if(skb == NULL) {
		printk("sendAckHelper: out of memory\n");
		return 0;
	}

	if(cont->state == CONT_BOOTSTRAP ||
	   type == TREQ_SLOWSTART) {
		proof = &tp->t.altProof;
		if(clientDebugLevel >= 2) {
			printk("sending alt proof\n");
			AckProof_dump(proof);
		}
	} else {
		proof = &tp->t.standardProof;
	}

	PACKET_TRACE_LOG("a2 ");
	skb_reserve(skb, MAX_TCP_HEADER);
	wreq = (WireTrickleRequest *)skb_put(skb, sizeof(WireTrickleRequest) + proof->numSacks * sizeof(WireSack));
	//printk("sendackhelper - req: %p\n", &req->cont);

	wreq->type = type;
	wreq->ucont_len = 0; // hack to make input to simulation well-formed
	recordSample(&ctx,0);
	recordSample(&ctx,1);

	__u32 oldClientTimestamp = cont->clientTimestamp ;
	__u32 oldClientState = cont->clientState;
	cont->clientTimestamp = jiffies;
	cont->clientState = tp->t.clientStateCounter;
	marshallContinuationClient(sk,&wreq->cont,cont, -1);
#ifdef ENABLE_HASHCOMPRESS
	// reset number of children that we have received
	cont->numChildrenReceived = 0;
	// dont restore the timestamp and client state; we need them when reconstructing the packet
#else
	cont->clientTimestamp = oldClientTimestamp;
	cont->clientState = oldClientState;
#endif

	marshallAckProof(&wreq->ackProof, proof);
	recordSample(&ctx,0);
	recordSample(&ctx,1);

#define BYTEREQ_IN_WINDOW(SK)	\
	((SK)->tp_pinfo.af_tcp.t.byteReqNext < (SK)->tp_pinfo.af_tcp.t.byteRcvNxt + (SK)->tp_pinfo.af_tcp.t.byteSkipHintAmount + (SK)->rcvbuf)
	PACKET_TRACE_LOG("a3 ");

	if(IS_SEND_UCONTREQ_STATE(tp)) {
		// Only send requests in normal state
		// Manage reliable request queue here
		if(HAS_PENDING_REQUESTS(sk)) {
			gHasPendingCount++;
			PACKET_TRACE_LOG("a10 ");

#if 0
			if(IS_RECOVERY_STATE()) 	printk("trying to send pending request during recovery\n");
#endif
			TICK();
			PROPAGATE_ERR(generateRequestsFromPending(sk, skb, wreq, cont),
				      "generateRequestsFromPending returned error %d\n", goto try_data);
			TICK();
		} else {
		try_data:
			PACKET_TRACE_LOG("a11 ");
			if(BYTEREQ_IN_WINDOW(sk) ||
			   !empty(&tp->t.missingDataMap)) {
				PACKET_TRACE_LOG("a12 ");
				gInWindowCount++;
#if 0
				if(IS_RECOVERY_STATE()) printk("trying to send data request during recovery\n");
#endif
				TICK();
				PROPAGATE_ERR(generateDataRequests(sk, skb, wreq, cont),
					      "generateDataRequests returned error %d\n", goto out_free_error);
				TICK();
#if 0
				if(IS_RECOVERY_STATE()) printk("might have sent data request during recovery\n");
#endif
			} else {
				PACKET_TRACE_LOG("a13 ");

				gOutOfWindowCount++;
				/* couldn't send out a request */
				//printk("couldnot sent out request 0 ");
				TICK();
			no_data_request:
				TICK();
				//printk("could not sent out request 1 ");
				if(tp->rcv_nxt > tp->copied_seq) {
					// user_ack will reset this bit later
					tp->t.timerState &= ~TRICKLES_ENABLE_DATA_TIMEOUT;
				}
				recordSample(&ctx,1);
#if 0
				if(IS_RECOVERY_STATE()) printk("could not send out request\n");
#endif
				goto out_free_error;
			}
		}
		/* Todo: Add support for direct interface */
	} else {
		/* In all other states, do only transport layer */
		printk("transport only\n");
		wreq->ucont_len = htons(0);
		wreq->cont.parent = TRANSPORT_ONLY_REQNUM;

		if(!runSimulation(sk,cont,skb)) {
			printk("could not run simulation ");
			goto out_free_ignore_this_cont;
		}
		if(PACKET_RESPONSE_LEN(cont,0) < USEFULNESS_THRESHOLD) {
			printk("Not useful at %d\n", __LINE__);
			goto out_free_ignore_this_cont;
		}
		static int transportCount = 0;
		transportCount++;
		if(trickles_ratelimit()) {
			printk("transportCount = %d\n", transportCount);
		}
	}
	PACKET_TRACE_LOG("a4 ");

	if(tp->t.eventsPos == 0) {
		goto sample;
	} else {
		struct TricklesLossEvent *lastEvent = &tp->t.events[tp->t.eventsPos - 1];
		if(tp->t.state != lastEvent->state) {
		// state change
			appendTricklesLossEvent(sk, MIN((cont+1)->mark, EVENT_CWND_MAX),
						EVENT_EXTRA_SEND, tp->t.state);
		}  else if(jiffies - lastEvent->time >= HZ) {
		sample:
			appendTricklesLossEvent(sk, MIN(tp->t.cont_list.len, EVENT_CWND_MAX),
						EVENT_EXTRA_SAMPLE0, tp->t.state);
			appendTricklesLossEvent(sk, MIN((cont+1)->mark, EVENT_CWND_MAX),
						EVENT_EXTRA_SAMPLE1, tp->t.state);
		}
	}
	PACKET_TRACE_LOG("a5 ");

	skb->csum = 0;
#ifndef SOFTWARE_CSUM
	skb->ip_summed = CHECKSUM_HW;
#else
	skb->ip_summed = 0;
#endif
	skb->sk = sk;
	tcp_header_size = sizeof(struct tcphdr) + TCPOLEN_TRICKLES;
	th = (struct tcphdr *) skb_push(skb, tcp_header_size);
	skb->h.th = th;
	th->source = sk->sport;
	th->dest = sk->dport;

	// Save minResponseLen in seqno for comparison at the server with the server side computation
	if(cont != NULL) {
#ifdef RECORD_UCONT_OFFSET
		th->seq = cont->ucont_offset;
#else
		th->seq = -2;
#endif
	} else {
		th->seq = -1;
	}

	// zero out flags and set tcp header size
	*(((__u16 *)th) + 6) = 0;

	th->doff = tcp_header_size >> 2;
	//th->ack = htonl(cont->seq);

	// TODO: Find uses for window, urg_ptr fields
	th->window = htons(windowValue);
	th->check = 0;
	th->urg_ptr = 0;
	*(__u32*)(th+1) = htonl((TCPOPT_TRICKLES << 24)  |
				(TCPOLEN_TRICKLES << 16) |
				0);
	th->ack = 1;
	th->syn = 0;
	th->fin = 0;
	th->rst = 0;

	th->seq = ENCODE_SIMULATION_RESULT(cont);
	th->ack_seq = packetID;
	packetID++;
	PACKET_TRACE_LOG("(send seq=%d len=%d) ", cont->seq, skb->len);

	recordSample(&ctx,0);

	SK_selectAndSend(sk, skb);

	printTimings(&ctx);
	return 1;
 out_free_error:
#if 0
	if(IS_RECOVERY_STATE()) printk(" out free error\n");
#endif
	__kfree_skb(skb);
	return 0;
 out_free_ignore_this_cont:
	//printk(" out free ignore this cont\n");
	__kfree_skb(skb);
	return 1;
}


struct SelectionContext {
	int minOffset;
	int position;
};

static void SelectionContext_init(struct SelectionContext *ctx, struct sock *sk) {
	struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;
	ctx->minOffset = -1;
	ctx->position = 0;

	int i;
	int currMin = INT_MAX;
	for(i=0; i < tp->t.numServers; i++) {
		struct trickles_server *server = &tp->t.servers[i];
		//printk("s[%d] = %d ", i, server->A);
		if(server->updateCount > 0) {
			currMin = min(server->A, currMin);
			if(currMin == server->A) {
				ctx->minOffset = i;
			}
		}
	}
	if(ctx->minOffset == -1) {
		printk("no match\n");
		ctx->minOffset = 0;
	}
	//printk("min is [%d] = %d\n", ctx->minOffset, currMin);
}

#define LAST_ADDRESS (-1)

static __u32 SK_selectAddress(struct sock *sk, struct SelectionContext *ctx) {
	struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;
	if(!SK_MULTIMODE(sk)) {
		if(ctx->position == 0) {
			printk("not in multimode\n");
			ctx->position++;
			return sk->daddr;
		} else {
			return LAST_ADDRESS;
		}
	}
	// There are multiple servers to choose from
	// XXX For now, do min with sample every probeRate jiffies
	while(1) {
		struct trickles_server *server = &tp->t.servers[ctx->position];
		if(ctx->position == ctx->minOffset) {
#if 0
			printk("sending actual to address [%d] => %X\n", 
			       ctx->position, server->address);
#endif
			static __u32 lastAddress;
			if(lastAddress != server->address) {
				gNumSwitches++;
				printk("%d: switched from %X to %X", 
				       jiffies, lastAddress, 
				       server->address);
				int i;
				for(i=0; i < tp->t.numServers; i++) {
					printk(" [%d,%d,%d]", tp->t.servers[i].A, tp->t.servers[i].D, tp->t.servers[i].updateCount);
				}
				printk("\n");
			}
			lastAddress = server->address;
			ctx->position++;
			return server->address;
		} else if(ctx->position >= tp->t.numServers) {
			ctx->position++;
			return LAST_ADDRESS;
		}
		// check for probe
		if(jiffies - server->lastProbeTime >= tp->t.probeRate) {
			server->lastProbeTime = jiffies;
			static int probeCount = 0;
			probeStat.address 	= server->address;
			probeStat.index 	= ctx->position;
#ifdef PRINT_PROBES_TX
			printk("[%d] probing to   [%d] => %X @ %d\n", probeCount++,
			       ctx->position, server->address, jiffies);
#endif
			ctx->position++;
			gNumProbes++;
			gProbeRate = tp->t.probeRate;
			return server->address;
		}
		ctx->position++;
	}
}

static void SK_selectAndSend(struct sock *sk, struct sk_buff *skb) {
	int res;
	struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;
	struct sk_buff *cskb;
	__u32 nextAddress;
	struct SelectionContext ctx;

	// XXX Ugly hack to switch between different destinations
	// daddr must be set before checksum
	SelectionContext_init(&ctx, sk);

	while((nextAddress = SK_selectAddress(sk, &ctx)) != LAST_ADDRESS) {
		sk->daddr = nextAddress;
		dst_release(sk->dst_cache);
		sk->dst_cache = NULL;

		cskb = skb_clone(skb, GFP_ATOMIC);
		if(cskb == NULL) {
			printk("out of memory in skb_clone\n");
			goto out_free;
		}
		cskb->sk = sk;
		dst_release(cskb->dst);
		cskb->dst = NULL;
		trickles_checksum(cskb, cskb->len);

		//printk("requestType=%d queuexmit\n", type);
		PACKET_TRACE_LOG("a6 ");

		// PACKET_SPACING_DIGEST('0');

		// XXX dest switching needs to invalidate the route
		if((res = tp->af_specific->queue_xmit(cskb, 0)) != 0) {
			if(trickles_ratelimit()) {
				printk("sendAckHelper wants to spill to overflow due to send failure (tx res = %d)\n", res);
#ifndef DISABLE_SENDACKOVERFLOW
				printk("However, it's disabled!!! All you need is an skb_copy() above in the queue_xmit, but I haven't tested it\n", res);
#endif
			}
#ifndef DISABLE_SENDACKOVERFLOW
			__skb_queue_tail(&tp->t.sendAckOverflow, cskb);
#endif
		} else {
			//LOG_PACKET_CONT(sk, -1, cont);
		}

	}
 out_free:
	kfree_skb(skb);

	// restore daddr for proper hash table lookup
	sk->daddr = TRICKLES_WILDADDR;
	// XXX End of ugly hack
}

/* Precondition: skb head must point at location to place request header */

#if 0
#define USERACK_BEAT(STR) if(NEED_USERACK(sk)) printk("USERACK:" STR);
#else
#define USERACK_BEAT(STR)
#endif

static void *CompleteRequestHeader_build(struct sk_buff *skb /* output */, 
		struct ConversionRequest *convReq, int isParallelMode, 
  		unsigned sendSeqNo) {
	struct WireUC_CVT_CompleteRequest *wConvReq;
	unsigned contLen;

	wConvReq = (struct WireUC_CVT_CompleteRequest*)
		skb_put(skb, sizeof(*wConvReq));
	if(convReq->completePred != NULL) {
		contLen = marshallUC_Continuation(&wConvReq->predCont,
						  convReq->completePred);
	} else {
		struct UC_Continuation scont = {
			.seq = -1,
			.validStart = -1,
			.validEnd = -1,
			.fields = 0,
			.dataLen = 0
		};
			
		contLen = marshallUC_Continuation(&wConvReq->predCont,
						  &scont);
	}

	skb_put(skb, contLen - sizeof(wConvReq->predCont));
	wConvReq->type = UC_COMPLETE;
	short outContLen = (char*)skb_put(skb, 0) - (char*)wConvReq;
	wConvReq->len = htons((short)outContLen);
	wConvReq->isParallel = isParallelMode;
	wConvReq->seq = htonl(sendSeqNo);

	return wConvReq;
}

static int CompleteRequestHeader_addData(struct sk_buff *skb /* output */, 
		void * reqStart,
		struct WireTrickleRequest *wreq,
		struct ConversionRequest *convReq,
		struct sk_buff *input_skb, 
		 int copyOffset, int maxCopyLen) {
	if(input_skb == NULL) {
		BUG();
	}

	short outContLen = (char*)skb_put(skb, 0) - (char*)reqStart;

	if(outContLen > TRICKLES_MSS) {
		printk("outContLen > TRICKLES_MSS\n");
		recordSample(&ctx,1);
		return OUT_FREE;
	}
	wreq->ucont_len = htons(outContLen);

	int copyLen = MIN(TRICKLES_MSS - outContLen, maxCopyLen);
	if(copyLen == 0) {
		BUG();
	}
	convReq->end = convReq->start + copyLen;

	/* Copy bytestream to request */
	BUG_TRAP(copyLen + outContLen <= TRICKLES_MSS);
	if(copyLen == 0) {
		printk("CopyLen == 0\n");
	}

	while(copyLen > 0) {
		unsigned pieceLen = MIN(input_skb->len - copyOffset, copyLen);
		memcpy(skb_put(skb, pieceLen), input_skb->data + copyOffset, pieceLen);
		copyOffset = 0;
		copyLen -= pieceLen;
		input_skb = input_skb->next;
	}
	gConversionCount++;
	return 0;
}

static inline
int generateRequestsFromPending(struct sock *sk, struct sk_buff *skb,
				 struct WireTrickleRequest *wreq,
				 CONTINUATION_TYPE *cont) {
#define ROLLBACK()  tp->t.request_snd_nxt--
	USERACK_BEAT("generateRequestsFromPending()\n");
	struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;
	recordSample(&ctx,2);
	/* Execute simulation to initialize
	   minResponseLen
	   firstTransportChild
	   numTransportChildren

	   MUST occur after skb is initialized with transport-level fields!
	*/
	if(!runSimulation(sk,cont,skb)) {
		printk("simulation failed\n");
		return OUT_FREE;
	}
	if(PACKET_RESPONSE_LEN(cont,0) < USEFULNESS_THRESHOLD) {
		BUG_TRAP(PACKET_RESPONSE_LEN(cont,0) == 0);
#if 0
		printk("Not useful at %d, %d %d\n", __LINE__,
		       PACKET_RESPONSE_LEN(cont,0), USEFULNESS_THRESHOLD);
#endif
		return OUT_FREE_IGNORE;
	}
	struct Request *mreq = (struct Request*)tp->t.queuedRequests.next;

	unlink((struct alloc_head*)mreq);
	insert_tail(&tp->t.sentRequests, (struct alloc_head *) mreq);
	mreq->transport_seq = cont->seq;
	if(mreq->isNew) {
		mreq->seq = tp->t.request_snd_nxt;
		tp->t.request_snd_nxt++; // sequence number is the identifier to match during scoreboard management
		mreq->isNew = 0;
	}
	// Now that we have UC sequence number, marshall continuation
	wreq->cont.parent = mreq->seq;

	/* All MTU handling is performed at this level */
	switch(mreq->type) {
	case MREQ_CONVERSION: {
		struct ConversionRequest *convReq =
			(struct ConversionRequest *) mreq;
		struct sk_buff *input_skb;
		unsigned outContLen, copyOffset;

	int isParallelMode = tp->trickles_opt & TCP_TRICKLES_PAR_REQUEST;
	if(isParallelMode) {
		void *reqStart = CompleteRequestHeader_build(skb, convReq, 1, convReq->parallelStart);
		int res;
		input_skb = convReq->data;
		// printk("sentConv %d ", mreq->seq);
		// request_dump((struct Request *)convReq);
		if(( res = CompleteRequestHeader_addData(skb, reqStart, 
				wreq, convReq, input_skb,
				0, input_skb->len)) != 0) {
			printk("received res = %d\n", res);
			ROLLBACK();
			return res;
		}
	} else {
		if(tp->t.snd_una <= convReq->start) {
			input_skb = convReq->data;
			copyOffset = convReq->offset;
			if(convReq->start != TCP_SKB_CB(input_skb)->seq + copyOffset) {
				BUG();
			}
		} else {
			if(tp->t.snd_una == tp->t.write_seq) {
				//printk("Conversion now obsolete\n");
				ROLLBACK();
				unlink((struct alloc_head*)convReq);
				return OUT_FREE;
			}
			// find input skb corresponding to current snd_una, and adjust convReq->input_skb accordingly
			input_skb = tp->t.requestBytes.next;
			while((struct sk_buff_head *)input_skb != &tp->t.requestBytes) {
				if(TCP_SKB_CB(input_skb)->seq <= tp->t.snd_una &&
				   tp->t.snd_una < TCP_SKB_CB(input_skb)->end_seq) {
					// printk("matched during update\n");
					break;
				}
				PACKET_TRACE_LOG("inputskb ");
				input_skb = input_skb->next;
			}
			if((struct sk_buff_head *)input_skb == &tp->t.requestBytes) {
				printk("screwed up during update\n");
				BUG();
			}
			convReq->data = input_skb;
			convReq->start = tp->t.snd_una;
			convReq->offset = copyOffset = convReq->start - TCP_SKB_CB(input_skb)->seq;
			// printk("2: start = %d, offset = %d\n", convReq->start, copyOffset);
			convReq->end = tp->t.write_seq;

			BUG_TRAP(convReq->offset >= 0);
			BUG_TRAP(convReq->end > convReq->start);
		}
		unsigned copySeq = TCP_SKB_CB(input_skb)->seq + copyOffset;
		void *reqStart;
		if(convReq->incomplete) {
			if(isParallelMode)
				BUG();
			printk("generating incomplete request\n");
			struct WireUC_CVT_IncompleteRequest *wInConvReq;
			unsigned contLen;

			/* get current position */
			wInConvReq = (struct WireUC_CVT_IncompleteRequest *)
				skb_put(skb, sizeof(*wInConvReq));
			contLen = convReq->predLength;
			skb_put(skb, contLen - sizeof(wInConvReq->predCont));
			memcpy(&wInConvReq->predCont, convReq->incompletePred, contLen);
			wInConvReq->type = UC_INCOMPLETE;
			outContLen = (char*)skb_put(skb, 0) - (char*)wInConvReq;
			wInConvReq->len = htons((short)outContLen);
			wInConvReq->seq = htonl(copySeq);
			reqStart = wInConvReq;
		} else {
			reqStart = CompleteRequestHeader_build(skb, convReq,
				       isParallelMode,copySeq);


#if 1
			static int dumpNext = 0;
			static int delta = 0;
			static void *lastPtr;
			if(gDumpConvCont || dumpNext) {
				printk("(%d) generating complete request from (%p) ", dumpNext, convReq->completePred); UC_Continuation_dump(convReq->completePred);
				if(tp->t.prevConvCont) { printk("prev is (%p) ", tp->t.prevConvCont); UC_Continuation_dump(tp->t.prevConvCont); };
				printk("last was %p, delta %d\n", lastPtr, delta);
				delta = 0;
				dumpNext = !dumpNext;
			} else {
				delta++;
				dumpNext = 0;
			}
			lastPtr = convReq->completePred;
#endif
		}
		int res;
		if((res = CompleteRequestHeader_addData(skb, reqStart, 
				wreq, convReq, input_skb,
				copyOffset,
				tp->t.write_seq - convReq->start)) != 0) {
			printk("res is %d, rolling back\n", res);
			ROLLBACK();
			return res;
		}
		/* Update snd_end to allow for progress check */
		tp->t.snd_end = convReq->end;
	}
		break;
	}
	case MREQ_CONTINUATION: {
		struct ContinuationRequest *updateReq = (struct ContinuationRequest *)mreq;
		struct WireUC_MGMT_UpdateRequest *wUpdateReq;
		int i;
		unsigned numContinuations = updateReq->numConts;
		unsigned totalLen = 0;

		wUpdateReq = (struct WireUC_MGMT_UpdateRequest*)skb_put(skb, sizeof(*wUpdateReq));
		wUpdateReq->newStart = htonl(updateReq->start);
		wUpdateReq->newEnd = htonl(updateReq->end);
		wUpdateReq->numContinuations = (__u8)numContinuations;
		for(i=0; i < numContinuations; i++) {
			// length
			__u16 *lenPtr = (__u16*)skb_put(skb, sizeof(__u16));
			unsigned contLen;
			contLen = marshallUC_Continuation((struct WireUC_Continuation*)skb_put(skb, 0), updateReq->conts[i]);
			skb_put(skb, contLen);
			*lenPtr = htons((short)contLen);
			totalLen += sizeof(__u16) + contLen;
		}
		BUG_TRAP(totalLen <= TRICKLES_MSS);
		wUpdateReq->type = UC_UPDATE;
		wUpdateReq->len = htons((short)(sizeof(*wUpdateReq) + totalLen));
		wreq->ucont_len = wUpdateReq->len;
		break;
	}
	default:
		printk("sendackhelper: Unknown request type!\n");
		recordSample(&ctx,1);
		ROLLBACK();
		return OUT_FREE;
	}
	mreq->transportResponseSeqStart = cont->firstTransportChild;
	mreq->transportResponseSeqEnd =
		mreq->transportResponseSeqStart + cont->numTransportChildren;

	recordSample(&ctx,2);
	return 0;
#undef ROLLBACK
}

/* Precondition: skb head must point at location to place request header */

static int sendOnlyOneRequest = 0;

static inline
void generateRequestsFromMissingDataMap(struct sock *sk, struct sk_buff *skb,
					unsigned tseq_start, unsigned tseq_end,
					struct UC_Continuation **pdreq_ucont,
					struct GenerateDataContext *gctx,
					int *numRequests);
static inline
void generateRequestsFromUnrequestedData(struct sock *sk, struct sk_buff *skb,
					unsigned tseq_start, unsigned tseq_end,
					struct UC_Continuation **pdreq_ucont,
					struct GenerateDataContext *gctx,
					int *numRequests);

static inline
int generateDataRequests(struct sock *sk, struct sk_buff *skb,
		 struct WireTrickleRequest *wreq,
		 CONTINUATION_TYPE *cont) {
	gGenDataRequestCount++;
	USERACK_BEAT("generateDataRequests()\n");
	struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;

	struct WireUC_DataRequest *wDataReq = (struct WireUC_DataRequest *)
		skb_put(skb, sizeof(struct WireUC_DataRequest));
	unsigned outContLen;
	void *ptr;

	/* Execute simulation to initialize
	   minResponseLen
	   firstTransportChild
	   numTransportChildren

	   MUST occur after skb is initialized with transport-level fields!

	   xxx There should not be any simulation
	   dependencies on the header fields that are
	   initialized after start of simulation
	*/
	if(!runSimulation(sk,cont,skb)) {
		printk("Simulation error\n");
		return OUT_FREE;
	}
	if(SIMULATION_NUM_PACKETS(cont) == 0) {
#if 0
		if(IS_RECOVERY_STATE()) {
			printk("no children\n");
		}
#endif
		return OUT_FREE_IGNORE;
	}
	// printk("%d packets: ", SIMULATION_NUM_PACKETS(cont));

	unsigned tseq_start = cont->firstTransportChild,
		tseq_end = tseq_start + cont->numTransportChildren;
	BUG_TRAP(tseq_start != -1 && tseq_end != -1);

	// update parent with latest sequence number
	wreq->cont.parent = DATA_ONLY_REQNUM;
	wDataReq->type = UC_DATA;
	wDataReq->len = -1;

	int numRequests = 0;
	// First generate requests for data that was already requested, but lost
	struct UC_Continuation *dreq_ucont = NULL;
	//printk("premissing\n");
	struct GenerateDataContext gctx;
	GenerateDataContext_init(&gctx, (void*)0xFFF00000, SIMULATION_PACKETS(cont),
				 SIMULATION_NUM_PACKETS(cont));
	generateRequestsFromMissingDataMap(sk, skb, tseq_start, tseq_end,
					&dreq_ucont, &gctx, &numRequests);
	GenerateDataContext_sanityCheck(&gctx);

	static int missingCount = 0;
	if(numRequests > 0) {
		//printk("0: request used %d, %d left\n", cont->minResponseLen - maxResponseLen, maxResponseLen);
		missingCount++;
		if(0 && trickles_ratelimit()) {
			printk("MissingCount = %d\n", missingCount);
		}
	}
	int numMissingRequests = numRequests;
	if(numRequests ==  0 || !sendOnlyOneRequest) {
		int origNumRequests = numRequests;
		generateRequestsFromUnrequestedData(sk, skb, tseq_start, tseq_end,
						    &dreq_ucont, &gctx, &numRequests);
		if(origNumRequests < SIMULATION_NUM_PACKETS(cont) &&
		   numRequests == origNumRequests) {
			LOG_PACKET_USERBLOCKEVENT(cont);
			tp->t.timerState |= TRICKLES_NEED_USERACK;
		}
	}
	numMissingRequests = -1;

	BUG_TRAP(numRequests <= MAX_NUM_DATACHUNKS);

	wDataReq->numRequestRanges = numRequests;
	//printk("Sending %d requests\n", numRequests);
	short wDataReqLen =
		WIREUC_DATAREQUEST_SIZE(wDataReq->numRequestRanges);
	wDataReq->len = htons(wDataReqLen);

#ifdef PRINT_CLIENT_ZEROCOUNT
	if(wDataReq->numRequestRanges) {
		static int zeroCount = 0;
		zeroCount++;
		if(trickles_ratelimit()) {
			printk("client ZeroCount (requestRanges) %d\n", zeroCount);
		}
	}
#endif

	if(dreq_ucont != NULL) {
		BUG_TRAP(numRequests > 0);
		outContLen = wDataReqLen +
			marshallUC_Continuation((struct WireUC_Continuation *)skb_put(skb,0), dreq_ucont);
		ptr = skb_put(skb, outContLen);
		wreq->ucont_len = htons(outContLen);
		BUG_TRAP(dreq_ucont->validStart <= dreq_ucont->validEnd);

		if(1) {
			struct WireUC_Continuation *wucont = (struct WireUC_Continuation*) ptr;
			BUG_TRAP(ntohl(wucont->validStart) <= ntohl(wucont->validEnd));

#ifdef RECORD_UCONT_OFFSET
			cont->ucont_offset = (char*)ptr - (char*)wreq;
#endif
			//printk("ucont offset = %d\n", cont->ucont_offset);
		}
	} else {
		//printk("no data request\n");
#if 0
		if(IS_RECOVERY_STATE()) {
			printk("no recovery data request -- ucontlist len = %d, num response packets = %d\n", tp->t.ucontList.len, SIMULATION_NUM_PACKETS(cont));
		}
#endif
		BUG_TRAP(numRequests == 0);
		return OUT_NODATAREQUEST;
	}

	recordSample(&ctx,3);
	recordSample(&ctx,4);

	return 0;
 }

static inline
int addDataRequestHelper(struct sock *sk, struct sk_buff *skb,
		   unsigned tseq_start,
			 struct DataRequestMapping *dataReqMap,
			 struct alloc_head *prev, struct alloc_head *next) {
	struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;
	 struct DataRequestMapping *finger;
	 finger = (struct DataRequestMapping*)tp->t.dataRequestMap.prev;

	 insert((struct alloc_head*)dataReqMap, prev, next);

	 dataReqMap->sent = 1;
	 BUG_TRAP(dataReqMap->start < dataReqMap->end);

	 //printk("Added data request [%d-%d]\n", dataReqMap->start, dataReqMap->end);
	 if(finger != (struct DataRequestMapping *)&tp->t.dataRequestMap) {
		 if(finger->transportResponseSeqEnd > tseq_start) {
			 if(!disableSevereErrors) {
				 printk("WARNING: Out of order continuation transportResponseSeqEnd received (%u %u). Either server or client is buggy\n", finger->transportResponseSeqEnd, tseq_start);
			 }
		 }
	 }
	 if(!skb_can_put(skb, sizeof(struct WireUC_DataRequestRange))) {
		 printk("Cannot add new data request range\n");
		 return -1;
	 }
	 struct WireUC_DataRequestRange *range = (struct WireUC_DataRequestRange *)
		 skb_put(skb, sizeof(struct WireUC_DataRequestRange));
	 range->start = htonl(dataReqMap->start);
	 range->end = htonl(dataReqMap->end);

	 //printk("Added request %d-%d\n", dataReqMap->start, dataReqMap->end);
	 gPacketAddedRequest++;
	 int currentRequestLen = dataReqMap->end - dataReqMap->start;
	 if(currentRequestLen < 300) {
		 gSmallRequestPackets++;
	 } else if(currentRequestLen < 800) {
		 gMediumRequestPackets++;
	 } else if(currentRequestLen < 1500) {
		 gLargeRequestPackets++;
	 } else if(currentRequestLen < 2500) {
		 gLargerRequestPackets++;
	 } else {
		 gLargestRequestPackets++;
	 }

	 return 0;
 }

static inline 
int addDataRequestFront(struct sock *sk, struct sk_buff *skb,
		 unsigned tseq_start, struct DataRequestMapping *dataReqMap) {
	struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;
	return addDataRequestHelper(sk,skb,tseq_start, dataReqMap, 
	    (struct alloc_head*)&tp->t.dataRequestMap, tp->t.dataRequestMap.next);
}

static inline 
int addDataRequestBack(struct sock *sk, struct sk_buff *skb,
		 unsigned tseq_start, struct DataRequestMapping *dataReqMap) {
	struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;
	return addDataRequestHelper(sk,skb,tseq_start, dataReqMap, 
	    tp->t.dataRequestMap.prev, (struct alloc_head*)&tp->t.dataRequestMap);
}

// Returns the number of generated requests

#define CAN_SEND_MORE_REQUESTS(CURR_REQNUM)			\
	((CURR_REQNUM) < MAX_NUM_DATACHUNKS)

#define CHECK_FOR_DIFFERENT_CONTINUATION(UCONT)		\
	(*pdreq_ucont != NULL && *pdreq_ucont != ucont)

static int 
GenerateDataContext_maxAdjustedLen(struct GenerateDataContext *gctx, int adj) {
	int overflow = 0, maxLen = -1;
	while(1) {
		int rval = GenerateDataContext_simulateRequest(gctx);
		if(rval < 0) {
			overflow = 1;
			break;
		}
		maxLen = rval - adj;
		if(maxLen < 0 && maxLen > -adj) {
			// not enough space for the adjustment
			GenerateDataContext_put(gctx, maxLen + adj);
		} else if(rval == 0) {
			// at the end of current packet, try again
			BUG_TRAP(maxLen == -adj);
		} else {
			BUG_TRAP(maxLen > 0);
			break;
		}
	}
	if(overflow) {
		maxLen = 0;
	}
	return maxLen;
}

static inline
void generateRequestsFromMissingDataMap(struct sock *sk, struct sk_buff *skb,
				unsigned tseq_start, unsigned tseq_end,
				struct UC_Continuation **pdreq_ucont,
				struct GenerateDataContext *gctx,
				int *numRequests) {
	USERACK_BEAT("generateRequestsFromMissingDataMap()\n");
	int origNumRequests = *numRequests;
	struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;
	BUG_TRAP(*numRequests < MAX_NUM_DATACHUNKS);
	int totalRequestLen = 0;

#if 0
	if(IS_RECOVERY_STATE()) {
		printk("recovery missing data map top\n");
	}
#endif
	while(CAN_SEND_MORE_REQUESTS(*numRequests)  &&
	      !empty(&tp->t.missingDataMap)) {
#if 0
		if(IS_RECOVERY_STATE()) {
			printk("recovery missing data map inside top\n");
		}
#endif
		// simulate server-side response to this request
		int maxLen = GenerateDataContext_maxAdjustedLen(gctx, FIN_HINT_SIZE);
		// printk("mlen=%d ", maxLen);
		if(maxLen <= 0) {
#if 0
			printk("missingdatamap: no more space for data chunks at ");
			GenerateDataContext_dump(gctx);
#endif
			if(maxLen < 0) {
				printk("maxlen(0) is %d %d\n", maxLen, FIN_HINT_SIZE);
				BUG();
			}
			break;
		}
		// printk("missingDataMap maxLen = %d ", maxLen);

		recordSample(&ctx,3);
		BUG_TRAP(enableDataRecovery);

		struct DataRequestMapping *dataReqMap = (struct DataRequestMapping*)
			tp->t.missingDataMap.prev;
		DataRequestMapping_hintFixup(dataReqMap);
		struct UC_Continuation *ucont = dataReqMap->ucont;

		if(!(dataReqMap->start < dataReqMap->end)) {
			unlink((struct alloc_head*) dataReqMap);
			freeDataRequestMapping(dataReqMap);
			continue;
		}

		
		int oldStart = dataReqMap->start;
		dataReqMap->start = MIN(MAX(dataReqMap->start, tp->t.byteRcvNxt), dataReqMap->end);
		if(oldStart != dataReqMap->start) {
			if(0 && trickles_ratelimit()) {
				printk("OldStart %d NewStart %d End %d\n",
				       oldStart, dataReqMap->start, dataReqMap->end);
			}
		}
		
		struct Range preDifference = { dataReqMap->start, dataReqMap->end, 1 },
			first;
		SK_data_ofo_queue_difference(&preDifference, sk, &first);
		dataReqMap->start = first.start;
		dataReqMap->end = first.end;

		if(CHECK_FOR_DIFFERENT_CONTINUATION(ucont)) {
#if 0
			printk("GenerateRequests from missing data map: Different data request continuation needed than the one passed in\n");
			printk("This happens when a continuation is used for an earlier data generation, but that continuation is not valid with this request range\n");
#endif
			gNeedDifferentContinuationCount ++;
			goto out;
		}
		if(ucont == NULL) {
			printk("Setting pdreq_ucont to NULL\n");
		}
		*pdreq_ucont = ucont;

		// insert any remainder from the first part
		if(dataReqMap->end - dataReqMap->start > maxLen) {
			unsigned newStart = dataReqMap->start + maxLen;
			struct DataRequestMapping *rest =
				newDataRequestMapping(ucont, -1, -1, newStart, dataReqMap->end);
			if(rest == NULL) {
				printk("out of memory while splitting missing data mapping\n");
				recordSample(&ctx,1);
				goto out;
			}
			dataReqMap->end = newStart;
			RECORD_MISSINGDATAMAP_INSERTION(rest);
			insert_tail(&tp->t.missingDataMap,
				    (struct alloc_head*)rest);
		}
		// insert remainder from rest, if extant
		if(dataReqMap->end < preDifference.end) {
			struct DataRequestMapping *remainder =
				newDataRequestMapping(ucont, -1, -1,dataReqMap->end, preDifference.end);
			RECORD_MISSINGDATAMAP_INSERTION(remainder);
#if 0
			printk("inserting rest remainder %d-%d\n", 
			       remainder->start, remainder->end);
			printk(" was "); Range_dump(&preDifference);
			printk("; %d-%d\n", dataReqMap->start, dataReqMap->end);
#endif
			insert_tail(&tp->t.missingDataMap, 
				    (struct alloc_head*) remainder);
		}

		int actualLen = dataReqMap->end - dataReqMap->start;
		if(!(actualLen <= maxLen)) {
			BUG_TRAP(actualLen <= maxLen);
		}

		unlink((struct alloc_head*)dataReqMap);
		if(actualLen == 0) {
			// this mapping is now useless
			freeDataRequestMapping(dataReqMap);
			continue;
		}

		//TRACE_K_PACKETS_ONCE(5);
		PACKET_TRACE_LOG("\nnew data req map %d-%d", 
				 dataReqMap->start, dataReqMap->end);
		PACKET_TRACE_LOG(";;");
		PACKET_TRACE_LOG_DO(SK_data_ofo_queue_dump(sk));
		PACKET_TRACE_LOG(";;");
		
		dataReqMap->transportResponseSeqStart = tseq_start;
		dataReqMap->transportResponseSeqEnd = tseq_end;
		recordSample(&ctx,3);
		//printk("missing dataRequest = [%d,%d]\n", dataReqMap->start, dataReqMap->end);
		if(addDataRequestFront(sk, skb, tseq_start, dataReqMap)) {
			printk("generateRequestsFromMissingDataMap: no more space in request for more data\n");
			goto out;
		}

		//printk("actualLen = %d\n", actualLen);
		void *check = GenerateDataContext_put(gctx, actualLen + FIN_HINT_SIZE);
		if(check == NULL) BUG();

		totalRequestLen += dataReqMap->end - dataReqMap->start;

		(*numRequests)++;
		if(sendOnlyOneRequest) {
			break;
		}
	}

	if(0 && *numRequests == origNumRequests) {
		printk("Missing data: No requests generated %d %d\n",
		       CAN_SEND_MORE_REQUESTS(*numRequests),
		       !empty(&tp->t.missingDataMap));
	}
 out:
	if(*numRequests == origNumRequests) {
		*pdreq_ucont = NULL;
	}
	PACKET_TRACE_LOG("missingReqLen = %d ; ", totalRequestLen);
}


// Returns the number of generated requests

static inline
void generateRequestsFromUnrequestedData(struct sock *sk, struct sk_buff *skb,
				unsigned tseq_start, unsigned tseq_end,
				struct UC_Continuation **pdreq_ucont,
				struct GenerateDataContext *gctx,
				int *numRequests) {
	gGenerateRequestsFromUnrequested++;
	USERACK_BEAT("generateRequestsFromUnrequestedData()\n");
	enum BreakReason {
		NONE,
		NO_MORE_SPACE,
		SEND_ONLY_ONE
	} reason = NONE;
	int origNumRequests = *numRequests;
	int loopTopCount = 0, loopBottomCount = 0;
	struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;
	int first = 1;
	int totalRequestLen = 0;

	 recordSample(&ctx,4);
#if 0
	if(IS_RECOVERY_STATE()) {
		printk("recovery unrequested top\n");
	}
#endif

	// We want to avoid sending short requests that don't use up
	// all available packets. So, only perform the in_window check
	// once
	 while(CAN_SEND_MORE_REQUESTS(*numRequests) &&
	       (!first || BYTEREQ_IN_WINDOW(sk))) {
		 first = 0;
#if 0
		if(IS_RECOVERY_STATE()) {
			printk("recovery unrequested data map inside top\n");
		}
#endif
		 loopTopCount++;
		 int maxLen = GenerateDataContext_maxAdjustedLen(gctx, FIN_HINT_SIZE);
		 // printk("mlen=%d ", maxLen);
		if(maxLen <= 0) {
#if 0
			printk("unrequestedData: no more space for data chunks at ");
			GenerateDataContext_dump(gctx);
#endif
			// GenerateDataContext_dump(gctx);
			if(maxLen < 0) {
				printk("maxlen(1) is %d %d\n", maxLen, FIN_HINT_SIZE);
				BUG();
			}
			reason = NO_MORE_SPACE;
			break;
		}
		//printk("UnrequestedData maxLen = %d ", maxLen);

		 struct sk_buff *finger;
		 unsigned start, end;
		 unsigned gapLen = 0;
		 // XXX: needs more performance tuning, e.g. hint pointing at next element to process

		 if(tp->t.byteReqHint) {
			 finger = tp->t.byteReqHint;
		 } else {
			 finger = tp->t.data_ofo_queue.next;
		 }
		 // SACK: Find a gap to fill in
		 while(finger != (struct sk_buff*)&tp->t.data_ofo_queue) {
			 if(SKB_CONTAINS(finger, tp->t.byteReqNext)) {
				 tp->t.byteReqNext = TCP_SKB_CB(finger)->end_seq;
				 if(finger->next != (struct sk_buff*)&tp->t.data_ofo_queue) {
					 gapLen = TCP_SKB_CB(finger->next)->seq - tp->t.byteReqNext;
				 }
			 } else if(TCP_SKB_CB(finger)->seq > tp->t.byteReqNext) {
				 break;
			 }
			 finger = finger->next;
		 }
		 if(gapLen == 0) {
			 gapLen = maxLen;
		 }
		 if(finger != (struct sk_buff *)&tp->t.data_ofo_queue) {
			 tp->t.byteReqHint = finger;
		 } else {
			 tp->t.byteReqHint = NULL;
		 }

		 int inSkippedRegion = 1;
		 struct UC_Continuation *ucont = NULL;
		 while(1) {
			 // Find the first real gap (e.g., not in a skipped part of a continuation
			 start = tp->t.byteReqNext;
			 ucont = findUCContinuation(sk, start, start + gapLen);
			 if(ucont == NULL || 
			    !(inSkippedRegion = UC_Continuation_inSkippedRegion(ucont, start))) {
				 // SK_ucontList_dump(sk);
				 break;
			 }
			 // skipped
#if 0
			 printk("skipped from %d to %d\n", tp->t.byteReqNext, 
				ucont->validEnd);
#endif
			 unsigned skipAmount = ucont->validEnd - tp->t.byteReqNext;
			 tp->t.byteReqNext = ucont->validEnd;
			 tp->t.byteSkipHintAmount += skipAmount;
			 if(tp->t.byteSkipHintAmount < 0) {
				 printk("byteskiphintamount is now %d, changed by %d\n", tp->t.byteReqNext, skipAmount);
			 }
			 // XXX this is not the best way of assigning the gap length
			 gapLen = maxLen;
		 }
		 if(ucont != NULL && inSkippedRegion) {
			 printk("found continuation is in the skipped region\n");
			 BUG();
		 }

		 // XXX XXX XXX
		 // Logic is not 100% kosher. State mutation occurs before checking that request can actually be sent
		 if(ucont == NULL) {
#if 0
			 static unsigned last;
			 if(last != start) {
				 printk("could not find ucont (%d,%d)\n", start, start + gapLen);
				 SK_ucontList_dump(sk);
			 }
			 last = start;
#endif
			 recordSample(&ctx,1);
			 goto error;
		 }

		 // Place this check before ALL state mutation
		if(CHECK_FOR_DIFFERENT_CONTINUATION(ucont)) {
#if 0
			printk("GenerateRequests from missing data map: Different data request continuation needed than the one passed in\n");
			printk("This happens when a continuation is used for an earlier data generation, but that continuation is not valid with this request range\n");
#endif
			gNeedDifferentContinuationCount ++;
			PACKET_TRACE_LOG("unreqLen(0) = %d ; ", totalRequestLen);
			return;
		}
		if(ucont == NULL) {
			printk("Setting pdreq_ucont to NULL\n");
		}
		*pdreq_ucont = ucont;

		int tryRequestLen = MIN(gapLen, maxLen);
		tp->t.byteReqNext = end =
			MIN(start + tryRequestLen, UC_Continuation_virtualEnd(ucont));
		 int actualLen = end - start;

		 tp->t.byteReqHint = NULL;
		 struct DataRequestMapping *dataReqMap =
			 newDataRequestMapping(ucont, tseq_start, tseq_end, start, end);
		 totalRequestLen += end - start;
		 if(dataReqMap == NULL) {
			 printk("Out of memory while allocating new data request mapping\n");
			 recordSample(&ctx,1);
			 goto error;
		 }
		 static int count = 0;
		 if(0 && count++ % 300 == 0) {
			 printk("adding %u-%u\n", dataReqMap->start, dataReqMap->end);
		 }
		 if(addDataRequestBack(sk, skb, tseq_start, dataReqMap)) {
			printk("generateRequestsFromUnrequestedData: no more space in request for more data\n");
		 }
		 BUG_TRAP(actualLen <= maxLen);

		 //printk("actualLen = %d\n", actualLen);
		void *check = GenerateDataContext_put(gctx, actualLen + FIN_HINT_SIZE);
		if(check == NULL) BUG();
		 (*numRequests)++;

		if(sendOnlyOneRequest) {
			reason = SEND_ONLY_ONE;
			break;
		}
		 loopBottomCount++;
	 }
	 if(loopTopCount == 0 || loopBottomCount == 0) {
		 gZeroLoopCount++;
	 }
	 if(*numRequests == origNumRequests) {
		 int canSendMore = CAN_SEND_MORE_REQUESTS(*numRequests);
		 int inWindow = BYTEREQ_IN_WINDOW(sk);
		 static int canSendMoreCount = 0;
		 static int noMoreSpaceCount = 0;
		 static int outOfWindowCount = 0;
		 if(canSendMore) {
			 canSendMoreCount++;
		 }
		 if(!inWindow) {
			 outOfWindowCount++;
		 }
		 if(reason == NO_MORE_SPACE) {
			 noMoreSpaceCount++;
		 }

		 if( (0 && NEED_USERACK(sk)) ||
		    (0 && reason != NO_MORE_SPACE && trickles_ratelimit())) {
			 printk("OrigData: No requests generated %d %d reason = %d top = %d bottom = %d canSendMoreCount = %d noMoreSpaceCount = %d canSendMoreCount - noMoreSpaceCount = %d outOfWindow = %d\n",
				canSendMore,
				inWindow,
				reason, loopTopCount, loopBottomCount,
				canSendMoreCount,
				noMoreSpaceCount,
				canSendMoreCount - noMoreSpaceCount,
				outOfWindowCount);
		 }
	 }
	 recordSample(&ctx,4);
	 if(reason == NO_MORE_SPACE) {
		 PACKET_TRACE_LOG_DO(GenerateDataContext_dump(gctx));
	 }
	 PACKET_TRACE_LOG("unreqLen(1) = %d ; %d/%d ; bytereq=%d ; moreReq=%d ; reason = %d ", 
			  totalRequestLen, *numRequests, origNumRequests,
			  BYTEREQ_IN_WINDOW(sk),
			  CAN_SEND_MORE_REQUESTS(*numRequests),
			  reason);
	 return;
 error:
	 PACKET_TRACE_LOG("unreqLen(2) = %d ; ", totalRequestLen);
	 USERACK_BEAT("unrequested data error\n");
	 ;
}

#if 0 // 0426 removed static to allow call from gdb
static
#endif
void ContList_dump(struct sock *sk) {
	struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;
	CONTINUATION_TYPE *msk = (CONTINUATION_TYPE *)tp->t.cont_list.next;
	printk("  ContList: ");

#if 0 // 0426 more extensive dump
	if(msk != (CONTINUATION_TYPE*)&tp->t.cont_list) {
		printk("%d-%d", ((CONTINUATION_TYPE *)tp->t.cont_list.next)->seq,
		       ((CONTINUATION_TYPE *)tp->t.cont_list.prev)->seq);
	}
#else
	alloc_head_walk(&tp->t.cont_list, msk) {
		printk("%d, ", msk->seq);
	}
#endif
	printk("\n");
}

static void requestSlowStart(struct sock *sk) {
	struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;
	printk("slowstart rcv_nxt = %d, cont_list.len = %d, ", tp->t.rcv_nxt, tp->t.cont_list.len); SK_dump_vars(sk);

	CONTINUATION_TYPE *msk = NULL, *curr_cont, *clean;
	struct sk_buff *skb;
	struct Request *mreq, *prev;
	struct DataRequestMapping *dataReq, *nextDataReq;
	__u32 left, right, lastRcv = tp->t.rcv_nxt - 1;
	int leftViolation = 0, rightViolation = 0;

	tp->t.timerState &= ~TRICKLES_NEED_SLOWSTART;
	if(clientDebugLevel >= 1) {
		printk("  client: slow start acking %u, tp->rcv_nxt = %u, tp->t.byteRcvNxt = %u, tp->copied_seq = %u\n", tp->t.rcv_nxt - 1, tp->rcv_nxt, tp->t.byteRcvNxt, tp->copied_seq);
		printk("Slow start dump\n");
	}
	right = AckProof_findRight(&tp->t.altProof, lastRcv);
	left = AckProof_findLeft(&tp->t.altProof, lastRcv);
	if(right != lastRcv) {
#if 0
		BUG_TRAP(right != tp->t.rcv_nxt - 1);
		printk("right (%u) != tp->t.rcv_nxt - 1 (%u)\n", right, tp->t.rcv_nxt - 1);
		AckProof_dump(&tp->t.altProof;
#endif
	}
	if(right >= lastRcv) {
		if(clientDebugLevel >= 2) {
			printk("right >= lastRcv ");
			AckProof_dump(&tp->t.altProof);
		}
	}
	alloc_head_reverse_walk(&tp->t.cont_list, curr_cont) {
		if(left <= curr_cont->TCPBase && curr_cont->TCPBase <= right) {
			msk = curr_cont;
			break;
			//BUG_TRAP();
		}
		if(left > curr_cont->TCPBase) leftViolation++;
		if(right < curr_cont->TCPBase) rightViolation++;
		if(curr_cont->TCPBase > tp->t.previous_base) {
			if(clientDebugLevel >= 2) {
				printk("requestslowstart tcpbase > previousbase\n");
			}
		}
	}

	if(msk == NULL) {
		if(0 || !disableSevereErrors)
			if(trickles_ratelimit())
				printk("%p: Could not find acceptable msk in requestSlowStart, contlist len = %d, left violations %d, right violations %d\n", sk, tp->t.cont_list.len, leftViolation, rightViolation);
		return;
	}
	if(clientDebugLevel >= 1)
	  printk("using cont %u, base = %u, left = %u right = %u\n", msk->seq, msk->TCPBase, left, right);
	BUG_TRAP(msk != (CONTINUATION_TYPE*)&tp->t.cont_list);
	skb = tp->t.ofo_queue.next;

	/* Clean up state to avoid interference from other packets */
	while(skb != (struct sk_buff*)&tp->t.ofo_queue) {
		struct sk_buff *prev = skb;
		skb = skb->next;
		__skb_unlink(prev, &tp->t.ofo_queue);

#if 1
		TCP_SKB_CB(skb)->dbg = __LINE__;
		if(try_queue_data(sk, prev) >= 0) {
			//printk("timeout: try queue data returned success (well, maybe it didn't actually stick in useful data\n");
		} else {
			//printk("timeout: try queue data returned failure\n");
		}
#else
		printk(" Timeout: I want to change this code to enqueue as much data as possible\n");
#endif

		delOfoSkb(prev);
		BUG_TRAP(TCP_SKB_CB(prev)->cont->list == NULL); // 0430 tracking down corruption bug
		MARK_PC(TCP_SKB_CB(prev)->cont);
		trickles_kfree_skb(prev);
	}
	clean = (CONTINUATION_TYPE*)tp->t.cont_list.next;
	while(clean != (CONTINUATION_TYPE*)&tp->t.cont_list) {
		CONTINUATION_TYPE *prev = clean;
		clean = clean->next;
		// 0424: clean out all continuations other than the one we are using for slowstart
		if(prev != msk) {
			unlinkCont(prev);
			MARK_PC(prev);
			freeClientSide_Continuation(prev);
		}
	}

	/* Retransmit all UC requests:
	   move sentRequests back to queuedRequests
	*/
	for(mreq = (struct Request*)tp->t.sentRequests.prev;
	    mreq != (struct Request*)&tp->t.sentRequests;
	    mreq = (struct Request*)prev) {
		prev = (struct Request*)mreq->prev;

		/* note: can't just splice the ends, since each list
		   node contains a pointer to the containing list */
		// Shift to front of queuedRequests, in order
		BUG_TRAP(!mreq->isNew);
		unlink((struct alloc_head*)mreq);
		resetRequest(mreq);
		CHECK_IF_ZEROREQUEST(mreq);
		// printk("retransmit %d\n", tp->t.request_rcv_nxt);
		insert_head(&tp->t.queuedRequests, (struct alloc_head*)mreq);
	}
	/* clear data requests */
	{
		int i;
		struct alloc_head_list* dataRequestLists[] = {
			&tp->t.dataRequestMap,
			&tp->t.missingDataMap};
		for(i=0; i < 2; i++) {
			struct alloc_head_list *currList = dataRequestLists[i];
			for(dataReq = (struct DataRequestMapping *)currList->next;
			    dataReq != (struct DataRequestMapping *)currList;
			    dataReq = nextDataReq) {
				nextDataReq = dataReq->next;
				unlink((struct alloc_head*)dataReq);
				freeDataRequestMapping(dataReq);
			}
		}

		tp->t.byteReqNext = tp->t.byteRcvNxt;
		tp->t.byteSkipHintAmount = 0;
		tp->t.byteReqHint = NULL;
	}

	tp->t.ack_prev = msk;
	INTEGRITY_CHECK(sk, tp->t.ack_prev);

	SAVE_ACK_PREV(tp);
	tp->t.ack_last = tp->t.ack_prev->seq + 1;
	if(!(!tp->t.ack_prev || tp->t.ack_prev->next)) {
		// 0429
		BUG_TRAP(!tp->t.ack_prev || tp->t.ack_prev->next);
		BUG();
	}

	// free sendAckOverflow list
	while((skb = __skb_dequeue(&tp->t.sendAckOverflow))) {
		__kfree_skb(skb);
	}
#if 0
	// recorded in SendAckHelper()
	appendTricklesLossEvent(sk, MIN(tp->t.ack_prev->startCwnd, EVENT_CWND_MAX),
				-3, tp->t.state);
#endif
	//printk("requestSlowStart -- calling sendAck\n");
	sendAckHelper(sk,tp->t.ack_prev,TREQ_SLOWSTART);
}


#ifndef USERTEST
/*
 *
 * Destructors
 *
 *
 */
static void trickles_clear_timers(struct sock *sk) {
	struct tcp_opt *tp = &(sk->tp_pinfo.af_tcp);
	if(timer_pending(&tp->t.slowstart_timer)) {
		static int numCleared = 0;
		if(del_timer(&tp->t.slowstart_timer)) {
			__sock_put(sk);
		}
		numCleared++;
		//printk("%d timers cleared\n", numCleared);
	}
	return;
}

#endif //USERTEST

static void trickles_destroy(struct sock *sk) {
	int i;
	struct sk_buff *skb;
	CONTINUATION_TYPE *cont;
	struct UC_Continuation *ucont;
	struct UC_DependencyNode *depNode;
	struct Request *req;
	struct tcp_opt *tp = &(sk->tp_pinfo.af_tcp);
	struct alloc_head_list *lists[] = {&tp->t.sentRequests, &tp->t.queuedRequests};
	struct alloc_head_list *dataRequestLists[] = {&tp->t.dataRequestMap, &tp->t.missingDataMap};

	StateCache_invalidate();

#ifdef SAVE_LAST_DATA_TIME
        struct timeval t1;
        do_gettimeofday(&t1);
        printk("last data at (%d,%d) %d = (%d,%d)\n", last_data_time.tv_sec,
               last_data_time.tv_usec, jiffies, t1.tv_sec, t1.tv_usec);
#endif // SAVE_LAST_DATA_TIME

	//printk("destroy() on entry\n");
#ifndef USERTEST
	if(!(tp->trickles_opt & TCP_TRICKLES_ENABLE)) {
		return;
	}

	//KGDB_ASSERT("BREAK", 0);
	/* Schedule vfree() for later */
	if(TRICKLES_USERAPI_CONFIGURED_TP(tp)) {
		schedule_work((struct work_struct *)(tp->cminisock_api_config.cfg.ctl + 1));
	}

	trickles_clear_timers(sk);
#endif //USERTEST

	//printk("destroy() before ofo_queue\n");
	/* drain ofo queues */
	while((skb=__skb_dequeue(&tp->t.ofo_queue))!=NULL) {
		if(TCP_SKB_CB(skb)->cont)
			MARK_PC(TCP_SKB_CB(skb)->cont);
		delOfoSkb(skb);
		trickles_kfree_skb(skb);
	}
	//printk("destroy() before freeing request_ofo_queue\n");
	while(!empty(&tp->t.request_ofo_queue)) {
		struct RequestOFOEntry *entry = (struct RequestOFOEntry*)
			tp->t.request_ofo_queue.next;
		BUG_TRAP(entry != (struct RequestOFOEntry *)&tp->t.request_ofo_queue);
		unlink((struct alloc_head*)entry);
		RequestOFOEntry_free(entry);
	}
	//printk("destroy() after freeing request_ofo_queue\n");
	while((skb=__skb_dequeue(&tp->t.data_ofo_queue))!=NULL) {
		// data ofo queue continuations were already deallocated
		// 0418 check skb reference count
#ifndef USERTEST
		if(atomic_read(&skb_shinfo(skb)->dataref) > 2) {
			printk("skb on data_ofo_queue had refcnt > 2\n");
			// xxx are there skb references other than this queue?
#if 0
			while(atomic_read(&skb_shinfo(skb)->dataref) >= 2) {
				trickles_kfree_skb(skb);
			}
#endif
		}
#endif // USERTEST
		trickles_kfree_skb(skb);
	}
	//printk("destroy() after data ofo queue\n");

	// Drain overflow queues
	while((skb=__skb_dequeue(&tp->t.prequeueOverflow))) {
		__kfree_skb(skb);
	}
	//printk("destroy() after overflow queue\n");
	while((skb=__skb_dequeue(&tp->t.sendAckOverflow))) {
		__kfree_skb(skb);
	}
	//printk("destroy() after sendack overvlow\n");
	while((skb=__skb_dequeue(&tp->t.recycleList))) {
		__kfree_skb(skb);
	}
	//printk("destroy() after recycle list\n");

	/* Clean protocol continuation list */
	cont = (CONTINUATION_TYPE *)tp->t.cont_list.next;
#if 0 // 0426 used to debug continuation memory leaks
	{
		static int cleanNum = 0;
		printk("conts cleaned: %d\n", cleanNum += tp->t.cont_list.len);
	}
#endif

	while(cont != (CONTINUATION_TYPE*)&tp->t.cont_list) {
		CONTINUATION_TYPE *prev = cont;
		cont = cont->next;
		unlinkCont(prev);
		MARK_PC(prev);
		freeClientSide_Continuation(prev);
	}

	/* Clean sent and pending requests */
	for(i=0; i < sizeof(lists)/sizeof(lists[0]); i++) {
		struct alloc_head_list *list = lists[i];
		for(req = (struct Request*)list->next; req != (struct Request*)list;) {
			struct Request *clean = req;
			req = (struct Request*)req->next;
			unlink((struct alloc_head*)clean);
			freeRequest(clean);
		}
	}

	for(i=0; i < sizeof(dataRequestLists)/sizeof(dataRequestLists[0]); i++) {
		struct DataRequestMapping *mapping;
		struct alloc_head_list *list = dataRequestLists[i];
		for(mapping  = (struct DataRequestMapping*)list->next;
		    mapping != (struct DataRequestMapping*)list;) {
			struct DataRequestMapping *clean = mapping;
			mapping = mapping->next;
			unlink((struct alloc_head*)clean);
			freeDataRequestMapping(clean);
		}
	}

	if(tp->t.newIncompleteRequest) {
		freeRequest((struct Request*)tp->t.newIncompleteRequest);
		tp->t.newIncompleteRequest = NULL;
	}
	if(tp->t.prevConvCont) {
		// don't bother with refcnt, since we're cleaning up
		kfree(tp->t.prevConvCont);
		tp->t.prevConvCont = NULL;
	}
	/* Clean user continuations and dependencies */
	for(ucont = (struct UC_Continuation*)tp->t.ucontList.next;
	    ucont != (struct UC_Continuation*)&tp->t.ucontList;) {
		struct UC_Continuation *clean = (struct UC_Continuation*) ucont;
		ucont = (struct UC_Continuation*)ucont->next;
		kfree(clean);
	}
	for(depNode = (struct UC_DependencyNode*)tp->t.depNodeList.next;
	    depNode != (struct UC_DependencyNode*)&tp->t.depNodeList;) {
		struct UC_DependencyNode *clean = depNode;
		depNode = (struct UC_DependencyNode*)depNode->next;
		vector_free(&depNode->depLinks);
		kfree(clean);
	}

	struct SkipCell *sc;
	for(sc = (struct SkipCell *) tp->t.skipList.next;
	    sc != (struct SkipCell *) &tp->t.skipList;	) {
		struct SkipCell *clean = sc;
		sc = (struct SkipCell *) sc->next;
		SkipCell_free(clean);
	}

#ifndef USERTEST
	/* deallocate minisockets */

	if((tp->trickles_opt & TCP_TRICKLES_ENABLE) &&
	   (tp->trickles_opt & TCP_TRICKLES_RSERVER) &&
	   TRICKLES_USERAPI_CONFIGURED_TP(tp)) {
		struct trickles_mmap_ctl *ctl = (struct trickles_mmap_ctl *)&tp->cminisock_api_config.cfg.ctl;
		struct cminisock *msk = (struct cminisock *)ctl->minisock_base;
		while((char*)msk <= (char*)ctl->ro_base + MINISOCK_LEN(ctl->ro_len)) {
			free_msk(sk,msk);
			msk++;
		}
	}
#endif // USERTEST

#ifdef OPENSSL_HMAC
	// for OpenSSL HMAC
	if(tp->t.hmacCTX) {
		kfree(tp->t.hmacCTX);
		tp->t.hmacCTX = NULL;
	}
#endif
	if(tp->t.nonceCTX) {
		kfree(tp->t.nonceCTX);
		tp->t.nonceCTX = NULL;
	}
	if(0 && trickles_ratelimit() && (numRxPackets != 0 || numTxPackets != 0)) {
		printk("numRxPackets = %llu, numRxBytes = %llu, avgRxPacketSize = %d, numTxPackets = %llu, numTxBytes = %llu, avgTxPacketSize = %d\n",
		       numRxPackets, numRxBytes, (__u32)(numRxPackets >> 4) ? (__u32)(numRxBytes >> 4) / (__u32)(numRxPackets >> 4) : 0,
		       numTxPackets, numTxBytes, (__u32)(numTxPackets >> 4) ? (__u32)(numTxBytes >> 4) / (__u32)(numTxPackets >> 4) : 0);
		numRxPackets = numRxBytes = numTxPackets = numTxBytes = 0;
	}

#ifndef USERTEST
	/* Unlink from global client socket list */
	if((tp->trickles_opt & TCP_TRICKLES_ENABLE) && !(tp->trickles_opt & TCP_TRICKLES_RSERVER)) {
		trickles_del_clientsock(sk);
	} else {
		BUG_TRAP(tp->t.dnext == NULL);
	}
#endif // USERTEST

#ifdef RECORD_LOSS_EVENTS
	if(tp->t.events != NULL) {
		struct TricklesProcLogEntry *newEntry =
			kmalloc(sizeof(struct TricklesProcLogEntry), GFP_ATOMIC);
		newEntry->next = newEntry->prev = NULL;
		newEntry->list = NULL;
		newEntry->addr = sk->daddr;
		newEntry->port = sk->dport;
		newEntry->rcv_nxt = tp->rcv_nxt;
		newEntry->t_rcv_nxt = tp->t.rcv_nxt;

		newEntry->events = tp->t.events;
		newEntry->size = tp->t.eventsSize;
		newEntry->returnedEvents = 0;
		newEntry->sentAmount = 0;
		insert_tail(&tricklesProcLogHead, (struct alloc_head *)newEntry);
	}
#endif
	if(sk->prev) {
		printk("Trickles prev != NULL\n");
	}
	if(sk->bind_next) {
		printk("Trickles bind_next != NULL\n");
	}
	gNumUncopiedBytes += tp->rcv_nxt - tp->copied_seq;
	//dump_global_stats();

	// SK_trickles_servers_dump(sk);

	printk("normal = %d, recovery = %d, slowstart = %d\n", 
	       gNormalCount, gRecoveryCount, gSlowStartCount);

	if(tp->t.msk_table != NULL) {
		printk("freeing msk table\n");
		MSKTable_free(tp->t.msk_table);
	}
}

#ifndef USERTEST

kmem_cache_t *clientSideContinuation_cache;

static inline void clientSideContinuation_init(void *p, kmem_cache_t *cache,
					       unsigned long flags) {
	return;
}

static char *contCacheName;

int trickles_init(void) {
	BUG_TRAP(HMAC_PHEADER_LEN == sizeof(PseudoHeader));
	sysctl_trickles_mss = 1374 - 16;
	//sysctl_trickles_mss = 1374 - 32;

	trickles_prot = tcp_prot;
	trickles_prot.sendmsg = trickles_sendmsg;
	trickles_prot.close = trickles_close;
	trickles_client_prot = trickles_prot;

	trickles_client_prot.sendmsg = trickles_client_sendmsg;
	trickles_client_prot.recvmsg = trickles_client_recvmsg;

	trickles_rcv_hook = trickles_rcv_impl;
	trickles_destroy_hook = trickles_destroy;

	cminisock_config_pipe_hook = cminisock_config_pipe_impl;
	trickles_sendv_hook = trickles_sendv_impl;
	trickles_send_hook = trickles_send_impl;
	trickles_sendfilev_hook = trickles_sendfilev_impl;
	trickles_mmap_hook = trickles_mmap_impl;
	trickles_setucont_hook = trickles_setucont_impl;

	trickles_sock_poll_hook = trickles_sock_poll_impl;
	trickles_init_sock_hook = trickles_init_sock_impl;

	trickles_send_ack_hook = user_ack_impl;

	trickles_sockets_head.tp_pinfo.af_tcp.t.dnext = &trickles_sockets_head;
	trickles_sockets_head.tp_pinfo.af_tcp.t.dprev = &trickles_sockets_head;

	trickles_setsockopt_hook = trickles_setsockopt_impl;
	trickles_getsockopt_hook = trickles_getsockopt_impl;

	printk("Warning: Low level Trickles client interface not implemented\n");
	trickles_sendmsg_hook = NULL;

	trickles_sendbulk_hook = trickles_sendbulk_impl;

	trickles_extract_events_hook = trickles_extract_events_impl;
	trickles_install_events_hook = trickles_install_events_impl;
	trickles_syn_piggyback_hook = trickles_syn_piggyback_impl;

	trickles_request_hook = trickles_request_impl;

	/* initialize crappy RNG */
	rand = jiffies;

	//trickles_client_connected_hook = trickles_client_connected_impl;

#ifdef USE_FLOATINGPOINT
	{
		int i;
		kernel_fpu_begin();
		barrier();
		init_fpu();
		barrier();
		for(i=0; i < NR_CPUS; i++) {
#ifdef FAST_CONTEXT
			asm __volatile__ ("fninit\n fnstcw %0": "=m"(fpu_kernel_save[i][0]));
			*((short*)fpu_kernel_save[i]) |= 0x1f; // mask all exceptions
#else
			asm __volatile__ ("fninit\n");
			barrier();
			FPU_SAVE(fpu_kernel_save[i]);
			barrier();
#endif
		}
		barrier();
		kernel_fpu_end();
	}
#else
		/*
		  for(i=0; i < 1000; i++) {
		  printk("mborg_isqrt(%d) = %d\n", i, mborg_isqrt4(i));
		  }
		*/
#endif // USE_FLOATINGPOINT

	printk("trickles loaded (hmac = %d nonce = %d): %s %s\n", generateHMAC, generateNonces, UTS_VERSION, LINUX_COMPILE_HOST);


#ifdef DEBUG_LIST
	printk("***** Warning: DebugList\n");
#endif

#ifdef CONFIG_DEBUG_SLAB
	printk("***** Warning: Compiled with SLAB debug on, will be absolutely extremely slow. You won't believe how slow this is.\n");
#endif

#ifdef FIXEDRTT
	printk("***** Warning :FIXEDRTT\n");
#endif

	if(disableSevereErrors) {
		printk("***** Warning: Printk of severe errors & warnings suppressed\n");
	}

#ifdef DEBUG_TRICKLES_ALLOCATION
	printk("***** Warning: debugging trickles allocation\n");
#endif

	if(!enableDataRecovery) {
		printk("**** Warning: enableDataRecovery == 0\n");
	}
	contCacheName = kmalloc(128, GFP_ATOMIC);
	// We leak about 30 objects from this slab every run. For now, change the name of the run on each bootup to avoid BUG() assertion on kmem_cache_create
	sprintf(contCacheName, "cont#%lu", jiffies);

	//0501 hack to find memory leak
	if(2 * sizeof(CONTINUATION_TYPE) > 4096) {
		BUG();
	}
#ifdef DEBUG_ALLOC
	printk("Warning: 4K allocation for clientsidecontinuation_cache: compiling in 386 mode to disable PSE, PGE. pse = %d, pge = %d; ack_prev integrity check\n", cpu_has_pse, cpu_has_pge);
	clientSideContinuation_cache =
		kmem_cache_create(contCacheName,
				  4096,
				  0,
				  SLAB_PAGE_ALIGN | SLAB_DEBUG_INITIAL | SLAB_POISON | SLAB_RED_ZONE,
				  clientSideContinuation_init, NULL);
#else
	clientSideContinuation_cache =
		kmem_cache_create(contCacheName,
				  CLIENTSIDE_CONTINUATION_SIZE,
				  0,
				  SLAB_HWCACHE_ALIGN /* | SLAB_DEBUG_INITIAL | SLAB_POISON | SLAB_RED_ZONE */,
				  clientSideContinuation_init, NULL);
#endif
#ifndef INIT2
	printk("Warning: not initializing both elements in continuation arrays\n");
#endif
#ifdef SAVE_APHIST
	printk("Warning: APHist array being allocated and wasting space\n");
#endif

	printk("Warning: Stuck client state detection (slow start left/right violation) disabled\n");
	printk("Warning: Disabled server-side recovery mode's out of memory errors\n");

#ifdef DISABLE_DATAREQUEST
	printk("Warning: Disabling DataRequest\n");
#endif
#ifdef RECORD_LOSS_EVENTS
	printk("Warning: Recording loss events\n");
#endif

#ifdef SLOWSTART_ONLY
	printk("Warning: Slow start only; no fast recovery\n");
#endif

#ifdef RANDOMIZE_SLOWSTART_TIMER
	printk("Randomizing slow start timer\n");
#endif

#ifdef STOMP_CONNECTIONS
	printk("Stomping connections every %d\n", STOMP_CONNECTIONS);
#endif

	sysctl_dbg_cwnd = 0;
	if(sysctl_dbg_cwnd) {
		printk("Dumping cwnd to log\n");
	}

	init_head(&tricklesProcLogHead);
	create_proc_read_entry("trickles", S_IRUGO | S_IWUSR,
			       NULL, trickles_read_proc, NULL);

	init_head(&tricklesCwndProcLogHead);
	create_proc_read_entry("trickles_cwnd", S_IRUGO | S_IWUSR,
			       NULL, trickles_cwnd_read_proc, NULL);

#ifdef LOG_CWND_ENABLE
	trickles_logCwnd_hook = trickles_logCwnd_impl;
	printk("Log cwnd enabled!!!\n");
#else
	trickles_logCwnd_hook = trickles_logCwnd_default;
#endif
	MSKTable_new = MSKTable_new_impl;

	printk("Multiplicative factor = %d\n", MULT_FACTOR);

#ifdef ACKTCP_CWND_SPEED_HACK
#define STRINGIFY(X) #X
	printk("Using AckTCPCwnd speed hack " STRINGIFY(ACKTCP_CWND_SPEED_HACK) "\n");
#undef STRINGIFY
#endif
	printk("Timeout multiplier: %d\n", TIMEOUT_MULTIPLIER);

#ifdef ZERO_SSTHRESH_PROTECTION_HACK
	printk("Zero ssthresh protection hack\n");
#endif
#ifdef DISABLE_ACKTCPCWND_WARNINGS
	printk("AckTCPCwnd warnings disabled\n");
#endif
#ifdef DISABLE_SENDACKOVERFLOW
	printk("SendAckOverflow disabled\n");
#endif

#ifdef FIXED_CRYPTO_KEYS
	printk("Fixed crypto keys\n");
#endif
	if(DISABLE_NONCE_CHECK) {
		printk("Nonce check disabled\n");
	}

#ifdef DISABLE_SADDR_HMAC
	printk("Server source address not included in HMAC\n");
#endif

#ifdef DISABLE_NONCE_FAIL
	printk("!!!Disabled nonce mismatch check!!!\n");
#endif

#ifdef PRINT_NONCE_DIAG
	{
		int i;
		struct aes_encrypt_ctx ctx;
		char nonce_key[NONCE_KEYLEN];
		char block[NONCE_BLOCKSIZE];
		memset(nonce_key, 0, NONCE_KEYLEN);
		memset(block, 0, NONCE_BLOCKSIZE);
		strcpy(nonce_key, "hello w");
		aes_encrypt_key(nonce_key, NONCE_KEYLEN, &ctx);
		for(i=0; i < 10; i++) {
			char output[NONCE_BLOCKSIZE];
			*(__u64*)block = i * i;
			aes_encrypt(block, output, &ctx);
			printk(" Input: ");
			hexdump(block, NONCE_BLOCKSIZE);
			printk("\n");
			printk("Output: ");
			hexdump(output, NONCE_BLOCKSIZE);
			printk("\n");
		}
#define TAR_MAX (10)
		__u32 testArray[TAR_MAX];
		for(i=1; i <= TAR_MAX; i++) {
			printk("Range nonce 1-%d 0x%0X\n", i,
			       testArray[i] =
			       generateCryptoRangeNonceHelper(&ctx, 1, i));
		}
		printk("Nonces 1-%d: ", TAR_MAX);
		struct NonceCtx nctx;
		nctx.new = 1;
		__u32 accum = 0;
		for(i=1; i <= TAR_MAX; i++) {
			__u32 curr = generateCryptoSingleNonceHelper(&ctx, i, &nctx);
			accum ^= curr;
			printk("0x%0X%c ", accum, (accum == testArray[i]) ? 'g' : '!');
		}
#undef TAR_MAX
	}
#endif
	printk("WIRECONT_MAC_LEN: %d\n", WIRECONT_MAC_LEN);

#ifdef RCV_COPY_TO_SMALLER_SKB
	printk("Client is copying dev skbs to minimal size skbs\n");
#endif
	printk("FullMSS = %d, MinimalMSS = %d, "
	       "CONTTYPELEN_FULL = %d, CONTTYPELEN_MINIMAL = %d, HASHCOMPRESS = %d, CONTTYPELEN_HASHCOMPRESSED = %d\n",
	       CONTTYPE_FULL_MSS, CONTTYPE_MINIMAL_MSS,
	       CONTTYPELEN_FULL, CONTTYPELEN_MINIMAL,
	       CONTTYPELEN_HASHCOMPRESS,
	       CONTTYPE_HASHCOMPRESS_MSS);

	if(sendOnlyOneRequest) {
		printk("sending only one request from missing data map and unrequested data\n");
	}

#ifdef SANITY_CHECK_RANGEHEADER
	printk("Warning: Sanity checking range header at kernel level in msk_transmit_skb()\n");
#endif

#ifdef GREP_FOR_RANGEHEADER
	printk("Warning: grepping for misplaced range header in input\n");
#endif

#ifdef CHECK_MINRESPONSELEN
	printk("Warning: Checking minresponselen\n");
#endif

#ifdef MIN_RESPONSELEN_ADJ_HACK
	printk("MinResponseLenAdjHack(%d) enabled\n", MIN_RESPONSELEN_ADJ_HACK);
#endif
#ifdef MIN_RESPONSELEN_ADJUP_TEST
	printk("MIN_RESPONSELEN_ADJUP_TEST -- performance will be horrible\n");
#endif

#ifdef RTT_INCLUDES_USER
	printk("Rtt will include server-side user time\n");
#else
	printk("Rtt will NOT include server-side user time\n");
#endif

#ifdef HIDE_PREMATURE_LOSS_DETECTION
	printk("Hiding premature loss detection, the slow start thresholds are (min,max) = (%d,%d)\n", MIN_SS_TIMEOUT, MAX_SS_TIMEOUT);
#endif

	if(TIMEOUT_MULTIPLIER != 2) {
		printk("Warning: Timeout multiplier %d != 2\n",
		       TIMEOUT_MULTIPLIER);
	}

	printk("HZ = %d\n", HZ);

#ifdef CHUNKID
	printk("Warning: using CHUNKID\n");
#endif
	if(!dbgBadChunk) {
		// printk("bad data chunk errors suppressed\n");
	}

	hist_init(&a_histogram, "A", 40, 0, 400);
	hist_init(&d_histogram, "D", 40, 0, 400);
	hist_init(&timeout_histogram, "timeout", 100, 0, 1000);
	hist_init(&rx_histogram, "rx", 15, 0, 1500);


#ifdef ENABLE_RECYCLING
	printk("SKB recycling enabled\n");
#else
	printk("SKB recycling disabled\n");
#endif

	printk("Server debug level = %d\n", serverDebugLevel);

	StateCache_init();
	printk("trickles continuation state cache enable: %d\n", sysctl_trickles_Continuation_enable);
	printk("Warning: Only one single global continuation state cache (yes, this is broken)\n");
	
#if 0
	printk("pmsk length is %d, msk length is %d\n", 
	       sizeof(struct pminisock), sizeof(struct cminisock));
#endif

#ifdef DISABLE_FAST_RECOVERY
	printk("fast recovery disabled\n");
#endif

	printk("RESPONSELEN_HASHCOMPRESS=%d, FIN_HINT_SIZE = %d\n", RESPONSELEN_HASHCOMPRESS, FIN_HINT_SIZE);

	return 0;
}

static void trickles_exit(void) {
	struct sock *sk = trickles_sockets_head.next;
	trickles_rcv_hook = trickles_rcv_default;
	trickles_destroy_hook = trickles_destroy_default;
	cminisock_config_pipe_hook = cminisock_config_pipe_default;
	trickles_sendv_hook = trickles_sendv_default;
	trickles_send_hook = trickles_send_default;
	trickles_sendfilev_hook = trickles_sendfilev_default;
	trickles_mmap_hook = trickles_mmap_default;
	trickles_sock_poll_hook = trickles_sock_poll_default;
	trickles_init_sock_hook = trickles_init_sock_default;
	trickles_send_ack_hook = trickles_send_ack_default;
	trickles_setucont_hook = trickles_setucont_default;
	trickles_setsockopt_hook = trickles_setsockopt_default;
	trickles_getsockopt_hook = trickles_getsockopt_default;

	trickles_sendmsg_hook = trickles_sendmsg_default;
	trickles_logCwnd_hook = trickles_logCwnd_default;

	trickles_sendbulk_hook = trickles_sendbulk_default;

	trickles_extract_events_hook = trickles_extract_events_default;
	trickles_install_events_hook = trickles_install_events_default;
	trickles_syn_piggyback_hook = trickles_syn_piggyback_default;
	trickles_request_hook = trickles_request_default;

	MSKTable_new = MSKTable_new_default;

	spin_lock(&trickles_sockets_head_lock);
	int i = 0;
	local_bh_disable();
	while(sk && sk != &trickles_sockets_head) {
		trickles_clear_timers(sk);
		sk = sk->tp_pinfo.af_tcp.t.dnext;
		i++;
	}
	printk("%d timers cleared\n", i);
	local_bh_enable();
	spin_unlock(&trickles_sockets_head_lock);
	//trickles_client_connected_hook = trickles_client_connected_default;
	printk("trickles unloaded\n");
	printk("numConversionRequests = %d, numContinuationRequests = %d, numDataRequestMappings = %d\n",
	       numConversionRequests, numContinuationRequests, numDataRequestMappings);

	printk("numRxPackets = %llu, numRxBytes = %llu, numTxPackets = %llu, numTxBytes = %llu\n",
	       numRxPackets, numRxBytes, numTxPackets, numTxBytes);

	kmem_cache_destroy(clientSideContinuation_cache);

	struct TricklesProcLogEntry *logEntry;
	struct TricklesCwndProcLogEntry *cwndLogEntry;
	local_bh_disable();
	alloc_head_walk(&tricklesProcLogHead, logEntry) {
		struct TricklesProcLogEntry *clean = logEntry;
		logEntry = (struct TricklesProcLogEntry*)logEntry->prev;
		unlink((struct alloc_head*)clean);
		kfree(clean->events);
		kfree(clean);
	}
	// should not need to take locks if bh is disabled
	alloc_head_walk(&tricklesCwndProcLogHead, cwndLogEntry) {
		struct TricklesCwndProcLogEntry *clean = cwndLogEntry;
		cwndLogEntry = (struct TricklesCwndProcLogEntry*)cwndLogEntry->prev;
		unlink((struct alloc_head*)clean);
		kfree(clean);
	}
	local_bh_enable();
	remove_proc_entry("trickles", NULL);
	remove_proc_entry("trickles_cwnd", NULL);
	dump_global_stats();

	hist_destroy(&a_histogram);
	hist_destroy(&d_histogram);
	hist_destroy(&timeout_histogram);
	hist_destroy(&rx_histogram);

	dump_cache_stats();
	StateCache_destroy();

	printk("sentBytes = %d, sentPackets = %d, avg = %d\n", 
	       gNumSentBytes, gNumSentPackets, gNumSentBytes > 0 ? gNumSentBytes / gNumSentPackets : -1);
	printk("contTypes full=%d hash=%d minimal=%d\n", gNumFull, gNumHash, gNumMinimal);
}

MODULE_AUTHOR("Alan Shieh");
MODULE_DESCRIPTION("Trickles module");
MODULE_LICENSE("GPL");
EXPORT_NO_SYMBOLS;
module_init(trickles_init);
module_exit(trickles_exit);
#endif // USERTEST

