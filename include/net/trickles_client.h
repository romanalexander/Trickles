#ifndef _IN_TRICKLES_H
	#error "File can only be included from trickles.h"
#endif // _IN_TRICKLES_H 

// Client side symbols

#ifdef __KERNEL__

void trickles_add_clientsock(struct sock *sk);
void trickles_del_clientsock(struct sock *sk);

void queueConversionRequests(struct sock *sk);
void pushRequests(struct sock *sk); // XXX Move pushRequests body into header so that it can be inlined
void finishIncompleteRequest(struct sock *sk);

int addNewUC_Continuation(struct sock *sk, struct UC_Continuation *newCont);
struct RequestOFOEntry;
void CompleteRequest_finish(struct sock *sk, CONTINUATION_TYPE *cont, 
		    char *ucont_start, int ucont_len, 
		    struct WireUC_CVT_CompleteResponse *completeResp,
		    struct RequestOFOEntry *ofo_entry);

// used by system call:
int CompleteRequest_parallel_queue(struct sock *sk, struct sk_buff *skb, int reserve_len);

inline void cleanTxQueue(struct sock *sk);

extern int gSocketConversionCount;

void SK_ucontList_dump(struct sock *sk);
void SK_data_ofo_queue_dump(struct sock *sk);
void SK_skiplist_dump(struct sock *sk);
void SK_data_request_dump_helper(struct alloc_head_list *list, int lim);
void SK_data_request_dump(struct sock *sk);
void SK_request_dump_helper(struct alloc_head_list *list);
void SK_request_dump(struct sock *sk);
void SK_dump_vars(struct sock *sk);

struct ConversionRequest *kmalloc_ConversionRequest(int gfp);
void freeRequest(struct Request *req);

#endif // __KERNEL__

/* Request types */

#ifndef USERTEST
#define TRICKLES_HAS_SENDSPACE(SK) \
	((SK)->tp_pinfo.af_tcp.t.write_seq < (SK)->tp_pinfo.af_tcp.t.snd_una + (SK)->sndbuf)
#else
#define TRICKLES_HAS_SENDSPACE(SK) (1)
#endif

struct DataRequestMapping {
	struct DataRequestMapping *prev;
	struct DataRequestMapping *next;
	struct alloc_head_list *list;

	struct UC_Continuation *ucont;
	unsigned sent;
	int completed; // fully completed

	unsigned transportResponseSeqStart, transportResponseSeqEnd;
	// start and end of byte range
	unsigned start, end;

	unsigned timestamp; // used to drive rtt computation
};

static inline
void submitDataRequestMapping(struct sock *sk, struct DataRequestMapping *dataReq,
					      unsigned newStart, unsigned newEnd) {
	struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;
	BUG_TRAP(dataReq->list == NULL);
	dataReq->completed = 0;
	dataReq->sent = 0;

	// poison values
	dataReq->transportResponseSeqStart = UINT_MAX;
	dataReq->transportResponseSeqEnd = UINT_MAX;
	dataReq->timestamp = UINT_MAX;
	dataReq->start = newStart;
	dataReq->end = newEnd;
	insert_tail(&tp->t.missingDataMap, (struct alloc_head*)dataReq);
}

static inline
void submitDerivedDataRequestMapping(struct sock *sk, struct DataRequestMapping *oldReqMap,
					    unsigned start, unsigned end) {
	struct DataRequestMapping *newMap =
		kmalloc(sizeof(struct DataRequestMapping), GFP_ATOMIC);
	*newMap = *oldReqMap;
	if(newMap == NULL) {
		if(!disableSevereErrors) {
			printk("emitDerivedDataRequest: out of memory\n");
		}
		return;
	}
	submitDataRequestMapping(sk, newMap, start, end);
}



extern int numDataRequestMappings;

static inline
struct DataRequestMapping *newDataRequestMapping(struct UC_Continuation *ucont, unsigned tseq_start, unsigned tseq_end,
						 unsigned start, unsigned end) {
	// printk("creating mapping %d-%d\n", start, end);
	struct DataRequestMapping *newMapping = kmalloc(sizeof(struct DataRequestMapping), GFP_ATOMIC);
	if(newMapping == NULL) return NULL;
	newMapping->next = newMapping->prev = NULL;
	newMapping->list = NULL;

	newMapping->completed = 0;
	newMapping->ucont = ucont;
	newMapping->transportResponseSeqStart = tseq_start;
	newMapping->transportResponseSeqEnd = tseq_end;
	newMapping->sent = 0;
	newMapping->start = start;
	newMapping->end = end;
#ifndef USERTEST
	newMapping->timestamp = jiffies;
#endif

	numDataRequestMappings++;
	return newMapping;
}

static inline void freeDataRequestMapping(struct DataRequestMapping *dataReq) {
	numDataRequestMappings--;
	kfree(dataReq);
}

/* These requests are queued in the reliable request queues. As the
   client earns tokens to use to service requests, the entries in this
   queue are sent to the server. During recovery, all requests are
   retried */

enum UserRequestType {
  /* MemoryREQuest */
	MREQ_WILD,
	MREQ_CONVERSION,
	MREQ_CONTINUATION,
};

struct Request {
  /* Generic "base" type */
#define MAX_MREQ_CHILDREN 4
#define REQUEST_FIELDS							\
	struct alloc_head *prev;					\
	struct alloc_head *next;					\
	struct alloc_head_list *list;					\
	enum UserRequestType type;					\
	unsigned numChildren; /* request v0: from responses. v1: unused */		\
	unsigned numActualChildren; /* v1: from server responses */	\
	unsigned childrenMask : MAX_MREQ_CHILDREN;			\
	struct { __u32 start, end; } childRanges[MAX_MREQ_CHILDREN];	\
	unsigned transport_seq;						\
	unsigned seq;							\
	unsigned start, end;					        \
		unsigned isNew : 1;					\
		unsigned allocated : 1;					\
		unsigned transportResponseSeqStart, transportResponseSeqEnd;

	// Request uses only alloc_head list management operations. Thus,
	// Request does not need a 'ctl' field

	REQUEST_FIELDS
};

static inline void resetRequest(struct Request *req) {
	req->numChildren = 0;
	req->numActualChildren = 0;
	req->childrenMask = 0;
	req->transport_seq = -1;
	req->seq = -1;
	req->isNew = 1;
}

static inline void initRequest(struct Request *req, enum UserRequestType type) {
	/* Initialize generic fields */
	req->type = type;
	req->prev = req->next = NULL;
	req->list = NULL;
	resetRequest(req);
	req->start = req->end = -1;
	req->allocated = 1;
}

void resetClientTimer(struct sock *sk);

static inline void queueNewRequest(struct sock *sk, struct Request *req) {
	struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;
	insert_tail(&tp->t.queuedRequests, (struct alloc_head*)req);
	tp->t.timerState |= TRICKLES_ENABLE_DATA_TIMEOUT;
	resetClientTimer(sk);
}

struct ConversionRequest {
	REQUEST_FIELDS

	_bool incomplete; //  0 = complete, 1 = incomplete
	// First skb that contains data to convert
	struct sk_buff *data;
	// Offset within sk_buff
	unsigned offset;
#if 0
	// Length to send. If necessary, consult successors to 'data'
	unsigned length;
	// if length == 0, length is undefined and should be set in sendAck (possibly performing fragmentation)
#endif

	unsigned predLength;
	unsigned parallelStart;
	unsigned ident;
	union {
		struct WireUC_CVT_IncompleteContinuation *incompletePred;
		struct UC_Continuation *completePred;
	};
};

static inline void initCompleteConversionRequest(struct ConversionRequest *req, struct UC_Continuation *pred, struct sk_buff *data, unsigned start) {
	initRequest((struct Request *)req, MREQ_CONVERSION);
	req->incomplete = 0;
	req->completePred = pred;
	if(req->completePred != NULL) {
		atomic_inc(&req->completePred->refcnt);

		if(atomic_read(&req->completePred->refcnt) < 2) {
			printk("refcnt should be > 1!\n");
			BUG();
		}
	}

	req->data = data;
	req->start = start;
	req->offset = req->start - TCP_SKB_CB(data)->seq;
}

static inline void initIncompleteConversionRequest(struct ConversionRequest *req, struct WireUC_CVT_IncompleteContinuation *pred, unsigned predLength, struct sk_buff *data, unsigned offset) {
	initRequest((struct Request *)req, MREQ_CONVERSION);
	req->incomplete = 1;
	req->incompletePred = pred;
	req->predLength = predLength;
	req->data = data;
	req->offset = offset;
}

struct ContinuationRequest {
	REQUEST_FIELDS

	// conts array is kmalloc()'d, and deallocated when the response is
	// processed, and request dequeued
	//
	// The continuations themselves are deallocated by higher
	// layer once no longer needed as dependencies
	unsigned numConts;
	struct UC_Continuation **conts;
};

static inline int initContinuationRequest(struct ContinuationRequest *req, unsigned start, unsigned end, int numConts) {
	initRequest((struct Request *)req, MREQ_CONTINUATION);
	req->start = start;
	req->end = end;
	req->numConts = numConts;
	req->conts = kmalloc(sizeof(struct UC_Continuation*) * numConts, GFP_ATOMIC);
	if(req == NULL) {
		if(trickles_ratelimit())
			printk("Could not allocate continuation request\n");
		return -1;
	}
	return 0;
}

extern int numContinuationRequests;
static inline struct ContinuationRequest *copyContinuationRequest(struct ContinuationRequest *src) {
	struct ContinuationRequest *newReq = kmalloc(sizeof(struct ContinuationRequest), GFP_ATOMIC);
	numContinuationRequests++;
	if(newReq == NULL) return NULL;
	*newReq = *src;
	newReq->conts = kmalloc(sizeof(struct UC_Continuation*) * newReq->numConts, GFP_ATOMIC);
	if(newReq->conts == NULL) {
		kfree(newReq);
		return NULL;
	}
	memcpy(newReq->conts, src->conts, sizeof(struct UC_Continuation*) * newReq->numConts);
	return newReq;
}

struct RequestOFOEntry {
	struct RequestOFOEntry *prev;
	struct RequestOFOEntry *next;
	struct alloc_head_list *list;

	CONTINUATION_TYPE *cont;
	int isSynack;
	__u32 parent;
	__u8 numSiblings;
	__u8 position;
};

static inline struct RequestOFOEntry *
RequestOFOEntry_new(CONTINUATION_TYPE *cont,
		    int isSynack, __u32 parent, __u8 numSiblings, __u8 position) {
	struct  RequestOFOEntry *rval =
		kmalloc(sizeof(struct RequestOFOEntry), GFP_ATOMIC);
	if(rval == NULL) {
		printk("Out of memory while allocating RequesOFOEntry\n");
		return NULL;
	}
	rval->prev = rval->next = NULL;
	rval->list = NULL;

	rval->cont = cont;
	rval->isSynack = isSynack;
	rval->parent = parent;
	rval->numSiblings = numSiblings;
	rval->position = position;

	return rval;
}

#if 0
static inline void freeClientSide_Continuation(CONTINUATION_TYPE *cont);
#else
#include "trickles_packet_helpers.h"
#endif
static inline
void RequestOFOEntry_free(struct RequestOFOEntry *entry) {
	BUG_TRAP(entry->prev == NULL && entry->next == NULL &&
		 entry->list == NULL);
	freeClientSide_Continuation(entry->cont);
	kfree(entry);
}

extern int (*trickles_rcv_hook)(struct sock *sk, struct sk_buff *skb);
extern void (*trickles_destroy_hook)(struct sock *sk);

int trickles_rcv_default(struct sock *sk, struct sk_buff *skb);
void trickles_destroy_default(struct sock *sk);

