// -*- mode: c -*-
#define USE_HASH_COMPRESS(SK) (!((SK)->tp_pinfo.af_tcp.trickles_opt & TCP_TRICKLES_DISABLE_HASHCOMPRESS))

	// Trickles versions of TCP variables
	struct {
		/* MALLOC FIELDS */
		int malloc_initialized;

		/* Maximum heap size, set during pipe configuration */
		int heapbytesize;
		int heapbytesallocated;
#ifdef USERTEST
		void *heap_absolute_base;
#endif

		/* heap size in blocks */
		int heapsize;

		/* Pointer to first block of the heap. */
		char *heapbase;
		
		/* Table indexed by block number giving per-block information. */
		union heap_info *heapinfo;

		/* Current search index for the heap table. */
		int heapindex;

		/* Limit of valid info table indices. */
		int heaplimit;

		/* Count of blocks for each fragment size. */
		int fragblocks[BLOCKLOG];

		/* Free list headers for each fragment size. */
		struct heap_list fraghead[BLOCKLOG];

		/* End malloc fields */

		unsigned clientStateCounter; // used to fill WireContinuation->clientState
#define IS_RECOVERY_STATE() (tp->t.state == TRICKLES_CLIENT_RECOVERY)
		int state;

		// Van Jacobsen's 1990 RTT estimator
		int A; // in jiffies/8
		int D; // in jiffies/8
		int RTO; // current timeout delay, in jiffies/8
		// Returns Van Jacobsen 1990 TCP RTT, in jiffies/8
#define DUMP_RTO(SK) ({					\
	struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;	\
	printk("A = %d, D = %d, RTO = %d", tp->t.A, tp->t.D, tp->t.RTO); \
})

#define VJ90RTO8(SK) ({					\
	struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;	\
	/* Effect is RTO = A + 4D */			\
	tp->t.A + (tp->t.D << 2);			\
})
#define RTO_IN_JIFFIES(SK) ({				\
	struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;	\
	tp->t.RTO >> 3;					\
})
#define RTO_FROM_JIFFIES(SK,NEWVAL) ({			\
	struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;	\
	tp->t.RTO = (NEWVAL) << 3;			\
})

#define INITIAL_RTO ((3 * HZ) << 3)
		/* NOTE!!!!! 
		   On setting enable_data_timeout, be sure to reset client timer
		*/

#define NEED_USERACK(SK) (sk->tp_pinfo.af_tcp.t.timerState & TRICKLES_NEED_USERACK)
#define TRICKLES_ENABLE_DATA_TIMEOUT (0x1)
#define TRICKLES_NEED_SLOWSTART (0x2)
#define TRICKLES_NEED_USERACK (0x4)
		int timerState; // bitmask for timer states

#define TRICKLES_CLIENT_NORMAL    1
#define TRICKLES_CLIENT_RECOVERY  2
#define TRICKLES_CLIENT_SLOWSTART 3
#define TRICKLES_CLIENT_SYNACK    4 // temporary state until response to SYN/ACK packet is received
#if 0
// Don't send requests during recovery: we dont know which packets the server will respond to, so best to wait until recovery is completed.
#define IS_SEND_UCONTREQ_STATE(TP) ((TP)->t.state == TRICKLES_CLIENT_NORMAL)
#else
// allow requests during recovery state
//#define IS_SEND_UCONTREQ_STATE(TP) ((TP)->t.state == TRICKLES_CLIENT_NORMAL || (TP)->t.state == TRICKLES_CLIENT_RECOVERY)

// allow requests during all states except synack
#define IS_SEND_UCONTREQ_STATE(TP) ((TP)->t.state == TRICKLES_CLIENT_NORMAL || (TP)->t.state == TRICKLES_CLIENT_RECOVERY || (TP)->t.state == TRICKLES_CLIENT_SLOWSTART)
#endif
		int rcv_nxt;
		int previous_base;
		struct sk_buff_head ofo_queue;

	  /* Transport continuation management: used to remember
	     current ack position
	     These refer to the copies in cont_list */
		struct cminisock *ack_prev;

		// 0430 - debugging ack_prev: temporary instrumentation to find out assignment history to ack_prev
//#define SAVE_APHIST
#ifdef SAVE_APHIST
#define ACK_PREV_HISTORY_ENTRIES (16)
		struct cminisock *aphist;
		int aphistpos;
#endif // SAVE_APHIST


		int ack_last; // one past last  ack packet we are allowed to use
//#define OO_THRESHOLD 3
#define OO_THRESHOLD (sysctl_tcp_reordering)
		int oo_count;
		int in_flight;

		AckProof standardProof;
		AckProof altProof;
		struct MSKTable *msk_table;
		__u8 space[12]; /* extra space for ackProofs and other fields */

		struct sock *dprev, 
			*dnext;
		struct sk_buff *dbg_skb;
		int testseq;

		/* in-sequence list of continuations (possibly no longer associated with packets in receive queue). Used for transport-level acking */
		struct alloc_head_list cont_list;
#ifndef USERTEST
		struct timer_list slowstart_timer;
#endif


		/* List of pending requests, sorted by increasing sequence
		   number. Entries are automatically retransmitted across recovery
		   operations 

		   This abstraction is used by data, continuation, and conversion requests
		*/
#define TRANSPORT_ONLY_REQNUM (UINT_MAX)
#define DATA_ONLY_REQNUM (UINT_MAX)
#define TRANSPORT_OR_DATA_ONLY_REQNUM (UINT_MAX)
		unsigned request_rcv_nxt;
		unsigned request_snd_nxt;
		struct alloc_head_list request_ofo_queue; // 0812 more efficient & cleaner to store continuations rather than full packets
		struct sk_buff_head data_ofo_queue; // all elements have CB->cont deallocated, e.g. CB->cont is not a valid pointer
		// the following queues are kept in increasing transport sequence number (where these are defined), and by request sequence number otherwise
		struct alloc_head_list sentRequests;   // already sent to server
		struct alloc_head_list queuedRequests; // waiting to be sent

		struct alloc_head_list dataRequestMap; // sorted in order of increasing transport response seq # ( this is a side effect of the insertion algorithm)
		struct alloc_head_list missingDataMap; // not sorted in any order
#define HAS_PENDING_REQUESTS(SK) (!empty(&(SK)->tp_pinfo.af_tcp.t.queuedRequests))

		// CLIENT data request manager
		unsigned byteReqNext; // Next byte to request
		unsigned byteRcvNxt;
		int byteSkipHintAmount;
		struct sk_buff *byteReqHint;

		// CLIENT ByteStream Conversion
#define CONVERSION_IDLE          (0)
#define CONVERSION_WAITFORSERVER (1)
#define CONVERSION_WAITFORUSER   (2)
		int conversionState;
		__u32 snd_una;
		__u32 snd_end; // bytes sent to server on last conversion request: [snd_una, snd_end). Snd_end is updated when a conversion request is transmitted
		__u32 write_seq;
		struct sk_buff_head requestBytes;
		struct ConversionRequest *newIncompleteRequest;
		struct UC_Continuation *prevConvCont;

		// CLIENT Continuation manager
		struct alloc_head_list ucontList; /* List of user continuations, sorted by valid range */
		struct alloc_head_list depNodeList; /* List of update dependencies, sorted by valid range. NO OVERLAPPING DEPENDENCIES */
		
		struct alloc_head_list skipList;   // list of FINs collected in fragmentSKB; list of FINs is used during removeObsoleteContinuation to check whether continuations have actually been finished

		// SERVER

		// Crypto contexts, kept ready-to-use (e.g., fully initialized).
		struct HMAC_CTX *hmacCTX;
		char hmacKey[HMACLEN];
		struct aes_encrypt_ctx *nonceCTX;
		struct sk_buff_head prequeueOverflow;
		struct sk_buff_head sendAckOverflow;
		// Skbs for recycling
		struct sk_buff_head recycleList;

		/* simulation response */
		struct cminisock *responseMSK; // only one response allowed
		struct alloc_head_list responseList;
		int responseCount;

		struct cminisock api_msk;
		
		struct TricklesLossEvent *events;
		int eventsPos;
		int eventsSize;

		// Multiple server 
#define MAX_TRICKLES_SERVERS (8)
#define SK_MULTIMODE(SK) ((SK)->tp_pinfo.af_tcp.t.numServers > 0)
#define TRICKLES_WILDADDR (0)
		struct trickles_server servers[MAX_TRICKLES_SERVERS];
		int numServers;

#define TRICKLES_DEFAULT_PROBE_RATE (HZ / 4)
		int probeRate; // in jiffies

#if 0
		//////////////// RPC processing
		struct dlist rpc_list;
#endif
		int requestNext;
	} t;
