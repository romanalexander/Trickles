#ifndef TRICKLES_H
#define TRICKLES_H
#define _IN_TRICKLES_H

#define ALIGN(P, N) ((typeof(P))(char*)(P) + (N - ((int)P) % N) % N)
#define CONTINUATION_TYPE struct cminisock
#define IMPLIES(X,Y) (!(X) || (Y))

#define EQ_TEST(X,Y)							\
	do {								\
		if((X) != (Y))						\
			printk(#X " = %d, " #Y " = %d\n", (int)(X), (int)(Y)); \
		else							\
			/* printk(#X " = " #Y "\n") */ ;		\
	} while(0)

#include <linux/stddef.h>
#include <linux/socket.h>
#include <linux/types.h>
#include <asm/atomic.h>

#ifdef __KERNEL__
#ifndef USERTEST
#include <linux/poll.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <net/tcp.h>

#else
#include "skbuff.h"
#endif

#ifdef __KERNEL__
/* CONFIGURATION */
extern const int generateHMAC;
extern const int generateNonces;

/* User api */
//#define SETUCONT_COMMAND

/* CRYPTO */

#include "trickles-crypto.h"

#define HMAC_KEYLEN (HMACLEN)
#define HMAC_BLOCKSIZE 64

#define NONCE_KEYLEN (16)
#define NONCE_BLOCKSIZE (16)

#ifdef OPENSSL_HMAC

#ifdef USE_SHA1
#define HMACLEN 20
typedef SHA_CTX DIGEST_CTX;
#define DIGEST_Init   SHA1_Init
#define DIGEST_Update SHA1_Update
#define DIGEST_Final  SHA1_Final
#else
#define HMACLEN 16
// MD5 defines
typedef MD5_CTX DIGEST_CTX;
#define DIGEST_Init   MD5_Init
#define DIGEST_Update MD5_Update
#define DIGEST_Final  MD5_Final
#endif

#ifdef USE_SHA1
#if HMACLEN != 20
#error "wrong HMACLEN for SHA1"
#endif
#endif

/******************** PRINTING *******************/
#define SUPPRESS_TRICKLES_MESSAGES

#include "trickles_logging.h"

typedef struct HMAC_CTX {
  char key[HMAC_BLOCKSIZE];
  DIGEST_CTX in_ctx;
  DIGEST_CTX out_ctx;
  DIGEST_CTX digest_ctx;
  int len;
} HMAC_CTX;

const static int net_msg_cost = 5*HZ;
const static int net_msg_burst = 10*5*HZ;

#ifndef USERTEST
#ifndef SUPPRESS_TRICKLES_MESSAGES
#define trickles_ratelimit() ({						\
        static spinlock_t ratelimit_lock = SPIN_LOCK_UNLOCKED;		\
        static unsigned long toks = 10*5*HZ;				\
        static unsigned long last_msg;					\
        static int missed;						\
        unsigned long flags;						\
        unsigned long now = jiffies; int result;			\
									\
        spin_lock_irqsave(&ratelimit_lock, flags);			\
        toks += now - last_msg;						\
        last_msg = now;							\
        if (toks > net_msg_burst)					\
                toks = net_msg_burst;					\
        if (toks >= net_msg_cost) {					\
                int lost = missed;					\
                missed = 0;						\
                toks -= net_msg_cost;					\
                spin_unlock_irqrestore(&ratelimit_lock, flags);		\
                if (lost)						\
                        printk(KERN_WARNING "NET %s:%d: %d messages suppressed.\n", __FILE__, __LINE__, lost); \
                result = 1;							\
        } else {							\
		missed++;						\
		spin_unlock_irqrestore(&ratelimit_lock, flags);		\
		result = 0;						\
	} result;							\
})
#else
#define  trickles_ratelimit() (0)
#endif // SUPPRESS_TRICKLES_MESSAGES
#else
#define trickles_ratelimit() (1)
#endif

// MIN/MAX defined using GCC extensions to suppress error messages
#define MIN(X,Y) ({ typeof(X) Z = (typeof(X))(Y); min(X,Z); })
#define MAX(X,Y) ({ typeof(X) Z = (typeof(X))(Y); max(X,Z); })

/* Internal constants */

//#define MAX_GAPSIZE 500
// XXX need to change
#define MAX_GAPSIZE 20

// MSS used for piggybacking data on SYN
extern int sysctl_trickles_mss;
extern int sysctl_trickles_hashcompress;

//#define MTU (1362)
#define ETHERNET_MTU (1500)
//#define TRICKLES_MSS (1374)
#define TRICKLES_MSS (sysctl_trickles_mss)
#define CONTTYPE_FULL_MSS TRICKLES_MSS
#define CONTTYPE_MINIMAL_MSS (TRICKLES_MSS + sizeof(struct WireContinuation) - (int)((struct WireContinuation*)0)->minimalContinuationEnd)
#define CONTTYPE_HASHCOMPRESS_MSS (TRICKLES_MSS + sizeof(struct WireContinuation) - (int)((struct WireContinuation*)0)->hash.end)
//#define CONTTYPE_MINIMAL_MSS TRICKLES_MSS


// Don't generate random keys for crypto
#define FIXED_CRYPTO_KEYS
#if 0
#define DISABLE_NONCE_CHECK 1
#else
#define DISABLE_NONCE_CHECK 0
#endif
//#define DISABLE_NONCE_FAIL

//#define PRINT_NONCE_DIAG
//#define PRINT_CLIENT_ZEROCOUNT
#define PRINT_CLIENT_CONVERSIONCOUNT

// Do not use the source address when computing hmac
#define DISABLE_SADDR_HMAC

// 0620 work around initial ssthresh being cut to 0
#if 1
#define ZERO_SSTHRESH_PROTECTION_HACK
#endif

// 0701 disable excess acktcpcwnd warnings
#define DISABLE_ACKTCPCWND_WARNINGS

#define MULT_FACTOR 2
#define RANDOMIZE_SLOWSTART_TIMER

#define ENABLE_HASHCOMPRESS

#define ENABLE_RECYCLING
#define NO_SIMULATION_SPLIT

#define ACKTCP_CWND_SPEED_HACK 1/2 // make acktcp increase at 1/2 of normal rate
// N.B. Timeout multiplier is not used when using VJ90 estimator
#define TIMEOUT_MULTIPLIER (2)

#define RCV_COPY_TO_SMALLER_SKB

#define ASSERT_TIMER_SET(SK) BUG_TRAP((SK)->tp_pinfo.af_tcp.t.slow_start_timer.list.next != NULL)

#define USE_SQRT
//#define USE_FLOATINGPOINT
//#define FPU_CTX0
#define FAST_CONTEXT
//#define USE_INCREMENTAL_CWND
//#define DEBUG_RECOVERY_MICROTEST
//#define TIME_TRICKLES
//#define USE_SHA1
//#define DEBUG_ALLOC

//#define STOMP_CONNECTIONS (200) // kludge to try to enforce connection fairness

//#define DISABLE_DATAREQUEST

#define GEN_JAM(NAME) if(trickles_ratelimit()) printk("%s:%s:%d jammed on %s\n", __FILE__, __FUNCTION__, __LINE__, NAME);

//#define SANITY_CHECK_RANGEHEADER
//#define GREP_FOR_RANGEHEADER

//#define SANITY_CHECK_MSK

#ifdef SANITY_CHECK_MSK
#define DO_SANITY_CHECK_MSK(MSK)					\
	do {								\
		int line = __LINE__, i = 0;				\
		for(i=0; i < (MSK)->num_packets; i++) {			\
			if((MSK)->packets[i].seq < (MSK)->TCPBase) {	\
				if(trickles_ratelimit())		\
					printk("seqno[%d] = %d < base = %d @%d\n", i, (MSK)->packets[i].seq, line, (MSK)->TCPBase); \
			}						\
		}							\
									\
} while(0)

#else
#define DO_SANITY_CHECK_MSK(MSK)
#endif

//#define CHECK_MINRESPONSELEN

//#define MIN_RESPONSELEN_ADJ_HACK 100
//#define MIN_RESPONSELEN_ADJUP_TEST

//#define DO_INTEGRITY_CHECK

#define DISABLE_SENDACKOVERFLOW

// #define FORCE_MSK_TRANSMIT_REORDERING

//#define FIXEDRTT (HZ/8)
//#define FIXEDRTT (HZ*2)

// Disable UCont layer to test Transport (Trickles congestion control)
// layer
// *** TRANSPORT_ONLY test has not been kept up-to-date
//#define TEST_TRANSPORT_ONLY


// #define TRACELOSS

#define ERROR printk

//#define DISABLE_FAST_RECOVERY

void hmac_setup(HMAC_CTX *ctx, char *key, int len);
void hmac_init(HMAC_CTX *ctx);
void hmac_update(HMAC_CTX *ctx, void *data, int len);
void hmac_final(HMAC_CTX *ctx, char *output);

#endif // OPENSSL_HMAC

/* END CRYPTO */

/* Imported kernel variables */

#ifndef USERTEST

extern struct tcp_func ipv4_specific;
extern struct or_calltable or_ipv4;

extern struct proto trickles_prot;
extern struct proto trickles_client_prot;
extern spinlock_t trickles_sockets_head_lock;
extern struct sock trickles_sockets_head;
#endif // USERTEST

/* Internal control flags */
extern int enableDataRecovery;
extern int serverDebugLevel;
extern int debugDrops;
extern int debugProofDrops;
extern int debugTransitions;
extern int clientDebugLevel;
extern int disableSevereErrors;
extern int printOverlap;
extern int disableTimeout;
extern int debugSimulation;

extern int userapi_pkt_spew;
extern int userapi_time_spew;

/* Internal debug counters */
extern __u64 numTxPackets;
extern __u64 numTxBytes;

extern __u64 numTxPackets;
extern __u64 numTxBytes;

/* Internal functions */

#define MINISOCK_LEN(RO_LEN) ((RO_LEN) / 4)
#define PMINISOCK_LEN(RO_LEN) ((RO_LEN) / 4)

#ifndef USERTEST
static inline void trickles_checksum(struct sk_buff *skb, int headerLen) {
	struct sock *sk = skb->sk;
#if 0
	printk("%X:%d => %X:%d\n", sk->saddr, (int)ntohs(skb->h.th->source), sk->daddr, 
	       (int)ntohs(skb->h.th->dest));
#endif
	if(skb->ip_summed == CHECKSUM_HW) {
		//printk("hw checksum\n");
		skb->h.th->check = 0;
		skb->h.th->check = ~tcp_v4_check(skb->h.th, skb->len, sk->saddr, sk->daddr,
					 0);
		skb->csum = offsetof(struct tcphdr, check);
	} else {
		skb->h.th->check = 0;
		skb->h.th->check = tcp_v4_check(skb->h.th, skb->len, sk->saddr, sk->daddr,
					 csum_partial((char*)skb->h.th, headerLen, skb->csum));
	}
}
#endif // USERTEST

void user_ack_impl(struct sock *sk);
void slow_start_timer(unsigned long data);
int trickles_send_ack_impl(struct sock *sk, int user_ctx);
int trickles_client_sendmsg(struct sock *sk, struct msghdr *msg, int size);
void computeMAC(struct sock *sk, PseudoHeader *phdr, const WireContinuation *cont, char *dest);

struct NonceCtx {
	int new;
	__u64 prevNumber;
	char prevBlock[NONCE_BLOCKSIZE];
};

__u32 generateSingleNonce(struct sock *sk, __u64 seqNum, struct NonceCtx *prevCtx);
__u32 generateRangeNonce(struct sock *sk, __u64 seqNumLeft, __u64 seqNumRight);


/* AckProof_checkRange returns the following */

enum CheckRangeResult {
  BADRANGE = 0,
  POISONEDRANGE  = -1,
  NORMALRANGE = 1
};

enum CheckRangeResult AckProof_checkRange(AckProof *proof, int left, int right);

int AckProof_update(struct sock *sk, AckProof *ackProof, CONTINUATION_TYPE *cont);
__u32 AckProof_findLeft(AckProof *proof, int start);
__u32 AckProof_findRight(AckProof *proof, int start);

int msk_transmit_skb(struct cminisock *msk, struct sk_buff *skb, int packet_num);

int server_rcv_impl(struct sock *sk, struct sk_buff *in_skb);
int client_rcv_impl(struct sock *sk, struct sk_buff *in_skb);

void zap_virt(void *address); // force unmap of page at address

/* Trickles malloc and free */

#ifdef MODULE
// XXX HACK
#define CAN_USE_TFREE
#endif // MODULE

#ifdef CAN_USE_TFREE
void *tmalloc(struct sock *sk, size_t size);
void tfree(struct sock *sk, void *ptr);
#endif // CAN_USE_TFREE

#endif // __KERNEL__ ???

#include "trickles_client.h"

#endif

#ifndef USERTEST
#include <net/cminisock.h>
#else
#include "cminisock.h"
#endif

#ifdef __KERNEL__

#include <net/../../net/ipv4/msk_table.h> // bad code alert

#ifndef MSKTABLE_NEW
struct MSKTable;
extern struct MSKTable *(*MSKTable_new)(int numEntries);
#endif // MSKTABLE_NEW

inline static void init_trickles_sock(struct sock *sk) {
	int i;
	struct tcp_opt *tp = &(sk->tp_pinfo.af_tcp);
	tp->trickles_opt = 0;
	tp->mac_changed = 0;

#ifndef USERTEST
	{
		memset(&tp->cminisock_api_config, 0, sizeof(tp->cminisock_api_config));
		init_head(&tp->cminisock_api_config.msk_freelist);

		tp->cminisock_api_config.cfg.ctl = NULL;

		tp->cminisock_api_config.event_lock = RW_LOCK_UNLOCKED;
	}
#endif
	tp->t.malloc_initialized = 0;

	tp->t.heapbytesize = 0;
	tp->t.heapbytesallocated = 0;

	for(i=0; i < BLOCKLOG; i++) {
		tp->t.fragblocks[i] = 0;
		tp->t.fraghead[i].next = tp->t.fraghead[i].prev = NULL;
	}

	tp->t.clientStateCounter = 0;
	tp->t.state    = TRICKLES_CLIENT_NORMAL;
	tp->t.A      = 0; // uninitialized
	tp->t.D      = 0; // uninitialized
	tp->t.RTO    = 0;
	tp->t.timerState = 0;
	tp->t.rcv_nxt  = 0;
	tp->t.previous_base = 0;
	skb_queue_head_init(&tp->t.ofo_queue);

	tp->t.ack_prev = NULL;

	//0430 - temporary instrumentation to find out assignment history to ack_prev
#ifdef SAVE_APHIST
	tp->t.aphist = kmalloc(ACK_PREV_HISTORY_ENTRIES * sizeof(struct cminisock), GFP_ATOMIC);
	if(tp->t.aphist == NULL) {
		printk("Out of memory while allocating aphist array\n");
		BUG();
	}
	memset(tp->t.aphist, 0, sizeof(tp->t.aphist));
	tp->t.aphistpos = 0;
#endif // SAVE_APHIST

	tp->t.ack_last = 0;
	tp->t.oo_count = 0;
	tp->t.in_flight = 0;

	tp->t.standardProof.numSacks = 0;
	tp->t.altProof.numSacks = 0;


	tp->t.dprev = tp->t.dnext = NULL;
	tp->t.dbg_skb = NULL;
	init_head(&tp->t.cont_list);
#ifndef USERTEST
	init_timer(&tp->t.slowstart_timer);
#endif

	// Request 0 = SYN
	tp->t.request_rcv_nxt = 0;
	tp->t.request_snd_nxt = 0;
	init_head(&tp->t.request_ofo_queue);
	skb_queue_head_init(&tp->t.data_ofo_queue);
	init_head(&tp->t.sentRequests);
	init_head(&tp->t.queuedRequests);

	init_head(&tp->t.dataRequestMap);
	init_head(&tp->t.missingDataMap);
	init_head(&tp->t.skipList);

	tp->t.byteReqNext = 0;
	tp->t.byteReqHint = NULL;
	tp->t.byteRcvNxt = 0;

	// initial conversion state is WAITFORSERVER because the
	// server pushes an initial continuation during a synack
	tp->t.conversionState = CONVERSION_WAITFORSERVER;
	tp->t.snd_una = tp->t.write_seq = 0;
	tp->t.snd_end = 0;
	skb_queue_head_init(&tp->t.requestBytes);
	tp->t.newIncompleteRequest = NULL;
	tp->t.prevConvCont = NULL;

	init_head(&tp->t.ucontList);
	init_head(&tp->t.depNodeList);

#if 0
	// for OpenSSL HMAC
	tp->t.hmacCTX = NULL;
#endif
	tp->t.nonceCTX = NULL;
	skb_queue_head_init(&tp->t.prequeueOverflow);
	skb_queue_head_init(&tp->t.sendAckOverflow);
	skb_queue_head_init(&tp->t.recycleList);

	tp->t.responseMSK = NULL;
	init_head(&tp->t.responseList);
	tp->t.responseCount = 0;

	tp->t.events = NULL;
	tp->drop_rate = 0;
	tp->instrumentation = 0;

	tp->t.numServers = 0;
	tp->t.probeRate = TRICKLES_DEFAULT_PROBE_RATE;
#if 0
	dlist_init_head(&tp->t.rpc_list);
#endif
	tp->t.requestNext = 0;

	tp->t.msk_table = MSKTable_new(MSK_TABLE_SIZE);
}

#endif // __KERNEL__

#include "trickles_userapi.h"

#ifdef __KERNEL__
#include "trickles_minisock_functions.h"

#include "trickles_alloc_opt.h"
#include "trickles_state_cache.h"

#endif // __KERNEL__

#undef _IN_TRICKLES_H
#endif // TRICKLES_H
