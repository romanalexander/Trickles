#ifdef __KERNEL__

// #include <linux/kernel.h>
#include <net/trickles.h>
#include <net/trickles_packet.h>
#include <net/cminisock.h>
#include <net/trickles_state_cache.h>
#include "cache_util.h"

#else

#include <string.h>
#include "util.h"
#include "continuation.h"
#define min(X,Y) ({ int __x = (X); int __y = (Y); __x < __y ? __x : __y; })
#define SELF_TEST

#endif // __KERNEL__

#ifdef __KERNEL__
	#ifdef SELF_TEST
	#error "Can't perform selftest with kernel compilation"
	#endif // SELF_TEST
#endif // __KERNEL__

#include "cache.h"

#if 1

#define MAX_CONTINUATION_BUCKETS 	(1024)
#define NUM_CONTINUATION 		(1024)

#else
#define MAX_CONTINUATION_BUCKETS 	(16)
#define NUM_CONTINUATION 		(16)
#endif

#define MAX_NONCE_BUCKETS  		(32)
#define NUM_NONCES  			(100)

#define CACHE_COMPARISON (0)

#define PRINT_STATS(LABEL)					\
	printk(#LABEL "\nLinksFollowed %d/%d Hitcount: %d / %d\nCell Memory %d/%d\n", (LABEL##_cache).linkCount, (LABEL##_cache).lookupCount, (LABEL##_cache).hitCount, (LABEL##_cache).total, LABEL##_cache.cellMem, LABEL##_cache.maxCellMem)

// N.B. Caches only kernel level information

// New parsed cache (higher performance)

//typedef __u32 cminisock_key;

struct pminisock_key {
#ifdef SOCKET_KEY
	struct sock *sk;
#endif
	__u32 seq;
};

struct cached_pminisock {
	struct pminisock *pmsk;
};

static inline struct pminisock_key pminisock_toKey(struct cached_pminisock *cmsk) {
	struct pminisock_key key;
#ifdef SOCKET_KEY
	key.sk = cmsk->msk->serverSK;
#endif
	key.seq = cmsk->pmsk->seq;
	return key;
}

static inline unsigned pminisock_hash(struct pminisock_key *key) {
	return hash((u1 *)&key->seq, sizeof(key->seq), 0);
}

static inline int pminisock_cmp(struct pminisock_key *k0, struct cached_pminisock *cmsk0,
				    struct pminisock_key *k1, struct cached_pminisock *cmsk1) {
	// printk("minisock keys: %d %d\n", *k0, *k1);
	return
#ifdef SOCKET_KEY
		k0->sk == k1->sk &&
#endif
		k0->seq == k1->seq;
}

// XXX Very ugly way to deal with dangling pointers inside cache !!!
// Currently, a socket does not know to purge the cache of entries
// that it owns. For now, the cache is purged after every element is
// purged, and before the data is deallocated

static void pminisock_evict(void *context, struct cached_pminisock *cmsk) {
	// printk("evict0\n");
	struct sock *sk = (struct sock *)context;
	if(cmsk->pmsk == NULL) {
		BUG();
	} else {
		BUG_TRAP(cmsk->pmsk->refCnt >= 1);
		pmsk_release(sk, cmsk->pmsk);
	}
	// printk("evict1\n");
	cmsk->pmsk = NULL;
}

#if 1
#define HAVE_INTEGRITY_OR_DIE()
#else
#define HAVE_INTEGRITY_OR_DIE() \
	ParsedPMinisock_integrityCheck()  ||				\
		( ERROR("integrity failure in %s", __PRETTY_FUNCTION__) && \
		  die());
#endif


#define ENCLOSING_CELL_VAR(CV,SV) struct ParsedPMinisock_cell *CV = ENCLOSING(struct ParsedPMinisock_cell, SV, SV)
#define VERIFY_HASH() ( (pminisock_hash(&cell->key) % ParsedPMinisock_cache.numBuckets) == i ) || ( ERROR("pminisock hash index integrity") && RETURN(0) )

NEW_CACHE_TYPE(ParsedPMinisock, struct pminisock_key, struct cached_pminisock,
	       MAX_CONTINUATION_BUCKETS,
	       NUM_CONTINUATION,
	       pminisock_toKey, pminisock_hash, pminisock_cmp, pminisock_evict);

#undef HAVE_INTEGRITY_OR_DIE
#undef ENCLOSING_CELL_VAR
#undef VERIFY_HASH

struct pminisock *pminisock_lookup(struct sock *sk, __u32 seqno, 
				   struct iphdr *iph, struct tcphdr *th) {
	struct ParsedPMinisock_cell *cell;
	struct pminisock_key key;

	ParsedPMinisock_cache.evictContext = sk;

#ifdef SOCKET_KEY
	key.sk = sk;
#endif
	key.seq = seqno;

	// printk("looking up seqno = %u\n", seqno);
	if(ParsedPMinisock_find_helper(&key, &cell)) {
#if 0
		if(CACHE_COMPARISON && (WireContinuation_inOutComp(cont, &cell->elem) != 0)) {
			printk("mismatch between input and continuation cache\n");;
			byte_diff(cont->hmac_start, cell->elem.copy_start, 
				  WIRECONT_MAC_LEN);
		}
		if(cont->tokenCounterBase != cell->elem.tokenCounterBase) {
			printk("Continuation (%d) hit, but %lld != %lld\n", cell->key, 
			       cont->tokenCounterBase, cell->elem.tokenCounterBase);
			return 0;
		}
#endif
		// Invariant: cache implies not in any event queue
		struct pminisock *pmsk = cell->elem.pmsk;
		BUG_TRAP(pmsk->refCnt == 1);

		if(!(  // seqno match is already verified
		     pmsk->daddr == iph->saddr &&
		     pmsk->dest == th->source)) {
			printk("flow validation failed\n");
			return NULL;
		}
		if(trickles_ratelimit()) {
			printk("Pminisock lookup does not perform validation yet\n");
		}

		// to enforce above invariant, we delete the cell from the cache
		ParsedPMinisock_deleteCell(cell);

		return pmsk;
	} else {
		// printk("Could not find\n");
	}
	return NULL;
}

// Invariant: When a minisocket is inserted into the cache, it MUST NOT be on any event list
int pminisock_insert(struct sock *sk, struct pminisock *pmsk) {
	BUG_TRAP(msk->refCnt >= 1);
	struct pminisock_key key;
#ifdef SOCKET_KEY
	key.sk = msk->serverSK;
#endif
	key.seq = pmsk->seq;
	// printk("Inserting %p with key %u\n", msk ,key);
	struct ParsedPMinisock_cell *cell = ParsedPMinisock_insert_helper(&key);
	if(cell != NULL) {
		pmsk_hold(pmsk);
		cell->elem.pmsk = pmsk;
		return 1;
	} else {
		return 0;
	}
}

void pminisock_evictN(int count) {
	BUG();
	//ParsedPMinisock_evict(count);
}

// XXXXXXXXXXXXXXXXXXXXX
// Old pre-parse cache code (low level, lower performance)
// XXXXXXXXXXXXXXXXXXXXX

typedef __u32 CachedWireContinuationKey;

static inline CachedWireContinuationKey seqnoToKey(__u32 seqno) {
	return ntohl(seqno);
}

static inline CachedWireContinuationKey CachedWireContinuation_toKey(struct CachedWireContinuation *msk) {
	return seqnoToKey(msk->hdr.seq);
}

static inline unsigned CachedWireContinuation_hash(CachedWireContinuationKey *key) {
	return hash((u1 *)key, sizeof(*key), 0);
}

static inline int CachedWireContinuation_cache_cmp(unsigned *k0, struct CachedWireContinuation *wcont0,
				    unsigned *k1, struct CachedWireContinuation *wcont1) {
	return *k0 == *k1;
}

static inline void CachedWireContinuation_evict(void *context, struct CachedWireContinuation *cwc) {
	// do nothing
}

typedef __u64 NonceKey;
struct NonceMap {
	NonceKey key;
	char output[NONCE_BLOCKSIZE];
};

static inline NonceKey nonce_toKey(struct NonceMap *map) {
	return map->key;
}

static inline unsigned nonce_hash(NonceKey *key) {
	return hash((u1 *)key, sizeof(*key), 0);
}

static inline int nonce_cmp(NonceKey *k0, struct NonceMap *map0,
			    NonceKey *k1, struct NonceMap *map1) {
	return *k0 == *k1;
}

static inline void nonce_evict(void *context, struct NonceMap *m) {
	// do nothing
}

#if 0
#define HAVE_INTEGRITY_OR_DIE()				\
	if(DEBUG_LEVEL >= INTEGRITY_LEVEL) {		\
		Continuation_integrityCheck()  ||			\
		( ERROR("integrity failure in %s", __PRETTY_FUNCTION__) && \
		  die());						\
	}
#else
#define HAVE_INTEGRITY_OR_DIE()
#endif

#define ENCLOSING_CELL_VAR(CV,SV) struct Continuation_cell *CV = ENCLOSING(struct Continuation_cell, SV, SV)
#define VERIFY_HASH()							\
	( (CachedWireContinuation_hash(&cell->key) % Continuation_cache.numBuckets) == i ) || \
	( ERROR("hash index integrity %X %X, %d %d", cell->key,		\
		CachedWireContinuation_hash(&cell->key),			\
		CachedWireContinuation_hash(&cell->key) % Continuation_cache.numBuckets, \
		i) && RETURN(0) )

NEW_CACHE_TYPE(Continuation, CachedWireContinuationKey, struct CachedWireContinuation,
	       MAX_CONTINUATION_BUCKETS,
	       NUM_CONTINUATION,
	       CachedWireContinuation_toKey,
	       CachedWireContinuation_hash,
	       CachedWireContinuation_cache_cmp,
	       CachedWireContinuation_evict);

#undef HAVE_INTEGRITY_OR_DIE
#undef ENCLOSING_CELL_VAR
#undef VERIFY_HASH


#define HAVE_INTEGRITY_OR_DIE()				\
	if(DEBUG_LEVEL >= INTEGRITY_LEVEL) {		\
		NonceKey_integrityCheck()  || die();	\
	}
#define ENCLOSING_CELL_VAR(CV,SV) struct NonceKey_cell *CV = ENCLOSING(struct NonceKey_cell, SV, SV)
#define VERIFY_HASH() ( (nonce_hash(&cell->key) % NonceKey_cache.numBuckets) == i ) || ( ERROR("hash index integrity") && RETURN(0) )

NEW_CACHE_TYPE(NonceKey, __u64, struct NonceMap,
	       MAX_NONCE_BUCKETS,
	       NUM_NONCES,
	       nonce_toKey, nonce_hash, nonce_cmp, nonce_evict);

#undef HAVE_INTEGRITY_OR_DIE
#undef ENCLOSING_CELL_VAR
#undef VERIFY_HASH

void StateCache_init(void) {
	ParsedPMinisock_cache_init();
	Continuation_cache_init();
	NonceKey_cache_init();

	// check cache alignment
	printk("cache stride is %d\n", 
	       (char*)&ParsedPMinisock_cache.buckets[1] -
	       (char*)&ParsedPMinisock_cache.buckets[0]);
}

void StateCache_invalidate(void) {
	ParsedPMinisock_cache_invalidate();
	Continuation_cache_invalidate();
	NonceKey_cache_invalidate();
}

void StateCache_resize(int size) {
	StateCache_invalidate();
	ParsedPMinisock_cache.maxCount = size;
	printk("State cache resized to %d\n", ParsedPMinisock_cache.maxCount);
}

void StateCache_destroy(void) {
	ParsedPMinisock_cache_destroy();
	Continuation_cache_destroy();
	NonceKey_cache_destroy();
}

// Check Continuation cache for a WireContinuation with the same sequence number
// If a continuation is found:
//    Fill continuation with contents of matching WireContinuation in the cache
//    return true
// Else:
//    return false
// Side-effect: Continuation is removed from the continuation cache

static inline void 
WireContinuation_copyIn(struct CachedWireContinuation *c, 
			struct WireContinuation *dcont,
			const CONTINUATION_TYPE *scont) {
	PseudoHeader *phdr = &c->hdr;
	MAC_GEN_PHDR();

	memcpy(c->copy_start, dcont->hmac_start, WIRECONT_MAC_LEN);
}

static inline int 
WireContinuation_checkAndCopyOut(struct WireContinuation *w, 
			 struct CachedWireContinuation *c,
			struct iphdr *iph, struct tcphdr *th) {
	PseudoHeader *phdr = &c->hdr;
	if(phdr->seq == w->seq && // seqno match is already verified
	   phdr->type == w->continuationType &&
	   phdr->first == w->firstChild &&
	   phdr->serverAddr == iph->daddr &&
	   phdr->serverPort == th->dest &&
	   phdr->clientAddr == iph->saddr &&
	   phdr->clientPort == th->source &&
	   w->tokenCounterBase == c->tokenCounterBase) {
		memcpy(w->hmac_start, c->copy_start, WIRECONT_MAC_LEN);
		return 1;
	} else {
		return 0;
	}
}

static inline int
WireContinuation_inOutComp(struct WireContinuation *w, 
			   struct CachedWireContinuation *c) {
	return memcmp(w->hmac_start, c->copy_start, WIRECONT_MAC_LEN);
}

int WireContinuation_lookup(struct WireContinuation *cont, 
			    struct iphdr *iph, struct tcphdr *th) {
	CachedWireContinuationKey key = seqnoToKey(cont->seq);
	struct Continuation_cell *cell;
	if(Continuation_find_helper(&key, &cell)) {
#if 0
		if(CACHE_COMPARISON && (WireContinuation_inOutComp(cont, &cell->elem) != 0)) {
			printk("mismatch between input and continuation cache\n");;
			byte_diff(cont->hmac_start, cell->elem.copy_start, 
				  WIRECONT_MAC_LEN);
		}
		if(cont->tokenCounterBase != cell->elem.tokenCounterBase) {
			printk("Continuation (%d) hit, but %lld != %lld\n", cell->key, 
			       cont->tokenCounterBase, cell->elem.tokenCounterBase);
			return 0;
		}
#endif
		if(!WireContinuation_checkAndCopyOut(cont, &cell->elem, iph, th)) {
			if(trickles_ratelimit()) {
				printk("Sequence number and flow ID did not match\n");
				return 0;
			}
		}
#if 0
		if(trickles_ratelimit()) {
			printk("isolating memory corruption\n");
		}
		return 1;
#endif
		Continuation_deleteCell(cell);

		return 1;
	}
	//printk("Continuation (%d) missed\n", cont->seq);
	return 0;
}

void WireContinuation_insert(struct WireContinuation *wcont, const CONTINUATION_TYPE *scont) {
	CachedWireContinuationKey key = seqnoToKey(wcont->seq);
	struct Continuation_cell *cell = Continuation_insert_helper(&key);
	if(cell != NULL) {
		WireContinuation_copyIn(&cell->elem, wcont, scont);
	}
}

void dump_cache_stats(void) {
	PRINT_STATS(ParsedPMinisock);
	PRINT_STATS(Continuation);
}

// USER LEVEL SELF-TEST

#ifdef SELF_TEST
#ifdef PROTOCOL_TRACE_TEST

struct WireContinuationElement {
	struct alloc_head *prev;
	struct alloc_head *next;
	struct alloc_head_list *list;

	struct WireContinuation cont;

	// propagate ack proof to the next element
	int ackProof;
	int left, right;
};

#endif // PROTOCOL_TRACE_TEST

void nonceFunc(__u64 seqno, char *output) {
	// output is NONCE_BLOCKSIZE long
	(NONCE_BLOCKSIZE % sizeof(__u64) == 0)|| die();
	for(i=0; i < NONCE_BLOCKSIZE)
}

__u32 generateNonce(__u64 seqno) {
	// generate nonce uses the nonce cache

	// make sure that the cache returns the correct value
	if(found) {
		if(value != nonceFunc(xxx)) {
			die();
		}
	}
}

// stress tests: manipulate the number of buckets and the number of elements

int main() {
	StateCache_init();

	// base functionality test -- insertion, deletion
	int leak_count; // run the test multiple times to test for leaks
	for(leak_count = 0; leak_count < NUM_LEAK_LOOPS; leak_count++) {
#define TESTVEC_LEN (32)
		int testvec_key[TESTVEC_LEN] = {
			1, 103, 1233, 2794, 5528, 4302, 8038, 8301, 4884, 1879, 5608, 8106, 6695, 4484, 4449, 1783, 6025, 2903, 7114, 7215, 9785, 7665, 5413, 6642, 7781, 1981, 2019, 6686, 8439, 5386, 3462, 3974
		};
		struct WireContinuation insertions[TESTVEC_LEN]; // int insertion tests
	{
		int i;
		for(i=0; i < TESTVEC_LEN; i++) {
			memset(&insertions[i], 0, sizeof(insertions[i]));
			insertions[i].seq = testvec_key[i];
			insertions[i].TCPBase = 
				insertions[i].tokenCounterBase = 0;
		}
	} // int i

	{
		int i;
		int test;
		for(test = 0; test <= 2; test++) {
			int remove = (test == 0);
			int expected = 0;

			int remove_some = (test == 2);
			int remove_stride = 10;
			printk("Running test %d\n", test);

			for(i=0; i < TESTVEC_LEN; i++) {
				int key = testvec_key[i];
				struct WireContinuation result;
				struct WireContinuation *input = &insertions[i];

				// keep everything at minimum count
				(Continuation_getCount() == expected) || die();
				// should not be present
				Continuation_find(&key, NULL) && die();
				Continuation_insert(input);
				(Continuation_getCount() == min(expected + 1, NUM_CONTINUATION)) || die();
				// should be found
				Continuation_find(&key, &result) || die();
				Continuation_find(&key, &result) || die();
				expected = min(expected + 1, NUM_CONTINUATION);
				if(remove || (remove_some && (i % remove_stride) == 0)) {
					WireContinuation_compare(input, &result) || die();
					Continuation_delete(&key); // should not be found
					expected--;
				}
			}
			PRINT_STATS(Continuation -- after steady insertion, 
				    Continuation_cache);
			printk("Final count after iteration %d: %d\n",
				test, Continuation_getCount());
			(expected == Continuation_evict(expected)) || die();
			(Continuation_getCount() == 0) || die();
		}
	} // int i

#if 0
		// increment 
		// 1) keys are generated as incremental values
		// 2) input cminisocks are shared
		while() {
			count() == expected;
			_find(); // should not be present
			_insert();
			count() == expected + 1;
			_find(); // should be found
			_delete(); // should not be found
			_insert(); // put it back in
			count() == expected + 1;
			expected += 1;
		}
#endif
	}
	PRINT_STATS(Continuation -- after big insertion, 
		    Continuation_cache);
	// XXX duplicate the continuation test code for nonces

#ifdef PROTOCOL_TRACE_TEST
	// test this only if the kernel code doesn't work

	// kernel-like workload (simulate the order of operations
	//    that would be generated by a single Trickles connection)

	__u64 seqNo = 0; // sequence numbers need to be disjoint
			 // between tests to avoid contamination
	Continuation_evict(everything);
#define MAX_WINDOW (5)

	int window;
	for(window = 1; window <= MAX_WINDOW; window++) { // 1,2,3,4,5
		// assumption: always have window continuations in flight
		// splitting should not make a major difference
		struct WireContinuationElement input_worklist;
		sturct WireContinuationElement output_worklist;
		// bootstrap
	{
		int i;
		for(i=0; i < window; i++) {
			// claim next window sequence numbers
			xxx fill worklist output;
		}
	}

		while (!empty(&worklist_output)) {
			worklist_input = worklist_output;
			if(REORDER) {
				xxx;
			}
			while(!empty(&worklist_input)) {
				dequeue(&worklist_input);
				// Request processing order:
				//   perform cache lookup
				_find();
				if(success) {
					compare with input (should be identical) ;
				}
				// verify nonce
				if(cont.ackProof != (generateNonce(cont.left) ^ 
						     generateNonce(cont.right + 1))) {
					die();
				}
				// compute & insert successor continuations
				successor = cont.seq + window;
				cont.left = cont.startSeq;
				cont.right = cont.seq;
				cont.ackProof = generateNonce(cont.left) ^
					generateNonce(cont.right);
				// add some random noise to the other
				// fields
				cont.noise = xxx;
				_insert(successor);
				insert(&output_worklist, successor);
			}
		}
	}
#endif // PROTOCOL_TRACE_TEST
	return 0;
}

#endif // SELF_TEST
