#include "trickles-int.h"

#include "memdump-util.h"

#include "cache_util.h"

#define LOG_RECOVERY (0)

// #define PRINT_TRANSMIT_CONT

static void dump_sk(struct sock *sk, int lineno) {
	struct tcp_opt *tp = &(sk->tp_pinfo.af_tcp);
	printk("At %d: %X:%d => %X:%d\n", lineno, sk->saddr, (int)ntohs(sk->sport), sk->daddr, (int)ntohs(sk->dport));
}

int userapi_pkt_spew = 0;
int userapi_time_spew = 0;

__u64 numTxPackets = 0;
__u64 numTxBytes = 0;

int debugSimulation = 0;

int gNormalCount = 0;
int gRecoveryCount = 0;
int gSlowStartCount = 0;

int gIsServer = 1;

extern const int dbgBadChunk;

extern int gNumRecoveryStates;
extern int gNumBootstrapStates;
extern int gNumBootstrapResponses;

static struct cminisock cpu_msk[NR_CPUS];

#define CURR_CPU_MSK(SK) ({					\
	struct cminisock *__msk = &cpu_msk[smp_processor_id()]; \
	msk_initStatic(__msk);				\
	__msk;						\
})

#ifndef USERTEST
void queue_upcall_msk_prealloc(struct sock *sk, enum cminisock_event_tag, struct cminisock *msk);
void queue_upcall_msk(enum cminisock_event_tag, struct cminisock *msk);

void queue_upcall_pmsk_prealloc(struct sock *sk, enum cminisock_event_tag, struct pminisock *msk);
void queue_upcall_pmsk(enum cminisock_event_tag, struct pminisock *msk);

void queue_upcall_deliver(struct sock *sk);

#endif // USERTEST

static int ExecuteTrickle(struct sock *sk, struct sk_buff *skb, enum cminisock_event_tag event);

/*
 *
 * Trickles Server state machine
 *
 */

#ifdef USE_FLOATINGPOINT
#define QUAD(SIGN,a,b,c) (-(b) SIGN sqrtf((b) * (b) - 4*(a)*(c))) / (2 * a)
#define COMPUTE_CWND(SSTHRESH, TCPBASE, SEQ) \
   QUAD(+, 1.0/2.0, 1.0/2.0, -((int)(SSTHRESH) * ((int)(SSTHRESH) + 1)) / 2.0 - (SEQ) + (TCPBASE));
#else
static unsigned int mborg_isqrt4(unsigned long val) {
 unsigned int temp, g=0;

  if (val >= 0x40000000) {
    g = 0x8000; 
    val -= 0x40000000;
  }

#define INNER_MBGSQRT(s)                      \
  temp = (g << (s)) + (1 << ((s) * 2 - 2));   \
  if (val >= temp) {                          \
    g += 1 << ((s)-1);                        \
    val -= temp;                              \
  }

  INNER_MBGSQRT (15)
  INNER_MBGSQRT (14)
  INNER_MBGSQRT (13)
  INNER_MBGSQRT (12)
  INNER_MBGSQRT (11)
  INNER_MBGSQRT (10)
  INNER_MBGSQRT ( 9)
  INNER_MBGSQRT ( 8)
  INNER_MBGSQRT ( 7)
  INNER_MBGSQRT ( 6)
  INNER_MBGSQRT ( 5)
  INNER_MBGSQRT ( 4)
  INNER_MBGSQRT ( 3)
  INNER_MBGSQRT ( 2)

#undef INNER_MBGSQRT

  temp = g+g+1;
  if (val >= temp) g++;
  return g;
}

#define QUAD(SIGN,a,b,c) (-(b) SIGN mborg_isqrt4((b) * (b) - 4*(a)*(c))) / (2 * a)

// TODO: Improve precision?
/*
 * Fixed point computation with a fast square root is a bit tricky. 
 * We perform the square root at .(2*PREC) precision, after which the datatype becomes
 * .(PREC) (since the scaling factor is taken to ^-0.5)

     In floating point, the expression is 
      - (1/2) + sqrt((1/2)^2 - 4*1/2*(-(ssthresh*(ssthresh+1)/2 - *(seq - TCPBase))))
*/

#define PREC (1)
#define COMPUTE_CWND(SSTHRESH, TCPBASE, SEQ) \
	(((-1 << (PREC - 1)) + mborg_isqrt4((1 << (2*PREC - 2)) - ((-((int)(ssthresh) * ((int)(ssthresh) + 1)) - 2 * (((int)seq) - (TCPBase))) << (2*PREC)))) >> PREC)
#endif // USE_FLOATINGPOINT

#define MAX_CWND ((1<<13)-1)
#define CLAMP(X) (MIN((X),MAX_CWND))

// TODO: Investigate using -msoftfloat, or saving/restoring FPU state
// while processing interrupts

int AckTCPCwnd(unsigned seq, const CONTINUATION_TYPE *cont, int *hintResult) {
  int res, hint = -1;
  // hint is processed as a relative offset in the body, then converted to an absolute offset just before returning
  unsigned startCwnd = cont->startCwnd;
  unsigned ssthresh = MIN(MAX(cont->ssthresh, startCwnd), MAX_CWND);
  unsigned TCPBase = cont->TCPBase;
  unsigned additiveStart = (ssthresh - startCwnd + TCPBase) + ssthresh;

#ifdef ACKTCP_CWND_SPEED_HACK
  seq = TCPBase + (seq - TCPBase) * ACKTCP_CWND_SPEED_HACK;
#endif

  if(seq < TCPBase) {
    if(!disableSevereErrors) 
      ERROR("Seq (%u) < TCPBase (%u)\n", seq, TCPBase);
    res = -1;
    goto done;
  }

#if 0
  // obsolete test
  if(seq - TCPBase > MAX_CWND * MAX_CWND) {
	  printk("Exceeded max limit without renormalizing\n");
	  res = -1;
	  goto done;
  }
#endif
  if(seq < ssthresh - startCwnd + TCPBase) {
    res = startCwnd + (seq - TCPBase);
  } else if(ssthresh - startCwnd + TCPBase <= seq &&
	    seq < additiveStart) {
    res = ssthresh;
  } else {
	  /* result is solution to x(x+1)-ssthresh(ssthresh+1)
                                   --------------------------- - N
                                                2                  */
	  //int offset = seq - TCPBase;
	  int offset = seq - additiveStart;
#ifdef USE_SQRT
	  int position, cwnd;
	  //double a = 1.0/2.0, b = 1.0/2.0, c = -((int)ssthresh * ((int)ssthresh + 1)) / 2.0 - seq + TCPBase;
	  cwnd = COMPUTE_CWND(ssthresh, TCPBase, seq);
	  
	  //val = 1/4 - (-((int)(ssthresh) * ((int)(ssthresh) + 1)) - 2 * (((int)seq) - (TCPBase)))
	  //printk("sqrt(%d) = %d\n", val, mborg_isqrt4(val));

	  cwnd = CLAMP(cwnd);
	  position = (cwnd*(cwnd+1)-ssthresh*(ssthresh+1)) / 2;
	  if(cwnd == MAX_CWND) {
		  res = cwnd;
		  hint = - 1;
	  } else {
		  if(offset >= position) {
			  int cwnd_1 = CLAMP(cwnd + 1),
				  cwnd_2 = CLAMP(cwnd + 2);
			  if(offset < position + cwnd_1) {
				  res = cwnd_1;
				  hint = additiveStart + position + cwnd_1;
			  } else {
				  if(!(offset < position + cwnd_1 + cwnd_2)) {
#ifndef DISABLE_ACKTCPCWND_WARNINGS
					  BUG_TRAP(0);
#endif
				  }
				  res = cwnd_2;
				  hint = additiveStart + position + cwnd_1 + cwnd_2;
			  }
		  } else if(offset < position) {
			  if(offset > position - cwnd) {
				  res = cwnd;
				  hint = additiveStart + position;
			  } else {
				  if(!(offset > position - cwnd - (cwnd - 1))) {
#ifndef DISABLE_ACKTCPCWND_WARNINGS
					  BUG_TRAP(0);
#endif
				  }
				  if((cwnd - 1) < ssthresh) {
#ifndef DISABLE_ACKTCPCWND_WARNINGS

					  BUG_TRAP(0);
#endif
				  }
#ifndef DISABLE_ACKTCPCWND_WARNINGS
				  BUG_TRAP(cwnd - 1 >= 1);
#endif
				  res = cwnd - 1;
				  hint = additiveStart + position - cwnd;
			  }		  
		  }
	  }
#else
	  // Fixed point Newton's method to solve (cwnd*(cwnd+1) - ssthresh*(ssthresh+)) / 2 = 
#define FRAC (2)
	  int i;
	  static int numIterations, count = 0;
	  //long long x;
	  typedef int FIXEDPT_TYPE;
	  FIXEDPT_TYPE x, oldX[32];;
	  // Special case: offset > max clamp
	  if(offset >= (MAX_CWND * (MAX_CWND + 1) - ssthresh*(ssthresh+1)) / 2) {
		  res = MAX_CWND;
		  goto done;
	  }

	  /* Newton iteration:
	     x_{k+1} = x_k - f(x_k)/f'(x_k) */
	  // set initial guess to maximum possible value to avoid converging to wrong root	  
	  x = (MAX_CWND) << FRAC;
#define MAX_NEWTON_ITERATIONS (sizeof(FIXEDPT_TYPE) * 8)
	  for(i=0; i < MAX_NEWTON_ITERATIONS; i++) {
		  FIXEDPT_TYPE cwnd, xupdate;
		  unsigned position;
		  cwnd = x >> FRAC;

#if 0
		  printk("offset = %d ssthresh = %d x_%d: %d ", offset, ssthresh, i, x >> FRAC);
		  printk("f(x_%d) * 2 = %d (%d %d %d) ", i, (x * (x + (1 << FRAC)) - (((int)ssthresh * ((int)ssthresh + 1) + 2 * offset) << (2 * FRAC))) >> (2 * FRAC), x * (x + (1 << FRAC)), (((int)ssthresh * ((int)ssthresh + 1) + 2 * offset)) << (2 * FRAC), (x * (x + (1 << FRAC)) - (((int)ssthresh * ((int)ssthresh + 1) + 2 * offset) << (2 * FRAC))));
		  printk("f'(x_%d) * 2 = %d ", i, (2 * x + (1 << FRAC)) >> FRAC);
		  printk("f/f' = %d ", ((x * (x + (1 << FRAC)) - (((int)ssthresh * ((int)ssthresh + 1) + 2 * offset) << (2 * FRAC))) /
					 (2 * x + (1 << FRAC))));
		  printk("\n");
#endif
		  position = (cwnd*(cwnd+1)-ssthresh*(ssthresh+1)) / 2;
		  if(offset - position >= 0 && 
		     offset - position < cwnd + 1) {
			  res = CLAMP(cwnd + 1);
			  hint = additiveStart + position + res;

			  if(i > numIterations || count == 100000) {
			    numIterations = i;
			    printk("%d iterations - result = %d\n", i, cwnd);
			    if(count == 100000) count = 0;
			  }
			  count++;
			  goto done;
		  } else if(position - offset > 0 &&
			    position - offset < cwnd) {
			  res = CLAMP(cwnd);
			  hint = additiveStart + position;

			  if(i > numIterations || count == 100000) {
			    numIterations = i;
			    printk("%d iterations - result = %d\n", i, cwnd);
			    if(count == 100000) count = 0;
			  }
			  count++;
			  goto done;
		  }
		  xupdate = (x - 
		       ((x * (x + (1 << FRAC)) - (((int)ssthresh * ((int)ssthresh + 1) + 2 * offset) << (2 * FRAC))) /
			(2 * x + (1 << FRAC))));
		  oldX[i] = x;
		  if(xupdate == x) {
			  int sign0 = ((int)ssthresh * ((int)ssthresh + 1) + 2 * offset) > 0 ? 1 : -1,
				  sign1 = (2 * x + (1 << FRAC)) > 0 ? 1 : -1;
			  x -= (sign0 * sign1) << FRAC;
		  } else {
			  x = xupdate;
		  }
	  }
	  printk("AckTCPCwnd SQRT: Too many iterations: x = %d f(x) = %d f'(x) = %d offset = %d ssthresh * (ssthresh+1) = %d, %d \n", 
		 x >> FRAC, 
		 (x * (x + (1 << FRAC)) - (((int)ssthresh * ((int)ssthresh + 1) + 2 * offset) << (2 * FRAC))) >> (2 * FRAC), 
		 ((2 * x) >> FRAC) + 1,
		 offset, 
		 ssthresh*(ssthresh+1), 
		 (((int)ssthresh * ((int)ssthresh + 1) + 2 * offset))/2);
	  for(i = 0; i < MAX_NEWTON_ITERATIONS; i++) {
		  printk("X_%d = %d\n", i, oldX[i]);
	  }
	  res = (-(1 << (FRAC-1)) + x) >> FRAC;

#endif
#undef FRAC
  }
  done:
	  ;
  if(res > MAX_CWND)
	  res = MAX_CWND;
  if(hintResult != NULL)
    *hintResult = (hint >= 0) ? hint : -1;
  ((CONTINUATION_TYPE*)cont)->mark = res; // tricklesLossEvent gets cwnd size from here
  return res;
}

inline int AckTCPCwndScalar(unsigned seq, const CONTINUATION_TYPE *cont) {
	return AckTCPCwnd(seq, cont, NULL);
}

int Sack_validate(CONTINUATION_TYPE *cont, Sack *sack) {
  if(sack->left > sack->right) {
    return 0;
  }
  /* Verify that cumulative nonce matches sack range */
  if(!DISABLE_NONCE_CHECK) {
    __u32 genNonce = generateRangeNonce(cont->sk, sack->left, sack->right);
    if(genNonce != sack->nonceSummary) {
#ifdef DISABLE_NONCE_FAIL // 0715 - this was old code used force side effect from generateRangeNonce() without actually performing nonce check
      static volatile int w;
      w++;
#else
      if(trickles_ratelimit()) {
	printk("nonce check failed for [%d-%d] = 0x%0X != 0x%0X\n", 
	       sack->left, sack->right, genNonce, sack->nonceSummary);
      }
      return 0;
#endif
    }
  }
#if 0
  if(trickles_ratelimit()) {
	  printk("nonce check succeeded\n");
  }
#endif
  return 1;
}

inline int Sack_contains(Sack *sack, int seq) {
  return sack->left <= seq && seq <= sack->right;
}

inline int Sack_gapLen(Sack *left, Sack *right) {
  return right->left - left->right - 1;
}

inline int Sack_adjacent(Sack *left, Sack *right) {
  return Sack_gapLen(left, right) == 0;
}

int AckProof_isPoisoned(AckProof *proof, Sack *sack) {
  /* For now, always return 0 */
  return 0;
}

int AckProof_validate(AckProof *proof) {
  int i;
  CONTINUATION_TYPE *cont = proof->cont;
  Sack *sacks = proof->sacks;
  int numSacks = proof->numSacks;
  // 0714 MAXSACKS is appropriate here (e.g., NOT MAX_KERNEL_SACKS) because 
  // this numSacks comes from the wire
  if(numSacks == 0 || numSacks > MAXSACKS || 
     sacks[0].left > cont->TCPBase) {
	  if(!disableSevereErrors)
		  printk("Zero sacks (%d), too many sacks, or start (%u) > TCPBase (%u) [seq = %u]\n", numSacks, sacks[0].left, cont->TCPBase, cont->seq);
    return 0;
  }
  for(i=0; i < numSacks; i++) {
    if(!Sack_validate(cont, &sacks[i])) {
      return 0;
    }
    if(i > 0 && sacks[i].left <= sacks[i-1].right) {
      return 0;
    }
  }
  return 1;
}

/* Note: FirstLoss considers poisoned nonces as present */
int AckProof_firstLoss(AckProof *proof) {
  int i, numSacks = proof->numSacks;
  Sack *sacks = proof->sacks;
  for(i=1; i < numSacks; i++) {
    if(!Sack_adjacent(&sacks[i-1], &sacks[i])) {
      return sacks[i-1].right + 1;
    }
  }
  ERROR("No loss!\n");
  return -1;
}

enum CheckRangeResult AckProof_checkRange(AckProof *proof, int left, int right) {
  int i;
  int cursor;
  int poisoned = 0;
  Sack *sacks = proof->sacks;
  /* Check if AckProof covers the desired range */
  cursor = left;
  for(i=0; i < proof->numSacks; i++) {
    if(Sack_contains(&sacks[i], cursor)) {
      if(AckProof_isPoisoned(proof, &sacks[i])) {
	poisoned = 1;
      }
      cursor = sacks[i].right + 1;
      if(cursor > right) break;
    }
  }
  if(i == proof->numSacks) {
    return BADRANGE;
  }
  return poisoned ? POISONEDRANGE : NORMALRANGE;
}

__u32 AckProof_findRight(AckProof *proof, int start) {
  int i;
  int cursor;
  int poisoned = 0;
  Sack *sacks = proof->sacks;
  /* Check if AckProof covers the desired range */
  cursor = start;
  for(i=0; i < proof->numSacks; i++) {
    if(Sack_contains(&sacks[i], cursor)) {
      if(AckProof_isPoisoned(proof, &sacks[i])) {
	poisoned = 1;
      }
      cursor = sacks[i].right + 1;
    }
  }
  if(cursor > start) 
	  return cursor - 1;
  else
	  return start - 1; // error condition
}

__u32 AckProof_findLeft(AckProof *proof, int start) {
  int i;
  int cursor;
  int poisoned = 0;
  Sack *sacks = proof->sacks;
  /* Check if AckProof covers the desired range */
  cursor = start;
  for(i=proof->numSacks - 1; i >= 0; i--) {
    if(Sack_contains(&sacks[i], cursor)) {
      if(AckProof_isPoisoned(proof, &sacks[i])) {
	poisoned = 1;
      }
      cursor = sacks[i].left - 1;
    }
  }
  if(cursor < start) 
	  return cursor + 1;
  else
	  return start + 1; // error condition
}

static int DoNormalStep(CONTINUATION_TYPE **cont, AckProof *ackProof, enum cminisock_event_tag event);
static int DoRecoveryStep(CONTINUATION_TYPE **cont, AckProof *ackProof, enum cminisock_event_tag event);
static int DoSlowStartStep(CONTINUATION_TYPE **cont, AckProof *ackProof, __u32 newBase, enum cminisock_event_tag event);

void AckProof_dump(AckProof *proof) {
	int i;
	printk("proof(%d) = ", proof->numSacks);
	for(i = 0; i < proof->numSacks; i++) {
		printk("[%d-%d]", proof->sacks[i].left, proof->sacks[i].right);
	}
	printk("\n");
}

WireTrickleRequest *WireTrickleRequest_extract(struct sock *serverSK, struct sk_buff *skb, struct cminisock **pmsk, int *error) {
	int sacks_len;
	WireTrickleRequest *req = (WireTrickleRequest*)skb->data;

	int ucont_len, input_len;
	char *ucont_data = NULL, *input = NULL;

	struct cminisock *msk = CURR_CPU_MSK(serverSK);
	struct pminisock *lookup, *packed_msk;
	*pmsk = NULL;

	*error = EINVAL;
#define D(X) 
	D(printk("1\n"));
	if(!pskb_may_pull(skb, sizeof(*req))) {
		if(trickles_ratelimit()) {
			printk("SKB too short for WireTrickleRequest, len = %d\n", skb->len);
		}
		return NULL;
	}

	D(printk("2\n"));
	__skb_pull(skb, sizeof(*req));
	/* Handle variable length fields */
	sacks_len = req->ackProof.numSacks * sizeof(WireSack);

	// 0714 MAXSACKS is appropriate here (e.g., NOT MAX_KERNEL_SACKS) because 
	// value comes from wire
	if(!(req->ackProof.numSacks <= MAXSACKS &&
	     pskb_may_pull(skb, sacks_len))) {
		printk("SKB too short for WireTrickleRequest (either too many sacks, or not enough space in packet header for sacks\n");
		goto free_and_return;
	}
	__skb_pull(skb, sacks_len);
	D(printk("3\n"));

	ucont_len = ntohs(req->ucont_len);
	if(!pskb_may_pull(skb, ucont_len)) {
		printk("WireTrickleRequest_extract: skb too short for ucont\n");
		goto free_and_return;
	}
	D(printk("4\n"));
	if(!SIMULATION_MODE(serverSK)) {
		D(printk("5\n"));
		if(ucont_len > 0) {
			ucont_data = tmalloc(serverSK, ucont_len);
			
			if(ucont_data == NULL) {
#if 0
				if(trickles_ratelimit()) {
					printk("WireTrickleRequest_extract: Out of memory while copying ucont\n");
				}
#endif
				*error = ENOMEM;
				goto free_and_return;
			}
			char *pkt_ucont_data;
			memcpy(ucont_data, pkt_ucont_data = (char*)skb->data, ucont_len);
			__skb_pull(skb, ucont_len);
		} else {
			ucont_data = NULL;
		}
	} else {
		D(printk("6\n"));

		ucont_len = 0;
		ucont_data = NULL;
	}

	BUG_TRAP(skb->len >= 0);
	if(!SIMULATION_MODE(serverSK)) {
		D(printk("7\n"));
		input_len = skb->len;
		//printk("input len = %d @ %d\n", msk->input_len, (char*)&msk->input_len - (char*)msk);
		if(input_len > 0) {
			input = tmalloc(serverSK, input_len);
			D(printk("7.1\n"));
			if(input == NULL) {
#if 0
				if(trickles_ratelimit()) {
					printk("WireTrickleRequest_extract: Out of memory while copying Conversion data\n");
				}
#endif
				*error = ENOMEM;
				goto free_and_return;
			}
			memcpy(input, (char*)skb->data, input_len);
		} else {
			D(printk("7.2\n"));
			input = NULL;
		}
	} else {
		D(printk("8\n"));
		input_len = 0;
		input = NULL;
	}

#define FINISH_MSK()				\
	msk->ucont_len = ucont_len;		\
	msk->ucont_data = ucont_data;		\
	ucont_data = NULL;			\
						\
	msk->input_len = input_len;		\
	msk->input = input;			\
	input = NULL;

	/* Now possible to decode msk */
	__u32 seqno = ntohl(req->cont.seq);
	if(trickles_ratelimit()) {
		printk("continuation cache forced off\n");
	}
	if(!SIMULATION_MODE(serverSK) && 
	   0 && sysctl_trickles_Continuation_enable) {
		D(printk("9\n"));
		if(( lookup = pminisock_lookup(serverSK, seqno,
					skb->nh.iph, skb->h.th)) != NULL) {
			D(printk("10\n"));
			struct WireContinuation *scont = &req->cont;

			// Fields that may not propagate from the cache
			// seq, firstChild, clientState, parent, clientTimestamp

			msk->sk = msk->serverSK = serverSK;
			unmarshallContinuationServerPMSK2MSK(serverSK, msk, lookup);
			msk->pmsk = packed_msk = lookup;

			// these fields need to be copied from the client-speciifed cont, since they are modified at the client
			msk->seq = ntohl(scont->seq);
			msk->firstChild = packed_msk->firstChild = 
				scont->firstChild;
			msk->clientState = packed_msk->clientState = 
				scont->clientState;
			msk->parent = packed_msk->parent = 
				scont->parent;
			msk->clientTimestamp = packed_msk->clientTimestamp = 
				scont->clientTimestamp;

			BUG_TRAP(msk->saddr == skb->nh.iph->daddr &&
				 msk->daddr == skb->nh.iph->saddr &&
				 msk->source == skb->h.th->dest &&
				 msk->dest == skb->h.th->source);

			BUG_TRAP(msk->ctl == ALLOC_PENDING);

			FINISH_MSK();
		} else {
			D(printk("11\n"));
			//printk("couldn't find %d\n", seqno);
			// DELAY();
			goto lookup_failed;
		}
	} else {
	lookup_failed:
		D(printk("12\n"));
		if(!SIMULATION_MODE(serverSK)) {
			msk = CURR_CPU_MSK(serverSK);
		} else {
			msk = alloc_trickles_msk(serverSK);
		}
		skb->sk = msk->sk = msk->serverSK = serverSK;
		packed_msk = alloc_trickles_pmsk(serverSK);
		if(packed_msk == NULL) {
			printk("no space for pmsk in extract\n");
			return NULL;
		}
		msk->pmsk = packed_msk;
		if(!unmarshallContinuationServerMSK(skb, msk, &req->cont)) {
			/* MAC error */
			if(trickles_ratelimit())
				printk("Mac error\n");
			goto free_and_return;
		}
		FINISH_MSK();
	}
	D(printk("14\n"));

	//printk("msk->input_len = %d\n", msk->input_len);
	*error = 0;
	*pmsk = msk;
	return req;
#undef FREE
 free_and_return:
	D(printk("13\n"));
	if(ucont_data != NULL) {
		tfree(serverSK, ucont_data);
	}
	if(input != NULL) {
		tfree(serverSK, input);
	}
	if(msk != NULL) {
		free_trickles_msk(serverSK, msk);
		free_trickles_msk_finish(serverSK, msk);
	}
	return NULL;

}

static inline void pre_init_sock(struct cminisock *msk, struct sk_buff *skb) {
	/* save the fields necessary for a later init_sock */
	if(!SIMULATION_MODE(msk->sk)) {
		msk->saddr = skb->nh.iph->daddr;
		msk->source = skb->h.th->dest;

		msk->daddr = skb->nh.iph->saddr;
		msk->dest = skb->h.th->source;
	}
}

#ifndef USERTEST
void DoUpcall(struct cminisock *msk, enum cminisock_event_tag event) {
	int i;
	struct NonceCtx ctx;
	if(!SIMULATION_MODE(msk->sk)) {
		int responseLen = 0;
		ctx.new = 1;
		//printk("packets base = %p\n", msk->packets);
		for(i=0; i < msk->num_packets; i++) {
			msk->packets[i].nonce = generateSingleNonce(msk->sk, msk->packets[i].seq, &ctx);
			msk->packets[i].ucontLen = 0;
			msk->packets[i].ucontData = NULL;
#ifdef CHECK_MINRESPONSELEN
			responseLen += msk->packets[i].len;
#else
			// touch responseLen to suppress compiler warnings
			responseLen = 0;
#endif
			//printk("packet[%d].len = %x (%p)\n", i, msk->packets[i].len, &msk->packets[i].len);
		}
		PACKET_TRACE_LOG_DO(
		    ({
			    int i;
			    printk("%d => {", msk->seq);
			    for(i=0; i < msk->num_packets; i++) {
				    printk(" %d ", msk->packets[i].seq);
				    if(i < msk->num_packets-1) {
					    printk(",");
				    }
			    }
			    printk("}");
		    }));
#ifdef CHECK_MINRESPONSELEN
		EQ_TEST(msk->simulationLen, responseLen);
		EQ_TEST(msk->simulationNumPackets, 
			msk->num_packets);
#if 0
		printk("len = %d,%d num_packets = %d,%d\n", 
		       msk->simulationLen, responseLen,
		       msk->simulationNumPackets, msk->num_packets);
#endif
#endif

		LOG_PACKET_CONTONLY(msk);
		
		unmarshallContinuationServerMSK2PMSK(msk->sk, msk->pmsk, msk);
#if 0
		printk("unmarshall continuation pmsk num_packets = %d msk num_packets = %d\n", 
		       msk->pmsk->num_packets, msk->num_packets);
#endif

		queue_upcall_pmsk_prealloc(msk->sk,event,msk->pmsk);
		queue_upcall_pmsk(event,msk->pmsk);

		// temporary backwards compatible rpc interface
		struct cminisock *copy = shallow_copy_msk(msk->serverSK, msk);
		if(copy == NULL) {
			printk(" ran out of memory just before upcall\n");
			free_trickles_msk(msk->serverSK, msk);
			free_trickles_msk_finish(msk->serverSK, msk);
			return;
		}
		queue_upcall_msk_prealloc(msk->sk,event,copy);
		queue_upcall_msk(event,copy);
		// printk("upcall seq is %d\n", msk->seq);

		queue_upcall_deliver(msk->sk);
	}
}
#endif

void  recordNewPacketContType(int contType);

static inline int doInitialCwnd(struct cminisock *msk, enum cminisock_event_tag tag, int seqno, int num_packets) {
	if(tag == SYN) {
		msk->ucont_len = 0;
		//printk("syn processing input_len = %d\n", msk->input_len);

		msk->clientState = 0;
		msk->mrtt = 0;

		// these values (firstLoss, firstBootstrapSeq) are not used in normal state ( syn/ack )
		msk->firstLoss = 0x1055;
		msk->firstBootstrapSeq = 0xb007;
		
		msk->ssthresh = 0x3fff; // small enough to prevent overflow when squaring
	}
	msk->TCPBase = seqno;

	if(!alloc_msk_packets(msk, num_packets)) {
		return -ENOMEM;
	}
	int i, first = 1;
	for(i=0; i < num_packets; i++) {
		__u32 seq = seqno + i;
		//printk("syn making seq %d\n", seq);
		makePacket(&msk->packets[i], seq, 1, TRICKLES_MSS, 
			   (first ? PTYPE_FIRST : 0) | PACKET_NORMAL, CONTTYPE_FULL1,
			   1 * TRICKLES_MSS,  -1, 1);
		recordNewPacketContType(CONTTYPE_FULL1);
		first = 0;
	}
	msk->num_packets = num_packets;
	//printk("msk (%p) num packets in syn is %d\n", msk, msk->num_packets);
	DoUpcall(msk, tag);
	return 0;
}

int server_rcv_impl(struct sock *sk, struct sk_buff *in_skb) {
	// if(!SIMULATION_MODE(sk)) printk("server received packet\n");
	int rval = -EINVAL;
	struct tcphdr *ith = in_skb->h.th;
	struct tcp_opt *tp = &(sk->tp_pinfo.af_tcp);
	struct cminisock *msk;

	if(0 && !SIMULATION_MODE(sk)) {
		static int count;
		printk("server_rcv_impl: %d\n", count++);
	}

	if(!SIMULATION_MODE(sk)) {
		START_PACKET();
	}

	TIMING_CTX_DEF0("server_rcv_impl", "");
	TIMING_CTX_DEF1(4);
	reinitTimingCtx(&ctx);
	recordSample(&ctx,0);

	if(!SIMULATION_MODE(sk) && !TRICKLES_USERAPI_CONFIGURED_TP(tp)) {
		printk("Not configured\n");
		goto out;
	}

#define ALLOC()								\
	if(SIMULATION_MODE(sk)) {					\
		msk = alloc_trickles_msk(sk);				\
	} else {							\
		msk = CURR_CPU_MSK(sk);			\
	}								\
									\
	msk->serverSK = sk;						\
	msk->sk = sk;							\
	in_skb->sk = sk;						\
									\
	pre_init_sock(msk,in_skb);

	recordSample(&ctx,0);
	if(SIMULATION_MODE(sk)) {
		goto normal;
	}
	if(ith->syn) {
		ALLOC();
		__u32 firstSeq;
		/* SYN packet format:
		 * Initial request continuation immediately follows TCP
		 * header
		 */
		if(ith->ack) {
			printk("warning: trickles server cannot handle syn/ack\n");
		}
		firstSeq = 1; // XXX Should be randomized

		msk->tokenCounterBase = tp->bigTokenCounter;
		tp->bigTokenCounter += ((__u64) 1)  << 32;

		int num_packets;

		msk->input_len = in_skb->len;
		//printk("msk->input_len = %d\n", msk->input_len);
		if(msk->input_len > 0) {
			// piggybacked data
			msk->input = tmalloc(in_skb->sk, msk->input_len);
			// printk("allocated piggy input to %p\n", msk->input);
			if(msk->input == NULL) {
				if(trickles_ratelimit()) {
					printk("Could not allocate memory for SYN, len = %d\n", msk->input_len);
				}
				goto out;
			}
			memcpy(msk->input, (char*)in_skb->data, msk->input_len);
			num_packets = msk->startCwnd = INITIAL_CWND;
		} else {
			// not piggybacked data
			msk->input = NULL;
			num_packets = 1;
			SET_DEFERRED_INITIALCWND(msk);
		}
		msk->pmsk = alloc_trickles_pmsk(sk);
		if(msk->pmsk == NULL) {
			goto out;
		}

		// printk("initial cwnd with %d\n", num_packets);
		if(doInitialCwnd(msk, SYN, firstSeq, num_packets) != 0)
			goto out;
	} else if(ith->fin) {
		/* FIN packet format:
		   WireTrickleRequest */
		/* Sequence number generation */
		recordSample(&ctx,0);
		printk("FIN execute trickle\n");
		ExecuteTrickle(sk, in_skb, FIN);
	} else if(ith->rst) {
		/* TODO: Implement reset handling */
		PACKET_TRACE_FINISH();
		return 0;
	} else {
	normal:
		//printk("Normal execute trickle\n");
		/* normal operation */
		recordSample(&ctx,0);
		ExecuteTrickle(sk, in_skb, ACK);
	}
#undef ALLOC
	recordSample(&ctx,0);
	//printTimings(&ctx);
	PACKET_TRACE_FINISH();
	return 0;
 out_dealloc_msk:
	if(rval != -ENOMEM) {
		// ENOMEM deallocates msk in callees. This is a hostorical artifact
		free_trickles_msk(sk,msk);
		free_trickles_msk_finish(sk,msk);
	}
 out:
	PACKET_TRACE_FINISH();
	return rval;
}

#if 0
#define SIMULATIONMODE_INIT() int simPrintCount = 0
#define SIMULATIONMODE_PRINT() if(SIMULATION_MODE(skb->sk)) /*printk("simulation mode : %d\n", simPrintCount++)*/ 
#else
#define SIMULATIONMODE_INIT()
#define SIMULATIONMODE_PRINT()
#endif

#if 0
#define DUMP_INPUTLEN()   printk("cont input len = %d @ %s:%d\n", (*cont)->input_len, __FILE__, __LINE__)
#else
#define DUMP_INPUTLEN()
#endif

static int ExecuteTrickle(struct sock *sk, struct sk_buff *skb,
			  enum cminisock_event_tag event) {
	//printk("executeTrickle ServerDebugLevel = %d\n", serverDebugLevel);
  int rval = -EINVAL;

  int error;
  AckProof ackProof;
  struct cminisock *cont;
  WireTrickleRequest *treq_hdr =
	  WireTrickleRequest_extract(sk, skb, &cont, &error);

  if(treq_hdr == NULL) {
    if(error == EINVAL) {
      if(trickles_ratelimit()) {
	printk("ExecuteTrickle: Could not find request header, or mac failed\n");
      }
      return -EINVAL;
    } else {
      BUG_TRAP(error == ENOMEM);
      return -ENOMEM;
    }
  }
  
  if(cont == NULL) {
	  if(trickles_ratelimit())
		  printk("out of memory\n");
	  return -ENOMEM;
  }

  enum CheckRangeResult rangeCheck;
  DUMP_INPUTLEN();

  SIMULATIONMODE_INIT();

  TIMING_CTX_DEF0("ExecuteTrickle", "");
  TIMING_CTX_DEF1(7);
  reinitTimingCtx(&ctx);
  recordSample(&ctx,0);
  cont->executionTrace = 0;

#ifdef PROPAGATE_ACKSEQ
  if(!SIMULATION_MODE(cont->sk)) {
	  cont->ack_seq = skb->h.th->ack_seq;
#ifdef CHECK_MINRESPONSELEN
	DECODE_SIMULATION_RESULT(skb->h.th->seq,
				 &cont->simulationLen,
				 &cont->simulationNumPackets);
#endif
	  cont->dbg_timestamp = jiffies;
  }
#endif

  recordSample(&ctx,0);
  SIMULATIONMODE_PRINT();
  unmarshallAckProof(&ackProof, &treq_hdr->ackProof);
  DUMP_INPUTLEN();
  ackProof.cont = cont;
  recordSample(&ctx,0);
  if(!SIMULATION_MODE(cont->sk) && !AckProof_validate(&ackProof)) {
    /* Bad nonce, or doesn't start at TCPBase */
    if(SIMULATION_MODE(skb->sk)  && debugSimulation)
      printk("ackproof validation failed\n");
    return -EINVAL;
  }

  SIMULATIONMODE_PRINT();
  recordSample(&ctx,0);
  if(serverDebugLevel >= 2) {
    printk("Server processing: %u\n", cont->seq);
    AckProof_dump(&ackProof);
  }

  /* Determine continuation mode */
  SIMULATIONMODE_PRINT();
  rangeCheck = AckProof_checkRange(&ackProof, cont->TCPBase, cont->seq);
  recordSample(&ctx,0);

  //printk("RequestType %d\n", treq_hdr->type);
  switch((enum TrickleRequestType)treq_hdr->type) {
  case TREQ_NORMAL: {
    // mrtt_1 = mrtt_0 * 7/8 + delta * 1/8
    cont->mrtt -= cont->mrtt >> 3;
    cont->mrtt += jiffies - cont->timestamp;

#ifdef RTT_INCLUDES_USER
    UPDATE_TIMESTAMP(cont);
#endif

  DUMP_INPUTLEN();
    switch(cont->state) {
    case CONT_NORMAL:
      if(serverDebugLevel >= 2)
        printk("Normal request => Normal state\n");
      switch(rangeCheck) {
      case NORMALRANGE:
	if(serverDebugLevel >= 2)
	  printk("  Normal Range\n");
	SIMULATIONMODE_PRINT();
#ifdef STOMP_CONNECTIONS
#define STOMP()								\
	if(!SIMULATION_MODE(skb->sk) &&					\
           cont->seq - cont->TCPBase >= STOMP_CONNECTIONS) {	\
	/* if(trickles_ratelimit()) {				\
		  printk("Stomping connection from %X:%d\n", (*cont)->daddr, (*cont)->dest); \
	  } */							\
	  return -EINVAL;							\
	}
#else
#define STOMP()
#endif
        STOMP();
	rval = DoNormalStep(&cont, &ackProof, event);
	recordSample(&ctx,0);
	break;
      case POISONEDRANGE:
      case BADRANGE:
	if(serverDebugLevel >= 2) {
	  printk("  Bad or poisoned Range (ack # %u)\n", cont->seq);
	  AckProof_dump(&ackProof);
	}
	rval = DoRecoveryStep(&cont, &ackProof, event);
	break;
      }
      break;
    case CONT_RECOVERY:
      if(serverDebugLevel >= 1)
	printk("Normal request => Recovery state\n");
      gNumRecoveryStates++;
      switch(rangeCheck) {
      default:
	// no action
	break;
      }
      break;
    case CONT_BOOTSTRAP:
      if(serverDebugLevel >= 1)
	printk("Normal request => Bootstrap state\n");
      gNumBootstrapStates++;
      switch(rangeCheck) {
      case POISONEDRANGE:
	if(serverDebugLevel >= 1)
	  printk("  Poisoned Range\n");
	// check that poison is only during recovery interval
	if(!(AckProof_checkRange(&ackProof, cont->TCPBase, cont->firstLoss-1) == NORMALRANGE
	     && AckProof_checkRange(&ackProof, cont->firstBootstrapSeq, cont->seq) == NORMALRANGE)) {
	  ERROR("poisoned packets where normal packets should be\n");
	  goto slow_start;
	}
      case NORMALRANGE:
	if(serverDebugLevel >= 1)
	  printk("  Normal Range\n");
	cont->TCPBase = cont->firstBootstrapSeq;
	if(serverDebugLevel >= 1)
	  printk("Bootstrap: TCPBase = %u CWND = %u SSTHRESH = %u\n", cont->TCPBase, cont->startCwnd, cont->ssthresh);
	STOMP();
	rval = DoNormalStep(&cont, &ackProof, event);
	break;
      case BADRANGE:
	if(serverDebugLevel >= 1)
	  printk("  Bad Range\n");
      slow_start:
	if(serverDebugLevel >= 1) {
		printk("slow start bad range: ");
		AckProof_dump(&ackProof);
	}
	rval = DoRecoveryStep(&cont, &ackProof, event);
	break;
      default:
	printk("  unknown state\n");
	return -EINVAL;
      }
      break;
    }
    break;
  }
  case TREQ_SLOWSTART: {
    __u32 seq;
    cont->mrtt = (jiffies - cont->timestamp) << 3;

#ifdef RTT_INCLUDES_USER
    UPDATE_TIMESTAMP(cont);
#endif

    if(serverDebugLevel >= 1) {
      printk("Slow Start request => \n");
      AckProof_dump(&ackProof);
    }
    seq = AckProof_findRight(&ackProof, cont->TCPBase);
    if(seq < cont->TCPBase) {
	    printk("  SlowStart: seq < cont->TCPBase\n");
	    return -EINVAL;
    }
    rval = DoSlowStartStep(&cont, &ackProof, seq + 1, event);
    break;
  }
  default:
    printk("  unknown request type\n");
  }

  recordSample(&ctx,0);
  //printTimings(&ctx);
  return rval;
}

extern int gNumSentBytes;
extern int gNumSentPackets;

extern int gNumFull;
extern int gNumHash;
extern int gNumMinimal;

void  recordNewPacketContType(int contType) {
	if(contType & CONTTYPE_HASHCOMPRESSED) {
		gNumHash++;
	} else {
		switch(contType) {
		case CONTTYPE_MINIMAL:
			gNumMinimal++;
			break;
		case CONTTYPE_FULL1:
		case CONTTYPE_FULL2:
			gNumFull++;
			break;
		default:
			printk("recordNewPacketContType: unknown continuation type\n");
		}
	}
}

int msk_transmit_skb(struct cminisock *msk, struct sk_buff *skb, int packet_num) {
	// dump_sk(msk->sk, __LINE__);
	//DO_SANITY_CHECK_MSK(msk);
	static int packetID = 0;

	int tcp_header_size;
	struct tcphdr *th;
	struct sock *sk;

#ifdef FORCE_MSK_TRANSMIT_REORDERING
	static struct sk_buff *reorder_skb = NULL;
#endif

#ifndef USERTEST
	struct tcp_func *af = &ipv4_specific;
#endif

	struct WireTrickleResponse *resp_hdr;
	int err;
	struct cminisock_packet *packet = &msk->packets[packet_num];
	int ucontLen = packet->ucontLen;
	int origSkbLen = skb->len;

#ifdef SANITY_CHECK_RANGEHEADER
	//printk("sanity checking range header\n");
	int printedoutput = 0;
	static int lastChunkID = -999;
	if(dbgBadChunk && ucontLen == 0 && skb->len >= sizeof(struct DataChunk)) {
		struct DataChunk *chunk = (struct DataChunk*)skb->data;
		int dataLen = DATA_LEN(chunk);
		if(dataLen > skb->len) {
			printk("Warning: Data chunk length exceeds skb length\n");
			printk("Packet %d(%d : id=%d) Chunk ID %d lastChunkID = %d => length %d ", 
			       packet_num, skb->len, packetID, 
#ifdef CHUNKID
			       chunk->chunkID, 
#else
			       -1,
#endif
			       lastChunkID,
			       dataLen);
			printk("skb_len = %d type = %d\n", skb->len, packet->type);
			//hexdump(chunk, (char*)skb->tail - (char*)chunk);
		}
		//printk("Packet %d(%d : id=%d) Chunk ID %d => length %d\n", packet_num, skb->len, packetID, /* chunk->chunkID */ -1, dataLen);
		printedoutput = 1;
#ifdef CHUNKID
		lastChunkID = chunk->chunkID;
#endif
	}
	if(ucontLen > 0) {
		//printk("Packet id=%d: ucont_len = %d\n", packetID, ucontLen);
		printedoutput = 1;
	}
	if(dbgBadChunk && !printedoutput) {
		int inferred_type = msk->tag;
		printk("Packet id=%d: no output, len = %d, inferred_type = %d\n", packetID, skb->len, inferred_type);
	}
#endif

	//printk("msk_transmit ucontLen[%d] = %d\n", packet_num, ucontLen);

	sk = skb->sk = msk->sk;

	//printk("msk_transmit_skb: skb len(%d) stcp len(%d)\n", skb->len, tcb->stcp_len);
	if(userapi_time_spew)
		printk("transmit time: %lu\n", jiffies);
#ifndef RTT_INCLUDES_USER
	msk->timestamp = jiffies;
#endif

	/* UCONT handling */
	BUG_TRAP(ucontLen >= 0);
	if(ucontLen > 0) {
		if(packet->ucontData != NULL) {
			memcpy(skb_push(skb, ucontLen),
			       packet->ucontData, ucontLen);
		} else {
			// Do nothing; already in the packet
		}
	}

#if 0
	printk("seq (%d) [%d,%d] = { ", packet->seq, skb->tail - skb->data, 
	       packet->contType);
	ResponseChunk_printAll(skb->data, skb->tail - skb->data);
	printk(" } ");
#endif
	gNumSentBytes += skb->len;
	gNumSentPackets++;

	if(packet->contType & CONTTYPE_HASHCOMPRESSED) {
		int fullType;
		struct WireContinuation *wcont;
		static struct WireContinuation scratch[NR_CPUS]; // avoid stack allocation (which risks stack overflow), and kmalloc, which is inefficient
		struct WireContinuation *wc_scratch = &scratch[smp_processor_id()];

		resp_hdr = (WireTrickleResponse*)skb_push(skb, RESPONSELEN_HASHCOMPRESS);
		wcont = &resp_hdr->cont;
		
		/* mask off hashcompressed bit to verify type */
		packet->contType &= ~CONTTYPE_HASHCOMPRESSED;
		fullType = packet->contType == CONTTYPE_FULL1 ||
			packet->contType == CONTTYPE_FULL2;
		BUG_TRAP(fullType ||
			 packet->contType == CONTTYPE_MINIMAL);
		// restore hashcompressed bit
		packet->contType |= CONTTYPE_HASHCOMPRESSED;

		wcont->continuationType = packet->contType;
		wcont->hash.seq = htonl(packet->seq);
		wcont->hash.parentSeq = msk->seq;

		wcont->hash.timestamp = htonl(msk->timestamp);
		wcont->hash.mrtt = htonl(msk->mrtt);

		// marshall continuation to get mac value
		if(fullType) {
			// do this for all "FULL" continuation types
			packet->contType &= ~CONTTYPE_HASHCOMPRESSED;
			marshallContinuationServer(sk, wc_scratch, msk, packet_num);
#ifdef PRINT_TRANSMIT_CONT
			WireContinuation_print(&wc_scratch);
#endif // PRINT_TRANSMIT_CONT

			packet->contType |= CONTTYPE_HASHCOMPRESSED;

			memcpy(wcont->hash.mac, wc_scratch->mac, HMACLEN);
		}
	} else {
		//printk("%d:msk_transmit_skb(%d), %d\n", (int)jiffies, skb->len, packet->seq);
		switch(packet->contType) {
		case CONTTYPE_MINIMAL:
			resp_hdr = (WireTrickleResponse*)skb_push(skb, RESPONSELEN_MINIMAL);
			resp_hdr->cont.seq = htonl(packet->seq);
			resp_hdr->cont.continuationType = CONTTYPE_MINIMAL;
			resp_hdr->cont.clientState = msk->clientState;
			resp_hdr->cont.parent = msk->parent;
			resp_hdr->cont.clientTimestamp = msk->clientTimestamp;
			break;
		case CONTTYPE_FULL1:
		case CONTTYPE_FULL2:
			/* Generate Trickle header */
			resp_hdr = (WireTrickleResponse*)skb_push(skb, sizeof(WireTrickleResponse));
			marshallContinuationServer(sk, &resp_hdr->cont, msk, packet_num);
#ifdef PRINT_TRANSMIT_CONT
			WireContinuation_print(&resp_hdr->cont);
#endif // PRINT_TRANSMIT_CONT

			// printk("sent seq %d\n", ntohl(resp_hdr->cont.seq));
	// Insert continuation into continuation cache

	/* NOTE:
	   The design here is a bit tricky.
	   
	   We want to reuse the existing msk where possible.  However,
	   we need to keep it unmodified until we're completely done
	   generating results. We record some position where the recycled
	   msk should be used (cacheRecycleIndex), and patch this up
	   in the caller (the {f,t}iov handler)
	*/
			if(sysctl_trickles_Continuation_enable) {
				if(HAS_VALID_CACHERECYCLEINDEX(msk->pmsk)) {
					pminisock_cache_child(msk->serverSK, msk, 
							      msk->pmsk, packet_num, CACHE_CHILD_COPY | CACHE_CHILD_CLEAR);
				} else {
					// delay reuse until later
					msk->pmsk->cacheRecycleIndex = msk->cacheRecycleIndex = packet_num;
					BUG_TRAP(packet_num == msk->pmsk->cacheRecycleIndex);
				}
			}
			break;
		default:
			resp_hdr = NULL;
			BUG();
		}
	}
	resp_hdr->nonce = packet->nonce;

	resp_hdr->ucont_len = htons((short)ucontLen);
	//printk("resphdr->ucont_len = %d\n", resp_hdr->ucont_len);
	resp_hdr->numSiblings = packet->numSiblings;
	resp_hdr->position = packet->position;

	// ByteNum in data chunks are now constructed at user level
	// E.G., the chunk descriptors are inlined with the data

	//printk("transmit_skb - resp_hdr: %p, ucont_len\n", &resp_hdr->cont, ntohs(resp_hdr->ucont_len));

	// printk("len=%d\n", skb->len);
	tcp_header_size = sizeof(struct tcphdr) + TCPOLEN_TRICKLES;
	th = (struct tcphdr *) skb_push(skb, tcp_header_size);
	skb->h.th = th;
	th->source = sk->sport;
	th->dest = msk->dest;

	// th->seq = htonl(msk->seq);
	th->seq = htonl(packet->seq);
#ifdef TRACELOSS
	printk("%d ", packet->seq);
#endif

	// 0615 - mark each packet with a unique identifier so we know exactly how many packets were sent
	static int gSendPacketNumber = 0;
	// save debugging information
	if(sysctl_dbg_cwnd) {
		trickles_logCwnd_hook(CWND_RECORD, 
				      msk->daddr, msk->dest, packet->seq,
				      gSendPacketNumber,
				      msk->startCwnd, msk->mark /* effCwnd */, msk->ssthresh,
				      msk->mrtt, msk->mrtt);
	}
	th->ack_seq = packetID;
	//LOG_PACKET(sk, th->ack_seq);
	packetID++;

	// set tcp header size and zero out flags 
	th->doff = tcp_header_size >> 2;
	th->res1= 0;
	th->cwr = 0;
	th->ece = 0;
	th->urg = 0;

	th->ack = 1;
	th->psh = 0;
	th->rst = 0;
	th->syn = 0;
	th->fin = 0;

	// TODO: Find uses for window, urg_ptr fields
	th->window = 0;
	th->check = 0;
	th->urg_ptr = 0;
	*(__u32*)(th+1) = htonl((TCPOPT_TRICKLES << 24)  | 
				(TCPOLEN_TRICKLES << 16) |
				((__u16)(sizeof(WireTrickleResponse) + msk->ucont_len)));

	switch(msk->tag) {
	case SYN:
		if(packet_num == 0) {
			th->syn = 1; // send syn/ack
			th->ack = 1;
		} else {
			goto ack;
		}
		break;
	case FIN:
		printk("sending fin\n");
		th->fin = 1;
		break;
	case ACK:
	ack:
		th->ack = 1;
		break;
	default:
		printk("msk_transmit_skb: unsupported event tag\n");
	}

	numTxPackets++;
	numTxBytes += skb->len;

	if(LOG_RECOVERY && msk->state == CONT_RECOVERY) {
		printk("%d/%d: len=%d\n", msk->seq, packet->seq, skb->len);
	}

	BUG_TRAP(sk->protocol == IPPROTO_TCP);
#if 0
	printk("Trickles checksum\n");
	dump_sk(skb->sk, __LINE__);
#endif
	trickles_checksum(skb, skb->len - origSkbLen);
	err = af->queue_xmit(skb, 0);

#if 0
	static int lastSeq = 0;
	printk("%d(%d) ", packet->seq, err);
	lastSeq = packet->seq;
#endif

	return err;
}



/*
  Sequence #
  State
  **Recovery:
  firstLoss
  firstBootstrapSeq

  **AckTCPCwnd
  startCwnd
  ssthresh
  TCPBase */

void NormalizeContinuation(CONTINUATION_TYPE *cont, AckProof *ackProof) {
#if 0
  // TODO: Disabled normalization code for now because Normalization complicates TCP update calculation
	unsigned seq = cont->seq;
	if(seq - cont->TCPBase > MAX_CWND * MAX_CWND) {
		int cwnd;
		// make sure normalization of parallel threads results in the same new TCPBase
		__u32 right = AckProof_findRight(ackProof, cont->TCPBase),
			newSeq = cont->TCPBase + MAX_CWND * MAX_CWND;
		BUG_TRAP(right >= cont->TCPBase);
		BUG_TRAP(newSeq <= right);
		cwnd = AckTCPCwndScalar(newSeq, cont);
		if(cwnd < 0) {
			printk("Bad CWND in normalizeContinuation\n");
			return;
		}
		cont->startCwnd = cwnd;
		cont->TCPBase = newSeq;
		printk("Warning: Normalization is not correct yet!\n");
	}
#endif
}

#ifdef USE_INCREMENTAL_CWND
 __u32 AckTCPHint(__u32 prevCwnd, __u32 *hint, __u32 seq, CONTINUATION_TYPE *cont) {
	__u32 currCwnd;
	// Updates result for next call to AckTCPHint
	if(*hint != -1) {
		/* Compute update starting from hint */
		currCwnd = prevCwnd;
		if(seq >= *hint) {
			int delta = seq  - *hint, ticks = 0;
			currCwnd = CLAMP(currCwnd + 1);
			if(currCwnd < cont->ssthresh) {
				currCwnd = CLAMP(MIN(cont->ssthresh, 
						     currCwnd + delta));
				delta -= currCwnd - prevCwnd;
			}
			while(delta >= currCwnd) {
				ticks++;
				BUG_TRAP(currCwnd >= cont->ssthresh);
				delta -= currCwnd;
				currCwnd = CLAMP(currCwnd + 1);
			}
			if(currCwnd < cont->ssthresh) {
				*hint = seq + 1;
			} else {
				*hint = seq + (-delta);
			}
		}
	} else {
		/* Compute from scratch */
		currCwnd = AckTCPCwndScalar(cont->seq, cont);
	}
	return currCwnd;
}
#endif // USE_INCREMENTAL_CWND

// CONTTYPE and FIRST_ACKSEQ macros need to be consistent. The
// potential pitfall is that the first_ackseq  computation assumes that a 
// conttype_full2 packet  follows a MINIMAL packet, and so requires -1 adjustment.
// However, if full1_interval is even, then conttype_full2 packet will be preceded by some
// kind of full packet.

#define FIRST_ACKSEQ(CONTTYPE, SEQ)			\
    ((CONTTYPE) == CONTTYPE_FULL2 ? (SEQ) - 1 : (SEQ))
#if 1
#define FULL1_INTERVAL (7) // must be odd, otherwise
#define CONTTYPE(OFFSET) (((OFFSET) < FULL1_INTERVAL) ? CONTTYPE_FULL1 : \
			  ((((OFFSET)) % 2 == 0) ? CONTTYPE_FULL2 : \
			   CONTTYPE_MINIMAL))
#else
    // disable delayed acks
#define CONTTYPE(OFFSET) (CONTTYPE_FULL1)
#endif 


static int DoNormalStep(CONTINUATION_TYPE **cont, 
			 AckProof *ackProof, 
			 enum cminisock_event_tag event) {
  //printk("doNormalStep ServerDebugLevel = %d\n", serverDebugLevel);
	gNormalCount++;
  int i, numPackets = 0;
  __u32 first_ack_seq = 
    FIRST_ACKSEQ((*cont)->continuationType, 
		 (*cont)->seq), firstResponseSeq;
  int prevCwnd, currCwnd;
  int numOutput;
  int first = 1, thisResponseLen = 0, hint;
  __u32 offset;

  if(IS_DEFERRED_INITIALCWND(*cont)) {
	  //printk("deferred\n");
	  (*cont)->startCwnd = INITIAL_CWND;
	  return doInitialCwnd(*cont, event, (*cont)->seq + 1, (*cont)->startCwnd);
  }

  (*cont)->executionTrace = 1;

  TIMING_CTX_DEF0("DoNormalStep", "");
  TIMING_CTX_DEF1(7);
  reinitTimingCtx(&ctx);
  recordSample(&ctx,0);

  prevCwnd = (first_ack_seq == (*cont)->TCPBase) ? 
    (*cont)->startCwnd : 
    AckTCPCwnd(first_ack_seq - 1, (*cont), &hint);
  recordSample(&ctx,0);

#ifndef USE_INCREMENTAL_CWND
  currCwnd = AckTCPCwndScalar((*cont)->seq, (*cont));
#else
  currCwnd = AckTCPHint(prevCwnd, &hint, (*cont)->seq, (*cont));
#endif
  (*cont)->actualCwnd = currCwnd;

  //printk("prevCwnd: %u currCwnd: %u - ", prevCwnd, currCwnd);
  recordSample(&ctx,0);
  numOutput = MAX(0, currCwnd - (int)prevCwnd);

  switch((*cont)->continuationType) {
  case CONTTYPE_FULL1:
    numOutput += 1;
    break;
  case CONTTYPE_FULL2:
    numOutput += 2;
    break;
  default:
    BUG();
  }

  if(prevCwnd < 0 || currCwnd < 0) {
    /* error in AckTCPCwnd; return without generating output */
    if(trickles_ratelimit()) {
	    ERROR("Error in acktcpcwnd base = %d %d=>%d %d=>%d\n", 
		  (*cont)->TCPBase,
		  first_ack_seq - 1, prevCwnd, 
		  (*cont)->seq, currCwnd);
    }
    free_trickles_msk((*cont)->sk,*cont);
    free_trickles_msk_finish((*cont)->sk,*cont);
    return -EINVAL;
  }
  if(numOutput < 0) {
    ERROR("Decrease in AckTCPCwnd\n");
    numOutput = 0;
  }
  if(numOutput > 5) {
    printk("bug in cwnd generation: ack_seq = %u-%u, TCPBase = %u, "
	   "cwnd = %u, numOutput = %u, \n",
	   first_ack_seq, (*cont)->seq, (*cont)->TCPBase, 
	   (*cont)->startCwnd, numOutput);
    
    free_trickles_msk((*cont)->sk,(*cont));
    free_trickles_msk_finish((*cont)->sk,(*cont));
    return -EINVAL;
  }
  recordSample(&ctx,0);
  NormalizeContinuation(*cont,ackProof);
  recordSample(&ctx,0);
  firstResponseSeq = first_ack_seq + prevCwnd;
  //printk("%d: normal: %d + %d\n", (int)jiffies, first_ack_seq, prevCwnd);

  // allocate space for packets
  if(!alloc_msk_packets((*cont), numOutput)) {
    free_trickles_msk((*cont)->sk,(*cont));
    free_trickles_msk_finish((*cont)->sk,(*cont));
    return -ENOMEM;
  }
  for(i=0; i < numOutput; i++) {
	  // printk("%d/%d:", i, numOutput);
    __u32 seq = firstResponseSeq + i;
    int thisMSS, nextResponseLen = 0, firstChild = -1, 
      numChildren = -1, contType;
    if(serverDebugLevel >= 1) {
      if((*cont)->state == CONT_BOOTSTRAP) {
	printk("  %u\n", seq);
      }
    }
    // Algorithm choices here affect normalize continuation
    offset = seq - (*cont)->TCPBase;

    /* calculate number of packets in successor*/
    contType = CONTTYPE(offset);

    //#ifdef ENABLE_HASHCOMPRESS
#if 1
    switch(contType) {
    case CONTTYPE_FULL1:
    case CONTTYPE_FULL2:
	    if(sysctl_trickles_hashcompress && USE_HASH_COMPRESS((*cont)->serverSK)) {
		    thisMSS = CONTTYPE_HASHCOMPRESS_MSS;
		    contType |= CONTTYPE_HASHCOMPRESSED;
	    } else {
		    thisMSS = CONTTYPE_FULL_MSS;
	    }
	    break;
    case CONTTYPE_MINIMAL:
	    thisMSS = CONTTYPE_MINIMAL_MSS;
	    /* DO NOT SET HASH COMPRESSED ON MINIMAL */
	    break;
    default:
	    thisMSS = -1;
	    BUG();
    }
#else
    switch(contType) {
    case CONTTYPE_FULL1:
    case CONTTYPE_FULL2:
	    thisMSS = CONTTYPE_FULL_MSS;
	    break;
    case CONTTYPE_MINIMAL:
	    thisMSS = CONTTYPE_MINIMAL_MSS;
	    break;
    default:
	    thisMSS = -1;
	    BUG();
    }
#endif
    thisResponseLen += thisMSS;
    makePacket(&(*cont)->packets[numPackets], seq, 0xdeadbeef, thisMSS, (first ? PTYPE_FIRST : 0) | PACKET_NORMAL, contType, nextResponseLen,
	       firstChild, numChildren);
    recordNewPacketContType(contType);
    // cminisock_packet_print(&(*cont)->packets[numPackets]);

    first = 0;
    numPackets++;
  }
  (*cont)->num_packets = numPackets;
  BUG_TRAP(numPackets <= numOutput);
  recordSample(&ctx,0);

  DO_SANITY_CHECK_MSK(*cont);
  DoUpcall((*cont), event);
  recordSample(&ctx,0);
  //printTimings(&ctx);
  return 0;
}


static int intersect(int start0, int end0, int start1, int end1) {
  int start = MAX(start0,start1),
    end = MIN(end0,end1);
  if(start <= end) {
    /* intersection */
    return end - start + 1;
  } else {
    return 0;
  }
}

#ifdef USERTEST
#if 0
#define serverDebugLevel recoveryDebugLevel
static int recoveryDebugLevel = 99; // temporary use in userspace debugging to print only recovery handler debugging information
#endif
#endif

static int DoRecoveryStep(CONTINUATION_TYPE **cont, AckProof *ackProof, 
			  enum cminisock_event_tag event) {
	gRecoveryCount++;
	BUG_TRAP(!IS_DEFERRED_INITIALCWND(*cont));
	if(LOG_RECOVERY && !SIMULATION_MODE((*cont)->sk))
		TRACE_THIS_PACKET();
  int i;
  Sack *sacks = ackProof->sacks;
  // XXX INTMAX suppresses "uninitialized variable" harmless warnings in gcc
  int numLosses = 0, numBootstrapLosses = 0, bootstrapStart, bootstrapEnd, 
	  afterGap = 0,gapLeft = INT_MAX, gapRight = INT_MAX;
  unsigned numPackets = 0;
  int origCwnd, origCwndPred = INT_MAX, newCwnd;
  int gaplen = INT_MAX;
  int adj = INT_MAX;
  __u32 ack_seq;
  __u32 lastRegularPacket;

  int numPacketsSendable;
  int numPacketsAllocated;

  int bootstrapIntersectStart, 
    bootstrapIntersectLast;

  (*cont)->executionTrace = 2;

#ifdef DISABLE_FAST_RECOVERY
  free_trickles_msk((*cont)->sk,(*cont));
  free_trickles_msk_finish((*cont)->sk,(*cont));
  //printk("recovery no packets\n");
  return 0;
#endif

  origCwnd = AckTCPCwndScalar(AckProof_firstLoss(ackProof), (*cont));
  if(origCwnd < 0) {
	  if(!disableSevereErrors)
		  printk("recoveryStep: OrigCwnd undefined\n");
	  free_trickles_msk((*cont)->sk,(*cont));
	  free_trickles_msk_finish((*cont)->sk,(*cont));
	  return -EINVAL;
  }
  if(LOG_RECOVERY && !SIMULATION_MODE((*cont)->sk)) {
	  static int recoveryCount = 0;
	  printk("doRecoveryStep %d, cwnd=%d, seq=%d\n",
		 recoveryCount++, origCwnd, (*cont)->seq);
  }

  (*cont)->state = CONT_RECOVERY;
  (*cont)->firstLoss = AckProof_firstLoss(ackProof);
  switch(CONTTYPE((*cont)->firstLoss - (*cont)->TCPBase)) {
  case CONTTYPE_FULL1: // fall-through
  case CONTTYPE_MINIMAL:
    origCwndPred = AckTCPCwndScalar(AckProof_firstLoss(ackProof)-1, (*cont));
    adj = 0;
    break;
  case CONTTYPE_FULL2:
    origCwndPred = AckTCPCwndScalar(AckProof_firstLoss(ackProof)-2, (*cont));
    adj = -1;
    break;
  }
  if(origCwnd < origCwndPred) {
    printk("recoveryStep: OrigCwnd < OrigCwndPred\n");
    free_trickles_msk((*cont)->sk,(*cont));
    free_trickles_msk_finish((*cont)->sk,(*cont));
    return -EINVAL;
  }
  lastRegularPacket =  ((*cont)->firstLoss - 1 + adj) + origCwndPred;
  (*cont)->num_packets = 0;

#if 0  // 0615
  printk("EffCwnd (recoverystep): %d\n", origCwnd);
#endif

  newCwnd = origCwnd / MULT_FACTOR;

  (*cont)->actualCwnd = newCwnd;

  // FIXME: should allow 2 different TCPBase in CMinisock, since
  // bootstrap and rtx ought to have different TCPBase
  (*cont)->TCPBase = (*cont)->firstBootstrapSeq = lastRegularPacket + 1;
  (*cont)->startCwnd = newCwnd;
#ifndef ZERO_SSTHRESH_PROTECTION_HACK
  (*cont)->ssthresh = newCwnd;
#else
  if(newCwnd == 0)
    (*cont)->ssthresh /= MULT_FACTOR;
  else
    (*cont)->ssthresh = newCwnd;
#endif

  bootstrapStart = lastRegularPacket - newCwnd;
  bootstrapEnd = bootstrapStart + newCwnd - 1;

  //printk("Bootstrap range = [%d,%d)\n", bootstrapStart, bootstrapEnd);

  // XXX 0427 TODO: Remove first transport child processing

  /* Find the number of gaps */
  for(i=0; i < ackProof->numSacks; i++) {
    int cursorgap = 0;
    if(i > 0 && !Sack_adjacent(&sacks[i-1], &sacks[i])) {
      gaplen = Sack_gapLen(&sacks[i-1], &sacks[i]);
      cursorgap = 1;
      numLosses += gaplen;
      numBootstrapLosses += 
	intersect(bootstrapStart, sacks[i].left-1,
		  bootstrapEnd, sacks[i-1].right+1);
    }
    if(Sack_contains(&ackProof->sacks[i], (*cont)->seq)) {
      if(((*cont)->seq == sacks[i].left || 
	  ((*cont)->continuationType == CONTTYPE_FULL2 && (*cont)->seq - 1 == sacks[i].left))
	  && cursorgap) {
	/* detected gap; measure size of gap */
	afterGap = 1;
	gapLeft = ackProof->sacks[i-1].right + 1,
	  gapRight = ackProof->sacks[i].left - 1;
      }
    }
  }

  if(serverDebugLevel >= 2) {
	  printk("RecoveryStep\n");
	  AckProof_dump(ackProof);
  }

  // Preallocate space for all packets that we are going to generate
  numPacketsSendable = 0;
  numPacketsAllocated = 0;
  if(afterGap) {
    int start, end;
    numPacketsAllocated += (gapRight - gapLeft) + 1; // range is inclusive
    /* intersect bootstrap range with gap */
    start = MAX(gapLeft, bootstrapStart);
    end = MIN(gapRight, bootstrapEnd);
    if(start <= end) {
      numPacketsAllocated += (end - start) + 1; // range is inclusive
    }
  }
  {
    /* intersect ack ack range with bootstrap range */
    bootstrapIntersectStart = MAX(FIRST_ACKSEQ((*cont)->continuationType, (*cont)->seq),
				  bootstrapStart);
    bootstrapIntersectLast = MIN((*cont)->seq,
				 bootstrapEnd);
    if(bootstrapIntersectStart <= bootstrapIntersectLast) {
      numPacketsAllocated += 
	bootstrapIntersectLast - bootstrapIntersectStart + 1; // range is inclusive
    }
  }
  if(numPacketsAllocated == 0) {
    free_trickles_msk((*cont)->sk,(*cont));
    free_trickles_msk_finish((*cont)->sk,(*cont));
    //printk("recovery no packets\n");
    return 0;
  }
  if(!alloc_msk_packets((*cont), numPacketsAllocated)) {
    free_trickles_msk((*cont)->sk,(*cont));
    free_trickles_msk_finish((*cont)->sk,(*cont));
    printk("recovery nomem\n");
    return -ENOMEM;
  }

  if(afterGap) {
    __u32 seq;
    if(serverDebugLevel >= 1) {
      printk("  Bootstrap [%d - %d], newCwnd %d\n", bootstrapStart, bootstrapEnd, newCwnd);
      printk("  Gaplen = %d (after gap)\n", gaplen);
    }
    /* Generate retransmits */
    if(gapRight - gapLeft > MAX_GAPSIZE) {
          //printk("recoveryStep: gap too large (%u-%u)\n", gapLeft, gapRight);
	  free_trickles_msk((*cont)->sk,(*cont));
	  free_trickles_msk_finish((*cont)->sk,(*cont));
	  if(trickles_ratelimit())
		  printk("recovery gapsize too big - %d\n", gapRight -  gapLeft);
	  return -EINVAL;
    }
    for(seq = gapLeft; seq <= gapRight; seq++) {
      if(serverDebugLevel >= 1) {
	      //printk("  Gap rtx %u\n", seq);
      }
      //printk("retrans template %d\n", seq);
      makePacket(&(*cont)->packets[numPackets], seq, 0xdeadbeef, CONTTYPE_MINIMAL_MSS, PACKET_RETRANS, CONTTYPE_MINIMAL, CONTTYPE_MINIMAL_MSS, 
			 -1, -1);
      recordNewPacketContType(CONTTYPE_MINIMAL);
    
      numPackets++;
      /* retransmit bootstrap packets that should have been clocked out by missing packets */
      /* xxx: merge with identical code below */
      if(seq >= bootstrapStart && seq <= bootstrapEnd) {
	      gNumBootstrapResponses++;
	__u32 bootstrap_seq = lastRegularPacket + 1 + (seq - bootstrapStart);
	unsigned firstChild;
	int numChildren, prevCwnd, currCwnd;
	if(serverDebugLevel >= 1) {
		//printk("  Gap bootstrap %u\n", bootstrap_seq);
	}
	if(seq == bootstrapStart) {
		// XXX Record number of bootstrap ranges here
	}
	if(bootstrap_seq == (*cont)->TCPBase) {
		// corner case
		firstChild = bootstrap_seq + (*cont)->startCwnd;
		numChildren = 1;
	} else {
		prevCwnd = AckTCPCwndScalar(bootstrap_seq - 1, *cont);
		currCwnd = AckTCPCwndScalar(bootstrap_seq, *cont);
		firstChild = bootstrap_seq + prevCwnd;
		numChildren = currCwnd - prevCwnd + 1;
	}

	//printk("0: bootstrap packet template %d\n", seq);
	makePacket(&(*cont)->packets[numPackets],
		   bootstrap_seq, 0xdeadbeef, CONTTYPE_FULL_MSS,
		   PACKET_BOOTSTRAP, CONTTYPE_FULL1, CONTTYPE_FULL_MSS,
		   firstChild, numChildren);
	recordNewPacketContType(CONTTYPE_FULL1);
	numPackets++;
      }
    }
    if(serverDebugLevel >= 1) {
      printk("  After RTX: %u packets\n", numPackets);
    }
  } else {
    if(serverDebugLevel >= 2) {
      printk("  Not after gap\n");
    }
  }
  /* Transmit bootstrap packets in 2nd half of recovery interval */
  BUG_TRAP((*cont)->continuationType == CONTTYPE_FULL1 ||
	   (*cont)->continuationType == CONTTYPE_FULL2);
  for(ack_seq = bootstrapIntersectStart;
      ack_seq <= bootstrapIntersectLast;
      ack_seq++) {
    /* Eventually, clock out newCwnd bootstrap packets. Clock out one
       here */
    __u32 seq = lastRegularPacket + 1 + (ack_seq - bootstrapStart);
    unsigned firstChild;
    int numChildren, prevCwnd, currCwnd;

    if(serverDebugLevel >= 1)
      printk("  Bootstrap %u\n", seq);

    /* copied from above */
    if(seq == (*cont)->TCPBase) {
      // corner case
      firstChild = seq + (*cont)->startCwnd;
      numChildren = 1;
    } else {
      prevCwnd = AckTCPCwndScalar(seq - 1, *cont);
      currCwnd = AckTCPCwndScalar(seq, *cont);
      firstChild = seq + prevCwnd;
      numChildren = currCwnd - prevCwnd + 1;
    }

    //printk("1: bootstrap packet template %d\n", seq);
    makePacket(&(*cont)->packets[numPackets], seq, 0xdeadbeef, CONTTYPE_FULL_MSS /* len */ , 
	       PACKET_BOOTSTRAP, CONTTYPE_FULL1, CONTTYPE_FULL_MSS, firstChild, numChildren);
    recordNewPacketContType(CONTTYPE_FULL1);

    numPackets++;
    if(serverDebugLevel >= 1) {
      printk("  After bootstrap: %u packets\n", numPackets);
    }
  }
  numPacketsSendable = numPackets;
  (*cont)->num_packets = numPackets;
  if(numPacketsSendable > numPacketsAllocated) {
    printk("Sendable = %d, allocated = %d\n", numPacketsSendable, numPacketsAllocated);
    BUG_TRAP(numPacketsSendable <= numPacketsAllocated);
  }

  LOG_PACKET_RECOVERYEVENT(*cont);
#if 0
  if(numPacketsSendable > 0) {
	  printk("recovery packet will generate %d response  packets\n", numPacketsSendable);
  }
#endif
  //printk("recovery upcall\n");
  DO_SANITY_CHECK_MSK(*cont);
  DoUpcall((*cont), event);
  return 0;
}

static int DoSlowStartStep(CONTINUATION_TYPE **cont, AckProof *ackProof, __u32 newBase, enum cminisock_event_tag event) {
	gSlowStartCount++;
	if(!SIMULATION_MODE((*cont)->sk)) {
		static int lastSeq = 0;
#if 0
		if((*cont)->seq <= lastSeq + 2) {
			TRACE_K_PACKETS(8);
		} else {
			TRACE_K_PACKETS(8);
		}
#endif
		lastSeq = (*cont)->seq;
	}
	
#ifdef TRACELOSS
	if(!SIMULATION_MODE((*cont)->sk)) {
		printk("\n");
	}
#endif
	//printk("SSStep ServerDebugLevel = %d\n", serverDebugLevel);
	if((*cont)->startCwnd == 0) {
		(*cont)->startCwnd = 1;
	}
  (*cont)->executionTrace = 3;

  int right = AckProof_findRight(ackProof, (*cont)->TCPBase);
  int effCwnd = AckTCPCwndScalar(right, (*cont));

  (*cont)->actualCwnd = effCwnd;
  LOG_PACKET_TIMEOUTEVENT0(*cont);
  

#ifndef ZERO_SSTHRESH_PROTECTION_HACK
  (*cont)->ssthresh = effCwnd / MULT_FACTOR;
#else
  if(effCwnd >= MULT_FACTOR) {
    (*cont)->ssthresh = effCwnd / MULT_FACTOR;
  } else {
    (*cont)->ssthresh /= 2;
  }
#endif

  (*cont)->TCPBase = newBase;
  (*cont)->startCwnd = SLOWSTART_CWND;

  (*cont)->actualCwnd = (*cont)->startCwnd;

#if 1 // startcwnd = k
  if(!alloc_msk_packets((*cont), (*cont)->startCwnd)) {
	  free_trickles_msk((*cont)->sk, (*cont));
	  free_trickles_msk_finish((*cont)->sk, (*cont));
	  return -ENOMEM;
  }
  (*cont)->num_packets = (*cont)->startCwnd;
  int i;
  for(i=0; i < (*cont)->num_packets; i++) {
#if 0
	  int full = i % 2 == 0;
	  int type = full ? CONTTYPE_FULL2 : CONTTYPE_MINIMAL;
	  int len = full ? CONTTYPE_FULL_MSS : CONTTYPE_MINIMAL_MSS;
#else
	  int type = CONTTYPE_FULL1;
	  int len = CONTTYPE_FULL_MSS;
#endif
	  makePacket(&(*cont)->packets[i], (*cont)->TCPBase + i, 0xdeadbeef, len,
		     (i == 0 ? PTYPE_FIRST : 0) | PACKET_NORMAL, type,
		     0,  -1, -1);
	  recordNewPacketContType(type);
  }
#else
#if 1 // startcwnd = 1
  if(!alloc_msk_packets((*cont), 1)) {
	  free_trickles_msk((*cont)->sk, (*cont));
	  free_trickles_msk_finish((*cont)->sk, (*cont));
	  return -ENOMEM;
  }
  makePacket(&(*cont)->packets[0], (*cont)->TCPBase, 0xdeadbeef, CONTTYPE_FULL_MSS /* len */,
	     PTYPE_FIRST | PACKET_NORMAL, CONTTYPE_FULL1, 
	     CONTTYPE_FULL_MSS, (*cont)->TCPBase + 1, 1);
  recordNewPacketContType(CONTTYPE_FULL1);
	  
#else // startcwnd = 2
  if(!alloc_msk_packets((*cont), 2)) {
	  free_trickles_msk((*cont)->sk, (*cont));
	  free_trickles_msk_finish((*cont)->sk, (*cont));
	  return -ENOMEM;
  }
  makePacket(&(*cont)->packets[0], (*cont)->TCPBase, 0xdeadbeef, CONTTYPE_FULL_MSS /* len */,
	     PTYPE_FIRST | PACKET_NORMAL, CONTTYPE_FULL1, 
	     CONTTYPE_FULL_MSS, (*cont)->TCPBase + 1, 1);
  makePacket(&(*cont)->packets[1], (*cont)->TCPBase, 0xdeadbeef, CONTTYPE_FULL_MSS  /* len */,
	     PACKET_NORMAL, CONTTYPE_FULL1, 
	     CONTTYPE_FULL_MSS, (*cont)->TCPBase + 2, 1);
  recordNewPacketContType(CONTTYPE_FULL1);
  recordNewPacketContType(CONTTYPE_FULL1);
#endif
#endif

  if(serverDebugLevel >= 1)
	  printk("slow start step TCPBase - %u seq - %u\n", (*cont)->TCPBase, 
		 (*cont)->packets[0].seq);

  LOG_PACKET_TIMEOUTEVENT1(*cont);
  DO_SANITY_CHECK_MSK(*cont);
  DoUpcall((*cont), event);
  return 0;
}

void pminisock_cache_child(struct sock *sk, struct cminisock *msk, 
		   struct pminisock *pmsk, int packet_number, int flags) {
	struct pminisock *newPmsk;
	int new = 0;
	if(flags & CACHE_CHILD_COPY) {
		newPmsk = shallow_copy_pmsk(sk, pmsk);
		if(newPmsk == NULL) {
			if(trickles_ratelimit()) {
				printk("out of memory\n");
			}
			return;
		}
		new = 1;
	} else {
		newPmsk = pmsk;
	}
	// precondition: refcnt == 1
	BUG_TRAP(newPmsk->refCnt == 1);
	if(newPmsk != NULL) {
		if(!new) {
			newPmsk->ctl = ALLOC_PENDING;
		}
		BUG_TRAP(newPmsk->ctl == ALLOC_PENDING);

		// seq ; firstChild ; state
		MARSHALL_PACKET_FIELDS(newPmsk, pmsk, packet_number, 
				       /* no conversion function */);

		// initialization based on unmarshallContinuation
		newPmsk->rawTimestamp = htonl(msk->timestamp);
		newPmsk->rawMrtt = htonl(msk->mrtt);
		newPmsk->num_packets = 0;

		if(flags & CACHE_CHILD_CLEAR) {
			pmsk_clear_fields(newPmsk);
		}

		// printk("inserted %u\n", newPmsk->seq);
		if(pminisock_insert(sk, newPmsk)) {
			// refcnt now 2
			pmsk_release(sk, newPmsk);
			BUG_TRAP(newPmsk->refCnt == 1);
			//printk("new(%d) newPmsk->refCnt[2] = %d\n", new, newPmsk->refCnt);
		} else {
			// refcnt now 1
			pmsk_release(sk, newPmsk);
			BUG_TRAP(newPmsk->refCnt == 0);
		}
	}
 }
