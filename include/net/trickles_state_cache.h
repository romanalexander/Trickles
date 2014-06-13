#ifndef TRICKLES_STATE_CACHE_H
#define TRICKLES_STATE_CACHE_H

#define DELAY() 	{ volatile int i; for(i=0; i < 1000000000; i++) { i = i; } }
//#define DELAY() 	{ volatile int i; for(i=0; i < 1000; i++) { i = i; } }

struct WireContinuation;
struct pminisock;

void StateCache_init(void);
void StateCache_destroy(void);
void StateCache_invalidate(void);

void StateCache_resize(int size);

void pminisock_evictN(int count);

struct pminisock *pminisock_lookup(struct sock *sk, __u32 seqno, 
				   struct iphdr *iph, struct tcphdr *th);
int pminisock_insert(struct sock *sk, struct pminisock *msk);

#if 0
int WireContinuation_lookup(struct WireContinuation *wcont, 
			     struct iphdr *iph, struct tcphdr *th)	;
void WireContinuation_insert(struct WireContinuation *cont, 
		    const CONTINUATION_TYPE *scont);
#endif

#define CACHE_SYSCTL_VAR(NAME)				\
extern int	sysctl_trickles_##NAME##_enable,	\
	sysctl_trickles_##NAME##_policy,		\
	sysctl_trickles_##NAME##_hits,			\
	sysctl_trickles_##NAME##_total

CACHE_SYSCTL_VAR(Continuation);
CACHE_SYSCTL_VAR(Nonce);
CACHE_SYSCTL_VAR(TCB);

void dump_cache_stats(void);

#undef CACHE_SYSCTL_VAR

#endif // TRICKLES_STATE_CACHE_H
