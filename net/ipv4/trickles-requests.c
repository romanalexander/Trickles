#include "trickles-int.h"

// RPC-style client requests

// Currently, only CONVERSION requests are RPC-style

static void (struct RPC_Call *rpc) {
}

static 
struct RPC_Call *RPC_match_helper(struct sock *sk, struct RPC_Call *hint,
				  unsigned pseq, unsigned tseq,
				  unsigned position) {
	
}

static 
struct RPC_Call *RPC_match(struct sock *sk, unsigned pseq, unsigned tseq,
			   unsigned position) {
}

void RPC_process(struct sock *sk, struct sock *skb) {
	int numMatches = 0;
	struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;
	CONTINUATION_TYPE *cont = TCP_SKB_CB(skb)->cont;

	// N.B.: Calls to process can unlink the current position	
	struct RPC_Call *match;
	while((match = RPC_match(sk, cont->parent, cont->seq, cont->position))
	      != NULL) {
		numMatches++;
		swich
	}
}

