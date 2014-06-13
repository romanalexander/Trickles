#ifndef TRICKLES_REQUESTS_H
#define TRICKLES_REQUESTS_H

#include <net/trickles_dlist.h>

enum RPC_Type {
	CONVERSION
	// DATA, etc
};

struct RPC_Call {
	// links for [tseq_start,tseq_end] sorted list (sorted by beginning of range)
	struct alloc_head *prev;
	struct alloc_head *next;
	struct alloc_head_list *list;

	enum RPC_Type type;

	int maxChildren; // from simulation
	int actualChildren; // from response packet headers

	int tseq_start, tseq_end;
	char data[0]; // aditional data
};

struct RPC_Conversion {
	// data fields
	xxx;
};

void RPC_send(struct sock *sk, struct RPC_Call *call) {
}

void RPC_cancel(struct sock *sk, struct RPC_Call *call) {
}

void RPC_resend(struct sock *sk, struct RPC_Call *call) {
}

#endif // TRICKLES_REQUESTS_H
