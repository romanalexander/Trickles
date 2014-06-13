#ifndef _IPT_SDNAT_H_target
#define _IPT_SDNAT_H_target

#define MAX_NUM_DST_ADDRS (8)

enum SDNAT_Algorithm {
	// Stateless algorithms
	// Source IP/port
	TCP_HASH,
	// Weighted round robin for every packet
	TRICKLES_SRR,
	// Random spraying on every packet
	TRICKLES_RANDOM,

	// XXX Add TRICKLES_WRANDOM?

	// Randomly assign flow to server
	TCP_RANDOM,


	// Stateful algorithms
	LEAST_CONNS, // Send connection to destination with the least number of connections
	WEIGHT_RR,   // Weighted round robin
};

struct SDNAT_Destination {
	// user interface
	unsigned long addr;
	int weight; // weighted round robin weight

	// internal state
	int num_conns; // number of connections
};

struct ipt_sdnat_target_info {
	enum SDNAT_Algorithm algorithm;
	// addresses with which to destination NAT
	int numDsts;
	int rrIndex;
	int rrCounter;
	struct SDNAT_Destination dst[MAX_NUM_DST_ADDRS];
};

#endif /*_IPT_SDNAT_H_target*/
