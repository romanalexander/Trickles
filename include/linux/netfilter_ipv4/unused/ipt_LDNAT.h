#ifndef _IPT_LDNAT_H_target
#define _IPT_LDNAT_H_target

#define MAX_NUM_DST_ADDRS (8)

#error "Use SDNAT instead"
enum LDNAT_Algorithm {
	TCP_HASH,
};

struct ipt_ldnat_target_info {
	enum LDNAT_Algorithm algorithm;
	// addresses with which to destination NAT
	int numDstAddrs;
	unsigned long dst_addrs[MAX_NUM_DST_ADDRS];
};

#endif /*_IPT_SDNAT_H_target*/
