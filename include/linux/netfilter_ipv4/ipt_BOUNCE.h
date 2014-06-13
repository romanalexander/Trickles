#ifndef _IPT_BOUNCE_H_target
#define _IPT_BOUNCE_H_target

// ipt_BOUNCE encapsulates packets (usually TCP) within UDP, and
// bounces it through a remote IP address

// Designed to be transparent to the transport layer (except for
// reduced MTU)

enum IPT_BounceDirection {
	IN, OUT
};

struct ipt_bounce_target_info {
	// Remote address to bounce packets through
	unsigned long bounce_addr;
	unsigned short bounce_port;
	// out or in
	enum IPT_BounceDirection direction;
};

struct ipudp {
	// externally visible IP addresses
	uint32_t saddr, daddr;
	char data[0];
} __attribute__ ((packed));


#endif /*_IPT_MARK_H_target*/
