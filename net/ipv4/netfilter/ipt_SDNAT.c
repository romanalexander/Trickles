/* "Stupid" DNAT implementation. 
 *
 *   Philosophy: Don't mess with conntrack or any of that nonsense,
 *   just change my darn destination address!
 *
 */
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <net/checksum.h>

#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter_ipv4/ipt_SDNAT.h>
#include <linux/random.h>

#include "rand-util.h"

#if 0
#define rand(X) mwc_rand(X)
#endif

struct drand48_data
  {
    unsigned short int __x[3];  /* Current state.  */
    unsigned short int __old_x[3]; /* Old state.  */
    unsigned short int __c;     /* Additive const. in congruential formula.  */
    unsigned short int init;  /* Flag for initializing.  */
    unsigned long long int __a; /* Factor in congruential formula.  */
  };

struct drand48_data __libc_drand48_data;

int
__srand48_r (seedval, buffer)
     long int seedval;
     struct drand48_data *buffer;
{
  /* The standards say we only have 32 bits.  */
  if (sizeof (long int) > 4)
    seedval &= 0xffffffffl;

  buffer->__x[2] = seedval >> 16;
  buffer->__x[1] = seedval & 0xffffl;
  buffer->__x[0] = 0x330e;

  buffer->__a = 0x5deece66dull;
  buffer->__c = 0xb;
  buffer->init = 1;

  return 0;
}

void
srand48 (seedval)
     long seedval;
{
  (void) __srand48_r (seedval, &__libc_drand48_data);
}

int
__drand48_iterate (xsubi, buffer)
     unsigned short int xsubi[3];
     struct drand48_data *buffer;
{
  uint64_t X;
  uint64_t result;

  /* Initialize buffer, if not yet done.  */
  if (__builtin_expect (!buffer->init, 0))
    {
      buffer->__a = 0x5deece66dull;
      buffer->__c = 0xb;
      buffer->init = 1;
    }

  /* Do the real work.  We choose a data type which contains at least
     48 bits.  Because we compute the modulus it does not care how
     many bits really are computed.  */

  X = (uint64_t) xsubi[2] << 32 | (uint32_t) xsubi[1] << 16 | xsubi[0];

  result = X * buffer->__a + buffer->__c;

  xsubi[0] = result & 0xffff;
  xsubi[1] = (result >> 16) & 0xffff;
  xsubi[2] = (result >> 32) & 0xffff;

  return 0;
}


int
__nrand48_r (xsubi, buffer, result)
     unsigned short int xsubi[3];
     struct drand48_data *buffer;
     long int *result;
{
  /* Compute next state.  */
  if (__drand48_iterate (xsubi, buffer) < 0)
    return -1;

  /* Store the result.  */
  if (sizeof (unsigned short int) == 2)
    *result = xsubi[2] << 15 | xsubi[1] >> 1;
  else
    *result = xsubi[2] >> 1;

  return 0;
}

long int
lrand48 ()
{
  long int result;

  (void) __nrand48_r (__libc_drand48_data.__x, &__libc_drand48_data, &result);

  return result;
}

#define rand() lrand48()
#define RAND_MAX ((1<<31) - 1)

static inline int rand_max(int val) {
	int rval = rand() / (RAND_MAX / val);
	if(rval >= val) {
		rval = val - 1;
	}
	if(rval < 0) {
		rval = 0;
	}
	return rval;
}

// #define DUMP_RANDOM_CHOICES

static int gNumConnsChanged;

#define PASS_THROUGH (0xFFFFFFFF)
#define NONE (0x00000000)

#if PASS_THROUGH == NONE
#error "Pass_through must not == none"
#endif

#if 1
// XXX test new nat cheat check code after verifying that calls to nat
// XXX cheat are correct
__u16 ip_nat_cheat_check(int compValue, int newValue, unsigned int check) {
	// http://www.faqs.org/rfcs/rfc1071.html
	__asm__(
		"xor $0xffff, %[check]        ;\n"
		"addl %[compValue], %[check]  ;\n" // can overflow
		"adcl %[newValue], %[check]   ;\n" // can overflow
		"adcl $0, %[check]            ;\n" // can overflow
		"adcl $0, %[check]            ;\n"
                : [check] "=r"(check)
		: "0" (check), [compValue] "rm" (compValue), 
		  [newValue] "rm" (newValue)
		);
	return csum_fold(check);
}
#else
#include <linux/netfilter_ipv4/ip_nat.h>
#endif

// This file is very similar to ipt_SDNAT.c.

///  HASH ALGORITHMS

///////// TCP_HASH

/* For now, use Linux IPv4 Hash function */
static inline int tcp_hashfn(__u32 laddr, __u16 lport,
				 __u32 faddr, __u16 fport)
{
	int h = ((laddr ^ lport) ^ (faddr ^ fport));
	h ^= h>>16;
	h ^= h>>8;
	return h;
}

static inline unsigned sourceHash(__u32 saddr, __u16 sport) {
	return tcp_hashfn(0,0,saddr,sport);
}

// based on tcp nat function of the same name
static void
tcp_manip_pkt(struct iphdr *iph, size_t len, u_int32_t newDstIP)
{
	struct tcphdr *hdr = (struct tcphdr *)((u_int32_t *)iph + iph->ihl);
	u_int32_t oldip;

	oldip = iph->daddr;

	/* Manipulate source address. We have 2 checksums to update:
	   IP header checksum and TCP pseudoheader checksum */
	iph->check = ip_nat_cheat_check(~oldip,newDstIP,iph->check);
	iph->daddr = newDstIP;

	/* this could be a inner header returned in icmp packet; in such
	   cases we cannot update the checksum field since it is outside of
	   the 8 bytes of transport layer headers we are guaranteed */
	if(((void *)&hdr->check + sizeof(hdr->check) - (void *)iph) <= len) {
		hdr->check = ip_nat_cheat_check(~oldip, newDstIP,hdr->check);
	}
#if 0
	if(net_ratelimit()) {
		printk("SDNAT packet manipulated, %X %X\n", oldip, newDstIP);
	}
#endif
}

static inline void rr_updateIndex(struct ipt_sdnat_target_info *sdnatinfo) {
	sdnatinfo->rrCounter++;
	if(sdnatinfo->rrCounter >=
	   sdnatinfo->dst[sdnatinfo->rrIndex].weight) {
		sdnatinfo->rrCounter = 0;
		sdnatinfo->rrIndex++;
		sdnatinfo->rrIndex %= sdnatinfo->numDsts;
	}
}

#if 1
#define TABLE_SIZE (1 << 14)
#else
#define TABLE_SIZE (1 << 4)
#endif
int gTrackingTableSize = TABLE_SIZE;

struct ConnTrack {
	struct ConnTrack *next;
	struct ConnTrack *prev;
	__u32 saddr;
	__u16 sport;
	int   daddr;
} __attribute__((packed));

static inline void conn_track_dump(struct ConnTrack *conn) {
	printk("next=%p prev=%p saddr=%X sport=%d daddr=%X\n", conn->next, 
	       conn->prev, conn->saddr, conn->sport, conn->daddr);
}

static inline void conn_track_unlink(struct ConnTrack *conn) {
	conn->prev->next = conn->next;
	conn->next->prev = conn->prev;
	conn->next = conn->prev = NULL;
}

static inline void conn_track_insert_tail(struct ConnTrack *bucket,
			       struct ConnTrack *conn) {
	struct ConnTrack *prev = bucket->prev, *next = bucket;
	prev->next = conn;
	conn->prev = prev;

	conn->next = next;
	next->prev = conn;
}

#define CONNTRACK_ISUNUSED(X) ((X)->saddr == 0 && (X)->daddr == 0)
#define BUCKET_ISEMPTY(X) \
	(CONNTRACK_ISUNUSED(X) && ((X)->next == (X))
#define CONNTRACK_MAKEUNUSED(X) do { (X)->saddr = 0; (X)->daddr = 0; } while (0)
#define CONNTRACK_ISUNCONNECTED(X) ((X)->daddr == 0)
#define CONNTRACK_INIT(X,SADDR,SPORT)			\
do {							\
	(X)->saddr = (SADDR);				\
	(X)->sport = (SPORT);				\
	(X)->daddr = 0; /* must start unconnected */ 	\
} while(0)

#define CONNTRACK_INITLIST(X)			\
do {						\
	(X)->next = (X);			\
	(X)->prev = (X);			\
} while(0)

struct ConnTrack g_tracking_table[TABLE_SIZE];

#define IS_CONNTRACK_ROOT(X)				\
	((X) >= &g_tracking_table[0] &&			\
	 (X) <  &g_tracking_table[gTrackingTableSize])

#define INVALID (0xdeadbeef)

// return index of selected server
static inline 
int pickdest(struct ipt_sdnat_target_info *sdnat, struct sk_buff *skb) {
	switch(sdnat->algorithm) {
	case LEAST_CONNS: {
		int minNumConns = INT_MAX;
		int entry = -1;
		int i;
		for(i=0; i < sdnat->numDsts; i++) {
			if(sdnat->dst[i].num_conns < minNumConns) {
				minNumConns = sdnat->dst[i].num_conns;
				entry = i;
			}
		}
		BUG_TRAP(entry != -1);
		return entry;
		break;
 	}
	case TCP_RANDOM: {
		return rand_max(sdnat->numDsts);
		break;
	}
	case WEIGHT_RR: {
		int index = sdnat->rrIndex;
		rr_updateIndex(sdnat);
		return index;
	}
	default:
		if(net_ratelimit()) {
			printk("pickdest encountered unsupported "
			       "algorithm %d\n", sdnat->algorithm);
		}
		return 0;
	}  // end switch
}

static inline
struct ConnTrack *get_bucket_root_helper(__u32 saddr, __u16 source) {
	int hash = sourceHash(saddr, source) % gTrackingTableSize;
	return &g_tracking_table[hash];
}

static inline 
struct ConnTrack *get_bucket_root(struct sk_buff *skb) {
	struct iphdr *iph = skb->nh.iph;
	struct tcphdr *th = skb->h.th;
	return get_bucket_root_helper(iph->saddr, th->source);
}

static inline
int conn_track_match(struct ConnTrack *conn, __u32 saddr, __u16 source) {
#if 1
	BUG_TRAP(conn != NULL);
#endif
	return conn->saddr == saddr && conn->sport == source;
}

static inline 
void conn_track_free(struct ConnTrack *conn) {
	if(IS_CONNTRACK_ROOT(conn)) {
		CONNTRACK_MAKEUNUSED(conn);
	} else {
		conn_track_unlink(conn);
		kfree(conn);
	}
}

static inline
struct ConnTrack *conn_track_lookup_helper(__u32 ip, __u16 sport) {
	struct ConnTrack *bucket = get_bucket_root_helper(ip, sport);
	// probe for existing connections
	int found = 0;
	struct ConnTrack *conn = bucket;
	do {
		if(conn_track_match(conn, ip, sport)) {
			found = 1;
			break;
		}
		conn = conn->next;
	} while(conn != bucket);
	if(found) {
		return conn;
	}

	return NULL;
}

static inline
struct ConnTrack *conn_track_lookup(struct sk_buff *skb) {
	return conn_track_lookup_helper(skb->nh.iph->saddr, skb->h.th->source);
}

static inline 
struct ConnTrack *
conn_track_lookup_or_alloc(struct sk_buff *skb, int allocate) {
	struct ConnTrack *rval = conn_track_lookup(skb);
	__u32 saddr = skb->nh.iph->saddr;
	__u16 sport = skb->h.th->source;

	if(rval == NULL && allocate) {
		// no matching entry
		struct ConnTrack *bucket = get_bucket_root(skb);
		if(CONNTRACK_ISUNUSED(bucket)) {
			rval = bucket;
			CONNTRACK_INIT(rval, saddr, sport);
			//conn_track_dump(rval);
		} else {
			rval = kmalloc(sizeof(struct ConnTrack), GFP_ATOMIC);
			if(rval) {
				CONNTRACK_INIT(rval, saddr, sport);
				rval->next = rval->prev = NULL;
				// link in new entry
				conn_track_insert_tail(bucket,rval);
			} else {
				if(net_ratelimit()) {
					printk("Warning: Could not allocate "
					       "memory for conntrack!\n");
				}
			}
		}
	}

	return rval;
}

#define CONN_DISC   (-1)
#define CONN_NONE    (0)
#define CONN_NEW     (1)

static inline 
int conn_track_statechange(struct ipt_sdnat_target_info *sdnatinfo,
			   struct ConnTrack *conn, struct sk_buff *skb)
{
	struct tcphdr *th = skb->h.th;
	int close = th->fin || th->rst;

	if(close) {
		// Decrease number of connections
		// XXX Yuck, linear search
		int i;
		int found = 0;
		for(i=0; i < sdnatinfo->numDsts; i++) {
			if(sdnatinfo->dst[i].addr == conn->daddr) {
				found = 1;
				break;
			}
		}
		if(found) {
			BUG_TRAP(i < sdnatinfo->numDsts);
			sdnatinfo->dst[i].num_conns--;
#if 0
			printk("dst[%d].num_conns = %d\n", i, sdnatinfo->dst[i].num_conns);
#endif
			gNumConnsChanged = 1;
		} else {
			if(net_ratelimit()) {
				printk("SDNAT: Could not find matching "
				       "destination during close()\n");
			}
		}
		return CONN_DISC;
	} else {
		if(CONNTRACK_ISUNCONNECTED(conn)) {
			// no dest addr; pick a new address
			int index;
			index = pickdest(sdnatinfo, skb);
			conn->daddr = sdnatinfo->dst[index].addr;
			sdnatinfo->dst[index].num_conns++;
#ifdef DUMP_RANDOM_CHOICES
			printk("pickdest addr: %d\n", conn->daddr);
#endif
#if 0
			printk("index = %d\n", index);
			printk("new connection, %d\n", sdnatinfo->dst[index].num_conns); conn_track_dump(conn);
#endif
			gNumConnsChanged = 1;
			return CONN_NEW;
		} else {
			// No change
			// XXX Record number of packets?
			return CONN_NONE;
		}
	}
}

static 
struct ConnTrack *
conn_track_helper(struct ipt_sdnat_target_info *sdnatinfo,
		  struct sk_buff *skb, int *change, __u32 *daddr)
{
	struct iphdr *iph = skb->nh.iph;
	struct tcphdr *th;
	int i;
	int allocate;
	struct ConnTrack *conn;

	skb->h.th = (struct tcphdr *)((__u32*)iph + iph->ihl);
	th = skb->h.th;

	if((int)skb->len - ((char*)th - (char*)iph) < 0) {
		if(net_ratelimit()) {
			printk("Packet too short\n");
		}
		return NULL;
	}

	if(th->syn) {
		allocate = 1;
	} else {
		allocate = 0;
	}
	int reverse = 0;
	// First, check to see if connection might be from servers
	for(i=0; i < sdnatinfo->numDsts; i++) {
		if(iph->saddr == sdnatinfo->dst[i].addr) {
			reverse = 1;
			break;
		}
	}
	if(reverse) {
		// Reverse, should be RST or FIN packet
		if(!(th->rst || th->fin)) {
			if(net_ratelimit()) {
				printk("Reverse packets ought to be RST or FIN\n");
			}
		}
		conn = conn_track_lookup_helper(iph->daddr, th->dest);
#if 0
		if(conn == NULL) {
			printk("could not find reverse lookup\n");
		} else {
			printk("found reverse lookup\n");
		}
#endif
	} else {
		conn = conn_track_lookup_or_alloc(skb, allocate);
	}

#warning "May need to periodically calibrate the number of connections!!!"
	// XXX Need to implement aging of half-opened connections
	// XXX Need better FIN handling
	if(conn != NULL) {
		*change = conn_track_statechange(sdnatinfo, conn, skb);
		*daddr = conn->daddr;
		if(*change == CONN_DISC) {
			conn_track_free(conn);
			conn = NULL;
		}
	} else {
#if 0
		if(!reverse && net_ratelimit()) {
			printk("SDNAT: could not find conn_track\n");
		}
#endif
		*change = 0;
		*daddr = NONE;
	}
	if(reverse) {
		*daddr = PASS_THROUGH;
	}

	return conn;
}

static int 
generic_conn_track(struct ipt_sdnat_target_info *sdnatinfo, 
		   struct sk_buff *skb, int *pDstAddr) {
	int change = 0;
	__u32 daddr;

	// return value ignored to suppress warning
	conn_track_helper(sdnatinfo, skb, &change, &daddr);
	if(daddr == NONE) {
#if 0
		if(net_ratelimit()) {
			printk("Received packet w/o connection table "
			       "entry\n");
		}
#endif
		*pDstAddr = NONE;
		return NF_DROP;
	} else if(daddr == PASS_THROUGH) {
		*pDstAddr = NONE;
		return IPT_CONTINUE;
	}
	*pDstAddr = daddr;
	return IPT_CONTINUE;
}

static unsigned int
target(struct sk_buff **pskb,
       unsigned int hooknum,
       const struct net_device *in,
       const struct net_device *out,
       const void *targinfo,
       void *userinfo)
{
	struct ipt_sdnat_target_info *sdnatinfo = targinfo;
	u_int32_t dstAddr;
	struct iphdr *iph = (*pskb)->nh.iph;
	struct tcphdr *th = (struct tcphdr *)((__u32*)iph + iph->ihl);

	switch(sdnatinfo->algorithm) {
	//
	// Stateless NAT
	//
	case TCP_HASH: {
		int index = sourceHash(iph->saddr,th->source) % 
			sdnatinfo->numDsts;
		dstAddr = sdnatinfo->dst[index].addr;
		break;
	}
	//
	// Conn-tracking NAT
	//
	case WEIGHT_RR:
	case TCP_RANDOM:
	case LEAST_CONNS: {
		int rval = generic_conn_track(sdnatinfo, *pskb, &dstAddr);
		if(dstAddr == NONE) return rval;
		break;
	}
	case TRICKLES_SRR: {
		dstAddr = sdnatinfo->dst[sdnatinfo->rrIndex].addr;
		rr_updateIndex((struct ipt_sdnat_target_info *)sdnatinfo);
#ifdef DUMP_RANDOM_CHOICES
		printk("dest addr: %d\n", dstAddr);
#endif
		break;
	}
	case TRICKLES_RANDOM: {
		int index = rand_max(sdnatinfo->numDsts);
		dstAddr = sdnatinfo->dst[index].addr;
#ifdef DUMP_RANDOM_CHOICES
		printk("dest addr: %d\n", dstAddr);
#endif
		break;
	}
	default:
		if(net_ratelimit()) {
			printk("Warning: Unknown SDNAT algorithm type\n");
		}
		return NF_DROP;
	}

	tcp_manip_pkt(iph, (char*)(*pskb)->tail - (char*)iph, dstAddr);
	return IPT_CONTINUE;
}

static int
checkentry(const char *tablename,
	   const struct ipt_entry *e,
           void *targinfo,
           unsigned int targinfosize,
           unsigned int hook_mask)
{
	int i;
	struct ipt_sdnat_target_info *sdnatinfo = targinfo;
	if (targinfosize != IPT_ALIGN(sizeof(struct ipt_sdnat_target_info))) {
		printk(KERN_WARNING "SDNAT: targinfosize %u != %Zu\n",
		       targinfosize,
		       IPT_ALIGN(sizeof(struct ipt_sdnat_target_info)));
		return 0;
	}
	if (sdnatinfo->numDsts > MAX_NUM_DST_ADDRS) {
		printk(KERN_WARNING "SDNAT: too many destination addresses\n");
		return 0;
	}

	if (strcmp(tablename, "mangle") != 0) {
		printk(KERN_WARNING "SDNAT: can only be called from \"mangle\" table, not \"%s\"\n", tablename);
		return 0;
	}

	switch(sdnatinfo->algorithm) {
	case TCP_HASH:
	case LEAST_CONNS:
	case TRICKLES_SRR:
	case TRICKLES_RANDOM:
	case TCP_RANDOM:
		break;
	case WEIGHT_RR:
		printk(KERN_WARNING "SDNAT: Weighted RR not supported yet\n");
		return 0;
	default:
		printk(KERN_WARNING "SDNAT: Unknown algorithm type\n");
		return 0;
	}
	// XXX HACK initialize data number of connections here
	for(i=0; i < sdnatinfo->numDsts; i++) {
		sdnatinfo->dst[i].num_conns = 0;
	}
	sdnatinfo->rrIndex = 0;

	return 1;
}

static struct ipt_target ipt_sdnat_reg
= { { NULL, NULL }, "SDNAT", target, checkentry, NULL, THIS_MODULE };

static int __init init(void)
{
	if (ipt_register_target(&ipt_sdnat_reg))
		return -EINVAL;

	int i;
	for(i=0; i < gTrackingTableSize; i++) {
		CONNTRACK_INIT(&g_tracking_table[i], 0, -1);
		CONNTRACK_INITLIST(&g_tracking_table[i]);
	}
	printk("SDNAT loaded\n");
	printk("Warning: Need to periodically synchronize the number of "
	       "connections!\n");

	// reseed random number generator
	int seed;
	get_random_bytes(&seed, sizeof(seed));
	printk("Random seed (srand48): %d\n", seed);
	srand48(seed);

	for(i=0; i < 20; i++) {
		printk("rand[%d]= %d\n", i, rand_max(3));
	}
	printk("Number of buckets: %d\n", gTrackingTableSize);
	return 0;
}

static void __exit fini(void)
{
	ipt_unregister_target(&ipt_sdnat_reg);

	int i;
	for(i=0; i < gTrackingTableSize; i++) {
		struct ConnTrack *root = &g_tracking_table[i];
		struct ConnTrack *conn = root->next;
		while(conn != root) {
			struct ConnTrack *clean = conn;
			//printk("conn = %p\n", conn);
			conn = conn->next;
			kfree(clean);
		}
	}
	if(gNumConnsChanged) {
		printk("Number of connections changed in some bucket\n");
	} else {
		printk("Number of connections never changed for any bucket\n");
	}
}

module_init(init);
module_exit(fini);
MODULE_LICENSE("GPL");
