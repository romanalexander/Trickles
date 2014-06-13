/* "Stupid" SNAT implementation. 
 *
 *   Philosophy: Don't mess with conntrack or any of that nonsense,
 *   just change my darn source address!
 * source /home/ashieh/gdbscripts/load192.168.0.10ipt_BOUNCE.o
 */
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <net/checksum.h>

#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter_ipv4/ipt_BOUNCE.h>

#define TRY_PULL_OR_FAIL(SKB,LEN,ERRSTR,ERRVAL)		\
	({								\
		if(!pskb_may_pull((SKB), (LEN))) {			\
			if(net_ratelimit()) {				\
				printk(ERRSTR);				\
			}						\
			return ERRVAL;					\
		}							\
	})


#define PULL_OR_FAIL(SKB,LEN,ERRSTR,ERRVAL)		\
	({						\
		struct sk_buff *_skb = (SKB);				\
		int _len = (LEN);					\
		TRY_PULL_OR_FAIL(_skb,_len,ERRSTR,ERRVAL);		\
		skb_pull(_skb, _len);	 /* final result */		\
	})

#define PUSH_OR_FAIL(SKB,LEN,ERRSTR,ERRVAL)		\
	({						\
		void *_tmp = skb_push((SKB),(LEN));	\
		if(_tmp == NULL) {			\
			if(net_ratelimit()) {		\
				printk(ERRSTR);		\
			}				\
			return ERRVAL;			\
		}					\
		_tmp;					\
	})


#define MIN(X,Y) ((X) < (Y) ? (X) : (Y))
#define MTU (1500)
const int ENCAP_HEADER_LEN = sizeof(struct udphdr) + sizeof(struct ipudp);

#define HH_LEN (15)

#define WIDTH (16)
static inline int hexdump_helper(void *ptr, int len, int format_offset) {
	int i, newlined = 0, format_val;
	char *data = (char*)ptr;
	for(i = 0, format_val = format_offset; 
	       i < len; i++, format_val++) {
		printk("%02X ", (unsigned char)data[i]);
		newlined = 0;
		if(format_val > 0) {
			int mod = format_val % WIDTH;
			if(mod == 0) {
				printk("\n");
				newlined = 1;
			} else if(mod == WIDTH/2) {
				printk("- ");
			}
		}
	}
#if 0
	if(!newlined) {
		printk("\n");
	}
#endif
	return format_val;
}

static inline int hexdump(void *data, int len) {
	return hexdump_helper(data, len, 0);
}

static inline void skb_dump(struct sk_buff *skb) {
	printk("[%p,%p,%p,%p]", skb->head, skb->data, skb->tail, skb->end);
}

/* Stolen from ipt_mirror.c */
static inline struct rtable *route(struct sk_buff *skb, int local)
{
        struct iphdr *iph = skb->nh.iph;
	struct dst_entry *odst;
	struct rt_key key = {};
	struct rtable *rt;

	if (local) {
		key.src = iph->saddr;
		key.dst = iph->daddr;
		key.tos = RT_TOS(iph->tos);

		if (ip_route_output_key(&rt, &key) != 0)
			return NULL;
	} else {
		/* non-local src, find valid iif to satisfy
		 * rp-filter when calling ip_route_input. */
		key.dst = iph->daddr;
		if (ip_route_output_key(&rt, &key) != 0)
			return NULL;

		odst = skb->dst;
		if (ip_route_input(skb, iph->saddr, iph->daddr,
		                   RT_TOS(iph->tos), rt->u.dst.dev) != 0) {
			dst_release(&rt->u.dst);
			return NULL;
		}
		dst_release(&rt->u.dst);
		rt = (struct rtable *)skb->dst;
		skb->dst = odst;
	}

	if (rt->u.dst.error) {
		dst_release(&rt->u.dst);
		rt = NULL;
	}

	return rt;
}

struct HeaderContext {
	char *rawBuf;
	char *ll_rawh;
	int ll_len;
	struct iphdr *iph;
	int ihl;
};


#define INCLUDE_LL (1)
static inline int parse_and_save_headers(struct HeaderContext *dst, 
			struct HeaderContext *src, struct sk_buff *skb,
			int updateFlags) {
	int my_ll_len, my_ihl;
	if(updateFlags & INCLUDE_LL) {
		src->rawBuf = src->ll_rawh = skb->mac.raw;
		src->ll_len = my_ll_len = (char*)skb->nh.raw - (char*)src->ll_rawh;

		dst->ll_rawh = dst->rawBuf;
		memcpy(dst->ll_rawh, src->ll_rawh, my_ll_len);
		dst->ll_len = my_ll_len;
		BUG_TRAP(my_ll_len == 14);

		dst->iph = (struct iphdr*)(dst->ll_rawh + my_ll_len);
	} else {
		src->rawBuf = (char*)skb->nh.iph;
		src->ll_rawh = NULL;
		src->ll_len = my_ll_len = -1;

		dst->ll_rawh = NULL;
		dst->ll_len = my_ll_len;

		dst->iph = (struct iphdr*)dst->rawBuf;
	}

	src->iph = skb->nh.iph;
	src->ihl = my_ihl = src->iph->ihl*4;

	BUG_TRAP(my_ihl == 20);
	memcpy(dst->iph, src->iph, my_ihl);
	dst->ihl = my_ihl;
#if 0
	printk("dumping iph: \n");
	hexdump(dst->iph, my_ihl);
#endif

	PULL_OR_FAIL(skb, my_ihl, "IP header too long in parse_header_and_save\n", -1);

	return 0;
}

static inline void h_update_and_push(struct sk_buff *skb, struct HeaderContext *template,
			__u32 newSrc, __u32 newDest, int newProto, 
			int adjPacketLen, int updateFlags) {
	struct iphdr *diph = template->iph;
	int ihl = template->ihl;
	BUG_TRAP(ihl == 20);
	int tot_len = ntohs(diph->tot_len) + adjPacketLen;

#if 0
	printk("new tot_len = %d\n", tot_len);
#endif
	diph->saddr = newSrc;
	diph->daddr = newDest;
	diph->tot_len = htons(tot_len);
	
	diph->protocol = newProto;
	diph->check = 0;
	// Compute checksum
	diph->check = ip_compute_csum((unsigned char *)diph, ihl);
	skb->nh.iph = (struct iphdr*)skb_push(skb, ihl);
	memcpy((char*)skb->nh.iph, diph, ihl);

	if(updateFlags & INCLUDE_LL) {
		// push on link layer header
		BUG_TRAP(template->ll_len == 14);
		skb->mac.raw = skb_push(skb, template->ll_len);
		memcpy(skb->mac.raw, template->ll_rawh, template->ll_len);
	}

#if 0
	printk("dumping final iph: \n");
	hexdump(skb->nh.iph, ihl);
#endif
}

static inline void renormalize(struct sk_buff *skb, struct HeaderContext *orig_template) {
	// Ugh, Linux (libPcap only?) doesn't like data not aligned at start of buffer. Do a memmove, along with some other fixups
	int movlen = skb->tail - skb->data;
	skb->nfcache |= NFC_ALTERED; // XXX is this really needed?
	char *start = orig_template->ll_rawh;
	memmove(start, skb->data, movlen);

	skb->data = skb->mac.raw = start;
	skb->tail = skb->data + skb->len;

	BUG_TRAP(orig_template->ll_len == 14);
	skb_pull(skb, orig_template->ll_len);

	// now at IP header
	skb->nh.iph = (struct iphdr*)skb->data;
	skb->h.th = (struct tcphdr*)((char*)skb->nh.iph + orig_template->ihl);

	// debugging mark
	skb->nfmark = 0xdeadbeef;

}

/* Stolen from ipt_MIRROR, which says, "Stolen from ip_finish_output2" */

static inline void ip_direct_send(struct sk_buff *skb)
{
	struct dst_entry *dst = skb->dst;
	struct hh_cache *hh = dst->hh;

	if (hh) {
		int hh_alen;

		read_lock_bh(&hh->hh_lock);
		hh_alen = HH_DATA_ALIGN(hh->hh_len);
  		memcpy(skb->data - hh_alen, hh->hh_data, hh_alen);
		read_unlock_bh(&hh->hh_lock);
		skb_push(skb, hh->hh_len);
		hh->hh_output(skb);
	} else if (dst->neighbour)
		dst->neighbour->output(skb);
	else {
		printk(KERN_DEBUG "khm in MIRROR\n");
		kfree_skb(skb);
	}
}

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

// based on tcp nat function of the same name
static inline int
encapsulate_packet_and_bounce(struct sk_buff *skb, unsigned int bounceIP, unsigned short bouncePort)
{
	// NF_STOLEN the packet, and send out an encapsulated replacement

	// Verify that the encapsulated packet will be short enough to send out
	if((skb->len > MTU - ENCAP_HEADER_LEN)) {
		if(net_ratelimit()) {
			printk("SKB too long for UDP encapsulation, or original skb too long\n");
			hexdump((char*)skb->data, MIN(skb->len, 64));
		}
		return -1;
	}
	if(skb->len != skb->tail - skb->data) {
		if(net_ratelimit()) {
			printk("SKB might be fragmented\n");
		}
		return -1;
	}

	struct sk_buff *outerSKB = 
		skb_copy_expand(skb, HH_LEN + ENCAP_HEADER_LEN, 0, GFP_ATOMIC);
	if(outerSKB == NULL) {
		printk("No memory for skb copy\n");
		return -1;
	}
	kfree_skb(skb);
	// From here on, manipulate outer SKB as if it was the original SKB
	skb = outerSKB;
	skb->nh.iph = (struct iphdr *)skb->data;

	char dhBuf[64];
	struct HeaderContext src;
	struct HeaderContext dst = {.rawBuf = dhBuf};
	if(parse_and_save_headers(&dst, &src, skb, 0) != 0) {
		if(net_ratelimit()) {
			printk("encapsulate parse_and_save_headers failed\n");
		}
	}

	__u32 	orig_saddr = src.iph->saddr,
		orig_daddr = src.iph->daddr;

	// At TCP header now
	int payload_len = skb->len;

	// Push on IP-UDP header
	struct ipudp *iuh = PUSH_OR_FAIL(skb, sizeof(struct ipudp), 
		 "Could not push on IP-UDP header\n", -1);

	iuh->saddr = orig_saddr;
	iuh->daddr = orig_daddr;

	// Push on UDP header
	struct udphdr *uh = PUSH_OR_FAIL(skb, sizeof(struct udphdr), 
		 "Not enough space in skb to push on udp header\n", -1);
	uh->source = bouncePort;
	uh->dest = bouncePort;
	uh->len = htons(ENCAP_HEADER_LEN + payload_len);
	uh->check = 0; // Disable checksum

	// Push on new IP header
	{
		__u32 	outer_saddr = orig_saddr,
			outer_daddr = bounceIP;
		h_update_and_push(skb, &dst, outer_saddr, outer_daddr,
			  IPPROTO_UDP, ENCAP_HEADER_LEN, 0);
	}

	// We've allocated a completely new skb, so we have to send
	// the packet manually. Packet isn't routed yet (we're in
	// OUTPUT mangle), so do the routing ourselves

	struct rtable *rt;
	if ((rt = route(skb, 1)) == NULL) {
		printk("Could not route\n");
		kfree_skb(skb);
		return 0;
	}

	dst_release(skb->dst);
	skb->dst = &rt->u.dst;
	skb->dev = skb->dst->dev;
	ip_direct_send(skb);

	return 0;
}

static inline int
deencapsulate_packet(struct sk_buff *skb)
{
	// Save Link and IP headers for later use
	char dhBuf[64];
	struct HeaderContext src;
	struct HeaderContext dst = {.rawBuf = dhBuf};
	if(parse_and_save_headers(&dst, &src, skb, INCLUDE_LL) != 0) {
		if(net_ratelimit()) {
			printk("deencapsulate parse_and_save_headers failed\n");
		}
		return -1;
	}
	if(dst.iph->protocol != IPPROTO_UDP) {
		if(net_ratelimit()) {
			printk("Non-UDP protocol in deencapsulate\n");
		}
		return -1;
	}

	struct udphdr *uh = (struct udphdr*)  skb->data;
	PULL_OR_FAIL(skb, sizeof(struct udphdr), 
		 "Not enough space for udp header in deencapsulate\n", -1);

	TRY_PULL_OR_FAIL(skb, ntohs(uh->len) - sizeof(struct udphdr),
		"Not enough space for UDP packet in deencapsulate\n", -1);

	struct ipudp *iuh = (struct ipudp *) skb->data;
	PULL_OR_FAIL(skb, sizeof(struct ipudp),
		"Not enough space for ipudp encapsulation header\n", -1);

	// SKB should now point at TCP header
	struct tcphdr *th = (struct tcphdr *) skb->data;

	// XXX Validate destination address?
	// iuh contains the externally-visible IP addresses.
	//
	// The new IP header should be the actual IP header with just
	// a source NAT.
	//
	// If we were to change the destination, perhaps using
	// iuh->daddr, then NAT would break

	// Push on LL, IP header (computing new checksum)
	{
 		__u32 	unwrapped_saddr = iuh->saddr,
			unwrapped_daddr = dst.iph->daddr;
		h_update_and_push(skb, &dst,
			unwrapped_saddr, unwrapped_daddr,
			IPPROTO_TCP, -ENCAP_HEADER_LEN, INCLUDE_LL);
	}

	renormalize(skb, &src);
	return 0;
}

static unsigned int
target(struct sk_buff **pskb,
       unsigned int hooknum,
       const struct net_device *in,
       const struct net_device *out,
       const void *targinfo,
       void *userinfo)
{
	const struct ipt_bounce_target_info *bounceinfo = targinfo;

	switch(bounceinfo->direction) {
	case IN:
		if(deencapsulate_packet(*pskb) == 0) {
			return IPT_CONTINUE;
		} else {
			printk("deenc drop\n");
			return NF_DROP;
		}
		break;
	case OUT:
		if(encapsulate_packet_and_bounce(*pskb, bounceinfo->bounce_addr, bounceinfo->bounce_port) == 0) {
			// We do our own transmit
			return NF_STOLEN;
			// NOTE: We can't return NF_DROP: TCP detects the
			// 	drop, and will sometimes cancel state changes, or
			// 	do other things in response to local congestion
			//return IPT_CONTINUE;
		} else {
			printk("enc drop\n");
			return NF_DROP;
		}
		break;
	default:
		if(net_ratelimit()) {
			printk("Unknown bounce direction\n");
		}
		return NF_DROP;
	}
}

static int
checkentry(const char *tablename,
	   const struct ipt_entry *e,
           void *targinfo,
           unsigned int targinfosize,
           unsigned int hook_mask)
{
	struct ipt_bounce_target_info *bounceinfo = (struct ipt_bounce_target_info*) targinfo;
	if (targinfosize != IPT_ALIGN(sizeof(struct ipt_bounce_target_info))) {
		printk(KERN_WARNING "BOUNCE: targinfosize %u != %Zu\n",
		       targinfosize,
		       IPT_ALIGN(sizeof(struct ipt_bounce_target_info)));
		return 0;
	}

	switch(bounceinfo->direction) {
	case OUT:
		// supposed to hook into OUTPUT mangle
		if (strcmp(tablename, "mangle") != 0) {
			printk(KERN_WARNING "BOUNCE: can only be called from \"mangle\" table, not \"%s\"\n", tablename);
			return 0;
		}
		break;
	case IN:
		// supposed to hook into PREROUTING mangle
		if (strcmp(tablename, "mangle") != 0) {
			printk(KERN_WARNING "BOUNCE: can only be called from \"mangle\" table, not \"%s\"\n", tablename);
			return 0;
		}
		break;
	default:
		printk("Unknown direction %d\n", bounceinfo->direction);
		return 0;
	}

	return 1;
}

static struct ipt_target ipt_bounce_reg
= { { NULL, NULL }, "BOUNCE", target, checkentry, NULL, THIS_MODULE };

static int __init init(void)
{
	printk("Loaded bounce module\n");
	if (ipt_register_target(&ipt_bounce_reg))
		return -EINVAL;

	return 0;
}

static void __exit fini(void)
{
	ipt_unregister_target(&ipt_bounce_reg);
}

module_init(init);
module_exit(fini);
MODULE_LICENSE("GPL");
