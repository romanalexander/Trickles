/* "Stupid" "Swap" NAT implementation. 
 *
 * This code implements a src/dst swap hack to enable some forms of
 * stateless many-one NAT
 *
 *   Standard Many-One NAT creates non-trivial mappings in protocol
 *   fields such as IP address and port number. To reverse these
 *   mappings, the NAT box needs to record information about the
 *   mapping of each connection.
 *
 *   One could avoid this restriction by adding a "NAT" field to the
 *   protocol headers that contains the inverse mapping information.
 *   See Stoica's SCORE paper for other tricks for constructing some
 *   other forms of stateless mappings.
 *
 *   This module implements part of a specialized alternative.
 *   External to internal addresses are destination NATed, as in the
 *   "triangle" topology. However, instead of sending a reply directly
 *   to the client, the server nodes send the reply through the NAT
 *   box, which is then sent back to this client.
 *
 *   To force the packets through the NAT box, we perform packet
 *   mangling on the servers to change the destination to the NAT's IP
 *   address. By default, the source address is the server's (or the
 *   NAT box's, in the case of triangle). However, this configuration
 *   requires the NAT box to store state to invert the original mapping.
 *
 *   Swap NAT is installed on a server's mangle chain, and (evilly)
 *   stores the final destination in the source address field. The
 *   destination address is still set to the NAT box. Thus, the
 *   source/dest are "swapped" from that in the triangle SSNAT/SDNAT
 *   algorithm. With this hack, the NAT box only needs to perform a
 *   swap between source/destination addresses to generate a
 *   properly-formatted final output.
 *
 *   Yet another trick of a similar flavor forces the clients to be
 *   remote addresses (e.g., outside the server subnet). Thus, the
 *   servers will unicast to the gateway packets that are destined for
 *   these remote addresses. The gateway happens to be a NAT box. The
 *   problem with this approach is that it assumes direct Layer-2
 *   connectivity between the servers and the gateway, whereas Swap
 *   NAT behaves properly when only Layer-3 connectivity is available.
 *
 *   Unfortunately, Linux seems to perform filtering of mangle changes
 *   at the OUTPUT layer which blocks packets that have a bogus source
 *   address. Therefore, we split the processing into two phases, one
 *   in the OUTPUT layer, to generate the proper destination, and
 *   another in the POSTROUTING layer, to rewrite the source address.
 *
 */
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <net/checksum.h>

#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter_ipv4/ipt_SWNAT.h>

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

static inline void
server_manip_pkt0(struct sk_buff *skb, size_t len, u_int32_t newDstIP)
{
	return;
}

// XXX Need to use destination caching
static int reroute(struct sk_buff *skb, __u32 ip) {
	struct rtable *rt;
	struct rt_key key;
	key.dst = ip;
	key.src = 0;
	key.tos = RT_TOS(skb->nh.iph->tos)|RTO_CONN;
	key.oif = 0;
	if (ip_route_output_key(&rt, &key) != 0) {
		if(net_ratelimit()) {
			printk("could not route in SWNAT\n");
			if(skb->dst) {
				dst_release(skb->dst);
				skb->dst = NULL;
			}
			return 0;
		}
	}
	skb->dst = dst_clone(&rt->u.dst);
	ip_rt_put(rt);
	return 1;
}	

static inline int
server_manip_pkt1(struct sk_buff *skb, size_t len, u_int32_t newDstIP) {
	struct iphdr *iph = skb->nh.iph;
	struct tcphdr *hdr = (struct tcphdr *)((u_int32_t *)iph + iph->ihl);
	u_int32_t oldDest, oldSrc;

	oldSrc = iph->saddr;
	oldDest = iph->daddr;

	// Look up new route (taken from ipt_MASQUERADE code)
	if(!reroute(skb, newDstIP)) 
		return 0;

	/* Manipulate source address. We have 2 checksums to update:
	   IP header checksum and TCP pseudoheader checksum */
	/* Note that the end-to-end result of all the cascaded filters
	   between server and client is to change the source address.
	 */

	iph->saddr = iph->daddr;
	iph->daddr  = newDstIP;
#if 0
	iph->check = ip_nat_cheat_check(~oldSrc,newDstIP,iph->check);
#else
	iph->check = 0;
	iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);
#endif
	/* this could be a inner header returned in icmp packet; in such
	   cases we cannot update the checksum field since it is outside of
	   the 8 bytes of transport layer headers we are guaranteed */
	if(((void *)&hdr->check + sizeof(hdr->check) - (void *)iph) <= len) {
		hdr->check = ip_nat_cheat_check(~oldSrc,newDstIP,hdr->check);
	}
	return 1;
}

// doesn't work; not routable
//#define SPACEY_ADDRESS (0xFF00007F)

// 192.168.0.254
#define SPACEY_ADDRESS (0xFE00A8C0)
// SPACEY_ADDRESS _must_ be routable!!!
// XXX make spacey_address a parameter

static int
nat_manip_pkt0(struct sk_buff *skb) {
	struct iphdr *iph = skb->nh.iph;

	//  Due to the properties of the TCP and IP checksums,
	//  swapping the source and destination addresses does not
	//  require a checksum update

	iph->daddr = iph->saddr;
	iph->saddr = SPACEY_ADDRESS;

#if 0
	// XXX current version of linux doesn't care about checksum
	// during internal processing
	iph->check = 0;
	iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);
#endif

	return 1;
}

static int
nat_manip_pkt1(struct sk_buff *skb, __u32 natAddr) {
	struct iphdr *iph = skb->nh.iph;

 	if(iph->saddr == SPACEY_ADDRESS)
		iph->saddr = natAddr;

	// rechecksum
	iph->check = 0;
	iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);

	return 1;
}

static unsigned int
target(struct sk_buff **pskb,
       unsigned int hooknum,
       const struct net_device *in,
       const struct net_device *out,
       const void *targinfo,
       void *userinfo)
{
	const struct ipt_swnat_target_info *swnatinfo = targinfo;

	switch(swnatinfo->algorithm) {
	case SWNAT_SERVER0:
		server_manip_pkt0((*pskb),
				  (char*)(*pskb)->tail - 
				  (char*)(*pskb)->nh.iph, 
				  swnatinfo->nat_addr);
		break;
	case SWNAT_SERVER1:
		if(!server_manip_pkt1((*pskb),
				      (char*)(*pskb)->tail - 
				      (char*)(*pskb)->nh.iph, 
				      swnatinfo->nat_addr)) {
			return NF_DROP;
		}
		break;
	case SWNAT_NATBOX0:
		if(!nat_manip_pkt0((*pskb))) {
			return NF_DROP;
		}
		break;
	case SWNAT_NATBOX1:
		if(!nat_manip_pkt1((*pskb), swnatinfo->nat_addr)) {
			return NF_DROP;
		}
		break;
	default:
		if(net_ratelimit()) {
			printk("SWNAT: Unknown protocol type!\n");
		}
	}
	return IPT_CONTINUE;
}

static int
checkentry(const char *tablename,
	   const struct ipt_entry *e,
           void *targinfo,
           unsigned int targinfosize,
           unsigned int hook_mask)
{
	const struct ipt_swnat_target_info *swnatinfo = targinfo;
	if (targinfosize != IPT_ALIGN(sizeof(struct ipt_swnat_target_info))) {
		printk(KERN_WARNING "SWNAT: targinfosize %u != %Zu\n",
		       targinfosize,
		       IPT_ALIGN(sizeof(struct ipt_swnat_target_info)));
		return 0;
	}

	if (strcmp(tablename, "mangle") != 0) {
		printk(KERN_WARNING "SWNAT: can only be called from \"mangle\" table, not \"%s\"\n", tablename);
		return 0;
	}

	// Verify that valid algorithm was requested
	switch(swnatinfo->algorithm) {
	case SWNAT_SERVER0:
		printk(KERN_WARNING "SWNAT: SERVER0 algorithm no longer used\n");
		return 0;
		break;
	case SWNAT_SERVER1:
		break;
	case SWNAT_NATBOX0:
		break;
	case SWNAT_NATBOX1:
		break;
	default:
		printk(KERN_WARNING "SWNAT: unknown algorithm '%d' specified\n", swnatinfo->algorithm);
		return 0;
	}

	return 1;
}

static struct ipt_target ipt_swnat_reg
= { { NULL, NULL }, "SWNAT", target, checkentry, NULL, THIS_MODULE };

static int __init init(void)
{
	if (ipt_register_target(&ipt_swnat_reg))
		return -EINVAL;

	return 0;
}

static void __exit fini(void)
{
	ipt_unregister_target(&ipt_swnat_reg);
}

module_init(init);
module_exit(fini);
MODULE_LICENSE("GPL");
