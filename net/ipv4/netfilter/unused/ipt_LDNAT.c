/* "Load balancing" DNAT implementation. 
 *
 *   
 *
 */
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <net/checksum.h>

#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter_ipv4/ipt_SDNAT.h>

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

static inline int sourceHash(__u32 saddr, __u16 sport) {
	return tcp_hashfn(0,0,saddr,sport);
}

// based on tcp nat function of the same name
static void
tcp_manip_pkt(struct iphdr *iph, size_t len,
	      u_int32_t newDstIP)
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

static unsigned int
target(struct sk_buff **pskb,
       unsigned int hooknum,
       const struct net_device *in,
       const struct net_device *out,
       const void *targinfo,
       void *userinfo)
{
	const struct ipt_sdnat_target_info *sdnatinfo = targinfo;
	u_int32_t dstAddr;
	struct iphdr *iph = (*pskb)->nh.iph;
	struct tcphdr *th = (struct tcphdr *)((__u32*)iph + iph->ihl);
#if 0
	if(net_ratelimit()) {
		printk("SDNAT target fired\n");
	}
#endif
	switch(sdnatinfo->algorithm) {
	case TCP_HASH: {
#if 0
		static int lasthash = -1;
		int hash = sourceHash(iph->saddr, 
				      th->source);
		if(hash != lasthash || net_ratelimit()) {
			printk("hash=%d (%d %d)\n", hash,
			       iph->saddr,
			       th->source);
		}
		lasthash = hash;
#endif
		int index = sourceHash(iph->saddr,th->source) % 
			sdnatinfo->numDstAddrs;
		dstAddr = sdnatinfo->dst_addrs[index];
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
	const struct ipt_sdnat_target_info *sdnatinfo = targinfo;
	if (targinfosize != IPT_ALIGN(sizeof(struct ipt_sdnat_target_info))) {
		printk(KERN_WARNING "SDNAT: targinfosize %u != %Zu\n",
		       targinfosize,
		       IPT_ALIGN(sizeof(struct ipt_sdnat_target_info)));
		return 0;
	}
	if (sdnatinfo->numDstAddrs > MAX_NUM_DST_ADDRS) {
		printk(KERN_WARNING "SDNAT: too many destination addresses\n");
		return 0;
	}

	if (strcmp(tablename, "mangle") != 0) {
		printk(KERN_WARNING "SDNAT: can only be called from \"mangle\" table, not \"%s\"\n", tablename);
		return 0;
	}

	return 1;
}

static struct ipt_target ipt_sdnat_reg
= { { NULL, NULL }, "SDNAT", target, checkentry, NULL, THIS_MODULE };

static int __init init(void)
{
	if (ipt_register_target(&ipt_sdnat_reg))
		return -EINVAL;

	return 0;
}

static void __exit fini(void)
{
	ipt_unregister_target(&ipt_sdnat_reg);
}

module_init(init);
module_exit(fini);
MODULE_LICENSE("GPL");
