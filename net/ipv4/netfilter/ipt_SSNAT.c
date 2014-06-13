/* "Stupid" SNAT implementation. 
 *
 *   Philosophy: Don't mess with conntrack or any of that nonsense,
 *   just change my darn source address!
 *
 */
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <net/checksum.h>

#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter_ipv4/ipt_SSNAT.h>

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
static void
tcp_manip_pkt(struct iphdr *iph, size_t len,
	      u_int32_t newSrcIP)
{
	struct tcphdr *hdr = (struct tcphdr *)((u_int32_t *)iph + iph->ihl);
	u_int32_t oldip;

	oldip = iph->saddr;

	/* Manipulate source address. We have 2 checksums to update:
	   IP header checksum and TCP pseudoheader checksum */
	iph->check = ip_nat_cheat_check(~oldip, newSrcIP,iph->check);
	iph->saddr = newSrcIP;

	/* this could be a inner header returned in icmp packet; in such
	   cases we cannot update the checksum field since it is outside of
	   the 8 bytes of transport layer headers we are guaranteed */
	if(((void *)&hdr->check + sizeof(hdr->check) - (void *)iph) <= len) {
		hdr->check = ip_nat_cheat_check(~oldip, newSrcIP,hdr->check);
	}
}

static unsigned int
target(struct sk_buff **pskb,
       unsigned int hooknum,
       const struct net_device *in,
       const struct net_device *out,
       const void *targinfo,
       void *userinfo)
{
	const struct ipt_ssnat_target_info *ssnatinfo = targinfo;

	tcp_manip_pkt((*pskb)->nh.iph,
		      (char*)(*pskb)->tail - (char*)(*pskb)->nh.iph, 
		      ssnatinfo->src_addr);
	return IPT_CONTINUE;
}

static int
checkentry(const char *tablename,
	   const struct ipt_entry *e,
           void *targinfo,
           unsigned int targinfosize,
           unsigned int hook_mask)
{
	if (targinfosize != IPT_ALIGN(sizeof(struct ipt_ssnat_target_info))) {
		printk(KERN_WARNING "SSNAT: targinfosize %u != %Zu\n",
		       targinfosize,
		       IPT_ALIGN(sizeof(struct ipt_ssnat_target_info)));
		return 0;
	}

	if (strcmp(tablename, "mangle") != 0) {
		printk(KERN_WARNING "SSNAT: can only be called from \"mangle\" table, not \"%s\"\n", tablename);
		return 0;
	}

	return 1;
}

static struct ipt_target ipt_ssnat_reg
= { { NULL, NULL }, "SSNAT", target, checkentry, NULL, THIS_MODULE };

static int __init init(void)
{
	if (ipt_register_target(&ipt_ssnat_reg))
		return -EINVAL;

	return 0;
}

static void __exit fini(void)
{
	ipt_unregister_target(&ipt_ssnat_reg);
}

module_init(init);
module_exit(fini);
MODULE_LICENSE("GPL");
