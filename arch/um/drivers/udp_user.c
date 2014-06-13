#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stddef.h>
#include <sched.h>
#include <string.h>
#include <sys/errno.h>
#include <sys/wait.h>
#include <sys/signal.h>
#include "user_util.h"
#include "kern_util.h"
#include "user.h"
#include "net_user.h"
#include "udp.h"
#include "helper.h"
#include "os.h"

#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/if_ether.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/tcp.h>
#include "udp_util.h"

#define SUPPORT_NAT
static int gDebugLevel = 0;

#ifdef INCLUDE_MAC
	#error INCLUDE_MAC support does not work
#endif

/* Checksum */
unsigned int csum_partial(const unsigned char * buff, int len, unsigned int sum);

static inline unsigned short ip_compute_csum(unsigned char * buff, int len)
{
	return csum_fold (csum_partial(buff, len, 0));
}

static inline unsigned long csum_tcpudp_nofold(unsigned long saddr,
						   unsigned long daddr,
						   unsigned short len,
						   unsigned short proto,
						   unsigned int sum)
{
    __asm__(
	"addl %1, %0	;\n"
	"adcl %2, %0	;\n"
	"adcl %3, %0	;\n"
	"adcl $0, %0	;\n"
	: "=r" (sum)
	: "g" (daddr), "g"(saddr), "g"((ntohs(len)<<16)+proto*256), "0"(sum));
    return sum;
}

/*
 * computes the checksum of the TCP/UDP pseudo-header
 * returns a 16-bit checksum, already complemented
 */
static inline unsigned short int csum_tcpudp_magic(unsigned long saddr,
						   unsigned long daddr,
						   unsigned short len,
						   unsigned short proto,
						   unsigned int sum)
{
	return csum_fold(csum_tcpudp_nofold(saddr,daddr,len,proto,sum));
}


/* We do checksum mangling, so if they were wrong before they're still
 * wrong.  Also works for incomplete packets (eg. ICMP dest
 * * unreachables.) */
static inline u_int16_t
ip_nat_cheat_check(u_int32_t oldvalinv, u_int32_t newval, u_int16_t oldcheck)
{
	u_int32_t diffs[] = { oldvalinv, newval };
	return csum_fold(csum_partial((char *)diffs, sizeof(diffs),
				oldcheck^0xFFFF));
}

static inline __u16 tcp_v4_check(struct tcphdr *th, int len,
				   unsigned long saddr, unsigned long daddr, 
				   unsigned long base)
{
	return csum_tcpudp_magic(saddr,daddr,len,IPPROTO_TCP,base);
}

/* UDP encapuslation */

struct ipudp {
	__u32 saddr, daddr;
	// TODO: Add protocol field
	char data[0];
} __attribute__ ((packed));

#define CHECK_SOCKET(FD) 		\
	if(pri->socket != FD) { 	\
		printk("%d: pri->socket (%d) != fd (%d)\n", __LINE__, pri->socket, (FD)); \
	}
#define DEBUG(N, STR, ...) \
	do { if(gDebugLevel >= N) printk(STR, ##__VA_ARGS__); } while(0)

#define DEBUG_GUARD(N, STMTS) \
	do { if(gDebugLevel >= N) { STMTS; } } while(0)


void udp_user_init(void *data, void *dev)
{
	struct udp_data *pri = data;
	pri->dev = dev;
}

static int udp_open(void *data)
{
	struct udp_data *pri = data;

	int sock;
	struct sockaddr_in sin;
	int protocol = IPPROTO_UDP;
	int raw_mode = 0, semantics = -1;

	if(!raw_mode) {
		semantics = SOCK_DGRAM;
	} else {
		perror("only cooked mode supoprted");
		return -1;
	}

	if ((sock = socket(PF_INET, semantics, protocol)) < 0) {
		perror("socket");
		return -1;
	}

	bzero((char *)& sin, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = pri->local_port;
	sin.sin_addr.s_addr = pri->local_addr;

	if ((bind(sock, (struct sockaddr *)& sin, sizeof(sin))) < 0) {
		perror("bind");
		return -1;
	}

	pri->socket = sock;

	return sock;
}

static void udp_close(int fd, void *data)
{
	struct udp_data *pri = data;
	CHECK_SOCKET(fd);
	close(pri->socket);
}

int udp_user_read(int fd, void *buf, int len, struct udp_data *pri)
{
	char buffer[BUF_SIZE], *udpStart = buffer + sizeof(struct iphdr);
	CHECK_SOCKET(fd);
 
#ifdef INCLUDE_MAC
	#error INCLUDE_MAC support does not work
#endif
	const int invalidPacketLen = -1;
	struct sockaddr_in srcAddr;
	int srcAddrLen = sizeof(struct sockaddr_in);
	int rcv_packet_len = invalidPacketLen;
	__u32 srcIP;

	if ((rcv_packet_len = recvfrom(fd, udpStart, BUF_SIZE, 0, 
		(struct sockaddr *) & srcAddr, &srcAddrLen)) <= 0) {
		//DEBUG(1, "recvfrom");
		return 0;
	}
	srcIP = srcAddr.sin_addr.s_addr;

	if(rcv_packet_len > 0) {
		DEBUG(2,"Packet recv'd(%d); need to perform unwrap operation\n",
			rcv_packet_len);
		/* XXX Copy unwrap code from kernel-level skbuff reorg stuff
		 * */
		struct ipudp *iuh = (struct ipudp *)udpStart;
		char *dataStart = (char*)(iuh + 1);
		struct iphdr *iph = ((struct iphdr*)dataStart) - 1;
		struct tcphdr *th = (struct tcphdr *)dataStart;

		int cookedLen = rcv_packet_len - sizeof(struct ipudp) + 
			sizeof(struct iphdr);

		if(cookedLen < sizeof(struct tcphdr)) {
			printk("Cooked length is shorter than minimum tcp "
				"header len\n");
			return 0;
		}

		__u16 origCheck = th->check;
		// This code does NOT respect the ipudp src and dest addresses
		// Remove UDP header; push on IP header
		if(iuh->saddr != srcIP) {
#ifndef SUPPORT_NAT
			addrPrintComp("IPUDP header src did not match addr",
				"!=",iuh->saddr, srcIP);
			return 0;
#else
			// th->check adjustment needed
			th->check = 
				ip_nat_cheat_check(~iuh->saddr, srcIP,
						th->check);
#endif
		}

		if(iuh->daddr != pri->local_addr) {
#ifndef SUPPORT_NAT
			addrPrintComp("IPUDP header dest did not match addr",
				"!=",iuh->daddr, pri->local_addr); 
			return 0;
#else
			// th->check adjustment needed
			th->check = 
				ip_nat_cheat_check(~iuh->daddr, pri->local_addr, 
						th->check);
#endif
		}

		int ihl = sizeof(*iph);

		iph->version = 4;
		iph->ihl = ihl / 4;
		iph->tos = 0;
		iph->tot_len = htons(cookedLen);
		static int ip_id = 0;
		iph->id = ip_id++;
		iph->frag_off = 0;
		iph->ttl = 255;
		iph->protocol = IPPROTO_TCP;
		iph->check = 0;
#ifdef SUPPORT_NAT
		iph->saddr = srcIP;
		iph->daddr = pri->local_addr;
#else
		iph->saddr = iuh->saddr;
		iph->daddr = iuh->daddr;
#endif
		iph->check = ip_compute_csum((unsigned char *)iph, ihl);

		// XXX should copy protocol from an ipudp field
		DEBUG(2,"Returning cooked length %d, "
			"origCheck = %d, newCheck = %d\n",
		       	cookedLen, origCheck, th->check);
		DEBUG_GUARD(2, printk("IPH: "); hexdump((char*)iph, ihl) ); 

		memcpy(buf, (char*)iph, cookedLen);
		return(cookedLen);
	}
	return 0;
}

int udp_user_write(int fd, void *buf, int len, struct udp_data *pri)
{
	char temp_buffer[BUF_SIZE];

	// Remove MAC and IP headers
	struct iphdr *iph;
#ifdef INCLUDE_MAC
#define MACLEN (sizeof(struct ethhdr))
	struct ethhdr *ethh = (struct ethhdr *)buf;
	iph = (struct iphdr*)(ethh + 1);
#else
	iph = (struct iphdr*) buf;
#define MACLEN (0)
#endif // INCLUDE_MAC

	int ihl = iph->ihl * 4; 
	__u32 	srcAddr = iph->saddr,
		destAddr = iph->daddr;
	__u16 	dstPort = pri->remote_port;

	char *dataStart = (char*)iph + ihl;
	int dataLen = len - MACLEN - ihl;

	DEBUG_GUARD(2, printk("IPH: "); hexdump((char*)iph, ihl) );

#if 1
	{
#ifdef INCLUDE_MAC
		DEBUG(2, "write mac: %Xll=>%Xll proto = %d\n", 
			macToULL(ethh->h_source), macToULL(ethh->h_dest),
			ethh->h_proto);
#endif // INCLUDE_MAC
		DEBUG(2, "write ip: len = %d, iph->ihl = %d, proto = %d\n", 
			len, iph->ihl, iph->protocol);
	}
#endif

	// Push on udp header
	int send_packet_len = 0;
	struct ipudp *iuh = (struct ipudp *)temp_buffer;
	send_packet_len += sizeof(struct ipudp);
	iuh->saddr = srcAddr;
	iuh->daddr = destAddr;

	// Copy data
	memcpy((char *)(iuh + 1), dataStart, dataLen);
	send_packet_len += dataLen;

	DEBUG_GUARD(2, printk("PostIUH: "); hexdump((char*)(iuh + 1), dataLen); );

	struct sockaddr_in dstAddr;
	bzero(&dstAddr, sizeof(dstAddr));
	dstAddr.sin_family = AF_INET;
	dstAddr.sin_port = dstPort;
	dstAddr.sin_addr.s_addr = destAddr;

	if (sendto(fd, (char*) iuh, send_packet_len, 0,
		(struct sockaddr *) & dstAddr, sizeof(dstAddr)) < 0) {
		DEBUG(1, "sendto");
		DEBUG(1, "socket = %d, send_packet_len = %d, dstAddr = %s\n",
				fd, send_packet_len,
				addrToA(dstAddr.sin_addr.s_addr));
		return 0;
	}
	DEBUG(2, "sendto %d %s\n", send_packet_len, 
			addrToA(dstAddr.sin_addr.s_addr));
	return len;
}

static int udp_set_mtu(int mtu, void *data)
{
	return(mtu);
}

struct net_user_info udp_user_info = {
	.init		= udp_user_init,
	.open		= udp_open,
	.close	 	= udp_close,
	.remove	 	= NULL,
	.set_mtu	= udp_set_mtu,
	.add_address	= NULL,
	.delete_address = NULL,
	.max_packet	= BUF_SIZE
};

struct in_addr make_inaddr(__u32 addr) {
	struct in_addr rval = {addr};
	return rval;
}

const char *addrToA(__u32 addr) {
        return inet_ntoa(make_inaddr(addr));
}

__u32 aToAddr(char *str) {
	return inet_addr(str);
}

/*
 * Overrides for Emacs so that we follow Linus's tabbing style.
 * Emacs will notice this stuff at the end of the file and automatically
 * adjust the settings for this buffer only.  This must remain at the end
 * of the file.
 * ---------------------------------------------------------------------------
 * Local variables:
 * c-file-style: "linux"
 * End:
 */
