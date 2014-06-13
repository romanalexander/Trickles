#include "linux/kernel.h"
#include "linux/stddef.h"
#include "linux/init.h"
#include "linux/netdevice.h"
#include "linux/if_arp.h"
#include "net_kern.h"
#include "net_user.h"
#include "kern.h"
#include "udp.h"

#include "udp_util.h"

//#include <assert.h>
#define assert(X) if(!X) { 					\
	printk("Assertion " ## #X ## " failed at %s:%d\n", 	\
		__FILE__, __LINE__)

struct udp_init {
	struct arg_list_dummy_wrapper argw;  /* XXX should be simpler... */
	__u32 local_addr;
	__u16 local_port;
	__u16 remote_port;
};

void udp_init(struct net_device *dev, void *data)
{
	struct uml_net_private *private;
	struct udp_data *spri;
	struct udp_init *init = data;
	int i;

	private = dev->priv;
	spri = (struct udp_data *) private->user;
	*spri = ((struct udp_data)
		{ .mode 	= LINUX,
		  .argw 	= init->argw,
		  .local_addr	= 0,
		  .local_port	= 0,
		  .remote_port	= 0
		  });

	dev->init = NULL;
	dev->hard_header_len = 0;
	dev->addr_len = 4;
	dev->type = ARPHRD_ETHER;
	dev->tx_queue_len = 256;
	dev->flags = IFF_NOARP;
	printk("UDP backend - commandline is ");
	for(i=0;spri->argw.argv[i]!=NULL;i++) {
		printk(" '%s'",spri->argw.argv[i]);
	}

	spri->local_addr = init->local_addr;
	spri->local_port = init->local_port;
	spri->remote_port = init->remote_port;
	udp_data_dump(spri);
	printk("\n");
}

static unsigned short udp_protocol(struct sk_buff *skbuff)
{
	return(htons(ETH_P_IP));
}

static int udp_read(int fd, struct sk_buff **skb, 
		       struct uml_net_private *lp)
{
	return(udp_user_read(fd, (*skb)->mac.raw, (*skb)->dev->mtu, 
			      (struct udp_data *) &lp->user));
}

static int udp_write(int fd, struct sk_buff **skb,
		      struct uml_net_private *lp)
{
	return(udp_user_write(fd, (*skb)->data, (*skb)->len, 
			       (struct udp_data *) &lp->user));
}

struct net_kern_info udp_kern_info = {
	.init			= udp_init,
	.protocol		= udp_protocol,
	.read			= udp_read,
	.write			= udp_write,
};

static int udp_setup(char *str, char **mac_out, void *data)
{
	struct udp_init *init = data;
	char *srcAddr, *srcPortStr, *dstPortStr;
	int i=0;

	*init = ((struct udp_init)
		{ argw :		{ { "udp", NULL  } } });

	// Split on commas
	str = split_if_spec(str, mac_out, &srcAddr, 
			&srcPortStr, &dstPortStr, 
			NULL);


	init->local_addr = aToAddr(srcAddr);
	init->local_port = htons(atoi(srcPortStr));
	init->remote_port = htons(atoi(dstPortStr));

	if(str == NULL) {
		printk("No command line arguments after remote_port\n");
		return(1);
	}

	do {
		if(i>=UDP_MAX_ARGS-1) {
			printk("udp_setup: truncating udp arguments\n");
			break;
		}
		init->argw.argv[i++] = str;
		while(*str && *str!=',') {
			if(*str=='_') *str=' ';
			str++;
		}
		if(*str!=',')
			break;
		*str++='\0';
	} while(1);
	init->argw.argv[i]=NULL;
	return(1);
}

static struct transport udp_transport = {
	.list 		= LIST_HEAD_INIT(udp_transport.list),
	.name 		= "udp",
	.setup  	= udp_setup,
	.user 		= &udp_user_info,
	.kern 		= &udp_kern_info,
	.private_size 	= sizeof(struct udp_data),
	.setup_size 	= sizeof(struct udp_init),
};

static int register_udp(void)
{
	register_transport(&udp_transport);
	return(1);
}

__initcall(register_udp);

void udp_data_dump(struct udp_data *data) {
	printk("Using addr %s:%d:%d\n", addrToA(data->local_addr),
			ntohs(data->local_port), ntohs(data->remote_port));
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
