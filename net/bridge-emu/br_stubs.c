#include <linux/kernel.h>
#include <linux/if_bridge.h>
#include <linux/smp_lock.h>
#include <asm/uaccess.h>
#include "br_private.h"
#include "br_private_stp.h"

void br_become_root_bridge(struct net_bridge *br) { }

int  br_is_root_bridge(struct net_bridge *br) {	return 0; }

void br_port_state_selection(struct net_bridge *br) { }

void br_topology_change_detection(struct net_bridge *br) { }

void br_transmit_config(struct net_bridge_port *p) { }

void br_config_bpdu_generation(struct net_bridge *br) { }

/* called under ioctl_lock or bridge lock */
struct net_bridge_port *br_get_port(struct net_bridge *br, int port_no)
{
	struct net_bridge_port *p;

	p = br->port_list;
	printk("port list head %p\n", p);
	while (p != NULL) {
		printk("port %p, portno %d\n", p, p->port_no);
		if (p->port_no == port_no)
			return p;

		p = p->next;
	}

	return NULL;
}

void br_configuration_update(struct net_bridge *br) { }

int br_is_designated_port(struct net_bridge_port *p) { return 0; }

void br_transmit_tcn(struct net_bridge *br) { }

