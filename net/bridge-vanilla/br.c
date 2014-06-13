/*
 *	Generic parts
 *	Linux ethernet bridge
 *
 *	Authors:
 *	Lennert Buytenhek		<buytenh@gnu.org>
 *
 *	$Id: br.c,v 1.1.1.1 2004/06/19 05:03:04 ashieh Exp $
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */

#include <linux/config.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/init.h>
#include <linux/if_bridge.h>
#include <linux/brlock.h>
#include <asm/uaccess.h>
#include "br_private.h"

#include "linux/proc_fs.h"

#if defined(CONFIG_ATM_LANE) || defined(CONFIG_ATM_LANE_MODULE)
#include "../atm/lec.h"
#endif

#define MIN(X,Y) (((X) < (Y)) ? (X) : (Y))

struct alloc_head_list bridgeLogHead;
int bridge_log_read_proc(char *page, char **start, off_t offset, int count,
			 int *eof, void *data);

void br_dec_use_count()
{
	MOD_DEC_USE_COUNT;
}

void br_inc_use_count()
{
	MOD_INC_USE_COUNT;
}

static int __init br_init(void)
{
	printk(KERN_INFO "NET4: Ethernet Bridge 008 - vanilla " 
#ifdef LOG_BRIDGE_PACKETS 
	       "Logging !!! "
#endif
	       "for NET4.0\n");

	br_handle_frame_hook = br_handle_frame;
	br_ioctl_hook = br_ioctl_deviceless_stub;
#if defined(CONFIG_ATM_LANE) || defined(CONFIG_ATM_LANE_MODULE)
	br_fdb_get_hook = br_fdb_get;
	br_fdb_put_hook = br_fdb_put;
#endif
	register_netdevice_notifier(&br_device_notifier);

#ifdef LOG_BRIDGE_PACKETS
	init_head(&bridgeLogHead);
	create_proc_read_entry("bridge_log", S_IRUGO | S_IWUSR,
			       NULL, bridge_log_read_proc, NULL);
#endif // LOG_BRIDGE_PACKETS

	return 0;
}

static void __br_clear_ioctl_hook(void)
{
	br_ioctl_hook = NULL;
}

static void __exit br_deinit(void)
{
	unregister_netdevice_notifier(&br_device_notifier);
	br_call_ioctl_atomic(__br_clear_ioctl_hook);

	br_write_lock_bh(BR_NETPROTO_LOCK);
	br_handle_frame_hook = NULL;
	br_write_unlock_bh(BR_NETPROTO_LOCK);

#ifdef LOG_BRIDGE_PACKETS
	struct BridgeLogEntry *bridgeEntry;
	alloc_head_walk(&bridgeLogHead, bridgeEntry) {
		struct BridgeLogEntry *clean = bridgeEntry;
		bridgeEntry = (struct BridgeLogEntry*)bridgeEntry->prev;
		unlink((struct alloc_head*)clean);
		kfree(clean);
	}
#endif // LOG_BRIDGE_PACKETS

#if defined(CONFIG_ATM_LANE) || defined(CONFIG_ATM_LANE_MODULE)
	br_fdb_get_hook = NULL;
	br_fdb_put_hook = NULL;
#endif

#ifdef LOG_BRIDGE_PACKETS
	remove_proc_entry("bridge_log", NULL);
#endif // LOG_BRIDGE_PACKETS
}

void br_log_impl(__u32 saddr, __u32 daddr, __u16 source, __u16 dest, 
		 __u32 seq, __u32 ack_seq) {
	struct BridgeLogEntry *newEntry = 
		kmalloc(sizeof(struct BridgeLogEntry), GFP_ATOMIC);
	if(newEntry == NULL) {
		return;
	}
	newEntry->saddr = saddr; newEntry->daddr = daddr;
	newEntry->source = source; newEntry->dest = dest;
	newEntry->seq = seq; newEntry->ack_seq = ack_seq;
	newEntry->sentAmount = 0;

	insert_tail(&bridgeLogHead, (struct alloc_head*)newEntry);
}

struct BoundedBuffer {
	char *dest;
	int len;
	int curPos;
};

void bb_init(struct BoundedBuffer *bb, char *buffer, int len) {
	bb->dest = buffer;
	bb->len = len;
	bb->curPos = 0;

	//printk("bbinit: %p %d %d\n", bb->dest, bb->len, bb->curPos);
}

int bb_write(struct BoundedBuffer *bb, const char *data, int len) {
	int prevPos = bb->curPos;
	int copyLen;
	bb->curPos = MIN(prevPos+len, bb->len);
	copyLen = bb->curPos - prevPos;

	memcpy(bb->dest + prevPos, data, copyLen);
	return copyLen;
}

int bridge_log_read_proc(char *page, char **start, off_t offset, int count,
			    int *eof, void *data)
{
    struct BridgeLogEntry *logEntry;
    struct BoundedBuffer bb;
    bb_init(&bb, page, count);

    local_bh_disable();
    alloc_head_walk(&bridgeLogHead, logEntry) {
	    if(1) {
		    char tempbuf[1024];
		    int wrlen, real_wrlen;
		    sprintf(tempbuf, "%X:%d=>%X:%d %u %u\n",
			    logEntry->saddr, (int)logEntry->source,
			    logEntry->daddr, (int)logEntry->dest,
			    logEntry->seq, logEntry->ack_seq);
		    // , logEntry->timestamp);
		    char *src = tempbuf + logEntry->sentAmount;
		    real_wrlen = bb_write(&bb, src, wrlen = strlen(src));
		    logEntry->sentAmount = real_wrlen;
	    
		    if(real_wrlen < wrlen) {
			    break;
		    }
		    if(real_wrlen == wrlen) {
			    struct BridgeLogEntry *clean;
			    clean = logEntry;
			    logEntry = (struct BridgeLogEntry*)logEntry->prev;
			    unlink((struct alloc_head*)clean);
			    kfree(clean);
		    }

	    }
    }
    if(empty(&bridgeLogHead)) {
	    // done with all entries
	    //printk("eof\n");
	    *eof = 1;
    } else {
	    *eof = 0;
    }
    local_bh_enable();

    //printk("curpos = %d %d\n", bb.curPos, loop_count);

    *start = page;
    return bb.curPos;
}

EXPORT_NO_SYMBOLS;

module_init(br_init)
module_exit(br_deinit)
MODULE_LICENSE("GPL");
