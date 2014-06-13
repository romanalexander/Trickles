#ifndef SKBSTAT_H
#define SKBSTAT_H
#include <linux/skbuff.h>

struct SKBStat {
	__u64 count;
	__u64 totalBytes;
	__u64 totalOverheadBytes;
};

#define SAFEAVG(SUM,COUNT)  (((__u32)((COUNT) >> 4)) ? ((__u32)((SUM) >> 4)) / ((__u32)((COUNT) >> 4)) : 0)

void SKBStat_update(struct SKBStat *sstat, struct sk_buff *skb, int overhead) {
	sstat->count++;
	sstat->totalBytes += skb->tail - skb->head;
	sstat->totalOverheadBytes += overhead;
}

void SKBStat_dump(struct SKBStat *sstat) {
	printk("total = %d, totalBytes = %d (%d), totalOverhead = %d (%d)\n",
	       (__u32) sstat->count, 
	       (__u32) sstat->totalBytes, (__u32) SAFEAVG(sstat->totalBytes, sstat->count), 
	       (__u32) sstat->totalOverheadBytes, (__u32) SAFEAVG(sstat->totalOverheadBytes, sstat->count));
}

#endif // SKBSTAT_H
