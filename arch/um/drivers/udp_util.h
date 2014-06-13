#ifndef UTIL_H
#define UTIL_H

static inline unsigned int csum_fold(unsigned int sum) {
	__asm__(
			"addl %1, %0		;\n"
			"adcl $0xffff, %0	;\n"
			: "=r" (sum)
			: "r" (sum << 16), "0" (sum & 0xffff0000)
	       );
	return (~sum) >> 16;
}

struct in_addr make_inaddr(__u32 addr);
const char *addrToA(__u32 addr);
__u32 aToAddr(char *str);

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
			if(mod == WIDTH - 1) {
				printk("\n");
				newlined = 1;
			} else if(mod == WIDTH/2-1) {
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

static inline __u64 macToULL(char mac[6]) {
	return (((__u64)ntohl(*(__u32*)(mac + 2))) << 16) | 
		(0xffff & ntohs(*(__u16*)(mac)));
}

static inline void addrPrintComp(char *s0, char *s1, __u32 addr0, __u32 addr1) {
	printk("%s: %s %s ", s0, addrToA(addr0), s1);
	// split in two pieces because addrToA return value 
	// is statically allocated
	printk("%s\n", addrToA(addr1));
}

#endif // UTIL_H

