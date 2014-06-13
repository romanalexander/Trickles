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
