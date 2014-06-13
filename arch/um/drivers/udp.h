#ifndef __UM_UDP_H
#define __UM_UDP_H

#define BUF_SIZE 1500
#define UDP_MAX_ARGS 100
struct arg_list_dummy_wrapper { char *argv[UDP_MAX_ARGS]; };
#include <asm/types.h>

enum UDP_Mode {
	PLANETLAB,
	LINUX
};

struct udp_data {
	void *dev;
	int socket;
	enum UDP_Mode mode;

	struct arg_list_dummy_wrapper argw;

	// Setup options
	__u32 local_addr;
	// Remote addr is determined by IP header from Linux
	__u16 local_port;
	__u16 remote_port;
};

void udp_data_dump(struct udp_data *data);

extern struct net_user_info udp_user_info;

extern int set_umn_addr(int fd, char *addr, char *ptp_addr);
extern int udp_user_read(int fd, void *buf, int len, struct udp_data *pri);
extern int udp_user_write(int fd, void *buf, int len, struct udp_data *pri);

#endif

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
