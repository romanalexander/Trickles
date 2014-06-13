#include <net/trickles.h>
/* Shared declarations between kernel and module */

int sysctl_dbg_cwnd = 0;

struct proto trickles_prot;

int stcp_enable_nodata = 0;
int stcp_enable_udelack = 1;
int stcp_enable_uack1 = 1;
int stcp_enable_recovery = 1;
int sysctl_trickles_mss = 1374;

int sysctl_trickles_hashcompress = 1;
//int g_trickles_mss = 1400;

#define CACHE_SYSCTL_VAR(NAME)				\
	int sysctl_trickles_##NAME##_enable = 0,	\
	sysctl_trickles_##NAME##_policy = 0,		\
	sysctl_trickles_##NAME##_hits = 0,		\
	sysctl_trickles_##NAME##_total = 0

CACHE_SYSCTL_VAR(Continuation);
CACHE_SYSCTL_VAR(Nonce);
CACHE_SYSCTL_VAR(TCB);

int trickles_rcv_default(struct sock *sk, struct sk_buff *skb) {
	return 0;
}

void trickles_destroy_default(struct sock *sk) {
}

struct MSKTable *MSKTable_new_default(int numEntries) {
	return NULL;
}

int cminisock_config_pipe_default(struct sock *sk, char *optdata, int optlen, int direction) { return -EINVAL; }

int trickles_sendv_default(int fd, struct cminisock *msk, struct tiovec *tiov, int tiovlen) { return -EINVAL; }

int trickles_send_default(int fd, struct cminisock *msk, char *buf, int len) { return -EINVAL; }

int trickles_sendfilev_default(int fd, struct cminisock *msk, struct fiovec *fiov, int fiovlen) { return -EINVAL; }

int trickles_mmap_default(struct file *file, struct socket *sock, struct vm_area_struct *vma) { return -ENODEV; }

int trickles_sock_poll_default(struct file * file, struct socket *sock, poll_table *wait) { return POLLERR; }

void trickles_init_sock_default(struct sock *sk, int val) { return; }

void trickles_send_ack_default(struct sock *sk) { return; }

int trickles_sendmsg_default(struct sock *sk, struct msghdr *msg, int size) { return -EINVAL; }

int trickles_setucont_default(int fd, struct cminisock *msk, int packetNum, char *ucont, unsigned ucont_len) { return -EINVAL; }

int trickles_setsockopt_default(struct sock *sk, int optname, int optval) { return -EINVAL; }
int trickles_getsockopt_default(struct sock *sk, int level, int optname, char *optval, int *optlen) { return -EINVAL; }

void trickles_logCwnd_default(enum LogCwndType type, int addr, int port, int seq, int ack_seq, int startCwnd, int effCwnd, int ssthresh, int rtt, int srtt) {
	return;
}

int trickles_sendbulk_default(int fd, struct mskdesc *descbuf, int descbuf_len) {
	return 0;
}

int trickles_extract_events_default(int fd, struct extract_mskdesc_in *descbuf, int descbuf_len, struct msk_collection *dest, int *destLen) {
	return -EINVAL;
}

int trickles_install_events_default(int fd, struct msk_collection *descbuf, int descbuf_len) {
	return -EINVAL;
}

void trickles_syn_piggyback_default(struct sock *sk, struct sk_buff *skb) {
	printk("piggyback_default\n");
	return;
}

int trickles_request_default(int fd, char *buf, int buf_len, int reserved_len) {
	printk("trickles_request_impl\n");
	return -1;
}

int (*trickles_rcv_hook)(struct sock *sk, struct sk_buff *skb) = trickles_rcv_default;

void (*trickles_destroy_hook)(struct sock *sk) = trickles_destroy_default;

int (*cminisock_config_pipe_hook)(struct sock *sk, char *optdata, int optlen, int direction) = cminisock_config_pipe_default;

int (*trickles_sendv_hook)(int fd, struct cminisock *msk, struct tiovec *iov, int tiovlen) = trickles_sendv_default;

int (*trickles_send_hook)(int fd, struct cminisock *msk, char *buf, int len) = trickles_send_default;

int (*trickles_sendfilev_hook)(int fd, struct cminisock *msk, struct fiovec *fiov, int fiovlen) = trickles_sendfilev_default;

int (*trickles_mmap_hook)(struct file *file, struct socket *sock, struct vm_area_struct *vma) = trickles_mmap_default;

int (*trickles_sock_poll_hook)(struct file * file, struct socket *sock, poll_table *wait) = trickles_sock_poll_default;

void (*trickles_init_sock_hook)(struct sock *sk, int val) = trickles_init_sock_default;

struct MSKTable *(*MSKTable_new)(int numEntries) = MSKTable_new_default;

void (*trickles_send_ack_hook)(struct sock *sk) = trickles_send_ack_default;

int (*trickles_sendmsg_hook)(struct sock *sk, struct msghdr *msg, int size) = trickles_sendmsg_default;

int (*trickles_setucont_hook)(int fd, struct cminisock *msk, int packetNum, char *ucont, unsigned ucont_len) = trickles_setucont_default;

int (*trickles_setsockopt_hook)(struct sock *sk, int optname, int optval) = trickles_setsockopt_default;
int (*trickles_getsockopt_hook)(struct sock *sk, int level, int optname, char *optval, int *optlen) = trickles_getsockopt_default;

void (*trickles_logCwnd_hook)(enum LogCwndType type, int addr, int port, int seq, int ack_seq, int startCwnd, int effCwnd, int ssthresh, int rtt, int srtt) = trickles_logCwnd_default;

int (*trickles_sendbulk_hook)(int fd, struct mskdesc *descbuf, int descbuf_len) = trickles_sendbulk_default;

int (*trickles_extract_events_hook)(int fd, struct extract_mskdesc_in *descbuf,int descbuf_len, struct msk_collection *dest, int *destLen) = trickles_extract_events_default;

int (*trickles_install_events_hook)(int fd, struct msk_collection *descbuf, int descbuf_len) = trickles_install_events_default;

void (*trickles_syn_piggyback_hook)(struct sock *sk, struct sk_buff *skb) = trickles_syn_piggyback_default;

int (*trickles_request_hook)(int fd, char *buf, int buf_len, int reserved_len) = trickles_request_default;

asmlinkage int sys_trickles_sendv(int fd, struct cminisock *msk, struct iovec *tiov, int tiovlen) {
	return trickles_sendv_hook(fd,msk,tiov,tiovlen);
}

asmlinkage int sys_trickles_send(int fd, struct cminisock *msk, char *buf, int len) {
	return trickles_send_hook(fd,msk,buf,len);
}

asmlinkage int sys_trickles_sendfilev(int fd, struct cminisock *msk, struct fiovec *fiov, int fiovlen) {
	return trickles_sendfilev_hook(fd,msk,fiov,fiovlen);
}

asmlinkage int sys_trickles_sendmsg(int fd, struct msghdr *user_msg, int size) {
	printk("undefined system call sys_trickles_sendmsg()\n");
	BUG();
	return -EINVAL;
}

asmlinkage int sys_trickles_setucont(int fd, struct cminisock *msk, int packetNum, char *ucont, unsigned ucont_len) {
	return trickles_setucont_hook(fd,msk,packetNum,ucont,ucont_len);
}

asmlinkage int sys_trickles_sendbulk(int fd, struct mskdesc *descbuf, int descbuf_len) {
	return trickles_sendbulk_hook(fd, descbuf, descbuf_len);
}

asmlinkage int sys_trickles_extract_events(int fd, struct extract_mskdesc_in *descbuf,int descbuf_len, struct msk_collection *dest, int *destLen) {
	return trickles_extract_events_hook(fd, descbuf, descbuf_len, dest, destLen);
}

asmlinkage int sys_trickles_install_events(int fd, struct msk_collection *descbuf, int descbuf_len) {
	return trickles_install_events_hook(fd, descbuf, descbuf_len);
}

asmlinkage int sys_trickles_request(int fd, char *buf, int buf_len, int reserved_len) {
	return trickles_request_hook(fd, buf, buf_len, reserved_len);
}

#include "rand-util.h"
