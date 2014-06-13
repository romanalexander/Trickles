// XXX DO NOT INCLUDE FROM ANY FILE OTHER THAN TRICKLES.H XXX
#ifndef _IN_TRICKLES_H
	#error "File can only be included from trickles.h"
#endif // _IN_TRICKLES_H 


// Trickles user api symbols

#ifndef USERTEST

#ifdef __KERNEL__
int trickles_mmap_impl(struct file *file, struct socket *sock, struct vm_area_struct *vma);
int trickles_sock_poll_impl(struct file * file, struct socket *sock, poll_table *wait);
void trickles_syn_piggyback_impl(struct sock *sk, struct sk_buff *skb);
#endif // __KERNEL__

void trickles_close(struct sock *sk, long timeout);
int trickles_sendmsg(struct sock *sk, struct msghdr *msg, int size);

void trickles_init_sock_impl(struct sock *sk, int val);

int cminisock_config_pipe_impl(struct sock *sk, char *optdata, int optlen, int direction);
int trickles_sendv_impl(int fd, struct cminisock *msk, struct tiovec *user_tiov, int tiovlen);
int trickles_sendfilev_impl(int fd, struct cminisock *msk, struct fiovec *user_fiov, int fiovlen);
int trickles_send_impl(int fd, struct cminisock *msk, char *buf, int len);

int trickles_setucont_impl(int fd, struct cminisock *msk, int pkt_num, char *ucont, unsigned ucont_len);

int trickles_setsockopt_impl(struct sock *sk, int optname, int optval);
int trickles_getsockopt_impl(struct sock *sk, int level, int optname, char *optval, int *optlen);

int trickles_client_recvmsg(struct sock *sk, struct msghdr *msg,
				    int len, int nonblock, int flags, int *addr_len);

struct mskdesc;
int trickles_sendbulk_impl(int fd, struct mskdesc *descbuf, int descbuf_len);

int trickles_extract_events_impl(int fd, struct extract_mskdesc_in *descbuf, int descbuf_len, struct msk_collection *dest, int *destLen);
int trickles_install_events_impl(int fd, struct msk_collection *descbuf, int descbuf_len);

int trickles_request_impl(int fd, char *buf, int buf_len, int reserved_len);

#endif // USERTEST

/* Trickles_mmap_ctl necessary for clients */

struct trickles_mmap_ctl {
	/* Shared memory is divided into read/write and read-only
	   portions. Read/write is for "safe" objects, e.g. client
	   continuation, client commands. Read-only is for kernel
	   continuation and other sensitive control information */
#define IN_TRICKLES_RW(TP,X) ((TP)->cminisock_api_config.cfg.ctl->rw_base <= (X) && (X) <= ((char*)(TP)->cminisock_api_config.cfg.ctl->rw_base + (TP)->cminisock_api_config.cfg.ctl->rw_len))

  // IS_TRICKLES_SOCK_ADDR is not a pretty condition. The upper address limit is not cleanly expressed.
#define KERNEL_MSK_BASE_ADDR(TP) ((TP)->cminisock_api_config.cfg.ctl->minisock_base)
#define KERNEL_MSK_LIMIT_ADDR(TP) ((TP)->cminisock_api_config.cfg.ctl->minisock_limit)

#if 1 // 0820 refactor for readability
#define IS_TRICKLES_SOCK_ADDR(TP,X) (((((char*)(X) - (char*)KERNEL_MSK_BASE_ADDR(TP)) % sizeof(struct cminisock)) == 0) && \
				     (((void*)((struct cminisock *)(X))) >= ((void*)KERNEL_MSK_BASE_ADDR(TP)) && ((void*)((struct cminisock *)(X) + 1)) <= KERNEL_MSK_LIMIT_ADDR(TP)))
#else
#define IS_TRICKLES_SOCK_ADDR(TP,X) (((((char*)(X) - (char*)(TP)->cminisock_api_config.cfg.ctl->minisock_base) % sizeof(struct cminisock)) == 0) && \
			((struct cminisock *)(X)) >= (TP)->cminisock_api_config.cfg.ctl->minisock_base && ((char*)(X) + sizeof(struct cminisock) - (char*)(TP)->cminisock_api_config.cfg.ctl->ro_base <= (TP)->cminisock_api_config.cfg.ctl->ro_len))
#endif
	void *rw_base;
	int rw_offs;
	__u32 rw_len;
	struct cminisock *minisock_base;
	void *minisock_limit;
	void *heap_base;

	void *ro_base;
	int ro_offs;
	int minisock_offs;

	struct pminisock *pminisock_base;
	int pminisock_offs;
	void *pminisock_limit;

	__u32 ro_len;

	struct alloc_head_list msk_eventlist;
	struct dlist pmsk_eventlist;

	atomic_t update_since_poll;
};

#ifdef __KERNEL__

/* force tcp_data_queue to accept data */
#define TRICKLES_DATAQUEUE_OVERRIDE(TP) (((TP)->trickles_opt & TCP_TRICKLES_ENABLE) && !((TP)->trickles_opt & TCP_TRICKLES_RSERVER))

#define INCLUDE_PACKET_HELPERS
#ifndef USERTEST
#include <net/trickles_packet.h>
#else
#include "trickles_packet.h"
#endif

#ifndef USERTEST
extern int (*trickles_send_hook)(int fd, struct cminisock *msk, char *buf, int len);
       int trickles_send_default(int fd, struct cminisock *msk, char *buf, int len);

extern int (*trickles_sendv_hook)(int fd, struct cminisock *msk, struct tiovec *tiov, int tiovlen);
       int trickles_sendv_default(int fd, struct cminisock *msk, struct tiovec *tiov, int tiovlen);

extern int (*trickles_sendfilev_hook)(int fd, struct cminisock *msk, struct fiovec *fiov, int fiovlen);
       int trickles_sendfilev_default(int fd, struct cminisock *msk, struct fiovec *fiov, int fiovlen);

extern int (*trickles_mmap_hook)(struct file *file, struct socket *sock, struct vm_area_struct *vma);
       int trickles_mmap_default(struct file *file, struct socket *sock, struct vm_area_struct *vma);

extern int (*trickles_sock_poll_hook)(struct file * file, struct socket *sock, poll_table *wait);
       int trickles_sock_poll_default(struct file * file, struct socket *sock, poll_table *wait);

extern void (*trickles_send_ack_hook)(struct sock *sk);
       void trickles_send_ack_default(struct sock *sk);

extern int (*trickles_setucont_hook)(int fd, struct cminisock *msk, int pktNum, char *ucont, unsigned ucont_len);
       int trickles_setucont_default(int fd, struct cminisock *msk, int pktNum, char *ucont, unsigned ucont_len);

extern int (*trickles_setsockopt_hook)(struct sock *sk, int optname, int optval);
         int trickles_setsockopt_default(struct sock *sk, int optname, int optval);

extern int (*trickles_getsockopt_hook)(struct sock *sk, int level, int optname, char *optval, int *optlen);
       int trickles_getsockopt_default(struct sock *sk, int level, int optname, char *optval, int *optlen);

//extern void (*trickles_client_connected_hook)(struct sock *sk);
//       void trickles_client_connected_default(struct sock *sk);

extern void (*trickles_init_sock_hook)(struct sock *sk, int val);
       void trickles_init_sock_default(struct sock *sk, int val);

extern int (*trickles_sendmsg_hook)(struct sock *sk, struct msghdr *msg, int size);
       int trickles_sendmsg_default(struct sock *sk, struct msghdr *msg, int size);

extern int (*trickles_sendbulk_hook)(int fd, struct mskdesc *descbuf, int descbuf_len);
       int trickles_sendbulk_default(int fd, struct mskdesc *descbuf, int descbuf_len);

extern int (*trickles_extract_events_hook)(int fd, struct extract_mskdesc_in *descbuf,int descbuf_len, struct msk_collection *dest, int *destLen);
       int trickles_extract_events_default(int fd, struct extract_mskdesc_in *descbuf, int descbuf_len, struct msk_collection *dest, int *destLen);

extern int (*trickles_install_events_hook)(int fd, struct msk_collection *descbuf, int descbuf_len);
       int trickles_install_events_default(int fd, struct msk_collection *descbuf, int descbuf_len);

extern int (*trickles_request_hook)(int fd, char *buf, int buf_len, int reserved_len);
       int trickles_request_default(int fd, char *buf, int buf_len, int reserved_len);

extern void (*trickles_syn_piggyback_hook)(struct sock *sk, struct sk_buff *skb);
        void trickles_syn_piggyback_default(struct sock *sk, struct sk_buff *skb);


#endif // USERTEST
#endif // __KERNEL__

/* User API */

#define MAX_TRICKLES_SHMEM_SIZE ((1<<16) * PAGE_SIZE)
#define TRICKLES_MAGIC (0xbaadd33d)

#define MSK_OFFSET(CFG,MSK) ((MSK) - (CFG)->ctl->minisock_base)
#define TRICKLES_USER_MSK_ADDR(CFG,UBASE,MSK) (MSK_OFFSET(CFG, MSK) + (struct cminisock*)((char*)(UBASE) + (CFG)->ctl->minisock_offs))

#define TRICKLES_USER_ADDR(CFG,UBASE,ADDR) (((char*)(ADDR) - (char*)(CFG)->ctl->ro_base) + ((char*)(UBASE)))

#define TRICKLES_KERNEL_EVENTLIST_ADDR(CFG,UBASE) ((struct alloc_head*)((char*)(CFG)->ctl->ro_base + ((char*)&(CFG)->ctl->msk_eventlist - (char*)(UBASE))))

