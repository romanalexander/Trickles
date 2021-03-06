#ifndef CMINISOCK_H
#define CMINISOCK_H

#include <net/trickles_dlist.h>

#define PROPAGATE_ACKSEQ

#define CMINISOCK_IN  0
#define CMINISOCK_OUT 1

void show_stack(unsigned long * esp);

enum cminisock_ctl {
	ALLOC_FREE = 0, // in free list
	ALLOC_READY = 1, // ready for user processing 
	ALLOC_PENDING = 2, // deferred update
	ALLOC_PROCESSING = 3, // in processing, ready to be freed
	ALLOC_HALFFREE = 4, // Disconnected from event queue, but not yet freed

	ALLOC_INVALID = 5 // used for object instances where ctl is unused
};

enum cminisock_event_tag {
	SYN, ACK, FIN, RST
};

struct alloc_head_list;

struct alloc_head {
	/* Must match order in minisocket header */
	struct alloc_head *prev;
	struct alloc_head *next;
	struct alloc_head_list *list;
	// CTL field is required for lists that implement memory heaps
	// If alloc_head is used only for list operations, ctl field is unnecessary
	enum cminisock_ctl ctl;
};

struct alloc_head_list {
	struct alloc_head *prev;
	struct alloc_head *next;
	struct alloc_head_list *list;
	enum cminisock_ctl ignore;
	int len;
};

struct vector {
	int num;
	int size;
	void **elems;
};

#ifdef __KERNEL__
#define vector_walk(VEC, ELEM, TEMP) \
  for((TEMP)=0, (ELEM)=(VEC)->elems[(TEMP)]; (TEMP) < (VEC)->num; (TEMP)++, (ELEM) = (VEC)->elems[(TEMP)])

static inline void vector_init(struct vector *vec, int initSize) {
	vec->num = 0;
	vec->size = initSize;
	vec->elems = kmalloc(vec->size * sizeof(vec->elems[0]), GFP_ATOMIC);
	if(vec->elems == NULL) {
		printk("Not enough memory while initializing vector\n");
	}
	return;
}

static inline void vector_free(struct vector *vec) {
	kfree(vec->elems);
	kfree(vec);
}
static inline void vector_append(struct vector *vec, void *newElem) {
	if(vec->num == vec->size) {
		void **newElems;
		vec->size *= 2;
		newElems = kmalloc(vec->size * sizeof(newElems[0]), GFP_ATOMIC);
		if(newElems == NULL) {
			printk("Not enough memory while resizing vector\n");
			// TODO: Throw proper exception
			BUG();
			return;
		}
	}
	vec->elems[vec->num++] = newElem;
}

#endif // __KERNEL__

#ifdef __KERNEL__
#define VALID_MSK_CTL(X) ((X)->ctl == ALLOC_READY || \
                          (X)->ctl == ALLOC_HALFFREE)

static inline int empty(struct alloc_head_list *head) {
	return head->next == (struct alloc_head*)head;
}

static inline void init_head(struct alloc_head_list *head) {
	head->next = head->prev = (struct alloc_head*)head;
	head->list = head;
	head->len = 0;
}

static inline void init_link(struct alloc_head *link) {
	link->next = link->prev = NULL;
	link->list = NULL;
	link->ctl = ALLOC_INVALID;
}


#if 0
static inline void unlink_head(struct alloc_head_list *head) {
	struct alloc_head *prev = head->prev;
	head->prev->next = head->next;
	head->next->prev = head->prev;
	head->next = head->prev = NULL;
	if(prev->next == prev && prev->prev != prev) {
		BUG();
		show_stack(NULL);
	}
	head->len--;
}
#endif

//#define DEBUG_LIST

static inline void insert_head(struct alloc_head_list *head, struct alloc_head *elem) {
#ifdef DEBUG_LIST
	if(elem->list) {
		BUG();
	}
#endif
	if(head->next == elem /* || elem->prev != NULL || elem->next != NULL */) {
		BUG();
		show_stack(NULL);	
	}
	elem->next = head->next;
	head->next->prev = elem;

	elem->prev = (struct alloc_head*)head;
	head->next = elem;

	elem->list = head;
	head->len++;
}

static inline void insert_tail(struct alloc_head_list *head, struct alloc_head *elem) {
#ifdef DEBUG_LIST
	if(elem->list) {
		BUG();
	}
#endif
	if(head->prev == elem /* || elem->prev != NULL || elem->next != NULL */) {
		BUG();
		show_stack(NULL);
	}
#if 1 // 10-01: moved next pointer up to make consistent with mb version
	elem->next = (struct alloc_head*)head;
#endif
	elem->prev = head->prev;

	head->prev->next = elem;

	elem->list = head;
	head->prev = elem;
	head->len++;
}

static inline void insert_tail_mb(struct alloc_head_list *head, struct alloc_head *elem) {
#ifdef DEBUG_LIST
	if(elem->list) {
		BUG();
	}
#endif
	if(head->prev == elem /* || elem->prev != NULL || elem->next != NULL */) {
		BUG();
		show_stack(NULL);
	}
	// moved next pointer up and added memory barrier to insure that forward walk through element list works properly without locking
	elem->next = (struct alloc_head*)head;
	elem->prev = head->prev;

	mb();

	head->prev->next = elem;

	elem->next = (struct alloc_head*)head;

	elem->list = head;
	head->prev = elem;
	head->len++;
}

static inline void unlink(struct alloc_head *elem) {
#ifdef DEBUG_LIST
	if(elem->list == (struct alloc_head_list*) elem) {
		BUG();
	}
#endif

	elem->next->prev = elem->prev;
	elem->prev->next = elem->next;
	elem->prev = elem->next = NULL;

	elem->list->len--;
	elem->list = NULL;
}

static inline void insert(struct alloc_head *elem, struct alloc_head *prev, struct alloc_head *next) {
#ifdef DEBUG_LIST
	if(elem->list) {
		BUG();
	}
	if(prev->next != next || next->prev != prev) {
		BUG();
	}
#endif

	if(!(elem->next == NULL && elem->prev == NULL)) BUG();
	elem->next = prev->next;
	prev->next = elem;

	elem->prev = prev;
	next->prev = elem;

	elem->list = prev->list;
	elem->list->len++;
}

#define alloc_head_walk(queue, elem) \
		for (elem = (typeof(elem))(queue)->next;	\
		     (elem != (typeof(elem))(queue));	\
		     elem=(typeof(elem))elem->next)

#define alloc_head_reverse_walk(queue, elem) \
		for (elem = (typeof(elem))(queue)->prev;	\
		     (elem != (typeof(elem))(queue));	\
		     elem=(typeof(elem))elem->prev)

#endif // __KERNEL__

struct cminisock_packet {
	__u32 nonce; // pregenerate nonces in batch
	__u32 seq;
	//__u32 ack_seq; // XXX probably vestigial
	__u16 len; // XXX Vestigial?

#define PTYPE_FIRST     (0x80)
#define PTYPE_STATEMASK (0x3)
#define PACKET_NORMAL    (0)
#define PACKET_RETRANS   (1)
#define PACKET_BOOTSTRAP (2)
	//__u8 type : 3;
	__u8 type;
	__u8 contType;

#define INVALID_POSITION (0xff)
	__u8 numSiblings; // UC-level number of siblings
	__u8 position; // UC position within sibling list. If packet looks like a data packet, and position == INVALID_POSITION, then client will ignore the packet

	// If ucontLen > 0 and ucontData == NULL, then the ucont is already present in the skbuff
	int ucontLen;
	char *ucontData; // kmalloc'd

	__u16 minResponseLen;
	__u32 firstTransportChild;
	__u8 numTransportChildren;

#ifdef USERTEST
	char *sentData;
	int dataLen;
#endif // USERTEST
};

static inline void cminisock_packet_print(struct cminisock_packet *pkt) {
	printk("{ seq = %d type = %d}\n", pkt->seq, pkt->contType);
}

static inline void makePacket(struct cminisock_packet *pkt, 
			      __u32 seq, 
			      __u32 ack_seq,
			      __u32 len, 
			      __u8 type, 
			      __u8 contType, 
			      __u16 minResponseLen,
			      __u32 firstTransportChild, 
			      __u8 numTransportChildren) {
  pkt->nonce = -1;
  pkt->seq = seq;
  //pkt->ack_seq = ack_seq;
  pkt->len = len;
  pkt->type = type;
  pkt->contType = contType;
  pkt->minResponseLen = minResponseLen;
  pkt->firstTransportChild = firstTransportChild;
  pkt->numTransportChildren = numTransportChildren;
  pkt->ucontLen = 0;
  pkt->ucontData = NULL;
  pkt->numSiblings = -1;
  pkt->position = INVALID_POSITION;
}

#ifdef __KERNEL__
static inline void setPacketUCont(struct cminisock_packet *packet, char *buf, unsigned long len) {
	if(len > packet->len + packet->ucontLen) {
		printk("Not enough space in packet for ucont %d %d + %d\n", 
		       (int) len, packet->len, packet->ucontLen);
		return;
	}
	if(packet->ucontData) {
		kfree(packet->ucontData);
		packet->len += packet->ucontLen;
		packet->ucontLen = 0;
	}
	packet->ucontData = buf;
	packet->ucontLen = len;
	packet->len -= packet->ucontLen;
}
#endif

#if 0
// 0517 - switched to dynamic allocation
//#define CMINISOCK_MAX_PACKETS (8)
#endif

struct pminisock;

#define PARENT_OF(NAME,VAL,PARENTTYPE)			\
	((PARENTTYPE*)(((char*)VAL) -			\
		       (int)(&((PARENTTYPE*)0)->NAME)))

#define MSK_HASH_OWNER(VAL) PARENT_OF(hash_link, (VAL), struct cminisock)
#define MSK_SORTED_OWNER(VAL) PARENT_OF(sorted_link, (VAL), struct cminisock)

struct cminisock {
	/* must match order in struct alloc_head */
	struct cminisock *prev;
	struct cminisock *next;
	struct alloc_head_list *list;
	enum cminisock_ctl ctl;

	/* Trickles storage table fields */

	struct alloc_head hash_link;
	struct alloc_head sorted_link;
	unsigned localParentID; // local parent ID

	/* used for classification in client side */
	enum cminisock_event_tag tag;
	__u32 saddr, daddr;
	__u16 source, dest;

	// Following fields are meaningless in userspace. While
	// processing a downcall, the kernel will insert 
	// stack-allocated structs as extra parameters to later
	// processing
	struct sock *sk; /* dummy socket used to drive IP xmit */

	__u32 flags;
	__u32 rcv_nxt;

	__u32 cum_nonce; /* gathered from the TrickleResponse header */

	/* Continuation fields */
	unsigned seq;
	unsigned continuationType;

	unsigned clientState;
	unsigned parent;
	__u32 rawTimestamp; // wire representations
	__u32 rawMrtt; 
#define UPDATE_TIMESTAMP(CONT) (CONT)->timestamp = jiffies

	unsigned timestamp; // in jiffies (server) units
	unsigned clientTimestamp; // in jiffies (client) units
	unsigned mrtt; // in jiffies units * 8 (3 fractional bits)
	__u32 state; // should be enum ContinuationState
	unsigned firstChild; // 1 if first child; 0 otherwise

	__u32 firstLoss;
	__u32 firstBootstrapSeq;
	unsigned startCwnd;
	unsigned ssthresh;
	unsigned TCPBase;
	__u64 tokenCounterBase; // starting offset for tokens in this connection

	int ucont_len;
	char *ucont_data; // kmalloc in client code, tmalloc in server code

#if 0
	__u16 rcv_ucont_offset;
	__u16 ucont_offset; // DEBUGGING INFORMATION : Offset of ucont from beginning of packet
#endif

#ifdef PROPAGATE_ACKSEQ
	__u32 ack_seq;
	int simulationLen;
	int simulationNumPackets;
	__u32 dbg_timestamp;
	__u32 dbg_mark;
#endif

	/* input sent to server during conversion phase */
	int input_len;
	char *input; // kmalloc in client code, tmalloc in server code
	char mac[40];

#if 0
	unsigned minResponseLen; // vestigial
#endif
	__u32 firstTransportChild;
	int numTransportChildren;

	int numChildrenReceived;
	struct cminisock *parentMSK;

	/* Debugging */
	int seqnum; // this minisock is the seqnum-th delivered to userspace

	int simulated; // client: 'simulated' == true <=> server-side simulation has been executed
	int executionTrace; // server - debugging information - used to print out execution path during server-side processing
	int actualCwnd;

#define CONTLIST (-1)
#define SKBLIST  (-2)
	int mark; // 0429 debugging mark / scratch space

	char clientside_copy_end[0];
	int num_packets;
	// 0517 - should we use variable length array or ptr? 
	// Variable length array work nicely if we had resizing malloc. But we don't.
	// Variable length array would also require moving cminisock allocation to tmalloc
	struct cminisock_packet *packets; // variable number of packets
	int refCnt;
	int cacheRecycleIndex; // points to the result packet that should  reuse this continuation
	struct sock *serverSK; // used for allocation. Initialized ONLY in executeTrickle, and during downcall (do_sendmsg)

	/* Support for debugging pmsk upgrade: For now, userspace will
	   use the compatibility interface */
	struct pminisock *pmsk;
	int isStatic;
};

struct pminisock {
	/* the content is based on the unmarshallContinuation PMSK
	   source and destination variants */
	/* these fields must match the order in list_link */
	struct pminisock *prev;
	struct pminisock *next;

	__u16 ctl 		: 3; /* enum cminisock_ctl  */
	__u16 tag 		: 3; /* enum cminisock_event_tag */

	__u16 continuationType	: 4;
	__u16 firstChild	 	: 1;
	__u16 refCnt		: 2;
	__s16 cacheRecycleIndex	: 3;

	__u8 num_packets;
	__u8 clientState;
	__u8 state;

	__u32 seq;
	__u32 parent;
	__u32 clientTimestamp;

	//tstamp
	__u32 rawTimestamp;
	__u32 rawMrtt;

	__u32 firstLoss;
	__u32 firstBootstrapSeq;
	__u32 startCwnd;
	__u32 ssthresh;
	__u32 TCPBase;

	// flow
	__u32 daddr;
	__u16 dest;

	__u64 tokenCounterBase;

	__u16 ucont_len;
	__u16 input_len;
	char *ucont_data;
	char *input;
	
	struct cminisock_packet *packets;
};

/* User API */

#ifdef SETUCONT_COMMAND
#define UCONT_DESC				\
	char *ucont_base;			\
	int ucont_len;

/* "Trickles iovec" */
struct ucontdesc {
	UCONT_DESC;
};
#else
#define UCONT_DESC  // intentionally empty
struct ucontdesc;
#endif // SETUCONT_COMMAND

struct tiovec;

#define NEXT_MSKDESC(MDESC) 					\
({								\
	(struct mskdesc*)(&((struct mskdesc *)MDESC)->tiov[((struct mskdesc *)MDESC)->tiov_num]);	\
})

struct tiovec {
	// field names are compatible with iov
#if 0
#define PACKET_CONTINUED (-1)
	int packetNum; // currently used only for sanity check
#endif
	void *iov_base;
	int iov_len;

	UCONT_DESC;
};

struct mskdesc {
	struct cminisock *msk;
	int tiov_num;
#ifdef PROPAGATE_ACKSEQ
	int dbg_mark; // appended to error printks
#endif

	// tiovec is appended to mskdesc
	struct  tiovec tiov[0];
};

/* Support for scatter-gather sendfile interface */
struct fiovec {
	int fd; // if fd == -2, interpret offset as memory address */
	loff_t offset;
	int len;
};

/* Support for event migration */

#define EVENT_COPYOUT 	(0x1)
#define EVENT_UNLINK 	(0x2)
#define EVENT_DEALLOC 	(0x4)

#define MSKDESC_IN_NEXT(DESC) ((DESC)+1)
struct extract_mskdesc_in {
	struct cminisock *msk;
	int operation;
}  __attribute__ ((packed));

#define MSKDESC_OUT_NEXT(DESC) ((char*)(DESC) + (DESC)->len)
// Convert an offset to a pointer
#define MSKDESC_OUT_TO_PTR(DESC,OFFSET) ((DESC)->data + (OFFSET))

struct extract_mskdesc_out {
	int len; // total length, including header
	// All pointers are converted to zeros
	struct cminisock msk;
	char data[0];

	// Data contains msk->packets, packets[]->ucontData,
	// msk->ucont_data, msk->input
}  __attribute__ ((packed));

struct msk_collection {
	char hmac[20];
	// N.B. ``len'' is not covered by hmac!
	int len;
	struct extract_mskdesc_out descs[0];
}  __attribute__ ((packed));

/***********************/

struct trickles_mmap_ctl;
struct trickles_config {
	/* IN */
	__u32  mmap_len;  /* multiple of page size */
	__u32 maxMSKCount; // maximum number of MSKs

  /* internal use only */
	struct trickles_mmap_ctl *ctl; // points to the read-only area
	/* OUT */
	void *mmap_base; /* user is responsible for vmalloc'ing this memory range */
	// these pages are mapped into kernel space until the user unmaps them
};

#ifdef __KERNEL__
#ifndef USERTEST
extern int (*cminisock_config_pipe_hook)(struct sock *sk, char *optdata, int optlen, int direction);
int cminisock_config_pipe_default(struct sock *sk, char *optdata, int optlen, int direction);

#define TRICKLES_USERAPI_CONFIGURED_TP(TP) ((TP)->cminisock_api_config.cfg.mmap_base != NULL && (TP)->cminisock_api_config.cfg.ctl != NULL)
struct trickles_kconfig {
	struct trickles_config cfg;
	struct alloc_head_list msk_freelist;
	struct dlist pmsk_freelist;

	rwlock_t event_lock; /* used to protect event queue. Mostly unused */
	int pending_delivery; /* used to lock out updates to configuration while a split delivery is pending */
};
#endif
#endif // __KERNEL__

enum cminisock_command_tag {
	POLL,
	PROCESS,
	DROP,
	STARTRCV
};

struct cminisock_cmd {
	int magic;
	struct cminisock *socket;
	enum cminisock_command_tag cmd;
};

#ifndef __KERNEL__
#ifndef USERTEST
#include <linux/unistd.h>

#ifndef __NR_cminisock_send
#define __NR_cminisock_send		280
#endif
#ifndef __NR_cminisock_sendv
#define __NR_cminisock_sendv		281
#endif
#ifndef __NR_cminisock_sendfilev
#define __NR_cminisock_sendfilev	282
#endif
#ifndef __NR_cminisock_setucont
#define __NR_cminisock_setucont		283
#endif
#ifndef __NR_cminisock_sendbulk
#define __NR_cminisock_sendbulk		284
#endif
#ifndef __NR_cminisock_extract_events
#define __NR_cminisock_extract_events		285
#endif
#ifndef __NR_cminisock_install_events
#define __NR_cminisock_install_events		286
#endif
#ifndef __NR_cminisock_request
#define __NR_cminisock_request		287
#endif
#define asmlinkage 

#if 1 // XXX Need this hack from time to time?
#undef _syscall0
#undef _syscall1
#undef _syscall2
#undef _syscall3
#undef _syscall4
#undef _syscall5
#undef _syscall6

#define __syscall_return(type, res) \
do { \
        if ((unsigned long)(res) >= (unsigned long)(-125)) { \
                errno = -(res); \
                res = -1; \
        } \
        return (type) (res); \
} while (0)

/* XXX - _foo needs to be __foo, while __NR_bar could be _NR_bar. */
#define _syscall0(type,name) \
type name(void) \
{ \
long __res; \
__asm__ volatile ("int $0x80" \
	: "=a" (__res) \
	: "0" (__NR_##name)); \
__syscall_return(type,__res); \
}

#define _syscall1(type,name,type1,arg1) \
type name(type1 arg1) \
{ \
long __res; \
__asm__ volatile ("int $0x80" \
	: "=a" (__res) \
	: "0" (__NR_##name),"b" ((long)(arg1))); \
__syscall_return(type,__res); \
}

#define _syscall2(type,name,type1,arg1,type2,arg2) \
type name(type1 arg1,type2 arg2) \
{ \
long __res; \
__asm__ volatile ("int $0x80" \
	: "=a" (__res) \
	: "0" (__NR_##name),"b" ((long)(arg1)),"c" ((long)(arg2))); \
__syscall_return(type,__res); \
}

#define _syscall3(type,name,type1,arg1,type2,arg2,type3,arg3) \
type name(type1 arg1,type2 arg2,type3 arg3) \
{ \
long __res; \
__asm__ volatile ("int $0x80" \
	: "=a" (__res) \
	: "0" (__NR_##name),"b" ((long)(arg1)),"c" ((long)(arg2)), \
		  "d" ((long)(arg3))); \
__syscall_return(type,__res); \
}

#define _syscall4(type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4) \
type name (type1 arg1, type2 arg2, type3 arg3, type4 arg4) \
{ \
long __res; \
__asm__ volatile ("int $0x80" \
	: "=a" (__res) \
	: "0" (__NR_##name),"b" ((long)(arg1)),"c" ((long)(arg2)), \
	  "d" ((long)(arg3)),"S" ((long)(arg4))); \
__syscall_return(type,__res); \
} 

#define _syscall5(type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4, \
	  type5,arg5) \
type name (type1 arg1,type2 arg2,type3 arg3,type4 arg4,type5 arg5) \
{ \
long __res; \
__asm__ volatile ("int $0x80" \
	: "=a" (__res) \
	: "0" (__NR_##name),"b" ((long)(arg1)),"c" ((long)(arg2)), \
	  "d" ((long)(arg3)),"S" ((long)(arg4)),"D" ((long)(arg5))); \
__syscall_return(type,__res); \
}

#define _syscall6(type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4, \
	  type5,arg5,type6,arg6) \
type name (type1 arg1,type2 arg2,type3 arg3,type4 arg4,type5 arg5,type6 arg6) \
{ \
long __res; \
__asm__ volatile ("push %%ebp ; movl %%eax,%%ebp ; movl %1,%%eax ; int $0x80 ; pop %%ebp" \
	: "=a" (__res) \
	: "i" (__NR_##name),"b" ((long)(arg1)),"c" ((long)(arg2)), \
	  "d" ((long)(arg3)),"S" ((long)(arg4)),"D" ((long)(arg5)), \
	  "0" ((long)(arg6))); \
__syscall_return(type,__res); \
}
#endif

extern asmlinkage int cminisock_send(int fd, struct cminisock *msk, char *buf, int len);
extern asmlinkage int cminisock_sendv(int fd,struct cminisock *msk, struct tiovec* iov,int tiovlen);
extern asmlinkage int cminisock_sendfilev(int fd,struct cminisock *msk, struct fiovec* fiov,int fiovlen);
extern asmlinkage int cminisock_setucont(int fd, struct cminisock *msk, int pktNum, char *newUcont, unsigned ucont_len);
extern asmlinkage int cminisock_sendbulk(int fd, struct mskdesc *descbuf, int descbuf_len);
extern asmlinkage int cminisock_extract_events(int fd, struct extract_mskdesc_in *descbuf, int descbuf_len, struct msk_collection *dest, int *destLen);
extern asmlinkage int cminisock_install_events(int fd, struct msk_collection *descbuf, int descbuf_len);
extern asmlinkage int cminisock_request(int fd, char *buf, int buf_len, int reserved_len);

#define CMINISOCK_SYSCALL()						\
_syscall4(int,cminisock_send,int,fd,struct cminisock *,msk,char*,buf,int,len); \
_syscall4(int,cminisock_sendv,int,fd,struct cminisock *,msk,struct tiovec*,tiov,int,tiovlen); \
_syscall4(int,cminisock_sendfilev,int,fd,struct cminisock *,msk,struct fiovec*,fiov,int,fiovlen); \
_syscall5(int,cminisock_setucont,int,fd,struct cminisock*,msk,int,pktNum,char*,newUcont,unsigned,ucont_len); \
_syscall3(int,cminisock_sendbulk,int,fd,struct mskdesc *,desc,int,descbuflen); \
_syscall5(int,cminisock_extract_events,int,fd,struct extract_mskdesc_in*,descbuf, int, descbuf_len, struct msk_collection*, dest, int *, destLen); \
_syscall3(int,cminisock_install_events,int,fd,struct msk_collection *,descbuf, int, descbuf_len); \
_syscall4(int,cminisock_request,int,fd,char *,buf, int, buf_len, int, reserved_len);

#endif
#endif // __KERNEL__

#endif // CMINISOCK_H
