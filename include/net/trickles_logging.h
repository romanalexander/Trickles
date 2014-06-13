// XXX DO NOT INCLUDE FROM ANY FILE OTHER THAN TRICKLES.H XXX
#ifndef _IN_TRICKLES_H
	#error "File can only be included from trickles.h"
#endif // _IN_TRICKLES_H 

/******************** LOGGING ********************/

//#define REPORT_RECOVERY
#if 0 // log_cwnd logging
#define LOG_CWND_ENABLE
// record events from LOG_CWND() sample locations
//#define LOG_CWND_CWND
// //#define LOG_CWND_CONT // not implemented

// record events from LOG_CWND_PACKET() locations
#define LOG_CWND_PACKET
#define LOG_CWND_CONTONLY
#define LOG_CWND_EVENTS
#endif // log_cwnd logging

#define SLOWSTART_CWND (2)
#define INITIAL_CWND (3)
//#define INITIAL_CWND (1)

// inflate the minimum slowstart timeout to an obscene value to avoid
// prematurely detecting loss
//#define HIDE_PREMATURE_LOSS_DETECTION

// Change the place where timestamp is set to current jiffies to
// include (or exclude) user app think time from the RTT
#define RTT_INCLUDES_USER

//#define RECORD_LOSS_EVENTS

struct TricklesLossEvent {
#define EVENT_EXTRA_SEND   (1)
#define EVENT_EXTRA_RECV   (2)
#define EVENT_EXTRA_SAMPLE0 (3)
#define EVENT_EXTRA_SAMPLE1 (4)
#define EVENT_CWND_WIDTH   7
#define EVENT_CWND_MAX ((1 << EVENT_CWND_WIDTH) - 1)
#define EVENT_GAP_WIDTH 5
	__u32 valid : 1;
	__u32 cwnd : EVENT_CWND_WIDTH; // 0xff = overflow
	__u32 extra : EVENT_GAP_WIDTH; // number of gaps detected before recovering
	__u32 state : 3;
	__u32 time : 24;
} __attribute__ ((packed));

/* DEBUG */
extern int sysctl_dbg_cwnd;

struct TricklesProcLogEntry {
	struct cminisock *prev;
	struct cminisock *next;
	struct alloc_head_list *list;

	__u32 addr;
	__u16 port;
	unsigned rcv_nxt;
	unsigned t_rcv_nxt;
	struct TricklesLossEvent *events;
	int size;
	int returnedEvents;
	int sentAmount;
};

#ifdef RECORD_LOSS_EVENTS
static inline
void appendTricklesLossEvent(struct sock *sk, unsigned cwnd,
			     int extra, int state) {
	struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;
	struct TricklesLossEvent *event =
		&tp->t.events[tp->t.eventsPos];
	event->valid = 1;
	event->cwnd = cwnd;
	event->extra = extra;
	event->state = state;
	event->time = jiffies;
	tp->t.eventsPos++;
	tp->t.eventsPos %= tp->t.eventsSize;
}
#else
#define appendTricklesLossEvent(W,X,Y,Z);
#endif // RECORD_LOSS_EVENTS

extern struct alloc_head_list tricklesProcLogHead;

int trickles_read_proc(char *page, char **start, off_t offset, int count,
		       int *eof, void *data);

enum LogCwndType {
	CWND_RECORD, CONTINUATION_RECORD, EVENT_RECORD, PACKET_RECORD
};

struct TricklesCwndProcLogEntry {
	struct cminisock *prev;
	struct cminisock *next;
	struct alloc_head_list *list;

	enum LogCwndType type;

	__u32 addr;
	__u32 port;
	__u32 seq;
	__u32 ack_seq;
	__u32 startCwnd;
	__u32 effCwnd;
	__u32 ssthresh;
#if 0
	unsigned int timestamp;
#else
	// high resolution timestamp
	unsigned int s;
	unsigned int us;
#endif
	int rtt, srtt;

	int sentAmount; // amount from this chunk read so far from procfs
};

extern struct alloc_head_list tricklesCwndProcLogHead;
extern spinlock_t cwndLogLock;

int trickles_cwnd_read_proc(char *page, char **start, off_t offset, int count,
			    int *eof, void *data);

extern void
(*trickles_logCwnd_hook)(enum LogCwndType type, int addr, int port, int seq, int ack_seq, int startCwnd, int effCwnd,
			 int ssthresh, int rtt, int srtt);

#ifdef LOG_CWND_CWND
#define LOG_CWND(SK, SEQ)						\
	do {								\
		struct tcp_opt *tp = &(SK)->tp_pinfo.af_tcp;		\
		if(tp->instrumentation) {				\
			trickles_logCwnd_hook((SK)->daddr, (SK)->dport, \
					      (SEQ), 0, tp->snd_cwnd,	\
					      tp->snd_cwnd,		\
					      tp->snd_ssthresh,		\
					      tp->srtt,			\
					      tp->srtt);		\
		}							\
	} while(0)

// XXX This is an ugly hack
#define LOG_ACK(SK, ACK_SEQ)						\
	do {								\
		struct tcp_opt *tp = &(SK)->tp_pinfo.af_tcp;		\
		if(tp->instrumentation) {				\
			trickles_logCwnd_hook((SK)->daddr, (SK)->dport, \
					      0, (ACK_SEQ), tp->snd_cwnd, \
					      tp->snd_cwnd,		\
					      tp->snd_ssthresh,		\
					      tp->srtt,			\
					      tp->srtt);		\
		}							\
	} while(0)

#else
#define LOG_CWND(SK, SEQ)
#define LOG_ACK(SK, ACK_SEQ)
#endif // LOG_CWND_CWND

#ifdef LOG_CWND_PACKET
#define LOG_PACKET(SK, SEQ)						\
	do {								\
		struct tcp_opt *tp = &(SK)->tp_pinfo.af_tcp;		\
		trickles_logCwnd_hook(PACKET_RECORD, (SK)->daddr, (SK)->dport, \
				      (SEQ), 0, tp->snd_cwnd,		\
				      tp->snd_cwnd,			\
				      tp->snd_ssthresh,			\
				      tp->srtt,				\
				      tp->srtt);			\
	} while(0)

#define LOG_PACKET_CONT(SK, SEQ, CONT)					\
	do {								\
		struct tcp_opt *tp = &(SK)->tp_pinfo.af_tcp;		\
		trickles_logCwnd_hook(PACKET_RECORD, (CONT)->seq, (SK)->dport, \
				      (SEQ), (CONT)->TCPBase, (CONT)->startCwnd,			\
				      /* effCwnd */ tp->snd_cwnd,		\
				      (CONT)->ssthresh,				\
				      tp->srtt,				\
				      tp->srtt);			\
	} while(0)

#else
#define LOG_PACKET(SK, SEQ)
#define LOG_PACKET_CONT(SK, SEQ, CONT)
#endif // LOG_CWND_PACKET

#ifdef LOG_CWND_CONTONLY
#define LOG_PACKET_CONTONLY(CONT)					\
	do {								\
		trickles_logCwnd_hook(CONTINUATION_RECORD,		\
				      (CONT)->daddr, (CONT)->dest,	\
				      (CONT)->continuationType, (CONT)->seq, (CONT)->startCwnd, \
				      (CONT)->actualCwnd,				\
				      (CONT)->ssthresh,				\
				      (CONT)->TCPBase,				\
				      -1);			\
	} while(0)
#else
#define LOG_PACKET_CONTONLY(CONT)
#endif // LOG_CWND_CONTONLY

#define RECOVERYEVENT (1)
#define TIMEOUTEVENT0 (2)
#define TIMEOUTEVENT1 (6)
#define USERBLOCKEVENT (3)
#define USERUNBLOCKEVENT (4)
#define USERBADUNBLOCKEVENT (5)
#define INSEQEVENT (7)

#ifdef LOG_CWND_EVENTS
#define LOG_PACKET_RECOVERYEVENT(CONT)		\
	do {								\
		trickles_logCwnd_hook(EVENT_RECORD,		\
				      (CONT)->source, (CONT)->dest,	\
				      RECOVERYEVENT, (CONT)->seq, (CONT)->startCwnd, \
				      (CONT)->actualCwnd,				\
				      (CONT)->ssthresh,				\
				      (CONT)->TCPBase,				\
				      -1);			\
	} while(0)

#define LOG_PACKET_TIMEOUTEVENT0(CONT)					\
	do {								\
		trickles_logCwnd_hook(EVENT_RECORD,		\
				      (CONT)->source, (CONT)->dest,	\
				      TIMEOUTEVENT0, (CONT)->seq, (CONT)->startCwnd, \
				      (CONT)->actualCwnd,				\
				      (CONT)->ssthresh,				\
				      (CONT)->TCPBase,				\
				      -1);			\
	} while(0)

#define LOG_PACKET_TIMEOUTEVENT1(CONT)					\
	do {								\
		trickles_logCwnd_hook(EVENT_RECORD,		\
				      (CONT)->source, (CONT)->dest,	\
				      TIMEOUTEVENT1, (CONT)->seq, (CONT)->startCwnd, \
				      (CONT)->actualCwnd,				\
				      (CONT)->ssthresh,				\
				      (CONT)->TCPBase,				\
				      -1);			\
	} while(0)

#define LOG_PACKET_GENERICEVENT(CONT, EVENT)					\
	do {								\
		struct cminisock junk;					\
		struct cminisock *__cont = (CONT);			\
		if(__cont == NULL) __cont = &junk;			\
		trickles_logCwnd_hook(EVENT_RECORD,		\
				      __cont->daddr, __cont->dest,	\
				      EVENT, __cont->seq, __cont->startCwnd, \
				      __cont->actualCwnd,				\
				      __cont->ssthresh,				\
				      __cont->TCPBase,				\
				      -1);			\
	} while(0)

#define LOG_PACKET_INSEQEVENT(CONT) LOG_PACKET_GENERICEVENT(CONT, INSEQEVENT)

#if 0
#define LOG_PACKET_USERBLOCKEVENT(CONT)		\
	LOG_PACKET_GENERICEVENT(CONT,USERBLOCKEVENT)
#define LOG_PACKET_USERUNBLOCKEVENT(CONT)		\
	LOG_PACKET_GENERICEVENT(CONT,USERUNBLOCKEVENT)
#define LOG_PACKET_USERBADUNBLOCKEVENT(CONT)		\
	LOG_PACKET_GENERICEVENT(CONT,USERBADUNBLOCKEVENT)
#else
#define LOG_PACKET_USERBLOCKEVENT(CONT)
#define LOG_PACKET_USERUNBLOCKEVENT(CONT)
#define LOG_PACKET_USERBADUNBLOCKEVENT(CONT)
#endif


#else // LOG_CWND_EVENTS
#define LOG_PACKET_RECOVERYEVENT(CONT)
#define LOG_PACKET_TIMEOUTEVENT0(CONT)
#define LOG_PACKET_TIMEOUTEVENT1(CONT)
#define LOG_PACKET_USERBLOCKEVENT(CONT)
#define LOG_PACKET_USERUNBLOCKEVENT(CONT)
#define LOG_PACKET_USERBADUNBLOCKEVENT(CONT)
#define LOG_PACKET_INSEQEVENT(CONT)
#endif //  LOG_CWND_EVENTS

enum LogCwndType;
void trickles_logCwnd_impl(enum LogCwndType type, int addr, int port,
			   int seq, int ack_seq,
			   int startCwnd, int effCwnd, int ssthresh,
			   int rtt, int srtt);
void trickles_logCwnd_default(enum LogCwndType type, int addr, int port,
			      int seq, int ack_seq,
			      int startCwnd, int effCwnd, int ssthresh,
			      int rtt, int srtt);


#if 0
extern ctl_table trickles_table[];
extern ctl_table trickles_trickles_table[];
extern ctl_table trickles_root_table[];
#endif
