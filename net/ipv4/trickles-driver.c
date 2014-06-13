#include "trickles-int.h"

// Self test

#define DATUMLEN (100000)
//#define DATUMLEN (100000000)

int client_rcv_impl(struct sock *sk, struct sk_buff *in_skb);
int server_rcv_impl(struct sock *sk, struct sk_buff *in_skb);

struct sock server, client;
struct sk_buff client_queue;
struct sk_buff server_queue;

#ifdef USE_UDP
int udpsock;
struct sockaddr_in peer;
#endif // USE_UDP

// dataRequestMapping testsuite

//#define TRUNCATE_SEND // Send less data than the client requests, in the "typical" fashion, e.g. drop data at the end
#define TRUNCATE_SEND_ALOT // Send less data than the client requests, in a really annoying fashion, e.g. all over the place. In particular, drop the tail of every packet, not just the end of a request

// Continuation management algorithms

#define CONT_MGMT0 (0) // original algorithm - use one large continuation for DATUMLEN
#define CONT_MGMT1 (1) // test0 - split DATUMLEN into 10 continuations, all sent at beginning 
#define CONT_MGMT2 (2) // test1 - split DATUMLEN into 10 continuations, all sent at beginning
   // However, server rejects continuations 5-9
   // Upon receiving continuation k, k < 5, send new continuations (k + 5)' (with a higher sequence number)
#define CONT_MGMT3 (3) // test2 - send DATUMLEN incrementally
#define NUMCHUNKS (10)
#define CHUNKSIZE (DATUMLEN / NUMCHUNKS)

//int continuationStyle = CONT_MGMT2;
int continuationStyle = CONT_MGMT1;
//int continuationSubstyle = 2; // 0 = "nice", 1 = "annoying" (e.g., introduce extra overlaps), 2 = "really annoying - annoying + permute delivery order
int continuationSubstyle = 2; // 0 = "nice", 1 = "annoying" (e.g., introduce extra overlaps), 2 = "really annoying - annoying + permute delivery order
int xlat0[] = {0,1,2,3,4,5,6,7,8,9};
int xlat1[] = {0,2,5,7,9,1,3,6,8,4};


void sendtoclient(struct sk_buff *skb) {
#ifndef USE_UDP
  skb_pull(skb, sizeof(struct iphdr));
  skb_pull(skb, skb->h.th->doff*4);
  __skb_queue_tail(&client_queue, skb);
#else
  skb_pull(skb, sizeof(struct iphdr));
  sendto(udpsock, skb->data, skb->len, 0, &peer, sizeof(struct sockaddr_in));
#endif // USE_UDP
}

void sendtoserver(struct sk_buff *skb) {
	skb_pull(skb, sizeof(struct iphdr));	
skb_pull(skb, skb->h.th->doff*4);
	__skb_queue_tail(&server_queue, skb);
}

void state_change(struct sock *sk) {
}

#define USER_HEAP_SIZE 2048
inline static void USER_init_trickles_sock(struct sock *sk) {
	struct tcp_opt *tp = &(sk->tp_pinfo.af_tcp);
	int error = 0;

	sk->state = 0;
	sk->dead = 0;
	sk->state_change = state_change;
	sk->rcvbuf = 100000000;
	sk->sndbuf = 10000000;
	sk->saddr = sk->daddr = 0;

	tp->trickles_opt = 1;
	// Use kernel code to initialize trickles-specific fields
	init_trickles_sock(sk);
	init_timer(&tp->t.slowstart_timer);
	// Set up heap
	tp->t.heapbytesize = USER_HEAP_SIZE * PAGE_SIZE;
	tp->t.heap_absolute_base = kmalloc(tp->t.heapbytesize, GFP_KERNEL);

	// Set up Crypto
	if(generateHMAC) {
		__u8 hmac_key[HMAC_KEYLEN];
		get_random_bytes(hmac_key, HMAC_KEYLEN);
#if OPENSSL_HMAC
		tp->t.hmacCTX = kmalloc(sizeof(*tp->t.hmacCTX), GFP_KERNEL);
		if(tp->t.hmacCTX == NULL) {
			error = -ENOMEM;
			goto out_dealloc;
		}
		hmac_setup(tp->t.hmacCTX, hmac_key, HMAC_KEYLEN);
#else
		BUG_TRAP(HMAC_KEYLEN <= HMACLEN);
		memcpy(tp->t.hmacKey, hmac_key, HMAC_KEYLEN);
#endif
	}
	if(generateNonces) {
		__u8 nonce_key[NONCE_KEYLEN];
		get_random_bytes(nonce_key, NONCE_KEYLEN);
		tp->t.nonceCTX = kmalloc(sizeof(*tp->t.nonceCTX), GFP_KERNEL);
		if(tp->t.nonceCTX == NULL) {
			error = -ENOMEM;
			goto out_dealloc;
		}
		aes_encrypt_key(nonce_key, NONCE_KEYLEN, tp->t.nonceCTX);
	}
 out_dealloc:
	;
}

void sendsyn() {
  struct sk_buff *synpkt;

  synpkt = alloc_skb(MAX_TCP_HEADER, -1);

  synpkt->nh.iph = (struct iphdr*)synpkt->data;
  skb_put(synpkt, sizeof(struct iphdr));
  synpkt->h.th = (struct tcphdr*)synpkt->data;
  skb_put(synpkt, sizeof(struct tcphdr));
  synpkt->h.th->syn = 1;
  synpkt->h.th->ack = 0;
  synpkt->h.th->fin = 0;
  synpkt->h.th->rst = 0;
  synpkt->h.th->doff = sizeof(struct tcphdr) / 4;
  sendtoserver(synpkt);
}

int main(int argc, char *argv[]) {
  int i, j, position;
  int count = 0;
  int lastSlowstartTime = 0;
  int alreadySent = 0;

#define NUM_INPUT_PIECES 2
  // alternate tests would use more pieces
#define FULLLEN (1000)
  char fullBuf[FULLLEN + 200];
  char buf[NUM_INPUT_PIECES][FULLLEN / NUM_INPUT_PIECES + NUM_INPUT_PIECES];
  struct iovec iov[NUM_INPUT_PIECES];
  struct msghdr msg = {msg_iov: iov, msg_iovlen: sizeof(iov)/sizeof(iov[0])};
  unsigned lastSent = -1;
  struct sockaddr_in addr;

  j=0;
  strcpy(fullBuf, "[");
  while(strlen(fullBuf) < FULLLEN) {
    char temp[100];
    sprintf(temp, "%d,", j++);
    strcat(fullBuf, temp);
  }
  for(i=FULLLEN-1; i >= 0; i--) {
    if(fullBuf[i] == ',') {
      strcpy(&fullBuf[i], "]");
      break;
    }
  }
  position = 0;
  for(i=0; i < NUM_INPUT_PIECES; i++) {
    int copyLen = min(sizeof(buf[i]), strlen(fullBuf) - position);
    memcpy(buf[i], fullBuf + position, copyLen);
    position += copyLen;
    iov[i].iov_base = buf[i];
    iov[i].iov_len = copyLen;
  }

  skb_queue_head_init(&client_queue);
  skb_queue_head_init(&server_queue);
  USER_init_trickles_sock(&server);
  USER_init_trickles_sock(&client);
  client.tp_pinfo.af_tcp.trickles_opt = 0;
  server.tp_pinfo.af_tcp.trickles_opt = TCP_TRICKLES_RSERVER;

  fprintf(stderr, "initializing\n");
  
#ifndef USE_UDP
  sendsyn();
  while(1) {
    struct sk_buff *skb;
    struct tcp_opt *ctp = &client.tp_pinfo.af_tcp;
    int processed = 0;
    int currCopiedSeq = client.tp_pinfo.af_tcp.copied_seq;
    
    if(lastSent == -1 || currCopiedSeq - lastSent >= DATUMLEN) {
	    lastSent = currCopiedSeq;
	    //#define NUMSEND 10
#ifdef NUMSEND
	    if(!alreadySent)
	      for(i=0; i < NUMSEND; i++) {
#endif // SENDSEND
		trickles_client_sendmsg(&client, &msg, sizeof(msg));
#ifdef NUMSEND
	      }
	    alreadySent = 1;
#endif // NUMSEND
    }
    while(!empty(&client_queue)) {
      static int counter = 0;
	    processed = 1;
	    skb = skb_dequeue(&client_queue);
	    counter++;
	    //	    if(counter > 10000 && (counter % 1000 == 1  || counter % 1000 == 3 || counter < 11000 && ntohl(skb->h.th->seq) == 12643) || /* counter % 100 == 12  */ 0 || client_rcv_impl(&client, skb)) 
	    //if(counter % 10 == 1) {
	    //if(counter > 1000 && (counter % 5 == 1)) {
	    //if(counter > 1000 && (counter % 5000 <= 10 && counter % 5 == 1)) {
		    //if(counter > 1000 && (counter % 5000 == 1)) {
	    if(counter > 1000 && (counter % 2000 <= 5)) {
		    struct WireTrickleResponse *tresp_hdr = (struct WireTrickleResponse*)skb->data;
		    skb->sk = &client;
		    printk("dropped packet with sequence number %d\n", ntohl(tresp_hdr->cont.seq));
		    kfree_skb(skb);
	    } else if(client_rcv_impl(&client, skb)) {
		    kfree_skb(skb);
	    }
    }
    while(!empty(&server_queue)) {
	    processed = 1;
	    skb = skb_dequeue(&server_queue);
	    if(server_rcv_impl(&server, skb)) kfree_skb(skb);
    }
    if(client.tp_pinfo.af_tcp.rcv_nxt - client.tp_pinfo.af_tcp.copied_seq > 0 &&
       (client.tp_pinfo.af_tcp.rcv_nxt - client.tp_pinfo.af_tcp.copied_seq > DATUMLEN / 2 || client.tp_pinfo.af_tcp.rcv_nxt % DATUMLEN == 0)) {
	    client.tp_pinfo.af_tcp.copied_seq = client.tp_pinfo.af_tcp.rcv_nxt;
	    //printk("Copied to \"user\"\n");
	    printk("rcv_nxt = %d, t.rcv_nxt = %d, ContList length = %d\n", ctp->rcv_nxt, ctp->t.rcv_nxt, ctp->t.cont_list.len);
    }
    if(!processed) {
	    count++;
	    user_ack_impl(&client);
	    if(client.state != TCP_ESTABLISHED) {
		    sendsyn();
		    // retransmit
	    } else if(count > 1 && time(NULL) - lastSlowstartTime >= 1) {
		    lastSlowstartTime = time(NULL);
	            usleep(10);
		    slow_start_timer((int)&client);
		    count = 0;
	    }
    } else {
	    count = 0;
    }
    if(client.tp_pinfo.af_tcp.copied_seq > 10000000) {
    //if(client.tp_pinfo.af_tcp.copied_seq > 1600000000) {
	    int i;
	    struct sk_buff *lists[] = {&server_queue, &client_queue};
#if 0
	    // we want to check for memory leaks, so don't explicitly deallocate storage
	    trickles_destroy(&server);
	    trickles_destroy(&client);
#endif
	    for(i=0; i < 2; i++) {
		    struct sk_buff *head = lists[i], *skb;
		    for(skb = skb_dequeue(head); skb != NULL; 
			skb = skb_dequeue(head)) {
			    kfree_skb(skb);
		    }
	    }
	    exit(0);
    }
  }
#else 
  udpsock = socket(PF_INET, SOCK_DGRAM, 0);
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_port = htons(1030+0);

  if(bind(udpsock, &addr, sizeof(addr)) == -1) {
    fprintf(stderr, "could not bind udp socket\n");
    exit(-1);
  }
  sendsyn();
  while(1) {
    struct sk_buff *skb;
    struct tcp_opt *ctp = &client.tp_pinfo.af_tcp;
    int processed = 0, numBytes;
    int currCopiedSeq = client.tp_pinfo.af_tcp.copied_seq;
    int peerSet = 0, addrlen;
#define MAX_UDP (2000)
    char buf[MAX_UDP];
    if(currCopiedSeq % DATUMLEN == 0 && currCopiedSeq != lastSent) {
	    lastSent = currCopiedSeq;
	    trickles_client_sendmsg(&client, &msg, sizeof(msg));
    }
    while((numBytes = recvfrom(udpsock, buf, MAX_UDP, MSG_DONTWAIT, &addr, &addrlen)) > 0) {
	    static int counter = 0;
	    processed = 1;
	    counter++;
	    skb = alloc_skb(500+numBytes, GFP_ATOMIC);
	    skb_reserve(skb, 500);
	    memcpy(skb->data, buf, numBytes);
	    skb->h.th = skb->data;
	    skb->nh.iph = ((struct iphdr*)skb->h.th)-1;
	    skb->nh.iph->saddr = addr.sin_addr.s_addr;
	    if(!peerSet) {
		    peer = addr;
	    }
	    skb->nh.iph->daddr = INADDR_LOOPBACK;
	    skb_pull(skb, sizeof(struct iphdr));
	    //	    if(counter > 10000 && (counter % 1000 == 1  || counter % 1000 == 3 || counter < 11000 && ntohl(skb->h.th->seq) == 12643) || /* counter % 100 == 12  */ 0 || client_rcv_impl(&client, skb)) 
#if 1
	    if(counter > 100 && (counter % 1000 <= 50 && counter % 5 == 1)) {
#else
	    if(counter > 1000 && counter % 5000 == 1) {
#endif
	    if(0) {
		    printk("dropped packet\n", seqno);
		    kfree_skb(skb);
	    } else if(server_rcv_impl(&server, skb)) {
		    kfree_skb(skb);
	    }
    }
    client.tp_pinfo.af_tcp.copied_seq = client.tp_pinfo.af_tcp.rcv_nxt;
    if(!processed) {
	    count++;
	    user_ack_impl(&client);
	    if(client.state != TCP_ESTABLISHED) {
		    sendsyn();
		    // retransmit
	    } else if(count > 1 && time(NULL) - lastSlowstartTime >= 1) {
		    lastSlowstartTime = time(NULL);
	            usleep(10);
		    slow_start_timer((int)&client);
		    count = 0;
	    }
    } else {
	    count = 0;
    }
    if(client.tp_pinfo.af_tcp.copied_seq > 80000) {
    //if(client.tp_pinfo.af_tcp.copied_seq > 1600000000) {
	    int i;
	    struct sk_buff *lists[] = {&server_queue, &client_queue};
	    trickles_destroy(&server);
	    trickles_destroy(&client);
	    for(i=0; i < 2; i++) {
		    struct sk_buff *head = lists[i], *skb;
		    for(skb = skb_dequeue(head); skb != NULL; 
			skb = skb_dequeue(head)) {
			    kfree_skb(skb);
		    }
	    }
	    exit(0);
    }
  }
#endif
  return 0;
}

void tcp_data_queue(struct sock *sk, struct sk_buff *skb) {
	struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;
	if(TCP_SKB_CB(skb)->seq == tp->rcv_nxt) {
		tp->rcv_nxt = TCP_SKB_CB(skb)->end_seq;
	} else {
		printk("DataQueue out of order!\n");
	}
	//printk("DataQueue seq %u\n", TCP_SKB_CB(skb)->seq);
	kfree_skb(skb);
}

void trap() {
	static int count = 0;
	count++;
}


struct ParseContinuation {
	int nextStart;
	int oldCount; // Count from previous parse
	int count; // number of elements we've parsed (in total)
	int sum; // sum of elements
	/* begin incomplete continuation fields */
	int values[0];
};

int validateParseContinuation(struct ParseContinuation *predConvCont, unsigned predConvContLen) {
	return (predConvCont->count >= 0) &&
		predConvContLen >= sizeof(*predConvCont)  &&
		(predConvContLen - sizeof(*predConvCont)) % sizeof(int) == 0;
}

static void parseInput(struct cminisock *msk, unsigned seq, unsigned validStart, struct ParseContinuation *predConvCont, unsigned predConvContLen, char *response) {
	int i;
	int numNewValues = 0, maxNumValues = (TRICKLES_MSS-200) / sizeof(int);
	int *newValues = kmalloc(2000 * sizeof(int), GFP_ATOMIC);
	int bytesConsumed = 0;
	char *tokenStart;
	int error = 0;
	char *input = msk->input;
	unsigned input_len = msk->input_len;
	int first = predConvCont->count == 0;
	char *tail;

	tokenStart = input;
	for(i=0; i < input_len; i++) {
		if(first && i == 0) {
			/* start of parse */
			if(input[i] != '[')
				goto error;
			tokenStart = input + 1;
		} else {
			if(isdigit(input[i])) continue;
			switch(input[i]) {
			case ',': {
				input[i] = '\0';
				newValues[numNewValues++] = atoi(tokenStart);
				bytesConsumed = i + 1;
				tokenStart = &input[i+1];
				continue;
			}
			case ']': {
				struct WireUC_CVT_CompleteResponse *completeResponse =
					(struct WireUC_CVT_CompleteResponse *)response;
				struct ParseContinuation *newConvCont;
				/* generate complete response */
				int bytesConsumed = i + 1;
				unsigned validStart;
				unsigned validEnd;
				int numOldValues = 
					(predConvContLen - sizeof(struct ParseContinuation)) / sizeof(int);

				switch(continuationStyle) {
				case CONT_MGMT0:
					validStart = predConvCont->nextStart;
					validEnd = validStart + DATUMLEN;
					break;
				case CONT_MGMT1:
				case CONT_MGMT2:
					validStart = predConvCont->nextStart;
					validEnd = validStart + CHUNKSIZE;
					break;
				case CONT_MGMT3:
				default:
					printk("ContinuationStyle %d not implemented\n", continuationStyle);
					exit(-1);
				}

				if(tokenStart != &input[i]) {
					/* new number */
					input[i] = '\0';
					newValues[numNewValues++] = atoi(tokenStart);
				}
				initCompleteResponse(completeResponse,
						     seq + bytesConsumed,
						     sizeof(struct ParseContinuation) /* new length */,
						     0,
						     validStart,
						     validEnd);
				newConvCont = WireUC_getDataStart(&completeResponse->newCont);
				*newConvCont = *predConvCont;
				newConvCont->nextStart = validStart + NUMCHUNKS * CHUNKSIZE;
				for(i=0; i < numOldValues; i++) {
					newConvCont->sum += predConvCont->values[i];
				}
				for(i=0; i < numNewValues; i++) {
					newConvCont->sum += newValues[i];
				}
				newConvCont->oldCount = newConvCont->count + numNewValues;
				newConvCont->count = 0;
				tail = (char*)completeResponse + ntohs(completeResponse->len);

				switch(continuationStyle) {
				case CONT_MGMT0:
					// do nothing
					break;
				case CONT_MGMT1: 
				case CONT_MGMT2: {	
					// append 9 more continuations
					int i;
					for(i=1; i < NUMCHUNKS; i++) {
						int *xlat;
						struct WireUC_NewContinuationResponse *newResponse = 
							(struct WireUC_NewContinuationResponse*)tail;
						struct ParseContinuation *pCont;
						if(continuationSubstyle < 2) {
							xlat = xlat0;
						} else {
							xlat = xlat1;
						}
						unsigned chunkStart = validStart + xlat[i] * CHUNKSIZE;
						unsigned chunkEnd = validStart + (xlat[i] + 1) * CHUNKSIZE;
						if(continuationSubstyle >= 1) {
							chunkStart -= 100;
						}
						if(continuationSubstyle >= 1) {
							chunkEnd = MIN(chunkEnd + 100, newConvCont->nextStart);
						}

						initNewContinuationResponse(newResponse, sizeof(struct ParseContinuation),
									    0, chunkStart, chunkEnd);
						pCont = WireUC_getDataStart(&newResponse->newCont);
						*pCont = *newConvCont;
						tail += ntohs(newResponse->len);
					}
					break;
				}
				case CONT_MGMT3:
				default:
					printk("ContinuationStyle %d not implemented\n", continuationStyle);
					exit(-1);
				}

				goto alreadySentCont;
			}
			default:
			error:
				error = 1;
				goto loopExit;
			}
		}
	}
 loopExit:
	/* either error happened, or could not read enough data */
	if(error) {
		struct WireUC_CVT_IncompleteResponse *incompleteResponse =
			(struct WireUC_CVT_IncompleteResponse *)response;
		printk("UC_INCOMPLETE response generation: Found invalid character in input\n");
		initIncompleteResponse(incompleteResponse,
				       + 0 /* bytesConsumed */,
				       error,
				       validStart,   // 0506 removing ntohl
				       predConvContLen);
		memcpy(incompleteResponse->newCont.data, (char*)predConvCont, predConvContLen);
		tail = response + ntohs(((struct WireUC_RespHeader*)response)->len);
	} else {
		/* Generate incomplete response */
		int j;
		struct WireUC_CVT_IncompleteResponse *incompleteResponse =
			(struct WireUC_CVT_IncompleteResponse *)response;
		struct ParseContinuation *newConvCont = (struct ParseContinuation *)incompleteResponse->newCont.data;
		int newConvContLen;
		int numOldValues = (predConvContLen - sizeof(struct ParseContinuation)) / sizeof(int);
		*newConvCont = *predConvCont;
		if(numOldValues + numNewValues > maxNumValues) {
			for(j=0; j < numOldValues; j++) {
				newConvCont->sum += predConvCont->values[j];
			}
			for(j=0; j < numNewValues; j++) {
				newConvCont->sum += newValues[j];
			}
			newConvCont->count += numNewValues;
			newConvContLen = sizeof(struct ParseContinuation);
		} else {
			for(j=0; j < numOldValues; j++) {
				newConvCont->values[j] = predConvCont->values[j];
			}
			for(j=0; j < numNewValues; j++) {
				newConvCont->values[numOldValues + j] = newValues[j];
			}
			newConvCont->count += numNewValues;
			newConvContLen = sizeof(struct ParseContinuation) + 
				sizeof(int) * (numOldValues + numNewValues);
		}
		initIncompleteResponse(incompleteResponse,
				       seq + bytesConsumed,
				       0 /* error */,
				       validStart,  // 0506 removing ntohl
				       newConvContLen);
		// sum is updated on ']'
		tail = response + ntohs(((struct WireUC_RespHeader*)response)->len);
	}
  alreadySentCont:
	{
		int ucont_len = tail - response;
		setPacketUCont(&msk->packets[0], (char*)response, 
			       ucont_len);
	}
	kfree(newValues);
}


void DoUpcall(struct cminisock *msk, enum cminisock_event_tag event) {
	int i, numSiblings = 0;
	struct WireUC_ReqHeader *hdr;
	int mgmtRequest = 0;
	struct ParseContinuation parseCont;
	unsigned start, end;
	int byteNum;
	int len, fullLen;
	struct sk_buff **skbs = kmalloc(sizeof(struct sk_buff *) * msk->num_packets, GFP_ATOMIC);
	if(skbs == NULL) {
		goto out;
	}

	if(SIMULATION_MODE(msk->sk)) {
		goto out;
	}
	msk->tag = event;

#ifdef TEST_TRANSPORT_ONLY
	{
		struct WireUC_DataRequest *dataReq = msk->ucont_data;
		if(event == SYN) {
			byteNum = 0;
			len = 0;
		} else {
			byteNum = ntohl(dataReq->start);
			len = ntohl(dataReq->end) - byteNum;
		}
		for(i=0; i < msk->num_packets; i++) {
			struct sk_buff *skb = alloc_skb(2000, GFP_ATOMIC);
			char testbuf[3000], *testptr = testbuf;
			int copyLen = MIN(len, msk->packets[i].len);
			skb_reserve(skb, MAX_TCP_HEADER + MAX_TRICKLES_SERVER_HDR_LEN);
			while(testptr - testbuf < copyLen) {
				char *teststr = "teststring";
				int testlen = strlen(teststr);
				memcpy(testptr, teststr, testlen);
				testptr += testlen;
			}
			memcpy(skb_put(skb, copyLen), testbuf, copyLen);
			msk->packets[i].byteNum = byteNum;
			byteNum += copyLen;
			len -= copyLen;
			msk_transmit_skb(msk, skb, i);
		}
	}
	
	free_trickles_msk(msk->sk,msk);
	free_trickles_msk_finish(msk->sk,msk);
	goto out;
#endif // TEST_TRANPORT_ONLY
	if(msk->ucont_len == 0) {
		if(event == SYN) {
			/* Generate initial continuation */
			char *response = kmalloc(ETHERNET_MTU, GFP_ATOMIC);
			struct WireUC_CVT_CompleteResponse *completeResponse = 
				(struct WireUC_CVT_CompleteResponse*)response;
			struct ParseContinuation *initConvCont;
			int responseLen;
			mgmtRequest = 1;
			if(response == NULL) {
				printk("Upcall error: out of memory while allocating initial continuation\n");
				goto out;
			}
			initCompleteResponse(completeResponse, 
					     + 0,
					     sizeof(struct ParseContinuation),
					     0,
					     0, 0);
			initConvCont = WireUC_getDataStart(&completeResponse->newCont);
			initConvCont->nextStart = 0;
			initConvCont->count = 0;
			initConvCont->sum = 0;
			responseLen = ntohs(((struct WireUC_RespHeader*)response)->len);
			setPacketUCont(&msk->packets[0], (char*)response, 
				       responseLen);
		} else {
			for(i=0; i < msk->num_packets; i++) {
				struct sk_buff *skb = alloc_skb(3000, GFP_ATOMIC);
				skb_reserve(skb, MAX_TCP_HEADER + MAX_TRICKLES_SERVER_HDR_LEN + msk->packets[i].ucontLen);
				msk_transmit_skb(msk, skb, i);
			}
			goto out;
		}
	}
	hdr = (struct WireUC_ReqHeader *)msk->ucont_data;
	if(msk->ucont_len > 0) {
		if(msk->ucont_len < sizeof(*hdr)) {
			printk("Upcall error: user continuation too short for request header\n");
			goto out;
		}
		/* Parsing algorithm for test:
		   [ open
		   ] close
		   , separator for parse

		   continuation: push integer translation at the end
		*/
		switch((enum UC_Type)hdr->type) {
		case UC_INCOMPLETE: {
			int predConvContLen = msk->ucont_len - sizeof(struct WireUC_CVT_IncompleteRequest);
			char *response = kmalloc(ETHERNET_MTU, GFP_ATOMIC);
			struct WireUC_CVT_IncompleteRequest *incompleteRequest = 
				(struct WireUC_CVT_IncompleteRequest *)hdr;
			struct ParseContinuation *predConvCont = 
				(struct ParseContinuation *)incompleteRequest->predCont.data;
			mgmtRequest = 1;

			if(response == NULL) {
				printk("UC_INCOMPLETE response generation - out of memory\n");
				goto out;
			}
			if(msk->ucont_len < sizeof(struct WireUC_CVT_IncompleteRequest)) {
				printk("UC_INCOMPLETE response generation - ucont too short\n");
				goto out;
			}
			if(predConvContLen < sizeof(struct ParseContinuation)) {
				printk("UC_INCOMPLETE: pred continuation too short\n");
				goto out;
			}
			if(!validateParseContinuation(predConvCont, predConvContLen)) {
				printk("Invalid parse continuation\n");
				goto out;
			}
			parseInput(msk, htonl(incompleteRequest->seq), incompleteRequest->predCont.validStart, predConvCont, predConvContLen, response);
			break;
		}
		case UC_COMPLETE: {
			struct WireUC_CVT_CompleteRequest *completeRequest = 
				(struct WireUC_CVT_CompleteRequest *) hdr;
			char *response = kmalloc(ETHERNET_MTU, GFP_ATOMIC);
			struct ParseContinuation *predConvCont = (struct ParseContinuation*)completeRequest->predCont.data;
			unsigned predConvContLen;
	  
			predConvContLen = msk->ucont_len - sizeof(struct WireUC_CVT_CompleteRequest);
			if(response == NULL) {
				printk("UC_COMPLETE response generation - out of memory\n");
				goto out;
			}
			if(msk->ucont_len < sizeof(struct WireUC_CVT_CompleteRequest)) {
				printk("UC_COMPLETE response generation - ucont too short\n");
				goto out;
			}
			if(predConvContLen < sizeof(struct ParseContinuation)) {
				printk("UC_COMPLETE: pred continuation too short\n");
				goto out;
			}
			mgmtRequest = 1;
			if(!validateParseContinuation(predConvCont, predConvContLen)) {
				printk("Invalid parse continuation\n");
				goto out;
			}
			parseInput(msk, htonl(completeRequest->seq), completeRequest->predCont.validStart, predConvCont, predConvContLen, response);
			break;
		}
		case UC_UPDATE:
			printk("DoUpcall: can't handle update requests\n");
			goto out;
			break;
		case UC_DATA: {
			struct WireUC_DataRequest *dataReq = (struct WireUC_DataRequest *)hdr;
			struct WireUC_Continuation *predCont = (struct WireUC_Continuation *)dataReq->data;
			struct ParseContinuation *predConvCont = (struct ParseContinuation *)predCont->data;
			unsigned predSeq;
			unsigned oldStart = ntohl(predCont->validStart),
				oldEnd = ntohl(predCont->validEnd);
			if(msk->ucont_len < sizeof(struct WireUC_DataRequest) + 
			   sizeof(struct WireUC_Continuation) + 
			   sizeof(struct ParseContinuation)) {
				printk("UC_DATA: ucont_len too short\n");
				goto out;
			}
			start = ntohl(dataReq->start);
			end = ntohl(dataReq->end);
			if(!(start >= oldStart && 
			     end <= oldEnd)) {
				printk("UC_DATA: request out of range\n");
				goto out;
			}
			mgmtRequest = 0;
			parseCont = *predConvCont;

			byteNum = start;
			len = end - start;
			predSeq = ntohl(predCont->seq);

			//printk("offset %d\n", start - oldStart);
			if(continuationStyle == CONT_MGMT2) {
				if(oldStart <= DATUMLEN / 2 || predSeq > 0) {
					// acceptable
#if 0
					if(oldStart < DATUMLEN / 2 - 200 && start == oldStart) {
						// Doesn't work!!! This is because the data requests are not necessarily aligned with the request boundaries
#else
					if(oldStart < DATUMLEN / 2 - 200 && start < oldStart + TRICKLES_MSS) {
#endif
						// push acceptable replacement to client
						char *response = kmalloc(2000, GFP_ATOMIC);
						struct WireUC_NewContinuationResponse *newResponse = 
							(struct WireUC_NewContinuationResponse*)response;
						struct ParseContinuation *pCont;
						int ucont_len;
						unsigned chunkStart, chunkEnd;
						chunkStart = parseCont.nextStart - DATUMLEN + 
							oldStart + NUMCHUNKS / 2 * CHUNKSIZE;
						chunkEnd = chunkStart + CHUNKSIZE;
						if(continuationSubstyle >= 1) {
							chunkStart -= 200;
							chunkEnd = MIN(chunkEnd + 200, parseCont.nextStart);
						}
						initNewContinuationResponse(newResponse, sizeof(struct ParseContinuation),
									    1, chunkStart, chunkEnd);
						printk("Pushing new continuation seq %d [%d-%d]\n", 
						       ntohl(newResponse->newCont.seq), 
						       ntohl(newResponse->newCont.validStart), 
						       ntohl(newResponse->newCont.validEnd));
						pCont = WireUC_getDataStart(&newResponse->newCont);
						*pCont = parseCont;
						ucont_len = ntohs(newResponse->len);

						setPacketUCont(&msk->packets[0], (char*)response, 
							       ucont_len);
						// postprocessing
						int totalLen = 0;
						for(i=0; i < msk->num_packets; i++) {
							totalLen += msk->packets[i].len;
						}

						if(len + ucont_len > totalLen) {
							len = totalLen - ucont_len;
						}
					}
				} else {
					printk("Dropping requests for data that had used stale conversion requests\n");
					goto out;
				}
			}
			break;
		}
		default:
			printk("DoUpcall: Unhandled ucont type\n");
			goto out;
		}
	}
	if(event == SYN) {
		byteNum = 0;
		len = 0;
	}
	
	fullLen = len;
	for(i=0; i < msk->num_packets; i++) {
		struct sk_buff *skb;
		skbs[i] = skb = alloc_skb(3000, GFP_ATOMIC);
		skb_reserve(skb, MAX_TCP_HEADER + MAX_TRICKLES_SERVER_HDR_LEN + msk->packets[i].ucontLen);

#ifdef TRUNCATE_SEND
			int realLen = (len > TRICKLES_MSS ? len - TRICKLES_MSS : len);
			// send part of request
			if(realLen != len) {
				//printk("DoUpcall - Kept %d-%d, Pruned %d-%d\n", byteNum,  byteNum + realLen, byteNum + realLen, byteNum + len);
			}
			len = realLen;
#endif
			// send full request
		if(!mgmtRequest) {
			char number[100];
			char *outPtr = skb->data;
			int chunkLen, copyLen = MIN(len, msk->packets[i].len);
			sprintf(number, "(%d/%d)", parseCont.sum, parseCont.oldCount);
			chunkLen = strlen(number);
			while((char*)outPtr - (char*)skb->data < copyLen) {
				memcpy(outPtr, number, chunkLen);
				outPtr += chunkLen;
			}

#ifdef TRUNCATE_SEND_ALOT
			int realCopyLen = (copyLen > TRICKLES_MSS ? copyLen - TRICKLES_MSS : copyLen);
			// send part of request
			if(realCopyLen != copyLen) {
				//printk("DoUpcall - Kept %d-%d, Pruned %d-%d\n", byteNum,  byteNum + realCopyLen, byteNum + realCopyLen, byteNum + copyLen);
			}
			skb_put(skb, realCopyLen);
#else
			skb_put(skb, copyLen);
#endif
			msk->packets[i].byteNum = byteNum;
			byteNum += copyLen;
			len -= copyLen;

			if(copyLen > 0) {
				numSiblings++;
				msk->packets[i].position = i;
			} else {
				msk->packets[i].position = INVALID_POSITION;
			}
		} else {
			msk->packets[i].numSiblings = 1;
			msk->packets[i].position = (i==0 ? 0 : INVALID_POSITION);
		}
	}
	for(i=0; i < msk->num_packets; i++) {
		if(!mgmtRequest)
			msk->packets[i].numSiblings = numSiblings;
		msk_transmit_skb(msk, skbs[i], i);
	}

 out:
	free_trickles_msk(msk->sk,msk);
	free_trickles_msk_finish(msk->sk,msk);
	if(skbs)
		kfree(skbs);
}
