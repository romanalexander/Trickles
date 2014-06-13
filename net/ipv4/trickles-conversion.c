#include "trickles-int.h"
// sk->tp_pinfo.af_tcp.trickles_opt
// TCP_TRICKLES_PAR_REQUEST

static void CompleteRequest_parallelFinish(struct sock *sk, CONTINUATION_TYPE *cont, struct UC_Continuation *ucont, int numSiblings);

int CompleteRequest_parallel_queue(struct sock *sk, struct sk_buff *skb, int reserve_len) {
	struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;
	struct ConversionRequest *req = kmalloc_ConversionRequest(GFP_ATOMIC);
	if(req == NULL) {
		printk("out of memory in conversionrequest\n");
		return -ENOMEM;
	}

	static int idents = 0;
	req->ident = idents++;
	// printk("ident=%d\n", req->ident);
	if(0 && idents > 20) {
		printk("======== %d ========\n", idents);
		SK_ucontList_dump(sk);
		SK_request_dump(sk);
		return 0;
	}

	initCompleteConversionRequest(req,
				      NULL /* no convReq */,
				      skb /* Data */,
				      0);
	req->parallelStart = tp->t.requestNext;
	tp->t.requestNext += reserve_len;
	queueNewRequest(sk, (struct Request *)req);

	// SK_request_dump(sk);
	return 0;
}

void CompleteRequest_finish(struct sock *sk, CONTINUATION_TYPE *cont, 
		    char *ucont_start, int ucont_len, 
		    struct WireUC_CVT_CompleteResponse *completeResp,
		    struct RequestOFOEntry *ofo_entry) {
	struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;
	struct UC_Continuation *ucont;
	if(ucont_len < sizeof(*completeResp)) {
		printk("User continuation too short for complete response\n");
		return;
	}
	if(tp->trickles_opt & TCP_TRICKLES_PAR_REQUEST) {
		struct UC_Continuation *ucont = 
			unmarshallUC_Continuation(&completeResp->newCont,
			  ucont_len - ((char*)&completeResp->newCont - (char*)ucont_start));
		if(ucont == NULL) {
			printk("pre parallelFinish: out of memory while allocating continuation\n");
			return;
		}

		CompleteRequest_parallelFinish(sk, cont, ucont, 
					       ofo_entry->numSiblings);
	} else {
		switch(tp->t.conversionState) {
			struct UC_Continuation *newConvCont;
			unsigned ackSeq;
		case CONVERSION_WAITFORSERVER:
			ucont = unmarshallUC_Continuation(&completeResp->newCont,
							  ucont_len - ((char*)&completeResp->newCont - (char*)ucont_start));
			if(ucont == NULL) {
				printk("Error while unmarshalling UC Continuation for UC_Complete packet\n");
				return;
			}
			/* Save continuation for use in subsequent conversion request */
			newConvCont = copyUC_Continuation(ucont);
			atomic_set(&newConvCont->refcnt, 1);
			if(newConvCont == NULL) {
				printk("Error while saving convCont in prevConvCont\n");
				kfree(ucont);
				return;
			}
			ackSeq = ntohl(completeResp->ack_seq);
			if(ackSeq > tp->t.snd_una) {
				tp->t.snd_una = ackSeq;
				//printk("snd_una = %d\n", tp->t.snd_una);
				if(tp->t.snd_una > tp->t.write_seq) {
					printk("Error! snd_una %d > tp->t.write_seq %d while processing CompleteConversion\n", tp->t.snd_una, tp->t.write_seq);
					tp->t.snd_una = tp->t.write_seq;
				}
			}
#if 0
			else {
				printk("snd_una not updated\n");
			}
#endif

			if(addNewUC_Continuation(sk, ucont)) {
				printk("UC_COMPLETE: error while adding new continuation "); UC_Continuation_dump(ucont);
				printk("conversioncount is %d \n", gSocketConversionCount);
				// TRACE_THIS_PACKET();
				SK_ucontList_dump(sk);
				SK_data_ofo_queue_dump(sk);
				SK_request_dump(sk);
				SK_dump_vars(sk);

				kfree(ucont);
				return;
			}
			if(tp->t.prevConvCont) {
				// XXX Leave these FINDING_LEAK defines in here to find the lurking memory leak
				UC_CONTINUATION_TRYFREE(tp->t.prevConvCont);
			}
			tp->t.prevConvCont = newConvCont;
			// printk("prevConvCont = "); UC_Continuation_dump(tp->t.prevConvCont);

			// XXX this code does not account for multiple user continuations
#if 0
			if(ntohs(completeResp->piggyLength) > 0) {
				SK_makeVirtualRequest(sk, ucont, 
						      cont->seq,
						      ucont->validStart, 
						      ucont->validStart + ntohs(completeResp->piggyLength));
			}
#endif
			if(tp->t.write_seq - tp->t.snd_una > 0) {
				queueConversionRequests(sk);
				tp->t.conversionState = CONVERSION_WAITFORSERVER;
#if 0 // 0426 - do not push out requests in interrupt context, since the requests will be sent automatically
				pushRequests(sk);
#endif
				//printk("update client state set conversion state to waitforserver\n");
			} else {
				cleanTxQueue(sk);
				tp->t.conversionState = CONVERSION_IDLE;
				//printk("update client state set conversion state to IDLE: %d\n", tp->t.conversionState);
			}
			break;
		case CONVERSION_IDLE:
			printk("Invalid state: CONVERSION_IDLE while processing completeResponse\n");
			return;
		case CONVERSION_WAITFORUSER:
			printk("Invalid state: CONVERSION_WAITFORUSER while processing completeResponse\n");
			return;
		default:
			printk("Invalid state!\n");
			BUG();
			return;
		}
	}
}

static 
void CompleteRequest_parallelFinish(struct sock *sk, CONTINUATION_TYPE *cont, 
		    struct UC_Continuation *ucont, int numSiblings) {
	struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;
	struct Request *parent_req, *next;

	if(addNewUC_Continuation(sk, ucont)) {
		printk("could not add uc continuation\n");
		UC_CONTINUATION_TRYFREE(ucont);
		return;
	}

	// COMPLETE requests use a _proper_ matching algorithm. As needs permit, the other request types will likewise be converted

	// the only requests that should be updated are in sentRequests
	// processing queuedRequests would be an optimization

	struct alloc_head_list *head = &tp->t.sentRequests;
	for(parent_req = (struct Request *) head->next,next = (struct Request *) parent_req->next;
	    (struct alloc_head_list *) parent_req != head; parent_req = next, next = (struct Request *)next->next) {
		if(!(parent_req->type == MREQ_CONVERSION &&
		     !((struct ConversionRequest *)parent_req)->incomplete)) {
			continue;
		}
		if(parent_req->seq != cont->parent) {
			continue;
		}

#if 0
		printk("checking %d <= %d < %d\n",
		       parent_req->transportResponseSeqStart,
		       cont->seq, parent_req->transportResponseSeqEnd);
#endif

		if(!(parent_req->transportResponseSeqStart <= cont->seq && 
		     cont->seq < parent_req->transportResponseSeqEnd)) {
			printk("matched parent, but did not match transport response seq\n");
			continue;
		}

		// sanity check the number of siblings
		if(parent_req->numActualChildren == 0) {
			parent_req->numActualChildren = numSiblings;
		}
		BUG_TRAP(parent_req->numActualChildren == numSiblings);
		unlink((struct alloc_head *) parent_req);
		kfree_skb(((struct ConversionRequest *)parent_req)->data);
		freeRequest(parent_req);

	}
	BUG_TRAP(cont->parent == tp->t.request_rcv_nxt);
	if(cont->parent == tp->t.request_rcv_nxt) {
		// printk("rcv_nxt++ %d\n", tp->t.request_rcv_nxt);
		tp->t.request_rcv_nxt++;
	}
}
