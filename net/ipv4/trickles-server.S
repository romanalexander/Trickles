
trickles-server.o:     file format elf32-i386

Disassembly of section .text:

00000000 <free_trickles_msk>:
/* Two phase free: first phase disconnects socket from event list,
   sets to ALLOC_PROCESSING; second phase adds the socket to free
   list, sets to ALLOC_FREE and ready for reuse */
#ifndef USERTEST
static inline void free_trickles_msk(struct sock *sk, struct cminisock *msk) {
       0:	55                   	push   %ebp
       1:	89 e5                	mov    %esp,%ebp
       3:	83 ec 0c             	sub    $0xc,%esp
       6:	89 5d fc             	mov    %ebx,0xfffffffc(%ebp)
	if(!SIMULATION_MODE(sk)) {
       9:	8b 45 08             	mov    0x8(%ebp),%eax
       c:	8b 5d 0c             	mov    0xc(%ebp),%ebx
       f:	8b 80 a8 02 00 00    	mov    0x2a8(%eax),%eax
      15:	a9 01 00 00 00       	test   $0x1,%eax
      1a:	74 05                	je     21 <free_trickles_msk+0x21>
      1c:	83 e0 08             	and    $0x8,%eax
      1f:	74 16                	je     37 <free_trickles_msk+0x37>
		if(msk->ctl == ALLOC_FREE || msk->ctl == ALLOC_PROCESSING) {
      21:	8b 43 0c             	mov    0xc(%ebx),%eax
      24:	85 c0                	test   %eax,%eax
      26:	74 48                	je     70 <free_trickles_msk+0x70>
      28:	83 f8 03             	cmp    $0x3,%eax
      2b:	74 43                	je     70 <free_trickles_msk+0x70>
			printk("double free\n");
			BUG();
		}
		if(msk->ctl == ALLOC_READY && msk->prev != NULL) {
      2d:	48                   	dec    %eax
      2e:	74 10                	je     40 <free_trickles_msk+0x40>
			unlink((struct alloc_head *)msk);
		}
		msk->ctl = ALLOC_PROCESSING;
      30:	c7 43 0c 03 00 00 00 	movl   $0x3,0xc(%ebx)
	}
}
      37:	8b 5d fc             	mov    0xfffffffc(%ebp),%ebx
      3a:	89 ec                	mov    %ebp,%esp
      3c:	5d                   	pop    %ebp
      3d:	c3                   	ret    
      3e:	89 f6                	mov    %esi,%esi
      40:	8b 03                	mov    (%ebx),%eax
      42:	85 c0                	test   %eax,%eax
      44:	74 ea                	je     30 <free_trickles_msk+0x30>
		BUG();
	}
#endif

	elem->next->prev = elem->prev;
      46:	8b 53 04             	mov    0x4(%ebx),%edx
      49:	89 02                	mov    %eax,(%edx)
	elem->prev->next = elem->next;
      4b:	8b 03                	mov    (%ebx),%eax
	elem->prev = elem->next = NULL;
      4d:	c7 03 00 00 00 00    	movl   $0x0,(%ebx)
      53:	89 50 04             	mov    %edx,0x4(%eax)

	elem->list->len--;
      56:	8b 43 08             	mov    0x8(%ebx),%eax
      59:	c7 43 04 00 00 00 00 	movl   $0x0,0x4(%ebx)
      60:	ff 48 10             	decl   0x10(%eax)
	elem->list = NULL;
      63:	c7 43 08 00 00 00 00 	movl   $0x0,0x8(%ebx)
      6a:	eb c4                	jmp    30 <free_trickles_msk+0x30>
      6c:	8d 74 26 00          	lea    0x0(%esi,1),%esi
#ifndef USERTEST
static inline void free_trickles_msk(struct sock *sk, struct cminisock *msk) {
	if(!SIMULATION_MODE(sk)) {
		if(msk->ctl == ALLOC_FREE || msk->ctl == ALLOC_PROCESSING) {
			printk("double free\n");
      70:	c7 04 24 00 00 00 00 	movl   $0x0,(%esp,1)
      77:	e8 fc ff ff ff       	call   78 <free_trickles_msk+0x78>
			BUG();
      7c:	c7 44 24 04 0d 00 00 	movl   $0xd,0x4(%esp,1)
      83:	00 
      84:	c7 04 24 11 00 00 00 	movl   $0x11,(%esp,1)
      8b:	e8 fc ff ff ff       	call   8c <free_trickles_msk+0x8c>
      90:	e8 fc ff ff ff       	call   91 <free_trickles_msk+0x91>
      95:	8b 43 0c             	mov    0xc(%ebx),%eax
      98:	eb 93                	jmp    2d <free_trickles_msk+0x2d>
      9a:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi

000000a0 <free_trickles_msk_finish>:
		}
		if(msk->ctl == ALLOC_READY && msk->prev != NULL) {
			unlink((struct alloc_head *)msk);
		}
		msk->ctl = ALLOC_PROCESSING;
	}
}

static inline void free_trickles_msk_finish(struct sock *sk, struct cminisock *msk) {
      a0:	55                   	push   %ebp
      a1:	89 e5                	mov    %esp,%ebp
      a3:	57                   	push   %edi
      a4:	56                   	push   %esi
      a5:	31 f6                	xor    %esi,%esi
      a7:	53                   	push   %ebx
      a8:	83 ec 10             	sub    $0x10,%esp
	struct tcp_opt *tp = &(sk->tp_pinfo.af_tcp);
      ab:	8b 45 08             	mov    0x8(%ebp),%eax
	struct alloc_head_list *head = &tp->cminisock_api_config.msk_freelist;
      ae:	8b 55 08             	mov    0x8(%ebp),%edx
      b1:	8b 7d 0c             	mov    0xc(%ebp),%edi
      b4:	05 bc 00 00 00       	add    $0xbc,%eax
      b9:	89 45 f0             	mov    %eax,0xfffffff0(%ebp)
      bc:	81 c2 90 02 00 00    	add    $0x290,%edx
      c2:	89 55 ec             	mov    %edx,0xffffffec(%ebp)
      c5:	8b 97 dc 00 00 00    	mov    0xdc(%edi),%edx
      cb:	39 d6                	cmp    %edx,%esi
      cd:	7d 2b                	jge    fa <free_trickles_msk_finish+0x5a>
      cf:	31 db                	xor    %ebx,%ebx
      d1:	eb 0d                	jmp    e0 <free_trickles_msk_finish+0x40>
      d3:	90                   	nop    
      d4:	90                   	nop    
      d5:	90                   	nop    
      d6:	90                   	nop    
      d7:	90                   	nop    
      d8:	90                   	nop    
      d9:	90                   	nop    
      da:	90                   	nop    
      db:	90                   	nop    
      dc:	90                   	nop    
      dd:	90                   	nop    
      de:	90                   	nop    
      df:	90                   	nop    
      e0:	8b 87 e0 00 00 00    	mov    0xe0(%edi),%eax
      e6:	8b 44 18 18          	mov    0x18(%eax,%ebx,1),%eax
      ea:	85 c0                	test   %eax,%eax
      ec:	0f 85 6e 01 00 00    	jne    260 <free_trickles_msk_finish+0x1c0>
      f2:	46                   	inc    %esi
      f3:	83 c3 28             	add    $0x28,%ebx
      f6:	39 d6                	cmp    %edx,%esi
      f8:	7c e6                	jl     e0 <free_trickles_msk_finish+0x40>
      fa:	8b 55 08             	mov    0x8(%ebp),%edx
      fd:	8b 82 a8 02 00 00    	mov    0x2a8(%edx),%eax
     103:	a9 01 00 00 00       	test   $0x1,%eax
     108:	74 05                	je     10f <free_trickles_msk_finish+0x6f>
     10a:	83 e0 08             	and    $0x8,%eax
     10d:	74 0e                	je     11d <free_trickles_msk_finish+0x7d>
     10f:	8b 87 e0 00 00 00    	mov    0xe0(%edi),%eax
     115:	85 c0                	test   %eax,%eax
     117:	0f 85 2d 01 00 00    	jne    24a <free_trickles_msk_finish+0x1aa>
     11d:	8b 87 80 00 00 00    	mov    0x80(%edi),%eax
     123:	85 c0                	test   %eax,%eax
     125:	0f 85 0b 01 00 00    	jne    236 <free_trickles_msk_finish+0x196>
     12b:	8b 87 88 00 00 00    	mov    0x88(%edi),%eax
     131:	85 c0                	test   %eax,%eax
     133:	0f 85 e9 00 00 00    	jne    222 <free_trickles_msk_finish+0x182>

	free_minisock(sk,msk);
	if(!SIMULATION_MODE(sk)) {
     139:	8b 55 08             	mov    0x8(%ebp),%edx
     13c:	8b 82 a8 02 00 00    	mov    0x2a8(%edx),%eax
     142:	a9 01 00 00 00       	test   $0x1,%eax
     147:	74 09                	je     152 <free_trickles_msk_finish+0xb2>
     149:	83 e0 08             	and    $0x8,%eax
     14c:	0f 84 89 00 00 00    	je     1db <free_trickles_msk_finish+0x13b>
		if(msk->ctl != ALLOC_PROCESSING && msk->ctl != ALLOC_HALFFREE) {
     152:	8b 47 0c             	mov    0xc(%edi),%eax
     155:	83 e8 03             	sub    $0x3,%eax
     158:	83 f8 01             	cmp    $0x1,%eax
     15b:	77 57                	ja     1b4 <free_trickles_msk_finish+0x114>
	if(elem->list) {
		BUG();
	}
#endif
	if(head->next == elem /* || elem->prev != NULL || elem->next != NULL */) {
     15d:	8b 45 ec             	mov    0xffffffec(%ebp),%eax
     160:	39 78 04             	cmp    %edi,0x4(%eax)
     163:	74 28                	je     18d <free_trickles_msk_finish+0xed>
		BUG();
		show_stack(NULL);	
	}
	elem->next = head->next;
     165:	8b 55 ec             	mov    0xffffffec(%ebp),%edx
     168:	8b 42 04             	mov    0x4(%edx),%eax
     16b:	89 47 04             	mov    %eax,0x4(%edi)
	head->next->prev = elem;
     16e:	8b 42 04             	mov    0x4(%edx),%eax
     171:	89 38                	mov    %edi,(%eax)

	elem->prev = (struct alloc_head*)head;
     173:	89 17                	mov    %edx,(%edi)
	head->next = elem;
     175:	89 7a 04             	mov    %edi,0x4(%edx)

	elem->list = head;
     178:	89 57 08             	mov    %edx,0x8(%edi)
	head->len++;
     17b:	ff 42 10             	incl   0x10(%edx)
			printk("free_rstcp_msk_finish without corresponding free_rstcp_msk\n");
			BUG();
		}
		insert_head(head, (struct alloc_head *)msk);
		msk->ctl = ALLOC_FREE;
     17e:	c7 47 0c 00 00 00 00 	movl   $0x0,0xc(%edi)
	} else {
		if(msk == tp->t.responseMSK) {
		} else {
			// overflow
			unlink((struct alloc_head*)msk);
			kfree(msk);
		}
		tp->t.responseCount--;
	}
	
}
     185:	83 c4 10             	add    $0x10,%esp
     188:	5b                   	pop    %ebx
     189:	5e                   	pop    %esi
     18a:	5f                   	pop    %edi
     18b:	5d                   	pop    %ebp
     18c:	c3                   	ret    
		BUG();
	}
#endif
	if(head->next == elem /* || elem->prev != NULL || elem->next != NULL */) {
		BUG();
     18d:	c7 44 24 04 0d 00 00 	movl   $0xd,0x4(%esp,1)
     194:	00 
     195:	c7 04 24 11 00 00 00 	movl   $0x11,(%esp,1)
     19c:	e8 fc ff ff ff       	call   19d <free_trickles_msk_finish+0xfd>
     1a1:	e8 fc ff ff ff       	call   1a2 <free_trickles_msk_finish+0x102>
		show_stack(NULL);	
     1a6:	c7 04 24 00 00 00 00 	movl   $0x0,(%esp,1)
     1ad:	e8 fc ff ff ff       	call   1ae <free_trickles_msk_finish+0x10e>
     1b2:	eb b1                	jmp    165 <free_trickles_msk_finish+0xc5>

	free_minisock(sk,msk);
	if(!SIMULATION_MODE(sk)) {
		if(msk->ctl != ALLOC_PROCESSING && msk->ctl != ALLOC_HALFFREE) {
			printk("free_rstcp_msk_finish without corresponding free_rstcp_msk\n");
     1b4:	c7 04 24 00 00 00 00 	movl   $0x0,(%esp,1)
     1bb:	e8 fc ff ff ff       	call   1bc <free_trickles_msk_finish+0x11c>
			BUG();
     1c0:	c7 44 24 04 0d 00 00 	movl   $0xd,0x4(%esp,1)
     1c7:	00 
     1c8:	c7 04 24 11 00 00 00 	movl   $0x11,(%esp,1)
     1cf:	e8 fc ff ff ff       	call   1d0 <free_trickles_msk_finish+0x130>
     1d4:	e8 fc ff ff ff       	call   1d5 <free_trickles_msk_finish+0x135>
     1d9:	eb 82                	jmp    15d <free_trickles_msk_finish+0xbd>
		}
		insert_head(head, (struct alloc_head *)msk);
		msk->ctl = ALLOC_FREE;
	} else {
		if(msk == tp->t.responseMSK) {
     1db:	8b 45 f0             	mov    0xfffffff0(%ebp),%eax
     1de:	3b b8 3c 0b 00 00    	cmp    0xb3c(%eax),%edi
     1e4:	74 2e                	je     214 <free_trickles_msk_finish+0x174>
		BUG();
	}
#endif

	elem->next->prev = elem->prev;
     1e6:	8b 57 04             	mov    0x4(%edi),%edx
     1e9:	8b 07                	mov    (%edi),%eax
     1eb:	89 02                	mov    %eax,(%edx)
	elem->prev->next = elem->next;
     1ed:	8b 07                	mov    (%edi),%eax
	elem->prev = elem->next = NULL;
     1ef:	c7 07 00 00 00 00    	movl   $0x0,(%edi)
     1f5:	89 50 04             	mov    %edx,0x4(%eax)

	elem->list->len--;
     1f8:	8b 47 08             	mov    0x8(%edi),%eax
     1fb:	c7 47 04 00 00 00 00 	movl   $0x0,0x4(%edi)
     202:	ff 48 10             	decl   0x10(%eax)
	elem->list = NULL;
     205:	c7 47 08 00 00 00 00 	movl   $0x0,0x8(%edi)
		if(msk == tp->t.responseMSK) {
		} else {
			// overflow
			unlink((struct alloc_head*)msk);
			kfree(msk);
     20c:	89 3c 24             	mov    %edi,(%esp,1)
     20f:	e8 fc ff ff ff       	call   210 <free_trickles_msk_finish+0x170>
		}
		tp->t.responseCount--;
     214:	8b 55 f0             	mov    0xfffffff0(%ebp),%edx
     217:	ff 8a 54 0b 00 00    	decl   0xb54(%edx)
     21d:	e9 63 ff ff ff       	jmp    185 <free_trickles_msk_finish+0xe5>
     222:	89 44 24 04          	mov    %eax,0x4(%esp,1)
     226:	8b 45 08             	mov    0x8(%ebp),%eax
     229:	89 04 24             	mov    %eax,(%esp,1)
     22c:	e8 fc ff ff ff       	call   22d <free_trickles_msk_finish+0x18d>
     231:	e9 03 ff ff ff       	jmp    139 <free_trickles_msk_finish+0x99>
     236:	89 44 24 04          	mov    %eax,0x4(%esp,1)
     23a:	8b 55 08             	mov    0x8(%ebp),%edx
     23d:	89 14 24             	mov    %edx,(%esp,1)
     240:	e8 fc ff ff ff       	call   241 <free_trickles_msk_finish+0x1a1>
     245:	e9 e1 fe ff ff       	jmp    12b <free_trickles_msk_finish+0x8b>
     24a:	89 44 24 04          	mov    %eax,0x4(%esp,1)
     24e:	8b 45 08             	mov    0x8(%ebp),%eax
     251:	89 04 24             	mov    %eax,(%esp,1)
     254:	e8 fc ff ff ff       	call   255 <free_trickles_msk_finish+0x1b5>
     259:	e9 bf fe ff ff       	jmp    11d <free_trickles_msk_finish+0x7d>
     25e:	89 f6                	mov    %esi,%esi
     260:	89 04 24             	mov    %eax,(%esp,1)
     263:	e8 fc ff ff ff       	call   264 <free_trickles_msk_finish+0x1c4>
     268:	8b 97 dc 00 00 00    	mov    0xdc(%edi),%edx
     26e:	e9 7f fe ff ff       	jmp    f2 <free_trickles_msk_finish+0x52>
     273:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi
     279:	8d bc 27 00 00 00 00 	lea    0x0(%edi,1),%edi

00000280 <unmarshallContinuationServer>:
  do{					\
    memcpy(dcont->mac, scont->mac, HMACLEN);	\
  } while(0)

UNMARSHALL_CONTINUATION(Server, SERVER_COMPUTE_MAC);
     280:	55                   	push   %ebp
     281:	89 e5                	mov    %esp,%ebp
     283:	31 d2                	xor    %edx,%edx
     285:	57                   	push   %edi
     286:	56                   	push   %esi
     287:	53                   	push   %ebx
     288:	83 ec 40             	sub    $0x40,%esp
     28b:	8b 45 08             	mov    0x8(%ebp),%eax
     28e:	8b 58 0c             	mov    0xc(%eax),%ebx
     291:	8b 83 a8 02 00 00    	mov    0x2a8(%ebx),%eax
     297:	a9 01 00 00 00       	test   $0x1,%eax
     29c:	74 05                	je     2a3 <unmarshallContinuationServer+0x23>
     29e:	83 e0 08             	and    $0x8,%eax
     2a1:	74 05                	je     2a8 <unmarshallContinuationServer+0x28>
     2a3:	ba 01 00 00 00       	mov    $0x1,%edx
     2a8:	85 d2                	test   %edx,%edx
     2aa:	0f 85 03 01 00 00    	jne    3b3 <unmarshallContinuationServer+0x133>
     2b0:	8b 55 10             	mov    0x10(%ebp),%edx
     2b3:	8b 4d 0c             	mov    0xc(%ebp),%ecx
     2b6:	0f b6 02             	movzbl (%edx),%eax
     2b9:	89 41 38             	mov    %eax,0x38(%ecx)
	__arch__swab24s(addr);
}

static __inline__ __const__ __u32 __fswab32(__u32 x)
{
     2bc:	8b 42 01             	mov    0x1(%edx),%eax

static __inline__ __const__ __u32 ___arch__swab32(__u32 x)
{
#ifdef CONFIG_X86_BSWAP
	__asm__("bswap %0" : "=r" (x) : "0" (x));
     2bf:	0f c8                	bswap  %eax
	__arch__swab24s(addr);
}

static __inline__ __const__ __u32 __fswab32(__u32 x)
{
     2c1:	89 41 34             	mov    %eax,0x34(%ecx)
  do{					\
    memcpy(dcont->mac, scont->mac, HMACLEN);	\
  } while(0)

UNMARSHALL_CONTINUATION(Server, SERVER_COMPUTE_MAC);
     2c4:	8b 42 09             	mov    0x9(%edx),%eax
     2c7:	89 41 3c             	mov    %eax,0x3c(%ecx)
     2ca:	8b 42 0d             	mov    0xd(%edx),%eax
     2cd:	89 41 40             	mov    %eax,0x40(%ecx)
     2d0:	8b 42 25             	mov    0x25(%edx),%eax
     2d3:	89 41 44             	mov    %eax,0x44(%ecx)
	__arch__swab24s(addr);
}

static __inline__ __const__ __u32 __fswab32(__u32 x)
{
     2d6:	8b 42 25             	mov    0x25(%edx),%eax

static __inline__ __const__ __u32 ___arch__swab32(__u32 x)
{
#ifdef CONFIG_X86_BSWAP
	__asm__("bswap %0" : "=r" (x) : "0" (x));
     2d9:	0f c8                	bswap  %eax
	__arch__swab24s(addr);
}

static __inline__ __const__ __u32 __fswab32(__u32 x)
{
     2db:	89 41 4c             	mov    %eax,0x4c(%ecx)
  do{					\
    memcpy(dcont->mac, scont->mac, HMACLEN);	\
  } while(0)

UNMARSHALL_CONTINUATION(Server, SERVER_COMPUTE_MAC);
     2de:	8b 42 11             	mov    0x11(%edx),%eax
     2e1:	89 41 50             	mov    %eax,0x50(%ecx)
     2e4:	8b 42 29             	mov    0x29(%edx),%eax
     2e7:	89 41 48             	mov    %eax,0x48(%ecx)
	__arch__swab24s(addr);
}

static __inline__ __const__ __u32 __fswab32(__u32 x)
{
     2ea:	8b 42 29             	mov    0x29(%edx),%eax

static __inline__ __const__ __u32 ___arch__swab32(__u32 x)
{
#ifdef CONFIG_X86_BSWAP
	__asm__("bswap %0" : "=r" (x) : "0" (x));
     2ed:	0f c8                	bswap  %eax
	__arch__swab24s(addr);
}

static __inline__ __const__ __u32 __fswab32(__u32 x)
{
     2ef:	89 41 54             	mov    %eax,0x54(%ecx)
  do{					\
    memcpy(dcont->mac, scont->mac, HMACLEN);	\
  } while(0)

UNMARSHALL_CONTINUATION(Server, SERVER_COMPUTE_MAC);
     2f2:	0f b6 42 2d          	movzbl 0x2d(%edx),%eax
     2f6:	89 41 58             	mov    %eax,0x58(%ecx)
     2f9:	0f b6 42 05          	movzbl 0x5(%edx),%eax
     2fd:	89 41 5c             	mov    %eax,0x5c(%ecx)
	__arch__swab24s(addr);
}

static __inline__ __const__ __u32 __fswab32(__u32 x)
{
     300:	8b 42 2e             	mov    0x2e(%edx),%eax

static __inline__ __const__ __u32 ___arch__swab32(__u32 x)
{
#ifdef CONFIG_X86_BSWAP
	__asm__("bswap %0" : "=r" (x) : "0" (x));
     303:	0f c8                	bswap  %eax
	__arch__swab24s(addr);
}

static __inline__ __const__ __u32 __fswab32(__u32 x)
{
     305:	89 41 60             	mov    %eax,0x60(%ecx)
     308:	8b 42 32             	mov    0x32(%edx),%eax

static __inline__ __const__ __u32 ___arch__swab32(__u32 x)
{
#ifdef CONFIG_X86_BSWAP
	__asm__("bswap %0" : "=r" (x) : "0" (x));
     30b:	0f c8                	bswap  %eax
	__arch__swab24s(addr);
}

static __inline__ __const__ __u32 __fswab32(__u32 x)
{
     30d:	89 41 64             	mov    %eax,0x64(%ecx)
     310:	8b 42 36             	mov    0x36(%edx),%eax

static __inline__ __const__ __u32 ___arch__swab32(__u32 x)
{
#ifdef CONFIG_X86_BSWAP
	__asm__("bswap %0" : "=r" (x) : "0" (x));
     313:	0f c8                	bswap  %eax
	__arch__swab24s(addr);
}

static __inline__ __const__ __u32 __fswab32(__u32 x)
{
     315:	89 41 68             	mov    %eax,0x68(%ecx)
     318:	8b 42 3a             	mov    0x3a(%edx),%eax

static __inline__ __const__ __u32 ___arch__swab32(__u32 x)
{
#ifdef CONFIG_X86_BSWAP
	__asm__("bswap %0" : "=r" (x) : "0" (x));
     31b:	0f c8                	bswap  %eax
	__arch__swab24s(addr);
}

static __inline__ __const__ __u32 __fswab32(__u32 x)
{
     31d:	89 41 6c             	mov    %eax,0x6c(%ecx)
     320:	8b 42 3e             	mov    0x3e(%edx),%eax

static __inline__ __const__ __u32 ___arch__swab32(__u32 x)
{
#ifdef CONFIG_X86_BSWAP
	__asm__("bswap %0" : "=r" (x) : "0" (x));
     323:	0f c8                	bswap  %eax
	__arch__swab24s(addr);
}

static __inline__ __const__ __u32 __fswab32(__u32 x)
{
     325:	89 41 70             	mov    %eax,0x70(%ecx)
  do{					\
    memcpy(dcont->mac, scont->mac, HMACLEN);	\
  } while(0)

UNMARSHALL_CONTINUATION(Server, SERVER_COMPUTE_MAC);
     328:	31 d2                	xor    %edx,%edx
     32a:	8b 75 08             	mov    0x8(%ebp),%esi
     32d:	8b 46 0c             	mov    0xc(%esi),%eax
     330:	8b 80 a8 02 00 00    	mov    0x2a8(%eax),%eax
     336:	a9 01 00 00 00       	test   $0x1,%eax
     33b:	74 05                	je     342 <unmarshallContinuationServer+0xc2>
     33d:	83 e0 08             	and    $0x8,%eax
     340:	74 05                	je     347 <unmarshallContinuationServer+0xc7>
     342:	ba 01 00 00 00       	mov    $0x1,%edx
     347:	85 d2                	test   %edx,%edx
     349:	75 39                	jne    384 <unmarshallContinuationServer+0x104>
     34b:	8b 4d 0c             	mov    0xc(%ebp),%ecx
     34e:	31 db                	xor    %ebx,%ebx
     350:	89 99 dc 00 00 00    	mov    %ebx,0xdc(%ecx)
     356:	8b 75 10             	mov    0x10(%ebp),%esi
     359:	8b 46 42             	mov    0x42(%esi),%eax
     35c:	8b 56 46             	mov    0x46(%esi),%edx
     35f:	89 41 74             	mov    %eax,0x74(%ecx)
     362:	31 c0                	xor    %eax,%eax
     364:	89 51 78             	mov    %edx,0x78(%ecx)
     367:	31 d2                	xor    %edx,%edx
     369:	89 91 c0 00 00 00    	mov    %edx,0xc0(%ecx)
     36f:	89 81 c4 00 00 00    	mov    %eax,0xc4(%ecx)
     375:	b9 01 00 00 00       	mov    $0x1,%ecx
     37a:	83 c4 40             	add    $0x40,%esp
     37d:	89 c8                	mov    %ecx,%eax
     37f:	5b                   	pop    %ebx
     380:	5e                   	pop    %esi
     381:	5f                   	pop    %edi
     382:	5d                   	pop    %ebp
     383:	c3                   	ret    
     384:	8b 7d 08             	mov    0x8(%ebp),%edi
     387:	8b 55 0c             	mov    0xc(%ebp),%edx
     38a:	8b 47 24             	mov    0x24(%edi),%eax
     38d:	8b 40 10             	mov    0x10(%eax),%eax
     390:	89 42 14             	mov    %eax,0x14(%edx)
     393:	8b 47 24             	mov    0x24(%edi),%eax
     396:	8b 40 0c             	mov    0xc(%eax),%eax
     399:	89 42 18             	mov    %eax,0x18(%edx)
     39c:	8b 47 20             	mov    0x20(%edi),%eax
     39f:	0f b7 40 02          	movzwl 0x2(%eax),%eax
     3a3:	66 89 42 1c          	mov    %ax,0x1c(%edx)
     3a7:	8b 47 20             	mov    0x20(%edi),%eax
     3aa:	0f b7 00             	movzwl (%eax),%eax
     3ad:	66 89 42 1e          	mov    %ax,0x1e(%edx)
     3b1:	eb 98                	jmp    34b <unmarshallContinuationServer+0xcb>
     3b3:	8b 55 10             	mov    0x10(%ebp),%edx
     3b6:	8d 7d e4             	lea    0xffffffe4(%ebp),%edi
     3b9:	8b 75 08             	mov    0x8(%ebp),%esi
     3bc:	8b 42 01             	mov    0x1(%edx),%eax
     3bf:	89 45 c4             	mov    %eax,0xffffffc4(%ebp)
     3c2:	0f b6 02             	movzbl (%edx),%eax
     3c5:	88 45 c8             	mov    %al,0xffffffc8(%ebp)
     3c8:	0f b6 42 05          	movzbl 0x5(%edx),%eax
     3cc:	88 45 c9             	mov    %al,0xffffffc9(%ebp)
     3cf:	8b 4e 24             	mov    0x24(%esi),%ecx
     3d2:	8b 41 10             	mov    0x10(%ecx),%eax
     3d5:	89 45 ca             	mov    %eax,0xffffffca(%ebp)
     3d8:	8b 56 20             	mov    0x20(%esi),%edx
     3db:	89 fe                	mov    %edi,%esi
     3dd:	0f b7 42 02          	movzwl 0x2(%edx),%eax
     3e1:	66 89 45 ce          	mov    %ax,0xffffffce(%ebp)
     3e5:	8b 41 0c             	mov    0xc(%ecx),%eax
     3e8:	89 45 d0             	mov    %eax,0xffffffd0(%ebp)
     3eb:	0f b7 02             	movzwl (%edx),%eax
     3ee:	8d 55 c4             	lea    0xffffffc4(%ebp),%edx
     3f1:	89 7c 24 0c          	mov    %edi,0xc(%esp,1)
     3f5:	89 54 24 04          	mov    %edx,0x4(%esp,1)
     3f9:	89 1c 24             	mov    %ebx,(%esp,1)
     3fc:	66 89 45 d4          	mov    %ax,0xffffffd4(%ebp)
     400:	8b 45 10             	mov    0x10(%ebp),%eax
     403:	89 44 24 08          	mov    %eax,0x8(%esp,1)
     407:	e8 fc ff ff ff       	call   408 <unmarshallContinuationServer+0x188>
     40c:	8b 45 10             	mov    0x10(%ebp),%eax
     40f:	b9 10 00 00 00       	mov    $0x10,%ecx
     414:	fc                   	cld    
     415:	83 c0 15             	add    $0x15,%eax
     418:	89 c7                	mov    %eax,%edi
     41a:	f3 a6                	repz cmpsb %es:(%edi),%ds:(%esi)
     41c:	0f 97 c2             	seta   %dl
     41f:	0f 92 c0             	setb   %al
     422:	31 c9                	xor    %ecx,%ecx
     424:	38 c2                	cmp    %al,%dl
     426:	0f 85 4e ff ff ff    	jne    37a <unmarshallContinuationServer+0xfa>
     42c:	e9 7f fe ff ff       	jmp    2b0 <unmarshallContinuationServer+0x30>
     431:	eb 0d                	jmp    440 <unmarshallContinuationClient>
     433:	90                   	nop    
     434:	90                   	nop    
     435:	90                   	nop    
     436:	90                   	nop    
     437:	90                   	nop    
     438:	90                   	nop    
     439:	90                   	nop    
     43a:	90                   	nop    
     43b:	90                   	nop    
     43c:	90                   	nop    
     43d:	90                   	nop    
     43e:	90                   	nop    
     43f:	90                   	nop    

00000440 <unmarshallContinuationClient>:
UNMARSHALL_CONTINUATION(Client, CLIENT_COMPUTE_MAC);
     440:	55                   	push   %ebp
     441:	89 e5                	mov    %esp,%ebp
     443:	57                   	push   %edi
     444:	56                   	push   %esi
     445:	53                   	push   %ebx
     446:	83 ec 0c             	sub    $0xc,%esp
     449:	8b 75 10             	mov    0x10(%ebp),%esi
     44c:	c7 44 24 08 10 00 00 	movl   $0x10,0x8(%esp,1)
     453:	00 
     454:	8b 5d 0c             	mov    0xc(%ebp),%ebx
     457:	8b 7d 08             	mov    0x8(%ebp),%edi
     45a:	8d 46 15             	lea    0x15(%esi),%eax
     45d:	89 44 24 04          	mov    %eax,0x4(%esp,1)
     461:	8d 83 8c 00 00 00    	lea    0x8c(%ebx),%eax
     467:	89 04 24             	mov    %eax,(%esp,1)
     46a:	e8 d1 29 00 00       	call   2e40 <__constant_memcpy>
     46f:	0f b6 06             	movzbl (%esi),%eax
     472:	31 d2                	xor    %edx,%edx
     474:	89 43 38             	mov    %eax,0x38(%ebx)
	__arch__swab24s(addr);
}

static __inline__ __const__ __u32 __fswab32(__u32 x)
{
     477:	8b 46 01             	mov    0x1(%esi),%eax

static __inline__ __const__ __u32 ___arch__swab32(__u32 x)
{
#ifdef CONFIG_X86_BSWAP
	__asm__("bswap %0" : "=r" (x) : "0" (x));
     47a:	0f c8                	bswap  %eax
	__arch__swab24s(addr);
}

static __inline__ __const__ __u32 __fswab32(__u32 x)
{
     47c:	89 43 34             	mov    %eax,0x34(%ebx)
    memcpy(dcont->mac, scont->mac, HMACLEN);	\
  } while(0)

UNMARSHALL_CONTINUATION(Server, SERVER_COMPUTE_MAC);
UNMARSHALL_CONTINUATION(Client, CLIENT_COMPUTE_MAC);
     47f:	8b 46 09             	mov    0x9(%esi),%eax
     482:	89 43 3c             	mov    %eax,0x3c(%ebx)
     485:	8b 46 0d             	mov    0xd(%esi),%eax
     488:	89 43 40             	mov    %eax,0x40(%ebx)
     48b:	8b 46 25             	mov    0x25(%esi),%eax
     48e:	89 43 44             	mov    %eax,0x44(%ebx)
	__arch__swab24s(addr);
}

static __inline__ __const__ __u32 __fswab32(__u32 x)
{
     491:	8b 46 25             	mov    0x25(%esi),%eax

static __inline__ __const__ __u32 ___arch__swab32(__u32 x)
{
#ifdef CONFIG_X86_BSWAP
	__asm__("bswap %0" : "=r" (x) : "0" (x));
     494:	0f c8                	bswap  %eax
	__arch__swab24s(addr);
}

static __inline__ __const__ __u32 __fswab32(__u32 x)
{
     496:	89 43 4c             	mov    %eax,0x4c(%ebx)
    memcpy(dcont->mac, scont->mac, HMACLEN);	\
  } while(0)

UNMARSHALL_CONTINUATION(Server, SERVER_COMPUTE_MAC);
UNMARSHALL_CONTINUATION(Client, CLIENT_COMPUTE_MAC);
     499:	8b 46 11             	mov    0x11(%esi),%eax
     49c:	89 43 50             	mov    %eax,0x50(%ebx)
     49f:	8b 46 29             	mov    0x29(%esi),%eax
     4a2:	89 43 48             	mov    %eax,0x48(%ebx)
	__arch__swab24s(addr);
}

static __inline__ __const__ __u32 __fswab32(__u32 x)
{
     4a5:	8b 46 29             	mov    0x29(%esi),%eax

static __inline__ __const__ __u32 ___arch__swab32(__u32 x)
{
#ifdef CONFIG_X86_BSWAP
	__asm__("bswap %0" : "=r" (x) : "0" (x));
     4a8:	0f c8                	bswap  %eax
	__arch__swab24s(addr);
}

static __inline__ __const__ __u32 __fswab32(__u32 x)
{
     4aa:	89 43 54             	mov    %eax,0x54(%ebx)
    memcpy(dcont->mac, scont->mac, HMACLEN);	\
  } while(0)

UNMARSHALL_CONTINUATION(Server, SERVER_COMPUTE_MAC);
UNMARSHALL_CONTINUATION(Client, CLIENT_COMPUTE_MAC);
     4ad:	0f b6 46 2d          	movzbl 0x2d(%esi),%eax
     4b1:	89 43 58             	mov    %eax,0x58(%ebx)
     4b4:	0f b6 46 05          	movzbl 0x5(%esi),%eax
     4b8:	89 43 5c             	mov    %eax,0x5c(%ebx)
	__arch__swab24s(addr);
}

static __inline__ __const__ __u32 __fswab32(__u32 x)
{
     4bb:	8b 46 2e             	mov    0x2e(%esi),%eax

static __inline__ __const__ __u32 ___arch__swab32(__u32 x)
{
#ifdef CONFIG_X86_BSWAP
	__asm__("bswap %0" : "=r" (x) : "0" (x));
     4be:	0f c8                	bswap  %eax
	__arch__swab24s(addr);
}

static __inline__ __const__ __u32 __fswab32(__u32 x)
{
     4c0:	89 43 60             	mov    %eax,0x60(%ebx)
     4c3:	8b 46 32             	mov    0x32(%esi),%eax

static __inline__ __const__ __u32 ___arch__swab32(__u32 x)
{
#ifdef CONFIG_X86_BSWAP
	__asm__("bswap %0" : "=r" (x) : "0" (x));
     4c6:	0f c8                	bswap  %eax
	__arch__swab24s(addr);
}

static __inline__ __const__ __u32 __fswab32(__u32 x)
{
     4c8:	89 43 64             	mov    %eax,0x64(%ebx)
     4cb:	8b 46 36             	mov    0x36(%esi),%eax

static __inline__ __const__ __u32 ___arch__swab32(__u32 x)
{
#ifdef CONFIG_X86_BSWAP
	__asm__("bswap %0" : "=r" (x) : "0" (x));
     4ce:	0f c8                	bswap  %eax
	__arch__swab24s(addr);
}

static __inline__ __const__ __u32 __fswab32(__u32 x)
{
     4d0:	89 43 68             	mov    %eax,0x68(%ebx)
     4d3:	8b 46 3a             	mov    0x3a(%esi),%eax

static __inline__ __const__ __u32 ___arch__swab32(__u32 x)
{
#ifdef CONFIG_X86_BSWAP
	__asm__("bswap %0" : "=r" (x) : "0" (x));
     4d6:	0f c8                	bswap  %eax
	__arch__swab24s(addr);
}

static __inline__ __const__ __u32 __fswab32(__u32 x)
{
     4d8:	89 43 6c             	mov    %eax,0x6c(%ebx)
     4db:	8b 46 3e             	mov    0x3e(%esi),%eax

static __inline__ __const__ __u32 ___arch__swab32(__u32 x)
{
#ifdef CONFIG_X86_BSWAP
	__asm__("bswap %0" : "=r" (x) : "0" (x));
     4de:	0f c8                	bswap  %eax
	__arch__swab24s(addr);
}

static __inline__ __const__ __u32 __fswab32(__u32 x)
{
     4e0:	89 43 70             	mov    %eax,0x70(%ebx)
    memcpy(dcont->mac, scont->mac, HMACLEN);	\
  } while(0)

UNMARSHALL_CONTINUATION(Server, SERVER_COMPUTE_MAC);
UNMARSHALL_CONTINUATION(Client, CLIENT_COMPUTE_MAC);
     4e3:	8b 47 0c             	mov    0xc(%edi),%eax
     4e6:	8b 80 a8 02 00 00    	mov    0x2a8(%eax),%eax
     4ec:	a9 01 00 00 00       	test   $0x1,%eax
     4f1:	74 05                	je     4f8 <unmarshallContinuationClient+0xb8>
     4f3:	83 e0 08             	and    $0x8,%eax
     4f6:	74 05                	je     4fd <unmarshallContinuationClient+0xbd>
     4f8:	ba 01 00 00 00       	mov    $0x1,%edx
     4fd:	85 d2                	test   %edx,%edx
     4ff:	75 31                	jne    532 <unmarshallContinuationClient+0xf2>
     501:	31 c0                	xor    %eax,%eax
     503:	31 ff                	xor    %edi,%edi
     505:	89 83 dc 00 00 00    	mov    %eax,0xdc(%ebx)
     50b:	8b 46 42             	mov    0x42(%esi),%eax
     50e:	8b 56 46             	mov    0x46(%esi),%edx
     511:	31 f6                	xor    %esi,%esi
     513:	89 bb c0 00 00 00    	mov    %edi,0xc0(%ebx)
     519:	89 b3 c4 00 00 00    	mov    %esi,0xc4(%ebx)
     51f:	89 43 74             	mov    %eax,0x74(%ebx)
     522:	b8 01 00 00 00       	mov    $0x1,%eax
     527:	89 53 78             	mov    %edx,0x78(%ebx)
     52a:	83 c4 0c             	add    $0xc,%esp
     52d:	5b                   	pop    %ebx
     52e:	5e                   	pop    %esi
     52f:	5f                   	pop    %edi
     530:	5d                   	pop    %ebp
     531:	c3                   	ret    
     532:	8b 47 24             	mov    0x24(%edi),%eax
     535:	8b 40 10             	mov    0x10(%eax),%eax
     538:	89 43 14             	mov    %eax,0x14(%ebx)
     53b:	8b 47 24             	mov    0x24(%edi),%eax
     53e:	8b 40 0c             	mov    0xc(%eax),%eax
     541:	89 43 18             	mov    %eax,0x18(%ebx)
     544:	8b 47 20             	mov    0x20(%edi),%eax
     547:	0f b7 40 02          	movzwl 0x2(%eax),%eax
     54b:	66 89 43 1c          	mov    %ax,0x1c(%ebx)
     54f:	8b 47 20             	mov    0x20(%edi),%eax
     552:	0f b7 00             	movzwl (%eax),%eax
     555:	66 89 43 1e          	mov    %ax,0x1e(%ebx)
     559:	eb a6                	jmp    501 <unmarshallContinuationClient+0xc1>
     55b:	90                   	nop    
     55c:	8d 74 26 00          	lea    0x0(%esi,1),%esi

00000560 <mborg_isqrt4>:
#define QUAD(SIGN,a,b,c) (-(b) SIGN sqrtf((b) * (b) - 4*(a)*(c))) / (2 * a)
#define COMPUTE_CWND(SSTHRESH, TCPBASE, SEQ) \
   QUAD(+, 1.0/2.0, 1.0/2.0, -((int)(SSTHRESH) * ((int)(SSTHRESH) + 1)) / 2.0 - (SEQ) + (TCPBASE));
#else
static unsigned int mborg_isqrt4(unsigned long val) {
     560:	55                   	push   %ebp
     561:	89 e5                	mov    %esp,%ebp
     563:	53                   	push   %ebx
     564:	8b 4d 08             	mov    0x8(%ebp),%ecx
  unsigned int temp, g=0;
     567:	31 db                	xor    %ebx,%ebx

  if (val >= 0x40000000) {
     569:	81 f9 ff ff ff 3f    	cmp    $0x3fffffff,%ecx
     56f:	76 0b                	jbe    57c <mborg_isqrt4+0x1c>
    g = 0x8000; 
     571:	bb 00 80 00 00       	mov    $0x8000,%ebx
    val -= 0x40000000;
     576:	81 e9 00 00 00 40    	sub    $0x40000000,%ecx
  }

#define INNER_MBGSQRT(s)                      \
  temp = (g << (s)) + (1 << ((s) * 2 - 2));   \
  if (val >= temp) {                          \
    g += 1 << ((s)-1);                        \
    val -= temp;                              \
  }

  INNER_MBGSQRT (15)
     57c:	89 d8                	mov    %ebx,%eax
     57e:	c1 e0 0f             	shl    $0xf,%eax
     581:	8d 90 00 00 00 10    	lea    0x10000000(%eax),%edx
     587:	39 d1                	cmp    %edx,%ecx
     589:	72 08                	jb     593 <mborg_isqrt4+0x33>
     58b:	81 c3 00 40 00 00    	add    $0x4000,%ebx
     591:	29 d1                	sub    %edx,%ecx
  INNER_MBGSQRT (14)
     593:	89 d8                	mov    %ebx,%eax
     595:	c1 e0 0e             	shl    $0xe,%eax
     598:	8d 90 00 00 00 04    	lea    0x4000000(%eax),%edx
     59e:	39 d1                	cmp    %edx,%ecx
     5a0:	72 08                	jb     5aa <mborg_isqrt4+0x4a>
     5a2:	81 c3 00 20 00 00    	add    $0x2000,%ebx
     5a8:	29 d1                	sub    %edx,%ecx
  INNER_MBGSQRT (13)
     5aa:	89 d8                	mov    %ebx,%eax
     5ac:	c1 e0 0d             	shl    $0xd,%eax
     5af:	8d 90 00 00 00 01    	lea    0x1000000(%eax),%edx
     5b5:	39 d1                	cmp    %edx,%ecx
     5b7:	72 08                	jb     5c1 <mborg_isqrt4+0x61>
     5b9:	81 c3 00 10 00 00    	add    $0x1000,%ebx
     5bf:	29 d1                	sub    %edx,%ecx
  INNER_MBGSQRT (12)
     5c1:	89 d8                	mov    %ebx,%eax
     5c3:	c1 e0 0c             	shl    $0xc,%eax
     5c6:	8d 90 00 00 40 00    	lea    0x400000(%eax),%edx
     5cc:	39 d1                	cmp    %edx,%ecx
     5ce:	72 08                	jb     5d8 <mborg_isqrt4+0x78>
     5d0:	81 c3 00 08 00 00    	add    $0x800,%ebx
     5d6:	29 d1                	sub    %edx,%ecx
  INNER_MBGSQRT (11)
     5d8:	89 d8                	mov    %ebx,%eax
     5da:	c1 e0 0b             	shl    $0xb,%eax
     5dd:	8d 90 00 00 10 00    	lea    0x100000(%eax),%edx
     5e3:	39 d1                	cmp    %edx,%ecx
     5e5:	72 08                	jb     5ef <mborg_isqrt4+0x8f>
     5e7:	81 c3 00 04 00 00    	add    $0x400,%ebx
     5ed:	29 d1                	sub    %edx,%ecx
  INNER_MBGSQRT (10)
     5ef:	89 d8                	mov    %ebx,%eax
     5f1:	c1 e0 0a             	shl    $0xa,%eax
     5f4:	8d 90 00 00 04 00    	lea    0x40000(%eax),%edx
     5fa:	39 d1                	cmp    %edx,%ecx
     5fc:	72 08                	jb     606 <mborg_isqrt4+0xa6>
     5fe:	81 c3 00 02 00 00    	add    $0x200,%ebx
     604:	29 d1                	sub    %edx,%ecx
  INNER_MBGSQRT ( 9)
     606:	89 d8                	mov    %ebx,%eax
     608:	c1 e0 09             	shl    $0x9,%eax
     60b:	8d 90 00 00 01 00    	lea    0x10000(%eax),%edx
     611:	39 d1                	cmp    %edx,%ecx
     613:	72 08                	jb     61d <mborg_isqrt4+0xbd>
     615:	81 c3 00 01 00 00    	add    $0x100,%ebx
     61b:	29 d1                	sub    %edx,%ecx
  INNER_MBGSQRT ( 8)
     61d:	89 d8                	mov    %ebx,%eax
     61f:	c1 e0 08             	shl    $0x8,%eax
     622:	8d 90 00 40 00 00    	lea    0x4000(%eax),%edx
     628:	39 d1                	cmp    %edx,%ecx
     62a:	72 05                	jb     631 <mborg_isqrt4+0xd1>
     62c:	83 eb 80             	sub    $0xffffff80,%ebx
     62f:	29 d1                	sub    %edx,%ecx
  INNER_MBGSQRT ( 7)
     631:	89 d8                	mov    %ebx,%eax
     633:	c1 e0 07             	shl    $0x7,%eax
     636:	8d 90 00 10 00 00    	lea    0x1000(%eax),%edx
     63c:	39 d1                	cmp    %edx,%ecx
     63e:	72 05                	jb     645 <mborg_isqrt4+0xe5>
     640:	83 c3 40             	add    $0x40,%ebx
     643:	29 d1                	sub    %edx,%ecx
  INNER_MBGSQRT ( 6)
     645:	89 d8                	mov    %ebx,%eax
     647:	c1 e0 06             	shl    $0x6,%eax
     64a:	8d 90 00 04 00 00    	lea    0x400(%eax),%edx
     650:	39 d1                	cmp    %edx,%ecx
     652:	72 05                	jb     659 <mborg_isqrt4+0xf9>
     654:	83 c3 20             	add    $0x20,%ebx
     657:	29 d1                	sub    %edx,%ecx
  INNER_MBGSQRT ( 5)
     659:	89 d8                	mov    %ebx,%eax
     65b:	c1 e0 05             	shl    $0x5,%eax
     65e:	8d 90 00 01 00 00    	lea    0x100(%eax),%edx
     664:	39 d1                	cmp    %edx,%ecx
     666:	72 05                	jb     66d <mborg_isqrt4+0x10d>
     668:	83 c3 10             	add    $0x10,%ebx
     66b:	29 d1                	sub    %edx,%ecx
  INNER_MBGSQRT ( 4)
     66d:	89 d8                	mov    %ebx,%eax
     66f:	c1 e0 04             	shl    $0x4,%eax
     672:	8d 50 40             	lea    0x40(%eax),%edx
     675:	39 d1                	cmp    %edx,%ecx
     677:	72 05                	jb     67e <mborg_isqrt4+0x11e>
     679:	83 c3 08             	add    $0x8,%ebx
     67c:	29 d1                	sub    %edx,%ecx
  INNER_MBGSQRT ( 3)
     67e:	8d 14 dd 10 00 00 00 	lea    0x10(,%ebx,8),%edx
     685:	39 d1                	cmp    %edx,%ecx
     687:	72 05                	jb     68e <mborg_isqrt4+0x12e>
     689:	83 c3 04             	add    $0x4,%ebx
     68c:	29 d1                	sub    %edx,%ecx
  INNER_MBGSQRT ( 2)
     68e:	8d 14 9d 04 00 00 00 	lea    0x4(,%ebx,4),%edx
     695:	39 d1                	cmp    %edx,%ecx
     697:	72 05                	jb     69e <mborg_isqrt4+0x13e>
     699:	83 c3 02             	add    $0x2,%ebx
     69c:	29 d1                	sub    %edx,%ecx

#undef INNER_MBGSQRT

  temp = g+g+1;
     69e:	8d 54 1b 01          	lea    0x1(%ebx,%ebx,1),%edx
  if (val >= temp) g++;
     6a2:	8d 43 01             	lea    0x1(%ebx),%eax
     6a5:	39 d1                	cmp    %edx,%ecx
     6a7:	0f 43 d8             	cmovae %eax,%ebx
  return g;
}
     6aa:	89 d8                	mov    %ebx,%eax
     6ac:	5b                   	pop    %ebx
     6ad:	5d                   	pop    %ebp
     6ae:	c3                   	ret    
     6af:	90                   	nop    

000006b0 <AckTCPCwnd>:

#define QUAD(SIGN,a,b,c) (-(b) SIGN mborg_isqrt4((b) * (b) - 4*(a)*(c))) / (2 * a)

// TODO: Improve precision?
/*
 * Fixed point computation with a fast square root is a bit tricky. 
 * We perform the square root at .(2*PREC) precision, after which the datatype becomes
 * .(PREC) (since the scaling factor is taken to ^-0.5)

     In floating point, the expression is 
      - (1/2) + sqrt((1/2)^2 - 4*1/2*(-(ssthresh*(ssthresh+1)/2 - *(seq - TCPBase))))
*/

#define PREC (1)
#define COMPUTE_CWND(SSTHRESH, TCPBASE, SEQ) \
	(((-1 << (PREC - 1)) + mborg_isqrt4((1 << (2*PREC - 2)) - ((-((int)(ssthresh) * ((int)(ssthresh) + 1)) - 2 * (((int)seq) - (TCPBase))) << (2*PREC)))) >> PREC)
#endif // USE_FLOATINGPOINT

#define MAX_CWND ((1<<13)-1)
#define CLAMP(X) (MIN((X),MAX_CWND))

// TODO: Investigate using -msoftfloat, or saving/restoring FPU state
// while processing interrupts

int AckTCPCwnd(unsigned seq, const CONTINUATION_TYPE *cont, int *hintResult) {
     6b0:	55                   	push   %ebp
     6b1:	89 e5                	mov    %esp,%ebp
     6b3:	57                   	push   %edi
  int res, hint = -1;
  // hint is processed as a relative offset in the body, then converted to an absolute offset just before returning
  unsigned startCwnd = cont->startCwnd;
  unsigned ssthresh = MIN(MAX(cont->ssthresh, startCwnd), MAX_CWND);
     6b4:	bf ff 1f 00 00       	mov    $0x1fff,%edi
     6b9:	56                   	push   %esi
     6ba:	53                   	push   %ebx
     6bb:	83 ec 18             	sub    $0x18,%esp
     6be:	c7 45 f0 ff ff ff ff 	movl   $0xffffffff,0xfffffff0(%ebp)
     6c5:	8b 55 0c             	mov    0xc(%ebp),%edx
     6c8:	8b 45 08             	mov    0x8(%ebp),%eax
     6cb:	8b 5a 68             	mov    0x68(%edx),%ebx
     6ce:	89 d1                	mov    %edx,%ecx
     6d0:	8b 52 6c             	mov    0x6c(%edx),%edx
  unsigned TCPBase = cont->TCPBase;
     6d3:	8b 49 70             	mov    0x70(%ecx),%ecx
     6d6:	39 d3                	cmp    %edx,%ebx
     6d8:	0f 43 d3             	cmovae %ebx,%edx
     6db:	81 fa 00 20 00 00    	cmp    $0x2000,%edx
     6e1:	0f 42 fa             	cmovb  %edx,%edi
  unsigned additiveStart = (ssthresh - startCwnd + TCPBase) + ssthresh;

#ifdef ACKTCP_CWND_SPEED_HACK
  seq = TCPBase + (seq - TCPBase) * ACKTCP_CWND_SPEED_HACK;
     6e4:	29 c8                	sub    %ecx,%eax
     6e6:	89 fa                	mov    %edi,%edx
     6e8:	29 da                	sub    %ebx,%edx
     6ea:	01 ca                	add    %ecx,%edx
     6ec:	8d 34 17             	lea    (%edi,%edx,1),%esi
     6ef:	89 75 ec             	mov    %esi,0xffffffec(%ebp)
     6f2:	d1 e8                	shr    %eax
     6f4:	8d 34 08             	lea    (%eax,%ecx,1),%esi
#endif

  if(seq < TCPBase) {
     6f7:	39 ce                	cmp    %ecx,%esi
     6f9:	73 65                	jae    760 <AckTCPCwnd+0xb0>
    if(!disableSevereErrors) 
     6fb:	8b 1d 00 00 00 00    	mov    0x0,%ebx
     701:	85 db                	test   %ebx,%ebx
     703:	74 3f                	je     744 <AckTCPCwnd+0x94>
      ERROR("Seq (%u) < TCPBase (%u)\n", seq, TCPBase);
    res = -1;
     705:	ba ff ff ff ff       	mov    $0xffffffff,%edx
    goto done;
  }

#if 0
  // obsolete test
  if(seq - TCPBase > MAX_CWND * MAX_CWND) {
	  printk("Exceeded max limit without renormalizing\n");
	  res = -1;
	  goto done;
  }
#endif
  if(seq < ssthresh - startCwnd + TCPBase) {
    res = startCwnd + (seq - TCPBase);
  } else if(ssthresh - startCwnd + TCPBase <= seq &&
	    seq < additiveStart) {
    res = ssthresh;
  } else {
	  /* result is solution to x(x+1)-ssthresh(ssthresh+1)
                                   --------------------------- - N
                                                2                  */
	  //int offset = seq - TCPBase;
	  int offset = seq - additiveStart;
#ifdef USE_SQRT
	  int position, cwnd;
	  //double a = 1.0/2.0, b = 1.0/2.0, c = -((int)ssthresh * ((int)ssthresh + 1)) / 2.0 - seq + TCPBase;
	  cwnd = COMPUTE_CWND(ssthresh, TCPBase, seq);
	  
	  //val = 1/4 - (-((int)(ssthresh) * ((int)(ssthresh) + 1)) - 2 * (((int)seq) - (TCPBase)))
	  //printk("sqrt(%d) = %d\n", val, mborg_isqrt4(val));

	  cwnd = CLAMP(cwnd);
	  position = (cwnd*(cwnd+1)-ssthresh*(ssthresh+1)) / 2;
	  if(cwnd == MAX_CWND) {
		  res = cwnd;
		  hint = - 1;
	  } else {
		  if(offset >= position) {
			  int cwnd_1 = CLAMP(cwnd + 1),
				  cwnd_2 = CLAMP(cwnd + 2);
			  if(offset < position + cwnd_1) {
				  res = cwnd_1;
				  hint = additiveStart + position + cwnd_1;
			  } else {
				  if(!(offset < position + cwnd_1 + cwnd_2)) {
#ifndef DISABLE_ACKTCPCWND_WARNINGS
					  BUG_TRAP(0);
#endif
				  }
				  res = cwnd_2;
				  hint = additiveStart + position + cwnd_1 + cwnd_2;
			  }
		  } else if(offset < position) {
			  if(offset > position - cwnd) {
				  res = cwnd;
				  hint = additiveStart + position;
			  } else {
				  if(!(offset > position - cwnd - (cwnd - 1))) {
#ifndef DISABLE_ACKTCPCWND_WARNINGS
					  BUG_TRAP(0);
#endif
				  }
				  if((cwnd - 1) < ssthresh) {
#ifndef DISABLE_ACKTCPCWND_WARNINGS

					  BUG_TRAP(0);
#endif
				  }
#ifndef DISABLE_ACKTCPCWND_WARNINGS
				  BUG_TRAP(cwnd - 1 >= 1);
#endif
				  res = cwnd - 1;
				  hint = additiveStart + position - cwnd;
			  }		  
		  }
	  }
#else
	  // Fixed point Newton's method to solve (cwnd*(cwnd+1) - ssthresh*(ssthresh+)) / 2 = 
#define FRAC (2)
	  int i;
	  static int numIterations, count = 0;
	  //long long x;
	  typedef int FIXEDPT_TYPE;
	  FIXEDPT_TYPE x, oldX[32];;
	  // Special case: offset > max clamp
	  if(offset >= (MAX_CWND * (MAX_CWND + 1) - ssthresh*(ssthresh+1)) / 2) {
		  res = MAX_CWND;
		  goto done;
	  }

	  /* Newton iteration:
	     x_{k+1} = x_k - f(x_k)/f'(x_k) */
	  // set initial guess to maximum possible value to avoid converging to wrong root	  
	  x = (MAX_CWND) << FRAC;
#define MAX_NEWTON_ITERATIONS (sizeof(FIXEDPT_TYPE) * 8)
	  for(i=0; i < MAX_NEWTON_ITERATIONS; i++) {
		  FIXEDPT_TYPE cwnd, xupdate;
		  unsigned position;
		  cwnd = x >> FRAC;

#if 0
		  printk("offset = %d ssthresh = %d x_%d: %d ", offset, ssthresh, i, x >> FRAC);
		  printk("f(x_%d) * 2 = %d (%d %d %d) ", i, (x * (x + (1 << FRAC)) - (((int)ssthresh * ((int)ssthresh + 1) + 2 * offset) << (2 * FRAC))) >> (2 * FRAC), x * (x + (1 << FRAC)), (((int)ssthresh * ((int)ssthresh + 1) + 2 * offset)) << (2 * FRAC), (x * (x + (1 << FRAC)) - (((int)ssthresh * ((int)ssthresh + 1) + 2 * offset) << (2 * FRAC))));
		  printk("f'(x_%d) * 2 = %d ", i, (2 * x + (1 << FRAC)) >> FRAC);
		  printk("f/f' = %d ", ((x * (x + (1 << FRAC)) - (((int)ssthresh * ((int)ssthresh + 1) + 2 * offset) << (2 * FRAC))) /
					 (2 * x + (1 << FRAC))));
		  printk("\n");
#endif
		  position = (cwnd*(cwnd+1)-ssthresh*(ssthresh+1)) / 2;
		  if(offset - position >= 0 && 
		     offset - position < cwnd + 1) {
			  res = CLAMP(cwnd + 1);
			  hint = additiveStart + position + res;

			  if(i > numIterations || count == 100000) {
			    numIterations = i;
			    printk("%d iterations - result = %d\n", i, cwnd);
			    if(count == 100000) count = 0;
			  }
			  count++;
			  goto done;
		  } else if(position - offset > 0 &&
			    position - offset < cwnd) {
			  res = CLAMP(cwnd);
			  hint = additiveStart + position;

			  if(i > numIterations || count == 100000) {
			    numIterations = i;
			    printk("%d iterations - result = %d\n", i, cwnd);
			    if(count == 100000) count = 0;
			  }
			  count++;
			  goto done;
		  }
		  xupdate = (x - 
		       ((x * (x + (1 << FRAC)) - (((int)ssthresh * ((int)ssthresh + 1) + 2 * offset) << (2 * FRAC))) /
			(2 * x + (1 << FRAC))));
		  oldX[i] = x;
		  if(xupdate == x) {
			  int sign0 = ((int)ssthresh * ((int)ssthresh + 1) + 2 * offset) > 0 ? 1 : -1,
				  sign1 = (2 * x + (1 << FRAC)) > 0 ? 1 : -1;
			  x -= (sign0 * sign1) << FRAC;
		  } else {
			  x = xupdate;
		  }
	  }
	  printk("AckTCPCwnd SQRT: Too many iterations: x = %d f(x) = %d f'(x) = %d offset = %d ssthresh * (ssthresh+1) = %d, %d \n", 
		 x >> FRAC, 
		 (x * (x + (1 << FRAC)) - (((int)ssthresh * ((int)ssthresh + 1) + 2 * offset) << (2 * FRAC))) >> (2 * FRAC), 
		 ((2 * x) >> FRAC) + 1,
		 offset, 
		 ssthresh*(ssthresh+1), 
		 (((int)ssthresh * ((int)ssthresh + 1) + 2 * offset))/2);
	  for(i = 0; i < MAX_NEWTON_ITERATIONS; i++) {
		  printk("X_%d = %d\n", i, oldX[i]);
	  }
	  res = (-(1 << (FRAC-1)) + x) >> FRAC;

#endif
#undef FRAC
  }
  done:
	  ;
  if(res > MAX_CWND)
     70a:	81 fa 00 20 00 00    	cmp    $0x2000,%edx
     710:	b8 ff 1f 00 00       	mov    $0x1fff,%eax
     715:	0f 4d d0             	cmovge %eax,%edx
	  res = MAX_CWND;
  if(hintResult != NULL)
     718:	8b 45 10             	mov    0x10(%ebp),%eax
     71b:	85 c0                	test   %eax,%eax
     71d:	74 12                	je     731 <AckTCPCwnd+0x81>
    *hintResult = (hint >= 0) ? hint : -1;
     71f:	83 7d f0 fe          	cmpl   $0xfffffffe,0xfffffff0(%ebp)
     723:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
     728:	8b 4d 10             	mov    0x10(%ebp),%ecx
     72b:	0f 4f 45 f0          	cmovg  0xfffffff0(%ebp),%eax
     72f:	89 01                	mov    %eax,(%ecx)
  ((CONTINUATION_TYPE*)cont)->mark = res; // tricklesLossEvent gets cwnd size from here
     731:	8b 75 0c             	mov    0xc(%ebp),%esi
  return res;
}
     734:	89 d0                	mov    %edx,%eax
     736:	89 96 d8 00 00 00    	mov    %edx,0xd8(%esi)
     73c:	83 c4 18             	add    $0x18,%esp
     73f:	5b                   	pop    %ebx
     740:	5e                   	pop    %esi
     741:	5f                   	pop    %edi
     742:	5d                   	pop    %ebp
     743:	c3                   	ret    
     744:	89 4c 24 08          	mov    %ecx,0x8(%esp,1)
     748:	89 74 24 04          	mov    %esi,0x4(%esp,1)
     74c:	c7 04 24 2c 00 00 00 	movl   $0x2c,(%esp,1)
     753:	e8 fc ff ff ff       	call   754 <AckTCPCwnd+0xa4>
     758:	eb ab                	jmp    705 <AckTCPCwnd+0x55>
     75a:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi
     760:	39 d6                	cmp    %edx,%esi
     762:	73 0c                	jae    770 <AckTCPCwnd+0xc0>
     764:	29 ce                	sub    %ecx,%esi
     766:	8d 14 1e             	lea    (%esi,%ebx,1),%edx
     769:	eb 9f                	jmp    70a <AckTCPCwnd+0x5a>
     76b:	90                   	nop    
     76c:	8d 74 26 00          	lea    0x0(%esi,1),%esi
     770:	39 f2                	cmp    %esi,%edx
     772:	77 07                	ja     77b <AckTCPCwnd+0xcb>
     774:	3b 75 ec             	cmp    0xffffffec(%ebp),%esi
     777:	89 fa                	mov    %edi,%edx
     779:	72 8f                	jb     70a <AckTCPCwnd+0x5a>
     77b:	8b 55 ec             	mov    0xffffffec(%ebp),%edx
     77e:	89 f0                	mov    %esi,%eax
     780:	89 fb                	mov    %edi,%ebx
     782:	29 ce                	sub    %ecx,%esi
     784:	29 d0                	sub    %edx,%eax
     786:	89 45 e8             	mov    %eax,0xffffffe8(%ebp)
     789:	8d 47 01             	lea    0x1(%edi),%eax
     78c:	0f af d8             	imul   %eax,%ebx
     78f:	8d 04 36             	lea    (%esi,%esi,1),%eax
     792:	89 da                	mov    %ebx,%edx
     794:	f7 da                	neg    %edx
     796:	29 c2                	sub    %eax,%edx
     798:	b8 01 00 00 00       	mov    $0x1,%eax
     79d:	c1 e2 02             	shl    $0x2,%edx
     7a0:	29 d0                	sub    %edx,%eax
     7a2:	89 04 24             	mov    %eax,(%esp,1)
     7a5:	e8 b6 fd ff ff       	call   560 <mborg_isqrt4>
     7aa:	b9 ff 1f 00 00       	mov    $0x1fff,%ecx
     7af:	48                   	dec    %eax
     7b0:	d1 e8                	shr    %eax
     7b2:	39 c1                	cmp    %eax,%ecx
     7b4:	0f 4f c8             	cmovg  %eax,%ecx
     7b7:	8d 41 01             	lea    0x1(%ecx),%eax
     7ba:	89 ce                	mov    %ecx,%esi
     7bc:	0f af f0             	imul   %eax,%esi
     7bf:	29 de                	sub    %ebx,%esi
     7c1:	d1 ee                	shr    %esi
     7c3:	81 f9 ff 1f 00 00    	cmp    $0x1fff,%ecx
     7c9:	74 62                	je     82d <AckTCPCwnd+0x17d>
     7cb:	39 75 e8             	cmp    %esi,0xffffffe8(%ebp)
     7ce:	7c 39                	jl     809 <AckTCPCwnd+0x159>
     7d0:	bb ff 1f 00 00       	mov    $0x1fff,%ebx
     7d5:	39 c3                	cmp    %eax,%ebx
     7d7:	ba ff 1f 00 00       	mov    $0x1fff,%edx
     7dc:	0f 4f d8             	cmovg  %eax,%ebx
     7df:	8d 41 02             	lea    0x2(%ecx),%eax
     7e2:	39 c2                	cmp    %eax,%edx
     7e4:	0f 4f d0             	cmovg  %eax,%edx
     7e7:	8d 04 33             	lea    (%ebx,%esi,1),%eax
     7ea:	39 45 e8             	cmp    %eax,0xffffffe8(%ebp)
     7ed:	7d 11                	jge    800 <AckTCPCwnd+0x150>
     7ef:	8b 45 ec             	mov    0xffffffec(%ebp),%eax
     7f2:	89 da                	mov    %ebx,%edx
     7f4:	01 f0                	add    %esi,%eax
     7f6:	01 d0                	add    %edx,%eax
     7f8:	89 45 f0             	mov    %eax,0xfffffff0(%ebp)
     7fb:	e9 0a ff ff ff       	jmp    70a <AckTCPCwnd+0x5a>
     800:	8b 45 ec             	mov    0xffffffec(%ebp),%eax
     803:	01 f0                	add    %esi,%eax
     805:	01 d8                	add    %ebx,%eax
     807:	eb ed                	jmp    7f6 <AckTCPCwnd+0x146>
     809:	89 f0                	mov    %esi,%eax
     80b:	29 c8                	sub    %ecx,%eax
     80d:	39 45 e8             	cmp    %eax,0xffffffe8(%ebp)
     810:	7e 0f                	jle    821 <AckTCPCwnd+0x171>
     812:	8b 45 ec             	mov    0xffffffec(%ebp),%eax
     815:	89 ca                	mov    %ecx,%edx
     817:	01 c6                	add    %eax,%esi
     819:	89 75 f0             	mov    %esi,0xfffffff0(%ebp)
     81c:	e9 e9 fe ff ff       	jmp    70a <AckTCPCwnd+0x5a>
     821:	8b 45 ec             	mov    0xffffffec(%ebp),%eax
     824:	8d 51 ff             	lea    0xffffffff(%ecx),%edx
     827:	01 c6                	add    %eax,%esi
     829:	29 ce                	sub    %ecx,%esi
     82b:	eb ec                	jmp    819 <AckTCPCwnd+0x169>
     82d:	c7 45 f0 ff ff ff ff 	movl   $0xffffffff,0xfffffff0(%ebp)
     834:	ba ff 1f 00 00       	mov    $0x1fff,%edx
     839:	e9 cc fe ff ff       	jmp    70a <AckTCPCwnd+0x5a>
     83e:	89 f6                	mov    %esi,%esi

00000840 <Sack_validate>:

inline int AckTCPCwndScalar(unsigned seq, const CONTINUATION_TYPE *cont) {
	return AckTCPCwnd(seq, cont, NULL);
}

int Sack_validate(CONTINUATION_TYPE *cont, Sack *sack) {
     840:	55                   	push   %ebp
     841:	89 e5                	mov    %esp,%ebp
     843:	83 ec 1c             	sub    $0x1c,%esp
     846:	89 5d f8             	mov    %ebx,0xfffffff8(%ebp)
     849:	8b 5d 0c             	mov    0xc(%ebp),%ebx
     84c:	89 75 fc             	mov    %esi,0xfffffffc(%ebp)
  if(sack->left > sack->right) {
     84f:	8b 43 04             	mov    0x4(%ebx),%eax
     852:	39 03                	cmp    %eax,(%ebx)
     854:	76 0c                	jbe    862 <Sack_validate+0x22>
    return 0;
  }
  /* Verify that cumulative nonce matches sack range */
  if(!DISABLE_NONCE_CHECK) {
    __u32 genNonce = generateRangeNonce(cont->sk, sack->left, sack->right);
    if(genNonce != sack->nonceSummary) {
#ifdef DISABLE_NONCE_FAIL // 0715 - this was old code used force side effect from generateRangeNonce() without actually performing nonce check
      static volatile int w;
      w++;
#else
      if(trickles_ratelimit()) {
	printk("nonce check failed for [%d-%d] = 0x%0X != 0x%0X\n", 
	       sack->left, sack->right, genNonce, sack->nonceSummary);
      }
      return 0;
     856:	31 c0                	xor    %eax,%eax
#endif
    }
  }
#if 0
  if(trickles_ratelimit()) {
	  printk("nonce check succeeded\n");
  }
#endif
  return 1;
}
     858:	8b 5d f8             	mov    0xfffffff8(%ebp),%ebx
     85b:	8b 75 fc             	mov    0xfffffffc(%ebp),%esi
     85e:	89 ec                	mov    %ebp,%esp
     860:	5d                   	pop    %ebp
     861:	c3                   	ret    
     862:	8b 43 04             	mov    0x4(%ebx),%eax
     865:	c7 44 24 10 00 00 00 	movl   $0x0,0x10(%esp,1)
     86c:	00 
     86d:	89 44 24 0c          	mov    %eax,0xc(%esp,1)
     871:	8b 03                	mov    (%ebx),%eax
     873:	c7 44 24 08 00 00 00 	movl   $0x0,0x8(%esp,1)
     87a:	00 
     87b:	89 44 24 04          	mov    %eax,0x4(%esp,1)
     87f:	8b 45 08             	mov    0x8(%ebp),%eax
     882:	8b 40 20             	mov    0x20(%eax),%eax
     885:	89 04 24             	mov    %eax,(%esp,1)
     888:	e8 fc ff ff ff       	call   889 <Sack_validate+0x49>
     88d:	3b 43 08             	cmp    0x8(%ebx),%eax
     890:	89 c6                	mov    %eax,%esi
     892:	0f 84 c5 00 00 00    	je     95d <Sack_validate+0x11d>
     898:	a1 00 00 00 00       	mov    0x0,%eax
     89d:	9c                   	pushf  
     89e:	59                   	pop    %ecx
     89f:	fa                   	cli    
     8a0:	89 c2                	mov    %eax,%edx
     8a2:	2b 15 30 e2 04 00    	sub    0x4e230,%edx
     8a8:	a3 30 e2 04 00       	mov    %eax,0x4e230
     8ad:	03 15 2c 00 00 00    	add    0x2c,%edx
     8b3:	81 fa 88 13 00 00    	cmp    $0x1388,%edx
     8b9:	89 15 2c 00 00 00    	mov    %edx,0x2c
     8bf:	76 0f                	jbe    8d0 <Sack_validate+0x90>
     8c1:	b8 88 13 00 00       	mov    $0x1388,%eax
     8c6:	ba 88 13 00 00       	mov    $0x1388,%edx
     8cb:	a3 2c 00 00 00       	mov    %eax,0x2c
     8d0:	81 fa f3 01 00 00    	cmp    $0x1f3,%edx
     8d6:	76 79                	jbe    951 <Sack_validate+0x111>
     8d8:	81 ea f4 01 00 00    	sub    $0x1f4,%edx
     8de:	a1 34 e2 04 00       	mov    0x4e234,%eax
     8e3:	89 15 2c 00 00 00    	mov    %edx,0x2c
     8e9:	c7 05 34 e2 04 00 00 	movl   $0x0,0x4e234
     8f0:	00 00 00 
     8f3:	51                   	push   %ecx
     8f4:	9d                   	popf   
     8f5:	85 c0                	test   %eax,%eax
     8f7:	75 36                	jne    92f <Sack_validate+0xef>
     8f9:	b8 01 00 00 00       	mov    $0x1,%eax
     8fe:	85 c0                	test   %eax,%eax
     900:	0f 84 50 ff ff ff    	je     856 <Sack_validate+0x16>
     906:	8b 43 08             	mov    0x8(%ebx),%eax
     909:	89 74 24 0c          	mov    %esi,0xc(%esp,1)
     90d:	89 44 24 10          	mov    %eax,0x10(%esp,1)
     911:	8b 43 04             	mov    0x4(%ebx),%eax
     914:	89 44 24 08          	mov    %eax,0x8(%esp,1)
     918:	8b 03                	mov    (%ebx),%eax
     91a:	c7 04 24 40 00 00 00 	movl   $0x40,(%esp,1)
     921:	89 44 24 04          	mov    %eax,0x4(%esp,1)
     925:	e8 fc ff ff ff       	call   926 <Sack_validate+0xe6>
     92a:	e9 27 ff ff ff       	jmp    856 <Sack_validate+0x16>
     92f:	89 44 24 0c          	mov    %eax,0xc(%esp,1)
     933:	c7 44 24 08 26 01 00 	movl   $0x126,0x8(%esp,1)
     93a:	00 
     93b:	c7 44 24 04 45 00 00 	movl   $0x45,0x4(%esp,1)
     942:	00 
     943:	c7 04 24 80 00 00 00 	movl   $0x80,(%esp,1)
     94a:	e8 fc ff ff ff       	call   94b <Sack_validate+0x10b>
     94f:	eb a8                	jmp    8f9 <Sack_validate+0xb9>
     951:	ff 05 34 e2 04 00    	incl   0x4e234
     957:	51                   	push   %ecx
     958:	9d                   	popf   
     959:	31 c0                	xor    %eax,%eax
     95b:	eb a1                	jmp    8fe <Sack_validate+0xbe>
     95d:	b8 01 00 00 00       	mov    $0x1,%eax
     962:	e9 f1 fe ff ff       	jmp    858 <Sack_validate+0x18>
     967:	89 f6                	mov    %esi,%esi
     969:	8d bc 27 00 00 00 00 	lea    0x0(%edi,1),%edi

00000970 <AckProof_isPoisoned>:

inline int Sack_contains(Sack *sack, int seq) {
  return sack->left <= seq && seq <= sack->right;
}

inline int Sack_gapLen(Sack *left, Sack *right) {
  return right->left - left->right - 1;
}

inline int Sack_adjacent(Sack *left, Sack *right) {
  return Sack_gapLen(left, right) == 0;
}

int AckProof_isPoisoned(AckProof *proof, Sack *sack) {
     970:	55                   	push   %ebp
     971:	89 e5                	mov    %esp,%ebp
  /* For now, always return 0 */
  return 0;
}
     973:	31 c0                	xor    %eax,%eax
     975:	5d                   	pop    %ebp
     976:	c3                   	ret    
     977:	89 f6                	mov    %esi,%esi
     979:	8d bc 27 00 00 00 00 	lea    0x0(%edi,1),%edi

00000980 <AckProof_validate>:

int AckProof_validate(AckProof *proof) {
     980:	55                   	push   %ebp
     981:	89 e5                	mov    %esp,%ebp
     983:	83 ec 24             	sub    $0x24,%esp
     986:	89 5d f4             	mov    %ebx,0xfffffff4(%ebp)
     989:	8b 55 08             	mov    0x8(%ebp),%edx
     98c:	89 75 f8             	mov    %esi,0xfffffff8(%ebp)
     98f:	89 7d fc             	mov    %edi,0xfffffffc(%ebp)
  int i;
  CONTINUATION_TYPE *cont = proof->cont;
  Sack *sacks = proof->sacks;
  int numSacks = proof->numSacks;
     992:	8b 32                	mov    (%edx),%esi
     994:	8d 4a 08             	lea    0x8(%edx),%ecx
     997:	8b 7a 04             	mov    0x4(%edx),%edi
  // 0714 MAXSACKS is appropriate here (e.g., NOT MAX_KERNEL_SACKS) because 
  // this numSacks comes from the wire
  if(numSacks == 0 || numSacks > MAXSACKS || 
     99a:	85 f6                	test   %esi,%esi
     99c:	74 12                	je     9b0 <AckProof_validate+0x30>
     99e:	83 fe 40             	cmp    $0x40,%esi
     9a1:	7f 0d                	jg     9b0 <AckProof_validate+0x30>
     9a3:	8b 47 70             	mov    0x70(%edi),%eax
     9a6:	39 42 08             	cmp    %eax,0x8(%edx)
     9a9:	76 4b                	jbe    9f6 <AckProof_validate+0x76>
     9ab:	90                   	nop    
     9ac:	8d 74 26 00          	lea    0x0(%esi,1),%esi
     sacks[0].left > cont->TCPBase) {
	  if(!disableSevereErrors)
     9b0:	8b 15 00 00 00 00    	mov    0x0,%edx
     9b6:	85 d2                	test   %edx,%edx
     9b8:	74 16                	je     9d0 <AckProof_validate+0x50>
		  printk("Zero sacks (%d), too many sacks, or start (%u) > TCPBase (%u) [seq = %u]\n", numSacks, sacks[0].left, cont->TCPBase, cont->seq);
    return 0;
  }
  for(i=0; i < numSacks; i++) {
    if(!Sack_validate(cont, &sacks[i])) {
      return 0;
    }
    if(i > 0 && sacks[i].left <= sacks[i-1].right) {
      return 0;
     9ba:	31 d2                	xor    %edx,%edx
    }
  }
  return 1;
}
     9bc:	8b 5d f4             	mov    0xfffffff4(%ebp),%ebx
     9bf:	89 d0                	mov    %edx,%eax
     9c1:	8b 75 f8             	mov    0xfffffff8(%ebp),%esi
     9c4:	8b 7d fc             	mov    0xfffffffc(%ebp),%edi
     9c7:	89 ec                	mov    %ebp,%esp
     9c9:	5d                   	pop    %ebp
     9ca:	c3                   	ret    
     9cb:	90                   	nop    
     9cc:	8d 74 26 00          	lea    0x0(%esi,1),%esi
     9d0:	8b 47 34             	mov    0x34(%edi),%eax
     9d3:	89 44 24 10          	mov    %eax,0x10(%esp,1)
     9d7:	8b 47 70             	mov    0x70(%edi),%eax
     9da:	89 44 24 0c          	mov    %eax,0xc(%esp,1)
     9de:	8b 01                	mov    (%ecx),%eax
     9e0:	89 74 24 04          	mov    %esi,0x4(%esp,1)
     9e4:	c7 04 24 c0 00 00 00 	movl   $0xc0,(%esp,1)
     9eb:	89 44 24 08          	mov    %eax,0x8(%esp,1)
     9ef:	e8 fc ff ff ff       	call   9f0 <AckProof_validate+0x70>
     9f4:	eb c4                	jmp    9ba <AckProof_validate+0x3a>
     9f6:	c7 45 f0 00 00 00 00 	movl   $0x0,0xfffffff0(%ebp)
     9fd:	39 75 f0             	cmp    %esi,0xfffffff0(%ebp)
     a00:	7d 39                	jge    a3b <AckProof_validate+0xbb>
     a02:	89 cb                	mov    %ecx,%ebx
     a04:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi
     a0a:	8d bf 00 00 00 00    	lea    0x0(%edi),%edi
     a10:	89 5c 24 04          	mov    %ebx,0x4(%esp,1)
     a14:	89 3c 24             	mov    %edi,(%esp,1)
     a17:	e8 fc ff ff ff       	call   a18 <AckProof_validate+0x98>
     a1c:	31 d2                	xor    %edx,%edx
     a1e:	85 c0                	test   %eax,%eax
     a20:	74 9a                	je     9bc <AckProof_validate+0x3c>
     a22:	8b 45 f0             	mov    0xfffffff0(%ebp),%eax
     a25:	85 c0                	test   %eax,%eax
     a27:	7e 07                	jle    a30 <AckProof_validate+0xb0>
     a29:	8b 43 f8             	mov    0xfffffff8(%ebx),%eax
     a2c:	39 03                	cmp    %eax,(%ebx)
     a2e:	76 8a                	jbe    9ba <AckProof_validate+0x3a>
     a30:	ff 45 f0             	incl   0xfffffff0(%ebp)
     a33:	83 c3 0c             	add    $0xc,%ebx
     a36:	39 75 f0             	cmp    %esi,0xfffffff0(%ebp)
     a39:	7c d5                	jl     a10 <AckProof_validate+0x90>
     a3b:	ba 01 00 00 00       	mov    $0x1,%edx
     a40:	e9 77 ff ff ff       	jmp    9bc <AckProof_validate+0x3c>
     a45:	8d 74 26 00          	lea    0x0(%esi,1),%esi
     a49:	8d bc 27 00 00 00 00 	lea    0x0(%edi,1),%edi

00000a50 <AckProof_firstLoss>:

/* Note: FirstLoss considers poisoned nonces as present */
int AckProof_firstLoss(AckProof *proof) {
     a50:	55                   	push   %ebp
     a51:	89 e5                	mov    %esp,%ebp
     a53:	56                   	push   %esi
     a54:	53                   	push   %ebx
  int i, numSacks = proof->numSacks;
  Sack *sacks = proof->sacks;
  for(i=1; i < numSacks; i++) {
     a55:	bb 01 00 00 00       	mov    $0x1,%ebx
     a5a:	83 ec 04             	sub    $0x4,%esp
     a5d:	8b 45 08             	mov    0x8(%ebp),%eax
     a60:	8b 30                	mov    (%eax),%esi
     a62:	39 f3                	cmp    %esi,%ebx
     a64:	7d 1f                	jge    a85 <AckProof_firstLoss+0x35>
     a66:	8d 50 14             	lea    0x14(%eax),%edx
     a69:	8d b4 26 00 00 00 00 	lea    0x0(%esi,1),%esi
     a70:	8b 4a f8             	mov    0xfffffff8(%edx),%ecx
     a73:	89 c8                	mov    %ecx,%eax
     a75:	f7 d0                	not    %eax
     a77:	03 02                	add    (%edx),%eax
     a79:	85 c0                	test   %eax,%eax
     a7b:	75 1e                	jne    a9b <AckProof_firstLoss+0x4b>
     a7d:	43                   	inc    %ebx
     a7e:	83 c2 0c             	add    $0xc,%edx
     a81:	39 f3                	cmp    %esi,%ebx
     a83:	7c eb                	jl     a70 <AckProof_firstLoss+0x20>
    if(!Sack_adjacent(&sacks[i-1], &sacks[i])) {
      return sacks[i-1].right + 1;
    }
  }
  ERROR("No loss!\n");
     a85:	c7 04 24 57 00 00 00 	movl   $0x57,(%esp,1)
     a8c:	e8 fc ff ff ff       	call   a8d <AckProof_firstLoss+0x3d>
  return -1;
     a91:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
}
     a96:	59                   	pop    %ecx
     a97:	5b                   	pop    %ebx
     a98:	5e                   	pop    %esi
     a99:	5d                   	pop    %ebp
     a9a:	c3                   	ret    
     a9b:	8d 41 01             	lea    0x1(%ecx),%eax
     a9e:	eb f6                	jmp    a96 <AckProof_firstLoss+0x46>

00000aa0 <AckProof_checkRange>:

enum CheckRangeResult AckProof_checkRange(AckProof *proof, int left, int right) {
     aa0:	55                   	push   %ebp
     aa1:	89 e5                	mov    %esp,%ebp
     aa3:	57                   	push   %edi
  int i;
  int cursor;
  int poisoned = 0;
  Sack *sacks = proof->sacks;
  /* Check if AckProof covers the desired range */
  cursor = left;
  for(i=0; i < proof->numSacks; i++) {
     aa4:	31 ff                	xor    %edi,%edi
     aa6:	56                   	push   %esi
     aa7:	53                   	push   %ebx
     aa8:	83 ec 14             	sub    $0x14,%esp
     aab:	c7 45 f0 00 00 00 00 	movl   $0x0,0xfffffff0(%ebp)
     ab2:	8b 45 08             	mov    0x8(%ebp),%eax
     ab5:	8b 5d 08             	mov    0x8(%ebp),%ebx
     ab8:	8b 4d 0c             	mov    0xc(%ebp),%ecx
     abb:	83 c0 08             	add    $0x8,%eax
     abe:	89 45 ec             	mov    %eax,0xffffffec(%ebp)
     ac1:	8b 1b                	mov    (%ebx),%ebx
     ac3:	39 df                	cmp    %ebx,%edi
     ac5:	89 5d e8             	mov    %ebx,0xffffffe8(%ebp)
     ac8:	7d 29                	jge    af3 <AckProof_checkRange+0x53>
     aca:	31 f6                	xor    %esi,%esi
     acc:	8d 74 26 00          	lea    0x0(%esi,1),%esi
     ad0:	8b 45 ec             	mov    0xffffffec(%ebp),%eax
     ad3:	31 d2                	xor    %edx,%edx
     ad5:	01 f0                	add    %esi,%eax
     ad7:	39 08                	cmp    %ecx,(%eax)
     ad9:	77 0b                	ja     ae6 <AckProof_checkRange+0x46>
     adb:	3b 48 04             	cmp    0x4(%eax),%ecx
     ade:	bb 01 00 00 00       	mov    $0x1,%ebx
     ae3:	0f 46 d3             	cmovbe %ebx,%edx
     ae6:	85 d2                	test   %edx,%edx
     ae8:	75 26                	jne    b10 <AckProof_checkRange+0x70>
     aea:	47                   	inc    %edi
     aeb:	83 c6 0c             	add    $0xc,%esi
     aee:	3b 7d e8             	cmp    0xffffffe8(%ebp),%edi
     af1:	7c dd                	jl     ad0 <AckProof_checkRange+0x30>
    if(Sack_contains(&sacks[i], cursor)) {
      if(AckProof_isPoisoned(proof, &sacks[i])) {
	poisoned = 1;
      }
      cursor = sacks[i].right + 1;
      if(cursor > right) break;
    }
  }
  if(i == proof->numSacks) {
     af3:	31 c0                	xor    %eax,%eax
     af5:	3b 7d e8             	cmp    0xffffffe8(%ebp),%edi
     af8:	74 0d                	je     b07 <AckProof_checkRange+0x67>
    return BADRANGE;
  }
  return poisoned ? POISONEDRANGE : NORMALRANGE;
     afa:	31 c0                	xor    %eax,%eax
     afc:	83 7d f0 00          	cmpl   $0x0,0xfffffff0(%ebp)
     b00:	0f 94 c0             	sete   %al
     b03:	8d 44 00 ff          	lea    0xffffffff(%eax,%eax,1),%eax
}
     b07:	83 c4 14             	add    $0x14,%esp
     b0a:	5b                   	pop    %ebx
     b0b:	5e                   	pop    %esi
     b0c:	5f                   	pop    %edi
     b0d:	5d                   	pop    %ebp
     b0e:	c3                   	ret    
     b0f:	90                   	nop    
     b10:	89 44 24 04          	mov    %eax,0x4(%esp,1)
     b14:	8b 45 08             	mov    0x8(%ebp),%eax
     b17:	bb 01 00 00 00       	mov    $0x1,%ebx
     b1c:	89 04 24             	mov    %eax,(%esp,1)
     b1f:	e8 fc ff ff ff       	call   b20 <AckProof_checkRange+0x80>
     b24:	85 c0                	test   %eax,%eax
     b26:	8b 45 ec             	mov    0xffffffec(%ebp),%eax
     b29:	0f 44 5d f0          	cmove  0xfffffff0(%ebp),%ebx
     b2d:	89 5d f0             	mov    %ebx,0xfffffff0(%ebp)
     b30:	8b 4c 30 04          	mov    0x4(%eax,%esi,1),%ecx
     b34:	41                   	inc    %ecx
     b35:	3b 4d 10             	cmp    0x10(%ebp),%ecx
     b38:	7f 0a                	jg     b44 <AckProof_checkRange+0xa4>
     b3a:	8b 5d 08             	mov    0x8(%ebp),%ebx
     b3d:	8b 1b                	mov    (%ebx),%ebx
     b3f:	89 5d e8             	mov    %ebx,0xffffffe8(%ebp)
     b42:	eb a6                	jmp    aea <AckProof_checkRange+0x4a>
     b44:	8b 45 08             	mov    0x8(%ebp),%eax
     b47:	8b 00                	mov    (%eax),%eax
     b49:	89 45 e8             	mov    %eax,0xffffffe8(%ebp)
     b4c:	eb a5                	jmp    af3 <AckProof_checkRange+0x53>
     b4e:	89 f6                	mov    %esi,%esi

00000b50 <AckProof_findRight>:

__u32 AckProof_findRight(AckProof *proof, int start) {
     b50:	55                   	push   %ebp
     b51:	89 e5                	mov    %esp,%ebp
     b53:	57                   	push   %edi
     b54:	56                   	push   %esi
     b55:	53                   	push   %ebx
     b56:	83 ec 10             	sub    $0x10,%esp
  int i;
  int cursor;
  int poisoned = 0;
  Sack *sacks = proof->sacks;
  /* Check if AckProof covers the desired range */
  cursor = start;
  for(i=0; i < proof->numSacks; i++) {
     b59:	c7 45 f0 00 00 00 00 	movl   $0x0,0xfffffff0(%ebp)
     b60:	8b 45 08             	mov    0x8(%ebp),%eax
     b63:	8b 7d 08             	mov    0x8(%ebp),%edi
     b66:	8b 4d 0c             	mov    0xc(%ebp),%ecx
     b69:	8b 00                	mov    (%eax),%eax
     b6b:	83 c7 08             	add    $0x8,%edi
     b6e:	39 45 f0             	cmp    %eax,0xfffffff0(%ebp)
     b71:	89 45 ec             	mov    %eax,0xffffffec(%ebp)
     b74:	7d 31                	jge    ba7 <AckProof_findRight+0x57>
     b76:	31 db                	xor    %ebx,%ebx
     b78:	90                   	nop    
     b79:	8d b4 26 00 00 00 00 	lea    0x0(%esi,1),%esi
     b80:	8d 14 3b             	lea    (%ebx,%edi,1),%edx
     b83:	31 c0                	xor    %eax,%eax
     b85:	39 0a                	cmp    %ecx,(%edx)
     b87:	77 0c                	ja     b95 <AckProof_findRight+0x45>
     b89:	3b 4c 1f 04          	cmp    0x4(%edi,%ebx,1),%ecx
     b8d:	be 01 00 00 00       	mov    $0x1,%esi
     b92:	0f 46 c6             	cmovbe %esi,%eax
     b95:	85 c0                	test   %eax,%eax
     b97:	75 27                	jne    bc0 <AckProof_findRight+0x70>
     b99:	ff 45 f0             	incl   0xfffffff0(%ebp)
     b9c:	83 c3 0c             	add    $0xc,%ebx
     b9f:	8b 45 ec             	mov    0xffffffec(%ebp),%eax
     ba2:	39 45 f0             	cmp    %eax,0xfffffff0(%ebp)
     ba5:	7c d9                	jl     b80 <AckProof_findRight+0x30>
    if(Sack_contains(&sacks[i], cursor)) {
      if(AckProof_isPoisoned(proof, &sacks[i])) {
	poisoned = 1;
      }
      cursor = sacks[i].right + 1;
    }
  }
  if(cursor > start) 
     ba7:	8b 55 0c             	mov    0xc(%ebp),%edx
     baa:	8d 41 ff             	lea    0xffffffff(%ecx),%eax
     bad:	4a                   	dec    %edx
     bae:	3b 4d 0c             	cmp    0xc(%ebp),%ecx
     bb1:	0f 4e c2             	cmovle %edx,%eax
	  return cursor - 1;
  else
	  return start - 1; // error condition
}
     bb4:	83 c4 10             	add    $0x10,%esp
     bb7:	5b                   	pop    %ebx
     bb8:	5e                   	pop    %esi
     bb9:	5f                   	pop    %edi
     bba:	5d                   	pop    %ebp
     bbb:	c3                   	ret    
     bbc:	8d 74 26 00          	lea    0x0(%esi,1),%esi
     bc0:	89 54 24 04          	mov    %edx,0x4(%esp,1)
     bc4:	8b 45 08             	mov    0x8(%ebp),%eax
     bc7:	89 04 24             	mov    %eax,(%esp,1)
     bca:	e8 fc ff ff ff       	call   bcb <AckProof_findRight+0x7b>
     bcf:	8b 75 08             	mov    0x8(%ebp),%esi
     bd2:	8b 4c 1f 04          	mov    0x4(%edi,%ebx,1),%ecx
     bd6:	8b 36                	mov    (%esi),%esi
     bd8:	41                   	inc    %ecx
     bd9:	89 75 ec             	mov    %esi,0xffffffec(%ebp)
     bdc:	eb bb                	jmp    b99 <AckProof_findRight+0x49>
     bde:	89 f6                	mov    %esi,%esi

00000be0 <AckProof_findLeft>:

__u32 AckProof_findLeft(AckProof *proof, int start) {
     be0:	55                   	push   %ebp
     be1:	89 e5                	mov    %esp,%ebp
     be3:	57                   	push   %edi
     be4:	56                   	push   %esi
     be5:	53                   	push   %ebx
     be6:	83 ec 08             	sub    $0x8,%esp
     be9:	8b 7d 08             	mov    0x8(%ebp),%edi
  int i;
  int cursor;
  int poisoned = 0;
  Sack *sacks = proof->sacks;
  /* Check if AckProof covers the desired range */
  cursor = start;
     bec:	8b 4d 0c             	mov    0xc(%ebp),%ecx
  for(i=proof->numSacks - 1; i >= 0; i--) {
     bef:	8b 37                	mov    (%edi),%esi
     bf1:	8d 57 08             	lea    0x8(%edi),%edx
     bf4:	4e                   	dec    %esi
     bf5:	78 24                	js     c1b <AckProof_findLeft+0x3b>
     bf7:	8d 04 76             	lea    (%esi,%esi,2),%eax
     bfa:	8d 1c 82             	lea    (%edx,%eax,4),%ebx
     bfd:	8d 76 00             	lea    0x0(%esi),%esi
     c00:	31 c0                	xor    %eax,%eax
     c02:	39 0b                	cmp    %ecx,(%ebx)
     c04:	77 0b                	ja     c11 <AckProof_findLeft+0x31>
     c06:	3b 4b 04             	cmp    0x4(%ebx),%ecx
     c09:	ba 01 00 00 00       	mov    $0x1,%edx
     c0e:	0f 46 c2             	cmovbe %edx,%eax
     c11:	85 c0                	test   %eax,%eax
     c13:	75 1b                	jne    c30 <AckProof_findLeft+0x50>
     c15:	83 eb 0c             	sub    $0xc,%ebx
     c18:	4e                   	dec    %esi
     c19:	79 e5                	jns    c00 <AckProof_findLeft+0x20>
    if(Sack_contains(&sacks[i], cursor)) {
      if(AckProof_isPoisoned(proof, &sacks[i])) {
	poisoned = 1;
      }
      cursor = sacks[i].left - 1;
    }
  }
  if(cursor < start) 
     c1b:	8b 55 0c             	mov    0xc(%ebp),%edx
     c1e:	8d 41 01             	lea    0x1(%ecx),%eax
     c21:	42                   	inc    %edx
     c22:	3b 4d 0c             	cmp    0xc(%ebp),%ecx
     c25:	0f 4d c2             	cmovge %edx,%eax
	  return cursor + 1;
  else
	  return start + 1; // error condition
}
     c28:	83 c4 08             	add    $0x8,%esp
     c2b:	5b                   	pop    %ebx
     c2c:	5e                   	pop    %esi
     c2d:	5f                   	pop    %edi
     c2e:	5d                   	pop    %ebp
     c2f:	c3                   	ret    
     c30:	89 5c 24 04          	mov    %ebx,0x4(%esp,1)
     c34:	89 3c 24             	mov    %edi,(%esp,1)
     c37:	e8 fc ff ff ff       	call   c38 <AckProof_findLeft+0x58>
     c3c:	8b 0b                	mov    (%ebx),%ecx
     c3e:	49                   	dec    %ecx
     c3f:	eb d4                	jmp    c15 <AckProof_findLeft+0x35>
     c41:	eb 0d                	jmp    c50 <AckProof_dump>
     c43:	90                   	nop    
     c44:	90                   	nop    
     c45:	90                   	nop    
     c46:	90                   	nop    
     c47:	90                   	nop    
     c48:	90                   	nop    
     c49:	90                   	nop    
     c4a:	90                   	nop    
     c4b:	90                   	nop    
     c4c:	90                   	nop    
     c4d:	90                   	nop    
     c4e:	90                   	nop    
     c4f:	90                   	nop    

00000c50 <AckProof_dump>:

static int DoNormalStep(CONTINUATION_TYPE **cont, AckProof *ackProof, enum cminisock_event_tag event);
static int DoRecoveryStep(CONTINUATION_TYPE **cont, AckProof *ackProof, enum cminisock_event_tag event);
static int DoSlowStartStep(CONTINUATION_TYPE **cont, AckProof *ackProof, __u32 newBase, enum cminisock_event_tag event);

void AckProof_dump(AckProof *proof) {
     c50:	55                   	push   %ebp
     c51:	89 e5                	mov    %esp,%ebp
     c53:	57                   	push   %edi
     c54:	56                   	push   %esi
	int i;
	printk("proof(%d) = ", proof->numSacks);
	for(i = 0; i < proof->numSacks; i++) {
     c55:	31 f6                	xor    %esi,%esi
     c57:	53                   	push   %ebx
     c58:	83 ec 0c             	sub    $0xc,%esp
     c5b:	8b 7d 08             	mov    0x8(%ebp),%edi
     c5e:	8b 07                	mov    (%edi),%eax
     c60:	c7 04 24 61 00 00 00 	movl   $0x61,(%esp,1)
     c67:	89 44 24 04          	mov    %eax,0x4(%esp,1)
     c6b:	e8 fc ff ff ff       	call   c6c <AckProof_dump+0x1c>
     c70:	3b 37                	cmp    (%edi),%esi
     c72:	7d 2e                	jge    ca2 <AckProof_dump+0x52>
     c74:	89 fb                	mov    %edi,%ebx
     c76:	8d 76 00             	lea    0x0(%esi),%esi
     c79:	8d bc 27 00 00 00 00 	lea    0x0(%edi,1),%edi
		printk("[%d-%d]", proof->sacks[i].left, proof->sacks[i].right);
     c80:	8b 43 0c             	mov    0xc(%ebx),%eax
     c83:	46                   	inc    %esi
     c84:	89 44 24 08          	mov    %eax,0x8(%esp,1)
     c88:	8b 43 08             	mov    0x8(%ebx),%eax
     c8b:	c7 04 24 6e 00 00 00 	movl   $0x6e,(%esp,1)
     c92:	83 c3 0c             	add    $0xc,%ebx
     c95:	89 44 24 04          	mov    %eax,0x4(%esp,1)
     c99:	e8 fc ff ff ff       	call   c9a <AckProof_dump+0x4a>
     c9e:	3b 37                	cmp    (%edi),%esi
     ca0:	7c de                	jl     c80 <AckProof_dump+0x30>
	}
	printk("\n");
     ca2:	c7 45 08 76 00 00 00 	movl   $0x76,0x8(%ebp)
     ca9:	83 c4 0c             	add    $0xc,%esp
     cac:	5b                   	pop    %ebx
     cad:	5e                   	pop    %esi
     cae:	5f                   	pop    %edi
     caf:	5d                   	pop    %ebp
     cb0:	e9 fc ff ff ff       	jmp    cb1 <AckProof_dump+0x61>
     cb5:	8d 74 26 00          	lea    0x0(%esi,1),%esi
     cb9:	8d bc 27 00 00 00 00 	lea    0x0(%edi,1),%edi

00000cc0 <WireTrickleRequest_extract>:
}

WireTrickleRequest *WireTrickleRequest_extract(struct cminisock *msk, struct sk_buff *skb, int *error) {
     cc0:	55                   	push   %ebp
     cc1:	89 e5                	mov    %esp,%ebp
	return __pskb_pull(skb,len);
}

static inline int pskb_may_pull(struct sk_buff *skb, unsigned int len)
{
     cc3:	b9 4e 00 00 00       	mov    $0x4e,%ecx
     cc8:	57                   	push   %edi
     cc9:	56                   	push   %esi
     cca:	53                   	push   %ebx
     ccb:	83 ec 14             	sub    $0x14,%esp
     cce:	8b 5d 0c             	mov    0xc(%ebp),%ebx
	int sacks_len;
	WireTrickleRequest *req = (WireTrickleRequest*)skb->data;
	*error = EINVAL;
     cd1:	8b 55 10             	mov    0x10(%ebp),%edx
     cd4:	8b 83 94 00 00 00    	mov    0x94(%ebx),%eax
     cda:	89 45 f0             	mov    %eax,0xfffffff0(%ebp)
     cdd:	c7 02 16 00 00 00    	movl   $0x16,(%edx)
}

static inline unsigned int skb_headlen(const struct sk_buff *skb)
{
	return skb->len - skb->data_len;
     ce3:	8b 53 70             	mov    0x70(%ebx),%edx
     ce6:	8b 43 74             	mov    0x74(%ebx),%eax
     ce9:	89 d6                	mov    %edx,%esi
     ceb:	29 c6                	sub    %eax,%esi
     ced:	b8 01 00 00 00       	mov    $0x1,%eax
     cf2:	39 f1                	cmp    %esi,%ecx
     cf4:	76 0a                	jbe    d00 <WireTrickleRequest_extract+0x40>
}

#define SKB_PAGE_ASSERT(skb) do { if (skb_shinfo(skb)->nr_frags) out_of_line_bug(); } while (0)
#define SKB_FRAG_ASSERT(skb) do { if (skb_shinfo(skb)->frag_list) out_of_line_bug(); } while (0)
#define SKB_LINEAR_ASSERT(skb) do { if (skb_is_nonlinear(skb)) out_of_line_bug(); } while (0)

/*
 *	Add data to an sk_buff
 */
 
static inline unsigned char *__skb_put(struct sk_buff *skb, unsigned int len)
{
	unsigned char *tmp=skb->tail;
	SKB_LINEAR_ASSERT(skb);
	skb->tail+=len;
	skb->len+=len;
	return tmp;
}

/**
 *	skb_put - add data to a buffer
 *	@skb: buffer to use 
 *	@len: amount of data to add
 *
 *	This function extends the used data area of the buffer. If this would
 *	exceed the total buffer size the kernel will panic. A pointer to the
 *	first byte of the extra data is returned.
 */
 
static inline unsigned char *skb_put(struct sk_buff *skb, unsigned int len)
{
	unsigned char *tmp=skb->tail;
	SKB_LINEAR_ASSERT(skb);
	skb->tail+=len;
	skb->len+=len;
	if(skb->tail>skb->end) {
		skb_over_panic(skb, len, current_text_addr());
	}
	return tmp;
}

static inline unsigned char *__skb_push(struct sk_buff *skb, unsigned int len)
{
	skb->data-=len;
	skb->len+=len;
	return skb->data;
}

/**
 *	skb_push - add data to the start of a buffer
 *	@skb: buffer to use 
 *	@len: amount of data to add
 *
 *	This function extends the used data area of the buffer at the buffer
 *	start. If this would exceed the total buffer headroom the kernel will
 *	panic. A pointer to the first byte of the extra data is returned.
 */

static inline unsigned char *skb_push(struct sk_buff *skb, unsigned int len)
{
	skb->data-=len;
	skb->len+=len;
	if(skb->data<skb->head) {
		skb_under_panic(skb, len, current_text_addr());
	}
	return skb->data;
}

static inline char *__skb_pull(struct sk_buff *skb, unsigned int len)
{
	skb->len-=len;
	if (skb->len < skb->data_len)
		out_of_line_bug();
	return 	skb->data+=len;
}

/**
 *	skb_pull - remove data from the start of a buffer
 *	@skb: buffer to use 
 *	@len: amount of data to remove
 *
 *	This function removes data from the start of a buffer, returning
 *	the memory to the headroom. A pointer to the next data in the buffer
 *	is returned. Once the data has been pulled future pushes will overwrite
 *	the old data.
 */

static inline unsigned char * skb_pull(struct sk_buff *skb, unsigned int len)
{	
	if (len > skb->len)
		return NULL;
	return __skb_pull(skb,len);
}

extern unsigned char * __pskb_pull_tail(struct sk_buff *skb, int delta);

static inline char *__pskb_pull(struct sk_buff *skb, unsigned int len)
{
	if (len > skb_headlen(skb) &&
	    __pskb_pull_tail(skb, len-skb_headlen(skb)) == NULL)
		return NULL;
	skb->len -= len;
	return 	skb->data += len;
}

static inline unsigned char * pskb_pull(struct sk_buff *skb, unsigned int len)
{	
	if (len > skb->len)
		return NULL;
	return __pskb_pull(skb,len);
}

static inline int pskb_may_pull(struct sk_buff *skb, unsigned int len)
{
	if (len <= skb_headlen(skb))
		return 1;
	if (len > skb->len)
     cf6:	31 c0                	xor    %eax,%eax
     cf8:	39 d1                	cmp    %edx,%ecx
     cfa:	0f 86 16 03 00 00    	jbe    1016 <WireTrickleRequest_extract+0x356>
     d00:	85 c0                	test   %eax,%eax
     d02:	0f 85 bb 00 00 00    	jne    dc3 <WireTrickleRequest_extract+0x103>

	if(!pskb_may_pull(skb, sizeof(*req))) {
		if(trickles_ratelimit()) {
     d08:	a1 00 00 00 00       	mov    0x0,%eax
     d0d:	9c                   	pushf  
     d0e:	59                   	pop    %ecx
     d0f:	fa                   	cli    
     d10:	89 c2                	mov    %eax,%edx
     d12:	8b 3d 38 e2 04 00    	mov    0x4e238,%edi
     d18:	8b 35 30 00 00 00    	mov    0x30,%esi
     d1e:	a3 38 e2 04 00       	mov    %eax,0x4e238
     d23:	29 fa                	sub    %edi,%edx
     d25:	01 f2                	add    %esi,%edx
     d27:	89 15 30 00 00 00    	mov    %edx,0x30
     d2d:	81 fa 88 13 00 00    	cmp    $0x1388,%edx
     d33:	76 10                	jbe    d45 <WireTrickleRequest_extract+0x85>
     d35:	bf 88 13 00 00       	mov    $0x1388,%edi
     d3a:	ba 88 13 00 00       	mov    $0x1388,%edx
     d3f:	89 3d 30 00 00 00    	mov    %edi,0x30
     d45:	81 fa f3 01 00 00    	cmp    $0x1f3,%edx
     d4b:	76 6a                	jbe    db7 <WireTrickleRequest_extract+0xf7>
     d4d:	31 f6                	xor    %esi,%esi
     d4f:	81 ea f4 01 00 00    	sub    $0x1f4,%edx
     d55:	a1 3c e2 04 00       	mov    0x4e23c,%eax
     d5a:	89 15 30 00 00 00    	mov    %edx,0x30
     d60:	89 35 3c e2 04 00    	mov    %esi,0x4e23c
     d66:	51                   	push   %ecx
     d67:	9d                   	popf   
     d68:	85 c0                	test   %eax,%eax
     d6a:	75 29                	jne    d95 <WireTrickleRequest_extract+0xd5>
     d6c:	b8 01 00 00 00       	mov    $0x1,%eax
     d71:	85 c0                	test   %eax,%eax
     d73:	75 0b                	jne    d80 <WireTrickleRequest_extract+0xc0>
			printk("SKB too short for WireTrickleRequest, len = %d\n", skb->len);
		}
		return NULL;
	}
	__skb_pull(skb, sizeof(*req));
	/* Handle variable length fields */
	sacks_len = req->ackProof.numSacks * sizeof(WireSack);

	// 0714 MAXSACKS is appropriate here (e.g., NOT MAX_KERNEL_SACKS) because 
	// value comes from wire
	if(!(req->ackProof.numSacks <= MAXSACKS &&
	     pskb_may_pull(skb, sacks_len))) {
		printk("SKB too short for WireTrickleRequest (either too many sacks, or not enough space in packet header for sacks\n");
		return NULL;
	}
	__skb_pull(skb, sacks_len);

	msk->ucont_len = ntohs(req->ucont_len);
	if(!pskb_may_pull(skb, msk->ucont_len)) {
		printk("WireTrickleRequest_extract: skb too short for ucont\n");
		return NULL;
	}
	if(!SIMULATION_MODE(msk->sk)) {
		if(msk->ucont_len > 0) {
			msk->ucont_data = tmalloc(skb->sk, msk->ucont_len);
			if(msk->ucont_data == NULL) {
#if 0
				if(trickles_ratelimit()) {
					printk("WireTrickleRequest_extract: Out of memory while copying ucont\n");
				}
#endif
				*error = ENOMEM;
				return NULL;
			}
			memcpy(msk->ucont_data, (char*)skb->data, msk->ucont_len);
			__skb_pull(skb, msk->ucont_len);
		} else {
			msk->ucont_data = NULL;
		}
	} else {
		msk->ucont_len = 0;
		msk->ucont_data = NULL;
	}

	BUG_TRAP(skb->len >= 0);
	if(!SIMULATION_MODE(msk->sk)) {
		msk->input_len = skb->len;
		if(msk->input_len > 0) {
			msk->input = tmalloc(skb->sk, msk->input_len);
			if(msk->input == NULL) {
#if 0
				if(trickles_ratelimit()) {
					printk("WireTrickleRequest_extract: Out of memory while copying Conversion data\n");
				}
#endif
				*error = ENOMEM;
				return NULL;
     d75:	31 c0                	xor    %eax,%eax
			}
			memcpy(msk->input, (char*)skb->data, msk->input_len);
		} else {
			msk->input = NULL;
		}
	} else {
		msk->input_len = 0;
		msk->input = NULL;
	}
	*error = 0;
	return req;
}
     d77:	83 c4 14             	add    $0x14,%esp
     d7a:	5b                   	pop    %ebx
     d7b:	5e                   	pop    %esi
     d7c:	5f                   	pop    %edi
     d7d:	5d                   	pop    %ebp
     d7e:	c3                   	ret    
     d7f:	90                   	nop    
     d80:	8b 43 70             	mov    0x70(%ebx),%eax
     d83:	c7 04 24 20 01 00 00 	movl   $0x120,(%esp,1)
     d8a:	89 44 24 04          	mov    %eax,0x4(%esp,1)
     d8e:	e8 fc ff ff ff       	call   d8f <WireTrickleRequest_extract+0xcf>
     d93:	eb e0                	jmp    d75 <WireTrickleRequest_extract+0xb5>
     d95:	89 44 24 0c          	mov    %eax,0xc(%esp,1)
     d99:	c7 44 24 08 bf 01 00 	movl   $0x1bf,0x8(%esp,1)
     da0:	00 
     da1:	c7 44 24 04 45 00 00 	movl   $0x45,0x4(%esp,1)
     da8:	00 
     da9:	c7 04 24 80 00 00 00 	movl   $0x80,(%esp,1)
     db0:	e8 fc ff ff ff       	call   db1 <WireTrickleRequest_extract+0xf1>
     db5:	eb b5                	jmp    d6c <WireTrickleRequest_extract+0xac>
     db7:	ff 05 3c e2 04 00    	incl   0x4e23c
     dbd:	51                   	push   %ecx
     dbe:	9d                   	popf   
     dbf:	31 c0                	xor    %eax,%eax
     dc1:	eb ae                	jmp    d71 <WireTrickleRequest_extract+0xb1>
}

static inline char *__skb_pull(struct sk_buff *skb, unsigned int len)
{
	skb->len-=len;
     dc3:	8b 4b 70             	mov    0x70(%ebx),%ecx
	if (skb->len < skb->data_len)
     dc6:	8b 73 74             	mov    0x74(%ebx),%esi
     dc9:	83 e9 4e             	sub    $0x4e,%ecx
     dcc:	89 4b 70             	mov    %ecx,0x70(%ebx)
     dcf:	39 f1                	cmp    %esi,%ecx
     dd1:	0f 82 5c 02 00 00    	jb     1033 <WireTrickleRequest_extract+0x373>
		out_of_line_bug();
     dd7:	83 83 94 00 00 00 4e 	addl   $0x4e,0x94(%ebx)
     dde:	8b 45 f0             	mov    0xfffffff0(%ebp),%eax
     de1:	0f b6 50 4d          	movzbl 0x4d(%eax),%edx
     de5:	0f b6 c2             	movzbl %dl,%eax
     de8:	8d 04 40             	lea    (%eax,%eax,2),%eax
     deb:	80 fa 40             	cmp    $0x40,%dl
     dee:	8d 3c 85 00 00 00 00 	lea    0x0(,%eax,4),%edi
     df5:	77 1b                	ja     e12 <WireTrickleRequest_extract+0x152>
}

static inline unsigned int skb_headlen(const struct sk_buff *skb)
{
	return skb->len - skb->data_len;
     df7:	89 ca                	mov    %ecx,%edx
     df9:	29 f2                	sub    %esi,%edx
     dfb:	39 d7                	cmp    %edx,%edi
     dfd:	b8 01 00 00 00       	mov    $0x1,%eax
     e02:	76 0a                	jbe    e0e <WireTrickleRequest_extract+0x14e>
}

#define SKB_PAGE_ASSERT(skb) do { if (skb_shinfo(skb)->nr_frags) out_of_line_bug(); } while (0)
#define SKB_FRAG_ASSERT(skb) do { if (skb_shinfo(skb)->frag_list) out_of_line_bug(); } while (0)
#define SKB_LINEAR_ASSERT(skb) do { if (skb_is_nonlinear(skb)) out_of_line_bug(); } while (0)

/*
 *	Add data to an sk_buff
 */
 
static inline unsigned char *__skb_put(struct sk_buff *skb, unsigned int len)
{
	unsigned char *tmp=skb->tail;
	SKB_LINEAR_ASSERT(skb);
	skb->tail+=len;
	skb->len+=len;
	return tmp;
}

/**
 *	skb_put - add data to a buffer
 *	@skb: buffer to use 
 *	@len: amount of data to add
 *
 *	This function extends the used data area of the buffer. If this would
 *	exceed the total buffer size the kernel will panic. A pointer to the
 *	first byte of the extra data is returned.
 */
 
static inline unsigned char *skb_put(struct sk_buff *skb, unsigned int len)
{
	unsigned char *tmp=skb->tail;
	SKB_LINEAR_ASSERT(skb);
	skb->tail+=len;
	skb->len+=len;
	if(skb->tail>skb->end) {
		skb_over_panic(skb, len, current_text_addr());
	}
	return tmp;
}

static inline unsigned char *__skb_push(struct sk_buff *skb, unsigned int len)
{
	skb->data-=len;
	skb->len+=len;
	return skb->data;
}

/**
 *	skb_push - add data to the start of a buffer
 *	@skb: buffer to use 
 *	@len: amount of data to add
 *
 *	This function extends the used data area of the buffer at the buffer
 *	start. If this would exceed the total buffer headroom the kernel will
 *	panic. A pointer to the first byte of the extra data is returned.
 */

static inline unsigned char *skb_push(struct sk_buff *skb, unsigned int len)
{
	skb->data-=len;
	skb->len+=len;
	if(skb->data<skb->head) {
		skb_under_panic(skb, len, current_text_addr());
	}
	return skb->data;
}

static inline char *__skb_pull(struct sk_buff *skb, unsigned int len)
{
	skb->len-=len;
	if (skb->len < skb->data_len)
		out_of_line_bug();
	return 	skb->data+=len;
}

/**
 *	skb_pull - remove data from the start of a buffer
 *	@skb: buffer to use 
 *	@len: amount of data to remove
 *
 *	This function removes data from the start of a buffer, returning
 *	the memory to the headroom. A pointer to the next data in the buffer
 *	is returned. Once the data has been pulled future pushes will overwrite
 *	the old data.
 */

static inline unsigned char * skb_pull(struct sk_buff *skb, unsigned int len)
{	
	if (len > skb->len)
		return NULL;
	return __skb_pull(skb,len);
}

extern unsigned char * __pskb_pull_tail(struct sk_buff *skb, int delta);

static inline char *__pskb_pull(struct sk_buff *skb, unsigned int len)
{
	if (len > skb_headlen(skb) &&
	    __pskb_pull_tail(skb, len-skb_headlen(skb)) == NULL)
		return NULL;
	skb->len -= len;
	return 	skb->data += len;
}

static inline unsigned char * pskb_pull(struct sk_buff *skb, unsigned int len)
{	
	if (len > skb->len)
		return NULL;
	return __pskb_pull(skb,len);
}

static inline int pskb_may_pull(struct sk_buff *skb, unsigned int len)
{
	if (len <= skb_headlen(skb))
		return 1;
	if (len > skb->len)
     e04:	31 c0                	xor    %eax,%eax
     e06:	39 cf                	cmp    %ecx,%edi
     e08:	0f 86 eb 01 00 00    	jbe    ff9 <WireTrickleRequest_extract+0x339>
     e0e:	85 c0                	test   %eax,%eax
     e10:	75 11                	jne    e23 <WireTrickleRequest_extract+0x163>
     e12:	c7 04 24 60 01 00 00 	movl   $0x160,(%esp,1)
     e19:	e8 fc ff ff ff       	call   e1a <WireTrickleRequest_extract+0x15a>
     e1e:	e9 52 ff ff ff       	jmp    d75 <WireTrickleRequest_extract+0xb5>
}

static inline char *__skb_pull(struct sk_buff *skb, unsigned int len)
{
	skb->len-=len;
     e23:	8b 43 70             	mov    0x70(%ebx),%eax
     e26:	29 f8                	sub    %edi,%eax
	if (skb->len < skb->data_len)
     e28:	3b 43 74             	cmp    0x74(%ebx),%eax
     e2b:	89 43 70             	mov    %eax,0x70(%ebx)
     e2e:	0f 82 ff 01 00 00    	jb     1033 <WireTrickleRequest_extract+0x373>
		out_of_line_bug();
     e34:	01 bb 94 00 00 00    	add    %edi,0x94(%ebx)
     e3a:	8b 55 f0             	mov    0xfffffff0(%ebp),%edx
#endif /* OPTIMIZE */


static __inline__ __const__ __u16 __fswab16(__u16 x)
{
     e3d:	8b 4d 08             	mov    0x8(%ebp),%ecx
     e40:	0f b7 42 4b          	movzwl 0x4b(%edx),%eax
/* gcc should generate this for open coded C now too. May be worth switching to 
   it because inline assembly cannot be scheduled. -AK */
static __inline__ __const__ __u16 ___arch__swab16(__u16 x)
{
	__asm__("xchgb %b0,%h0"		/* swap bytes		*/
     e44:	86 c4                	xchg   %al,%ah
#endif /* OPTIMIZE */


static __inline__ __const__ __u16 __fswab16(__u16 x)
{
     e46:	0f b7 c0             	movzwl %ax,%eax
     e49:	89 41 7c             	mov    %eax,0x7c(%ecx)
}

static inline unsigned int skb_headlen(const struct sk_buff *skb)
{
	return skb->len - skb->data_len;
     e4c:	8b 53 70             	mov    0x70(%ebx),%edx
     e4f:	8b 4b 74             	mov    0x74(%ebx),%ecx
     e52:	89 d6                	mov    %edx,%esi
     e54:	29 ce                	sub    %ecx,%esi
     e56:	b9 01 00 00 00       	mov    $0x1,%ecx
     e5b:	39 f0                	cmp    %esi,%eax
     e5d:	76 0a                	jbe    e69 <WireTrickleRequest_extract+0x1a9>
}

#define SKB_PAGE_ASSERT(skb) do { if (skb_shinfo(skb)->nr_frags) out_of_line_bug(); } while (0)
#define SKB_FRAG_ASSERT(skb) do { if (skb_shinfo(skb)->frag_list) out_of_line_bug(); } while (0)
#define SKB_LINEAR_ASSERT(skb) do { if (skb_is_nonlinear(skb)) out_of_line_bug(); } while (0)

/*
 *	Add data to an sk_buff
 */
 
static inline unsigned char *__skb_put(struct sk_buff *skb, unsigned int len)
{
	unsigned char *tmp=skb->tail;
	SKB_LINEAR_ASSERT(skb);
	skb->tail+=len;
	skb->len+=len;
	return tmp;
}

/**
 *	skb_put - add data to a buffer
 *	@skb: buffer to use 
 *	@len: amount of data to add
 *
 *	This function extends the used data area of the buffer. If this would
 *	exceed the total buffer size the kernel will panic. A pointer to the
 *	first byte of the extra data is returned.
 */
 
static inline unsigned char *skb_put(struct sk_buff *skb, unsigned int len)
{
	unsigned char *tmp=skb->tail;
	SKB_LINEAR_ASSERT(skb);
	skb->tail+=len;
	skb->len+=len;
	if(skb->tail>skb->end) {
		skb_over_panic(skb, len, current_text_addr());
	}
	return tmp;
}

static inline unsigned char *__skb_push(struct sk_buff *skb, unsigned int len)
{
	skb->data-=len;
	skb->len+=len;
	return skb->data;
}

/**
 *	skb_push - add data to the start of a buffer
 *	@skb: buffer to use 
 *	@len: amount of data to add
 *
 *	This function extends the used data area of the buffer at the buffer
 *	start. If this would exceed the total buffer headroom the kernel will
 *	panic. A pointer to the first byte of the extra data is returned.
 */

static inline unsigned char *skb_push(struct sk_buff *skb, unsigned int len)
{
	skb->data-=len;
	skb->len+=len;
	if(skb->data<skb->head) {
		skb_under_panic(skb, len, current_text_addr());
	}
	return skb->data;
}

static inline char *__skb_pull(struct sk_buff *skb, unsigned int len)
{
	skb->len-=len;
	if (skb->len < skb->data_len)
		out_of_line_bug();
	return 	skb->data+=len;
}

/**
 *	skb_pull - remove data from the start of a buffer
 *	@skb: buffer to use 
 *	@len: amount of data to remove
 *
 *	This function removes data from the start of a buffer, returning
 *	the memory to the headroom. A pointer to the next data in the buffer
 *	is returned. Once the data has been pulled future pushes will overwrite
 *	the old data.
 */

static inline unsigned char * skb_pull(struct sk_buff *skb, unsigned int len)
{	
	if (len > skb->len)
		return NULL;
	return __skb_pull(skb,len);
}

extern unsigned char * __pskb_pull_tail(struct sk_buff *skb, int delta);

static inline char *__pskb_pull(struct sk_buff *skb, unsigned int len)
{
	if (len > skb_headlen(skb) &&
	    __pskb_pull_tail(skb, len-skb_headlen(skb)) == NULL)
		return NULL;
	skb->len -= len;
	return 	skb->data += len;
}

static inline unsigned char * pskb_pull(struct sk_buff *skb, unsigned int len)
{	
	if (len > skb->len)
		return NULL;
	return __pskb_pull(skb,len);
}

static inline int pskb_may_pull(struct sk_buff *skb, unsigned int len)
{
	if (len <= skb_headlen(skb))
		return 1;
	if (len > skb->len)
     e5f:	31 c9                	xor    %ecx,%ecx
     e61:	39 d0                	cmp    %edx,%eax
     e63:	0f 86 76 01 00 00    	jbe    fdf <WireTrickleRequest_extract+0x31f>
     e69:	85 c9                	test   %ecx,%ecx
     e6b:	0f 84 62 01 00 00    	je     fd3 <WireTrickleRequest_extract+0x313>
     e71:	8b 45 08             	mov    0x8(%ebp),%eax
     e74:	8b 50 20             	mov    0x20(%eax),%edx
     e77:	8b 82 a8 02 00 00    	mov    0x2a8(%edx),%eax
     e7d:	a9 01 00 00 00       	test   $0x1,%eax
     e82:	74 09                	je     e8d <WireTrickleRequest_extract+0x1cd>
     e84:	83 e0 08             	and    $0x8,%eax
     e87:	0f 84 2f 01 00 00    	je     fbc <WireTrickleRequest_extract+0x2fc>
     e8d:	8b 4d 08             	mov    0x8(%ebp),%ecx
     e90:	8b 41 7c             	mov    0x7c(%ecx),%eax
     e93:	85 c0                	test   %eax,%eax
     e95:	0f 8e 11 01 00 00    	jle    fac <WireTrickleRequest_extract+0x2ec>
     e9b:	89 44 24 04          	mov    %eax,0x4(%esp,1)
     e9f:	8b 43 0c             	mov    0xc(%ebx),%eax
     ea2:	89 04 24             	mov    %eax,(%esp,1)
     ea5:	e8 fc ff ff ff       	call   ea6 <WireTrickleRequest_extract+0x1e6>
     eaa:	89 c2                	mov    %eax,%edx
     eac:	8b 45 08             	mov    0x8(%ebp),%eax
     eaf:	85 d2                	test   %edx,%edx
     eb1:	89 90 80 00 00 00    	mov    %edx,0x80(%eax)
     eb7:	75 0e                	jne    ec7 <WireTrickleRequest_extract+0x207>
     eb9:	8b 55 10             	mov    0x10(%ebp),%edx
     ebc:	c7 02 0c 00 00 00    	movl   $0xc,(%edx)
     ec2:	e9 ae fe ff ff       	jmp    d75 <WireTrickleRequest_extract+0xb5>
return __res;
}

static inline void * __memcpy(void * to, const void * from, size_t n)
{
     ec7:	8b 4d 08             	mov    0x8(%ebp),%ecx
int d0, d1, d2;
__asm__ __volatile__(
     eca:	89 d7                	mov    %edx,%edi
     ecc:	8b b3 94 00 00 00    	mov    0x94(%ebx),%esi
     ed2:	8b 41 7c             	mov    0x7c(%ecx),%eax
     ed5:	89 c1                	mov    %eax,%ecx
     ed7:	c1 e9 02             	shr    $0x2,%ecx
     eda:	f3 a5                	repz movsl %ds:(%esi),%es:(%edi)
     edc:	a8 02                	test   $0x2,%al
     ede:	74 02                	je     ee2 <WireTrickleRequest_extract+0x222>
     ee0:	66 a5                	movsw  %ds:(%esi),%es:(%edi)
     ee2:	a8 01                	test   $0x1,%al
     ee4:	74 01                	je     ee7 <WireTrickleRequest_extract+0x227>
     ee6:	a4                   	movsb  %ds:(%esi),%es:(%edi)
	return skb->data;
}

static inline char *__skb_pull(struct sk_buff *skb, unsigned int len)
{
     ee7:	8b 45 08             	mov    0x8(%ebp),%eax
     eea:	8b 50 7c             	mov    0x7c(%eax),%edx
	skb->len-=len;
     eed:	8b 43 70             	mov    0x70(%ebx),%eax
     ef0:	29 d0                	sub    %edx,%eax
	if (skb->len < skb->data_len)
     ef2:	3b 43 74             	cmp    0x74(%ebx),%eax
     ef5:	89 43 70             	mov    %eax,0x70(%ebx)
     ef8:	0f 82 35 01 00 00    	jb     1033 <WireTrickleRequest_extract+0x373>
     efe:	01 93 94 00 00 00    	add    %edx,0x94(%ebx)
     f04:	8b 4d 08             	mov    0x8(%ebp),%ecx
     f07:	8b 51 20             	mov    0x20(%ecx),%edx
     f0a:	8b 82 a8 02 00 00    	mov    0x2a8(%edx),%eax
     f10:	a9 01 00 00 00       	test   $0x1,%eax
     f15:	74 05                	je     f1c <WireTrickleRequest_extract+0x25c>
     f17:	83 e0 08             	and    $0x8,%eax
     f1a:	74 7b                	je     f97 <WireTrickleRequest_extract+0x2d7>
     f1c:	8b 43 70             	mov    0x70(%ebx),%eax
     f1f:	8b 55 08             	mov    0x8(%ebp),%edx
     f22:	85 c0                	test   %eax,%eax
     f24:	89 82 84 00 00 00    	mov    %eax,0x84(%edx)
     f2a:	7e 5e                	jle    f8a <WireTrickleRequest_extract+0x2ca>
     f2c:	89 44 24 04          	mov    %eax,0x4(%esp,1)
     f30:	8b 43 0c             	mov    0xc(%ebx),%eax
     f33:	89 04 24             	mov    %eax,(%esp,1)
     f36:	e8 fc ff ff ff       	call   f37 <WireTrickleRequest_extract+0x277>
     f3b:	8b 4d 08             	mov    0x8(%ebp),%ecx
     f3e:	85 c0                	test   %eax,%eax
     f40:	89 c7                	mov    %eax,%edi
     f42:	89 81 88 00 00 00    	mov    %eax,0x88(%ecx)
     f48:	75 0e                	jne    f58 <WireTrickleRequest_extract+0x298>
     f4a:	8b 45 10             	mov    0x10(%ebp),%eax
     f4d:	c7 00 0c 00 00 00    	movl   $0xc,(%eax)
     f53:	e9 1d fe ff ff       	jmp    d75 <WireTrickleRequest_extract+0xb5>
return __res;
}

static inline void * __memcpy(void * to, const void * from, size_t n)
{
     f58:	8b 55 08             	mov    0x8(%ebp),%edx
     f5b:	8b b3 94 00 00 00    	mov    0x94(%ebx),%esi
     f61:	8b 82 84 00 00 00    	mov    0x84(%edx),%eax
int d0, d1, d2;
__asm__ __volatile__(
     f67:	89 c1                	mov    %eax,%ecx
     f69:	c1 e9 02             	shr    $0x2,%ecx
     f6c:	f3 a5                	repz movsl %ds:(%esi),%es:(%edi)
     f6e:	a8 02                	test   $0x2,%al
     f70:	74 02                	je     f74 <WireTrickleRequest_extract+0x2b4>
     f72:	66 a5                	movsw  %ds:(%esi),%es:(%edi)
     f74:	a8 01                	test   $0x1,%al
     f76:	74 01                	je     f79 <WireTrickleRequest_extract+0x2b9>
     f78:	a4                   	movsb  %ds:(%esi),%es:(%edi)
     f79:	8b 55 10             	mov    0x10(%ebp),%edx
     f7c:	c7 02 00 00 00 00    	movl   $0x0,(%edx)
     f82:	8b 45 f0             	mov    0xfffffff0(%ebp),%eax
     f85:	e9 ed fd ff ff       	jmp    d77 <WireTrickleRequest_extract+0xb7>
     f8a:	8b 4d 08             	mov    0x8(%ebp),%ecx
     f8d:	31 db                	xor    %ebx,%ebx
     f8f:	89 99 88 00 00 00    	mov    %ebx,0x88(%ecx)
     f95:	eb e2                	jmp    f79 <WireTrickleRequest_extract+0x2b9>
     f97:	8b 45 08             	mov    0x8(%ebp),%eax
     f9a:	31 c9                	xor    %ecx,%ecx
     f9c:	31 d2                	xor    %edx,%edx
     f9e:	89 88 84 00 00 00    	mov    %ecx,0x84(%eax)
     fa4:	89 90 88 00 00 00    	mov    %edx,0x88(%eax)
     faa:	eb cd                	jmp    f79 <WireTrickleRequest_extract+0x2b9>
     fac:	8b 45 08             	mov    0x8(%ebp),%eax
     faf:	31 ff                	xor    %edi,%edi
     fb1:	89 b8 80 00 00 00    	mov    %edi,0x80(%eax)
     fb7:	e9 4e ff ff ff       	jmp    f0a <WireTrickleRequest_extract+0x24a>
     fbc:	8b 4d 08             	mov    0x8(%ebp),%ecx
     fbf:	31 f6                	xor    %esi,%esi
     fc1:	c7 41 7c 00 00 00 00 	movl   $0x0,0x7c(%ecx)
     fc8:	89 b1 80 00 00 00    	mov    %esi,0x80(%ecx)
     fce:	e9 37 ff ff ff       	jmp    f0a <WireTrickleRequest_extract+0x24a>
     fd3:	c7 04 24 e0 01 00 00 	movl   $0x1e0,(%esp,1)
     fda:	e9 3a fe ff ff       	jmp    e19 <WireTrickleRequest_extract+0x159>
	return skb->data_len;
}

static inline unsigned int skb_headlen(const struct sk_buff *skb)
{
     fdf:	89 1c 24             	mov    %ebx,(%esp,1)
     fe2:	29 f0                	sub    %esi,%eax
     fe4:	89 44 24 04          	mov    %eax,0x4(%esp,1)
     fe8:	e8 fc ff ff ff       	call   fe9 <WireTrickleRequest_extract+0x329>
     fed:	31 c9                	xor    %ecx,%ecx
     fef:	85 c0                	test   %eax,%eax
     ff1:	0f 95 c1             	setne  %cl
     ff4:	e9 70 fe ff ff       	jmp    e69 <WireTrickleRequest_extract+0x1a9>
     ff9:	89 1c 24             	mov    %ebx,(%esp,1)
     ffc:	89 f8                	mov    %edi,%eax
     ffe:	29 d0                	sub    %edx,%eax
    1000:	89 44 24 04          	mov    %eax,0x4(%esp,1)
    1004:	e8 fc ff ff ff       	call   1005 <WireTrickleRequest_extract+0x345>
    1009:	85 c0                	test   %eax,%eax
    100b:	0f 95 c0             	setne  %al
    100e:	0f b6 c0             	movzbl %al,%eax
    1011:	e9 f8 fd ff ff       	jmp    e0e <WireTrickleRequest_extract+0x14e>
    1016:	89 1c 24             	mov    %ebx,(%esp,1)
    1019:	89 c8                	mov    %ecx,%eax
    101b:	29 f0                	sub    %esi,%eax
    101d:	89 44 24 04          	mov    %eax,0x4(%esp,1)
    1021:	e8 fc ff ff ff       	call   1022 <WireTrickleRequest_extract+0x362>
    1026:	85 c0                	test   %eax,%eax
    1028:	0f 95 c0             	setne  %al
    102b:	0f b6 c0             	movzbl %al,%eax
    102e:	e9 cd fc ff ff       	jmp    d00 <WireTrickleRequest_extract+0x40>
	return skb->len - skb->data_len;
}

#define SKB_PAGE_ASSERT(skb) do { if (skb_shinfo(skb)->nr_frags) out_of_line_bug(); } while (0)
#define SKB_FRAG_ASSERT(skb) do { if (skb_shinfo(skb)->frag_list) out_of_line_bug(); } while (0)
#define SKB_LINEAR_ASSERT(skb) do { if (skb_is_nonlinear(skb)) out_of_line_bug(); } while (0)

/*
 *	Add data to an sk_buff
 */
 
static inline unsigned char *__skb_put(struct sk_buff *skb, unsigned int len)
{
	unsigned char *tmp=skb->tail;
	SKB_LINEAR_ASSERT(skb);
	skb->tail+=len;
	skb->len+=len;
	return tmp;
}

/**
 *	skb_put - add data to a buffer
 *	@skb: buffer to use 
 *	@len: amount of data to add
 *
 *	This function extends the used data area of the buffer. If this would
 *	exceed the total buffer size the kernel will panic. A pointer to the
 *	first byte of the extra data is returned.
 */
 
static inline unsigned char *skb_put(struct sk_buff *skb, unsigned int len)
{
	unsigned char *tmp=skb->tail;
	SKB_LINEAR_ASSERT(skb);
	skb->tail+=len;
	skb->len+=len;
	if(skb->tail>skb->end) {
		skb_over_panic(skb, len, current_text_addr());
	}
	return tmp;
}

static inline unsigned char *__skb_push(struct sk_buff *skb, unsigned int len)
{
	skb->data-=len;
	skb->len+=len;
	return skb->data;
}

/**
 *	skb_push - add data to the start of a buffer
 *	@skb: buffer to use 
 *	@len: amount of data to add
 *
 *	This function extends the used data area of the buffer at the buffer
 *	start. If this would exceed the total buffer headroom the kernel will
 *	panic. A pointer to the first byte of the extra data is returned.
 */

static inline unsigned char *skb_push(struct sk_buff *skb, unsigned int len)
{
	skb->data-=len;
	skb->len+=len;
	if(skb->data<skb->head) {
		skb_under_panic(skb, len, current_text_addr());
	}
	return skb->data;
}

static inline char *__skb_pull(struct sk_buff *skb, unsigned int len)
{
	skb->len-=len;
	if (skb->len < skb->data_len)
		out_of_line_bug();
    1033:	c7 04 24 4c 03 00 00 	movl   $0x34c,(%esp,1)
    103a:	e8 fc ff ff ff       	call   103b <WireTrickleRequest_extract+0x37b>
    103f:	90                   	nop    

00001040 <DoUpcall>:

static inline void pre_init_sock(struct cminisock *msk, struct sk_buff *skb) {
	/* save the fields necessary for a later init_sock */
	if(!SIMULATION_MODE(msk->sk)) {
		msk->saddr = skb->nh.iph->daddr;
		msk->source = skb->h.th->dest;

		msk->daddr = skb->nh.iph->saddr;
		msk->dest = skb->h.th->source;
	}
}

#ifndef USERTEST
void DoUpcall(struct cminisock *msk, enum cminisock_event_tag event) {
    1040:	55                   	push   %ebp
    1041:	89 e5                	mov    %esp,%ebp
    1043:	57                   	push   %edi
    1044:	56                   	push   %esi
    1045:	53                   	push   %ebx
    1046:	83 ec 30             	sub    $0x30,%esp
	int i;
	struct NonceCtx ctx;
	if(!SIMULATION_MODE(msk->sk)) {
    1049:	8b 55 08             	mov    0x8(%ebp),%edx
    104c:	8b 42 20             	mov    0x20(%edx),%eax
    104f:	8b 90 a8 02 00 00    	mov    0x2a8(%eax),%edx
    1055:	f7 c2 01 00 00 00    	test   $0x1,%edx
    105b:	74 09                	je     1066 <DoUpcall+0x26>
    105d:	83 e2 08             	and    $0x8,%edx
    1060:	0f 84 b4 00 00 00    	je     111a <DoUpcall+0xda>
		ctx.new = 1;
    1066:	c7 45 d4 01 00 00 00 	movl   $0x1,0xffffffd4(%ebp)
		for(i=0; i < msk->num_packets; i++) {
    106d:	8b 55 08             	mov    0x8(%ebp),%edx
    1070:	31 ff                	xor    %edi,%edi
    1072:	3b ba dc 00 00 00    	cmp    0xdc(%edx),%edi
    1078:	7d 66                	jge    10e0 <DoUpcall+0xa0>
    107a:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi
			msk->packets[i].nonce = generateSingleNonce(msk->sk, msk->packets[i].seq, &ctx);
    1080:	8b 55 08             	mov    0x8(%ebp),%edx
    1083:	8d 1c bf             	lea    (%edi,%edi,4),%ebx
    1086:	47                   	inc    %edi
    1087:	c1 e3 03             	shl    $0x3,%ebx
    108a:	8b b2 e0 00 00 00    	mov    0xe0(%edx),%esi
    1090:	8d 55 d4             	lea    0xffffffd4(%ebp),%edx
    1093:	89 54 24 0c          	mov    %edx,0xc(%esp,1)
    1097:	8b 54 1e 04          	mov    0x4(%esi,%ebx,1),%edx
    109b:	c7 44 24 08 00 00 00 	movl   $0x0,0x8(%esp,1)
    10a2:	00 
    10a3:	89 04 24             	mov    %eax,(%esp,1)
    10a6:	89 54 24 04          	mov    %edx,0x4(%esp,1)
    10aa:	e8 fc ff ff ff       	call   10ab <DoUpcall+0x6b>
			msk->packets[i].ucontLen = 0;
			msk->packets[i].ucontData = NULL;
    10af:	31 c9                	xor    %ecx,%ecx
    10b1:	89 04 1e             	mov    %eax,(%esi,%ebx,1)
    10b4:	31 f6                	xor    %esi,%esi
    10b6:	8b 55 08             	mov    0x8(%ebp),%edx
    10b9:	8b 82 e0 00 00 00    	mov    0xe0(%edx),%eax
    10bf:	89 74 18 14          	mov    %esi,0x14(%eax,%ebx,1)
    10c3:	8b 82 e0 00 00 00    	mov    0xe0(%edx),%eax
    10c9:	89 4c 18 18          	mov    %ecx,0x18(%eax,%ebx,1)
    10cd:	3b ba dc 00 00 00    	cmp    0xdc(%edx),%edi
    10d3:	7d 08                	jge    10dd <DoUpcall+0x9d>
    10d5:	8b 55 08             	mov    0x8(%ebp),%edx
    10d8:	8b 42 20             	mov    0x20(%edx),%eax
    10db:	eb a3                	jmp    1080 <DoUpcall+0x40>
    10dd:	8b 42 20             	mov    0x20(%edx),%eax
		}
		queue_upcall_prealloc(msk->sk,event,msk);
    10e0:	89 04 24             	mov    %eax,(%esp,1)
    10e3:	8b 55 08             	mov    0x8(%ebp),%edx
    10e6:	89 54 24 08          	mov    %edx,0x8(%esp,1)
    10ea:	8b 55 0c             	mov    0xc(%ebp),%edx
    10ed:	89 54 24 04          	mov    %edx,0x4(%esp,1)
    10f1:	e8 fc ff ff ff       	call   10f2 <DoUpcall+0xb2>
		queue_upcall(event,msk);
    10f6:	8b 45 08             	mov    0x8(%ebp),%eax
    10f9:	8b 55 0c             	mov    0xc(%ebp),%edx
    10fc:	89 44 24 04          	mov    %eax,0x4(%esp,1)
    1100:	89 14 24             	mov    %edx,(%esp,1)
    1103:	e8 fc ff ff ff       	call   1104 <DoUpcall+0xc4>
		queue_upcall_deliver(msk->sk,msk);
    1108:	8b 45 08             	mov    0x8(%ebp),%eax
    110b:	89 44 24 04          	mov    %eax,0x4(%esp,1)
    110f:	8b 40 20             	mov    0x20(%eax),%eax
    1112:	89 04 24             	mov    %eax,(%esp,1)
    1115:	e8 fc ff ff ff       	call   1116 <DoUpcall+0xd6>
	}
 }
    111a:	83 c4 30             	add    $0x30,%esp
    111d:	5b                   	pop    %ebx
    111e:	5e                   	pop    %esi
    111f:	5f                   	pop    %edi
    1120:	5d                   	pop    %ebp
    1121:	c3                   	ret    
    1122:	8d b4 26 00 00 00 00 	lea    0x0(%esi,1),%esi
    1129:	8d bc 27 00 00 00 00 	lea    0x0(%edi,1),%edi

00001130 <server_rcv_impl>:
#endif

int server_rcv_impl(struct sock *sk, struct sk_buff *in_skb) {
    1130:	55                   	push   %ebp
    1131:	89 e5                	mov    %esp,%ebp
    1133:	57                   	push   %edi
    1134:	56                   	push   %esi
    1135:	53                   	push   %ebx
    1136:	83 ec 1c             	sub    $0x1c,%esp
	int rval = -EINVAL;
    1139:	c7 45 ec ea ff ff ff 	movl   $0xffffffea,0xffffffec(%ebp)
    1140:	8b 5d 0c             	mov    0xc(%ebp),%ebx
    1143:	8b 75 08             	mov    0x8(%ebp),%esi
	struct tcphdr *ith = in_skb->h.th;
    1146:	8b 43 20             	mov    0x20(%ebx),%eax
	struct tcp_opt *tp = &(sk->tp_pinfo.af_tcp);
    1149:	8d be bc 00 00 00    	lea    0xbc(%esi),%edi
    114f:	89 45 e8             	mov    %eax,0xffffffe8(%ebp)
	struct cminisock *msk;

	TIMING_CTX_DEF0("server_rcv_impl", "");
	TIMING_CTX_DEF1(4);
	reinitTimingCtx(&ctx);
	recordSample(&ctx,0);

	if(!SIMULATION_MODE(sk) && !TRICKLES_USERAPI_CONFIGURED_TP(tp)) {
    1152:	8b 86 a8 02 00 00    	mov    0x2a8(%esi),%eax
    1158:	a9 01 00 00 00       	test   $0x1,%eax
    115d:	74 05                	je     1164 <server_rcv_impl+0x34>
    115f:	83 e0 08             	and    $0x8,%eax
    1162:	74 0e                	je     1172 <server_rcv_impl+0x42>
    1164:	8b 87 d0 01 00 00    	mov    0x1d0(%edi),%eax
    116a:	85 c0                	test   %eax,%eax
    116c:	0f 84 c2 02 00 00    	je     1434 <server_rcv_impl+0x304>
		printk("Not configured\n");
		goto out;
	}

	msk = alloc_trickles_msk(sk);
    1172:	89 34 24             	mov    %esi,(%esp,1)
    1175:	e8 f6 1f 00 00       	call   3170 <alloc_trickles_msk>
    117a:	89 45 f0             	mov    %eax,0xfffffff0(%ebp)

        if(msk == NULL) {
    117d:	85 c0                	test   %eax,%eax
    117f:	0f 85 bb 00 00 00    	jne    1240 <server_rcv_impl+0x110>
		if(trickles_ratelimit())
    1185:	a1 00 00 00 00       	mov    0x0,%eax
    118a:	9c                   	pushf  
    118b:	59                   	pop    %ecx
    118c:	fa                   	cli    
    118d:	89 c2                	mov    %eax,%edx
    118f:	8b 35 40 e2 04 00    	mov    0x4e240,%esi
    1195:	8b 1d 34 00 00 00    	mov    0x34,%ebx
    119b:	a3 40 e2 04 00       	mov    %eax,0x4e240
    11a0:	29 f2                	sub    %esi,%edx
    11a2:	01 da                	add    %ebx,%edx
    11a4:	89 15 34 00 00 00    	mov    %edx,0x34
    11aa:	81 fa 88 13 00 00    	cmp    $0x1388,%edx
    11b0:	76 0f                	jbe    11c1 <server_rcv_impl+0x91>
    11b2:	b8 88 13 00 00       	mov    $0x1388,%eax
    11b7:	ba 88 13 00 00       	mov    $0x1388,%edx
    11bc:	a3 34 00 00 00       	mov    %eax,0x34
    11c1:	81 fa f3 01 00 00    	cmp    $0x1f3,%edx
    11c7:	76 67                	jbe    1230 <server_rcv_impl+0x100>
    11c9:	31 ff                	xor    %edi,%edi
    11cb:	81 ea f4 01 00 00    	sub    $0x1f4,%edx
    11d1:	a1 44 e2 04 00       	mov    0x4e244,%eax
    11d6:	89 15 34 00 00 00    	mov    %edx,0x34
    11dc:	89 3d 44 e2 04 00    	mov    %edi,0x4e244
    11e2:	51                   	push   %ecx
    11e3:	9d                   	popf   
    11e4:	85 c0                	test   %eax,%eax
    11e6:	75 26                	jne    120e <server_rcv_impl+0xde>
    11e8:	b8 01 00 00 00       	mov    $0x1,%eax
    11ed:	85 c0                	test   %eax,%eax
    11ef:	75 0f                	jne    1200 <server_rcv_impl+0xd0>
			printk("could not allocate minisock\n");
		goto out;
        }

	msk->sk = sk;
	in_skb->sk = sk;
	pre_init_sock(msk,in_skb);

	recordSample(&ctx,0);
	if(SIMULATION_MODE(sk)) {
		goto normal;
	}
	if(ith->syn) {
		__u32 firstSeq;
		/* SYN packet format:
		 * Initial request continuation immediately follows TCP
		 * header
		 */
		if(ith->ack) {
			printk("warning: trickles server cannot handle syn/ack\n");
		}
		firstSeq = 1; // XXX Should be randomized
		if(!alloc_msk_packets(msk, 1)) {
			goto out;
		}
		makePacket(&msk->packets[0], firstSeq, 1, MTU, 
			   -1, PTYPE_FIRST | PACKET_NORMAL, CONTTYPE_FULL1,
			   1 * MTU,  firstSeq + 1, 1);
		/* xxx Should Trickles allow data on SYN packets */
		msk->ucont_len = 0;

		msk->clientState = -1;
		msk->mrtt = 0;

		// these values (firstLoss, firstBootstrapSeq) are not used in normal state ( syn/ack )
		msk->firstLoss = 0x1055;
		msk->firstBootstrapSeq = 0xb007;
		msk->startCwnd = 1;
		msk->ssthresh = 0x3fff; // small enough to prevent overflow when squaring
		//msk->ssthresh = 0x100;
		msk->TCPBase = msk->packets[0].seq;
		msk->tokenCounterBase = tp->bigTokenCounter;
		tp->bigTokenCounter += ((__u64) 1)  << 32;

		DoUpcall(msk, SYN);

#if 0
		// Automatic packet generation
		tp->t.dbg_skb = skb_copy(in_skb, GFP_ATOMIC);
		tp->t.slowstart_timer.function = &testTimer;
		tp->t.slowstart_timer.data = (long)sk;
		resetClientTimer(sk);
#endif
	} else if(ith->fin) {
		/* FIN packet format:
		   WireTrickleRequest */
		/* Sequence number generation */
		recordSample(&ctx,0);
		if((rval = ExecuteTrickle(&msk, in_skb, FIN))) {
			goto out_dealloc_msk;
		}
	} else if(ith->rst) {
		/* TODO: Implement reset handling */
		goto out_dealloc_msk;	
	} else {
	normal:
		/* normal operation */
		recordSample(&ctx,0);
		if((rval = ExecuteTrickle(&msk, in_skb, ACK))) {
			goto out_dealloc_msk;
		}
	}
	recordSample(&ctx,0);
	//printTimings(&ctx);
	return 0;
 out_dealloc_msk:
	if(rval != -ENOMEM) {
		// ENOMEM deallocates msk in callees. This is a hostorical artifact
		free_trickles_msk(sk,msk);
		free_trickles_msk_finish(sk,msk);
	}
 out:
	return rval;
    11f1:	8b 45 ec             	mov    0xffffffec(%ebp),%eax
}
    11f4:	83 c4 1c             	add    $0x1c,%esp
    11f7:	5b                   	pop    %ebx
    11f8:	5e                   	pop    %esi
    11f9:	5f                   	pop    %edi
    11fa:	5d                   	pop    %ebp
    11fb:	c3                   	ret    
    11fc:	8d 74 26 00          	lea    0x0(%esi,1),%esi
    1200:	c7 04 24 78 00 00 00 	movl   $0x78,(%esp,1)
    1207:	e8 fc ff ff ff       	call   1208 <server_rcv_impl+0xd8>
    120c:	eb e3                	jmp    11f1 <server_rcv_impl+0xc1>
    120e:	89 44 24 0c          	mov    %eax,0xc(%esp,1)
    1212:	c7 44 24 08 36 02 00 	movl   $0x236,0x8(%esp,1)
    1219:	00 
    121a:	c7 44 24 04 45 00 00 	movl   $0x45,0x4(%esp,1)
    1221:	00 
    1222:	c7 04 24 80 00 00 00 	movl   $0x80,(%esp,1)
    1229:	e8 fc ff ff ff       	call   122a <server_rcv_impl+0xfa>
    122e:	eb b8                	jmp    11e8 <server_rcv_impl+0xb8>
    1230:	ff 05 44 e2 04 00    	incl   0x4e244
    1236:	51                   	push   %ecx
    1237:	9d                   	popf   
    1238:	31 c0                	xor    %eax,%eax
    123a:	eb b1                	jmp    11ed <server_rcv_impl+0xbd>
    123c:	8d 74 26 00          	lea    0x0(%esi,1),%esi
    1240:	89 70 20             	mov    %esi,0x20(%eax)
    1243:	89 73 0c             	mov    %esi,0xc(%ebx)
    1246:	8b 55 f0             	mov    0xfffffff0(%ebp),%edx
    1249:	8b 42 20             	mov    0x20(%edx),%eax
    124c:	8b 80 a8 02 00 00    	mov    0x2a8(%eax),%eax
    1252:	a9 01 00 00 00       	test   $0x1,%eax
    1257:	74 05                	je     125e <server_rcv_impl+0x12e>
    1259:	83 e0 08             	and    $0x8,%eax
    125c:	74 27                	je     1285 <server_rcv_impl+0x155>
    125e:	8b 43 24             	mov    0x24(%ebx),%eax
    1261:	8b 40 10             	mov    0x10(%eax),%eax
    1264:	89 42 14             	mov    %eax,0x14(%edx)
    1267:	8b 43 20             	mov    0x20(%ebx),%eax
    126a:	0f b7 40 02          	movzwl 0x2(%eax),%eax
    126e:	66 89 42 1c          	mov    %ax,0x1c(%edx)
    1272:	8b 43 24             	mov    0x24(%ebx),%eax
    1275:	8b 40 0c             	mov    0xc(%eax),%eax
    1278:	89 42 18             	mov    %eax,0x18(%edx)
    127b:	8b 43 20             	mov    0x20(%ebx),%eax
    127e:	0f b7 00             	movzwl (%eax),%eax
    1281:	66 89 42 1e          	mov    %ax,0x1e(%edx)
    1285:	8b 86 a8 02 00 00    	mov    0x2a8(%esi),%eax
    128b:	a9 01 00 00 00       	test   $0x1,%eax
    1290:	74 09                	je     129b <server_rcv_impl+0x16b>
    1292:	83 e0 08             	and    $0x8,%eax
    1295:	0f 84 44 01 00 00    	je     13df <server_rcv_impl+0x2af>
    129b:	8b 45 e8             	mov    0xffffffe8(%ebp),%eax
    129e:	0f b6 50 0d          	movzbl 0xd(%eax),%edx
    12a2:	88 d0                	mov    %dl,%al
    12a4:	24 02                	and    $0x2,%al
    12a6:	84 c0                	test   %al,%al
    12a8:	0f 84 22 01 00 00    	je     13d0 <server_rcv_impl+0x2a0>
    12ae:	80 e2 10             	and    $0x10,%dl
    12b1:	84 d2                	test   %dl,%dl
    12b3:	0f 85 03 01 00 00    	jne    13bc <server_rcv_impl+0x28c>
    12b9:	c7 44 24 04 01 00 00 	movl   $0x1,0x4(%esp,1)
    12c0:	00 
    12c1:	8b 45 f0             	mov    0xfffffff0(%ebp),%eax
    12c4:	89 04 24             	mov    %eax,(%esp,1)
    12c7:	e8 84 1c 00 00       	call   2f50 <alloc_msk_packets>
    12cc:	85 c0                	test   %eax,%eax
    12ce:	0f 84 1d ff ff ff    	je     11f1 <server_rcv_impl+0xc1>
			      __u8 type, 
			      __u8 contType, 
			      __u16 minResponseLen,
			      __u32 firstTransportChild, 
			      __u8 numTransportChildren) {
    12d4:	8b 45 f0             	mov    0xfffffff0(%ebp),%eax
    12d7:	8b 90 e0 00 00 00    	mov    0xe0(%eax),%edx
  pkt->nonce = -1;
  pkt->seq = seq;
  //pkt->ack_seq = ack_seq;
  pkt->len = len;
  pkt->byteNum = byteNum;
  pkt->type = type;
  pkt->contType = contType;
    12dd:	0f b6 42 10          	movzbl 0x10(%edx),%eax
    12e1:	c7 42 04 01 00 00 00 	movl   $0x1,0x4(%edx)
    12e8:	c7 02 ff ff ff ff    	movl   $0xffffffff,(%edx)
    12ee:	c7 42 08 52 05 00 00 	movl   $0x552,0x8(%edx)
    12f5:	24 c0                	and    $0xc0,%al
    12f7:	0c 08                	or     $0x8,%al
    12f9:	88 42 10             	mov    %al,0x10(%edx)
    12fc:	c7 42 0c ff ff ff ff 	movl   $0xffffffff,0xc(%edx)
  pkt->minResponseLen = minResponseLen;
    1303:	66 c7 42 1c 52 05    	movw   $0x552,0x1c(%edx)
  pkt->firstTransportChild = firstTransportChild;
    1309:	c7 42 20 02 00 00 00 	movl   $0x2,0x20(%edx)
  pkt->numTransportChildren = numTransportChildren;
    1310:	c6 42 24 01          	movb   $0x1,0x24(%edx)
  pkt->ucontLen = 0;
    1314:	c7 42 14 00 00 00 00 	movl   $0x0,0x14(%edx)
  pkt->ucontData = NULL;
    131b:	c7 42 18 00 00 00 00 	movl   $0x0,0x18(%edx)
  pkt->numSiblings = -1;
    1322:	c6 42 11 ff          	movb   $0xff,0x11(%edx)
  pkt->position = INVALID_POSITION;
    1326:	c6 42 12 ff          	movb   $0xff,0x12(%edx)
    132a:	8b 45 f0             	mov    0xfffffff0(%ebp),%eax
    132d:	c7 40 7c 00 00 00 00 	movl   $0x0,0x7c(%eax)
    1334:	8b 45 f0             	mov    0xfffffff0(%ebp),%eax
    1337:	c7 40 3c ff ff ff ff 	movl   $0xffffffff,0x3c(%eax)
    133e:	8b 45 f0             	mov    0xfffffff0(%ebp),%eax
    1341:	c7 40 54 00 00 00 00 	movl   $0x0,0x54(%eax)
    1348:	8b 45 f0             	mov    0xfffffff0(%ebp),%eax
    134b:	c7 40 60 55 10 00 00 	movl   $0x1055,0x60(%eax)
    1352:	8b 45 f0             	mov    0xfffffff0(%ebp),%eax
    1355:	c7 40 64 07 b0 00 00 	movl   $0xb007,0x64(%eax)
    135c:	8b 45 f0             	mov    0xfffffff0(%ebp),%eax
    135f:	c7 40 68 01 00 00 00 	movl   $0x1,0x68(%eax)
    1366:	8b 45 f0             	mov    0xfffffff0(%ebp),%eax
    1369:	c7 40 6c ff 3f 00 00 	movl   $0x3fff,0x6c(%eax)
    1370:	8b 55 f0             	mov    0xfffffff0(%ebp),%edx
    1373:	8b 82 e0 00 00 00    	mov    0xe0(%edx),%eax
    1379:	8b 40 04             	mov    0x4(%eax),%eax
    137c:	89 42 70             	mov    %eax,0x70(%edx)
    137f:	8b 87 f0 01 00 00    	mov    0x1f0(%edi),%eax
    1385:	8b 97 f4 01 00 00    	mov    0x1f4(%edi),%edx
    138b:	8b 4d f0             	mov    0xfffffff0(%ebp),%ecx
    138e:	89 41 74             	mov    %eax,0x74(%ecx)
    1391:	89 51 78             	mov    %edx,0x78(%ecx)
    1394:	83 87 f0 01 00 00 00 	addl   $0x0,0x1f0(%edi)
    139b:	83 97 f4 01 00 00 01 	adcl   $0x1,0x1f4(%edi)
    13a2:	c7 44 24 04 00 00 00 	movl   $0x0,0x4(%esp,1)
    13a9:	00 
    13aa:	8b 45 f0             	mov    0xfffffff0(%ebp),%eax
    13ad:	89 04 24             	mov    %eax,(%esp,1)
    13b0:	e8 fc ff ff ff       	call   13b1 <server_rcv_impl+0x281>
    13b5:	31 c0                	xor    %eax,%eax
    13b7:	e9 38 fe ff ff       	jmp    11f4 <server_rcv_impl+0xc4>
    13bc:	c7 04 24 20 02 00 00 	movl   $0x220,(%esp,1)
    13c3:	e8 fc ff ff ff       	call   13c4 <server_rcv_impl+0x294>
    13c8:	e9 ec fe ff ff       	jmp    12b9 <server_rcv_impl+0x189>
    13cd:	8d 76 00             	lea    0x0(%esi),%esi
    13d0:	88 d0                	mov    %dl,%al
    13d2:	24 01                	and    $0x1,%al
    13d4:	84 c0                	test   %al,%al
    13d6:	75 52                	jne    142a <server_rcv_impl+0x2fa>
    13d8:	80 e2 04             	and    $0x4,%dl
    13db:	84 d2                	test   %dl,%dl
    13dd:	75 1e                	jne    13fd <server_rcv_impl+0x2cd>
    13df:	c7 44 24 08 01 00 00 	movl   $0x1,0x8(%esp,1)
    13e6:	00 
    13e7:	89 5c 24 04          	mov    %ebx,0x4(%esp,1)
    13eb:	8d 45 f0             	lea    0xfffffff0(%ebp),%eax
    13ee:	89 04 24             	mov    %eax,(%esp,1)
    13f1:	e8 4a 00 00 00       	call   1440 <ExecuteTrickle>
    13f6:	89 45 ec             	mov    %eax,0xffffffec(%ebp)
    13f9:	85 c0                	test   %eax,%eax
    13fb:	74 b8                	je     13b5 <server_rcv_impl+0x285>
    13fd:	83 7d ec f4          	cmpl   $0xfffffff4,0xffffffec(%ebp)
    1401:	0f 84 ea fd ff ff    	je     11f1 <server_rcv_impl+0xc1>
    1407:	89 34 24             	mov    %esi,(%esp,1)
    140a:	8b 45 f0             	mov    0xfffffff0(%ebp),%eax
    140d:	89 44 24 04          	mov    %eax,0x4(%esp,1)
    1411:	e8 ea eb ff ff       	call   0 <free_trickles_msk>
    1416:	8b 45 f0             	mov    0xfffffff0(%ebp),%eax
    1419:	89 34 24             	mov    %esi,(%esp,1)
    141c:	89 44 24 04          	mov    %eax,0x4(%esp,1)
    1420:	e8 7b ec ff ff       	call   a0 <free_trickles_msk_finish>
    1425:	e9 c7 fd ff ff       	jmp    11f1 <server_rcv_impl+0xc1>
    142a:	c7 44 24 08 02 00 00 	movl   $0x2,0x8(%esp,1)
    1431:	00 
    1432:	eb b3                	jmp    13e7 <server_rcv_impl+0x2b7>
    1434:	c7 04 24 95 00 00 00 	movl   $0x95,(%esp,1)
    143b:	e9 c7 fd ff ff       	jmp    1207 <server_rcv_impl+0xd7>

00001440 <ExecuteTrickle>:

#if 0
#define SIMULATIONMODE_INIT() int simPrintCount = 0
#define SIMULATIONMODE_PRINT() if(SIMULATION_MODE(skb->sk)) /*printk("simulation mode : %d\n", simPrintCount++)*/ 
#else
#define SIMULATIONMODE_INIT()
#define SIMULATIONMODE_PRINT()
#endif

static int ExecuteTrickle(struct cminisock **cont, struct sk_buff *skb, enum cminisock_event_tag event) {
    1440:	55                   	push   %ebp
    1441:	89 e5                	mov    %esp,%ebp
  int rval = -EINVAL;
    1443:	b8 ea ff ff ff       	mov    $0xffffffea,%eax
    1448:	57                   	push   %edi

  int error;
  AckProof ackProof;
  WireTrickleRequest *treq_hdr = WireTrickleRequest_extract(*cont, skb, &error);
  enum CheckRangeResult rangeCheck;

  SIMULATIONMODE_INIT();

  TIMING_CTX_DEF0("ExecuteTrickle", "");
  TIMING_CTX_DEF1(7);
  reinitTimingCtx(&ctx);
  recordSample(&ctx,0);
  (*cont)->executionTrace = 0;
    1449:	31 ff                	xor    %edi,%edi
    144b:	56                   	push   %esi
    144c:	53                   	push   %ebx
    144d:	81 ec 28 03 00 00    	sub    $0x328,%esp
    1453:	89 85 dc fc ff ff    	mov    %eax,0xfffffcdc(%ebp)
    1459:	8d 85 e0 fc ff ff    	lea    0xfffffce0(%ebp),%eax
    145f:	8b 55 08             	mov    0x8(%ebp),%edx
    1462:	89 44 24 08          	mov    %eax,0x8(%esp,1)
    1466:	8b 45 0c             	mov    0xc(%ebp),%eax
    1469:	89 44 24 04          	mov    %eax,0x4(%esp,1)
    146d:	8b 02                	mov    (%edx),%eax
    146f:	89 04 24             	mov    %eax,(%esp,1)
    1472:	e8 fc ff ff ff       	call   1473 <ExecuteTrickle+0x33>
    1477:	8b 4d 08             	mov    0x8(%ebp),%ecx
    147a:	89 c6                	mov    %eax,%esi

  if(treq_hdr == NULL) {
    147c:	85 f6                	test   %esi,%esi
    147e:	8b 01                	mov    (%ecx),%eax
    1480:	89 b8 d0 00 00 00    	mov    %edi,0xd0(%eax)
    1486:	0f 84 c4 04 00 00    	je     1950 <ExecuteTrickle+0x510>
    if(error == EINVAL) {
      if(trickles_ratelimit()) {
	printk("ExecuteTrickle: Could not find request header\n");
      }
      return -EINVAL;
    } else {
      BUG_TRAP(error == ENOMEM);
      return -ENOMEM;
    }
  }
  
  if(!unmarshallContinuationServer(skb, *cont, &treq_hdr->cont)) {
    148c:	8b 55 08             	mov    0x8(%ebp),%edx
    148f:	8d 46 01             	lea    0x1(%esi),%eax
    1492:	8b 4d 0c             	mov    0xc(%ebp),%ecx
    1495:	89 44 24 08          	mov    %eax,0x8(%esp,1)
    1499:	8b 02                	mov    (%edx),%eax
    149b:	89 0c 24             	mov    %ecx,(%esp,1)
    149e:	89 44 24 04          	mov    %eax,0x4(%esp,1)
    14a2:	e8 d9 ed ff ff       	call   280 <unmarshallContinuationServer>
    14a7:	85 c0                	test   %eax,%eax
    14a9:	0f 85 b9 00 00 00    	jne    1568 <ExecuteTrickle+0x128>
    /* MAC error */
	  if(trickles_ratelimit())
    14af:	a1 00 00 00 00       	mov    0x0,%eax
    14b4:	9c                   	pushf  
    14b5:	59                   	pop    %ecx
    14b6:	fa                   	cli    
    14b7:	89 c2                	mov    %eax,%edx
    14b9:	8b 1d 50 e2 04 00    	mov    0x4e250,%ebx
    14bf:	8b 3d 3c 00 00 00    	mov    0x3c,%edi
    14c5:	a3 50 e2 04 00       	mov    %eax,0x4e250
    14ca:	29 da                	sub    %ebx,%edx
    14cc:	01 fa                	add    %edi,%edx
    14ce:	89 15 3c 00 00 00    	mov    %edx,0x3c
    14d4:	81 fa 88 13 00 00    	cmp    $0x1388,%edx
    14da:	76 10                	jbe    14ec <ExecuteTrickle+0xac>
    14dc:	be 88 13 00 00       	mov    $0x1388,%esi
    14e1:	ba 88 13 00 00       	mov    $0x1388,%edx
    14e6:	89 35 3c 00 00 00    	mov    %esi,0x3c
    14ec:	81 fa f3 01 00 00    	cmp    $0x1f3,%edx
    14f2:	76 68                	jbe    155c <ExecuteTrickle+0x11c>
    14f4:	31 db                	xor    %ebx,%ebx
    14f6:	81 ea f4 01 00 00    	sub    $0x1f4,%edx
    14fc:	a1 54 e2 04 00       	mov    0x4e254,%eax
    1501:	89 15 3c 00 00 00    	mov    %edx,0x3c
    1507:	89 1d 54 e2 04 00    	mov    %ebx,0x4e254
    150d:	51                   	push   %ecx
    150e:	9d                   	popf   
    150f:	85 c0                	test   %eax,%eax
    1511:	75 27                	jne    153a <ExecuteTrickle+0xfa>
    1513:	b8 01 00 00 00       	mov    $0x1,%eax
    1518:	85 c0                	test   %eax,%eax
    151a:	75 10                	jne    152c <ExecuteTrickle+0xec>
		  printk("Mac error\n");
    return -EINVAL;
  }
  recordSample(&ctx,0);
  SIMULATIONMODE_PRINT();
  unmarshallAckProof(&ackProof, &treq_hdr->ackProof);
  ackProof.cont = *cont;
  recordSample(&ctx,0);
  if(!SIMULATION_MODE((*cont)->sk) && !AckProof_validate(&ackProof)) {
    /* Bad nonce, or doesn't start at TCPBase */
    if(SIMULATION_MODE(skb->sk)  && debugSimulation)
      printk("ackproof validation failed\n");
    return -EINVAL;
  }

  SIMULATIONMODE_PRINT();
  recordSample(&ctx,0);
  if(serverDebugLevel >= 2) {
    printk("Server processing: %u\n", (*cont)->seq);
    AckProof_dump(&ackProof);
  }

  /* Determine continuation mode */
  SIMULATIONMODE_PRINT();
  rangeCheck = AckProof_checkRange(&ackProof, (*cont)->TCPBase, (*cont)->seq);
  recordSample(&ctx,0);

  switch((enum TrickleRequestType)treq_hdr->type) {
  case TREQ_NORMAL: {
    // mrtt_1 = mrtt_0 * 7/8 + delta * 1/8
    (*cont)->mrtt -= (*cont)->mrtt >> 3;
    (*cont)->mrtt += jiffies - (*cont)->timestamp;
    switch((*cont)->state) {
    case CONT_NORMAL:
      if(serverDebugLevel >= 2)
        printk("Normal request => Normal state\n");
      switch(rangeCheck) {
      case NORMALRANGE:
	if(serverDebugLevel >= 2)
	  printk("  Normal Range\n");
	SIMULATIONMODE_PRINT();
#ifdef STOMP_CONNECTIONS
#define STOMP()								\
	if(!SIMULATION_MODE(skb->sk) &&					\
           (*cont)->seq - (*cont)->TCPBase >= STOMP_CONNECTIONS) {	\
	/* if(trickles_ratelimit()) {				\
		  printk("Stomping connection from %X:%d\n", (*cont)->daddr, (*cont)->dest); \
	  } */							\
	  return -EINVAL;							\
	}
#else
#define STOMP()
#endif
        STOMP();
	rval = DoNormalStep(cont, &ackProof, event);
	recordSample(&ctx,0);
	break;
      case POISONEDRANGE:
      case BADRANGE:
	if(serverDebugLevel >= 2) {
	  printk("  Bad or poisoned Range (ack # %u)\n", (*cont)->seq);
	  AckProof_dump(&ackProof);
	}
	rval = DoRecoveryStep(cont, &ackProof, event);
	break;
      }
      break;
    case CONT_RECOVERY:
      if(serverDebugLevel >= 1)
	printk("Normal request => Recovery state\n");
      switch(rangeCheck) {
      default:
	// no action
	break;
      }
      break;
    case CONT_BOOTSTRAP:
      if(serverDebugLevel >= 1)
	printk("Normal request => Bootstrap state\n");
      switch(rangeCheck) {
      case POISONEDRANGE:
	if(serverDebugLevel >= 1)
	  printk("  Poisoned Range\n");
	// check that poison is only during recovery interval
	if(!(AckProof_checkRange(&ackProof, (*cont)->TCPBase, (*cont)->firstLoss-1) == NORMALRANGE
	     && AckProof_checkRange(&ackProof, (*cont)->firstBootstrapSeq, (*cont)->seq) == NORMALRANGE)) {
	  ERROR("poisoned packets where normal packets should be\n");
	  goto slow_start;
	}
      case NORMALRANGE:
	if(serverDebugLevel >= 1)
	  printk("  Normal Range\n");
	(*cont)->TCPBase = (*cont)->firstBootstrapSeq;
	if(serverDebugLevel >= 1)
	  printk("Bootstrap: TCPBase = %u CWND = %u SSTHRESH = %u\n", (*cont)->TCPBase, (*cont)->startCwnd, (*cont)->ssthresh);
	STOMP();
	rval = DoNormalStep(cont, &ackProof, event);
	break;
      case BADRANGE:
	if(serverDebugLevel >= 1)
	  printk("  Bad Range\n");
      slow_start:
	if(serverDebugLevel >= 1) {
		printk("slow start bad range: ");
		AckProof_dump(&ackProof);
	}
	rval = DoRecoveryStep(cont, &ackProof, event);
	break;
      default:
	printk("  unknown state\n");
	return -EINVAL;
      }
      break;
    }
    break;
  }
  case TREQ_SLOWSTART: {
    __u32 seq;
    (*cont)->mrtt = (jiffies - (*cont)->timestamp) << 3;
    if(serverDebugLevel >= 1) {
      printk("Slow Start request => \n");
      AckProof_dump(&ackProof);
    }
    seq = AckProof_findRight(&ackProof, (*cont)->TCPBase);
    if(seq < (*cont)->TCPBase) {
	    printk("  SlowStart: seq < (*cont)->TCPBase\n");
	    return -EINVAL;
    151c:	b8 ea ff ff ff       	mov    $0xffffffea,%eax
    }
    rval = DoSlowStartStep(cont, &ackProof, seq + 1, event);
    break;
  }
  default:
    printk("  unknown request type\n");
  }

  recordSample(&ctx,0);
  //printTimings(&ctx);
  return rval;
}
    1521:	81 c4 28 03 00 00    	add    $0x328,%esp
    1527:	5b                   	pop    %ebx
    1528:	5e                   	pop    %esi
    1529:	5f                   	pop    %edi
    152a:	5d                   	pop    %ebp
    152b:	c3                   	ret    
    152c:	c7 04 24 a5 00 00 00 	movl   $0xa5,(%esp,1)
    1533:	e8 fc ff ff ff       	call   1534 <ExecuteTrickle+0xf4>
    1538:	eb e2                	jmp    151c <ExecuteTrickle+0xdc>
    153a:	89 44 24 0c          	mov    %eax,0xc(%esp,1)
    153e:	c7 44 24 08 b2 02 00 	movl   $0x2b2,0x8(%esp,1)
    1545:	00 
    1546:	c7 44 24 04 45 00 00 	movl   $0x45,0x4(%esp,1)
    154d:	00 
    154e:	c7 04 24 80 00 00 00 	movl   $0x80,(%esp,1)
    1555:	e8 fc ff ff ff       	call   1556 <ExecuteTrickle+0x116>
    155a:	eb b7                	jmp    1513 <ExecuteTrickle+0xd3>
    155c:	ff 05 54 e2 04 00    	incl   0x4e254
    1562:	51                   	push   %ecx
    1563:	9d                   	popf   
    1564:	31 c0                	xor    %eax,%eax
    1566:	eb b0                	jmp    1518 <ExecuteTrickle+0xd8>
static inline void unmarshallAckProof(AckProof *dproof, const WireAckProof *sproof) {
#define NHCONVERTLONG(X) dproof->X = ntohl(sproof->X);
#define COPYLONG(X) dproof->X = sproof->X
  int i;
  dproof->numSacks = sproof->numSacks;
    1568:	0f b6 46 4d          	movzbl 0x4d(%esi),%eax
  for(i=0; i < sproof->numSacks; i++) {
    156c:	31 db                	xor    %ebx,%ebx
    156e:	8d bd e4 fc ff ff    	lea    0xfffffce4(%ebp),%edi
    1574:	8d 4e 4d             	lea    0x4d(%esi),%ecx
    1577:	89 85 e4 fc ff ff    	mov    %eax,0xfffffce4(%ebp)
    157d:	80 7e 4d 00          	cmpb   $0x0,0x4d(%esi)
    1581:	74 34                	je     15b7 <ExecuteTrickle+0x177>
    1583:	31 d2                	xor    %edx,%edx
    1585:	8d 74 26 00          	lea    0x0(%esi,1),%esi
    1589:	8d bc 27 00 00 00 00 	lea    0x0(%edi,1),%edi
	__arch__swab24s(addr);
}

static __inline__ __const__ __u32 __fswab32(__u32 x)
{
    1590:	8b 44 11 01          	mov    0x1(%ecx,%edx,1),%eax
#define NHCONVERTLONG(X) dproof->X = ntohl(sproof->X);
#define COPYLONG(X) dproof->X = sproof->X
  int i;
  dproof->numSacks = sproof->numSacks;
  for(i=0; i < sproof->numSacks; i++) {
    1594:	43                   	inc    %ebx

static __inline__ __const__ __u32 ___arch__swab32(__u32 x)
{
#ifdef CONFIG_X86_BSWAP
	__asm__("bswap %0" : "=r" (x) : "0" (x));
    1595:	0f c8                	bswap  %eax
	__arch__swab24s(addr);
}

static __inline__ __const__ __u32 __fswab32(__u32 x)
{
    1597:	89 44 17 08          	mov    %eax,0x8(%edi,%edx,1)
    159b:	8b 44 11 05          	mov    0x5(%ecx,%edx,1),%eax

static __inline__ __const__ __u32 ___arch__swab32(__u32 x)
{
#ifdef CONFIG_X86_BSWAP
	__asm__("bswap %0" : "=r" (x) : "0" (x));
    159f:	0f c8                	bswap  %eax
	__arch__swab24s(addr);
}

static __inline__ __const__ __u32 __fswab32(__u32 x)
{
    15a1:	89 44 17 0c          	mov    %eax,0xc(%edi,%edx,1)
  dproof->numSacks = sproof->numSacks;
  for(i=0; i < sproof->numSacks; i++) {
    NHCONVERTLONG(sacks[i].left);
    NHCONVERTLONG(sacks[i].right);
    COPYLONG(sacks[i].nonceSummary);
    15a5:	8b 44 11 09          	mov    0x9(%ecx,%edx,1),%eax
    15a9:	89 44 17 10          	mov    %eax,0x10(%edi,%edx,1)
    15ad:	83 c2 0c             	add    $0xc,%edx
    15b0:	0f b6 01             	movzbl (%ecx),%eax
    15b3:	39 c3                	cmp    %eax,%ebx
    15b5:	7c d9                	jl     1590 <ExecuteTrickle+0x150>
    15b7:	8b 45 08             	mov    0x8(%ebp),%eax
    15ba:	8b 10                	mov    (%eax),%edx
    15bc:	89 95 e8 fc ff ff    	mov    %edx,0xfffffce8(%ebp)
    15c2:	8b 42 20             	mov    0x20(%edx),%eax
    15c5:	8b 80 a8 02 00 00    	mov    0x2a8(%eax),%eax
    15cb:	a9 01 00 00 00       	test   $0x1,%eax
    15d0:	74 05                	je     15d7 <ExecuteTrickle+0x197>
    15d2:	83 e0 08             	and    $0x8,%eax
    15d5:	74 4e                	je     1625 <ExecuteTrickle+0x1e5>
    15d7:	89 3c 24             	mov    %edi,(%esp,1)
    15da:	e8 fc ff ff ff       	call   15db <ExecuteTrickle+0x19b>
    15df:	85 c0                	test   %eax,%eax
    15e1:	75 3d                	jne    1620 <ExecuteTrickle+0x1e0>
    15e3:	8b 55 0c             	mov    0xc(%ebp),%edx
    15e6:	8b 42 0c             	mov    0xc(%edx),%eax
    15e9:	8b 80 a8 02 00 00    	mov    0x2a8(%eax),%eax
    15ef:	a9 01 00 00 00       	test   $0x1,%eax
    15f4:	0f 84 22 ff ff ff    	je     151c <ExecuteTrickle+0xdc>
    15fa:	83 e0 08             	and    $0x8,%eax
    15fd:	0f 85 19 ff ff ff    	jne    151c <ExecuteTrickle+0xdc>
    1603:	8b 3d 00 00 00 00    	mov    0x0,%edi
    1609:	85 ff                	test   %edi,%edi
    160b:	0f 84 0b ff ff ff    	je     151c <ExecuteTrickle+0xdc>
    1611:	c7 04 24 b0 00 00 00 	movl   $0xb0,(%esp,1)
    1618:	e9 16 ff ff ff       	jmp    1533 <ExecuteTrickle+0xf3>
    161d:	8d 76 00             	lea    0x0(%esi),%esi
    1620:	8b 4d 08             	mov    0x8(%ebp),%ecx
    1623:	8b 11                	mov    (%ecx),%edx
    1625:	83 3d 00 00 00 00 01 	cmpl   $0x1,0x0
    162c:	0f 8f f7 02 00 00    	jg     1929 <ExecuteTrickle+0x4e9>
    1632:	8b 42 34             	mov    0x34(%edx),%eax
    1635:	89 44 24 08          	mov    %eax,0x8(%esp,1)
    1639:	8b 42 70             	mov    0x70(%edx),%eax
    163c:	89 3c 24             	mov    %edi,(%esp,1)
    163f:	89 44 24 04          	mov    %eax,0x4(%esp,1)
    1643:	e8 fc ff ff ff       	call   1644 <ExecuteTrickle+0x204>
    1648:	89 c3                	mov    %eax,%ebx
    164a:	0f b6 06             	movzbl (%esi),%eax
    164d:	85 c0                	test   %eax,%eax
    164f:	0f 84 a0 00 00 00    	je     16f5 <ExecuteTrickle+0x2b5>
    1655:	48                   	dec    %eax
    1656:	74 17                	je     166f <ExecuteTrickle+0x22f>
    1658:	c7 04 24 cc 00 00 00 	movl   $0xcc,(%esp,1)
    165f:	e8 fc ff ff ff       	call   1660 <ExecuteTrickle+0x220>
    1664:	8b 85 dc fc ff ff    	mov    0xfffffcdc(%ebp),%eax
    166a:	e9 b2 fe ff ff       	jmp    1521 <ExecuteTrickle+0xe1>
    166f:	8b 4d 08             	mov    0x8(%ebp),%ecx
    1672:	a1 00 00 00 00       	mov    0x0,%eax
    1677:	8b 11                	mov    (%ecx),%edx
    1679:	8b 4a 4c             	mov    0x4c(%edx),%ecx
    167c:	29 c8                	sub    %ecx,%eax
    167e:	c1 e0 03             	shl    $0x3,%eax
    1681:	89 42 54             	mov    %eax,0x54(%edx)
    1684:	a1 00 00 00 00       	mov    0x0,%eax
    1689:	85 c0                	test   %eax,%eax
    168b:	7e 14                	jle    16a1 <ExecuteTrickle+0x261>
    168d:	c7 04 24 e4 00 00 00 	movl   $0xe4,(%esp,1)
    1694:	e8 fc ff ff ff       	call   1695 <ExecuteTrickle+0x255>
    1699:	89 3c 24             	mov    %edi,(%esp,1)
    169c:	e8 fc ff ff ff       	call   169d <ExecuteTrickle+0x25d>
    16a1:	8b 55 08             	mov    0x8(%ebp),%edx
    16a4:	8b 02                	mov    (%edx),%eax
    16a6:	8b 40 70             	mov    0x70(%eax),%eax
    16a9:	89 3c 24             	mov    %edi,(%esp,1)
    16ac:	89 44 24 04          	mov    %eax,0x4(%esp,1)
    16b0:	e8 fc ff ff ff       	call   16b1 <ExecuteTrickle+0x271>
    16b5:	8b 4d 08             	mov    0x8(%ebp),%ecx
    16b8:	89 c2                	mov    %eax,%edx
    16ba:	8b 01                	mov    (%ecx),%eax
    16bc:	3b 50 70             	cmp    0x70(%eax),%edx
    16bf:	73 0c                	jae    16cd <ExecuteTrickle+0x28d>
    16c1:	c7 04 24 60 02 00 00 	movl   $0x260,(%esp,1)
    16c8:	e9 66 fe ff ff       	jmp    1533 <ExecuteTrickle+0xf3>
    16cd:	89 7c 24 04          	mov    %edi,0x4(%esp,1)
    16d1:	8b 45 10             	mov    0x10(%ebp),%eax
    16d4:	89 44 24 0c          	mov    %eax,0xc(%esp,1)
    16d8:	8d 42 01             	lea    0x1(%edx),%eax
    16db:	8b 55 08             	mov    0x8(%ebp),%edx
    16de:	89 44 24 08          	mov    %eax,0x8(%esp,1)
    16e2:	89 14 24             	mov    %edx,(%esp,1)
    16e5:	e8 66 15 00 00       	call   2c50 <DoSlowStartStep>
    16ea:	89 85 dc fc ff ff    	mov    %eax,0xfffffcdc(%ebp)
    16f0:	e9 6f ff ff ff       	jmp    1664 <ExecuteTrickle+0x224>
    16f5:	8b 55 08             	mov    0x8(%ebp),%edx
    16f8:	8b 0a                	mov    (%edx),%ecx
    16fa:	8b 41 54             	mov    0x54(%ecx),%eax
    16fd:	89 c2                	mov    %eax,%edx
    16ff:	c1 ea 03             	shr    $0x3,%edx
    1702:	29 d0                	sub    %edx,%eax
    1704:	89 41 54             	mov    %eax,0x54(%ecx)
    1707:	8b 4d 08             	mov    0x8(%ebp),%ecx
    170a:	a1 00 00 00 00       	mov    0x0,%eax
    170f:	8b 11                	mov    (%ecx),%edx
    1711:	8b 72 4c             	mov    0x4c(%edx),%esi
    1714:	29 f0                	sub    %esi,%eax
    1716:	01 42 54             	add    %eax,0x54(%edx)
    1719:	8b 01                	mov    (%ecx),%eax
    171b:	8b 40 58             	mov    0x58(%eax),%eax
    171e:	83 f8 01             	cmp    $0x1,%eax
    1721:	0f 84 e9 01 00 00    	je     1910 <ExecuteTrickle+0x4d0>
    1727:	83 f8 01             	cmp    $0x1,%eax
    172a:	0f 82 53 01 00 00    	jb     1883 <ExecuteTrickle+0x443>
    1730:	83 f8 02             	cmp    $0x2,%eax
    1733:	0f 85 2b ff ff ff    	jne    1664 <ExecuteTrickle+0x224>
    1739:	a1 00 00 00 00       	mov    0x0,%eax
    173e:	85 c0                	test   %eax,%eax
    1740:	7e 0c                	jle    174e <ExecuteTrickle+0x30e>
    1742:	c7 04 24 a0 02 00 00 	movl   $0x2a0,(%esp,1)
    1749:	e8 fc ff ff ff       	call   174a <ExecuteTrickle+0x30a>
    174e:	85 db                	test   %ebx,%ebx
    1750:	0f 84 1a 01 00 00    	je     1870 <ExecuteTrickle+0x430>
    1756:	85 db                	test   %ebx,%ebx
    1758:	7e 77                	jle    17d1 <ExecuteTrickle+0x391>
    175a:	4b                   	dec    %ebx
    175b:	74 0c                	je     1769 <ExecuteTrickle+0x329>
    175d:	c7 04 24 fc 00 00 00 	movl   $0xfc,(%esp,1)
    1764:	e9 ca fd ff ff       	jmp    1533 <ExecuteTrickle+0xf3>
    1769:	a1 00 00 00 00       	mov    0x0,%eax
    176e:	85 c0                	test   %eax,%eax
    1770:	7e 0c                	jle    177e <ExecuteTrickle+0x33e>
    1772:	c7 04 24 0d 01 00 00 	movl   $0x10d,(%esp,1)
    1779:	e8 fc ff ff ff       	call   177a <ExecuteTrickle+0x33a>
    177e:	8b 4d 08             	mov    0x8(%ebp),%ecx
    1781:	8b 11                	mov    (%ecx),%edx
    1783:	8b 42 64             	mov    0x64(%edx),%eax
    1786:	89 42 70             	mov    %eax,0x70(%edx)
    1789:	8b 35 00 00 00 00    	mov    0x0,%esi
    178f:	85 f6                	test   %esi,%esi
    1791:	7e 23                	jle    17b6 <ExecuteTrickle+0x376>
    1793:	8b 11                	mov    (%ecx),%edx
    1795:	8b 42 6c             	mov    0x6c(%edx),%eax
    1798:	89 44 24 0c          	mov    %eax,0xc(%esp,1)
    179c:	8b 42 68             	mov    0x68(%edx),%eax
    179f:	89 44 24 08          	mov    %eax,0x8(%esp,1)
    17a3:	8b 42 70             	mov    0x70(%edx),%eax
    17a6:	c7 04 24 e0 02 00 00 	movl   $0x2e0,(%esp,1)
    17ad:	89 44 24 04          	mov    %eax,0x4(%esp,1)
    17b1:	e8 fc ff ff ff       	call   17b2 <ExecuteTrickle+0x372>
    17b6:	89 7c 24 04          	mov    %edi,0x4(%esp,1)
    17ba:	8b 45 10             	mov    0x10(%ebp),%eax
    17bd:	8b 55 08             	mov    0x8(%ebp),%edx
    17c0:	89 44 24 08          	mov    %eax,0x8(%esp,1)
    17c4:	89 14 24             	mov    %edx,(%esp,1)
    17c7:	e8 14 08 00 00       	call   1fe0 <DoNormalStep>
    17cc:	e9 19 ff ff ff       	jmp    16ea <ExecuteTrickle+0x2aa>
    17d1:	43                   	inc    %ebx
    17d2:	75 89                	jne    175d <ExecuteTrickle+0x31d>
    17d4:	a1 00 00 00 00       	mov    0x0,%eax
    17d9:	85 c0                	test   %eax,%eax
    17db:	7e 0c                	jle    17e9 <ExecuteTrickle+0x3a9>
    17dd:	c7 04 24 1d 01 00 00 	movl   $0x11d,(%esp,1)
    17e4:	e8 fc ff ff ff       	call   17e5 <ExecuteTrickle+0x3a5>
    17e9:	8b 4d 08             	mov    0x8(%ebp),%ecx
    17ec:	8b 11                	mov    (%ecx),%edx
    17ee:	8b 42 60             	mov    0x60(%edx),%eax
    17f1:	48                   	dec    %eax
    17f2:	89 44 24 08          	mov    %eax,0x8(%esp,1)
    17f6:	8b 42 70             	mov    0x70(%edx),%eax
    17f9:	89 3c 24             	mov    %edi,(%esp,1)
    17fc:	89 44 24 04          	mov    %eax,0x4(%esp,1)
    1800:	e8 fc ff ff ff       	call   1801 <ExecuteTrickle+0x3c1>
    1805:	48                   	dec    %eax
    1806:	74 44                	je     184c <ExecuteTrickle+0x40c>
    1808:	c7 04 24 20 03 00 00 	movl   $0x320,(%esp,1)
    180f:	e8 fc ff ff ff       	call   1810 <ExecuteTrickle+0x3d0>
    1814:	a1 00 00 00 00       	mov    0x0,%eax
    1819:	85 c0                	test   %eax,%eax
    181b:	7e 14                	jle    1831 <ExecuteTrickle+0x3f1>
    181d:	c7 04 24 2f 01 00 00 	movl   $0x12f,(%esp,1)
    1824:	e8 fc ff ff ff       	call   1825 <ExecuteTrickle+0x3e5>
    1829:	89 3c 24             	mov    %edi,(%esp,1)
    182c:	e8 fc ff ff ff       	call   182d <ExecuteTrickle+0x3ed>
    1831:	89 7c 24 04          	mov    %edi,0x4(%esp,1)
    1835:	8b 4d 10             	mov    0x10(%ebp),%ecx
    1838:	8b 45 08             	mov    0x8(%ebp),%eax
    183b:	89 4c 24 08          	mov    %ecx,0x8(%esp,1)
    183f:	89 04 24             	mov    %eax,(%esp,1)
    1842:	e8 d9 0b 00 00       	call   2420 <DoRecoveryStep>
    1847:	e9 9e fe ff ff       	jmp    16ea <ExecuteTrickle+0x2aa>
    184c:	8b 45 08             	mov    0x8(%ebp),%eax
    184f:	8b 10                	mov    (%eax),%edx
    1851:	8b 42 34             	mov    0x34(%edx),%eax
    1854:	89 44 24 08          	mov    %eax,0x8(%esp,1)
    1858:	8b 42 64             	mov    0x64(%edx),%eax
    185b:	89 3c 24             	mov    %edi,(%esp,1)
    185e:	89 44 24 04          	mov    %eax,0x4(%esp,1)
    1862:	e8 fc ff ff ff       	call   1863 <ExecuteTrickle+0x423>
    1867:	48                   	dec    %eax
    1868:	75 9e                	jne    1808 <ExecuteTrickle+0x3c8>
    186a:	e9 fa fe ff ff       	jmp    1769 <ExecuteTrickle+0x329>
    186f:	90                   	nop    
    1870:	8b 1d 00 00 00 00    	mov    0x0,%ebx
    1876:	85 db                	test   %ebx,%ebx
    1878:	7e b7                	jle    1831 <ExecuteTrickle+0x3f1>
    187a:	c7 04 24 46 01 00 00 	movl   $0x146,(%esp,1)
    1881:	eb 8c                	jmp    180f <ExecuteTrickle+0x3cf>
    1883:	83 3d 00 00 00 00 01 	cmpl   $0x1,0x0
    188a:	7f 73                	jg     18ff <ExecuteTrickle+0x4bf>
    188c:	83 fb ff             	cmp    $0xffffffff,%ebx
    188f:	0f 8c cf fd ff ff    	jl     1664 <ExecuteTrickle+0x224>
    1895:	85 db                	test   %ebx,%ebx
    1897:	7e 25                	jle    18be <ExecuteTrickle+0x47e>
    1899:	4b                   	dec    %ebx
    189a:	0f 85 c4 fd ff ff    	jne    1664 <ExecuteTrickle+0x224>
    18a0:	83 3d 00 00 00 00 01 	cmpl   $0x1,0x0
    18a7:	0f 8e 09 ff ff ff    	jle    17b6 <ExecuteTrickle+0x376>
    18ad:	c7 04 24 0d 01 00 00 	movl   $0x10d,(%esp,1)
    18b4:	e8 fc ff ff ff       	call   18b5 <ExecuteTrickle+0x475>
    18b9:	e9 f8 fe ff ff       	jmp    17b6 <ExecuteTrickle+0x376>
    18be:	83 3d 00 00 00 00 01 	cmpl   $0x1,0x0
    18c5:	7f 16                	jg     18dd <ExecuteTrickle+0x49d>
    18c7:	89 7c 24 04          	mov    %edi,0x4(%esp,1)
    18cb:	8b 45 10             	mov    0x10(%ebp),%eax
    18ce:	8b 55 08             	mov    0x8(%ebp),%edx
    18d1:	89 44 24 08          	mov    %eax,0x8(%esp,1)
    18d5:	89 14 24             	mov    %edx,(%esp,1)
    18d8:	e9 65 ff ff ff       	jmp    1842 <ExecuteTrickle+0x402>
    18dd:	8b 4d 08             	mov    0x8(%ebp),%ecx
    18e0:	8b 01                	mov    (%ecx),%eax
    18e2:	8b 40 34             	mov    0x34(%eax),%eax
    18e5:	c7 04 24 60 03 00 00 	movl   $0x360,(%esp,1)
    18ec:	89 44 24 04          	mov    %eax,0x4(%esp,1)
    18f0:	e8 fc ff ff ff       	call   18f1 <ExecuteTrickle+0x4b1>
    18f5:	89 3c 24             	mov    %edi,(%esp,1)
    18f8:	e8 fc ff ff ff       	call   18f9 <ExecuteTrickle+0x4b9>
    18fd:	eb c8                	jmp    18c7 <ExecuteTrickle+0x487>
    18ff:	c7 04 24 a0 03 00 00 	movl   $0x3a0,(%esp,1)
    1906:	e8 fc ff ff ff       	call   1907 <ExecuteTrickle+0x4c7>
    190b:	e9 7c ff ff ff       	jmp    188c <ExecuteTrickle+0x44c>
    1910:	a1 00 00 00 00       	mov    0x0,%eax
    1915:	85 c0                	test   %eax,%eax
    1917:	0f 8e 47 fd ff ff    	jle    1664 <ExecuteTrickle+0x224>
    191d:	c7 04 24 c0 03 00 00 	movl   $0x3c0,(%esp,1)
    1924:	e9 36 fd ff ff       	jmp    165f <ExecuteTrickle+0x21f>
    1929:	8b 42 34             	mov    0x34(%edx),%eax
    192c:	c7 04 24 53 01 00 00 	movl   $0x153,(%esp,1)
    1933:	89 44 24 04          	mov    %eax,0x4(%esp,1)
    1937:	e8 fc ff ff ff       	call   1938 <ExecuteTrickle+0x4f8>
    193c:	89 3c 24             	mov    %edi,(%esp,1)
    193f:	e8 fc ff ff ff       	call   1940 <ExecuteTrickle+0x500>
    1944:	8b 45 08             	mov    0x8(%ebp),%eax
    1947:	8b 10                	mov    (%eax),%edx
    1949:	e9 e4 fc ff ff       	jmp    1632 <ExecuteTrickle+0x1f2>
    194e:	89 f6                	mov    %esi,%esi
    1950:	8b 85 e0 fc ff ff    	mov    0xfffffce0(%ebp),%eax
    1956:	83 f8 16             	cmp    $0x16,%eax
    1959:	74 23                	je     197e <ExecuteTrickle+0x53e>
    195b:	83 f8 0c             	cmp    $0xc,%eax
    195e:	74 14                	je     1974 <ExecuteTrickle+0x534>
    1960:	c7 44 24 04 ab 02 00 	movl   $0x2ab,0x4(%esp,1)
    1967:	00 
    1968:	c7 04 24 00 04 00 00 	movl   $0x400,(%esp,1)
    196f:	e8 fc ff ff ff       	call   1970 <ExecuteTrickle+0x530>
    1974:	b8 f4 ff ff ff       	mov    $0xfffffff4,%eax
    1979:	e9 a3 fb ff ff       	jmp    1521 <ExecuteTrickle+0xe1>
    197e:	a1 00 00 00 00       	mov    0x0,%eax
    1983:	9c                   	pushf  
    1984:	59                   	pop    %ecx
    1985:	fa                   	cli    
    1986:	89 c2                	mov    %eax,%edx
    1988:	8b 35 48 e2 04 00    	mov    0x4e248,%esi
    198e:	8b 1d 38 00 00 00    	mov    0x38,%ebx
    1994:	a3 48 e2 04 00       	mov    %eax,0x4e248
    1999:	29 f2                	sub    %esi,%edx
    199b:	01 da                	add    %ebx,%edx
    199d:	89 15 38 00 00 00    	mov    %edx,0x38
    19a3:	81 fa 88 13 00 00    	cmp    $0x1388,%edx
    19a9:	76 10                	jbe    19bb <ExecuteTrickle+0x57b>
    19ab:	bf 88 13 00 00       	mov    $0x1388,%edi
    19b0:	ba 88 13 00 00       	mov    $0x1388,%edx
    19b5:	89 3d 38 00 00 00    	mov    %edi,0x38
    19bb:	81 fa f3 01 00 00    	cmp    $0x1f3,%edx
    19c1:	76 5a                	jbe    1a1d <ExecuteTrickle+0x5dd>
    19c3:	31 f6                	xor    %esi,%esi
    19c5:	81 ea f4 01 00 00    	sub    $0x1f4,%edx
    19cb:	a1 4c e2 04 00       	mov    0x4e24c,%eax
    19d0:	89 15 38 00 00 00    	mov    %edx,0x38
    19d6:	89 35 4c e2 04 00    	mov    %esi,0x4e24c
    19dc:	51                   	push   %ecx
    19dd:	9d                   	popf   
    19de:	85 c0                	test   %eax,%eax
    19e0:	75 19                	jne    19fb <ExecuteTrickle+0x5bb>
    19e2:	b8 01 00 00 00       	mov    $0x1,%eax
    19e7:	85 c0                	test   %eax,%eax
    19e9:	0f 84 2d fb ff ff    	je     151c <ExecuteTrickle+0xdc>
    19ef:	c7 04 24 60 04 00 00 	movl   $0x460,(%esp,1)
    19f6:	e9 38 fb ff ff       	jmp    1533 <ExecuteTrickle+0xf3>
    19fb:	89 44 24 0c          	mov    %eax,0xc(%esp,1)
    19ff:	c7 44 24 08 a6 02 00 	movl   $0x2a6,0x8(%esp,1)
    1a06:	00 
    1a07:	c7 44 24 04 45 00 00 	movl   $0x45,0x4(%esp,1)
    1a0e:	00 
    1a0f:	c7 04 24 80 00 00 00 	movl   $0x80,(%esp,1)
    1a16:	e8 fc ff ff ff       	call   1a17 <ExecuteTrickle+0x5d7>
    1a1b:	eb c5                	jmp    19e2 <ExecuteTrickle+0x5a2>
    1a1d:	ff 05 4c e2 04 00    	incl   0x4e24c
    1a23:	51                   	push   %ecx
    1a24:	9d                   	popf   
    1a25:	31 c0                	xor    %eax,%eax
    1a27:	eb be                	jmp    19e7 <ExecuteTrickle+0x5a7>
    1a29:	8d b4 26 00 00 00 00 	lea    0x0(%esi,1),%esi

00001a30 <msk_transmit_skb>:

int msk_transmit_skb(struct cminisock *msk, struct sk_buff *skb, int packet_num) {
    1a30:	55                   	push   %ebp
    1a31:	89 e5                	mov    %esp,%ebp
    1a33:	57                   	push   %edi
    1a34:	56                   	push   %esi
    1a35:	53                   	push   %ebx
    1a36:	83 ec 34             	sub    $0x34,%esp
	int tcp_header_size;
	struct tcphdr *th;
	struct sock *sk;

#ifdef FORCE_MSK_TRANSMIT_REORDERING
	static struct sk_buff *reorder_skb = NULL;
#endif

#ifndef USERTEST
	struct tcp_func *af = &ipv4_specific;
#endif

	struct WireTrickleResponse *resp_hdr;
	int err;
	int ucontLen = msk->packets[packet_num].ucontLen;
    1a39:	8b 45 08             	mov    0x8(%ebp),%eax
    1a3c:	8b 4d 10             	mov    0x10(%ebp),%ecx
    1a3f:	8b 90 e0 00 00 00    	mov    0xe0(%eax),%edx
    1a45:	8d 04 89             	lea    (%ecx,%ecx,4),%eax
	int origSkbLen = skb->len;

	sk = skb->sk = msk->sk;
    1a48:	8b 4d 0c             	mov    0xc(%ebp),%ecx
    1a4b:	8d 1c c5 00 00 00 00 	lea    0x0(,%eax,8),%ebx
    1a52:	8b 45 0c             	mov    0xc(%ebp),%eax
    1a55:	8b 54 1a 14          	mov    0x14(%edx,%ebx,1),%edx
    1a59:	89 55 f0             	mov    %edx,0xfffffff0(%ebp)
    1a5c:	8b 55 08             	mov    0x8(%ebp),%edx
    1a5f:	8b 40 70             	mov    0x70(%eax),%eax
    1a62:	89 45 ec             	mov    %eax,0xffffffec(%ebp)
    1a65:	8b 52 20             	mov    0x20(%edx),%edx
    1a68:	89 55 e8             	mov    %edx,0xffffffe8(%ebp)
    1a6b:	89 51 0c             	mov    %edx,0xc(%ecx)

	//printk("msk_transmit_skb: skb len(%d) stcp len(%d)\n", skb->len, tcb->stcp_len);
	if(userapi_time_spew)
    1a6e:	a1 00 00 00 00       	mov    0x0,%eax
    1a73:	85 c0                	test   %eax,%eax
    1a75:	0f 85 35 05 00 00    	jne    1fb0 <msk_transmit_skb+0x580>
		printk("transmit time: %lu\n", jiffies);
	msk->timestamp = jiffies;
    1a7b:	a1 00 00 00 00       	mov    0x0,%eax
    1a80:	8b 55 08             	mov    0x8(%ebp),%edx
    1a83:	89 42 4c             	mov    %eax,0x4c(%edx)

	/* UCONT handling */
	BUG_TRAP(ucontLen >= 0);
    1a86:	8b 45 f0             	mov    0xfffffff0(%ebp),%eax
    1a89:	85 c0                	test   %eax,%eax
    1a8b:	0f 88 ff 04 00 00    	js     1f90 <msk_transmit_skb+0x560>
	if(ucontLen > 0) {
    1a91:	8b 7d f0             	mov    0xfffffff0(%ebp),%edi
    1a94:	85 ff                	test   %edi,%edi
    1a96:	0f 8e e4 04 00 00    	jle    1f80 <msk_transmit_skb+0x550>
		if(msk->packets[packet_num].ucontData != NULL) {
    1a9c:	8b 4d 08             	mov    0x8(%ebp),%ecx
    1a9f:	8b 91 e0 00 00 00    	mov    0xe0(%ecx),%edx
    1aa5:	8b 74 1a 18          	mov    0x18(%edx,%ebx,1),%esi
    1aa9:	85 f6                	test   %esi,%esi
    1aab:	74 5b                	je     1b08 <msk_transmit_skb+0xd8>
 */

static inline unsigned char *skb_push(struct sk_buff *skb, unsigned int len)
{
	skb->data-=len;
    1aad:	8b 55 0c             	mov    0xc(%ebp),%edx
    1ab0:	8b 4d f0             	mov    0xfffffff0(%ebp),%ecx
    1ab3:	8b 82 94 00 00 00    	mov    0x94(%edx),%eax
    1ab9:	29 c8                	sub    %ecx,%eax
    1abb:	89 82 94 00 00 00    	mov    %eax,0x94(%edx)
	skb->len+=len;
    1ac1:	8b 4d f0             	mov    0xfffffff0(%ebp),%ecx
    1ac4:	01 4a 70             	add    %ecx,0x70(%edx)
	if(skb->data<skb->head) {
    1ac7:	3b 82 90 00 00 00    	cmp    0x90(%edx),%eax
    1acd:	0f 82 8d 04 00 00    	jb     1f60 <msk_transmit_skb+0x530>
		skb_under_panic(skb, len, current_text_addr());
	}
    1ad3:	8b 45 0c             	mov    0xc(%ebp),%eax
return __res;
}

static inline void * __memcpy(void * to, const void * from, size_t n)
{
    1ad6:	8b 55 08             	mov    0x8(%ebp),%edx
int d0, d1, d2;
__asm__ __volatile__(
    1ad9:	8b 4d f0             	mov    0xfffffff0(%ebp),%ecx
	skb->data-=len;
	skb->len+=len;
	if(skb->data<skb->head) {
		skb_under_panic(skb, len, current_text_addr());
	}
    1adc:	8b b8 94 00 00 00    	mov    0x94(%eax),%edi
return __res;
}

static inline void * __memcpy(void * to, const void * from, size_t n)
{
    1ae2:	8b 82 e0 00 00 00    	mov    0xe0(%edx),%eax
int d0, d1, d2;
__asm__ __volatile__(
    1ae8:	c1 e9 02             	shr    $0x2,%ecx
    1aeb:	8b 74 18 18          	mov    0x18(%eax,%ebx,1),%esi
    1aef:	8b 45 f0             	mov    0xfffffff0(%ebp),%eax
    1af2:	f3 a5                	repz movsl %ds:(%esi),%es:(%edi)
    1af4:	a8 02                	test   $0x2,%al
    1af6:	74 02                	je     1afa <msk_transmit_skb+0xca>
    1af8:	66 a5                	movsw  %ds:(%esi),%es:(%edi)
    1afa:	a8 01                	test   $0x1,%al
    1afc:	74 01                	je     1aff <msk_transmit_skb+0xcf>
    1afe:	a4                   	movsb  %ds:(%esi),%es:(%edi)
    1aff:	8b 4d 08             	mov    0x8(%ebp),%ecx
    1b02:	8b 91 e0 00 00 00    	mov    0xe0(%ecx),%edx
			memcpy(skb_push(skb, ucontLen),
			       msk->packets[packet_num].ucontData, ucontLen);
		} else {
			// Do nothing; already in the packet
		}
	}

	if(msk->packets[packet_num].contType & CONTTYPE_HASHCOMPRESSED) {
    1b08:	8b 4d 10             	mov    0x10(%ebp),%ecx
    1b0b:	8d 04 89             	lea    (%ecx,%ecx,4),%eax
    1b0e:	8d 34 c5 00 00 00 00 	lea    0x0(,%eax,8),%esi
    1b15:	0f b6 44 32 10       	movzbl 0x10(%edx,%esi,1),%eax
    1b1a:	c0 e8 03             	shr    $0x3,%al
#ifdef ENABLE_HASHCOMPRESS
		int fullType;
		struct WireContinuation *wcont;
		static struct WireContinuation scratch[NR_CPUS]; // avoid stack allocation (which risks stack overflow), and kmalloc, which is inefficient
		struct WireContinuation *wc_scratch = &scratch[smp_processor_id()];

		resp_hdr = (WireTrickleResponse*)skb_push(skb, RESPONSELEN_HASHCOMPRESS);
		wcont = &resp_hdr->cont;
		
		/* mask off hashcompressed bit to verify type */
		msk->packets[packet_num].contType &= ~CONTTYPE_HASHCOMPRESSED;
		fullType = msk->packets[packet_num].contType == CONTTYPE_FULL1 ||
			msk->packets[packet_num].contType == CONTTYPE_FULL2;
		BUG_TRAP(fullType ||
			 msk->packets[packet_num].contType == CONTTYPE_MINIMAL);
		// restore hashcompressed bit
		msk->packets[packet_num].contType |= CONTTYPE_HASHCOMPRESSED;

		wcont->continuationType = msk->packets[packet_num].contType;
		wcont->hash.timestamp = htonl(msk->timestamp);
		wcont->hash.mrtt = htonl(msk->mrtt);
		wcont->hash.parentSeq = msk->seq;
		wcont->hash.clientState = msk->clientState;
		wcont->hash.position = packet_num;

		// marshall continuation to get mac value
		if(fullType) {
			// do this for all "FULL" continuation types
			msk->packets[packet_num].contType &= ~CONTTYPE_HASHCOMPRESSED;
			marshallContinuationServer(sk, wc_scratch, msk, packet_num);
			msk->packets[packet_num].contType |= CONTTYPE_HASHCOMPRESSED;

			memcpy(wcont->hash.mac, wc_scratch->mac, HMACLEN);
		}
#else
		printk("msk_transmit_skb: hash compress not enabled\n");
		BUG();
#endif
	} else {
		switch(msk->packets[packet_num].contType) {
    1b1d:	83 e0 07             	and    $0x7,%eax
    1b20:	0f 84 cc 03 00 00    	je     1ef2 <msk_transmit_skb+0x4c2>
    1b26:	83 f8 02             	cmp    $0x2,%eax
    1b29:	0f 8f a3 03 00 00    	jg     1ed2 <msk_transmit_skb+0x4a2>
 */

static inline unsigned char *skb_push(struct sk_buff *skb, unsigned int len)
{
	skb->data-=len;
    1b2f:	8b 4d 0c             	mov    0xc(%ebp),%ecx
    1b32:	8b 81 94 00 00 00    	mov    0x94(%ecx),%eax
	skb->len+=len;
    1b38:	83 41 70 56          	addl   $0x56,0x70(%ecx)
    1b3c:	83 e8 56             	sub    $0x56,%eax
	if(skb->data<skb->head) {
    1b3f:	3b 81 90 00 00 00    	cmp    0x90(%ecx),%eax
    1b45:	89 81 94 00 00 00    	mov    %eax,0x94(%ecx)
    1b4b:	0f 82 64 03 00 00    	jb     1eb5 <msk_transmit_skb+0x485>
		skb_under_panic(skb, len, current_text_addr());
	}
    1b51:	8b 45 0c             	mov    0xc(%ebp),%eax
		case CONTTYPE_MINIMAL:
			resp_hdr = (WireTrickleResponse*)skb_push(skb, RESPONSELEN_MINIMAL);
			resp_hdr->cont.seq = htonl(msk->packets[packet_num].seq);
			resp_hdr->cont.continuationType = CONTTYPE_MINIMAL;
			resp_hdr->cont.clientState = msk->clientState;
			resp_hdr->cont.parent = msk->parent;
			resp_hdr->cont.clientTimestamp = msk->clientTimestamp;
			break;
		case CONTTYPE_FULL1:
		case CONTTYPE_FULL2:
			/* Generate Trickle header */
			resp_hdr = (WireTrickleResponse*)skb_push(skb, sizeof(WireTrickleResponse));
			marshallContinuationServer(sk, &resp_hdr->cont, msk, packet_num);
    1b54:	8b 55 10             	mov    0x10(%ebp),%edx
    1b57:	8b 4d 08             	mov    0x8(%ebp),%ecx
	skb->data-=len;
	skb->len+=len;
	if(skb->data<skb->head) {
		skb_under_panic(skb, len, current_text_addr());
	}
    1b5a:	8b 98 94 00 00 00    	mov    0x94(%eax),%ebx
    1b60:	89 54 24 0c          	mov    %edx,0xc(%esp,1)
    1b64:	89 4c 24 08          	mov    %ecx,0x8(%esp,1)
    1b68:	8d 43 0c             	lea    0xc(%ebx),%eax
    1b6b:	89 44 24 04          	mov    %eax,0x4(%esp,1)
    1b6f:	8b 45 e8             	mov    0xffffffe8(%ebp),%eax
    1b72:	89 04 24             	mov    %eax,(%esp,1)
    1b75:	e8 96 17 00 00       	call   3310 <marshallContinuationServer>
			break;
		default:
			resp_hdr = NULL;
			BUG();
		}
	}
	resp_hdr->nonce = msk->packets[packet_num].nonce;
    1b7a:	8b 4d 08             	mov    0x8(%ebp),%ecx
    1b7d:	8b 91 e0 00 00 00    	mov    0xe0(%ecx),%edx
    1b83:	8b 4d 10             	mov    0x10(%ebp),%ecx
    1b86:	8d 04 89             	lea    (%ecx,%ecx,4),%eax
    1b89:	8d 34 c5 00 00 00 00 	lea    0x0(,%eax,8),%esi
    1b90:	8b 04 32             	mov    (%edx,%esi,1),%eax
    1b93:	89 03                	mov    %eax,(%ebx)

	resp_hdr->ucont_len = htons((short)ucontLen);
    1b95:	0f b7 45 f0          	movzwl 0xfffffff0(%ebp),%eax
/* gcc should generate this for open coded C now too. May be worth switching to 
   it because inline assembly cannot be scheduled. -AK */
static __inline__ __const__ __u16 ___arch__swab16(__u16 x)
{
	__asm__("xchgb %b0,%h0"		/* swap bytes		*/
    1b99:	86 c4                	xchg   %al,%ah
#endif /* OPTIMIZE */


static __inline__ __const__ __u16 __fswab16(__u16 x)
{
    1b9b:	66 89 43 0a          	mov    %ax,0xa(%ebx)
	resp_hdr->byteNum = htonl(msk->packets[packet_num].byteNum);
    1b9f:	8b 55 08             	mov    0x8(%ebp),%edx
    1ba2:	8b 82 e0 00 00 00    	mov    0xe0(%edx),%eax
	__arch__swab24s(addr);
}

static __inline__ __const__ __u32 __fswab32(__u32 x)
{
    1ba8:	8b 44 30 0c          	mov    0xc(%eax,%esi,1),%eax

static __inline__ __const__ __u32 ___arch__swab32(__u32 x)
{
#ifdef CONFIG_X86_BSWAP
	__asm__("bswap %0" : "=r" (x) : "0" (x));
    1bac:	0f c8                	bswap  %eax
	__arch__swab24s(addr);
}

static __inline__ __const__ __u32 __fswab32(__u32 x)
{
    1bae:	89 43 04             	mov    %eax,0x4(%ebx)
	resp_hdr->numSiblings = msk->packets[packet_num].numSiblings;
    1bb1:	8b 82 e0 00 00 00    	mov    0xe0(%edx),%eax
    1bb7:	0f b6 44 30 11       	movzbl 0x11(%eax,%esi,1),%eax
    1bbc:	88 43 08             	mov    %al,0x8(%ebx)
	resp_hdr->position = msk->packets[packet_num].position;
    1bbf:	8b 82 e0 00 00 00    	mov    0xe0(%edx),%eax
    1bc5:	0f b6 44 30 12       	movzbl 0x12(%eax,%esi,1),%eax
    1bca:	88 43 09             	mov    %al,0x9(%ebx)
 */

static inline unsigned char *skb_push(struct sk_buff *skb, unsigned int len)
{
	skb->data-=len;
    1bcd:	8b 4d 0c             	mov    0xc(%ebp),%ecx
    1bd0:	8b 81 94 00 00 00    	mov    0x94(%ecx),%eax
	skb->len+=len;
    1bd6:	83 41 70 18          	addl   $0x18,0x70(%ecx)
    1bda:	83 e8 18             	sub    $0x18,%eax
	if(skb->data<skb->head) {
    1bdd:	3b 81 90 00 00 00    	cmp    0x90(%ecx),%eax
    1be3:	89 81 94 00 00 00    	mov    %eax,0x94(%ecx)
    1be9:	0f 82 a9 02 00 00    	jb     1e98 <msk_transmit_skb+0x468>
		skb_under_panic(skb, len, current_text_addr());
	}
    1bef:	8b 45 0c             	mov    0xc(%ebp),%eax
    1bf2:	8b 98 94 00 00 00    	mov    0x94(%eax),%ebx

	//printk("transmit_skb - resp_hdr: %p, ucont_len\n", &resp_hdr->cont, ntohs(resp_hdr->ucont_len));

	tcp_header_size = sizeof(struct tcphdr) + TCPOLEN_TRICKLES;
	th = (struct tcphdr *) skb_push(skb, tcp_header_size);
	skb->h.th = th;
    1bf8:	89 58 20             	mov    %ebx,0x20(%eax)
	th->source = sk->sport;
    1bfb:	8b 55 e8             	mov    0xffffffe8(%ebp),%edx
    1bfe:	0f b7 42 22          	movzwl 0x22(%edx),%eax
    1c02:	66 89 03             	mov    %ax,(%ebx)
	th->dest = msk->dest;
    1c05:	8b 4d 08             	mov    0x8(%ebp),%ecx
    1c08:	0f b7 41 1e          	movzwl 0x1e(%ecx),%eax
    1c0c:	66 89 43 02          	mov    %ax,0x2(%ebx)
	__arch__swab24s(addr);
}

static __inline__ __const__ __u32 __fswab32(__u32 x)
{
    1c10:	8b 41 34             	mov    0x34(%ecx),%eax

static __inline__ __const__ __u32 ___arch__swab32(__u32 x)
{
#ifdef CONFIG_X86_BSWAP
	__asm__("bswap %0" : "=r" (x) : "0" (x));
    1c13:	0f c8                	bswap  %eax
	__arch__swab24s(addr);
}

static __inline__ __const__ __u32 __fswab32(__u32 x)
{
    1c15:	89 43 04             	mov    %eax,0x4(%ebx)

	th->seq = htonl(msk->seq);

	// 0615 - mark each packet with a unique identifier so we know exactly how many packets were sent
	static int gSendPacketNumber = 0;
	// save debugging information
	if(sysctl_dbg_cwnd) {
    1c18:	a1 00 00 00 00       	mov    0x0,%eax
    1c1d:	85 c0                	test   %eax,%eax
    1c1f:	0f 85 20 02 00 00    	jne    1e45 <msk_transmit_skb+0x415>
		trickles_logCwnd_hook(msk->daddr, msk->dest, msk->packets[packet_num].seq,
				      gSendPacketNumber,
				      msk->startCwnd, msk->mark /* effCwnd */, msk->ssthresh,
				      msk->mrtt, msk->mrtt);
	}
#if 0
	th->ack_seq = htonl(gSendPacketNumber++);
#else
	th->ack_seq = htonl(msk->packets[packet_num].byteNum);
    1c25:	8b 55 08             	mov    0x8(%ebp),%edx
    1c28:	8b 82 e0 00 00 00    	mov    0xe0(%edx),%eax
#endif

	// set tcp header size and zero out flags 
	th->doff = tcp_header_size >> 2;
	th->res1= 0;
	th->cwr = 0;
	th->ece = 0;
	th->urg = 0;

	th->ack = 1;
	th->psh = 0;
	th->rst = 0;
	th->syn = 0;
	th->fin = 0;
    1c2e:	b2 10                	mov    $0x10,%dl
	__arch__swab24s(addr);
}

static __inline__ __const__ __u32 __fswab32(__u32 x)
{
    1c30:	8b 44 30 0c          	mov    0xc(%eax,%esi,1),%eax
    1c34:	c6 43 0c 60          	movb   $0x60,0xc(%ebx)

static __inline__ __const__ __u32 ___arch__swab32(__u32 x)
{
#ifdef CONFIG_X86_BSWAP
	__asm__("bswap %0" : "=r" (x) : "0" (x));
    1c38:	0f c8                	bswap  %eax
    1c3a:	88 53 0d             	mov    %dl,0xd(%ebx)
	__arch__swab24s(addr);
}

static __inline__ __const__ __u32 __fswab32(__u32 x)
{
    1c3d:	89 43 08             	mov    %eax,0x8(%ebx)

	// TODO: Find uses for window, urg_ptr fields
	th->window = 0;
    1c40:	66 c7 43 0e 00 00    	movw   $0x0,0xe(%ebx)
	th->check = 0;
    1c46:	66 c7 43 10 00 00    	movw   $0x0,0x10(%ebx)
	th->urg_ptr = 0;
    1c4c:	66 c7 43 12 00 00    	movw   $0x0,0x12(%ebx)
	*(__u32*)(th+1) = htonl((TCPOPT_TRICKLES << 24)  | 
    1c52:	8b 4d 08             	mov    0x8(%ebp),%ecx
    1c55:	0f b7 41 7c          	movzwl 0x7c(%ecx),%eax
    1c59:	83 c0 56             	add    $0x56,%eax
    1c5c:	0f b7 c0             	movzwl %ax,%eax
    1c5f:	0d 00 00 04 0b       	or     $0xb040000,%eax

static __inline__ __const__ __u32 ___arch__swab32(__u32 x)
{
#ifdef CONFIG_X86_BSWAP
	__asm__("bswap %0" : "=r" (x) : "0" (x));
    1c64:	0f c8                	bswap  %eax
	__arch__swab24s(addr);
}

static __inline__ __const__ __u32 __fswab32(__u32 x)
{
    1c66:	89 43 14             	mov    %eax,0x14(%ebx)
				(TCPOLEN_TRICKLES << 16) |
				((__u16)(sizeof(WireTrickleResponse) + msk->ucont_len)));

	switch(msk->tag) {
    1c69:	8b 41 10             	mov    0x10(%ecx),%eax
    1c6c:	83 f8 01             	cmp    $0x1,%eax
    1c6f:	74 1e                	je     1c8f <msk_transmit_skb+0x25f>
    1c71:	83 f8 01             	cmp    $0x1,%eax
    1c74:	0f 82 c6 01 00 00    	jb     1e40 <msk_transmit_skb+0x410>
    1c7a:	83 f8 02             	cmp    $0x2,%eax
    1c7d:	0f 84 ae 01 00 00    	je     1e31 <msk_transmit_skb+0x401>
	case SYN:
		th->syn = 1; // send syn/ack
		th->ack = 1;
		break;
	case FIN:
		th->fin = 1;
		break;
	case ACK:
		break;
	default:
		printk("msk_transmit_skb: unsupported event tag\n");
    1c83:	c7 04 24 a0 04 00 00 	movl   $0x4a0,(%esp,1)
    1c8a:	e8 fc ff ff ff       	call   1c8b <msk_transmit_skb+0x25b>
	}

	numTxPackets++;
    1c8f:	83 05 00 00 00 00 01 	addl   $0x1,0x0
	numTxBytes += skb->len;
    1c96:	8b 4d 0c             	mov    0xc(%ebp),%ecx
    1c99:	83 15 04 00 00 00 00 	adcl   $0x0,0x4
    1ca0:	31 d2                	xor    %edx,%edx
    1ca2:	8b 41 70             	mov    0x70(%ecx),%eax
    1ca5:	01 05 00 00 00 00    	add    %eax,0x0

#define MINISOCK_LEN(RO_LEN) ((RO_LEN) / 2)

#ifndef USERTEST
static inline void trickles_checksum(struct sk_buff *skb, int headerLen) {
    1cab:	8b 45 ec             	mov    0xffffffec(%ebp),%eax
    1cae:	11 15 04 00 00 00    	adc    %edx,0x4

#define MINISOCK_LEN(RO_LEN) ((RO_LEN) / 2)

#ifndef USERTEST
static inline void trickles_checksum(struct sk_buff *skb, int headerLen) {
    1cb4:	8b 51 70             	mov    0x70(%ecx),%edx
	struct sock *sk = skb->sk;
    1cb7:	8b 71 0c             	mov    0xc(%ecx),%esi
    1cba:	29 c2                	sub    %eax,%edx
	if(skb->ip_summed == CHECKSUM_HW) {
    1cbc:	80 79 7f 01          	cmpb   $0x1,0x7f(%ecx)
    1cc0:	0f 84 1b 01 00 00    	je     1de1 <msk_transmit_skb+0x3b1>
		skb->h.th->check = 0;
		skb->h.th->check = ~tcp_v4_check(skb->h.th, skb->len, sk->saddr, sk->daddr,
					 0);
		skb->csum = offsetof(struct tcphdr, check);
	} else {
		skb->h.th->check = 0;
    1cc6:	8b 4d 0c             	mov    0xc(%ebp),%ecx
    1cc9:	8b 41 20             	mov    0x20(%ecx),%eax
    1ccc:	66 c7 40 10 00 00    	movw   $0x0,0x10(%eax)
		skb->h.th->check = tcp_v4_check(skb->h.th, skb->len, sk->saddr, sk->daddr, 
    1cd2:	8b 41 20             	mov    0x20(%ecx),%eax
    1cd5:	89 45 e4             	mov    %eax,0xffffffe4(%ebp)
 */
static __inline__ u16 tcp_v4_check(struct tcphdr *th, int len,
				   unsigned long saddr, unsigned long daddr, 
				   unsigned long base)
{
    1cd8:	8b 59 70             	mov    0x70(%ecx),%ebx
    1cdb:	8b 7e 70             	mov    0x70(%esi),%edi
    1cde:	8b 41 78             	mov    0x78(%ecx),%eax
    1ce1:	8b 36                	mov    (%esi),%esi
						   unsigned long daddr,
						   unsigned short len,
						   unsigned short proto,
						   unsigned int sum)
{
    1ce3:	0f b7 db             	movzwl %bx,%ebx
 */
static __inline__ u16 tcp_v4_check(struct tcphdr *th, int len,
				   unsigned long saddr, unsigned long daddr, 
				   unsigned long base)
{
    1ce6:	89 54 24 04          	mov    %edx,0x4(%esp,1)
    1cea:	8b 55 e4             	mov    0xffffffe4(%ebp),%edx
/* gcc should generate this for open coded C now too. May be worth switching to 
   it because inline assembly cannot be scheduled. -AK */
static __inline__ __const__ __u16 ___arch__swab16(__u16 x)
{
	__asm__("xchgb %b0,%h0"		/* swap bytes		*/
    1ced:	86 df                	xchg   %bl,%bh
 */
static __inline__ u16 tcp_v4_check(struct tcphdr *th, int len,
				   unsigned long saddr, unsigned long daddr, 
				   unsigned long base)
{
    1cef:	89 44 24 08          	mov    %eax,0x8(%esp,1)
#endif /* OPTIMIZE */


static __inline__ __const__ __u16 __fswab16(__u16 x)
{
    1cf3:	c1 e3 10             	shl    $0x10,%ebx
    1cf6:	81 c3 00 06 00 00    	add    $0x600,%ebx
 */
static __inline__ u16 tcp_v4_check(struct tcphdr *th, int len,
				   unsigned long saddr, unsigned long daddr, 
				   unsigned long base)
{
    1cfc:	89 14 24             	mov    %edx,(%esp,1)
    1cff:	e8 fc ff ff ff       	call   1d00 <msk_transmit_skb+0x2d0>
    1d04:	8b 4d e4             	mov    0xffffffe4(%ebp),%ecx
#endif /* OPTIMIZE */


static __inline__ __const__ __u16 __fswab16(__u16 x)
{
    1d07:	01 f0                	add    %esi,%eax
    1d09:	11 f8                	adc    %edi,%eax
    1d0b:	11 d8                	adc    %ebx,%eax
    1d0d:	83 d0 00             	adc    $0x0,%eax
 */

static inline unsigned int csum_fold(unsigned int sum)
{
	__asm__(
    1d10:	89 c2                	mov    %eax,%edx
    1d12:	81 e2 00 00 ff ff    	and    $0xffff0000,%edx
    1d18:	c1 e0 10             	shl    $0x10,%eax
    1d1b:	01 c2                	add    %eax,%edx
    1d1d:	81 d2 ff ff 00 00    	adc    $0xffff,%edx
    1d23:	f7 d2                	not    %edx
		"addl %1, %0		;\n"
		"adcl $0xffff, %0	;\n"
		: "=r" (sum)
		: "r" (sum << 16), "0" (sum & 0xffff0000)
	);
	return (~sum) >> 16;
}

static inline unsigned long csum_tcpudp_nofold(unsigned long saddr,
						   unsigned long daddr,
						   unsigned short len,
						   unsigned short proto,
						   unsigned int sum)
{
    __asm__(
	"addl %1, %0	;\n"
	"adcl %2, %0	;\n"
	"adcl %3, %0	;\n"
	"adcl $0, %0	;\n"
	: "=r" (sum)
	: "g" (daddr), "g"(saddr), "g"((ntohs(len)<<16)+proto*256), "0"(sum));
    return sum;
}

/*
 * computes the checksum of the TCP/UDP pseudo-header
 * returns a 16-bit checksum, already complemented
 */
static inline unsigned short int csum_tcpudp_magic(unsigned long saddr,
						   unsigned long daddr,
						   unsigned short len,
						   unsigned short proto,
						   unsigned int sum)
{
    1d25:	c1 ea 10             	shr    $0x10,%edx
 */
static __inline__ u16 tcp_v4_check(struct tcphdr *th, int len,
				   unsigned long saddr, unsigned long daddr, 
				   unsigned long base)
{
    1d28:	66 89 51 10          	mov    %dx,0x10(%ecx)

#ifndef USERTEST
	trickles_checksum(skb, skb->len - origSkbLen);
	if(sk->protocol == IPPROTO_TCP) {
    1d2c:	8b 55 e8             	mov    0xffffffe8(%ebp),%edx
    1d2f:	0f b6 82 33 0c 00 00 	movzbl 0xc33(%edx),%eax
    1d36:	3c 06                	cmp    $0x6,%al
    1d38:	0f 84 93 00 00 00    	je     1dd1 <msk_transmit_skb+0x3a1>
#ifndef FORCE_MSK_TRANSMIT_REORDERING
		err = af->queue_xmit(skb, 0);
#else
		if(reorder_skb == NULL) {
			reorder_skb = skb;
			err = 0;
		} else {
			err = af->queue_xmit(skb, 0);
			err = af->queue_xmit(reorder_skb, 0) | err;
		}
#endif
	} else {
		struct udphdr *udp_hdr;
		BUG_TRAP(sk->protocol == IPPROTO_UDP);
    1d3e:	3c 11                	cmp    $0x11,%al
    1d40:	74 14                	je     1d56 <msk_transmit_skb+0x326>
    1d42:	c7 44 24 04 f5 03 00 	movl   $0x3f5,0x4(%esp,1)
    1d49:	00 
    1d4a:	c7 04 24 e0 04 00 00 	movl   $0x4e0,(%esp,1)
    1d51:	e8 fc ff ff ff       	call   1d52 <msk_transmit_skb+0x322>
 */

static inline unsigned char *skb_push(struct sk_buff *skb, unsigned int len)
{
	skb->data-=len;
    1d56:	8b 55 0c             	mov    0xc(%ebp),%edx
    1d59:	8b 82 94 00 00 00    	mov    0x94(%edx),%eax
	skb->len+=len;
    1d5f:	83 42 70 08          	addl   $0x8,0x70(%edx)
    1d63:	83 e8 08             	sub    $0x8,%eax
	if(skb->data<skb->head) {
    1d66:	3b 82 90 00 00 00    	cmp    0x90(%edx),%eax
    1d6c:	89 82 94 00 00 00    	mov    %eax,0x94(%edx)
    1d72:	72 43                	jb     1db7 <msk_transmit_skb+0x387>
		skb_under_panic(skb, len, current_text_addr());
	}
    1d74:	8b 4d 0c             	mov    0xc(%ebp),%ecx
    1d77:	8b 81 94 00 00 00    	mov    0x94(%ecx),%eax
		udp_hdr = (struct udphdr*) 
			skb_push(skb, sizeof(struct udphdr));
		udp_hdr->source = sk->sport;
    1d7d:	8b 4d e8             	mov    0xffffffe8(%ebp),%ecx
    1d80:	0f b7 51 22          	movzwl 0x22(%ecx),%edx
    1d84:	66 89 10             	mov    %dx,(%eax)
		udp_hdr->dest = sk->dport;
    1d87:	0f b7 51 08          	movzwl 0x8(%ecx),%edx
		udp_hdr->len = htons(sizeof(struct udphdr));
    1d8b:	66 c7 40 04 00 08    	movw   $0x800,0x4(%eax)
		udp_hdr->check = 0;
    1d91:	66 c7 40 06 00 00    	movw   $0x0,0x6(%eax)
    1d97:	66 89 50 02          	mov    %dx,0x2(%eax)
		err = af->queue_xmit(skb, 0);
    1d9b:	8b 45 0c             	mov    0xc(%ebp),%eax
    1d9e:	c7 44 24 04 00 00 00 	movl   $0x0,0x4(%esp,1)
    1da5:	00 
    1da6:	89 04 24             	mov    %eax,(%esp,1)
    1da9:	ff 15 00 00 00 00    	call   *0x0
	}
#else
	err = 0;
	skb->nh.iph = (struct iphdr*)skb_push(skb, sizeof(struct iphdr));
	skb->nh.iph->daddr = msk->daddr;
	skb->nh.iph->saddr = msk->saddr;
	sendtoclient(skb);
#endif // USERTEST
	return err;
}
    1daf:	83 c4 34             	add    $0x34,%esp
    1db2:	5b                   	pop    %ebx
    1db3:	5e                   	pop    %esi
    1db4:	5f                   	pop    %edi
    1db5:	5d                   	pop    %ebp
    1db6:	c3                   	ret    
{
	skb->data-=len;
	skb->len+=len;
	if(skb->data<skb->head) {
		skb_under_panic(skb, len, current_text_addr());
    1db7:	c7 44 24 08 bf 1d 00 	movl   $0x1dbf,0x8(%esp,1)
    1dbe:	00 
    1dbf:	c7 44 24 04 08 00 00 	movl   $0x8,0x4(%esp,1)
    1dc6:	00 
    1dc7:	89 14 24             	mov    %edx,(%esp,1)
    1dca:	e8 fc ff ff ff       	call   1dcb <msk_transmit_skb+0x39b>
    1dcf:	eb a3                	jmp    1d74 <msk_transmit_skb+0x344>
    1dd1:	c7 44 24 04 00 00 00 	movl   $0x0,0x4(%esp,1)
    1dd8:	00 
    1dd9:	8b 4d 0c             	mov    0xc(%ebp),%ecx
    1ddc:	89 0c 24             	mov    %ecx,(%esp,1)
    1ddf:	eb c8                	jmp    1da9 <msk_transmit_skb+0x379>
#ifndef USERTEST
static inline void trickles_checksum(struct sk_buff *skb, int headerLen) {
	struct sock *sk = skb->sk;
	if(skb->ip_summed == CHECKSUM_HW) {
		skb->h.th->check = 0;
    1de1:	8b 41 20             	mov    0x20(%ecx),%eax
						   unsigned long daddr,
						   unsigned short len,
						   unsigned short proto,
						   unsigned int sum)
{
    1de4:	31 d2                	xor    %edx,%edx
#ifndef USERTEST
static inline void trickles_checksum(struct sk_buff *skb, int headerLen) {
	struct sock *sk = skb->sk;
	if(skb->ip_summed == CHECKSUM_HW) {
		skb->h.th->check = 0;
    1de6:	66 c7 40 10 00 00    	movw   $0x0,0x10(%eax)
		skb->h.th->check = ~tcp_v4_check(skb->h.th, skb->len, sk->saddr, sk->daddr,
    1dec:	8b 45 0c             	mov    0xc(%ebp),%eax
    1def:	8b 48 20             	mov    0x20(%eax),%ecx
						   unsigned long daddr,
						   unsigned short len,
						   unsigned short proto,
						   unsigned int sum)
{
    1df2:	0f b7 40 70          	movzwl 0x70(%eax),%eax
/* gcc should generate this for open coded C now too. May be worth switching to 
   it because inline assembly cannot be scheduled. -AK */
static __inline__ __const__ __u16 ___arch__swab16(__u16 x)
{
	__asm__("xchgb %b0,%h0"		/* swap bytes		*/
    1df6:	86 c4                	xchg   %al,%ah
#endif /* OPTIMIZE */


static __inline__ __const__ __u16 __fswab16(__u16 x)
{
    1df8:	c1 e0 10             	shl    $0x10,%eax
    1dfb:	05 00 06 00 00       	add    $0x600,%eax
    1e00:	03 16                	add    (%esi),%edx
    1e02:	13 56 70             	adc    0x70(%esi),%edx
    1e05:	11 c2                	adc    %eax,%edx
    1e07:	83 d2 00             	adc    $0x0,%edx
 */

static inline unsigned int csum_fold(unsigned int sum)
{
	__asm__(
    1e0a:	89 d0                	mov    %edx,%eax
    1e0c:	25 00 00 ff ff       	and    $0xffff0000,%eax
    1e11:	c1 e2 10             	shl    $0x10,%edx
    1e14:	01 d0                	add    %edx,%eax
    1e16:	15 ff ff 00 00       	adc    $0xffff,%eax
		"addl %1, %0		;\n"
		"adcl $0xffff, %0	;\n"
		: "=r" (sum)
		: "r" (sum << 16), "0" (sum & 0xffff0000)
	);
	return (~sum) >> 16;
}

static inline unsigned long csum_tcpudp_nofold(unsigned long saddr,
						   unsigned long daddr,
						   unsigned short len,
						   unsigned short proto,
						   unsigned int sum)
{
    __asm__(
	"addl %1, %0	;\n"
	"adcl %2, %0	;\n"
	"adcl %3, %0	;\n"
	"adcl $0, %0	;\n"
	: "=r" (sum)
	: "g" (daddr), "g"(saddr), "g"((ntohs(len)<<16)+proto*256), "0"(sum));
    return sum;
}

/*
 * computes the checksum of the TCP/UDP pseudo-header
 * returns a 16-bit checksum, already complemented
 */
static inline unsigned short int csum_tcpudp_magic(unsigned long saddr,
						   unsigned long daddr,
						   unsigned short len,
						   unsigned short proto,
						   unsigned int sum)
{
    1e1b:	c1 e8 10             	shr    $0x10,%eax
 */
static __inline__ u16 tcp_v4_check(struct tcphdr *th, int len,
				   unsigned long saddr, unsigned long daddr, 
				   unsigned long base)
{
    1e1e:	66 89 41 10          	mov    %ax,0x10(%ecx)
	if(skb->ip_summed == CHECKSUM_HW) {
		skb->h.th->check = 0;
		skb->h.th->check = ~tcp_v4_check(skb->h.th, skb->len, sk->saddr, sk->daddr,
					 0);
		skb->csum = offsetof(struct tcphdr, check);
    1e22:	8b 55 0c             	mov    0xc(%ebp),%edx
    1e25:	c7 42 78 10 00 00 00 	movl   $0x10,0x78(%edx)
    1e2c:	e9 fb fe ff ff       	jmp    1d2c <msk_transmit_skb+0x2fc>
    1e31:	80 ca 01             	or     $0x1,%dl
    1e34:	88 53 0d             	mov    %dl,0xd(%ebx)
    1e37:	e9 53 fe ff ff       	jmp    1c8f <msk_transmit_skb+0x25f>
    1e3c:	8d 74 26 00          	lea    0x0(%esi,1),%esi
    1e40:	80 ca 12             	or     $0x12,%dl
    1e43:	eb ef                	jmp    1e34 <msk_transmit_skb+0x404>
    1e45:	8b 41 54             	mov    0x54(%ecx),%eax
    1e48:	89 44 24 20          	mov    %eax,0x20(%esp,1)
    1e4c:	89 44 24 1c          	mov    %eax,0x1c(%esp,1)
    1e50:	8b 41 6c             	mov    0x6c(%ecx),%eax
    1e53:	89 44 24 18          	mov    %eax,0x18(%esp,1)
    1e57:	8b 81 d8 00 00 00    	mov    0xd8(%ecx),%eax
    1e5d:	89 44 24 14          	mov    %eax,0x14(%esp,1)
    1e61:	8b 41 68             	mov    0x68(%ecx),%eax
    1e64:	89 44 24 10          	mov    %eax,0x10(%esp,1)
    1e68:	a1 40 00 00 00       	mov    0x40,%eax
    1e6d:	89 44 24 0c          	mov    %eax,0xc(%esp,1)
    1e71:	8b 81 e0 00 00 00    	mov    0xe0(%ecx),%eax
    1e77:	8b 44 30 04          	mov    0x4(%eax,%esi,1),%eax
    1e7b:	89 44 24 08          	mov    %eax,0x8(%esp,1)
    1e7f:	0f bf 41 1e          	movswl 0x1e(%ecx),%eax
    1e83:	89 44 24 04          	mov    %eax,0x4(%esp,1)
    1e87:	8b 41 18             	mov    0x18(%ecx),%eax
    1e8a:	89 04 24             	mov    %eax,(%esp,1)
    1e8d:	ff 15 00 00 00 00    	call   *0x0
    1e93:	e9 8d fd ff ff       	jmp    1c25 <msk_transmit_skb+0x1f5>
{
	skb->data-=len;
	skb->len+=len;
	if(skb->data<skb->head) {
		skb_under_panic(skb, len, current_text_addr());
    1e98:	c7 44 24 08 a0 1e 00 	movl   $0x1ea0,0x8(%esp,1)
    1e9f:	00 
    1ea0:	c7 44 24 04 18 00 00 	movl   $0x18,0x4(%esp,1)
    1ea7:	00 
    1ea8:	89 0c 24             	mov    %ecx,(%esp,1)
    1eab:	e8 fc ff ff ff       	call   1eac <msk_transmit_skb+0x47c>
    1eb0:	e9 3a fd ff ff       	jmp    1bef <msk_transmit_skb+0x1bf>
    1eb5:	c7 44 24 08 bd 1e 00 	movl   $0x1ebd,0x8(%esp,1)
    1ebc:	00 
    1ebd:	c7 44 24 04 56 00 00 	movl   $0x56,0x4(%esp,1)
    1ec4:	00 
    1ec5:	89 0c 24             	mov    %ecx,(%esp,1)
    1ec8:	e8 fc ff ff ff       	call   1ec9 <msk_transmit_skb+0x499>
    1ecd:	e9 7f fc ff ff       	jmp    1b51 <msk_transmit_skb+0x121>
    1ed2:	c7 44 24 04 0d 00 00 	movl   $0xd,0x4(%esp,1)
    1ed9:	00 
    1eda:	31 db                	xor    %ebx,%ebx
    1edc:	c7 04 24 11 00 00 00 	movl   $0x11,(%esp,1)
    1ee3:	e8 fc ff ff ff       	call   1ee4 <msk_transmit_skb+0x4b4>
    1ee8:	e8 fc ff ff ff       	call   1ee9 <msk_transmit_skb+0x4b9>
    1eed:	e9 88 fc ff ff       	jmp    1b7a <msk_transmit_skb+0x14a>
 */

static inline unsigned char *skb_push(struct sk_buff *skb, unsigned int len)
{
	skb->data-=len;
    1ef2:	8b 55 0c             	mov    0xc(%ebp),%edx
    1ef5:	8b 82 94 00 00 00    	mov    0x94(%edx),%eax
	skb->len+=len;
    1efb:	83 42 70 21          	addl   $0x21,0x70(%edx)
    1eff:	83 e8 21             	sub    $0x21,%eax
	if(skb->data<skb->head) {
    1f02:	3b 82 90 00 00 00    	cmp    0x90(%edx),%eax
    1f08:	89 82 94 00 00 00    	mov    %eax,0x94(%edx)
    1f0e:	72 36                	jb     1f46 <msk_transmit_skb+0x516>
    1f10:	8b 55 08             	mov    0x8(%ebp),%edx
	skb->data-=len;
	skb->len+=len;
	if(skb->data<skb->head) {
		skb_under_panic(skb, len, current_text_addr());
	}
    1f13:	8b 4d 0c             	mov    0xc(%ebp),%ecx
    1f16:	8b 82 e0 00 00 00    	mov    0xe0(%edx),%eax
	skb->data-=len;
	skb->len+=len;
	if(skb->data<skb->head) {
		skb_under_panic(skb, len, current_text_addr());
	}
    1f1c:	8b 99 94 00 00 00    	mov    0x94(%ecx),%ebx
	__arch__swab24s(addr);
}

static __inline__ __const__ __u32 __fswab32(__u32 x)
{
    1f22:	8b 44 30 04          	mov    0x4(%eax,%esi,1),%eax

static __inline__ __const__ __u32 ___arch__swab32(__u32 x)
{
#ifdef CONFIG_X86_BSWAP
	__asm__("bswap %0" : "=r" (x) : "0" (x));
    1f26:	0f c8                	bswap  %eax
    1f28:	c6 43 0c 00          	movb   $0x0,0xc(%ebx)
	__arch__swab24s(addr);
}

static __inline__ __const__ __u32 __fswab32(__u32 x)
{
    1f2c:	89 43 0d             	mov    %eax,0xd(%ebx)
    1f2f:	8b 42 3c             	mov    0x3c(%edx),%eax
    1f32:	89 43 15             	mov    %eax,0x15(%ebx)
    1f35:	8b 42 40             	mov    0x40(%edx),%eax
    1f38:	89 43 19             	mov    %eax,0x19(%ebx)
    1f3b:	8b 42 50             	mov    0x50(%edx),%eax
    1f3e:	89 43 1d             	mov    %eax,0x1d(%ebx)
    1f41:	e9 34 fc ff ff       	jmp    1b7a <msk_transmit_skb+0x14a>
{
	skb->data-=len;
	skb->len+=len;
	if(skb->data<skb->head) {
		skb_under_panic(skb, len, current_text_addr());
    1f46:	c7 44 24 08 4e 1f 00 	movl   $0x1f4e,0x8(%esp,1)
    1f4d:	00 
    1f4e:	c7 44 24 04 21 00 00 	movl   $0x21,0x4(%esp,1)
    1f55:	00 
    1f56:	89 14 24             	mov    %edx,(%esp,1)
    1f59:	e8 fc ff ff ff       	call   1f5a <msk_transmit_skb+0x52a>
    1f5e:	eb b0                	jmp    1f10 <msk_transmit_skb+0x4e0>
    1f60:	c7 44 24 08 68 1f 00 	movl   $0x1f68,0x8(%esp,1)
    1f67:	00 
    1f68:	89 4c 24 04          	mov    %ecx,0x4(%esp,1)
    1f6c:	89 14 24             	mov    %edx,(%esp,1)
    1f6f:	e8 fc ff ff ff       	call   1f70 <msk_transmit_skb+0x540>
    1f74:	e9 5a fb ff ff       	jmp    1ad3 <msk_transmit_skb+0xa3>
    1f79:	8d b4 26 00 00 00 00 	lea    0x0(%esi,1),%esi
return __res;
}

static inline void * __memcpy(void * to, const void * from, size_t n)
{
    1f80:	8b 45 08             	mov    0x8(%ebp),%eax
    1f83:	8b 90 e0 00 00 00    	mov    0xe0(%eax),%edx
    1f89:	e9 7a fb ff ff       	jmp    1b08 <msk_transmit_skb+0xd8>
    1f8e:	89 f6                	mov    %esi,%esi
    1f90:	c7 44 24 04 59 03 00 	movl   $0x359,0x4(%esp,1)
    1f97:	00 
    1f98:	c7 04 24 40 05 00 00 	movl   $0x540,(%esp,1)
    1f9f:	e8 fc ff ff ff       	call   1fa0 <msk_transmit_skb+0x570>
    1fa4:	e9 e8 fa ff ff       	jmp    1a91 <msk_transmit_skb+0x61>
    1fa9:	8d b4 26 00 00 00 00 	lea    0x0(%esi,1),%esi
    1fb0:	c7 04 24 6a 01 00 00 	movl   $0x16a,(%esp,1)
    1fb7:	a1 00 00 00 00       	mov    0x0,%eax
    1fbc:	89 44 24 04          	mov    %eax,0x4(%esp,1)
    1fc0:	e8 fc ff ff ff       	call   1fc1 <msk_transmit_skb+0x591>
    1fc5:	e9 b1 fa ff ff       	jmp    1a7b <msk_transmit_skb+0x4b>
    1fca:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi

00001fd0 <NormalizeContinuation>:



/*
  Sequence #
  State
  **Recovery:
  firstLoss
  firstBootstrapSeq

  **AckTCPCwnd
  startCwnd
  ssthresh
  TCPBase */

void NormalizeContinuation(CONTINUATION_TYPE *cont, AckProof *ackProof) {
    1fd0:	55                   	push   %ebp
    1fd1:	89 e5                	mov    %esp,%ebp
#if 0
  // TODO: Disabled normalization code for now because Normalization complicates TCP update calculation
	unsigned seq = cont->seq;
	if(seq - cont->TCPBase > MAX_CWND * MAX_CWND) {
		int cwnd;
		// make sure normalization of parallel threads results in the same new TCPBase
		__u32 right = AckProof_findRight(ackProof, cont->TCPBase),
			newSeq = cont->TCPBase + MAX_CWND * MAX_CWND;
		BUG_TRAP(right >= cont->TCPBase);
		BUG_TRAP(newSeq <= right);
		cwnd = AckTCPCwndScalar(newSeq, cont);
		if(cwnd < 0) {
			printk("Bad CWND in normalizeContinuation\n");
			return;
		}
		cont->startCwnd = cwnd;
		cont->TCPBase = newSeq;
		printk("Warning: Normalization is not correct yet!\n");
	}
#endif
}
    1fd3:	5d                   	pop    %ebp
    1fd4:	c3                   	ret    
    1fd5:	8d 74 26 00          	lea    0x0(%esi,1),%esi
    1fd9:	8d bc 27 00 00 00 00 	lea    0x0(%edi,1),%edi

00001fe0 <DoNormalStep>:

#ifdef USE_INCREMENTAL_CWND
 __u32 AckTCPHint(__u32 prevCwnd, __u32 *hint, __u32 seq, CONTINUATION_TYPE *cont) {
	__u32 currCwnd;
	// Updates result for next call to AckTCPHint
	if(*hint != -1) {
		/* Compute update starting from hint */
		currCwnd = prevCwnd;
		if(seq >= *hint) {
			int delta = seq  - *hint, ticks = 0;
			currCwnd = CLAMP(currCwnd + 1);
			if(currCwnd < cont->ssthresh) {
				currCwnd = CLAMP(MIN(cont->ssthresh, 
						     currCwnd + delta));
				delta -= currCwnd - prevCwnd;
			}
			while(delta >= currCwnd) {
				ticks++;
				BUG_TRAP(currCwnd >= cont->ssthresh);
				delta -= currCwnd;
				currCwnd = CLAMP(currCwnd + 1);
			}
			if(currCwnd < cont->ssthresh) {
				*hint = seq + 1;
			} else {
				*hint = seq + (-delta);
			}
		}
	} else {
		/* Compute from scratch */
		currCwnd = AckTCPCwndScalar(cont->seq, cont);
	}
	return currCwnd;
}
#endif // USE_INCREMENTAL_CWND

#define INITIAL_CWND (0)
#define FIRST_ACKSEQ(CONTTYPE, SEQ) \
    ((CONTTYPE) == CONTTYPE_FULL2 ? (SEQ) - 1 : (SEQ))
static int DoNormalStep(CONTINUATION_TYPE **cont, 
			 AckProof *ackProof, 
			 enum cminisock_event_tag event) {
    1fe0:	55                   	push   %ebp
    1fe1:	89 e5                	mov    %esp,%ebp
    1fe3:	57                   	push   %edi
	int i, numPackets = 0;
  __u32 first_ack_seq = 
    FIRST_ACKSEQ((*cont)->continuationType, 
		 (*cont)->seq), firstResponseSeq;
  int prevCwnd, currCwnd;
  int numOutput;
  int first = 1, thisResponseLen = 0, hint;
  __u32 offset;

  (*cont)->executionTrace = 1;
    1fe4:	bf 01 00 00 00       	mov    $0x1,%edi
    1fe9:	56                   	push   %esi
    1fea:	53                   	push   %ebx
    1feb:	83 ec 30             	sub    $0x30,%esp
    1fee:	c7 45 e8 00 00 00 00 	movl   $0x0,0xffffffe8(%ebp)
    1ff5:	8b 55 08             	mov    0x8(%ebp),%edx
    1ff8:	8b 02                	mov    (%edx),%eax
    1ffa:	83 78 38 02          	cmpl   $0x2,0x38(%eax)
    1ffe:	89 b8 d0 00 00 00    	mov    %edi,0xd0(%eax)
    2004:	8b 70 34             	mov    0x34(%eax),%esi

  TIMING_CTX_DEF0("DoNormalStep", "");
  TIMING_CTX_DEF1(7);
  reinitTimingCtx(&ctx);
  recordSample(&ctx,0);

  prevCwnd = (first_ack_seq == (*cont)->TCPBase) ? 
    2007:	8b 45 08             	mov    0x8(%ebp),%eax
    200a:	8d 56 ff             	lea    0xffffffff(%esi),%edx
    200d:	0f 44 f2             	cmove  %edx,%esi
    2010:	8b 10                	mov    (%eax),%edx
    2012:	3b 72 70             	cmp    0x70(%edx),%esi
    2015:	0f 84 cd 03 00 00    	je     23e8 <DoNormalStep+0x408>
    201b:	89 54 24 04          	mov    %edx,0x4(%esp,1)
    201f:	8d 45 f0             	lea    0xfffffff0(%ebp),%eax
    2022:	89 44 24 08          	mov    %eax,0x8(%esp,1)
    2026:	8d 46 ff             	lea    0xffffffff(%esi),%eax
    2029:	89 04 24             	mov    %eax,(%esp,1)
    202c:	e8 fc ff ff ff       	call   202d <DoNormalStep+0x4d>
    2031:	89 c7                	mov    %eax,%edi
    2033:	8b 45 08             	mov    0x8(%ebp),%eax
    2036:	8b 10                	mov    (%eax),%edx
    2038:	8b 42 34             	mov    0x34(%edx),%eax
    203b:	89 54 24 04          	mov    %edx,0x4(%esp,1)
    203f:	c7 44 24 08 00 00 00 	movl   $0x0,0x8(%esp,1)
    2046:	00 
    2047:	89 04 24             	mov    %eax,(%esp,1)
    204a:	e8 fc ff ff ff       	call   204b <DoNormalStep+0x6b>
    (*cont)->startCwnd : 
    AckTCPCwnd(first_ack_seq - 1, (*cont), &hint);
  recordSample(&ctx,0);

#ifndef USE_INCREMENTAL_CWND
  currCwnd = AckTCPCwndScalar((*cont)->seq, (*cont));
#else
  currCwnd = AckTCPHint(prevCwnd, &hint, (*cont)->seq, (*cont));
#endif
  (*cont)->actualCwnd = currCwnd;
    204f:	8b 55 08             	mov    0x8(%ebp),%edx
    2052:	89 c3                	mov    %eax,%ebx
    2054:	8b 02                	mov    (%edx),%eax
    2056:	89 98 d4 00 00 00    	mov    %ebx,0xd4(%eax)

  //printk("prevCwnd: %u currCwnd: %u - ", prevCwnd, currCwnd);
  recordSample(&ctx,0);
  numOutput = MAX(0, currCwnd - (int)prevCwnd);
    205c:	89 d8                	mov    %ebx,%eax
    205e:	29 f8                	sub    %edi,%eax
    2060:	c7 45 e0 00 00 00 00 	movl   $0x0,0xffffffe0(%ebp)
    2067:	0f 48 45 e0          	cmovs  0xffffffe0(%ebp),%eax
    206b:	89 45 e0             	mov    %eax,0xffffffe0(%ebp)

  switch((*cont)->continuationType) {
    206e:	8b 02                	mov    (%edx),%eax
    2070:	8b 40 38             	mov    0x38(%eax),%eax
    2073:	83 f8 01             	cmp    $0x1,%eax
    2076:	0f 84 64 03 00 00    	je     23e0 <DoNormalStep+0x400>
    207c:	83 f8 02             	cmp    $0x2,%eax
    207f:	0f 84 4f 03 00 00    	je     23d4 <DoNormalStep+0x3f4>
  case CONTTYPE_FULL1:
    numOutput += 1;
    break;
  case CONTTYPE_FULL2:
    numOutput += 2;
    break;
  default:
    BUG();
    2085:	c7 44 24 04 0d 00 00 	movl   $0xd,0x4(%esp,1)
    208c:	00 
    208d:	c7 04 24 11 00 00 00 	movl   $0x11,(%esp,1)
    2094:	e8 fc ff ff ff       	call   2095 <DoNormalStep+0xb5>
    2099:	e8 fc ff ff ff       	call   209a <DoNormalStep+0xba>
  }

  if(prevCwnd < 0 || currCwnd < 0) {
    209e:	85 ff                	test   %edi,%edi
    20a0:	0f 88 7e 02 00 00    	js     2324 <DoNormalStep+0x344>
    20a6:	85 db                	test   %ebx,%ebx
    20a8:	0f 88 76 02 00 00    	js     2324 <DoNormalStep+0x344>
    /* error in AckTCPCwnd; return without generating output */
    if(trickles_ratelimit()) {
      ERROR("Error in acktcpcwnd\n");
    }
    free_trickles_msk((*cont)->sk,*cont);
    free_trickles_msk_finish((*cont)->sk,*cont);
    return -EINVAL;
  }
  if(numOutput < 0) {
    20ae:	8b 45 e0             	mov    0xffffffe0(%ebp),%eax
    20b1:	85 c0                	test   %eax,%eax
    20b3:	0f 88 53 02 00 00    	js     230c <DoNormalStep+0x32c>
    ERROR("Decrease in AckTCPCwnd\n");
    numOutput = 0;
  }
  if(numOutput > 5) {
    20b9:	83 7d e0 05          	cmpl   $0x5,0xffffffe0(%ebp)
    20bd:	7e 66                	jle    2125 <DoNormalStep+0x145>
    printk("bug in cwnd generation: ack_seq = %u-%u, TCPBase = %u, "
    20bf:	8b 45 e0             	mov    0xffffffe0(%ebp),%eax
    20c2:	89 44 24 14          	mov    %eax,0x14(%esp,1)
    20c6:	8b 45 08             	mov    0x8(%ebp),%eax
    20c9:	8b 10                	mov    (%eax),%edx
    20cb:	8b 42 68             	mov    0x68(%edx),%eax
    20ce:	89 44 24 10          	mov    %eax,0x10(%esp,1)
    20d2:	8b 42 70             	mov    0x70(%edx),%eax
    20d5:	89 44 24 0c          	mov    %eax,0xc(%esp,1)
    20d9:	8b 42 34             	mov    0x34(%edx),%eax
    20dc:	89 74 24 04          	mov    %esi,0x4(%esp,1)
    20e0:	c7 04 24 a0 05 00 00 	movl   $0x5a0,(%esp,1)
    20e7:	89 44 24 08          	mov    %eax,0x8(%esp,1)
    20eb:	e8 fc ff ff ff       	call   20ec <DoNormalStep+0x10c>
	   "cwnd = %u, numOutput = %u, \n",
	   first_ack_seq, (*cont)->seq, (*cont)->TCPBase, 
	   (*cont)->startCwnd, numOutput);
    
    free_trickles_msk((*cont)->sk,(*cont));
    20f0:	8b 55 08             	mov    0x8(%ebp),%edx
    20f3:	8b 02                	mov    (%edx),%eax
    20f5:	89 44 24 04          	mov    %eax,0x4(%esp,1)
    20f9:	8b 40 20             	mov    0x20(%eax),%eax
    20fc:	89 04 24             	mov    %eax,(%esp,1)
    20ff:	e8 fc de ff ff       	call   0 <free_trickles_msk>
    free_trickles_msk_finish((*cont)->sk,(*cont));
    2104:	8b 55 08             	mov    0x8(%ebp),%edx
    2107:	8b 02                	mov    (%edx),%eax
    2109:	89 44 24 04          	mov    %eax,0x4(%esp,1)
    210d:	8b 40 20             	mov    0x20(%eax),%eax
    2110:	89 04 24             	mov    %eax,(%esp,1)
    2113:	e8 88 df ff ff       	call   a0 <free_trickles_msk_finish>
    return -EINVAL;
    2118:	b8 ea ff ff ff       	mov    $0xffffffea,%eax
  }
  recordSample(&ctx,0);
  NormalizeContinuation(*cont,ackProof);
  recordSample(&ctx,0);
  firstResponseSeq = first_ack_seq + prevCwnd;

  // allocate space for packets
  if(!alloc_msk_packets((*cont), numOutput)) {
    free_trickles_msk((*cont)->sk,(*cont));
    free_trickles_msk_finish((*cont)->sk,(*cont));
    return -ENOMEM;
  }
  for(i=0; i < numOutput; i++) {
    __u32 seq = firstResponseSeq + i;
    int thisMTU, nextResponseLen = 0, firstChild = -1, 
      numChildren = -1, contType;
    if(serverDebugLevel >= 1) {
      if((*cont)->state == CONT_BOOTSTRAP) {
	printk("  %u\n", seq);
      }
    }
    // Algorithm choices here affect normalize continuation
    offset = seq - (*cont)->TCPBase;

#define CONTTYPE(OFFSET) (((OFFSET) <= 8) ? CONTTYPE_FULL1 :		\
			  (((OFFSET) % 2 == 0) ? CONTTYPE_FULL2 :	\
			   CONTTYPE_MINIMAL))

    /* calculate number of packets in successor*/
    contType = CONTTYPE(offset);

#ifdef ENABLE_HASHCOMPRESS
    switch(contType) {
    case CONTTYPE_FULL1:
    case CONTTYPE_FULL2:
	    thisMTU = CONTTYPE_HASHCOMPRESS_MTU;
	    break;
    case CONTTYPE_MINIMAL:
	    thisMTU = CONTTYPE_HASHCOMPRESS_MTU;
	    break;
    default:
	    thisMTU = -1;
	    BUG();
    }
    contType |= CONTTYPE_HASHCOMPRESSED;
#else
    switch(contType) {
    case CONTTYPE_FULL1:
    case CONTTYPE_FULL2:
	    thisMTU = CONTTYPE_FULL_MTU;
	    break;
    case CONTTYPE_MINIMAL:
	    thisMTU = CONTTYPE_MINIMAL_MTU;
	    break;
    default:
	    thisMTU = -1;
	    BUG();
    }
#endif
    thisResponseLen += thisMTU;
    makePacket(&(*cont)->packets[numPackets], seq, 0xdeadbeef, thisMTU, -1, (first ? PTYPE_FIRST : 0) | PACKET_NORMAL, contType, nextResponseLen,
	       firstChild, numChildren);


    first = 0;
    numPackets++;
  }
  (*cont)->num_packets = numPackets;
  BUG_TRAP(numPackets <= numOutput);
  recordSample(&ctx,0);

  DoUpcall((*cont), event);
  recordSample(&ctx,0);
  //printTimings(&ctx);
  return 0;
}
    211d:	83 c4 30             	add    $0x30,%esp
    2120:	5b                   	pop    %ebx
    2121:	5e                   	pop    %esi
    2122:	5f                   	pop    %edi
    2123:	5d                   	pop    %ebp
    2124:	c3                   	ret    
    2125:	8b 45 0c             	mov    0xc(%ebp),%eax
    2128:	01 fe                	add    %edi,%esi
    212a:	8b 55 08             	mov    0x8(%ebp),%edx
    212d:	89 44 24 04          	mov    %eax,0x4(%esp,1)
    2131:	8b 02                	mov    (%edx),%eax
    2133:	89 04 24             	mov    %eax,(%esp,1)
    2136:	e8 fc ff ff ff       	call   2137 <DoNormalStep+0x157>
    213b:	8b 45 e0             	mov    0xffffffe0(%ebp),%eax
    213e:	8b 55 08             	mov    0x8(%ebp),%edx
    2141:	89 75 e4             	mov    %esi,0xffffffe4(%ebp)
    2144:	89 44 24 04          	mov    %eax,0x4(%esp,1)
    2148:	8b 02                	mov    (%edx),%eax
    214a:	89 04 24             	mov    %eax,(%esp,1)
    214d:	e8 fe 0d 00 00       	call   2f50 <alloc_msk_packets>
    2152:	85 c0                	test   %eax,%eax
    2154:	0f 84 80 01 00 00    	je     22da <DoNormalStep+0x2fa>
    215a:	c7 45 ec 00 00 00 00 	movl   $0x0,0xffffffec(%ebp)
    2161:	8b 45 e0             	mov    0xffffffe0(%ebp),%eax
    2164:	39 45 ec             	cmp    %eax,0xffffffec(%ebp)
    2167:	0f 8d f6 00 00 00    	jge    2263 <DoNormalStep+0x283>
    216d:	8b 55 e8             	mov    0xffffffe8(%ebp),%edx
    2170:	8d 04 92             	lea    (%edx,%edx,4),%eax
    2173:	c1 e0 03             	shl    $0x3,%eax
    2176:	89 45 dc             	mov    %eax,0xffffffdc(%ebp)
    2179:	8d b4 26 00 00 00 00 	lea    0x0(%esi,1),%esi
    2180:	8b 75 e4             	mov    0xffffffe4(%ebp),%esi
    2183:	8b 45 ec             	mov    0xffffffec(%ebp),%eax
    2186:	8b 3d 00 00 00 00    	mov    0x0,%edi
    218c:	01 c6                	add    %eax,%esi
    218e:	85 ff                	test   %edi,%edi
    2190:	0f 8e 3a 01 00 00    	jle    22d0 <DoNormalStep+0x2f0>
    2196:	8b 45 08             	mov    0x8(%ebp),%eax
    2199:	8b 10                	mov    (%eax),%edx
    219b:	83 7a 58 02          	cmpl   $0x2,0x58(%edx)
    219f:	0f 84 1b 01 00 00    	je     22c0 <DoNormalStep+0x2e0>
    21a5:	8b 5a 70             	mov    0x70(%edx),%ebx
    21a8:	89 f0                	mov    %esi,%eax
    21aa:	29 d8                	sub    %ebx,%eax
    21ac:	83 f8 08             	cmp    $0x8,%eax
    21af:	0f 86 fb 00 00 00    	jbe    22b0 <DoNormalStep+0x2d0>
    21b5:	31 db                	xor    %ebx,%ebx
    21b7:	a9 01 00 00 00       	test   $0x1,%eax
    21bc:	0f 94 c3             	sete   %bl
    21bf:	01 db                	add    %ebx,%ebx
    21c1:	85 db                	test   %ebx,%ebx
    21c3:	bf 87 05 00 00       	mov    $0x587,%edi
    21c8:	74 2d                	je     21f7 <DoNormalStep+0x217>
    21ca:	83 fb 02             	cmp    $0x2,%ebx
    21cd:	bf 52 05 00 00       	mov    $0x552,%edi
    21d2:	7e 23                	jle    21f7 <DoNormalStep+0x217>
    21d4:	c7 44 24 04 0d 00 00 	movl   $0xd,0x4(%esp,1)
    21db:	00 
    21dc:	bf ff ff ff ff       	mov    $0xffffffff,%edi
    21e1:	c7 04 24 11 00 00 00 	movl   $0x11,(%esp,1)
    21e8:	e8 fc ff ff ff       	call   21e9 <DoNormalStep+0x209>
    21ed:	e8 fc ff ff ff       	call   21ee <DoNormalStep+0x20e>
    21f2:	8b 45 08             	mov    0x8(%ebp),%eax
    21f5:	8b 10                	mov    (%eax),%edx
			      __u8 type, 
			      __u8 contType, 
			      __u16 minResponseLen,
			      __u32 firstTransportChild, 
			      __u8 numTransportChildren) {
    21f7:	8b 8a e0 00 00 00    	mov    0xe0(%edx),%ecx
    21fd:	8b 45 dc             	mov    0xffffffdc(%ebp),%eax
    2200:	01 c8                	add    %ecx,%eax
    2202:	88 d9                	mov    %bl,%cl
  pkt->nonce = -1;
  pkt->seq = seq;
  //pkt->ack_seq = ack_seq;
  pkt->len = len;
  pkt->byteNum = byteNum;
  pkt->type = type;
  pkt->contType = contType;
    2204:	c0 e1 03             	shl    $0x3,%cl
    2207:	0f b6 50 10          	movzbl 0x10(%eax),%edx
    220b:	c7 00 ff ff ff ff    	movl   $0xffffffff,(%eax)
    2211:	89 70 04             	mov    %esi,0x4(%eax)
    2214:	89 78 08             	mov    %edi,0x8(%eax)
    2217:	80 e2 c0             	and    $0xc0,%dl
    221a:	08 ca                	or     %cl,%dl
    221c:	c7 40 0c ff ff ff ff 	movl   $0xffffffff,0xc(%eax)
    2223:	88 50 10             	mov    %dl,0x10(%eax)
  pkt->minResponseLen = minResponseLen;
    2226:	66 c7 40 1c 00 00    	movw   $0x0,0x1c(%eax)
  pkt->firstTransportChild = firstTransportChild;
    222c:	c7 40 20 ff ff ff ff 	movl   $0xffffffff,0x20(%eax)
  pkt->numTransportChildren = numTransportChildren;
    2233:	c6 40 24 ff          	movb   $0xff,0x24(%eax)
  pkt->ucontLen = 0;
    2237:	c7 40 14 00 00 00 00 	movl   $0x0,0x14(%eax)
  pkt->ucontData = NULL;
    223e:	c7 40 18 00 00 00 00 	movl   $0x0,0x18(%eax)
  pkt->numSiblings = -1;
    2245:	c6 40 11 ff          	movb   $0xff,0x11(%eax)
  pkt->position = INVALID_POSITION;
    2249:	c6 40 12 ff          	movb   $0xff,0x12(%eax)
    224d:	8b 55 e0             	mov    0xffffffe0(%ebp),%edx
    2250:	ff 45 ec             	incl   0xffffffec(%ebp)
    2253:	83 45 dc 28          	addl   $0x28,0xffffffdc(%ebp)
    2257:	ff 45 e8             	incl   0xffffffe8(%ebp)
    225a:	39 55 ec             	cmp    %edx,0xffffffec(%ebp)
    225d:	0f 8c 1d ff ff ff    	jl     2180 <DoNormalStep+0x1a0>
    2263:	8b 55 08             	mov    0x8(%ebp),%edx
    2266:	8b 02                	mov    (%edx),%eax
    2268:	8b 55 e8             	mov    0xffffffe8(%ebp),%edx
    226b:	89 90 dc 00 00 00    	mov    %edx,0xdc(%eax)
    2271:	8b 45 e0             	mov    0xffffffe0(%ebp),%eax
    2274:	39 c2                	cmp    %eax,%edx
    2276:	7f 1b                	jg     2293 <DoNormalStep+0x2b3>
    2278:	8b 45 10             	mov    0x10(%ebp),%eax
    227b:	8b 55 08             	mov    0x8(%ebp),%edx
    227e:	89 44 24 04          	mov    %eax,0x4(%esp,1)
    2282:	8b 02                	mov    (%edx),%eax
    2284:	89 04 24             	mov    %eax,(%esp,1)
    2287:	e8 fc ff ff ff       	call   2288 <DoNormalStep+0x2a8>
    228c:	31 c0                	xor    %eax,%eax
    228e:	e9 8a fe ff ff       	jmp    211d <DoNormalStep+0x13d>
    2293:	c7 44 24 04 db 04 00 	movl   $0x4db,0x4(%esp,1)
    229a:	00 
    229b:	c7 04 24 00 06 00 00 	movl   $0x600,(%esp,1)
    22a2:	e8 fc ff ff ff       	call   22a3 <DoNormalStep+0x2c3>
    22a7:	eb cf                	jmp    2278 <DoNormalStep+0x298>
    22a9:	8d b4 26 00 00 00 00 	lea    0x0(%esi,1),%esi
    22b0:	bb 01 00 00 00       	mov    $0x1,%ebx
    22b5:	e9 07 ff ff ff       	jmp    21c1 <DoNormalStep+0x1e1>
    22ba:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi
    22c0:	89 74 24 04          	mov    %esi,0x4(%esp,1)
    22c4:	c7 04 24 7e 01 00 00 	movl   $0x17e,(%esp,1)
    22cb:	e8 fc ff ff ff       	call   22cc <DoNormalStep+0x2ec>
    22d0:	8b 45 08             	mov    0x8(%ebp),%eax
    22d3:	8b 10                	mov    (%eax),%edx
    22d5:	e9 cb fe ff ff       	jmp    21a5 <DoNormalStep+0x1c5>
    22da:	8b 55 08             	mov    0x8(%ebp),%edx
    22dd:	8b 02                	mov    (%edx),%eax
    22df:	89 44 24 04          	mov    %eax,0x4(%esp,1)
    22e3:	8b 40 20             	mov    0x20(%eax),%eax
    22e6:	89 04 24             	mov    %eax,(%esp,1)
    22e9:	e8 12 dd ff ff       	call   0 <free_trickles_msk>
    22ee:	8b 55 08             	mov    0x8(%ebp),%edx
    22f1:	8b 02                	mov    (%edx),%eax
    22f3:	89 44 24 04          	mov    %eax,0x4(%esp,1)
    22f7:	8b 40 20             	mov    0x20(%eax),%eax
    22fa:	89 04 24             	mov    %eax,(%esp,1)
    22fd:	e8 9e dd ff ff       	call   a0 <free_trickles_msk_finish>
    2302:	b8 f4 ff ff ff       	mov    $0xfffffff4,%eax
    2307:	e9 11 fe ff ff       	jmp    211d <DoNormalStep+0x13d>
    230c:	c7 04 24 84 01 00 00 	movl   $0x184,(%esp,1)
    2313:	e8 fc ff ff ff       	call   2314 <DoNormalStep+0x334>
    2318:	c7 45 e0 00 00 00 00 	movl   $0x0,0xffffffe0(%ebp)
    231f:	e9 95 fd ff ff       	jmp    20b9 <DoNormalStep+0xd9>
    2324:	a1 00 00 00 00       	mov    0x0,%eax
    2329:	9c                   	pushf  
    232a:	59                   	pop    %ecx
    232b:	fa                   	cli    
    232c:	89 c2                	mov    %eax,%edx
    232e:	8b 1d 58 e2 04 00    	mov    0x4e258,%ebx
    2334:	8b 3d 44 00 00 00    	mov    0x44,%edi
    233a:	a3 58 e2 04 00       	mov    %eax,0x4e258
    233f:	29 da                	sub    %ebx,%edx
    2341:	01 fa                	add    %edi,%edx
    2343:	89 15 44 00 00 00    	mov    %edx,0x44
    2349:	81 fa 88 13 00 00    	cmp    $0x1388,%edx
    234f:	76 10                	jbe    2361 <DoNormalStep+0x381>
    2351:	be 88 13 00 00       	mov    $0x1388,%esi
    2356:	ba 88 13 00 00       	mov    $0x1388,%edx
    235b:	89 35 44 00 00 00    	mov    %esi,0x44
    2361:	81 fa f3 01 00 00    	cmp    $0x1f3,%edx
    2367:	76 5f                	jbe    23c8 <DoNormalStep+0x3e8>
    2369:	31 db                	xor    %ebx,%ebx
    236b:	81 ea f4 01 00 00    	sub    $0x1f4,%edx
    2371:	a1 5c e2 04 00       	mov    0x4e25c,%eax
    2376:	89 15 44 00 00 00    	mov    %edx,0x44
    237c:	89 1d 5c e2 04 00    	mov    %ebx,0x4e25c
    2382:	51                   	push   %ecx
    2383:	9d                   	popf   
    2384:	85 c0                	test   %eax,%eax
    2386:	75 1e                	jne    23a6 <DoNormalStep+0x3c6>
    2388:	b8 01 00 00 00       	mov    $0x1,%eax
    238d:	85 c0                	test   %eax,%eax
    238f:	0f 84 5b fd ff ff    	je     20f0 <DoNormalStep+0x110>
    2395:	c7 04 24 9c 01 00 00 	movl   $0x19c,(%esp,1)
    239c:	e8 fc ff ff ff       	call   239d <DoNormalStep+0x3bd>
    23a1:	e9 4a fd ff ff       	jmp    20f0 <DoNormalStep+0x110>
    23a6:	89 44 24 0c          	mov    %eax,0xc(%esp,1)
    23aa:	c7 44 24 08 83 04 00 	movl   $0x483,0x8(%esp,1)
    23b1:	00 
    23b2:	c7 44 24 04 45 00 00 	movl   $0x45,0x4(%esp,1)
    23b9:	00 
    23ba:	c7 04 24 80 00 00 00 	movl   $0x80,(%esp,1)
    23c1:	e8 fc ff ff ff       	call   23c2 <DoNormalStep+0x3e2>
    23c6:	eb c0                	jmp    2388 <DoNormalStep+0x3a8>
    23c8:	ff 05 5c e2 04 00    	incl   0x4e25c
    23ce:	51                   	push   %ecx
    23cf:	9d                   	popf   
    23d0:	31 c0                	xor    %eax,%eax
    23d2:	eb b9                	jmp    238d <DoNormalStep+0x3ad>
    23d4:	83 45 e0 02          	addl   $0x2,0xffffffe0(%ebp)
    23d8:	e9 c1 fc ff ff       	jmp    209e <DoNormalStep+0xbe>
    23dd:	8d 76 00             	lea    0x0(%esi),%esi
    23e0:	ff 45 e0             	incl   0xffffffe0(%ebp)
    23e3:	e9 b6 fc ff ff       	jmp    209e <DoNormalStep+0xbe>
    23e8:	8b 7a 68             	mov    0x68(%edx),%edi
    23eb:	e9 48 fc ff ff       	jmp    2038 <DoNormalStep+0x58>

000023f0 <intersect>:


static int intersect(int start0, int end0, int start1, int end1) {
    23f0:	55                   	push   %ebp
    23f1:	89 e5                	mov    %esp,%ebp
    23f3:	53                   	push   %ebx
    23f4:	8b 45 10             	mov    0x10(%ebp),%eax
    23f7:	8b 4d 08             	mov    0x8(%ebp),%ecx
    23fa:	8b 5d 0c             	mov    0xc(%ebp),%ebx
    23fd:	8b 55 14             	mov    0x14(%ebp),%edx
  int start = MAX(start0,start1),
    2400:	39 c8                	cmp    %ecx,%eax
    2402:	0f 4d c8             	cmovge %eax,%ecx
    end = MIN(end0,end1);
    2405:	89 d8                	mov    %ebx,%eax
    2407:	39 da                	cmp    %ebx,%edx
    2409:	0f 4e c2             	cmovle %edx,%eax
  if(start <= end) {
    240c:	39 c1                	cmp    %eax,%ecx
    240e:	7f 06                	jg     2416 <intersect+0x26>
    /* intersection */
    return end - start + 1;
    2410:	29 c8                	sub    %ecx,%eax
    2412:	40                   	inc    %eax
  } else {
    return 0;
  }
}
    2413:	5b                   	pop    %ebx
    2414:	5d                   	pop    %ebp
    2415:	c3                   	ret    
    2416:	31 c0                	xor    %eax,%eax
    2418:	eb f9                	jmp    2413 <intersect+0x23>
    241a:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi

00002420 <DoRecoveryStep>:

#ifdef USERTEST
#if 0
#define serverDebugLevel recoveryDebugLevel
static int recoveryDebugLevel = 99; // temporary use in userspace debugging to print only recovery handler debugging information
#endif
#endif

static int DoRecoveryStep(CONTINUATION_TYPE **cont, AckProof *ackProof, 
			  enum cminisock_event_tag event) {
    2420:	55                   	push   %ebp
    2421:	89 e5                	mov    %esp,%ebp
    2423:	57                   	push   %edi
  int i;
  Sack *sacks = ackProof->sacks;
  // XXX INTMAX suppresses "uninitialized variable" harmless warnings in gcc
  int numLosses = 0, numBootstrapLosses = 0, bootstrapStart, bootstrapEnd, 
	  afterGap = 0,gapLeft = INT_MAX, gapRight = INT_MAX;
  unsigned numPackets = 0;
  int origCwnd, origCwndPred = INT_MAX, newCwnd;
    2424:	bf ff ff ff 7f       	mov    $0x7fffffff,%edi
    2429:	56                   	push   %esi
  int gaplen = INT_MAX;
  int adj = INT_MAX;
  __u32 ack_seq;
  __u32 lastRegularPacket;

  int numPacketsSendable;
  int numPacketsAllocated;

  int bootstrapIntersectStart, 
    bootstrapIntersectLast;

  (*cont)->executionTrace = 2;
    242a:	be 02 00 00 00       	mov    $0x2,%esi
    242f:	53                   	push   %ebx
    2430:	83 ec 74             	sub    $0x74,%esp
    2433:	c7 45 e4 00 00 00 00 	movl   $0x0,0xffffffe4(%ebp)
    243a:	8b 45 0c             	mov    0xc(%ebp),%eax
    243d:	c7 45 e0 ff ff ff 7f 	movl   $0x7fffffff,0xffffffe0(%ebp)
    2444:	8b 55 08             	mov    0x8(%ebp),%edx
    2447:	c7 45 dc ff ff ff 7f 	movl   $0x7fffffff,0xffffffdc(%ebp)
    244e:	83 c0 08             	add    $0x8,%eax
    2451:	89 45 f0             	mov    %eax,0xfffffff0(%ebp)
    2454:	c7 45 d8 00 00 00 00 	movl   $0x0,0xffffffd8(%ebp)
    245b:	c7 45 d0 ff ff ff 7f 	movl   $0x7fffffff,0xffffffd0(%ebp)
    2462:	c7 45 cc ff ff ff 7f 	movl   $0x7fffffff,0xffffffcc(%ebp)
    2469:	8b 02                	mov    (%edx),%eax
    246b:	89 b0 d0 00 00 00    	mov    %esi,0xd0(%eax)
    2471:	8b 4d 0c             	mov    0xc(%ebp),%ecx
    2474:	89 0c 24             	mov    %ecx,(%esp,1)
    2477:	e8 fc ff ff ff       	call   2478 <DoRecoveryStep+0x58>
    247c:	8b 75 08             	mov    0x8(%ebp),%esi
    247f:	8b 16                	mov    (%esi),%edx
    2481:	c7 44 24 08 00 00 00 	movl   $0x0,0x8(%esp,1)
    2488:	00 
    2489:	89 04 24             	mov    %eax,(%esp,1)
    248c:	89 54 24 04          	mov    %edx,0x4(%esp,1)
    2490:	e8 fc ff ff ff       	call   2491 <DoRecoveryStep+0x71>

  origCwnd = AckTCPCwndScalar(AckProof_firstLoss(ackProof), (*cont));
  if(origCwnd < 0) {
    2495:	85 c0                	test   %eax,%eax
    2497:	89 c6                	mov    %eax,%esi
    2499:	0f 88 71 07 00 00    	js     2c10 <DoRecoveryStep+0x7f0>
	  if(!disableSevereErrors)
		  printk("recoveryStep: OrigCwnd undefined\n");
	  free_trickles_msk((*cont)->sk,(*cont));
	  free_trickles_msk_finish((*cont)->sk,(*cont));
	  return -EINVAL;
  }
  (*cont)->state = CONT_RECOVERY;
    249f:	8b 55 08             	mov    0x8(%ebp),%edx
    24a2:	8b 02                	mov    (%edx),%eax
    24a4:	c7 40 58 01 00 00 00 	movl   $0x1,0x58(%eax)
  (*cont)->firstLoss = AckProof_firstLoss(ackProof);
    24ab:	8b 4d 0c             	mov    0xc(%ebp),%ecx
    24ae:	8b 1a                	mov    (%edx),%ebx
    24b0:	89 0c 24             	mov    %ecx,(%esp,1)
    24b3:	e8 fc ff ff ff       	call   24b4 <DoRecoveryStep+0x94>
    24b8:	89 43 60             	mov    %eax,0x60(%ebx)
  switch(CONTTYPE((*cont)->firstLoss - (*cont)->TCPBase)) {
    24bb:	8b 55 08             	mov    0x8(%ebp),%edx
    24be:	8b 02                	mov    (%edx),%eax
    24c0:	8b 50 60             	mov    0x60(%eax),%edx
    24c3:	8b 48 70             	mov    0x70(%eax),%ecx
    24c6:	29 ca                	sub    %ecx,%edx
    24c8:	83 fa 08             	cmp    $0x8,%edx
    24cb:	0f 86 2f 07 00 00    	jbe    2c00 <DoRecoveryStep+0x7e0>
    24d1:	31 c0                	xor    %eax,%eax
    24d3:	f7 c2 01 00 00 00    	test   $0x1,%edx
    24d9:	0f 94 c0             	sete   %al
    24dc:	01 c0                	add    %eax,%eax
    24de:	83 f8 01             	cmp    $0x1,%eax
    24e1:	0f 8e df 06 00 00    	jle    2bc6 <DoRecoveryStep+0x7a6>
    24e7:	83 f8 02             	cmp    $0x2,%eax
    24ea:	0f 84 a1 06 00 00    	je     2b91 <DoRecoveryStep+0x771>
  case CONTTYPE_FULL1: // fall-through
  case CONTTYPE_MINIMAL:
    origCwndPred = AckTCPCwndScalar(AckProof_firstLoss(ackProof)-1, (*cont));
    adj = 0;
    break;
  case CONTTYPE_FULL2:
    origCwndPred = AckTCPCwndScalar(AckProof_firstLoss(ackProof)-2, (*cont));
    adj = -1;
    break;
  }
  if(origCwnd < origCwndPred) {
    24f0:	39 fe                	cmp    %edi,%esi
    24f2:	0f 8c 88 06 00 00    	jl     2b80 <DoRecoveryStep+0x760>
    printk("recoveryStep: OrigCwnd < OrigCwndPred\n");
    free_trickles_msk((*cont)->sk,(*cont));
    free_trickles_msk_finish((*cont)->sk,(*cont));
    return -EINVAL;
  }
  lastRegularPacket =  ((*cont)->firstLoss - 1 + adj) + origCwndPred;
    24f8:	8b 55 08             	mov    0x8(%ebp),%edx
    24fb:	8b 02                	mov    (%edx),%eax
    24fd:	8b 48 60             	mov    0x60(%eax),%ecx
    2500:	01 4d cc             	add    %ecx,0xffffffcc(%ebp)
    2503:	8b 55 cc             	mov    0xffffffcc(%ebp),%edx
    2506:	01 fa                	add    %edi,%edx
  (*cont)->num_packets = 0;
    2508:	31 ff                	xor    %edi,%edi
    250a:	8d 4a ff             	lea    0xffffffff(%edx),%ecx
    250d:	89 4d c4             	mov    %ecx,0xffffffc4(%ebp)
    2510:	89 b8 dc 00 00 00    	mov    %edi,0xdc(%eax)

#if 0  // 0615
  printk("EffCwnd (recoverystep): %d\n", origCwnd);
#endif

  newCwnd = origCwnd / MULT_FACTOR;
    2516:	89 f0                	mov    %esi,%eax
    2518:	c1 e8 1f             	shr    $0x1f,%eax
    251b:	01 c6                	add    %eax,%esi
    251d:	d1 fe                	sar    %esi
    251f:	89 75 d4             	mov    %esi,0xffffffd4(%ebp)

  (*cont)->actualCwnd = newCwnd;
    2522:	8b 75 08             	mov    0x8(%ebp),%esi
    2525:	8b 4d d4             	mov    0xffffffd4(%ebp),%ecx
    2528:	8b 06                	mov    (%esi),%eax

  // FIXME: should allow 2 different TCPBase in CMinisock, since
  // bootstrap and rtx ought to have different TCPBase
  (*cont)->TCPBase = (*cont)->firstBootstrapSeq = lastRegularPacket + 1;
  (*cont)->startCwnd = newCwnd;
#ifndef ZERO_SSTHRESH_PROTECTION_HACK
  (*cont)->ssthresh = newCwnd;
#else
  if(newCwnd == 0)
    252a:	85 c9                	test   %ecx,%ecx
    252c:	89 88 d4 00 00 00    	mov    %ecx,0xd4(%eax)
    2532:	8b 06                	mov    (%esi),%eax
    2534:	89 50 64             	mov    %edx,0x64(%eax)
    2537:	89 50 70             	mov    %edx,0x70(%eax)
    253a:	8b 06                	mov    (%esi),%eax
    253c:	89 48 68             	mov    %ecx,0x68(%eax)
    253f:	0f 85 2b 06 00 00    	jne    2b70 <DoRecoveryStep+0x750>
    (*cont)->ssthresh /= MULT_FACTOR;
    2545:	8b 06                	mov    (%esi),%eax
    2547:	d1 68 6c             	shrl   0x6c(%eax)
  else
    (*cont)->ssthresh = newCwnd;
#endif

  bootstrapStart = lastRegularPacket - newCwnd;
    254a:	8b 4d c4             	mov    0xffffffc4(%ebp),%ecx
  bootstrapEnd = bootstrapStart + newCwnd - 1;

  // XXX 0427 TODO: Remove first transport child processing

  /* Find the number of gaps */
  for(i=0; i < ackProof->numSacks; i++) {
    254d:	31 ff                	xor    %edi,%edi
    254f:	8b 5d d4             	mov    0xffffffd4(%ebp),%ebx
    2552:	8b 75 d4             	mov    0xffffffd4(%ebp),%esi
    2555:	8b 45 0c             	mov    0xc(%ebp),%eax
    2558:	29 d9                	sub    %ebx,%ecx
    255a:	89 4d ec             	mov    %ecx,0xffffffec(%ebp)
    255d:	8d 74 0e ff          	lea    0xffffffff(%esi,%ecx,1),%esi
    2561:	89 75 e8             	mov    %esi,0xffffffe8(%ebp)
    2564:	8b 00                	mov    (%eax),%eax
    2566:	39 c7                	cmp    %eax,%edi
    2568:	89 45 a4             	mov    %eax,0xffffffa4(%ebp)
    256b:	0f 8d 82 00 00 00    	jge    25f3 <DoRecoveryStep+0x1d3>
    2571:	8b 55 08             	mov    0x8(%ebp),%edx
    2574:	31 c9                	xor    %ecx,%ecx
    2576:	8b 1a                	mov    (%edx),%ebx
    2578:	90                   	nop    
    2579:	8d b4 26 00 00 00 00 	lea    0x0(%esi,1),%esi
    int cursorgap = 0;
    2580:	c7 45 bc 00 00 00 00 	movl   $0x0,0xffffffbc(%ebp)
    if(i > 0 && !Sack_adjacent(&sacks[i-1], &sacks[i])) {
    2587:	85 ff                	test   %edi,%edi
    2589:	7e 19                	jle    25a4 <DoRecoveryStep+0x184>
    258b:	8b 75 f0             	mov    0xfffffff0(%ebp),%esi
    258e:	8b 04 0e             	mov    (%esi,%ecx,1),%eax
    2591:	8b 54 0e f8          	mov    0xfffffff8(%esi,%ecx,1),%edx
    2595:	29 d0                	sub    %edx,%eax
    2597:	48                   	dec    %eax
    2598:	74 0a                	je     25a4 <DoRecoveryStep+0x184>
    259a:	89 45 d0             	mov    %eax,0xffffffd0(%ebp)
      gaplen = Sack_gapLen(&sacks[i-1], &sacks[i]);
      cursorgap = 1;
    259d:	c7 45 bc 01 00 00 00 	movl   $0x1,0xffffffbc(%ebp)
    25a4:	8b 45 0c             	mov    0xc(%ebp),%eax
    25a7:	31 d2                	xor    %edx,%edx
    25a9:	8b 75 0c             	mov    0xc(%ebp),%esi
    25ac:	01 c8                	add    %ecx,%eax
    25ae:	89 45 b8             	mov    %eax,0xffffffb8(%ebp)
    25b1:	8b 43 34             	mov    0x34(%ebx),%eax
    25b4:	8b 74 0e 08          	mov    0x8(%esi,%ecx,1),%esi
    25b8:	89 75 90             	mov    %esi,0xffffff90(%ebp)
    25bb:	39 c6                	cmp    %eax,%esi
    25bd:	77 0f                	ja     25ce <DoRecoveryStep+0x1ae>
    25bf:	8b 75 0c             	mov    0xc(%ebp),%esi
    25c2:	3b 44 0e 0c          	cmp    0xc(%esi,%ecx,1),%eax
    25c6:	be 01 00 00 00       	mov    $0x1,%esi
    25cb:	0f 46 d6             	cmovbe %esi,%edx
    25ce:	85 d2                	test   %edx,%edx
    25d0:	74 18                	je     25ea <DoRecoveryStep+0x1ca>
      numLosses += gaplen;
      numBootstrapLosses += 
	intersect(bootstrapStart, sacks[i].left-1,
		  bootstrapEnd, sacks[i-1].right+1);
    }
    if(Sack_contains(&ackProof->sacks[i], (*cont)->seq)) {
      if(((*cont)->seq == sacks[i].left || 
    25d2:	8b 75 f0             	mov    0xfffffff0(%ebp),%esi
    25d5:	8b 14 0e             	mov    (%esi,%ecx,1),%edx
    25d8:	39 d0                	cmp    %edx,%eax
    25da:	0f 84 69 05 00 00    	je     2b49 <DoRecoveryStep+0x729>
    25e0:	83 7b 38 02          	cmpl   $0x2,0x38(%ebx)
    25e4:	0f 84 56 05 00 00    	je     2b40 <DoRecoveryStep+0x720>
    25ea:	47                   	inc    %edi
    25eb:	83 c1 0c             	add    $0xc,%ecx
    25ee:	3b 7d a4             	cmp    0xffffffa4(%ebp),%edi
    25f1:	7c 8d                	jl     2580 <DoRecoveryStep+0x160>
	  ((*cont)->continuationType == CONTTYPE_FULL2 && (*cont)->seq - 1 == sacks[i].left))
	  && cursorgap) {
	/* detected gap; measure size of gap */
	afterGap = 1;
	gapLeft = ackProof->sacks[i-1].right + 1,
	  gapRight = ackProof->sacks[i].left - 1;
      }
    }
  }

  if(serverDebugLevel >= 2) {
    25f3:	83 3d 00 00 00 00 01 	cmpl   $0x1,0x0
    25fa:	0f 8f 21 05 00 00    	jg     2b21 <DoRecoveryStep+0x701>
	  printk("RecoveryStep\n");
	  AckProof_dump(ackProof);
  }

  // Preallocate space for all packets that we are going to generate
  numPacketsSendable = 0;
  numPacketsAllocated = 0;
    2600:	c7 45 c0 00 00 00 00 	movl   $0x0,0xffffffc0(%ebp)
  if(afterGap) {
    2607:	8b 4d e4             	mov    0xffffffe4(%ebp),%ecx
    260a:	85 c9                	test   %ecx,%ecx
    260c:	74 32                	je     2640 <DoRecoveryStep+0x220>
    int start, end;
    numPacketsAllocated += (gapRight - gapLeft) + 1; // range is inclusive
    260e:	8b 55 e0             	mov    0xffffffe0(%ebp),%edx
    2611:	8b 45 dc             	mov    0xffffffdc(%ebp),%eax
    /* intersect bootstrap range with gap */
    start = MAX(gapLeft, bootstrapStart);
    end = MIN(gapRight, bootstrapEnd);
    2614:	8b 4d dc             	mov    0xffffffdc(%ebp),%ecx
    2617:	29 d0                	sub    %edx,%eax
    2619:	8b 55 e0             	mov    0xffffffe0(%ebp),%edx
    261c:	40                   	inc    %eax
    261d:	39 55 ec             	cmp    %edx,0xffffffec(%ebp)
    2620:	89 45 c0             	mov    %eax,0xffffffc0(%ebp)
    2623:	89 c8                	mov    %ecx,%eax
    2625:	0f 4d 55 ec          	cmovge 0xffffffec(%ebp),%edx
    2629:	39 4d e8             	cmp    %ecx,0xffffffe8(%ebp)
    262c:	0f 4e 45 e8          	cmovle 0xffffffe8(%ebp),%eax
    if(start <= end) {
    2630:	39 c2                	cmp    %eax,%edx
    2632:	7f 0c                	jg     2640 <DoRecoveryStep+0x220>
      numPacketsAllocated += (end - start) + 1; // range is inclusive
    2634:	8b 75 c0             	mov    0xffffffc0(%ebp),%esi
    2637:	29 d0                	sub    %edx,%eax
    2639:	8d 74 30 01          	lea    0x1(%eax,%esi,1),%esi
    263d:	89 75 c0             	mov    %esi,0xffffffc0(%ebp)
    }
  }
  {
    /* intersect ack ack range with bootstrap range */
    bootstrapIntersectStart = MAX(FIRST_ACKSEQ((*cont)->continuationType, (*cont)->seq),
				  bootstrapStart);
    2640:	8b 45 08             	mov    0x8(%ebp),%eax
    2643:	8b 7d ec             	mov    0xffffffec(%ebp),%edi
    bootstrapIntersectLast = MIN((*cont)->seq,
				 bootstrapEnd);
    2646:	8b 75 e8             	mov    0xffffffe8(%ebp),%esi
    2649:	8b 08                	mov    (%eax),%ecx
    264b:	8b 51 34             	mov    0x34(%ecx),%edx
    264e:	83 79 38 02          	cmpl   $0x2,0x38(%ecx)
    2652:	8d 42 ff             	lea    0xffffffff(%edx),%eax
    2655:	0f 45 c2             	cmovne %edx,%eax
    2658:	39 c7                	cmp    %eax,%edi
    265a:	0f 42 f8             	cmovb  %eax,%edi
    265d:	39 d6                	cmp    %edx,%esi
    265f:	0f 46 d6             	cmovbe %esi,%edx
    if(bootstrapIntersectStart <= bootstrapIntersectLast) {
    2662:	39 d7                	cmp    %edx,%edi
    2664:	89 55 b4             	mov    %edx,0xffffffb4(%ebp)
    2667:	7f 0e                	jg     2677 <DoRecoveryStep+0x257>
      numPacketsAllocated += 
    2669:	89 d0                	mov    %edx,%eax
    266b:	8b 55 c0             	mov    0xffffffc0(%ebp),%edx
    266e:	29 f8                	sub    %edi,%eax
    2670:	8d 54 10 01          	lea    0x1(%eax,%edx,1),%edx
    2674:	89 55 c0             	mov    %edx,0xffffffc0(%ebp)
	bootstrapIntersectLast - bootstrapIntersectStart + 1; // range is inclusive
    }
  }
  if(numPacketsAllocated == 0) {
    2677:	8b 45 c0             	mov    0xffffffc0(%ebp),%eax
    267a:	85 c0                	test   %eax,%eax
    267c:	75 2d                	jne    26ab <DoRecoveryStep+0x28b>
    free_trickles_msk((*cont)->sk,(*cont));
    267e:	89 4c 24 04          	mov    %ecx,0x4(%esp,1)
    2682:	8b 41 20             	mov    0x20(%ecx),%eax
    2685:	89 04 24             	mov    %eax,(%esp,1)
    2688:	e8 73 d9 ff ff       	call   0 <free_trickles_msk>
    free_trickles_msk_finish((*cont)->sk,(*cont));
    268d:	8b 4d 08             	mov    0x8(%ebp),%ecx
    2690:	8b 01                	mov    (%ecx),%eax
    2692:	89 44 24 04          	mov    %eax,0x4(%esp,1)
    2696:	8b 40 20             	mov    0x20(%eax),%eax
    2699:	89 04 24             	mov    %eax,(%esp,1)
    269c:	e8 ff d9 ff ff       	call   a0 <free_trickles_msk_finish>
    return 0;
  }
  if(!alloc_msk_packets((*cont), numPacketsAllocated)) {
    free_trickles_msk((*cont)->sk,(*cont));
    free_trickles_msk_finish((*cont)->sk,(*cont));
    return -ENOMEM;
  }

  if(afterGap) {
    __u32 seq;
    if(serverDebugLevel >= 1) {
      printk("  Bootstrap [%d - %d], newCwnd %d\n", bootstrapStart, bootstrapEnd, newCwnd);
      printk("  Gaplen = %d (after gap)\n", gaplen);
    }
    /* Generate retransmits */
    if(gapRight - gapLeft > MAX_GAPSIZE) {
          //printk("recoveryStep: gap too large (%u-%u)\n", gapLeft, gapRight);
	  free_trickles_msk((*cont)->sk,(*cont));
	  free_trickles_msk_finish((*cont)->sk,(*cont));
	  return -EINVAL;
    }
    for(seq = gapLeft; seq <= gapRight; seq++) {
      if(serverDebugLevel >= 1) {
	printk("  Gap rtx %u\n", seq);
      }
      makePacket(&(*cont)->packets[numPackets], seq, 0xdeadbeef, MTU, -1, PACKET_RETRANS, CONTTYPE_MINIMAL, MTU, 
			 -1, -1);
      numPackets++;
      /* retransmit bootstrap packets that should have been clocked out by missing packets */
      /* xxx: merge with identical code below */
      if(seq >= bootstrapStart && seq <= bootstrapEnd) {
	__u32 bootstrap_seq = lastRegularPacket + 1 + (seq - bootstrapStart);
	unsigned firstChild;
	int numChildren, prevCwnd, currCwnd;
	if(serverDebugLevel >= 1) {
		printk("  Gap bootstrap %u\n", bootstrap_seq);
	}
	if(bootstrap_seq == (*cont)->TCPBase) {
		// corner case
		firstChild = bootstrap_seq + (*cont)->startCwnd;
		numChildren = 1;
	} else {
		prevCwnd = AckTCPCwndScalar(bootstrap_seq - 1, *cont);
		currCwnd = AckTCPCwndScalar(bootstrap_seq, *cont);
		firstChild = bootstrap_seq + prevCwnd;
		numChildren = currCwnd - prevCwnd + 1;
	}

	makePacket(&(*cont)->packets[numPackets],
		   bootstrap_seq, 0xdeadbeef, MTU, -1, 
		   PACKET_BOOTSTRAP, CONTTYPE_FULL1, CONTTYPE_FULL_MTU,
		   firstChild, numChildren);
	numPackets++;
      }
    }
    if(serverDebugLevel >= 1) {
      printk("  After RTX: %u packets\n", numPackets);
    }
  } else {
    if(serverDebugLevel >= 2) {
      printk("  Not after gap\n");
    }
  }
  /* Transmit bootstrap packets in 2nd half of recovery interval */
  BUG_TRAP((*cont)->continuationType == CONTTYPE_FULL1 ||
	   (*cont)->continuationType == CONTTYPE_FULL2);
  for(ack_seq = bootstrapIntersectStart;
      ack_seq <= bootstrapIntersectLast;
      ack_seq++) {
    /* Eventually, clock out newCwnd bootstrap packets. Clock out one
       here */
    __u32 seq = lastRegularPacket + 1 + (ack_seq - bootstrapStart);
    unsigned firstChild;
    int numChildren, prevCwnd, currCwnd;

    if(serverDebugLevel >= 1)
      printk("  Bootstrap %u\n", seq);

    /* copied from above */
    if(seq == (*cont)->TCPBase) {
      // corner case
      firstChild = seq + (*cont)->startCwnd;
      numChildren = 1;
    } else {
      prevCwnd = AckTCPCwndScalar(seq - 1, *cont);
      currCwnd = AckTCPCwndScalar(seq, *cont);
      firstChild = seq + prevCwnd;
      numChildren = currCwnd - prevCwnd + 1;
    }

    makePacket(&(*cont)->packets[numPackets],
	       seq, 0xdeadbeef, MTU, -1, PACKET_BOOTSTRAP, 
	       CONTTYPE_FULL1, MTU, firstChild, numChildren);
    numPackets++;
    if(serverDebugLevel >= 1) {
      printk("  After bootstrap: %u packets\n", numPackets);
    }
  }
  numPacketsSendable = numPackets;
  (*cont)->num_packets = numPackets;
  if(numPacketsSendable > numPacketsAllocated) {
    printk("Sendable = %d, allocated = %d\n", numPacketsSendable, numPacketsAllocated);
    BUG_TRAP(numPacketsSendable <= numPacketsAllocated);
  }

  DoUpcall((*cont), event);
  return 0;
    26a1:	31 c0                	xor    %eax,%eax
}
    26a3:	83 c4 74             	add    $0x74,%esp
    26a6:	5b                   	pop    %ebx
    26a7:	5e                   	pop    %esi
    26a8:	5f                   	pop    %edi
    26a9:	5d                   	pop    %ebp
    26aa:	c3                   	ret    
    26ab:	89 0c 24             	mov    %ecx,(%esp,1)
    26ae:	8b 75 c0             	mov    0xffffffc0(%ebp),%esi
    26b1:	89 74 24 04          	mov    %esi,0x4(%esp,1)
    26b5:	e8 96 08 00 00       	call   2f50 <alloc_msk_packets>
    26ba:	85 c0                	test   %eax,%eax
    26bc:	0f 84 2d 04 00 00    	je     2aef <DoRecoveryStep+0x6cf>
    26c2:	8b 75 e4             	mov    0xffffffe4(%ebp),%esi
    26c5:	85 f6                	test   %esi,%esi
    26c7:	0f 84 04 04 00 00    	je     2ad1 <DoRecoveryStep+0x6b1>
    26cd:	8b 1d 00 00 00 00    	mov    0x0,%ebx
    26d3:	85 db                	test   %ebx,%ebx
    26d5:	7e 34                	jle    270b <DoRecoveryStep+0x2eb>
    26d7:	c7 04 24 60 06 00 00 	movl   $0x660,(%esp,1)
    26de:	8b 75 d4             	mov    0xffffffd4(%ebp),%esi
    26e1:	8b 45 e8             	mov    0xffffffe8(%ebp),%eax
    26e4:	8b 55 ec             	mov    0xffffffec(%ebp),%edx
    26e7:	89 74 24 0c          	mov    %esi,0xc(%esp,1)
    26eb:	89 44 24 08          	mov    %eax,0x8(%esp,1)
    26ef:	89 54 24 04          	mov    %edx,0x4(%esp,1)
    26f3:	e8 fc ff ff ff       	call   26f4 <DoRecoveryStep+0x2d4>
    26f8:	8b 4d d0             	mov    0xffffffd0(%ebp),%ecx
    26fb:	c7 04 24 b1 01 00 00 	movl   $0x1b1,(%esp,1)
    2702:	89 4c 24 04          	mov    %ecx,0x4(%esp,1)
    2706:	e8 fc ff ff ff       	call   2707 <DoRecoveryStep+0x2e7>
    270b:	8b 45 dc             	mov    0xffffffdc(%ebp),%eax
    270e:	8b 4d e0             	mov    0xffffffe0(%ebp),%ecx
    2711:	29 c8                	sub    %ecx,%eax
    2713:	83 f8 0a             	cmp    $0xa,%eax
    2716:	0f 8f 86 03 00 00    	jg     2aa2 <DoRecoveryStep+0x682>
    271c:	8b 75 e0             	mov    0xffffffe0(%ebp),%esi
    271f:	3b 75 dc             	cmp    0xffffffdc(%ebp),%esi
    2722:	0f 87 9d 01 00 00    	ja     28c5 <DoRecoveryStep+0x4a5>
    2728:	8b 55 ec             	mov    0xffffffec(%ebp),%edx
    272b:	8b 45 c4             	mov    0xffffffc4(%ebp),%eax
    272e:	29 d0                	sub    %edx,%eax
    2730:	8b 55 d8             	mov    0xffffffd8(%ebp),%edx
    2733:	8d 04 30             	lea    (%eax,%esi,1),%eax
    2736:	89 45 9c             	mov    %eax,0xffffff9c(%ebp)
    2739:	8d 04 92             	lea    (%edx,%edx,4),%eax
    273c:	c1 e0 03             	shl    $0x3,%eax
    273f:	89 45 98             	mov    %eax,0xffffff98(%ebp)
    2742:	89 45 94             	mov    %eax,0xffffff94(%ebp)
    2745:	8d 74 26 00          	lea    0x0(%esi,1),%esi
    2749:	8d bc 27 00 00 00 00 	lea    0x0(%edi,1),%edi
    2750:	8b 1d 00 00 00 00    	mov    0x0,%ebx
    2756:	85 db                	test   %ebx,%ebx
    2758:	7e 10                	jle    276a <DoRecoveryStep+0x34a>
    275a:	89 74 24 04          	mov    %esi,0x4(%esp,1)
    275e:	c7 04 24 cc 01 00 00 	movl   $0x1cc,(%esp,1)
    2765:	e8 fc ff ff ff       	call   2766 <DoRecoveryStep+0x346>
			      __u8 type, 
			      __u8 contType, 
			      __u16 minResponseLen,
			      __u32 firstTransportChild, 
			      __u8 numTransportChildren) {
    276a:	8b 4d 08             	mov    0x8(%ebp),%ecx
    276d:	8b 55 94             	mov    0xffffff94(%ebp),%edx
    2770:	8b 01                	mov    (%ecx),%eax
    2772:	8b 88 e0 00 00 00    	mov    0xe0(%eax),%ecx
    2778:	01 ca                	add    %ecx,%edx
  pkt->nonce = -1;
  pkt->seq = seq;
  //pkt->ack_seq = ack_seq;
  pkt->len = len;
  pkt->byteNum = byteNum;
  pkt->type = type;
    277a:	0f b6 42 10          	movzbl 0x10(%edx),%eax
    277e:	c7 02 ff ff ff ff    	movl   $0xffffffff,(%edx)
    2784:	89 72 04             	mov    %esi,0x4(%edx)
    2787:	c7 42 08 52 05 00 00 	movl   $0x552,0x8(%edx)
    278e:	0c 01                	or     $0x1,%al
  pkt->contType = contType;
    2790:	24 c1                	and    $0xc1,%al
    2792:	c7 42 0c ff ff ff ff 	movl   $0xffffffff,0xc(%edx)
    2799:	88 42 10             	mov    %al,0x10(%edx)
  pkt->minResponseLen = minResponseLen;
    279c:	66 c7 42 1c 52 05    	movw   $0x552,0x1c(%edx)
  pkt->firstTransportChild = firstTransportChild;
    27a2:	c7 42 20 ff ff ff ff 	movl   $0xffffffff,0x20(%edx)
  pkt->numTransportChildren = numTransportChildren;
    27a9:	c6 42 24 ff          	movb   $0xff,0x24(%edx)
  pkt->ucontLen = 0;
    27ad:	c7 42 14 00 00 00 00 	movl   $0x0,0x14(%edx)
  pkt->ucontData = NULL;
    27b4:	c7 42 18 00 00 00 00 	movl   $0x0,0x18(%edx)
  pkt->numSiblings = -1;
    27bb:	c6 42 11 ff          	movb   $0xff,0x11(%edx)
  pkt->position = INVALID_POSITION;
    27bf:	c6 42 12 ff          	movb   $0xff,0x12(%edx)
    27c3:	83 45 98 28          	addl   $0x28,0xffffff98(%ebp)
    27c7:	83 45 94 28          	addl   $0x28,0xffffff94(%ebp)
    27cb:	ff 45 d8             	incl   0xffffffd8(%ebp)
    27ce:	3b 75 ec             	cmp    0xffffffec(%ebp),%esi
    27d1:	0f 82 e1 00 00 00    	jb     28b8 <DoRecoveryStep+0x498>
    27d7:	3b 75 e8             	cmp    0xffffffe8(%ebp),%esi
    27da:	0f 87 d8 00 00 00    	ja     28b8 <DoRecoveryStep+0x498>
    27e0:	8b 45 9c             	mov    0xffffff9c(%ebp),%eax
    27e3:	8b 15 00 00 00 00    	mov    0x0,%edx
    27e9:	40                   	inc    %eax
    27ea:	89 45 b0             	mov    %eax,0xffffffb0(%ebp)
    27ed:	85 d2                	test   %edx,%edx
    27ef:	7e 10                	jle    2801 <DoRecoveryStep+0x3e1>
    27f1:	89 44 24 04          	mov    %eax,0x4(%esp,1)
    27f5:	c7 04 24 da 01 00 00 	movl   $0x1da,(%esp,1)
    27fc:	e8 fc ff ff ff       	call   27fd <DoRecoveryStep+0x3dd>
    2801:	8b 55 08             	mov    0x8(%ebp),%edx
    2804:	8b 4d b0             	mov    0xffffffb0(%ebp),%ecx
    2807:	8b 1a                	mov    (%edx),%ebx
    2809:	3b 4b 70             	cmp    0x70(%ebx),%ecx
    280c:	0f 84 7f 02 00 00    	je     2a91 <DoRecoveryStep+0x671>
    2812:	89 5c 24 04          	mov    %ebx,0x4(%esp,1)
    2816:	8b 45 9c             	mov    0xffffff9c(%ebp),%eax
    2819:	c7 44 24 08 00 00 00 	movl   $0x0,0x8(%esp,1)
    2820:	00 
    2821:	89 04 24             	mov    %eax,(%esp,1)
    2824:	e8 fc ff ff ff       	call   2825 <DoRecoveryStep+0x405>
    2829:	8b 55 08             	mov    0x8(%ebp),%edx
    282c:	89 c3                	mov    %eax,%ebx
    282e:	8b 4d b0             	mov    0xffffffb0(%ebp),%ecx
    2831:	8b 02                	mov    (%edx),%eax
    2833:	c7 44 24 08 00 00 00 	movl   $0x0,0x8(%esp,1)
    283a:	00 
    283b:	89 0c 24             	mov    %ecx,(%esp,1)
    283e:	89 44 24 04          	mov    %eax,0x4(%esp,1)
    2842:	e8 fc ff ff ff       	call   2843 <DoRecoveryStep+0x423>
    2847:	8b 4d b0             	mov    0xffffffb0(%ebp),%ecx
    284a:	29 d8                	sub    %ebx,%eax
    284c:	40                   	inc    %eax
    284d:	89 45 ac             	mov    %eax,0xffffffac(%ebp)
    2850:	8b 45 08             	mov    0x8(%ebp),%eax
    2853:	01 d9                	add    %ebx,%ecx
    2855:	8b 18                	mov    (%eax),%ebx
			      __u8 type, 
			      __u8 contType, 
			      __u16 minResponseLen,
			      __u32 firstTransportChild, 
			      __u8 numTransportChildren) {
    2857:	8b 83 e0 00 00 00    	mov    0xe0(%ebx),%eax
    285d:	8b 55 98             	mov    0xffffff98(%ebp),%edx
    2860:	01 c2                	add    %eax,%edx
  pkt->nonce = -1;
    2862:	c7 02 ff ff ff ff    	movl   $0xffffffff,(%edx)
  pkt->seq = seq;
    2868:	8b 45 b0             	mov    0xffffffb0(%ebp),%eax
  //pkt->ack_seq = ack_seq;
  pkt->len = len;
    286b:	c7 42 08 52 05 00 00 	movl   $0x552,0x8(%edx)
  pkt->byteNum = byteNum;
    2872:	c7 42 0c ff ff ff ff 	movl   $0xffffffff,0xc(%edx)
  pkt->type = type;
  pkt->contType = contType;
  pkt->minResponseLen = minResponseLen;
    2879:	66 c7 42 1c 52 05    	movw   $0x552,0x1c(%edx)
    287f:	89 42 04             	mov    %eax,0x4(%edx)
    2882:	0f b6 42 10          	movzbl 0x10(%edx),%eax
  pkt->firstTransportChild = firstTransportChild;
    2886:	89 4a 20             	mov    %ecx,0x20(%edx)
    2889:	24 ca                	and    $0xca,%al
    288b:	0c 0a                	or     $0xa,%al
    288d:	88 42 10             	mov    %al,0x10(%edx)
  pkt->numTransportChildren = numTransportChildren;
    2890:	0f b6 4d ac          	movzbl 0xffffffac(%ebp),%ecx
  pkt->ucontLen = 0;
    2894:	c7 42 14 00 00 00 00 	movl   $0x0,0x14(%edx)
  pkt->ucontData = NULL;
    289b:	c7 42 18 00 00 00 00 	movl   $0x0,0x18(%edx)
  pkt->numSiblings = -1;
    28a2:	c6 42 11 ff          	movb   $0xff,0x11(%edx)
  pkt->position = INVALID_POSITION;
    28a6:	c6 42 12 ff          	movb   $0xff,0x12(%edx)
    28aa:	88 4a 24             	mov    %cl,0x24(%edx)
    28ad:	83 45 98 28          	addl   $0x28,0xffffff98(%ebp)
    28b1:	83 45 94 28          	addl   $0x28,0xffffff94(%ebp)
    28b5:	ff 45 d8             	incl   0xffffffd8(%ebp)
    28b8:	ff 45 9c             	incl   0xffffff9c(%ebp)
    28bb:	46                   	inc    %esi
    28bc:	3b 75 dc             	cmp    0xffffffdc(%ebp),%esi
    28bf:	0f 86 8b fe ff ff    	jbe    2750 <DoRecoveryStep+0x330>
    28c5:	a1 00 00 00 00       	mov    0x0,%eax
    28ca:	85 c0                	test   %eax,%eax
    28cc:	7e 13                	jle    28e1 <DoRecoveryStep+0x4c1>
    28ce:	c7 04 24 ee 01 00 00 	movl   $0x1ee,(%esp,1)
    28d5:	8b 75 d8             	mov    0xffffffd8(%ebp),%esi
    28d8:	89 74 24 04          	mov    %esi,0x4(%esp,1)
    28dc:	e8 fc ff ff ff       	call   28dd <DoRecoveryStep+0x4bd>
    28e1:	8b 55 08             	mov    0x8(%ebp),%edx
    28e4:	8b 02                	mov    (%edx),%eax
    28e6:	8b 40 38             	mov    0x38(%eax),%eax
    28e9:	48                   	dec    %eax
    28ea:	83 f8 01             	cmp    $0x1,%eax
    28ed:	0f 87 85 01 00 00    	ja     2a78 <DoRecoveryStep+0x658>
    28f3:	89 7d c8             	mov    %edi,0xffffffc8(%ebp)
    28f6:	8b 4d b4             	mov    0xffffffb4(%ebp),%ecx
    28f9:	39 cf                	cmp    %ecx,%edi
    28fb:	0f 87 0c 01 00 00    	ja     2a0d <DoRecoveryStep+0x5ed>
    2901:	8b 75 ec             	mov    0xffffffec(%ebp),%esi
    2904:	8b 55 d8             	mov    0xffffffd8(%ebp),%edx
    2907:	29 75 c4             	sub    %esi,0xffffffc4(%ebp)
    290a:	8b 45 c4             	mov    0xffffffc4(%ebp),%eax
    290d:	01 c7                	add    %eax,%edi
    290f:	8d 04 92             	lea    (%edx,%edx,4),%eax
    2912:	c1 e0 03             	shl    $0x3,%eax
    2915:	89 45 a0             	mov    %eax,0xffffffa0(%ebp)
    2918:	90                   	nop    
    2919:	8d b4 26 00 00 00 00 	lea    0x0(%esi,1),%esi
    2920:	a1 00 00 00 00       	mov    0x0,%eax
    2925:	8d 77 01             	lea    0x1(%edi),%esi
    2928:	85 c0                	test   %eax,%eax
    292a:	7e 10                	jle    293c <DoRecoveryStep+0x51c>
    292c:	89 74 24 04          	mov    %esi,0x4(%esp,1)
    2930:	c7 04 24 07 02 00 00 	movl   $0x207,(%esp,1)
    2937:	e8 fc ff ff ff       	call   2938 <DoRecoveryStep+0x518>
    293c:	8b 4d 08             	mov    0x8(%ebp),%ecx
    293f:	8b 19                	mov    (%ecx),%ebx
    2941:	3b 73 70             	cmp    0x70(%ebx),%esi
    2944:	0f 84 1b 01 00 00    	je     2a65 <DoRecoveryStep+0x645>
    294a:	89 5c 24 04          	mov    %ebx,0x4(%esp,1)
    294e:	c7 44 24 08 00 00 00 	movl   $0x0,0x8(%esp,1)
    2955:	00 
    2956:	89 3c 24             	mov    %edi,(%esp,1)
    2959:	e8 fc ff ff ff       	call   295a <DoRecoveryStep+0x53a>
    295e:	8b 55 08             	mov    0x8(%ebp),%edx
    2961:	89 c3                	mov    %eax,%ebx
    2963:	8b 02                	mov    (%edx),%eax
    2965:	c7 44 24 08 00 00 00 	movl   $0x0,0x8(%esp,1)
    296c:	00 
    296d:	89 34 24             	mov    %esi,(%esp,1)
    2970:	89 44 24 04          	mov    %eax,0x4(%esp,1)
    2974:	e8 fc ff ff ff       	call   2975 <DoRecoveryStep+0x555>
    2979:	8d 0c 33             	lea    (%ebx,%esi,1),%ecx
    297c:	29 d8                	sub    %ebx,%eax
    297e:	40                   	inc    %eax
    297f:	89 45 a8             	mov    %eax,0xffffffa8(%ebp)
    2982:	8b 45 08             	mov    0x8(%ebp),%eax
    2985:	8b 18                	mov    (%eax),%ebx
			      __u8 type, 
			      __u8 contType, 
			      __u16 minResponseLen,
			      __u32 firstTransportChild, 
			      __u8 numTransportChildren) {
    2987:	8b 83 e0 00 00 00    	mov    0xe0(%ebx),%eax
    298d:	8b 55 a0             	mov    0xffffffa0(%ebp),%edx
    2990:	01 c2                	add    %eax,%edx
  pkt->nonce = -1;
  pkt->seq = seq;
  //pkt->ack_seq = ack_seq;
  pkt->len = len;
  pkt->byteNum = byteNum;
  pkt->type = type;
  pkt->contType = contType;
    2992:	0f b6 42 10          	movzbl 0x10(%edx),%eax
    2996:	c7 02 ff ff ff ff    	movl   $0xffffffff,(%edx)
    299c:	89 72 04             	mov    %esi,0x4(%edx)
    299f:	c7 42 08 52 05 00 00 	movl   $0x552,0x8(%edx)
    29a6:	24 ca                	and    $0xca,%al
    29a8:	0c 0a                	or     $0xa,%al
    29aa:	c7 42 0c ff ff ff ff 	movl   $0xffffffff,0xc(%edx)
    29b1:	88 42 10             	mov    %al,0x10(%edx)
  pkt->minResponseLen = minResponseLen;
    29b4:	66 c7 42 1c 52 05    	movw   $0x552,0x1c(%edx)
  pkt->firstTransportChild = firstTransportChild;
    29ba:	89 4a 20             	mov    %ecx,0x20(%edx)
  pkt->numTransportChildren = numTransportChildren;
    29bd:	0f b6 4d a8          	movzbl 0xffffffa8(%ebp),%ecx
  pkt->ucontLen = 0;
    29c1:	c7 42 14 00 00 00 00 	movl   $0x0,0x14(%edx)
  pkt->ucontData = NULL;
    29c8:	c7 42 18 00 00 00 00 	movl   $0x0,0x18(%edx)
  pkt->numSiblings = -1;
    29cf:	c6 42 11 ff          	movb   $0xff,0x11(%edx)
  pkt->position = INVALID_POSITION;
    29d3:	c6 42 12 ff          	movb   $0xff,0x12(%edx)
    29d7:	88 4a 24             	mov    %cl,0x24(%edx)
    29da:	a1 00 00 00 00       	mov    0x0,%eax
    29df:	83 45 a0 28          	addl   $0x28,0xffffffa0(%ebp)
    29e3:	ff 45 d8             	incl   0xffffffd8(%ebp)
    29e6:	85 c0                	test   %eax,%eax
    29e8:	7e 13                	jle    29fd <DoRecoveryStep+0x5dd>
    29ea:	c7 04 24 a0 06 00 00 	movl   $0x6a0,(%esp,1)
    29f1:	8b 75 d8             	mov    0xffffffd8(%ebp),%esi
    29f4:	89 74 24 04          	mov    %esi,0x4(%esp,1)
    29f8:	e8 fc ff ff ff       	call   29f9 <DoRecoveryStep+0x5d9>
    29fd:	ff 45 c8             	incl   0xffffffc8(%ebp)
    2a00:	47                   	inc    %edi
    2a01:	8b 45 b4             	mov    0xffffffb4(%ebp),%eax
    2a04:	39 45 c8             	cmp    %eax,0xffffffc8(%ebp)
    2a07:	0f 86 13 ff ff ff    	jbe    2920 <DoRecoveryStep+0x500>
    2a0d:	8b 55 08             	mov    0x8(%ebp),%edx
    2a10:	8b 4d d8             	mov    0xffffffd8(%ebp),%ecx
    2a13:	8b 02                	mov    (%edx),%eax
    2a15:	89 88 dc 00 00 00    	mov    %ecx,0xdc(%eax)
    2a1b:	8b 75 c0             	mov    0xffffffc0(%ebp),%esi
    2a1e:	39 f1                	cmp    %esi,%ecx
    2a20:	7f 19                	jg     2a3b <DoRecoveryStep+0x61b>
    2a22:	8b 45 10             	mov    0x10(%ebp),%eax
    2a25:	8b 55 08             	mov    0x8(%ebp),%edx
    2a28:	89 44 24 04          	mov    %eax,0x4(%esp,1)
    2a2c:	8b 02                	mov    (%edx),%eax
    2a2e:	89 04 24             	mov    %eax,(%esp,1)
    2a31:	e8 fc ff ff ff       	call   2a32 <DoRecoveryStep+0x612>
    2a36:	e9 66 fc ff ff       	jmp    26a1 <DoRecoveryStep+0x281>
    2a3b:	89 74 24 08          	mov    %esi,0x8(%esp,1)
    2a3f:	89 4c 24 04          	mov    %ecx,0x4(%esp,1)
    2a43:	c7 04 24 c0 06 00 00 	movl   $0x6c0,(%esp,1)
    2a4a:	e8 fc ff ff ff       	call   2a4b <DoRecoveryStep+0x62b>
    2a4f:	c7 44 24 04 e2 05 00 	movl   $0x5e2,0x4(%esp,1)
    2a56:	00 
    2a57:	c7 04 24 e0 06 00 00 	movl   $0x6e0,(%esp,1)
    2a5e:	e8 fc ff ff ff       	call   2a5f <DoRecoveryStep+0x63f>
    2a63:	eb bd                	jmp    2a22 <DoRecoveryStep+0x602>
    2a65:	8b 43 68             	mov    0x68(%ebx),%eax
    2a68:	89 f1                	mov    %esi,%ecx
    2a6a:	c7 45 a8 01 00 00 00 	movl   $0x1,0xffffffa8(%ebp)
    2a71:	01 c1                	add    %eax,%ecx
    2a73:	e9 0f ff ff ff       	jmp    2987 <DoRecoveryStep+0x567>
    2a78:	c7 44 24 04 bd 05 00 	movl   $0x5bd,0x4(%esp,1)
    2a7f:	00 
    2a80:	c7 04 24 40 07 00 00 	movl   $0x740,(%esp,1)
    2a87:	e8 fc ff ff ff       	call   2a88 <DoRecoveryStep+0x668>
    2a8c:	e9 62 fe ff ff       	jmp    28f3 <DoRecoveryStep+0x4d3>
    2a91:	8b 43 68             	mov    0x68(%ebx),%eax
    2a94:	c7 45 ac 01 00 00 00 	movl   $0x1,0xffffffac(%ebp)
    2a9b:	01 c1                	add    %eax,%ecx
    2a9d:	e9 b5 fd ff ff       	jmp    2857 <DoRecoveryStep+0x437>
    2aa2:	8b 75 08             	mov    0x8(%ebp),%esi
    2aa5:	8b 06                	mov    (%esi),%eax
    2aa7:	89 44 24 04          	mov    %eax,0x4(%esp,1)
    2aab:	8b 40 20             	mov    0x20(%eax),%eax
    2aae:	89 04 24             	mov    %eax,(%esp,1)
    2ab1:	e8 4a d5 ff ff       	call   0 <free_trickles_msk>
    2ab6:	8b 06                	mov    (%esi),%eax
    2ab8:	89 44 24 04          	mov    %eax,0x4(%esp,1)
    2abc:	8b 40 20             	mov    0x20(%eax),%eax
    2abf:	89 04 24             	mov    %eax,(%esp,1)
    2ac2:	e8 d9 d5 ff ff       	call   a0 <free_trickles_msk_finish>
    2ac7:	b8 ea ff ff ff       	mov    $0xffffffea,%eax
    2acc:	e9 d2 fb ff ff       	jmp    26a3 <DoRecoveryStep+0x283>
    2ad1:	83 3d 00 00 00 00 01 	cmpl   $0x1,0x0
    2ad8:	0f 8e 03 fe ff ff    	jle    28e1 <DoRecoveryStep+0x4c1>
    2ade:	c7 04 24 17 02 00 00 	movl   $0x217,(%esp,1)
    2ae5:	e8 fc ff ff ff       	call   2ae6 <DoRecoveryStep+0x6c6>
    2aea:	e9 f2 fd ff ff       	jmp    28e1 <DoRecoveryStep+0x4c1>
    2aef:	8b 55 08             	mov    0x8(%ebp),%edx
    2af2:	8b 02                	mov    (%edx),%eax
    2af4:	89 44 24 04          	mov    %eax,0x4(%esp,1)
    2af8:	8b 40 20             	mov    0x20(%eax),%eax
    2afb:	89 04 24             	mov    %eax,(%esp,1)
    2afe:	e8 fd d4 ff ff       	call   0 <free_trickles_msk>
    2b03:	8b 4d 08             	mov    0x8(%ebp),%ecx
    2b06:	8b 01                	mov    (%ecx),%eax
    2b08:	89 44 24 04          	mov    %eax,0x4(%esp,1)
    2b0c:	8b 40 20             	mov    0x20(%eax),%eax
    2b0f:	89 04 24             	mov    %eax,(%esp,1)
    2b12:	e8 89 d5 ff ff       	call   a0 <free_trickles_msk_finish>
    2b17:	b8 f4 ff ff ff       	mov    $0xfffffff4,%eax
    2b1c:	e9 82 fb ff ff       	jmp    26a3 <DoRecoveryStep+0x283>
    2b21:	c7 04 24 28 02 00 00 	movl   $0x228,(%esp,1)
    2b28:	e8 fc ff ff ff       	call   2b29 <DoRecoveryStep+0x709>
    2b2d:	8b 45 0c             	mov    0xc(%ebp),%eax
    2b30:	89 04 24             	mov    %eax,(%esp,1)
    2b33:	e8 fc ff ff ff       	call   2b34 <DoRecoveryStep+0x714>
    2b38:	e9 c3 fa ff ff       	jmp    2600 <DoRecoveryStep+0x1e0>
    2b3d:	8d 76 00             	lea    0x0(%esi),%esi
    2b40:	48                   	dec    %eax
    2b41:	39 d0                	cmp    %edx,%eax
    2b43:	0f 85 a1 fa ff ff    	jne    25ea <DoRecoveryStep+0x1ca>
    2b49:	8b 75 bc             	mov    0xffffffbc(%ebp),%esi
    2b4c:	85 f6                	test   %esi,%esi
    2b4e:	0f 84 96 fa ff ff    	je     25ea <DoRecoveryStep+0x1ca>
    2b54:	c7 45 e4 01 00 00 00 	movl   $0x1,0xffffffe4(%ebp)
    2b5b:	8b 45 b8             	mov    0xffffffb8(%ebp),%eax
    2b5e:	8b 75 90             	mov    0xffffff90(%ebp),%esi
    2b61:	8b 10                	mov    (%eax),%edx
    2b63:	4e                   	dec    %esi
    2b64:	89 75 dc             	mov    %esi,0xffffffdc(%ebp)
    2b67:	42                   	inc    %edx
    2b68:	89 55 e0             	mov    %edx,0xffffffe0(%ebp)
    2b6b:	e9 7a fa ff ff       	jmp    25ea <DoRecoveryStep+0x1ca>
    2b70:	8b 75 08             	mov    0x8(%ebp),%esi
    2b73:	8b 55 d4             	mov    0xffffffd4(%ebp),%edx
    2b76:	8b 06                	mov    (%esi),%eax
    2b78:	89 50 6c             	mov    %edx,0x6c(%eax)
    2b7b:	e9 ca f9 ff ff       	jmp    254a <DoRecoveryStep+0x12a>
    2b80:	c7 04 24 e0 07 00 00 	movl   $0x7e0,(%esp,1)
    2b87:	e8 fc ff ff ff       	call   2b88 <DoRecoveryStep+0x768>
    2b8c:	e9 11 ff ff ff       	jmp    2aa2 <DoRecoveryStep+0x682>
    2b91:	8b 45 0c             	mov    0xc(%ebp),%eax
    2b94:	89 04 24             	mov    %eax,(%esp,1)
    2b97:	e8 fc ff ff ff       	call   2b98 <DoRecoveryStep+0x778>
    2b9c:	8b 4d 08             	mov    0x8(%ebp),%ecx
    2b9f:	83 e8 02             	sub    $0x2,%eax
    2ba2:	8b 11                	mov    (%ecx),%edx
    2ba4:	c7 44 24 08 00 00 00 	movl   $0x0,0x8(%esp,1)
    2bab:	00 
    2bac:	89 04 24             	mov    %eax,(%esp,1)
    2baf:	89 54 24 04          	mov    %edx,0x4(%esp,1)
    2bb3:	e8 fc ff ff ff       	call   2bb4 <DoRecoveryStep+0x794>
    2bb8:	c7 45 cc ff ff ff ff 	movl   $0xffffffff,0xffffffcc(%ebp)
    2bbf:	89 c7                	mov    %eax,%edi
    2bc1:	e9 2a f9 ff ff       	jmp    24f0 <DoRecoveryStep+0xd0>
    2bc6:	8b 4d 0c             	mov    0xc(%ebp),%ecx
    2bc9:	89 0c 24             	mov    %ecx,(%esp,1)
    2bcc:	e8 fc ff ff ff       	call   2bcd <DoRecoveryStep+0x7ad>
    2bd1:	8b 4d 08             	mov    0x8(%ebp),%ecx
    2bd4:	48                   	dec    %eax
    2bd5:	8b 11                	mov    (%ecx),%edx
    2bd7:	c7 44 24 08 00 00 00 	movl   $0x0,0x8(%esp,1)
    2bde:	00 
    2bdf:	89 04 24             	mov    %eax,(%esp,1)
    2be2:	89 54 24 04          	mov    %edx,0x4(%esp,1)
    2be6:	e8 fc ff ff ff       	call   2be7 <DoRecoveryStep+0x7c7>
    2beb:	c7 45 cc 00 00 00 00 	movl   $0x0,0xffffffcc(%ebp)
    2bf2:	89 c7                	mov    %eax,%edi
    2bf4:	e9 f7 f8 ff ff       	jmp    24f0 <DoRecoveryStep+0xd0>
    2bf9:	8d b4 26 00 00 00 00 	lea    0x0(%esi,1),%esi
    2c00:	b8 01 00 00 00       	mov    $0x1,%eax
    2c05:	e9 d4 f8 ff ff       	jmp    24de <DoRecoveryStep+0xbe>
    2c0a:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi
    2c10:	8b 1d 00 00 00 00    	mov    0x0,%ebx
    2c16:	85 db                	test   %ebx,%ebx
    2c18:	74 1e                	je     2c38 <DoRecoveryStep+0x818>
    2c1a:	8b 55 08             	mov    0x8(%ebp),%edx
    2c1d:	8b 02                	mov    (%edx),%eax
    2c1f:	89 44 24 04          	mov    %eax,0x4(%esp,1)
    2c23:	8b 40 20             	mov    0x20(%eax),%eax
    2c26:	89 04 24             	mov    %eax,(%esp,1)
    2c29:	e8 d2 d3 ff ff       	call   0 <free_trickles_msk>
    2c2e:	8b 4d 08             	mov    0x8(%ebp),%ecx
    2c31:	8b 01                	mov    (%ecx),%eax
    2c33:	e9 80 fe ff ff       	jmp    2ab8 <DoRecoveryStep+0x698>
    2c38:	c7 04 24 20 08 00 00 	movl   $0x820,(%esp,1)
    2c3f:	e8 fc ff ff ff       	call   2c40 <DoRecoveryStep+0x820>
    2c44:	eb d4                	jmp    2c1a <DoRecoveryStep+0x7fa>
    2c46:	8d 76 00             	lea    0x0(%esi),%esi
    2c49:	8d bc 27 00 00 00 00 	lea    0x0(%edi,1),%edi

00002c50 <DoSlowStartStep>:

static int DoSlowStartStep(CONTINUATION_TYPE **cont, AckProof *ackProof, __u32 newBase, enum cminisock_event_tag event) {
    2c50:	55                   	push   %ebp
    2c51:	89 e5                	mov    %esp,%ebp
  (*cont)->executionTrace = 3;
    2c53:	ba 03 00 00 00       	mov    $0x3,%edx
    2c58:	53                   	push   %ebx
    2c59:	83 ec 0c             	sub    $0xc,%esp
    2c5c:	8b 5d 08             	mov    0x8(%ebp),%ebx
    2c5f:	8b 03                	mov    (%ebx),%eax
    2c61:	89 90 d0 00 00 00    	mov    %edx,0xd0(%eax)

  int right = AckProof_findRight(ackProof, (*cont)->TCPBase);
    2c67:	8b 03                	mov    (%ebx),%eax
    2c69:	8b 40 70             	mov    0x70(%eax),%eax
    2c6c:	89 44 24 04          	mov    %eax,0x4(%esp,1)
    2c70:	8b 45 0c             	mov    0xc(%ebp),%eax
    2c73:	89 04 24             	mov    %eax,(%esp,1)
    2c76:	e8 fc ff ff ff       	call   2c77 <DoSlowStartStep+0x27>
    2c7b:	8b 13                	mov    (%ebx),%edx
    2c7d:	c7 44 24 08 00 00 00 	movl   $0x0,0x8(%esp,1)
    2c84:	00 
    2c85:	89 04 24             	mov    %eax,(%esp,1)
    2c88:	89 54 24 04          	mov    %edx,0x4(%esp,1)
    2c8c:	e8 fc ff ff ff       	call   2c8d <DoSlowStartStep+0x3d>
  int effCwnd = AckTCPCwndScalar(right, (*cont));
#ifndef ZERO_SSTHRESH_PROTECTION_HACK
  (*cont)->ssthresh = effCwnd / MULT_FACTOR;
#else
  if(effCwnd >= MULT_FACTOR) {
    2c91:	83 f8 01             	cmp    $0x1,%eax
    2c94:	89 c1                	mov    %eax,%ecx
    2c96:	0f 8e 04 01 00 00    	jle    2da0 <DoSlowStartStep+0x150>
    (*cont)->ssthresh = effCwnd / MULT_FACTOR;
    2c9c:	8b 13                	mov    (%ebx),%edx
    2c9e:	c1 e8 1f             	shr    $0x1f,%eax
    2ca1:	8d 04 08             	lea    (%eax,%ecx,1),%eax
    2ca4:	d1 f8                	sar    %eax
    2ca6:	89 42 6c             	mov    %eax,0x6c(%edx)
  } else {
    (*cont)->ssthresh /= 2;
  }
#endif

  (*cont)->TCPBase = newBase;
    2ca9:	8b 13                	mov    (%ebx),%edx
    2cab:	8b 45 10             	mov    0x10(%ebp),%eax
    2cae:	89 42 70             	mov    %eax,0x70(%edx)
  (*cont)->startCwnd = 1;
    2cb1:	8b 03                	mov    (%ebx),%eax
    2cb3:	c7 40 68 01 00 00 00 	movl   $0x1,0x68(%eax)

  (*cont)->actualCwnd = (*cont)->startCwnd;
    2cba:	8b 13                	mov    (%ebx),%edx
    2cbc:	8b 42 68             	mov    0x68(%edx),%eax
    2cbf:	89 82 d4 00 00 00    	mov    %eax,0xd4(%edx)

#if 1
  if(!alloc_msk_packets((*cont), 1)) {
    2cc5:	c7 44 24 04 01 00 00 	movl   $0x1,0x4(%esp,1)
    2ccc:	00 
    2ccd:	8b 03                	mov    (%ebx),%eax
    2ccf:	89 04 24             	mov    %eax,(%esp,1)
    2cd2:	e8 79 02 00 00       	call   2f50 <alloc_msk_packets>
    2cd7:	85 c0                	test   %eax,%eax
    2cd9:	0f 84 97 00 00 00    	je     2d76 <DoSlowStartStep+0x126>
			      __u8 type, 
			      __u8 contType, 
			      __u16 minResponseLen,
			      __u32 firstTransportChild, 
			      __u8 numTransportChildren) {
    2cdf:	8b 03                	mov    (%ebx),%eax
    2ce1:	8b 90 e0 00 00 00    	mov    0xe0(%eax),%edx
    2ce7:	8b 40 70             	mov    0x70(%eax),%eax
  pkt->nonce = -1;
    2cea:	c7 02 ff ff ff ff    	movl   $0xffffffff,(%edx)
    2cf0:	8d 48 01             	lea    0x1(%eax),%ecx
  pkt->seq = seq;
    2cf3:	89 42 04             	mov    %eax,0x4(%edx)
  //pkt->ack_seq = ack_seq;
  pkt->len = len;
  pkt->byteNum = byteNum;
  pkt->type = type;
  pkt->contType = contType;
    2cf6:	0f b6 42 10          	movzbl 0x10(%edx),%eax
    2cfa:	c7 42 08 52 05 00 00 	movl   $0x552,0x8(%edx)
    2d01:	c7 42 0c ff ff ff ff 	movl   $0xffffffff,0xc(%edx)
  pkt->minResponseLen = minResponseLen;
    2d08:	66 c7 42 1c 52 05    	movw   $0x552,0x1c(%edx)
    2d0e:	24 c0                	and    $0xc0,%al
    2d10:	0c 08                	or     $0x8,%al
    2d12:	88 42 10             	mov    %al,0x10(%edx)
  pkt->firstTransportChild = firstTransportChild;
    2d15:	89 4a 20             	mov    %ecx,0x20(%edx)
  pkt->numTransportChildren = numTransportChildren;
    2d18:	c6 42 24 01          	movb   $0x1,0x24(%edx)
  pkt->ucontLen = 0;
    2d1c:	c7 42 14 00 00 00 00 	movl   $0x0,0x14(%edx)
  pkt->ucontData = NULL;
    2d23:	c7 42 18 00 00 00 00 	movl   $0x0,0x18(%edx)
  pkt->numSiblings = -1;
    2d2a:	c6 42 11 ff          	movb   $0xff,0x11(%edx)
  pkt->position = INVALID_POSITION;
    2d2e:	c6 42 12 ff          	movb   $0xff,0x12(%edx)
	  free_trickles_msk((*cont)->sk, (*cont));
	  free_trickles_msk_finish((*cont)->sk, (*cont));
	  return -ENOMEM;
  }
  makePacket(&(*cont)->packets[0], (*cont)->TCPBase, 0xdeadbeef, MTU, -1, PTYPE_FIRST | PACKET_NORMAL, CONTTYPE_FULL1, 
	     CONTTYPE_FULL_MTU, (*cont)->TCPBase + 1, 1);
#else
  if(!alloc_msk_packets((*cont), 2)) {
	  free_trickles_msk((*cont)->sk, (*cont));
	  free_trickles_msk_finish((*cont)->sk, (*cont));
	  return -ENOMEM;
  }
  makePacket(&(*cont)->packets[0], (*cont)->TCPBase, 0xdeadbeef, MTU, -1, 
	     PTYPE_FIRST | PACKET_NORMAL, CONTTYPE_FULL1, 
	     CONTTYPE_FULL_MTU, (*cont)->TCPBase + 1, 1);

  makePacket(&(*cont)->packets[1], (*cont)->TCPBase, 0xdeadbeef, MTU, -1, 
	     PACKET_NORMAL, CONTTYPE_FULL1, 
	     CONTTYPE_FULL_MTU, (*cont)->TCPBase + 2, 1);
#endif

  if(serverDebugLevel >= 1)
    2d32:	a1 00 00 00 00       	mov    0x0,%eax
    2d37:	85 c0                	test   %eax,%eax
    2d39:	7e 22                	jle    2d5d <DoSlowStartStep+0x10d>
	  printk("slow start step TCPBase - %u seq - %u\n", (*cont)->TCPBase, 
    2d3b:	8b 13                	mov    (%ebx),%edx
    2d3d:	8b 82 e0 00 00 00    	mov    0xe0(%edx),%eax
    2d43:	8b 40 04             	mov    0x4(%eax),%eax
    2d46:	89 44 24 08          	mov    %eax,0x8(%esp,1)
    2d4a:	8b 42 70             	mov    0x70(%edx),%eax
    2d4d:	c7 04 24 60 08 00 00 	movl   $0x860,(%esp,1)
    2d54:	89 44 24 04          	mov    %eax,0x4(%esp,1)
    2d58:	e8 fc ff ff ff       	call   2d59 <DoSlowStartStep+0x109>
		 (*cont)->packets[0].seq);

  DoUpcall((*cont), event);
    2d5d:	8b 45 14             	mov    0x14(%ebp),%eax
    2d60:	89 44 24 04          	mov    %eax,0x4(%esp,1)
    2d64:	8b 03                	mov    (%ebx),%eax
    2d66:	89 04 24             	mov    %eax,(%esp,1)
    2d69:	e8 fc ff ff ff       	call   2d6a <DoSlowStartStep+0x11a>
  return 0;
    2d6e:	31 c0                	xor    %eax,%eax
}
    2d70:	83 c4 0c             	add    $0xc,%esp
    2d73:	5b                   	pop    %ebx
    2d74:	5d                   	pop    %ebp
    2d75:	c3                   	ret    
    2d76:	8b 03                	mov    (%ebx),%eax
    2d78:	89 44 24 04          	mov    %eax,0x4(%esp,1)
    2d7c:	8b 40 20             	mov    0x20(%eax),%eax
    2d7f:	89 04 24             	mov    %eax,(%esp,1)
    2d82:	e8 79 d2 ff ff       	call   0 <free_trickles_msk>
    2d87:	8b 03                	mov    (%ebx),%eax
    2d89:	89 44 24 04          	mov    %eax,0x4(%esp,1)
    2d8d:	8b 40 20             	mov    0x20(%eax),%eax
    2d90:	89 04 24             	mov    %eax,(%esp,1)
    2d93:	e8 08 d3 ff ff       	call   a0 <free_trickles_msk_finish>
    2d98:	b8 f4 ff ff ff       	mov    $0xfffffff4,%eax
    2d9d:	eb d1                	jmp    2d70 <DoSlowStartStep+0x120>
    2d9f:	90                   	nop    
    2da0:	8b 03                	mov    (%ebx),%eax
    2da2:	d1 68 6c             	shrl   0x6c(%eax)
    2da5:	e9 ff fe ff ff       	jmp    2ca9 <DoSlowStartStep+0x59>
    2daa:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi

00002db0 <AckTCPCwndScalar>:
    2db0:	55                   	push   %ebp
    2db1:	89 e5                	mov    %esp,%ebp
    2db3:	83 ec 0c             	sub    $0xc,%esp
    2db6:	c7 44 24 08 00 00 00 	movl   $0x0,0x8(%esp,1)
    2dbd:	00 
    2dbe:	8b 45 0c             	mov    0xc(%ebp),%eax
    2dc1:	89 44 24 04          	mov    %eax,0x4(%esp,1)
    2dc5:	8b 45 08             	mov    0x8(%ebp),%eax
    2dc8:	89 04 24             	mov    %eax,(%esp,1)
    2dcb:	e8 fc ff ff ff       	call   2dcc <AckTCPCwndScalar+0x1c>
    2dd0:	89 ec                	mov    %ebp,%esp
    2dd2:	5d                   	pop    %ebp
    2dd3:	c3                   	ret    
    2dd4:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi
    2dda:	8d bf 00 00 00 00    	lea    0x0(%edi),%edi

00002de0 <Sack_contains>:
    2de0:	55                   	push   %ebp
    2de1:	89 e5                	mov    %esp,%ebp
    2de3:	8b 4d 08             	mov    0x8(%ebp),%ecx
    2de6:	8b 45 0c             	mov    0xc(%ebp),%eax
    2de9:	31 d2                	xor    %edx,%edx
    2deb:	39 01                	cmp    %eax,(%ecx)
    2ded:	77 0b                	ja     2dfa <Sack_contains+0x1a>
    2def:	3b 41 04             	cmp    0x4(%ecx),%eax
    2df2:	b8 01 00 00 00       	mov    $0x1,%eax
    2df7:	0f 46 d0             	cmovbe %eax,%edx
    2dfa:	5d                   	pop    %ebp
    2dfb:	89 d0                	mov    %edx,%eax
    2dfd:	c3                   	ret    
    2dfe:	89 f6                	mov    %esi,%esi

00002e00 <Sack_gapLen>:
    2e00:	55                   	push   %ebp
    2e01:	89 e5                	mov    %esp,%ebp
    2e03:	8b 45 0c             	mov    0xc(%ebp),%eax
    2e06:	8b 55 08             	mov    0x8(%ebp),%edx
    2e09:	5d                   	pop    %ebp
    2e0a:	8b 00                	mov    (%eax),%eax
    2e0c:	8b 4a 04             	mov    0x4(%edx),%ecx
    2e0f:	29 c8                	sub    %ecx,%eax
    2e11:	48                   	dec    %eax
    2e12:	c3                   	ret    
    2e13:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi
    2e19:	8d bc 27 00 00 00 00 	lea    0x0(%edi,1),%edi

00002e20 <Sack_adjacent>:
    2e20:	55                   	push   %ebp
    2e21:	89 e5                	mov    %esp,%ebp
    2e23:	8b 45 0c             	mov    0xc(%ebp),%eax
    2e26:	8b 10                	mov    (%eax),%edx
    2e28:	8b 45 08             	mov    0x8(%ebp),%eax
    2e2b:	5d                   	pop    %ebp
    2e2c:	4a                   	dec    %edx
    2e2d:	3b 50 04             	cmp    0x4(%eax),%edx
    2e30:	0f 94 c0             	sete   %al
    2e33:	0f b6 c0             	movzbl %al,%eax
    2e36:	c3                   	ret    
    2e37:	89 f6                	mov    %esi,%esi
    2e39:	8d bc 27 00 00 00 00 	lea    0x0(%edi,1),%edi

00002e40 <__constant_memcpy>:
 * This looks horribly ugly, but the compiler can optimize it totally,
 * as the count is constant.
 */
static inline void * __constant_memcpy(void * to, const void * from, size_t n)
{
    2e40:	55                   	push   %ebp
    2e41:	89 e5                	mov    %esp,%ebp
    2e43:	83 ec 0c             	sub    $0xc,%esp
    2e46:	89 75 f8             	mov    %esi,0xfffffff8(%ebp)
    2e49:	8b 4d 10             	mov    0x10(%ebp),%ecx
    2e4c:	8b 55 08             	mov    0x8(%ebp),%edx
    2e4f:	89 7d fc             	mov    %edi,0xfffffffc(%ebp)
	switch (n) {
    2e52:	83 f9 14             	cmp    $0x14,%ecx
    2e55:	8b 75 0c             	mov    0xc(%ebp),%esi
    2e58:	0f 87 82 00 00 00    	ja     2ee0 <__constant_memcpy+0xa0>
    2e5e:	ff 24 8d 2c 00 00 00 	jmp    *0x2c(,%ecx,4)
		case 0:
			return to;
		case 1:
			*(unsigned char *)to = *(const unsigned char *)from;
    2e65:	0f b6 06             	movzbl (%esi),%eax
    2e68:	88 02                	mov    %al,(%edx)
    2e6a:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi
			return to;
		case 2:
			*(unsigned short *)to = *(const unsigned short *)from;
			return to;
		case 3:
			*(unsigned short *)to = *(const unsigned short *)from;
			*(2+(unsigned char *)to) = *(2+(const unsigned char *)from);
			return to;
		case 4:
			*(unsigned long *)to = *(const unsigned long *)from;
			return to;
		case 6:	/* for Ethernet addresses */
			*(unsigned long *)to = *(const unsigned long *)from;
			*(2+(unsigned short *)to) = *(2+(const unsigned short *)from);
			return to;
		case 8:
			*(unsigned long *)to = *(const unsigned long *)from;
			*(1+(unsigned long *)to) = *(1+(const unsigned long *)from);
			return to;
		case 12:
			*(unsigned long *)to = *(const unsigned long *)from;
			*(1+(unsigned long *)to) = *(1+(const unsigned long *)from);
			*(2+(unsigned long *)to) = *(2+(const unsigned long *)from);
			return to;
		case 16:
			*(unsigned long *)to = *(const unsigned long *)from;
			*(1+(unsigned long *)to) = *(1+(const unsigned long *)from);
			*(2+(unsigned long *)to) = *(2+(const unsigned long *)from);
			*(3+(unsigned long *)to) = *(3+(const unsigned long *)from);
			return to;
		case 20:
			*(unsigned long *)to = *(const unsigned long *)from;
			*(1+(unsigned long *)to) = *(1+(const unsigned long *)from);
			*(2+(unsigned long *)to) = *(2+(const unsigned long *)from);
			*(3+(unsigned long *)to) = *(3+(const unsigned long *)from);
			*(4+(unsigned long *)to) = *(4+(const unsigned long *)from);
			return to;
	}
#define COMMON(x) \
__asm__ __volatile__( \
	"rep ; movsl" \
	x \
	: "=&c" (d0), "=&D" (d1), "=&S" (d2) \
	: "0" (n/4),"1" ((long) to),"2" ((long) from) \
	: "memory");
{
	int d0, d1, d2;
	switch (n % 4) {
		case 0: COMMON(""); return to;
		case 1: COMMON("\n\tmovsb"); return to;
		case 2: COMMON("\n\tmovsw"); return to;
		default: COMMON("\n\tmovsw\n\tmovsb"); return to;
	}
}
  
#undef COMMON
}
    2e70:	8b 75 f8             	mov    0xfffffff8(%ebp),%esi
    2e73:	89 d0                	mov    %edx,%eax
    2e75:	8b 7d fc             	mov    0xfffffffc(%ebp),%edi
    2e78:	89 ec                	mov    %ebp,%esp
    2e7a:	5d                   	pop    %ebp
    2e7b:	c3                   	ret    
    2e7c:	0f b7 06             	movzwl (%esi),%eax
    2e7f:	66 89 02             	mov    %ax,(%edx)
    2e82:	eb ec                	jmp    2e70 <__constant_memcpy+0x30>
    2e84:	0f b7 06             	movzwl (%esi),%eax
    2e87:	66 89 02             	mov    %ax,(%edx)
    2e8a:	0f b6 46 02          	movzbl 0x2(%esi),%eax
    2e8e:	88 42 02             	mov    %al,0x2(%edx)
    2e91:	eb dd                	jmp    2e70 <__constant_memcpy+0x30>
    2e93:	8b 06                	mov    (%esi),%eax
    2e95:	89 02                	mov    %eax,(%edx)
    2e97:	eb d7                	jmp    2e70 <__constant_memcpy+0x30>
    2e99:	8b 06                	mov    (%esi),%eax
    2e9b:	89 02                	mov    %eax,(%edx)
    2e9d:	0f b7 46 04          	movzwl 0x4(%esi),%eax
    2ea1:	66 89 42 04          	mov    %ax,0x4(%edx)
    2ea5:	eb c9                	jmp    2e70 <__constant_memcpy+0x30>
    2ea7:	8b 06                	mov    (%esi),%eax
    2ea9:	89 02                	mov    %eax,(%edx)
    2eab:	8b 46 04             	mov    0x4(%esi),%eax
    2eae:	89 42 04             	mov    %eax,0x4(%edx)
    2eb1:	eb bd                	jmp    2e70 <__constant_memcpy+0x30>
    2eb3:	8b 06                	mov    (%esi),%eax
    2eb5:	89 02                	mov    %eax,(%edx)
    2eb7:	8b 46 04             	mov    0x4(%esi),%eax
    2eba:	89 42 04             	mov    %eax,0x4(%edx)
    2ebd:	8b 46 08             	mov    0x8(%esi),%eax
    2ec0:	89 42 08             	mov    %eax,0x8(%edx)
    2ec3:	eb ab                	jmp    2e70 <__constant_memcpy+0x30>
    2ec5:	8b 06                	mov    (%esi),%eax
    2ec7:	89 02                	mov    %eax,(%edx)
    2ec9:	8b 46 04             	mov    0x4(%esi),%eax
    2ecc:	89 42 04             	mov    %eax,0x4(%edx)
    2ecf:	8b 46 08             	mov    0x8(%esi),%eax
    2ed2:	89 42 08             	mov    %eax,0x8(%edx)
    2ed5:	8b 46 0c             	mov    0xc(%esi),%eax
    2ed8:	89 42 0c             	mov    %eax,0xc(%edx)
    2edb:	eb 93                	jmp    2e70 <__constant_memcpy+0x30>
    2edd:	8d 76 00             	lea    0x0(%esi),%esi
    2ee0:	89 c8                	mov    %ecx,%eax
    2ee2:	83 e0 03             	and    $0x3,%eax
    2ee5:	83 f8 01             	cmp    $0x1,%eax
    2ee8:	74 36                	je     2f20 <__constant_memcpy+0xe0>
    2eea:	83 f8 01             	cmp    $0x1,%eax
    2eed:	72 22                	jb     2f11 <__constant_memcpy+0xd1>
    2eef:	83 f8 02             	cmp    $0x2,%eax
    2ef2:	74 0f                	je     2f03 <__constant_memcpy+0xc3>
    2ef4:	c1 e9 02             	shr    $0x2,%ecx
    2ef7:	89 d7                	mov    %edx,%edi
    2ef9:	f3 a5                	repz movsl %ds:(%esi),%es:(%edi)
    2efb:	66 a5                	movsw  %ds:(%esi),%es:(%edi)
    2efd:	a4                   	movsb  %ds:(%esi),%es:(%edi)
    2efe:	e9 6d ff ff ff       	jmp    2e70 <__constant_memcpy+0x30>
    2f03:	c1 e9 02             	shr    $0x2,%ecx
    2f06:	89 d7                	mov    %edx,%edi
    2f08:	f3 a5                	repz movsl %ds:(%esi),%es:(%edi)
    2f0a:	66 a5                	movsw  %ds:(%esi),%es:(%edi)
    2f0c:	e9 5f ff ff ff       	jmp    2e70 <__constant_memcpy+0x30>
    2f11:	c1 e9 02             	shr    $0x2,%ecx
    2f14:	89 d7                	mov    %edx,%edi
    2f16:	f3 a5                	repz movsl %ds:(%esi),%es:(%edi)
    2f18:	e9 53 ff ff ff       	jmp    2e70 <__constant_memcpy+0x30>
    2f1d:	8d 76 00             	lea    0x0(%esi),%esi
    2f20:	c1 e9 02             	shr    $0x2,%ecx
    2f23:	89 d7                	mov    %edx,%edi
    2f25:	f3 a5                	repz movsl %ds:(%esi),%es:(%edi)
    2f27:	a4                   	movsb  %ds:(%esi),%es:(%edi)
    2f28:	e9 43 ff ff ff       	jmp    2e70 <__constant_memcpy+0x30>
    2f2d:	8b 06                	mov    (%esi),%eax
    2f2f:	89 02                	mov    %eax,(%edx)
    2f31:	8b 46 04             	mov    0x4(%esi),%eax
    2f34:	89 42 04             	mov    %eax,0x4(%edx)
    2f37:	8b 46 08             	mov    0x8(%esi),%eax
    2f3a:	89 42 08             	mov    %eax,0x8(%edx)
    2f3d:	8b 46 0c             	mov    0xc(%esi),%eax
    2f40:	89 42 0c             	mov    %eax,0xc(%edx)
    2f43:	8b 46 10             	mov    0x10(%esi),%eax
    2f46:	89 42 10             	mov    %eax,0x10(%edx)
    2f49:	e9 22 ff ff ff       	jmp    2e70 <__constant_memcpy+0x30>
    2f4e:	89 f6                	mov    %esi,%esi

00002f50 <alloc_msk_packets>:
#endif

#ifndef USERTEST

static inline int alloc_msk_packets(struct cminisock *msk, int numPackets) {
    2f50:	55                   	push   %ebp
    2f51:	89 e5                	mov    %esp,%ebp
    2f53:	56                   	push   %esi
    2f54:	53                   	push   %ebx
    2f55:	83 ec 10             	sub    $0x10,%esp
    2f58:	8b 5d 08             	mov    0x8(%ebp),%ebx
    2f5b:	8b 75 0c             	mov    0xc(%ebp),%esi
	BUG_TRAP(msk->num_packets == 0);
    2f5e:	8b 83 dc 00 00 00    	mov    0xdc(%ebx),%eax
    2f64:	85 c0                	test   %eax,%eax
    2f66:	0f 85 e5 01 00 00    	jne    3151 <alloc_msk_packets+0x201>
	BUG_TRAP(numPackets >= 0);
    2f6c:	85 f6                	test   %esi,%esi
    2f6e:	0f 88 c4 01 00 00    	js     3138 <alloc_msk_packets+0x1e8>
#define MAX_NUM_SIMULATION_PACKETS (8000)
	static struct cminisock_packet packets[NR_CPUS][MAX_NUM_SIMULATION_PACKETS];
	if(!SIMULATION_MODE(msk->sk)) {
    2f74:	8b 53 20             	mov    0x20(%ebx),%edx
    2f77:	8b 82 a8 02 00 00    	mov    0x2a8(%edx),%eax
    2f7d:	a9 01 00 00 00       	test   $0x1,%eax
    2f82:	74 09                	je     2f8d <alloc_msk_packets+0x3d>
    2f84:	83 e0 08             	and    $0x8,%eax
    2f87:	0f 84 e3 00 00 00    	je     3070 <alloc_msk_packets+0x120>
		msk->packets = tmalloc(msk->sk, sizeof(struct cminisock_packet) * numPackets);
    2f8d:	89 14 24             	mov    %edx,(%esp,1)
    2f90:	8d 04 b6             	lea    (%esi,%esi,4),%eax
    2f93:	c1 e0 03             	shl    $0x3,%eax
    2f96:	89 44 24 04          	mov    %eax,0x4(%esp,1)
    2f9a:	e8 fc ff ff ff       	call   2f9b <alloc_msk_packets+0x4b>
    2f9f:	89 83 e0 00 00 00    	mov    %eax,0xe0(%ebx)
		if(msk->packets == NULL) {
    2fa5:	85 c0                	test   %eax,%eax
    2fa7:	0f 85 b3 00 00 00    	jne    3060 <alloc_msk_packets+0x110>
			if(trickles_ratelimit()) {
    2fad:	a1 00 00 00 00       	mov    0x0,%eax
    2fb2:	9c                   	pushf  
    2fb3:	59                   	pop    %ecx
    2fb4:	fa                   	cli    
    2fb5:	89 c2                	mov    %eax,%edx
    2fb7:	8b 35 20 e2 04 00    	mov    0x4e220,%esi
    2fbd:	8b 1d 04 00 00 00    	mov    0x4,%ebx
    2fc3:	a3 20 e2 04 00       	mov    %eax,0x4e220
    2fc8:	29 f2                	sub    %esi,%edx
    2fca:	01 da                	add    %ebx,%edx
    2fcc:	89 15 04 00 00 00    	mov    %edx,0x4
    2fd2:	81 fa 88 13 00 00    	cmp    $0x1388,%edx
    2fd8:	76 10                	jbe    2fea <alloc_msk_packets+0x9a>
    2fda:	be 88 13 00 00       	mov    $0x1388,%esi
    2fdf:	ba 88 13 00 00       	mov    $0x1388,%edx
    2fe4:	89 35 04 00 00 00    	mov    %esi,0x4
    2fea:	81 fa f3 01 00 00    	cmp    $0x1f3,%edx
    2ff0:	76 61                	jbe    3053 <alloc_msk_packets+0x103>
    2ff2:	31 db                	xor    %ebx,%ebx
    2ff4:	81 ea f4 01 00 00    	sub    $0x1f4,%edx
    2ffa:	a1 24 e2 04 00       	mov    0x4e224,%eax
    2fff:	89 15 04 00 00 00    	mov    %edx,0x4
    3005:	89 1d 24 e2 04 00    	mov    %ebx,0x4e224
    300b:	51                   	push   %ecx
    300c:	9d                   	popf   
    300d:	85 c0                	test   %eax,%eax
    300f:	75 20                	jne    3031 <alloc_msk_packets+0xe1>
    3011:	b8 01 00 00 00       	mov    $0x1,%eax
    3016:	85 c0                	test   %eax,%eax
    3018:	75 09                	jne    3023 <alloc_msk_packets+0xd3>
				printk("out of memory while tmalloc()'ing space for packets\n");
			}
			return 0;
		}
	} else {
		// avoid malloc
		if(numPackets <= MAX_NUM_SIMULATION_PACKETS) {
			msk->packets = packets[smp_processor_id()];
		} else {
			msk->packets = NULL;
			if(trickles_ratelimit()) {
				printk("Too many packets requested during simulation\n");
			}
			return 0;
    301a:	31 c0                	xor    %eax,%eax
		}
	}
	msk->num_packets = numPackets;
	return 1;
}
    301c:	83 c4 10             	add    $0x10,%esp
    301f:	5b                   	pop    %ebx
    3020:	5e                   	pop    %esi
    3021:	5d                   	pop    %ebp
    3022:	c3                   	ret    
    3023:	c7 04 24 a0 08 00 00 	movl   $0x8a0,(%esp,1)
    302a:	e8 fc ff ff ff       	call   302b <alloc_msk_packets+0xdb>
    302f:	eb e9                	jmp    301a <alloc_msk_packets+0xca>
    3031:	89 44 24 0c          	mov    %eax,0xc(%esp,1)
    3035:	c7 44 24 08 7b 03 00 	movl   $0x37b,0x8(%esp,1)
    303c:	00 
    303d:	c7 44 24 04 e0 08 00 	movl   $0x8e0,0x4(%esp,1)
    3044:	00 
    3045:	c7 04 24 80 00 00 00 	movl   $0x80,(%esp,1)
    304c:	e8 fc ff ff ff       	call   304d <alloc_msk_packets+0xfd>
    3051:	eb be                	jmp    3011 <alloc_msk_packets+0xc1>
    3053:	ff 05 24 e2 04 00    	incl   0x4e224
    3059:	51                   	push   %ecx
    305a:	9d                   	popf   
    305b:	31 c0                	xor    %eax,%eax
    305d:	eb b7                	jmp    3016 <alloc_msk_packets+0xc6>
    305f:	90                   	nop    
    3060:	89 b3 dc 00 00 00    	mov    %esi,0xdc(%ebx)
    3066:	b8 01 00 00 00       	mov    $0x1,%eax
    306b:	eb af                	jmp    301c <alloc_msk_packets+0xcc>
    306d:	8d 76 00             	lea    0x0(%esi),%esi
    3070:	81 fe 40 1f 00 00    	cmp    $0x1f40,%esi
    3076:	7f 0d                	jg     3085 <alloc_msk_packets+0x135>
    3078:	b8 20 00 00 00       	mov    $0x20,%eax
    307d:	89 83 e0 00 00 00    	mov    %eax,0xe0(%ebx)
    3083:	eb db                	jmp    3060 <alloc_msk_packets+0x110>
    3085:	31 c0                	xor    %eax,%eax
    3087:	89 83 e0 00 00 00    	mov    %eax,0xe0(%ebx)
    308d:	a1 00 00 00 00       	mov    0x0,%eax
    3092:	9c                   	pushf  
    3093:	59                   	pop    %ecx
    3094:	fa                   	cli    
    3095:	89 c2                	mov    %eax,%edx
    3097:	8b 35 28 e2 04 00    	mov    0x4e228,%esi
    309d:	8b 1d 08 00 00 00    	mov    0x8,%ebx
    30a3:	a3 28 e2 04 00       	mov    %eax,0x4e228
    30a8:	29 f2                	sub    %esi,%edx
    30aa:	01 da                	add    %ebx,%edx
    30ac:	89 15 08 00 00 00    	mov    %edx,0x8
    30b2:	81 fa 88 13 00 00    	cmp    $0x1388,%edx
    30b8:	76 10                	jbe    30ca <alloc_msk_packets+0x17a>
    30ba:	be 88 13 00 00       	mov    $0x1388,%esi
    30bf:	ba 88 13 00 00       	mov    $0x1388,%edx
    30c4:	89 35 08 00 00 00    	mov    %esi,0x8
    30ca:	81 fa f3 01 00 00    	cmp    $0x1f3,%edx
    30d0:	76 5a                	jbe    312c <alloc_msk_packets+0x1dc>
    30d2:	31 db                	xor    %ebx,%ebx
    30d4:	81 ea f4 01 00 00    	sub    $0x1f4,%edx
    30da:	a1 2c e2 04 00       	mov    0x4e22c,%eax
    30df:	89 15 08 00 00 00    	mov    %edx,0x8
    30e5:	89 1d 2c e2 04 00    	mov    %ebx,0x4e22c
    30eb:	51                   	push   %ecx
    30ec:	9d                   	popf   
    30ed:	85 c0                	test   %eax,%eax
    30ef:	75 19                	jne    310a <alloc_msk_packets+0x1ba>
    30f1:	b8 01 00 00 00       	mov    $0x1,%eax
    30f6:	85 c0                	test   %eax,%eax
    30f8:	0f 84 1c ff ff ff    	je     301a <alloc_msk_packets+0xca>
    30fe:	c7 04 24 20 09 00 00 	movl   $0x920,(%esp,1)
    3105:	e9 20 ff ff ff       	jmp    302a <alloc_msk_packets+0xda>
    310a:	89 44 24 0c          	mov    %eax,0xc(%esp,1)
    310e:	c7 44 24 08 86 03 00 	movl   $0x386,0x8(%esp,1)
    3115:	00 
    3116:	c7 44 24 04 e0 08 00 	movl   $0x8e0,0x4(%esp,1)
    311d:	00 
    311e:	c7 04 24 80 00 00 00 	movl   $0x80,(%esp,1)
    3125:	e8 fc ff ff ff       	call   3126 <alloc_msk_packets+0x1d6>
    312a:	eb c5                	jmp    30f1 <alloc_msk_packets+0x1a1>
    312c:	ff 05 2c e2 04 00    	incl   0x4e22c
    3132:	51                   	push   %ecx
    3133:	9d                   	popf   
    3134:	31 c0                	xor    %eax,%eax
    3136:	eb be                	jmp    30f6 <alloc_msk_packets+0x1a6>
    3138:	c7 44 24 04 75 03 00 	movl   $0x375,0x4(%esp,1)
    313f:	00 
    3140:	c7 04 24 60 09 00 00 	movl   $0x960,(%esp,1)
    3147:	e8 fc ff ff ff       	call   3148 <alloc_msk_packets+0x1f8>
    314c:	e9 23 fe ff ff       	jmp    2f74 <alloc_msk_packets+0x24>
    3151:	c7 44 24 04 74 03 00 	movl   $0x374,0x4(%esp,1)
    3158:	00 
    3159:	c7 04 24 c0 09 00 00 	movl   $0x9c0,(%esp,1)
    3160:	e8 fc ff ff ff       	call   3161 <alloc_msk_packets+0x211>
    3165:	e9 02 fe ff ff       	jmp    2f6c <alloc_msk_packets+0x1c>
    316a:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi

00003170 <alloc_trickles_msk>:

static inline 
int can_alloc_trickles_msk(struct sock *sk) {
	struct tcp_opt *tp = &(sk->tp_pinfo.af_tcp);
	struct alloc_head_list *head = &tp->cminisock_api_config.msk_freelist;
	struct cminisock *curr = 
		(struct cminisock *)head->next;
	while((struct alloc_head_list*)curr != head && curr->ctl == ALLOC_PROCESSING) {
		//printk("alloc_head loop\n");
		curr = curr->next;
	}
	return (struct alloc_head_list*)curr != head;
}

static inline struct cminisock *alloc_trickles_msk(struct sock *sk) {
    3170:	55                   	push   %ebp
    3171:	89 e5                	mov    %esp,%ebp
    3173:	57                   	push   %edi
    3174:	56                   	push   %esi
    3175:	53                   	push   %ebx
    3176:	83 ec 0c             	sub    $0xc,%esp
    3179:	8b 75 08             	mov    0x8(%ebp),%esi
	struct tcp_opt *tp = &(sk->tp_pinfo.af_tcp);
	struct alloc_head_list *head = &tp->cminisock_api_config.msk_freelist;
	struct cminisock *rval = NULL, *curr = (struct cminisock *)tp->cminisock_api_config.msk_freelist.next;

	if(!SIMULATION_MODE(sk)) {
    317c:	8b 96 a8 02 00 00    	mov    0x2a8(%esi),%edx
    3182:	8d be bc 00 00 00    	lea    0xbc(%esi),%edi
    3188:	8d 8e 90 02 00 00    	lea    0x290(%esi),%ecx
    318e:	8b 87 d8 01 00 00    	mov    0x1d8(%edi),%eax
    3194:	f7 c2 01 00 00 00    	test   $0x1,%edx
    319a:	74 09                	je     31a5 <alloc_trickles_msk+0x35>
    319c:	83 e2 08             	and    $0x8,%edx
    319f:	0f 84 91 00 00 00    	je     3236 <alloc_trickles_msk+0xc6>
		while((struct alloc_head_list*)curr != head && curr->ctl == ALLOC_PROCESSING) {
    31a5:	39 c8                	cmp    %ecx,%eax
    31a7:	74 77                	je     3220 <alloc_trickles_msk+0xb0>
    31a9:	83 78 0c 03          	cmpl   $0x3,0xc(%eax)
    31ad:	74 75                	je     3224 <alloc_trickles_msk+0xb4>
			//printk("alloc_head loop\n");
			curr = curr->next;
		}
		//printk("out of alloc_head loop\n");

		if((struct alloc_head_list *)curr == head) return NULL;
    31af:	39 c8                	cmp    %ecx,%eax
    31b1:	74 6d                	je     3220 <alloc_trickles_msk+0xb0>
	
		rval = curr;
    31b3:	89 c3                	mov    %eax,%ebx
		BUG();
	}
#endif

	elem->next->prev = elem->prev;
    31b5:	8b 50 04             	mov    0x4(%eax),%edx
    31b8:	8b 00                	mov    (%eax),%eax
    31ba:	89 02                	mov    %eax,(%edx)
	elem->prev->next = elem->next;
    31bc:	8b 03                	mov    (%ebx),%eax
	elem->prev = elem->next = NULL;
    31be:	c7 03 00 00 00 00    	movl   $0x0,(%ebx)
    31c4:	89 50 04             	mov    %edx,0x4(%eax)

	elem->list->len--;
    31c7:	8b 43 08             	mov    0x8(%ebx),%eax
    31ca:	c7 43 04 00 00 00 00 	movl   $0x0,0x4(%ebx)
    31d1:	ff 48 10             	decl   0x10(%eax)
	elem->list = NULL;
    31d4:	c7 43 08 00 00 00 00 	movl   $0x0,0x8(%ebx)
		}
		tp->t.responseCount++;

		rval->sk = sk;
		rval->ctl = ALLOC_PENDING;
    31db:	c7 43 0c 02 00 00 00 	movl   $0x2,0xc(%ebx)
    31e2:	31 c0                	xor    %eax,%eax
    31e4:	89 83 dc 00 00 00    	mov    %eax,0xdc(%ebx)
    31ea:	31 c0                	xor    %eax,%eax
    31ec:	89 83 80 00 00 00    	mov    %eax,0x80(%ebx)
    31f2:	31 c0                	xor    %eax,%eax
    31f4:	89 83 84 00 00 00    	mov    %eax,0x84(%ebx)
    31fa:	31 c0                	xor    %eax,%eax
    31fc:	89 83 88 00 00 00    	mov    %eax,0x88(%ebx)
    3202:	31 c0                	xor    %eax,%eax
    3204:	89 83 e0 00 00 00    	mov    %eax,0xe0(%ebx)
	}

	init_minisock(rval);

	return rval;
    320a:	89 d8                	mov    %ebx,%eax
    320c:	c7 43 7c 00 00 00 00 	movl   $0x0,0x7c(%ebx)
}
    3213:	83 c4 0c             	add    $0xc,%esp
    3216:	5b                   	pop    %ebx
    3217:	5e                   	pop    %esi
    3218:	5f                   	pop    %edi
    3219:	5d                   	pop    %ebp
    321a:	c3                   	ret    
    321b:	90                   	nop    
    321c:	8d 74 26 00          	lea    0x0(%esi,1),%esi
    3220:	31 c0                	xor    %eax,%eax
    3222:	eb ef                	jmp    3213 <alloc_trickles_msk+0xa3>
    3224:	8b 40 04             	mov    0x4(%eax),%eax
    3227:	39 c8                	cmp    %ecx,%eax
    3229:	74 f5                	je     3220 <alloc_trickles_msk+0xb0>
    322b:	83 78 0c 03          	cmpl   $0x3,0xc(%eax)
    322f:	74 f3                	je     3224 <alloc_trickles_msk+0xb4>
    3231:	e9 79 ff ff ff       	jmp    31af <alloc_trickles_msk+0x3f>
    3236:	8b 97 54 0b 00 00    	mov    0xb54(%edi),%edx
    323c:	85 d2                	test   %edx,%edx
    323e:	75 28                	jne    3268 <alloc_trickles_msk+0xf8>
    3240:	8b 9f 3c 0b 00 00    	mov    0xb3c(%edi),%ebx
    3246:	c7 43 08 00 00 00 00 	movl   $0x0,0x8(%ebx)
    324d:	c7 03 00 00 00 00    	movl   $0x0,(%ebx)
    3253:	c7 43 04 00 00 00 00 	movl   $0x0,0x4(%ebx)
    325a:	ff 87 54 0b 00 00    	incl   0xb54(%edi)
    3260:	89 73 20             	mov    %esi,0x20(%ebx)
    3263:	e9 73 ff ff ff       	jmp    31db <alloc_trickles_msk+0x6b>
    3268:	c7 44 24 04 20 00 00 	movl   $0x20,0x4(%esp,1)
    326f:	00 
    3270:	c7 04 24 e4 00 00 00 	movl   $0xe4,(%esp,1)
    3277:	e8 fc ff ff ff       	call   3278 <alloc_trickles_msk+0x108>
    327c:	85 c0                	test   %eax,%eax
    327e:	89 c3                	mov    %eax,%ebx
    3280:	74 73                	je     32f5 <alloc_trickles_msk+0x185>
    3282:	c7 00 00 00 00 00    	movl   $0x0,(%eax)
    3288:	c7 40 04 00 00 00 00 	movl   $0x0,0x4(%eax)
    328f:	c7 40 08 00 00 00 00 	movl   $0x0,0x8(%eax)
	elem->list = head;
	head->len++;
}

static inline void insert_tail(struct alloc_head_list *head, struct alloc_head *elem) {
    3296:	8d 86 fc 0b 00 00    	lea    0xbfc(%esi),%eax
    329c:	89 45 f0             	mov    %eax,0xfffffff0(%ebp)
#ifdef DEBUG_LIST
	if(elem->list) {
		BUG();
	}
#endif
	if(head->prev == elem /* || elem->prev != NULL || elem->next != NULL */) {
    329f:	8b 86 fc 0b 00 00    	mov    0xbfc(%esi),%eax
    32a5:	39 d8                	cmp    %ebx,%eax
    32a7:	74 1f                	je     32c8 <alloc_trickles_msk+0x158>
		BUG();
		show_stack(NULL);
	}
	elem->prev = head->prev;
    32a9:	89 03                	mov    %eax,(%ebx)
	head->prev->next = elem;
    32ab:	8b 86 fc 0b 00 00    	mov    0xbfc(%esi),%eax
    32b1:	89 58 04             	mov    %ebx,0x4(%eax)

	elem->next = (struct alloc_head*)head;
    32b4:	8b 45 f0             	mov    0xfffffff0(%ebp),%eax
    32b7:	89 43 04             	mov    %eax,0x4(%ebx)

	elem->list = head;
    32ba:	89 43 08             	mov    %eax,0x8(%ebx)
	head->prev = elem;
	head->len++;
    32bd:	ff 40 10             	incl   0x10(%eax)
    32c0:	89 9e fc 0b 00 00    	mov    %ebx,0xbfc(%esi)
    32c6:	eb 92                	jmp    325a <alloc_trickles_msk+0xea>
    32c8:	c7 44 24 04 0d 00 00 	movl   $0xd,0x4(%esp,1)
    32cf:	00 
    32d0:	c7 04 24 11 00 00 00 	movl   $0x11,(%esp,1)
    32d7:	e8 fc ff ff ff       	call   32d8 <alloc_trickles_msk+0x168>
    32dc:	e8 fc ff ff ff       	call   32dd <alloc_trickles_msk+0x16d>
    32e1:	c7 04 24 00 00 00 00 	movl   $0x0,(%esp,1)
    32e8:	e8 fc ff ff ff       	call   32e9 <alloc_trickles_msk+0x179>
    32ed:	8b 86 fc 0b 00 00    	mov    0xbfc(%esi),%eax
    32f3:	eb b4                	jmp    32a9 <alloc_trickles_msk+0x139>
			rval->next = rval->prev = NULL;
		} else {
			rval = kmalloc(sizeof (struct cminisock), GFP_ATOMIC);
			if(rval == NULL) {
				printk("out of memory during compatibility mode\n");
    32f5:	c7 04 24 40 0a 00 00 	movl   $0xa40,(%esp,1)
    32fc:	e8 fc ff ff ff       	call   32fd <alloc_trickles_msk+0x18d>
    3301:	e9 1a ff ff ff       	jmp    3220 <alloc_trickles_msk+0xb0>
    3306:	8d 76 00             	lea    0x0(%esi),%esi
    3309:	8d bc 27 00 00 00 00 	lea    0x0(%edi,1),%edi

00003310 <marshallContinuationServer>:
  do{						\
    memcpy(dcont->mac, scont->mac, HMACLEN);	\
  } while(0)

MARSHALL_CONTINUATION(Server, 1, SERVER_COMPUTE_MAC)
    3310:	55                   	push   %ebp
    3311:	89 e5                	mov    %esp,%ebp
    3313:	57                   	push   %edi
    3314:	56                   	push   %esi
    3315:	53                   	push   %ebx
    3316:	83 ec 30             	sub    $0x30,%esp
    3319:	8b 75 10             	mov    0x10(%ebp),%esi
    331c:	8b 5d 0c             	mov    0xc(%ebp),%ebx
    331f:	8b 7d 14             	mov    0x14(%ebp),%edi
    3322:	8b 46 3c             	mov    0x3c(%esi),%eax
    3325:	85 ff                	test   %edi,%edi
    3327:	89 43 09             	mov    %eax,0x9(%ebx)
    332a:	8b 46 40             	mov    0x40(%esi),%eax
    332d:	89 43 0d             	mov    %eax,0xd(%ebx)
    3330:	0f 88 0c 01 00 00    	js     3442 <marshallContinuationServer+0x132>
    3336:	8b 86 e0 00 00 00    	mov    0xe0(%esi),%eax
    333c:	8d 14 bf             	lea    (%edi,%edi,4),%edx
    333f:	c1 e2 03             	shl    $0x3,%edx
	__arch__swab24s(addr);
}

static __inline__ __const__ __u32 __fswab32(__u32 x)
{
    3342:	8b 44 10 04          	mov    0x4(%eax,%edx,1),%eax

static __inline__ __const__ __u32 ___arch__swab32(__u32 x)
{
#ifdef CONFIG_X86_BSWAP
	__asm__("bswap %0" : "=r" (x) : "0" (x));
    3346:	0f c8                	bswap  %eax
	__arch__swab24s(addr);
}

static __inline__ __const__ __u32 __fswab32(__u32 x)
{
    3348:	89 43 01             	mov    %eax,0x1(%ebx)
  do{						\
    memcpy(dcont->mac, scont->mac, HMACLEN);	\
  } while(0)

MARSHALL_CONTINUATION(Server, 1, SERVER_COMPUTE_MAC)
    334b:	8b 86 e0 00 00 00    	mov    0xe0(%esi),%eax
    3351:	0f b6 44 10 10       	movzbl 0x10(%eax,%edx,1),%eax
    3356:	c6 43 05 00          	movb   $0x0,0x5(%ebx)
    335a:	c0 e8 03             	shr    $0x3,%al
    335d:	24 07                	and    $0x7,%al
    335f:	88 03                	mov    %al,(%ebx)
    3361:	8b 86 e0 00 00 00    	mov    0xe0(%esi),%eax
    3367:	0f b6 44 10 10       	movzbl 0x10(%eax,%edx,1),%eax
    336c:	24 03                	and    $0x3,%al
    336e:	0f b6 f8             	movzbl %al,%edi
    3371:	83 ff 02             	cmp    $0x2,%edi
    3374:	0f 8f aa 00 00 00    	jg     3424 <marshallContinuationServer+0x114>
    337a:	0f b6 04 bd 08 00 00 	movzbl 0x8(,%edi,4),%eax
    3381:	00 
    3382:	88 43 2d             	mov    %al,0x2d(%ebx)
	__arch__swab24s(addr);
}

static __inline__ __const__ __u32 __fswab32(__u32 x)
{
    3385:	8b 46 4c             	mov    0x4c(%esi),%eax

static __inline__ __const__ __u32 ___arch__swab32(__u32 x)
{
#ifdef CONFIG_X86_BSWAP
	__asm__("bswap %0" : "=r" (x) : "0" (x));
    3388:	0f c8                	bswap  %eax
	__arch__swab24s(addr);
}

static __inline__ __const__ __u32 __fswab32(__u32 x)
{
    338a:	89 43 25             	mov    %eax,0x25(%ebx)
  do{						\
    memcpy(dcont->mac, scont->mac, HMACLEN);	\
  } while(0)

MARSHALL_CONTINUATION(Server, 1, SERVER_COMPUTE_MAC)
    338d:	8b 46 50             	mov    0x50(%esi),%eax
    3390:	89 43 11             	mov    %eax,0x11(%ebx)
	__arch__swab24s(addr);
}

static __inline__ __const__ __u32 __fswab32(__u32 x)
{
    3393:	8b 46 54             	mov    0x54(%esi),%eax

static __inline__ __const__ __u32 ___arch__swab32(__u32 x)
{
#ifdef CONFIG_X86_BSWAP
	__asm__("bswap %0" : "=r" (x) : "0" (x));
    3396:	0f c8                	bswap  %eax
	__arch__swab24s(addr);
}

static __inline__ __const__ __u32 __fswab32(__u32 x)
{
    3398:	89 43 29             	mov    %eax,0x29(%ebx)
    339b:	8b 46 60             	mov    0x60(%esi),%eax

static __inline__ __const__ __u32 ___arch__swab32(__u32 x)
{
#ifdef CONFIG_X86_BSWAP
	__asm__("bswap %0" : "=r" (x) : "0" (x));
    339e:	0f c8                	bswap  %eax
	__arch__swab24s(addr);
}

static __inline__ __const__ __u32 __fswab32(__u32 x)
{
    33a0:	89 43 2e             	mov    %eax,0x2e(%ebx)
    33a3:	8b 46 64             	mov    0x64(%esi),%eax

static __inline__ __const__ __u32 ___arch__swab32(__u32 x)
{
#ifdef CONFIG_X86_BSWAP
	__asm__("bswap %0" : "=r" (x) : "0" (x));
    33a6:	0f c8                	bswap  %eax
	__arch__swab24s(addr);
}

static __inline__ __const__ __u32 __fswab32(__u32 x)
{
    33a8:	89 43 32             	mov    %eax,0x32(%ebx)
    33ab:	8b 46 68             	mov    0x68(%esi),%eax

static __inline__ __const__ __u32 ___arch__swab32(__u32 x)
{
#ifdef CONFIG_X86_BSWAP
	__asm__("bswap %0" : "=r" (x) : "0" (x));
    33ae:	0f c8                	bswap  %eax
	__arch__swab24s(addr);
}

static __inline__ __const__ __u32 __fswab32(__u32 x)
{
    33b0:	89 43 36             	mov    %eax,0x36(%ebx)
    33b3:	8b 46 6c             	mov    0x6c(%esi),%eax

static __inline__ __const__ __u32 ___arch__swab32(__u32 x)
{
#ifdef CONFIG_X86_BSWAP
	__asm__("bswap %0" : "=r" (x) : "0" (x));
    33b6:	0f c8                	bswap  %eax
	__arch__swab24s(addr);
}

static __inline__ __const__ __u32 __fswab32(__u32 x)
{
    33b8:	89 43 3a             	mov    %eax,0x3a(%ebx)
    33bb:	8b 46 70             	mov    0x70(%esi),%eax

static __inline__ __const__ __u32 ___arch__swab32(__u32 x)
{
#ifdef CONFIG_X86_BSWAP
	__asm__("bswap %0" : "=r" (x) : "0" (x));
    33be:	0f c8                	bswap  %eax
	__arch__swab24s(addr);
}

static __inline__ __const__ __u32 __fswab32(__u32 x)
{
    33c0:	89 43 3e             	mov    %eax,0x3e(%ebx)
  do{						\
    memcpy(dcont->mac, scont->mac, HMACLEN);	\
  } while(0)

MARSHALL_CONTINUATION(Server, 1, SERVER_COMPUTE_MAC)
    33c3:	8b 46 74             	mov    0x74(%esi),%eax
    33c6:	8b 56 78             	mov    0x78(%esi),%edx
    33c9:	89 43 42             	mov    %eax,0x42(%ebx)
    33cc:	8b 43 01             	mov    0x1(%ebx),%eax
    33cf:	89 53 46             	mov    %edx,0x46(%ebx)
    33d2:	8d 55 d4             	lea    0xffffffd4(%ebp),%edx
    33d5:	89 45 d4             	mov    %eax,0xffffffd4(%ebp)
    33d8:	0f b6 03             	movzbl (%ebx),%eax
    33db:	88 45 d8             	mov    %al,0xffffffd8(%ebp)
    33de:	80 7b 05 00          	cmpb   $0x0,0x5(%ebx)
    33e2:	0f 95 45 d9          	setne  0xffffffd9(%ebp)
    33e6:	8b 46 14             	mov    0x14(%esi),%eax
    33e9:	89 45 da             	mov    %eax,0xffffffda(%ebp)
    33ec:	0f b7 46 1c          	movzwl 0x1c(%esi),%eax
    33f0:	66 89 45 de          	mov    %ax,0xffffffde(%ebp)
    33f4:	8b 46 18             	mov    0x18(%esi),%eax
    33f7:	89 45 e0             	mov    %eax,0xffffffe0(%ebp)
    33fa:	0f b7 46 1e          	movzwl 0x1e(%esi),%eax
    33fe:	89 5c 24 08          	mov    %ebx,0x8(%esp,1)
    3402:	89 54 24 04          	mov    %edx,0x4(%esp,1)
    3406:	66 89 45 e4          	mov    %ax,0xffffffe4(%ebp)
    340a:	8d 43 15             	lea    0x15(%ebx),%eax
    340d:	89 44 24 0c          	mov    %eax,0xc(%esp,1)
    3411:	8b 45 08             	mov    0x8(%ebp),%eax
    3414:	89 04 24             	mov    %eax,(%esp,1)
    3417:	e8 fc ff ff ff       	call   3418 <marshallContinuationServer+0x108>
    341c:	83 c4 30             	add    $0x30,%esp
    341f:	5b                   	pop    %ebx
    3420:	5e                   	pop    %esi
    3421:	5f                   	pop    %edi
    3422:	5d                   	pop    %ebp
    3423:	c3                   	ret    
    3424:	c7 44 24 04 0d 00 00 	movl   $0xd,0x4(%esp,1)
    342b:	00 
    342c:	c7 04 24 11 00 00 00 	movl   $0x11,(%esp,1)
    3433:	e8 fc ff ff ff       	call   3434 <marshallContinuationServer+0x124>
    3438:	e8 fc ff ff ff       	call   3439 <marshallContinuationServer+0x129>
    343d:	e9 38 ff ff ff       	jmp    337a <marshallContinuationServer+0x6a>
    3442:	c7 44 24 04 51 00 00 	movl   $0x51,0x4(%esp,1)
    3449:	00 
    344a:	c7 04 24 80 0a 00 00 	movl   $0xa80,(%esp,1)
    3451:	e8 fc ff ff ff       	call   3452 <marshallContinuationServer+0x142>
    3456:	e9 db fe ff ff       	jmp    3336 <marshallContinuationServer+0x26>
