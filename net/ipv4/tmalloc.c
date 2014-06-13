// MALLOC and FREE
/* malloc.c - C standard library routine.
   Copyright (c) 1989, 1993  Michael J. Haertel
   You may redistribute this library under the terms of the
   GNU Library General Public License (version 2 or any later
   version) as published by the Free Software Foundation.
   THIS SOFTWARE IS PROVIDED "AS IS" WITHOUT ANY EXPRESS OR IMPLIED
   WARRANTY.  IN PARTICULAR, THE AUTHOR MAKES NO REPRESENTATION OR
   WARRANTY OF ANY KIND CONCERNING THE MERCHANTABILITY OF THIS
   SOFTWARE OR ITS FITNESS FOR ANY PARTICULAR PURPOSE. */

#ifndef USERTEST
#include <linux/stddef.h>
#include <net/tmalloc.h>
#include <net/sock.h>
#include <net/trickles.h>
#else
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "tmalloc.h"
#include "compat.h"
#include "skbuff.h"
#endif

#define DEBUG_ALLOC(X)

void *trickles_morecore(struct sock *sk, long size) {
    void *result;
    struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;
    if(tp->t.heapbytesallocated + size > tp->t.heapbytesize) {
      if(trickles_ratelimit()) {
	printk("tmalloc: out of memory\n");
      }
      return NULL;
    }
#ifndef USERTEST
    result = (char*)tp->cminisock_api_config.cfg.ctl->heap_base;
#else 
    result = (char*)tp->t.heap_absolute_base;
#endif
    result = (char*)result + tp->t.heapbytesallocated;
    tp->t.heapbytesallocated += size;
    return result;
}

void *(*_morecore)(struct sock *, long) = trickles_morecore;

void tfree(struct sock *sk, void *ptr);

/* Aligned allocation. */
static void *
align(struct sock *sk, size_t size)
{
    void *result;
    unsigned int adj;

    result = (*_morecore)(sk, size);
    adj = (unsigned int) ((char *) result - (char *) NULL) % BLOCKSIZE;
    if (adj != 0) {
	(*_morecore)(sk,adj = BLOCKSIZE - adj);
	result = (char *) result + adj;
    }
    return result;
}

/* Set everything up and remember that we have. */
static int
initialize_malloc(struct sock *sk)
{
    struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;
    tp->t.heapsize = tp->t.heapbytesize / BLOCKSIZE;
    tp->t.heapinfo = align(sk, tp->t.heapsize * sizeof (union heap_info));
    if (!tp->t.heapinfo)
	return 0;
    memset(tp->t.heapinfo, 0, tp->t.heapsize * sizeof (union heap_info));
    tp->t.heapinfo[0].free.size = 0;
    tp->t.heapinfo[0].free.next = tp->t.heapinfo[0].free.prev = 0;
    tp->t.heapindex = 0;
    tp->t.heapbase = (char *) tp->t.heapinfo;
    tp->t.malloc_initialized = 1;
    return 1;
}

/* Get neatly aligned memory, initializing or growing the
   heap info table as necessary. */
static void *
morecore(struct sock *sk, size_t size)
{
    struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;
    void *result;
    union heap_info *newinfo, *oldinfo;
    int newsize;

    result = align(sk,size);
    if (!result)
	return NULL;

    /* Check if we need to grow the info table. */
    if (BLOCK(sk,(char *) result + size) > tp->t.heapsize) {
	newsize = tp->t.heapsize;
	while (BLOCK(sk,(char *) result + size) > newsize)
	    newsize *= 2;
	newinfo = align(sk,newsize * sizeof (union heap_info));
	if (!newinfo) {
	    (*_morecore)(sk,-size);
	    return NULL;
	}
	memset(newinfo, 0, newsize * sizeof (union heap_info));
	memcpy(newinfo, tp->t.heapinfo, tp->t.heapsize * sizeof (union heap_info));
	oldinfo = tp->t.heapinfo;
	newinfo[BLOCK(sk,oldinfo)].busy.type = 0;
	newinfo[BLOCK(sk,oldinfo)].busy.info.size
	    = BLOCKIFY(tp->t.heapsize * sizeof (union heap_info));
	tp->t.heapinfo = newinfo;
	tfree(sk,oldinfo);
	tp->t.heapsize = newsize;
    }
    tp->t.heaplimit = BLOCK(sk,(char *) result + size);
    return result;
}

/* Allocate memory from the heap. */
void *
tmalloc(struct sock *sk, size_t size)
{
	DEBUG_ALLOC(printk("tmalloc %d\n", size));
    struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;
    void *result;
    int log, block, blocks, i, lastblocks, start;
    struct heap_list *next;

    if(SIMULATION_MODE(sk)) {
	    return kmalloc(size, GFP_ATOMIC);
    }

    if (!tp->t.malloc_initialized && !initialize_malloc(sk))
	return NULL;

    if (size == 0)
	return NULL;

    if (size < sizeof (struct heap_list))
	size = sizeof (struct heap_list);

    /* Determine the allocation policy based on the request size. */
    if (size <= BLOCKSIZE / 2) {
	/* Small allocation to receive a fragment of a block. Determine
	   the logarithm to base two of the fragment size. */
	--size;
	for (log = 1; (size >>= 1) != 0; ++log)
	    ;

	/* Look in the fragment lists for a free fragment of the
	   desired size. */
	if ((next = tp->t.fraghead[log].next) != 0) {
	    /* There are free fragments of this size.  Pop a fragment
	       out of the fragment list and return it.  Update the block's
	       nfree and first counters. */
	    result = next;
	    next->prev->next = next->next;
	    if (next->next)
		next->next->prev = next->prev;
	    block = BLOCK(sk,result);
	    if (--tp->t.heapinfo[block].busy.info.frag.nfree)
		tp->t.heapinfo[block].busy.info.frag.first
		    = (unsigned int) ((char *) next->next - (char *) NULL)
		      % BLOCKSIZE >> log;
	} else {
	    /* No free fragments of the desired size, so get a new block
	       and break it into fragments, returning the first. */
	    result = tmalloc(sk,BLOCKSIZE);
	    if (!result)
		return NULL;
	    ++tp->t.fragblocks[log];

	    /* Link all fragments but the first into the free list. */
	    for (i = 1; i < BLOCKSIZE >> log; ++i) {
		next = (struct heap_list *) ((char *) result + (i << log));
		next->next = tp->t.fraghead[log].next;
		next->prev = &tp->t.fraghead[log];
		next->prev->next = next;
		if (next->next)
		    next->next->prev = next;
	    }

	    /* Initialize the nfree and first counters for this block. */
	    block = BLOCK(sk,result);
	    tp->t.heapinfo[block].busy.type = log;
	    tp->t.heapinfo[block].busy.info.frag.nfree = i - 1;
	    tp->t.heapinfo[block].busy.info.frag.first = i - 1;
	}
    } else {
	/* Large allocation to receive one or more blocks.  Search
	   the free list in a circle starting at the last place visited.
	   If we loop completely around without finding a large enough
	   space we will have to get more memory from the system. */
	blocks = BLOCKIFY(size);
	start = block = tp->t.heapindex;
	while (tp->t.heapinfo[block].free.size < blocks) {
	    block = tp->t.heapinfo[block].free.next;
	    if (block == start) {
		/* Need to get more from the system.  Check to see if
		   the new core will be contiguous with the final free
		   block; if so we don't need to get as much. */
		block = tp->t.heapinfo[0].free.prev;
		lastblocks = tp->t.heapinfo[block].free.size;
		if (tp->t.heaplimit && block + lastblocks == tp->t.heaplimit
		    && (*_morecore)(sk,0) == ADDRESS(sk,block + lastblocks)
		    && morecore(sk,(blocks - lastblocks) * BLOCKSIZE)) {
		    /* Note that morecore() can change the location of
		       the final block if it moves the info table and the
		       old one gets coalesced into the final block. */
		    block = tp->t.heapinfo[0].free.prev;
		    tp->t.heapinfo[block].free.size += blocks - lastblocks;
		    continue;
		}
		result = morecore(sk,blocks * BLOCKSIZE);
		if (!result)
		    return NULL;
		block = BLOCK(sk,result);
		tp->t.heapinfo[block].busy.type = 0;
		tp->t.heapinfo[block].busy.info.size = blocks;

		DEBUG_ALLOC(printk("tmalloc: returning %p\n", result));
		//show_stack(0);

		return result;
	    }
	}

	/* At this point we have found a suitable free list entry.
	   Figure out how to remove what we need from the list. */
	result = ADDRESS(sk,block);
	if (tp->t.heapinfo[block].free.size > blocks) {
	    /* The block we found has a bit left over, so relink the
	       tail end back into the free list. */
	    tp->t.heapinfo[block + blocks].free.size
		= tp->t.heapinfo[block].free.size - blocks;
	    tp->t.heapinfo[block + blocks].free.next
		= tp->t.heapinfo[block].free.next;
	    tp->t.heapinfo[block + blocks].free.prev
		= tp->t.heapinfo[block].free.prev;
	    tp->t.heapinfo[tp->t.heapinfo[block].free.prev].free.next
		= tp->t.heapinfo[tp->t.heapinfo[block].free.next].free.prev
		    = tp->t.heapindex = block + blocks;
	} else {
	    /* The block exactly matches our requirements, so
	       just remove it from the list. */
	    tp->t.heapinfo[tp->t.heapinfo[block].free.next].free.prev
		= tp->t.heapinfo[block].free.prev;
	    tp->t.heapinfo[tp->t.heapinfo[block].free.prev].free.next
		= tp->t.heapindex = tp->t.heapinfo[block].free.next;
	}

	tp->t.heapinfo[block].busy.type = 0;
	tp->t.heapinfo[block].busy.info.size = blocks;
    }

    DEBUG_ALLOC(printk("tmalloc: returning %p\n", result));
    //show_stack(0);

    return result;
}

/* Return memory to the heap. */
void
tfree(struct sock *sk, void *ptr)
{
	DEBUG_ALLOC(printk("tfreeing %p\n", ptr));
    struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;
    int block, blocks, i, type;
    struct heap_list *prev, *next;

    if (!ptr)
	return;

    if(SIMULATION_MODE(sk)) {
	    kfree(ptr);
	    return;
    }

    block = BLOCK(sk,ptr);

    switch (type = tp->t.heapinfo[block].busy.type) {
    case 0:
	/* Find the free cluster previous to this one in the free list.
	   Start searching at the last block referenced; this may benefit
	   programs with locality of allocation. */
	i = tp->t.heapindex;
	if (i > block)
	    while (i > block)
		i = tp->t.heapinfo[i].free.prev;
	else {
	    do
		i = tp->t.heapinfo[i].free.next;
	    while (i > 0 && i < block);
	    i = tp->t.heapinfo[i].free.prev;
	}

	/* Determine how to link this block into the free list. */
	if (block == i + tp->t.heapinfo[i].free.size) {
	    /* Coalesce this block with its predecessor. */
	    tp->t.heapinfo[i].free.size += tp->t.heapinfo[block].busy.info.size;
	    block = i;
	} else {
	    /* Really link this block back into the free list. */
	    tp->t.heapinfo[block].free.size = tp->t.heapinfo[block].busy.info.size;
	    tp->t.heapinfo[block].free.next = tp->t.heapinfo[i].free.next;
	    tp->t.heapinfo[block].free.prev = i;
	    tp->t.heapinfo[i].free.next = block;
	    tp->t.heapinfo[tp->t.heapinfo[block].free.next].free.prev = block;
	}

	/* Now that the block is linked in, see if we can coalesce it
	   with its successor (by deleting its successor from the list
	   and adding in its size). */
	if (block + tp->t.heapinfo[block].free.size == tp->t.heapinfo[block].free.next) {
	    tp->t.heapinfo[block].free.size
		+= tp->t.heapinfo[tp->t.heapinfo[block].free.next].free.size;
	    tp->t.heapinfo[block].free.next
		= tp->t.heapinfo[tp->t.heapinfo[block].free.next].free.next;
	    tp->t.heapinfo[tp->t.heapinfo[block].free.next].free.prev = block;
	}

	/* Now see if we can return stuff to the system. */
	blocks = tp->t.heapinfo[block].free.size;
	if (blocks >= FINAL_FREE_BLOCKS && block + blocks == tp->t.heaplimit
	    && (*_morecore)(sk,0) == ADDRESS(sk,block + blocks)) {
	    tp->t.heaplimit -= blocks;
	    (*_morecore)(sk,-blocks * BLOCKSIZE);
	    tp->t.heapinfo[tp->t.heapinfo[block].free.prev].free.next
		= tp->t.heapinfo[block].free.next;
	    tp->t.heapinfo[tp->t.heapinfo[block].free.next].free.prev
		= tp->t.heapinfo[block].free.prev;
	    block = tp->t.heapinfo[block].free.prev;
	}

	/* Set the next search to begin at this block. */
	tp->t.heapindex = block;
	break;

    default:
	/* Get the address of the first free fragment in this block. */
	prev = (struct heap_list *) ((char *) ADDRESS(sk,block)
				+ (tp->t.heapinfo[block].busy.info.frag.first
				   << type));

	if (tp->t.heapinfo[block].busy.info.frag.nfree == (BLOCKSIZE >> type) - 1
	&& tp->t.fragblocks[type] > 1) {
	    /* If all fragments of this block are free, remove them
	       from the fragment list and free the whole block. */
	    --tp->t.fragblocks[type];
	    for (next = prev, i = 1; i < BLOCKSIZE >> type; ++i)
		next = next->next;
	    prev->prev->next = next;
	    if (next)
		next->prev = prev->prev;
	    tp->t.heapinfo[block].busy.type = 0;
	    tp->t.heapinfo[block].busy.info.size = 1;
	    tfree(sk,ADDRESS(sk,block));
	} else if (tp->t.heapinfo[block].busy.info.frag.nfree) {
	    /* If some fragments of this block are free, link this fragment
	       into the fragment list after the first free fragment of
	       this block. */
	    next = ptr;
	    next->next = prev->next;
	    next->prev = prev;
	    prev->next = next;
	    if (next->next)
		next->next->prev = next;
	    ++tp->t.heapinfo[block].busy.info.frag.nfree;
	} else {
	    /* No fragments of this block are free, so link this fragment
	       into the fragment list and announce that it is the first
	       free fragment of this block. */
	    prev = (struct heap_list *) ptr;
	    tp->t.heapinfo[block].busy.info.frag.nfree = 1;
	    tp->t.heapinfo[block].busy.info.frag.first
		= (unsigned int) ((char *) ptr - (char *) NULL) % BLOCKSIZE
		  >> type;
	    prev->next = tp->t.fraghead[type].next;
	    prev->prev = &tp->t.fraghead[type];
	    prev->prev->next = prev;
	    if (prev->next)
		prev->next->prev = prev;
	}
	break;
    }
}
