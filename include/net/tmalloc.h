#ifndef TMALLOC_H
#define TMALLOC_H
/* The allocator divides the heap into blocks of fixed size; large
   requests receive one or more whole blocks, and small requests
   receive a fragment of a block.  Fragment sizes are powers of two,
   and all fragments of a block are the same size.  When all the
   fragments in a block have been freed, the block itself is freed.
   WARNING: BLOCKSIZE must be set greater than or equal to the
   machine's page size for valloc() to work correctly.  The default
   definition here is 4096 bytes. */
#define CHAR_BIT (8)
#define INT_BIT (CHAR_BIT * sizeof (int))
#define BLOCKLOG (INT_BIT > 16 ? 12 : 9)
#define BLOCKSIZE (1 << BLOCKLOG)
#define BLOCKIFY(SIZE) (((SIZE) + BLOCKSIZE - 1) / BLOCKSIZE)

/* Number of contiguous free blocks allowed to build up at the end of
   memory before they will be returned to the system. */
#define FINAL_FREE_BLOCKS 8

/* Data structure giving per-block information. */
union heap_info {
    struct {
	int type;		/* Zero for a large block, or positive
				   giving the logarithm to the base two
				   of the fragment size. */
	union {
	    struct {
		int nfree;	/* Free fragments in a fragmented block. */
		int first;	/* First free fragment of the block. */
	    } frag;
	    int size;		/* Size (in blocks) of a large cluster. */
	} info;
    } busy;
    struct {
	int size;		/* Size (in blocks) of a free cluster. */
	int next;		/* Index of next free cluster. */
	int prev;		/* Index of previous free cluster. */
    } free;
};
#define BLOCK(SK,A) (((char *) (A) - (SK)->tp_pinfo.af_tcp.t.heapbase) / BLOCKSIZE + 1)
#define ADDRESS(SK,B) ((void *) (((B) - 1) * BLOCKSIZE + (SK)->tp_pinfo.af_tcp.t.heapbase))


/* Doubly linked lists of free fragments. */
struct heap_list {
    struct heap_list *next;
    struct heap_list *prev;
};
#endif // TMALLOC_H

