#ifndef CACHE_UTIL_H
#define CACHE_UTIL_H

#include <net/trickles_dlist.h>

/*
 * http://burtleburtle.net/bob/hash/evahash.html
 */

typedef  unsigned long int  u4;   /* unsigned 4-byte type */
typedef  unsigned     char  u1;   /* unsigned 1-byte type */

/* The mixing step */
#define mix(a,b,c) \
{ \
  a=a-b;  a=a-c;  a=a^(c>>13); \
  b=b-c;  b=b-a;  b=b^(a<<8);  \
  c=c-a;  c=c-b;  c=c^(b>>13); \
  a=a-b;  a=a-c;  a=a^(c>>12); \
  b=b-c;  b=b-a;  b=b^(a<<16); \
  c=c-a;  c=c-b;  c=c^(b>>5);  \
  a=a-b;  a=a-c;  a=a^(c>>3);  \
  b=b-c;  b=b-a;  b=b^(a<<10); \
  c=c-a;  c=c-b;  c=c^(b>>15); \
}

/* The whole new hash function */
static inline
u4 hash( 
     register u1 *k,        /* the key */
	u4           length,   /* the length of the key in bytes */
	u4           initval  /* the previous hash, or an arbitrary value */
     )
{
   register u4 a,b,c;  /* the internal state */
   u4          len;    /* how many key bytes still need mixing */

   /* Set up the internal state */
   len = length;
   a = b = 0x9e3779b9;  /* the golden ratio; an arbitrary value */
   c = initval;         /* variable initialization of internal state */

   /*---------------------------------------- handle most of the key */
   while (len >= 12)
   {
      a=a+(k[0]+((u4)k[1]<<8)+((u4)k[2]<<16) +((u4)k[3]<<24));
      b=b+(k[4]+((u4)k[5]<<8)+((u4)k[6]<<16) +((u4)k[7]<<24));
      c=c+(k[8]+((u4)k[9]<<8)+((u4)k[10]<<16)+((u4)k[11]<<24));
      mix(a,b,c);
      k = k+12; len = len-12;
   }

   /*------------------------------------- handle the last 11 bytes */
   c = c+length;
   switch(len)              /* all the case statements fall through */
   {
   case 11: c=c+((u4)k[10]<<24);
   case 10: c=c+((u4)k[9]<<16);
   case 9 : c=c+((u4)k[8]<<8);
      /* the first byte of c is reserved for the length */
   case 8 : b=b+((u4)k[7]<<24);
   case 7 : b=b+((u4)k[6]<<16);
   case 6 : b=b+((u4)k[5]<<8);
   case 5 : b=b+k[4];
   case 4 : a=a+((u4)k[3]<<24);
   case 3 : a=a+((u4)k[2]<<16);
   case 2 : a=a+((u4)k[1]<<8);
   case 1 : a=a+k[0];
     /* case 0: nothing left to add */
   }
   mix(a,b,c);
   /*-------------------------------------------- report the result */
   return c;
}


#define die() ({ do { printk("dying at %s:%s():%d\n", __FILE__, __PRETTY_FUNCTION__, __LINE__); BUG(); } while(0) ; 1 ; })

#define RETURN(V) ({ return(V); 1; })

#define PRINTK(S, ...) ({ printk(S,##__VA_ARGS__); 1; })

#undef ERROR
#define ERROR(S,...) (PRINTK(S "\n",##__VA_ARGS__))

#define ENCLOSING(S,F,V) ((S*) (((char*) V) - ((char*) &((S*)0)->F)))

#define ASSERT_OR_RETURN(E)						\
do {									\
	if(!(E)) {							\
		printk("(%s) failed at %s:%s():%d\n",			\
			#E, __FILE__, __PRETTY_FUNCTION__, __LINE__);	\
		return 0;						\
	}								\
} while(0)

#define ASSERT_OR_DIE(E)						\
do {									\
	if(!(E)) {							\
		printk("(%s) failed at %s:%s():%d\n",			\
			#E, __FILE__, __PRETTY_FUNCTION__, __LINE__);	\
		die();							\
	}								\
} while(0)

static inline void byte_diff(const void *_a, const void *_b, int len) {
	int i;
	int state = 0;
	int runStart = -1;
	const unsigned char *a = _a, *b = _b;
	for(i=0; i < len; i++) {
		if(state == 0) {
			if(a[i] != b[i]) {
				runStart = i;
				state = 1;
			}
		} else if(state == 1) {
			if(a[i] == b[i]) {
				printk("[%d-%d]: ", runStart, i - 1);
				int j;
				for(j=runStart; j < i; j++) {
					printk("%02X,%02X ", a[j], b[j]);
				}
				printk("\n");
				state = 0;
			}
		}
	}
}

static inline int list_integrityCheck(struct alloc_head_list *list) {
	int count = 0;
	struct alloc_head *elem;
	alloc_head_walk(list, elem) {
		ASSERT_OR_RETURN(elem->list == list);
		count++;
	}
	ASSERT_OR_RETURN(count == list->len);
	return 1;
}


#endif // CACHE_UTIL_h
