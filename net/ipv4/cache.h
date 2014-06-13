#ifdef __KERNEL__
#include <linux/kernel.h>
#include <net/trickles_packet.h>
#else
#include <sys/types.h>
#include "util.h"
#endif // __KERNEL__
// #include "list.h"

// type of comparison function: int fn(key_type *, elem_type *, key_type *, elem_type *)
// type of hash function:
// key_type fn(elem_type *)

#undef likely
#undef unlikely
#define likely(X) (X)
#define unlikely(X) (X)

#define DEBUG_LEVEL (0)
// level above which integrity check is performed after every operation
#define INTEGRITY_LEVEL (2) 
#undef BUG_TRAP
#define BUG_TRAP(X) 

// precondition: the first part of an element is acceptable for determining that fast is present. In the case of Cminisock cache, this is just a pointer to the cminisock, so this assumption is correct
#define INIT_FAST(BUCKET) *(int*)&(BUCKET)->fastCell.elem = 0
#define HAVE_FAST(BUCKET) (*(int*)&(BUCKET)->fastCell.elem != 0)

// N.B. EVICT_HOOK_FN only called on eviction!
#define NEW_CACHE_TYPE(NAME, KEY_TYPE, ELEM_TYPE, MAX_NUM_BUCKETS, MAX_SIZE, \
		       ELEM_TO_KEY_FN, HASH_FN, KEY_COMP_FN, EVICT_HOOK_FN) \
									\
struct NAME##_cell {						\
	KEY_TYPE key;							\
	ELEM_TYPE elem;							\
};									\
									\
struct NAME##_bucket {							\
	struct NAME##_cell fastCell;			\
};					\
									\
struct NAME##_cache_root {						\
	struct NAME##_bucket buckets[MAX_NUM_BUCKETS];			\
	int count; /* current number of elements */	\
									\
	int numBuckets;							\
	int maxCount; /* max number of elements */			\
									\
	int hitCount;							\
	int total;							\
									\
	int cellMem;							\
	int maxCellMem;							\
	int linkCount;							\
	int lookupCount;							\
	void *evictContext;						\
	struct NAME##_cell *cells;					\
} NAME##_cache;								\
									\
static inline int NAME##_isFastCell(struct NAME##_cell *cell) {		\
	struct NAME##_cache_root *cache = &NAME##_cache;		\
	return 	cell >= (struct NAME##_cell*)cache->buckets &&	\
		cell <  (struct NAME##_cell*)(cache->buckets + MAX_NUM_BUCKETS);	\
}									\
									\
static struct NAME##_cell *NAME##_newCell(void);			\
static void NAME##_deleteCell(struct NAME##_cell *cell); /* not the converse of newCell ; the real converse is _freeCell */ \
static int NAME##_integrityCheck(void);				\
static void NAME##_evictOne(struct NAME##_cell **cell);			\
static int NAME##_evict(int toEvict);			\
static void NAME##_cache_init(void) {					\
	struct NAME##_cache_root *cache = &NAME##_cache;		\
									\
	cache->count = 0;						\
	cache->numBuckets = MAX_NUM_BUCKETS;				\
	cache->maxCount = MAX_SIZE;					\
	cache->hitCount = 0;						\
	cache->total = 0;						\
	cache->cellMem = 0;						\
	cache->maxCellMem = 0;						\
	cache->linkCount = 0;						\
	cache->lookupCount = 0;						\
									\
	int i;								\
	for(i=0; i < cache->numBuckets; i++) {				\
		struct NAME##_bucket *bucket = &cache->buckets[i];	\
		INIT_FAST(bucket);					\
	}								\
									\
	HAVE_INTEGRITY_OR_DIE();					\
}									\
									\
static void NAME##_cache_invalidate(void) {				\
	struct NAME##_cache_root *cache = &NAME##_cache;		\
	int i;								\
	for(i=0; i < cache->numBuckets; i++) {				\
		struct NAME##_bucket *bucket = &cache->buckets[i];	\
		if(HAVE_FAST(bucket)) {					\
			EVICT_HOOK_FN(cache->evictContext, &bucket->fastCell.elem); \
			NAME##_deleteCell(&bucket->fastCell);		\
		}							\
	}								\
}									\
static void NAME##_cache_destroy(void) {				\
	NAME##_cache_invalidate();					\
}									\
									\
static int NAME##_getCount(void) {					\
	HAVE_INTEGRITY_OR_DIE();					\
	return NAME##_cache.count;					\
}									\
									\
static int NAME##_integrityCheck(void) {				\
	struct NAME##_cache_root *cache = &NAME##_cache; \
	(cache->hitCount >= 0 && cache->total >= 0 &&			\
	 cache->hitCount <= cache->total) ||				\
		(ERROR("stat integrity") && RETURN(0));			\
	/* walk down all buckets */					\
	int i, lookupCount = 0;						\
									\
	for(i=0; i < cache->numBuckets; i++) {				\
		struct NAME##_bucket *bucket = &cache->buckets[i];	\
		/* fprintf(stderr, "Integrity check on bucket %d/%d\n", i, MAX_NUM_BUCKETS); */ 	\
		if(HAVE_FAST(bucket)) {					\
			struct NAME##_cell *cell = &bucket->fastCell;	\
			VERIFY_HASH();					\
			lookupCount++;					\
		}							\
	}								\
									\
	/* printf("lookup count: %d, count: %d\n", lookupCount, cache->count); */ \
	ASSERT_OR_RETURN(lookupCount == cache->count);			\
	ASSERT_OR_RETURN(cache->count <= cache->maxCount);			\
	return 1;							\
}									\
									\
static void NAME##_resetStats(void) {					\
	struct NAME##_cache_root *cache = &NAME##_cache;		\
	cache->hitCount = 0;						\
	cache->total = 0;						\
}									\
									\
static struct NAME##_cell *NAME##_findInBucket(struct NAME##_bucket *bucket, KEY_TYPE *key) { \
	struct NAME##_cache_root *cache = &NAME##_cache;		\
	cache->lookupCount++;						\
	if(HAVE_FAST(bucket)) {						\
		struct NAME##_cell *cell = &bucket->fastCell;		\
		if(KEY_COMP_FN(key, NULL, &cell->key, &cell->elem)) {	\
			return cell;					\
		}							\
	}								\
	return NULL;							\
} \
									\
static struct NAME##_cell *NAME##_insert_helper(KEY_TYPE *key) { \
	struct NAME##_cache_root *cache = &NAME##_cache;		\
	struct NAME##_bucket *bucket =					\
		&cache->buckets[HASH_FN(key) % cache->numBuckets];	\
									\
	struct NAME##_cell *cell = NULL;					\
	if(!HAVE_FAST(bucket)) {	/* free */			\
		cell = &bucket->fastCell;				\
	} else {							\
		/* evict existing element */				\
		cell = &bucket->fastCell;				\
		EVICT_HOOK_FN(cache->evictContext, &cell->elem);	\
		NAME##_deleteCell(cell);				\
	}								\
	cache->count++;							\
	cell->key = *key;						\
	return cell;							\
}									\
									\
static int NAME##_insert(ELEM_TYPE *elem) {			\
	HAVE_INTEGRITY_OR_DIE();					\
	KEY_TYPE key = ELEM_TO_KEY_FN(elem);				\
	struct NAME##_cell *cell = NAME##_insert_helper(&key);		\
	if(cell == NULL) return 0;					\
	cell->elem = *elem;						\
									\
	/* xxx need to insert into algorithm list as well */		\
	HAVE_INTEGRITY_OR_DIE();					\
	return 1;							\
}									\
									\
static int NAME##_find_helper(KEY_TYPE *key, struct NAME##_cell **hint) { \
	struct NAME##_cache_root *cache = &NAME##_cache;		\
	struct NAME##_bucket *bucket =					\
		&cache->buckets[HASH_FN(key) % cache->numBuckets];	\
	struct NAME##_cell *lookup;						\
	lookup = NAME##_findInBucket(bucket, key);					\
	if(lookup != NULL) {						\
		*hint = lookup;						\
	}								\
	HAVE_INTEGRITY_OR_DIE();					\
	int found = lookup != NULL;					\
	if(found) {							\
		cache->hitCount++;					\
	}								\
	cache->total++;							\
	return found;						\
}									\
									\
static int NAME##_find(KEY_TYPE *key, ELEM_TYPE *result) {	\
	struct NAME##_cell *cell = NULL;				\
	int found = NAME##_find_helper(key, &cell);			\
	if(found) {							\
		*result = cell->elem;					\
	}								\
	HAVE_INTEGRITY_OR_DIE();					\
	return found;							\
}									\
/* N.B. EVICT_HOOK_FN only called on eviction, and not any other operation (including deleteCell! */ \
static void NAME##_freeCell(struct NAME##_cell *cell);			\
static void NAME##_deleteCell(struct NAME##_cell *cell) { \
	/* sort of like evict, but you know which one you want */	\
	NAME##_freeCell(cell);						\
}									\
static int NAME##_delete(KEY_TYPE *key) {			\
	struct NAME##_cell *cell = NULL;				\
	int found = NAME##_find_helper(key, &cell);			\
	if(likely(found)) {						\
		NAME##_deleteCell(cell);				\
	}								\
	HAVE_INTEGRITY_OR_DIE();					\
	return found;							\
}									\
static void NAME##_freeCell(struct NAME##_cell *cell) { \
	/* sort of like evict, but you know which one you want */	\
	struct NAME##_bucket *bucket = ENCLOSING(struct NAME##_bucket, fastCell, cell);	\
	INIT_FAST(bucket);						\
}
