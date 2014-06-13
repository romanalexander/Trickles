#ifdef __KERNEL__

#include "trickles-int.h"
#include <net/trickles_packet_helpers.h>
#include <net/cminisock.h>

#include "cache_util.h" // for hash
#include "msk_table.h"

#else

#include <stdio.h>

#include <stdlib.h>
#include <assert.h>

#define BUG() assert(0)
#define BUG_TRAP(X) assert(X)

#include "msk_table.h"
#include "cminisock.h"

int gMallocCount = 0;
int gFreeCount = 0;

#define kmalloc(X,Y) ({ gMallocCount++; malloc(X); })
#define kfree(X) ({ gFreeCount++; free(X); })
#define freeClientSide_Continuation(X) kfree(X)

#define printk(X,...) fprintf(stderr, X ,##__VA_ARGS__)

#define PARANOID

int nextParentID = 0;

#endif


// #define PRINT_MSK_TABLE_INSERTION

struct MSKTable *MSKTable_new_impl(int numEntries) {
	int i;
	struct MSKTable *table = 
		kmalloc(sizeof(struct MSKTable) + 
			numEntries * sizeof(struct MSKTableEntry), GFP_ATOMIC);
	table->num_entries = numEntries;
	init_head(&table->sorted_link);
	for(i=0; i < table->num_entries; i++) {
		init_head(&table->entries[i].link);
	}
	return table;
}

void MSKTable_clear(struct MSKTable *table) {
	int count = 0;
	struct alloc_head *sorted_link, *next;
	for(sorted_link = table->sorted_link.next;
	    sorted_link != (struct alloc_head*)&table->sorted_link;
	    sorted_link = next) {
		next = sorted_link->next;
		struct cminisock *msk = MSK_SORTED_OWNER(sorted_link);
		cminisock_tableUnlink(msk);
		freeClientSide_Continuation(msk);
		count++;
	}
}

void MSKTable_free(struct MSKTable *table) {
	MSKTable_clear(table);
	kfree(table);
}

static int cminisock_hash_seq(unsigned seq) {
	return hash((u1*)&seq,sizeof(seq),0);
}

static int cminisock_hash(struct cminisock *msk) {
	return cminisock_hash_seq(msk->seq);
}

// precondition: msk is a kmalloc()'ed object that we now own
// postcondition: preceding entries with matching seq are removed

void MSKTable_insert(struct MSKTable *table, struct cminisock *msk) {
	// Careful! This function is a bit delicate. There are 2
	// different kinds of links being thrown around

	int entry = cminisock_hash(msk) % table->num_entries;

	init_link(&msk->hash_link);
	init_link(&msk->sorted_link);

	struct alloc_head_list *entry_list = &table->entries[entry].link;
	struct alloc_head *hash_link, *sorted_link, *next;

	for(hash_link = entry_list->next; 
	    hash_link != (struct alloc_head*)entry_list; 
	    hash_link = next) {
		next = hash_link->next;
		struct cminisock *c_msk = MSK_HASH_OWNER(hash_link);
		if(c_msk->seq == msk->seq) {
			// found an older match
			// printk("found match in insert, removing\n");
			unlink(hash_link);
			unlink(&c_msk->sorted_link);
			freeClientSide_Continuation(c_msk);
		}
	}
	insert_tail(entry_list, &msk->hash_link);

	// sorted insertion
	if(table->sorted_link.len == 0) {
		insert_head(&table->sorted_link, &msk->sorted_link);
	} else {
		int inserted = 0;
		if(msk->seq < MSK_SORTED_OWNER(table->sorted_link.next)->seq) {
			insert_head(&table->sorted_link, &msk->sorted_link);
			inserted = 1;
		} else {
			for(sorted_link = (struct alloc_head*)table->sorted_link.next;
			    sorted_link != (struct alloc_head*)&table->sorted_link;
			    sorted_link = next) {
				next = sorted_link->next;
				struct cminisock *c_msk = 
					MSK_SORTED_OWNER(sorted_link);

				// ruled out by prepocessing from above
				BUG_TRAP(c_msk->seq != msk->seq);

				if(c_msk->seq < msk->seq &&
				   ( /* tail */
				    next == (struct alloc_head*)&table->sorted_link
				    || msk->seq < MSK_SORTED_OWNER(next)->seq)) {
					insert(&msk->sorted_link, sorted_link, next);
					inserted = 1;
					break;
				}
			}
		}
		BUG_TRAP(inserted);
	}

#ifdef PRINT_MSK_TABLE_INSERTION
	static struct WireContinuation wcont;
	static struct sock dummySK;

	marshallContinuationClient(&dummySK, &wcont, msk, -1);
	WireContinuation_print(&wcont);
#endif // PRINT_MSK_TABLE_INSERTION
}

// Finds matching entry for seq and parentID
struct cminisock *MSKTable_lookup(struct MSKTable *table, unsigned seq, 
		     int parentID, unsigned parentIDMask) {
	int entry = cminisock_hash_seq(seq) % table->num_entries;
	struct alloc_head_list *entry_list = &table->entries[entry].link;
	struct alloc_head *hash_link;
	struct cminisock *rval = NULL;
	
	alloc_head_walk(entry_list, hash_link) {
		struct cminisock *msk = MSK_HASH_OWNER(hash_link);
		if(msk->seq == seq && 
		  (msk->localParentID & parentIDMask) == (parentID & parentIDMask)) {
			rval = msk;
			break;
		}
	}
#if 0
	if(rval == NULL) {
		printk("Could not find %d %d 0x%X\n", seq, parentID, parentIDMask);
	}
#endif

	return rval;
}

void cminisock_tableUnlink(struct cminisock *msk) {
	unlink(&msk->hash_link);
	unlink(&msk->sorted_link);
}

void cminisock_print(struct cminisock *msk) {
	printk("seq = %d, id = %d\n", msk->seq, msk->localParentID);
}

// Remove all entries prior to min_seq
void MSKTable_clean(struct MSKTable *table, unsigned min_seq) {
	struct alloc_head *sorted_link, *next;

	int cleanCount = 0;
#ifdef PARANOID
	int prevSeq = 0;
#endif
	for(sorted_link = table->sorted_link.next; 
	    sorted_link != (struct alloc_head*)&table->sorted_link;
	    sorted_link = next) {
		next = sorted_link->next;

		struct cminisock *msk = MSK_SORTED_OWNER(sorted_link);
#ifdef PARANOID
		BUG_TRAP(prevSeq <= msk->seq);
		prevSeq = msk->seq;
#endif
		cleanCount++;
		if(msk->seq >= min_seq) {
			break;
		}
		unlink(&msk->hash_link);
		unlink(&msk->sorted_link);
		freeClientSide_Continuation(msk);
	}
	// printk("Cleaned %d\n", cleanCount);
}

int MSKTable_count(struct MSKTable *table) {
	return table->sorted_link.len;
}

void MSKTable_print(struct MSKTable *table) {
	int i;
	for(i = 0; i < table->num_entries; i++) {
		struct MSKTableEntry *ent = &table->entries[i];
		struct alloc_head *hash_link;
		if(ent->link.len > 0) {
			printk("Bucket %d [len = %d]:\n", i, ent->link.len);
			alloc_head_walk(&ent->link, hash_link) {
				struct cminisock *msk = MSK_HASH_OWNER(hash_link);
				printk("\t"); cminisock_print(msk);
			}
		}
	}
	struct alloc_head *sorted_link;
	printk("Sorted list [len = %d]:\n", table->sorted_link.len);
	alloc_head_walk(&table->sorted_link, sorted_link) {
		struct cminisock *msk = MSK_SORTED_OWNER(sorted_link);
		printk("\t"); cminisock_print(msk);
	}
}

int MSKTable_sanityCheck(struct MSKTable *table) {
	// 1. 	scan through all the buckets and verify that the entries in the
	//	bucket has the right hash
	// 2. 	Verify that the count of elements in the buckets matches the sorted list
	// 3.	Verify ordering in sorted list
	int i;
	int hashCount = 0;
	int isSane = 1;
	for(i = 0; i < table->num_entries; i++) {
		struct MSKTableEntry *ent = &table->entries[i];
		struct alloc_head *hash_link;
		alloc_head_walk(&ent->link, hash_link) {
			struct cminisock *msk = MSK_HASH_OWNER(hash_link);
			if((cminisock_hash(msk) % table->num_entries) != i) {
				printk("Hash did not match entry sequence number\n");
				isSane = 0;
			}
			hashCount++;
		}
	}
	struct alloc_head *sorted_link;
	int lastSeq = -1;
	int listCount = 0;
	alloc_head_walk(&table->sorted_link, sorted_link) {
		struct cminisock *msk = MSK_SORTED_OWNER(sorted_link);
		if(lastSeq >= (int)msk->seq) {
			printk("sorted list out of order\n");
			isSane = 0;
		}
		lastSeq = msk->seq;
		listCount++;
	}
	isSane = isSane && (listCount == hashCount);
	BUG_TRAP(listCount == hashCount);
	isSane = isSane && (listCount == table->sorted_link.len);
	BUG_TRAP(listCount == table->sorted_link.len);
	return isSane;
}

#ifndef __KERNEL__

/* self test code */

static inline
struct cminisock *cminisock_new(unsigned seq, int localParentID) {
	struct cminisock *msk = kmalloc(sizeof(struct cminisock), 0);
	msk->seq = seq;
	msk->localParentID = localParentID;
	init_link(&msk->hash_link);
	init_link(&msk->sorted_link);
	return msk;
}

enum VerificationType {
	INSERTION,
	DELETION
};

int gErrorCount = 0;
void failHelper(int line, char *X, int i, int j) {
	gErrorCount++;
	printk("Failed @ %d (%d,%d): %s\n", line, i,j,X);
}

void kmalloc_check(int line) {
	printk("Allocated %d, deallocated %d\n", gFreeCount, gMallocCount);

	if(gFreeCount != gMallocCount) {
		failHelper(line, "Malloc and free count did not match", -1, -1);
	}
}

#define FAIL(X) do { failHelper(__LINE__,X,i,j); } while(0)

 static int checkResultLogic(int resultFlag, int result, int i, int j) {
	switch(resultFlag) {
	case 0:
		if(result) {
			FAIL("found when not inserted");
			return 0;
		}
		break;
	case 1:
		if(!result) {
			FAIL("not found when inserted");
			return 0;
		}
		break;
	default:
		BUG_TRAP(0);
	}
	return 1;
}

struct LookupSpec {
	int seq;
	int parentID;
	int mask;
	int result;
	int insertionPoint; // if outer loop is >= this value, then the result must match (if == 1)
	int deletionPoint; // similarly for deletion
};

static int checkLookups(struct MSKTable *table, int i, // the spec
			enum VerificationType type,
			struct LookupSpec *lookupSpec,
			int lookupSpecCount) {
	int j;
	int result = 1;
	for(j = 0; j < lookupSpecCount; j++) {
		struct LookupSpec *lspec = &lookupSpec[j];
		struct cminisock *val = 
			MSKTable_lookup(table, lspec->seq, lspec->parentID, lspec->mask);
		switch(type) {
		case INSERTION:
			if(i < lspec->insertionPoint) {
				if(!(val == NULL)) {
					FAIL("found before inserted");
					result = 0;
				}
			} else {
				checkResultLogic(lspec->result, val != NULL, i, j);
			}
			break;
		case DELETION:
			if(i < lspec->deletionPoint) {
				checkResultLogic(lspec->result, val != NULL, i, j);
			} else {
				if(!(val == NULL)) {
					FAIL("found after deletion");
					result = 0;
				}
			}
			break;
		}
	}
	return result;
}
struct InsertSpec {
	int seq;
	int localParentID;
} ;

void insertFromSpec(struct MSKTable *table, 
		    struct InsertSpec *insertSpec,  int insertSpecCount, 
		    struct LookupSpec *lookupSpec, int lookupSpecCount,
		    int shouldPrint,
		    struct cminisock **insertions, int *insertionCount) {
	int i;
	for(i=0; i < insertSpecCount; i++) {
		struct cminisock *msk = 
			cminisock_new(insertSpec[i].seq,
				      insertSpec[i].localParentID);
		MSKTable_insert(table, msk);
		MSKTable_sanityCheck(table);
		printk("Inserted %d\n", i);
		if(shouldPrint) {
			MSKTable_print(table);
		}
		// XXX test duplicated insertion

		insertions[(*insertionCount)++] = msk;
		checkLookups(table, i, INSERTION, lookupSpec,
			     lookupSpecCount);
	}
}

int main(int argc, char **argv) {
	int testSizes[] = { 1, 10 };
	int testSize;

	struct InsertSpec insertSpec[] = { 
		{ 1, 0x05 },
		{ 2, 0x0a },
		{ 3, 0x55 },
		{ 4, 0x75 },
		{ 5, 0x1005 },
		{ 6, 0x100a },
		{ 7, 0x1055 },
		{ 8, 0x1075 }
	}; /* reorder ?? */

	struct LookupSpec lookupSpec[] = {
		{ 5, 0x05, 0xff, 1, 4, 4 },
		{ 5, 0x04, 0xff, 0, 0, 0 },
		{ 5, 0x04, 0x00, 1, 4, 4 },

		{ 8, 0x75, 0xff, 1, 7, 7 },
		{ 8, 0x74, 0xff, 0, 7, 7 },
		{ 8, 0x1075, 0xffff, 1, 7, 7 },
		{ 1, 0x05, 0xff, 1, 0, 0 },
	};

	struct InsertSpec reorderedInsertSpec[] = { 
		{ 2, 0x0a },
		{ 4, 0x75 },
		{ 3, 0x55 },
		{ 1, 0x05 },
	};

	struct LookupSpec reorderedLookupSpec[] = {
		{ 1, 0x05, 0xff, 1, 3, 3 },
		{ 2, 0x0a, 0xff, 1, 0, 0 },
		{ 3, 0x55, 0xff, 1, 2, 2 },
		{ 4, 0x75, 0xff, 1, 1, 1 },
	};

	struct InsertSpec duplicatedInsertSpec[] = { 
		{ 1, 0x05 + 0x10 }, /* " prime" versions" */
		{ 2, 0x0a + 0x10 },
		{ 3, 0x55 + 0x10 },
		{ 4, 0x75 + 0x10 },

		{ 1, 0x05 },
		{ 2, 0x0a },
		{ 3, 0x55 },
		{ 4, 0x75 },
	};

	struct LookupSpec duplicatedLookupSpec[] = {
		{ 1, 0x15, 0xff, 1, 0, 0 },
		{ 2, 0x1a, 0xff, 1, 1, 1 },
		{ 3, 0x65, 0xff, 1, 2, 2 },
		{ 4, 0x85, 0xff, 1, 3, 3 },

		{ 1, 0x05, 0xff, 1, 4, 4 },
		{ 2, 0x0a, 0xff, 1, 5, 5 },
		{ 3, 0x55, 0xff, 1, 6, 6 },
		{ 4, 0x75, 0xff, 1, 7, 7 },
	};

	struct Spec {
		char *name;
		struct InsertSpec *insertSpec ;
		int insertSpecCount;
		struct LookupSpec *lookupSpec;
		int lookupSpecCount;
		int doDeleteTest;
		int doCleanTest;
	} topSpecs[] = {
		{ "linear insertion", insertSpec, 8, lookupSpec, 7, 1, 1 },
		{ "reordered insertion", reorderedInsertSpec, 4, reorderedLookupSpec, 4, 1, 1 },
		{ "duplicated", duplicatedInsertSpec, 8, duplicatedLookupSpec, 4, 0, 0 }
	};
	int numSpecs = 3;
#define MAX_NUM_INSERTIONS (1000)
#define PRINT_INSERTION_DELETION (0)
	int m;
	for(m = 0; m < sizeof(testSizes) / sizeof(testSizes[0]); m++) {
		testSize = testSizes[m];
		int n;
		int i;
		// increasing
		printk("Insertion test on test size = %d\n", testSize);

		for(n = 0; n < numSpecs; n++) {
			struct MSKTable *table = MSKTable_new(testSize);
			int insertionCount = 0;
			struct cminisock *insertions[MAX_NUM_INSERTIONS];

			struct Spec *spec = &topSpecs[n];
			struct LookupSpec *lookupSpec = spec->lookupSpec;
			int lookupSpecCount = spec->lookupSpecCount;
			struct InsertSpec *insertSpec = spec->insertSpec;
			int insertSpecCount = spec->insertSpecCount;
			printk("========\nTest: %s\n========\n", spec->name);
	
			insertFromSpec(table, insertSpec, insertSpecCount, 
				       lookupSpec, lookupSpecCount,
				       PRINT_INSERTION_DELETION, 
				       insertions, &insertionCount);
			if(spec->doDeleteTest) {
				printk("Deletion test\n");
				for(i=0; i < insertionCount; i++) {
					int oldCount;
					int j = 0;
					struct cminisock *msk = insertions[i];
					oldCount = MSKTable_count(table);
					cminisock_tableUnlink(msk);
					MSKTable_sanityCheck(table);
					printk("Deleted %d\n", i);
					MSKTable_print(table);
					if(MSKTable_count(table) != oldCount - 1) {
						FAIL("Deletion did not decrease count");
					}
					checkLookups(table, i, DELETION, lookupSpec,
						     lookupSpecCount);
				}
			}
			MSKTable_free(table);

			if(spec->doCleanTest) {
				printk("Clean test\n=========\n");

				int p;
				for(p=1; p < insertSpecCount+2; p++) {
					printk("Cleaning starting from %d\n", p);
					table = MSKTable_new(testSize);
					insertionCount = 0;
					insertFromSpec(table, insertSpec, insertSpecCount, 
						       lookupSpec, lookupSpecCount,
						       0,
						       insertions, &insertionCount);
					int preCount = MSKTable_count(table),
						target = preCount - p + 1;
					MSKTable_clean(table, p);
					int postCount = MSKTable_count(table);
					if(postCount != target) {
						failHelper(__LINE__, "Cleaning count mismatch", n,p);
						printk("Was %d, should be %d\n", postCount, target);
					}
					MSKTable_free(table);
				}
			}
			kmalloc_check(__LINE__);
		}
	}
	printk("%d errors\n", gErrorCount);

	kmalloc_check(__LINE__);
	return 0;
}

#endif // __KERNEL__

