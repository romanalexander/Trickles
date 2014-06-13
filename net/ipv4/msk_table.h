#ifndef MSK_TABLE_H
#define MSK_TABLE_H

#define MSK_TABLE_SIZE (16)

#include <net/cminisock.h>

struct MSKTableEntry {
	 // pointer to a list of cminisock ; chains through msk_table_link
	struct alloc_head_list link;
};

struct MSKTable {
	unsigned int num_entries;
	// sorted by sequence numbers
	struct alloc_head_list sorted_link;

	struct MSKTableEntry entries[0];
};

#ifndef MSKTABLE_NEW
extern struct MSKTable *(*MSKTable_new)(int numEntries);
#endif // MSKTABLE_NEW

struct MSKTable *MSKTable_new_impl(int numEntries);
struct MSKTable *MSKTable_new_default(int numEntries);

void MSKTable_free(struct MSKTable *table);

void MSKTable_insert(struct MSKTable *table, struct cminisock *msk);

struct cminisock *MSKTable_lookup(struct MSKTable *table, unsigned seq, 
		     int parentID, unsigned parentIDMask);

// clear all msk entries
void MSKTable_clear(struct MSKTable *table);

void MSKTable_clean(struct MSKTable *table, unsigned min_seq);

void cminisock_tableUnlink(struct cminisock *msk);

#endif // MSK_TABLE_H

