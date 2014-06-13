#ifndef TRICKLES_DLIST_H
#define TRICKLES_DLIST_H

struct dlist {
	struct list_link *prev;
	struct list_link *next;
};

struct list_link { // link for a particular list
	// order must match alloc head link slots

	struct list_link *prev;
	struct list_link *next;
};

#ifdef __KERNEL__

static void list_link_init(struct list_link *head) {
	head->next = head->prev = NULL;
}

#define dlist_head_walk(queue, elem) \
		for (elem = (typeof(elem))(queue)->next;	\
		     (elem != (typeof(elem))(queue));	\
		     elem=(typeof(elem))elem->next)

static int dlist_integrityCheck(struct dlist *list) {
	const int limit = 4000;
	int count = 0;
	struct list_link *elem;
	dlist_head_walk(list, elem) {
		count++;
		if(count >= limit) {
			printk("dlist limit exceeded\n");
			return 0;
		}
	}
	return 1;
}

static void dlist_init(struct dlist *dlist) {
	dlist->next = dlist->prev = (struct list_link*)dlist;
}

static void dlist_insert_head(struct dlist *head, struct list_link *elem) {
	if(head->next == elem /* || elem->prev != NULL || elem->next != NULL */) {
		BUG();
		show_stack(NULL);	
	}
	elem->next = head->next;
	head->next->prev = elem;

	elem->prev = (struct list_link *)head;
	head->next = elem;
}

static void dlist_insert_tail(struct dlist *head, struct list_link *elem) {
	if(head->prev == elem /* || elem->prev != NULL || elem->next != NULL */) {
		BUG();
		show_stack(NULL);
	}
	elem->next = (struct list_link *)head;
	elem->prev = head->prev;
	head->prev->next = elem;
	head->prev = elem;
}

static void dlist_insert_tail_mb(struct dlist *head, struct list_link *elem) {
	if(head->prev == elem /* || elem->prev != NULL || elem->next != NULL */) {
		BUG();
		show_stack(NULL);
	}
	elem->next = (struct list_link *)head;
	elem->prev = head->prev;
	mb();
	head->prev->next = elem;
	head->prev = elem;
}

static void dlist_unlink(struct list_link *elem) {
	elem->next->prev = elem->prev;
	elem->prev->next = elem->next;
	elem->prev = elem->next = NULL;
}

static inline int dlist_empty(const struct dlist *list) {
	return (struct dlist *)list->next == list;
}

#endif // __KERNEL__

#endif // TRICKLES_DLIST_H
