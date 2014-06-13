struct linear_bounded_buffer {
	char *start;
	char *curr;
	int limit;
};

static inline
void *lbb_get_end(struct linear_bounded_buffer *lbb) {
	return lbb->start + lbb->limit;
}

static inline
int lbb_get_offset(struct linear_bounded_buffer *lbb) {
	return lbb->curr - lbb->start;
}

static inline
void *lbb_get_pos(struct linear_bounded_buffer *lbb) {
	return lbb->curr;
}

static inline
int lbb_check_reserve(struct linear_bounded_buffer *lbb, int len) {
	return lbb->curr + len - lbb->start <= lbb->limit;
}

static inline
void *lbb_reserve(struct linear_bounded_buffer *lbb, int len) {
	char *rval;
	rval = lbb->curr;

	if(!lbb_check_reserve(lbb,len)) {
		return NULL;
	}
	lbb->curr += len;
	return rval;
}

static inline 
void *lbb_append(struct linear_bounded_buffer *lbb, void *data, int len) {
	char *dest = lbb_reserve(lbb, len);
	if(dest == NULL) return NULL;
	memcpy(dest, data, len);
	return dest;
}
