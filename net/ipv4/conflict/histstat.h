#ifndef HISTSTAT_H
#define HISTSTAT_H

// Record and plot a histogram

struct histogram {
	char name[64];

	int numBins;
	int minVal;
	int maxVal;
	int *bins;
};

static inline void hist_init(struct histogram *hist, char *name, int numBins, int minVal, int maxVal) {
	strcpy(hist->name, name);
	hist->numBins = numBins;
	hist->minVal = minVal;
	hist->maxVal = maxVal;
	// reserve slots for overflow and underflow
	int alloc_size = (numBins + 2) * sizeof(int);
	hist->bins = kmalloc(alloc_size, GFP_ATOMIC);
	memset(hist->bins, 0, alloc_size);
}

static inline void hist_destroy(struct histogram *hist) {
	kfree(hist->bins);
}

static inline void hist_addPoint(struct histogram *hist, int value) {
	int normalizedPosition = 
		(value - hist->minVal) * hist->numBins /
		(hist->maxVal - hist->minVal);
	int index = -1;
	if(normalizedPosition < 0) {
		// set to underflow
		index = 0;
	} else if(normalizedPosition >= hist->numBins) {
		// set to overflow
		index = hist->numBins + 1;
	} else {
		// skip past underflow position
		index = 1 + normalizedPosition;
	}
	hist->bins[index]++;
}

static inline void hist_dump(struct histogram *hist) {
	int i;
	printk("Histogram %s\n", hist->name);
	printk("[Underflow] = %d\n", hist->bins[0]);
#define INVERT_VALUE(I) (I) * (hist->maxVal - hist->minVal) / \
		hist->numBins + hist->minVal
	for(i=0; i < hist->numBins; i++) {
		int binStart = INVERT_VALUE(i), 
			binEnd = INVERT_VALUE(i+1) - 1;
		printk("[%d-%d] = %d\n", binStart, binEnd, hist->bins[i+1]);
	}
	printk("[Overflow] = %d\n", hist->bins[hist->numBins+1]);
#undef INVERT_VALUE
}

#endif // HISTSTAT_H
