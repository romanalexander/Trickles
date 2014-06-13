#ifdef TIME_TRICKLES
#include <asm/msr.h>

#define NUM_CLASSES 10
#define NUM_SAMPLES 100

struct TimingClass {
	const char *name;
	int ctr, 
		ctrTrigger, // only prints when ctr == ctrTrigger
		count;
	__u64 in[NUM_SAMPLES];
	__u32 total[NUM_SAMPLES];
};

struct TimingCtx {
	const char *label;
	int numClasses;
	struct TimingClass classes[NUM_CLASSES];
};

static void initTimingCtx(struct TimingCtx *ctx, const char *triggerNames[], const int triggerLevels[], int numClasses) {
	int i;
	ctx->numClasses = numClasses;
	ctx->label = triggerNames[0];
	for(i=0; i < numClasses; i++) {
		ctx->classes[i].name = triggerNames[i+1]; 
		ctx->classes[i].ctr = 0;
		ctx->classes[i].ctrTrigger = triggerLevels[i];
		ctx->classes[i].count = 0;
		memset(ctx->classes[i].in, 0, 
		       sizeof(ctx->classes[i].in));
		memset(ctx->classes[i].total, 0, 
		       sizeof(ctx->classes[i].total));
	}
}

static void reinitTimingCtx(struct TimingCtx *ctx) {
	int i;
	for(i=0; i < ctx->numClasses; i++) {
		ctx->classes[i].ctr = 0;
	}
}

#define TIMING_CTX_DEF0(...)			\
	const char *classNames[] = {__VA_ARGS__};

#define TIMING_CTX_DEF1(...)							\
	static struct TimingCtx ctx;						\
	static int initialized = 0;						\
	const int classTriggers[] = {__VA_ARGS__};				\
	if(!initialized) {							\
		initTimingCtx(&ctx, classNames, classTriggers, 			\
			      sizeof(classTriggers)/sizeof(classTriggers[0]));	\
		BUG_TRAP(sizeof(classTriggers) / sizeof(classTriggers[0]) ==	\
			 sizeof(classNames) / sizeof(classNames[0]) - 1);	\
		initialized = 1;						\
	}									\
	reinitTimingCtx(&ctx)

static inline void recordSample(struct TimingCtx *ctx, int class) {
	__u32 low, high;
	rdtsc(low,high);
	ctx->classes[class].in[ctx->classes[class].ctr++] = low | (high << 32);
}

static inline void printTimings(struct TimingCtx *ctx) {
	int i, j, display = 0, first = 1;
	for(i=0; i < ctx->numClasses; i++) {
		struct TimingClass *class = &ctx->classes[i];
		if(class->ctr == class->ctrTrigger) {
			// if(class->count % 10000 == 9999) {
			if(class->count % 5000 == 4999) {
				display = 1;
			}
			for(j=1; j < class->ctr; j++) {
				class->total[j] += class->in[j] - class->in[j-1];
			}
			class->count++;
			if(display) {
				if(first) {
					printk("Average %s ", ctx->label);
					first = 0;
				}
				printk("%s: ", class->name);
				for(j=1; j < class->ctr; j++) {
					printk("%d ", class->total[j]/class->count);
					class->total[j] = 0;
				}
				class->count = 0;
			}
		}
	}
	if(display) printk("\n");
}

#else
#undef rdtscl
#define rdtscl(X)

#define TIMING_CTX_DEF0(...)
#define TIMING_CTX_DEF1(...)
#define recordSample(X,Y)
#define reinitTimingCtx(X)
#define printTimings(X)

#endif
