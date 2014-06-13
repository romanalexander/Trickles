static int mwc_carry = 9969;
static int mwc_x = 3939;
const static int A = 2051013963;
#define MWC_MODULUS_SHIFT (16)
#define MWC_MODULUS (1 << MWC_MODULUS_SHIFT)

inline void mwc_srand(int seed) {
	mwc_x = seed;
}

inline int mwc_rand(void) {
	/* Multiply - with - carry generator */
	int res0 = (A * mwc_x + mwc_carry);
	mwc_carry = res0 >> MWC_MODULUS_SHIFT;
	return mwc_x = res0 & (MWC_MODULUS - 1);
}
