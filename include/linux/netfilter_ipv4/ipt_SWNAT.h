#ifndef _IPT_SWNAT_H_target
#define _IPT_SWNAT_H_target


// Type of SWNAT to perform
enum SWNAT_Algorithm {
	// SERVER0 is used in the OUTPUT chain. It saves the
	// original destination in the mark field

	// SERVER1 is used in the POSTROUTING chain. It sets the source
	// to the mark field (e.g., the original destination)

	// Similarly for NATBOX0 and NATBOX1
	
	// Note that SERVER0 is not currently used
	SWNAT_SERVER0,// Swap destination into source, set NAT box as
	SWNAT_SERVER1,// destination
        SWNAT_NATBOX0,  // NAT-box side algorithm
        SWNAT_NATBOX1  // NAT-box side algorithm
};

struct ipt_swnat_target_info {
	enum SWNAT_Algorithm algorithm;
	unsigned long nat_addr; // the address of the NAT box
};

#endif /*_IPT_MARK_H_target*/
