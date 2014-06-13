#include <stdio.h>
#include <string.h>
#define printk printf
#include "memdump-util.h"

int main() {
	char *input = "About This DocumentTable of Contents1. Overview2. Quick Start3. Settings3.1. Appearance3.2. Actions3.3. Feedback3.4. Access Methods3.5. Prediction4. Screen-by-Screen Description4.1. Back4.2. Compose4.3. Launcher4.4. Activate4.5. Menus4.6. Toolbars4.7. UI Grab";
	int total = strlen(input), half = total / 2;
	int cont = hexdump(input, half);
	hexdump_helper(input + half, total - half, cont);
}
