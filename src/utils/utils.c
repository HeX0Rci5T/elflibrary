#include <linux/types.h>
#include <stdio.h>
#include <ctype.h>
#include "../../include/utils.h"

static __u8 *hexdump_char_color(__u8 c) {
	__u8 *clr = CRST;
	if (isprint(c)) {
		clr = BLUE;
	} else if (isspace(c) || !c) {
		clr = RED;
	} else if (c == 0xff) {
		clr = GRN;
	}
	return clr;
}

void _hexdump(void *addr, __u64 sz) {
	__u8 *ptr = addr;

	for (__u64 i = 0; i <= sz; i++) {
		__u8 ch = ptr[i];

		if ( ( !(i % 0x10) && i) || i >= sz) {
			__u8 n = 0x10;

			if (i >= sz) {
				n = !(sz % 0x10) ? 0x10 : (sz % 0x10);
				for (int x = n; x < 0x10; x++) {
					if (!(i % 4)) printf("  ");
					printf("   ");
				}
			}

			printf("\t|\t");

			for (__u8 l = 0; l < n; l++) {
				__u8 c = ptr[ (i-n)+l ];
				__u8 *clr = hexdump_char_color(c);
				printf("%s%c" CRST, clr, isprint(c) ? c : '.');
			}

			puts("");
			if (i >= sz) return;
		}

		if (!i || !(i % 0x10))
			printf(CRST "0x%012x :\t", i);

		if ( !(i % 4) && i && (i % 0x10))
			printf("| ");

		__u8 *clr = hexdump_char_color(ptr[i]);
		printf("%s%02x " CRST, clr, ch);
	}
}
