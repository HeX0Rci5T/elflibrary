// #include <endian.h>
// #include "../../include/elf.hh"

// static __u8 bits(elf_t *elf) {
// 	__u8 b = elf->ptr[EI_CLASS];
// 	if (b == ELFCLASS32)	return 32;
// 	if (b == ELFCLASS64)	return 64;
// 	return 0;
// }

// static __u16 endian(elf_t *elf) {
// 	__u8 b = elf->ptr[EI_DATA];
// 	if (b == ELFDATA2LSB) return LITTLE_ENDIAN;
// 	if (b == ELFDATA2MSB) return BIG_ENDIAN;
// 	return 0;
// }
