#include <stdio.h>
#include <x86disass/disass.hpp>
#include <elflib/elf.hpp>

#define SYE_HEADER 	"\e[1;30m-<[\e[1;40m " BCYAN "SlitYerELF \e[0m\e[1;30m]>-" CRST

auto is_str = [](char *ptr) {
	for (char *c = ptr; ;c++) {
		if (c != (char*)ptr && !*c)
			break;

		if (!isprint(*c)) return false;
	}

	return true;
};


__u8 *sym_name(Elf& elf, Elf_Sym *sym) {
	for (auto& stab : elf.symtab)
		foreach_sym(&stab, s)
			if (sym == s)
				return &stab.str[sym->st_name];

	return (__u8*)"---";
}
Elf_Sym *closest_sym(Elf& elf, __u64 min_off=0) {
	Elf_Sym *pick = NULL;
	for (auto& stab : elf.symtab) {
		foreach_sym(&stab, sym) {
			if (!(sym->st_info & STT_FUNC)) continue;

			if (min_off < elf.vtof(sym->st_value) && (!pick || pick->st_value > sym->st_value))
				pick = sym;
		}
	}
	return pick;	
}


// elf.vtof(sym->st_value) - sec->sh_filesz
void disasm(Disass &d, Elf& elf, __u8 *pfx, __u64 off, __u64 size) {
	void *ptr = elf.off<void*>(off);

	d.iter(ptr, size, [&](__u64 i, insn_t& in) {
		// if (in.IsNull() || !in.IsPtr() || in.PtrAddr() == -1)
		// 	return;	// next

		__u64 virt	= in.PtrAddr(elf.ftov(off + i));
		__u64 off	= elf.vtof(virt);

		printf("    [" BBLUE"%s + %u"CRST "] - %s to virt [" BGRN"0x%lx"CRST "] / off [" BGRN"0x%lx"CRST "]\n",
			pfx, i, (!in.Mnemo()) ? "??" : in.Mnemo(), virt, off);

		char *dst = (char*)(elf.map + off);
		if (off != -1 && is_str(dst)) {
			printf("        ");
			__u64 len = strlen(dst);
			_hexdump((char*)dst, len > 0x10 ? 0x10 : len);
			puts("");
		}
	});
}
int main(int argc, char *argv[]) {
	std::printf("%s\n", SYE_HEADER);
	Elf elf = Elf("/usr/bin/ls");
	foreach_phdr(&elf, p) {
		std::printf("0x%-10lx - 0x%-10lx %s%s%s\n",
			p->p_offset, p->p_filesz,
			(p->p_flags & PF_R ? "R" : "-"),
			(p->p_flags & PF_W ? BBLUE"W"CRST : "-"),
			(p->p_flags & PF_X ? BRED"X"CRST : "-"));
	}
	
	auto d = Disass();
	foreach_shdr(&elf, sec) {
		void *ptr = elf.off<void*>(sec->sh_offset);

		if (sec->sh_flags & SHF_EXECINSTR) {
			printf(BGRN"%-10s"CRST "~~~.~.~+~.~.~~>\n", &elf.sec.str[sec->sh_name]);

			Elf_Sym *sym = NULL;
			while (		!!(sym = closest_sym(elf, (!sym) ? sec->sh_offset : elf.vtof(sym->st_value)))
					&&	_contain_(sec->sh_offset, sec->sh_size, elf.vtof(sym->st_value)))
			{
				disasm(d, elf, sym_name(elf, sym), elf.vtof(sym->st_value), sym->st_size);
			}

			printf("\n");
		}
	}

	return 0;
}
