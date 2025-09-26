#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#define ELF_INTERNAL_H
#include "../../include/elf.hh"
#undef ELF_INTERNAL_H

#define ELF_MAGIC(ptr) ({										\
		__u8 *b = (__u8*)(ptr);									\
		!!(b[0]=='\x7f' && b[1]=='E' && b[2]=='L' && b[3]=='F');\
	})

__s8 ParseElf::load_elf(elf_t *elf, char *file) {
	struct stat st = {0};

	int fd = open(file, O_RDONLY);
	if (fd == -1) return -1;

	if (stat(file, &st) == -1) {
		close(fd);
		return -1;
	}

	elf->file	= new char[strlen(file)];
	elf->size	= st.st_size;
	elf->map	= mmap(0, elf->size, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);
	strcpy(elf->file, file);
	
	if (elf->map == MAP_FAILED) {
		close(fd);
		return -1;
	}

	close(fd);
	return 0;
}

__s8 ParseElf::init_elf(elf_t *elf, char *file) {
	if (!ELF_MAGIC(elf->map))
		return -1;

	if (!!elf->has_phdr())
		elf->phdr = (Elf_Phdr*)(elf->map + elf->ehdr->e_phoff);

	if (!!elf->has_shdr()) {
		elf->shdr		 = (Elf_Shdr*)(elf->map + elf->ehdr->e_shoff);
		elf->sec.str_sec = &elf->shdr[elf->ehdr->e_shstrndx];
		elf->sec.str	 = (__u8*)(elf->map + elf->sec.str_sec->sh_offset);
	}
	if (set_dynamic(elf) == -1) return -1;
	if (init_gnuver(elf) == -1)	return -1;
	if (init_symtab(elf) == -1)	return -1;
	if (init_reltab(elf) == -1)	return -1;
	if (init_relr(elf) == -1)	return -1;
	
	return 0;
}

static __s8 ParseElf::init_relr(elf_t *elf) {
	foreach_shdr(elf, sec) if (sec->sh_type == SHT_RELR) {
		elf->relrtab.push_back(elf_relr_t{
			.sec = sec,
			.tab = (__u64*)(elf->map + sec->sh_offset),
			.num = sec->sh_size / sizeof(__u64),
		});
	}
	return 0;
}

static __s8 ParseElf::init_gnuver(elf_t *elf) {
	foreach_shdr(elf, sec)
		switch (sec->sh_type) {
			case SHT_GNU_versym:
				elf->gnu.versym.tab = (__u16*)(elf->map+sec->sh_offset);
				elf->gnu.versym.sec = sec;
			break;
			case SHT_GNU_verdef:
				elf->gnu.verdef.tab = (Elf_Verdef*)(elf->map+sec->sh_offset);
				elf->gnu.verdef.sec = sec;
			break;
			case SHT_GNU_verneed:
				elf->gnu.verneed.tab = (Elf_Verneed*)(elf->map+sec->sh_offset);
				elf->gnu.verneed.sec = sec;
			break;
		}
	return 0;
}

static __s8 ParseElf::set_dynamic(elf_t *elf) {
	if (!elf->has_phdr() && !elf->has_shdr())
		return -1;

	if (elf->has_shdr()) {
		foreach_shdr(elf, sec) {
			if (sec->sh_type == SHT_DYNAMIC) {
				elf->dyn.src.off	= sec->sh_offset,
				elf->dyn.src.size	= sec->sh_size;
				elf->dyn.src.sec	= sec;
				elf->dyn.tab		= (Elf_Dyn*)(elf->map + sec->sh_offset);
			}
		}
	} else {
		foreach_phdr(elf, p) if (p->p_type == PT_DYNAMIC) {
				elf->dyn.src.off	= p->p_offset,
				elf->dyn.src.size	= p->p_filesz;
				elf->dyn.src.phdr	= p;
				elf->dyn.tab		= (Elf_Dyn*)(elf->map + p->p_offset);

				if (elf->has_shdr()) {
					foreach_shdr(elf, sec)
						if (	sec->sh_type == SHT_DYNAMIC
							&&	sec->sh_offset == p->p_offset)
						{
							elf->dyn.src.sec = sec; break;
						}
				}
			}
	}
	if (!!elf->dyn.tab) {
		foreach_dynamic(elf, d)
			if (d->d_tag == DT_STRTAB)
				elf->strtab = elf->off<__u8*>(d->d_un.d_ptr);
	}
	return 0;
}

static __s8 ParseElf::init_reltab(elf_t *elf) {
	if (!!elf->has_phdr()) {
		if (!elf->dyn.tab) return -1;

		elf_rela_t plt = {}, rel = { .t = DT_REL }, rela = { .t = DT_RELA };

		foreach_dynamic(elf, e) {
			void *ptr = (elf->map + elf->vtof(e->d_un.d_ptr));
			__u64 v = e->d_un.d_val;

			switch (e->d_tag) {
				case DT_PLTREL:		plt.t		= v;			break;
				case DT_PLTRELSZ:	plt.size	= v;			break;
				case DT_JMPREL:		plt.off=v; plt.ptr=ptr;		break;
				case DT_REL:		rel.off=v; rel.ptr=ptr;		break;
				case DT_RELSZ:		rel.size	= v;			break;
				case DT_RELA:		rela.off=v; rela.ptr=ptr;	break;
				case DT_RELASZ:		rela.size	= v;			break;
			}
		}
		if (!!rel.off)	elf->add_reltab(rel);
		if (!!rela.off)	elf->add_reltab(rela);
		if (!!plt.off)	elf->add_reltab(plt);

	} else if (!elf->has_phdr() && !!elf->has_shdr()) {
		foreach_shdr(elf, sec) {
			elf_rela_t st = {
				.t	= sec->sh_type,
				.sec	= sec,
				.ptr	= elf->map + sec->sh_offset,
			 };
			elf->add_reltab(st);
		}
	} else return -1;

	return 0;
}

static __s8 ParseElf::init_symtab(elf_t *elf) {
	if (!elf->has_shdr()) return -1;

	foreach_shdr(elf, sec) {
		if (sec->sh_type != SHT_DYNSYM && sec->sh_type != SHT_SYMTAB)
			continue;
 
		elf_symtab_t sym = {
			.t		= sec->sh_type,
			.src	= {
				.sec	= sec,
				.off	= sec->sh_offset,
			},
			.tab		= (Elf_Sym*)(elf->map + sec->sh_offset),
			.str		= (__u8*)(elf->map + elf->shdr[sec->sh_link].sh_offset),
			.str_sec	= &elf->shdr[sec->sh_link],
		};

		elf->add_symtab(sym);
	}

	return 0;
}

__u64 elf_t::vtof(__u64 virt) {
	foreach_phdr(this, p) {
		if (_contain_(p->p_vaddr, ALIGN(p->p_memsz, p->p_align), virt))
			return p->p_offset + (virt - p->p_vaddr);
	}
	return -1;
}

__u64 elf_t::ftov(__u64 off) {
	foreach_phdr(this, p) {
		if (_contain_(p->p_offset, p->p_filesz, off))
			return p->p_vaddr + (off - p->p_offset);
	}
	return -1;
}


template<typename R>
__u8 *elf_t::_rel_name(elf_t *elf, elf_rela_t& rtab, R *r) {
	if (!rtab.sec) return nullptr;

	Elf_Shdr *sec	= &shdr[rtab.sec->sh_link];
	Elf_Sym *stab	= off<Elf_Sym*>(sec->sh_offset);
	Elf_Sym *sym	= &stab[ELF64_R_SYM(r->r_info)];

	__u8 *str = off<__u8*>(shdr[sec->sh_link].sh_offset);
	return !sym->st_name ? nullptr : &str[sym->st_name];
}

__u8 *elf_t::rela_name(elf_rela_t& rtab, Elf_Rela *r) { elf_t::_rel_name(this, rtab, r); }
__u8 *elf_t::rel_name(elf_rela_t& rtab, Elf_Rel *r) { elf_t::_rel_name(this, rtab, r); }

void elf_t::add_reltab(elf_rela_t& st) {
	if (!st.sec && !!st.off && has_shdr())
		foreach_shdr(this, s)
			if (s->sh_offset == st.off) {
				st.sec = s;
				break;
			}

	if (!!st.sec)
		st.str = off<__u8*>(shdr[st.sec->sh_link].sh_offset);

	switch (st.t) {
		case SHT_REL:
		case DT_REL: st.t = DT_REL;
			reltab.push_back(st);
			break;

		case SHT_RELA:
		case DT_RELA: st.t = DT_RELA;
			relatab.push_back(st);
			break;
	}
}

void elf_t::add_symtab(elf_symtab_t& sym) {
	symtab.push_back(sym);
}

__u8 Elf::OffPerm(__u64 off) {
	if (this->has_phdr()) return PhdrOffPerm(off);
	if (this->has_shdr()) return ShdrOffPerm(off);

	return 0;
}

__u8 Elf::VirtPerm(__u64 v) {
	return OffPerm(vtof(v));
}

__u8 Elf::PhdrOffPerm(__u64 off) {
	foreach_phdr(this, p) {
		if (_contain_(p->p_offset, p->p_filesz, off))
			return p->p_flags;
	}
	return 0;
}

__u8 ParseElf::ShdrPerms(Elf_Shdr *sec) {
	__u8 f = sec->sh_flags;
	return (PF_R | (!!(f & SHF_WRITE) ? PF_W : 0 | !!(f & SHF_EXECINSTR) ? PF_X : 0));
}

__u8 Elf::ShdrOffPerm(__u64 off) {
	foreach_shdr(this, sec) {
		if (sec->hasOff(off))
			return ParseElf::ShdrPerms(sec);
	}
	return 0;
}


// template<typename F> void Elf::each_rela(F fn) {
// 	for (auto& rtab : relatab)
// 		foreach_rela(&rtab, r) fn(rtab, r);
// }
// template<typename F> void Elf::each_rel(F fn) {
// 	for (auto& rtab : reltab)
// 		foreach_rel(&rtab, r) fn(rtab, r);
// }
// template<typename F> void Elf::each_sym(F fn) {
// 	for (auto& stab : symtab)
// 		foreach_sym(&stab, sym) fn(stab, sym);
// }


bool ElfX_Phdr::hasOff(__u64 off)	{ return _contain_(p_offset, p_filesz, off); }
bool ElfX_Phdr::hasVirt(__u64 virt) { return _contain_(p_vaddr, p_memsz, virt); }
bool ElfX_Phdr::operator<(Elf_Phdr *p) { return (void*)this > (void*)p; }
void ElfX_Phdr::operator++() {
	memcpy(this, &(dynamic_cast<Elf_Phdr *>(this))[1], sizeof(Elf_Phdr));
}
bool ElfX_Phdr::Is(__u8 perm) {
	return p_flags & perm;
}
__u64 ElfX_Phdr::Offset() { return p_offset; }



bool ElfX_Shdr::hasOff(__u64 off)	{ return _contain_(sh_offset, sh_size, off); }
bool ElfX_Shdr::hasVirt(__u64 virt) { return _contain_(sh_addr, sh_size, virt); }
bool ElfX_Shdr::operator<(Elf_Shdr *s) { return (void*)this > (void*)s; }
void ElfX_Shdr::operator++() {
	memcpy(this, &(dynamic_cast<Elf_Shdr *>(this))[1], sizeof(Elf_Shdr));
}
bool ElfX_Shdr::Is(__u8 perm) {
	return ParseElf::ShdrPerms(this) & perm;
}
__u64 ElfX_Shdr::Offset() { return sh_offset; }

ElfX_Phdr *elf_t::vtoph(__u64 virt) {
	foreach_phdr(this, p) if (p->hasVirt(virt)) return p;
	return nullptr;
}

ElfX_Phdr *elf_t::ftoph(__u64 off) {
	foreach_phdr(this, p) if (p->hasOff(off)) return p;
	return nullptr;
}

ElfX_Shdr *elf_t::ftosh(__u64 off) {
	foreach_shdr(this, s) if (s->hasOff(off)) return s;
	return nullptr;
}

ElfX_Shdr *elf_t::vtosh(__u64 virt) {
	foreach_shdr(this, s) if (s->hasVirt(virt)) return s;
	return nullptr;
}


std::string elf_t::sec_name(Elf_Shdr *s) {
	return std::string(reinterpret_cast<const char*>(&sec.str[s->sh_name]));
}

elf_symtab_t *elf_t::dyntab() {
	for (auto& stab : symtab) if (stab.t == SHT_DYNSYM) return &stab;
	return nullptr;
}

bool ParseElf::dyn_is_ptr(Elf_Dyn *dyn) {
	switch (dyn->d_tag) {
		case DT_RUNPATH:
		case DT_SONAME:
		case DT_HASH:
		case DT_STRTAB:
		case DT_SYMTAB:
		case DT_RELA:
		case DT_INIT:
		case DT_FINI:
		case DT_RPATH:
		case DT_PLTGOT:
		case DT_INIT_ARRAY:
		case DT_FINI_ARRAY:
		case DT_REL:
		case DT_JMPREL:
		case DT_VERSYM:
		case DT_VERNEED:
			return true;
	}

	return false;
}
