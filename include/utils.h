// #include <linux/types.h>
// #include <stdio.h>
// #include <string.h>
// #include <stddef.h>
// #include <stdbool.h>
// #include <sys/mman.h>
// #include <ctype.h>

// #define _contains_(a, b, c)		((a) <= (c) && (a)+(b) > (c))

#define BRED	"\e[1;31m"
#define RED		"\e[0;31m"
#define BGRN	"\e[1;32m"
#define GRN		"\e[0;32m"
#define BBLUE	"\e[1;34m"
#define BLUE	"\e[0;34m"
#define YLW		"\e[0;33m"
#define BYLW	"\e[1;33m"
#define CYAN	"\e[0;36m"
#define BCYAN	"\e[1;36m"
#define WHT		"\e[0;37m"
#define BWHT	"\e[1;37m"
#define CRST	"\e[0m"

#define ALIGN(_v_, align)	(((_v_) + ((align)-1)) & ~((align)-1))

// #define color(c, str)	c str CRST

// #define p(s)		puts(s);
// #define pf(s, ...)	printf(s, __VA_ARGS__);
// extern int (*pf)(const char *f, ...);
// extern int (*p)(const char *f);

// // #define _dbg(fmt, ...)	prf("[+]  " fmt"\n", __VA_ARGS__);

// // #define RELF_foreach_modif(t, r, p)		\
// // 		foreach_list((&r->out.list), e)	\
// // 			if ((p=(re_modif *)e->dat) && (p->type == t || !t))

// // #define _assert(b, str)			if (!(b)) _die(str);
// // #define _assertf(b, str, ...)	if (!(b)) {							\
// // 		__u8 *buff	= malloc(snprintf(NULL, 0, str, __VA_ARGS__));	\
// // 		sprintf(buff, str, __VA_ARGS__);							\
// // 		_die(buff);													\
// // 	}

// // #define PR_ERR		BRED "  [-!-]  "CRST
// // #define PR_DBG		BGRN "  [+]    "CRST
// // #define PR_WARN		BYLW "  [WARN] "CRST
// // #define PR_INFO		BBLUE"  [info] "CRST

// // #define prf_x(t, str, ...)			\
// // 		prf(t "@%s:%lu " str "\n", __FUNCTION__, __LINE__, __VA_ARGS__);
#ifdef __cplusplus
extern "C" {
#endif

void _hexdump(void *addr, __u64 sz);

#ifdef __cplusplus	
}
#endif
#define _contain_(a, sz, off)		(a <= off && (a + sz) > off)
// // #define _contains_(a, sz1, b, sz2)	(a <= b && (a + sz1) >= (b + sz2))
#define _crossed_(a, sz1, b, sz2)	(((a) >= (b) && (a) < (b) + (sz2)) || ((b) >= (a) && (b) < (a) + (sz1)))

// // #define foreach(arr, e, type)		\
// // 		for (type *e = &arr[0]; e < &arr[sizeof(arr)/sizeof(type)]; e++)

// // #define _zero(ptr, sz) { memset(ptr, 0, sz); }

// // #define DIE(str)		{ perror(str); exit(-1); }
// // #define FDIE(str, ...)	{ printf(str "\n", __VA_ARGS__); exit(-1); }



// // void *map_anon(__u64 sz);
// // void _hexdump(void *ptr, __u64 sz);
// // __s8 is_string(void *addr);
// // __s8 _qstrcmp(__u8 *a, __u8 *b);

// // __s8 file_exists(__u8 *file);
// // void _memset(__u8 *dst, __u8 ch, __u64 sz);
// // void _die(__u8 *s);
// // void *xmalloc(__u64 sz);

// // __u64 _wr(int fd, __u64 off, __u8 *src, __u64 len);
// // __u64 _wr_mm(int fd, __u64 off, struct mmsz_tup *mm);
// // __u64 _rd(int fd, __u64 off, __u8 *src, __u64 len);


// bool streq(char *a, char *b);
// void *mmap_fd(int fd, size_t size);