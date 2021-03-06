





















typedef __builtin_va_list __gnuc_va_list;

typedef __gnuc_va_list va_list;









typedef struct
{
  unsigned long fds_bits[(1024 / (8 * sizeof (unsigned long)))];
} __kernel_fd_set;


typedef void (*__kernel_sighandler_t) (int);


typedef int __kernel_key_t;



typedef unsigned short __kernel_dev_t;
typedef unsigned long __kernel_ino_t;
typedef unsigned short __kernel_mode_t;
typedef unsigned short __kernel_nlink_t;
typedef long __kernel_off_t;
typedef int __kernel_pid_t;
typedef unsigned short __kernel_ipc_pid_t;
typedef unsigned short __kernel_uid_t;
typedef unsigned short __kernel_gid_t;
typedef unsigned int __kernel_size_t;
typedef int __kernel_ssize_t;
typedef int __kernel_ptrdiff_t;
typedef long __kernel_time_t;
typedef long __kernel_suseconds_t;
typedef long __kernel_clock_t;
typedef int __kernel_daddr_t;
typedef char *__kernel_caddr_t;
typedef unsigned short __kernel_uid16_t;
typedef unsigned short __kernel_gid16_t;
typedef unsigned int __kernel_uid32_t;
typedef unsigned int __kernel_gid32_t;

typedef unsigned short __kernel_old_uid_t;
typedef unsigned short __kernel_old_gid_t;


typedef long long __kernel_loff_t;


typedef struct
{

  int val[2];



} __kernel_fsid_t;






typedef unsigned short umode_t;






typedef __signed__ char __s8;
typedef unsigned char __u8;

typedef __signed__ short __s16;
typedef unsigned short __u16;

typedef __signed__ int __s32;
typedef unsigned int __u32;


typedef __signed__ long long __s64;
typedef unsigned long long __u64;

typedef signed char s8;
typedef unsigned char u8;

typedef signed short s16;
typedef unsigned short u16;

typedef signed int s32;
typedef unsigned int u32;

typedef signed long long s64;
typedef unsigned long long u64;

typedef u32 dma_addr_t;

typedef u64 dma64_addr_t;




typedef __kernel_fd_set fd_set;
typedef __kernel_dev_t dev_t;
typedef __kernel_ino_t ino_t;
typedef __kernel_mode_t mode_t;
typedef __kernel_nlink_t nlink_t;
typedef __kernel_off_t off_t;
typedef __kernel_pid_t pid_t;
typedef __kernel_daddr_t daddr_t;
typedef __kernel_key_t key_t;
typedef __kernel_suseconds_t suseconds_t;


typedef __kernel_uid32_t uid_t;
typedef __kernel_gid32_t gid_t;
typedef __kernel_uid16_t uid16_t;
typedef __kernel_gid16_t gid16_t;



typedef __kernel_old_uid_t old_uid_t;
typedef __kernel_old_gid_t old_gid_t;

typedef __kernel_loff_t loff_t;

typedef __kernel_size_t size_t;




typedef __kernel_ssize_t ssize_t;




typedef __kernel_ptrdiff_t ptrdiff_t;




typedef __kernel_time_t time_t;




typedef __kernel_clock_t clock_t;




typedef __kernel_caddr_t caddr_t;



typedef unsigned char u_char;
typedef unsigned short u_short;
typedef unsigned int u_int;
typedef unsigned long u_long;


typedef unsigned char unchar;
typedef unsigned short ushort;
typedef unsigned int uint;
typedef unsigned long ulong;




typedef __u8 u_int8_t;
typedef __s8 int8_t;
typedef __u16 u_int16_t;
typedef __s16 int16_t;
typedef __u32 u_int32_t;
typedef __s32 int32_t;



typedef __u8 uint8_t;
typedef __u16 uint16_t;
typedef __u32 uint32_t;


typedef __u64 uint64_t;
typedef __u64 u_int64_t;
typedef __s64 int64_t;

struct ustat
{
  __kernel_daddr_t f_tfree;
  __kernel_ino_t f_tinode;
  char f_fname[6];
  char f_fpack[6];
};





static __inline__ __const__ __u32
___arch__swab32 (__u32 x)
{

__asm__ ("bswap %0": "=r" (x):"0" (x));







  return x;
}



static __inline__ __const__ __u16
___arch__swab16 (__u16 x)
{
__asm__ ("xchgb %b0,%h0": "=q" (x):"0" (x));
  return x;
}


static inline __u64
___arch__swab64 (__u64 val)
{
  union
  {
    struct
    {
      __u32 a, b;
    } s;
    __u64 u;
  } v;
  v.u = val;

asm ("bswapl %0 ; bswapl %1 ; xchgl %0,%1": "=r" (v.s.a), "=r" (v.s.b):"0" (v.s.a),
       "1" (v.s.
	    b));





  return v.u;
}






static __inline__ __const__ __u16
__fswab16 (__u16 x)
{
  return ___arch__swab16 (x);
}
static __inline__ __u16
__swab16p (__u16 * x)
{
  return ___arch__swab16 (*(x));
}
static __inline__ void
__swab16s (__u16 * addr)
{
  do
    {
      *(addr) = ___arch__swab16 (*((addr)));
    }
  while (0);
}

static __inline__ __const__ __u32
__fswab24 (__u32 x)
{
  return (
	   {
	   __u32 __tmp = (x);
	   (
	     {
	     __u32 __x = (__tmp);
	     ((__u32)
	      (((__x & (__u32) 0x000000ffUL) << 16) |
	       (__x & (__u32) 0x0000ff00UL) | ((__x & (__u32) 0x00ff0000UL) >>
					       16)));
	     }
	   );
	   }
  );
}
static __inline__ __u32
__swab24p (__u32 * x)
{
  return (
	   {
	   __u32 __tmp = (*(x));
	   (
	     {
	     __u32 __x = (__tmp);
	     ((__u32)
	      (((__x & (__u32) 0x000000ffUL) << 16) |
	       (__x & (__u32) 0x0000ff00UL) | ((__x & (__u32) 0x00ff0000UL) >>
					       16)));
	     }
	   );
	   }
  );
}
static __inline__ void
__swab24s (__u32 * addr)
{
  do
    {
      *(addr) = (
		  {
		  __u32 __tmp = (*((addr)));
		  (
		    {
		    __u32 __x = (__tmp);
		    ((__u32)
		     (((__x & (__u32) 0x000000ffUL) << 16) |
		      (__x & (__u32) 0x0000ff00UL) |
		      ((__x & (__u32) 0x00ff0000UL) >> 16)));
		    }
		  );
		  }
      );
    }
  while (0);
}

static __inline__ __const__ __u32
__fswab32 (__u32 x)
{
  return ___arch__swab32 (x);
}
static __inline__ __u32
__swab32p (__u32 * x)
{
  return ___arch__swab32 (*(x));
}
static __inline__ void
__swab32s (__u32 * addr)
{
  do
    {
      *(addr) = ___arch__swab32 (*((addr)));
    }
  while (0);
}


static __inline__ __const__ __u64
__fswab64 (__u64 x)
{





  return ___arch__swab64 (x);

}
static __inline__ __u64
__swab64p (__u64 * x)
{
  return ___arch__swab64 (*(x));
}
static __inline__ void
__swab64s (__u64 * addr)
{
  do
    {
      *(addr) = ___arch__swab64 (*((addr)));
    }
  while (0);
}





extern __u32 ntohl (__u32);
extern __u32 htonl (__u32);
extern unsigned short int ntohs (unsigned short int);
extern unsigned short int htons (unsigned short int);




extern int console_printk[];

struct completion;

extern struct notifier_block *panic_notifier_list;
void panic (const char *fmt, ...)
  __attribute__ ((noreturn, format (printf, 1, 2)));
__attribute__ ((regparm (0)))
     void
     do_exit (long error_code) __attribute__ ((noreturn));
     void
     complete_and_exit (struct completion *, long) __attribute__ ((noreturn));
     extern int
     abs (int);
     extern unsigned long
     simple_strtoul (const char *, char **, unsigned int);
     extern long
     simple_strtol (const char *, char **, unsigned int);
     extern unsigned long long
     simple_strtoull (const char *, char **, unsigned int);
     extern long long
     simple_strtoll (const char *, char **, unsigned int);
     extern int
     sprintf (char *buf, const char *fmt, ...)
  __attribute__ ((format (printf, 2, 3)));
     extern int
     vsprintf (char *buf, const char *, va_list);
     extern int
     snprintf (char *buf, size_t size, const char *fmt, ...)
  __attribute__ ((format (printf, 3, 4)));
     extern int
     vsnprintf (char *buf, size_t size, const char *fmt, va_list args);

     extern int
     sscanf (const char *, const char *, ...)
  __attribute__ ((format (scanf, 2, 3)));
     extern int
     vsscanf (const char *, const char *, va_list);

     extern int
     get_option (char **str, int *pint);
     extern char *
     get_options (char *str, int nints, int *ints);
     extern unsigned long long
     memparse (char *ptr, char **retptr);
     extern void
     dev_probe_lock (void);
     extern void
     dev_probe_unlock (void);

     extern int
     session_of_pgrp (int pgrp);

__attribute__ ((regparm (0)))
     int
     printk (const char *fmt, ...) __attribute__ ((format (printf, 1, 2)));

     static inline void
     console_silent (void)
{
  (console_printk[0]) = 0;
}

static inline void
console_verbose (void)
{
  if ((console_printk[0]))
    (console_printk[0]) = 15;
}

extern void bust_spinlocks (int yes);
extern int oops_in_progress;

extern int tainted;
extern const char *print_tainted (void);

extern void dump_stack (void);

extern void __out_of_line_bug (int line) __attribute__ ((noreturn));





struct sysinfo
{
  long uptime;
  unsigned long loads[3];
  unsigned long totalram;
  unsigned long freeram;
  unsigned long sharedram;
  unsigned long bufferram;
  unsigned long totalswap;
  unsigned long freeswap;
  unsigned short procs;
  unsigned short pad;
  unsigned long totalhigh;
  unsigned long freehigh;
  unsigned int mem_unit;
  char _f[20 - 2 * sizeof (long) - sizeof (int)];
};








extern unsigned long event;










struct pt_regs
{
  long ebx;
  long ecx;
  long edx;
  long esi;
  long edi;
  long ebp;
  long eax;
  int xds;
  int xes;
  long orig_eax;
  long eip;
  int xcs;
  long eflags;
  long esp;
  int xss;
};

extern void show_regs (struct pt_regs *);






















struct vm86_regs
{



  long ebx;
  long ecx;
  long edx;
  long esi;
  long edi;
  long ebp;
  long eax;
  long __null_ds;
  long __null_es;
  long __null_fs;
  long __null_gs;
  long orig_eax;
  long eip;
  unsigned short cs, __csh;
  long eflags;
  long esp;
  unsigned short ss, __ssh;



  unsigned short es, __esh;
  unsigned short ds, __dsh;
  unsigned short fs, __fsh;
  unsigned short gs, __gsh;
};

struct revectored_struct
{
  unsigned long __map[8];
};

struct vm86_struct
{
  struct vm86_regs regs;
  unsigned long flags;
  unsigned long screen_bitmap;
  unsigned long cpu_type;
  struct revectored_struct int_revectored;
  struct revectored_struct int21_revectored;
};






struct vm86plus_info_struct
{
  unsigned long force_return_for_pic:1;
  unsigned long vm86dbg_active:1;
  unsigned long vm86dbg_TFpendig:1;
  unsigned long unused:28;
  unsigned long is_vm86pus:1;
  unsigned char vm86dbg_intxxtab[32];
};

struct vm86plus_struct
{
  struct vm86_regs regs;
  unsigned long flags;
  unsigned long screen_bitmap;
  unsigned long cpu_type;
  struct revectored_struct int_revectored;
  struct revectored_struct int21_revectored;
  struct vm86plus_info_struct vm86plus;
};

struct kernel_vm86_regs
{



  long ebx;
  long ecx;
  long edx;
  long esi;
  long edi;
  long ebp;
  long eax;
  long __null_ds;
  long __null_es;
  long orig_eax;
  long eip;
  unsigned short cs, __csh;
  long eflags;
  long esp;
  unsigned short ss, __ssh;



  unsigned short es, __esh;
  unsigned short ds, __dsh;
  unsigned short fs, __fsh;
  unsigned short gs, __gsh;
};

struct kernel_vm86_struct
{
  struct kernel_vm86_regs regs;

  unsigned long flags;
  unsigned long screen_bitmap;
  unsigned long cpu_type;
  struct revectored_struct int_revectored;
  struct revectored_struct int21_revectored;
  struct vm86plus_info_struct vm86plus;
  struct pt_regs *regs32;

};

void handle_vm86_fault (struct kernel_vm86_regs *, long);
int handle_vm86_trap (struct kernel_vm86_regs *, long, int);







struct _fpreg
{
  unsigned short significand[4];
  unsigned short exponent;
};

struct _fpxreg
{
  unsigned short significand[4];
  unsigned short exponent;
  unsigned short padding[3];
};

struct _xmmreg
{
  unsigned long element[4];
};

struct _fpstate
{

  unsigned long cw;
  unsigned long sw;
  unsigned long tag;
  unsigned long ipoff;
  unsigned long cssel;
  unsigned long dataoff;
  unsigned long datasel;
  struct _fpreg _st[8];
  unsigned short status;
  unsigned short magic;


  unsigned long _fxsr_env[6];
  unsigned long mxcsr;
  unsigned long reserved;
  struct _fpxreg _fxsr_st[8];
  struct _xmmreg _xmm[8];
  unsigned long padding[56];
};



struct sigcontext
{
  unsigned short gs, __gsh;
  unsigned short fs, __fsh;
  unsigned short es, __esh;
  unsigned short ds, __dsh;
  unsigned long edi;
  unsigned long esi;
  unsigned long ebp;
  unsigned long esp;
  unsigned long ebx;
  unsigned long edx;
  unsigned long ecx;
  unsigned long eax;
  unsigned long trapno;
  unsigned long err;
  unsigned long eip;
  unsigned short cs, __csh;
  unsigned long eflags;
  unsigned long esp_at_signal;
  unsigned short ss, __ssh;
  struct _fpstate *fpstate;
  unsigned long oldmask;
  unsigned long cr2;
};


int restore_i387_soft (void *s387, struct _fpstate *buf);
int save_i387_soft (void *s387, struct _fpstate *buf);





struct info
{
  long ___orig_eip;
  long ___ebx;
  long ___ecx;
  long ___edx;
  long ___esi;
  long ___edi;
  long ___ebp;
  long ___eax;
  long ___ds;
  long ___es;
  long ___orig_eax;
  long ___eip;
  long ___cs;
  long ___eflags;
  long ___esp;
  long ___ss;
  long ___vm86_es;
  long ___vm86_ds;
  long ___vm86_fs;
  long ___vm86_gs;
};





typedef struct
{
  unsigned long pte_low;
} pte_t;
typedef struct
{
  unsigned long pmd;
} pmd_t;
typedef struct
{
  unsigned long pgd;
} pgd_t;




typedef struct
{
  unsigned long pgprot;
} pgprot_t;









void show_stack (unsigned long *esp);


static __inline__ int
get_order (unsigned long size)
{
  int order;

  size = (size - 1) >> (12 - 1);
  order = -1;
  do
    {
      size >>= 1;
      order++;
    }
  while (size);
  return order;
}


















struct cpuinfo_x86
{
  __u8 x86;
  __u8 x86_vendor;
  __u8 x86_model;
  __u8 x86_mask;
  char wp_works_ok;
  char hlt_works_ok;
  char hard_math;
  char rfu;
  int cpuid_level;
  __u32 x86_capability[6];
  char x86_vendor_id[16];
  char x86_model_id[64];
  int x86_cache_size;

  int fdiv_bug;
  int f00f_bug;
  int coma_bug;
  unsigned long loops_per_jiffy;
  unsigned long *pgd_quick;
  unsigned long *pmd_quick;
  unsigned long *pte_quick;
  unsigned long pgtable_cache_sz;
} __attribute__ ((__aligned__ ((1 << ((5))))));

extern struct cpuinfo_x86 boot_cpu_data;
extern struct tss_struct init_tss[1];

extern char ignore_irq13;

extern void identify_cpu (struct cpuinfo_x86 *);
extern void print_cpu_info (struct cpuinfo_x86 *);
extern void dodgy_tsc (void);

static inline void
cpuid (int op, int *eax, int *ebx, int *ecx, int *edx)
{
__asm__ ("cpuid": "=a" (*eax), "=b" (*ebx), "=c" (*ecx), "=d" (*edx):"0" (op));
}




static inline unsigned int
cpuid_eax (unsigned int op)
{
  unsigned int eax;

__asm__ ("cpuid": "=a" (eax): "0" (op):"bx", "cx", "dx");
  return eax;
}
static inline unsigned int
cpuid_ebx (unsigned int op)
{
  unsigned int eax, ebx;

__asm__ ("cpuid": "=a" (eax), "=b" (ebx): "0" (op):"cx", "dx");
  return ebx;
}
static inline unsigned int
cpuid_ecx (unsigned int op)
{
  unsigned int eax, ecx;

__asm__ ("cpuid": "=a" (eax), "=c" (ecx): "0" (op):"bx", "dx");
  return ecx;
}
static inline unsigned int
cpuid_edx (unsigned int op)
{
  unsigned int eax, edx;

__asm__ ("cpuid": "=a" (eax), "=d" (edx): "0" (op):"bx", "cx");
  return edx;
}


extern unsigned long mmu_cr4_features;

static inline void
set_in_cr4 (unsigned long mask)
{
  mmu_cr4_features |= mask;
__asm__ ("movl %%cr4,%%eax\n\t" "orl %0,%%eax\n\t" "movl %%eax,%%cr4\n": : "irg" (mask):"ax");
}

static inline void
clear_in_cr4 (unsigned long mask)
{
  mmu_cr4_features &= ~mask;
__asm__ ("movl %%cr4,%%eax\n\t" "andl %0,%%eax\n\t" "movl %%eax,%%cr4\n": : "irg" (~mask):"ax");
}


extern int MCA_bus;



extern unsigned int machine_id;
extern unsigned int machine_submodel_id;
extern unsigned int BIOS_revision;
extern unsigned int mca_pentium_flag;

struct i387_fsave_struct
{
  long cwd;
  long swd;
  long twd;
  long fip;
  long fcs;
  long foo;
  long fos;
  long st_space[20];
  long status;
};

struct i387_fxsave_struct
{
  unsigned short cwd;
  unsigned short swd;
  unsigned short twd;
  unsigned short fop;
  long fip;
  long fcs;
  long foo;
  long fos;
  long mxcsr;
  long reserved;
  long st_space[32];
  long xmm_space[32];
  long padding[56];
} __attribute__ ((aligned (16)));

struct i387_soft_struct
{
  long cwd;
  long swd;
  long twd;
  long fip;
  long fcs;
  long foo;
  long fos;
  long st_space[20];
  unsigned char ftop, changed, lookahead, no_update, rm, alimit;
  struct info *info;
  unsigned long entry_eip;
};

union i387_union
{
  struct i387_fsave_struct fsave;
  struct i387_fxsave_struct fxsave;
  struct i387_soft_struct soft;
};

typedef struct
{
  unsigned long seg;
} mm_segment_t;

struct tss_struct
{
  unsigned short back_link, __blh;
  unsigned long esp0;
  unsigned short ss0, __ss0h;
  unsigned long esp1;
  unsigned short ss1, __ss1h;
  unsigned long esp2;
  unsigned short ss2, __ss2h;
  unsigned long __cr3;
  unsigned long eip;
  unsigned long eflags;
  unsigned long eax, ecx, edx, ebx;
  unsigned long esp;
  unsigned long ebp;
  unsigned long esi;
  unsigned long edi;
  unsigned short es, __esh;
  unsigned short cs, __csh;
  unsigned short ss, __ssh;
  unsigned short ds, __dsh;
  unsigned short fs, __fsh;
  unsigned short gs, __gsh;
  unsigned short ldt, __ldth;
  unsigned short trace, bitmap;
  unsigned long io_bitmap[32 + 1];



  unsigned long __cacheline_filler[5];
};

struct thread_struct
{
  unsigned long esp0;
  unsigned long eip;
  unsigned long esp;
  unsigned long fs;
  unsigned long gs;

  unsigned long debugreg[8];

  unsigned long cr2, trap_no, error_code;

  union i387_union i387;

  struct vm86_struct *vm86_info;
  unsigned long screen_bitmap;
  unsigned long v86flags, v86mask, saved_esp0;

  int ioperm;
  unsigned long io_bitmap[32 + 1];

  struct pt_regs *kgdbregs;

};

struct task_struct;
struct mm_struct;


extern void release_thread (struct task_struct *);



extern int arch_kernel_thread (int (*fn) (void *), void *arg,
			       unsigned long flags);





static inline void
copy_segments (struct task_struct *p, struct mm_struct *mm)
{
}
static inline void
release_segments (struct mm_struct *mm)
{
}




static inline unsigned long
thread_saved_pc (struct thread_struct *t)
{
  return ((unsigned long *) t->esp)[3];
}

unsigned long get_wchan (struct task_struct *p);

struct microcode_header
{
  unsigned int hdrver;
  unsigned int rev;
  unsigned int date;
  unsigned int sig;
  unsigned int cksum;
  unsigned int ldrver;
  unsigned int pf;
  unsigned int datasize;
  unsigned int totalsize;
  unsigned int reserved[3];
};

struct microcode
{
  struct microcode_header hdr;
  unsigned int bits[0];
};

typedef struct microcode microcode_t;
typedef struct microcode_header microcode_header_t;


struct extended_signature
{
  unsigned int sig;
  unsigned int pf;
  unsigned int cksum;
};

struct extended_sigtable
{
  unsigned int count;
  unsigned int cksum;
  unsigned int reserved[3];
  struct extended_signature sigs[0];
};




static inline void
rep_nop (void)
{
  __asm__ __volatile__ ("rep;nop":::"memory");
}







static inline void
prefetch (const void *x)
{
  __asm__ __volatile__ ("prefetchnta (%0)"::"r" (x));
}



static inline void
prefetchw (const void *x)
{;
}



struct list_head
{
  struct list_head *next, *prev;
};

static inline void
__list_add (struct list_head *new,
	    struct list_head *prev, struct list_head *next)
{
  next->prev = new;
  new->next = next;
  new->prev = prev;
  prev->next = new;
}


static inline void
list_add (struct list_head *new, struct list_head *head)
{
  __list_add (new, head, head->next);
}


static inline void
list_add_tail (struct list_head *new, struct list_head *head)
{
  __list_add (new, head->prev, head);
}


static inline void
__list_del (struct list_head *prev, struct list_head *next)
{
  next->prev = prev;
  prev->next = next;
}






static inline void
list_del (struct list_head *entry)
{
  __list_del (entry->prev, entry->next);
  entry->next = (void *) 0;
  entry->prev = (void *) 0;
}





static inline void
list_del_init (struct list_head *entry)
{
  __list_del (entry->prev, entry->next);
  do
    {
      (entry)->next = (entry);
      (entry)->prev = (entry);
    }
  while (0);
}






static inline void
list_move (struct list_head *list, struct list_head *head)
{
  __list_del (list->prev, list->next);
  list_add (list, head);
}






static inline void
list_move_tail (struct list_head *list, struct list_head *head)
{
  __list_del (list->prev, list->next);
  list_add_tail (list, head);
}





static inline int
list_empty (struct list_head *head)
{
  return head->next == head;
}

static inline void
__list_splice (struct list_head *list, struct list_head *head)
{
  struct list_head *first = list->next;
  struct list_head *last = list->prev;
  struct list_head *at = head->next;

  first->prev = head;
  head->next = first;

  last->next = at;
  at->prev = last;
}






static inline void
list_splice (struct list_head *list, struct list_head *head)
{
  if (!list_empty (list))
    __list_splice (list, head);
}


static inline void
list_splice_init (struct list_head *list, struct list_head *head)
{
  if (!list_empty (list))
    {
      __list_splice (list, head);
      do
	{
	  (list)->next = (list);
	  (list)->prev = (list);
	}
      while (0);
    }
}

















typedef int (*__init_module_func_t) (void);
typedef void (*__cleanup_module_func_t) (void);




static inline int
generic_ffs (int x)
{
  int r = 1;

  if (!x)
    return 0;
  if (!(x & 0xffff))
    {
      x >>= 16;
      r += 16;
    }
  if (!(x & 0xff))
    {
      x >>= 8;
      r += 8;
    }
  if (!(x & 0xf))
    {
      x >>= 4;
      r += 4;
    }
  if (!(x & 3))
    {
      x >>= 2;
      r += 2;
    }
  if (!(x & 1))
    {
      x >>= 1;
      r += 1;
    }
  return r;
}






static inline unsigned int
generic_hweight32 (unsigned int w)
{
  unsigned int res = (w & 0x55555555) + ((w >> 1) & 0x55555555);
  res = (res & 0x33333333) + ((res >> 2) & 0x33333333);
  res = (res & 0x0F0F0F0F) + ((res >> 4) & 0x0F0F0F0F);
  res = (res & 0x00FF00FF) + ((res >> 8) & 0x00FF00FF);
  return (res & 0x0000FFFF) + ((res >> 16) & 0x0000FFFF);
}

static inline unsigned int
generic_hweight16 (unsigned int w)
{
  unsigned int res = (w & 0x5555) + ((w >> 1) & 0x5555);
  res = (res & 0x3333) + ((res >> 2) & 0x3333);
  res = (res & 0x0F0F) + ((res >> 4) & 0x0F0F);
  return (res & 0x00FF) + ((res >> 8) & 0x00FF);
}

static inline unsigned int
generic_hweight8 (unsigned int w)
{
  unsigned int res = (w & 0x55) + ((w >> 1) & 0x55);
  res = (res & 0x33) + ((res >> 2) & 0x33);
  return (res & 0x0F) + ((res >> 4) & 0x0F);
}



static __inline__ void
set_bit (int nr, volatile void *addr)
{
  __asm__ __volatile__ (""
			"btsl %1,%0":"=m" ((*(volatile long *)
					    addr)):"Ir" (nr));
}


static __inline__ void
__set_bit (int nr, volatile void *addr)
{
__asm__ ("btsl %1,%0": "=m" ((*(volatile long *) addr)):"Ir" (nr));
}


static __inline__ void
clear_bit (int nr, volatile void *addr)
{
  __asm__ __volatile__ (""
			"btrl %1,%0":"=m" ((*(volatile long *)
					    addr)):"Ir" (nr));
}


static __inline__ void
__change_bit (int nr, volatile void *addr)
{
  __asm__
    __volatile__ ("btcl %1,%0":"=m" ((*(volatile long *) addr)):"Ir" (nr));
}


static __inline__ void
change_bit (int nr, volatile void *addr)
{
  __asm__ __volatile__ (""
			"btcl %1,%0":"=m" ((*(volatile long *)
					    addr)):"Ir" (nr));
}


static __inline__ int
test_and_set_bit (int nr, volatile void *addr)
{
  int oldbit;

  __asm__ __volatile__ (""
			"btsl %2,%1\n\tsbbl %0,%0":"=r" (oldbit),
			"=m" ((*(volatile long *) addr)):"Ir" (nr):"memory");
  return oldbit;
}


static __inline__ int
__test_and_set_bit (int nr, volatile void *addr)
{
  int oldbit;

__asm__ ("btsl %2,%1\n\tsbbl %0,%0": "=r" (oldbit), "=m" ((*(volatile long *) addr)):"Ir" (nr));
  return oldbit;
}


static __inline__ int
test_and_clear_bit (int nr, volatile void *addr)
{
  int oldbit;

  __asm__ __volatile__ (""
			"btrl %2,%1\n\tsbbl %0,%0":"=r" (oldbit),
			"=m" ((*(volatile long *) addr)):"Ir" (nr):"memory");
  return oldbit;
}


static __inline__ int
__test_and_clear_bit (int nr, volatile void *addr)
{
  int oldbit;

__asm__ ("btrl %2,%1\n\tsbbl %0,%0": "=r" (oldbit), "=m" ((*(volatile long *) addr)):"Ir" (nr));
  return oldbit;
}


static __inline__ int
__test_and_change_bit (int nr, volatile void *addr)
{
  int oldbit;

  __asm__ __volatile__ ("btcl %2,%1\n\tsbbl %0,%0":"=r" (oldbit),
			"=m" ((*(volatile long *) addr)):"Ir" (nr):"memory");
  return oldbit;
}


static __inline__ int
test_and_change_bit (int nr, volatile void *addr)
{
  int oldbit;

  __asm__ __volatile__ (""
			"btcl %2,%1\n\tsbbl %0,%0":"=r" (oldbit),
			"=m" ((*(volatile long *) addr)):"Ir" (nr):"memory");
  return oldbit;
}


static __inline__ int
constant_test_bit (int nr, const volatile void *addr)
{
  return ((1UL << (nr & 31)) &
	  (((const volatile unsigned int *) addr)[nr >> 5])) != 0;
}

static __inline__ int
variable_test_bit (int nr, volatile void *addr)
{
  int oldbit;

  __asm__
    __volatile__ ("btl %2,%1\n\tsbbl %0,%0":"=r" (oldbit):"m"
		  ((*(volatile long *) addr)), "Ir" (nr));
  return oldbit;
}


static __inline__ int
find_first_zero_bit (void *addr, unsigned size)
{
  int d0, d1, d2;
  int res;

  if (!size)
    return 0;

  __asm__ __volatile__ ("movl $-1,%%eax\n\t"
			"xorl %%edx,%%edx\n\t"
			"repe; scasl\n\t"
			"je 1f\n\t"
			"xorl -4(%%edi),%%eax\n\t"
			"subl $4,%%edi\n\t"
			"bsfl %%eax,%%edx\n"
			"1:\tsubl %%ebx,%%edi\n\t"
			"shll $3,%%edi\n\t"
			"addl %%edi,%%edx":"=d" (res), "=&c" (d0), "=&D" (d1),
			"=&a" (d2):"1" ((size + 31) >> 5), "2" (addr),
			"b" (addr));
  return res;
}







static __inline__ int
find_next_zero_bit (void *addr, int size, int offset)
{
  unsigned long *p = ((unsigned long *) addr) + (offset >> 5);
  int set = 0, bit = offset & 31, res;

  if (bit)
    {



    __asm__ ("bsfl %1,%0\n\t" "jne 1f\n\t" "movl $32, %0\n" "1:": "=r" (set):"r" (~
	   (*p >>
	    bit)));
      if (set < (32 - bit))
	return set + offset;
      set = 32 - bit;
      p++;
    }



  res = find_first_zero_bit (p, size - 32 * (p - (unsigned long *) addr));
  return (offset + set + res);
}







static __inline__ unsigned long
ffz (unsigned long word)
{
__asm__ ("bsfl %1,%0": "=r" (word):"r" (~word));
  return word;
}


static __inline__ int
ffs (int x)
{
  int r;

__asm__ ("bsfl %1,%0\n\t" "jnz 1f\n\t" "movl $-1,%0\n" "1:": "=r" (r):"rm" (x));
  return r + 1;
}






struct task_struct;
extern void __switch_to (struct task_struct *prev, struct task_struct *next)
  __attribute__ ((regparm (3)));

static inline unsigned long
_get_base (char *addr)
{
  unsigned long __base;
__asm__ ("movb %3,%%dh\n\t" "movb %2,%%dl\n\t" "shll $16,%%edx\n\t" "movw %1,%%dx": "=&d" (__base):"m" (*((addr) + 2)),
	   "m" (*((addr) + 4)),
	   "m" (*((addr) + 7)));
  return __base;
}


static inline unsigned long
get_limit (unsigned long segment)
{
  unsigned long __limit;
__asm__ ("lsll %1,%0": "=r" (__limit):"r" (segment));
  return __limit + 1;
}







struct __xchg_dummy
{
  unsigned long a[100];
};

static inline void
__set_64bit (unsigned long long *ptr, unsigned int low, unsigned int high)
{
  __asm__ __volatile__ ("\n1:\t"
			"movl (%0), %%eax\n\t"
			"movl 4(%0), %%edx\n\t"
			"lock cmpxchg8b (%0)\n\t"
			"jnz 1b"::"D" (ptr),
			"b" (low), "c" (high):"ax", "dx", "memory");
}

static inline void
__set_64bit_constant (unsigned long long *ptr, unsigned long long value)
{
  __set_64bit (ptr, (unsigned int) (value),
	       (unsigned int) ((value) >> 32ULL));
}



static inline void
__set_64bit_var (unsigned long long *ptr, unsigned long long value)
{
  __set_64bit (ptr, *(((unsigned int *) &(value)) + 0),
	       *(((unsigned int *) &(value)) + 1));
}


static inline unsigned long
__xchg (unsigned long x, volatile void *ptr, int size)
{
  switch (size)
    {
    case 1:
    __asm__ __volatile__ ("xchgb %b0,%1": "=q" (x): "m" (*((struct __xchg_dummy *) (ptr))), "0" (x):"memory");
      break;
    case 2:
    __asm__ __volatile__ ("xchgw %w0,%1": "=r" (x): "m" (*((struct __xchg_dummy *) (ptr))), "0" (x):"memory");
      break;
    case 4:
    __asm__ __volatile__ ("xchgl %0,%1": "=r" (x): "m" (*((struct __xchg_dummy *) (ptr))), "0" (x):"memory");
      break;
    }
  return x;
}


static inline unsigned long
__cmpxchg (volatile void *ptr, unsigned long old, unsigned long new, int size)
{
  unsigned long prev;
  switch (size)
    {
    case 1:
    __asm__ __volatile__ ("" "cmpxchgb %b1,%2": "=a" (prev): "q" (new), "m" (*((struct __xchg_dummy *) (ptr))), "0" (old):"memory");
      return prev;
    case 2:
    __asm__ __volatile__ ("" "cmpxchgw %w1,%2": "=a" (prev): "q" (new), "m" (*((struct __xchg_dummy *) (ptr))), "0" (old):"memory");
      return prev;
    case 4:
    __asm__ __volatile__ ("" "cmpxchgl %1,%2": "=a" (prev): "q" (new), "m" (*((struct __xchg_dummy *) (ptr))), "0" (old):"memory");
      return prev;
    }
  return old;
}


void disable_hlt (void);
void enable_hlt (void);

extern unsigned long dmi_broken;
extern int is_sony_vaio_laptop;





typedef struct
{
} spinlock_t;

typedef struct
{
} rwlock_t;

typedef struct
{
  spinlock_t lock;
} spinlock_cacheline_t;


struct __wait_queue
{
  unsigned int flags;

  struct task_struct *task;
  struct list_head task_list;




};
typedef struct __wait_queue wait_queue_t;

struct __wait_queue_head
{
  spinlock_t lock;
  struct list_head task_list;




};
typedef struct __wait_queue_head wait_queue_head_t;

static inline void
init_waitqueue_head (wait_queue_head_t * q)
{




  q->lock = (spinlock_t)
  {
  };
  do
    {
      (&q->task_list)->next = (&q->task_list);
      (&q->task_list)->prev = (&q->task_list);
    }
  while (0);




}

static inline void
init_waitqueue_entry (wait_queue_t * q, struct task_struct *p)
{




  q->flags = 0;
  q->task = p;



}

static inline int
waitqueue_active (wait_queue_head_t * q)
{






  return !list_empty (&q->task_list);
}

static inline void
__add_wait_queue (wait_queue_head_t * head, wait_queue_t * new)
{

  list_add (&new->task_list, &head->task_list);
}




static inline void
__add_wait_queue_tail (wait_queue_head_t * head, wait_queue_t * new)
{

  list_add_tail (&new->task_list, &head->task_list);
}

static inline void
__remove_wait_queue (wait_queue_head_t * head, wait_queue_t * old)
{





  list_del (&old->task_list);
}















typedef __kernel_fsid_t fsid_t;



struct statfs
{
  long f_type;
  long f_bsize;
  long f_blocks;
  long f_bfree;
  long f_bavail;
  long f_files;
  long f_ffree;
  __kernel_fsid_t f_fsid;
  long f_namelen;
  long f_spare[6];
};






struct __kernel_sockaddr_storage
{
  unsigned short ss_family;

  char __data[128 - sizeof (unsigned short)];


} __attribute__ ((aligned ((__alignof__ (struct sockaddr *)))));














struct iovec
{
  void *iov_base;
  __kernel_size_t iov_len;
};



typedef unsigned short sa_family_t;





struct sockaddr
{
  sa_family_t sa_family;
  char sa_data[14];
};

struct linger
{
  int l_onoff;
  int l_linger;
};

struct msghdr
{
  void *msg_name;
  int msg_namelen;
  struct iovec *msg_iov;
  __kernel_size_t msg_iovlen;
  void *msg_control;
  __kernel_size_t msg_controllen;
  unsigned msg_flags;
};







struct cmsghdr
{
  __kernel_size_t cmsg_len;
  int cmsg_level;
  int cmsg_type;
};

static inline struct cmsghdr *
__cmsg_nxthdr (void *__ctl, __kernel_size_t __size, struct cmsghdr *__cmsg)
{
  struct cmsghdr *__ptr;

  __ptr =
    (struct cmsghdr *) (((unsigned char *) __cmsg) +
			(((__cmsg->cmsg_len) + sizeof (long) -
			  1) & ~(sizeof (long) - 1)));
  if ((unsigned long) ((char *) (__ptr + 1) - (char *) __ctl) > __size)
    return (struct cmsghdr *) 0;

  return __ptr;
}

static inline struct cmsghdr *
cmsg_nxthdr (struct msghdr *__msg, struct cmsghdr *__cmsg)
{
  return __cmsg_nxthdr (__msg->msg_control, __msg->msg_controllen, __cmsg);
}







struct ucred
{
  __u32 pid;
  __u32 uid;
  __u32 gid;
};

extern int memcpy_fromiovec (unsigned char *kdata, struct iovec *iov,
			     int len);
extern int memcpy_fromiovecend (unsigned char *kdata, struct iovec *iov,
				int offset, int len);
extern int csum_partial_copy_fromiovecend (unsigned char *kdata,
					   struct iovec *iov, int offset,
					   unsigned int len, int *csump);

extern int verify_iovec (struct msghdr *m, struct iovec *iov, char *address,
			 int mode);
extern int memcpy_toiovec (struct iovec *v, unsigned char *kdata, int len);
extern void memcpy_tokerneliovec (struct iovec *iov, unsigned char *kdata,
				  int len);
extern int move_addr_to_user (void *kaddr, int klen, void *uaddr, int *ulen);
extern int move_addr_to_kernel (void *uaddr, int ulen, void *kaddr);
extern int put_cmsg (struct msghdr *, int level, int type, int len,
		     void *data);



struct poll_table_struct;

typedef enum
{
  SS_FREE = 0,
  SS_UNCONNECTED,
  SS_CONNECTING,
  SS_CONNECTED,
  SS_DISCONNECTING
} socket_state;

struct socket
{
  socket_state state;

  unsigned long flags;
  struct proto_ops *ops;
  struct inode *inode;
  struct fasync_struct *fasync_list;
  struct file *file;
  struct sock *sk;
  wait_queue_head_t wait;

  short type;
  unsigned char passcred;
};



struct scm_cookie;
struct vm_area_struct;
struct page;

struct proto_ops
{
  int family;

  int (*release) (struct socket * sock);
  int (*bind) (struct socket * sock, struct sockaddr * umyaddr,
	       int sockaddr_len);
  int (*connect) (struct socket * sock, struct sockaddr * uservaddr,
		  int sockaddr_len, int flags);
  int (*socketpair) (struct socket * sock1, struct socket * sock2);
  int (*accept) (struct socket * sock, struct socket * newsock, int flags);
  int (*getname) (struct socket * sock, struct sockaddr * uaddr,
		  int *usockaddr_len, int peer);
  unsigned int (*poll) (struct file * file, struct socket * sock,
			struct poll_table_struct * wait);
  int (*ioctl) (struct socket * sock, unsigned int cmd, unsigned long arg);
  int (*listen) (struct socket * sock, int len);
  int (*shutdown) (struct socket * sock, int flags);
  int (*setsockopt) (struct socket * sock, int level, int optname,
		     char *optval, int optlen);
  int (*getsockopt) (struct socket * sock, int level, int optname,
		     char *optval, int *optlen);
  int (*sendmsg) (struct socket * sock, struct msghdr * m, int total_len,
		  struct scm_cookie * scm);
  int (*recvmsg) (struct socket * sock, struct msghdr * m, int total_len,
		  int flags, struct scm_cookie * scm);
  int (*mmap) (struct file * file, struct socket * sock,
	       struct vm_area_struct * vma);
    ssize_t (*sendpage) (struct socket * sock, struct page * page, int offset,
			 size_t size, int flags);
};

struct net_proto_family
{
  int family;
  int (*create) (struct socket * sock, int protocol);


  short authentication;
  short encryption;
  short encrypt_net;
};

struct net_proto
{
  const char *name;
  void (*init_func) (struct net_proto *);
};

extern int sock_wake_async (struct socket *sk, int how, int band);
extern int sock_register (struct net_proto_family *fam);
extern int sock_unregister (int family);
extern struct socket *sock_alloc (void);
extern int sock_create (int family, int type, int proto, struct socket **);
extern void sock_release (struct socket *);
extern int sock_sendmsg (struct socket *, struct msghdr *m, int len);
extern int sock_recvmsg (struct socket *, struct msghdr *m, int len,
			 int flags);
extern int sock_readv_writev (int type, struct inode *inode,
			      struct file *file, const struct iovec *iov,
			      long count, long size);
extern struct socket *sockfd_lookup (int fd, int *err);

extern int sock_map_fd (struct socket *sock);
extern int net_ratelimit (void);
extern unsigned long net_random (void);
extern void net_srandom (unsigned long);



typedef unsigned short kdev_t;

extern const char *kdevname (kdev_t);

static inline unsigned int
kdev_t_to_nr (kdev_t dev)
{
  return (((unsigned int) ((dev) >> 8)) << 8) |
    ((unsigned int) ((dev) & ((1U << 8) - 1)));
}

static inline kdev_t
to_kdev_t (int dev)
{
  int major, minor;

  major = (dev >> 8);
  minor = (dev & 0xff);

  return (((major) << 8) | (minor));
}


















typedef struct
{
  volatile int counter;
} atomic_t;

static __inline__ void
atomic_add (int i, atomic_t * v)
{
  __asm__ __volatile__ ("" "addl %1,%0":"=m" (v->counter):"ir" (i),
			"m" (v->counter));
}


static __inline__ void
atomic_sub (int i, atomic_t * v)
{
  __asm__ __volatile__ ("" "subl %1,%0":"=m" (v->counter):"ir" (i),
			"m" (v->counter));
}


static __inline__ int
atomic_sub_and_test (int i, atomic_t * v)
{
  unsigned char c;

  __asm__ __volatile__ ("" "subl %2,%0; sete %1":"=m" (v->counter),
			"=qm" (c):"ir" (i), "m" (v->counter):"memory");
  return c;
}


static __inline__ void
atomic_inc (atomic_t * v)
{
  __asm__ __volatile__ ("" "incl %0":"=m" (v->counter):"m" (v->counter));
}


static __inline__ void
atomic_dec (atomic_t * v)
{
  __asm__ __volatile__ ("" "decl %0":"=m" (v->counter):"m" (v->counter));
}


static __inline__ int
atomic_dec_and_test (atomic_t * v)
{
  unsigned char c;

  __asm__ __volatile__ ("" "decl %0; sete %1":"=m" (v->counter),
			"=qm" (c):"m" (v->counter):"memory");
  return c != 0;
}


static __inline__ int
atomic_inc_and_test (atomic_t * v)
{
  unsigned char c;

  __asm__ __volatile__ ("" "incl %0; sete %1":"=m" (v->counter),
			"=qm" (c):"m" (v->counter):"memory");
  return c != 0;
}


static __inline__ int
atomic_add_negative (int i, atomic_t * v)
{
  unsigned char c;

  __asm__ __volatile__ ("" "addl %2,%0; sets %1":"=m" (v->counter),
			"=qm" (c):"ir" (i), "m" (v->counter):"memory");
  return c;
}







extern int gdb_enter;
extern int gdb_ttyS;
extern int gdb_baud;
extern int gdb_initialized;
extern int gdb_irq;

enum regnames
{ _EAX,
  _ECX,
  _EDX,
  _EBX,
  _ESP,
  _EBP,
  _ESI,
  _EDI,
  _PC,
  _PS,
  _CS,
  _SS,
  _DS,
  _ES,
  _FS,
  _GS
};



struct console;
void gdb_console_write (struct console *co, const char *s, unsigned count);
void gdb_console_init (void);

void gdb_wait (struct pt_regs *regs);









int gdb_hook (void);


void set_debug_traps (void);


void breakpoint (void);


int kgdb_output_string (const char *s, unsigned int count);

extern int gdb_enter;
extern int gdb_ttyS;
extern int gdb_baud;
extern int gdb_initialized;

void putDebugChar (char);
char getDebugChar (void);
int hexToInt (char **ptr, int *intValue);
int kgdb_handle_exception (int exVector, int signo, int err_code,
			   struct pt_regs *linux_regs);
char *hex2mem (char *buf, char *mem, int count, int can_fault);
char *mem2hex (char *mem, char *buf, int count, int can_fault);
void putpacket (char *buffer);


extern volatile int kgdb_memerr_expected;




typedef int gdb_debug_hook (int exVector, int signo, int err_code,
			    struct pt_regs *regs);





extern gdb_debug_hook *linux_debug_hook;
extern atomic_t kgdb_lock;
extern spinlock_t slavecpulocks[8];
extern volatile int procindebug[8];
extern int kgdb_initialized;
extern struct kgdb_arch arch_kgdb_ops;
extern struct task_struct *kgdb_usethread, *kgdb_contthread;
extern volatile int kgdb_memerr;
extern atomic_t kgdb_setting_breakpoint;
extern atomic_t kgdb_killed_or_detached;
extern atomic_t kgdb_might_be_resumed;
extern volatile unsigned kgdb_step;


enum gdb_bptype
{
  bp_breakpoint = '0',
  bp_hardware_breakpoint,
  bp_write_watchpoint,
  bp_read_watchpoint,
  bp_access_watchpoint
};

enum gdb_bpstate
{
  bp_disabled,
  bp_enabled
};





struct gdb_breakpoint
{
  unsigned int bpt_addr;
  unsigned char saved_instr[1];
  enum gdb_bptype type;
  enum gdb_bpstate state;
};

typedef struct gdb_breakpoint gdb_breakpoint_t;







struct kgdb_arch
{
  unsigned char gdb_bpt_instr[1];
  unsigned long flags;

  int (*kgdb_init) (void);
  void (*regs_to_gdb_regs) (int *gdb_regs, struct pt_regs * regs);
  void (*sleeping_thread_to_gdb_regs) (int *gdb_regs, struct task_struct * p);
  void (*gdb_regs_to_regs) (int *gdb_regs, struct pt_regs * regs);
  void (*printexpinfo) (int exceptionNo, int errorcode, char *buffer);
  void (*disable_hw_debug) (struct pt_regs * regs);
  void (*post_master_code) (struct pt_regs * regs, int eVector, int err_code);
  int (*handle_buffer) (int vector, int signo, int err_code,
			char *InBuffer, char *outBuffer,
			struct pt_regs * regs);
  int (*set_break) (unsigned long addr, int type);
  int (*remove_break) (unsigned long addr, int type);
  void (*correct_hw_break) (void);
  void (*handler_exit) (void);
};



typedef unsigned char threadref[8];


struct console;
extern void gdb_console_write (struct console *co, const char *s,
			       unsigned count);




struct vfsmount
{
  struct list_head mnt_hash;
  struct vfsmount *mnt_parent;
  struct dentry *mnt_mountpoint;
  struct dentry *mnt_root;
  struct super_block *mnt_sb;
  struct list_head mnt_mounts;
  struct list_head mnt_child;
  atomic_t mnt_count;
  int mnt_flags;
  char *mnt_devname;
  struct list_head mnt_list;
};

static inline struct vfsmount *
mntget (struct vfsmount *mnt)
{
  if (mnt)
    atomic_inc (&mnt->mnt_count);
  return mnt;
}

extern void __mntput (struct vfsmount *mnt);

static inline void
mntput (struct vfsmount *mnt)
{
  if (mnt)
    {
      if (atomic_dec_and_test (&mnt->mnt_count))
	__mntput (mnt);
    }
}



struct qstr
{
  const unsigned char *name;
  unsigned int len;
  unsigned int hash;
};

struct dentry_stat_t
{
  int nr_dentry;
  int nr_unused;
  int age_limit;
  int want_pages;
  int dummy[2];
};
extern struct dentry_stat_t dentry_stat;






static __inline__ unsigned long
partial_name_hash (unsigned long c, unsigned long prevhash)
{
  return (prevhash + (c << 4) + (c >> 4)) * 11;
}


static __inline__ unsigned long
end_name_hash (unsigned long hash)
{
  return (unsigned int) hash;
}


static __inline__ unsigned int
full_name_hash (const unsigned char *name, unsigned int len)
{
  unsigned long hash = 0;
  while (len--)
    hash = partial_name_hash (*name++, hash);
  return end_name_hash (hash);
}



struct dentry
{
  atomic_t d_count;
  unsigned int d_flags;
  struct inode *d_inode;
  struct dentry *d_parent;
  struct list_head d_hash;
  struct list_head d_lru;
  struct list_head d_child;
  struct list_head d_subdirs;
  struct list_head d_alias;
  int d_mounted;
  struct qstr d_name;
  unsigned long d_time;
  struct dentry_operations *d_op;
  struct super_block *d_sb;
  unsigned long d_vfs_flags;
  void *d_fsdata;
  unsigned char d_iname[16];
};

struct dentry_operations
{
  int (*d_revalidate) (struct dentry *, int);
  int (*d_hash) (struct dentry *, struct qstr *);
  int (*d_compare) (struct dentry *, struct qstr *, struct qstr *);
  int (*d_delete) (struct dentry *);
  void (*d_release) (struct dentry *);
  void (*d_iput) (struct dentry *, struct inode *);
};

extern spinlock_t dcache_lock;

static __inline__ void
d_drop (struct dentry *dentry)
{
  (void) (&dcache_lock);
  list_del (&dentry->d_hash);
  do
    {
      (&dentry->d_hash)->next = (&dentry->d_hash);
      (&dentry->d_hash)->prev = (&dentry->d_hash);
    }
  while (0);
  do
    {
    }
  while (0);
}

static __inline__ int
dname_external (struct dentry *d)
{
  return d->d_name.name != d->d_iname;
}




extern void d_instantiate (struct dentry *, struct inode *);
extern void d_delete (struct dentry *);


extern struct dentry *d_alloc (struct dentry *, const struct qstr *);
extern void shrink_dcache_sb (struct super_block *);
extern void shrink_dcache_parent (struct dentry *);
extern int d_invalidate (struct dentry *);


struct zone_struct;

extern int shrink_dcache_memory (int, unsigned int);
extern void prune_dcache (int);


extern int shrink_icache_memory (int, int);
extern void prune_icache (int);


extern int shrink_dqcache_memory (int, unsigned int);


extern struct dentry *d_alloc_root (struct inode *);


extern void d_genocide (struct dentry *);

extern struct dentry *d_find_alias (struct inode *);
extern void d_prune_aliases (struct inode *);


extern int have_submounts (struct dentry *);




extern void d_rehash (struct dentry *);

static __inline__ void
d_add (struct dentry *entry, struct inode *inode)
{
  d_instantiate (entry, inode);
  d_rehash (entry);
}


extern void d_move (struct dentry *, struct dentry *);


extern struct dentry *d_lookup (struct dentry *, struct qstr *);


extern int d_validate (struct dentry *, struct dentry *);

extern char *__d_path (struct dentry *, struct vfsmount *, struct dentry *,
		       struct vfsmount *, char *, int);

static __inline__ struct dentry *
dget (struct dentry *dentry)
{
  if (dentry)
    {
      if (!((&dentry->d_count)->counter))
	__out_of_line_bug (251);
      atomic_inc (&dentry->d_count);
    }
  return dentry;
}

extern struct dentry *dget_locked (struct dentry *);

static __inline__ int
d_unhashed (struct dentry *dentry)
{
  return list_empty (&dentry->d_hash);
}

extern void dput (struct dentry *);

static __inline__ int
d_mountpoint (struct dentry *dentry)
{
  return dentry->d_mounted;
}

extern struct vfsmount *lookup_mnt (struct vfsmount *, struct dentry *);











struct __old_kernel_stat
{
  unsigned short st_dev;
  unsigned short st_ino;
  unsigned short st_mode;
  unsigned short st_nlink;
  unsigned short st_uid;
  unsigned short st_gid;
  unsigned short st_rdev;
  unsigned long st_size;
  unsigned long st_atime;
  unsigned long st_mtime;
  unsigned long st_ctime;
};

struct stat
{
  unsigned short st_dev;
  unsigned short __pad1;
  unsigned long st_ino;
  unsigned short st_mode;
  unsigned short st_nlink;
  unsigned short st_uid;
  unsigned short st_gid;
  unsigned short st_rdev;
  unsigned short __pad2;
  unsigned long st_size;
  unsigned long st_blksize;
  unsigned long st_blocks;
  unsigned long st_atime;
  unsigned long __unused1;
  unsigned long st_mtime;
  unsigned long __unused2;
  unsigned long st_ctime;
  unsigned long __unused3;
  unsigned long __unused4;
  unsigned long __unused5;
};




struct stat64
{
  unsigned short st_dev;
  unsigned char __pad0[10];


  unsigned long __st_ino;

  unsigned int st_mode;
  unsigned int st_nlink;

  unsigned long st_uid;
  unsigned long st_gid;

  unsigned short st_rdev;
  unsigned char __pad3[10];

  long long st_size;
  unsigned long st_blksize;

  unsigned long st_blocks;
  unsigned long __pad4;

  unsigned long st_atime;
  unsigned long __pad5;

  unsigned long st_mtime;
  unsigned long __pad6;

  unsigned long st_ctime;
  unsigned long __pad7;

  unsigned long long st_ino;
};






extern char *___strtok;
extern char *strpbrk (const char *, const char *);
extern char *strtok (char *, const char *);
extern char *strsep (char **, const char *);
extern __kernel_size_t strspn (const char *, const char *);







static inline char *
strcpy (char *dest, const char *src)
{
  int d0, d1, d2;
  __asm__ __volatile__ ("1:\tlodsb\n\t"
			"stosb\n\t"
			"testb %%al,%%al\n\t"
			"jne 1b":"=&S" (d0), "=&D" (d1), "=&a" (d2):"0" (src),
			"1" (dest):"memory");
  return dest;
}


static inline char *
strncpy (char *dest, const char *src, size_t count)
{
  int d0, d1, d2, d3;
  __asm__ __volatile__ ("1:\tdecl %2\n\t"
			"js 2f\n\t"
			"lodsb\n\t"
			"stosb\n\t"
			"testb %%al,%%al\n\t"
			"jne 1b\n\t"
			"rep\n\t"
			"stosb\n"
			"2:":"=&S" (d0), "=&D" (d1), "=&c" (d2),
			"=&a" (d3):"0" (src), "1" (dest),
			"2" (count):"memory");
  return dest;
}


static inline char *
strcat (char *dest, const char *src)
{
  int d0, d1, d2, d3;
  __asm__ __volatile__ ("repne\n\t"
			"scasb\n\t"
			"decl %1\n"
			"1:\tlodsb\n\t"
			"stosb\n\t"
			"testb %%al,%%al\n\t"
			"jne 1b":"=&S" (d0), "=&D" (d1), "=&a" (d2),
			"=&c" (d3):"0" (src), "1" (dest), "2" (0),
			"3" (0xffffffff):"memory");
  return dest;
}


static inline char *
strncat (char *dest, const char *src, size_t count)
{
  int d0, d1, d2, d3;
  __asm__ __volatile__ ("repne\n\t"
			"scasb\n\t"
			"decl %1\n\t"
			"movl %8,%3\n"
			"1:\tdecl %3\n\t"
			"js 2f\n\t"
			"lodsb\n\t"
			"stosb\n\t"
			"testb %%al,%%al\n\t"
			"jne 1b\n"
			"2:\txorl %2,%2\n\t"
			"stosb":"=&S" (d0), "=&D" (d1), "=&a" (d2),
			"=&c" (d3):"0" (src), "1" (dest), "2" (0),
			"3" (0xffffffff), "g" (count):"memory");
  return dest;
}


static inline int
strcmp (const char *cs, const char *ct)
{
  int d0, d1;
  register int __res;
  __asm__ __volatile__ ("1:\tlodsb\n\t"
			"scasb\n\t"
			"jne 2f\n\t"
			"testb %%al,%%al\n\t"
			"jne 1b\n\t"
			"xorl %%eax,%%eax\n\t"
			"jmp 3f\n"
			"2:\tsbbl %%eax,%%eax\n\t"
			"orb $1,%%al\n"
			"3:":"=a" (__res), "=&S" (d0), "=&D" (d1):"1" (cs),
			"2" (ct));
  return __res;
}


static inline int
strncmp (const char *cs, const char *ct, size_t count)
{
  register int __res;
  int d0, d1, d2;
  __asm__ __volatile__ ("1:\tdecl %3\n\t"
			"js 2f\n\t"
			"lodsb\n\t"
			"scasb\n\t"
			"jne 3f\n\t"
			"testb %%al,%%al\n\t"
			"jne 1b\n"
			"2:\txorl %%eax,%%eax\n\t"
			"jmp 4f\n"
			"3:\tsbbl %%eax,%%eax\n\t"
			"orb $1,%%al\n"
			"4:":"=a" (__res), "=&S" (d0), "=&D" (d1),
			"=&c" (d2):"1" (cs), "2" (ct), "3" (count));
  return __res;
}


static inline char *
strchr (const char *s, int c)
{
  int d0;
  register char *__res;
  __asm__ __volatile__ ("movb %%al,%%ah\n"
			"1:\tlodsb\n\t"
			"cmpb %%ah,%%al\n\t"
			"je 2f\n\t"
			"testb %%al,%%al\n\t"
			"jne 1b\n\t"
			"movl $1,%1\n"
			"2:\tmovl %1,%0\n\t"
			"decl %0":"=a" (__res), "=&S" (d0):"1" (s), "0" (c));
  return __res;
}


static inline char *
strrchr (const char *s, int c)
{
  int d0, d1;
  register char *__res;
  __asm__ __volatile__ ("movb %%al,%%ah\n"
			"1:\tlodsb\n\t"
			"cmpb %%ah,%%al\n\t"
			"jne 2f\n\t"
			"leal -1(%%esi),%0\n"
			"2:\ttestb %%al,%%al\n\t"
			"jne 1b":"=g" (__res), "=&S" (d0), "=&a" (d1):"0" (0),
			"1" (s), "2" (c));
  return __res;
}


static inline size_t
strlen (const char *s)
{
  int d0;
  register int __res;
  __asm__ __volatile__ ("repne\n\t"
			"scasb\n\t"
			"notl %0\n\t"
			"decl %0":"=c" (__res), "=&D" (d0):"1" (s), "a" (0),
			"0" (0xffffffff));
  return __res;
}

static inline void *
__memcpy (void *to, const void *from, size_t n)
{
  int d0, d1, d2;
  __asm__ __volatile__ ("rep ; movsl\n\t"
			"testb $2,%b4\n\t"
			"je 1f\n\t"
			"movsw\n"
			"1:\ttestb $1,%b4\n\t"
			"je 2f\n\t"
			"movsb\n"
			"2:":"=&c" (d0), "=&D" (d1), "=&S" (d2):"0" (n / 4),
			"q" (n), "1" ((long) to), "2" ((long) from):"memory");
  return (to);
}





static inline void *
__constant_memcpy (void *to, const void *from, size_t n)
{
  switch (n)
    {
    case 0:
      return to;
    case 1:
      *(unsigned char *) to = *(const unsigned char *) from;
      return to;
    case 2:
      *(unsigned short *) to = *(const unsigned short *) from;
      return to;
    case 3:
      *(unsigned short *) to = *(const unsigned short *) from;
      *(2 + (unsigned char *) to) = *(2 + (const unsigned char *) from);
      return to;
    case 4:
      *(unsigned long *) to = *(const unsigned long *) from;
      return to;
    case 6:
      *(unsigned long *) to = *(const unsigned long *) from;
      *(2 + (unsigned short *) to) = *(2 + (const unsigned short *) from);
      return to;
    case 8:
      *(unsigned long *) to = *(const unsigned long *) from;
      *(1 + (unsigned long *) to) = *(1 + (const unsigned long *) from);
      return to;
    case 12:
      *(unsigned long *) to = *(const unsigned long *) from;
      *(1 + (unsigned long *) to) = *(1 + (const unsigned long *) from);
      *(2 + (unsigned long *) to) = *(2 + (const unsigned long *) from);
      return to;
    case 16:
      *(unsigned long *) to = *(const unsigned long *) from;
      *(1 + (unsigned long *) to) = *(1 + (const unsigned long *) from);
      *(2 + (unsigned long *) to) = *(2 + (const unsigned long *) from);
      *(3 + (unsigned long *) to) = *(3 + (const unsigned long *) from);
      return to;
    case 20:
      *(unsigned long *) to = *(const unsigned long *) from;
      *(1 + (unsigned long *) to) = *(1 + (const unsigned long *) from);
      *(2 + (unsigned long *) to) = *(2 + (const unsigned long *) from);
      *(3 + (unsigned long *) to) = *(3 + (const unsigned long *) from);
      *(4 + (unsigned long *) to) = *(4 + (const unsigned long *) from);
      return to;
    }







  {
    int d0, d1, d2;
    switch (n % 4)
      {
      case 0:
      __asm__ __volatile__ ("rep ; movsl" "": "=&c" (d0), "=&D" (d1), "=&S" (d2): "0" (n / 4), "1" ((long) to), "2" ((long) from):"memory");;
	return to;
      case 1:
      __asm__ __volatile__ ("rep ; movsl" "\n\tmovsb": "=&c" (d0), "=&D" (d1), "=&S" (d2): "0" (n / 4), "1" ((long) to), "2" ((long) from):"memory");;
	return to;
      case 2:
      __asm__ __volatile__ ("rep ; movsl" "\n\tmovsw": "=&c" (d0), "=&D" (d1), "=&S" (d2): "0" (n / 4), "1" ((long) to), "2" ((long) from):"memory");;
	return to;
      default:
      __asm__ __volatile__ ("rep ; movsl" "\n\tmovsw\n\tmovsb": "=&c" (d0), "=&D" (d1), "=&S" (d2): "0" (n / 4), "1" ((long) to), "2" ((long) from):"memory");;
	return to;
      }
  }


}


extern void __struct_cpy_bug (void);

static inline void *
memmove (void *dest, const void *src, size_t n)
{
  int d0, d1, d2;
  if (dest < src)
    __asm__ __volatile__ ("rep\n\t"
			  "movsb":"=&c" (d0), "=&S" (d1), "=&D" (d2):"0" (n),
			  "1" (src), "2" (dest):"memory");
  else
__asm__ __volatile__ ("std\n\t" "rep\n\t" "movsb\n\t" "cld": "=&c" (d0), "=&S" (d1), "=&D" (d2): "0" (n), "1" (n - 1 + (const char *) src), "2" (n - 1 + (char *) dest):"memory");
  return dest;
}




static inline void *
memchr (const void *cs, int c, size_t count)
{
  int d0;
  register void *__res;
  if (!count)
    return ((void *) 0);
  __asm__ __volatile__ ("repne\n\t"
			"scasb\n\t"
			"je 1f\n\t"
			"movl $1,%0\n"
			"1:\tdecl %0":"=D" (__res), "=&c" (d0):"a" (c),
			"0" (cs), "1" (count));
  return __res;
}

static inline void *
__memset_generic (void *s, char c, size_t count)
{
  int d0, d1;
  __asm__ __volatile__ ("rep\n\t"
			"stosb":"=&c" (d0), "=&D" (d1):"a" (c), "1" (s),
			"0" (count):"memory");
  return s;
}


static inline void *
__constant_c_memset (void *s, unsigned long c, size_t count)
{
  int d0, d1;
  __asm__ __volatile__ ("rep ; stosl\n\t"
			"testb $2,%b3\n\t"
			"je 1f\n\t"
			"stosw\n"
			"1:\ttestb $1,%b3\n\t"
			"je 2f\n\t"
			"stosb\n"
			"2:":"=&c" (d0), "=&D" (d1):"a" (c), "q" (count),
			"0" (count / 4), "1" ((long) s):"memory");
  return (s);
}



static inline size_t
strnlen (const char *s, size_t count)
{
  int d0;
  register int __res;
  __asm__ __volatile__ ("movl %2,%0\n\t"
			"jmp 2f\n"
			"1:\tcmpb $0,(%0)\n\t"
			"je 3f\n\t"
			"incl %0\n"
			"2:\tdecl %1\n\t"
			"cmpl $-1,%1\n\t"
			"jne 1b\n"
			"3:\tsubl %2,%0":"=a" (__res), "=&d" (d0):"c" (s),
			"1" (count));
  return __res;
}




extern char *strstr (const char *cs, const char *ct);





static inline void *
__constant_c_and_count_memset (void *s, unsigned long pattern, size_t count)
{
  switch (count)
    {
    case 0:
      return s;
    case 1:
      *(unsigned char *) s = pattern;
      return s;
    case 2:
      *(unsigned short *) s = pattern;
      return s;
    case 3:
      *(unsigned short *) s = pattern;
      *(2 + (unsigned char *) s) = pattern;
      return s;
    case 4:
      *(unsigned long *) s = pattern;
      return s;
    }







  {
    int d0, d1;
    switch (count % 4)
      {
      case 0:
      __asm__ __volatile__ ("rep ; stosl" "": "=&c" (d0), "=&D" (d1): "a" (pattern), "0" (count / 4), "1" ((long) s):"memory");
	return s;
      case 1:
      __asm__ __volatile__ ("rep ; stosl" "\n\tstosb": "=&c" (d0), "=&D" (d1): "a" (pattern), "0" (count / 4), "1" ((long) s):"memory");
	return s;
      case 2:
      __asm__ __volatile__ ("rep ; stosl" "\n\tstosw": "=&c" (d0), "=&D" (d1): "a" (pattern), "0" (count / 4), "1" ((long) s):"memory");
	return s;
      default:
      __asm__ __volatile__ ("rep ; stosl" "\n\tstosw\n\tstosb": "=&c" (d0), "=&D" (d1): "a" (pattern), "0" (count / 4), "1" ((long) s):"memory");
	return s;
      }
  }


}


static inline void *
memscan (void *addr, int c, size_t size)
{
  if (!size)
    return addr;
__asm__ ("repnz; scasb\n\t" "jnz 1f\n\t" "dec %%edi\n" "1:": "=D" (addr), "=c" (size):"0" (addr), "1" (size),
	   "a"
	   (c));
  return addr;
}



extern int strnicmp (const char *, const char *, __kernel_size_t);

extern int __builtin_memcmp (const void *, const void *, __kernel_size_t);





struct poll_table_struct;

struct files_stat_struct
{
  int nr_files;
  int nr_free_files;
  int max_files;
};
extern struct files_stat_struct files_stat;

struct inodes_stat_t
{
  int nr_inodes;
  int nr_unused;
  int dummy[5];
};
extern struct inodes_stat_t inodes_stat;

extern int leases_enable, dir_notify_enable, lease_break_time;





struct rw_semaphore;






struct rwsem_waiter;

extern struct rw_semaphore *rwsem_down_read_failed (struct rw_semaphore *sem)
  __attribute__ ((regparm (3)));
extern struct rw_semaphore *rwsem_down_write_failed (struct rw_semaphore *sem)
  __attribute__ ((regparm (3)));
extern struct rw_semaphore *rwsem_wake (struct rw_semaphore *)
  __attribute__ ((regparm (3)));




struct rw_semaphore
{
  signed long count;






  spinlock_t wait_lock;
  struct list_head wait_list;



};

static inline void
init_rwsem (struct rw_semaphore *sem)
{
  sem->count = 0x00000000;
  do
    {
    }
  while (0);
  do
    {
      (&sem->wait_list)->next = (&sem->wait_list);
      (&sem->wait_list)->prev = (&sem->wait_list);
    }
  while (0);



}




static inline void
__down_read (struct rw_semaphore *sem)
{
  __asm__ __volatile__ ("# beginning down_read\n\t"
			"" "  incl      (%%eax)\n\t"
			"  js        2f\n\t"
			"1:\n\t"
			".subsection 1\n\t" "" ".ifndef " ".text.lock."
			"tmalloc" "\n\t" ".text.lock." "tmalloc" ":\n\t"
			".endif\n\t" "2:\n\t" "  pushl     %%ecx\n\t"
			"  pushl     %%edx\n\t"
			"  call      rwsem_down_read_failed\n\t"
			"  popl      %%edx\n\t" "  popl      %%ecx\n\t"
			"  jmp       1b\n" ".previous\n\t"
			"# ending down_read\n\t":"+m" (sem->
						       count):"a"
			(sem):"memory", "cc");
}




static inline int
__down_read_trylock (struct rw_semaphore *sem)
{
  __s32 result, tmp;
  __asm__ __volatile__ ("# beginning __down_read_trylock\n\t"
			"  movl      %0,%1\n\t"
			"1:\n\t"
			"  movl	     %1,%2\n\t"
			"  addl      %3,%2\n\t"
			"  jle	     2f\n\t"
			"" "  cmpxchgl  %2,%0\n\t"
			"  jnz	     1b\n\t"
			"2:\n\t"
			"# ending __down_read_trylock\n\t":"+m" (sem->
								 count),
			"=&a" (result),
			"=&r" (tmp):"i" (0x00000001):"memory", "cc");
  return result >= 0 ? 1 : 0;
}




static inline void
__down_write (struct rw_semaphore *sem)
{
  int tmp;

  tmp = ((-0x00010000) + 0x00000001);
  __asm__ __volatile__ ("# beginning down_write\n\t"
			"" "  xadd      %0,(%%eax)\n\t"
			"  testl     %0,%0\n\t"
			"  jnz       2f\n\t"
			"1:\n\t"
			".subsection 1\n\t" "" ".ifndef " ".text.lock."
			"tmalloc" "\n\t" ".text.lock." "tmalloc" ":\n\t"
			".endif\n\t" "2:\n\t" "  pushl     %%ecx\n\t"
			"  call      rwsem_down_write_failed\n\t"
			"  popl      %%ecx\n\t" "  jmp       1b\n"
			".previous\n\t" "# ending down_write":"+d" (tmp),
			"+m" (sem->count):"a" (sem):"memory", "cc");
}




static inline int
__down_write_trylock (struct rw_semaphore *sem)
{
  signed long ret =
    ((__typeof__ (*(&sem->count)))
     __cmpxchg ((&sem->count), (unsigned long) (0x00000000),
		(unsigned long) (((-0x00010000) + 0x00000001)),
		sizeof (*(&sem->count))));


  if (ret == 0x00000000)
    return 1;
  return 0;
}




static inline void
__up_read (struct rw_semaphore *sem)
{
  __s32 tmp = -0x00000001;
  __asm__ __volatile__ ("# beginning __up_read\n\t"
			"" "  xadd      %%edx,(%%eax)\n\t"
			"  js        2f\n\t"
			"1:\n\t"
			".subsection 1\n\t" "" ".ifndef " ".text.lock."
			"tmalloc" "\n\t" ".text.lock." "tmalloc" ":\n\t"
			".endif\n\t" "2:\n\t" "  decw      %%dx\n\t"
			"  jnz       1b\n\t" "  pushl     %%ecx\n\t"
			"  call      rwsem_wake\n\t" "  popl      %%ecx\n\t"
			"  jmp       1b\n" ".previous\n\t"
			"# ending __up_read\n":"+m" (sem->count),
			"+d" (tmp):"a" (sem):"memory", "cc");
}




static inline void
__up_write (struct rw_semaphore *sem)
{
  __asm__ __volatile__ ("# beginning __up_write\n\t"
			"  movl      %2,%%edx\n\t"
			"" "  xaddl     %%edx,(%%eax)\n\t"
			"  jnz       2f\n\t"
			"1:\n\t"
			".subsection 1\n\t" "" ".ifndef " ".text.lock."
			"tmalloc" "\n\t" ".text.lock." "tmalloc" ":\n\t"
			".endif\n\t" "2:\n\t" "  decw      %%dx\n\t"
			"  jnz       1b\n\t" "  pushl     %%ecx\n\t"
			"  call      rwsem_wake\n\t" "  popl      %%ecx\n\t"
			"  jmp       1b\n" ".previous\n\t"
			"# ending __up_write\n":"+m" (sem->count):"a" (sem),
			"i" (-((-0x00010000) + 0x00000001)):"memory", "cc",
			"edx");
}




static inline void
rwsem_atomic_add (int delta, struct rw_semaphore *sem)
{
  __asm__ __volatile__ ("" "addl %1,%0":"=m" (sem->count):"ir" (delta),
			"m" (sem->count));
}




static inline int
rwsem_atomic_update (int delta, struct rw_semaphore *sem)
{
  int tmp = delta;

  __asm__ __volatile__ ("" "xadd %0,(%2)":"+r" (tmp),
			"=m" (sem->count):"r" (sem),
			"m" (sem->count):"memory");

  return tmp + delta;
}



static inline void
down_read (struct rw_semaphore *sem)
{
  ;
  __down_read (sem);
  ;
}




static inline int
down_read_trylock (struct rw_semaphore *sem)
{
  int ret;
  ;
  ret = __down_read_trylock (sem);
  ;
  return ret;
}




static inline void
down_write (struct rw_semaphore *sem)
{
  ;
  __down_write (sem);
  ;
}




static inline int
down_write_trylock (struct rw_semaphore *sem)
{
  int ret;
  ;
  ret = __down_write_trylock (sem);
  ;
  return ret;
}




static inline void
up_read (struct rw_semaphore *sem)
{
  ;
  __up_read (sem);
  ;
}




static inline void
up_write (struct rw_semaphore *sem)
{
  ;
  __up_write (sem);
  ;
}



struct semaphore
{
  atomic_t count;
  int sleepers;
  wait_queue_head_t wait;



};

static inline void
sema_init (struct semaphore *sem, int val)
{






  (((&sem->count)->counter) = (val));
  sem->sleepers = 0;
  init_waitqueue_head (&sem->wait);



}

static inline void
init_MUTEX (struct semaphore *sem)
{
  sema_init (sem, 1);
}

static inline void
init_MUTEX_LOCKED (struct semaphore *sem)
{
  sema_init (sem, 0);
}

__attribute__ ((regparm (0)))
     void __down_failed (void);
__attribute__ ((regparm (0)))
     int __down_failed_interruptible (void);
__attribute__ ((regparm (0)))
     int __down_failed_trylock (void);
__attribute__ ((regparm (0)))
     void __up_wakeup (void);

__attribute__ ((regparm (0)))
     void __down (struct semaphore *sem);
__attribute__ ((regparm (0)))
     int __down_interruptible (struct semaphore *sem);
__attribute__ ((regparm (0)))
     int __down_trylock (struct semaphore *sem);
__attribute__ ((regparm (0)))
     void __up (struct semaphore *sem);






     static inline void down (struct semaphore *sem)
{




  __asm__ __volatile__ ("# atomic down operation\n\t"
			"" "decl %0\n\t"
			"js 2f\n"
			"1:\n"
			".subsection 1\n\t" "" ".ifndef " ".text.lock."
			"tmalloc" "\n\t" ".text.lock." "tmalloc" ":\n\t"
			".endif\n\t" "2:\tcall __down_failed\n\t" "jmp 1b\n"
			".previous\n\t":"=m" (sem->count):"c" (sem):"memory");
}





static inline int
down_interruptible (struct semaphore *sem)
{
  int result;





  __asm__ __volatile__ ("# atomic interruptible down operation\n\t"
			"" "decl %1\n\t"
			"js 2f\n\t"
			"xorl %0,%0\n"
			"1:\n"
			".subsection 1\n\t" "" ".ifndef " ".text.lock."
			"tmalloc" "\n\t" ".text.lock." "tmalloc" ":\n\t"
			".endif\n\t"
			"2:\tcall __down_failed_interruptible\n\t" "jmp 1b\n"
			".previous\n\t":"=a" (result),
			"=m" (sem->count):"c" (sem):"memory");
  return result;
}





static inline int
down_trylock (struct semaphore *sem)
{
  int result;





  __asm__ __volatile__ ("# atomic interruptible down operation\n\t"
			"" "decl %1\n\t"
			"js 2f\n\t"
			"xorl %0,%0\n"
			"1:\n"
			".subsection 1\n\t" "" ".ifndef " ".text.lock."
			"tmalloc" "\n\t" ".text.lock." "tmalloc" ":\n\t"
			".endif\n\t" "2:\tcall __down_failed_trylock\n\t"
			"jmp 1b\n" ".previous\n\t":"=a" (result),
			"=m" (sem->count):"c" (sem):"memory");
  return result;
}







static inline void
up (struct semaphore *sem)
{



  __asm__ __volatile__ ("# atomic up operation\n\t"
			"" "incl %0\n\t"
			"jle 2f\n"
			"1:\n"
			".subsection 1\n\t" "" ".ifndef " ".text.lock."
			"tmalloc" "\n\t" ".text.lock." "tmalloc" ":\n\t"
			".endif\n\t" "2:\tcall __up_wakeup\n\t" "jmp 1b\n"
			".previous\n\t" ".subsection 0\n":"=m" (sem->
								count):"c"
			(sem):"memory");
}

static inline int
sem_getcount (struct semaphore *sem)
{
  return ((&sem->count)->counter);
}




extern void update_atime (struct inode *);
extern void update_mctime (struct inode *);


extern void buffer_init (unsigned long);
extern void inode_init (unsigned long);
extern void mnt_init (unsigned long);
extern void files_init (unsigned long mempages);


enum bh_state_bits
{
  BH_Uptodate,
  BH_Dirty,
  BH_Lock,
  BH_Req,
  BH_Mapped,
  BH_New,
  BH_Async,
  BH_Wait_IO,
  BH_Launder,
  BH_Attached,
  BH_JBD,
  BH_Sync,
  BH_Delay,

  BH_PrivateStart,


};

struct buffer_head
{

  struct buffer_head *b_next;
  unsigned long b_blocknr;
  unsigned short b_size;
  unsigned short b_list;
  kdev_t b_dev;

  atomic_t b_count;
  kdev_t b_rdev;
  unsigned long b_state;
  unsigned long b_flushtime;

  struct buffer_head *b_next_free;
  struct buffer_head *b_prev_free;
  struct buffer_head *b_this_page;
  struct buffer_head *b_reqnext;

  struct buffer_head **b_pprev;
  char *b_data;
  struct page *b_page;
  void (*b_end_io) (struct buffer_head * bh, int uptodate);
  void *b_private;

  unsigned long b_rsector;
  wait_queue_head_t b_wait;

  struct list_head b_inode_buffers;
};

typedef void (bh_end_io_t) (struct buffer_head * bh, int uptodate);
void init_buffer (struct buffer_head *, bh_end_io_t *, void *);

extern void set_bh_page (struct buffer_head *bh, struct page *page,
			 unsigned long offset);









struct pipe_inode_info
{
  wait_queue_head_t wait;
  char *base;
  unsigned int len;
  unsigned int start;
  unsigned int readers;
  unsigned int writers;
  unsigned int waiting_readers;
  unsigned int waiting_writers;
  unsigned int r_counter;
  unsigned int w_counter;
};

void pipe_wait (struct inode *inode);

struct inode *pipe_new (struct inode *inode);








struct minix_inode_info
{
  union
  {
    __u16 i1_data[16];
    __u32 i2_data[16];
  } u;
};



struct ext2_inode_info
{
  __u32 i_data[15];
  __u32 i_flags;
  __u32 i_faddr;
  __u8 i_frag_no;
  __u8 i_frag_size;
  __u16 i_state;
  __u32 i_file_acl;
  __u32 i_dir_acl;
  __u32 i_dtime;
  __u32 i_block_group;
  __u32 i_next_alloc_block;
  __u32 i_next_alloc_goal;
  __u32 i_prealloc_block;
  __u32 i_prealloc_count;
  __u32 i_dir_start_lookup;
};



struct ext3_inode_info
{
  __u32 i_data[15];
  __u32 i_flags;






  __u32 i_file_acl;
  __u32 i_dir_acl;
  __u32 i_dtime;
  __u32 i_block_group;
  __u32 i_state;
  __u32 i_next_alloc_block;
  __u32 i_next_alloc_goal;




  __u32 i_dir_start_lookup;

  struct list_head i_orphan;

  loff_t i_disksize;

  struct rw_semaphore truncate_sem;
};





struct hpfs_inode_info
{
  unsigned long mmu_private;
  ino_t i_parent_dir;
  unsigned i_dno;
  unsigned i_dpos;
  unsigned i_dsubdno;
  unsigned i_file_sec;
  unsigned i_disk_sec;
  unsigned i_n_secs;
  unsigned i_ea_size;
  unsigned i_conv:2;
  unsigned i_ea_mode:1;
  unsigned i_ea_uid:1;
  unsigned i_ea_gid:1;
  unsigned i_dirty:1;
  struct semaphore i_sem;
  loff_t **i_rddir_off;
};








struct ntfs_attribute;
struct ntfs_sb_info;




typedef u8 ntfs_u8;
typedef u16 ntfs_u16;
typedef u32 ntfs_u32;
typedef u64 ntfs_u64;
typedef s8 ntfs_s8;
typedef s16 ntfs_s16;
typedef s32 ntfs_s32;
typedef s64 ntfs_s64;




typedef __kernel_mode_t ntmode_t;



typedef uid_t ntfs_uid_t;



typedef gid_t ntfs_gid_t;



typedef __kernel_size_t ntfs_size_t;



typedef __kernel_time_t ntfs_time_t;





typedef u16 ntfs_wchar_t;




typedef s64 ntfs_offset_t;




typedef u64 ntfs_time64_t;

typedef s32 ntfs_cluster_t;



struct ntfs_inode_info
{
  struct ntfs_sb_info *vol;
  unsigned long i_number;
  __u16 sequence_number;
  unsigned char *attr;
  int attr_count;
  struct ntfs_attribute *attrs;
  int record_count;
  int *records;

  union
  {
    struct
    {
      int recordsize;
      int clusters_per_record;
    } index;
  } u;
};









struct msdos_inode_info
{
  unsigned long mmu_private;
  int i_start;
  int i_logstart;
  int i_attrs;
  int i_ctime_ms;
  loff_t i_pos;
  struct inode *i_fat_inode;
  struct list_head i_fat_hash;
};



struct dir_locking_info
{
  wait_queue_head_t p;
  short int looking;
  short int creating;



  long pid;

};

struct umsdos_inode_info
{
  struct msdos_inode_info msdos_info;
  struct dir_locking_info dir_info;
  int i_patched;
  int i_is_hlink;
  off_t pos;
};





enum isofs_file_format
{
  isofs_file_normal = 0,
  isofs_file_sparse = 1,
  isofs_file_compressed = 2,
};




struct iso_inode_info
{
  unsigned int i_first_extent;
  unsigned char i_file_format;
  unsigned char i_format_parm[3];
  unsigned long i_next_section_ino;
  off_t i_section_size;
};











enum rpc_auth_flavor
{
  RPC_AUTH_NULL = 0,
  RPC_AUTH_UNIX = 1,
  RPC_AUTH_SHORT = 2,
  RPC_AUTH_DES = 3,
  RPC_AUTH_KRB = 4,
};

enum rpc_msg_type
{
  RPC_CALL = 0,
  RPC_REPLY = 1
};

enum rpc_reply_stat
{
  RPC_MSG_ACCEPTED = 0,
  RPC_MSG_DENIED = 1
};

enum rpc_accept_stat
{
  RPC_SUCCESS = 0,
  RPC_PROG_UNAVAIL = 1,
  RPC_PROG_MISMATCH = 2,
  RPC_PROC_UNAVAIL = 3,
  RPC_GARBAGE_ARGS = 4,
  RPC_SYSTEM_ERR = 5
};

enum rpc_reject_stat
{
  RPC_MISMATCH = 0,
  RPC_AUTH_ERROR = 1
};

enum rpc_auth_stat
{
  RPC_AUTH_OK = 0,
  RPC_AUTH_BADCRED = 1,
  RPC_AUTH_REJECTEDCRED = 2,
  RPC_AUTH_BADVERF = 3,
  RPC_AUTH_REJECTEDVERF = 4,
  RPC_AUTH_TOOWEAK = 5
};


enum nfs_stat
{
  NFS_OK = 0,
  NFSERR_PERM = 1,
  NFSERR_NOENT = 2,
  NFSERR_IO = 5,
  NFSERR_NXIO = 6,
  NFSERR_EAGAIN = 11,
  NFSERR_ACCES = 13,
  NFSERR_EXIST = 17,
  NFSERR_XDEV = 18,
  NFSERR_NODEV = 19,
  NFSERR_NOTDIR = 20,
  NFSERR_ISDIR = 21,
  NFSERR_INVAL = 22,
  NFSERR_FBIG = 27,
  NFSERR_NOSPC = 28,
  NFSERR_ROFS = 30,
  NFSERR_MLINK = 31,
  NFSERR_OPNOTSUPP = 45,
  NFSERR_NAMETOOLONG = 63,
  NFSERR_NOTEMPTY = 66,
  NFSERR_DQUOT = 69,
  NFSERR_STALE = 70,
  NFSERR_REMOTE = 71,
  NFSERR_WFLUSH = 99,
  NFSERR_BADHANDLE = 10001,
  NFSERR_NOT_SYNC = 10002,
  NFSERR_BAD_COOKIE = 10003,
  NFSERR_NOTSUPP = 10004,
  NFSERR_TOOSMALL = 10005,
  NFSERR_SERVERFAULT = 10006,
  NFSERR_BADTYPE = 10007,
  NFSERR_JUKEBOX = 10008
};



enum nfs_ftype
{
  NFNON = 0,
  NFREG = 1,
  NFDIR = 2,
  NFBLK = 3,
  NFCHR = 4,
  NFLNK = 5,
  NFSOCK = 6,
  NFBAD = 7,
  NFFIFO = 8
};






struct nfs_fh
{
  unsigned short size;
  unsigned char data[64];
};

enum nfs3_stable_how
{
  NFS_UNSTABLE = 0,
  NFS_DATA_SYNC = 1,
  NFS_FILE_SYNC = 2
};





struct nfs_inode_info
{



  __u64 fileid;




  struct nfs_fh fh;




  unsigned short flags;

  unsigned long read_cache_jiffies;
  __u64 read_cache_ctime;
  __u64 read_cache_mtime;
  __u64 read_cache_isize;
  unsigned long attrtimeo;
  unsigned long attrtimeo_timestamp;





  unsigned long cache_mtime_jiffies;





  __u32 cookieverf[2];




  struct list_head read;
  struct list_head dirty;
  struct list_head commit;
  struct list_head writeback;

  unsigned int nread, ndirty, ncommit, npages;


  struct rpc_cred *mm_cred;
};

struct nfs_lock_info
{
  u32 state;
  u32 flags;
  struct nlm_host *host;
};








struct sysv_inode_info
{
  u32 i_data[10 + 1 + 1 + 1];




  u32 i_dir_start_lookup;
};

















struct exec
{
  unsigned long a_info;
  unsigned a_text;
  unsigned a_data;
  unsigned a_bss;
  unsigned a_syms;
  unsigned a_entry;
  unsigned a_trsize;
  unsigned a_drsize;
};





enum machine_type
{



  M_OLDSUN2 = 0,




  M_68010 = 1,




  M_68020 = 2,




  M_SPARC = 3,


  M_386 = 100,
  M_MIPS1 = 151,
  M_MIPS2 = 152
};

struct nlist
{
  union
  {
    char *n_name;
    struct nlist *n_next;
    long n_strx;
  } n_un;
  unsigned char n_type;
  char n_other;
  short n_desc;
  unsigned long n_value;
};

struct relocation_info
{

  int r_address;

  unsigned int r_symbolnum:24;



  unsigned int r_pcrel:1;


  unsigned int r_length:2;






  unsigned int r_extern:1;







  unsigned int r_pad:4;

};





struct timespec
{
  time_t tv_sec;
  long tv_nsec;
};

static __inline__ unsigned long
timespec_to_jiffies (struct timespec *value)
{
  unsigned long sec = value->tv_sec;
  long nsec = value->tv_nsec;

  if (sec >= (((~0UL >> 1) - 1) / 100))
    return ((~0UL >> 1) - 1);
  nsec += 1000000000L / 100 - 1;
  nsec /= 1000000000L / 100;
  return 100 * sec + nsec;
}

static __inline__ void
jiffies_to_timespec (unsigned long jiffies, struct timespec *value)
{
  value->tv_nsec = (jiffies % 100) * (1000000000L / 100);
  value->tv_sec = jiffies / 100;
}


static inline unsigned long
mktime (unsigned int year, unsigned int mon,
	unsigned int day, unsigned int hour,
	unsigned int min, unsigned int sec)
{
  if (0 >= (int) (mon -= 2))
    {
      mon += 12;
      year -= 1;
    }

  return ((((unsigned long) (year / 4 - year / 100 + year / 400 +
			     367 * mon / 12 + day) + year * 365 -
	    719499) * 24 + hour) * 60 + min) * 60 + sec;
}




struct timeval
{
  time_t tv_sec;
  suseconds_t tv_usec;
};

struct timezone
{
  int tz_minuteswest;
  int tz_dsttime;
};




extern void do_gettimeofday (struct timeval *tv);
extern void do_settimeofday (struct timeval *tv);

struct itimerspec
{
  struct timespec it_interval;
  struct timespec it_value;
};

struct itimerval
{
  struct timeval it_interval;
  struct timeval it_value;
};


struct affs_ext_key
{
  u32 ext;
  u32 key;
};




struct affs_inode_info
{
  u32 i_opencnt;
  struct semaphore i_link_lock;
  struct semaphore i_ext_lock;

  u32 i_blkcnt;
  u32 i_extcnt;
  u32 *i_lc;
  u32 i_lc_size;
  u32 i_lc_shift;
  u32 i_lc_mask;
  struct affs_ext_key *i_ac;
  u32 i_ext_last;
  struct buffer_head *i_ext_bh;
  unsigned long mmu_private;
  u32 i_protect;
  u32 i_lastalloc;
  int i_pa_cnt;

};



struct ufs_inode_info
{
  union
  {
    __u32 i_data[15];
    __u8 i_symlink[4 * 15];
  } i_u1;
  __u32 i_flags;
  __u32 i_gen;
  __u32 i_shadow;
  __u32 i_unused1;
  __u32 i_unused2;
  __u32 i_oeftflag;
  __u16 i_osync;
  __u32 i_lastfrag;
};



typedef int32_t efs_block_t;
typedef uint32_t efs_ino_t;






typedef union extent_u
{
  unsigned char raw[8];
  struct extent_s
  {
    unsigned int ex_magic:8;
    unsigned int ex_bn:24;
    unsigned int ex_length:8;
    unsigned int ex_offset:24;
  } cooked;
} efs_extent;

typedef struct edevs
{
  short odev;
  unsigned int ndev;
} efs_devs;





struct efs_dinode
{
  u_short di_mode;
  short di_nlink;
  u_short di_uid;
  u_short di_gid;
  int32_t di_size;
  int32_t di_atime;
  int32_t di_mtime;
  int32_t di_ctime;
  uint32_t di_gen;
  short di_numextents;
  u_char di_version;
  u_char di_spare;
  union di_addr
  {
    efs_extent di_extents[12];
    efs_devs di_dev;
  } di_u;
};


struct efs_inode_info
{
  int numextents;
  int lastextent;

  efs_extent extents[12];
};





typedef unsigned long long u_quad_t;

struct venus_dirent
{
  unsigned long d_fileno;
  unsigned short d_reclen;
  unsigned char d_type;
  unsigned char d_namlen;
  char d_name[255 + 1];
};

typedef u_long VolumeId;
typedef u_long VnodeId;
typedef u_long Unique_t;
typedef u_long FileVersion;




typedef struct ViceFid
{
  VolumeId Volume;
  VnodeId Vnode;
  Unique_t Unique;
} ViceFid;




static __inline__ ino_t
coda_f2i (struct ViceFid *fid)
{
  if (!fid)
    return 0;
  if (fid->Vnode == 0xfffffffe || fid->Vnode == 0xffffffff)
    return ((fid->Volume << 20) | (fid->Unique & 0xfffff));
  else
    return (fid->Unique + (fid->Vnode << 10) + (fid->Volume << 20));
}


typedef u_int32_t vuid_t;
typedef u_int32_t vgid_t;




struct coda_cred
{
  vuid_t cr_uid, cr_euid, cr_suid, cr_fsuid;
  vgid_t cr_groupid, cr_egid, cr_sgid, cr_fsgid;
};







enum coda_vtype
{ C_VNON, C_VREG, C_VDIR, C_VBLK, C_VCHR, C_VLNK, C_VSOCK, C_VFIFO, C_VBAD };

struct coda_vattr
{
  long va_type;
  u_short va_mode;
  short va_nlink;
  vuid_t va_uid;
  vgid_t va_gid;
  long va_fileid;
  u_quad_t va_size;
  long va_blocksize;
  struct timespec va_atime;
  struct timespec va_mtime;
  struct timespec va_ctime;
  u_long va_gen;
  u_long va_flags;
  u_quad_t va_rdev;
  u_quad_t va_bytes;
  u_quad_t va_filerev;
};




struct coda_statfs
{
  int32_t f_blocks;
  int32_t f_bfree;
  int32_t f_bavail;
  int32_t f_files;
  int32_t f_ffree;
};

struct coda_in_hdr
{
  unsigned long opcode;
  unsigned long unique;
  u_short pid;
  u_short pgid;
  u_short sid;
  struct coda_cred cred;
};


struct coda_out_hdr
{
  unsigned long opcode;
  unsigned long unique;
  unsigned long result;
};


struct coda_root_out
{
  struct coda_out_hdr oh;
  ViceFid VFid;
};

struct coda_root_in
{
  struct coda_in_hdr in;
};


struct coda_open_in
{
  struct coda_in_hdr ih;
  ViceFid VFid;
  int flags;
};

struct coda_open_out
{
  struct coda_out_hdr oh;
  u_quad_t dev;
  ino_t inode;
};



struct coda_store_in
{
  struct coda_in_hdr ih;
  ViceFid VFid;
  int flags;
};

struct coda_store_out
{
  struct coda_out_hdr out;
};


struct coda_release_in
{
  struct coda_in_hdr ih;
  ViceFid VFid;
  int flags;
};

struct coda_release_out
{
  struct coda_out_hdr out;
};


struct coda_close_in
{
  struct coda_in_hdr ih;
  ViceFid VFid;
  int flags;
};

struct coda_close_out
{
  struct coda_out_hdr out;
};


struct coda_ioctl_in
{
  struct coda_in_hdr ih;
  ViceFid VFid;
  int cmd;
  int len;
  int rwflag;
  char *data;
};

struct coda_ioctl_out
{
  struct coda_out_hdr oh;
  int len;
  caddr_t data;
};



struct coda_getattr_in
{
  struct coda_in_hdr ih;
  ViceFid VFid;
};

struct coda_getattr_out
{
  struct coda_out_hdr oh;
  struct coda_vattr attr;
};



struct coda_setattr_in
{
  struct coda_in_hdr ih;
  ViceFid VFid;
  struct coda_vattr attr;
};

struct coda_setattr_out
{
  struct coda_out_hdr out;
};


struct coda_access_in
{
  struct coda_in_hdr ih;
  ViceFid VFid;
  int flags;
};

struct coda_access_out
{
  struct coda_out_hdr out;
};







struct coda_lookup_in
{
  struct coda_in_hdr ih;
  ViceFid VFid;
  int name;
  int flags;
};

struct coda_lookup_out
{
  struct coda_out_hdr oh;
  ViceFid VFid;
  int vtype;
};



struct coda_create_in
{
  struct coda_in_hdr ih;
  ViceFid VFid;
  struct coda_vattr attr;
  int excl;
  int mode;
  int name;
};

struct coda_create_out
{
  struct coda_out_hdr oh;
  ViceFid VFid;
  struct coda_vattr attr;
};



struct coda_remove_in
{
  struct coda_in_hdr ih;
  ViceFid VFid;
  int name;
};

struct coda_remove_out
{
  struct coda_out_hdr out;
};


struct coda_link_in
{
  struct coda_in_hdr ih;
  ViceFid sourceFid;
  ViceFid destFid;
  int tname;
};

struct coda_link_out
{
  struct coda_out_hdr out;
};



struct coda_rename_in
{
  struct coda_in_hdr ih;
  ViceFid sourceFid;
  int srcname;
  ViceFid destFid;
  int destname;
};

struct coda_rename_out
{
  struct coda_out_hdr out;
};


struct coda_mkdir_in
{
  struct coda_in_hdr ih;
  ViceFid VFid;
  struct coda_vattr attr;
  int name;
};

struct coda_mkdir_out
{
  struct coda_out_hdr oh;
  ViceFid VFid;
  struct coda_vattr attr;
};



struct coda_rmdir_in
{
  struct coda_in_hdr ih;
  ViceFid VFid;
  int name;
};

struct coda_rmdir_out
{
  struct coda_out_hdr out;
};


struct coda_symlink_in
{
  struct coda_in_hdr ih;
  ViceFid VFid;
  int srcname;
  struct coda_vattr attr;
  int tname;
};

struct coda_symlink_out
{
  struct coda_out_hdr out;
};


struct coda_readlink_in
{
  struct coda_in_hdr ih;
  ViceFid VFid;
};

struct coda_readlink_out
{
  struct coda_out_hdr oh;
  int count;
  caddr_t data;
};



struct coda_fsync_in
{
  struct coda_in_hdr ih;
  ViceFid VFid;
};

struct coda_fsync_out
{
  struct coda_out_hdr out;
};


struct coda_vget_in
{
  struct coda_in_hdr ih;
  ViceFid VFid;
};

struct coda_vget_out
{
  struct coda_out_hdr oh;
  ViceFid VFid;
  int vtype;
};

struct coda_purgeuser_out
{
  struct coda_out_hdr oh;
  struct coda_cred cred;
};



struct coda_zapfile_out
{
  struct coda_out_hdr oh;
  ViceFid CodaFid;
};



struct coda_zapdir_out
{
  struct coda_out_hdr oh;
  ViceFid CodaFid;
};



struct coda_zapvnode_out
{
  struct coda_out_hdr oh;
  struct coda_cred cred;
  ViceFid VFid;
};



struct coda_purgefid_out
{
  struct coda_out_hdr oh;
  ViceFid CodaFid;
};



struct coda_replace_out
{
  struct coda_out_hdr oh;
  ViceFid NewFid;
  ViceFid OldFid;
};


struct coda_open_by_fd_in
{
  struct coda_in_hdr ih;
  ViceFid VFid;
  int flags;
};

struct coda_open_by_fd_out
{
  struct coda_out_hdr oh;
  int fd;


  struct file *fh;

};


struct coda_open_by_path_in
{
  struct coda_in_hdr ih;
  ViceFid VFid;
  int flags;
};

struct coda_open_by_path_out
{
  struct coda_out_hdr oh;
  int path;
};


struct coda_statfs_in
{
  struct coda_in_hdr in;
};

struct coda_statfs_out
{
  struct coda_out_hdr oh;
  struct coda_statfs stat;
};

union inputArgs
{
  struct coda_in_hdr ih;
  struct coda_open_in coda_open;
  struct coda_store_in coda_store;
  struct coda_release_in coda_release;
  struct coda_close_in coda_close;
  struct coda_ioctl_in coda_ioctl;
  struct coda_getattr_in coda_getattr;
  struct coda_setattr_in coda_setattr;
  struct coda_access_in coda_access;
  struct coda_lookup_in coda_lookup;
  struct coda_create_in coda_create;
  struct coda_remove_in coda_remove;
  struct coda_link_in coda_link;
  struct coda_rename_in coda_rename;
  struct coda_mkdir_in coda_mkdir;
  struct coda_rmdir_in coda_rmdir;
  struct coda_symlink_in coda_symlink;
  struct coda_readlink_in coda_readlink;
  struct coda_fsync_in coda_fsync;
  struct coda_vget_in coda_vget;
  struct coda_open_by_fd_in coda_open_by_fd;
  struct coda_open_by_path_in coda_open_by_path;
  struct coda_statfs_in coda_statfs;
};

union outputArgs
{
  struct coda_out_hdr oh;
  struct coda_root_out coda_root;
  struct coda_open_out coda_open;
  struct coda_ioctl_out coda_ioctl;
  struct coda_getattr_out coda_getattr;
  struct coda_lookup_out coda_lookup;
  struct coda_create_out coda_create;
  struct coda_mkdir_out coda_mkdir;
  struct coda_readlink_out coda_readlink;
  struct coda_vget_out coda_vget;
  struct coda_purgeuser_out coda_purgeuser;
  struct coda_zapfile_out coda_zapfile;
  struct coda_zapdir_out coda_zapdir;
  struct coda_zapvnode_out coda_zapvnode;
  struct coda_purgefid_out coda_purgefid;
  struct coda_replace_out coda_replace;
  struct coda_open_by_fd_out coda_open_by_fd;
  struct coda_open_by_path_out coda_open_by_path;
  struct coda_statfs_out coda_statfs;
};

union coda_downcalls
{


  struct coda_purgeuser_out purgeuser;
  struct coda_zapfile_out zapfile;
  struct coda_zapdir_out zapdir;
  struct coda_zapvnode_out zapvnode;
  struct coda_purgefid_out purgefid;
  struct coda_replace_out replace;
};







struct ViceIoctl
{
  caddr_t in, out;
  short in_size;
  short out_size;
};

struct PioctlData
{
  const char *path;
  int follow;
  struct ViceIoctl vi;
};

struct coda_mount_data
{
  int version;
  int fd;
};





struct coda_inode_info
{
  struct ViceFid c_fid;
  u_short c_flags;
  struct list_head c_cilist;
  int c_mapcount;
  struct coda_cred c_cached_cred;
  unsigned int c_cached_perm;
};





struct coda_file_info
{
  int cfi_magic;
  int cfi_mapcount;
  struct file *cfi_container;
  struct coda_cred cfi_cred;
};

int coda_cnode_make (struct inode **, struct ViceFid *, struct super_block *);
struct inode *coda_iget (struct super_block *sb, struct ViceFid *fid,
			 struct coda_vattr *attr);
int coda_cnode_makectl (struct inode **inode, struct super_block *sb);
struct inode *coda_fid_to_inode (ViceFid * fid, struct super_block *sb);
void coda_replace_fid (struct inode *, ViceFid *, ViceFid *);







struct romfs_inode_info
{
  unsigned long i_metasize;
  unsigned long i_dataoffset;
};



typedef struct
{
  unsigned long val;
} swp_entry_t;

struct shmem_inode_info
{
  spinlock_t lock;
  unsigned long next_index;
  swp_entry_t i_direct[16];
  void **i_indirect;
  unsigned long map_direct[16];
  void **map_indirect;
  unsigned long swapped;
  unsigned long flags;
  struct list_head list;
  struct inode *inode;
};

struct shmem_sb_info
{
  unsigned long max_blocks;
  unsigned long free_blocks;
  unsigned long max_inodes;
  unsigned long free_inodes;
  spinlock_t stat_lock;
};



struct smb_inode_info
{





  unsigned int open;
  __u16 fileid;
  __u16 attr;

  __u16 access;
  __u16 flags;
  unsigned long oldmtime;
  unsigned long closed;
  unsigned openers;
};



struct hfs_inode_info
{
  int magic;

  unsigned long mmu_private;
  struct hfs_cat_entry *entry;


  struct hfs_fork *fork;
  int convert;


  ino_t file_type;
  char dir_size;


  const struct hfs_hdr_layout *default_layout;
  struct hfs_hdr_layout *layout;


  int tz_secondswest;


  void (*d_drop_op) (struct dentry *, const ino_t);
};



struct adfs_inode_info
{
  unsigned long mmu_private;
  unsigned long parent_id;
  __u32 loadaddr;
  __u32 execaddr;
  unsigned int filetype;
  unsigned int attr;
  int stamped:1;
};





typedef __u16 qnx4_nxtnt_t;
typedef __u8 qnx4_ftype_t;

typedef struct
{
  __u32 xtnt_blk;
  __u32 xtnt_size;
} qnx4_xtnt_t;

typedef __u16 qnx4_mode_t;
typedef __u16 qnx4_muid_t;
typedef __u16 qnx4_mgid_t;
typedef __u32 qnx4_off_t;
typedef __u16 qnx4_nlink_t;





struct qnx4_inode_info
{
  char i_reserved[16];
  qnx4_off_t i_size;
  qnx4_xtnt_t i_first_xtnt;
  __u32 i_xblk;
  __s32 i_ftime;
  __s32 i_mtime;
  __s32 i_atime;
  __s32 i_ctime;
  qnx4_nxtnt_t i_num_xtnts;
  qnx4_mode_t i_mode;
  qnx4_muid_t i_uid;
  qnx4_mgid_t i_gid;
  qnx4_nlink_t i_nlink;
  __u8 i_zero[4];
  qnx4_ftype_t i_type;
  __u8 i_status;
  unsigned long mmu_private;
};



typedef enum
{



  i_item_key_version_mask = 0x0001,


  i_stat_data_version_mask = 0x0002,

  i_pack_on_close_mask = 0x0004,

  i_nopack_mask = 0x0008,



  i_link_saved_unlink_mask = 0x0010,
  i_link_saved_truncate_mask = 0x0020
} reiserfs_inode_flags;


struct reiserfs_inode_info
{
  __u32 i_key[4];



  __u32 i_flags;

  __u32 i_first_direct_byte;


  __u32 i_attrs;

  int i_prealloc_block;
  int i_prealloc_count;
  struct list_head i_prealloc_list;


  int new_packing_locality:1;






  unsigned long i_trans_id;
  unsigned long i_trans_index;





  unsigned long i_tail_trans_id;
  unsigned long i_tail_trans_index;
};



struct bfs_inode_info
{
  unsigned long i_dsk_ino;
  unsigned long i_sblock;
  unsigned long i_eblock;
};



typedef struct
{
  __u32 logicalBlockNum;
  __u16 partitionReferenceNum;
} __attribute__ ((packed)) lb_addr;


struct udf_inode_info
{
  long i_umtime;
  long i_uctime;
  long i_crtime;
  long i_ucrtime;

  lb_addr i_location;
  __u64 i_unique;
  __u32 i_lenEAttr;
  __u32 i_lenAlloc;
  __u64 i_lenExtents;
  __u32 i_next_alloc_block;
  __u32 i_next_alloc_goal;
  unsigned i_alloc_type:3;
  unsigned i_extended_fe:1;
  unsigned i_strat_4096:1;
  unsigned i_new_inode:1;
  unsigned reserved:26;
};



struct ncp_inode_info
{
  __u32 dirEntNum __attribute__ ((packed));
  __u32 DosDirNum __attribute__ ((packed));
  __u32 volNumber __attribute__ ((packed));
  __u32 nwattr;
  struct semaphore open_sem;
  atomic_t opened;
  int access;
  __u32 server_file_handle __attribute__ ((packed));
  __u8 open_create_action __attribute__ ((packed));
  __u8 file_handle[6] __attribute__ ((packed));
};


struct proc_inode_info
{
  struct task_struct *task;
  int type;
  union
  {
    int (*proc_get_link) (struct inode *, struct dentry **,
			  struct vfsmount **);
    int (*proc_read) (struct task_struct * task, char *page);
  } op;
  struct file *file;
};


struct usb_device;
struct usb_bus;

struct usbdev_inode_info
{
  struct list_head dlist;
  struct list_head slist;
  union
  {
    struct usb_device *dev;
    struct usb_bus *bus;
  } p;
};



struct hostfs_inode_info
{
};





struct hppfs_inode_info
{
  struct dentry *proc_dentry;
};



struct jffs2_inode_info
{

  struct semaphore sem;


  __u32 highest_version;


  struct jffs2_node_frag *fraglist;






  struct jffs2_full_dnode *metadata;


  struct jffs2_full_dirent *dents;


  struct jffs2_inode_cache *inocache;





  __u16 flags;
  __u8 usercompr;
};








struct cramfs_sb_info
{
  unsigned long magic;
  unsigned long size;
  unsigned long blocks;
  unsigned long files;
  unsigned long flags;
};


struct iattr
{
  unsigned int ia_valid;
  umode_t ia_mode;
  uid_t ia_uid;
  gid_t ia_gid;
  loff_t ia_size;
  time_t ia_atime;
  time_t ia_mtime;
  time_t ia_ctime;
  unsigned int ia_attr_flags;
};















typedef __kernel_uid32_t qid_t;
typedef __u64 qsize_t;

struct if_dqblk
{
  __u64 dqb_bhardlimit;
  __u64 dqb_bsoftlimit;
  __u64 dqb_curspace;
  __u64 dqb_ihardlimit;
  __u64 dqb_isoftlimit;
  __u64 dqb_curinodes;
  __u64 dqb_btime;
  __u64 dqb_itime;
  __u32 dqb_valid;
};

struct if_dqinfo
{
  __u64 dqi_bgrace;
  __u64 dqi_igrace;
  __u32 dqi_flags;
  __u32 dqi_valid;
};





typedef struct fs_disk_quota
{
  __s8 d_version;
  __s8 d_flags;
  __u16 d_fieldmask;
  __u32 d_id;
  __u64 d_blk_hardlimit;
  __u64 d_blk_softlimit;
  __u64 d_ino_hardlimit;
  __u64 d_ino_softlimit;
  __u64 d_bcount;
  __u64 d_icount;
  __s32 d_itimer;

  __s32 d_btimer;
  __u16 d_iwarns;
  __u16 d_bwarns;
  __s32 d_padding2;
  __u64 d_rtb_hardlimit;
  __u64 d_rtb_softlimit;
  __u64 d_rtbcount;
  __s32 d_rtbtimer;
  __u16 d_rtbwarns;
  __s16 d_padding3;
  char d_padding4[8];
} fs_disk_quota_t;

typedef struct fs_qfilestat
{
  __u64 qfs_ino;
  __u64 qfs_nblks;
  __u32 qfs_nextents;
} fs_qfilestat_t;

typedef struct fs_quota_stat
{
  __s8 qs_version;
  __u16 qs_flags;
  __s8 qs_pad;
  fs_qfilestat_t qs_uquota;
  fs_qfilestat_t qs_gquota;
  __u32 qs_incoredqs;
  __s32 qs_btimelimit;
  __s32 qs_itimelimit;
  __s32 qs_rtbtimelimit;
  __u16 qs_bwarnlimit;
  __u16 qs_iwarnlimit;
} fs_quota_stat_t;



struct v1_mem_dqinfo
{
};



struct v2_mem_dqinfo
{
  unsigned int dqi_blocks;
  unsigned int dqi_free_blk;
  unsigned int dqi_free_entry;
};





struct mem_dqblk
{
  __u32 dqb_bhardlimit;
  __u32 dqb_bsoftlimit;
  qsize_t dqb_curspace;
  __u32 dqb_ihardlimit;
  __u32 dqb_isoftlimit;
  __u32 dqb_curinodes;
  time_t dqb_btime;
  time_t dqb_itime;
};




struct quota_format_type;

struct mem_dqinfo
{
  struct quota_format_type *dqi_format;
  int dqi_flags;
  unsigned int dqi_bgrace;
  unsigned int dqi_igrace;
  union
  {
    struct v1_mem_dqinfo v1_i;
    struct v2_mem_dqinfo v2_i;
  } u;
};





extern inline void
mark_info_dirty (struct mem_dqinfo *info)
{
  info->dqi_flags |= 0x10000;
}


struct dqstats
{
  int lookups;
  int drops;
  int reads;
  int writes;
  int cache_hits;
  int allocated_dquots;
  int free_dquots;
  int syncs;
};

extern struct dqstats dqstats;

struct dquot
{
  struct list_head dq_hash;
  struct list_head dq_inuse;
  struct list_head dq_free;
  wait_queue_head_t dq_wait_lock;
  wait_queue_head_t dq_wait_free;
  int dq_count;
  int dq_dup_ref;


  struct super_block *dq_sb;
  unsigned int dq_id;
  kdev_t dq_dev;
  loff_t dq_off;
  short dq_type;
  short dq_flags;
  struct mem_dqblk dq_dqb;
};







struct quota_format_ops
{
  int (*check_quota_file) (struct super_block * sb, int type);
  int (*read_file_info) (struct super_block * sb, int type);
  int (*write_file_info) (struct super_block * sb, int type);
  int (*free_file_info) (struct super_block * sb, int type);
  int (*read_dqblk) (struct dquot * dquot);
  int (*commit_dqblk) (struct dquot * dquot);
};


struct dquot_operations
{
  void (*initialize) (struct inode *, int);
  void (*drop) (struct inode *);
  int (*alloc_space) (struct inode *, qsize_t, int);
  int (*alloc_inode) (const struct inode *, unsigned long);
  void (*free_space) (struct inode *, qsize_t);
  void (*free_inode) (const struct inode *, unsigned long);
  int (*transfer) (struct inode *, struct iattr *);
  int (*write_dquot) (struct dquot *);
};


struct quotactl_ops
{
  int (*quota_on) (struct super_block *, int, int, char *);
  int (*quota_off) (struct super_block *, int);
  int (*quota_sync) (struct super_block *, int);
  int (*get_info) (struct super_block *, int, struct if_dqinfo *);
  int (*set_info) (struct super_block *, int, struct if_dqinfo *);
  int (*get_dqblk) (struct super_block *, int, qid_t, struct if_dqblk *);
  int (*set_dqblk) (struct super_block *, int, qid_t, struct if_dqblk *);
  int (*get_xstate) (struct super_block *, struct fs_quota_stat *);
  int (*set_xstate) (struct super_block *, unsigned int, int);
  int (*get_xquota) (struct super_block *, int, qid_t,
		     struct fs_disk_quota *);
  int (*set_xquota) (struct super_block *, int, qid_t,
		     struct fs_disk_quota *);
};

struct quota_format_type
{
  int qf_fmt_id;
  struct quota_format_ops *qf_ops;
  struct module *qf_owner;
  struct quota_format_type *qf_next;
};




struct quota_info
{
  unsigned int flags;
  struct semaphore dqio_sem;
  struct semaphore dqoff_sem;
  struct file *files[2];
  struct mem_dqinfo info[2];
  struct quota_format_ops *ops[2];
};

static inline int
is_enabled (struct quota_info *dqopt, int type)
{
  switch (type)
    {
    case 0:
      return dqopt->flags & 0x01;
    case 1:
      return dqopt->flags & 0x02;
    }
  return 0;
}





int register_quota_format (struct quota_format_type *fmt);
void unregister_quota_format (struct quota_format_type *fmt);
void init_dquot_operations (struct dquot_operations *fsdqops);






struct page;
struct address_space;
struct kiobuf;

struct address_space_operations
{
  int (*writepage) (struct page *);
  int (*readpage) (struct file *, struct page *);
  int (*sync_page) (struct page *);




  int (*prepare_write) (struct file *, struct page *, unsigned, unsigned);
  int (*commit_write) (struct file *, struct page *, unsigned, unsigned);

  int (*bmap) (struct address_space *, long);
  int (*flushpage) (struct page *, unsigned long);
  int (*releasepage) (struct page *, int);

  int (*direct_IO) (int, struct inode *, struct kiobuf *, unsigned long, int);

  int (*direct_fileIO) (int, struct file *, struct kiobuf *, unsigned long,
			int);
  void (*removepage) (struct page *);
};

struct address_space
{
  struct list_head clean_pages;
  struct list_head dirty_pages;
  struct list_head locked_pages;
  unsigned long nrpages;
  struct address_space_operations *a_ops;
  struct inode *host;
  struct vm_area_struct *i_mmap;
  struct vm_area_struct *i_mmap_shared;
  spinlock_t i_shared_lock;
  int gfp_mask;
};

struct char_device
{
  struct list_head hash;
  atomic_t count;
  dev_t dev;
  atomic_t openers;
  struct semaphore sem;
};

struct block_device
{
  struct list_head bd_hash;
  atomic_t bd_count;
  struct inode *bd_inode;
  dev_t bd_dev;
  int bd_openers;
  const struct block_device_operations *bd_op;
  struct semaphore bd_sem;
  struct list_head bd_inodes;
};

struct inode
{
  struct list_head i_hash;
  struct list_head i_list;
  struct list_head i_dentry;

  struct list_head i_dirty_buffers;
  struct list_head i_dirty_data_buffers;

  unsigned long i_ino;
  atomic_t i_count;
  kdev_t i_dev;
  umode_t i_mode;
  nlink_t i_nlink;
  uid_t i_uid;
  gid_t i_gid;
  kdev_t i_rdev;
  loff_t i_size;
  time_t i_atime;
  time_t i_mtime;
  time_t i_ctime;
  unsigned int i_blkbits;
  unsigned long i_blksize;
  unsigned long i_blocks;
  unsigned long i_version;
  unsigned short i_bytes;
  struct semaphore i_sem;
  struct rw_semaphore i_alloc_sem;
  struct semaphore i_zombie;
  struct inode_operations *i_op;
  struct file_operations *i_fop;
  struct super_block *i_sb;
  wait_queue_head_t i_wait;
  struct file_lock *i_flock;
  struct address_space *i_mapping;
  struct address_space i_data;
  struct dquot *i_dquot[2];

  struct list_head i_devices;
  struct pipe_inode_info *i_pipe;
  struct block_device *i_bdev;
  struct char_device *i_cdev;

  unsigned long i_dnotify_mask;
  struct dnotify_struct *i_dnotify;

  unsigned long i_state;

  unsigned int i_flags;
  unsigned char i_sock;

  atomic_t i_writecount;
  unsigned int i_attr_flags;
  __u32 i_generation;
  union
  {
    struct minix_inode_info minix_i;
    struct ext2_inode_info ext2_i;
    struct ext3_inode_info ext3_i;
    struct hpfs_inode_info hpfs_i;
    struct ntfs_inode_info ntfs_i;
    struct msdos_inode_info msdos_i;
    struct umsdos_inode_info umsdos_i;
    struct iso_inode_info isofs_i;
    struct nfs_inode_info nfs_i;
    struct sysv_inode_info sysv_i;
    struct affs_inode_info affs_i;
    struct ufs_inode_info ufs_i;
    struct efs_inode_info efs_i;
    struct romfs_inode_info romfs_i;
    struct shmem_inode_info shmem_i;
    struct coda_inode_info coda_i;
    struct smb_inode_info smbfs_i;
    struct hfs_inode_info hfs_i;
    struct adfs_inode_info adfs_i;
    struct qnx4_inode_info qnx4_i;
    struct reiserfs_inode_info reiserfs_i;
    struct bfs_inode_info bfs_i;
    struct udf_inode_info udf_i;
    struct ncp_inode_info ncpfs_i;
    struct proc_inode_info proc_i;
    struct socket socket_i;
    struct usbdev_inode_info usbdev_i;
    struct hostfs_inode_info hostfs_i;
    struct hppfs_inode_info hppfs_i;
    struct jffs2_inode_info jffs2_i;
    void *generic_ip;
  } u;
};

static inline void
inode_add_bytes (struct inode *inode, loff_t bytes)
{
  inode->i_blocks += bytes >> 9;
  bytes &= 511;
  inode->i_bytes += bytes;
  if (inode->i_bytes >= 512)
    {
      inode->i_blocks++;
      inode->i_bytes -= 512;
    }
}

static inline void
inode_sub_bytes (struct inode *inode, loff_t bytes)
{
  inode->i_blocks -= bytes >> 9;
  bytes &= 511;
  if (inode->i_bytes < bytes)
    {
      inode->i_blocks--;
      inode->i_bytes += 512;
    }
  inode->i_bytes -= bytes;
}

static inline loff_t
inode_get_bytes (struct inode *inode)
{
  return (((loff_t) inode->i_blocks) << 9) + inode->i_bytes;
}

static inline void
inode_set_bytes (struct inode *inode, loff_t bytes)
{
  inode->i_blocks = bytes >> 9;
  inode->i_bytes = bytes & 511;
}

struct fown_struct
{
  int pid;
  uid_t uid, euid;
  int signum;
};

struct file
{
  struct list_head f_list;
  struct dentry *f_dentry;
  struct vfsmount *f_vfsmnt;
  struct file_operations *f_op;
  atomic_t f_count;
  unsigned int f_flags;
  mode_t f_mode;
  loff_t f_pos;
  unsigned long f_reada, f_ramax, f_raend, f_ralen, f_rawin;
  struct fown_struct f_owner;
  unsigned int f_uid, f_gid;
  int f_error;

  unsigned long f_version;


  void *private_data;


  struct kiobuf *f_iobuf;
  long f_iobuf_lock;
};
extern spinlock_t files_lock;






extern int init_private_file (struct file *, struct dentry *, int);

typedef struct files_struct *fl_owner_t;

struct file_lock
{
  struct file_lock *fl_next;
  struct list_head fl_link;
  struct list_head fl_block;
  fl_owner_t fl_owner;
  unsigned int fl_pid;
  wait_queue_head_t fl_wait;
  struct file *fl_file;
  unsigned char fl_flags;
  unsigned char fl_type;
  loff_t fl_start;
  loff_t fl_end;

  void (*fl_notify) (struct file_lock *);
  void (*fl_insert) (struct file_lock *);
  void (*fl_remove) (struct file_lock *);

  struct fasync_struct *fl_fasync;
  unsigned long fl_break_time;

  union
  {
    struct nfs_lock_info nfs_fl;
  } fl_u;
};

extern struct list_head file_lock_list;







struct flock
{
  short l_type;
  short l_whence;
  off_t l_start;
  off_t l_len;
  pid_t l_pid;
};

struct flock64
{
  short l_type;
  short l_whence;
  loff_t l_start;
  loff_t l_len;
  pid_t l_pid;
};



extern int fcntl_getlk (unsigned int, struct flock *);
extern int fcntl_setlk (unsigned int, unsigned int, struct flock *);

extern int fcntl_getlk64 (unsigned int, struct flock64 *);
extern int fcntl_setlk64 (unsigned int, unsigned int, struct flock64 *);


extern void locks_init_lock (struct file_lock *);
extern void locks_copy_lock (struct file_lock *, struct file_lock *);
extern void locks_remove_posix (struct file *, fl_owner_t);
extern void locks_remove_flock (struct file *);
extern struct file_lock *posix_test_lock (struct file *, struct file_lock *);
extern int posix_lock_file (struct file *, struct file_lock *, unsigned int);
extern void posix_block_lock (struct file_lock *, struct file_lock *);
extern void posix_unblock_lock (struct file_lock *);
extern int posix_locks_deadlock (struct file_lock *, struct file_lock *);
extern int __get_lease (struct inode *inode, unsigned int flags);
extern time_t lease_get_mtime (struct inode *);
extern int lock_may_read (struct inode *, loff_t start, unsigned long count);
extern int lock_may_write (struct inode *, loff_t start, unsigned long count);
extern void steal_locks (fl_owner_t from);

struct fasync_struct
{
  int magic;
  int fa_fd;
  struct fasync_struct *fa_next;
  struct file *fa_file;
};




extern int fasync_helper (int, struct file *, int, struct fasync_struct **);

extern void kill_fasync (struct fasync_struct **, int, int);

extern void __kill_fasync (struct fasync_struct *, int, int);

struct nameidata
{
  struct dentry *dentry;
  struct vfsmount *mnt;
  struct qstr last;
  unsigned int flags;
  int last_type;
};








struct minix_sb_info
{
  unsigned long s_ninodes;
  unsigned long s_nzones;
  unsigned long s_imap_blocks;
  unsigned long s_zmap_blocks;
  unsigned long s_firstdatazone;
  unsigned long s_log_zone_size;
  unsigned long s_max_size;
  int s_dirsize;
  int s_namelen;
  int s_link_max;
  struct buffer_head **s_imap;
  struct buffer_head **s_zmap;
  struct buffer_head *s_sbh;
  struct minix_super_block *s_ms;
  unsigned short s_mount_state;
  unsigned short s_version;
};



struct ext2_sb_info
{
  unsigned long s_frag_size;
  unsigned long s_frags_per_block;
  unsigned long s_inodes_per_block;
  unsigned long s_frags_per_group;
  unsigned long s_blocks_per_group;
  unsigned long s_inodes_per_group;
  unsigned long s_itb_per_group;
  unsigned long s_gdb_count;
  unsigned long s_desc_per_block;
  unsigned long s_groups_count;
  struct buffer_head *s_sbh;
  struct ext2_super_block *s_es;
  struct buffer_head **s_group_desc;
  unsigned short s_loaded_inode_bitmaps;
  unsigned short s_loaded_block_bitmaps;
  unsigned long s_inode_bitmap_number[8];
  struct buffer_head *s_inode_bitmap[8];
  unsigned long s_block_bitmap_number[8];
  struct buffer_head *s_block_bitmap[8];
  unsigned long s_mount_opt;
  uid_t s_resuid;
  gid_t s_resgid;
  unsigned short s_mount_state;
  unsigned short s_pad;
  int s_addr_per_block_bits;
  int s_desc_per_block_bits;
  int s_inode_size;
  int s_first_ino;
};





struct timer_list
{
  struct list_head list;
  unsigned long expires;
  unsigned long data;
  void (*function) (unsigned long);
};

extern void add_timer (struct timer_list *timer);
extern int del_timer (struct timer_list *timer);

int mod_timer (struct timer_list *timer, unsigned long expires);

extern void it_real_fn (unsigned long);

static inline void
init_timer (struct timer_list *timer)
{
  timer->list.next = timer->list.prev = ((void *) 0);
}

static inline int
timer_pending (const struct timer_list *timer)
{
  return timer->list.next != ((void *) 0);
}



struct ext3_sb_info
{
  unsigned long s_frag_size;
  unsigned long s_frags_per_block;
  unsigned long s_inodes_per_block;
  unsigned long s_frags_per_group;
  unsigned long s_blocks_per_group;
  unsigned long s_inodes_per_group;
  unsigned long s_itb_per_group;
  unsigned long s_gdb_count;
  unsigned long s_desc_per_block;
  unsigned long s_groups_count;
  struct buffer_head *s_sbh;
  struct ext3_super_block *s_es;
  struct buffer_head **s_group_desc;
  unsigned short s_loaded_inode_bitmaps;
  unsigned short s_loaded_block_bitmaps;
  unsigned long s_inode_bitmap_number[8];
  struct buffer_head *s_inode_bitmap[8];
  unsigned long s_block_bitmap_number[8];
  struct buffer_head *s_block_bitmap[8];
  unsigned long s_mount_opt;
  uid_t s_resuid;
  gid_t s_resgid;
  unsigned short s_mount_state;
  unsigned short s_pad;
  int s_addr_per_block_bits;
  int s_desc_per_block_bits;
  int s_inode_size;
  int s_first_ino;
  u32 s_next_generation;


  struct inode *s_journal_inode;
  struct journal_s *s_journal;
  struct list_head s_orphan;
  unsigned long s_commit_interval;
  struct block_device *journal_bdev;




};





struct hpfs_sb_info
{
  ino_t sb_root;
  unsigned sb_fs_size;
  unsigned sb_bitmaps;
  unsigned sb_dirband_start;
  unsigned sb_dirband_size;
  unsigned sb_dmap;
  unsigned sb_n_free;
  unsigned sb_n_free_dnodes;
  uid_t sb_uid;
  gid_t sb_gid;
  umode_t sb_mode;
  unsigned sb_conv:2;
  unsigned sb_eas:2;
  unsigned sb_err:2;
  unsigned sb_chk:2;
  unsigned sb_lowercase:1;
  unsigned sb_was_error:1;
  unsigned sb_chkdsk:2;
  unsigned sb_rd_fnode:2;
  unsigned sb_rd_inode:2;


  wait_queue_head_t sb_iget_q;
  unsigned char *sb_cp_table;


  unsigned *sb_bmp_dir;
  unsigned sb_c_bitmap;
  wait_queue_head_t sb_creation_de;

  unsigned sb_creation_de_lock:1;

  int sb_timeshift;
};







struct ntfs_sb_info
{

  ntfs_uid_t uid;
  ntfs_gid_t gid;
  ntmode_t umask;
  void *nls_map;
  unsigned int ngt;
  char mft_zone_multiplier;
  unsigned long mft_data_pos;
  ntfs_cluster_t mft_zone_pos;
  ntfs_cluster_t mft_zone_start;
  ntfs_cluster_t mft_zone_end;
  ntfs_cluster_t data1_zone_pos;
  ntfs_cluster_t data2_zone_pos;


  ntfs_size_t partition_bias;

  ntfs_u32 at_standard_information;
  ntfs_u32 at_attribute_list;
  ntfs_u32 at_file_name;
  ntfs_u32 at_volume_version;
  ntfs_u32 at_security_descriptor;
  ntfs_u32 at_volume_name;
  ntfs_u32 at_volume_information;
  ntfs_u32 at_data;
  ntfs_u32 at_index_root;
  ntfs_u32 at_index_allocation;
  ntfs_u32 at_bitmap;
  ntfs_u32 at_symlink;

  int sector_size;
  int cluster_size;
  int cluster_size_bits;
  int mft_clusters_per_record;
  int mft_record_size;
  int mft_record_size_bits;
  int index_clusters_per_record;
  int index_record_size;
  int index_record_size_bits;
  ntfs_cluster_t nr_clusters;
  ntfs_cluster_t mft_lcn;
  ntfs_cluster_t mft_mirr_lcn;

  unsigned char *mft;
  unsigned short *upcase;
  unsigned int upcase_length;

  struct ntfs_inode_info *mft_ino;
  struct ntfs_inode_info *mftmirr;
  struct ntfs_inode_info *bitmap;
  struct super_block *sb;
  unsigned char ino_flags;
};










struct cvf_format
{
  int cvf_version;
  char *cvf_version_text;
  unsigned long flags;
  int (*detect_cvf) (struct super_block * sb);
  int (*mount_cvf) (struct super_block * sb, char *options);
  int (*unmount_cvf) (struct super_block * sb);
  struct buffer_head *(*cvf_bread) (struct super_block * sb, int block);
  struct buffer_head *(*cvf_getblk) (struct super_block * sb, int block);
  void (*cvf_brelse) (struct super_block * sb, struct buffer_head * bh);
  void (*cvf_mark_buffer_dirty) (struct super_block * sb,
				 struct buffer_head * bh);
  void (*cvf_set_uptodate) (struct super_block * sb,
			    struct buffer_head * bh, int val);
  int (*cvf_is_uptodate) (struct super_block * sb, struct buffer_head * bh);
  void (*cvf_ll_rw_block) (struct super_block * sb,
			   int opr, int nbreq, struct buffer_head * bh[32]);
  int (*fat_access) (struct super_block * sb, int nr, int new_value);
  int (*cvf_statfs) (struct super_block * sb, struct statfs * buf,
		     int bufsiz);
  int (*cvf_bmap) (struct inode * inode, int block);
    ssize_t (*cvf_file_read) (struct file *, char *, size_t, loff_t *);
    ssize_t (*cvf_file_write) (struct file *, const char *, size_t, loff_t *);
  int (*cvf_mmap) (struct file *, struct vm_area_struct *);
  int (*cvf_readpage) (struct inode *, struct page *);
  int (*cvf_writepage) (struct inode *, struct page *);
  int (*cvf_dir_ioctl) (struct inode * inode, struct file * filp,
			unsigned int cmd, unsigned long arg);
  void (*zero_out_cluster) (struct inode *, int clusternr);
};

int register_cvf_format (struct cvf_format *cvf_format);
int unregister_cvf_format (struct cvf_format *cvf_format);
void dec_cvf_format_use_count_by_version (int version);
int detect_cvf (struct super_block *sb, char *force);

extern struct cvf_format *cvf_formats[];
extern int cvf_format_use_count[];






struct fat_mount_options
{
  uid_t fs_uid;
  gid_t fs_gid;
  unsigned short fs_umask;
  unsigned short codepage;
  char *iocharset;
  unsigned short shortname;
  unsigned char name_check;
  unsigned char conversion;
  unsigned quiet:1,
    showexec:1,
    sys_immutable:1,
    dotsOK:1,
    isvfat:1,
    utf8:1, unicode_xlate:1, posixfs:1, numtail:1, atari:1, fat32:1, nocase:1;
};

struct msdos_sb_info
{
  unsigned short cluster_size;
  unsigned short cluster_bits;
  unsigned char fats, fat_bits;
  unsigned short fat_start;
  unsigned long fat_length;
  unsigned long dir_start;
  unsigned short dir_entries;
  unsigned long data_start;
  unsigned long clusters;
  unsigned long root_cluster;
  unsigned long fsinfo_sector;
  struct semaphore fat_lock;
  int prev_free;
  int free_clusters;
  struct fat_mount_options options;
  struct nls_table *nls_disk;
  struct nls_table *nls_io;
  struct cvf_format *cvf_format;
  void *dir_ops;
  void *private_data;
  int dir_per_block;
  int dir_per_block_bits;
};








struct isofs_sb_info
{
  unsigned long s_ninodes;
  unsigned long s_nzones;
  unsigned long s_firstdatazone;
  unsigned long s_log_zone_size;
  unsigned long s_max_size;

  unsigned char s_high_sierra;
  unsigned char s_mapping;
  int s_rock_offset;
  unsigned char s_rock;
  unsigned char s_joliet_level;
  unsigned char s_utf8;
  unsigned char s_cruft;


  unsigned char s_unhide;
  unsigned char s_nosuid;
  unsigned char s_nodev;
  unsigned char s_nocompress;

  mode_t s_mode;
  gid_t s_gid;
  uid_t s_uid;
  struct nls_table *s_nls_iocharset;
};



struct nfs_server
{
  struct rpc_clnt *client;
  struct nfs_rpc_ops *rpc_ops;
  int flags;
  unsigned int rsize;
  unsigned int rpages;
  unsigned int wsize;
  unsigned int wpages;
  unsigned int dtsize;
  unsigned int bsize;
  unsigned int acregmin;
  unsigned int acregmax;
  unsigned int acdirmin;
  unsigned int acdirmax;
  unsigned int namelen;
  char *hostname;
  struct nfs_reqlist *rw_requests;
  struct list_head lru_read, lru_dirty, lru_commit, lru_busy;
};




struct nfs_sb_info
{
  struct nfs_server s_server;
};



struct sysv_sb_info
{
  int s_type;
  char s_bytesex;
  char s_truncate;

  nlink_t s_link_max;
  unsigned int s_inodes_per_block;
  unsigned int s_inodes_per_block_1;
  unsigned int s_inodes_per_block_bits;
  unsigned int s_ind_per_block;
  unsigned int s_ind_per_block_bits;
  unsigned int s_ind_per_block_2;
  unsigned int s_toobig_block;
  unsigned int s_block_base;
  unsigned short s_fic_size;
  unsigned short s_flc_size;

  struct buffer_head *s_bh1;
  struct buffer_head *s_bh2;


  char *s_sbd1;
  char *s_sbd2;
  u16 *s_sb_fic_count;
  u16 *s_sb_fic_inodes;
  u16 *s_sb_total_free_inodes;
  u16 *s_bcache_count;
  u32 *s_bcache;
  u32 *s_free_blocks;
  u32 *s_sb_time;
  u32 *s_sb_state;


  u32 s_firstinodezone;
  u32 s_firstdatazone;
  u32 s_ninodes;
  u32 s_ndatazones;
  u32 s_nzones;
  u16 s_namelen;
};



struct affs_bm_info
{
  u32 bm_key;
  u32 bm_free;
};

struct affs_sb_info
{
  int s_partition_size;
  int s_reserved;

  u32 s_data_blksize;
  u32 s_root_block;
  int s_hashsize;
  unsigned long s_flags;
  uid_t s_uid;
  gid_t s_gid;
  umode_t s_mode;
  struct buffer_head *s_root_bh;
  struct semaphore s_bmlock;
  struct affs_bm_info *s_bitmap;
  u32 s_bmap_count;
  u32 s_bmap_bits;
  u32 s_last_bmap;
  struct buffer_head *s_bmap_bh;
  char *s_prefix;
  int s_prefix_len;
  char s_volume[32];
};





struct ufs_timeval
{
  __s32 tv_sec;
  __s32 tv_usec;
};

struct ufs_dir_entry
{
  __u32 d_ino;
  __u16 d_reclen;
  union
  {
    __u16 d_namlen;
    struct
    {
      __u8 d_type;
      __u8 d_namlen;
    } d_44;
  } d_u;
  __u8 d_name[255 + 1];
};

struct ufs_csum
{
  __u32 cs_ndir;
  __u32 cs_nbfree;
  __u32 cs_nifree;
  __u32 cs_nffree;
};




struct ufs_super_block
{
  __u32 fs_link;
  __u32 fs_rlink;
  __u32 fs_sblkno;
  __u32 fs_cblkno;
  __u32 fs_iblkno;
  __u32 fs_dblkno;
  __u32 fs_cgoffset;
  __u32 fs_cgmask;
  __u32 fs_time;
  __u32 fs_size;
  __u32 fs_dsize;
  __u32 fs_ncg;
  __u32 fs_bsize;
  __u32 fs_fsize;
  __u32 fs_frag;

  __u32 fs_minfree;
  __u32 fs_rotdelay;
  __u32 fs_rps;

  __u32 fs_bmask;
  __u32 fs_fmask;
  __u32 fs_bshift;
  __u32 fs_fshift;

  __u32 fs_maxcontig;
  __u32 fs_maxbpg;

  __u32 fs_fragshift;
  __u32 fs_fsbtodb;
  __u32 fs_sbsize;
  __u32 fs_csmask;
  __u32 fs_csshift;
  __u32 fs_nindir;
  __u32 fs_inopb;
  __u32 fs_nspf;

  __u32 fs_optim;

  union
  {
    struct
    {
      __u32 fs_npsect;
    } fs_sun;
    struct
    {
      __s32 fs_state;
    } fs_sunx86;
  } fs_u1;
  __u32 fs_interleave;
  __u32 fs_trackskew;




  __u32 fs_id[2];

  __u32 fs_csaddr;
  __u32 fs_cssize;
  __u32 fs_cgsize;

  __u32 fs_ntrak;
  __u32 fs_nsect;
  __u32 fs_spc;

  __u32 fs_ncyl;

  __u32 fs_cpg;
  __u32 fs_ipg;
  __u32 fs_fpg;

  struct ufs_csum fs_cstotal;

  __s8 fs_fmod;
  __s8 fs_clean;
  __s8 fs_ronly;
  __s8 fs_flags;
  __s8 fs_fsmnt[512];

  __u32 fs_cgrotor;
  __u32 fs_csp[31];
  __u32 fs_maxcluster;
  __u32 fs_cpc;
  __u16 fs_opostbl[16][8];
  union
  {
    struct
    {
      __s32 fs_sparecon[53];
      __s32 fs_reclaim;
      __s32 fs_sparecon2[1];
      __s32 fs_state;
      __u32 fs_qbmask[2];
      __u32 fs_qfmask[2];
    } fs_sun;
    struct
    {
      __s32 fs_sparecon[53];
      __s32 fs_reclaim;
      __s32 fs_sparecon2[1];
      __u32 fs_npsect;
      __u32 fs_qbmask[2];
      __u32 fs_qfmask[2];
    } fs_sunx86;
    struct
    {
      __s32 fs_sparecon[50];
      __s32 fs_contigsumsize;
      __s32 fs_maxsymlinklen;
      __s32 fs_inodefmt;
      __u32 fs_maxfilesize[2];
      __u32 fs_qbmask[2];
      __u32 fs_qfmask[2];
      __s32 fs_state;
    } fs_44;
  } fs_u2;
  __s32 fs_postblformat;
  __s32 fs_nrpos;
  __s32 fs_postbloff;
  __s32 fs_rotbloff;
  __s32 fs_magic;
  __u8 fs_space[1];
};

struct ufs_cylinder_group
{
  __u32 cg_link;
  __u32 cg_magic;
  __u32 cg_time;
  __u32 cg_cgx;
  __u16 cg_ncyl;
  __u16 cg_niblk;
  __u32 cg_ndblk;
  struct ufs_csum cg_cs;
  __u32 cg_rotor;
  __u32 cg_frotor;
  __u32 cg_irotor;
  __u32 cg_frsum[(8192 / 1024)];
  __u32 cg_btotoff;
  __u32 cg_boff;
  __u32 cg_iusedoff;
  __u32 cg_freeoff;
  __u32 cg_nextfreeoff;
  union
  {
    struct
    {
      __u32 cg_clustersumoff;
      __u32 cg_clusteroff;
      __u32 cg_nclusterblks;
      __u32 cg_sparecon[13];
    } cg_44;
    __u32 cg_sparecon[16];
  } cg_u;
  __u8 cg_space[1];

};




struct ufs_inode
{
  __u16 ui_mode;
  __u16 ui_nlink;
  union
  {
    struct
    {
      __u16 ui_suid;
      __u16 ui_sgid;
    } oldids;
    __u32 ui_inumber;
    __u32 ui_author;
  } ui_u1;
  __u64 ui_size;
  struct ufs_timeval ui_atime;
  struct ufs_timeval ui_mtime;
  struct ufs_timeval ui_ctime;
  union
  {
    struct
    {
      __u32 ui_db[12];
      __u32 ui_ib[3];
    } ui_addr;
    __u8 ui_symlink[4 * (12 + 3)];
  } ui_u2;
  __u32 ui_flags;
  __u32 ui_blocks;
  __u32 ui_gen;
  union
  {
    struct
    {
      __u32 ui_shadow;
      __u32 ui_uid;
      __u32 ui_gid;
      __u32 ui_oeftflag;
    } ui_sun;
    struct
    {
      __u32 ui_uid;
      __u32 ui_gid;
      __s32 ui_spare[2];
    } ui_44;
    struct
    {
      __u32 ui_uid;
      __u32 ui_gid;
      __u16 ui_modeh;
      __u16 ui_spare;
      __u32 ui_trans;
    } ui_hurd;
  } ui_u3;
};

extern void ufs_free_fragments (struct inode *, unsigned, unsigned);
extern void ufs_free_blocks (struct inode *, unsigned, unsigned);
extern unsigned ufs_new_fragments (struct inode *, u32 *, unsigned, unsigned,
				   unsigned, int *);


extern struct ufs_cg_private_info *ufs_load_cylinder (struct super_block *,
						      unsigned);
extern void ufs_put_cylinder (struct super_block *, unsigned);


extern struct inode_operations ufs_dir_inode_operations;
extern int ufs_check_dir_entry (const char *, struct inode *,
				struct ufs_dir_entry *, struct buffer_head *,
				unsigned long);
extern int ufs_add_link (struct dentry *, struct inode *);
extern ino_t ufs_inode_by_name (struct inode *, struct dentry *);
extern int ufs_make_empty (struct inode *, struct inode *);
extern struct ufs_dir_entry *ufs_find_entry (struct dentry *,
					     struct buffer_head **);
extern int ufs_delete_entry (struct inode *, struct ufs_dir_entry *,
			     struct buffer_head *);
extern int ufs_empty_dir (struct inode *);
extern struct ufs_dir_entry *ufs_dotdot (struct inode *,
					 struct buffer_head **);
extern void ufs_set_link (struct inode *, struct ufs_dir_entry *,
			  struct buffer_head *, struct inode *);


extern struct inode_operations ufs_file_inode_operations;
extern struct file_operations ufs_file_operations;

extern struct address_space_operations ufs_aops;


extern void ufs_free_inode (struct inode *inode);
extern struct inode *ufs_new_inode (const struct inode *, int);


extern int ufs_frag_map (struct inode *, int);
extern void ufs_read_inode (struct inode *);
extern void ufs_put_inode (struct inode *);
extern void ufs_write_inode (struct inode *, int);
extern int ufs_sync_inode (struct inode *);
extern void ufs_delete_inode (struct inode *);
extern struct buffer_head *ufs_getfrag (struct inode *, unsigned, int, int *);
extern struct buffer_head *ufs_bread (struct inode *, unsigned, int, int *);


extern struct file_operations ufs_dir_operations;


extern struct file_system_type ufs_fs_type;
extern void ufs_warning (struct super_block *, const char *, const char *,
			 ...) __attribute__ ((format (printf, 3, 4)));
extern void ufs_error (struct super_block *, const char *, const char *, ...)
  __attribute__ ((format (printf, 3, 4)));
extern void ufs_panic (struct super_block *, const char *, const char *, ...)
  __attribute__ ((format (printf, 3, 4)));
extern void ufs_write_super (struct super_block *);


extern struct inode_operations ufs_fast_symlink_inode_operations;


extern void ufs_truncate (struct inode *);






struct ufs_buffer_head
{
  unsigned fragment;
  unsigned count;
  struct buffer_head *bh[(8192 / 1024)];
};

struct ufs_cg_private_info
{
  struct ufs_cylinder_group ucg;
  __u32 c_cgx;
  __u16 c_ncyl;
  __u16 c_niblk;
  __u32 c_ndblk;
  __u32 c_rotor;
  __u32 c_frotor;
  __u32 c_irotor;
  __u32 c_btotoff;
  __u32 c_boff;
  __u32 c_iusedoff;
  __u32 c_freeoff;
  __u32 c_nextfreeoff;
  __u32 c_clustersumoff;
  __u32 c_clusteroff;
  __u32 c_nclusterblks;
};

struct ufs_sb_private_info
{
  struct ufs_buffer_head s_ubh;
  __u32 s_sblkno;
  __u32 s_cblkno;
  __u32 s_iblkno;
  __u32 s_dblkno;
  __u32 s_cgoffset;
  __u32 s_cgmask;
  __u32 s_size;
  __u32 s_dsize;
  __u32 s_ncg;
  __u32 s_bsize;
  __u32 s_fsize;
  __u32 s_fpb;
  __u32 s_minfree;
  __u32 s_bmask;
  __u32 s_fmask;
  __u32 s_bshift;
  __u32 s_fshift;
  __u32 s_fpbshift;
  __u32 s_fsbtodb;
  __u32 s_sbsize;
  __u32 s_csmask;
  __u32 s_csshift;
  __u32 s_nindir;
  __u32 s_inopb;
  __u32 s_nspf;
  __u32 s_npsect;
  __u32 s_interleave;
  __u32 s_trackskew;
  __u32 s_csaddr;
  __u32 s_cssize;
  __u32 s_cgsize;
  __u32 s_ntrak;
  __u32 s_nsect;
  __u32 s_spc;
  __u32 s_ipg;
  __u32 s_fpg;
  __u32 s_cpc;
  __s32 s_contigsumsize;
  __s64 s_qbmask;
  __s64 s_qfmask;
  __s32 s_postblformat;
  __s32 s_nrpos;
  __s32 s_postbloff;
  __s32 s_rotbloff;

  __u32 s_fpbmask;
  __u32 s_apb;
  __u32 s_2apb;
  __u32 s_3apb;
  __u32 s_apbmask;
  __u32 s_apbshift;
  __u32 s_2apbshift;
  __u32 s_3apbshift;
  __u32 s_nspfshift;
  __u32 s_nspb;
  __u32 s_inopf;
  __u32 s_sbbase;
  __u32 s_bpf;
  __u32 s_bpfshift;
  __u32 s_bpfmask;

  __u32 s_maxsymlinklen;
};





struct ufs_sb_info
{
  struct ufs_sb_private_info *s_uspi;
  struct ufs_csum *s_csp[31];
  unsigned s_bytesex;
  unsigned s_flags;
  struct buffer_head **s_ucg;
  struct ufs_cg_private_info *s_ucpi[8];
  unsigned s_cgno[8];
  unsigned short s_cg_loaded;
  unsigned s_mount_opt;
};







struct ufs_super_block_first
{
  __u32 fs_link;
  __u32 fs_rlink;
  __u32 fs_sblkno;
  __u32 fs_cblkno;
  __u32 fs_iblkno;
  __u32 fs_dblkno;
  __u32 fs_cgoffset;
  __u32 fs_cgmask;
  __u32 fs_time;
  __u32 fs_size;
  __u32 fs_dsize;
  __u32 fs_ncg;
  __u32 fs_bsize;
  __u32 fs_fsize;
  __u32 fs_frag;
  __u32 fs_minfree;
  __u32 fs_rotdelay;
  __u32 fs_rps;
  __u32 fs_bmask;
  __u32 fs_fmask;
  __u32 fs_bshift;
  __u32 fs_fshift;
  __u32 fs_maxcontig;
  __u32 fs_maxbpg;
  __u32 fs_fragshift;
  __u32 fs_fsbtodb;
  __u32 fs_sbsize;
  __u32 fs_csmask;
  __u32 fs_csshift;
  __u32 fs_nindir;
  __u32 fs_inopb;
  __u32 fs_nspf;
  __u32 fs_optim;
  union
  {
    struct
    {
      __u32 fs_npsect;
    } fs_sun;
    struct
    {
      __s32 fs_state;
    } fs_sunx86;
  } fs_u1;
  __u32 fs_interleave;
  __u32 fs_trackskew;
  __u32 fs_id[2];
  __u32 fs_csaddr;
  __u32 fs_cssize;
  __u32 fs_cgsize;
  __u32 fs_ntrak;
  __u32 fs_nsect;
  __u32 fs_spc;
  __u32 fs_ncyl;
  __u32 fs_cpg;
  __u32 fs_ipg;
  __u32 fs_fpg;
  struct ufs_csum fs_cstotal;
  __s8 fs_fmod;
  __s8 fs_clean;
  __s8 fs_ronly;
  __s8 fs_flags;
  __s8 fs_fsmnt[512 - 212];

};

struct ufs_super_block_second
{
  __s8 fs_fsmnt[212];
  __u32 fs_cgrotor;
  __u32 fs_csp[31];
  __u32 fs_maxcluster;
  __u32 fs_cpc;
  __u16 fs_opostbl[82];
};

struct ufs_super_block_third
{
  __u16 fs_opostbl[46];
  union
  {
    struct
    {
      __s32 fs_sparecon[53];
      __s32 fs_reclaim;
      __s32 fs_sparecon2[1];
      __s32 fs_state;
      __u32 fs_qbmask[2];
      __u32 fs_qfmask[2];
    } fs_sun;
    struct
    {
      __s32 fs_sparecon[53];
      __s32 fs_reclaim;
      __s32 fs_sparecon2[1];
      __u32 fs_npsect;
      __u32 fs_qbmask[2];
      __u32 fs_qfmask[2];
    } fs_sunx86;
    struct
    {
      __s32 fs_sparecon[50];
      __s32 fs_contigsumsize;
      __s32 fs_maxsymlinklen;
      __s32 fs_inodefmt;
      __u32 fs_maxfilesize[2];
      __u32 fs_qbmask[2];
      __u32 fs_qfmask[2];
      __s32 fs_state;
    } fs_44;
  } fs_u2;
  __s32 fs_postblformat;
  __s32 fs_nrpos;
  __s32 fs_postbloff;
  __s32 fs_rotbloff;
  __s32 fs_magic;
  __u8 fs_space[1];
};



struct efs_super
{
  int32_t fs_size;
  int32_t fs_firstcg;
  int32_t fs_cgfsize;
  short fs_cgisize;
  short fs_sectors;
  short fs_heads;
  short fs_ncg;
  short fs_dirty;
  int32_t fs_time;
  int32_t fs_magic;
  char fs_fname[6];
  char fs_fpack[6];
  int32_t fs_bmsize;
  int32_t fs_tfree;
  int32_t fs_tinode;
  int32_t fs_bmblock;
  int32_t fs_replsb;
  int32_t fs_lastialloc;
  char fs_spare[20];
  int32_t fs_checksum;
};


struct efs_sb_info
{
  int32_t fs_magic;
  int32_t fs_start;
  int32_t first_block;
  int32_t total_blocks;
  int32_t group_size;
  int32_t data_free;
  int32_t inode_free;
  short inode_blocks;
  short total_groups;
};







struct romfs_sb_info
{
  unsigned long s_maxsize;
};





enum smb_protocol
{
  SMB_PROTOCOL_NONE,
  SMB_PROTOCOL_CORE,
  SMB_PROTOCOL_COREPLUS,
  SMB_PROTOCOL_LANMAN1,
  SMB_PROTOCOL_LANMAN2,
  SMB_PROTOCOL_NT1
};

enum smb_case_hndl
{
  SMB_CASE_DEFAULT,
  SMB_CASE_LOWER,
  SMB_CASE_UPPER
};

struct smb_dskattr
{
  __u16 total;
  __u16 allocblocks;
  __u16 blocksize;
  __u16 free;
};

struct smb_conn_opt
{


  unsigned int fd;

  enum smb_protocol protocol;
  enum smb_case_hndl case_handling;



  __u32 max_xmit;
  __u16 server_uid;
  __u16 tid;


  __u16 secmode;
  __u16 maxmux;
  __u16 maxvcs;
  __u16 rawmode;
  __u32 sesskey;


  __u32 maxraw;
  __u32 capabilities;
  __s16 serverzone;
};




struct smb_nls_codepage
{
  char local_name[20];
  char remote_name[20];
};

struct smb_fattr
{

  __u16 attr;

  unsigned long f_ino;
  umode_t f_mode;
  nlink_t f_nlink;
  uid_t f_uid;
  gid_t f_gid;
  kdev_t f_rdev;
  loff_t f_size;
  time_t f_atime;
  time_t f_mtime;
  time_t f_ctime;
  unsigned long f_blksize;
  unsigned long f_blocks;
  int f_unix;
};

enum smb_conn_state
{
  CONN_VALID,
  CONN_INVALID,

  CONN_RETRIED,
  CONN_RETRYING
};








struct smb_sb_info
{
  enum smb_conn_state state;
  struct file *sock_file;

  struct smb_mount_data_kernel *mnt;
  unsigned char *temp_buf;




  unsigned int generation;
  pid_t conn_pid;
  struct smb_conn_opt opt;

  struct semaphore sem;
  wait_queue_head_t wait;

  __u32 packet_size;
  unsigned char *packet;
  unsigned short rcls;
  unsigned short err;


  void *data_ready;


  struct nls_table *remote_nls;
  struct nls_table *local_nls;




  char *name_buf;

  struct smb_ops *ops;
};


static inline void
smb_lock_server (struct smb_sb_info *server)
{
  down (&(server->sem));
}

static inline void
smb_unlock_server (struct smb_sb_info *server)
{
  up (&(server->sem));
}




struct hfs_name;

typedef int (*hfs_namein_fn) (char *, const struct hfs_name *);
typedef void (*hfs_nameout_fn) (struct hfs_name *, const char *, int);
typedef void (*hfs_ifill_fn) (struct inode *, ino_t, const int);






struct hfs_sb_info
{
  int magic;
  struct hfs_mdb *s_mdb;
  int s_quiet;

  int s_lowercase;
  int s_afpd;
  int s_version;
  hfs_namein_fn s_namein;


  hfs_nameout_fn s_nameout;


  hfs_ifill_fn s_ifill;

  const struct hfs_name *s_reserved1;
  const struct hfs_name *s_reserved2;
  __u32 s_type;
  __u32 s_creator;
  umode_t s_umask;

  uid_t s_uid;
  gid_t s_gid;
  char s_conv;
};



struct adfs_discmap;
struct adfs_dir_ops;




struct adfs_sb_info
{
  struct adfs_discmap *s_map;
  struct adfs_dir_ops *s_dir;

  uid_t s_uid;
  gid_t s_gid;
  umode_t s_owner_mask;
  umode_t s_other_mask;

  __u32 s_ids_per_zone;
  __u32 s_idlen;
  __u32 s_map_size;
  unsigned long s_size;
  signed int s_map2blk;
  unsigned int s_log2sharesize;
  unsigned int s_version;
  unsigned int s_namelen;
};





struct qnx4_inode_entry
{
  char di_fname[16];
  qnx4_off_t di_size;
  qnx4_xtnt_t di_first_xtnt;
  __u32 di_xblk;
  __s32 di_ftime;
  __s32 di_mtime;
  __s32 di_atime;
  __s32 di_ctime;
  qnx4_nxtnt_t di_num_xtnts;
  qnx4_mode_t di_mode;
  qnx4_muid_t di_uid;
  qnx4_mgid_t di_gid;
  qnx4_nlink_t di_nlink;
  __u8 di_zero[4];
  qnx4_ftype_t di_type;
  __u8 di_status;
};

struct qnx4_link_info
{
  char dl_fname[48];
  __u32 dl_inode_blk;
  __u8 dl_inode_ndx;
  __u8 dl_spare[10];
  __u8 dl_status;
};

struct qnx4_xblk
{
  __u32 xblk_next_xblk;
  __u32 xblk_prev_xblk;
  __u8 xblk_num_xtnts;
  __u8 xblk_spare[3];
  __s32 xblk_num_blocks;
  qnx4_xtnt_t xblk_xtnts[60];
  char xblk_signature[8];
  qnx4_xtnt_t xblk_first_xtnt;
};

struct qnx4_super_block
{
  struct qnx4_inode_entry RootDir;
  struct qnx4_inode_entry Inode;
  struct qnx4_inode_entry Boot;
  struct qnx4_inode_entry AltBoot;
};

extern struct dentry *qnx4_lookup (struct inode *dir, struct dentry *dentry);
extern unsigned long qnx4_count_free_blocks (struct super_block *sb);
extern unsigned long qnx4_block_map (struct inode *inode, long iblock);

extern struct buffer_head *qnx4_getblk (struct inode *, int, int);
extern struct buffer_head *qnx4_bread (struct inode *, int, int);

extern int qnx4_create (struct inode *dir, struct dentry *dentry, int mode);
extern struct inode_operations qnx4_file_inode_operations;
extern struct inode_operations qnx4_dir_inode_operations;
extern struct file_operations qnx4_file_operations;
extern struct file_operations qnx4_dir_operations;
extern int qnx4_is_free (struct super_block *sb, long block);
extern int qnx4_set_bitmap (struct super_block *sb, long block, int busy);
extern int qnx4_create (struct inode *inode, struct dentry *dentry, int mode);
extern void qnx4_truncate (struct inode *inode);
extern void qnx4_free_inode (struct inode *inode);
extern int qnx4_unlink (struct inode *dir, struct dentry *dentry);
extern int qnx4_rmdir (struct inode *dir, struct dentry *dentry);
extern int qnx4_sync_file (struct file *file, struct dentry *dentry, int);
extern int qnx4_sync_inode (struct inode *inode);
extern int qnx4_get_block (struct inode *inode, long iblock,
			   struct buffer_head *bh, int create);






struct qnx4_sb_info
{
  struct buffer_head *sb_buf;
  struct qnx4_super_block *sb;
  unsigned int Version;
  struct qnx4_inode_entry *BitMap;
};











struct tq_struct
{
  struct list_head list;
  unsigned long sync;
  void (*routine) (void *);
  void *data;
};

typedef struct list_head task_queue;




extern task_queue tq_timer, tq_immediate, tq_disk;

extern spinlock_t tqueue_lock;





static inline int
queue_task (struct tq_struct *bh_pointer, task_queue * bh_list)
{
  int ret = 0;
  if (!test_and_set_bit (0, &bh_pointer->sync))
    {
      unsigned long flags;
      do
	{
	  do
	    {
	      __asm__ __volatile__ ("pushfl ; popl %0":"=g" (flags):);
	      __asm__ __volatile__ ("cli":::"memory");
	    }
	  while (0);;
	  (void) (&tqueue_lock);
	}
      while (0);
      list_add_tail (&bh_pointer->list, bh_list);
      do
	{
	  do
	    {
	    }
	  while (0);
	  __asm__ __volatile__ ("pushl %0 ; popfl"::"g" (flags):"memory",
				"cc");
	}
      while (0);
      ret = 1;
    }
  return ret;
}





extern void __run_task_queue (task_queue * list);

static inline void
run_task_queue (task_queue * list)
{
  if ((!list_empty (&*list)))
    __run_task_queue (list);
}



typedef enum
{
  reiserfs_attrs_cleared = 0x00000001,
} reiserfs_super_block_flags;

struct reiserfs_journal_cnode
{
  struct buffer_head *bh;
  kdev_t dev;
  unsigned long blocknr;
  long state;
  struct reiserfs_journal_list *jlist;
  struct reiserfs_journal_cnode *next;
  struct reiserfs_journal_cnode *prev;
  struct reiserfs_journal_cnode *hprev;
  struct reiserfs_journal_cnode *hnext;
};

struct reiserfs_bitmap_node
{
  int id;
  char *data;
  struct list_head list;
};

struct reiserfs_list_bitmap
{
  struct reiserfs_journal_list *journal_list;
  struct reiserfs_bitmap_node **bitmaps;
};




struct reiserfs_transaction_handle
{

  char *t_caller;
  int t_blocks_logged;
  int t_blocks_allocated;
  unsigned long t_trans_id;
  struct super_block *t_super;

  int displace_new_blocks:1;

};







struct reiserfs_journal_list
{
  unsigned long j_start;
  unsigned long j_len;
  atomic_t j_nonzerolen;
  atomic_t j_commit_left;
  atomic_t j_flushing;
  atomic_t j_commit_flushing;
  atomic_t j_older_commits_done;
  unsigned long j_trans_id;
  time_t j_timestamp;
  struct reiserfs_list_bitmap *j_list_bitmap;
  struct buffer_head *j_commit_bh;
  struct reiserfs_journal_cnode *j_realblock;
  struct reiserfs_journal_cnode *j_freedlist;
  wait_queue_head_t j_commit_wait;
  wait_queue_head_t j_flush_wait;
};

struct reiserfs_page_list;

struct reiserfs_journal
{
  struct buffer_head **j_ap_blocks;
  struct reiserfs_journal_cnode *j_last;
  struct reiserfs_journal_cnode *j_first;

  kdev_t j_dev;
  struct file *j_dev_file;
  struct block_device *j_dev_bd;
  int j_1st_reserved_block;

  long j_state;
  unsigned long j_trans_id;
  unsigned long j_mount_id;
  unsigned long j_start;
  unsigned long j_len;
  unsigned long j_len_alloc;
  atomic_t j_wcount;
  unsigned long j_bcount;
  unsigned long j_first_unflushed_offset;
  unsigned long j_last_flush_trans_id;
  struct buffer_head *j_header_bh;




  struct reiserfs_page_list *j_flush_pages;
  time_t j_trans_start_time;
  wait_queue_head_t j_wait;
  atomic_t j_wlock;
  wait_queue_head_t j_join_wait;
  atomic_t j_jlock;
  int j_journal_list_index;
  int j_list_bitmap_index;
  int j_must_wait;
  int j_next_full_flush;
  int j_next_async_flush;

  int j_cnode_used;
  int j_cnode_free;

  unsigned int s_journal_trans_max;
  unsigned int s_journal_max_batch;
  unsigned int s_journal_max_commit_age;
  unsigned int s_journal_max_trans_age;

  struct reiserfs_journal_cnode *j_cnode_free_list;
  struct reiserfs_journal_cnode *j_cnode_free_orig;

  int j_free_bitmap_nodes;
  int j_used_bitmap_nodes;
  struct list_head j_bitmap_nodes;
  struct list_head j_dirty_buffers;
  struct reiserfs_list_bitmap j_list_bitmap[5];
  struct reiserfs_journal_list j_journal_list[64];
  struct reiserfs_journal_cnode *j_hash_table[8192];
  struct reiserfs_journal_cnode *j_list_hash_table[8192];

  struct list_head j_prealloc_list;
};




typedef __u32 (*hashf_t) (const signed char *, int);

struct reiserfs_bitmap_info
{

  __u16 first_zero_hint;
  __u16 free_count;
  struct buffer_head *bh;
};

struct proc_dir_entry;

typedef struct reiserfs_proc_info_data
{
} reiserfs_proc_info_data_t;



struct reiserfs_sb_info
{
  struct buffer_head *s_sbh;


  struct reiserfs_super_block *s_rs;
  struct reiserfs_bitmap_info *s_ap_bitmap;
  struct reiserfs_journal *s_journal;
  unsigned short s_mount_state;


  void (*end_io_handler) (struct buffer_head *, int);
  hashf_t s_hash_function;


  unsigned long s_mount_opt;



  struct
  {
    unsigned long bits;
    unsigned long large_file_size;
    int border;
    int preallocmin;
    int preallocsize;


  } s_alloc_options;


  wait_queue_head_t s_wait;

  atomic_t s_generation_counter;

  unsigned long s_properties;



  int s_kmallocs;
  int s_disk_reads;
  int s_disk_writes;
  int s_fix_nodes;
  int s_do_balance;
  int s_unneeded_left_neighbor;
  int s_good_search_by_key_reada;
  int s_bmaps;
  int s_bmaps_without_search;
  int s_direct2indirect;
  int s_indirect2direct;



  int s_is_unlinked_ok;
  reiserfs_proc_info_data_t s_proc_info_data;
  struct proc_dir_entry *procdir;
  int reserved_blocks;
};

void reiserfs_file_buffer (struct buffer_head *bh, int list);
int reiserfs_is_super (struct super_block *s);
int journal_mark_dirty (struct reiserfs_transaction_handle *,
			struct super_block *, struct buffer_head *bh);
int flush_old_commits (struct super_block *s, int);
int show_reiserfs_locks (void);
int reiserfs_resize (struct super_block *, unsigned long);



struct bfs_sb_info
{
  unsigned long si_blocks;
  unsigned long si_freeb;
  unsigned long si_freei;
  unsigned long si_lf_ioff;
  unsigned long si_lf_sblk;
  unsigned long si_lf_eblk;
  unsigned long si_lasti;
  char *si_imap;
  struct buffer_head *si_sbh;
  struct bfs_super_block *si_bfs_sb;
};





struct udf_sparing_data
{
  __u16 s_packet_len;
  struct buffer_head *s_spar_map[4];
};

struct udf_virtual_data
{
  __u32 s_num_entries;
  __u16 s_start_offset;
};

struct udf_bitmap
{
  __u32 s_extLength;
  __u32 s_extPosition;
  __u16 s_nr_groups;
  struct buffer_head **s_block_bitmap;
};

struct udf_part_map
{
  union
  {
    struct udf_bitmap *s_bitmap;
    struct inode *s_table;
  } s_uspace;
  union
  {
    struct udf_bitmap *s_bitmap;
    struct inode *s_table;
  } s_fspace;
  __u32 s_partition_root;
  __u32 s_partition_len;
  __u16 s_partition_type;
  __u16 s_partition_num;
  union
  {
    struct udf_sparing_data s_sparing;
    struct udf_virtual_data s_virtual;
  } s_type_specific;
    __u32 (*s_partition_func) (struct super_block *, __u32, __u16, __u32);
  __u16 s_volumeseqnum;
  __u16 s_partition_flags;
};



struct udf_sb_info
{
  struct udf_part_map *s_partmaps;
  __u8 s_volident[32];


  __u16 s_partitions;
  __u16 s_partition;


  __s32 s_session;
  __u32 s_anchor[4];
  __u32 s_lastblock;

  struct buffer_head *s_lvidbh;


  mode_t s_umask;
  gid_t s_gid;
  uid_t s_uid;


  time_t s_recordtime;


  __u16 s_serialnum;


  __u16 s_udfrev;


  __u32 s_flags;


  struct nls_table *s_nls_map;


  struct inode *s_vat;
};







struct ncp_request_header
{
  __u16 type __attribute__ ((packed));
  __u8 sequence __attribute__ ((packed));
  __u8 conn_low __attribute__ ((packed));
  __u8 task __attribute__ ((packed));
  __u8 conn_high __attribute__ ((packed));
  __u8 function __attribute__ ((packed));
  __u8 data[0] __attribute__ ((packed));
};




struct ncp_reply_header
{
  __u16 type __attribute__ ((packed));
  __u8 sequence __attribute__ ((packed));
  __u8 conn_low __attribute__ ((packed));
  __u8 task __attribute__ ((packed));
  __u8 conn_high __attribute__ ((packed));
  __u8 completion_code __attribute__ ((packed));
  __u8 connection_state __attribute__ ((packed));
  __u8 data[0] __attribute__ ((packed));
};



struct ncp_volume_info
{
  __u32 total_blocks;
  __u32 free_blocks;
  __u32 purgeable_blocks;
  __u32 not_yet_purgeable_blocks;
  __u32 total_dir_entries;
  __u32 available_dir_entries;
  __u8 sectors_per_block;
  char volume_name[(16) + 1];
};

struct nw_info_struct
{
  __u32 spaceAlloc __attribute__ ((packed));
  __u32 attributes __attribute__ ((packed));
  __u16 flags __attribute__ ((packed));
  __u32 dataStreamSize __attribute__ ((packed));
  __u32 totalStreamSize __attribute__ ((packed));
  __u16 numberOfStreams __attribute__ ((packed));
  __u16 creationTime __attribute__ ((packed));
  __u16 creationDate __attribute__ ((packed));
  __u32 creatorID __attribute__ ((packed));
  __u16 modifyTime __attribute__ ((packed));
  __u16 modifyDate __attribute__ ((packed));
  __u32 modifierID __attribute__ ((packed));
  __u16 lastAccessDate __attribute__ ((packed));
  __u16 archiveTime __attribute__ ((packed));
  __u16 archiveDate __attribute__ ((packed));
  __u32 archiverID __attribute__ ((packed));
  __u16 inheritedRightsMask __attribute__ ((packed));
  __u32 dirEntNum __attribute__ ((packed));
  __u32 DosDirNum __attribute__ ((packed));
  __u32 volNumber __attribute__ ((packed));
  __u32 EADataSize __attribute__ ((packed));
  __u32 EAKeyCount __attribute__ ((packed));
  __u32 EAKeySize __attribute__ ((packed));
  __u32 NSCreator __attribute__ ((packed));
  __u8 nameLen __attribute__ ((packed));
  __u8 entryName[256] __attribute__ ((packed));
};

struct nw_modify_dos_info
{
  __u32 attributes __attribute__ ((packed));
  __u16 creationDate __attribute__ ((packed));
  __u16 creationTime __attribute__ ((packed));
  __u32 creatorID __attribute__ ((packed));
  __u16 modifyDate __attribute__ ((packed));
  __u16 modifyTime __attribute__ ((packed));
  __u32 modifierID __attribute__ ((packed));
  __u16 archiveDate __attribute__ ((packed));
  __u16 archiveTime __attribute__ ((packed));
  __u32 archiverID __attribute__ ((packed));
  __u16 lastAccessDate __attribute__ ((packed));
  __u16 inheritanceGrantMask __attribute__ ((packed));
  __u16 inheritanceRevokeMask __attribute__ ((packed));
  __u32 maximumSpace __attribute__ ((packed));
};

struct nw_search_sequence
{
  __u8 volNumber __attribute__ ((packed));
  __u32 dirBase __attribute__ ((packed));
  __u32 sequence __attribute__ ((packed));
};


struct ncp_mount_data
{
  int version;
  unsigned int ncp_fd;
  __kernel_uid_t mounted_uid;
  __kernel_pid_t wdog_pid;

  unsigned char mounted_vol[(16) + 1];
  unsigned int time_out;

  unsigned int retry_count;
  unsigned int flags;

  __kernel_uid_t uid;
  __kernel_gid_t gid;
  __kernel_mode_t file_mode;
  __kernel_mode_t dir_mode;
};



struct ncp_mount_data_v4
{
  int version;
  unsigned long flags;


  unsigned long mounted_uid;

  long wdog_pid;

  unsigned int ncp_fd;
  unsigned int time_out;

  unsigned int retry_count;



  unsigned long uid;
  unsigned long gid;

  unsigned long file_mode;
  unsigned long dir_mode;
};



struct ncp_mount_data_kernel
{
  unsigned long flags;
  unsigned int int_flags;

  __kernel_uid32_t mounted_uid;
  __kernel_pid_t wdog_pid;
  unsigned int ncp_fd;
  unsigned int time_out;

  unsigned int retry_count;
  unsigned char mounted_vol[(16) + 1];
  __kernel_uid32_t uid;
  __kernel_gid32_t gid;
  __kernel_mode_t file_mode;
  __kernel_mode_t dir_mode;
};






struct ncp_server
{

  struct ncp_mount_data_kernel m;



  __u8 name_space[(256) + 2];

  struct file *ncp_filp;

  u8 sequence;
  u8 task;
  u16 connection;

  u8 completion;
  u8 conn_status;



  int buffer_size;

  int reply_size;

  int packet_size;
  unsigned char *packet;


  int lock;
  struct semaphore sem;

  int current_size;
  int has_subfunction;
  int ncp_reply_size;

  int root_setuped;


  int sign_wanted;
  int sign_active;
  char sign_root[8];
  char sign_last[16];


  struct
  {
    int auth_type;
    size_t object_name_len;
    void *object_name;
    int object_type;
  } auth;

  struct
  {
    size_t len;
    void *data;
  } priv;


  struct nls_table *nls_vol;
  struct nls_table *nls_io;


  int dentry_ttl;


  unsigned int flags;
};

static inline int
ncp_conn_valid (struct ncp_server *server)
{
  return ((server->conn_status & 0x11) == 0);
}

static inline void
ncp_invalidate_conn (struct ncp_server *server)
{
  server->conn_status |= 0x01;
}



struct usbdev_sb_info
{
  struct list_head slist;
  struct list_head ilist;
  uid_t devuid;
  gid_t devgid;
  umode_t devmode;
  uid_t busuid;
  gid_t busgid;
  umode_t busmode;
  uid_t listuid;
  gid_t listgid;
  umode_t listmode;
};












struct completion
{
  unsigned int done;
  wait_queue_head_t wait;
};







static inline void
init_completion (struct completion *x)
{
  x->done = 0;
  init_waitqueue_head (&x->wait);
}

extern void wait_for_completion (struct completion *)
  __attribute__ ((regparm (3)));
extern void complete (struct completion *) __attribute__ ((regparm (3)));


struct jffs2_sb_info
{
  struct mtd_info *mtd;

  __u32 highest_ino;
  unsigned int flags;
  spinlock_t nodelist_lock;


  struct task_struct *gc_task;
  struct semaphore gc_thread_start;
  struct completion gc_thread_exit;



  struct semaphore alloc_sem;




  __u32 flash_size;
  __u32 used_size;
  __u32 dirty_size;
  __u32 free_size;
  __u32 erasing_size;
  __u32 bad_size;
  __u32 sector_size;



  __u32 nr_free_blocks;
  __u32 nr_erasing_blocks;

  __u32 nr_blocks;
  struct jffs2_eraseblock *blocks;

  struct jffs2_eraseblock *nextblock;

  struct jffs2_eraseblock *gcblock;

  struct list_head clean_list;
  struct list_head dirty_list;
  struct list_head erasing_list;
  struct list_head erase_pending_list;
  struct list_head erase_complete_list;
  struct list_head free_list;
  struct list_head bad_list;
  struct list_head bad_used_list;

  spinlock_t erase_completion_lock;

  wait_queue_head_t erase_wait;
  struct jffs2_inode_cache *inocache_list[1];
  spinlock_t inocache_lock;
};


extern struct list_head super_blocks;
extern spinlock_t sb_lock;



struct super_block
{
  struct list_head s_list;
  kdev_t s_dev;
  unsigned long s_blocksize;
  unsigned char s_blocksize_bits;
  unsigned char s_dirt;
  unsigned long long s_maxbytes;
  struct file_system_type *s_type;
  struct super_operations *s_op;
  struct dquot_operations *dq_op;
  struct quotactl_ops *s_qcop;
  unsigned long s_flags;
  unsigned long s_magic;
  struct dentry *s_root;
  struct rw_semaphore s_umount;
  struct semaphore s_lock;
  int s_count;
  atomic_t s_active;

  struct list_head s_dirty;
  struct list_head s_locked_inodes;
  struct list_head s_files;

  struct block_device *s_bdev;
  struct list_head s_instances;
  struct quota_info s_dquot;

  union
  {
    struct minix_sb_info minix_sb;
    struct ext2_sb_info ext2_sb;
    struct ext3_sb_info ext3_sb;
    struct hpfs_sb_info hpfs_sb;
    struct ntfs_sb_info ntfs_sb;
    struct msdos_sb_info msdos_sb;
    struct isofs_sb_info isofs_sb;
    struct nfs_sb_info nfs_sb;
    struct sysv_sb_info sysv_sb;
    struct affs_sb_info affs_sb;
    struct ufs_sb_info ufs_sb;
    struct efs_sb_info efs_sb;
    struct shmem_sb_info shmem_sb;
    struct romfs_sb_info romfs_sb;
    struct smb_sb_info smbfs_sb;
    struct hfs_sb_info hfs_sb;
    struct adfs_sb_info adfs_sb;
    struct qnx4_sb_info qnx4_sb;
    struct reiserfs_sb_info reiserfs_sb;
    struct bfs_sb_info bfs_sb;
    struct udf_sb_info udf_sb;
    struct ncp_server ncpfs_sb;
    struct usbdev_sb_info usbdevfs_sb;
    struct jffs2_sb_info jffs2_sb;
    struct cramfs_sb_info cramfs_sb;
    void *generic_sbp;
  } u;




  struct semaphore s_vfs_rename_sem;

  struct semaphore s_nfsd_free_path_sem;
};




extern int vfs_create (struct inode *, struct dentry *, int);
extern int vfs_mkdir (struct inode *, struct dentry *, int);
extern int vfs_mknod (struct inode *, struct dentry *, int, dev_t);
extern int vfs_symlink (struct inode *, struct dentry *, const char *);
extern int vfs_link (struct dentry *, struct inode *, struct dentry *);
extern int vfs_rmdir (struct inode *, struct dentry *);
extern int vfs_unlink (struct inode *, struct dentry *);
extern int vfs_rename (struct inode *, struct dentry *, struct inode *,
		       struct dentry *);

typedef int (*filldir_t) (void *, const char *, int, loff_t, ino_t, unsigned);

struct block_device_operations
{
  int (*open) (struct inode *, struct file *);
  int (*release) (struct inode *, struct file *);
  int (*ioctl) (struct inode *, struct file *, unsigned, unsigned long);
  int (*check_media_change) (kdev_t);
  int (*revalidate) (kdev_t);
  struct module *owner;
};






struct file_operations
{
  struct module *owner;
    loff_t (*llseek) (struct file *, loff_t, int);
    ssize_t (*read) (struct file *, char *, size_t, loff_t *);
    ssize_t (*write) (struct file *, const char *, size_t, loff_t *);
  int (*readdir) (struct file *, void *, filldir_t);
  unsigned int (*poll) (struct file *, struct poll_table_struct *);
  int (*ioctl) (struct inode *, struct file *, unsigned int, unsigned long);
  int (*mmap) (struct file *, struct vm_area_struct *);
  void (*munmap) (struct file *, struct vm_area_struct *,
		  unsigned long start, unsigned long len);
  int (*open) (struct inode *, struct file *);
  int (*flush) (struct file *);
  int (*release) (struct inode *, struct file *);
  int (*fsync) (struct file *, struct dentry *, int datasync);
  int (*fasync) (int, struct file *, int);
  int (*lock) (struct file *, int, struct file_lock *);
    ssize_t (*readv) (struct file *, const struct iovec *, unsigned long,
		      loff_t *);
    ssize_t (*writev) (struct file *, const struct iovec *, unsigned long,
		       loff_t *);
    ssize_t (*sendpage) (struct file *, struct page *, int, size_t, loff_t *,
			 int);
  unsigned long (*get_unmapped_area) (struct file *, unsigned long,
				      unsigned long, unsigned long,
				      unsigned long);
};

struct inode_operations
{
  int (*create) (struct inode *, struct dentry *, int);
  struct dentry *(*lookup) (struct inode *, struct dentry *);
  int (*link) (struct dentry *, struct inode *, struct dentry *);
  int (*unlink) (struct inode *, struct dentry *);
  int (*symlink) (struct inode *, struct dentry *, const char *);
  int (*mkdir) (struct inode *, struct dentry *, int);
  int (*rmdir) (struct inode *, struct dentry *);
  int (*mknod) (struct inode *, struct dentry *, int, int);
  int (*rename) (struct inode *, struct dentry *,
		 struct inode *, struct dentry *);
  int (*readlink) (struct dentry *, char *, int);
  int (*follow_link) (struct dentry *, struct nameidata *);
  void (*truncate) (struct inode *);
  int (*permission) (struct inode *, int);
  int (*revalidate) (struct dentry *);
  int (*setattr) (struct dentry *, struct iattr *);
  int (*getattr) (struct dentry *, struct iattr *);
  int (*setxattr) (struct dentry *, const char *, void *, size_t, int);
    ssize_t (*getxattr) (struct dentry *, const char *, void *, size_t);
    ssize_t (*listxattr) (struct dentry *, char *, size_t);
  int (*removexattr) (struct dentry *, const char *);
};

struct seq_file;





struct super_operations
{
  struct inode *(*alloc_inode) (struct super_block * sb);
  void (*destroy_inode) (struct inode *);

  void (*read_inode) (struct inode *);







  void (*read_inode2) (struct inode *, void *);
  void (*dirty_inode) (struct inode *);
  void (*write_inode) (struct inode *, int);
  void (*put_inode) (struct inode *);
  void (*delete_inode) (struct inode *);
  void (*put_super) (struct super_block *);
  void (*write_super) (struct super_block *);
  int (*sync_fs) (struct super_block *);
  void (*write_super_lockfs) (struct super_block *);
  void (*unlockfs) (struct super_block *);
  int (*statfs) (struct super_block *, struct statfs *);
  int (*remount_fs) (struct super_block *, int *, char *);
  void (*clear_inode) (struct inode *);
  void (*umount_begin) (struct super_block *);

  struct dentry *(*fh_to_dentry) (struct super_block * sb, __u32 * fh,
				  int len, int fhtype, int parent);
  int (*dentry_to_fh) (struct dentry *, __u32 * fh, int *lenp,
		       int need_parent);
  int (*show_options) (struct seq_file *, struct vfsmount *);
};

extern void __mark_inode_dirty (struct inode *, int);
static inline void
mark_inode_dirty (struct inode *inode)
{
  __mark_inode_dirty (inode, (1 | 2 | 4));
}

static inline void
mark_inode_dirty_sync (struct inode *inode)
{
  __mark_inode_dirty (inode, 1);
}

static inline void
mark_inode_dirty_pages (struct inode *inode)
{
  __mark_inode_dirty (inode, 4);
}

struct file_system_type
{
  const char *name;
  int fs_flags;
  struct super_block *(*read_super) (struct super_block *, void *, int);
  struct module *owner;
  struct file_system_type *next;
  struct list_head fs_supers;
};

extern int register_filesystem (struct file_system_type *);
extern int unregister_filesystem (struct file_system_type *);
extern struct vfsmount *kern_mount (struct file_system_type *);
extern int may_umount (struct vfsmount *);
extern long do_mount (char *, char *, char *, unsigned long, void *);



extern int vfs_statfs (struct super_block *, struct statfs *);

extern int locks_mandatory_locked (struct inode *);
extern int locks_mandatory_area (int, struct inode *, struct file *, loff_t,
				 size_t);

static inline int
locks_verify_locked (struct inode *inode)
{
  if ((((inode)->i_sb->s_flags & (64))
       && ((inode)->i_mode & (0002000 | 00010)) == 0002000))
    return locks_mandatory_locked (inode);
  return 0;
}

static inline int
locks_verify_area (int read_write, struct inode *inode,
		   struct file *filp, loff_t offset, size_t count)
{
  if (inode->i_flock
      && (((inode)->i_sb->s_flags & (64))
	  && ((inode)->i_mode & (0002000 | 00010)) == 0002000))
    return locks_mandatory_area (read_write, inode, filp, offset, count);
  return 0;
}

static inline int
locks_verify_truncate (struct inode *inode, struct file *filp, loff_t size)
{
  if (inode->i_flock
      && (((inode)->i_sb->s_flags & (64))
	  && ((inode)->i_mode & (0002000 | 00010)) == 0002000))
    return locks_mandatory_area (2, inode, filp,
				 size < inode->i_size ? size : inode->i_size,
				 (size <
				  inode->i_size ? inode->i_size -
				  size : size - inode->i_size));
  return 0;
}

static inline int
get_lease (struct inode *inode, unsigned int mode)
{
  if (inode->i_flock)
    return __get_lease (inode, mode);
  return 0;
}



__attribute__ ((regparm (0)))
     long sys_open (const char *, int, int);
__attribute__ ((regparm (0)))
     long sys_close (unsigned int);
     extern int do_truncate (struct dentry *, loff_t start);

     extern struct file *filp_open (const char *, int, int);
     extern struct file *dentry_open (struct dentry *, struct vfsmount *,
				      int);
     extern int filp_close (struct file *, fl_owner_t id);
     extern char *getname (const char *);


     extern void vfs_caches_init (unsigned long);




     enum
     { BDEV_FILE, BDEV_SWAP, BDEV_FS, BDEV_RAW };
     extern int register_blkdev (unsigned int, const char *,
				 struct block_device_operations *);
     extern int unregister_blkdev (unsigned int, const char *);
     extern struct block_device *bdget (dev_t);
     extern int bd_acquire (struct inode *inode);
     extern void bd_forget (struct inode *inode);
     extern void bdput (struct block_device *);
     extern struct char_device *cdget (dev_t);
     extern void cdput (struct char_device *);
     extern int blkdev_open (struct inode *, struct file *);
     extern int blkdev_close (struct inode *, struct file *);
     extern struct file_operations def_blk_fops;
     extern struct address_space_operations def_blk_aops;
     extern struct file_operations def_fifo_fops;
     extern int ioctl_by_bdev (struct block_device *, unsigned,
			       unsigned long);
     extern int blkdev_get (struct block_device *, mode_t, unsigned, int);
     extern int blkdev_put (struct block_device *, int);


     extern const struct block_device_operations *get_blkfops (unsigned int);
     extern int register_chrdev (unsigned int, const char *,
				 struct file_operations *);
     extern int unregister_chrdev (unsigned int, const char *);
     extern int chrdev_open (struct inode *, struct file *);
     extern const char *bdevname (kdev_t);
     extern const char *cdevname (kdev_t);
     extern const char *kdevname (kdev_t);
     extern void init_special_inode (struct inode *, umode_t, int);


     extern void make_bad_inode (struct inode *);
     extern int is_bad_inode (struct inode *);

     extern struct file_operations read_fifo_fops;
     extern struct file_operations write_fifo_fops;
     extern struct file_operations rdwr_fifo_fops;
     extern struct file_operations read_pipe_fops;
     extern struct file_operations write_pipe_fops;
     extern struct file_operations rdwr_pipe_fops;

     extern int fs_may_remount_ro (struct super_block *);

     extern int try_to_free_buffers (struct page *, unsigned int)
  __attribute__ ((regparm (3)));
     extern void refile_buffer (struct buffer_head *buf);
     extern void create_empty_buffers (struct page *, kdev_t, unsigned long);
     extern void end_buffer_io_sync (struct buffer_head *bh, int uptodate);
     extern void end_buffer_io_async (struct buffer_head *bh, int uptodate);


     extern void set_buffer_async_io (struct buffer_head *bh);






     static inline void get_bh (struct buffer_head *bh)
{
  atomic_inc (&(bh)->b_count);
}

static inline void
put_bh (struct buffer_head *bh)
{
  __asm__ __volatile__ ("":::"memory");
  atomic_dec (&bh->b_count);
}




static inline void
mark_buffer_uptodate (struct buffer_head *bh, int on)
{
  if (on)
    set_bit (BH_Uptodate, &bh->b_state);
  else
    clear_bit (BH_Uptodate, &bh->b_state);
}



static inline void
__mark_buffer_clean (struct buffer_head *bh)
{
  refile_buffer (bh);
}

static inline void
mark_buffer_clean (struct buffer_head *bh)
{
  if (test_and_clear_bit (BH_Dirty, &(bh)->b_state))
    __mark_buffer_clean (bh);
}

extern void __mark_dirty (struct buffer_head *bh)
  __attribute__ ((regparm (3)));
extern void __mark_buffer_dirty (struct buffer_head *bh)
  __attribute__ ((regparm (3)));
extern void mark_buffer_dirty (struct buffer_head *bh)
  __attribute__ ((regparm (3)));

extern void buffer_insert_list (struct buffer_head *, struct list_head *)
  __attribute__ ((regparm (3)));

static inline void
buffer_insert_inode_queue (struct buffer_head *bh, struct inode *inode)
{
  buffer_insert_list (bh, &inode->i_dirty_buffers);
}

static inline void
buffer_insert_inode_data_queue (struct buffer_head *bh, struct inode *inode)
{
  buffer_insert_list (bh, &inode->i_dirty_data_buffers);
}

static inline int
atomic_set_buffer_dirty (struct buffer_head *bh)
{
  return test_and_set_bit (BH_Dirty, &bh->b_state);
}

static inline void
mark_buffer_async (struct buffer_head *bh, int on)
{
  if (on)
    set_bit (BH_Async, &bh->b_state);
  else
    clear_bit (BH_Async, &bh->b_state);
}

static inline void
set_buffer_attached (struct buffer_head *bh)
{
  set_bit (BH_Attached, &bh->b_state);
}

static inline void
clear_buffer_attached (struct buffer_head *bh)
{
  clear_bit (BH_Attached, &bh->b_state);
}

static inline int
buffer_attached (struct buffer_head *bh)
{
  return (__builtin_constant_p (BH_Attached) ?
	  constant_test_bit ((BH_Attached),
			     (&bh->
			      b_state)) : variable_test_bit ((BH_Attached),
							     (&bh->b_state)));
}







static inline void
buffer_IO_error (struct buffer_head *bh)
{
  mark_buffer_clean (bh);



  bh->b_end_io (bh, 0);
}

static inline void
mark_buffer_dirty_inode (struct buffer_head *bh, struct inode *inode)
{
  mark_buffer_dirty (bh);
  buffer_insert_inode_queue (bh, inode);
}

extern void set_buffer_flushtime (struct buffer_head *);
extern inline int get_buffer_flushtime (void);
extern void balance_dirty (void);
extern int check_disk_change (kdev_t);
extern int invalidate_inodes (struct super_block *);
extern int invalidate_device (kdev_t, int);
extern void invalidate_inode_pages (struct inode *);
extern void invalidate_inode_pages2 (struct address_space *);
extern void invalidate_inode_buffers (struct inode *);


extern void invalidate_bdev (struct block_device *, int);
extern void __invalidate_buffers (kdev_t dev, int);
extern void sync_inodes (kdev_t);
extern void sync_unlocked_inodes (void);
extern void write_inode_now (struct inode *, int);
extern int sync_buffers (kdev_t, int);
extern void sync_dev (kdev_t);
extern int fsync_dev (kdev_t);
extern int fsync_super (struct super_block *);
extern int fsync_no_super (kdev_t);
extern void sync_inodes_sb (struct super_block *);
extern int fsync_buffers_list (struct list_head *);
static inline int
fsync_inode_buffers (struct inode *inode)
{
  return fsync_buffers_list (&inode->i_dirty_buffers);
}
static inline int
fsync_inode_data_buffers (struct inode *inode)
{
  return fsync_buffers_list (&inode->i_dirty_data_buffers);
}
extern int inode_has_buffers (struct inode *);
extern int do_fdatasync (struct file *);
extern int filemap_fdatawrite (struct address_space *);
extern int filemap_fdatasync (struct address_space *);
extern int filemap_fdatawait (struct address_space *);
extern void sync_supers (kdev_t dev, int wait);
extern int bmap (struct inode *, int);
extern int notify_change (struct dentry *, struct iattr *);
extern int permission (struct inode *, int);
extern int vfs_permission (struct inode *, int);
extern int get_write_access (struct inode *);
extern int deny_write_access (struct file *);
static inline void
put_write_access (struct inode *inode)
{
  atomic_dec (&inode->i_writecount);
}
static inline void
allow_write_access (struct file *file)
{
  if (file)
    atomic_inc (&file->f_dentry->d_inode->i_writecount);
}
extern int do_pipe (int *);

extern int open_namei (const char *, int, int, struct nameidata *);

extern int kernel_read (struct file *, unsigned long, char *, unsigned long);
extern struct file *open_exec (const char *);


extern int is_subdir (struct dentry *, struct dentry *);
extern ino_t find_inode_number (struct dentry *, struct qstr *);

static inline void *
ERR_PTR (long error)
{
  return (void *) error;
}

static inline long
PTR_ERR (const void *ptr)
{
  return (long) ptr;
}

static inline long
IS_ERR (const void *ptr)
{
  return (unsigned long) ptr > (unsigned long) -1000L;
}


enum
{ LAST_NORM, LAST_ROOT, LAST_DOT, LAST_DOTDOT, LAST_BIND };

typedef struct
{
  size_t written;
  size_t count;
  char *buf;
  int error;
} read_descriptor_t;

typedef int (*read_actor_t) (read_descriptor_t *, struct page *,
			     unsigned long, unsigned long);


extern loff_t default_llseek (struct file *file, loff_t offset, int origin);

extern int __user_walk (const char *, unsigned, struct nameidata *)
  __attribute__ ((regparm (3)));
extern int path_init (const char *, unsigned, struct nameidata *)
  __attribute__ ((regparm (3)));
extern int path_walk (const char *, struct nameidata *)
  __attribute__ ((regparm (3)));
extern int path_lookup (const char *, unsigned, struct nameidata *)
  __attribute__ ((regparm (3)));
extern int link_path_walk (const char *, struct nameidata *)
  __attribute__ ((regparm (3)));
extern void path_release (struct nameidata *);
extern int follow_down (struct vfsmount **, struct dentry **);
extern int follow_up (struct vfsmount **, struct dentry **);
extern struct dentry *lookup_one_len (const char *, struct dentry *, int);
extern struct dentry *lookup_hash (struct qstr *, struct dentry *);



extern void inode_init_once (struct inode *);
extern void __inode_init_once (struct inode *);
extern void iput (struct inode *);
extern void refile_inode (struct inode *inode);
extern void force_delete (struct inode *);
extern struct inode *igrab (struct inode *);
extern struct inode *ilookup (struct super_block *, unsigned long);
extern ino_t iunique (struct super_block *, ino_t);
extern void unlock_new_inode (struct inode *);

typedef int (*find_inode_t) (struct inode *, unsigned long, void *);

extern struct inode *iget4_locked (struct super_block *, unsigned long,
				   find_inode_t, void *);

static inline struct inode *
iget4 (struct super_block *sb, unsigned long ino,
       find_inode_t find_actor, void *opaque)
{
  struct inode *inode = iget4_locked (sb, ino, find_actor, opaque);

  if (inode && (inode->i_state & 64))
    {



      if (sb->s_op->read_inode2)
	sb->s_op->read_inode2 (inode, opaque);
      else
	sb->s_op->read_inode (inode);
      unlock_new_inode (inode);
    }

  return inode;
}

static inline struct inode *
iget (struct super_block *sb, unsigned long ino)
{
  struct inode *inode = iget4_locked (sb, ino, ((void *) 0), ((void *) 0));

  if (inode && (inode->i_state & 64))
    {
      sb->s_op->read_inode (inode);
      unlock_new_inode (inode);
    }

  return inode;
}

static inline struct inode *
iget_locked (struct super_block *sb, unsigned long ino)
{
  return iget4_locked (sb, ino, ((void *) 0), ((void *) 0));
}

extern void clear_inode (struct inode *);
extern struct inode *new_inode (struct super_block *sb);
extern void remove_suid (struct inode *inode);

extern void insert_inode_hash (struct inode *);
extern void remove_inode_hash (struct inode *);
extern struct file *get_empty_filp (void);
extern void file_move (struct file *f, struct list_head *list);
extern struct buffer_head *get_hash_table (kdev_t, int, int);
extern struct buffer_head *getblk (kdev_t, int, int);
extern void ll_rw_block (int, int, struct buffer_head *bh[]);
extern void submit_bh (int, struct buffer_head *);
extern int is_read_only (kdev_t);
extern void __brelse (struct buffer_head *);
static inline void
brelse (struct buffer_head *buf)
{
  if (buf)
    __brelse (buf);
}
extern void __bforget (struct buffer_head *);
static inline void
bforget (struct buffer_head *buf)
{
  if (buf)
    __bforget (buf);
}
extern int set_blocksize (kdev_t, int);
extern int sb_set_blocksize (struct super_block *, int);
extern int sb_min_blocksize (struct super_block *, int);
extern struct buffer_head *bread (kdev_t, int, int);
static inline struct buffer_head *
sb_bread (struct super_block *sb, int block)
{
  return bread (sb->s_dev, block, sb->s_blocksize);
}
static inline struct buffer_head *
sb_getblk (struct super_block *sb, int block)
{
  return getblk (sb->s_dev, block, sb->s_blocksize);
}
static inline struct buffer_head *
sb_get_hash_table (struct super_block *sb, int block)
{
  return get_hash_table (sb->s_dev, block, sb->s_blocksize);
}
extern void wakeup_bdflush (void);
extern void wakeup_kupdate (void);
extern void put_unused_buffer_head (struct buffer_head *bh);
extern struct buffer_head *get_unused_buffer_head (int async);
extern int block_dump;

extern int brw_page (int, struct page *, kdev_t, int[], int);

typedef int (get_block_t) (struct inode *, long, struct buffer_head *, int);


extern int try_to_release_page (struct page *page, int gfp_mask);
extern int discard_bh_page (struct page *, unsigned long, int);


extern int block_symlink (struct inode *, const char *, int);
extern int block_write_full_page (struct page *, get_block_t *);
extern int block_read_full_page (struct page *, get_block_t *);
extern int block_prepare_write (struct page *, unsigned, unsigned,
				get_block_t *);
extern int cont_prepare_write (struct page *, unsigned, unsigned,
			       get_block_t *, unsigned long *);
extern int generic_cont_expand (struct inode *inode, loff_t size);
extern int block_commit_write (struct page *page, unsigned from, unsigned to);
extern int block_sync_page (struct page *);

int generic_block_bmap (struct address_space *, long, get_block_t *);
int generic_commit_write (struct file *, struct page *, unsigned, unsigned);
int block_truncate_page (struct address_space *, loff_t, get_block_t *);
extern int generic_direct_IO (int, struct inode *, struct kiobuf *,
			      unsigned long, int, get_block_t *);
extern int waitfor_one_page (struct page *);
extern int writeout_one_page (struct page *);

extern int generic_file_mmap (struct file *, struct vm_area_struct *);
extern int file_read_actor (read_descriptor_t * desc, struct page *page,
			    unsigned long offset, unsigned long size);
extern ssize_t generic_file_read (struct file *, char *, size_t, loff_t *);
extern inline ssize_t do_generic_direct_read (struct file *, char *, size_t,
					      loff_t *);
extern int precheck_file_write (struct file *, struct inode *, size_t *,
				loff_t *);
extern ssize_t generic_file_write (struct file *, const char *, size_t,
				   loff_t *);
extern void do_generic_file_read (struct file *, loff_t *,
				  read_descriptor_t *, read_actor_t);
extern ssize_t do_generic_file_write (struct file *, const char *, size_t,
				      loff_t *);
extern ssize_t do_generic_direct_write (struct file *, const char *, size_t,
					loff_t *);
extern loff_t no_llseek (struct file *file, loff_t offset, int origin);
extern loff_t generic_file_llseek (struct file *file, loff_t offset,
				   int origin);
extern ssize_t generic_read_dir (struct file *, char *, size_t, loff_t *);
extern int generic_file_open (struct inode *inode, struct file *filp);

extern struct file_operations generic_ro_fops;

extern int vfs_readlink (struct dentry *, char *, int, const char *);
extern int vfs_follow_link (struct nameidata *, const char *);
extern int page_readlink (struct dentry *, char *, int);
extern int page_follow_link (struct dentry *, struct nameidata *);
extern struct inode_operations page_symlink_inode_operations;

extern int vfs_readdir (struct file *, filldir_t, void *);
extern int dcache_dir_open (struct inode *, struct file *);
extern int dcache_dir_close (struct inode *, struct file *);
extern loff_t dcache_dir_lseek (struct file *, loff_t, int);
extern int dcache_dir_fsync (struct file *, struct dentry *, int);
extern int dcache_readdir (struct file *, void *, filldir_t);
extern struct file_operations dcache_dir_ops;

extern struct file_system_type *get_fs_type (const char *name);
extern struct super_block *get_super (kdev_t);
extern void drop_super (struct super_block *sb);
static inline int
is_mounted (kdev_t dev)
{
  struct super_block *sb = get_super (dev);
  if (sb)
    {
      drop_super (sb);
      return 1;
    }
  return 0;
}
unsigned long generate_cluster (kdev_t, int b[], int);
unsigned long generate_cluster_swab32 (kdev_t, int b[], int);
extern kdev_t ROOT_DEV;
extern char root_device_name[];


extern void show_buffers (void);





extern ssize_t char_read (struct file *, char *, size_t, loff_t *);
extern ssize_t block_read (struct file *, char *, size_t, loff_t *);
extern int read_ahead[];

extern ssize_t char_write (struct file *, const char *, size_t, loff_t *);
extern ssize_t block_write (struct file *, const char *, size_t, loff_t *);

extern int file_fsync (struct file *, struct dentry *, int);
extern int generic_buffer_fdatasync (struct inode *inode,
				     unsigned long start_idx,
				     unsigned long end_idx);
extern int generic_osync_inode (struct inode *, int);




extern int inode_change_ok (struct inode *, struct iattr *);
extern int inode_setattr (struct inode *, struct iattr *);


extern int unshare_files (void);

static inline struct dentry *
lock_parent (struct dentry *dentry)
{
  struct dentry *dir = dget (dentry->d_parent);

  down (&dir->d_inode->i_sem);
  return dir;
}

static inline struct dentry *
get_parent (struct dentry *dentry)
{
  return dget (dentry->d_parent);
}

static inline void
unlock_dir (struct dentry *dir)
{
  up (&dir->d_inode->i_sem);
  dput (dir);
}





static inline void
double_down (struct semaphore *s1, struct semaphore *s2)
{
  if (s1 != s2)
    {
      if ((unsigned long) s1 < (unsigned long) s2)
	{
	  struct semaphore *tmp = s2;
	  s2 = s1;
	  s1 = tmp;
	}
      down (s1);
    }
  down (s2);
}


static inline void
triple_down (struct semaphore *s1, struct semaphore *s2, struct semaphore *s3)
{
  if (s1 != s2)
    {
      if ((unsigned long) s1 < (unsigned long) s2)
	{
	  if ((unsigned long) s1 < (unsigned long) s3)
	    {
	      struct semaphore *tmp = s3;
	      s3 = s1;
	      s1 = tmp;
	    }
	  if ((unsigned long) s1 < (unsigned long) s2)
	    {
	      struct semaphore *tmp = s2;
	      s2 = s1;
	      s1 = tmp;
	    }
	}
      else
	{
	  if ((unsigned long) s1 < (unsigned long) s3)
	    {
	      struct semaphore *tmp = s3;
	      s3 = s1;
	      s1 = tmp;
	    }
	  if ((unsigned long) s2 < (unsigned long) s3)
	    {
	      struct semaphore *tmp = s3;
	      s3 = s2;
	      s2 = tmp;
	    }
	}
      down (s1);
    }
  else if ((unsigned long) s2 < (unsigned long) s3)
    {
      struct semaphore *tmp = s3;
      s3 = s2;
      s2 = tmp;
    }
  down (s2);
  down (s3);
}

static inline void
double_up (struct semaphore *s1, struct semaphore *s2)
{
  up (s1);
  if (s1 != s2)
    up (s2);
}

static inline void
triple_up (struct semaphore *s1, struct semaphore *s2, struct semaphore *s3)
{
  up (s1);
  if (s1 != s2)
    up (s2);
  up (s3);
}

static inline void
double_lock (struct dentry *d1, struct dentry *d2)
{
  double_down (&d1->d_inode->i_sem, &d2->d_inode->i_sem);
}

static inline void
double_unlock (struct dentry *d1, struct dentry *d2)
{
  double_up (&d1->d_inode->i_sem, &d2->d_inode->i_sem);
  dput (d1);
  dput (d2);
}



typedef struct __user_cap_header_struct
{
  __u32 version;
  int pid;
} *cap_user_header_t;

typedef struct __user_cap_data_struct
{
  __u32 effective;
  __u32 permitted;
  __u32 inheritable;
} *cap_user_data_t;

typedef __u32 kernel_cap_t;

extern kernel_cap_t cap_bset;

static inline kernel_cap_t
cap_combine (kernel_cap_t a, kernel_cap_t b)
{
  kernel_cap_t dest;
  (dest) = (a) | (b);
  return dest;
}

static inline kernel_cap_t
cap_intersect (kernel_cap_t a, kernel_cap_t b)
{
  kernel_cap_t dest;
  (dest) = (a) & (b);
  return dest;
}

static inline kernel_cap_t
cap_drop (kernel_cap_t a, kernel_cap_t drop)
{
  kernel_cap_t dest;
  (dest) = (a) & ~(drop);
  return dest;
}

static inline kernel_cap_t
cap_invert (kernel_cap_t c)
{
  kernel_cap_t dest;
  (dest) = ~(c);
  return dest;
}



struct linux_binprm
{
  char buf[128];
  struct page *page[32];
  unsigned long p;
  int sh_bang;
  struct file *file;
  int e_uid, e_gid;
  kernel_cap_t cap_inheritable, cap_permitted, cap_effective;
  int argc, envc;
  char *filename;
  unsigned long loader, exec;
};





struct linux_binfmt
{
  struct linux_binfmt *next;
  struct module *module;
  int (*load_binary) (struct linux_binprm *, struct pt_regs * regs);
  int (*load_shlib) (struct file *);
  int (*core_dump) (long signr, struct pt_regs * regs, struct file * file);
  unsigned long min_coredump;
};

extern int register_binfmt (struct linux_binfmt *);
extern int unregister_binfmt (struct linux_binfmt *);

extern int prepare_binprm (struct linux_binprm *);
extern void remove_arg_zero (struct linux_binprm *);
extern int search_binary_handler (struct linux_binprm *, struct pt_regs *);
extern int flush_old_exec (struct linux_binprm *bprm);
extern int setup_arg_pages (struct linux_binprm *bprm);
extern int copy_strings (int argc, char **argv, struct linux_binprm *bprm);
extern int copy_strings_kernel (int argc, char **argv,
				struct linux_binprm *bprm);
extern void compute_creds (struct linux_binprm *binprm);
extern int do_coredump (long signr, struct pt_regs *regs);
extern void set_binfmt (struct linux_binfmt *new);








struct tms
{
  clock_t tms_utime;
  clock_t tms_stime;
  clock_t tms_cutime;
  clock_t tms_cstime;
};








typedef unsigned long long cycles_t;

extern cycles_t cacheflush_time;

static inline cycles_t
get_cycles (void)
{



  unsigned long long ret;

  __asm__ __volatile__ ("rdtsc":"=A" (ret));
  return ret;

}

extern unsigned long cpu_khz;


struct timex
{
  unsigned int modes;
  long offset;
  long freq;
  long maxerror;
  long esterror;
  int status;
  long constant;
  long precision;
  long tolerance;


  struct timeval time;
  long tick;

  long ppsfreq;
  long jitter;
  int shift;
  long stabil;
  long jitcnt;
  long calcnt;
  long errcnt;
  long stbcnt;

  int:32;
  int:32;
  int:32;
  int:32;
  int:32;
  int:32;
  int:32;
  int:32;
  int:32;
  int:32;
  int:32;
  int:32;
};

extern long tick;
extern int tickadj;




extern int time_state;
extern int time_status;
extern long time_offset;
extern long time_constant;
extern long time_tolerance;
extern long time_precision;
extern long time_maxerror;
extern long time_esterror;

extern long time_phase;
extern long time_freq;
extern long time_adj;
extern long time_reftime;

extern long time_adjust;


extern long pps_offset;
extern long pps_jitter;
extern long pps_freq;
extern long pps_stabil;
extern long pps_valid;


extern int pps_shift;
extern long pps_jitcnt;
extern long pps_calcnt;
extern long pps_errcnt;
extern long pps_stbcnt;



typedef struct rb_node_s
{
  struct rb_node_s *rb_parent;
  int rb_color;


  struct rb_node_s *rb_right;
  struct rb_node_s *rb_left;
}
rb_node_t;

typedef struct rb_root_s
{
  struct rb_node_s *rb_node;
}
rb_root_t;





extern void rb_insert_color (rb_node_t *, rb_root_t *);
extern void rb_erase (rb_node_t *, rb_root_t *);

static inline void
rb_link_node (rb_node_t * node, rb_node_t * parent, rb_node_t ** rb_link)
{
  node->rb_parent = parent;
  node->rb_color = 0;
  node->rb_left = node->rb_right = ((void *) 0);

  *rb_link = node;
}









typedef struct
{
  int size;
  struct semaphore sem;
  void *ldt;
} mm_context_t;








static __inline__ int
scsi_blk_major (int m)
{
  return (((m) == 8 || ((m) >= 65 && (m) <= 71)) || (m) == 11);
}


static __inline__ int
ide_blk_major (int m)
{
  return ((m) == 3 || (m) == 22 || (m) == 33 || (m) == 34 || (m) == 56
	  || (m) == 57 || (m) == 88 || (m) == 89 || (m) == 90 || (m) == 91);
}

















typedef unsigned char cc_t;
typedef unsigned int speed_t;
typedef unsigned int tcflag_t;


struct termios
{
  tcflag_t c_iflag;
  tcflag_t c_oflag;
  tcflag_t c_cflag;
  tcflag_t c_lflag;
  cc_t c_line;
  cc_t c_cc[19];
};




struct winsize
{
  unsigned short ws_row;
  unsigned short ws_col;
  unsigned short ws_xpixel;
  unsigned short ws_ypixel;
};


struct termio
{
  unsigned short c_iflag;
  unsigned short c_oflag;
  unsigned short c_cflag;
  unsigned short c_lflag;
  unsigned char c_line;
  unsigned char c_cc[8];
};





struct tty_driver
{
  int magic;
  const char *driver_name;
  const char *name;
  int name_base;
  short major;
  short minor_start;
  short num;
  short type;
  short subtype;
  struct termios init_termios;
  int flags;
  int *refcount;
  struct proc_dir_entry *proc_entry;
  struct tty_driver *other;




  struct tty_struct **table;
  struct termios **termios;
  struct termios **termios_locked;
  void *driver_state;





  int (*open) (struct tty_struct * tty, struct file * filp);
  void (*close) (struct tty_struct * tty, struct file * filp);
  int (*write) (struct tty_struct * tty, int from_user,
		const unsigned char *buf, int count);
  void (*put_char) (struct tty_struct * tty, unsigned char ch);
  void (*flush_chars) (struct tty_struct * tty);
  int (*write_room) (struct tty_struct * tty);
  int (*chars_in_buffer) (struct tty_struct * tty);
  int (*ioctl) (struct tty_struct * tty, struct file * file,
		unsigned int cmd, unsigned long arg);
  void (*set_termios) (struct tty_struct * tty, struct termios * old);
  void (*throttle) (struct tty_struct * tty);
  void (*unthrottle) (struct tty_struct * tty);
  void (*stop) (struct tty_struct * tty);
  void (*start) (struct tty_struct * tty);
  void (*hangup) (struct tty_struct * tty);
  void (*break_ctl) (struct tty_struct * tty, int state);
  void (*flush_buffer) (struct tty_struct * tty);
  void (*set_ldisc) (struct tty_struct * tty);
  void (*wait_until_sent) (struct tty_struct * tty, int timeout);
  void (*send_xchar) (struct tty_struct * tty, char ch);
  int (*read_proc) (char *page, char **start, off_t off,
		    int count, int *eof, void *data);
  int (*write_proc) (struct file * file, const char *buffer,
		     unsigned long count, void *data);




  struct tty_driver *next;
  struct tty_driver *prev;
};



struct tty_ldisc
{
  int magic;
  char *name;
  int num;
  int flags;



  int (*open) (struct tty_struct *);
  void (*close) (struct tty_struct *);
  void (*flush_buffer) (struct tty_struct * tty);
    ssize_t (*chars_in_buffer) (struct tty_struct * tty);
    ssize_t (*read) (struct tty_struct * tty, struct file * file,
		     unsigned char *buf, size_t nr);
    ssize_t (*write) (struct tty_struct * tty, struct file * file,
		      const unsigned char *buf, size_t nr);
  int (*ioctl) (struct tty_struct * tty, struct file * file,
		unsigned int cmd, unsigned long arg);
  void (*set_termios) (struct tty_struct * tty, struct termios * old);
  unsigned int (*poll) (struct tty_struct *, struct file *,
			struct poll_table_struct *);




  void (*receive_buf) (struct tty_struct *, const unsigned char *cp,
		       char *fp, int count);
  int (*receive_room) (struct tty_struct *);
  void (*write_wakeup) (struct tty_struct *);
};


struct screen_info
{
  u8 orig_x;
  u8 orig_y;
  u16 dontuse1;
  u16 orig_video_page;
  u8 orig_video_mode;
  u8 orig_video_cols;
  u16 unused2;
  u16 orig_video_ega_bx;
  u16 unused3;
  u8 orig_video_lines;
  u8 orig_video_isVGA;
  u16 orig_video_points;


  u16 lfb_width;
  u16 lfb_height;
  u16 lfb_depth;
  u32 lfb_base;
  u32 lfb_size;
  u16 dontuse2, dontuse3;
  u16 lfb_linelength;
  u8 red_size;
  u8 red_pos;
  u8 green_size;
  u8 green_pos;
  u8 blue_size;
  u8 blue_pos;
  u8 rsvd_size;
  u8 rsvd_pos;
  u16 vesapm_seg;
  u16 vesapm_off;
  u16 pages;

};

extern struct screen_info screen_info;

struct tty_flip_buffer
{
  struct tq_struct tqueue;
  struct semaphore pty_sem;
  char *char_buf_ptr;
  unsigned char *flag_buf_ptr;
  int count;
  int buf_num;
  unsigned char char_buf[2 * 512];
  char flag_buf[2 * 512];
  unsigned char slop[4];
};

struct tty_struct
{
  int magic;
  struct tty_driver driver;
  struct tty_ldisc ldisc;
  struct termios *termios, *termios_locked;
  int pgrp;
  int session;
  kdev_t device;
  unsigned long flags;
  int count;
  struct winsize winsize;
  unsigned char stopped:1, hw_stopped:1, flow_stopped:1, packet:1;
  unsigned char low_latency:1, warned:1;
  unsigned char ctrl_status;

  struct tty_struct *link;
  struct fasync_struct *fasync;
  struct tty_flip_buffer flip;
  int max_flip_cnt;
  int alt_speed;
  wait_queue_head_t write_wait;
  wait_queue_head_t read_wait;
  struct tq_struct tq_hangup;
  void *disc_data;
  void *driver_data;
  struct list_head tty_files;







  unsigned int column;
  unsigned char lnext:1, erasing:1, raw:1, real_raw:1, icanon:1;
  unsigned char closing:1;
  unsigned short minimum_to_wake;
  unsigned long overrun_time;
  int num_overrun;
  unsigned long process_char_map[256 / (8 * sizeof (unsigned long))];
  char *read_buf;
  int read_head;
  int read_tail;
  int read_cnt;
  unsigned long read_flags[4096 / (8 * sizeof (unsigned long))];
  int canon_data;
  unsigned long canon_head;
  unsigned int canon_column;
  struct semaphore atomic_read;
  struct semaphore atomic_write;
  spinlock_t read_lock;

  struct tq_struct SAK_tq;



};

extern void tty_write_flush (struct tty_struct *);

extern struct termios tty_std_termios;
extern struct tty_ldisc ldiscs[];
extern int fg_console, last_console, want_console;

extern int kmsg_redirect;

extern void con_init (void);
extern void console_init (void);

extern int lp_init (void);
extern int pty_init (void);
extern void tty_init (void);
extern int mxser_init (void);
extern int moxa_init (void);
extern int ip2_init (void);
extern int pcxe_init (void);
extern int pc_init (void);
extern int vcs_init (void);
extern int rp_init (void);
extern int cy_init (void);
extern int stl_init (void);
extern int stli_init (void);
extern int specialix_init (void);
extern int espserial_init (void);
extern int macserial_init (void);
extern int stdio_init (void);
extern int a2232board_init (void);

extern int tty_paranoia_check (struct tty_struct *tty, kdev_t device,
			       const char *routine);
extern char *tty_name (struct tty_struct *tty, char *buf);
extern void tty_wait_until_sent (struct tty_struct *tty, long timeout);
extern int tty_check_change (struct tty_struct *tty);
extern void stop_tty (struct tty_struct *tty);
extern void start_tty (struct tty_struct *tty);
extern int tty_register_ldisc (int disc, struct tty_ldisc *new_ldisc);
extern int tty_register_driver (struct tty_driver *driver);
extern int tty_unregister_driver (struct tty_driver *driver);
extern void tty_register_devfs (struct tty_driver *driver, unsigned int flags,
				unsigned minor);
extern void tty_unregister_devfs (struct tty_driver *driver, unsigned minor);
extern int tty_read_raw_data (struct tty_struct *tty, unsigned char *bufp,
			      int buflen);
extern void tty_write_message (struct tty_struct *tty, char *msg);

extern int is_orphaned_pgrp (int pgrp);
extern int is_ignored (int sig);
extern int tty_signal (int sig, struct tty_struct *tty);
extern void tty_hangup (struct tty_struct *tty);
extern void tty_vhangup (struct tty_struct *tty);
extern void tty_unhangup (struct file *filp);
extern int tty_hung_up_p (struct file *filp);
extern void do_SAK (struct tty_struct *tty);
extern void disassociate_ctty (int priv);
extern void tty_flip_buffer_push (struct tty_struct *tty);
extern int tty_get_baud_rate (struct tty_struct *tty);


extern struct tty_ldisc tty_ldisc_N_TTY;


extern int n_tty_ioctl (struct tty_struct *tty, struct file *file,
			unsigned int cmd, unsigned long arg);



extern void serial_console_init (void);



extern int pcxe_open (struct tty_struct *tty, struct file *filp);



extern void console_print (const char *);



extern int vt_ioctl (struct tty_struct *tty, struct file *file,
		     unsigned int cmd, unsigned long arg);

extern void stdio_console_init (void);







struct ipc_perm
{
  __kernel_key_t key;
  __kernel_uid_t uid;
  __kernel_gid_t gid;
  __kernel_uid_t cuid;
  __kernel_gid_t cgid;
  __kernel_mode_t mode;
  unsigned short seq;
};




struct ipc64_perm
{
  __kernel_key_t key;
  __kernel_uid32_t uid;
  __kernel_gid32_t gid;
  __kernel_uid32_t cuid;
  __kernel_gid32_t cgid;
  __kernel_mode_t mode;
  unsigned short __pad1;
  unsigned short seq;
  unsigned short __pad2;
  unsigned long __unused1;
  unsigned long __unused2;
};


struct kern_ipc_perm
{
  key_t key;
  uid_t uid;
  gid_t gid;
  uid_t cuid;
  gid_t cgid;
  mode_t mode;
  unsigned long seq;
};


struct semid_ds
{
  struct ipc_perm sem_perm;
  __kernel_time_t sem_otime;
  __kernel_time_t sem_ctime;
  struct sem *sem_base;
  struct sem_queue *sem_pending;
  struct sem_queue **sem_pending_last;
  struct sem_undo *undo;
  unsigned short sem_nsems;
};




struct semid64_ds
{
  struct ipc64_perm sem_perm;
  __kernel_time_t sem_otime;
  unsigned long __unused1;
  __kernel_time_t sem_ctime;
  unsigned long __unused2;
  unsigned long sem_nsems;
  unsigned long __unused3;
  unsigned long __unused4;
};



struct sembuf
{
  unsigned short sem_num;
  short sem_op;
  short sem_flg;
};


union semun
{
  int val;
  struct semid_ds *buf;
  unsigned short *array;
  struct seminfo *__buf;
  void *__pad;
};

struct seminfo
{
  int semmap;
  int semmni;
  int semmns;
  int semmnu;
  int semmsl;
  int semopm;
  int semume;
  int semusz;
  int semvmx;
  int semaem;
};

struct sem
{
  int semval;
  int sempid;
};


struct sem_array
{
  struct kern_ipc_perm sem_perm;
  time_t sem_otime;
  time_t sem_ctime;
  struct sem *sem_base;
  struct sem_queue *sem_pending;
  struct sem_queue **sem_pending_last;
  struct sem_undo *undo;
  unsigned long sem_nsems;
};


struct sem_queue
{
  struct sem_queue *next;
  struct sem_queue **prev;
  struct task_struct *sleeper;
  struct sem_undo *undo;
  int pid;
  int status;
  struct sem_array *sma;
  int id;
  struct sembuf *sops;
  int nsops;
  int alter;
};




struct sem_undo
{
  struct sem_undo *proc_next;
  struct sem_undo *id_next;
  int semid;
  short *semadj;
};

__attribute__ ((regparm (0)))
     long
     sys_semget (key_t key, int nsems, int semflg);
__attribute__ ((regparm (0)))
     long
     sys_semop (int semid, struct sembuf *sops, unsigned nsops);
__attribute__ ((regparm (0)))
     long
     sys_semctl (int semid, int semnum, int cmd, union semun arg);
__attribute__ ((regparm (0)))
     long
     sys_semtimedop (int semid, struct sembuf *sops,
		     unsigned nsops, const struct timespec *timeout);












     struct siginfo;

     typedef unsigned long
       old_sigset_t;

     typedef struct
     {
       unsigned long
       sig[(64 / 32)];
     } sigset_t;

     typedef void (*__sighandler_t) (int);






     struct old_sigaction
     {
       __sighandler_t
	 sa_handler;
       old_sigset_t
	 sa_mask;
       unsigned long
	 sa_flags;
       void (*sa_restorer) (void);
     };

     struct sigaction
     {
       __sighandler_t
	 sa_handler;
       unsigned long
	 sa_flags;
       void (*sa_restorer) (void);
       sigset_t
	 sa_mask;
     };

     struct k_sigaction
     {
       struct sigaction
	 sa;
     };

     typedef struct sigaltstack
     {
       void *
	 ss_sp;
       int
	 ss_flags;
       size_t
	 ss_size;
     } stack_t;






     static __inline__ void
     sigaddset (sigset_t * set, int _sig)
{
__asm__ ("btsl %1,%0": "=m" (*set): "Ir" (_sig - 1):"cc");
}

static __inline__ void
sigdelset (sigset_t * set, int _sig)
{
__asm__ ("btrl %1,%0": "=m" (*set): "Ir" (_sig - 1):"cc");
}

static __inline__ int
__const_sigismember (sigset_t * set, int _sig)
{
  unsigned long sig = _sig - 1;
  return 1 & (set->sig[sig / 32] >> (sig % 32));
}

static __inline__ int
__gen_sigismember (sigset_t * set, int _sig)
{
  int ret;
__asm__ ("btl %2,%1\n\tsbbl %0,%0": "=r" (ret): "m" (*set), "Ir" (_sig - 1):"cc");
  return ret;
}


static __inline__ int
sigfindinword (unsigned long word)
{
__asm__ ("bsfl %1,%0": "=r" (word): "rm" (word):"cc");
  return word;
}










typedef union sigval
{
  int sival_int;
  void *sival_ptr;
} sigval_t;




typedef struct siginfo
{
  int si_signo;
  int si_errno;
  int si_code;

  union
  {
    int _pad[((128 / sizeof (int)) - 3)];


    struct
    {
      pid_t _pid;
      uid_t _uid;
    } _kill;


    struct
    {
      unsigned int _timer1;
      unsigned int _timer2;
    } _timer;


    struct
    {
      pid_t _pid;
      uid_t _uid;
      sigval_t _sigval;
    } _rt;


    struct
    {
      pid_t _pid;
      uid_t _uid;
      int _status;
      clock_t _utime;
      clock_t _stime;
    } _sigchld;


    struct
    {
      void *_addr;
    } _sigfault;


    struct
    {
      int _band;
      int _fd;
    } _sigpoll;
  } _sifields;
} siginfo_t;

typedef struct sigevent
{
  sigval_t sigev_value;
  int sigev_signo;
  int sigev_notify;
  union
  {
    int _pad[((64 / sizeof (int)) - 3)];

    struct
    {
      void (*_function) (sigval_t);
      void *_attribute;
    } _sigev_thread;
  } _sigev_un;
} sigevent_t;







static inline void
copy_siginfo (siginfo_t * to, siginfo_t * from)
{
  if (from->si_code < 0)
    (__builtin_constant_p (sizeof (siginfo_t)) ?
     __constant_memcpy ((to), (from), (sizeof (siginfo_t))) : __memcpy ((to),
									(from),
									(sizeof
									 (siginfo_t))));
  else

    (__builtin_constant_p
     (3 * sizeof (int) +
      sizeof (from->_sifields._sigchld)) ? __constant_memcpy ((to), (from),
							      (3 *
							       sizeof (int) +
							       sizeof (from->
								       _sifields.
								       _sigchld)))
     : __memcpy ((to), (from),
		 (3 * sizeof (int) + sizeof (from->_sifields._sigchld))));
}

extern int copy_siginfo_to_user (siginfo_t * to, siginfo_t * from);







struct sigqueue
{
  struct sigqueue *next;
  siginfo_t info;
};

struct sigpending
{
  struct sigqueue *head, **tail;
  sigset_t signal;
};

static inline void
sigorsets (sigset_t * r, const sigset_t * a, const sigset_t * b)
{
  unsigned long a0, a1, a2, a3, b0, b1, b2, b3;
  unsigned long i;
  for (i = 0; i < (64 / 32) / 4; ++i)
    {
      a0 = a->sig[4 * i + 0];
      a1 = a->sig[4 * i + 1];
      a2 = a->sig[4 * i + 2];
      a3 = a->sig[4 * i + 3];
      b0 = b->sig[4 * i + 0];
      b1 = b->sig[4 * i + 1];
      b2 = b->sig[4 * i + 2];
      b3 = b->sig[4 * i + 3];
      r->sig[4 * i + 0] = ((a0) | (b0));
      r->sig[4 * i + 1] = ((a1) | (b1));
      r->sig[4 * i + 2] = ((a2) | (b2));
      r->sig[4 * i + 3] = ((a3) | (b3));
    }
  switch ((64 / 32) % 4)
    {
    case 3:
      a0 = a->sig[4 * i + 0];
      a1 = a->sig[4 * i + 1];
      a2 = a->sig[4 * i + 2];
      b0 = b->sig[4 * i + 0];
      b1 = b->sig[4 * i + 1];
      b2 = b->sig[4 * i + 2];
      r->sig[4 * i + 0] = ((a0) | (b0));
      r->sig[4 * i + 1] = ((a1) | (b1));
      r->sig[4 * i + 2] = ((a2) | (b2));
      break;
    case 2:
      a0 = a->sig[4 * i + 0];
      a1 = a->sig[4 * i + 1];
      b0 = b->sig[4 * i + 0];
      b1 = b->sig[4 * i + 1];
      r->sig[4 * i + 0] = ((a0) | (b0));
      r->sig[4 * i + 1] = ((a1) | (b1));
      break;
    case 1:
      a0 = a->sig[4 * i + 0];
      b0 = b->sig[4 * i + 0];
      r->sig[4 * i + 0] = ((a0) | (b0));
      break;
    }
}


static inline void
sigandsets (sigset_t * r, const sigset_t * a, const sigset_t * b)
{
  unsigned long a0, a1, a2, a3, b0, b1, b2, b3;
  unsigned long i;
  for (i = 0; i < (64 / 32) / 4; ++i)
    {
      a0 = a->sig[4 * i + 0];
      a1 = a->sig[4 * i + 1];
      a2 = a->sig[4 * i + 2];
      a3 = a->sig[4 * i + 3];
      b0 = b->sig[4 * i + 0];
      b1 = b->sig[4 * i + 1];
      b2 = b->sig[4 * i + 2];
      b3 = b->sig[4 * i + 3];
      r->sig[4 * i + 0] = ((a0) & (b0));
      r->sig[4 * i + 1] = ((a1) & (b1));
      r->sig[4 * i + 2] = ((a2) & (b2));
      r->sig[4 * i + 3] = ((a3) & (b3));
    }
  switch ((64 / 32) % 4)
    {
    case 3:
      a0 = a->sig[4 * i + 0];
      a1 = a->sig[4 * i + 1];
      a2 = a->sig[4 * i + 2];
      b0 = b->sig[4 * i + 0];
      b1 = b->sig[4 * i + 1];
      b2 = b->sig[4 * i + 2];
      r->sig[4 * i + 0] = ((a0) & (b0));
      r->sig[4 * i + 1] = ((a1) & (b1));
      r->sig[4 * i + 2] = ((a2) & (b2));
      break;
    case 2:
      a0 = a->sig[4 * i + 0];
      a1 = a->sig[4 * i + 1];
      b0 = b->sig[4 * i + 0];
      b1 = b->sig[4 * i + 1];
      r->sig[4 * i + 0] = ((a0) & (b0));
      r->sig[4 * i + 1] = ((a1) & (b1));
      break;
    case 1:
      a0 = a->sig[4 * i + 0];
      b0 = b->sig[4 * i + 0];
      r->sig[4 * i + 0] = ((a0) & (b0));
      break;
    }
}


static inline void
signandsets (sigset_t * r, const sigset_t * a, const sigset_t * b)
{
  unsigned long a0, a1, a2, a3, b0, b1, b2, b3;
  unsigned long i;
  for (i = 0; i < (64 / 32) / 4; ++i)
    {
      a0 = a->sig[4 * i + 0];
      a1 = a->sig[4 * i + 1];
      a2 = a->sig[4 * i + 2];
      a3 = a->sig[4 * i + 3];
      b0 = b->sig[4 * i + 0];
      b1 = b->sig[4 * i + 1];
      b2 = b->sig[4 * i + 2];
      b3 = b->sig[4 * i + 3];
      r->sig[4 * i + 0] = ((a0) & ~(b0));
      r->sig[4 * i + 1] = ((a1) & ~(b1));
      r->sig[4 * i + 2] = ((a2) & ~(b2));
      r->sig[4 * i + 3] = ((a3) & ~(b3));
    }
  switch ((64 / 32) % 4)
    {
    case 3:
      a0 = a->sig[4 * i + 0];
      a1 = a->sig[4 * i + 1];
      a2 = a->sig[4 * i + 2];
      b0 = b->sig[4 * i + 0];
      b1 = b->sig[4 * i + 1];
      b2 = b->sig[4 * i + 2];
      r->sig[4 * i + 0] = ((a0) & ~(b0));
      r->sig[4 * i + 1] = ((a1) & ~(b1));
      r->sig[4 * i + 2] = ((a2) & ~(b2));
      break;
    case 2:
      a0 = a->sig[4 * i + 0];
      a1 = a->sig[4 * i + 1];
      b0 = b->sig[4 * i + 0];
      b1 = b->sig[4 * i + 1];
      r->sig[4 * i + 0] = ((a0) & ~(b0));
      r->sig[4 * i + 1] = ((a1) & ~(b1));
      break;
    case 1:
      a0 = a->sig[4 * i + 0];
      b0 = b->sig[4 * i + 0];
      r->sig[4 * i + 0] = ((a0) & ~(b0));
      break;
    }
}


static inline void
signotset (sigset_t * set)
{
  unsigned long i;
  for (i = 0; i < (64 / 32) / 4; ++i)
    {
      set->sig[4 * i + 0] = (~(set->sig[4 * i + 0]));
      set->sig[4 * i + 1] = (~(set->sig[4 * i + 1]));
      set->sig[4 * i + 2] = (~(set->sig[4 * i + 2]));
      set->sig[4 * i + 3] = (~(set->sig[4 * i + 3]));
    }
  switch ((64 / 32) % 4)
    {
    case 3:
      set->sig[4 * i + 2] = (~(set->sig[4 * i + 2]));
    case 2:
      set->sig[4 * i + 1] = (~(set->sig[4 * i + 1]));
    case 1:
      set->sig[4 * i + 0] = (~(set->sig[4 * i + 0]));
    }
}




static inline void
sigemptyset (sigset_t * set)
{
  switch ((64 / 32))
    {
    default:
      (__builtin_constant_p (0)
       ? (__builtin_constant_p ((sizeof (sigset_t))) ?
	  __constant_c_and_count_memset (((set)),
					 ((0x01010101UL *
					   (unsigned char) (0))),
					 ((sizeof (sigset_t)))) :
	  __constant_c_memset (((set)),
			       ((0x01010101UL * (unsigned char) (0))),
			       ((sizeof (sigset_t)))))
       : (__builtin_constant_p ((sizeof (sigset_t))) ?
	  __memset_generic ((((set))), (((0))),
			    (((sizeof (sigset_t))))) :
	  __memset_generic (((set)), ((0)), ((sizeof (sigset_t))))));
      break;
    case 2:
      set->sig[1] = 0;
    case 1:
      set->sig[0] = 0;
      break;
    }
}

static inline void
sigfillset (sigset_t * set)
{
  switch ((64 / 32))
    {
    default:
      (__builtin_constant_p (-1)
       ? (__builtin_constant_p ((sizeof (sigset_t))) ?
	  __constant_c_and_count_memset (((set)),
					 ((0x01010101UL *
					   (unsigned char) (-1))),
					 ((sizeof (sigset_t)))) :
	  __constant_c_memset (((set)),
			       ((0x01010101UL * (unsigned char) (-1))),
			       ((sizeof (sigset_t)))))
       : (__builtin_constant_p ((sizeof (sigset_t))) ?
	  __memset_generic ((((set))), (((-1))),
			    (((sizeof (sigset_t))))) :
	  __memset_generic (((set)), ((-1)), ((sizeof (sigset_t))))));
      break;
    case 2:
      set->sig[1] = -1;
    case 1:
      set->sig[0] = -1;
      break;
    }
}

extern char *render_sigset_t (sigset_t * set, char *buffer);



static inline void
sigaddsetmask (sigset_t * set, unsigned long mask)
{
  set->sig[0] |= mask;
}

static inline void
sigdelsetmask (sigset_t * set, unsigned long mask)
{
  set->sig[0] &= ~mask;
}

static inline int
sigtestsetmask (sigset_t * set, unsigned long mask)
{
  return (set->sig[0] & mask) != 0;
}

static inline void
siginitset (sigset_t * set, unsigned long mask)
{
  set->sig[0] = mask;
  switch ((64 / 32))
    {
    default:
      (__builtin_constant_p (0)
       ? (__builtin_constant_p ((sizeof (long) * ((64 / 32) - 1))) ?
	  __constant_c_and_count_memset (((&set->sig[1])),
					 ((0x01010101UL *
					   (unsigned char) (0))),
					 ((sizeof (long) *
					   ((64 / 32) -
					    1)))) :
	  __constant_c_memset (((&set->sig[1])),
			       ((0x01010101UL * (unsigned char) (0))),
			       ((sizeof (long) *
				 ((64 / 32) -
				  1)))))
       : (__builtin_constant_p ((sizeof (long) * ((64 / 32) - 1))) ?
	  __memset_generic ((((&set->sig[1]))), (((0))),
			    (((sizeof (long) *
			       ((64 / 32) -
				1))))) : __memset_generic (((&set->sig[1])),
							   ((0)),
							   ((sizeof (long) *
							     ((64 / 32) -
							      1))))));
      break;
    case 2:
      set->sig[1] = 0;
    case 1:;
    }
}

static inline void
siginitsetinv (sigset_t * set, unsigned long mask)
{
  set->sig[0] = ~mask;
  switch ((64 / 32))
    {
    default:
      (__builtin_constant_p (-1)
       ? (__builtin_constant_p ((sizeof (long) * ((64 / 32) - 1))) ?
	  __constant_c_and_count_memset (((&set->sig[1])),
					 ((0x01010101UL *
					   (unsigned char) (-1))),
					 ((sizeof (long) *
					   ((64 / 32) -
					    1)))) :
	  __constant_c_memset (((&set->sig[1])),
			       ((0x01010101UL * (unsigned char) (-1))),
			       ((sizeof (long) *
				 ((64 / 32) -
				  1)))))
       : (__builtin_constant_p ((sizeof (long) * ((64 / 32) - 1))) ?
	  __memset_generic ((((&set->sig[1]))), (((-1))),
			    (((sizeof (long) *
			       ((64 / 32) -
				1))))) : __memset_generic (((&set->sig[1])),
							   ((-1)),
							   ((sizeof (long) *
							     ((64 / 32) -
							      1))))));
      break;
    case 2:
      set->sig[1] = -1;
    case 1:;
    }
}



static inline void
init_sigpending (struct sigpending *sig)
{
  sigemptyset (&sig->signal);
  sig->head = ((void *) 0);
  sig->tail = &sig->head;
}

extern long do_sigpending (void *, unsigned long);







extern unsigned securebits;






struct fs_struct
{
  atomic_t count;
  rwlock_t lock;
  int umask;
  struct dentry *root, *pwd, *altroot;
  struct vfsmount *rootmnt, *pwdmnt, *altrootmnt;
};

extern void exit_fs (struct task_struct *);
extern void set_fs_altroot (void);






static inline void
set_fs_root (struct fs_struct *fs,
	     struct vfsmount *mnt, struct dentry *dentry)
{
  struct dentry *old_root;
  struct vfsmount *old_rootmnt;
  (void) (&fs->lock);
  old_root = fs->root;
  old_rootmnt = fs->rootmnt;
  fs->rootmnt = mntget (mnt);
  fs->root = dget (dentry);
  do
    {
    }
  while (0);
  if (old_root)
    {
      dput (old_root);
      mntput (old_rootmnt);
    }
}






static inline void
set_fs_pwd (struct fs_struct *fs, struct vfsmount *mnt, struct dentry *dentry)
{
  struct dentry *old_pwd;
  struct vfsmount *old_pwdmnt;
  (void) (&fs->lock);
  old_pwd = fs->pwd;
  old_pwdmnt = fs->pwdmnt;
  fs->pwdmnt = mntget (mnt);
  fs->pwd = dget (dentry);
  do
    {
    }
  while (0);
  if (old_pwd)
    {
      dput (old_pwd);
      mntput (old_pwdmnt);
    }
}

struct fs_struct *copy_fs_struct (struct fs_struct *old);
void put_fs_struct (struct fs_struct *fs);


struct exec_domain;

extern unsigned long avenrun[];

extern int nr_running, nr_threads;
extern int last_pid;







struct rusage
{
  struct timeval ru_utime;
  struct timeval ru_stime;
  long ru_maxrss;
  long ru_ixrss;
  long ru_idrss;
  long ru_isrss;
  long ru_minflt;
  long ru_majflt;
  long ru_nswap;
  long ru_inblock;
  long ru_oublock;
  long ru_msgsnd;
  long ru_msgrcv;
  long ru_nsignals;
  long ru_nvcsw;
  long ru_nivcsw;
};

struct rlimit
{
  unsigned long rlim_cur;
  unsigned long rlim_max;
};





struct sched_param
{
  int sched_priority;
};

struct completion;

extern rwlock_t tasklist_lock;
extern spinlock_t runqueue_lock;
extern spinlock_t mmlist_lock;

extern void sched_init (void);
extern void init_idle (void);
extern void show_state (void);
extern void cpu_init (void);
extern void trap_init (void);
extern void update_process_times (int user);
extern void update_one_process (struct task_struct *p, unsigned long user,
				unsigned long system, int cpu);


extern signed long schedule_timeout (signed long timeout)
  __attribute__ ((regparm (3)));
__attribute__ ((regparm (0)))
     void
     do_schedule (void);
__attribute__ ((regparm (0)))
     void
     kern_schedule (void);
__attribute__ ((regparm (0)))
     void
     kern_do_schedule (struct pt_regs);

     extern int
     schedule_task (struct tq_struct *task);
     extern void
     flush_scheduled_tasks (void);
     extern int
     start_context_thread (void);
     extern int
     current_is_keventd (void);

     struct namespace;



     struct files_struct
     {
       atomic_t
	 count;
       rwlock_t
	 file_lock;
       int
	 max_fds;
       int
	 max_fdset;
       int
	 next_fd;
       struct file **
	 fd;
       fd_set *
	 close_on_exec;
       fd_set *
	 open_fds;
       fd_set
	 close_on_exec_init;
       fd_set
	 open_fds_init;
       struct file *
	 fd_array[32];
     };

     extern int
       max_map_count;

     struct mm_struct
     {
       struct vm_area_struct *
	 mmap;
       rb_root_t
	 mm_rb;
       struct vm_area_struct *
	 mmap_cache;
       pgd_t *
	 pgd;
       atomic_t
	 mm_users;
       atomic_t
	 mm_count;
       int
	 map_count;
       struct rw_semaphore
	 mmap_sem;
       spinlock_t
	 page_table_lock;

       struct list_head
	 mmlist;




       unsigned long
	 start_code,
	 end_code,
	 start_data,
	 end_data;
       unsigned long
	 start_brk,
	 brk,
	 start_stack;
       unsigned long
	 arg_start,
	 arg_end,
	 env_start,
	 env_end;
       unsigned long
	 rss,
	 total_vm,
	 locked_vm;
       unsigned long
	 def_flags;
       unsigned long
	 cpu_vm_mask;
       unsigned long
	 swap_address;

       unsigned
	 dumpable:
	 1;


       mm_context_t
	 context;
     };

     extern int
       mmlist_nr;

     struct signal_struct
     {
       atomic_t
	 count;
       struct k_sigaction
	 action[64];
       spinlock_t
	 siglock;
     };

     struct user_struct
     {
       atomic_t
	 __count;
       atomic_t
	 processes;
       atomic_t
	 files;


       struct user_struct *
       next, **
	 pprev;
       uid_t
	 uid;
     };






     extern struct user_struct
       root_user;


     struct task_struct
     {



       volatile long
	 state;
       unsigned long
	 flags;
       int
	 sigpending;
       mm_segment_t
	 addr_limit;



       struct exec_domain *
	 exec_domain;
       volatile long
	 need_resched;
       unsigned long
	 ptrace;

       int
	 lock_depth;






       long
	 counter;
       long
	 nice;
       unsigned long
	 policy;
       struct mm_struct *
	 mm;
       int
	 processor;

       unsigned long
	 cpus_runnable,
	 cpus_allowed;




       struct list_head
	 run_list;
       unsigned long
	 sleep_time;

       struct task_struct *
       next_task, *
	 prev_task;
       struct mm_struct *
	 active_mm;
       struct list_head
	 local_pages;
       unsigned int
	 allocation_order,
	 nr_local_pages;


       struct linux_binfmt *
	 binfmt;
       int
	 exit_code,
	 exit_signal;
       int
	 pdeath_signal;

       unsigned long
	 personality;
       int
	 did_exec:
	 1;
       unsigned
	 task_dumpable:
	 1;
       pid_t
	 pid;
       pid_t
	 pgrp;
       pid_t
	 tty_old_pgrp;
       pid_t
	 session;
       pid_t
	 tgid;

       int
	 leader;





       struct task_struct *
       p_opptr, *
       p_pptr, *
       p_cptr, *
       p_ysptr, *
	 p_osptr;
       struct list_head
	 thread_group;


       struct task_struct *
	 pidhash_next;
       struct task_struct **
	 pidhash_pprev;

       wait_queue_head_t
	 wait_chldexit;
       struct completion *
	 vfork_done;
       unsigned long
	 rt_priority;
       unsigned long
	 it_real_value,
	 it_prof_value,
	 it_virt_value;
       unsigned long
	 it_real_incr,
	 it_prof_incr,
	 it_virt_incr;
       struct timer_list
	 real_timer;
       struct tms
	 times;
       unsigned long
	 start_time;
       long
	 per_cpu_utime[1],
	 per_cpu_stime[1];

       unsigned long
	 min_flt,
	 maj_flt,
	 nswap,
	 cmin_flt,
	 cmaj_flt,
	 cnswap;
       int
	 swappable:
	 1;

       uid_t
	 uid,
	 euid,
	 suid,
	 fsuid;
       gid_t
	 gid,
	 egid,
	 sgid,
	 fsgid;
       int
	 ngroups;
       gid_t
	 groups[32];
       kernel_cap_t
	 cap_effective,
	 cap_inheritable,
	 cap_permitted;
       int
	 keep_capabilities:
	 1;
       struct user_struct *
	 user;

       struct rlimit
	 rlim[11];
       unsigned short
	 used_math;
       char
	 comm[16];

       int
	 link_count,
	 total_link_count;
       struct tty_struct *
	 tty;
       unsigned int
	 locks;

       struct sem_undo *
	 semundo;
       struct sem_queue *
	 semsleeping;

       struct thread_struct
	 thread;

       struct fs_struct *
	 fs;

       struct files_struct *
	 files;

       struct namespace *
	 namespace;

       spinlock_t
	 sigmask_lock;
       struct signal_struct *
	 sig;

       sigset_t
	 blocked;
       struct sigpending
	 pending;

       unsigned long
	 sas_ss_sp;
       size_t
	 sas_ss_size;
       int (*notifier) (void *priv);
       void *
	 notifier_data;
       sigset_t *
	 notifier_mask;


       u32
	 parent_exec_id;
       u32
	 self_exec_id;

       spinlock_t
	 alloc_lock;


       void *
	 journal_info;
     };

     extern void
     yield (void);




     extern struct exec_domain
       default_exec_domain;

     union task_union
     {
       struct task_struct
	 task;
       unsigned long
       stack[2048 * sizeof (long) / sizeof (long)];
     };

     extern union task_union
       init_task_union;

     extern struct mm_struct
       init_mm;
     extern struct task_struct *
       init_tasks[1];



     extern struct task_struct *
     pidhash[(4096 >> 2)];



     static inline void
     hash_pid (struct task_struct *p)
{
  struct task_struct **htable =
    &pidhash[((((p->pid) >> 8) ^ (p->pid)) & ((4096 >> 2) - 1))];

  if ((p->pidhash_next = *htable) != ((void *) 0))
    (*htable)->pidhash_pprev = &p->pidhash_next;
  *htable = p;
  p->pidhash_pprev = htable;
}

static inline void
unhash_pid (struct task_struct *p)
{
  if (p->pidhash_next)
    p->pidhash_next->pidhash_pprev = p->pidhash_pprev;
  *p->pidhash_pprev = p->pidhash_next;
}

static inline struct task_struct *
find_task_by_pid (int pid)
{
  struct task_struct *p, **htable =
    &pidhash[((((pid) >> 8) ^ (pid)) & ((4096 >> 2) - 1))];

  for (p = *htable; p && p->pid != pid; p = p->pidhash_next)
    ;

  return p;
}



static inline void
task_set_cpu (struct task_struct *tsk, unsigned int cpu)
{
  tsk->processor = cpu;
  tsk->cpus_runnable = 1UL << cpu;
}

static inline void
task_release_cpu (struct task_struct *tsk)
{
  tsk->cpus_runnable = ~0UL;
}


extern struct user_struct *alloc_uid (uid_t);
extern void free_uid (struct user_struct *);
extern void switch_uid (struct user_struct *);





struct task_struct;

static inline struct task_struct *
get_current (void)
{
  struct task_struct *current;
__asm__ ("andl %%esp,%0; ": "=r" (current):"0" (~8191UL));
  return current;
}



extern unsigned long volatile jiffies;
extern unsigned long itimer_ticks;
extern unsigned long itimer_next;
extern struct timeval xtime;
extern void do_timer (struct pt_regs *);

extern unsigned int *prof_buffer;
extern unsigned long prof_len;
extern unsigned long prof_shift;



extern void __wake_up (wait_queue_head_t * q, unsigned int mode, int nr)
  __attribute__ ((regparm (3)));
extern void __wake_up_sync (wait_queue_head_t * q, unsigned int mode, int nr)
  __attribute__ ((regparm (3)));
extern void sleep_on (wait_queue_head_t * q) __attribute__ ((regparm (3)));
extern long sleep_on_timeout (wait_queue_head_t * q, signed long timeout)
  __attribute__ ((regparm (3)));

extern void interruptible_sleep_on (wait_queue_head_t * q)
  __attribute__ ((regparm (3)));
extern long interruptible_sleep_on_timeout (wait_queue_head_t * q,
					    signed long timeout)
  __attribute__ ((regparm (3)));

extern int wake_up_process (struct task_struct *tsk)
  __attribute__ ((regparm (3)));

__attribute__ ((regparm (0)))
     long
     sys_wait4 (pid_t pid, unsigned int *stat_addr, int options,
		struct rusage *ru);

     extern int
     in_group_p (gid_t);
     extern int
     in_egroup_p (gid_t);

     extern void
     proc_caches_init (void);
     extern void
     flush_signals (struct task_struct *);
     extern void
     flush_signal_handlers (struct task_struct *);
     extern void
     sig_exit (int, int, struct siginfo *);
     extern int
     dequeue_signal (sigset_t *, siginfo_t *);
     extern void
     block_all_signals (int (*notifier) (void *priv), void *priv,
			sigset_t * mask);
     extern void
     unblock_all_signals (void);
     extern int
     send_sig_info (int, struct siginfo *, struct task_struct *);
     extern int
     force_sig_info (int, struct siginfo *, struct task_struct *);
     extern int
     kill_pg_info (int, struct siginfo *, pid_t);
     extern int
     kill_sl_info (int, struct siginfo *, pid_t);
     extern int
     kill_proc_info (int, struct siginfo *, pid_t);
     extern void
     notify_parent (struct task_struct *, int);
     extern void
     do_notify_parent (struct task_struct *, int);
     extern void
     force_sig (int, struct task_struct *);
     extern int
     send_sig (int, struct task_struct *, int);
     extern int
     kill_pg (pid_t, int, int);
     extern int
     kill_sl (pid_t, int, int);
     extern int
     kill_proc (pid_t, int, int);
     extern int
     do_sigaction (int, const struct k_sigaction *, struct k_sigaction *);
     extern int
     do_sigaltstack (const stack_t *, stack_t *, unsigned long);

     static inline int
     signal_pending (struct task_struct *p)
{
  return (p->sigpending != 0);
}





static inline int
has_pending_signals (sigset_t * signal, sigset_t * blocked)
{
  unsigned long ready;
  long i;

  switch ((64 / 32))
    {
    default:
      for (i = (64 / 32), ready = 0; --i >= 0;)
	ready |= signal->sig[i] & ~blocked->sig[i];
      break;

    case 4:
      ready = signal->sig[3] & ~blocked->sig[3];
      ready |= signal->sig[2] & ~blocked->sig[2];
      ready |= signal->sig[1] & ~blocked->sig[1];
      ready |= signal->sig[0] & ~blocked->sig[0];
      break;

    case 2:
      ready = signal->sig[1] & ~blocked->sig[1];
      ready |= signal->sig[0] & ~blocked->sig[0];
      break;

    case 1:
      ready = signal->sig[0] & ~blocked->sig[0];
    }
  return ready != 0;
}





static inline void
recalc_sigpending (struct task_struct *t)
{
  t->sigpending = has_pending_signals (&t->pending.signal, &t->blocked);
}



static inline int
on_sig_stack (unsigned long sp)
{
  return (sp - get_current ()->sas_ss_sp < get_current ()->sas_ss_size);
}

static inline int
sas_ss_flags (unsigned long sp)
{
  return (get_current ()->sas_ss_size == 0 ? 2 : on_sig_stack (sp) ? 1 : 0);
}

extern int request_irq (unsigned int,
			void (*handler) (int, void *, struct pt_regs *),
			unsigned long, const char *, void *);
extern void free_irq (unsigned int, void *);

static inline int
suser (void)
{
  if (!
      ((1 << (0 + 1)) & 0x00000000 ? (1 << (0)) & 0x00000000 : (1 << (0)) &
       securebits) && get_current ()->euid == 0)
    {
      get_current ()->flags |= 0x00000100;
      return 1;
    }
  return 0;
}

static inline int
fsuser (void)
{
  if (!
      ((1 << (0 + 1)) & 0x00000000 ? (1 << (0)) & 0x00000000 : (1 << (0)) &
       securebits) && get_current ()->fsuid == 0)
    {
      get_current ()->flags |= 0x00000100;
      return 1;
    }
  return 0;
}







static inline int
capable (int cap)
{

  if (((get_current ()->cap_effective) & (1 << (cap))))



    {
      get_current ()->flags |= 0x00000100;
      return 1;
    }
  return 0;
}




extern struct mm_struct *mm_alloc (void);

extern struct mm_struct *start_lazy_tlb (void);
extern void end_lazy_tlb (struct mm_struct *mm);


extern inline void __mmdrop (struct mm_struct *)
  __attribute__ ((regparm (3)));
static inline void
mmdrop (struct mm_struct *mm)
{
  if (atomic_dec_and_test (&mm->mm_count))
    __mmdrop (mm);
}


extern void mmput (struct mm_struct *);

extern void mm_release (void);




extern struct file **alloc_fd_array (int);
extern int expand_fd_array (struct files_struct *, int nr);
extern void free_fd_array (struct file **, int);

extern fd_set *alloc_fdset (int);
extern int expand_fdset (struct files_struct *, int nr);
extern void free_fdset (fd_set *, int);

extern int copy_thread (int, unsigned long, unsigned long, unsigned long,
			struct task_struct *, struct pt_regs *);
extern void flush_thread (void);
extern void exit_thread (void);

extern void exit_mm (struct task_struct *);
extern void exit_files (struct task_struct *);
extern void exit_sighand (struct task_struct *);

extern void reparent_to_init (void);
extern void daemonize (void);

extern int do_execve (char *, char **, char **, struct pt_regs *);
extern int do_fork (unsigned long, unsigned long, struct pt_regs *,
		    unsigned long);

extern void add_wait_queue (wait_queue_head_t * q, wait_queue_t * wait)
  __attribute__ ((regparm (3)));
extern void add_wait_queue_exclusive (wait_queue_head_t * q,
				      wait_queue_t * wait)
  __attribute__ ((regparm (3)));
extern void remove_wait_queue (wait_queue_head_t * q, wait_queue_t * wait)
  __attribute__ ((regparm (3)));

extern long kernel_thread (int (*fn) (void *), void *arg,
			   unsigned long flags);

static inline void
del_from_runqueue (struct task_struct *p)
{
  nr_running--;
  p->sleep_time = jiffies;
  list_del (&p->run_list);
  p->run_list.next = ((void *) 0);
}

static inline int
task_on_runqueue (struct task_struct *p)
{
  return (p->run_list.next != ((void *) 0));
}

static inline void
unhash_process (struct task_struct *p)
{
  if (task_on_runqueue (p))
    __out_of_line_bug (912);
  do
    {
      __asm__ __volatile__ ("cli":::"memory");
      (void) (&tasklist_lock);
    }
  while (0);
  nr_threads--;
  unhash_pid (p);
  do
    {
      (p)->next_task->prev_task = (p)->prev_task;
      (p)->prev_task->next_task = (p)->next_task;
      if ((p)->p_osptr)
	(p)->p_osptr->p_ysptr = (p)->p_ysptr;
      if ((p)->p_ysptr)
	(p)->p_ysptr->p_osptr = (p)->p_osptr;
      else
	(p)->p_pptr->p_cptr = (p)->p_osptr;
    }
  while (0);
  list_del (&p->thread_group);
  do
    {
      do
	{
	}
      while (0);
      __asm__ __volatile__ ("sti":::"memory");
    }
  while (0);
}


static inline void
task_lock (struct task_struct *p)
{
  (void) (&p->alloc_lock);
}

static inline void
task_unlock (struct task_struct *p)
{
  do
    {
    }
  while (0);
}


static inline char *
d_path (struct dentry *dentry, struct vfsmount *vfsmnt, char *buf, int buflen)
{
  char *res;
  struct vfsmount *rootmnt;
  struct dentry *root;
  (void) (&get_current ()->fs->lock);
  rootmnt = mntget (get_current ()->fs->rootmnt);
  root = dget (get_current ()->fs->root);
  do
    {
    }
  while (0);
  (void) (&dcache_lock);
  res = __d_path (dentry, vfsmnt, root, rootmnt, buf, buflen);
  do
    {
    }
  while (0);
  dput (root);
  mntput (rootmnt);
  return res;
}

static inline int
need_resched (void)
{
  return (__builtin_expect ((get_current ()->need_resched), 0));
}

extern void __cond_resched (void);
static inline void
cond_resched (void)
{
  if (need_resched ())
    __cond_resched ();
}

static inline void
schedule (void)
{

  kern_schedule ();



}












typedef struct free_area_struct
{
  struct list_head free_list;
  unsigned long *map;
} free_area_t;

struct pglist_data;

typedef struct zone_watermarks_s
{
  unsigned long min, low, high;
} zone_watermarks_t;

typedef struct zone_struct
{



  spinlock_t lock;
  unsigned long free_pages;







  zone_watermarks_t watermarks[3];







  unsigned long need_balance;

  unsigned long nr_active_pages, nr_inactive_pages;

  unsigned long nr_cache_pages;





  free_area_t free_area[10];

  wait_queue_head_t *wait_table;
  unsigned long wait_table_size;
  unsigned long wait_table_shift;




  struct pglist_data *zone_pgdat;
  struct page *zone_mem_map;
  unsigned long zone_start_paddr;
  unsigned long zone_start_mapnr;




  char *name;
  unsigned long size;
  unsigned long realsize;
} zone_t;

typedef struct zonelist_struct
{
  zone_t *zones[3 + 1];
} zonelist_t;

struct bootmem_data;
typedef struct pglist_data
{
  zone_t node_zones[3];
  zonelist_t node_zonelists[0x0f + 1];
  int nr_zones;
  struct page *node_mem_map;
  unsigned long *valid_addr_bitmap;
  struct bootmem_data *bdata;
  unsigned long node_start_paddr;
  unsigned long node_start_mapnr;
  unsigned long node_size;
  int node_id;
  struct pglist_data *node_next;
} pg_data_t;

extern int numnodes;
extern pg_data_t *pgdat_list;

struct page;
extern void show_free_areas_core (pg_data_t * pgdat);
extern void free_area_init_core (int nid, pg_data_t * pgdat,
				 struct page **gmap,
				 unsigned long *zones_size,
				 unsigned long paddr,
				 unsigned long *zholes_size,
				 struct page *pmap);

extern pg_data_t contig_page_data;

static inline zone_t *
next_zone (zone_t * zone)
{
  pg_data_t *pgdat = zone->zone_pgdat;

  if (zone - pgdat->node_zones < 3 - 1)
    zone++;

  else if (pgdat->node_next)
    {
      pgdat = pgdat->node_next;
      zone = pgdat->node_zones;
    }
  else
    zone = ((void *) 0);

  return zone;
}




union swap_header
{
  struct
  {
    char reserved[(1UL << 12) - 10];
    char magic[10];
  } magic;
  struct
  {
    char bootbits[1024];
    unsigned int version;
    unsigned int last_page;
    unsigned int nr_badpages;
    unsigned int padding[125];
    unsigned int badpages[1];
  } info;
};

struct swap_info_struct
{
  unsigned int flags;
  kdev_t swap_device;
  spinlock_t sdev_lock;
  struct dentry *swap_file;
  struct vfsmount *swap_vfsmnt;
  unsigned short *swap_map;
  unsigned int lowest_bit;
  unsigned int highest_bit;
  unsigned int cluster_next;
  unsigned int cluster_nr;
  int prio;
  int pages;
  unsigned long max;
  int next;
};

extern int nr_swap_pages;




extern unsigned int nr_free_pages (void);
extern unsigned int nr_free_buffer_pages (void);
extern unsigned int freeable_lowmem (void);
extern int nr_active_pages;
extern int nr_inactive_pages;
extern unsigned long page_cache_size;
extern atomic_t buffermem_pages;

extern spinlock_cacheline_t pagecache_lock_cacheline;


extern void __remove_inode_page (struct page *);


struct task_struct;
struct vm_area_struct;
struct sysinfo;

struct zone_t;


extern void lru_cache_add (struct page *) __attribute__ ((regparm (3)));
extern void __lru_cache_del (struct page *) __attribute__ ((regparm (3)));
extern void lru_cache_del (struct page *) __attribute__ ((regparm (3)));

extern void activate_page (struct page *) __attribute__ ((regparm (3)));

extern void swap_setup (void);


extern wait_queue_head_t kswapd_wait;
extern int try_to_free_pages_zone (zone_t *, unsigned int)
  __attribute__ ((regparm (3)));
extern int try_to_free_pages (unsigned int) __attribute__ ((regparm (3)));
extern int vm_vfs_scan_ratio, vm_cache_scan_ratio, vm_lru_balance_ratio,
  vm_passes, vm_gfp_debug, vm_mapped_ratio;


extern void rw_swap_page (int, struct page *);
extern void rw_swap_page_nolock (int, swp_entry_t, char *);






extern void show_swap_cache_info (void);

extern int add_to_swap_cache (struct page *, swp_entry_t);
extern void __delete_from_swap_cache (struct page *page);
extern void delete_from_swap_cache (struct page *page);
extern void free_page_and_swap_cache (struct page *page);
extern struct page *lookup_swap_cache (swp_entry_t);
extern struct page *read_swap_cache_async (swp_entry_t);


extern void out_of_memory (void);


extern int total_swap_pages;
extern unsigned int nr_swapfiles;
extern struct swap_info_struct swap_info[];
extern int is_swap_partition (kdev_t);
extern void si_swapinfo (struct sysinfo *);
extern swp_entry_t get_swap_page (void);
extern void get_swaphandle_info (swp_entry_t, unsigned long *, kdev_t *,
				 struct inode **);
extern int swap_duplicate (swp_entry_t);
extern int valid_swaphandles (swp_entry_t, unsigned long *);
extern void swap_free (swp_entry_t);
extern void free_swap_and_cache (swp_entry_t);
struct swap_list_t
{
  int head;
  int next;
};
extern struct swap_list_t swap_list;
__attribute__ ((regparm (0)))
     long
     sys_swapoff (const char *);
__attribute__ ((regparm (0)))
     long
     sys_swapon (const char *, int);

     extern spinlock_cacheline_t
       pagemap_lru_lock_cacheline;


     extern void
     mark_page_accessed (struct page *) __attribute__ ((regparm (3)));

     extern void
     delta_nr_active_pages (struct page *page, long delta);



     extern void
     delta_nr_inactive_pages (struct page *page, long delta);

     extern void
     delta_nr_cache_pages (struct page *page, long delta);



     extern spinlock_t
       swaplock;






     extern int
     shmem_unuse (swp_entry_t entry, struct page *page);



     extern unsigned long
       max_mapnr;
     extern unsigned long
       num_physpages;
     extern unsigned long
       num_mappedpages;
     extern void *
       high_memory;
     extern int
       page_cluster;

     extern struct list_head
       active_list;
     extern struct list_head
       inactive_list;








     static inline int
     __acpi_acquire_global_lock (unsigned int *lock)
{
  unsigned int old, new, val;
  do
    {
      old = *lock;
      new = (((old & ~0x3) + 2) + ((old >> 1) & 0x1));
      val =
	((__typeof__ (*(lock)))
	 __cmpxchg ((lock), (unsigned long) (old), (unsigned long) (new),
		    sizeof (*(lock))));
    }
  while (__builtin_expect ((val != old), 0));
  return (new < 3) ? -1 : 0;
}

static inline int
__acpi_release_global_lock (unsigned int *lock)
{
  unsigned int old, new, val;
  do
    {
      old = *lock;
      new = old & ~0x3;
      val =
	((__typeof__ (*(lock)))
	 __cmpxchg ((lock), (unsigned long) (old), (unsigned long) (new),
		    sizeof (*(lock))));
    }
  while (__builtin_expect ((val != old), 0));
  return old & 0x1;
}


static inline void
acpi_noirq_set (void)
{
}
static inline int
acpi_irq_balance_set (char *str)
{
  return 0;
}




struct local_apic
{

  struct
  {
    unsigned int __reserved[4];
  } __reserved_01;

  struct
  {
    unsigned int __reserved[4];
  } __reserved_02;

  struct
  {
    unsigned int __reserved_1:24, phys_apic_id:4, __reserved_2:4;
    unsigned int __reserved[3];
  } id;

  const struct
  {
    unsigned int version:8, __reserved_1:8, max_lvt:8, __reserved_2:8;
    unsigned int __reserved[3];
  } version;

  struct
  {
    unsigned int __reserved[4];
  } __reserved_03;

  struct
  {
    unsigned int __reserved[4];
  } __reserved_04;

  struct
  {
    unsigned int __reserved[4];
  } __reserved_05;

  struct
  {
    unsigned int __reserved[4];
  } __reserved_06;

  struct
  {
    unsigned int priority:8, __reserved_1:24;
    unsigned int __reserved_2[3];
  } tpr;

  const struct
  {
    unsigned int priority:8, __reserved_1:24;
    unsigned int __reserved_2[3];
  } apr;

  const struct
  {
    unsigned int priority:8, __reserved_1:24;
    unsigned int __reserved_2[3];
  } ppr;

  struct
  {
    unsigned int eoi;
    unsigned int __reserved[3];
  } eoi;

  struct
  {
    unsigned int __reserved[4];
  } __reserved_07;

  struct
  {
    unsigned int __reserved_1:24, logical_dest:8;
    unsigned int __reserved_2[3];
  } ldr;

  struct
  {
    unsigned int __reserved_1:28, model:4;
    unsigned int __reserved_2[3];
  } dfr;

  struct
  {
    unsigned int spurious_vector:8,
      apic_enabled:1, focus_cpu:1, __reserved_2:22;
    unsigned int __reserved_3[3];
  } svr;

  struct
  {
    unsigned int bitfield;
    unsigned int __reserved[3];
  } isr[8];

  struct
  {
    unsigned int bitfield;
    unsigned int __reserved[3];
  } tmr[8];

  struct
  {
    unsigned int bitfield;
    unsigned int __reserved[3];
  } irr[8];

  union
  {
    struct
    {
      unsigned int send_cs_error:1,
	receive_cs_error:1,
	send_accept_error:1,
	receive_accept_error:1,
	__reserved_1:1,
	send_illegal_vector:1,
	receive_illegal_vector:1, illegal_register_address:1, __reserved_2:24;
      unsigned int __reserved_3[3];
    } error_bits;
    struct
    {
      unsigned int errors;
      unsigned int __reserved_3[3];
    } all_errors;
  } esr;

  struct
  {
    unsigned int __reserved[4];
  } __reserved_08;

  struct
  {
    unsigned int __reserved[4];
  } __reserved_09;

  struct
  {
    unsigned int __reserved[4];
  } __reserved_10;

  struct
  {
    unsigned int __reserved[4];
  } __reserved_11;

  struct
  {
    unsigned int __reserved[4];
  } __reserved_12;

  struct
  {
    unsigned int __reserved[4];
  } __reserved_13;

  struct
  {
    unsigned int __reserved[4];
  } __reserved_14;

  struct
  {
    unsigned int vector:8,
      delivery_mode:3,
      destination_mode:1,
      delivery_status:1,
      __reserved_1:1,
      level:1, trigger:1, __reserved_2:2, shorthand:2, __reserved_3:12;
    unsigned int __reserved_4[3];
  } icr1;

  struct
  {
    union
    {
      unsigned int __reserved_1:24, phys_dest:4, __reserved_2:4;
      unsigned int __reserved_3:24, logical_dest:8;
    } dest;
    unsigned int __reserved_4[3];
  } icr2;

  struct
  {
    unsigned int vector:8,
      __reserved_1:4,
      delivery_status:1,
      __reserved_2:3, mask:1, timer_mode:1, __reserved_3:14;
    unsigned int __reserved_4[3];
  } lvt_timer;

  struct
  {
    unsigned int __reserved[4];
  } __reserved_15;

  struct
  {
    unsigned int vector:8,
      delivery_mode:3,
      __reserved_1:1,
      delivery_status:1, __reserved_2:3, mask:1, __reserved_3:15;
    unsigned int __reserved_4[3];
  } lvt_pc;

  struct
  {
    unsigned int vector:8,
      delivery_mode:3,
      __reserved_1:1,
      delivery_status:1,
      polarity:1, remote_irr:1, trigger:1, mask:1, __reserved_2:15;
    unsigned int __reserved_3[3];
  } lvt_lint0;

  struct
  {
    unsigned int vector:8,
      delivery_mode:3,
      __reserved_1:1,
      delivery_status:1,
      polarity:1, remote_irr:1, trigger:1, mask:1, __reserved_2:15;
    unsigned int __reserved_3[3];
  } lvt_lint1;

  struct
  {
    unsigned int vector:8,
      __reserved_1:4,
      delivery_status:1, __reserved_2:3, mask:1, __reserved_3:15;
    unsigned int __reserved_4[3];
  } lvt_error;

  struct
  {
    unsigned int initial_count;
    unsigned int __reserved_2[3];
  } timer_icr;

  const struct
  {
    unsigned int curr_count;
    unsigned int __reserved_2[3];
  } timer_ccr;

  struct
  {
    unsigned int __reserved[4];
  } __reserved_16;

  struct
  {
    unsigned int __reserved[4];
  } __reserved_17;

  struct
  {
    unsigned int __reserved[4];
  } __reserved_18;

  struct
  {
    unsigned int __reserved[4];
  } __reserved_19;

  struct
  {
    unsigned int divisor:4, __reserved_1:28;
    unsigned int __reserved_2[3];
  } timer_dcr;

  struct
  {
    unsigned int __reserved[4];
  } __reserved_20;

} __attribute__ ((packed));


enum fixed_addresses
{

  FIX_APIC_BASE,


  FIX_IO_APIC_BASE_0,
  FIX_IO_APIC_BASE_END = FIX_IO_APIC_BASE_0 + 8 - 1,

  __end_of_permanent_fixed_addresses,


  FIX_BTMAP_END = __end_of_permanent_fixed_addresses,
  FIX_BTMAP_BEGIN = FIX_BTMAP_END + 16 - 1,
  __end_of_fixed_addresses
};

extern void __set_fixmap (enum fixed_addresses idx,
			  unsigned long phys, pgprot_t flags);

extern void __this_fixmap_does_not_exist (void);






static inline unsigned long
fix_to_virt (const unsigned int idx)
{

  if (idx >= __end_of_fixed_addresses)
    __this_fixmap_does_not_exist ();

  return ((0xffffe000UL) - ((idx) << 12));
}








extern pgd_t swapper_pg_dir[1024];
extern void paging_init (void);

extern unsigned long pgkern_mask;

extern unsigned long empty_zero_page[1024];



static inline int
pgd_none (pgd_t pgd)
{
  return 0;
}
static inline int
pgd_bad (pgd_t pgd)
{
  return 0;
}
static inline int
pgd_present (pgd_t pgd)
{
  return 1;
}


static inline pmd_t *
pmd_offset (pgd_t * dir, unsigned long address)
{
  return (pmd_t *) dir;
}



extern unsigned long pg0[1024];

static inline int
pte_read (pte_t pte)
{
  return (pte).pte_low & 0x004;
}
static inline int
pte_exec (pte_t pte)
{
  return (pte).pte_low & 0x004;
}
static inline int
pte_dirty (pte_t pte)
{
  return (pte).pte_low & 0x040;
}
static inline int
pte_young (pte_t pte)
{
  return (pte).pte_low & 0x020;
}
static inline int
pte_write (pte_t pte)
{
  return (pte).pte_low & 0x002;
}

static inline pte_t
pte_rdprotect (pte_t pte)
{
  (pte).pte_low &= ~0x004;
  return pte;
}
static inline pte_t
pte_exprotect (pte_t pte)
{
  (pte).pte_low &= ~0x004;
  return pte;
}
static inline pte_t
pte_mkclean (pte_t pte)
{
  (pte).pte_low &= ~0x040;
  return pte;
}
static inline pte_t
pte_mkold (pte_t pte)
{
  (pte).pte_low &= ~0x020;
  return pte;
}
static inline pte_t
pte_wrprotect (pte_t pte)
{
  (pte).pte_low &= ~0x002;
  return pte;
}
static inline pte_t
pte_mkread (pte_t pte)
{
  (pte).pte_low |= 0x004;
  return pte;
}
static inline pte_t
pte_mkexec (pte_t pte)
{
  (pte).pte_low |= 0x004;
  return pte;
}
static inline pte_t
pte_mkdirty (pte_t pte)
{
  (pte).pte_low |= 0x040;
  return pte;
}
static inline pte_t
pte_mkyoung (pte_t pte)
{
  (pte).pte_low |= 0x020;
  return pte;
}
static inline pte_t
pte_mkwrite (pte_t pte)
{
  (pte).pte_low |= 0x002;
  return pte;
}

static inline int
ptep_test_and_clear_dirty (pte_t * ptep)
{
  return test_and_clear_bit (6, ptep);
}
static inline int
ptep_test_and_clear_young (pte_t * ptep)
{
  return test_and_clear_bit (5, ptep);
}
static inline void
ptep_set_wrprotect (pte_t * ptep)
{
  clear_bit (1, ptep);
}
static inline void
ptep_mkdirty (pte_t * ptep)
{
  set_bit (6, ptep);
}


static inline pte_t
pte_modify (pte_t pte, pgprot_t newprot)
{
  pte.pte_low &= ((~((1UL << 12) - 1)) | 0x020 | 0x040);
  pte.pte_low |= ((newprot).pgprot);
  return pte;
}


struct page;
int change_page_attr (struct page *, int, pgprot_t prot);


struct vm_area_struct
{
  struct mm_struct *vm_mm;
  unsigned long vm_start;
  unsigned long vm_end;



  struct vm_area_struct *vm_next;

  pgprot_t vm_page_prot;
  unsigned long vm_flags;

  rb_node_t vm_rb;






  struct vm_area_struct *vm_next_share;
  struct vm_area_struct **vm_pprev_share;


  struct vm_operations_struct *vm_ops;


  unsigned long vm_pgoff;

  struct file *vm_file;
  unsigned long vm_raend;
  void *vm_private_data;
};

extern int vm_min_readahead;
extern int vm_max_readahead;





extern pgprot_t protection_map[16];







struct vm_operations_struct
{
  void (*open) (struct vm_area_struct * area);
  void (*close) (struct vm_area_struct * area);
  struct page *(*nopage) (struct vm_area_struct * area, unsigned long address,
			  int unused);
};

typedef struct page
{
  struct list_head list;
  struct address_space *mapping;
  unsigned long index;
  struct page *next_hash;

  atomic_t count;
  unsigned long flags;

  struct list_head lru;

  struct page **pprev_hash;
  struct buffer_head *buffers;

} mem_map_t;

struct zone_struct;
extern struct zone_struct *zone_table[];

static inline zone_t *
page_zone (struct page *page)
{
  return zone_table[page->flags >> (32 - 8)];
}

static inline void
set_page_zone (struct page *page, unsigned long zone_num)
{
  page->flags &= ~(~0UL << (32 - 8));
  page->flags |= zone_num << (32 - 8);
}


extern void set_page_dirty (struct page *) __attribute__ ((regparm (3)));

extern mem_map_t *mem_map;







extern struct page *_alloc_pages (unsigned int gfp_mask, unsigned int order)
  __attribute__ ((regparm (3)));
extern struct page *__alloc_pages (unsigned int gfp_mask, unsigned int order,
				   zonelist_t * zonelist)
  __attribute__ ((regparm (3)));
extern struct page *alloc_pages_node (int nid, unsigned int gfp_mask,
				      unsigned int order);


static inline struct page *
arch_validate (struct page *page, unsigned int gfp_mask, int order)
{
  return (page);
}



static inline void
arch_free_page (struct page *page, int order)
{
}


static inline struct page *
alloc_pages (unsigned int gfp_mask, unsigned int order)
{



  if (order >= 10)
    return ((void *) 0);
  return arch_validate (_alloc_pages (gfp_mask, order), gfp_mask, order);
}



extern unsigned long __get_free_pages (unsigned int gfp_mask,
				       unsigned int order)
  __attribute__ ((regparm (3)));
extern unsigned long get_zeroed_page (unsigned int gfp_mask)
  __attribute__ ((regparm (3)));

extern void __free_pages (struct page *page, unsigned int order)
  __attribute__ ((regparm (3)));
extern void free_pages (unsigned long addr, unsigned int order)
  __attribute__ ((regparm (3)));




extern void show_free_areas (void);
extern void show_free_areas_node (pg_data_t * pgdat);

extern void clear_page_tables (struct mm_struct *, unsigned long, int);

extern int fail_writepage (struct page *);
struct page *shmem_nopage (struct vm_area_struct *vma, unsigned long address,
			   int unused);
struct file *shmem_file_setup (char *name, loff_t size);
extern void shmem_lock (struct file *file, int lock);
extern int shmem_zero_setup (struct vm_area_struct *);

extern void zap_page_range (struct mm_struct *mm, unsigned long address,
			    unsigned long size);
extern int copy_page_range (struct mm_struct *dst, struct mm_struct *src,
			    struct vm_area_struct *vma);
extern int remap_page_range (unsigned long from, unsigned long to,
			     unsigned long size, pgprot_t prot);
extern int zeromap_page_range (unsigned long from, unsigned long size,
			       pgprot_t prot);

extern int vmtruncate (struct inode *inode, loff_t offset);
extern pmd_t *__pmd_alloc (struct mm_struct *mm, pgd_t * pgd,
			   unsigned long address)
  __attribute__ ((regparm (3)));
extern pte_t *pte_alloc (struct mm_struct *mm, pmd_t * pmd,
			 unsigned long address) __attribute__ ((regparm (3)));
extern int handle_mm_fault (struct mm_struct *mm, struct vm_area_struct *vma,
			    unsigned long address, int write_access);
extern int make_pages_present (unsigned long addr, unsigned long end);
extern int access_process_vm (struct task_struct *tsk, unsigned long addr,
			      void *buf, int len, int write);
extern int ptrace_readdata (struct task_struct *tsk, unsigned long src,
			    char *dst, int len);
extern int ptrace_writedata (struct task_struct *tsk, char *src,
			     unsigned long dst, int len);
extern int ptrace_attach (struct task_struct *tsk);
extern int ptrace_detach (struct task_struct *, unsigned int);
extern void ptrace_disable (struct task_struct *);
extern int ptrace_check_attach (struct task_struct *task, int kill);

int get_user_pages (struct task_struct *tsk, struct mm_struct *mm,
		    unsigned long start, int len, int write, int force,
		    struct page **pages, struct vm_area_struct **vmas);

extern long do_mprotect (struct mm_struct *mm, unsigned long start,
			 size_t len, unsigned long prot);






static inline pmd_t *
pmd_alloc (struct mm_struct *mm, pgd_t * pgd, unsigned long address)
{
  if (pgd_none (*pgd))
    return __pmd_alloc (mm, pgd, address);
  return pmd_offset (pgd, address);
}

extern int pgt_cache_water[2];
extern int check_pgt_cache (void);

extern void free_area_init (unsigned long *zones_size);
extern void free_area_init_node (int nid, pg_data_t * pgdat,
				 struct page *pmap, unsigned long *zones_size,
				 unsigned long zone_start_paddr,
				 unsigned long *zholes_size);
extern void mem_init (void);
extern void show_mem (void);
extern void si_meminfo (struct sysinfo *val);
extern void swapin_readahead (swp_entry_t);

extern struct address_space swapper_space;


static inline int
is_page_cache_freeable (struct page *page)
{
  return ((&(page)->count)->counter) - !!page->buffers == 1;
}

extern int can_share_swap_page (struct page *) __attribute__ ((regparm (3)));
extern int remove_exclusive_swap_page (struct page *)
  __attribute__ ((regparm (3)));

extern void __free_pte (pte_t);


extern void lock_vma_mappings (struct vm_area_struct *);
extern void unlock_vma_mappings (struct vm_area_struct *);
extern void insert_vm_struct (struct mm_struct *, struct vm_area_struct *);
extern void __insert_vm_struct (struct mm_struct *, struct vm_area_struct *);
extern void build_mmap_rb (struct mm_struct *);
extern void exit_mmap (struct mm_struct *);

extern unsigned long get_unmapped_area (struct file *, unsigned long,
					unsigned long, unsigned long,
					unsigned long);

extern unsigned long do_mmap_pgoff (struct mm_struct *mm, struct file *file,
				    unsigned long addr, unsigned long len,
				    unsigned long prot, unsigned long flag,
				    unsigned long pgoff);

static inline unsigned long
do_mmap (struct file *file, unsigned long addr,
	 unsigned long len, unsigned long prot,
	 unsigned long flag, unsigned long offset)
{
  unsigned long ret = -22;
  if ((offset + (((len) + (1UL << 12) - 1) & (~((1UL << 12) - 1)))) < offset)
    goto out;
  if (!(offset & ~(~((1UL << 12) - 1))))
    ret = do_mmap_pgoff (get_current ()->mm, file, addr, len, prot, flag,
			 offset >> 12);
out:
  return ret;
}

extern int do_munmap (struct mm_struct *, unsigned long, size_t);

extern unsigned long do_brk (unsigned long, unsigned long);

static inline void
__vma_unlink (struct mm_struct *mm, struct vm_area_struct *vma,
	      struct vm_area_struct *prev)
{
  prev->vm_next = vma->vm_next;
  rb_erase (&vma->vm_rb, &mm->mm_rb);
  if (mm->mmap_cache == vma)
    mm->mmap_cache = prev;
}

static inline int
can_vma_merge (struct vm_area_struct *vma, unsigned long vm_flags)
{
  if (!vma->vm_file && vma->vm_flags == vm_flags)
    return 1;
  else
    return 0;
}

struct zone_t;

extern void remove_inode_page (struct page *);
extern unsigned long page_unuse (struct page *);
extern void truncate_inode_pages (struct address_space *, loff_t);


extern int filemap_sync (struct vm_area_struct *, unsigned long, size_t,
			 unsigned int);
extern struct page *filemap_nopage (struct vm_area_struct *, unsigned long,
				    int);

static inline unsigned int
pf_gfp_mask (unsigned int gfp_mask)
{

  if (get_current ()->flags & 0x00004000)
    gfp_mask &= ~(0x40 | 0x80 | 0x100);

  return gfp_mask;
}



static inline int
expand_stack (struct vm_area_struct *vma, unsigned long address)
{
  unsigned long grow;






  address &= (~((1UL << 12) - 1));
  (void) (&vma->vm_mm->page_table_lock);
  grow = (vma->vm_start - address) >> 12;
  if (vma->vm_end - address > get_current ()->rlim[3].rlim_cur ||
      ((vma->vm_mm->total_vm + grow) << 12) >
      get_current ()->rlim[9].rlim_cur)
    {
      do
	{
	}
      while (0);
      return -12;
    }
  vma->vm_start = address;
  vma->vm_pgoff -= grow;
  vma->vm_mm->total_vm += grow;
  if (vma->vm_flags & 0x00002000)
    vma->vm_mm->locked_vm += grow;
  do
    {
    }
  while (0);
  return 0;
}


extern struct vm_area_struct *find_vma (struct mm_struct *mm,
					unsigned long addr);
extern struct vm_area_struct *find_vma_prev (struct mm_struct *mm,
					     unsigned long addr,
					     struct vm_area_struct **pprev);



static inline struct vm_area_struct *
find_vma_intersection (struct mm_struct *mm, unsigned long start_addr,
		       unsigned long end_addr)
{
  struct vm_area_struct *vma = find_vma (mm, start_addr);

  if (vma && end_addr <= vma->vm_start)
    vma = ((void *) 0);
  return vma;
}

extern struct vm_area_struct *find_extend_vma (struct mm_struct *mm,
					       unsigned long addr);

extern struct page *vmalloc_to_page (void *addr);








static inline pgd_t *
get_pgd_slow (void)
{
  pgd_t *pgd =
    (pgd_t *) __get_free_pages (((0x20 | 0x10 | 0x40 | 0x80 | 0x100)), 0);

  if (pgd)
    {
      (__builtin_constant_p (0)
       ? (__builtin_constant_p
	  ((((((unsigned long) (0xC0000000))) / (1UL << 22)) *
	    sizeof (pgd_t))) ? __constant_c_and_count_memset (((pgd)),
							      ((0x01010101UL *
								(unsigned
								 char) (0))),
							      ((((((unsigned
								    long)
								   (0xC0000000)))
								 /
								 (1UL << 22))
								*
								sizeof
								(pgd_t)))) :
	  __constant_c_memset (((pgd)),
			       ((0x01010101UL * (unsigned char) (0))),
			       ((((((unsigned long) (0xC0000000))) /
				  (1UL << 22)) *
				 sizeof (pgd_t)))))
       : (__builtin_constant_p
	  ((((((unsigned long) (0xC0000000))) / (1UL << 22)) *
	    sizeof (pgd_t))) ? __memset_generic ((((pgd))), (((0))),
						 (((((((unsigned
							long) (0xC0000000))) /
						     (1UL << 22)) *
						    sizeof (pgd_t))))) :
	  __memset_generic (((pgd)), ((0)),
			    ((((((unsigned long) (0xC0000000))) /
			       (1UL << 22)) * sizeof (pgd_t))))));
      (__builtin_constant_p
       ((1024 -
	 ((((unsigned long) (0xC0000000))) / (1UL << 22))) *
	sizeof (pgd_t)) ? __constant_memcpy ((pgd +
					      ((((unsigned
						  long) (0xC0000000))) /
					       (1UL << 22))),
					     (swapper_pg_dir +
					      ((((unsigned
						  long) (0xC0000000))) /
					       (1UL << 22))),
					     ((1024 -
					       ((((unsigned
						   long) (0xC0000000))) /
						(1UL << 22))) *
					      sizeof (pgd_t))) :
       __memcpy ((pgd + ((((unsigned long) (0xC0000000))) / (1UL << 22))),
		 (swapper_pg_dir +
		  ((((unsigned long) (0xC0000000))) / (1UL << 22))),
		 ((1024 -
		   ((((unsigned long) (0xC0000000))) / (1UL << 22))) *
		  sizeof (pgd_t))));


    }
  return pgd;
}



static inline pgd_t *
get_pgd_fast (void)
{
  unsigned long *ret;

  if ((ret = (boot_cpu_data.pgd_quick)) != ((void *) 0))
    {
      (boot_cpu_data.pgd_quick) = (unsigned long *) (*ret);
      ret[0] = 0;
      (boot_cpu_data.pgtable_cache_sz)--;
    }
  else
    ret = (unsigned long *) get_pgd_slow ();
  return (pgd_t *) ret;
}

static inline void
free_pgd_fast (pgd_t * pgd)
{
  *(unsigned long *) pgd = (unsigned long) (boot_cpu_data.pgd_quick);
  (boot_cpu_data.pgd_quick) = (unsigned long *) pgd;
  (boot_cpu_data.pgtable_cache_sz)++;
}

static inline void
free_pgd_slow (pgd_t * pgd)
{







  free_pages (((unsigned long) pgd), 0);

}

static inline pte_t *
pte_alloc_one (struct mm_struct *mm, unsigned long address)
{
  pte_t *pte;

  pte = (pte_t *) __get_free_pages (((0x20 | 0x10 | 0x40 | 0x80 | 0x100)), 0);
  if (pte)
    (__builtin_constant_p (0)
     ? (__builtin_constant_p (((1UL << 12))) ?
	__constant_c_and_count_memset ((((void *) (pte))),
				       ((0x01010101UL * (unsigned char) (0))),
				       (((1UL << 12)))) :
	__constant_c_memset ((((void *) (pte))),
			     ((0x01010101UL * (unsigned char) (0))),
			     (((1UL << 12)))))
     : (__builtin_constant_p (((1UL << 12))) ?
	__memset_generic (((((void *) (pte)))), (((0))),
			  ((((1UL << 12))))) :
	__memset_generic ((((void *) (pte))), ((0)), (((1UL << 12))))));
  return pte;
}

static inline pte_t *
pte_alloc_one_fast (struct mm_struct *mm, unsigned long address)
{
  unsigned long *ret;

  if ((ret = (unsigned long *) (boot_cpu_data.pte_quick)) != ((void *) 0))
    {
      (boot_cpu_data.pte_quick) = (unsigned long *) (*ret);
      ret[0] = ret[1];
      (boot_cpu_data.pgtable_cache_sz)--;
    }
  return (pte_t *) ret;
}

static inline void
pte_free_fast (pte_t * pte)
{
  *(unsigned long *) pte = (unsigned long) (boot_cpu_data.pte_quick);
  (boot_cpu_data.pte_quick) = (unsigned long *) pte;
  (boot_cpu_data.pgtable_cache_sz)++;
}

static __inline__ void
pte_free_slow (pte_t * pte)
{
  free_pages (((unsigned long) pte), 0);
}


extern int do_check_pgt_cache (int, int);

static inline void
flush_tlb_mm (struct mm_struct *mm)
{
  if (mm == get_current ()->active_mm)
    do
      {
	unsigned int tmpreg;
	__asm__ __volatile__ ("movl %%cr3, %0;  # flush TLB \n"
			      "movl %0, %%cr3;              \n":"=r"
			      (tmpreg)::"memory");
      }
    while (0);
}

static inline void
flush_tlb_page (struct vm_area_struct *vma, unsigned long addr)
{
  if (vma->vm_mm == get_current ()->active_mm)
    __asm__ __volatile__ ("invlpg %0"::"m" (*(char *) addr));
}

static inline void
flush_tlb_range (struct mm_struct *mm, unsigned long start, unsigned long end)
{
  if (mm == get_current ()->active_mm)
    do
      {
	unsigned int tmpreg;
	__asm__ __volatile__ ("movl %%cr3, %0;  # flush TLB \n"
			      "movl %0, %%cr3;              \n":"=r"
			      (tmpreg)::"memory");
      }
    while (0);
}


static inline void
flush_tlb_pgtables (struct mm_struct *mm,
		    unsigned long start, unsigned long end)
{
  flush_tlb_mm (mm);
}



static inline unsigned int
nr_free_highpages (void)
{
  return 0;
}

static inline void *
kmap (struct page *page)
{
  return ((void
	   *) ((unsigned
		long) ((((page) - page_zone (page)->zone_mem_map) << 12) +
		       page_zone (page)->zone_start_paddr) +
	       ((unsigned long) (0xC0000000))));
}


static inline void
clear_user_highpage (struct page *page, unsigned long vaddr)
{
  void *addr = kmap (page);
  (__builtin_constant_p (0)
   ? (__builtin_constant_p (((1UL << 12))) ?
      __constant_c_and_count_memset ((((void *) (addr))),
				     ((0x01010101UL * (unsigned char) (0))),
				     (((1UL << 12)))) :
      __constant_c_memset ((((void *) (addr))),
			   ((0x01010101UL * (unsigned char) (0))),
			   (((1UL << 12)))))
   : (__builtin_constant_p (((1UL << 12))) ?
      __memset_generic (((((void *) (addr)))), (((0))),
			((((1UL << 12))))) :
      __memset_generic ((((void *) (addr))), ((0)), (((1UL << 12))))));
  do
    {
    }
  while (0);
}

static inline void
clear_highpage (struct page *page)
{
  (__builtin_constant_p (0)
   ? (__builtin_constant_p (((1UL << 12))) ?
      __constant_c_and_count_memset ((((void *) (kmap (page)))),
				     ((0x01010101UL * (unsigned char) (0))),
				     (((1UL << 12)))) :
      __constant_c_memset ((((void *) (kmap (page)))),
			   ((0x01010101UL * (unsigned char) (0))),
			   (((1UL << 12)))))
   : (__builtin_constant_p (((1UL << 12))) ?
      __memset_generic (((((void *) (kmap (page))))), (((0))),
			((((1UL << 12))))) :
      __memset_generic ((((void *) (kmap (page)))), ((0)), (((1UL << 12))))));
  do
    {
    }
  while (0);
}




static inline void
memclear_highpage_flush (struct page *page, unsigned int offset,
			 unsigned int size)
{
  char *kaddr;

  if (offset + size > (1UL << 12))
    __out_of_line_bug (105);
  kaddr = kmap (page);
  (__builtin_constant_p (0)
   ? (__builtin_constant_p ((size)) ?
      __constant_c_and_count_memset (((kaddr + offset)),
				     ((0x01010101UL * (unsigned char) (0))),
				     ((size))) :
      __constant_c_memset (((kaddr + offset)),
			   ((0x01010101UL * (unsigned char) (0))),
			   ((size)))) : (__builtin_constant_p ((size)) ?
					 __memset_generic ((((kaddr +
							      offset))),
							   (((0))),
							   (((size)))) :
					 __memset_generic (((kaddr + offset)),
							   ((0)), ((size)))));
  do
    {
    }
  while (0);
  do
    {
    }
  while (0);
  do
    {
    }
  while (0);
}

static inline void
copy_user_highpage (struct page *to, struct page *from, unsigned long vaddr)
{
  char *vfrom, *vto;

  vfrom = kmap (from);
  vto = kmap (to);
  (__builtin_constant_p ((1UL << 12)) ?
   __constant_memcpy (((void *) (vto)), ((void *) (vfrom)),
		      ((1UL << 12))) : __memcpy (((void *) (vto)),
						 ((void *) (vfrom)),
						 ((1UL << 12))));
  do
    {
    }
  while (0);
  do
    {
    }
  while (0);
}

static inline void
copy_highpage (struct page *to, struct page *from)
{
  char *vfrom, *vto;

  vfrom = kmap (from);
  vto = kmap (to);
  (__builtin_constant_p ((1UL << 12)) ?
   __constant_memcpy (((void *) (vto)), ((void *) (vfrom)),
		      ((1UL << 12))) : __memcpy (((void *) (vto)),
						 ((void *) (vfrom)),
						 ((1UL << 12))));
  do
    {
    }
  while (0);
  do
    {
    }
  while (0);
}



struct nf_conntrack
{
  atomic_t use;
  void (*destroy) (struct nf_conntrack *);
};

struct nf_ct_info
{
  struct nf_conntrack *master;
};


struct sk_buff_head
{

  struct sk_buff *next;
  struct sk_buff *prev;

  __u32 qlen;
  spinlock_t lock;
};

struct sk_buff;



typedef struct skb_frag_struct skb_frag_t;

struct skb_frag_struct
{
  struct page *page;
  __u16 page_offset;
  __u16 size;
};




struct skb_shared_info
{
  atomic_t dataref;
  unsigned int nr_frags;
  struct sk_buff *frag_list;
  skb_frag_t frags[6];
};

struct sk_buff
{

  struct sk_buff *next;
  struct sk_buff *prev;

  struct sk_buff_head *list;
  struct sock *sk;
  struct timeval stamp;
  struct net_device *dev;
  struct net_device *real_dev;





  union
  {
    struct tcphdr *th;
    struct udphdr *uh;
    struct icmphdr *icmph;
    struct igmphdr *igmph;
    struct iphdr *ipiph;
    struct spxhdr *spxh;
    unsigned char *raw;
  } h;


  union
  {
    struct iphdr *iph;
    struct ipv6hdr *ipv6h;
    struct arphdr *arph;
    struct ipxhdr *ipxh;
    unsigned char *raw;
  } nh;


  union
  {
    struct ethhdr *ethernet;
    unsigned char *raw;
  } mac;

  struct dst_entry *dst;







  char cb[96];
  int alloc_pool;

  unsigned int len;
  unsigned int data_len;
  unsigned int csum;
  unsigned char __unused, cloned, pkt_type, ip_summed;
  __u32 priority;
  atomic_t users;
  unsigned short protocol;
  unsigned short security;
  unsigned int truesize;

  unsigned char *head;
  unsigned char *data;
  unsigned char *tail;
  unsigned char *end;

  void (*destructor) (struct sk_buff *);


  unsigned long nfmark;

  __u32 nfcache;

  struct nf_ct_info *nfct;

  __u32 tc_index;

};




static inline void record_transfer_skb (struct sk_buff *skb, int newType);
static inline
  void record_new_skb (struct sk_buff *skb, int type, int include_body);
static inline void record_free_skb_head (struct sk_buff *skb);
static inline void record_free_skb_body (struct sk_buff *skb);







typedef struct kmem_cache_s kmem_cache_t;

extern void kmem_cache_init (void);
extern void kmem_cache_sizes_init (void);

extern kmem_cache_t *kmem_find_general_cachep (size_t, int gfpflags);
extern kmem_cache_t *kmem_cache_create (const char *, size_t, size_t,
					unsigned long, void (*)(void *,
								kmem_cache_t
								*,
								unsigned
								long),
					void (*)(void *, kmem_cache_t *,
						 unsigned long));
extern int kmem_cache_destroy (kmem_cache_t *);
extern int kmem_cache_shrink (kmem_cache_t *);
extern void *kmem_cache_alloc (kmem_cache_t *, int);
extern void kmem_cache_free (kmem_cache_t *, void *);
extern unsigned int kmem_cache_size (kmem_cache_t *);

extern void *kmalloc (size_t, int);
extern void kfree (const void *);

extern int kmem_cache_reap (int) __attribute__ ((regparm (3)));


extern kmem_cache_t *vm_area_cachep;
extern kmem_cache_t *mm_cachep;
extern kmem_cache_t *names_cachep;
extern kmem_cache_t *files_cachep;
extern kmem_cache_t *filp_cachep;
extern kmem_cache_t *dquot_cachep;
extern kmem_cache_t *bh_cachep;
extern kmem_cache_t *fs_cachep;
extern kmem_cache_t *sigact_cachep;




extern void __kfree_skb (struct sk_buff *skb);
extern struct sk_buff *alloc_skb (unsigned int size, int priority);
extern void kfree_skbmem (struct sk_buff *skb);
extern struct sk_buff *skb_clone (struct sk_buff *skb, int priority);
extern struct sk_buff *skb_copy (const struct sk_buff *skb, int priority);
extern struct sk_buff *pskb_copy (struct sk_buff *skb, int gfp_mask);
extern int pskb_expand_head (struct sk_buff *skb, int nhead, int ntail,
			     int gfp_mask);
extern struct sk_buff *skb_realloc_headroom (struct sk_buff *skb,
					     unsigned int headroom);
extern struct sk_buff *skb_copy_expand (const struct sk_buff *skb,
					int newheadroom, int newtailroom,
					int priority);
extern struct sk_buff *skb_pad (struct sk_buff *skb, int pad);

extern void skb_over_panic (struct sk_buff *skb, int len, void *here);
extern void skb_under_panic (struct sk_buff *skb, int len, void *here);

static inline int
skb_queue_empty (struct sk_buff_head *list)
{
  return (list->next == (struct sk_buff *) list);
}


static inline struct sk_buff *
skb_get (struct sk_buff *skb)
{
  atomic_inc (&skb->users);
  return skb;
}


static inline void
kfree_skb (struct sk_buff *skb)
{
  if (((&skb->users)->counter) == 1 || atomic_dec_and_test (&skb->users))
    __kfree_skb (skb);
}


static inline void
kfree_skb_fast (struct sk_buff *skb)
{
  if (((&skb->users)->counter) == 1 || atomic_dec_and_test (&skb->users))
    kfree_skbmem (skb);
}


static inline int
skb_cloned (struct sk_buff *skb)
{
  return skb->cloned
    && ((&((struct skb_shared_info *) ((skb)->end))->dataref)->counter) != 1;
}


static inline int
skb_shared (struct sk_buff *skb)
{
  return (((&skb->users)->counter) != 1);
}


static inline struct sk_buff *
skb_share_check (struct sk_buff *skb, int pri)
{
  if (skb_shared (skb))
    {
      struct sk_buff *nskb;
      nskb = skb_clone (skb, pri);
      kfree_skb (skb);
      return nskb;
    }
  return skb;
}


static inline struct sk_buff *
skb_unshare (struct sk_buff *skb, int pri)
{
  struct sk_buff *nskb;
  if (!skb_cloned (skb))
    return skb;
  nskb = skb_copy (skb, pri);
  kfree_skb (skb);
  return nskb;
}


static inline struct sk_buff *
skb_peek (struct sk_buff_head *list_)
{
  struct sk_buff *list = ((struct sk_buff *) list_)->next;
  if (list == (struct sk_buff *) list_)
    list = ((void *) 0);
  return list;
}


static inline struct sk_buff *
skb_peek_tail (struct sk_buff_head *list_)
{
  struct sk_buff *list = ((struct sk_buff *) list_)->prev;
  if (list == (struct sk_buff *) list_)
    list = ((void *) 0);
  return list;
}


static inline __u32
skb_queue_len (struct sk_buff_head *list_)
{
  return (list_->qlen);
}

static inline void
skb_queue_head_init (struct sk_buff_head *list)
{
  do
    {
    }
  while (0);
  list->prev = (struct sk_buff *) list;
  list->next = (struct sk_buff *) list;
  list->qlen = 0;
}


static inline void
__skb_queue_head (struct sk_buff_head *list, struct sk_buff *newsk)
{
  struct sk_buff *prev, *next;

  newsk->list = list;
  list->qlen++;
  prev = (struct sk_buff *) list;
  next = prev->next;
  newsk->next = next;
  newsk->prev = prev;
  next->prev = newsk;
  prev->next = newsk;
}


static inline void
skb_queue_head (struct sk_buff_head *list, struct sk_buff *newsk)
{
  unsigned long flags;

  do
    {
      do
	{
	  __asm__ __volatile__ ("pushfl ; popl %0":"=g" (flags):);
	  __asm__ __volatile__ ("cli":::"memory");
	}
      while (0);;
      (void) (&list->lock);
    }
  while (0);
  __skb_queue_head (list, newsk);
  do
    {
      do
	{
	}
      while (0);
      __asm__ __volatile__ ("pushl %0 ; popfl"::"g" (flags):"memory", "cc");
    }
  while (0);
}


static inline void
__skb_queue_tail (struct sk_buff_head *list, struct sk_buff *newsk)
{
  struct sk_buff *prev, *next;

  newsk->list = list;
  list->qlen++;
  next = (struct sk_buff *) list;
  prev = next->prev;
  newsk->next = next;
  newsk->prev = prev;
  next->prev = newsk;
  prev->next = newsk;
}


static inline void
skb_queue_tail (struct sk_buff_head *list, struct sk_buff *newsk)
{
  unsigned long flags;

  do
    {
      do
	{
	  __asm__ __volatile__ ("pushfl ; popl %0":"=g" (flags):);
	  __asm__ __volatile__ ("cli":::"memory");
	}
      while (0);;
      (void) (&list->lock);
    }
  while (0);
  __skb_queue_tail (list, newsk);
  do
    {
      do
	{
	}
      while (0);
      __asm__ __volatile__ ("pushl %0 ; popfl"::"g" (flags):"memory", "cc");
    }
  while (0);
}


static inline struct sk_buff *
__skb_dequeue (struct sk_buff_head *list)
{
  struct sk_buff *next, *prev, *result;

  prev = (struct sk_buff *) list;
  next = prev->next;
  result = ((void *) 0);
  if (next != prev)
    {
      result = next;
      next = next->next;
      list->qlen--;
      next->prev = prev;
      prev->next = next;
      result->next = ((void *) 0);
      result->prev = ((void *) 0);
      result->list = ((void *) 0);
    }
  return result;
}


static inline struct sk_buff *
skb_dequeue (struct sk_buff_head *list)
{
  unsigned long flags;
  struct sk_buff *result;

  do
    {
      do
	{
	  __asm__ __volatile__ ("pushfl ; popl %0":"=g" (flags):);
	  __asm__ __volatile__ ("cli":::"memory");
	}
      while (0);;
      (void) (&list->lock);
    }
  while (0);
  result = __skb_dequeue (list);
  do
    {
      do
	{
	}
      while (0);
      __asm__ __volatile__ ("pushl %0 ; popfl"::"g" (flags):"memory", "cc");
    }
  while (0);
  return result;
}





static inline void
__skb_insert (struct sk_buff *newsk,
	      struct sk_buff *prev, struct sk_buff *next,
	      struct sk_buff_head *list)
{
  newsk->next = next;
  newsk->prev = prev;
  next->prev = newsk;
  prev->next = newsk;
  newsk->list = list;
  list->qlen++;
}


static inline void
skb_insert (struct sk_buff *old, struct sk_buff *newsk)
{
  unsigned long flags;

  do
    {
      do
	{
	  __asm__ __volatile__ ("pushfl ; popl %0":"=g" (flags):);
	  __asm__ __volatile__ ("cli":::"memory");
	}
      while (0);;
      (void) (&old->list->lock);
    }
  while (0);
  __skb_insert (newsk, old->prev, old, old->list);
  do
    {
      do
	{
	}
      while (0);
      __asm__ __volatile__ ("pushl %0 ; popfl"::"g" (flags):"memory", "cc");
    }
  while (0);
}





static inline void
__skb_append (struct sk_buff *old, struct sk_buff *newsk)
{
  __skb_insert (newsk, old, old->next, old->list);
}


static inline void
skb_append (struct sk_buff *old, struct sk_buff *newsk)
{
  unsigned long flags;

  do
    {
      do
	{
	  __asm__ __volatile__ ("pushfl ; popl %0":"=g" (flags):);
	  __asm__ __volatile__ ("cli":::"memory");
	}
      while (0);;
      (void) (&old->list->lock);
    }
  while (0);
  __skb_append (old, newsk);
  do
    {
      do
	{
	}
      while (0);
      __asm__ __volatile__ ("pushl %0 ; popfl"::"g" (flags):"memory", "cc");
    }
  while (0);
}






static inline void
__skb_unlink (struct sk_buff *skb, struct sk_buff_head *list)
{
  struct sk_buff *next, *prev;

  list->qlen--;
  next = skb->next;
  prev = skb->prev;
  skb->next = ((void *) 0);
  skb->prev = ((void *) 0);
  skb->list = ((void *) 0);
  next->prev = prev;
  prev->next = next;
}


static inline void
skb_unlink (struct sk_buff *skb)
{
  struct sk_buff_head *list = skb->list;

  if (list)
    {
      unsigned long flags;

      do
	{
	  do
	    {
	      __asm__ __volatile__ ("pushfl ; popl %0":"=g" (flags):);
	      __asm__ __volatile__ ("cli":::"memory");
	    }
	  while (0);;
	  (void) (&list->lock);
	}
      while (0);
      if (skb->list == list)
	__skb_unlink (skb, skb->list);
      do
	{
	  do
	    {
	    }
	  while (0);
	  __asm__ __volatile__ ("pushl %0 ; popfl"::"g" (flags):"memory",
				"cc");
	}
      while (0);
    }
}


static inline struct sk_buff *
__skb_dequeue_tail (struct sk_buff_head *list)
{
  struct sk_buff *skb = skb_peek_tail (list);
  if (skb)
    __skb_unlink (skb, list);
  return skb;
}


static inline struct sk_buff *
skb_dequeue_tail (struct sk_buff_head *list)
{
  unsigned long flags;
  struct sk_buff *result;

  do
    {
      do
	{
	  __asm__ __volatile__ ("pushfl ; popl %0":"=g" (flags):);
	  __asm__ __volatile__ ("cli":::"memory");
	}
      while (0);;
      (void) (&list->lock);
    }
  while (0);
  result = __skb_dequeue_tail (list);
  do
    {
      do
	{
	}
      while (0);
      __asm__ __volatile__ ("pushl %0 ; popfl"::"g" (flags):"memory", "cc");
    }
  while (0);
  return result;
}

static inline int
skb_is_nonlinear (const struct sk_buff *skb)
{
  return skb->data_len;
}

static inline unsigned int
skb_headlen (const struct sk_buff *skb)
{
  return skb->len - skb->data_len;
}


static inline unsigned char *
__skb_put (struct sk_buff *skb, unsigned int len)
{
  unsigned char *tmp = skb->tail;
  do
    {
      if (skb_is_nonlinear (skb))
	__out_of_line_bug (785);
    }
  while (0);
  skb->tail += len;
  skb->len += len;
  return tmp;
}


static inline unsigned char *
skb_put (struct sk_buff *skb, unsigned int len)
{
  unsigned char *tmp = skb->tail;
  do
    {
      if (skb_is_nonlinear (skb))
	__out_of_line_bug (804);
    }
  while (0);
  skb->tail += len;
  skb->len += len;
  if (skb->tail > skb->end)
    {
      skb_over_panic (skb, len, (
				  {
				  void *pc;
      __asm__ ("movl $1f,%0\n1:":"=g" (pc));
				  pc;
				  }));
    }
  return tmp;
}

static inline unsigned char *
__skb_push (struct sk_buff *skb, unsigned int len)
{
  skb->data -= len;
  skb->len += len;
  return skb->data;
}


static inline unsigned char *
skb_push (struct sk_buff *skb, unsigned int len)
{
  skb->data -= len;
  skb->len += len;
  if (skb->data < skb->head)
    {
      skb_under_panic (skb, len, (
				   {
				   void *pc;
      __asm__ ("movl $1f,%0\n1:": "=g" (pc));
				   pc;
				   }));
    }
  return skb->data;
}

static inline char *
__skb_pull (struct sk_buff *skb, unsigned int len)
{
  skb->len -= len;
  if (skb->len < skb->data_len)
    __out_of_line_bug (844);
  return skb->data += len;
}


static inline unsigned char *
skb_pull (struct sk_buff *skb, unsigned int len)
{
  if (len > skb->len)
    return ((void *) 0);
  return __skb_pull (skb, len);
}

extern unsigned char *__pskb_pull_tail (struct sk_buff *skb, int delta);

static inline char *
__pskb_pull (struct sk_buff *skb, unsigned int len)
{
  if (len > skb_headlen (skb) &&
      __pskb_pull_tail (skb, len - skb_headlen (skb)) == ((void *) 0))
    return ((void *) 0);
  skb->len -= len;
  return skb->data += len;
}

static inline unsigned char *
pskb_pull (struct sk_buff *skb, unsigned int len)
{
  if (len > skb->len)
    return ((void *) 0);
  return __pskb_pull (skb, len);
}

static inline int
pskb_may_pull (struct sk_buff *skb, unsigned int len)
{
  if (len <= skb_headlen (skb))
    return 1;
  if (len > skb->len)
    return 0;
  return (__pskb_pull_tail (skb, len - skb_headlen (skb)) != ((void *) 0));
}


static inline int
skb_headroom (const struct sk_buff *skb)
{
  return skb->data - skb->head;
}


static inline int
skb_tailroom (const struct sk_buff *skb)
{
  return skb_is_nonlinear (skb) ? 0 : skb->end - skb->tail;
}


static inline void
skb_reserve (struct sk_buff *skb, unsigned int len)
{
  skb->data += len;
  skb->tail += len;
}

extern int ___pskb_trim (struct sk_buff *skb, unsigned int len, int realloc);

static inline void
__skb_trim (struct sk_buff *skb, unsigned int len)
{
  if (!skb->data_len)
    {
      skb->len = len;
      skb->tail = skb->data + len;
    }
  else
    {
      ___pskb_trim (skb, len, 0);
    }
}


static inline void
skb_trim (struct sk_buff *skb, unsigned int len)
{
  if (skb->len > len)
    {
      __skb_trim (skb, len);
    }
}


static inline int
__pskb_trim (struct sk_buff *skb, unsigned int len)
{
  if (!skb->data_len)
    {
      skb->len = len;
      skb->tail = skb->data + len;
      return 0;
    }
  else
    {
      return ___pskb_trim (skb, len, 1);
    }
}

static inline int
pskb_trim (struct sk_buff *skb, unsigned int len)
{
  if (len < skb->len)
    return __pskb_trim (skb, len);
  return 0;
}


static inline void
skb_orphan (struct sk_buff *skb)
{
  if (skb->destructor)
    skb->destructor (skb);
  skb->destructor = ((void *) 0);
  skb->sk = ((void *) 0);
}


static inline void
skb_queue_purge (struct sk_buff_head *list)
{
  struct sk_buff *skb;
  while ((skb = skb_dequeue (list)) != ((void *) 0))
    kfree_skb (skb);
}


static inline void
__skb_queue_purge (struct sk_buff_head *list)
{
  struct sk_buff *skb;
  while ((skb = __skb_dequeue (list)) != ((void *) 0))
    kfree_skb (skb);
}


static inline struct sk_buff *
__dev_alloc_skb (unsigned int length, int gfp_mask)
{
  struct sk_buff *skb;

  skb = alloc_skb (length + 16, gfp_mask);
  if (skb)
    {
      record_transfer_skb (skb, (0x77));
      skb_reserve (skb, 16);
    }
  return skb;
}


static inline struct sk_buff *
dev_alloc_skb (unsigned int length)
{
  return __dev_alloc_skb (length, (0x20));
}


static inline int
skb_cow (struct sk_buff *skb, unsigned int headroom)
{
  int delta = (headroom > 16 ? headroom : 16) - skb_headroom (skb);

  if (delta < 0)
    delta = 0;

  if (delta || skb_cloned (skb))
    return pskb_expand_head (skb, (delta + 15) & ~15, 0, (0x20));
  return 0;
}


static inline struct sk_buff *
skb_padto (struct sk_buff *skb, unsigned int len)
{
  unsigned int size = skb->len;
  if (__builtin_expect ((size >= len), 1))
    return skb;
  return skb_pad (skb, len - size);
}


int skb_linearize (struct sk_buff *skb, int gfp);

static inline void *
kmap_skb_frag (const skb_frag_t * frag)
{






  return kmap (frag->page);
}

static inline void
kunmap_skb_frag (void *vaddr)
{
  do
    {
    }
  while (0);



}







extern struct sk_buff *skb_recv_datagram (struct sock *sk, unsigned flags,
					  int noblock, int *err);
extern unsigned int datagram_poll (struct file *file, struct socket *sock,
				   struct poll_table_struct *wait);
extern int skb_copy_datagram (const struct sk_buff *from, int offset,
			      char *to, int size);
extern int skb_copy_datagram_iovec (const struct sk_buff *from, int offset,
				    struct iovec *to, int size);
extern int skb_copy_and_csum_datagram (const struct sk_buff *skb, int offset,
				       u8 * to, int len, unsigned int *csump);
extern int skb_copy_and_csum_datagram_iovec (const struct sk_buff *skb,
					     int hlen, struct iovec *iov);
extern void skb_free_datagram (struct sock *sk, struct sk_buff *skb);

extern unsigned int skb_checksum (const struct sk_buff *skb, int offset,
				  int len, unsigned int csum);
extern int skb_copy_bits (const struct sk_buff *skb, int offset, void *to,
			  int len);
extern unsigned int skb_copy_and_csum_bits (const struct sk_buff *skb,
					    int offset, u8 * to, int len,
					    unsigned int csum);
extern void skb_copy_and_csum_dev (const struct sk_buff *skb, u8 * to);

extern void skb_init (void);
extern void skb_add_mtu (int mtu);


static inline void
nf_conntrack_put (struct nf_ct_info *nfct)
{
  if (nfct && atomic_dec_and_test (&nfct->master->use))
    nfct->master->destroy (nfct->master);
}
static inline void
nf_conntrack_get (struct nf_ct_info *nfct)
{
  if (nfct)
    atomic_inc (&nfct->master->use);
}


extern atomic_t g_device_skb;
extern atomic_t g_device_skb_num;
extern atomic_t g_other_skb;
extern atomic_t g_other_skb_num;

static inline void
record_new_skb (struct sk_buff *skb, int type, int include_body)
{
}

static inline void
record_free_skb_body (struct sk_buff *skb)
{
}

static inline void
record_free_skb_head (struct sk_buff *skb)
{
}

static inline void
record_transfer_skb (struct sk_buff *skb, int newType)
{
}










struct pollfd
{
  int fd;
  short events;
  short revents;
};









extern int __verify_write (const void *, unsigned long);

static inline int
verify_area (int type, const void *addr, unsigned long size)
{
  return ((
	    {
	    unsigned long flag, sum;
  asm ("addl %3,%1 ; sbbl %0,%0; cmpl %1,%4; sbbl $0,%0": "=&r" (flag), "=r" (sum):"1" (addr), "g" ((int) (size)),
		 "g" (get_current ()->addr_limit.
		      seg));
	    flag;
	    }) == 0) ? 0 : -14;
}


struct exception_table_entry
{
  unsigned long insn, fixup;
};


extern unsigned long search_exception_table (unsigned long);

extern void __get_user_1 (void);
extern void __get_user_2 (void);
extern void __get_user_4 (void);

extern void __put_user_1 (void);
extern void __put_user_2 (void);
extern void __put_user_4 (void);
extern void __put_user_8 (void);

extern void __put_user_bad (void);

struct __large_struct
{
  unsigned long buf[100];
};

extern long __get_user_bad (void);

static inline unsigned long
__generic_copy_from_user_nocheck (void *to, const void *from, unsigned long n)
{
  do
    {
      int __d0, __d1;
      __asm__ __volatile__ ("0:	rep; movsl\n" "	movl %3,%0\n"
			    "1:	rep; movsb\n" "2:\n"
			    ".section .fixup,\"ax\"\n"
			    "3:	lea 0(%3,%0,4),%0\n"
			    "4:	pushl %0\n"
			    "	pushl %%eax\n"
			    "	xorl %%eax,%%eax\n"
			    "	rep; stosb\n"
			    "	popl %%eax\n"
			    "	popl %0\n"
			    "	jmp 2b\n"
			    ".previous\n"
			    ".section __ex_table,\"a\"\n"
			    "	.align 4\n"
			    "	.long 0b,3b\n"
			    "	.long 1b,4b\n"
			    ".previous":"=&c"
			    (n),
			    "=&D"
			    (__d0),
			    "=&S"
			    (__d1):"r"
			    (n & 3),
			    "0" (n / 4), "1" (to), "2" (from):"memory");
    }
  while (0);
  return n;
}

static inline unsigned long
__generic_copy_to_user_nocheck (void *to, const void *from, unsigned long n)
{
  do
    {
      int __d0, __d1;
      __asm__ __volatile__ ("0:	rep; movsl\n" "	movl %3,%0\n"
			    "1:	rep; movsb\n" "2:\n"
			    ".section .fixup,\"ax\"\n"
			    "3:	lea 0(%3,%0,4),%0\n" "	jmp 2b\n"
			    ".previous\n"
			    ".section __ex_table,\"a\"\n"
			    "	.align 4\n" "	.long 0b,3b\n"
			    "	.long 1b,2b\n"
			    ".previous":"=&c" (n),
			    "=&D" (__d0),
			    "=&S" (__d1):"r" (n & 3),
			    "0" (n / 4), "1" (to), "2" (from):"memory");
    }
  while (0);
  return n;
}


unsigned long __generic_copy_to_user (void *, const void *, unsigned long);
unsigned long __generic_copy_from_user (void *, const void *, unsigned long);

static inline unsigned long
__constant_copy_to_user (void *to, const void *from, unsigned long n)
{
  prefetch (from);
  if (((
	 {
unsigned long flag, sum; asm ("addl %3,%1 ; sbbl %0,%0; cmpl %1,%4; sbbl $0,%0": "=&r" (flag), "=r" (sum):"1" (to), "g" ((int) (n)), "g" (get_current ()->addr_limit.seg));
	 flag;}) ==
       0))
    do
      {
	int __d0, __d1;
	switch (n & 3)
	  {
	  default:
	  __asm__ __volatile__ ("0:	rep; movsl\n" "1:\n" ".section .fixup,\"ax\"\n" "2:	shl $2,%0\n" "	jmp 1b\n" ".previous\n" ".section __ex_table,\"a\"\n" "	.align 4\n" "	.long 0b,2b\n" ".previous": "=c" (n), "=&S" (__d0), "=&D" (__d1): "1" (from), "2" (to), "0" (n / 4):"memory");
	    break;
	  case 1:
	  __asm__ __volatile__ ("0:	rep; movsl\n" "1:	movsb\n" "2:\n" ".section .fixup,\"ax\"\n" "3:	shl $2,%0\n" "4:	incl %0\n" "	jmp 2b\n" ".previous\n" ".section __ex_table,\"a\"\n" "	.align 4\n" "	.long 0b,3b\n" "	.long 1b,4b\n" ".previous": "=c" (n), "=&S" (__d0), "=&D" (__d1): "1" (from), "2" (to), "0" (n / 4):"memory");
	    break;
	  case 2:
	  __asm__ __volatile__ ("0:	rep; movsl\n" "1:	movsw\n" "2:\n" ".section .fixup,\"ax\"\n" "3:	shl $2,%0\n" "4:	addl $2,%0\n" "	jmp 2b\n" ".previous\n" ".section __ex_table,\"a\"\n" "	.align 4\n" "	.long 0b,3b\n" "	.long 1b,4b\n" ".previous": "=c" (n), "=&S" (__d0), "=&D" (__d1): "1" (from), "2" (to), "0" (n / 4):"memory");
	    break;
	  case 3:
	  __asm__ __volatile__ ("0:	rep; movsl\n" "1:	movsw\n" "2:	movsb\n" "3:\n" ".section .fixup,\"ax\"\n" "4:	shl $2,%0\n" "5:	addl $2,%0\n" "6:	incl %0\n" "	jmp 3b\n" ".previous\n" ".section __ex_table,\"a\"\n" "	.align 4\n" "	.long 0b,4b\n" "	.long 1b,5b\n" "	.long 2b,6b\n" ".previous": "=c" (n), "=&S" (__d0), "=&D" (__d1): "1" (from), "2" (to), "0" (n / 4):"memory");
	    break;
	  }
      }
    while (0);
  return n;
}

static inline unsigned long
__constant_copy_from_user (void *to, const void *from, unsigned long n)
{
  if (((
	 {
unsigned long flag, sum; asm ("addl %3,%1 ; sbbl %0,%0; cmpl %1,%4; sbbl $0,%0": "=&r" (flag), "=r" (sum):"1" (from), "g" ((int) (n)), "g" (get_current ()->addr_limit.seg));
	 flag;}) ==
       0))
    do
      {
	int __d0, __d1;
	switch (n & 3)
	  {
	  default:
	  __asm__ __volatile__ ("0:	rep; movsl\n" "1:\n" ".section .fixup,\"ax\"\n" "2:	pushl %0\n" "	pushl %%eax\n" "	xorl %%eax,%%eax\n" "	rep; stosl\n" "	popl %%eax\n" "	popl %0\n" "	shl $2,%0\n" "	jmp 1b\n" ".previous\n" ".section __ex_table,\"a\"\n" "	.align 4\n" "	.long 0b,2b\n" ".previous": "=c" (n), "=&S" (__d0), "=&D" (__d1): "1" (from), "2" (to), "0" (n / 4):"memory");
	    break;
	  case 1:
	  __asm__ __volatile__ ("0:	rep; movsl\n" "1:	movsb\n" "2:\n" ".section .fixup,\"ax\"\n" "3:	pushl %0\n" "	pushl %%eax\n" "	xorl %%eax,%%eax\n" "	rep; stosl\n" "	stosb\n" "	popl %%eax\n" "	popl %0\n" "	shl $2,%0\n" "	incl %0\n" "	jmp 2b\n" "4:	pushl %%eax\n" "	xorl %%eax,%%eax\n" "	stosb\n" "	popl %%eax\n" "	incl %0\n" "	jmp 2b\n" ".previous\n" ".section __ex_table,\"a\"\n" "	.align 4\n" "	.long 0b,3b\n" "	.long 1b,4b\n" ".previous": "=c" (n), "=&S" (__d0), "=&D" (__d1): "1" (from), "2" (to), "0" (n / 4):"memory");
	    break;
	  case 2:
	  __asm__ __volatile__ ("0:	rep; movsl\n" "1:	movsw\n" "2:\n" ".section .fixup,\"ax\"\n" "3:	pushl %0\n" "	pushl %%eax\n" "	xorl %%eax,%%eax\n" "	rep; stosl\n" "	stosw\n" "	popl %%eax\n" "	popl %0\n" "	shl $2,%0\n" "	addl $2,%0\n" "	jmp 2b\n" "4:	pushl %%eax\n" "	xorl %%eax,%%eax\n" "	stosw\n" "	popl %%eax\n" "	addl $2,%0\n" "	jmp 2b\n" ".previous\n" ".section __ex_table,\"a\"\n" "	.align 4\n" "	.long 0b,3b\n" "	.long 1b,4b\n" ".previous": "=c" (n), "=&S" (__d0), "=&D" (__d1): "1" (from), "2" (to), "0" (n / 4):"memory");
	    break;
	  case 3:
	  __asm__ __volatile__ ("0:	rep; movsl\n" "1:	movsw\n" "2:	movsb\n" "3:\n" ".section .fixup,\"ax\"\n" "4:	pushl %0\n" "	pushl %%eax\n" "	xorl %%eax,%%eax\n" "	rep; stosl\n" "	stosw\n" "	stosb\n" "	popl %%eax\n" "	popl %0\n" "	shl $2,%0\n" "	addl $3,%0\n" "	jmp 2b\n" "5:	pushl %%eax\n" "	xorl %%eax,%%eax\n" "	stosw\n" "	stosb\n" "	popl %%eax\n" "	addl $3,%0\n" "	jmp 2b\n" "6:	pushl %%eax\n" "	xorl %%eax,%%eax\n" "	stosb\n" "	popl %%eax\n" "	incl %0\n" "	jmp 3b\n" ".previous\n" ".section __ex_table,\"a\"\n" "	.align 4\n" "	.long 0b,4b\n" "	.long 1b,5b\n" "	.long 2b,6b\n" ".previous": "=c" (n), "=&S" (__d0), "=&D" (__d1): "1" (from), "2" (to), "0" (n / 4):"memory");
	    break;
	  }
      }
    while (0);
  else
    (__builtin_constant_p (0)
     ? (__builtin_constant_p ((n)) ?
	__constant_c_and_count_memset (((to)),
				       ((0x01010101UL * (unsigned char) (0))),
				       ((n))) : __constant_c_memset (((to)),
								     ((0x01010101UL * (unsigned char) (0))), ((n)))) : (__builtin_constant_p ((n)) ? __memset_generic ((((to))), (((0))), (((n)))) : __memset_generic (((to)), ((0)), ((n)))));
  return n;
}

static inline unsigned long
__constant_copy_to_user_nocheck (void *to, const void *from, unsigned long n)
{
  do
    {
      int __d0, __d1;
      switch (n & 3)
	{
	default:
	__asm__ __volatile__ ("0:	rep; movsl\n" "1:\n" ".section .fixup,\"ax\"\n" "2:	shl $2,%0\n" "	jmp 1b\n" ".previous\n" ".section __ex_table,\"a\"\n" "	.align 4\n" "	.long 0b,2b\n" ".previous": "=c" (n), "=&S" (__d0), "=&D" (__d1): "1" (from), "2" (to), "0" (n / 4):"memory");
	  break;
	case 1:
	__asm__ __volatile__ ("0:	rep; movsl\n" "1:	movsb\n" "2:\n" ".section .fixup,\"ax\"\n" "3:	shl $2,%0\n" "4:	incl %0\n" "	jmp 2b\n" ".previous\n" ".section __ex_table,\"a\"\n" "	.align 4\n" "	.long 0b,3b\n" "	.long 1b,4b\n" ".previous": "=c" (n), "=&S" (__d0), "=&D" (__d1): "1" (from), "2" (to), "0" (n / 4):"memory");
	  break;
	case 2:
	__asm__ __volatile__ ("0:	rep; movsl\n" "1:	movsw\n" "2:\n" ".section .fixup,\"ax\"\n" "3:	shl $2,%0\n" "4:	addl $2,%0\n" "	jmp 2b\n" ".previous\n" ".section __ex_table,\"a\"\n" "	.align 4\n" "	.long 0b,3b\n" "	.long 1b,4b\n" ".previous": "=c" (n), "=&S" (__d0), "=&D" (__d1): "1" (from), "2" (to), "0" (n / 4):"memory");
	  break;
	case 3:
	__asm__ __volatile__ ("0:	rep; movsl\n" "1:	movsw\n" "2:	movsb\n" "3:\n" ".section .fixup,\"ax\"\n" "4:	shl $2,%0\n" "5:	addl $2,%0\n" "6:	incl %0\n" "	jmp 3b\n" ".previous\n" ".section __ex_table,\"a\"\n" "	.align 4\n" "	.long 0b,4b\n" "	.long 1b,5b\n" "	.long 2b,6b\n" ".previous": "=c" (n), "=&S" (__d0), "=&D" (__d1): "1" (from), "2" (to), "0" (n / 4):"memory");
	  break;
	}
    }
  while (0);
  return n;
}

static inline unsigned long
__constant_copy_from_user_nocheck (void *to, const void *from,
				   unsigned long n)
{
  do
    {
      int __d0, __d1;
      switch (n & 3)
	{
	default:
	__asm__ __volatile__ ("0:	rep; movsl\n" "1:\n" ".section .fixup,\"ax\"\n" "2:	pushl %0\n" "	pushl %%eax\n" "	xorl %%eax,%%eax\n" "	rep; stosl\n" "	popl %%eax\n" "	popl %0\n" "	shl $2,%0\n" "	jmp 1b\n" ".previous\n" ".section __ex_table,\"a\"\n" "	.align 4\n" "	.long 0b,2b\n" ".previous": "=c" (n), "=&S" (__d0), "=&D" (__d1): "1" (from), "2" (to), "0" (n / 4):"memory");
	  break;
	case 1:
	__asm__ __volatile__ ("0:	rep; movsl\n" "1:	movsb\n" "2:\n" ".section .fixup,\"ax\"\n" "3:	pushl %0\n" "	pushl %%eax\n" "	xorl %%eax,%%eax\n" "	rep; stosl\n" "	stosb\n" "	popl %%eax\n" "	popl %0\n" "	shl $2,%0\n" "	incl %0\n" "	jmp 2b\n" "4:	pushl %%eax\n" "	xorl %%eax,%%eax\n" "	stosb\n" "	popl %%eax\n" "	incl %0\n" "	jmp 2b\n" ".previous\n" ".section __ex_table,\"a\"\n" "	.align 4\n" "	.long 0b,3b\n" "	.long 1b,4b\n" ".previous": "=c" (n), "=&S" (__d0), "=&D" (__d1): "1" (from), "2" (to), "0" (n / 4):"memory");
	  break;
	case 2:
	__asm__ __volatile__ ("0:	rep; movsl\n" "1:	movsw\n" "2:\n" ".section .fixup,\"ax\"\n" "3:	pushl %0\n" "	pushl %%eax\n" "	xorl %%eax,%%eax\n" "	rep; stosl\n" "	stosw\n" "	popl %%eax\n" "	popl %0\n" "	shl $2,%0\n" "	addl $2,%0\n" "	jmp 2b\n" "4:	pushl %%eax\n" "	xorl %%eax,%%eax\n" "	stosw\n" "	popl %%eax\n" "	addl $2,%0\n" "	jmp 2b\n" ".previous\n" ".section __ex_table,\"a\"\n" "	.align 4\n" "	.long 0b,3b\n" "	.long 1b,4b\n" ".previous": "=c" (n), "=&S" (__d0), "=&D" (__d1): "1" (from), "2" (to), "0" (n / 4):"memory");
	  break;
	case 3:
	__asm__ __volatile__ ("0:	rep; movsl\n" "1:	movsw\n" "2:	movsb\n" "3:\n" ".section .fixup,\"ax\"\n" "4:	pushl %0\n" "	pushl %%eax\n" "	xorl %%eax,%%eax\n" "	rep; stosl\n" "	stosw\n" "	stosb\n" "	popl %%eax\n" "	popl %0\n" "	shl $2,%0\n" "	addl $3,%0\n" "	jmp 2b\n" "5:	pushl %%eax\n" "	xorl %%eax,%%eax\n" "	stosw\n" "	stosb\n" "	popl %%eax\n" "	addl $3,%0\n" "	jmp 2b\n" "6:	pushl %%eax\n" "	xorl %%eax,%%eax\n" "	stosb\n" "	popl %%eax\n" "	incl %0\n" "	jmp 3b\n" ".previous\n" ".section __ex_table,\"a\"\n" "	.align 4\n" "	.long 0b,4b\n" "	.long 1b,5b\n" "	.long 2b,6b\n" ".previous": "=c" (n), "=&S" (__d0), "=&D" (__d1): "1" (from), "2" (to), "0" (n / 4):"memory");
	  break;
	}
    }
  while (0);
  return n;
}


long strncpy_from_user (char *dst, const char *src, long count);
long __strncpy_from_user (char *dst, const char *src, long count);

long strnlen_user (const char *str, long n);
unsigned long clear_user (void *mem, unsigned long len);
unsigned long __clear_user (void *mem, unsigned long len);


struct poll_table_page;

typedef struct poll_table_struct
{
  int error;
  struct poll_table_page *table;
} poll_table;

extern void __pollwait (struct file *filp, wait_queue_head_t * wait_address,
			poll_table * p);

static inline void
poll_wait (struct file *filp, wait_queue_head_t * wait_address,
	   poll_table * p)
{
  if (p && wait_address)
    __pollwait (filp, wait_address, p);
}

static inline void
poll_initwait (poll_table * pt)
{
  pt->error = 0;
  pt->table = ((void *) 0);
}
extern void poll_freewait (poll_table * pt);






typedef struct
{
  unsigned long *in, *out, *ex;
  unsigned long *res_in, *res_out, *res_ex;
} fd_set_bits;

static inline int
get_fd_set (unsigned long nr, void *ufdset, unsigned long *fdset)
{
  nr =
    ((((nr) + (8 * sizeof (long)) -
       1) / (8 * sizeof (long))) * sizeof (long));
  if (ufdset)
    {
      int error;
      error = verify_area (1, ufdset, nr);
      if (!error
	  && (__builtin_constant_p (nr) ?
	      __constant_copy_from_user_nocheck ((fdset), (ufdset),
						 (nr)) :
	      __generic_copy_from_user_nocheck ((fdset), (ufdset), (nr))))
	error = -14;
      return error;
    }
  (__builtin_constant_p (0)
   ? (__builtin_constant_p ((nr)) ?
      __constant_c_and_count_memset (((fdset)),
				     ((0x01010101UL * (unsigned char) (0))),
				     ((nr))) : __constant_c_memset (((fdset)),
								    ((0x01010101UL * (unsigned char) (0))), ((nr)))) : (__builtin_constant_p ((nr)) ? __memset_generic ((((fdset))), (((0))), (((nr)))) : __memset_generic (((fdset)), ((0)), ((nr)))));
  return 0;
}

static inline void
set_fd_set (unsigned long nr, void *ufdset, unsigned long *fdset)
{
  if (ufdset)
    (__builtin_constant_p
     (((((nr) + (8 * sizeof (long)) -
	 1) / (8 * sizeof (long))) *
       sizeof (long))) ? __constant_copy_to_user_nocheck ((ufdset), (fdset),
							  (((((nr) +
							      (8 *
							       sizeof (long))
							      -
							      1) / (8 *
								    sizeof
								    (long))) *
							    sizeof (long)))) :
     __generic_copy_to_user_nocheck ((ufdset), (fdset),
				     (((((nr) + (8 * sizeof (long)) -
					 1) / (8 * sizeof (long))) *
				       sizeof (long)))));
}

static inline void
zero_fd_set (unsigned long nr, unsigned long *fdset)
{
  (__builtin_constant_p (0)
   ? (__builtin_constant_p
      ((((((nr) + (8 * sizeof (long)) -
	   1) / (8 * sizeof (long))) *
	 sizeof (long)))) ? __constant_c_and_count_memset (((fdset)),
							   ((0x01010101UL *
							     (unsigned
							      char) (0))),
							   ((((((nr) +
								(8 *
								 sizeof
								 (long)) -
								1) / (8 *
								      sizeof
								      (long)))
							      *
							      sizeof
							      (long))))) :
      __constant_c_memset (((fdset)), ((0x01010101UL * (unsigned char) (0))),
			   ((((((nr) + (8 * sizeof (long)) -
				1) / (8 * sizeof (long))) *
			      sizeof (long))))))
   : (__builtin_constant_p
      ((((((nr) + (8 * sizeof (long)) -
	   1) / (8 * sizeof (long))) *
	 sizeof (long)))) ? __memset_generic ((((fdset))), (((0))),
					      (((((((nr) +
						    (8 * sizeof (long)) -
						    1) / (8 *
							  sizeof (long))) *
						  sizeof (long)))))) :
      __memset_generic (((fdset)), ((0)),
			((((((nr) + (8 * sizeof (long)) -
			     1) / (8 * sizeof (long))) * sizeof (long)))))));
}

extern int do_select (int n, fd_set_bits * fds, long *timeout);






enum
{
  IPPROTO_IP = 0,
  IPPROTO_ICMP = 1,
  IPPROTO_IGMP = 2,
  IPPROTO_IPIP = 4,
  IPPROTO_TCP = 6,
  IPPROTO_EGP = 8,
  IPPROTO_PUP = 12,
  IPPROTO_UDP = 17,
  IPPROTO_IDP = 22,
  IPPROTO_RSVP = 46,
  IPPROTO_GRE = 47,

  IPPROTO_IPV6 = 41,

  IPPROTO_PIM = 103,

  IPPROTO_ESP = 50,
  IPPROTO_AH = 51,
  IPPROTO_COMP = 108,
  IPPROTO_SCTP = 132,

  IPPROTO_RAW = 255,
  IPPROTO_MAX
};



struct in_addr
{
  __u32 s_addr;
};

struct ip_mreq
{
  struct in_addr imr_multiaddr;
  struct in_addr imr_interface;
};

struct ip_mreqn
{
  struct in_addr imr_multiaddr;
  struct in_addr imr_address;
  int imr_ifindex;
};

struct ip_mreq_source
{
  __u32 imr_multiaddr;
  __u32 imr_interface;
  __u32 imr_sourceaddr;
};

struct ip_msfilter
{
  __u32 imsf_multiaddr;
  __u32 imsf_interface;
  __u32 imsf_fmode;
  __u32 imsf_numsrc;
  __u32 imsf_slist[1];
};





struct group_req
{
  __u32 gr_interface;
  struct __kernel_sockaddr_storage gr_group;
};

struct group_source_req
{
  __u32 gsr_interface;
  struct __kernel_sockaddr_storage gsr_group;
  struct __kernel_sockaddr_storage gsr_source;
};

struct group_filter
{
  __u32 gf_interface;
  struct __kernel_sockaddr_storage gf_group;
  __u32 gf_fmode;
  __u32 gf_numsrc;
  struct __kernel_sockaddr_storage gf_slist[1];
};





struct in_pktinfo
{
  int ipi_ifindex;
  struct in_addr ipi_spec_dst;
  struct in_addr ipi_addr;
};



struct sockaddr_in
{
  sa_family_t sin_family;
  unsigned short int sin_port;
  struct in_addr sin_addr;


  unsigned char __pad[16 - sizeof (short int) -
		      sizeof (unsigned short int) - sizeof (struct in_addr)];
};




struct icmphdr
{
  __u8 type;
  __u8 code;
  __u16 checksum;
  union
  {
    struct
    {
      __u16 id;
      __u16 sequence;
    } echo;
    __u32 gateway;
    struct
    {
      __u16 __unused;
      __u16 mtu;
    } frag;
  } un;
};







struct icmp_filter
{
  __u32 data;
};




struct tcphdr
{
  __u16 source;
  __u16 dest;
  __u32 seq;
  __u32 ack_seq;

  __u16 res1:4,
    doff:4, fin:1, syn:1, rst:1, psh:1, ack:1, urg:1, ece:1, cwr:1;

  __u16 window;
  __u16 check;
  __u16 urg_ptr;
};


enum
{
  TCP_ESTABLISHED = 1,
  TCP_SYN_SENT,
  TCP_SYN_RECV,
  TCP_FIN_WAIT1,
  TCP_FIN_WAIT2,
  TCP_TIME_WAIT,
  TCP_CLOSE,
  TCP_CLOSE_WAIT,
  TCP_LAST_ACK,
  TCP_LISTEN,
  TCP_CLOSING,

  TCP_MAX_STATES
};




enum
{
  TCPF_ESTABLISHED = (1 << 1),
  TCPF_SYN_SENT = (1 << 2),
  TCPF_SYN_RECV = (1 << 3),
  TCPF_FIN_WAIT1 = (1 << 4),
  TCPF_FIN_WAIT2 = (1 << 5),
  TCPF_TIME_WAIT = (1 << 6),
  TCPF_CLOSE = (1 << 7),
  TCPF_CLOSE_WAIT = (1 << 8),
  TCPF_LAST_ACK = (1 << 9),
  TCPF_LISTEN = (1 << 10),
  TCPF_CLOSING = (1 << 11)
};






union tcp_word_hdr
{
  struct tcphdr hdr;
  __u32 words[5];
};



enum
{
  TCP_FLAG_CWR =
    ((__u32)
     ((((__u32) ((0x00800000)) & (__u32) 0x000000ffUL) << 24) |
      (((__u32) ((0x00800000)) & (__u32) 0x0000ff00UL) << 8) |
      (((__u32) ((0x00800000)) & (__u32) 0x00ff0000UL) >> 8) |
      (((__u32) ((0x00800000)) & (__u32) 0xff000000UL) >> 24))),
  TCP_FLAG_ECE =
    ((__u32)
     ((((__u32) ((0x00400000)) & (__u32) 0x000000ffUL) << 24) |
      (((__u32) ((0x00400000)) & (__u32) 0x0000ff00UL) << 8) |
      (((__u32) ((0x00400000)) & (__u32) 0x00ff0000UL) >> 8) |
      (((__u32) ((0x00400000)) & (__u32) 0xff000000UL) >> 24))),
  TCP_FLAG_URG =
    ((__u32)
     ((((__u32) ((0x00200000)) & (__u32) 0x000000ffUL) << 24) |
      (((__u32) ((0x00200000)) & (__u32) 0x0000ff00UL) << 8) |
      (((__u32) ((0x00200000)) & (__u32) 0x00ff0000UL) >> 8) |
      (((__u32) ((0x00200000)) & (__u32) 0xff000000UL) >> 24))),
  TCP_FLAG_ACK =
    ((__u32)
     ((((__u32) ((0x00100000)) & (__u32) 0x000000ffUL) << 24) |
      (((__u32) ((0x00100000)) & (__u32) 0x0000ff00UL) << 8) |
      (((__u32) ((0x00100000)) & (__u32) 0x00ff0000UL) >> 8) |
      (((__u32) ((0x00100000)) & (__u32) 0xff000000UL) >> 24))),
  TCP_FLAG_PSH =
    ((__u32)
     ((((__u32) ((0x00080000)) & (__u32) 0x000000ffUL) << 24) |
      (((__u32) ((0x00080000)) & (__u32) 0x0000ff00UL) << 8) |
      (((__u32) ((0x00080000)) & (__u32) 0x00ff0000UL) >> 8) |
      (((__u32) ((0x00080000)) & (__u32) 0xff000000UL) >> 24))),
  TCP_FLAG_RST =
    ((__u32)
     ((((__u32) ((0x00040000)) & (__u32) 0x000000ffUL) << 24) |
      (((__u32) ((0x00040000)) & (__u32) 0x0000ff00UL) << 8) |
      (((__u32) ((0x00040000)) & (__u32) 0x00ff0000UL) >> 8) |
      (((__u32) ((0x00040000)) & (__u32) 0xff000000UL) >> 24))),
  TCP_FLAG_SYN =
    ((__u32)
     ((((__u32) ((0x00020000)) & (__u32) 0x000000ffUL) << 24) |
      (((__u32) ((0x00020000)) & (__u32) 0x0000ff00UL) << 8) |
      (((__u32) ((0x00020000)) & (__u32) 0x00ff0000UL) >> 8) |
      (((__u32) ((0x00020000)) & (__u32) 0xff000000UL) >> 24))),
  TCP_FLAG_FIN =
    ((__u32)
     ((((__u32) ((0x00010000)) & (__u32) 0x000000ffUL) << 24) |
      (((__u32) ((0x00010000)) & (__u32) 0x0000ff00UL) << 8) |
      (((__u32) ((0x00010000)) & (__u32) 0x00ff0000UL) >> 8) |
      (((__u32) ((0x00010000)) & (__u32) 0xff000000UL) >> 24))),
  TCP_RESERVED_BITS =
    ((__u32)
     ((((__u32) ((0x0F000000)) & (__u32) 0x000000ffUL) << 24) |
      (((__u32) ((0x0F000000)) & (__u32) 0x0000ff00UL) << 8) |
      (((__u32) ((0x0F000000)) & (__u32) 0x00ff0000UL) >> 8) |
      (((__u32) ((0x0F000000)) & (__u32) 0xff000000UL) >> 24))),
  TCP_DATA_OFFSET =
    ((__u32)
     ((((__u32) ((0xF0000000)) & (__u32) 0x000000ffUL) << 24) |
      (((__u32) ((0xF0000000)) & (__u32) 0x0000ff00UL) << 8) |
      (((__u32) ((0xF0000000)) & (__u32) 0x00ff0000UL) >> 8) |
      (((__u32) ((0xF0000000)) & (__u32) 0xff000000UL) >> 24)))
};

enum tcp_ca_state
{
  TCP_CA_Open = 0,

  TCP_CA_Disorder = 1,

  TCP_CA_CWR = 2,

  TCP_CA_Recovery = 3,

  TCP_CA_Loss = 4
};

struct tcp_info
{
  __u8 tcpi_state;
  __u8 tcpi_ca_state;
  __u8 tcpi_retransmits;
  __u8 tcpi_probes;
  __u8 tcpi_backoff;
  __u8 tcpi_options;
  __u8 tcpi_snd_wscale:4, tcpi_rcv_wscale:4;

  __u32 tcpi_rto;
  __u32 tcpi_ato;
  __u32 tcpi_snd_mss;
  __u32 tcpi_rcv_mss;

  __u32 tcpi_unacked;
  __u32 tcpi_sacked;
  __u32 tcpi_lost;
  __u32 tcpi_retrans;
  __u32 tcpi_fackets;


  __u32 tcpi_last_data_sent;
  __u32 tcpi_last_ack_sent;
  __u32 tcpi_last_data_recv;
  __u32 tcpi_last_ack_recv;


  __u32 tcpi_pmtu;
  __u32 tcpi_rcv_ssthresh;
  __u32 tcpi_rtt;
  __u32 tcpi_rttvar;
  __u32 tcpi_snd_ssthresh;
  __u32 tcpi_snd_cwnd;
  __u32 tcpi_advmss;
  __u32 tcpi_reordering;
};













typedef struct
{
  unsigned int clock_rate;
  unsigned int clock_type;
  unsigned short loopback;
} sync_serial_settings;

typedef struct
{
  unsigned int clock_rate;
  unsigned int clock_type;
  unsigned short loopback;
  unsigned int slot_map;
} te1_settings;

typedef struct
{
  unsigned short encoding;
  unsigned short parity;
} raw_hdlc_proto;

typedef struct
{
  unsigned int t391;
  unsigned int t392;
  unsigned int n391;
  unsigned int n392;
  unsigned int n393;
  unsigned short lmi;
  unsigned short dce;
} fr_proto;

typedef struct
{
  unsigned int dlci;
} fr_proto_pvc;

typedef struct
{
  unsigned int dlci;
  char master[16];
} fr_proto_pvc_info;

typedef struct
{
  unsigned int interval;
  unsigned int timeout;
} cisco_proto;


struct ifmap
{
  unsigned long mem_start;
  unsigned long mem_end;
  unsigned short base_addr;
  unsigned char irq;
  unsigned char dma;
  unsigned char port;

};

struct if_settings
{
  unsigned int type;
  unsigned int size;
  union
  {

    raw_hdlc_proto *raw_hdlc;
    cisco_proto *cisco;
    fr_proto *fr;
    fr_proto_pvc *fr_pvc;
    fr_proto_pvc_info *fr_pvc_info;


    sync_serial_settings *sync;
    te1_settings *te1;
  } ifs_ifsu;
};

struct ifreq
{

  union
  {
    char ifrn_name[16];
  } ifr_ifrn;

  union
  {
    struct sockaddr ifru_addr;
    struct sockaddr ifru_dstaddr;
    struct sockaddr ifru_broadaddr;
    struct sockaddr ifru_netmask;
    struct sockaddr ifru_hwaddr;
    short ifru_flags;
    int ifru_ivalue;
    int ifru_mtu;
    struct ifmap ifru_map;
    char ifru_slave[16];
    char ifru_newname[16];
    char *ifru_data;
    struct if_settings ifru_settings;
  } ifr_ifru;
};

struct ifconf
{
  int ifc_len;
  union
  {
    char *ifcu_buf;
    struct ifreq *ifcu_req;
  } ifc_ifcu;
};



struct ethhdr
{
  unsigned char h_dest[6];
  unsigned char h_source[6];
  unsigned short h_proto;
} __attribute__ ((packed));





struct sockaddr_pkt
{
  unsigned short spkt_family;
  unsigned char spkt_device[14];
  unsigned short spkt_protocol;
};

struct sockaddr_ll
{
  unsigned short sll_family;
  unsigned short sll_protocol;
  int sll_ifindex;
  unsigned short sll_hatype;
  unsigned char sll_pkttype;
  unsigned char sll_halen;
  unsigned char sll_addr[8];
};

struct tpacket_stats
{
  unsigned int tp_packets;
  unsigned int tp_drops;
};

struct tpacket_hdr
{
  unsigned long tp_status;





  unsigned int tp_len;
  unsigned int tp_snaplen;
  unsigned short tp_mac;
  unsigned short tp_net;
  unsigned int tp_sec;
  unsigned int tp_usec;
};

struct tpacket_req
{
  unsigned int tp_block_size;
  unsigned int tp_block_nr;
  unsigned int tp_frame_size;
  unsigned int tp_frame_nr;
};

struct packet_mreq
{
  int mr_ifindex;
  unsigned short mr_type;
  unsigned short mr_alen;
  unsigned char mr_address[8];
};


struct divert_blk;
struct vlan_group;
struct ethtool_ops;

struct net_device_stats
{
  unsigned long rx_packets;
  unsigned long tx_packets;
  unsigned long rx_bytes;
  unsigned long tx_bytes;
  unsigned long rx_errors;
  unsigned long tx_errors;
  unsigned long rx_dropped;
  unsigned long tx_dropped;
  unsigned long multicast;
  unsigned long collisions;


  unsigned long rx_length_errors;
  unsigned long rx_over_errors;
  unsigned long rx_crc_errors;
  unsigned long rx_frame_errors;
  unsigned long rx_fifo_errors;
  unsigned long rx_missed_errors;


  unsigned long tx_aborted_errors;
  unsigned long tx_carrier_errors;
  unsigned long tx_fifo_errors;
  unsigned long tx_heartbeat_errors;
  unsigned long tx_window_errors;


  unsigned long rx_compressed;
  unsigned long tx_compressed;
};



enum
{
  IF_PORT_UNKNOWN = 0,
  IF_PORT_10BASE2,
  IF_PORT_10BASET,
  IF_PORT_AUI,
  IF_PORT_100BASET,
  IF_PORT_100BASETX,
  IF_PORT_100BASEFX
};



extern const char *if_port_text[];




struct neighbour;
struct neigh_parms;
struct sk_buff;

struct netif_rx_stats
{
  unsigned total;
  unsigned dropped;
  unsigned time_squeeze;
  unsigned throttled;
  unsigned fastroute_hit;
  unsigned fastroute_success;
  unsigned fastroute_defer;
  unsigned fastroute_deferred_out;
  unsigned fastroute_latency_reduction;
  unsigned cpu_collision;
} __attribute__ ((__aligned__ ((1 << ((5))))));

extern struct netif_rx_stats netdev_rx_stat[];






struct dev_mc_list
{
  struct dev_mc_list *next;
  __u8 dmi_addr[8];
  unsigned char dmi_addrlen;
  int dmi_users;
  int dmi_gusers;
};

struct hh_cache
{
  struct hh_cache *hh_next;
  atomic_t hh_refcnt;
  unsigned short hh_type;



  int hh_len;
  int (*hh_output) (struct sk_buff * skb);
  rwlock_t hh_lock;







  unsigned long hh_data[(((32) + (16 - 1)) & ~(16 - 1)) / sizeof (long)];
};






enum netdev_state_t
{
  __LINK_STATE_XOFF = 0,
  __LINK_STATE_START,
  __LINK_STATE_PRESENT,
  __LINK_STATE_SCHED,
  __LINK_STATE_NOCARRIER,
  __LINK_STATE_RX_SCHED
};






struct netdev_boot_setup
{
  char name[16];
  struct ifmap map;
};

struct net_device
{






  char name[16];





  unsigned long rmem_end;
  unsigned long rmem_start;
  unsigned long mem_end;
  unsigned long mem_start;
  unsigned long base_addr;
  unsigned int irq;






  unsigned char if_port;
  unsigned char dma;

  unsigned long state;

  struct net_device *next;


  int (*init) (struct net_device * dev);



  struct net_device *next_sched;


  int ifindex;
  int iflink;


  struct net_device_stats *(*get_stats) (struct net_device * dev);
  struct iw_statistics *(*get_wireless_stats) (struct net_device * dev);



  struct iw_handler_def *wireless_handlers;

  struct ethtool_ops *ethtool_ops;

  unsigned long trans_start;
  unsigned long last_rx;

  unsigned short flags;
  unsigned short gflags;
  unsigned short priv_flags;
  unsigned short unused_alignment_fixer;



  unsigned mtu;
  unsigned short type;
  unsigned short hard_header_len;
  void *priv;

  struct net_device *master;




  unsigned char broadcast[8];
  unsigned char dev_addr[8];
  unsigned char addr_len;

  struct dev_mc_list *mc_list;
  int mc_count;
  int promiscuity;
  int allmulti;

  int watchdog_timeo;
  struct timer_list watchdog_timer;



  void *atalk_ptr;
  void *ip_ptr;
  void *dn_ptr;
  void *ip6_ptr;
  void *ec_ptr;

  struct list_head poll_list;
  int quota;
  int weight;

  struct Qdisc *qdisc;
  struct Qdisc *qdisc_sleeping;
  struct Qdisc *qdisc_list;
  struct Qdisc *qdisc_ingress;
  unsigned long tx_queue_len;


  spinlock_t xmit_lock;



  int xmit_lock_owner;

  spinlock_t queue_lock;

  atomic_t refcnt;

  int deadbeaf;


  int features;

  void (*uninit) (struct net_device * dev);

  void (*destructor) (struct net_device * dev);


  int (*open) (struct net_device * dev);
  int (*stop) (struct net_device * dev);
  int (*hard_start_xmit) (struct sk_buff * skb, struct net_device * dev);

  int (*poll) (struct net_device * dev, int *quota);
  int (*hard_header) (struct sk_buff * skb,
		      struct net_device * dev,
		      unsigned short type,
		      void *daddr, void *saddr, unsigned len);
  int (*rebuild_header) (struct sk_buff * skb);

  void (*set_multicast_list) (struct net_device * dev);

  int (*set_mac_address) (struct net_device * dev, void *addr);

  int (*do_ioctl) (struct net_device * dev, struct ifreq * ifr, int cmd);

  int (*set_config) (struct net_device * dev, struct ifmap * map);

  int (*hard_header_cache) (struct neighbour * neigh, struct hh_cache * hh);
  void (*header_cache_update) (struct hh_cache * hh,
			       struct net_device * dev, unsigned char *haddr);

  int (*change_mtu) (struct net_device * dev, int new_mtu);


  void (*tx_timeout) (struct net_device * dev);

  void (*vlan_rx_register) (struct net_device * dev, struct vlan_group * grp);
  void (*vlan_rx_add_vid) (struct net_device * dev, unsigned short vid);
  void (*vlan_rx_kill_vid) (struct net_device * dev, unsigned short vid);

  int (*hard_header_parse) (struct sk_buff * skb, unsigned char *haddr);
  int (*neigh_setup) (struct net_device * dev, struct neigh_parms *);
  int (*accept_fastpath) (struct net_device *, struct dst_entry *);


  struct module *owner;


  struct net_bridge_port *br_port;

};




struct packet_type
{
  unsigned short type;
  struct net_device *dev;
  int (*func) (struct sk_buff *, struct net_device *, struct packet_type *);
  void *data;
  struct packet_type *next;
};




typedef void irqreturn_t;




struct irqaction
{
  void (*handler) (int, void *, struct pt_regs *);
  unsigned long flags;
  unsigned long mask;
  const char *name;
  void *dev_id;
  struct irqaction *next;
};





enum
{
  TIMER_BH = 0,
  TQUEUE_BH,
  DIGI_BH,
  SERIAL_BH,
  RISCOM8_BH,
  SPECIALIX_BH,
  AURORA_BH,
  ESP_BH,
  SCSI_BH,
  IMMEDIATE_BH,
  CYCLADES_BH,
  CM206_BH,
  JS_BH,
  MACSERIAL_BH,
  ISICOM_BH
};











static __inline__ int
irq_cannonicalize (int irq)
{
  return ((irq == 2) ? 9 : irq);
}

extern void disable_irq (unsigned int);
extern void disable_irq_nosync (unsigned int);
extern void enable_irq (unsigned int);
extern void release_x86_irqs (struct task_struct *);


struct hw_interrupt_type
{
  const char *typename;
  unsigned int (*startup) (unsigned int irq);
  void (*shutdown) (unsigned int irq);
  void (*enable) (unsigned int irq);
  void (*disable) (unsigned int irq);
  void (*ack) (unsigned int irq);
  void (*end) (unsigned int irq);
  void (*set_affinity) (unsigned int irq, unsigned long mask);
};

typedef struct hw_interrupt_type hw_irq_controller;

typedef struct
{
  unsigned int status;
  hw_irq_controller *handler;
  struct irqaction *action;
  unsigned int depth;
  spinlock_t lock;
} __attribute__ ((__aligned__ ((1 << ((5)))))) irq_desc_t;

extern irq_desc_t irq_desc[224];



extern int irq_vector[224];

extern void mask_irq (unsigned int irq);
extern void unmask_irq (unsigned int irq);
extern void disable_8259A_irq (unsigned int irq);
extern void enable_8259A_irq (unsigned int irq);
extern int i8259A_irq_pending (unsigned int irq);
extern void make_8259A_irq (unsigned int irq);
extern void init_8259A (int aeoi);
extern void send_IPI_self (int vector) __attribute__ ((regparm (3)));
extern void init_VISWS_APIC_irqs (void);
extern void setup_IO_APIC (void);
extern void disable_IO_APIC (void);
extern void print_IO_APIC (void);
extern int IO_APIC_get_PCI_irq_vector (int bus, int slot, int fn);
extern void send_IPI (int dest, int vector);

extern unsigned long io_apic_irqs;

extern atomic_t irq_err_count;
extern atomic_t irq_mis_count;

extern char _stext, _etext;

extern unsigned long prof_cpu_mask;
extern unsigned int *prof_buffer;
extern unsigned long prof_len;
extern unsigned long prof_shift;





static inline void
x86_do_profile (unsigned long eip)
{
  if (!prof_buffer)
    return;





  if (!((1 << 0) & prof_cpu_mask))
    return;

  eip -= (unsigned long) &_stext;
  eip >>= prof_shift;





  if (eip > prof_len - 1)
    eip = prof_len - 1;
  atomic_inc ((atomic_t *) & prof_buffer[eip]);
}


static inline void
hw_resend_irq (struct hw_interrupt_type *h, unsigned int i)
{
  if ((((i) >= 16) || ((1 << (i)) & io_apic_irqs)))
    send_IPI_self (irq_vector[i]);
}



extern int handle_IRQ_event (unsigned int, struct pt_regs *,
			     struct irqaction *);
extern int setup_irq (unsigned int, struct irqaction *);

extern hw_irq_controller no_irq_type;
extern void no_action (int cpl, void *dev_id, struct pt_regs *regs);




typedef struct
{
  unsigned int __softirq_pending;
  unsigned int __local_irq_count;
  unsigned int __local_bh_count;
  unsigned int __syscall_count;
  struct task_struct *__ksoftirqd_task;
  unsigned int __nmi_count;
} __attribute__ ((__aligned__ ((1 << ((5)))))) irq_cpustat_t;



extern irq_cpustat_t irq_stat[];





enum
{
  HI_SOFTIRQ = 0,
  NET_TX_SOFTIRQ,
  NET_RX_SOFTIRQ,
  TASKLET_SOFTIRQ
};





struct softirq_action
{
  void (*action) (struct softirq_action *);
  void *data;
};

__attribute__ ((regparm (0)))
     void
     do_softirq (void);
     extern void
     open_softirq (int nr, void (*action) (struct softirq_action *),
		   void *data);
     extern void
     softirq_init (void);

     extern void
     cpu_raise_softirq (unsigned int cpu, unsigned int nr)
  __attribute__ ((regparm (3)));
     extern void
     raise_softirq (unsigned int nr) __attribute__ ((regparm (3)));

     struct tasklet_struct
     {
       struct tasklet_struct *
	 next;
       unsigned long
	 state;
       atomic_t
	 count;
       void (*func) (unsigned long);
       unsigned long
	 data;
     };

     enum
     {
       TASKLET_STATE_SCHED,
       TASKLET_STATE_RUN
     };

     struct tasklet_head
     {
       struct tasklet_struct *
	 list;
     } __attribute__ ((__aligned__ ((1 << ((5))))));

     extern struct tasklet_head
       tasklet_vec[1];
     extern struct tasklet_head
       tasklet_hi_vec[1];

     extern void
     __tasklet_schedule (struct tasklet_struct *t)
  __attribute__ ((regparm (3)));

     static inline void
     tasklet_schedule (struct tasklet_struct *t)
{
  if (!test_and_set_bit (TASKLET_STATE_SCHED, &t->state))
    __tasklet_schedule (t);
}

extern void __tasklet_hi_schedule (struct tasklet_struct *t)
  __attribute__ ((regparm (3)));

static inline void
tasklet_hi_schedule (struct tasklet_struct *t)
{
  if (!test_and_set_bit (TASKLET_STATE_SCHED, &t->state))
    __tasklet_hi_schedule (t);
}


static inline void
tasklet_disable_nosync (struct tasklet_struct *t)
{
  atomic_inc (&t->count);
  __asm__ __volatile__ ("":::"memory");
}

static inline void
tasklet_disable (struct tasklet_struct *t)
{
  tasklet_disable_nosync (t);
  do
    {
    }
  while (0);
  __asm__ __volatile__ ("":::"memory");
}

static inline void
tasklet_enable (struct tasklet_struct *t)
{
  __asm__ __volatile__ ("":::"memory");
  atomic_dec (&t->count);
}

static inline void
tasklet_hi_enable (struct tasklet_struct *t)
{
  __asm__ __volatile__ ("":::"memory");
  atomic_dec (&t->count);
}

extern void tasklet_kill (struct tasklet_struct *t);
extern void tasklet_init (struct tasklet_struct *t,
			  void (*func) (unsigned long), unsigned long data);

extern struct tasklet_struct bh_task_vec[];


extern spinlock_t global_bh_lock;

static inline void
mark_bh (int nr)
{
  tasklet_hi_schedule (bh_task_vec + nr);
}

extern void init_bh (int nr, void (*routine) (void));
extern void remove_bh (int nr);

extern unsigned long probe_irq_on (void);
extern int probe_irq_off (unsigned long);
extern unsigned int probe_irq_mask (unsigned long);



struct notifier_block
{
  int (*notifier_call) (struct notifier_block * self, unsigned long, void *);
  struct notifier_block *next;
  int priority;
};




extern int notifier_chain_register (struct notifier_block **list,
				    struct notifier_block *n);
extern int notifier_chain_unregister (struct notifier_block **nl,
				      struct notifier_block *n);
extern int notifier_call_chain (struct notifier_block **n, unsigned long val,
				void *v);


extern struct net_device loopback_dev;
extern struct net_device *dev_base;
extern rwlock_t dev_base_lock;

extern int netdev_boot_setup_add (char *name, struct ifmap *map);
extern int netdev_boot_setup_check (struct net_device *dev);
extern struct net_device *dev_getbyhwaddr (unsigned short type, char *hwaddr);
extern void dev_add_pack (struct packet_type *pt);
extern void dev_remove_pack (struct packet_type *pt);
extern int dev_get (const char *name);
extern struct net_device *dev_get_by_flags (unsigned short flags,
					    unsigned short mask);
extern struct net_device *__dev_get_by_flags (unsigned short flags,
					      unsigned short mask);
extern struct net_device *dev_get_by_name (const char *name);
extern struct net_device *__dev_get_by_name (const char *name);
extern struct net_device *dev_alloc (const char *name, int *err);
extern int dev_alloc_name (struct net_device *dev, const char *name);
extern int dev_open (struct net_device *dev);
extern int dev_close (struct net_device *dev);
extern int dev_queue_xmit (struct sk_buff *skb);
extern int register_netdevice (struct net_device *dev);
extern int unregister_netdevice (struct net_device *dev);
extern int register_netdevice_notifier (struct notifier_block *nb);
extern int unregister_netdevice_notifier (struct notifier_block *nb);
extern int dev_new_index (void);
extern struct net_device *dev_get_by_index (int ifindex);
extern struct net_device *__dev_get_by_index (int ifindex);
extern int dev_restart (struct net_device *dev);

typedef int gifconf_func_t (struct net_device *dev, char *bufptr, int len);
extern int register_gifconf (unsigned int family, gifconf_func_t * gifconf);
static inline int
unregister_gifconf (unsigned int family)
{
  return register_gifconf (family, 0);
}






struct softnet_data
{
  int throttle;
  int cng_level;
  int avg_blog;
  struct sk_buff_head input_pkt_queue;
  struct list_head poll_list;
  struct net_device *output_queue;
  struct sk_buff *completion_queue;

  struct net_device blog_dev;
} __attribute__ ((__aligned__ ((1 << ((5))))));


extern struct softnet_data softnet_data[1];



static inline void
__netif_schedule (struct net_device *dev)
{
  if (!test_and_set_bit (__LINK_STATE_SCHED, &dev->state))
    {
      unsigned long flags;
      int cpu = 0;

      do
	{
	  __asm__ __volatile__ ("pushfl ; popl %0":"=g" (flags):);
	  __asm__ __volatile__ ("cli":::"memory");
	}
      while (0);;
      dev->next_sched = softnet_data[cpu].output_queue;
      softnet_data[cpu].output_queue = dev;
      cpu_raise_softirq (cpu, NET_TX_SOFTIRQ);
      __asm__ __volatile__ ("pushl %0 ; popfl"::"g" (flags):"memory", "cc");
    }
}

static inline void
netif_schedule (struct net_device *dev)
{
  if (!
      (__builtin_constant_p (__LINK_STATE_XOFF) ?
       constant_test_bit ((__LINK_STATE_XOFF),
			  (&dev->
			   state)) : variable_test_bit ((__LINK_STATE_XOFF),
							(&dev->state))))
    __netif_schedule (dev);
}

static inline void
netif_start_queue (struct net_device *dev)
{
  clear_bit (__LINK_STATE_XOFF, &dev->state);
}

static inline void
netif_wake_queue (struct net_device *dev)
{
  if (test_and_clear_bit (__LINK_STATE_XOFF, &dev->state))
    __netif_schedule (dev);
}

static inline void
netif_stop_queue (struct net_device *dev)
{
  set_bit (__LINK_STATE_XOFF, &dev->state);
}

static inline int
netif_queue_stopped (struct net_device *dev)
{
  return (__builtin_constant_p (__LINK_STATE_XOFF) ?
	  constant_test_bit ((__LINK_STATE_XOFF),
			     (&dev->
			      state)) :
	  variable_test_bit ((__LINK_STATE_XOFF), (&dev->state)));
}

static inline int
netif_running (struct net_device *dev)
{
  return (__builtin_constant_p (__LINK_STATE_START) ?
	  constant_test_bit ((__LINK_STATE_START),
			     (&dev->
			      state)) :
	  variable_test_bit ((__LINK_STATE_START), (&dev->state)));
}





static inline void
dev_kfree_skb_irq (struct sk_buff *skb)
{
  if (atomic_dec_and_test (&skb->users))
    {
      int cpu = 0;
      unsigned long flags;

      do
	{
	  __asm__ __volatile__ ("pushfl ; popl %0":"=g" (flags):);
	  __asm__ __volatile__ ("cli":::"memory");
	}
      while (0);;
      skb->next = softnet_data[cpu].completion_queue;
      softnet_data[cpu].completion_queue = skb;
      cpu_raise_softirq (cpu, NET_TX_SOFTIRQ);
      __asm__ __volatile__ ("pushl %0 ; popfl"::"g" (flags):"memory", "cc");
    }
}




static inline void
dev_kfree_skb_any (struct sk_buff *skb)
{
  if ((((void) ((0)), irq_stat[0].__local_irq_count) != 0))
    dev_kfree_skb_irq (skb);
  else
    kfree_skb (skb);
}


extern int netif_rx (struct sk_buff *skb);

extern int netif_receive_skb (struct sk_buff *skb);
extern int dev_ioctl (unsigned int cmd, void *);
extern int dev_ethtool (struct ifreq *);
extern int dev_change_flags (struct net_device *, unsigned);
extern void dev_queue_xmit_nit (struct sk_buff *skb, struct net_device *dev);

extern void dev_init (void);

extern int netdev_nit;




static inline int
netif_rx_ni (struct sk_buff *skb)
{
  int err = netif_rx (skb);
  if (((void) ((0)), irq_stat[0].__softirq_pending))
    do_softirq ();
  return err;
}

static inline void
dev_init_buffers (struct net_device *dev)
{

}

extern int netdev_finish_unregister (struct net_device *dev);

static inline void
dev_put (struct net_device *dev)
{
  if (atomic_dec_and_test (&dev->refcnt))
    netdev_finish_unregister (dev);
}


static inline int
netif_carrier_ok (struct net_device *dev)
{
  return !(__builtin_constant_p (__LINK_STATE_NOCARRIER) ?
	   constant_test_bit ((__LINK_STATE_NOCARRIER),
			      (&dev->
			       state)) :
	   variable_test_bit ((__LINK_STATE_NOCARRIER), (&dev->state)));
}

extern void __netdev_watchdog_up (struct net_device *dev);

static inline void
netif_carrier_on (struct net_device *dev)
{
  clear_bit (__LINK_STATE_NOCARRIER, &dev->state);
  if (netif_running (dev))
    __netdev_watchdog_up (dev);
}

static inline void
netif_carrier_off (struct net_device *dev)
{
  set_bit (__LINK_STATE_NOCARRIER, &dev->state);
}


static inline int
netif_device_present (struct net_device *dev)
{
  return (__builtin_constant_p (__LINK_STATE_PRESENT) ?
	  constant_test_bit ((__LINK_STATE_PRESENT),
			     (&dev->
			      state)) :
	  variable_test_bit ((__LINK_STATE_PRESENT), (&dev->state)));
}

static inline void
netif_device_detach (struct net_device *dev)
{
  if (test_and_clear_bit (__LINK_STATE_PRESENT, &dev->state) &&
      netif_running (dev))
    {
      netif_stop_queue (dev);
    }
}

static inline void
netif_device_attach (struct net_device *dev)
{
  if (!test_and_set_bit (__LINK_STATE_PRESENT, &dev->state) &&
      netif_running (dev))
    {
      netif_wake_queue (dev);
      __netdev_watchdog_up (dev);
    }
}






enum
{
  NETIF_MSG_DRV = 0x0001,
  NETIF_MSG_PROBE = 0x0002,
  NETIF_MSG_LINK = 0x0004,
  NETIF_MSG_TIMER = 0x0008,
  NETIF_MSG_IFDOWN = 0x0010,
  NETIF_MSG_IFUP = 0x0020,
  NETIF_MSG_RX_ERR = 0x0040,
  NETIF_MSG_TX_ERR = 0x0080,
  NETIF_MSG_TX_QUEUED = 0x0100,
  NETIF_MSG_INTR = 0x0200,
  NETIF_MSG_TX_DONE = 0x0400,
  NETIF_MSG_RX_STATUS = 0x0800,
  NETIF_MSG_PKTDATA = 0x1000,
  NETIF_MSG_HW = 0x2000,
  NETIF_MSG_WOL = 0x4000,
};

static inline int
netif_rx_schedule_prep (struct net_device *dev)
{
  return netif_running (dev) &&
    !test_and_set_bit (__LINK_STATE_RX_SCHED, &dev->state);
}





static inline void
__netif_rx_schedule (struct net_device *dev)
{
  unsigned long flags;
  int cpu = 0;

  do
    {
      __asm__ __volatile__ ("pushfl ; popl %0":"=g" (flags):);
      __asm__ __volatile__ ("cli":::"memory");
    }
  while (0);;
  atomic_inc (&(dev)->refcnt);
  list_add_tail (&dev->poll_list, &softnet_data[cpu].poll_list);
  if (dev->quota < 0)
    dev->quota += dev->weight;
  else
    dev->quota = dev->weight;
  do
    {
      ((void) ((cpu)), irq_stat[0].__softirq_pending) |=
	1UL << (NET_RX_SOFTIRQ);
    }
  while (0);
  __asm__ __volatile__ ("pushl %0 ; popfl"::"g" (flags):"memory", "cc");
}



static inline void
netif_rx_schedule (struct net_device *dev)
{
  if (netif_rx_schedule_prep (dev))
    __netif_rx_schedule (dev);
}




static inline int
netif_rx_reschedule (struct net_device *dev, int undo)
{
  if (netif_rx_schedule_prep (dev))
    {
      unsigned long flags;
      int cpu = 0;

      dev->quota += undo;

      do
	{
	  __asm__ __volatile__ ("pushfl ; popl %0":"=g" (flags):);
	  __asm__ __volatile__ ("cli":::"memory");
	}
      while (0);;
      list_add_tail (&dev->poll_list, &softnet_data[cpu].poll_list);
      do
	{
	  ((void) ((cpu)), irq_stat[0].__softirq_pending) |=
	    1UL << (NET_RX_SOFTIRQ);
	}
      while (0);
      __asm__ __volatile__ ("pushl %0 ; popfl"::"g" (flags):"memory", "cc");
      return 1;
    }
  return 0;
}






static inline void
netif_rx_complete (struct net_device *dev)
{
  unsigned long flags;

  do
    {
      __asm__ __volatile__ ("pushfl ; popl %0":"=g" (flags):);
      __asm__ __volatile__ ("cli":::"memory");
    }
  while (0);;
  if (!
      (__builtin_constant_p (__LINK_STATE_RX_SCHED) ?
       constant_test_bit ((__LINK_STATE_RX_SCHED),
			  (&dev->
			   state)) :
       variable_test_bit ((__LINK_STATE_RX_SCHED), (&dev->state))))
    do
      {
	if (!(0))
	  {
	    printk ("kgdb assertion failed: %s\n", "BUG");
	    show_stack (((void *) 0));
	    breakpoint ();
	  }
      }
    while (0);
  list_del (&dev->poll_list);
  __asm__ __volatile__ ("":::"memory");
  clear_bit (__LINK_STATE_RX_SCHED, &dev->state);
  __asm__ __volatile__ ("pushl %0 ; popfl"::"g" (flags):"memory", "cc");
}

static inline void
netif_poll_disable (struct net_device *dev)
{
  while (test_and_set_bit (__LINK_STATE_RX_SCHED, &dev->state))
    {

      get_current ()->state = 1;
      schedule_timeout (1);
    }
}

static inline void
netif_poll_enable (struct net_device *dev)
{
  clear_bit (__LINK_STATE_RX_SCHED, &dev->state);
}




static inline void
__netif_rx_complete (struct net_device *dev)
{
  if (!
      (__builtin_constant_p (__LINK_STATE_RX_SCHED) ?
       constant_test_bit ((__LINK_STATE_RX_SCHED),
			  (&dev->
			   state)) :
       variable_test_bit ((__LINK_STATE_RX_SCHED), (&dev->state))))
    do
      {
	if (!(0))
	  {
	    printk ("kgdb assertion failed: %s\n", "BUG");
	    show_stack (((void *) 0));
	    breakpoint ();
	  }
      }
    while (0);
  list_del (&dev->poll_list);
  __asm__ __volatile__ ("":::"memory");
  clear_bit (__LINK_STATE_RX_SCHED, &dev->state);
}

static inline void
netif_tx_disable (struct net_device *dev)
{
  do
    {
      do
	{
	  ((void) ((0)), irq_stat[0].__local_bh_count)++;
	  __asm__ __volatile__ ("":::"memory");
	}
      while (0);
      (void) (&dev->xmit_lock);
    }
  while (0);
  netif_stop_queue (dev);
  do
    {
      do
	{
	}
      while (0);
      do
	{
	  unsigned int *ptr = &((void) ((0)), irq_stat[0].__local_bh_count);
	  __asm__ __volatile__ ("":::"memory");
	  if (!--*ptr)
	    __asm__ __volatile__ ("cmpl $0, -8(%0);" "jnz 2f;" "1:;"
				  ".subsection 1\n\t" "" ".ifndef "
				  ".text.lock." "tmalloc" "\n\t" ".text.lock."
				  "tmalloc" ":\n\t" ".endif\n\t"
				  "2: pushl %%eax; pushl %%ecx; pushl %%edx;"
				  "call %c1;"
				  "popl %%edx; popl %%ecx; popl %%eax;"
				  "jmp 1b;" ".previous\n\t"::"r" (ptr),
				  "i" (do_softirq));
	}
      while (0);
    }
  while (0);
}



extern void ether_setup (struct net_device *dev);
extern void fddi_setup (struct net_device *dev);
extern void tr_setup (struct net_device *dev);
extern void fc_setup (struct net_device *dev);
extern void fc_freedev (struct net_device *dev);

extern struct net_device *alloc_netdev (int sizeof_priv, const char *name,
					void (*setup) (struct net_device *));
extern int register_netdev (struct net_device *dev);
extern void unregister_netdev (struct net_device *dev);

extern void dev_mc_upload (struct net_device *dev);
extern int dev_mc_delete (struct net_device *dev, void *addr, int alen,
			  int all);
extern int dev_mc_add (struct net_device *dev, void *addr, int alen,
		       int newonly);
extern void dev_mc_discard (struct net_device *dev);
extern void dev_set_promiscuity (struct net_device *dev, int inc);
extern void dev_set_allmulti (struct net_device *dev, int inc);
extern void netdev_state_change (struct net_device *dev);

extern void dev_load (const char *name);
extern void dev_mcast_init (void);
extern int netdev_register_fc (struct net_device *dev,
			       void (*stimul) (struct net_device * dev));
extern void netdev_unregister_fc (int bit);
extern int netdev_max_backlog;
extern int weight_p;
extern unsigned long netdev_fc_xoff;
extern atomic_t netdev_dropping;
extern int netdev_set_master (struct net_device *dev,
			      struct net_device *master);
extern struct sk_buff *skb_checksum_help (struct sk_buff *skb);






static inline void
free_netdev (struct net_device *dev)
{
  kfree (dev);
}







struct in6_addr
{
  union
  {
    __u8 u6_addr8[16];
    __u16 u6_addr16[8];
    __u32 u6_addr32[4];
  } in6_u;



};





extern const struct in6_addr in6addr_any;

extern const struct in6_addr in6addr_loopback;


struct sockaddr_in6
{
  unsigned short int sin6_family;
  __u16 sin6_port;
  __u32 sin6_flowinfo;
  struct in6_addr sin6_addr;
  __u32 sin6_scope_id;
};

struct ipv6_mreq
{

  struct in6_addr ipv6mr_multiaddr;


  int ipv6mr_ifindex;
};



struct in6_flowlabel_req
{
  struct in6_addr flr_dst;
  __u32 flr_label;
  __u8 flr_action;
  __u8 flr_share;
  __u16 flr_flags;
  __u16 flr_expires;
  __u16 flr_linger;
  __u32 __flr_pad;

};


struct inet_protocol
{
  int (*handler) (struct sk_buff * skb);
  void (*err_handler) (struct sk_buff * skb, u32 info);
  struct inet_protocol *next;
  unsigned char protocol;
  unsigned char copy:1;
  void *data;
  const char *name;
};

struct inet_protosw
{
  struct list_head list;


  unsigned short type;
  int protocol;

  struct proto *prot;
  struct proto_ops *ops;

  int capability;



  char no_check;
  unsigned char flags;
};



extern struct inet_protocol *inet_protocol_base;
extern struct inet_protocol *inet_protos[32];
extern struct list_head inetsw[(10 + 1)];






extern void inet_add_protocol (struct inet_protocol *prot);
extern int inet_del_protocol (struct inet_protocol *prot);
extern void inet_register_protosw (struct inet_protosw *p);
extern void inet_unregister_protosw (struct inet_protosw *p);








struct datalink_proto
{
  unsigned short type_len;
  unsigned char type[8];
  const char *string_name;
  unsigned short header_length;
  int (*rcvfunc) (struct sk_buff *, struct net_device *,
		  struct packet_type *);
  void (*datalink_header) (struct datalink_proto *, struct sk_buff *,
			   unsigned char *);
  struct datalink_proto *next;
};









struct sockaddr_ipx
{
  sa_family_t sipx_family;
  __u16 sipx_port;
  __u32 sipx_network;
  unsigned char sipx_node[6];
  __u8 sipx_type;
  unsigned char sipx_zero;
};

typedef struct ipx_route_definition
{
  __u32 ipx_network;
  __u32 ipx_router_network;
  unsigned char ipx_router_node[6];
} ipx_route_definition;

typedef struct ipx_interface_definition
{
  __u32 ipx_network;
  unsigned char ipx_device[16];
  unsigned char ipx_dlink_type;






  unsigned char ipx_special;



  unsigned char ipx_node[6];
} ipx_interface_definition;

typedef struct ipx_config_data
{
  unsigned char ipxcfg_auto_select_primary;
  unsigned char ipxcfg_auto_create_interfaces;
} ipx_config_data;





struct ipx_route_def
{
  __u32 ipx_network;
  __u32 ipx_router_network;

  unsigned char ipx_router_node[6];
  unsigned char ipx_device[16];
  unsigned short ipx_flags;




};

extern int ipxrtr_route_skb (struct sk_buff *);
extern int ipx_if_offset (unsigned long ipx_net_number);
extern void ipx_remove_socket (struct sock *sk);


typedef struct
{
  __u32 net;
  __u8 node[6];
  __u16 sock;
} ipx_address;






struct ipxhdr
{
  __u16 ipx_checksum __attribute__ ((packed));

  __u16 ipx_pktsize __attribute__ ((packed));
  __u8 ipx_tctrl;
  __u8 ipx_type;






  ipx_address ipx_dest __attribute__ ((packed));
  ipx_address ipx_source __attribute__ ((packed));
};

typedef struct ipx_interface
{

  __u32 if_netnum;
  unsigned char if_node[6];
  atomic_t refcnt;


  struct net_device *if_dev;
  struct datalink_proto *if_dlink;
  unsigned short if_dlink_type;


  unsigned short if_sknum;
  struct sock *if_sklist;
  spinlock_t if_sklist_lock;


  int if_ipx_offset;
  unsigned char if_internal;
  unsigned char if_primary;

  struct ipx_interface *if_next;
} ipx_interface;

typedef struct ipx_route
{
  __u32 ir_net;
  ipx_interface *ir_intrfc;
  unsigned char ir_routed;
  unsigned char ir_router_node[6];
  struct ipx_route *ir_next;
  atomic_t refcnt;
} ipx_route;


struct ipx_cb
{
  u8 ipx_tctrl;
  u32 ipx_dest_net;
  u32 ipx_source_net;
  struct
  {
    u32 netnum;
    int index;
  } last_hop;
};




extern int ipx_register_spx (struct proto_ops **, struct net_proto_family *);
extern int ipx_unregister_spx (void);




struct sock_filter
{
  __u16 code;
  __u8 jt;
  __u8 jf;
  __u32 k;
};

struct sock_fprog
{
  unsigned short len;
  struct sock_filter *filter;
};


struct sk_filter
{
  atomic_t refcnt;
  unsigned int len;
  struct sock_filter insns[0];
};

static inline unsigned int
sk_filter_len (struct sk_filter *fp)
{
  return fp->len * sizeof (struct sock_filter) + sizeof (*fp);
}


extern int sk_run_filter (struct sk_buff *skb, struct sock_filter *filter,
			  int flen);
extern int sk_attach_filter (struct sock_fprog *fprog, struct sock *sk);
extern int sk_chk_filter (struct sock_filter *filter, int flen);








struct neigh_parms
{
  struct neigh_parms *next;
  int (*neigh_setup) (struct neighbour *);
  struct neigh_table *tbl;
  int entries;
  void *priv;

  void *sysctl_table;

  int base_reachable_time;
  int retrans_time;
  int gc_staletime;
  int reachable_time;
  int delay_probe_time;

  int queue_len;
  int ucast_probes;
  int app_probes;
  int mcast_probes;
  int anycast_delay;
  int proxy_delay;
  int proxy_qlen;
  int locktime;
};

struct neigh_statistics
{
  unsigned long allocs;
  unsigned long res_failed;
  unsigned long rcv_probes_mcast;
  unsigned long rcv_probes_ucast;
};

struct neighbour
{
  struct neighbour *next;
  struct neigh_table *tbl;
  struct neigh_parms *parms;
  struct net_device *dev;
  unsigned long used;
  unsigned long confirmed;
  unsigned long updated;
  __u8 flags;
  __u8 nud_state;
  __u8 type;
  __u8 dead;
  atomic_t probes;
  rwlock_t lock;
  unsigned char ha[(8 + sizeof (unsigned long) - 1) &
		   ~(sizeof (unsigned long) - 1)];
  struct hh_cache *hh;
  atomic_t refcnt;
  int (*output) (struct sk_buff * skb);
  struct sk_buff_head arp_queue;
  struct timer_list timer;
  struct neigh_ops *ops;
  u8 primary_key[0];
};

struct neigh_ops
{
  int family;
  void (*destructor) (struct neighbour *);
  void (*solicit) (struct neighbour *, struct sk_buff *);
  void (*error_report) (struct neighbour *, struct sk_buff *);
  int (*output) (struct sk_buff *);
  int (*connected_output) (struct sk_buff *);
  int (*hh_output) (struct sk_buff *);
  int (*queue_xmit) (struct sk_buff *);
};

struct pneigh_entry
{
  struct pneigh_entry *next;
  struct net_device *dev;
  u8 key[0];
};

struct neigh_table
{
  struct neigh_table *next;
  int family;
  int entry_size;
  int key_len;
    __u32 (*hash) (const void *pkey, const struct net_device *);
  int (*constructor) (struct neighbour *);
  int (*pconstructor) (struct pneigh_entry *);
  void (*pdestructor) (struct pneigh_entry *);
  void (*proxy_redo) (struct sk_buff * skb);
  char *id;
  struct neigh_parms parms;

  int gc_interval;
  int gc_thresh1;
  int gc_thresh2;
  int gc_thresh3;
  unsigned long last_flush;
  struct timer_list gc_timer;
  struct timer_list proxy_timer;
  struct sk_buff_head proxy_queue;
  int entries;
  rwlock_t lock;
  unsigned long last_rand;
  struct neigh_parms *parms_list;
  kmem_cache_t *kmem_cachep;
  struct tasklet_struct gc_task;
  struct neigh_statistics stats;
  struct neighbour *hash_buckets[0x1F + 1];
  struct pneigh_entry *phash_buckets[0xF + 1];
};

extern void neigh_table_init (struct neigh_table *tbl);
extern int neigh_table_clear (struct neigh_table *tbl);
extern struct neighbour *neigh_lookup (struct neigh_table *tbl,
				       const void *pkey,
				       struct net_device *dev);
extern struct neighbour *neigh_create (struct neigh_table *tbl,
				       const void *pkey,
				       struct net_device *dev);
extern void neigh_destroy (struct neighbour *neigh);
extern int __neigh_event_send (struct neighbour *neigh, struct sk_buff *skb);
extern int neigh_update (struct neighbour *neigh, const u8 * lladdr, u8 new,
			 int override, int arp);
extern void neigh_changeaddr (struct neigh_table *tbl,
			      struct net_device *dev);
extern int neigh_ifdown (struct neigh_table *tbl, struct net_device *dev);
extern int neigh_resolve_output (struct sk_buff *skb);
extern int neigh_connected_output (struct sk_buff *skb);
extern int neigh_compat_output (struct sk_buff *skb);
extern struct neighbour *neigh_event_ns (struct neigh_table *tbl,
					 u8 * lladdr, void *saddr,
					 struct net_device *dev);

extern struct neigh_parms *neigh_parms_alloc (struct net_device *dev,
					      struct neigh_table *tbl);
extern void neigh_parms_release (struct neigh_table *tbl,
				 struct neigh_parms *parms);
extern unsigned long neigh_rand_reach_time (unsigned long base);

extern void pneigh_enqueue (struct neigh_table *tbl, struct neigh_parms *p,
			    struct sk_buff *skb);
extern struct pneigh_entry *pneigh_lookup (struct neigh_table *tbl,
					   const void *key,
					   struct net_device *dev, int creat);
extern int pneigh_delete (struct neigh_table *tbl, const void *key,
			  struct net_device *dev);

struct netlink_callback;
struct nlmsghdr;
extern int neigh_dump_info (struct sk_buff *skb, struct netlink_callback *cb);
extern int neigh_add (struct sk_buff *skb, struct nlmsghdr *nlh, void *arg);
extern int neigh_delete (struct sk_buff *skb, struct nlmsghdr *nlh,
			 void *arg);
extern void neigh_app_ns (struct neighbour *n);

extern int neigh_sysctl_register (struct net_device *dev,
				  struct neigh_parms *p, int p_id,
				  int pdev_id, char *p_name);
extern void neigh_sysctl_unregister (struct neigh_parms *p);





static inline void
neigh_release (struct neighbour *neigh)
{
  if (atomic_dec_and_test (&neigh->refcnt))
    neigh_destroy (neigh);
}

static inline struct neighbour *
neigh_clone (struct neighbour *neigh)
{
  if (neigh)
    atomic_inc (&neigh->refcnt);
  return neigh;
}



static inline void
neigh_confirm (struct neighbour *neigh)
{
  if (neigh)
    neigh->confirmed = jiffies;
}

static inline int
neigh_is_connected (struct neighbour *neigh)
{
  return neigh->nud_state & (0x80 | 0x40 | 0x02);
}

static inline int
neigh_is_valid (struct neighbour *neigh)
{
  return neigh->nud_state & (0x80 | 0x40 | 0x02 | 0x10 | 0x04 | 0x08);
}

static inline int
neigh_event_send (struct neighbour *neigh, struct sk_buff *skb)
{
  neigh->used = jiffies;
  if (!(neigh->nud_state & ((0x80 | 0x40 | 0x02) | 0x08 | 0x10)))
    return __neigh_event_send (neigh, skb);
  return 0;
}

static inline struct neighbour *
__neigh_lookup (struct neigh_table *tbl, const void *pkey,
		struct net_device *dev, int creat)
{
  struct neighbour *n = neigh_lookup (tbl, pkey, dev);

  if (n || !creat)
    return n;

  n = neigh_create (tbl, pkey, dev);
  return IS_ERR (n) ? ((void *) 0) : n;
}

static inline struct neighbour *
__neigh_lookup_errno (struct neigh_table *tbl, const void *pkey,
		      struct net_device *dev)
{
  struct neighbour *n = neigh_lookup (tbl, pkey, dev);

  if (n)
    return n;

  return neigh_create (tbl, pkey, dev);
}



struct sk_buff;

struct dst_entry
{
  struct dst_entry *next;
  atomic_t __refcnt;
  int __use;
  struct net_device *dev;
  int obsolete;
  int flags;

  unsigned long lastuse;
  unsigned long expires;

  unsigned mxlock;
  unsigned pmtu;
  unsigned window;
  unsigned rtt;
  unsigned rttvar;
  unsigned ssthresh;
  unsigned cwnd;
  unsigned advmss;
  unsigned reordering;

  unsigned long rate_last;
  unsigned long rate_tokens;

  int error;

  struct neighbour *neighbour;
  struct hh_cache *hh;

  int (*input) (struct sk_buff *);
  int (*output) (struct sk_buff *);





  struct dst_ops *ops;

  char info[0];
};


struct dst_ops
{
  unsigned short family;
  unsigned short protocol;
  unsigned gc_thresh;

  int (*gc) (void);
  struct dst_entry *(*check) (struct dst_entry *, __u32 cookie);
  struct dst_entry *(*reroute) (struct dst_entry *, struct sk_buff *);
  void (*destroy) (struct dst_entry *);
  struct dst_entry *(*negative_advice) (struct dst_entry *);
  void (*link_failure) (struct sk_buff *);
  int entry_size;

  atomic_t entries;
  kmem_cache_t *kmem_cachep;
};



static inline void
dst_hold (struct dst_entry *dst)
{
  atomic_inc (&dst->__refcnt);
}

static inline struct dst_entry *
dst_clone (struct dst_entry *dst)
{
  if (dst)
    atomic_inc (&dst->__refcnt);
  return dst;
}

static inline void
dst_release (struct dst_entry *dst)
{
  if (dst)
    atomic_dec (&dst->__refcnt);
}

extern void *dst_alloc (struct dst_ops *ops);
extern void __dst_free (struct dst_entry *dst);
extern void dst_destroy (struct dst_entry *dst);

static inline void
dst_free (struct dst_entry *dst)
{
  if (dst->obsolete > 1)
    return;
  if (!((&dst->__refcnt)->counter))
    {
      dst_destroy (dst);
      return;
    }
  __dst_free (dst);
}

static inline void
dst_confirm (struct dst_entry *dst)
{
  if (dst)
    neigh_confirm (dst->neighbour);
}

static inline void
dst_negative_advice (struct dst_entry **dst_p)
{
  struct dst_entry *dst = *dst_p;
  if (dst && dst->ops->negative_advice)
    *dst_p = dst->ops->negative_advice (dst);
}

static inline void
dst_link_failure (struct sk_buff *skb)
{
  struct dst_entry *dst = skb->dst;
  if (dst && dst->ops && dst->ops->link_failure)
    dst->ops->link_failure (skb);
}

static inline void
dst_set_expires (struct dst_entry *dst, int timeout)
{
  unsigned long expires = jiffies + timeout;

  if (expires == 0)
    expires = 1;

  if (dst->expires == 0 || (long) (dst->expires - expires) > 0)
    dst->expires = expires;
}

extern void dst_init (void);




struct unix_opt
{
  struct unix_address *addr;
  struct dentry *dentry;
  struct vfsmount *mnt;
  struct semaphore readsem;
  struct sock *other;
  struct sock **list;
  struct sock *gc_tree;
  atomic_t inflight;
  rwlock_t lock;
  wait_queue_head_t peer_wait;
};




struct ipx_opt
{
  ipx_address dest_addr;
  ipx_interface *intrfc;
  unsigned short port;



  unsigned short type;




  unsigned short ipx_ncp_conn;
};

struct raw_opt
{
  struct icmp_filter filter;
};



struct inet_opt
{
  int ttl;
  int tos;
  unsigned cmsg_flags;
  struct ip_options *opt;
  unsigned char hdrincl;
  __u8 mc_ttl;
  __u8 mc_loop;
  unsigned recverr:1, freebind:1;
  __u16 id;
  __u8 pmtudisc;
  int mc_index;
  __u32 mc_addr;
  struct ip_mc_socklist *mc_list;
};

struct tcp_sack_block
{
  __u32 start_seq;
  __u32 end_seq;
};









struct dlist
{
  struct list_link *prev;
  struct list_link *next;
};

struct list_link
{


  struct list_link *prev;
  struct list_link *next;
};



static void
list_link_init (struct list_link *head)
{
  head->next = head->prev = ((void *) 0);
}






static int
dlist_integrityCheck (struct dlist *list)
{
  const int limit = 4000;
  int count = 0;
  struct list_link *elem;
  for (elem = (typeof (elem)) (list)->next; (elem != (typeof (elem)) (list));
       elem = (typeof (elem)) elem->next)
    {
      count++;
      if (count >= limit)
	{
	  printk ("dlist limit exceeded\n");
	  return 0;
	}
    }
  return 1;
}

static void
dlist_init (struct dlist *dlist)
{
  dlist->next = dlist->prev = (struct list_link *) dlist;
}

static void
dlist_insert_head (struct dlist *head, struct list_link *elem)
{
  if (head->next == elem)
    {
      do
	{
	  if (!(0))
	    {
	      printk ("kgdb assertion failed: %s\n", "BUG");
	      show_stack (((void *) 0));
	      breakpoint ();
	    }
	}
      while (0);
      show_stack (((void *) 0));
    }
  elem->next = head->next;
  head->next->prev = elem;

  elem->prev = (struct list_link *) head;
  head->next = elem;
}

static void
dlist_insert_tail (struct dlist *head, struct list_link *elem)
{
  if (head->prev == elem)
    {
      do
	{
	  if (!(0))
	    {
	      printk ("kgdb assertion failed: %s\n", "BUG");
	      show_stack (((void *) 0));
	      breakpoint ();
	    }
	}
      while (0);
      show_stack (((void *) 0));
    }
  elem->next = (struct list_link *) head;
  elem->prev = head->prev;
  head->prev->next = elem;
  head->prev = elem;
}

static void
dlist_insert_tail_mb (struct dlist *head, struct list_link *elem)
{
  if (head->prev == elem)
    {
      do
	{
	  if (!(0))
	    {
	      printk ("kgdb assertion failed: %s\n", "BUG");
	      show_stack (((void *) 0));
	      breakpoint ();
	    }
	}
      while (0);
      show_stack (((void *) 0));
    }
  elem->next = (struct list_link *) head;
  elem->prev = head->prev;
  __asm__ __volatile__ ("lock; addl $0,0(%%esp)":::"memory");
  head->prev->next = elem;
  head->prev = elem;
}

static void
dlist_unlink (struct list_link *elem)
{
  elem->next->prev = elem->prev;
  elem->prev->next = elem->next;
  elem->prev = elem->next = ((void *) 0);
}

static inline int
dlist_empty (const struct dlist *list)
{
  return (struct dlist *) list->next == list;
}








void show_stack (unsigned long *esp);

enum cminisock_ctl
{
  ALLOC_FREE = 0,
  ALLOC_READY = 1,
  ALLOC_PENDING = 2,
  ALLOC_PROCESSING = 3,
  ALLOC_HALFFREE = 4
};

enum cminisock_event_tag
{
  SYN, ACK, FIN, RST
};

struct alloc_head_list;

struct alloc_head
{

  struct alloc_head *prev;
  struct alloc_head *next;
  struct alloc_head_list *list;


  enum cminisock_ctl ctl;
};

struct alloc_head_list
{
  struct alloc_head *prev;
  struct alloc_head *next;
  struct alloc_head_list *list;
  enum cminisock_ctl ignore;
  int len;
};

struct vector
{
  int num;
  int size;
  void **elems;
};





static inline void
vector_init (struct vector *vec, int initSize)
{
  vec->num = 0;
  vec->size = initSize;
  vec->elems = kmalloc (vec->size * sizeof (vec->elems[0]), (0x20));
  if (vec->elems == ((void *) 0))
    {
      printk ("Not enough memory while initializing vector\n");
    }
  return;
}

static inline void
vector_free (struct vector *vec)
{
  kfree (vec->elems);
  kfree (vec);
}
static inline void
vector_append (struct vector *vec, void *newElem)
{
  if (vec->num == vec->size)
    {
      void **newElems;
      vec->size *= 2;
      newElems = kmalloc (vec->size * sizeof (newElems[0]), (0x20));
      if (newElems == ((void *) 0))
	{
	  printk ("Not enough memory while resizing vector\n");

	  do
	    {
	      if (!(0))
		{
		  printk ("kgdb assertion failed: %s\n", "BUG");
		  show_stack (((void *) 0));
		  breakpoint ();
		}
	    }
	  while (0);
	  return;
	}
    }
  vec->elems[vec->num++] = newElem;
}







static inline int
empty (struct alloc_head_list *head)
{
  return head->next == (struct alloc_head *) head;
}

static inline void
init_head (struct alloc_head_list *head)
{
  head->next = head->prev = (struct alloc_head *) head;
  head->list = head;
  head->len = 0;
}


static inline void
insert_head (struct alloc_head_list *head, struct alloc_head *elem)
{





  if (head->next == elem)
    {
      do
	{
	  if (!(0))
	    {
	      printk ("kgdb assertion failed: %s\n", "BUG");
	      show_stack (((void *) 0));
	      breakpoint ();
	    }
	}
      while (0);
      show_stack (((void *) 0));
    }
  elem->next = head->next;
  head->next->prev = elem;

  elem->prev = (struct alloc_head *) head;
  head->next = elem;

  elem->list = head;
  head->len++;
}

static inline void
insert_tail (struct alloc_head_list *head, struct alloc_head *elem)
{





  if (head->prev == elem)
    {
      do
	{
	  if (!(0))
	    {
	      printk ("kgdb assertion failed: %s\n", "BUG");
	      show_stack (((void *) 0));
	      breakpoint ();
	    }
	}
      while (0);
      show_stack (((void *) 0));
    }

  elem->next = (struct alloc_head *) head;

  elem->prev = head->prev;

  head->prev->next = elem;

  elem->list = head;
  head->prev = elem;
  head->len++;
}

static inline void
insert_tail_mb (struct alloc_head_list *head, struct alloc_head *elem)
{





  if (head->prev == elem)
    {
      do
	{
	  if (!(0))
	    {
	      printk ("kgdb assertion failed: %s\n", "BUG");
	      show_stack (((void *) 0));
	      breakpoint ();
	    }
	}
      while (0);
      show_stack (((void *) 0));
    }

  elem->next = (struct alloc_head *) head;
  elem->prev = head->prev;

  __asm__ __volatile__ ("lock; addl $0,0(%%esp)":::"memory");

  head->prev->next = elem;

  elem->next = (struct alloc_head *) head;

  elem->list = head;
  head->prev = elem;
  head->len++;
}

static inline void
unlink (struct alloc_head *elem)
{






  elem->next->prev = elem->prev;
  elem->prev->next = elem->next;
  elem->prev = elem->next = ((void *) 0);

  elem->list->len--;
  elem->list = ((void *) 0);
}

static inline void
insert (struct alloc_head *elem, struct alloc_head *prev,
	struct alloc_head *next)
{

  if (!(elem->next == ((void *) 0) && elem->prev == ((void *) 0)))
    do
      {
	if (!(0))
	  {
	    printk ("kgdb assertion failed: %s\n", "BUG");
	    show_stack (((void *) 0));
	    breakpoint ();
	  }
      }
    while (0);
  elem->next = prev->next;
  prev->next = elem;

  elem->prev = prev;
  next->prev = elem;

  elem->list = prev->list;
  elem->list->len++;
}


struct cminisock_packet
{
  __u32 nonce;
  __u32 seq;

  __u16 len;







  __u8 type;
  __u8 contType:3;


  __u8 numSiblings;
  __u8 position;


  int ucontLen;
  char *ucontData;

  __u16 minResponseLen;
  __u32 firstTransportChild;
  __u8 numTransportChildren;





};

static inline void
makePacket (struct cminisock_packet *pkt,
	    __u32 seq,
	    __u32 ack_seq,
	    __u32 len,
	    __u8 type,
	    __u8 contType,
	    __u16 minResponseLen,
	    __u32 firstTransportChild, __u8 numTransportChildren)
{
  pkt->nonce = -1;
  pkt->seq = seq;

  pkt->len = len;
  pkt->type = type;
  pkt->contType = contType;
  pkt->minResponseLen = minResponseLen;
  pkt->firstTransportChild = firstTransportChild;
  pkt->numTransportChildren = numTransportChildren;
  pkt->ucontLen = 0;
  pkt->ucontData = ((void *) 0);
  pkt->numSiblings = -1;
  pkt->position = (0xff);
}


static inline void
setPacketUCont (struct cminisock_packet *packet, char *buf, unsigned long len)
{
  if (len > packet->len + packet->ucontLen)
    {
      printk ("Not enough space in packet for ucont %d %d + %d\n",
	      (int) len, packet->len, packet->ucontLen);
      return;
    }
  if (packet->ucontData)
    {
      kfree (packet->ucontData);
      packet->len += packet->ucontLen;
      packet->ucontLen = 0;
    }
  packet->ucontData = buf;
  packet->ucontLen = len;
  packet->len -= packet->ucontLen;
}







struct pminisock;

struct cminisock
{

  struct cminisock *prev;
  struct cminisock *next;
  struct alloc_head_list *list;
  enum cminisock_ctl ctl;


  enum cminisock_event_tag tag;
  __u32 saddr, daddr;
  __u16 source, dest;





  struct sock *sk;

  __u32 flags;
  __u32 rcv_nxt;

  __u32 cum_nonce;


  unsigned seq;
  unsigned continuationType;

  unsigned clientState;
  unsigned parent;
  __u32 rawTimestamp;
  __u32 rawMrtt;


  unsigned timestamp;
  unsigned clientTimestamp;
  unsigned mrtt;
  __u32 state;
  unsigned firstChild;

  __u32 firstLoss;
  __u32 firstBootstrapSeq;
  unsigned startCwnd;
  unsigned ssthresh;
  unsigned TCPBase;
  __u64 tokenCounterBase;

  int ucont_len;
  char *ucont_data;







  __u32 ack_seq;
  int simulationLen;
  int simulationNumPackets;
  __u32 dbg_timestamp;
  __u32 dbg_mark;



  int input_len;
  char *input;
  char mac[40];




  __u32 firstTransportChild;
  int numTransportChildren;

  int numChildrenReceived;
  struct cminisock *parentMSK;


  int seqnum;

  int simulated;
  int executionTrace;
  int actualCwnd;



  int mark;

  char clientside_copy_end[0];
  int num_packets;



  struct cminisock_packet *packets;
  int refCnt;
  int cacheRecycleIndex;
  struct sock *serverSK;



  struct pminisock *pmsk;
  int isStatic;
};

struct pminisock
{



  struct pminisock *prev;
  struct pminisock *next;

  __u16 ctl:3;
  __u16 tag:3;

  __u16 continuationType:4;
  __u16 firstChild:1;
  __u16 refCnt:2;
  __s16 cacheRecycleIndex:3;

  __u8 num_packets;
  __u8 clientState;
  __u8 state;

  __u32 seq;
  __u32 parent;
  __u32 clientTimestamp;


  __u32 rawTimestamp;
  __u32 rawMrtt;

  __u32 firstLoss;
  __u32 firstBootstrapSeq;
  __u32 startCwnd;
  __u32 ssthresh;
  __u32 TCPBase;


  __u32 daddr;
  __u16 dest;

  __u64 tokenCounterBase;

  __u16 ucont_len;
  __u16 input_len;
  char *ucont_data;
  char *input;

  struct cminisock_packet *packets;
};

struct ucontdesc;


struct tiovec;






struct tiovec
{





  void *iov_base;
  int iov_len;

   ;
};

struct mskdesc
{
  struct cminisock *msk;
  int tiov_num;

  int dbg_mark;



  struct tiovec tiov[0];
};


struct fiovec
{
  int fd;
  loff_t offset;
  int len;
};

struct extract_mskdesc_in
{
  struct cminisock *msk;
  int operation;
} __attribute__ ((packed));





struct extract_mskdesc_out
{
  int len;

  struct cminisock msk;
  char data[0];



} __attribute__ ((packed));

struct msk_collection
{
  char hmac[20];

  int len;
  struct extract_mskdesc_out descs[0];
} __attribute__ ((packed));



struct trickles_mmap_ctl;
struct trickles_config
{

  __u32 mmap_len;
  __u32 maxMSKCount;


  struct trickles_mmap_ctl *ctl;

  void *mmap_base;

};



extern int (*cminisock_config_pipe_hook) (struct sock * sk, char *optdata,
					  int optlen, int direction);
int cminisock_config_pipe_default (struct sock *sk, char *optdata, int optlen,
				   int direction);


struct trickles_kconfig
{
  struct trickles_config cfg;
  struct alloc_head_list msk_freelist;
  struct dlist pmsk_freelist;

  rwlock_t event_lock;
  int pending_delivery;
};



enum cminisock_command_tag
{
  POLL,
  PROCESS,
  DROP,
  STARTRCV
};

struct cminisock_cmd
{
  int magic;
  struct cminisock *socket;
  enum cminisock_command_tag cmd;
};









struct ip_options
{
  __u32 faddr;
  unsigned char optlen;
  unsigned char srr;
  unsigned char rr;
  unsigned char ts;
  unsigned char is_setbyuser:1,
    is_data:1,
    is_strictroute:1,
    srr_is_hit:1, is_changed:1, rr_needaddr:1, ts_needtime:1, ts_needaddr:1;
  unsigned char router_alert;
  unsigned char __pad1;
  unsigned char __pad2;
  unsigned char __data[0];
};




struct iphdr
{

  __u8 ihl:4, version:4;






  __u8 tos;
  __u16 tot_len;
  __u16 id;
  __u16 frag_off;
  __u8 ttl;
  __u8 protocol;
  __u16 check;
  __u32 saddr;
  __u32 daddr;

};













struct sockaddr_nl
{
  sa_family_t nl_family;
  unsigned short nl_pad;
  __u32 nl_pid;
  __u32 nl_groups;
};

struct nlmsghdr
{
  __u32 nlmsg_len;
  __u16 nlmsg_type;
  __u16 nlmsg_flags;
  __u32 nlmsg_seq;
  __u32 nlmsg_pid;
};

struct nlmsgerr
{
  int error;
  struct nlmsghdr msg;
};





struct netlink_skb_parms
{
  struct ucred creds;
  __u32 pid;
  __u32 groups;
  __u32 dst_pid;
  __u32 dst_groups;
  kernel_cap_t eff_cap;
};





extern int netlink_attach (int unit,
			   int (*function) (int, struct sk_buff * skb));
extern void netlink_detach (int unit);
extern int netlink_post (int unit, struct sk_buff *skb);
extern int init_netlink (void);
extern struct sock *netlink_kernel_create (int unit,
					   void (*input) (struct sock * sk,
							  int len));
extern void netlink_ack (struct sk_buff *in_skb, struct nlmsghdr *nlh,
			 int err);
extern int netlink_unicast (struct sock *ssk, struct sk_buff *skb, __u32 pid,
			    int nonblock);
extern void netlink_broadcast (struct sock *ssk, struct sk_buff *skb,
			       __u32 pid, __u32 group, int allocation);
extern void netlink_set_err (struct sock *ssk, __u32 pid, __u32 group,
			     int code);
extern int netlink_register_notifier (struct notifier_block *nb);
extern int netlink_unregister_notifier (struct notifier_block *nb);

struct netlink_callback
{
  struct sk_buff *skb;
  struct nlmsghdr *nlh;
  int (*dump) (struct sk_buff * skb, struct netlink_callback * cb);
  int (*done) (struct netlink_callback * cb);
  int family;
  long args[4];
};

struct netlink_notify
{
  int pid;
  int protocol;
};

static __inline__ struct nlmsghdr *
__nlmsg_put (struct sk_buff *skb, u32 pid, u32 seq, int type, int len)
{
  struct nlmsghdr *nlh;
  int size = ((len) + (((sizeof (struct nlmsghdr)) + 4 - 1) & ~(4 - 1)));

  nlh = (struct nlmsghdr *) skb_put (skb, (((size) + 4 - 1) & ~(4 - 1)));
  nlh->nlmsg_type = type;
  nlh->nlmsg_len = size;
  nlh->nlmsg_flags = 0;
  nlh->nlmsg_pid = pid;
  nlh->nlmsg_seq = seq;
  return nlh;
}





extern int netlink_dump_start (struct sock *ssk, struct sk_buff *skb,
			       struct nlmsghdr *nlh,
			       int (*dump) (struct sk_buff * skb,
					    struct netlink_callback *),
			       int (*done) (struct netlink_callback *));



extern void netlink_set_nonroot (int protocol, unsigned flag);


struct rtattr
{
  unsigned short rta_len;
  unsigned short rta_type;
};

struct rtmsg
{
  unsigned char rtm_family;
  unsigned char rtm_dst_len;
  unsigned char rtm_src_len;
  unsigned char rtm_tos;

  unsigned char rtm_table;
  unsigned char rtm_protocol;
  unsigned char rtm_scope;
  unsigned char rtm_type;

  unsigned rtm_flags;
};



enum
{
  RTN_UNSPEC,
  RTN_UNICAST,
  RTN_LOCAL,
  RTN_BROADCAST,

  RTN_ANYCAST,

  RTN_MULTICAST,
  RTN_BLACKHOLE,
  RTN_UNREACHABLE,
  RTN_PROHIBIT,
  RTN_THROW,
  RTN_NAT,
  RTN_XRESOLVE,
};

enum rt_scope_t
{
  RT_SCOPE_UNIVERSE = 0,

  RT_SCOPE_SITE = 200,
  RT_SCOPE_LINK = 253,
  RT_SCOPE_HOST = 254,
  RT_SCOPE_NOWHERE = 255
};

enum rt_class_t
{
  RT_TABLE_UNSPEC = 0,

  RT_TABLE_DEFAULT = 253,
  RT_TABLE_MAIN = 254,
  RT_TABLE_LOCAL = 255
};






enum rtattr_type_t
{
  RTA_UNSPEC,
  RTA_DST,
  RTA_SRC,
  RTA_IIF,
  RTA_OIF,
  RTA_GATEWAY,
  RTA_PRIORITY,
  RTA_PREFSRC,
  RTA_METRICS,
  RTA_MULTIPATH,
  RTA_PROTOINFO,
  RTA_FLOW,
  RTA_CACHEINFO
};

struct rtnexthop
{
  unsigned short rtnh_len;
  unsigned char rtnh_flags;
  unsigned char rtnh_hops;
  int rtnh_ifindex;
};

struct rta_cacheinfo
{
  __u32 rta_clntref;
  __u32 rta_lastuse;
  __s32 rta_expires;
  __u32 rta_error;
  __u32 rta_used;


  __u32 rta_id;
  __u32 rta_ts;
  __u32 rta_tsage;
};



enum
{
  RTAX_UNSPEC,

  RTAX_LOCK,

  RTAX_MTU,

  RTAX_WINDOW,

  RTAX_RTT,

  RTAX_RTTVAR,

  RTAX_SSTHRESH,

  RTAX_CWND,

  RTAX_ADVMSS,

  RTAX_REORDERING,

};

struct ifaddrmsg
{
  unsigned char ifa_family;
  unsigned char ifa_prefixlen;
  unsigned char ifa_flags;
  unsigned char ifa_scope;
  int ifa_index;
};

enum
{
  IFA_UNSPEC,
  IFA_ADDRESS,
  IFA_LOCAL,
  IFA_LABEL,
  IFA_BROADCAST,
  IFA_ANYCAST,
  IFA_CACHEINFO
};

struct ifa_cacheinfo
{
  __s32 ifa_prefered;
  __s32 ifa_valid;
};

struct ndmsg
{
  unsigned char ndm_family;
  unsigned char ndm_pad1;
  unsigned short ndm_pad2;
  int ndm_ifindex;
  __u16 ndm_state;
  __u8 ndm_flags;
  __u8 ndm_type;
};

enum
{
  NDA_UNSPEC,
  NDA_DST,
  NDA_LLADDR,
  NDA_CACHEINFO
};

struct nda_cacheinfo
{
  __u32 ndm_confirmed;
  __u32 ndm_used;
  __u32 ndm_updated;
  __u32 ndm_refcnt;
};





struct rtgenmsg
{
  unsigned char rtgen_family;
};

struct ifinfomsg
{
  unsigned char ifi_family;
  unsigned char __ifi_pad;
  unsigned short ifi_type;
  int ifi_index;
  unsigned ifi_flags;
  unsigned ifi_change;
};

enum
{
  IFLA_UNSPEC,
  IFLA_ADDRESS,
  IFLA_BROADCAST,
  IFLA_IFNAME,
  IFLA_MTU,
  IFLA_LINK,
  IFLA_QDISC,
  IFLA_STATS,
  IFLA_COST,

  IFLA_PRIORITY,

  IFLA_MASTER,

  IFLA_WIRELESS,

  IFLA_PROTINFO,

};

enum
{
  IFLA_INET6_UNSPEC,
  IFLA_INET6_FLAGS,
  IFLA_INET6_CONF,
  IFLA_INET6_STATS,
  IFLA_INET6_MCAST,
};







struct tcmsg
{
  unsigned char tcm_family;
  unsigned char tcm__pad1;
  unsigned short tcm__pad2;
  int tcm_ifindex;
  __u32 tcm_handle;
  __u32 tcm_parent;
  __u32 tcm_info;
};

enum
{
  TCA_UNSPEC,
  TCA_KIND,
  TCA_OPTIONS,
  TCA_STATS,
  TCA_XSTATS,
  TCA_RATE,
};

static __inline__ int
rtattr_strcmp (struct rtattr *rta, char *str)
{
  int len = strlen (str) + 1;
  return len > rta->rta_len
    ||
    __builtin_memcmp (((void *) (((char *) (rta)) +
				 ((((sizeof (struct rtattr)) + 4 - 1) & ~(4 -
									  1))
				  + (0)))), str, len);
}

extern int rtattr_parse (struct rtattr *tb[], int maxattr, struct rtattr *rta,
			 int len);

extern struct sock *rtnl;

struct rtnetlink_link
{
  int (*doit) (struct sk_buff *, struct nlmsghdr *, void *attr);
  int (*dumpit) (struct sk_buff *, struct netlink_callback * cb);
};

extern struct rtnetlink_link *rtnetlink_links[32];
extern int rtnetlink_dump_ifinfo (struct sk_buff *skb,
				  struct netlink_callback *cb);
extern int rtnetlink_send (struct sk_buff *skb, u32 pid, u32 group, int echo);
extern int rtnetlink_put_metrics (struct sk_buff *skb, unsigned *metrics);

extern void __rta_fill (struct sk_buff *skb, int attrtype, int attrlen,
			const void *data);





extern void rtmsg_ifinfo (int type, struct net_device *dev, unsigned change);

extern struct semaphore rtnl_sem;

extern void rtnl_lock (void);
extern void rtnl_unlock (void);
extern void rtnetlink_init (void);





typedef int _bool;

enum ContinuationState
{
  CONT_NORMAL = 0,
  CONT_RECOVERY = 1,
  CONT_BOOTSTRAP = 2
};

struct PseudoHeader
{
  __u32 seq;
  __u8 type;
  __u8 first;
  __u32 serverAddr;
  __u16 serverPort;
  __u32 clientAddr;
  __u16 clientPort;
} __attribute__ ((packed));

typedef struct PseudoHeader PseudoHeader;

struct WireContinuation
{
  __u8 continuationType;
  union
  {
    struct
    {

      __u32 timestamp;
      __u32 mrtt;


      __u16 parentSeq;
      __u8 clientState;



      __u16 position;

      __u8 mac[16];
      __u8 end[0];
    } hash;
    struct
    {

      __u32 seq;

      __u8 firstChild;


      __u32 clientState;
      __u32 parent;
      __u32 clientTimestamp;

      __u8 minimalContinuationEnd[0];

      __u8 mac[16];
      __u8 hmac_start[0];
    };
    struct
    {




      __u32 seq;

      __u8 firstChild;


      __u32 clientState;
      __u32 parent;
      __u32 clientTimestamp;

      __u8 minimalContinuationEnd[0];

      __u8 mac[16];
      __u8 hmac_start[0];
    } named;
  };

  __u32 timestamp;
  __u32 mrtt;
  __u8 state;
  __u32 firstLoss;
  __u32 firstBootstrapSeq;
  __u32 startCwnd;
  __u32 ssthresh;
  __u32 TCPBase;
  __u64 tokenCounterBase;
} __attribute__ ((packed));
typedef struct WireContinuation WireContinuation;


struct CachedWireContinuation
{
  PseudoHeader hdr;
  __u8 copy_start[0];
  __u32 timestamp;
  __u32 mrtt;
  __u8 state;
  __u32 firstLoss;
  __u32 firstBootstrapSeq;
  __u32 startCwnd;
  __u32 ssthresh;
  __u32 TCPBase;
  __u64 tokenCounterBase;
} __attribute__ ((packed));




struct WireSack
{
  __u32 left, right;
  __u32 nonceSummary;
} __attribute__ ((packed));

typedef struct WireSack WireSack;

struct WireAckProof
{



  __u8 numSacks;
  WireSack sacks[0];
} __attribute__ ((packed));

typedef struct WireAckProof WireAckProof;

enum TrickleRequestType
{

  TREQ_NORMAL = 0,
  TREQ_SLOWSTART = 1
};

struct WireTrickleRequest
{
  __u8 type;
  WireContinuation cont;


  __u16 ucont_len;
  WireAckProof ackProof;





} __attribute__ ((packed));




typedef struct WireTrickleRequest WireTrickleRequest;

enum ResponseChunkTypes
{
  RCHUNK_PUSH_HINT = 1,
  RCHUNK_DATA = 2,
  RCHUNK_SKIP = 3,
  RCHUNK_FINHINT = 4
};



struct ResponseChunk
{
  __u8 type:4;
  __u8 flags:4;
  __u16 chunkLen;;
  __u8 chunkData[0];
} __attribute__ ((packed));

static inline int
ResponseChunk_isPadding (struct ResponseChunk *c)
{
  return c->type == 0 && c->flags == 0;
}







struct PushHintChunk
{
  __u8 type:4;
  __u8 flags:4;
  __u16 chunkLen;;

  __u32 chunkID;

  __u32 start, end;
} __attribute__ ((packed));

static inline void
pushhint_dump (struct PushHintChunk *phchunk)
{
  printk ("PHChunk %p = { type = %d, chunkLen = %d, range=[%d-%d] }\n",
	  phchunk, phchunk->type, ntohs (phchunk->chunkLen),
	  ntohl (phchunk->start), ntohl (phchunk->end));
}

struct DataChunk
{
  __u8 type:4;
  __u8 flags:4;
  __u16 chunkLen;

  __u32 chunkID;

  __u32 byteNum;
  __u8 data[0];
} __attribute__ ((packed));


struct SkipChunk
{
  __u8 type:4;
  __u8 flags:4;
  __u16 chunkLen;

  __u32 chunkID;

  __u32 byteNum;
  __u32 len;
} __attribute__ ((packed));

struct FINHintChunk
{
  __u8 type:4;
  __u8 flags:4;
  __u16 chunkLen;

  __u32 chunkID;

  __u32 byteNum;
  __u32 len;
} __attribute__ ((packed));






static inline int
isDataSubchunk (struct ResponseChunk *d)
{
  return (d->type == RCHUNK_DATA ||
	  d->type == RCHUNK_SKIP || d->type == RCHUNK_FINHINT);
}

static inline int
DataSubchunk_validate (struct ResponseChunk *d)
{
  int c0 = 1, c1 = 1, c2 = 1, c3 = 1;
  if (!((c0 = isDataSubchunk (d))))
    {
      printk ("KERNEL: assertion (" "(c0 = isDataSubchunk(d))" ") failed at "
	      "/home/ashieh/current/include/net/trickles_packet.h" "(%d)\n",
	      291);
    };
  switch (d->type)
    {
    case RCHUNK_DATA:
      if (!((c1 = !(d->flags & ~0x1))))
	{
	  printk ("KERNEL: assertion (" "(c1 = !(d->flags & ~DCHUNK_FIN))"
		  ") failed at "
		  "/home/ashieh/current/include/net/trickles_packet.h"
		  "(%d)\n", 294);
	};
      break;
    case RCHUNK_SKIP:
    case RCHUNK_FINHINT:
      if (!((c1 = (d->flags == 0))))
	{
	  printk ("KERNEL: assertion (" "(c1 = (d->flags == 0))"
		  ") failed at "
		  "/home/ashieh/current/include/net/trickles_packet.h"
		  "(%d)\n", 298);
	};
      break;
    }
  return c0 && c1 && c2 && c3;
}





struct WireTrickleResponse
{
  __u32 nonce;
  __u8 numSiblings;
  __u8 position;

  __u16 ucont_len;
  WireContinuation cont;






} __attribute__ ((packed));

typedef struct WireTrickleResponse WireTrickleResponse;

typedef struct
{
  __u32 left, right;
  __u32 nonceSummary;
} Sack;



typedef struct
{
  int numSacks;
  struct cminisock *cont;
  Sack sacks[(64)];
} AckProof;

enum UC_Type
{
  UC_INCOMPLETE,
  UC_COMPLETE,
  UC_UPDATE,
  UC_DATA,
  UC_NEWCONT
};







struct WireUC_RespHeader
{
  __u8 type;
  __u8 error;
  __u16 len;
  __u8 standardEnd[0];
} __attribute__ ((packed));






struct WireUC_ReqHeader
{
  __u8 type;
  __u16 len;
  __u8 standardEnd[0];
} __attribute__ ((packed));

struct WireUC_CVT_IncompleteContinuation
{

  __u32 validStart;
  char data[0];
} __attribute__ ((packed));

struct WireUC_CVT_IncompleteResponse
{
  __u8 type;
  __u8 error;
  __u16 len;
  __u8 standardEnd[0];
  __u32 ack_seq;

  struct WireUC_CVT_IncompleteContinuation newCont;
} __attribute__ ((packed));

struct WireUC_CVT_IncompleteRequest
{
  __u8 type;
  __u16 len;
  __u8 standardEnd[0];
  __u32 seq;


  struct WireUC_CVT_IncompleteContinuation predCont;
} __attribute__ ((packed));

struct WireUC_Continuation
{
  __u32 seq;
  __u32 validStart, validEnd;






  __u8 fields;


  char data[0];
} __attribute__ ((packed));

struct SkipCell
{
  struct alloc_head *prev;
  struct alloc_head *next;
  struct alloc_head_list *list;

  unsigned start, end;
};

struct UC_Continuation
{
  struct alloc_head *prev;
  struct alloc_head *next;
  struct alloc_head_list *list;

  unsigned seq;
  unsigned validStart, validEnd;

  u8 FIN_received:1;
  u8 FINHint:1;
  unsigned FINHintPosition;







  unsigned clientValidStart, clientValidEnd;




  __u8 fields;




  atomic_t refcnt;

  unsigned dataLen;
  union
  {
    struct
    {
      unsigned obsoleteAt;
      char data[0];
    } kernel;
    struct
    {
      char data[0];
    } client;
  };
};

struct WireUC_DepRange
{
  __u32 start, end;
};
struct WireUC_Dependency
{
  struct WireUC_DepRange succ, pred;
};


struct UC_DependencyNode
{

  struct alloc_head *prev;
  struct alloc_head *next;
  struct alloc_head_list *list;

  unsigned start, end;

  _bool resolved;
  struct UC_Continuation *cont;
  _bool requested;

  int refCnt;
  struct vector depLinks;
};

struct UC_DependencyLink
{
  unsigned destStart, destEnd;
  struct UC_DependencyNode *dest;
};


struct WireUC_MGMT_Dependency
{

  __u8 numDeps;
  struct WireUC_Dependency deps[0];
} __attribute__ ((packed));

struct WireUC_MGMT_UpdateResponse
{
  __u8 type;
  __u8 error;
  __u16 len;
  __u8 standardEnd[0];

  struct WireUC_Continuation newCont;
} __attribute__ ((packed));

struct WireUC_MGMT_UpdateRequest
{
  __u8 type;
  __u16 len;
  __u8 standardEnd[0];

  __u32 newStart, newEnd;
  __u8 numContinuations;




} __attribute__ ((packed));

struct WireUC_CVT_CompleteRequest
{
  __u8 type;
  __u16 len;
  __u8 standardEnd[0];
  __u32 seq;
  __u8 isParallel:1;

  struct WireUC_Continuation predCont;
} __attribute__ ((packed));

struct WireUC_CVT_CompleteResponse
{
  __u8 type;
  __u8 error;
  __u16 len;
  __u8 standardEnd[0];
  __u32 ack_seq;

  __u16 piggyLength;





  struct WireUC_Continuation newCont;
} __attribute__ ((packed));



struct WireUC_DataRequestRange
{
  __u32 start;
  __u32 end;
} __attribute__ ((packed));

struct WireUC_DataRequest
{
  __u8 type;
  __u16 len;
  __u8 standardEnd[0];
  __u8 numRequestRanges;
  struct WireUC_DataRequestRange ranges[0];

} __attribute__ ((packed));



struct WireUC_NewContinuationResponse
{
  __u8 type;
  __u8 error;
  __u16 len;
  __u8 standardEnd[0];

  struct WireUC_Continuation newCont;
};


struct HMAC_CTX;
struct aes_encrypt_ctx;
struct Request;



union heap_info
{
  struct
  {
    int type;


    union
    {
      struct
      {
	int nfree;
	int first;
      } frag;
      int size;
    } info;
  } busy;
  struct
  {
    int size;
    int next;
    int prev;
  } free;
};





struct heap_list
{
  struct heap_list *next;
  struct heap_list *prev;
};


struct trickles_server
{
  __u32 lastProbeTime;
  __u32 address;


  int A;
  int D;
};

static void
trickles_server_init (struct trickles_server *server)
{
  server->lastProbeTime = 0;
  server->address = 0;
  server->A = 0;
  server->D = 0;
}


struct tcp_opt
{
  int tcp_header_len;





  __u32 pred_flags;






  __u32 rcv_nxt;
  __u32 snd_nxt;

  __u32 snd_una;
  __u32 snd_sml;
  __u32 rcv_tstamp;
  __u32 lsndtime;


  struct
  {
    __u8 pending;
    __u8 quick;
    __u8 pingpong;
    __u8 blocked;
    __u32 ato;
    unsigned long timeout;
    __u32 lrcvtime;
    __u16 last_seg_size;
    __u16 rcv_mss;
  } ack;


  struct
  {
    struct sk_buff_head prequeue;
    struct task_struct *task;
    struct iovec *iov;
    int memory;
    int len;
  } ucopy;

  __u32 snd_wl1;
  __u32 snd_wnd;
  __u32 max_window;
  __u32 pmtu_cookie;
  __u16 mss_cache;
  __u16 mss_clamp;
  __u16 ext_header_len;
  __u8 ca_state;
  __u8 retransmits;

  __u8 reordering;
  __u8 queue_shrunk;
  __u8 defer_accept;


  __u8 backoff;
  __u32 srtt;
  __u32 mdev;
  __u32 mdev_max;
  __u32 rttvar;
  __u32 rtt_seq;
  __u32 rto;

  __u32 packets_out;
  __u32 left_out;
  __u32 retrans_out;





  __u32 snd_ssthresh;
  __u32 snd_cwnd;
  __u16 snd_cwnd_cnt;
  __u16 snd_cwnd_clamp;
  __u32 snd_cwnd_used;
  __u32 snd_cwnd_stamp;


  unsigned long timeout;
  struct timer_list retransmit_timer;
  struct timer_list delack_timer;

  struct sk_buff_head out_of_order_queue;

  struct tcp_func *af_specific;
  struct sk_buff *send_head;
  struct page *sndmsg_page;
  u32 sndmsg_off;

  __u32 rcv_wnd;
  __u32 rcv_wup;
  __u32 write_seq;
  __u32 pushed_seq;
  __u32 copied_seq;



  char tstamp_ok, wscale_ok, sack_ok;
  char saw_tstamp;
  __u8 snd_wscale;
  __u8 rcv_wscale;
  __u8 nonagle;
  __u8 keepalive_probes;


  __u32 rcv_tsval;
  __u32 rcv_tsecr;
  __u32 ts_recent;
  long ts_recent_stamp;


  __u16 user_mss;
  __u8 dsack;
  __u8 eff_sacks;
  struct tcp_sack_block duplicate_sack[1];
  struct tcp_sack_block selective_acks[4];

  __u32 window_clamp;
  __u32 rcv_ssthresh;
  __u8 probes_out;
  __u8 num_sacks;
  __u16 advmss;

  __u8 syn_retries;
  __u8 ecn_flags;
  __u16 prior_ssthresh;
  __u32 lost_out;
  __u32 sacked_out;
  __u32 fackets_out;
  __u32 high_seq;

  __u32 retrans_stamp;


  __u32 undo_marker;
  int undo_retrans;
  __u32 urg_seq;
  __u16 urg_data;
  __u8 pending;
  __u8 urg_mode;
  __u32 snd_up;

  rwlock_t syn_wait_lock;
  struct tcp_listen_opt *listen_opt;


  struct open_request *accept_queue;
  struct open_request *accept_queue_tail;

  int write_pending;

  unsigned int keepalive_time;
  unsigned int keepalive_intvl;
  int linger2;

  int frto_counter;
  __u32 frto_highmark;

  unsigned long last_synq_overflow;


  struct
  {
    __u32 bw_ns_est;
    __u32 bw_est;
    __u32 rtt_win_sx;
    __u32 bk;
    __u32 snd_una;
    __u32 cumul_ack;
    __u32 accounted;
    __u32 rtt;
    __u32 rtt_min;
  } westwood;



  struct trickles_kconfig cminisock_api_config;


  int trickles_opt;
  __u64 bigTokenCounter;


  int trickles_req_start, trickles_req_len;
  int trickles_state;

  char last_mac_src[6];
  int mac_changed;

  int drop_rate;
  int instrumentation;

  char simulationSpace[256];




  struct
  {

    int malloc_initialized;


    int heapbytesize;
    int heapbytesallocated;





    int heapsize;


    char *heapbase;


    union heap_info *heapinfo;


    int heapindex;


    int heaplimit;


    int fragblocks[(((8) * sizeof (int)) > 16 ? 12 : 9)];


    struct heap_list fraghead[(((8) * sizeof (int)) > 16 ? 12 : 9)];



    unsigned clientStateCounter;

    int state;


    int A;
    int D;
    int RTO;

    int timerState;

    int rcv_nxt;
    int previous_base;
    struct sk_buff_head ofo_queue;




    struct cminisock *ack_prev;

    int ack_last;


    int oo_count;
    int in_flight;

    AckProof standardProof;
    AckProof altProof;
    __u8 space[16];

    struct sock *dprev, *dnext;
    struct sk_buff *dbg_skb;
    int testseq;


    struct alloc_head_list cont_list;

    struct timer_list slowstart_timer;

    unsigned request_rcv_nxt;
    unsigned request_snd_nxt;
    struct alloc_head_list request_ofo_queue;
    struct sk_buff_head data_ofo_queue;

    struct alloc_head_list sentRequests;
    struct alloc_head_list queuedRequests;

    struct alloc_head_list dataRequestMap;
    struct alloc_head_list missingDataMap;



    unsigned byteReqNext;
    unsigned byteRcvNxt;
    int byteSkipHintAmount;
    struct sk_buff *byteReqHint;





    int conversionState;
    __u32 snd_una;
    __u32 snd_end;
    __u32 write_seq;
    struct sk_buff_head requestBytes;
    struct ConversionRequest *newIncompleteRequest;
    struct UC_Continuation *prevConvCont;


    struct alloc_head_list ucontList;
    struct alloc_head_list depNodeList;

    struct alloc_head_list skipList;




    struct HMAC_CTX *hmacCTX;
    char hmacKey[16];
    struct aes_encrypt_ctx *nonceCTX;
    struct sk_buff_head prequeueOverflow;
    struct sk_buff_head sendAckOverflow;

    struct sk_buff_head recycleList;


    struct cminisock *responseMSK;
    struct alloc_head_list responseList;
    int responseCount;

    struct cminisock api_msk;

    struct TricklesLossEvent *events;
    int eventsPos;
    int eventsSize;





    struct trickles_server servers[(8)];
    int numServers;


    int probeRate;





    int requestNext;
  } t;

};

typedef struct
{
  spinlock_t slock;
  unsigned int users;
  wait_queue_head_t wq;
} socket_lock_t;







struct sock
{

  __u32 daddr;
  __u32 rcv_saddr;
  __u16 dport;
  unsigned short num;
  int bound_dev_if;


  struct sock *next;
  struct sock **pprev;
  struct sock *bind_next;
  struct sock **bind_pprev;

  volatile unsigned char state, zapped;
  __u16 sport;

  unsigned short family;
  unsigned char reuse;
  unsigned char shutdown;
  atomic_t refcnt;

  socket_lock_t lock;
  int rcvbuf;

  wait_queue_head_t *sleep;
  struct dst_entry *dst_cache;
  rwlock_t dst_lock;
  atomic_t rmem_alloc;
  struct sk_buff_head receive_queue;
  atomic_t wmem_alloc;
  struct sk_buff_head write_queue;
  atomic_t omem_alloc;
  int wmem_queued;
  int forward_alloc;
  __u32 saddr;
  unsigned int allocation;
  int sndbuf;
  struct sock *prev;




  volatile char dead,
    done, urginline, keepopen, linger, destroy, no_check, broadcast, bsdism;
  unsigned char debug;
  unsigned char rcvtstamp;
  unsigned char use_write_queue;
  unsigned char userlocks;

  int route_caps;
  int proc;
  unsigned long lingertime;

  int hashent;
  struct sock *pair;





  struct
  {
    struct sk_buff *head;
    struct sk_buff *tail;
  } backlog;

  rwlock_t callback_lock;


  struct sk_buff_head error_queue;

  struct proto *prot;







  union
  {
    struct tcp_opt af_tcp;




    struct raw_opt tp_raw4;

  } tp_pinfo;

  int err, err_soft;



  unsigned short ack_backlog;
  unsigned short max_ack_backlog;
  __u32 priority;
  unsigned short type;
  unsigned char localroute;
  unsigned char protocol;
  struct ucred peercred;
  int rcvlowat;
  long rcvtimeo;
  long sndtimeo;



  struct sk_filter *filter;

  union
  {
    void *destruct_hook;
    struct unix_opt af_unix;

    struct inet_opt af_inet;





    struct ipx_opt af_ipx;





    struct packet_opt *af_packet;

    struct netlink_opt *af_netlink;

  } protinfo;



  struct timer_list timer;
  struct timeval stamp;


  struct socket *socket;


  void *user_data;


  void (*state_change) (struct sock * sk);
  void (*data_ready) (struct sock * sk, int bytes);
  void (*write_space) (struct sock * sk);
  void (*error_report) (struct sock * sk);

  int (*backlog_rcv) (struct sock * sk, struct sk_buff * skb);
  void (*destruct) (struct sock * sk);
};

struct proto
{
  void (*close) (struct sock * sk, long timeout);
  int (*connect) (struct sock * sk, struct sockaddr * uaddr, int addr_len);
  int (*disconnect) (struct sock * sk, int flags);

  struct sock *(*accept) (struct sock * sk, int flags, int *err);

  int (*ioctl) (struct sock * sk, int cmd, unsigned long arg);
  int (*init) (struct sock * sk);
  int (*destroy) (struct sock * sk);
  void (*shutdown) (struct sock * sk, int how);
  int (*setsockopt) (struct sock * sk, int level,
		     int optname, char *optval, int optlen);
  int (*getsockopt) (struct sock * sk, int level,
		     int optname, char *optval, int *option);
  int (*sendmsg) (struct sock * sk, struct msghdr * msg, int len);
  int (*recvmsg) (struct sock * sk, struct msghdr * msg,
		  int len, int noblock, int flags, int *addr_len);
  int (*bind) (struct sock * sk, struct sockaddr * uaddr, int addr_len);

  int (*backlog_rcv) (struct sock * sk, struct sk_buff * skb);


  void (*hash) (struct sock * sk);
  void (*unhash) (struct sock * sk);
  int (*get_port) (struct sock * sk, unsigned short snum);

  char name[32];

  struct
  {
    int inuse;
    u8 __pad[(1 << ((5))) - sizeof (int)];
  } stats[1];
};


static __inline__ void
sock_prot_inc_use (struct proto *prot)
{
  prot->stats[0].inuse++;
}

static __inline__ void
sock_prot_dec_use (struct proto *prot)
{
  prot->stats[0].inuse--;
}


extern void __lock_sock (struct sock *sk);
extern void __release_sock (struct sock *sk);

extern struct sock *sk_alloc (int family, int priority, int zero_it);
extern void sk_free (struct sock *sk);

extern struct sk_buff *sock_wmalloc (struct sock *sk,
				     unsigned long size, int force,
				     int priority);
extern struct sk_buff *sock_rmalloc (struct sock *sk,
				     unsigned long size, int force,
				     int priority);
extern void sock_wfree (struct sk_buff *skb);
extern void sock_rfree (struct sk_buff *skb);

extern int sock_setsockopt (struct socket *sock, int level,
			    int op, char *optval, int optlen);

extern int sock_getsockopt (struct socket *sock, int level,
			    int op, char *optval, int *optlen);
extern struct sk_buff *sock_alloc_send_skb (struct sock *sk,
					    unsigned long size,
					    int noblock, int *errcode);
extern struct sk_buff *sock_alloc_send_pskb (struct sock *sk,
					     unsigned long header_len,
					     unsigned long data_len,
					     int noblock, int *errcode);
extern void *sock_kmalloc (struct sock *sk, int size, int priority);
extern void sock_kfree_s (struct sock *sk, void *mem, int size);





extern int sock_no_release (struct socket *);
extern int sock_no_bind (struct socket *, struct sockaddr *, int);
extern int sock_no_connect (struct socket *, struct sockaddr *, int, int);
extern int sock_no_socketpair (struct socket *, struct socket *);
extern int sock_no_accept (struct socket *, struct socket *, int);
extern int sock_no_getname (struct socket *, struct sockaddr *, int *, int);
extern unsigned int sock_no_poll (struct file *, struct socket *,
				  struct poll_table_struct *);
extern int sock_no_ioctl (struct socket *, unsigned int, unsigned long);
extern int sock_no_listen (struct socket *, int);
extern int sock_no_shutdown (struct socket *, int);
extern int sock_no_getsockopt (struct socket *, int, int, char *, int *);
extern int sock_no_setsockopt (struct socket *, int, int, char *, int);
extern int sock_no_fcntl (struct socket *, unsigned int, unsigned long);
extern int sock_no_sendmsg (struct socket *,
			    struct msghdr *, int, struct scm_cookie *);
extern int sock_no_recvmsg (struct socket *,
			    struct msghdr *, int, int, struct scm_cookie *);
extern int sock_no_mmap (struct file *file,
			 struct socket *sock, struct vm_area_struct *vma);
extern ssize_t sock_no_sendpage (struct socket *sock,
				 struct page *page,
				 int offset, size_t size, int flags);





extern void sock_def_destruct (struct sock *);


extern void sock_init_data (struct socket *sock, struct sock *sk);

extern void sklist_remove_socket (struct sock **list, struct sock *sk);
extern void sklist_insert_socket (struct sock **list, struct sock *sk);
extern void sklist_destroy_socket (struct sock **list, struct sock *sk);

static inline int
sk_filter (struct sock *sk, struct sk_buff *skb, int needlock)
{
  int err = 0;

  if (sk->filter)
    {
      struct sk_filter *filter;

      if (needlock)
	(void) (&((sk)->lock.slock));

      filter = sk->filter;
      if (filter)
	{
	  int pkt_len = sk_run_filter (skb, filter->insns,
				       filter->len);
	  if (!pkt_len)
	    err = -1;
	  else
	    skb_trim (skb, pkt_len);
	}

      if (needlock)
	do
	  {
	  }
	while (0);
    }
  return err;
}


static inline void
sk_filter_release (struct sock *sk, struct sk_filter *fp)
{
  unsigned int size = sk_filter_len (fp);

  atomic_sub (size, &sk->omem_alloc);

  if (atomic_dec_and_test (&fp->refcnt))
    kfree (fp);
}

static inline void
sk_filter_charge (struct sock *sk, struct sk_filter *fp)
{
  atomic_inc (&fp->refcnt);
  atomic_add (sk_filter_len (fp), &sk->omem_alloc);
}


static inline void
sock_hold (struct sock *sk)
{
  atomic_inc (&sk->refcnt);
}




static inline void
__sock_put (struct sock *sk)
{
  atomic_dec (&sk->refcnt);
}


static inline void
sock_put (struct sock *sk)
{
  if (atomic_dec_and_test (&sk->refcnt))
    sk_free (sk);
}


static inline void
sock_orphan (struct sock *sk)
{
  do
    {
      do
	{
	  ((void) ((0)), irq_stat[0].__local_bh_count)++;
	  __asm__ __volatile__ ("":::"memory");
	}
      while (0);
      (void) (&sk->callback_lock);
    }
  while (0);
  sk->dead = 1;
  sk->socket = ((void *) 0);
  sk->sleep = ((void *) 0);
  do
    {
      do
	{
	}
      while (0);
      do
	{
	  unsigned int *ptr = &((void) ((0)), irq_stat[0].__local_bh_count);
	  __asm__ __volatile__ ("":::"memory");
	  if (!--*ptr)
	    __asm__ __volatile__ ("cmpl $0, -8(%0);" "jnz 2f;" "1:;"
				  ".subsection 1\n\t" "" ".ifndef "
				  ".text.lock." "tmalloc" "\n\t" ".text.lock."
				  "tmalloc" ":\n\t" ".endif\n\t"
				  "2: pushl %%eax; pushl %%ecx; pushl %%edx;"
				  "call %c1;"
				  "popl %%edx; popl %%ecx; popl %%eax;"
				  "jmp 1b;" ".previous\n\t"::"r" (ptr),
				  "i" (do_softirq));
	}
      while (0);
    }
  while (0);
}

static inline void
sock_graft (struct sock *sk, struct socket *parent)
{
  do
    {
      do
	{
	  ((void) ((0)), irq_stat[0].__local_bh_count)++;
	  __asm__ __volatile__ ("":::"memory");
	}
      while (0);
      (void) (&sk->callback_lock);
    }
  while (0);
  sk->sleep = &parent->wait;
  parent->sk = sk;
  sk->socket = parent;
  do
    {
      do
	{
	}
      while (0);
      do
	{
	  unsigned int *ptr = &((void) ((0)), irq_stat[0].__local_bh_count);
	  __asm__ __volatile__ ("":::"memory");
	  if (!--*ptr)
	    __asm__ __volatile__ ("cmpl $0, -8(%0);" "jnz 2f;" "1:;"
				  ".subsection 1\n\t" "" ".ifndef "
				  ".text.lock." "tmalloc" "\n\t" ".text.lock."
				  "tmalloc" ":\n\t" ".endif\n\t"
				  "2: pushl %%eax; pushl %%ecx; pushl %%edx;"
				  "call %c1;"
				  "popl %%edx; popl %%ecx; popl %%eax;"
				  "jmp 1b;" ".previous\n\t"::"r" (ptr),
				  "i" (do_softirq));
	}
      while (0);
    }
  while (0);
}

static inline int
sock_i_uid (struct sock *sk)
{
  int uid;

  (void) (&sk->callback_lock);
  uid = sk->socket ? sk->socket->inode->i_uid : 0;
  do
    {
    }
  while (0);
  return uid;
}

static inline unsigned long
sock_i_ino (struct sock *sk)
{
  unsigned long ino;

  (void) (&sk->callback_lock);
  ino = sk->socket ? sk->socket->inode->i_ino : 0;
  do
    {
    }
  while (0);
  return ino;
}

static inline struct dst_entry *
__sk_dst_get (struct sock *sk)
{
  return sk->dst_cache;
}

static inline struct dst_entry *
sk_dst_get (struct sock *sk)
{
  struct dst_entry *dst;

  (void) (&sk->dst_lock);
  dst = sk->dst_cache;
  if (dst)
    dst_hold (dst);
  do
    {
    }
  while (0);
  return dst;
}

static inline void
__sk_dst_set (struct sock *sk, struct dst_entry *dst)
{
  struct dst_entry *old_dst;

  old_dst = sk->dst_cache;
  sk->dst_cache = dst;
  dst_release (old_dst);
}

static inline void
sk_dst_set (struct sock *sk, struct dst_entry *dst)
{
  (void) (&sk->dst_lock);
  __sk_dst_set (sk, dst);
  do
    {
    }
  while (0);
}

static inline void
__sk_dst_reset (struct sock *sk)
{
  struct dst_entry *old_dst;

  old_dst = sk->dst_cache;
  sk->dst_cache = ((void *) 0);
  dst_release (old_dst);
}

static inline void
sk_dst_reset (struct sock *sk)
{
  (void) (&sk->dst_lock);
  __sk_dst_reset (sk);
  do
    {
    }
  while (0);
}

static inline struct dst_entry *
__sk_dst_check (struct sock *sk, u32 cookie)
{
  struct dst_entry *dst = sk->dst_cache;

  if (dst && dst->obsolete && dst->ops->check (dst, cookie) == ((void *) 0))
    {
      sk->dst_cache = ((void *) 0);
      return ((void *) 0);
    }

  return dst;
}

static inline struct dst_entry *
sk_dst_check (struct sock *sk, u32 cookie)
{
  struct dst_entry *dst = sk_dst_get (sk);

  if (dst && dst->obsolete && dst->ops->check (dst, cookie) == ((void *) 0))
    {
      sk_dst_reset (sk);
      return ((void *) 0);
    }

  return dst;
}


static inline void
skb_set_owner_w (struct sk_buff *skb, struct sock *sk)
{
  sock_hold (sk);
  skb->sk = sk;
  skb->destructor = sock_wfree;
  atomic_add (skb->truesize, &sk->wmem_alloc);
}

static inline void
skb_set_owner_r (struct sk_buff *skb, struct sock *sk)
{
  skb->sk = sk;
  skb->destructor = sock_rfree;
  atomic_add (skb->truesize, &sk->rmem_alloc);
}

static inline int
sock_queue_rcv_skb (struct sock *sk, struct sk_buff *skb)
{
  int err = 0;
  int skb_len;




  if (((&sk->rmem_alloc)->counter) + skb->truesize >= (unsigned) sk->rcvbuf)
    {
      err = -12;
      goto out;
    }





  err = sk_filter (sk, skb, 1);
  if (err)
    goto out;

  skb->dev = ((void *) 0);
  skb_set_owner_r (skb, sk);






  skb_len = skb->len;

  skb_queue_tail (&sk->receive_queue, skb);
  if (!sk->dead)
    sk->data_ready (sk, skb_len);
out:
  return err;
}

static inline int
sock_queue_err_skb (struct sock *sk, struct sk_buff *skb)
{



  if (((&sk->rmem_alloc)->counter) + skb->truesize >= (unsigned) sk->rcvbuf)
    return -12;
  skb_set_owner_r (skb, sk);
  skb_queue_tail (&sk->error_queue, skb);
  if (!sk->dead)
    sk->data_ready (sk, skb->len);
  return 0;
}





static inline int
sock_error (struct sock *sk)
{
  int err =
    ((__typeof__ (*(&sk->err)))
     __xchg ((unsigned long) (0), (&sk->err), sizeof (*(&sk->err))));
  return -err;
}

static inline unsigned long
sock_wspace (struct sock *sk)
{
  int amt = 0;

  if (!(sk->shutdown & 2))
    {
      amt = sk->sndbuf - ((&sk->wmem_alloc)->counter);
      if (amt < 0)
	amt = 0;
    }
  return amt;
}

static inline void
sk_wake_async (struct sock *sk, int how, int band)
{
  if (sk->socket && sk->socket->fasync_list)
    sock_wake_async (sk->socket, how, band);
}







static inline int
sock_writeable (struct sock *sk)
{
  return ((&sk->wmem_alloc)->counter) < (sk->sndbuf / 2);
}

static inline int
gfp_any (void)
{
  return (((void) ((0)),
	   irq_stat[0].__local_bh_count) !=
	  0) ? (0x20) : (0x20 | 0x10 | 0x40 | 0x80 | 0x100);
}

static inline long
sock_rcvtimeo (struct sock *sk, int noblock)
{
  return noblock ? 0 : sk->rcvtimeo;
}

static inline long
sock_sndtimeo (struct sock *sk, int noblock)
{
  return noblock ? 0 : sk->sndtimeo;
}

static inline int
sock_rcvlowat (struct sock *sk, int waitall, int len)
{
  return (waitall ? len : (
			    {
			    int __x = (sk->rcvlowat);
			    int __y = (len);
			    __x < __y ? __x : __y;
			    })) ? : 1;
}




static inline int
sock_intr_errno (long timeo)
{
  return timeo == ((long) (~0UL >> 1)) ? -512 : -4;
}

static __inline__ void
sock_recv_timestamp (struct msghdr *msg, struct sock *sk, struct sk_buff *skb)
{
  if (sk->rcvtstamp)
    put_cmsg (msg, 1, 29, sizeof (skb->stamp), &skb->stamp);
  else
    sk->stamp = skb->stamp;
}


extern __u32 sysctl_wmem_max;
extern __u32 sysctl_rmem_max;













struct ipv4_devconf
{
  int accept_redirects;
  int send_redirects;
  int secure_redirects;
  int shared_media;
  int accept_source_route;
  int rp_filter;
  int proxy_arp;
  int bootp_relay;
  int log_martians;
  int forwarding;
  int mc_forwarding;
  int tag;
  int arp_filter;
  int arp_announce;
  int arp_ignore;
  int medium_id;
  int force_igmp_version;
  void *sysctl;
};

extern struct ipv4_devconf ipv4_devconf;

struct in_device
{
  struct net_device *dev;
  atomic_t refcnt;
  rwlock_t lock;
  int dead;
  struct in_ifaddr *ifa_list;
  struct ip_mc_list *mc_list;
  rwlock_t mc_lock;
  struct ip_mc_list *mc_tomb;
  unsigned long mr_v1_seen;
  unsigned long mr_v2_seen;
  unsigned long mr_maxdelay;
  unsigned char mr_qrv;
  unsigned char mr_gq_running;
  unsigned char mr_ifc_count;
  struct timer_list mr_gq_timer;
  struct timer_list mr_ifc_timer;

  struct neigh_parms *arp_parms;
  struct ipv4_devconf cnf;
};

struct in_ifaddr
{
  struct in_ifaddr *ifa_next;
  struct in_device *ifa_dev;
  u32 ifa_local;
  u32 ifa_address;
  u32 ifa_mask;
  u32 ifa_broadcast;
  u32 ifa_anycast;
  unsigned char ifa_scope;
  unsigned char ifa_flags;
  unsigned char ifa_prefixlen;
  char ifa_label[16];
};

extern int register_inetaddr_notifier (struct notifier_block *nb);
extern int unregister_inetaddr_notifier (struct notifier_block *nb);

extern struct net_device *ip_dev_find (u32 addr);
extern int inet_addr_onlink (struct in_device *in_dev, u32 a, u32 b);
extern int devinet_ioctl (unsigned int cmd, void *);
extern void devinet_init (void);
extern struct in_device *inetdev_init (struct net_device *dev);
extern struct in_device *inetdev_by_index (int);
extern u32 inet_select_addr (const struct net_device *dev, u32 dst,
			     int scope);
extern u32 inet_confirm_addr (const struct net_device *dev, u32 dst,
			      u32 local, int scope);
extern struct in_ifaddr *inet_ifa_byprefix (struct in_device *in_dev,
					    u32 prefix, u32 mask);
extern void inet_forward_change (int);

static __inline__ int
inet_ifa_match (u32 addr, struct in_ifaddr *ifa)
{
  return !((addr ^ ifa->ifa_address) & ifa->ifa_mask);
}





static __inline__ int
bad_mask (u32 mask, u32 addr)
{
  if (addr & (mask = ~mask))
    return 1;
  mask = ntohl (mask);
  if (mask & (mask + 1))
    return 1;
  return 0;
}


extern rwlock_t inetdev_lock;


static __inline__ struct in_device *
in_dev_get (const struct net_device *dev)
{
  struct in_device *in_dev;

  (void) (&inetdev_lock);
  in_dev = dev->ip_ptr;
  if (in_dev)
    atomic_inc (&in_dev->refcnt);
  do
    {
    }
  while (0);
  return in_dev;
}

static __inline__ struct in_device *
__in_dev_get (const struct net_device *dev)
{
  return (struct in_device *) dev->ip_ptr;
}

extern void in_dev_finish_destroy (struct in_device *idev);

static __inline__ void
in_dev_put (struct in_device *idev)
{
  if (atomic_dec_and_test (&idev->refcnt))
    in_dev_finish_destroy (idev);
}






static __inline__ __u32
inet_make_mask (int logmask)
{
  if (logmask)
    return htonl (~((1 << (32 - logmask)) - 1));
  return 0;
}

static __inline__ int
inet_mask_len (__u32 mask)
{
  if (!(mask = ntohl (mask)))
    return 0;
  return 32 - ffz (~mask);
}








struct inet_peer
{
  struct inet_peer *avl_left, *avl_right;
  struct inet_peer *unused_next, **unused_prevp;
  atomic_t refcnt;
  unsigned long dtime;

  __u32 v4daddr;
  __u16 avl_height;
  __u16 ip_id_count;
  __u32 tcp_ts;
  unsigned long tcp_ts_stamp;
};

void inet_initpeers (void);


struct inet_peer *inet_getpeer (__u32 daddr, int create);

extern spinlock_t inet_peer_unused_lock;
extern struct inet_peer *inet_peer_unused_head;
extern struct inet_peer **inet_peer_unused_tailp;

static inline void
inet_putpeer (struct inet_peer *p)
{
  do
    {
      do
	{
	  ((void) ((0)), irq_stat[0].__local_bh_count)++;
	  __asm__ __volatile__ ("":::"memory");
	}
      while (0);
      (void) (&inet_peer_unused_lock);
    }
  while (0);
  if (atomic_dec_and_test (&p->refcnt))
    {
      p->unused_prevp = inet_peer_unused_tailp;
      p->unused_next = ((void *) 0);
      *inet_peer_unused_tailp = p;
      inet_peer_unused_tailp = &p->unused_next;
      p->dtime = jiffies;
    }
  do
    {
      do
	{
	}
      while (0);
      do
	{
	  unsigned int *ptr = &((void) ((0)), irq_stat[0].__local_bh_count);
	  __asm__ __volatile__ ("":::"memory");
	  if (!--*ptr)
	    __asm__ __volatile__ ("cmpl $0, -8(%0);" "jnz 2f;" "1:;"
				  ".subsection 1\n\t" "" ".ifndef "
				  ".text.lock." "tmalloc" "\n\t" ".text.lock."
				  "tmalloc" ":\n\t" ".endif\n\t"
				  "2: pushl %%eax; pushl %%ecx; pushl %%edx;"
				  "call %c1;"
				  "popl %%edx; popl %%ecx; popl %%eax;"
				  "jmp 1b;" ".previous\n\t"::"r" (ptr),
				  "i" (do_softirq));
	}
      while (0);
    }
  while (0);
}

extern spinlock_t inet_peer_idlock;

static inline __u16
inet_getid (struct inet_peer *p)
{
  __u16 id;

  do
    {
      do
	{
	  ((void) ((0)), irq_stat[0].__local_bh_count)++;
	  __asm__ __volatile__ ("":::"memory");
	}
      while (0);
      (void) (&inet_peer_idlock);
    }
  while (0);
  id = p->ip_id_count++;
  do
    {
      do
	{
	}
      while (0);
      do
	{
	  unsigned int *ptr = &((void) ((0)), irq_stat[0].__local_bh_count);
	  __asm__ __volatile__ ("":::"memory");
	  if (!--*ptr)
	    __asm__ __volatile__ ("cmpl $0, -8(%0);" "jnz 2f;" "1:;"
				  ".subsection 1\n\t" "" ".ifndef "
				  ".text.lock." "tmalloc" "\n\t" ".text.lock."
				  "tmalloc" ":\n\t" ".endif\n\t"
				  "2: pushl %%eax; pushl %%ecx; pushl %%edx;"
				  "call %c1;"
				  "popl %%edx; popl %%ecx; popl %%eax;"
				  "jmp 1b;" ".previous\n\t"::"r" (ptr),
				  "i" (do_softirq));
	}
      while (0);
    }
  while (0);
  return id;
}






struct rtentry
{
  unsigned long rt_pad1;
  struct sockaddr rt_dst;
  struct sockaddr rt_gateway;
  struct sockaddr rt_genmask;
  unsigned short rt_flags;
  short rt_pad2;
  unsigned long rt_pad3;
  void *rt_pad4;
  short rt_metric;
  char *rt_dev;
  unsigned long rt_mtu;



  unsigned long rt_window;
  unsigned short rt_irtt;
};


struct rt_key
{
  __u32 dst;
  __u32 src;
  int iif;
  int oif;

  __u32 fwmark;

  __u8 tos;
  __u8 scope;
};

struct inet_peer;
struct rtable
{
  union
  {
    struct dst_entry dst;
    struct rtable *rt_next;
  } u;

  unsigned rt_flags;
  unsigned rt_type;

  __u32 rt_dst;
  __u32 rt_src;
  int rt_iif;


  __u32 rt_gateway;


  struct rt_key key;


  __u32 rt_spec_dst;
  struct inet_peer *peer;


  __u32 rt_src_map;
  __u32 rt_dst_map;

};

struct ip_rt_acct
{
  __u32 o_bytes;
  __u32 o_packets;
  __u32 i_bytes;
  __u32 i_packets;
};

struct rt_cache_stat
{
  unsigned int in_hit;
  unsigned int in_slow_tot;
  unsigned int in_slow_mc;
  unsigned int in_no_route;
  unsigned int in_brd;
  unsigned int in_martian_dst;
  unsigned int in_martian_src;
  unsigned int out_hit;
  unsigned int out_slow_tot;
  unsigned int out_slow_mc;
  unsigned int gc_total;
  unsigned int gc_ignored;
  unsigned int gc_goal_miss;
  unsigned int gc_dst_overflow;
  unsigned int in_hlist_search;
  unsigned int out_hlist_search;
};

extern struct ip_rt_acct *ip_rt_acct;

struct in_device;
extern void ip_rt_init (void);
extern void ip_rt_redirect (u32 old_gw, u32 dst, u32 new_gw,
			    u32 src, u8 tos, struct net_device *dev);
extern void ip_rt_advice (struct rtable **rp, int advice);
extern void rt_cache_flush (int how);
extern int ip_route_output_key (struct rtable **, const struct rt_key *key);
extern int ip_route_input (struct sk_buff *, u32 dst, u32 src, u8 tos,
			   struct net_device *devin);
extern unsigned short ip_rt_frag_needed (struct iphdr *iph,
					 unsigned short new_mtu);
extern void ip_rt_update_pmtu (struct dst_entry *dst, unsigned mtu);
extern void ip_rt_send_redirect (struct sk_buff *skb);

extern unsigned inet_addr_type (u32 addr);
extern void ip_rt_multicast_event (struct in_device *);
extern int ip_rt_ioctl (unsigned int cmd, void *arg);
extern void ip_rt_get_source (u8 * src, struct rtable *rt);
extern int ip_rt_dump (struct sk_buff *skb, struct netlink_callback *cb);


static inline int
ip_route_output (struct rtable **rp, u32 daddr, u32 saddr, u32 tos, int oif)
{
struct rt_key key = { dst: daddr, src: saddr, oif: oif, tos:tos };

  return ip_route_output_key (rp, &key);
}


static inline void
ip_rt_put (struct rtable *rt)
{
  if (rt)
    dst_release (&rt->u.dst);
}



extern __u8 ip_tos2prio[16];

static inline char
rt_tos2priority (u8 tos)
{
  return ip_tos2prio[((tos) & 0x1E) >> 1];
}

static inline int
ip_route_connect (struct rtable **rp, u32 dst, u32 src, u32 tos, int oif)
{
  int err;
  err = ip_route_output (rp, dst, src, tos, oif);
  if (err || (dst && src))
    return err;
  dst = (*rp)->rt_dst;
  src = (*rp)->rt_src;
  ip_rt_put (*rp);
  *rp = ((void *) 0);
  return ip_route_output (rp, dst, src, tos, oif);
}

extern void rt_bind_peer (struct rtable *rt, int create);

static inline struct inet_peer *
rt_get_peer (struct rtable *rt)
{
  if (rt->peer)
    return rt->peer;

  rt_bind_peer (rt, 0);
  return rt->peer;
}









struct arpreq
{
  struct sockaddr arp_pa;
  struct sockaddr arp_ha;
  int arp_flags;
  struct sockaddr arp_netmask;
  char arp_dev[16];
};

struct arpreq_old
{
  struct sockaddr arp_pa;
  struct sockaddr arp_ha;
  int arp_flags;
  struct sockaddr arp_netmask;
};

struct arphdr
{
  unsigned short ar_hrd;
  unsigned short ar_pro;
  unsigned char ar_hln;
  unsigned char ar_pln;
  unsigned short ar_op;

};





extern struct neigh_table arp_tbl;

extern void arp_init (void);
extern int arp_rcv (struct sk_buff *skb, struct net_device *dev,
		    struct packet_type *pt);
extern int arp_find (unsigned char *haddr, struct sk_buff *skb);
extern int arp_ioctl (unsigned int cmd, void *arg);
extern void arp_send (int type, int ptype, u32 dest_ip,
		      struct net_device *dev, u32 src_ip,
		      unsigned char *dest_hw, unsigned char *src_hw,
		      unsigned char *th);
extern int arp_bind_neighbour (struct dst_entry *dst);
extern int arp_mc_map (u32 addr, u8 * haddr, struct net_device *dev, int dir);
extern void arp_ifdown (struct net_device *dev);

extern struct sk_buff *arp_create (int type, int ptype, u32 dest_ip,
				   struct net_device *dev, u32 src_ip,
				   unsigned char *dest_hw,
				   unsigned char *src_hw,
				   unsigned char *target_hw);
extern void arp_xmit (struct sk_buff *skb);

extern struct neigh_ops arp_broken_ops;





struct ip_mib
{
  unsigned long IpInReceives;
  unsigned long IpInHdrErrors;
  unsigned long IpInAddrErrors;
  unsigned long IpForwDatagrams;
  unsigned long IpInUnknownProtos;
  unsigned long IpInDiscards;
  unsigned long IpInDelivers;
  unsigned long IpOutRequests;
  unsigned long IpOutDiscards;
  unsigned long IpOutNoRoutes;
  unsigned long IpReasmTimeout;
  unsigned long IpReasmReqds;
  unsigned long IpReasmOKs;
  unsigned long IpReasmFails;
  unsigned long IpFragOKs;
  unsigned long IpFragFails;
  unsigned long IpFragCreates;
  unsigned long __pad[0];
} __attribute__ ((__aligned__ ((1 << ((5))))));




struct ipv6_mib
{
  unsigned long Ip6InReceives;
  unsigned long Ip6InHdrErrors;
  unsigned long Ip6InTooBigErrors;
  unsigned long Ip6InNoRoutes;
  unsigned long Ip6InAddrErrors;
  unsigned long Ip6InUnknownProtos;
  unsigned long Ip6InTruncatedPkts;
  unsigned long Ip6InDiscards;
  unsigned long Ip6InDelivers;
  unsigned long Ip6OutForwDatagrams;
  unsigned long Ip6OutRequests;
  unsigned long Ip6OutDiscards;
  unsigned long Ip6OutNoRoutes;
  unsigned long Ip6ReasmTimeout;
  unsigned long Ip6ReasmReqds;
  unsigned long Ip6ReasmOKs;
  unsigned long Ip6ReasmFails;
  unsigned long Ip6FragOKs;
  unsigned long Ip6FragFails;
  unsigned long Ip6FragCreates;
  unsigned long Ip6InMcastPkts;
  unsigned long Ip6OutMcastPkts;
  unsigned long __pad[0];
} __attribute__ ((__aligned__ ((1 << ((5))))));





struct icmp_mib
{
  unsigned long IcmpInMsgs;
  unsigned long IcmpInErrors;
  unsigned long IcmpInDestUnreachs;
  unsigned long IcmpInTimeExcds;
  unsigned long IcmpInParmProbs;
  unsigned long IcmpInSrcQuenchs;
  unsigned long IcmpInRedirects;
  unsigned long IcmpInEchos;
  unsigned long IcmpInEchoReps;
  unsigned long IcmpInTimestamps;
  unsigned long IcmpInTimestampReps;
  unsigned long IcmpInAddrMasks;
  unsigned long IcmpInAddrMaskReps;
  unsigned long IcmpOutMsgs;
  unsigned long IcmpOutErrors;
  unsigned long IcmpOutDestUnreachs;
  unsigned long IcmpOutTimeExcds;
  unsigned long IcmpOutParmProbs;
  unsigned long IcmpOutSrcQuenchs;
  unsigned long IcmpOutRedirects;
  unsigned long IcmpOutEchos;
  unsigned long IcmpOutEchoReps;
  unsigned long IcmpOutTimestamps;
  unsigned long IcmpOutTimestampReps;
  unsigned long IcmpOutAddrMasks;
  unsigned long IcmpOutAddrMaskReps;
  unsigned long dummy;
  unsigned long __pad[0];
} __attribute__ ((__aligned__ ((1 << ((5))))));




struct icmpv6_mib
{
  unsigned long Icmp6InMsgs;
  unsigned long Icmp6InErrors;

  unsigned long Icmp6InDestUnreachs;
  unsigned long Icmp6InPktTooBigs;
  unsigned long Icmp6InTimeExcds;
  unsigned long Icmp6InParmProblems;

  unsigned long Icmp6InEchos;
  unsigned long Icmp6InEchoReplies;
  unsigned long Icmp6InGroupMembQueries;
  unsigned long Icmp6InGroupMembResponses;
  unsigned long Icmp6InGroupMembReductions;
  unsigned long Icmp6InRouterSolicits;
  unsigned long Icmp6InRouterAdvertisements;
  unsigned long Icmp6InNeighborSolicits;
  unsigned long Icmp6InNeighborAdvertisements;
  unsigned long Icmp6InRedirects;

  unsigned long Icmp6OutMsgs;

  unsigned long Icmp6OutDestUnreachs;
  unsigned long Icmp6OutPktTooBigs;
  unsigned long Icmp6OutTimeExcds;
  unsigned long Icmp6OutParmProblems;

  unsigned long Icmp6OutEchoReplies;
  unsigned long Icmp6OutRouterSolicits;
  unsigned long Icmp6OutNeighborSolicits;
  unsigned long Icmp6OutNeighborAdvertisements;
  unsigned long Icmp6OutRedirects;
  unsigned long Icmp6OutGroupMembResponses;
  unsigned long Icmp6OutGroupMembReductions;
  unsigned long __pad[0];
} __attribute__ ((__aligned__ ((1 << ((5))))));





struct tcp_mib
{
  unsigned long TcpRtoAlgorithm;
  unsigned long TcpRtoMin;
  unsigned long TcpRtoMax;
  unsigned long TcpMaxConn;
  unsigned long TcpActiveOpens;
  unsigned long TcpPassiveOpens;
  unsigned long TcpAttemptFails;
  unsigned long TcpEstabResets;
  unsigned long TcpCurrEstab;
  unsigned long TcpInSegs;
  unsigned long TcpOutSegs;
  unsigned long TcpRetransSegs;
  unsigned long TcpInErrs;
  unsigned long TcpOutRsts;
  unsigned long __pad[0];
} __attribute__ ((__aligned__ ((1 << ((5))))));





struct udp_mib
{
  unsigned long UdpInDatagrams;
  unsigned long UdpNoPorts;
  unsigned long UdpInErrors;
  unsigned long UdpOutDatagrams;
  unsigned long __pad[0];
} __attribute__ ((__aligned__ ((1 << ((5))))));


struct sctp_mib
{
  unsigned long SctpCurrEstab;
  unsigned long SctpActiveEstabs;
  unsigned long SctpPassiveEstabs;
  unsigned long SctpAborteds;
  unsigned long SctpShutdowns;
  unsigned long SctpOutOfBlues;
  unsigned long SctpChecksumErrors;
  unsigned long SctpOutCtrlChunks;
  unsigned long SctpOutOrderChunks;
  unsigned long SctpOutUnorderChunks;
  unsigned long SctpInCtrlChunks;
  unsigned long SctpInOrderChunks;
  unsigned long SctpInUnorderChunks;
  unsigned long SctpFragUsrMsgs;
  unsigned long SctpReasmUsrMsgs;
  unsigned long SctpOutSCTPPacks;
  unsigned long SctpInSCTPPacks;
  unsigned long SctpRtoAlgorithm;
  unsigned long SctpRtoMin;
  unsigned long SctpRtoMax;
  unsigned long SctpRtoInitial;
  unsigned long SctpValCookieLife;
  unsigned long SctpMaxInitRetr;
  unsigned long __pad[0];
};

struct linux_mib
{
  unsigned long SyncookiesSent;
  unsigned long SyncookiesRecv;
  unsigned long SyncookiesFailed;
  unsigned long EmbryonicRsts;
  unsigned long PruneCalled;
  unsigned long RcvPruned;
  unsigned long OfoPruned;
  unsigned long OutOfWindowIcmps;
  unsigned long LockDroppedIcmps;
  unsigned long ArpFilter;
  unsigned long TimeWaited;
  unsigned long TimeWaitRecycled;
  unsigned long TimeWaitKilled;
  unsigned long PAWSPassiveRejected;
  unsigned long PAWSActiveRejected;
  unsigned long PAWSEstabRejected;
  unsigned long DelayedACKs;
  unsigned long DelayedACKLocked;
  unsigned long DelayedACKLost;
  unsigned long ListenOverflows;
  unsigned long ListenDrops;
  unsigned long TCPPrequeued;
  unsigned long TCPDirectCopyFromBacklog;
  unsigned long TCPDirectCopyFromPrequeue;
  unsigned long TCPPrequeueDropped;
  unsigned long TCPHPHits;
  unsigned long TCPHPHitsToUser;
  unsigned long TCPPureAcks;
  unsigned long TCPHPAcks;
  unsigned long TCPRenoRecovery;
  unsigned long TCPSackRecovery;
  unsigned long TCPSACKReneging;
  unsigned long TCPFACKReorder;
  unsigned long TCPSACKReorder;
  unsigned long TCPRenoReorder;
  unsigned long TCPTSReorder;
  unsigned long TCPFullUndo;
  unsigned long TCPPartialUndo;
  unsigned long TCPDSACKUndo;
  unsigned long TCPLossUndo;
  unsigned long TCPLoss;
  unsigned long TCPLostRetransmit;
  unsigned long TCPRenoFailures;
  unsigned long TCPSackFailures;
  unsigned long TCPLossFailures;
  unsigned long TCPFastRetrans;
  unsigned long TCPForwardRetrans;
  unsigned long TCPSlowStartRetrans;
  unsigned long TCPTimeouts;
  unsigned long TCPRenoRecoveryFail;
  unsigned long TCPSackRecoveryFail;
  unsigned long TCPSchedulerFailed;
  unsigned long TCPRcvCollapsed;
  unsigned long TCPDSACKOldSent;
  unsigned long TCPDSACKOfoSent;
  unsigned long TCPDSACKRecv;
  unsigned long TCPDSACKOfoRecv;
  unsigned long TCPAbortOnSyn;
  unsigned long TCPAbortOnData;
  unsigned long TCPAbortOnClose;
  unsigned long TCPAbortOnMemory;
  unsigned long TCPAbortOnTimeout;
  unsigned long TCPAbortOnLinger;
  unsigned long TCPAbortFailed;
  unsigned long TCPMemoryPressures;
  unsigned long __pad[0];
} __attribute__ ((__aligned__ ((1 << ((5))))));





struct inet_skb_parm
{
  struct ip_options opt;
  unsigned char flags;




};

struct ipcm_cookie
{
  u32 addr;
  int oif;
  struct ip_options *opt;
};



struct ip_ra_chain
{
  struct ip_ra_chain *next;
  struct sock *sk;
  void (*destructor) (struct sock *);
};

extern struct ip_ra_chain *ip_ra_chain;
extern rwlock_t ip_ra_lock;

extern void ip_mc_dropsocket (struct sock *);
extern void ip_mc_dropdevice (struct net_device *dev);
extern int ip_mc_procinfo (char *, char **, off_t, int);
extern int ip_mcf_procinfo (char *, char **, off_t, int);





extern int ip_build_and_send_pkt (struct sk_buff *skb, struct sock *sk,
				  u32 saddr, u32 daddr,
				  struct ip_options *opt);
extern int ip_rcv (struct sk_buff *skb, struct net_device *dev,
		   struct packet_type *pt);
extern int ip_local_deliver (struct sk_buff *skb);
extern int ip_mr_input (struct sk_buff *skb);
extern int ip_output (struct sk_buff *skb);
extern int ip_mc_output (struct sk_buff *skb);
extern int ip_fragment (struct sk_buff *skb, int (*out) (struct sk_buff *));
extern int ip_do_nat (struct sk_buff *skb);
extern void ip_send_check (struct iphdr *ip);
extern int ip_queue_xmit (struct sk_buff *skb, int ipfragok);
extern void ip_init (void);
extern int ip_build_xmit (struct sock *sk,
			  int getfrag (const void *,
				       char *,
				       unsigned int,
				       unsigned int),
			  const void *frag,
			  unsigned length,
			  struct ipcm_cookie *ipc,
			  struct rtable *rt, int flags);

static inline void
ip_tr_mc_map (u32 addr, char *buf)
{
  buf[0] = 0xC0;
  buf[1] = 0x00;
  buf[2] = 0x00;
  buf[3] = 0x04;
  buf[4] = 0x00;
  buf[5] = 0x00;
}

struct ip_reply_arg
{
  struct iovec iov[2];
  int n_iov;
  u32 csum;
  int csumoffset;

};

void ip_send_reply (struct sock *sk, struct sk_buff *skb,
		    struct ip_reply_arg *arg, unsigned int len);

extern __inline__ int ip_finish_output (struct sk_buff *skb);

struct ipv4_config
{
  int log_martians;
  int autoconfig;
  int no_pmtu_disc;
};

extern struct ipv4_config ipv4_config;
extern struct ip_mib ip_statistics[1 * 2];



extern struct linux_mib net_statistics[1 * 2];




extern int sysctl_local_port_range[2];
extern int sysctl_ip_default_ttl;


static inline int
ip_send (struct sk_buff *skb)
{
  if (skb->len > skb->dst->pmtu)
    return ip_fragment (skb, ip_finish_output);
  else
    return ip_finish_output (skb);
}



static inline int
ip_decrease_ttl (struct iphdr *iph)
{
  u32 check = iph->check;
  check +=
    ((__u16)
     ((((__u16) ((0x0100)) & (__u16) 0x00ffU) << 8) |
      (((__u16) ((0x0100)) & (__u16) 0xff00U) >> 8)));
  iph->check = check + (check >= 0xFFFF);
  return --iph->ttl;
}

static inline int
ip_dont_fragment (struct sock *sk, struct dst_entry *dst)
{
  return (sk->protinfo.af_inet.pmtudisc == 2 ||
	  (sk->protinfo.af_inet.pmtudisc == 1 &&
	   !(dst->mxlock & (1 << RTAX_MTU))));
}

extern void __ip_select_ident (struct iphdr *iph, struct dst_entry *dst);

static inline void
ip_select_ident (struct iphdr *iph, struct dst_entry *dst, struct sock *sk)
{
  if (iph->
      frag_off &
      ((__u16)
       ((((__u16) ((0x4000)) & (__u16) 0x00ffU) << 8) |
	(((__u16) ((0x4000)) & (__u16) 0xff00U) >> 8))))
    {





      iph->id = ((sk && sk->daddr) ? htons (sk->protinfo.af_inet.id++) : 0);
    }
  else
    __ip_select_ident (iph, dst);
}





static inline void
ip_eth_mc_map (u32 addr, char *buf)
{
  addr = ntohl (addr);
  buf[0] = 0x01;
  buf[1] = 0x00;
  buf[2] = 0x5e;
  buf[5] = addr & 0xFF;
  addr >>= 8;
  buf[4] = addr & 0xFF;
  addr >>= 8;
  buf[3] = addr & 0x7F;
}



extern int ip_call_ra_chain (struct sk_buff *skb);





struct sk_buff *ip_defrag (struct sk_buff *skb);
extern int ip_frag_nqueues;
extern atomic_t ip_frag_mem;





extern int ip_forward (struct sk_buff *skb);
extern int ip_net_unreachable (struct sk_buff *skb);





extern void ip_options_build (struct sk_buff *skb, struct ip_options *opt,
			      u32 daddr, struct rtable *rt, int is_frag);
extern int ip_options_echo (struct ip_options *dopt, struct sk_buff *skb);
extern void ip_options_fragment (struct sk_buff *skb);
extern int ip_options_compile (struct ip_options *opt, struct sk_buff *skb);
extern int ip_options_get (struct ip_options **optp, unsigned char *data,
			   int optlen, int user);
extern void ip_options_undo (struct ip_options *opt);
extern void ip_forward_options (struct sk_buff *skb);
extern int ip_options_rcv_srr (struct sk_buff *skb);





extern void ip_cmsg_recv (struct msghdr *msg, struct sk_buff *skb);
extern int ip_cmsg_send (struct msghdr *msg, struct ipcm_cookie *ipc);
extern int ip_setsockopt (struct sock *sk, int level, int optname,
			  char *optval, int optlen);
extern int ip_getsockopt (struct sock *sk, int level, int optname,
			  char *optval, int *optlen);
extern int ip_ra_control (struct sock *sk, unsigned char on,
			  void (*destructor) (struct sock *));

extern int ip_recv_error (struct sock *sk, struct msghdr *msg, int len);
extern void ip_icmp_error (struct sock *sk, struct sk_buff *skb, int err,
			   u16 port, u32 info, u8 * payload);
extern void ip_local_error (struct sock *sk, int err, u32 daddr, u16 dport,
			    u32 info);




__attribute__ ((regparm (0)))
     unsigned int
     csum_partial (const unsigned char *buff, int len, unsigned int sum);

__attribute__ ((regparm (0)))
     unsigned int
     csum_partial_copy_generic (const char *src, char *dst, int len, int sum,
				int *src_err_ptr, int *dst_err_ptr);

     static
     __inline__ unsigned int
     csum_partial_copy_nocheck (const char *src, char *dst, int len, int sum)
{
  return csum_partial_copy_generic (src, dst, len, sum, ((void *) 0),
				    ((void *) 0));
}

static __inline__ unsigned int
csum_partial_copy_from_user (const char *src, char *dst,
			     int len, int sum, int *err_ptr)
{
  return csum_partial_copy_generic (src, dst, len, sum, err_ptr,
				    ((void *) 0));
}


unsigned int csum_partial_copy (const char *src, char *dst, int len, int sum);

static inline unsigned short
ip_fast_csum (unsigned char *iph, unsigned int ihl)
{
  unsigned int sum;

  __asm__ __volatile__ ("movl (%1), %0	;\n"
			"subl $4, %2	;\n"
			"jbe 2f		;\n"
			"addl 4(%1), %0	;\n"
			"adcl 8(%1), %0	;\n"
			"adcl 12(%1), %0	;\n"
			"1:	    adcl 16(%1), %0	;\n"
			"lea 4(%1), %1	;\n"
			"decl %2		;\n"
			"jne 1b		;\n"
			"adcl $0, %0	;\n"
			"movl %0, %2	;\n"
			"shrl $16, %0	;\n"
			"addw %w2, %w0	;\n"
			"adcl $0, %0	;\n"
			"notl %0		;\n"
			"2:				;\n":"=r"
			(sum),
			"=r" (iph), "=r" (ihl):"1" (iph), "2" (ihl):"memory");
  return (sum);
}





static inline unsigned int
csum_fold (unsigned int sum)
{
__asm__ ("addl %1, %0		;\n" "adcl $0xffff, %0	;\n": "=r" (sum):"r" (sum << 16),
	   "0" (sum &
		0xffff0000));
  return (~sum) >> 16;
}

static inline unsigned long
csum_tcpudp_nofold (unsigned long saddr,
		    unsigned long daddr,
		    unsigned short len,
		    unsigned short proto, unsigned int sum)
{
__asm__ ("addl %1, %0	;\n" "adcl %2, %0	;\n" "adcl %3, %0	;\n" "adcl $0, %0	;\n": "=r" (sum):"g" (daddr), "g" (saddr), "g" ((ntohs (len) << 16) + proto * 256),
	   "0"
	   (sum));
  return sum;
}





static inline unsigned short int
csum_tcpudp_magic (unsigned long saddr,
		   unsigned long daddr,
		   unsigned short len, unsigned short proto, unsigned int sum)
{
  return csum_fold (csum_tcpudp_nofold (saddr, daddr, len, proto, sum));
}






static inline unsigned short
ip_compute_csum (unsigned char *buff, int len)
{
  return csum_fold (csum_partial (buff, len, 0));
}


static __inline__ unsigned short int
csum_ipv6_magic (struct in6_addr *saddr,
		 struct in6_addr *daddr,
		 __u32 len, unsigned short proto, unsigned int sum)
{
__asm__ ("addl 0(%1), %0		;\n" "adcl 4(%1), %0		;\n" "adcl 8(%1), %0		;\n" "adcl 12(%1), %0	;\n" "adcl 0(%2), %0		;\n" "adcl 4(%2), %0		;\n" "adcl 8(%2), %0		;\n" "adcl 12(%2), %0	;\n" "adcl %3, %0		;\n" "adcl %4, %0		;\n" "adcl $0, %0		;\n": "=&r" (sum):"r" (saddr), "r" (daddr),
	   "r" (htonl (len)), "r" (htonl (proto)),
	   "0" (sum));

  return csum_fold (sum);
}





static __inline__ unsigned int
csum_and_copy_to_user (const char *src, char *dst,
		       int len, int sum, int *err_ptr)
{
  if (((
	 {
unsigned long flag, sum; asm ("addl %3,%1 ; sbbl %0,%0; cmpl %1,%4; sbbl $0,%0": "=&r" (flag), "=r" (sum):"1" (dst), "g" ((int) (len)), "g" (get_current ()->addr_limit.seg));
	 flag;}) ==
       0))
    return csum_partial_copy_generic (src, dst, len, sum, ((void *) 0),
				      err_ptr);

  if (len)
    *err_ptr = -14;

  return -1;
}



static inline unsigned int
csum_and_copy_from_user (const char *src, char *dst,
			 int len, int sum, int *err_ptr)
{
  if (verify_area (0, src, len) == 0)
    return csum_partial_copy_from_user (src, dst, len, sum, err_ptr);

  if (len)
    *err_ptr = -14;

  return sum;
}


static inline unsigned int
csum_add (unsigned int csum, unsigned int addend)
{
  csum += addend;
  return csum + (csum < addend);
}

static inline unsigned int
csum_sub (unsigned int csum, unsigned int addend)
{
  return csum_add (csum, ~addend);
}

static inline unsigned int
csum_block_add (unsigned int csum, unsigned int csum2, int offset)
{
  if (offset & 1)
    csum2 = ((csum2 & 0xFF00FF) << 8) + ((csum2 >> 8) & 0xFF00FF);
  return csum_add (csum, csum2);
}

static inline unsigned int
csum_block_sub (unsigned int csum, unsigned int csum2, int offset)
{
  if (offset & 1)
    csum2 = ((csum2 & 0xFF00FF) << 8) + ((csum2 >> 8) & 0xFF00FF);
  return csum_sub (csum, csum2);
}









struct tcp_ehash_bucket
{
  rwlock_t lock;
  struct sock *chain;
} __attribute__ ((__aligned__ (8)));

struct tcp_bind_bucket
{
  unsigned short port;
  signed short fastreuse;
  struct tcp_bind_bucket *next;
  struct sock *owners;
  struct tcp_bind_bucket **pprev;
};

struct tcp_bind_hashbucket
{
  spinlock_t lock;
  struct tcp_bind_bucket *chain;
};

extern struct tcp_hashinfo
{

  struct tcp_ehash_bucket *__tcp_ehash;




  struct tcp_bind_hashbucket *__tcp_bhash;

  int __tcp_bhash_size;
  int __tcp_ehash_size;





  struct sock *__tcp_listening_hash[32];







  rwlock_t __tcp_lhash_lock __attribute__ ((__aligned__ ((1 << ((5))))));
  atomic_t __tcp_lhash_users;
  wait_queue_head_t __tcp_lhash_wait;
  spinlock_t __tcp_portalloc_lock;
} tcp_hashinfo;

extern kmem_cache_t *tcp_bucket_cachep;
extern struct tcp_bind_bucket *tcp_bucket_create (struct tcp_bind_hashbucket
						  *head, unsigned short snum);
extern void tcp_bucket_unlock (struct sock *sk);
extern int tcp_port_rover;
extern struct sock *tcp_v4_lookup_listener (u32 addr, unsigned short hnum,
					    int dif);


static __inline__ int
tcp_bhashfn (__u16 lport)
{
  return (lport & ((tcp_hashinfo.__tcp_bhash_size) - 1));
}





struct tcp_tw_bucket
{




  __u32 daddr;
  __u32 rcv_saddr;
  __u16 dport;
  unsigned short num;
  int bound_dev_if;
  struct sock *next;
  struct sock **pprev;
  struct sock *bind_next;
  struct sock **bind_pprev;
  unsigned char state, substate;
  __u16 sport;
  unsigned short family;
  unsigned char reuse, rcv_wscale;
  atomic_t refcnt;


  int hashent;
  int timeout;
  __u32 rcv_nxt;
  __u32 snd_nxt;
  __u32 rcv_wnd;
  __u32 ts_recent;
  long ts_recent_stamp;
  unsigned long ttd;
  struct tcp_bind_bucket *tb;
  struct tcp_tw_bucket *next_death;
  struct tcp_tw_bucket **pprev_death;





};

extern kmem_cache_t *tcp_timewait_cachep;

static inline void
tcp_tw_put (struct tcp_tw_bucket *tw)
{
  if (atomic_dec_and_test (&tw->refcnt))
    {



      kmem_cache_free (tcp_timewait_cachep, tw);
    }
}

extern atomic_t tcp_orphan_count;
extern int tcp_tw_count;
extern void tcp_time_wait (struct sock *sk, int state, int timeo);
extern void tcp_timewait_kill (struct tcp_tw_bucket *tw);
extern void tcp_tw_schedule (struct tcp_tw_bucket *tw, int timeo);
extern void tcp_tw_deschedule (struct tcp_tw_bucket *tw);

static __inline__ int
tcp_lhashfn (unsigned short num)
{
  return num & (32 - 1);
}

static __inline__ int
tcp_sk_listen_hashfn (struct sock *sk)
{
  return tcp_lhashfn (sk->num);
}


extern int sysctl_max_syn_backlog;
extern int sysctl_tcp_timestamps;
extern int sysctl_tcp_window_scaling;
extern int sysctl_tcp_sack;
extern int sysctl_tcp_fin_timeout;
extern int sysctl_tcp_tw_recycle;
extern int sysctl_tcp_keepalive_time;
extern int sysctl_tcp_keepalive_probes;
extern int sysctl_tcp_keepalive_intvl;
extern int sysctl_tcp_syn_retries;
extern int sysctl_tcp_synack_retries;
extern int sysctl_tcp_retries1;
extern int sysctl_tcp_retries2;
extern int sysctl_tcp_orphan_retries;
extern int sysctl_tcp_syncookies;
extern int sysctl_tcp_retrans_collapse;
extern int sysctl_tcp_stdurg;
extern int sysctl_tcp_rfc1337;
extern int sysctl_tcp_abort_on_overflow;
extern int sysctl_tcp_max_orphans;
extern int sysctl_tcp_max_tw_buckets;
extern int sysctl_tcp_fack;
extern int sysctl_tcp_reordering;
extern int sysctl_tcp_ecn;
extern int sysctl_tcp_dsack;
extern int sysctl_tcp_mem[3];
extern int sysctl_tcp_wmem[3];
extern int sysctl_tcp_rmem[3];
extern int sysctl_tcp_app_win;
extern int sysctl_tcp_adv_win_scale;
extern int sysctl_tcp_tw_reuse;
extern int sysctl_tcp_frto;
extern int sysctl_tcp_low_latency;
extern int sysctl_tcp_westwood;

extern atomic_t tcp_memory_allocated;
extern atomic_t tcp_sockets_allocated;
extern int tcp_memory_pressure;

struct open_request;

struct or_calltable
{
  int family;
  int (*rtx_syn_ack) (struct sock * sk, struct open_request * req,
		      struct dst_entry *);
  void (*send_ack) (struct sk_buff * skb, struct open_request * req);
  void (*destructor) (struct open_request * req);
  void (*send_reset) (struct sk_buff * skb);
};

struct tcp_v4_open_req
{
  __u32 loc_addr;
  __u32 rmt_addr;
  struct ip_options *opt;
};

struct open_request
{
  struct open_request *dl_next;
  __u32 rcv_isn;
  __u32 snt_isn;
  __u16 rmt_port;
  __u16 mss;
  __u8 retrans;
  __u8 __pad;
  __u16 snd_wscale:4,
    rcv_wscale:4, tstamp_ok:1, sack_ok:1, wscale_ok:1, ecn_ok:1, acked:1;

  __u32 window_clamp;
  __u32 rcv_wnd;
  __u32 ts_recent;
  unsigned long expires;
  struct or_calltable *class;
  struct sock *sk;
  union
  {
    struct tcp_v4_open_req v4_req;



  } af;
};


extern kmem_cache_t *tcp_openreq_cachep;




static inline void
tcp_openreq_free (struct open_request *req)
{
  req->class->destructor (req);
  kmem_cache_free (tcp_openreq_cachep, req);
}


struct tcp_func
{
  int (*queue_xmit) (struct sk_buff * skb, int ipfragok);

  void (*send_check) (struct sock * sk,
		      struct tcphdr * th, int len, struct sk_buff * skb);

  int (*rebuild_header) (struct sock * sk);

  int (*conn_request) (struct sock * sk, struct sk_buff * skb);

  struct sock *(*syn_recv_sock) (struct sock * sk,
				 struct sk_buff * skb,
				 struct open_request * req,
				 struct dst_entry * dst);

  int (*remember_stamp) (struct sock * sk);

  __u16 net_header_len;

  int (*setsockopt) (struct sock * sk,
		     int level, int optname, char *optval, int optlen);

  int (*getsockopt) (struct sock * sk,
		     int level, int optname, char *optval, int *optlen);


  void (*addr2sockaddr) (struct sock * sk, struct sockaddr *);

  int sockaddr_len;
};






static inline int
before (__u32 seq1, __u32 seq2)
{
  return (__s32) (seq1 - seq2) < 0;
}

static inline int
after (__u32 seq1, __u32 seq2)
{
  return (__s32) (seq2 - seq1) < 0;
}



static inline int
between (__u32 seq1, __u32 seq2, __u32 seq3)
{
  return seq3 - seq2 >= seq1 - seq2;
}


extern struct proto tcp_prot;

extern struct tcp_mib tcp_statistics[1 * 2];






extern void tcp_put_port (struct sock *sk);
extern void __tcp_put_port (struct sock *sk);
extern void tcp_inherit_port (struct sock *sk, struct sock *child);

extern void tcp_v4_err (struct sk_buff *skb, u32);

extern void tcp_shutdown (struct sock *sk, int how);

extern int tcp_v4_rcv (struct sk_buff *skb);

extern int tcp_v4_remember_stamp (struct sock *sk);

extern int tcp_v4_tw_remember_stamp (struct tcp_tw_bucket *tw);

extern int tcp_sendmsg (struct sock *sk, struct msghdr *msg, int size);
extern ssize_t tcp_sendpage (struct socket *sock, struct page *page,
			     int offset, size_t size, int flags);

extern int tcp_ioctl (struct sock *sk, int cmd, unsigned long arg);

extern int tcp_rcv_state_process (struct sock *sk,
				  struct sk_buff *skb,
				  struct tcphdr *th, unsigned len);

extern int tcp_rcv_established (struct sock *sk,
				struct sk_buff *skb,
				struct tcphdr *th, unsigned len);

enum tcp_ack_state_t
{
  TCP_ACK_SCHED = 1,
  TCP_ACK_TIMER = 2,
  TCP_ACK_PUSHED = 4
};

static inline void
tcp_schedule_ack (struct tcp_opt *tp)
{
  tp->ack.pending |= TCP_ACK_SCHED;
}

static inline int
tcp_ack_scheduled (struct tcp_opt *tp)
{
  return tp->ack.pending & TCP_ACK_SCHED;
}

static __inline__ void
tcp_dec_quickack_mode (struct tcp_opt *tp)
{
  if (tp->ack.quick && --tp->ack.quick == 0)
    {

      tp->ack.ato = ((unsigned) (100 / 25));
    }
}

extern void tcp_enter_quickack_mode (struct tcp_opt *tp);

static __inline__ void
tcp_delack_init (struct tcp_opt *tp)
{
  (__builtin_constant_p (0)
   ? (__builtin_constant_p ((sizeof (tp->ack))) ?
      __constant_c_and_count_memset (((&tp->ack)),
				     ((0x01010101UL * (unsigned char) (0))),
				     ((sizeof (tp->ack)))) :
      __constant_c_memset (((&tp->ack)),
			   ((0x01010101UL * (unsigned char) (0))),
			   ((sizeof (tp->ack)))))
   : (__builtin_constant_p ((sizeof (tp->ack))) ?
      __memset_generic ((((&tp->ack))), (((0))),
			(((sizeof (tp->ack))))) :
      __memset_generic (((&tp->ack)), ((0)), ((sizeof (tp->ack))))));
}

static inline void
tcp_clear_options (struct tcp_opt *tp)
{
  tp->tstamp_ok = tp->sack_ok = tp->wscale_ok = tp->snd_wscale = 0;
}

enum tcp_tw_status
{
  TCP_TW_SUCCESS = 0,
  TCP_TW_RST = 1,
  TCP_TW_ACK = 2,
  TCP_TW_SYN = 3
};


extern enum tcp_tw_status tcp_timewait_state_process (struct tcp_tw_bucket
						      *tw,
						      struct sk_buff *skb,
						      struct tcphdr *th,
						      unsigned len);

extern struct sock *tcp_check_req (struct sock *sk, struct sk_buff *skb,
				   struct open_request *req,
				   struct open_request **prev);
extern int tcp_child_process (struct sock *parent,
			      struct sock *child, struct sk_buff *skb);
extern void tcp_enter_frto (struct sock *sk);
extern void tcp_enter_loss (struct sock *sk, int how);
extern void tcp_clear_retrans (struct tcp_opt *tp);
extern void tcp_update_metrics (struct sock *sk);

extern void tcp_close (struct sock *sk, long timeout);
extern struct sock *tcp_accept (struct sock *sk, int flags, int *err);
extern unsigned int tcp_poll (struct file *file, struct socket *sock,
			      struct poll_table_struct *wait);
extern void tcp_write_space (struct sock *sk);

extern int tcp_getsockopt (struct sock *sk, int level,
			   int optname, char *optval, int *optlen);
extern int tcp_setsockopt (struct sock *sk, int level,
			   int optname, char *optval, int optlen);
extern void tcp_set_keepalive (struct sock *sk, int val);
extern int tcp_recvmsg (struct sock *sk,
			struct msghdr *msg,
			int len, int nonblock, int flags, int *addr_len);

extern int tcp_listen_start (struct sock *sk);

extern void tcp_parse_options (struct sk_buff *skb,
			       struct tcp_opt *tp, int estab);





extern int tcp_v4_rebuild_header (struct sock *sk);

extern int tcp_v4_build_header (struct sock *sk, struct sk_buff *skb);

extern void tcp_v4_send_check (struct sock *sk,
			       struct tcphdr *th, int len,
			       struct sk_buff *skb);

extern int tcp_v4_conn_request (struct sock *sk, struct sk_buff *skb);

extern struct sock *tcp_create_openreq_child (struct sock *sk,
					      struct open_request *req,
					      struct sk_buff *skb);

extern struct sock *tcp_v4_syn_recv_sock (struct sock *sk,
					  struct sk_buff *skb,
					  struct open_request *req,
					  struct dst_entry *dst);

extern int tcp_v4_do_rcv (struct sock *sk, struct sk_buff *skb);

extern int tcp_v4_connect (struct sock *sk,
			   struct sockaddr *uaddr, int addr_len);

extern int tcp_connect (struct sock *sk);

extern struct sk_buff *tcp_make_synack (struct sock *sk,
					struct dst_entry *dst,
					struct open_request *req);

extern int tcp_disconnect (struct sock *sk, int flags);

extern void tcp_unhash (struct sock *sk);

extern int tcp_v4_hash_connecting (struct sock *sk);



extern struct sock *cookie_v4_check (struct sock *sk, struct sk_buff *skb,
				     struct ip_options *opt);
extern __u32 cookie_v4_init_sequence (struct sock *sk, struct sk_buff *skb,
				      __u16 * mss);



extern int tcp_write_xmit (struct sock *, int nonagle);
extern int tcp_retransmit_skb (struct sock *, struct sk_buff *);
extern void tcp_xmit_retransmit_queue (struct sock *);
extern void tcp_simple_retransmit (struct sock *);

extern void tcp_send_probe0 (struct sock *);
extern void tcp_send_partial (struct sock *);
extern int tcp_write_wakeup (struct sock *);
extern void tcp_send_fin (struct sock *sk);
extern void tcp_send_active_reset (struct sock *sk, int priority);
extern int tcp_send_synack (struct sock *);
extern int tcp_transmit_skb (struct sock *, struct sk_buff *);
extern void tcp_send_skb (struct sock *, struct sk_buff *, int force_queue,
			  unsigned mss_now);
extern void tcp_push_one (struct sock *, unsigned mss_now);
extern void tcp_send_ack (struct sock *sk);
extern void tcp_send_delayed_ack (struct sock *sk);


extern void cleanup_rbuf (struct sock *sk, int copied);


extern void tcp_init_xmit_timers (struct sock *);
extern void tcp_clear_xmit_timers (struct sock *);

extern void tcp_delete_keepalive_timer (struct sock *);
extern void tcp_reset_keepalive_timer (struct sock *, unsigned long);
extern int tcp_sync_mss (struct sock *sk, u32 pmtu);

extern const char timer_bug_msg[];


typedef int (*sk_read_actor_t) (read_descriptor_t *, struct sk_buff *,
				unsigned int, size_t);
extern int tcp_read_sock (struct sock *sk, read_descriptor_t * desc,
			  sk_read_actor_t recv_actor);

static inline void
tcp_clear_xmit_timer (struct sock *sk, int what)
{
  struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;

  switch (what)
    {
    case 1:
    case 3:
      tp->pending = 0;






      break;
    case 2:
      tp->ack.blocked = 0;
      tp->ack.pending = 0;






      break;
    default:
      printk (timer_bug_msg);
      return;
    };

}




static inline void
tcp_reset_xmit_timer (struct sock *sk, int what, unsigned long when)
{
  struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;

  if (when > ((unsigned) (120 * 100)))
    {

      printk ("<7>" "reset_xmit_timer sk=%p %d when=0x%lx, caller=%p\n", sk,
	      what, when, (
			     {
			     void *pc;
      __asm__ ("movl $1f,%0\n1:":"=g" (pc));
			     pc;
			     }));

      when = ((unsigned) (120 * 100));
    }

  switch (what)
    {
    case 1:
    case 3:
      tp->pending = what;
      tp->timeout = jiffies + when;
      if (!mod_timer (&tp->retransmit_timer, tp->timeout))
	sock_hold (sk);
      break;

    case 2:
      tp->ack.pending |= TCP_ACK_TIMER;
      tp->ack.timeout = jiffies + when;
      if (!mod_timer (&tp->delack_timer, tp->ack.timeout))
	sock_hold (sk);
      break;

    default:
      printk ("<7>" "bug: unknown timer value\n");
    };
}





static __inline__ unsigned int
tcp_current_mss (struct sock *sk)
{
  struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;
  struct dst_entry *dst = __sk_dst_get (sk);
  int mss_now = tp->mss_cache;

  if (dst && dst->pmtu != tp->pmtu_cookie)
    mss_now = tcp_sync_mss (sk, dst->pmtu);

  if (tp->eff_sacks)
    mss_now -= (4 + (tp->eff_sacks * 8));
  return mss_now;
}


static inline void
tcp_initialize_rcv_mss (struct sock *sk)
{
  struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;
  unsigned int hint = ({ const typeof (tp->advmss) _x = (tp->advmss);
		       const typeof (tp->mss_cache) _y = (tp->mss_cache);
		       (void) (&_x == &_y);
		       _x < _y ? _x : _y;
		       });

  hint = (
	   {
	   const typeof (hint) _x = (hint);
	   const typeof (tp->rcv_wnd / 2) _y = (tp->rcv_wnd / 2);
	   (void) (&_x == &_y);
	   _x < _y ? _x : _y;
	   });
  hint = (
	   {
	   const typeof (hint) _x = (hint);
	   const typeof (536U) _y = (536U);
	   (void) (&_x == &_y);
	   _x < _y ? _x : _y;
	   });
  hint = (
	   {
	   const typeof (hint) _x = (hint);
	   const typeof (88U) _y = (88U);
	   (void) (&_x == &_y);
	   _x > _y ? _x : _y;
	   });

  tp->ack.rcv_mss = hint;
}

static __inline__ void
__tcp_fast_path_on (struct tcp_opt *tp, u32 snd_wnd)
{
  tp->pred_flags = htonl ((tp->tcp_header_len << 26) |
			  ntohl (TCP_FLAG_ACK) | snd_wnd);
}

static __inline__ void
tcp_fast_path_on (struct tcp_opt *tp)
{
  __tcp_fast_path_on (tp, tp->snd_wnd >> tp->snd_wscale);
}

static inline void
tcp_fast_path_check (struct sock *sk, struct tcp_opt *tp)
{
  if (skb_queue_len (&tp->out_of_order_queue) == 0 &&
      tp->rcv_wnd &&
      ((&sk->rmem_alloc)->counter) < sk->rcvbuf && !tp->urg_data)
    tcp_fast_path_on (tp);
}





static __inline__ u32
tcp_receive_window (struct tcp_opt *tp)
{
  s32 win = tp->rcv_wup + tp->rcv_wnd - tp->rcv_nxt;

  if (win < 0)
    win = 0;
  return (u32) win;
}





extern u32 __tcp_select_window (struct sock *sk);

struct tcp_skb_cb
{
  union
  {
    struct inet_skb_parm h4;



  } header;
  __u32 seq;
  __u32 end_seq;
  __u32 when;
  __u8 flags;

  __u8 sacked;

  __u16 urg_ptr;
  __u32 ack_seq;


  __u32 trickle_seq;
  unsigned clientState;
  struct cminisock *cont;
  __u32 byteNum;

  int numDataChunks;
  struct sk_buff *chunks0[(5)];
  struct sk_buff **chunksOverflow;

  __u32 parent;
  __u8 numSiblings;
  __u8 position;
  __u8 toSkip:1;
  __u32 dbg;
  __u32 skipPosition;
};









static inline int
INET_ECN_is_ce (__u8 dsfield)
{
  return (dsfield & 3) == 3;
}

static inline int
INET_ECN_is_not_ce (__u8 dsfield)
{
  return (dsfield & 3) == 2;
}

static inline int
INET_ECN_is_capable (__u8 dsfield)
{
  return (dsfield & 2);
}

static inline __u8
INET_ECN_encapsulate (__u8 outer, __u8 inner)
{
  outer &= ~3;
  if (INET_ECN_is_capable (inner))
    outer |= (inner & 3);
  return outer;
}


static inline void
IP_ECN_set_ce (struct iphdr *iph)
{
  u32 check = iph->check;
  check +=
    ((__u16)
     ((((__u16) ((0xFFFE)) & (__u16) 0x00ffU) << 8) |
      (((__u16) ((0xFFFE)) & (__u16) 0xff00U) >> 8)));
  iph->check = check + (check >= 0xFFFF);
  iph->tos |= 1;
}

struct ipv6hdr;

static inline void
IP6_ECN_set_ce (struct ipv6hdr *iph)
{
  *(u32 *) iph |= htonl (1 << 20);
}









static __inline__ void
TCP_ECN_queue_cwr (struct tcp_opt *tp)
{
  if (tp->ecn_flags & 1)
    tp->ecn_flags |= 2;
}




static __inline__ void
TCP_ECN_send_synack (struct tcp_opt *tp, struct sk_buff *skb)
{
  ((struct tcp_skb_cb *) &((skb)->cb[0]))->flags &= ~0x80;
  if (!(tp->ecn_flags & 1))
    ((struct tcp_skb_cb *) &((skb)->cb[0]))->flags &= ~0x40;
}

static __inline__ void
TCP_ECN_send_syn (struct tcp_opt *tp, struct sk_buff *skb)
{
  tp->ecn_flags = 0;
  if (sysctl_tcp_ecn)
    {
      ((struct tcp_skb_cb *) &((skb)->cb[0]))->flags |= 0x40 | 0x80;
      tp->ecn_flags = 1;
    }
}

static __inline__ void
TCP_ECN_make_synack (struct open_request *req, struct tcphdr *th)
{
  if (req->ecn_ok)
    th->ece = 1;
}

static __inline__ void
TCP_ECN_send (struct sock *sk, struct tcp_opt *tp, struct sk_buff *skb,
	      int tcp_header_len)
{
  if (tp->ecn_flags & 1)
    {

      if (skb->len != tcp_header_len &&
	  !before (((struct tcp_skb_cb *) &((skb)->cb[0]))->seq, tp->snd_nxt))
	{
	  do
	    {
	      (sk)->protinfo.af_inet.tos |= 2;
	    }
	  while (0);
	  if (tp->ecn_flags & 2)
	    {
	      tp->ecn_flags &= ~2;
	      skb->h.th->cwr = 1;
	    }
	}
      else
	{

	  do
	    {
	      (sk)->protinfo.af_inet.tos &= ~3;
	    }
	  while (0);
	}
      if (tp->ecn_flags & 4)
	skb->h.th->ece = 1;
    }
}



static __inline__ void
TCP_ECN_accept_cwr (struct tcp_opt *tp, struct sk_buff *skb)
{
  if (skb->h.th->cwr)
    tp->ecn_flags &= ~4;
}

static __inline__ void
TCP_ECN_withdraw_cwr (struct tcp_opt *tp)
{
  tp->ecn_flags &= ~4;
}

static __inline__ void
TCP_ECN_check_ce (struct tcp_opt *tp, struct sk_buff *skb)
{
  if (tp->ecn_flags & 1)
    {
      if (INET_ECN_is_ce (((struct tcp_skb_cb *) &((skb)->cb[0]))->flags))
	tp->ecn_flags |= 4;



      else
	if (!INET_ECN_is_capable
	    ((((struct tcp_skb_cb *) &((skb)->cb[0]))->flags)))
	tcp_enter_quickack_mode (tp);
    }
}

static __inline__ void
TCP_ECN_rcv_synack (struct tcp_opt *tp, struct tcphdr *th)
{
  if ((tp->ecn_flags & 1) && (!th->ece || th->cwr))
    tp->ecn_flags &= ~1;
}

static __inline__ void
TCP_ECN_rcv_syn (struct tcp_opt *tp, struct tcphdr *th)
{
  if ((tp->ecn_flags & 1) && (!th->ece || !th->cwr))
    tp->ecn_flags &= ~1;
}

static __inline__ int
TCP_ECN_rcv_ecn_echo (struct tcp_opt *tp, struct tcphdr *th)
{
  if (th->ece && !th->syn && (tp->ecn_flags & 1))
    return 1;
  return 0;
}

static __inline__ void
TCP_ECN_openreq_child (struct tcp_opt *tp, struct open_request *req)
{
  tp->ecn_flags = req->ecn_ok ? 1 : 0;
}

static __inline__ void
TCP_ECN_create_request (struct open_request *req, struct tcphdr *th)
{
  if (sysctl_tcp_ecn && th->ece && th->cwr)
    req->ecn_ok = 1;
}







static inline int
tcp_min_write_space (struct sock *sk)
{
  return sk->wmem_queued / 2;
}

static inline int
tcp_wspace (struct sock *sk)
{
  return sk->sndbuf - sk->wmem_queued;
}


static __inline__ unsigned int
tcp_packets_in_flight (struct tcp_opt *tp)
{
  return tp->packets_out - tp->left_out + tp->retrans_out;
}






static inline __u32
tcp_recalc_ssthresh (struct tcp_opt *tp)
{
  return (
	   {
	   const typeof (tp->snd_cwnd >> 1U) _x = (tp->snd_cwnd >> 1U);
	   const typeof (2U) _y = (2U);
	   (void) (&_x == &_y);
	   _x > _y ? _x : _y;
	   });
}





static inline __u32
tcp_current_ssthresh (struct tcp_opt *tp)
{
  if ((1 << tp->ca_state) & ((1 << TCP_CA_CWR) | (1 << TCP_CA_Recovery)))
    return tp->snd_ssthresh;
  else
    return (
	     {
	     const typeof (tp->snd_ssthresh) _x = (tp->snd_ssthresh);
	     const typeof (((tp->snd_cwnd >> 1) + (tp->snd_cwnd >> 2))) _y =
	     (((tp->snd_cwnd >> 1) + (tp->snd_cwnd >> 2)));
	     (void) (&_x == &_y);
	     _x > _y ? _x : _y;
	     });


}

static inline void
tcp_sync_left_out (struct tcp_opt *tp)
{
  if (tp->sack_ok && tp->sacked_out >= tp->packets_out - tp->lost_out)
    tp->sacked_out = tp->packets_out - tp->lost_out;
  tp->left_out = tp->sacked_out + tp->lost_out;
}

extern void tcp_cwnd_application_limited (struct sock *sk);



static inline void
tcp_cwnd_validate (struct sock *sk, struct tcp_opt *tp)
{
  if (tp->packets_out >= tp->snd_cwnd)
    {

      tp->snd_cwnd_used = 0;
      tp->snd_cwnd_stamp = ((__u32) (jiffies));
    }
  else
    {

      if (tp->packets_out > tp->snd_cwnd_used)
	tp->snd_cwnd_used = tp->packets_out;

      if ((s32) (((__u32) (jiffies)) - tp->snd_cwnd_stamp) >= tp->rto)
	tcp_cwnd_application_limited (sk);
    }
}


static inline void
__tcp_enter_cwr (struct tcp_opt *tp)
{
  tp->undo_marker = 0;
  tp->snd_ssthresh = tcp_recalc_ssthresh (tp);
  tp->snd_cwnd = (
		   {
		   const typeof (tp->snd_cwnd) _x = (tp->snd_cwnd);
		   const typeof (tcp_packets_in_flight (tp) + 1U) _y =
		   (tcp_packets_in_flight (tp) + 1U);
		   (void) (&_x == &_y);
		   _x < _y ? _x : _y;
		   });

  tp->snd_cwnd_cnt = 0;
  tp->high_seq = tp->snd_nxt;
  tp->snd_cwnd_stamp = ((__u32) (jiffies));
  TCP_ECN_queue_cwr (tp);
}

static inline void
tcp_enter_cwr (struct tcp_opt *tp)
{
  tp->prior_ssthresh = 0;
  if (tp->ca_state < TCP_CA_CWR)
    {
      __tcp_enter_cwr (tp);
      tp->ca_state = TCP_CA_CWR;
    }
}

extern __u32 tcp_init_cwnd (struct tcp_opt *tp);




static __inline__ __u32
tcp_max_burst (struct tcp_opt *tp)
{
  return 3;
}

static __inline__ int
tcp_minshall_check (struct tcp_opt *tp)
{
  return after (tp->snd_sml, tp->snd_una) &&
    !after (tp->snd_sml, tp->snd_nxt);
}

static __inline__ void
tcp_minshall_update (struct tcp_opt *tp, int mss, struct sk_buff *skb)
{
  if (skb->len < mss)
    tp->snd_sml = ((struct tcp_skb_cb *) &((skb)->cb[0]))->end_seq;
}


static __inline__ int
tcp_nagle_check (struct tcp_opt *tp, struct sk_buff *skb, unsigned mss_now,
		 int nonagle)
{
  return (skb->len < mss_now &&
	  !(((struct tcp_skb_cb *) &((skb)->cb[0]))->flags & 0x01) &&
	  (nonagle == 2 ||
	   (!nonagle && tp->packets_out && tcp_minshall_check (tp))));
}




static __inline__ int
tcp_snd_test (struct tcp_opt *tp, struct sk_buff *skb,
	      unsigned cur_mss, int nonagle)
{

  return ((nonagle == 1 || tp->urg_mode
	   || !tcp_nagle_check (tp, skb, cur_mss, nonagle)) &&
	  ((tcp_packets_in_flight (tp) < tp->snd_cwnd) ||
	   (((struct tcp_skb_cb *) &((skb)->cb[0]))->flags & 0x01)) &&
	  !after (((struct tcp_skb_cb *) &((skb)->cb[0]))->end_seq,
		  tp->snd_una + tp->snd_wnd));
}

static __inline__ void
tcp_check_probe_timer (struct sock *sk, struct tcp_opt *tp)
{
  if (!tp->packets_out && !tp->pending)
    tcp_reset_xmit_timer (sk, 3, tp->rto);
}

static __inline__ int
tcp_skb_is_last (struct sock *sk, struct sk_buff *skb)
{
  return (skb->next == (struct sk_buff *) &sk->write_queue);
}





static __inline__ void
__tcp_push_pending_frames (struct sock *sk,
			   struct tcp_opt *tp, unsigned cur_mss, int nonagle)
{
  struct sk_buff *skb = tp->send_head;

  if (skb)
    {
      if (!tcp_skb_is_last (sk, skb))
	nonagle = 1;
      if (!tcp_snd_test (tp, skb, cur_mss, nonagle) ||
	  tcp_write_xmit (sk, nonagle))
	tcp_check_probe_timer (sk, tp);
    }
  tcp_cwnd_validate (sk, tp);
}

static __inline__ void
tcp_push_pending_frames (struct sock *sk, struct tcp_opt *tp)
{
  __tcp_push_pending_frames (sk, tp, tcp_current_mss (sk), tp->nonagle);
}

static __inline__ int
tcp_may_send_now (struct sock *sk, struct tcp_opt *tp)
{
  struct sk_buff *skb = tp->send_head;

  return (skb &&
	  tcp_snd_test (tp, skb, tcp_current_mss (sk),
			tcp_skb_is_last (sk, skb) ? 1 : tp->nonagle));
}

static __inline__ void
tcp_init_wl (struct tcp_opt *tp, u32 ack, u32 seq)
{
  tp->snd_wl1 = seq;
}

static __inline__ void
tcp_update_wl (struct tcp_opt *tp, u32 ack, u32 seq)
{
  tp->snd_wl1 = seq;
}

extern void tcp_destroy_sock (struct sock *sk);





static __inline__ u16
tcp_v4_check (struct tcphdr *th, int len,
	      unsigned long saddr, unsigned long daddr, unsigned long base)
{
  return csum_tcpudp_magic (saddr, daddr, len, IPPROTO_TCP, base);
}

static __inline__ int
__tcp_checksum_complete (struct sk_buff *skb)
{
  return (unsigned short)
    csum_fold (skb_checksum (skb, 0, skb->len, skb->csum));
}

static __inline__ int
tcp_checksum_complete (struct sk_buff *skb)
{
  return skb->ip_summed != 2 && __tcp_checksum_complete (skb);
}



static __inline__ void
tcp_prequeue_init (struct tcp_opt *tp)
{
  tp->ucopy.task = ((void *) 0);
  tp->ucopy.len = 0;
  tp->ucopy.memory = 0;
  skb_queue_head_init (&tp->ucopy.prequeue);
}


static __inline__ int
tcp_prequeue (struct sock *sk, struct sk_buff *skb)
{
  struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;

  if (!sysctl_tcp_low_latency && tp->ucopy.task)
    {
      __skb_queue_tail (&tp->ucopy.prequeue, skb);
      tp->ucopy.memory += skb->truesize;
      if (tp->ucopy.memory > sk->rcvbuf)
	{
	  struct sk_buff *skb1;

	  if (sk->lock.users)
	    __out_of_line_bug (1399);

	  while ((skb1 = __skb_dequeue (&tp->ucopy.prequeue)) != ((void *) 0))
	    {
	      sk->backlog_rcv (sk, skb1);
	      ((net_statistics)[2 * 0].TCPPrequeueDropped++);
	    }

	  tp->ucopy.memory = 0;
	}
      else if (skb_queue_len (&tp->ucopy.prequeue) == 1)
	{
	  __wake_up ((sk->sleep), 1, 1);
	  if (!tcp_ack_scheduled (tp))
	    tcp_reset_xmit_timer (sk, 2, (3 * ((unsigned) (100 / 5))) / 4);
	}
      return 1;
    }
  return 0;
}


static __inline__ void
tcp_set_state (struct sock *sk, int state)
{
  int oldstate = sk->state;

  switch (state)
    {
    case TCP_ESTABLISHED:
      if (oldstate != TCP_ESTABLISHED)
	((tcp_statistics)
	 [2 * 0 +
	  !(((void) ((0)),
	     irq_stat[0].__local_bh_count) != 0)].TcpCurrEstab++);
      break;

    case TCP_CLOSE:
      if (oldstate == TCP_CLOSE_WAIT || oldstate == TCP_ESTABLISHED)
	((tcp_statistics)
	 [2 * 0 +
	  !(((void) ((0)),
	     irq_stat[0].__local_bh_count) != 0)].TcpEstabResets++);

      sk->prot->unhash (sk);
      if (sk->prev && !(sk->userlocks & 8))
	tcp_put_port (sk);

    default:
      if (oldstate == TCP_ESTABLISHED)
	tcp_statistics[0 * 2 +
		       !(((void) ((0)),
			  irq_stat[0].__local_bh_count) != 0)].TcpCurrEstab--;
    }




  sk->state = state;




}

static __inline__ void
tcp_done (struct sock *sk)
{
  tcp_set_state (sk, TCP_CLOSE);
  tcp_clear_xmit_timers (sk);

  sk->shutdown = 3;

  if (!sk->dead)
    sk->state_change (sk);
  else
    tcp_destroy_sock (sk);
}

static __inline__ void
tcp_sack_reset (struct tcp_opt *tp)
{
  tp->dsack = 0;
  tp->eff_sacks = 0;
  tp->num_sacks = 0;
}

static __inline__ void
tcp_build_and_update_options (__u32 * ptr, struct tcp_opt *tp, __u32 tstamp)
{
  if (tp->tstamp_ok)
    {
      *ptr++ =
	((__u32)
	 ((((__u32) (((1 << 24) | (1 << 16) | (8 << 8) | 10)) & (__u32)
	    0x000000ffUL) << 24) |
	  (((__u32) (((1 << 24) | (1 << 16) | (8 << 8) | 10)) & (__u32)
	    0x0000ff00UL) << 8) |
	  (((__u32) (((1 << 24) | (1 << 16) | (8 << 8) | 10)) & (__u32)
	    0x00ff0000UL) >> 8) |
	  (((__u32) (((1 << 24) | (1 << 16) | (8 << 8) | 10)) & (__u32)
	    0xff000000UL) >> 24)));



      *ptr++ = htonl (tstamp);
      *ptr++ = htonl (tp->ts_recent);
    }
  if (tp->eff_sacks)
    {
      struct tcp_sack_block *sp =
	tp->dsack ? tp->duplicate_sack : tp->selective_acks;
      int this_sack;

      *ptr++ =
	((__u32)
	 ((((__u32)
	    (((1 << 24) | (1 << 16) | (5 << 8) | (2 + (tp->eff_sacks * 8)))) &
	    (__u32) 0x000000ffUL) << 24) |
	  (((__u32)
	    (((1 << 24) | (1 << 16) | (5 << 8) | (2 + (tp->eff_sacks * 8)))) &
	    (__u32) 0x0000ff00UL) << 8) |
	  (((__u32)
	    (((1 << 24) | (1 << 16) | (5 << 8) | (2 + (tp->eff_sacks * 8)))) &
	    (__u32) 0x00ff0000UL) >> 8) |
	  (((__u32)
	    (((1 << 24) | (1 << 16) | (5 << 8) | (2 + (tp->eff_sacks * 8)))) &
	    (__u32) 0xff000000UL) >> 24)));




      for (this_sack = 0; this_sack < tp->eff_sacks; this_sack++)
	{
	  *ptr++ = htonl (sp[this_sack].start_seq);
	  *ptr++ = htonl (sp[this_sack].end_seq);
	}
      if (tp->dsack)
	{
	  tp->dsack = 0;
	  tp->eff_sacks--;
	}
    }
}






static inline void
tcp_syn_build_options (__u32 * ptr, int mss, int ts, int sack,
		       int offer_wscale, int wscale, __u32 tstamp,
		       __u32 ts_recent)
{

  *ptr++ = htonl ((2 << 24) | (4 << 16) | mss);
  if (ts)
    {
      if (sack)
	*ptr++ =
	  ((__u32)
	   ((((__u32) (((4 << 24) | (2 << 16) | (8 << 8) | 10)) & (__u32)
	      0x000000ffUL) << 24) |
	    (((__u32) (((4 << 24) | (2 << 16) | (8 << 8) | 10)) & (__u32)
	      0x0000ff00UL) << 8) |
	    (((__u32) (((4 << 24) | (2 << 16) | (8 << 8) | 10)) & (__u32)
	      0x00ff0000UL) >> 8) |
	    (((__u32) (((4 << 24) | (2 << 16) | (8 << 8) | 10)) & (__u32)
	      0xff000000UL) >> 24)));

      else
	*ptr++ =
	  ((__u32)
	   ((((__u32) (((1 << 24) | (1 << 16) | (8 << 8) | 10)) & (__u32)
	      0x000000ffUL) << 24) |
	    (((__u32) (((1 << 24) | (1 << 16) | (8 << 8) | 10)) & (__u32)
	      0x0000ff00UL) << 8) |
	    (((__u32) (((1 << 24) | (1 << 16) | (8 << 8) | 10)) & (__u32)
	      0x00ff0000UL) >> 8) |
	    (((__u32) (((1 << 24) | (1 << 16) | (8 << 8) | 10)) & (__u32)
	      0xff000000UL) >> 24)));

      *ptr++ = htonl (tstamp);
      *ptr++ = htonl (ts_recent);
    }
  else if (sack)
    *ptr++ =
      ((__u32)
       ((((__u32) (((1 << 24) | (1 << 16) | (4 << 8) | 2)) & (__u32)
	  0x000000ffUL) << 24) |
	(((__u32) (((1 << 24) | (1 << 16) | (4 << 8) | 2)) & (__u32)
	  0x0000ff00UL) << 8) |
	(((__u32) (((1 << 24) | (1 << 16) | (4 << 8) | 2)) & (__u32)
	  0x00ff0000UL) >> 8) |
	(((__u32) (((1 << 24) | (1 << 16) | (4 << 8) | 2)) & (__u32)
	  0xff000000UL) >> 24)));

  if (offer_wscale)
    *ptr++ = htonl ((1 << 24) | (3 << 16) | (3 << 8) | (wscale));
}


static inline void
tcp_select_initial_window (int __space, __u32 mss,
			   __u32 * rcv_wnd,
			   __u32 * window_clamp,
			   int wscale_ok, __u8 * rcv_wscale)
{
  unsigned int space = (__space < 0 ? 0 : __space);


  if (*window_clamp == 0)
    (*window_clamp) = (65535 << 14);
  space = (
	    {
	    const typeof (*window_clamp) _x = (*window_clamp);
	    const typeof (space) _y = (space);
	    (void) (&_x == &_y);
	    _x < _y ? _x : _y;
	    });


  if (space > mss)
    space = (space / mss) * mss;







  (*rcv_wnd) = (
		 {
		 const typeof (space) _x = (space);
		 const typeof (32767U) _y = (32767U);
		 (void) (&_x == &_y);
		 _x < _y ? _x : _y;
		 });
  (*rcv_wscale) = 0;
  if (wscale_ok)
    {

      while (space > 65535 && (*rcv_wscale) < 14)
	{
	  space >>= 1;
	  (*rcv_wscale)++;
	}
      if (*rcv_wscale && sysctl_tcp_app_win && space >= mss && space - (
									 {
									 const
									 typeof
									 ((space >> sysctl_tcp_app_win)) _x = ((space >> sysctl_tcp_app_win)); const typeof (mss >> *rcv_wscale) _y = (mss >> *rcv_wscale); (void) (&_x == &_y); _x > _y ? _x : _y;}) < 65536 / 2)
	(*rcv_wscale)--;
    }





  if (mss > (1 << *rcv_wscale))
    {
      int init_cwnd = 4;
      if (mss > 1460 * 3)
	init_cwnd = 2;
      else if (mss > 1460)
	init_cwnd = 3;
      if (*rcv_wnd > init_cwnd * mss)
	*rcv_wnd = init_cwnd * mss;
    }

  (*window_clamp) = (
		      {
		      const typeof (65535U << (*rcv_wscale)) _x =
		      (65535U << (*rcv_wscale));
		      const typeof (*window_clamp) _y = (*window_clamp);
		      (void) (&_x == &_y);
		      _x < _y ? _x : _y;
		      });
}

static inline int
tcp_win_from_space (int space)
{
  return sysctl_tcp_adv_win_scale <= 0 ?
    (space >> (-sysctl_tcp_adv_win_scale)) :
    space - (space >> sysctl_tcp_adv_win_scale);
}


static inline int
tcp_space (struct sock *sk)
{
  return tcp_win_from_space (sk->rcvbuf - ((&sk->rmem_alloc)->counter));
}

static inline int
tcp_full_space (struct sock *sk)
{
  return tcp_win_from_space (sk->rcvbuf);
}

static inline void
tcp_acceptq_removed (struct sock *sk)
{
  sk->ack_backlog--;
}

static inline void
tcp_acceptq_added (struct sock *sk)
{
  sk->ack_backlog++;
}

static inline int
tcp_acceptq_is_full (struct sock *sk)
{
  return sk->ack_backlog > sk->max_ack_backlog;
}

static inline void
tcp_acceptq_queue (struct sock *sk, struct open_request *req,
		   struct sock *child)
{
  struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;

  req->sk = child;
  tcp_acceptq_added (sk);

  if (!tp->accept_queue_tail)
    {
      tp->accept_queue = req;
    }
  else
    {
      tp->accept_queue_tail->dl_next = req;
    }
  tp->accept_queue_tail = req;
  req->dl_next = ((void *) 0);
}

struct tcp_listen_opt
{
  u8 max_qlen_log;
  int qlen;
  int qlen_young;
  int clock_hand;
  u32 hash_rnd;
  struct open_request *syn_table[512];
};

static inline void
tcp_synq_removed (struct sock *sk, struct open_request *req)
{
  struct tcp_listen_opt *lopt = sk->tp_pinfo.af_tcp.listen_opt;

  if (--lopt->qlen == 0)
    tcp_delete_keepalive_timer (sk);
  if (req->retrans == 0)
    lopt->qlen_young--;
}

static inline void
tcp_synq_added (struct sock *sk)
{
  struct tcp_listen_opt *lopt = sk->tp_pinfo.af_tcp.listen_opt;

  if (lopt->qlen++ == 0)
    tcp_reset_keepalive_timer (sk, ((unsigned) (3 * 100)));
  lopt->qlen_young++;
}

static inline int
tcp_synq_len (struct sock *sk)
{
  return sk->tp_pinfo.af_tcp.listen_opt->qlen;
}

static inline int
tcp_synq_young (struct sock *sk)
{
  return sk->tp_pinfo.af_tcp.listen_opt->qlen_young;
}

static inline int
tcp_synq_is_full (struct sock *sk)
{
  return tcp_synq_len (sk) >> sk->tp_pinfo.af_tcp.listen_opt->max_qlen_log;
}

static inline void
tcp_synq_unlink (struct tcp_opt *tp, struct open_request *req,
		 struct open_request **prev)
{
  (void) (&tp->syn_wait_lock);
  *prev = req->dl_next;
  do
    {
    }
  while (0);
}

static inline void
tcp_synq_drop (struct sock *sk, struct open_request *req,
	       struct open_request **prev)
{
  tcp_synq_unlink (&sk->tp_pinfo.af_tcp, req, prev);
  tcp_synq_removed (sk, req);
  tcp_openreq_free (req);
}

static __inline__ void
tcp_openreq_init (struct open_request *req,
		  struct tcp_opt *tp, struct sk_buff *skb)
{
  req->rcv_wnd = 0;
  req->rcv_isn = ((struct tcp_skb_cb *) &((skb)->cb[0]))->seq;
  req->mss = tp->mss_clamp;
  req->ts_recent = tp->saw_tstamp ? tp->rcv_tsval : 0;
  req->tstamp_ok = tp->tstamp_ok;
  req->sack_ok = tp->sack_ok;
  req->snd_wscale = tp->snd_wscale;
  req->wscale_ok = tp->wscale_ok;
  req->acked = 0;
  req->ecn_ok = 0;
  req->rmt_port = skb->h.th->source;
}



static inline void
tcp_free_skb (struct sock *sk, struct sk_buff *skb)
{
  sk->tp_pinfo.af_tcp.queue_shrunk = 1;
  sk->wmem_queued -= skb->truesize;
  sk->forward_alloc += skb->truesize;
  __kfree_skb (skb);
}

static inline void
tcp_charge_skb (struct sock *sk, struct sk_buff *skb)
{
  sk->wmem_queued += skb->truesize;
  sk->forward_alloc -= skb->truesize;
}

extern void __tcp_mem_reclaim (struct sock *sk);
extern int tcp_mem_schedule (struct sock *sk, int size, int kind);

static inline void
tcp_mem_reclaim (struct sock *sk)
{
  if (sk->forward_alloc >= ((int) (1UL << 12)))
    __tcp_mem_reclaim (sk);
}

static inline void
tcp_enter_memory_pressure (void)
{
  if (!tcp_memory_pressure)
    {
      ((net_statistics)
       [2 * 0 +
	!(((void) ((0)),
	   irq_stat[0].__local_bh_count) != 0)].TCPMemoryPressures++);
      tcp_memory_pressure = 1;
    }
}

static inline void
tcp_moderate_sndbuf (struct sock *sk)
{
  if (!(sk->userlocks & 1))
    {
      sk->sndbuf = (
		     {
		     const typeof (sk->sndbuf) _x = (sk->sndbuf);
		     const typeof (sk->wmem_queued / 2) _y =
		     (sk->wmem_queued / 2);
		     (void) (&_x == &_y);
		     _x < _y ? _x : _y;
		     });
      sk->sndbuf = (
		     {
		     const typeof (sk->sndbuf) _x = (sk->sndbuf);
		     const typeof (2048) _y = (2048);
		     (void) (&_x == &_y);
		     _x > _y ? _x : _y;
		     });
    }
}

static inline struct sk_buff *
tcp_alloc_pskb (struct sock *sk, int size, int mem, int gfp)
{
  struct sk_buff *skb = alloc_skb (size + (128 + 32), gfp);

  if (skb)
    {
      skb->truesize += mem;
      if (sk->forward_alloc >= (int) skb->truesize ||
	  tcp_mem_schedule (sk, skb->truesize, 0))
	{
	  skb_reserve (skb, (128 + 32));
	  return skb;
	}
      __kfree_skb (skb);
    }
  else
    {
      tcp_enter_memory_pressure ();
      tcp_moderate_sndbuf (sk);
    }
  return ((void *) 0);
}

static inline struct sk_buff *
tcp_alloc_skb (struct sock *sk, int size, int gfp)
{
  return tcp_alloc_pskb (sk, size, 0, gfp);
}

static inline struct page *
tcp_alloc_page (struct sock *sk)
{
  if (sk->forward_alloc >= (int) (1UL << 12) ||
      tcp_mem_schedule (sk, (1UL << 12), 0))
    {
      struct page *page = alloc_pages (sk->allocation, 0);
      if (page)
	return page;
    }
  tcp_enter_memory_pressure ();
  tcp_moderate_sndbuf (sk);
  return ((void *) 0);
}

static inline void
tcp_writequeue_purge (struct sock *sk)
{
  struct sk_buff *skb;

  while ((skb = __skb_dequeue (&sk->write_queue)) != ((void *) 0))
    tcp_free_skb (sk, skb);
  tcp_mem_reclaim (sk);
}

extern void tcp_rfree (struct sk_buff *skb);

static inline void
tcp_set_owner_r (struct sk_buff *skb, struct sock *sk)
{
  skb->sk = sk;
  skb->destructor = tcp_rfree;
  atomic_add (skb->truesize, &sk->rmem_alloc);
  sk->forward_alloc -= skb->truesize;
}

extern void tcp_listen_wlock (void);






static inline void
tcp_listen_lock (void)
{

  (void) (&(tcp_hashinfo.__tcp_lhash_lock));
  atomic_inc (&(tcp_hashinfo.__tcp_lhash_users));
  do
    {
    }
  while (0);
}

static inline void
tcp_listen_unlock (void)
{
  if (atomic_dec_and_test (&(tcp_hashinfo.__tcp_lhash_users)))
    __wake_up ((&(tcp_hashinfo.__tcp_lhash_wait)), 2 | 1, 1);
}

static inline int
keepalive_intvl_when (struct tcp_opt *tp)
{
  return tp->keepalive_intvl ? : sysctl_tcp_keepalive_intvl;
}

static inline int
keepalive_time_when (struct tcp_opt *tp)
{
  return tp->keepalive_time ? : sysctl_tcp_keepalive_time;
}

static inline int
tcp_fin_time (struct tcp_opt *tp)
{
  int fin_timeout = tp->linger2 ? : sysctl_tcp_fin_timeout;

  if (fin_timeout < (tp->rto << 2) - (tp->rto >> 1))
    fin_timeout = (tp->rto << 2) - (tp->rto >> 1);

  return fin_timeout;
}

static inline int
tcp_paws_check (struct tcp_opt *tp, int rst)
{
  if ((s32) (tp->rcv_tsval - tp->ts_recent) >= 0)
    return 0;
  if (xtime.tv_sec >= tp->ts_recent_stamp + (60 * 60 * 24 * 24))
    return 0;

  if (rst && xtime.tv_sec >= tp->ts_recent_stamp + 60)
    return 0;
  return 1;
}



static inline int
tcp_use_frto (const struct sock *sk)
{
  const struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;





  return (sysctl_tcp_frto && tp->send_head &&
	  !after (((struct tcp_skb_cb *) &((tp->send_head)->cb[0]))->end_seq,
		  tp->snd_una + tp->snd_wnd));
}

static inline void
tcp_mib_init (void)
{

  ((tcp_statistics)[2 * 0 + 1].TcpRtoAlgorithm += 1);
  ((tcp_statistics)[2 * 0 + 1].TcpRtoMin +=
   ((unsigned) (100 / 5)) * 1000 / 100);
  ((tcp_statistics)[2 * 0 + 1].TcpRtoMax +=
   ((unsigned) (120 * 100)) * 1000 / 100);
  ((tcp_statistics)[2 * 0 + 1].TcpMaxConn += -1);
}







static inline void
tcp_westwood_update_rtt (struct tcp_opt *tp, __u32 rtt_seq)
{
  if (sysctl_tcp_westwood)
    tp->westwood.rtt = rtt_seq;
}

void __tcp_westwood_fast_bw (struct sock *, struct sk_buff *);
void __tcp_westwood_slow_bw (struct sock *, struct sk_buff *);

static inline void
__tcp_init_westwood (struct sock *sk)
{
  struct tcp_opt *tp = &(sk->tp_pinfo.af_tcp);

  tp->westwood.bw_ns_est = 0;
  tp->westwood.bw_est = 0;
  tp->westwood.accounted = 0;
  tp->westwood.cumul_ack = 0;
  tp->westwood.rtt_win_sx = ((__u32) (jiffies));
  tp->westwood.rtt = 20 * 100;
  tp->westwood.rtt_min = 20 * 100;
  tp->westwood.snd_una = tp->snd_una;
}

static inline void
tcp_init_westwood (struct sock *sk)
{
  __tcp_init_westwood (sk);
}

static inline void
tcp_westwood_fast_bw (struct sock *sk, struct sk_buff *skb)
{
  if (sysctl_tcp_westwood)
    __tcp_westwood_fast_bw (sk, skb);
}

static inline void
tcp_westwood_slow_bw (struct sock *sk, struct sk_buff *skb)
{
  if (sysctl_tcp_westwood)
    __tcp_westwood_slow_bw (sk, skb);
}

static inline __u32
__tcp_westwood_bw_rttmin (struct tcp_opt *tp)
{
  return (__u32) ((tp->westwood.bw_est) * (tp->westwood.rtt_min) /
		  (__u32) (tp->mss_cache));
}

static inline __u32
tcp_westwood_bw_rttmin (struct tcp_opt *tp)
{
  __u32 ret = 0;

  if (sysctl_tcp_westwood)
    ret = (__u32) ((
		     {
		     const typeof (__tcp_westwood_bw_rttmin (tp)) _x =
		     (__tcp_westwood_bw_rttmin (tp));
		     const typeof (2U) _y = (2U);
		     (void) (&_x == &_y);
		     _x > _y ? _x : _y;
		     }
		   ));

  return ret;
}

static inline int
tcp_westwood_ssthresh (struct tcp_opt *tp)
{
  int ret = 0;
  __u32 ssthresh;

  if (sysctl_tcp_westwood)
    {
      if (!(ssthresh = tcp_westwood_bw_rttmin (tp)))
	return ret;

      tp->snd_ssthresh = ssthresh;
      ret = 1;
    }

  return ret;
}

static inline int
tcp_westwood_cwnd (struct tcp_opt *tp)
{
  int ret = 0;
  __u32 cwnd;

  if (sysctl_tcp_westwood)
    {
      if (!(cwnd = tcp_westwood_bw_rttmin (tp)))
	return ret;

      tp->snd_cwnd = cwnd;
      ret = 1;
    }

  return ret;
}

static inline int
tcp_westwood_complete_cwr (struct tcp_opt *tp)
{
  int ret = 0;

  if (sysctl_tcp_westwood)
    {
      if (tcp_westwood_cwnd (tp))
	{
	  tp->snd_ssthresh = tp->snd_cwnd;
	  ret = 1;
	}
    }

  return ret;
}









extern const int generateHMAC;
extern const int generateNonces;













typedef struct MD5state_st
{
  unsigned int A, B, C, D;
  unsigned int Nl, Nh;
  unsigned int data[(64 / 4)];
  int num;
} MD5_CTX;

void MD5_Init (MD5_CTX * c);
void MD5_Update (MD5_CTX * c, const void *data, unsigned long len);
void MD5_Final (unsigned char *md, MD5_CTX * c);
unsigned char *MD5 (const unsigned char *d, unsigned long n,
		    unsigned char *md);
void MD5_Transform (MD5_CTX * c, const unsigned char *b);












typedef unsigned char aes_08t;





typedef unsigned int aes_32t;

typedef struct aes_encrypt_ctx
{
  aes_32t ks[60];
  aes_32t rn;
} aes_encrypt_ctx;

typedef struct aes_decrypt_ctx
{
  aes_32t ks[60];
  aes_32t rn;
} aes_decrypt_ctx;




void gen_tabs (void);







int aes_encrypt_key128 (const unsigned char *in_key, aes_encrypt_ctx cx[1]);



int aes_encrypt_key192 (const unsigned char *in_key, aes_encrypt_ctx cx[1]);



int aes_encrypt_key256 (const unsigned char *in_key, aes_encrypt_ctx cx[1]);



int aes_encrypt_key (const unsigned char *in_key, int key_len,
		     aes_encrypt_ctx cx[1]);


int aes_encrypt (const unsigned char *in_blk, unsigned char *out_blk,
		 const aes_encrypt_ctx cx[1]);





int aes_decrypt_key128 (const unsigned char *in_key, aes_decrypt_ctx cx[1]);



int aes_decrypt_key192 (const unsigned char *in_key, aes_decrypt_ctx cx[1]);



int aes_decrypt_key256 (const unsigned char *in_key, aes_decrypt_ctx cx[1]);



int aes_decrypt_key (const unsigned char *in_key, int key_len,
		     aes_decrypt_ctx cx[1]);


int aes_decrypt (const unsigned char *in_blk, unsigned char *out_blk,
		 const aes_decrypt_ctx cx[1]);



typedef MD5_CTX DIGEST_CTX;



struct TricklesLossEvent
{







  __u32 valid:1;
  __u32 cwnd:7;
  __u32 extra:5;
  __u32 state:3;
  __u32 time:24;
} __attribute__ ((packed));


extern int sysctl_dbg_cwnd;

struct TricklesProcLogEntry
{
  struct cminisock *prev;
  struct cminisock *next;
  struct alloc_head_list *list;

  __u32 addr;
  __u16 port;
  unsigned rcv_nxt;
  unsigned t_rcv_nxt;
  struct TricklesLossEvent *events;
  int size;
  int returnedEvents;
  int sentAmount;
};

extern struct alloc_head_list tricklesProcLogHead;

int trickles_read_proc (char *page, char **start, off_t offset, int count,
			int *eof, void *data);

enum LogCwndType
{
  CWND_RECORD, CONTINUATION_RECORD, EVENT_RECORD, PACKET_RECORD
};

struct TricklesCwndProcLogEntry
{
  struct cminisock *prev;
  struct cminisock *next;
  struct alloc_head_list *list;

  enum LogCwndType type;

  __u32 addr;
  __u32 port;
  __u32 seq;
  __u32 ack_seq;
  __u32 startCwnd;
  __u32 effCwnd;
  __u32 ssthresh;




  unsigned int s;
  unsigned int us;

  int rtt, srtt;

  int sentAmount;
};

extern struct alloc_head_list tricklesCwndProcLogHead;
extern spinlock_t cwndLogLock;

int trickles_cwnd_read_proc (char *page, char **start, off_t offset,
			     int count, int *eof, void *data);

extern void
  (*trickles_logCwnd_hook) (enum LogCwndType type, int addr, int port,
			    int seq, int ack_seq, int startCwnd, int effCwnd,
			    int ssthresh, int rtt, int srtt);

enum LogCwndType;
void trickles_logCwnd_impl (enum LogCwndType type, int addr, int port,
			    int seq, int ack_seq,
			    int startCwnd, int effCwnd, int ssthresh,
			    int rtt, int srtt);
void trickles_logCwnd_default (enum LogCwndType type, int addr, int port,
			       int seq, int ack_seq,
			       int startCwnd, int effCwnd, int ssthresh,
			       int rtt, int srtt);


typedef struct HMAC_CTX
{
  char key[64];
  DIGEST_CTX in_ctx;
  DIGEST_CTX out_ctx;
  DIGEST_CTX digest_ctx;
  int len;
} HMAC_CTX;

const static int net_msg_cost = 5 * 100;
const static int net_msg_burst = 10 * 5 * 100;

extern int sysctl_trickles_mss;

void hmac_setup (HMAC_CTX * ctx, char *key, int len);
void hmac_init (HMAC_CTX * ctx);
void hmac_update (HMAC_CTX * ctx, void *data, int len);
void hmac_final (HMAC_CTX * ctx, char *output);

extern struct tcp_func ipv4_specific;
extern struct or_calltable or_ipv4;

extern struct proto trickles_prot;
extern struct proto trickles_client_prot;
extern spinlock_t trickles_sockets_head_lock;
extern struct sock trickles_sockets_head;



extern int enableDataRecovery;
extern int serverDebugLevel;
extern int debugDrops;
extern int debugProofDrops;
extern int debugTransitions;
extern int clientDebugLevel;
extern int disableSevereErrors;
extern int printOverlap;
extern int disableTimeout;
extern int debugSimulation;

extern int userapi_pkt_spew;
extern int userapi_time_spew;


extern __u64 numTxPackets;
extern __u64 numTxBytes;

extern __u64 numTxPackets;
extern __u64 numTxBytes;







static inline void
trickles_checksum (struct sk_buff *skb, int headerLen)
{
  struct sock *sk = skb->sk;




  if (skb->ip_summed == 1)
    {

      skb->h.th->check = 0;
      skb->h.th->check =
	~tcp_v4_check (skb->h.th, skb->len, sk->saddr, sk->daddr, 0);
      skb->csum = ((size_t) & ((struct tcphdr *) 0)->check);
    }
  else
    {
      skb->h.th->check = 0;
      skb->h.th->check =
	tcp_v4_check (skb->h.th, skb->len, sk->saddr, sk->daddr,
		      csum_partial ((char *) skb->h.th, headerLen,
				    skb->csum));
    }
}


void user_ack_impl (struct sock *sk);
void slow_start_timer (unsigned long data);
int trickles_send_ack_impl (struct sock *sk, int user_ctx);
int trickles_client_sendmsg (struct sock *sk, struct msghdr *msg, int size);
void computeMAC (struct sock *sk, PseudoHeader * phdr,
		 const WireContinuation * cont, char *dest);

struct NonceCtx
{
  int new;
  __u64 prevNumber;
  char prevBlock[(16)];
};

__u32 generateSingleNonce (struct sock *sk, __u64 seqNum,
			   struct NonceCtx *prevCtx);
__u32 generateRangeNonce (struct sock *sk, __u64 seqNumLeft,
			  __u64 seqNumRight);




enum CheckRangeResult
{
  BADRANGE = 0,
  POISONEDRANGE = -1,
  NORMALRANGE = 1
};

enum CheckRangeResult AckProof_checkRange (AckProof * proof, int left,
					   int right);

int AckProof_update (struct sock *sk, AckProof * ackProof,
		     struct cminisock *cont);
__u32 AckProof_findLeft (AckProof * proof, int start);
__u32 AckProof_findRight (AckProof * proof, int start);

int msk_transmit_skb (struct cminisock *msk, struct sk_buff *skb,
		      int packet_num);

int server_rcv_impl (struct sock *sk, struct sk_buff *in_skb);
int client_rcv_impl (struct sock *sk, struct sk_buff *in_skb);

void zap_virt (void *address);

void *tmalloc (struct sock *sk, size_t size);
void tfree (struct sock *sk, void *ptr);






void trickles_add_clientsock (struct sock *sk);
void trickles_del_clientsock (struct sock *sk);

void queueConversionRequests (struct sock *sk);
void pushRequests (struct sock *sk);
void finishIncompleteRequest (struct sock *sk);

int addNewUC_Continuation (struct sock *sk, struct UC_Continuation *newCont);
struct RequestOFOEntry;
void CompleteRequest_finish (struct sock *sk, struct cminisock *cont,
			     char *ucont_start, int ucont_len,
			     struct WireUC_CVT_CompleteResponse *completeResp,
			     struct RequestOFOEntry *ofo_entry);


int CompleteRequest_parallel_queue (struct sock *sk, struct sk_buff *skb,
				    int reserve_len);

inline void cleanTxQueue (struct sock *sk);

extern int gSocketConversionCount;

void SK_ucontList_dump (struct sock *sk);
void SK_data_ofo_queue_dump (struct sock *sk);
void SK_skiplist_dump (struct sock *sk);
void SK_data_request_dump_helper (struct alloc_head_list *list, int lim);
void SK_data_request_dump (struct sock *sk);
void SK_request_dump_helper (struct alloc_head_list *list);
void SK_request_dump (struct sock *sk);
void SK_dump_vars (struct sock *sk);

struct ConversionRequest *kmalloc_ConversionRequest (int gfp);
void freeRequest (struct Request *req);

struct DataRequestMapping
{
  struct DataRequestMapping *prev;
  struct DataRequestMapping *next;
  struct alloc_head_list *list;

  struct UC_Continuation *ucont;
  unsigned sent;
  int completed;

  unsigned transportResponseSeqStart, transportResponseSeqEnd;

  unsigned start, end;

  unsigned timestamp;
};

static inline void
submitDataRequestMapping (struct sock *sk, struct DataRequestMapping *dataReq,
			  unsigned newStart, unsigned newEnd)
{
  struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;
  if (!(dataReq->list == ((void *) 0)))
    {
      printk ("KERNEL: assertion (" "dataReq->list == NULL" ") failed at "
	      "/home/ashieh/current/include/net/trickles_client.h" "(%d)\n",
	      73);
    };
  dataReq->completed = 0;
  dataReq->sent = 0;


  dataReq->transportResponseSeqStart = (4294967295U);
  dataReq->transportResponseSeqEnd = (4294967295U);
  dataReq->timestamp = (4294967295U);
  dataReq->start = newStart;
  dataReq->end = newEnd;
  insert_tail (&tp->t.missingDataMap, (struct alloc_head *) dataReq);
}

static inline void
submitDerivedDataRequestMapping (struct sock *sk,
				 struct DataRequestMapping *oldReqMap,
				 unsigned start, unsigned end)
{
  struct DataRequestMapping *newMap =
    kmalloc (sizeof (struct DataRequestMapping), (0x20));
  *newMap = *oldReqMap;
  if (newMap == ((void *) 0))
    {
      if (!disableSevereErrors)
	{
	  printk ("emitDerivedDataRequest: out of memory\n");
	}
      return;
    }
  submitDataRequestMapping (sk, newMap, start, end);
}



extern int numDataRequestMappings;

static inline struct DataRequestMapping *
newDataRequestMapping (struct UC_Continuation *ucont, unsigned tseq_start,
		       unsigned tseq_end, unsigned start, unsigned end)
{

  struct DataRequestMapping *newMapping =
    kmalloc (sizeof (struct DataRequestMapping), (0x20));
  if (newMapping == ((void *) 0))
    return ((void *) 0);
  newMapping->next = newMapping->prev = ((void *) 0);
  newMapping->list = ((void *) 0);

  newMapping->completed = 0;
  newMapping->ucont = ucont;
  newMapping->transportResponseSeqStart = tseq_start;
  newMapping->transportResponseSeqEnd = tseq_end;
  newMapping->sent = 0;
  newMapping->start = start;
  newMapping->end = end;

  newMapping->timestamp = jiffies;


  numDataRequestMappings++;
  return newMapping;
}

static inline void
freeDataRequestMapping (struct DataRequestMapping *dataReq)
{
  numDataRequestMappings--;
  kfree (dataReq);
}






enum UserRequestType
{

  MREQ_WILD,
  MREQ_CONVERSION,
  MREQ_CONTINUATION,
};

struct Request
{

  struct alloc_head *prev;
  struct alloc_head *next;
  struct alloc_head_list *list;
  enum UserRequestType type;
  unsigned numChildren;
  unsigned numActualChildren;
  unsigned childrenMask:4;
  struct
  {
    __u32 start, end;
  } childRanges[4];
  unsigned transport_seq;
  unsigned seq;
  unsigned start, end;
  unsigned isNew:1;
  unsigned allocated:1;
  unsigned transportResponseSeqStart, transportResponseSeqEnd;
};

static inline void
resetRequest (struct Request *req)
{
  req->numChildren = 0;
  req->numActualChildren = 0;
  req->childrenMask = 0;
  req->transport_seq = -1;
  req->seq = -1;
  req->isNew = 1;
}

static inline void
initRequest (struct Request *req, enum UserRequestType type)
{

  req->type = type;
  req->prev = req->next = ((void *) 0);
  req->list = ((void *) 0);
  resetRequest (req);
  req->start = req->end = -1;
  req->allocated = 1;
}

void resetClientTimer (struct sock *sk);

static inline void
queueNewRequest (struct sock *sk, struct Request *req)
{
  struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;
  insert_tail (&tp->t.queuedRequests, (struct alloc_head *) req);
  tp->t.timerState |= (0x1);
  resetClientTimer (sk);
}

struct ConversionRequest
{
  struct alloc_head *prev;
  struct alloc_head *next;
  struct alloc_head_list *list;
  enum UserRequestType type;
  unsigned numChildren;
  unsigned numActualChildren;
  unsigned childrenMask:4;
  struct
  {
    __u32 start, end;
  } childRanges[4];
  unsigned transport_seq;
  unsigned seq;
  unsigned start, end;
  unsigned isNew:1;
  unsigned allocated:1;
  unsigned transportResponseSeqStart, transportResponseSeqEnd;

  _bool incomplete;

  struct sk_buff *data;

  unsigned offset;






  unsigned predLength;
  unsigned parallelStart;
  unsigned ident;
  union
  {
    struct WireUC_CVT_IncompleteContinuation *incompletePred;
    struct UC_Continuation *completePred;
  };
};

static inline void
initCompleteConversionRequest (struct ConversionRequest *req,
			       struct UC_Continuation *pred,
			       struct sk_buff *data, unsigned start)
{
  initRequest ((struct Request *) req, MREQ_CONVERSION);
  req->incomplete = 0;
  req->completePred = pred;
  if (req->completePred != ((void *) 0))
    {
      atomic_inc (&req->completePred->refcnt);

      if (((&req->completePred->refcnt)->counter) < 2)
	{
	  printk ("refcnt should be > 1!\n");
	  do
	    {
	      if (!(0))
		{
		  printk ("kgdb assertion failed: %s\n", "BUG");
		  show_stack (((void *) 0));
		  breakpoint ();
		}
	    }
	  while (0);
	}
    }

  req->data = data;
  req->start = start;
  req->offset = req->start - ((struct tcp_skb_cb *) &((data)->cb[0]))->seq;
}

static inline void
initIncompleteConversionRequest (struct ConversionRequest *req,
				 struct WireUC_CVT_IncompleteContinuation
				 *pred, unsigned predLength,
				 struct sk_buff *data, unsigned offset)
{
  initRequest ((struct Request *) req, MREQ_CONVERSION);
  req->incomplete = 1;
  req->incompletePred = pred;
  req->predLength = predLength;
  req->data = data;
  req->offset = offset;
}

struct ContinuationRequest
{
  struct alloc_head *prev;
  struct alloc_head *next;
  struct alloc_head_list *list;
  enum UserRequestType type;
  unsigned numChildren;
  unsigned numActualChildren;
  unsigned childrenMask:4;
  struct
  {
    __u32 start, end;
  } childRanges[4];
  unsigned transport_seq;
  unsigned seq;
  unsigned start, end;
  unsigned isNew:1;
  unsigned allocated:1;
  unsigned transportResponseSeqStart, transportResponseSeqEnd;






  unsigned numConts;
  struct UC_Continuation **conts;
};

static inline int
initContinuationRequest (struct ContinuationRequest *req, unsigned start,
			 unsigned end, int numConts)
{
  initRequest ((struct Request *) req, MREQ_CONTINUATION);
  req->start = start;
  req->end = end;
  req->numConts = numConts;
  req->conts = kmalloc (sizeof (struct UC_Continuation *) * numConts, (0x20));
  if (req == ((void *) 0))
    {
      if ((0))
	printk ("Could not allocate continuation request\n");
      return -1;
    }
  return 0;
}

extern int numContinuationRequests;
static inline struct ContinuationRequest *
copyContinuationRequest (struct ContinuationRequest *src)
{
  struct ContinuationRequest *newReq =
    kmalloc (sizeof (struct ContinuationRequest), (0x20));
  numContinuationRequests++;
  if (newReq == ((void *) 0))
    return ((void *) 0);
  *newReq = *src;
  newReq->conts =
    kmalloc (sizeof (struct UC_Continuation *) * newReq->numConts, (0x20));
  if (newReq->conts == ((void *) 0))
    {
      kfree (newReq);
      return ((void *) 0);
    }
  (__builtin_constant_p (sizeof (struct UC_Continuation *) * newReq->numConts)
   ? __constant_memcpy ((newReq->conts), (src->conts),
			(sizeof (struct UC_Continuation *) *
			 newReq->numConts)) : __memcpy ((newReq->conts),
							(src->conts),
							(sizeof
							 (struct
							  UC_Continuation *) *
							 newReq->numConts)));
  return newReq;
}

struct RequestOFOEntry
{
  struct RequestOFOEntry *prev;
  struct RequestOFOEntry *next;
  struct alloc_head_list *list;

  struct cminisock *cont;
  int isSynack;
  __u32 parent;
  __u8 numSiblings;
  __u8 position;
};

static inline struct RequestOFOEntry *
RequestOFOEntry_new (struct cminisock *cont,
		     int isSynack, __u32 parent, __u8 numSiblings,
		     __u8 position)
{
  struct RequestOFOEntry *rval =
    kmalloc (sizeof (struct RequestOFOEntry), (0x20));
  if (rval == ((void *) 0))
    {
      printk ("Out of memory while allocating RequesOFOEntry\n");
      return ((void *) 0);
    }
  rval->prev = rval->next = ((void *) 0);
  rval->list = ((void *) 0);

  rval->cont = cont;
  rval->isSynack = isSynack;
  rval->parent = parent;
  rval->numSiblings = numSiblings;
  rval->position = position;

  return rval;
}
















struct WireContinuation;
struct pminisock;

void StateCache_init (void);
void StateCache_destroy (void);
void StateCache_invalidate (void);

void StateCache_resize (int size);

void pminisock_evictN (int count);

struct pminisock *pminisock_lookup (struct sock *sk, __u32 seqno,
				    struct iphdr *iph, struct tcphdr *th);
int pminisock_insert (struct sock *sk, struct pminisock *msk);

extern int sysctl_trickles_Continuation_enable,
  sysctl_trickles_Continuation_policy, sysctl_trickles_Continuation_hits,
  sysctl_trickles_Continuation_total;
extern int sysctl_trickles_Nonce_enable, sysctl_trickles_Nonce_policy,
  sysctl_trickles_Nonce_hits, sysctl_trickles_Nonce_total;
extern int sysctl_trickles_TCB_enable, sysctl_trickles_TCB_policy,
  sysctl_trickles_TCB_hits, sysctl_trickles_TCB_total;

void dump_cache_stats (void);


static inline void
marshallContinuationServer (struct sock *sk, WireContinuation * dcont,
			    const struct cminisock *scont, int pktNum)
{
  dcont->clientState = scont->clientState;
  dcont->parent = scont->parent;
  if (1)
    {
      (
	{
	(dcont)->seq = htonl ((scont)->packets[pktNum].seq);
	(dcont)->continuationType = (scont)->packets[pktNum].contType;
	if ((scont)->packets[pktNum].type & (0x80))
	{
	(dcont)->firstChild = 1;}
	else
	{
	(dcont)->firstChild = 0;}
	static const int stateConversionMap[] =
	{
	0, 1, 2};
	int conversionOffset = (scont)->packets[pktNum].type & (0x3);
	if (conversionOffset >= (3))
	{
	do
	{
	if (!(0))
	{
	printk ("kgdb assertion failed: %s\n", "BUG");
	show_stack (((void *) 0)); breakpoint ();}}
	while (0);}
	(dcont)->state = stateConversionMap[conversionOffset];}
	  );
	  dcont->timestamp = htonl (scont->timestamp);
	  dcont->clientTimestamp = scont->clientTimestamp;
	  dcont->mrtt = htonl (scont->mrtt);
	}
	else
	{
	  dcont->seq = htonl (scont->seq);
	  dcont->continuationType = scont->continuationType;
	  dcont->firstChild = scont->firstChild;
	  dcont->state = scont->state;
	  dcont->timestamp = scont->rawTimestamp;
	  dcont->clientTimestamp = scont->clientTimestamp;
	  dcont->mrtt = scont->rawMrtt;
	}
	dcont->firstLoss = htonl (scont->firstLoss);
	dcont->firstBootstrapSeq = htonl (scont->firstBootstrapSeq);
	dcont->startCwnd = htonl (scont->startCwnd);
	dcont->ssthresh = htonl (scont->ssthresh);
	dcont->TCPBase = htonl (scont->TCPBase);
	dcont->tokenCounterBase = scont->tokenCounterBase;
	do
	  {
	    PseudoHeader hdr, *phdr = &hdr;
	    phdr->seq = dcont->seq;
	    phdr->type = dcont->continuationType;
	    phdr->first = dcont->firstChild ? 1 : 0;
	    phdr->serverAddr = scont->saddr;
	    phdr->serverPort = scont->source;
	    phdr->clientAddr = scont->daddr;
	    phdr->clientPort = scont->dest;
	    computeMAC (sk, phdr, dcont, dcont->mac);
	  }
	while (0);
      }
      static inline void marshallContinuationServerCopyMAC (struct sock *sk,
							    WireContinuation *
							    dcont,
							    const struct
							    cminisock *scont,
							    int pktNum)
      {
	dcont->clientState = scont->clientState;
	dcont->parent = scont->parent;
	if (1)
	  {
	    (
	      {
	      (dcont)->seq = htonl ((scont)->packets[pktNum].seq);
	      (dcont)->continuationType = (scont)->packets[pktNum].contType;
	      if ((scont)->packets[pktNum].type & (0x80))
	      {
	      (dcont)->firstChild = 1;}
	      else
	      {
	      (dcont)->firstChild = 0;}
	      static const int stateConversionMap[] =
	      {
	      0, 1, 2};
	      int conversionOffset = (scont)->packets[pktNum].type & (0x3);
	      if (conversionOffset >= (3))
	      {
	      do
	      {
	      if (!(0))
	      {
	      printk ("kgdb assertion failed: %s\n", "BUG");
	      show_stack (((void *) 0)); breakpoint ();}}
	      while (0);}
	      (dcont)->state = stateConversionMap[conversionOffset];}
		);
		dcont->timestamp = htonl (scont->timestamp);
		dcont->clientTimestamp = scont->clientTimestamp;
		dcont->mrtt = htonl (scont->mrtt);
	      }
	      else
	      {
		dcont->seq = htonl (scont->seq);
		dcont->continuationType = scont->continuationType;
		dcont->firstChild = scont->firstChild;
		dcont->state = scont->state;
		dcont->timestamp = scont->rawTimestamp;
		dcont->clientTimestamp = scont->clientTimestamp;
		dcont->mrtt = scont->rawMrtt;
	      }
	      dcont->firstLoss = htonl (scont->firstLoss);
	      dcont->firstBootstrapSeq = htonl (scont->firstBootstrapSeq);
	      dcont->startCwnd = htonl (scont->startCwnd);
	      dcont->ssthresh = htonl (scont->ssthresh);
	      dcont->TCPBase = htonl (scont->TCPBase);
	      dcont->tokenCounterBase = scont->tokenCounterBase;
	      do
		{
		  (__builtin_constant_p (16) ?
		   __constant_memcpy ((dcont->mac), (scont->mac),
				      (16)) : __memcpy ((dcont->mac),
							(scont->mac), (16)));
		}
	      while (0);
	    }
	    static inline void marshallContinuationClient (struct sock *sk,
							   WireContinuation *
							   dcont,
							   const struct
							   cminisock *scont,
							   int pktNum)
	    {
	      dcont->clientState = scont->clientState;
	      dcont->parent = scont->parent;
	      if (0)
		{
		  (
		    {
		    (dcont)->seq = htonl ((scont)->packets[pktNum].seq);
		    (dcont)->continuationType =
		    (scont)->packets[pktNum].contType;
		    if ((scont)->packets[pktNum].type & (0x80))
		    {
		    (dcont)->firstChild = 1;}
		    else
		    {
		    (dcont)->firstChild = 0;}
		    static const int stateConversionMap[] =
		    {
		    0, 1, 2};
		    int conversionOffset =
		    (scont)->packets[pktNum].type & (0x3);
		    if (conversionOffset >= (3))
		    {
		    do
		    {
		    if (!(0))
		    {
		    printk ("kgdb assertion failed: %s\n", "BUG");
		    show_stack (((void *) 0)); breakpoint ();}}
		    while (0);}
		    (dcont)->state = stateConversionMap[conversionOffset];}
		      );
		      dcont->timestamp = htonl (scont->timestamp);
		      dcont->clientTimestamp = scont->clientTimestamp;
		      dcont->mrtt = htonl (scont->mrtt);
		    }
		    else
		    {
		      dcont->seq = htonl (scont->seq);
		      dcont->continuationType = scont->continuationType;
		      dcont->firstChild = scont->firstChild;
		      dcont->state = scont->state;
		      dcont->timestamp = scont->rawTimestamp;
		      dcont->clientTimestamp = scont->clientTimestamp;
		      dcont->mrtt = scont->rawMrtt;
		    }
		    dcont->firstLoss = htonl (scont->firstLoss);
		    dcont->firstBootstrapSeq =
		      htonl (scont->firstBootstrapSeq);
		    dcont->startCwnd = htonl (scont->startCwnd);
		    dcont->ssthresh = htonl (scont->ssthresh);
		    dcont->TCPBase = htonl (scont->TCPBase);
		    dcont->tokenCounterBase = scont->tokenCounterBase;
		    do
		      {
			(__builtin_constant_p (16) ?
			 __constant_memcpy ((dcont->mac), (scont->mac),
					    (16)) : __memcpy ((dcont->mac),
							      (scont->mac),
							      (16)));
		      }
		    while (0);
		  }




		  static inline void marshallAckProof (WireAckProof * dproof,
						       const AckProof *
						       sproof)
		  {


		    int i;
		    dproof->numSacks = (
					 {
					 typeof (sproof->numSacks) Z =
					 (typeof (sproof->numSacks)) (64);
					 (
					   {
					   const typeof (sproof->
							 numSacks) _x =
					   (sproof->numSacks);
					   const typeof (Z) _y = (Z);
					   (void) (&_x == &_y);
					   _x < _y ? _x : _y;
					   });
					 });
		    for (i = 0; i < dproof->numSacks; i++)
		      {
			dproof->sacks[i].left =
			  htonl (sproof->sacks[i].left);;
			dproof->sacks[i].right =
			  htonl (sproof->sacks[i].right);;
			dproof->sacks[i].nonceSummary =
			  sproof->sacks[i].nonceSummary;
		      }


		  }




		  struct sk_buff;

		  static inline int unmarshallContinuationServerMSK (struct
								     sk_buff
								     *skb,
								     struct
								     cminisock
								     *dcont,
								     const
								     WireContinuation
								     * scont)
		  {
		    do
		      {
			if (__builtin_expect
			    ((!(((skb->sk)->tp_pinfo.af_tcp.
				 trickles_opt & 0x1)
				&& !((skb->sk)->tp_pinfo.af_tcp.
				     trickles_opt & (skb->sk)->tp_pinfo.
				     af_tcp.trickles_opt & 0x8))), 0))
			  {
			    char mac[16];
			    PseudoHeader hdr, *phdr = &hdr;
			    phdr->seq = scont->seq;
			    phdr->type = scont->continuationType;
			    phdr->first = scont->firstChild;
			    phdr->serverAddr = skb->nh.iph->daddr;
			    phdr->serverPort = skb->h.th->dest;
			    phdr->clientAddr = skb->nh.iph->saddr;
			    phdr->clientPort = skb->h.th->source;
			    computeMAC (skb->sk, phdr, scont, mac);
			    if (__builtin_memcmp (mac, scont->mac, 16))
			      {
				printk ("failed hmac comparison\n");
				return 0;
			      }
			  }
		      }
		    while (0);;
		    dcont->continuationType = scont->continuationType;
		    dcont->seq = ntohl (scont->seq);;
		    dcont->clientState = scont->clientState;
		    dcont->parent = scont->parent;
		    dcont->rawTimestamp = scont->timestamp;
		    dcont->timestamp = ntohl (scont->timestamp);
		    dcont->rawMrtt = scont->mrtt;
		    dcont->mrtt = ntohl (scont->mrtt);;
		    dcont->clientTimestamp = scont->clientTimestamp;
		    dcont->state = scont->state;
		    dcont->firstChild = scont->firstChild;
		    dcont->firstLoss = ntohl (scont->firstLoss);;
		    dcont->firstBootstrapSeq =
		      ntohl (scont->firstBootstrapSeq);;
		    dcont->startCwnd = ntohl (scont->startCwnd);;
		    dcont->ssthresh = ntohl (scont->ssthresh);;
		    dcont->TCPBase = ntohl (scont->TCPBase);;
		    if (__builtin_expect
			((!(((skb->sk)->tp_pinfo.af_tcp.trickles_opt & 0x1)
			    && !((skb->sk)->tp_pinfo.af_tcp.
				 trickles_opt & (skb->sk)->tp_pinfo.af_tcp.
				 trickles_opt & 0x8))), 0))
		      {
			dcont->saddr = skb->nh.iph->daddr;
			dcont->daddr = skb->nh.iph->saddr;
			dcont->source = skb->h.th->dest;
			dcont->dest = skb->h.th->source;
		      };
		    dcont->tokenCounterBase = scont->tokenCounterBase;
		    dcont->num_packets = 0;
		    dcont->numChildrenReceived = 0;
		    dcont->parentMSK = ((void *) 0);;
		    return 1;
		  };






		  static inline int unmarshallContinuationServerPMSK (struct
								      sk_buff
								      *skb,
								      struct
								      pminisock
								      *dcont,
								      const
								      WireContinuation
								      * scont)
		  {
		    do
		      {
			if (__builtin_expect
			    ((!(((skb->sk)->tp_pinfo.af_tcp.
				 trickles_opt & 0x1)
				&& !((skb->sk)->tp_pinfo.af_tcp.
				     trickles_opt & (skb->sk)->tp_pinfo.
				     af_tcp.trickles_opt & 0x8))), 0))
			  {
			    char mac[16];
			    PseudoHeader hdr, *phdr = &hdr;
			    phdr->seq = scont->seq;
			    phdr->type = scont->continuationType;
			    phdr->first = scont->firstChild;
			    phdr->serverAddr = skb->nh.iph->daddr;
			    phdr->serverPort = skb->h.th->dest;
			    phdr->clientAddr = skb->nh.iph->saddr;
			    phdr->clientPort = skb->h.th->source;
			    computeMAC (skb->sk, phdr, scont, mac);
			    if (__builtin_memcmp (mac, scont->mac, 16))
			      {
				printk ("failed hmac comparison\n");
				return 0;
			      }
			  }
		      }
		    while (0);;
		    dcont->continuationType = scont->continuationType;
		    dcont->seq = ntohl (scont->seq);;
		    dcont->clientState = scont->clientState;
		    dcont->parent = scont->parent;
		    dcont->rawTimestamp = scont->timestamp;
		    dcont->rawMrtt = scont->mrtt;;
		    dcont->clientTimestamp = scont->clientTimestamp;
		    dcont->state = scont->state;
		    dcont->firstChild = scont->firstChild;
		    dcont->firstLoss = ntohl (scont->firstLoss);;
		    dcont->firstBootstrapSeq =
		      ntohl (scont->firstBootstrapSeq);;
		    dcont->startCwnd = ntohl (scont->startCwnd);;
		    dcont->ssthresh = ntohl (scont->ssthresh);;
		    dcont->TCPBase = ntohl (scont->TCPBase);;
		    dcont->daddr = skb->nh.iph->saddr;
		    dcont->dest = skb->h.th->source;;
		    dcont->tokenCounterBase = scont->tokenCounterBase;
		    dcont->num_packets = 0;;
		    return 1;
		  };






		  static inline int
		    unmarshallContinuationServerPMSK2MSK (struct sock *sk,
							  struct cminisock
							  *dcont,
							  struct pminisock
							  *scont)
		  {;
		    dcont->continuationType = scont->continuationType;
		    dcont->seq = scont->seq;
		    dcont->clientState = scont->clientState;
		    dcont->parent = scont->parent;
		    dcont->rawTimestamp = scont->rawTimestamp;
		    dcont->timestamp = ntohl (scont->rawTimestamp);
		    dcont->rawMrtt = scont->rawMrtt;
		    dcont->mrtt = ntohl (scont->rawMrtt);
		    dcont->tag = scont->tag;
		    dcont->clientTimestamp = scont->clientTimestamp;
		    dcont->state = scont->state;
		    dcont->firstChild = scont->firstChild;
		    dcont->firstLoss = scont->firstLoss;
		    dcont->firstBootstrapSeq = scont->firstBootstrapSeq;
		    dcont->startCwnd = scont->startCwnd;
		    dcont->ssthresh = scont->ssthresh;
		    dcont->TCPBase = scont->TCPBase;
		    dcont->saddr = sk->saddr;
		    dcont->source = sk->sport;
		    dcont->daddr = scont->daddr;
		    dcont->dest = scont->dest;;
		    dcont->tokenCounterBase = scont->tokenCounterBase;
		    dcont->num_packets = 0;;
		    dcont->pmsk = scont;
		    dcont->num_packets = scont->num_packets;
		    dcont->ucont_data = scont->ucont_data;
		    dcont->ucont_len = scont->ucont_len;
		    dcont->input = scont->input;
		    dcont->input_len = scont->input_len;
		    dcont->packets = scont->packets;;
		    return 1;
		  };






		  static inline int
		    unmarshallContinuationServerMSK2PMSK (struct sock *sk,
							  struct pminisock
							  *dcont,
							  struct cminisock
							  *scont)
		  {;
		    dcont->continuationType = scont->continuationType;
		    dcont->seq = scont->seq;
		    dcont->clientState = scont->clientState;
		    dcont->parent = scont->parent;
		    dcont->rawTimestamp = scont->rawTimestamp;
		    dcont->rawMrtt = scont->rawMrtt;
		    dcont->tag = scont->tag;
		    dcont->clientTimestamp = scont->clientTimestamp;
		    dcont->state = scont->state;
		    dcont->firstChild = scont->firstChild;
		    dcont->firstLoss = scont->firstLoss;
		    dcont->firstBootstrapSeq = scont->firstBootstrapSeq;
		    dcont->startCwnd = scont->startCwnd;
		    dcont->ssthresh = scont->ssthresh;
		    dcont->TCPBase = scont->TCPBase;
		    dcont->daddr = scont->daddr;
		    dcont->dest = scont->dest;;
		    dcont->tokenCounterBase = scont->tokenCounterBase;
		    dcont->num_packets = 0;;
		    dcont->num_packets = scont->num_packets;
		    dcont->ucont_data = scont->ucont_data;
		    dcont->ucont_len = scont->ucont_len;
		    dcont->input = scont->input;
		    dcont->input_len = scont->input_len;
		    dcont->packets = scont->packets;;
		    return 1;
		  };






		  static inline int unmarshallContinuationClient (struct
								  sk_buff
								  *skb,
								  struct
								  cminisock
								  *dcont,
								  const
								  WireContinuation
								  * scont)
		  {
		    do
		      {
			(__builtin_constant_p (16) ?
			 __constant_memcpy ((dcont->mac), (scont->mac),
					    (16)) : __memcpy ((dcont->mac),
							      (scont->mac),
							      (16)));
		      }
		    while (0);
		    dcont->continuationType = scont->continuationType;
		    dcont->seq = ntohl (scont->seq);;
		    dcont->clientState = scont->clientState;
		    dcont->parent = scont->parent;
		    dcont->rawTimestamp = scont->timestamp;
		    dcont->timestamp = ntohl (scont->timestamp);
		    dcont->rawMrtt = scont->mrtt;
		    dcont->mrtt = ntohl (scont->mrtt);;
		    dcont->clientTimestamp = scont->clientTimestamp;
		    dcont->state = scont->state;
		    dcont->firstChild = scont->firstChild;
		    dcont->firstLoss = ntohl (scont->firstLoss);;
		    dcont->firstBootstrapSeq =
		      ntohl (scont->firstBootstrapSeq);;
		    dcont->startCwnd = ntohl (scont->startCwnd);;
		    dcont->ssthresh = ntohl (scont->ssthresh);;
		    dcont->TCPBase = ntohl (scont->TCPBase);;
		    if (__builtin_expect
			((!(((skb->sk)->tp_pinfo.af_tcp.trickles_opt & 0x1)
			    && !((skb->sk)->tp_pinfo.af_tcp.
				 trickles_opt & (skb->sk)->tp_pinfo.af_tcp.
				 trickles_opt & 0x8))), 0))
		      {
			dcont->saddr = skb->nh.iph->daddr;
			dcont->daddr = skb->nh.iph->saddr;
			dcont->source = skb->h.th->dest;
			dcont->dest = skb->h.th->source;
		      };
		    dcont->tokenCounterBase = scont->tokenCounterBase;
		    dcont->num_packets = 0;
		    dcont->numChildrenReceived = 0;
		    dcont->parentMSK = ((void *) 0);;
		    return 1;
		  };

		  extern int numContinuations;


		  extern kmem_cache_t *clientSideContinuation_cache;







		  static inline int SIMULATION_TOTAL_LEN (struct cminisock
							  *cont)
		  {
		    int i;
		    int total = 0;

		    for (i = 0; i < (((cont) + 1)->num_packets); i++)
		      {
			total += (((cont) + 1)->packets)[i].len;
		      }

		    return total;
		  }





		  static inline void DECODE_SIMULATION_RESULT (__u32 value,
							       int *pTotalLen,
							       int
							       *pNumPackets)
		  {
		    *pTotalLen = value & 0xffff;
		    *pNumPackets = (value >> 16) & 0xffff;
		  }





		  static inline struct cminisock
		    *newClientSide_Continuation (int flags)
		  {
		    int i;



		    struct cminisock *rval =
		      kmem_cache_alloc (clientSideContinuation_cache, (0x20));






		    if (rval == ((void *) 0))
		      {
			printk
			  ("out of memory while allocating continuation\n");
			return ((void *) 0);
		      }

		    rval->prev = rval->next = ((void *) 0);
		    rval->list = ((void *) 0);

		    for (i = 0; i < 2; i++)
		      {



			(rval + i)->ucont_len = 0;
			(rval + i)->ucont_data = ((void *) 0);
			(rval + i)->input_len = 0;
			(rval + i)->input = ((void *) 0);

			(rval + i)->mark = 0;
			(rval + i)->simulated = 0;
		      }
		    rval->sk = ((void *) 0);
		    return rval;
		  }

		  static inline void *kmalloc_dup (void *src, int len,
						   unsigned gfp)
		  {
		    char *ptr = kmalloc (len, gfp);
		    if (ptr == ((void *) 0))
		      {
			printk ("out of memory in kmalloc_dup\n");
			return ((void *) 0);
		      }
		    (__builtin_constant_p (len) ?
		     __constant_memcpy ((ptr), (src),
					(len)) : __memcpy ((ptr), (src),
							   (len)));
		    return ptr;
		  }

		  static inline struct cminisock
		    *copyClientSide_Continuation (struct cminisock *cont,
						  int flags)
		  {
		    int i;



		    struct cminisock *rval =
		      kmem_cache_alloc (clientSideContinuation_cache, (0x20));

		    if (rval == ((void *) 0))
		      {
			printk
			  ("out of memory while allocating continuation to copy\n");
			return ((void *) 0);
		      }
		    rval->prev = rval->next = ((void *) 0);
		    rval->list = ((void *) 0);

		    (__builtin_constant_p
		     ((int) ((struct cminisock *) 0)->
		      clientside_copy_end) ? __constant_memcpy ((rval),
								(cont),
								((int)
								 ((struct
								   cminisock
								   *) 0)->
								 clientside_copy_end))
		     : __memcpy ((rval), (cont),
				 ((int) ((struct cminisock *) 0)->
				  clientside_copy_end)));
		    for (i = 0; i < 2; i++)
		      {

			(rval + i)->ucont_len = 0;
			(rval + i)->ucont_data = ((void *) 0);

			(rval + i)->input_len = 0;
			(rval + i)->input = ((void *) 0);

			(rval + i)->mark = 0;
			(rval + i)->simulated = 0;
			(rval + i)->num_packets = 0;
			(rval + i)->actualCwnd = 0;
		      }

		    return rval;
		  }


		  static inline void freeClientSide_Continuation (struct
								  cminisock
								  *cont)
		  {

		    int i;

		    if (cont->list)
		      {
			do
			  {
			    if (!(0))
			      {
				printk ("kgdb assertion failed: %s\n", "BUG");
				show_stack (((void *) 0));
				breakpoint ();
			      }
			  }
			while (0);
		      }

		    for (i = 0; i < 2; i++)
		      {
			if ((cont + i)->ucont_data)
			  kfree ((cont + i)->ucont_data);
			if ((cont + i)->input)
			  kfree ((cont + i)->input);
		      }

		    kmem_cache_free (clientSideContinuation_cache, cont);



		  }

		  static inline
		    struct SkipCell *SkipCell_new (unsigned start,
						   unsigned end)
		  {
		    struct SkipCell *cell =
		      kmalloc (sizeof (struct SkipCell), (0x20));
		    cell->prev = cell->next = ((void *) 0);
		    cell->list = ((void *) 0);

		    cell->start = start;
		    cell->end = end;
		    return cell;
		  }

		  static inline void SkipCell_free (struct SkipCell *cell)
		  {
		    kfree (cell);
		  }

		  static void SkipCell_dump (struct SkipCell *cell)
		  {
		    if ((struct alloc_head_list *) cell == cell->list)
		      {
			printk ("end");
		      }
		    else
		      {
			printk ("cell[%d-%d] ", cell->start, cell->end);
		      }
		  }

		  static int SkipCell_intersectRange (struct SkipCell *c0,
						      unsigned start,
						      unsigned end)
		  {
		    unsigned left = ({ typeof (c0->start) Z =
				     (typeof (c0->start)) (start);
				     (
				       {
				       const typeof (c0->start) _x =
				       (c0->start);
				       const typeof (Z) _y = (Z);
				       (void) (&_x == &_y);
				       _x > _y ? _x : _y;
				       });
				     });
		    unsigned right = ({ typeof (c0->end) Z =
				      (typeof (c0->end)) (end);
				      (
					{
					const typeof (c0->end) _x = (c0->end);
					const typeof (Z) _y = (Z);
					(void) (&_x == &_y);
					_x < _y ? _x : _y;
					});
				      });
		    return left < right;
		  }

		  static int SkipCell_intersect (struct SkipCell *c0,
						 struct SkipCell *c1)
		  {
		    return SkipCell_intersectRange (c0, c1->start, c1->end);
		  }

		  static inline int SkipCell_compare (struct SkipCell *c0,
						      struct SkipCell *c1)
		  {
		    return c0->start == c1->start && c0->end == c1->end;
		  }

		  static int SkipCell_insert (struct sock *sk,
					      struct SkipCell *cell)
		  {
		    struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;
		    struct alloc_head_list *list = &tp->t.skipList;
		    struct SkipCell *prev = (struct SkipCell *) list;
		    if (empty (list))
		      {
			insert_tail (list, (struct alloc_head *) cell);
			return 1;
		      }
		    else
		      {
			int found = 0;
			struct SkipCell *next =
			  (struct SkipCell *) list->next;
			if (cell->end <= next->start)
			  {
			    if (!((struct alloc_head_list *) prev == list))
			      {
				printk ("KERNEL: assertion ("
					"(struct alloc_head_list *)prev == list"
					") failed at "
					"/home/ashieh/current/include/net/trickles_packet_helpers.h"
					"(%d)\n", 564);
			      };

			    found = 1;
			  }
			else
			  {
			    for (next = (typeof (next)) (list)->next;
				 (next != (typeof (next)) (list));
				 next = (typeof (next)) next->next)
			      {
				if ((struct alloc_head_list *) prev != list &&
				    (struct alloc_head_list *) next != list)
				  {
				    if (prev->end <= cell->start &&
					cell->end <= next->start)
				      {

					found = 1;
					break;
				      }
				    if (SkipCell_compare (prev, cell))
				      {

					return 0;
				      }
				    if (cell->end <= next->start)
				      {
					printk
					  ("no acceptable insertion point for skip\n");
					do
					  {
					    if (!(0))
					      {
						printk
						  ("kgdb assertion failed: %s\n",
						   "BUG");
						show_stack (((void *) 0));
						breakpoint ();
					      }
					  }
					while (0);
					return 0;
				      }
				  }
				prev = next;
			      }
			  }
			if ((struct alloc_head_list *) next == list)
			  {
			    if (prev->end <= cell->start)
			      {
				if (found)
				  do
				    {
				      if (!(0))
					{
					  printk
					    ("kgdb assertion failed: %s\n",
					     "BUG");
					  show_stack (((void *) 0));
					  breakpoint ();
					}
				    }
				  while (0);

				found = 1;
			      }
			    else
			      {

				return 0;
			      }
			  }
			if (found)
			  {
			    if (SkipCell_intersect (prev, cell) ||
				SkipCell_intersect (cell, next))
			      {
				printk
				  ("found an insertion point, but turns out to have overlap\n");
				do
				  {
				    if (!(0))
				      {
					printk ("kgdb assertion failed: %s\n",
						"BUG");
					show_stack (((void *) 0));
					breakpoint ();
				      }
				  }
				while (0);
			      }
			    else
			      {

				insert ((struct alloc_head *) cell,
					(struct alloc_head *) prev,
					(struct alloc_head *) next);
				return 1;
			      }
			  }

			if (!(!found))
			  {
			    printk ("KERNEL: assertion (" "!found"
				    ") failed at "
				    "/home/ashieh/current/include/net/trickles_packet_helpers.h"
				    "(%d)\n", 623);
			  };
			do
			  {
			    if (!(0))
			      {
				printk ("kgdb assertion failed: %s\n", "BUG");
				show_stack (((void *) 0));
				breakpoint ();
			      }
			  }
			while (0);
			return 0;
		      }
		  }

		  static inline void unmarshallAckProof (AckProof * dproof,
							 const WireAckProof *
							 sproof)
		  {


		    int i;
		    dproof->numSacks = sproof->numSacks;
		    for (i = 0; i < sproof->numSacks; i++)
		      {
			dproof->sacks[i].left =
			  ntohl (sproof->sacks[i].left);;
			dproof->sacks[i].right =
			  ntohl (sproof->sacks[i].right);;
			dproof->sacks[i].nonceSummary =
			  sproof->sacks[i].nonceSummary;
		      }


		  }

		  static inline struct UC_Continuation
		    *unmarshallUC_Continuation (struct WireUC_Continuation
						*scont, unsigned length)
		  {
		    unsigned dataLen =
		      length - sizeof (struct WireUC_Continuation);
		    struct UC_Continuation *rval =
		      kmalloc (sizeof (struct UC_Continuation) + dataLen,
			       (0x20));

		    if (rval == ((void *) 0))
		      {
			printk
			  ("Out of memory while unmarshalling UC_Continuation\n");
			return ((void *) 0);
		      }
		    rval->prev = rval->next = ((void *) 0);
		    rval->list = ((void *) 0);

		    rval->seq = ntohl (scont->seq);
		    rval->validStart = ntohl (scont->validStart);
		    rval->validEnd = ntohl (scont->validEnd);

		    rval->FIN_received = 0;
		    rval->FINHint = 0;
		    rval->FINHintPosition = 0xffffffff;

		    rval->fields = scont->fields;
		    rval->dataLen = dataLen;
		    rval->kernel.obsoleteAt = rval->validEnd;
		    (__builtin_constant_p (dataLen) ?
		     __constant_memcpy ((rval->kernel.data), (scont->data),
					(dataLen)) : __memcpy ((rval->kernel.
								data),
							       (scont->data),
							       (dataLen)));
		    return rval;
		  }

		  static void
		    UC_Continuation_receivedFIN (struct UC_Continuation *cont,
						 unsigned finPosition)
		  {
		    cont->FIN_received = 1;
		    cont->FINHint = 1;
		    cont->FINHintPosition = finPosition;
		    if (!(finPosition <= cont->kernel.obsoleteAt))
		      {
			printk ("KERNEL: assertion ("
				"finPosition <= cont->kernel.obsoleteAt"
				") failed at "
				"/home/ashieh/current/include/net/trickles_packet_helpers.h"
				"(%d)\n", 674);
		      };




		    cont->kernel.obsoleteAt = finPosition;
		  }

		  static void
		    UC_Continuation_setFINHint (struct UC_Continuation *cont,
						unsigned finHintPosition)
		  {
		    if (cont->FINHint
			&& cont->FINHintPosition != finHintPosition)
		      {
			printk
			  ("Warning! client does not properly multiple hints in the same continuation (curr=%d, new=%d)\n",
			   cont->FINHintPosition, finHintPosition);
		      }
		    if (!cont->FIN_received)
		      {
			cont->FINHint = 1;
			cont->FINHintPosition = finHintPosition;
		      }
		  }

		  static unsigned UC_Continuation_virtualEnd (struct
							      UC_Continuation
							      *cont)
		  {
		    if (cont->FINHint)
		      {
			if (!(cont->FINHintPosition <= cont->validEnd))
			  {
			    printk ("KERNEL: assertion ("
				    "cont->FINHintPosition <= cont->validEnd"
				    ") failed at "
				    "/home/ashieh/current/include/net/trickles_packet_helpers.h"
				    "(%d)\n", 696);
			  };
			return cont->FINHintPosition;
		      }
		    else
		      {
			return cont->validEnd;
		      }
		  }

		  static unsigned UC_Continuation_actualEnd (struct
							     UC_Continuation
							     *cont)
		  {
		    if (cont->FIN_received)
		      {
			return cont->FINHintPosition;
		      }
		    else
		      {
			return cont->validEnd;
		      }
		  }

		  static int
		    UC_Continuation_inSkippedRegion (struct UC_Continuation
						     *cont, unsigned position)
		  {
		    if (!
			(cont->validStart <= position
			 && position < cont->validEnd))
		      {
			printk ("KERNEL: assertion ("
				"cont->validStart <= position && position < cont->validEnd"
				") failed at "
				"/home/ashieh/current/include/net/trickles_packet_helpers.h"
				"(%d)\n", 713);
		      };
		    return position >= UC_Continuation_virtualEnd (cont) &&
		      position < cont->validEnd;
		  }

		  static inline unsigned marshallUC_Continuation (struct
								  WireUC_Continuation
								  *dcont,
								  struct
								  UC_Continuation
								  *scont)
		  {
		    int dataLen = scont->dataLen;
		    dcont->seq = htonl (scont->seq);
		    dcont->validStart = htonl (scont->validStart);
		    dcont->validEnd = htonl (scont->validEnd);
		    dcont->fields = scont->fields;
		    (__builtin_constant_p (dataLen) ?
		     __constant_memcpy ((dcont->data), (scont->kernel.data),
					(dataLen)) : __memcpy ((dcont->data),
							       (scont->kernel.
								data),
							       (dataLen)));
		    return sizeof (*dcont) + dataLen;
		  }

		  static inline void WireUC_addDependency (struct
							   WireUC_Continuation
							   *completeResp,
							   struct
							   UC_DependencyLink
							   *dep)
		  {
		    printk ("Dependency handling not complete\n");
		    do
		      {
			if (!(0))
			  {
			    printk ("kgdb assertion failed: %s\n", "BUG");
			    show_stack (((void *) 0));
			    breakpoint ();
			  }
		      }
		    while (0);
		    completeResp->fields |= (0x01);


		  }

		  static inline struct UC_Continuation
		    *copyUC_Continuation (struct UC_Continuation *scont)
		  {

		    int dataLen = scont->dataLen;
		    struct UC_Continuation *rval =
		      kmalloc (sizeof (*rval) + dataLen, (0x20));
		    if (rval == ((void *) 0))
		      {
			printk
			  ("Out of memory while copying UC_Continuation\n");
			return ((void *) 0);
		      }
		    *rval = *scont;
		    rval->prev = rval->next = ((void *) 0);
		    rval->list = ((void *) 0);

		    (__builtin_constant_p (dataLen) ?
		     __constant_memcpy ((rval->kernel.data),
					(scont->kernel.data),
					(dataLen)) : __memcpy ((rval->kernel.
								data),
							       (scont->kernel.
								data),
							       (dataLen)));
		    return rval;
		  }

		  static inline struct UC_DependencyLink
		    *unmarshallUC_Dependency (struct sock *sk,
					      struct WireUC_Dependency *sdep)
		  {

		    printk ("Dependency management doesn't work yet\n");
		    do
		      {
			if (!(0))
			  {
			    printk ("kgdb assertion failed: %s\n", "BUG");
			    show_stack (((void *) 0));
			    breakpoint ();
			  }
		      }
		    while (0);
		    return ((void *) 0);

		  }

		  static inline int freeDependencyNode (struct sock *sk,
							struct
							UC_DependencyNode
							*dep)
		  {

		    printk ("Dependency management doesn't work yet\n");
		    do
		      {
			if (!(0))
			  {
			    printk ("kgdb assertion failed: %s\n", "BUG");
			    show_stack (((void *) 0));
			    breakpoint ();
			  }
		      }
		    while (0);
		    return -1;

		  }

		  static inline struct UC_DependencyNode
		    *copyUC_DependencyNode (struct UC_DependencyNode *sdep)
		  {

		    printk ("Dependency management doesn't work yet\n");
		    do
		      {
			if (!(0))
			  {
			    printk ("kgdb assertion failed: %s\n", "BUG");
			    show_stack (((void *) 0));
			    breakpoint ();
			  }
		      }
		    while (0);
		    return ((void *) 0);

		  }

		  static inline
		    void updateUC_ContinuationAndDependency (struct
							     UC_Continuation
							     *cont,
							     struct
							     UC_DependencyNode
							     *dep)
		  {

		    printk ("Dependency management doesn't work yet\n");
		    do
		      {
			if (!(0))
			  {
			    printk ("kgdb assertion failed: %s\n", "BUG");
			    show_stack (((void *) 0));
			    breakpoint ();
			  }
		      }
		    while (0);

		  }

		  static inline int addDependencyLink (struct
						       UC_DependencyNode
						       *changedDep,
						       struct
						       UC_DependencyLink
						       *newLink)
		  {

		    printk ("Dependency management doesn't work yet\n");
		    do
		      {
			if (!(0))
			  {
			    printk ("kgdb assertion failed: %s\n", "BUG");
			    show_stack (((void *) 0));
			    breakpoint ();
			  }
		      }
		    while (0);
		    return -1;

		  }




		  static inline
		    void WireUC_clearFields (struct WireUC_Continuation
					     *wireContinuation)
		  {
		    wireContinuation->fields = 0;
		  }

		  static inline void *WireUC_getDataStart (struct
							   WireUC_Continuation
							   *wireContinuation)
		  {
		    char *rval = wireContinuation->data;

		    if (wireContinuation->fields & (0x01))
		      {
			printk
			  ("getWireUC_dataStart: no dependency support\n");
			do
			  {
			    if (!(0))
			      {
				printk ("kgdb assertion failed: %s\n", "BUG");
				show_stack (((void *) 0));
				breakpoint ();
			      }
			  }
			while (0);
		      }
		    if (wireContinuation->fields & ~((0x01)))
		      {
			printk ("getWireUC_dataStart: unknown field\n");
			do
			  {
			    if (!(0))
			      {
				printk ("kgdb assertion failed: %s\n", "BUG");
				show_stack (((void *) 0));
				breakpoint ();
			      }
			  }
			while (0);
		      }


		    return rval;
		  }

		  static inline void initResponseHeader (struct
							 WireUC_RespHeader
							 *resp,
							 enum UC_Type type,
							 int error,
							 unsigned len)
		  {
		    resp->type = type;
		    resp->error = error;
		    resp->len = htons ((short) len);
		  }

		  static inline void initIncompleteResponse (struct
							     WireUC_CVT_IncompleteResponse
							     *incompleteResp,
							     unsigned ack_seq,
							     int error,
							     unsigned
							     validStart,
							     unsigned
							     convContLen)
		  {
		    initResponseHeader ((struct WireUC_RespHeader *)
					incompleteResp, UC_INCOMPLETE, error,
					sizeof (struct
						WireUC_CVT_IncompleteResponse)
					+ convContLen);
		    incompleteResp->ack_seq = htonl (ack_seq);
		    incompleteResp->newCont.validStart = htonl (validStart);
		  }

		  static inline void initCompleteResponse (struct
							   WireUC_CVT_CompleteResponse
							   *completeResp,
							   unsigned ack_seq,
							   unsigned
							   convContLen,
							   unsigned seq,
							   unsigned
							   validStart,
							   unsigned validEnd,
							   __u16 piggyLength)
		  {
		    initResponseHeader ((struct WireUC_RespHeader *)
					completeResp, UC_COMPLETE, 0,
					sizeof (struct
						WireUC_CVT_CompleteResponse) +
					convContLen);
		    completeResp->ack_seq = htonl (ack_seq);
		    completeResp->piggyLength = htons (piggyLength);
		    completeResp->newCont.seq = htonl (seq);
		    completeResp->newCont.validStart = htonl (validStart);
		    completeResp->newCont.validEnd = htonl (validEnd);
		    completeResp->newCont.fields = 0;
		  }

		  static inline void initNewContinuationResponse (struct
								  WireUC_NewContinuationResponse
								  *newContinuationResp,
								  unsigned
								  contLen,
								  unsigned
								  seq,
								  unsigned
								  validStart,
								  unsigned
								  validEnd)
		  {
		    initResponseHeader ((struct WireUC_RespHeader *)
					newContinuationResp, UC_NEWCONT, 0,
					sizeof (struct
						WireUC_NewContinuationResponse)
					+ contLen);
		    newContinuationResp->newCont.seq = htonl (seq);
		    newContinuationResp->newCont.validStart =
		      htonl (validStart);
		    newContinuationResp->newCont.validEnd = htonl (validEnd);
		    newContinuationResp->newCont.fields = 0;
		  }



		  static inline void UC_Continuation_dump_string (char *dest,
								  struct
								  UC_Continuation
								  *ucont)
		  {
		    sprintf (dest,
			     "{ seq=[%d]\nvalid=[%d-%d]\ncvalid=[%d-%d] }\n",
			     ucont->seq, ucont->validStart, ucont->validEnd,
			     ucont->clientValidStart, ucont->clientValidEnd);
		  }

		  static inline void UC_Continuation_dump (struct
							   UC_Continuation
							   *ucont)
		  {
		    char temp[1024];
		    UC_Continuation_dump_string (temp, ucont);
		    printk (temp);
		  }


		  static inline struct DataChunk
		    *data_buildChunkHeader (struct DataChunk *chunk,
					    int byteNum, int chunkLen)
		  {
		    if (!(!(chunkLen & ~0xffff)))
		      {
			printk ("KERNEL: assertion (" "! (chunkLen & ~0xffff)"
				") failed at "
				"/home/ashieh/current/include/net/trickles_packet_helpers.h"
				"(%d)\n", 958);
		      };
		    chunk->byteNum = htonl (byteNum);
		    chunk->type = RCHUNK_DATA;
		    chunk->flags = 0;
		    chunk->chunkLen =
		      htons (chunkLen + sizeof (struct DataChunk));

		    return (struct DataChunk *) (chunk->data + chunkLen);
		  }

		  static inline struct ResponseChunk
		    *skip_buildChunkHeader (struct ResponseChunk *chunk,
					    __u32 byteNum, __u32 skipLen)
		  {
		    int len;
		    struct SkipChunk *schunk = (struct SkipChunk *) chunk;
		    schunk->type = RCHUNK_SKIP;
		    chunk->flags = 0;
		    schunk->chunkLen = htons (len =
					      sizeof (struct SkipChunk));
		    schunk->byteNum = htonl (byteNum);
		    schunk->len = htonl (skipLen);
		    return (struct ResponseChunk *) ((char *) schunk + len);
		  }

		  static inline struct ResponseChunk
		    *finhint_buildChunkHeader (struct ResponseChunk *chunk,
					       __u32 byteNum, __u32 skipLen)
		  {
		    int len;
		    struct FINHintChunk *shchunk =
		      (struct FINHintChunk *) chunk;
		    shchunk->type = RCHUNK_FINHINT;
		    chunk->flags = 0;
		    shchunk->chunkLen = htons (len =
					       sizeof (struct FINHintChunk));
		    shchunk->byteNum = htonl (byteNum);
		    shchunk->len = htonl (skipLen);
		    return (struct ResponseChunk *) ((char *) shchunk + len);
		  }

		  static inline struct ResponseChunk
		    *pushhint_buildChunkHeader (struct ResponseChunk *chunk,
						int start, int end)
		  {
		    struct PushHintChunk *phchunk =
		      (struct PushHintChunk *) chunk;
		    phchunk->type = RCHUNK_PUSH_HINT;
		    chunk->flags = 0;
		    phchunk->chunkLen = htons (sizeof (struct PushHintChunk));
		    phchunk->start = htonl (start);
		    phchunk->end = htonl (end);


		    return (struct ResponseChunk *) (phchunk + 1);
		  }



		  struct GenerateDataContext
		  {
		    int packetNum;
		    int packetPos;
		    char *outputStart;
		    char *outputPos;

		    struct cminisock_packet *packets;
		    int numPackets;
		  };

		  static inline
		    void GenerateDataContext_init (struct GenerateDataContext
						   *ctx, char *dest,
						   struct cminisock_packet
						   *packets, int numPackets)
		  {
		    ctx->packetNum = 0;
		    ctx->packetPos = 0;
		    ctx->outputPos = ctx->outputStart = dest;
		    ctx->packets = packets;
		    ctx->numPackets = numPackets;
		  }

		  static inline
		    void GenerateDataContext_describePackets (struct
							      GenerateDataContext
							      *ctx)
		  {
		    int i;
		    for (i = 0; i < ctx->numPackets; i++)
		      {
			printk ("Packet [%d] = %d\n", i, ctx->packets[i].len);
		      }
		  }

		  static inline
		    void GenerateDataContext_dump (struct GenerateDataContext
						   *ctx)
		  {
		    printk
		      ("\tPacketNum = %d\n\tPacketPos = %d\n\tOutputPos = %p\n\tnumPackets = %d\n\tpackets = %p\n",
		       ctx->packetNum, ctx->packetPos, ctx->outputPos,
		       ctx->numPackets, ctx->packets);
		  }



		  static inline
		    int GenerateDataContext_packetSpace (struct
							 GenerateDataContext
							 *ctx)
		  {
		    if (ctx->packetNum >= ctx->numPackets)
		      {
			return 0;
		      }
		    return ((ctx)->packets[(ctx)->packetNum].len -
			    (ctx)->packets[(ctx)->packetNum].ucontLen) -
		      ctx->packetPos;
		  }

		  static inline
		    char *GenerateDataContext_put (struct GenerateDataContext
						   *ctx, int numBytes)
		  {

		    if (numBytes == 0)
		      return ctx->outputPos;

		    do
		      {
			if (ctx->packetNum >= ctx->numPackets)
			  {
			    return ((void *) 0);
			  }
		      }
		    while (0);

		    if (!(ctx->packetNum <= ctx->numPackets))
		      {
			if (!(ctx->packetNum <= ctx->numPackets))
			  {
			    printk ("KERNEL: assertion ("
				    "ctx->packetNum <= ctx->numPackets"
				    ") failed at "
				    "/home/ashieh/current/include/net/trickles_packet_helpers.h"
				    "(%d)\n", 1065);
			  };
			printk ("%d !<= %d\n", ctx->packetNum,
				ctx->numPackets);
		      }
		    char *temp;
		    if (GenerateDataContext_packetSpace (ctx) >= numBytes)
		      {


		      }
		    else
		      {


			ctx->outputPos +=
			  ((ctx)->packets[(ctx)->packetNum].len -
			   (ctx)->packets[(ctx)->packetNum].ucontLen) -
			  ctx->packetPos;
			ctx->packetPos = 0;
			ctx->packetNum++;
		      }
		    temp = ctx->outputPos;
		    ctx->packetPos += numBytes;
		    ctx->outputPos += numBytes;

		    do
		      {
			if (ctx->packetNum >= ctx->numPackets)
			  {
			    return ((void *) 0);
			  }
		      }
		    while (0);

		    if (!
			(ctx->packetPos <=
			 ((ctx)->packets[(ctx)->packetNum].len -
			  (ctx)->packets[(ctx)->packetNum].ucontLen)))
		      {
			printk ("KERNEL: assertion ("
				"ctx->packetPos <= PACKET_LEN(ctx)"
				") failed at "
				"/home/ashieh/current/include/net/trickles_packet_helpers.h"
				"(%d)\n", 1085);
		      };

		    if (ctx->packetPos ==
			((ctx)->packets[(ctx)->packetNum].len -
			 (ctx)->packets[(ctx)->packetNum].ucontLen))
		      {
			ctx->packetPos = 0;
			ctx->packetNum++;
		      }
		    return temp;

		  }

		  static inline
		    struct ResponseChunk
		    *GenerateDataContext_reserveChunkHeader (struct
							     GenerateDataContext
							     *ctx,
							     int headerLen,
							     int
							     generatePadding)
		  {
		    char *currpos = ctx->outputPos;
		    struct ResponseChunk *output = (struct ResponseChunk *)
		      GenerateDataContext_put (ctx, headerLen);
		    if (output == ((void *) 0))
		      {

			return ((void *) 0);
		      }
		    else
		      {

			if (currpos != (char *) output)
			  {

			    if (generatePadding)
			      {

				while (currpos != (char *) output)
				  {
				    *currpos++ = (0x00);
				  }
			      }
			  }
		      }

		    return output;
		  }

		  static inline
		    struct DataChunk
		    *GenerateDataContext_reserveHeader (struct
							GenerateDataContext
							*ctx,
							int generatePadding)
		  {

		    char *currpos = ctx->outputPos;
		    struct DataChunk *output =
		      (struct DataChunk *) GenerateDataContext_put (ctx,
								    sizeof
								    (struct
								     DataChunk));
		    if (output == ((void *) 0))
		      {

			return ((void *) 0);
		      }
		    else
		      {

			if (currpos != (char *) output)
			  {

			    if (generatePadding)
			      {

				while (currpos != (char *) output)
				  {
				    *currpos++ = (0x00);
				  }
			      }
			  }
		      }

		    return output;
		  }

		  static inline
		    int GenerateDataContext_simulateRequest (struct
							     GenerateDataContext
							     *gctx)
		  {
		    struct DataChunk *test =
		      GenerateDataContext_reserveHeader (gctx, 0);
		    if (test == ((void *) 0))
		      {
			return -1;
		      }

		    int maxLen = GenerateDataContext_packetSpace (gctx);
		    return maxLen;
		  }

		  static inline int validateDataChunks (char *start, int len)
		  {

		    int chunknum = 0, dataLen = 0;
		    struct DataChunk *chunk = (struct DataChunk *) start;
		    int goodCount = 0, loopcount = 0, printAtReturn =
		      0, count = 0;
		    while ((char *) (chunk + 1) - start < len)
		      {
			int len =
			  ntohs ((chunk)->chunkLen) -
			  sizeof (struct DataChunk);
			if (len <= 0)
			  {
			    if ((0))
			      printk ("bad length chunk(%d) -- ", len);
			    printAtReturn = 1;
			  }
			else
			  {
			    goodCount++;
			  }
			dataLen += len;
			chunknum++;

			chunk =
			  ((void *) ((char *) (chunk) +
				     ntohs ((chunk)->chunkLen)));


			loopcount++;
			if (loopcount > (100))
			  {
			    printk
			      ("validation limit exceeded, goodCount = %d\n",
			       goodCount);
			    return -1;
			  }
		      }
		    if ((char *) chunk - start > len)
		      {
			printk ("data chunk validation failed, %d > %d\n",
				(char *) chunk - start, len);
			return -chunknum - 1;
		      }
		    if (printAtReturn)
		      {
			printk ("returning\n");
		      }
		    return chunknum;

		  }

		  static inline
		    void GenerateDataContext_sanityCheck (struct
							  GenerateDataContext
							  *gctx)
		  {

		    if (!(gctx->packetNum <= gctx->numPackets))
		      {
			printk ("KERNEL: assertion ("
				"gctx->packetNum <= gctx->numPackets"
				") failed at "
				"/home/ashieh/current/include/net/trickles_packet_helpers.h"
				"(%d)\n", 1194);
		      };


		    int i;
		    int totalLen = 0;
		    int outputLen = gctx->outputPos - gctx->outputStart;
		    char *buf = gctx->outputStart;

		  }

		  static inline
		    void ResponseChunks_dump (char *start, int count)
		  {
		    struct ResponseChunk *buf =
		      (struct ResponseChunk *) start;
		    printk ("{");
		    while (count > 0)
		      {
			int len = ntohs (buf->chunkLen);
			printk ("[%d] t=%d f=%d l=%d: ", (char *) buf - start,
				buf->type, buf->flags, len);
			switch (buf->type)
			  {
			  case RCHUNK_PUSH_HINT:
			    break;
			  case RCHUNK_DATA:
			    {
			      struct DataChunk *dc = (struct DataChunk *) buf;
			      printk ("[%d,%d]", ntohl (dc->byteNum),
				      ntohl (dc->byteNum) + len -
				      sizeof (struct DataChunk));
			      break;
			    }
			  case RCHUNK_SKIP:
			    {
			      struct SkipChunk *sc = (struct SkipChunk *) buf;
			      printk ("[%d,%d]", ntohl (sc->byteNum),
				      ntohl (sc->byteNum) + ntohl (sc->len));
			      break;
			    }
			  case RCHUNK_FINHINT:
			    {
			      struct FINHintChunk *fc =
				(struct FINHintChunk *) buf;
			      printk ("[%d,%d]", ntohl (fc->byteNum),
				      ntohl (fc->byteNum) + ntohl (fc->len));
			      break;
			    }
			  }
			printk ("\n");
			buf = (char *) buf + len;
			count--;
		      }
		    printk ("}\n");

		  }


		  static inline
		    void RequestOFOEntry_free (struct RequestOFOEntry *entry)
		  {
		    if (!
			(entry->prev == ((void *) 0)
			 && entry->next == ((void *) 0)
			 && entry->list == ((void *) 0)))
		      {
			printk ("KERNEL: assertion ("
				"entry->prev == NULL && entry->next == NULL && entry->list == NULL"
				") failed at "
				"/home/ashieh/current/include/net/trickles_client.h"
				"(%d)\n", 331);
		      };

		    freeClientSide_Continuation (entry->cont);
		    kfree (entry);
		  }

		  extern int (*trickles_rcv_hook) (struct sock * sk,
						   struct sk_buff * skb);
		  extern void (*trickles_destroy_hook) (struct sock * sk);

		  int trickles_rcv_default (struct sock *sk,
					    struct sk_buff *skb);
		  void trickles_destroy_default (struct sock *sk);


		  inline static void init_trickles_sock (struct sock *sk)
		  {
		    int i;
		    struct tcp_opt *tp = &(sk->tp_pinfo.af_tcp);
		    tp->trickles_opt = 0;
		    tp->mac_changed = 0;


		    {
		      (__builtin_constant_p (0)
		       ? (__builtin_constant_p
			  ((sizeof (tp->cminisock_api_config))) ?
			  __constant_c_and_count_memset (((&tp->
							   cminisock_api_config)),
							 ((0x01010101UL *
							   (unsigned
							    char) (0))),
							 ((sizeof
							   (tp->
							    cminisock_api_config))))
			  :
			  __constant_c_memset (((&tp->cminisock_api_config)),
					       ((0x01010101UL *
						 (unsigned char) (0))),
					       ((sizeof
						 (tp->
						  cminisock_api_config)))))
		       : (__builtin_constant_p
			  ((sizeof (tp->cminisock_api_config))) ?
			  __memset_generic ((((&tp->cminisock_api_config))),
					    (((0))),
					    (((sizeof
					       (tp->
						cminisock_api_config))))) :
			  __memset_generic (((&tp->cminisock_api_config)),
					    ((0)),
					    ((sizeof
					      (tp->cminisock_api_config))))));
		      init_head (&tp->cminisock_api_config.msk_freelist);

		      tp->cminisock_api_config.cfg.ctl = ((void *) 0);

		      tp->cminisock_api_config.event_lock = (rwlock_t)
		      {
		      };
		    }

		    tp->t.malloc_initialized = 0;

		    tp->t.heapbytesize = 0;
		    tp->t.heapbytesallocated = 0;

		    for (i = 0; i < (((8) * sizeof (int)) > 16 ? 12 : 9); i++)
		      {
			tp->t.fragblocks[i] = 0;
			tp->t.fraghead[i].next = tp->t.fraghead[i].prev =
			  ((void *) 0);
		      }

		    tp->t.clientStateCounter = 0;
		    tp->t.state = 1;
		    tp->t.A = 0;
		    tp->t.D = 0;
		    tp->t.RTO = 0;
		    tp->t.timerState = 0;
		    tp->t.rcv_nxt = 0;
		    tp->t.previous_base = 0;
		    skb_queue_head_init (&tp->t.ofo_queue);

		    tp->t.ack_prev = ((void *) 0);

		    tp->t.ack_last = 0;
		    tp->t.oo_count = 0;
		    tp->t.in_flight = 0;

		    tp->t.standardProof.numSacks = 0;
		    tp->t.altProof.numSacks = 0;


		    tp->t.dprev = tp->t.dnext = ((void *) 0);
		    tp->t.dbg_skb = ((void *) 0);
		    init_head (&tp->t.cont_list);

		    init_timer (&tp->t.slowstart_timer);



		    tp->t.request_rcv_nxt = 0;
		    tp->t.request_snd_nxt = 0;
		    init_head (&tp->t.request_ofo_queue);
		    skb_queue_head_init (&tp->t.data_ofo_queue);
		    init_head (&tp->t.sentRequests);
		    init_head (&tp->t.queuedRequests);

		    init_head (&tp->t.dataRequestMap);
		    init_head (&tp->t.missingDataMap);
		    init_head (&tp->t.skipList);

		    tp->t.byteReqNext = 0;
		    tp->t.byteReqHint = ((void *) 0);
		    tp->t.byteRcvNxt = 0;



		    tp->t.conversionState = (1);
		    tp->t.snd_una = tp->t.write_seq = 0;
		    tp->t.snd_end = 0;
		    skb_queue_head_init (&tp->t.requestBytes);
		    tp->t.newIncompleteRequest = ((void *) 0);
		    tp->t.prevConvCont = ((void *) 0);

		    init_head (&tp->t.ucontList);
		    init_head (&tp->t.depNodeList);





		    tp->t.nonceCTX = ((void *) 0);
		    skb_queue_head_init (&tp->t.prequeueOverflow);
		    skb_queue_head_init (&tp->t.sendAckOverflow);
		    skb_queue_head_init (&tp->t.recycleList);

		    tp->t.responseMSK = ((void *) 0);
		    init_head (&tp->t.responseList);
		    tp->t.responseCount = 0;

		    tp->t.events = ((void *) 0);
		    tp->drop_rate = 0;
		    tp->instrumentation = 0;

		    tp->t.numServers = 0;
		    tp->t.probeRate = (100 / 4);



		    tp->t.requestNext = 0;
		  }




		  int trickles_mmap_impl (struct file *file,
					  struct socket *sock,
					  struct vm_area_struct *vma);
		  int trickles_sock_poll_impl (struct file *file,
					       struct socket *sock,
					       poll_table * wait);
		  void trickles_syn_piggyback_impl (struct sock *sk,
						    struct sk_buff *skb);


		  void trickles_close (struct sock *sk, long timeout);
		  int trickles_sendmsg (struct sock *sk, struct msghdr *msg,
					int size);

		  void trickles_init_sock_impl (struct sock *sk, int val);

		  int cminisock_config_pipe_impl (struct sock *sk,
						  char *optdata, int optlen,
						  int direction);
		  int trickles_sendv_impl (int fd, struct cminisock *msk,
					   struct tiovec *user_tiov,
					   int tiovlen);
		  int trickles_sendfilev_impl (int fd, struct cminisock *msk,
					       struct fiovec *user_fiov,
					       int fiovlen);
		  int trickles_send_impl (int fd, struct cminisock *msk,
					  char *buf, int len);

		  int trickles_setucont_impl (int fd, struct cminisock *msk,
					      int pkt_num, char *ucont,
					      unsigned ucont_len);

		  int trickles_setsockopt_impl (struct sock *sk, int optname,
						int optval);
		  int trickles_getsockopt_impl (struct sock *sk, int level,
						int optname, char *optval,
						int *optlen);

		  int trickles_client_recvmsg (struct sock *sk,
					       struct msghdr *msg, int len,
					       int nonblock, int flags,
					       int *addr_len);

		  struct mskdesc;
		  int trickles_sendbulk_impl (int fd, struct mskdesc *descbuf,
					      int descbuf_len);

		  int trickles_extract_events_impl (int fd,
						    struct extract_mskdesc_in
						    *descbuf, int descbuf_len,
						    struct msk_collection
						    *dest, int *destLen);
		  int trickles_install_events_impl (int fd,
						    struct msk_collection
						    *descbuf,
						    int descbuf_len);

		  int trickles_request_impl (int fd, char *buf, int buf_len,
					     int reserved_len);





		  struct trickles_mmap_ctl
		  {

		    void *rw_base;
		    int rw_offs;
		    __u32 rw_len;
		    struct cminisock *minisock_base;
		    void *minisock_limit;
		    void *heap_base;

		    void *ro_base;
		    int ro_offs;
		    int minisock_offs;

		    struct pminisock *pminisock_base;
		    int pminisock_offs;
		    void *pminisock_limit;

		    __u32 ro_len;

		    struct alloc_head_list msk_eventlist;
		    struct dlist pmsk_eventlist;

		    atomic_t update_since_poll;
		  };

		  extern int (*trickles_send_hook) (int fd,
						    struct cminisock * msk,
						    char *buf, int len);
		  int trickles_send_default (int fd, struct cminisock *msk,
					     char *buf, int len);

		  extern int (*trickles_sendv_hook) (int fd,
						     struct cminisock * msk,
						     struct tiovec * tiov,
						     int tiovlen);
		  int trickles_sendv_default (int fd, struct cminisock *msk,
					      struct tiovec *tiov,
					      int tiovlen);

		  extern int (*trickles_sendfilev_hook) (int fd,
							 struct cminisock *
							 msk,
							 struct fiovec * fiov,
							 int fiovlen);
		  int trickles_sendfilev_default (int fd,
						  struct cminisock *msk,
						  struct fiovec *fiov,
						  int fiovlen);

		  extern int (*trickles_mmap_hook) (struct file * file,
						    struct socket * sock,
						    struct vm_area_struct *
						    vma);
		  int trickles_mmap_default (struct file *file,
					     struct socket *sock,
					     struct vm_area_struct *vma);

		  extern int (*trickles_sock_poll_hook) (struct file * file,
							 struct socket * sock,
							 poll_table * wait);
		  int trickles_sock_poll_default (struct file *file,
						  struct socket *sock,
						  poll_table * wait);

		  extern void (*trickles_send_ack_hook) (struct sock * sk);
		  void trickles_send_ack_default (struct sock *sk);

		  extern int (*trickles_setucont_hook) (int fd,
							struct cminisock *
							msk, int pktNum,
							char *ucont,
							unsigned ucont_len);
		  int trickles_setucont_default (int fd,
						 struct cminisock *msk,
						 int pktNum, char *ucont,
						 unsigned ucont_len);

		  extern int (*trickles_setsockopt_hook) (struct sock * sk,
							  int optname,
							  int optval);
		  int trickles_setsockopt_default (struct sock *sk,
						   int optname, int optval);

		  extern int (*trickles_getsockopt_hook) (struct sock * sk,
							  int level,
							  int optname,
							  char *optval,
							  int *optlen);
		  int trickles_getsockopt_default (struct sock *sk, int level,
						   int optname, char *optval,
						   int *optlen);




		  extern void (*trickles_init_sock_hook) (struct sock * sk,
							  int val);
		  void trickles_init_sock_default (struct sock *sk, int val);

		  extern int (*trickles_sendmsg_hook) (struct sock * sk,
						       struct msghdr * msg,
						       int size);
		  int trickles_sendmsg_default (struct sock *sk,
						struct msghdr *msg, int size);

		  extern int (*trickles_sendbulk_hook) (int fd,
							struct mskdesc *
							descbuf,
							int descbuf_len);
		  int trickles_sendbulk_default (int fd,
						 struct mskdesc *descbuf,
						 int descbuf_len);

		  extern int (*trickles_extract_events_hook) (int fd,
							      struct
							      extract_mskdesc_in
							      * descbuf,
							      int descbuf_len,
							      struct
							      msk_collection *
							      dest,
							      int *destLen);
		  int trickles_extract_events_default (int fd,
						       struct
						       extract_mskdesc_in
						       *descbuf,
						       int descbuf_len,
						       struct msk_collection
						       *dest, int *destLen);

		  extern int (*trickles_install_events_hook) (int fd,
							      struct
							      msk_collection *
							      descbuf,
							      int
							      descbuf_len);
		  int trickles_install_events_default (int fd,
						       struct msk_collection
						       *descbuf,
						       int descbuf_len);

		  extern int (*trickles_request_hook) (int fd, char *buf,
						       int buf_len,
						       int reserved_len);
		  int trickles_request_default (int fd, char *buf,
						int buf_len,
						int reserved_len);

		  extern void (*trickles_syn_piggyback_hook) (struct sock *
							      sk,
							      struct sk_buff *
							      skb);
		  void trickles_syn_piggyback_default (struct sock *sk,
						       struct sk_buff *skb);










		  static void init_minisock (struct cminisock *msk)
		  {
		    msk->num_packets = 0;
		    msk->ucont_len = 0;
		    msk->ucont_data = ((void *) 0);
		    msk->input_len = 0;
		    msk->input = ((void *) 0);
		    msk->packets = ((void *) 0);

		    msk->refCnt = 1;

		    msk->cacheRecycleIndex = -1;
		    msk->serverSK = ((void *) 0);
		    msk->pmsk = ((void *) 0);
		    msk->isStatic = 0;
		  }

		  static void msk_initStatic (struct cminisock *msk)
		  {
		    init_minisock (msk);
		    msk->isStatic = 1;
		    msk->prev = msk->next = ((void *) 0);
		    msk->ctl = ALLOC_PENDING;
		  }

		  static void init_pminisock (struct pminisock *pmsk)
		  {
		    pmsk->num_packets = 0;
		    pmsk->ucont_len = 0;
		    pmsk->ucont_data = ((void *) 0);
		    pmsk->input_len = 0;
		    pmsk->input = ((void *) 0);
		    pmsk->packets = ((void *) 0);
		    pmsk->refCnt = 1;
		    pmsk->cacheRecycleIndex = -1;
		  }

		  static void free_msk (struct sock *sk,
					struct cminisock *msk);

		  static inline void msk_free_fields (struct sock *sk,
						      struct cminisock *msk)
		  {
		    free_msk (sk, msk);
		  }



		  static inline int alloc_msk_packets (struct cminisock *msk,
						       int numPackets)
		  {
		    if (msk->num_packets > 0)
		      {
			printk ("msk packets is %d\n", msk->num_packets);
		      }
		    if (!(msk->num_packets == 0))
		      {
			printk ("KERNEL: assertion (" "msk->num_packets == 0"
				") failed at "
				"/home/ashieh/current/include/net/trickles_minisock_functions.h"
				"(%d)\n", 53);
		      };
		    if (!(numPackets >= 0))
		      {
			printk ("KERNEL: assertion (" "numPackets >= 0"
				") failed at "
				"/home/ashieh/current/include/net/trickles_minisock_functions.h"
				"(%d)\n", 54);
		      };

		    static struct cminisock_packet packets[1][(8000)];
		    if (!
			(((msk->sk)->tp_pinfo.af_tcp.trickles_opt & 0x1)
			 && !((msk->sk)->tp_pinfo.af_tcp.
			      trickles_opt & (msk->sk)->tp_pinfo.af_tcp.
			      trickles_opt & 0x8)))
		      {
			msk->packets =
			  tmalloc (msk->sk,
				   sizeof (struct cminisock_packet) *
				   numPackets);



			if (msk->packets == ((void *) 0))
			  {
			    if ((0))
			      {
				printk
				  ("out of memory while tmalloc()'ing space for packets\n");
			      }
			    return 0;
			  }
		      }
		    else
		      {

			if (numPackets <= (8000))
			  {
			    msk->packets = packets[0];
			  }
			else
			  {
			    msk->packets = ((void *) 0);
			    if ((0))
			      {
				printk
				  ("Too many packets requested during simulation\n");
			      }
			    return 0;
			  }
		      }
		    msk->num_packets = numPackets;
		    return 1;
		  }

		  static inline int can_alloc_trickles_msk (struct sock *sk)
		  {
		    struct tcp_opt *tp = &(sk->tp_pinfo.af_tcp);
		    struct alloc_head_list *head =
		      &tp->cminisock_api_config.msk_freelist;
		    struct cminisock *curr = (struct cminisock *) head->next;
		    while ((struct alloc_head_list *) curr != head
			   && curr->ctl == ALLOC_PROCESSING)
		      {

			curr = curr->next;
		      }
		    return (struct alloc_head_list *) curr != head;
		  }

		  static struct pminisock *alloc_trickles_pmsk (struct sock
								*sk)
		  {
		    struct tcp_opt *tp = &(sk->tp_pinfo.af_tcp);
		    struct list_link *phead =
		      (struct list_link *) &tp->cminisock_api_config.
		      pmsk_freelist;
		    struct pminisock *rval = ((void *) 0), *pcurr =
		      (struct pminisock *) tp->cminisock_api_config.
		      pmsk_freelist.next;

		    if (!
			(((sk)->tp_pinfo.af_tcp.trickles_opt & 0x1)
			 && !((sk)->tp_pinfo.af_tcp.trickles_opt & (sk)->
			      tp_pinfo.af_tcp.trickles_opt & 0x8)))
		      {
			while ((struct list_link *) pcurr != phead &&
			       pcurr->ctl == ALLOC_PROCESSING)
			  {

			    pcurr = pcurr->next;
			  }

			if ((struct list_link *) pcurr == phead)
			  {
			    printk ("no list_link\n");
			    return ((void *) 0);
			  }
			dlist_unlink ((struct list_link *) pcurr);
		      }
		    else
		      {

			static struct pminisock pmsk;
			pcurr = &pmsk;
		      }

		    rval = pcurr;
		    rval->ctl = ALLOC_PENDING;

		    init_pminisock (rval);

		    return rval;
		  }

		  static inline struct cminisock *alloc_trickles_msk (struct
								      sock
								      *sk)
		  {
		    struct tcp_opt *tp = &(sk->tp_pinfo.af_tcp);
		    struct alloc_head_list *head =
		      &tp->cminisock_api_config.msk_freelist;
		    struct cminisock *rval = ((void *) 0), *curr =
		      (struct cminisock *) tp->cminisock_api_config.
		      msk_freelist.next;

		    if (!
			(((sk)->tp_pinfo.af_tcp.trickles_opt & 0x1)
			 && !((sk)->tp_pinfo.af_tcp.trickles_opt & (sk)->
			      tp_pinfo.af_tcp.trickles_opt & 0x8)))
		      {
			while ((struct alloc_head_list *) curr != head &&
			       curr->ctl == ALLOC_PROCESSING)
			  {

			    curr = curr->next;
			  }


			if ((struct alloc_head_list *) curr == head)
			  {
			    printk ("no alloc_head\n");
			    return ((void *) 0);
			  }

			rval = curr;
			unlink ((struct alloc_head *) rval);
			rval->ctl = ALLOC_PENDING;
		      }
		    else
		      {
			if (tp->t.responseCount == 0)
			  {
			    rval = tp->t.responseMSK;
			    rval->list = ((void *) 0);
			    rval->next = rval->prev = ((void *) 0);
			  }
			else
			  {
			    rval =
			      kmalloc (sizeof (struct cminisock), (0x20));
			    if (rval == ((void *) 0))
			      {
				printk
				  ("out of memory during compatibility mode\n");
				return ((void *) 0);
			      }
			    rval->next = rval->prev = ((void *) 0);
			    rval->list = ((void *) 0);
			    insert_tail (&tp->t.responseList,
					 (struct alloc_head *) rval);
			  }
			tp->t.responseCount++;

			rval->sk = sk;
			rval->ctl = ALLOC_PENDING;
		      }

		    init_minisock (rval);

		    return rval;
		  }



		  static void free_trickles_msk (struct sock *sk,
						 struct cminisock *msk);
		  static void free_trickles_msk_finish (struct sock *sk,
							struct cminisock
							*msk);

		  static void free_trickles_pmsk (struct sock *sk,
						  struct pminisock *msk);
		  static void free_trickles_pmsk_finish (struct sock *sk,
							 struct pminisock
							 *msk);

		  static inline void msk_hold (struct cminisock *msk)
		  {
		    msk->refCnt++;
		  } static struct cminisock *shallow_copy_msk (struct sock
							       *sk,
							       struct
							       cminisock
							       *pmsk)
		  {
		    struct cminisock *rval = alloc_trickles_msk (sk);
		    struct alloc_head_list head;
		    if (rval == ((void *) 0))
		      {
			struct tcp_opt *tp = &(sk->tp_pinfo.af_tcp);
			printk ("out of memory while shallow copying msk\n");
			printk ("list len is %d\n",
				tp->cminisock_api_config.msk_freelist.len);
			return ((void *) 0);
		      }
		    head = *(struct alloc_head_list *) rval;
		    *rval = *pmsk;
		    *(struct alloc_head_list *) rval = head;
		    rval->refCnt = 1;
		    rval->isStatic = 0;
		    return rval;
		  }
		  static struct cminisock *copy_msk (struct sock *sk,
						     struct cminisock *pmsk)
		  {
		    struct cminisock *rval = shallow_copy_msk (sk, pmsk);
		    if (rval == ((void *) 0))
		      {
			printk ("out of memory while copying msk\n");
			return ((void *) 0);
		      }
		    rval->num_packets = 0;
		    rval->packets = ((void *) 0);
		    rval->pmsk = ((void *) 0);
		    if (rval->ucont_len > 0)
		      {
			rval->ucont_data = tmalloc (sk, rval->ucont_len);
			if (rval->ucont_data == ((void *) 0))
			  {
			    printk
			      ("out of tmalloc memory while copying msk (len = %d)\n",
			       rval->ucont_len);
			    free_trickles_msk (sk, rval);
			    free_trickles_msk_finish (sk, rval);
			    return ((void *) 0);
			  }
		      }
		    else
		      {
			rval->ucont_data = ((void *) 0);
		    } if (rval->input_len > 0)
		      {
			rval->input = tmalloc (sk, rval->input_len);
			if (rval->input == ((void *) 0))
			  {
			    printk
			      ("out of tmalloc memory while copying msk (%s len = %d)\n",
			       "msk", rval->input_len);
			    tfree (sk, rval->ucont_data);
			    free_trickles_msk (sk, rval);
			    free_trickles_msk_finish (sk, rval);
			    return ((void *) 0);
			  }
		      }
		    else
		      {
			rval->input = ((void *) 0);
		    } if (rval->ucont_data)
		      (__builtin_constant_p (rval->ucont_len) ?
		       __constant_memcpy ((rval->ucont_data),
					  (pmsk->ucont_data),
					  (rval->
					   ucont_len)) : __memcpy ((rval->
								    ucont_data),
								   (pmsk->
								    ucont_data),
								   (rval->
								    ucont_len)));
		    if (rval->input)
		      (__builtin_constant_p (rval->input_len) ?
		       __constant_memcpy ((rval->input), (pmsk->input),
					  (rval->
					   input_len)) : __memcpy ((rval->
								    input),
								   (pmsk->
								    input),
								   (rval->
								    input_len)));
		    return rval;
		  }
		  static void free_trickles_msk (struct sock *sk,
						 struct cminisock *msk)
		  {
		    if (!
			(((sk)->tp_pinfo.af_tcp.trickles_opt & 0x1)
			 && !((sk)->tp_pinfo.af_tcp.trickles_opt & (sk)->
			      tp_pinfo.af_tcp.trickles_opt & 0x8)))
		      {
			if (msk->ctl == ALLOC_FREE
			    || msk->ctl == ALLOC_PROCESSING)
			  {
			    printk ("double free\n");
			    do
			      {
				if (!(0))
				  {
				    printk ("kgdb assertion failed: %s\n",
					    "BUG");
				    show_stack (((void *) 0));
				    breakpoint ();
				  }
			      }
			    while (0);
			  }
			if (msk->ctl == ALLOC_READY
			    && msk->prev != ((void *) 0))
			  {
			    unlink ((struct alloc_head *) msk);
			  }
			msk->ctl = ALLOC_PROCESSING;
		      }
		  } static void free_msk (struct sock *sk,
					  struct cminisock *msk)
		  {
		    int i;
		    for (i = 0; i < msk->num_packets; i++)
		      {
			if (msk->packets[i].ucontData != ((void *) 0))
			  {
			    kfree (msk->packets[i].ucontData);
			  }
		    }
		      if (!
			    (((sk)->tp_pinfo.af_tcp.trickles_opt & 0x1)
			       && !((sk)->tp_pinfo.af_tcp.
				      trickles_opt & (sk)->tp_pinfo.af_tcp.
				      trickles_opt & 0x8)) && msk->packets)
		      {
			tfree (sk, msk->packets);
			msk->packets = ((void *) 0);
		      }
		    msk->num_packets = 0;
		    if (msk->ucont_data != ((void *) 0))
		      {
			tfree (sk, msk->ucont_data);
			msk->ucont_data = ((void *) 0);
		      }
		    msk->ucont_len = 0;
		    if (msk->input != ((void *) 0))
		      {
			tfree (sk, msk->input);
			msk->input = ((void *) 0);
		      }
		    msk->input_len = 0;
		  } static void msk_release (struct sock *sk,
					     struct cminisock *msk)
		  {
		    msk->refCnt--;
		    if (!(msk->refCnt <= 3))
		      {
			printk ("KERNEL: assertion (" "msk->refCnt <= 3"
				") failed at "
				"/home/ashieh/current/include/net/trickles_minisock_functions.h"
				"(%d)\n", 381);
		      };
		    if (msk->refCnt == 0)
		      {
			struct tcp_opt *tp = &(sk->tp_pinfo.af_tcp);
			struct alloc_head_list *head =
			  &tp->cminisock_api_config.msk_freelist;
			free_msk (sk, msk);
			if (!msk->isStatic)
			  {
			    if (!
				(((sk)->tp_pinfo.af_tcp.trickles_opt & 0x1)
				 && !((sk)->tp_pinfo.af_tcp.
				      trickles_opt & (sk)->tp_pinfo.af_tcp.
				      trickles_opt & 0x8)))
			      {
				insert_head ((head),
					     (struct alloc_head *) (msk));
				msk->ctl = ALLOC_FREE;
			      }
			    else
			      {
				if (msk != tp->t.responseMSK)
				  {
				    unlink ((struct alloc_head *) msk);
				    kfree (msk);
				  }
				tp->t.responseCount--;
			  }}
		      }
		    else
		      {
		      }
		    if (msk->pmsk != ((void *) 0))
		      {
			struct pminisock *pmsk = msk->pmsk;
			free_trickles_pmsk (sk, pmsk);
			free_trickles_pmsk_finish (sk, pmsk);
		      };
		  } static void free_trickles_msk_finish (struct sock *sk,
							  struct cminisock
							  *msk)
		  {
		    if (!
			(((sk)->tp_pinfo.af_tcp.trickles_opt & 0x1)
			 && !((sk)->tp_pinfo.af_tcp.trickles_opt & (sk)->
			      tp_pinfo.af_tcp.trickles_opt & 0x8)))
		      {
			if (msk->ctl != ALLOC_PROCESSING
			    && msk->ctl != ALLOC_HALFFREE)
			  {
			    printk
			      ("(free_trickles_msk_finish %s) without corresponding free_trickles_msk: msk->ctl = %d\n",
			       "msk", msk->ctl);
			    do
			      {
				if (!(0))
				  {
				    printk ("kgdb assertion failed: %s\n",
					    "BUG");
				    show_stack (((void *) 0));
				    breakpoint ();
				  }
			      }
			    while (0);
			  }
		      }
		    msk_release (sk, msk);
		  }
		  static inline void msk_clear_fields (struct cminisock *msk)
		  {
		    msk->num_packets = 0;
		    msk->packets = ((void *) 0);
		    msk->ucont_len = 0;
		    msk->ucont_data = ((void *) 0);
		    msk->input_len = 0;
		    msk->input = ((void *) 0);
		  };

		  static inline void pmsk_hold (struct pminisock *msk)
		  {
		    msk->refCnt++;
		  } static struct pminisock *shallow_copy_pmsk (struct sock
								*sk,
								struct
								pminisock
								*pmsk)
		  {
		    struct pminisock *rval = alloc_trickles_pmsk (sk);
		    struct list_link head;
		    if (rval == ((void *) 0))
		      {
			struct tcp_opt *tp = &(sk->tp_pinfo.af_tcp);
			printk ("out of memory while shallow copying msk\n");;
			return ((void *) 0);
		      }
		    head = *(struct list_link *) rval;
		    *rval = *pmsk;
		    *(struct list_link *) rval = head;
		    rval->refCnt = 1;
		    return rval;
		  }
		  static struct pminisock *copy_pmsk (struct sock *sk,
						      struct pminisock *pmsk)
		  {
		    struct pminisock *rval = shallow_copy_pmsk (sk, pmsk);
		    if (rval == ((void *) 0))
		      {
			printk ("out of memory while copying msk\n");
			return ((void *) 0);
		      }
		    rval->num_packets = 0;
		    rval->packets = ((void *) 0);
		    if (rval->ucont_len > 0)
		      {
			rval->ucont_data = tmalloc (sk, rval->ucont_len);
			if (rval->ucont_data == ((void *) 0))
			  {
			    printk
			      ("out of tmalloc memory while copying msk (len = %d)\n",
			       rval->ucont_len);
			    free_trickles_pmsk (sk, rval);
			    free_trickles_pmsk_finish (sk, rval);
			    return ((void *) 0);
			  }
		      }
		    else
		      {
			rval->ucont_data = ((void *) 0);
		    } if (rval->input_len > 0)
		      {
			rval->input = tmalloc (sk, rval->input_len);
			if (rval->input == ((void *) 0))
			  {
			    printk
			      ("out of tmalloc memory while copying msk (%s len = %d)\n",
			       "pmsk", rval->input_len);
			    tfree (sk, rval->ucont_data);
			    free_trickles_pmsk (sk, rval);
			    free_trickles_pmsk_finish (sk, rval);
			    return ((void *) 0);
			  }
		      }
		    else
		      {
			rval->input = ((void *) 0);
		    } if (rval->ucont_data)
		      (__builtin_constant_p (rval->ucont_len) ?
		       __constant_memcpy ((rval->ucont_data),
					  (pmsk->ucont_data),
					  (rval->
					   ucont_len)) : __memcpy ((rval->
								    ucont_data),
								   (pmsk->
								    ucont_data),
								   (rval->
								    ucont_len)));
		    if (rval->input)
		      (__builtin_constant_p (rval->input_len) ?
		       __constant_memcpy ((rval->input), (pmsk->input),
					  (rval->
					   input_len)) : __memcpy ((rval->
								    input),
								   (pmsk->
								    input),
								   (rval->
								    input_len)));
		    return rval;
		  }
		  static void free_trickles_pmsk (struct sock *sk,
						  struct pminisock *msk)
		  {
		    if (!
			(((sk)->tp_pinfo.af_tcp.trickles_opt & 0x1)
			 && !((sk)->tp_pinfo.af_tcp.trickles_opt & (sk)->
			      tp_pinfo.af_tcp.trickles_opt & 0x8)))
		      {
			if (msk->ctl == ALLOC_FREE
			    || msk->ctl == ALLOC_PROCESSING)
			  {
			    printk ("double free\n");
			    do
			      {
				if (!(0))
				  {
				    printk ("kgdb assertion failed: %s\n",
					    "BUG");
				    show_stack (((void *) 0));
				    breakpoint ();
				  }
			      }
			    while (0);
			  }
			if (msk->ctl == ALLOC_READY
			    && msk->prev != ((void *) 0))
			  {
			    dlist_unlink ((struct list_link *) (msk));
			  }
			msk->ctl = ALLOC_PROCESSING;
		      }
		  } static void free_pmsk (struct sock *sk,
					   struct pminisock *msk)
		  {
		    int i;
		    for (i = 0; i < msk->num_packets; i++)
		      {
			if (msk->packets[i].ucontData != ((void *) 0))
			  {
			    kfree (msk->packets[i].ucontData);
			  }
		    }
		      if (!
			    (((sk)->tp_pinfo.af_tcp.trickles_opt & 0x1)
			       && !((sk)->tp_pinfo.af_tcp.
				      trickles_opt & (sk)->tp_pinfo.af_tcp.
				      trickles_opt & 0x8)) && msk->packets)
		      {
			tfree (sk, msk->packets);
			msk->packets = ((void *) 0);
		      }
		    msk->num_packets = 0;
		    if (msk->ucont_data != ((void *) 0))
		      {
			tfree (sk, msk->ucont_data);
			msk->ucont_data = ((void *) 0);
		      }
		    msk->ucont_len = 0;
		    if (msk->input != ((void *) 0))
		      {
			tfree (sk, msk->input);
			msk->input = ((void *) 0);
		      }
		    msk->input_len = 0;
		  } static void pmsk_release (struct sock *sk,
					      struct pminisock *msk)
		  {
		    msk->refCnt--;
		    if (!(msk->refCnt <= 3))
		      {
			printk ("KERNEL: assertion (" "msk->refCnt <= 3"
				") failed at "
				"/home/ashieh/current/include/net/trickles_minisock_functions.h"
				"(%d)\n", 392);
		      };
		    if (msk->refCnt == 0)
		      {
			struct tcp_opt *tp = &(sk->tp_pinfo.af_tcp);
			struct dlist *head =
			  &tp->cminisock_api_config.pmsk_freelist;
			free_pmsk (sk, msk);
			if (!
			    ((((sk)->tp_pinfo.af_tcp.trickles_opt & 0x1)
			      && !((sk)->tp_pinfo.af_tcp.trickles_opt & (sk)->
				   tp_pinfo.af_tcp.trickles_opt & 0x8))
			     || !(msk >=
				  (struct pminisock *) tp->
				  cminisock_api_config.cfg.ctl->pminisock_base
				  && (msk + 1) <=
				  (struct pminisock *) tp->
				  cminisock_api_config.cfg.ctl->
				  pminisock_limit)))
			  {
			    if (!
				(((sk)->tp_pinfo.af_tcp.trickles_opt & 0x1)
				 && !((sk)->tp_pinfo.af_tcp.
				      trickles_opt & (sk)->tp_pinfo.af_tcp.
				      trickles_opt & 0x8)))
			      {
				dlist_insert_head (head,
						   (struct list_link
						    *) (msk));
				msk->ctl = ALLOC_FREE;
			      }
			    else
			      {;
			      }
			  }
		      }
		    else
		      {
		      };
		  }
		  static void free_trickles_pmsk_finish (struct sock *sk,
							 struct pminisock
							 *msk)
		  {
		    if (!
			(((sk)->tp_pinfo.af_tcp.trickles_opt & 0x1)
			 && !((sk)->tp_pinfo.af_tcp.trickles_opt & (sk)->
			      tp_pinfo.af_tcp.trickles_opt & 0x8)))
		      {
			if (msk->ctl != ALLOC_PROCESSING
			    && msk->ctl != ALLOC_HALFFREE)
			  {
			    printk
			      ("(free_trickles_msk_finish %s) without corresponding free_trickles_msk: msk->ctl = %d\n",
			       "pmsk", msk->ctl);
			    do
			      {
				if (!(0))
				  {
				    printk ("kgdb assertion failed: %s\n",
					    "BUG");
				    show_stack (((void *) 0));
				    breakpoint ();
				  }
			      }
			    while (0);
			  }
		      }
		    pmsk_release (sk, msk);
		  }
		  static inline void pmsk_clear_fields (struct pminisock *msk)
		  {
		    msk->num_packets = 0;
		    msk->packets = ((void *) 0);
		    msk->ucont_len = 0;
		    msk->ucont_data = ((void *) 0);
		    msk->input_len = 0;
		    msk->input = ((void *) 0);
		  };

		  void pminisock_cache_child (struct sock *sk,
					      struct cminisock *msk,
					      struct pminisock *pmsk,
					      int packet_number, int flags);




		  static inline void recycle_headerinit (void *p)
		  {
		    struct sk_buff *skb = p;

		    skb->next = ((void *) 0);
		    skb->prev = ((void *) 0);
		    skb->list = ((void *) 0);
		    skb->sk = ((void *) 0);
		    skb->stamp.tv_sec = 0;
		    skb->dev = ((void *) 0);
		    skb->real_dev = ((void *) 0);
		    skb->dst = ((void *) 0);
		    (__builtin_constant_p (0)
		     ? (__builtin_constant_p ((sizeof (skb->cb))) ?
			__constant_c_and_count_memset (((skb->cb)),
						       ((0x01010101UL *
							 (unsigned
							  char) (0))),
						       ((sizeof (skb->cb)))) :
			__constant_c_memset (((skb->cb)),
					     ((0x01010101UL *
					       (unsigned char) (0))),
					     ((sizeof (skb->cb)))))
		     : (__builtin_constant_p ((sizeof (skb->cb))) ?
			__memset_generic ((((skb->cb))), (((0))),
					  (((sizeof (skb->cb))))) :
			__memset_generic (((skb->cb)), ((0)),
					  ((sizeof (skb->cb))))));
		    skb->pkt_type = 0;
		    skb->ip_summed = 0;
		    skb->priority = 0;
		    skb->security = 0;
		    skb->destructor = ((void *) 0);


		    skb->nfmark = skb->nfcache = 0;
		    skb->nfct = ((void *) 0);





		    skb->tc_index = 0;

		  }


		  static inline void save_for_recycle (struct sock *sk,
						       struct sk_buff *skb)
		  {
		    struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;
		    int r0 =
		      ((struct skb_shared_info *) ((skb)->end))->nr_frags !=
		      0, r1 = tp->t.recycleList.qlen >= (1000), r2 =
		      skb->truesize - sizeof (struct sk_buff) <
		      ((128 + 32) + (sizeof (WireTrickleResponse)) +
		       (sysctl_trickles_mss));
		    if (r0 || r1 || r2)
		      {
			if (r0 || r2)
			  {
			    if ((0))
			      printk
				("Unsuitable for recycling %d %d %d truesize = %d skblen = %d\n",
				 r0, r1, r2, skb->truesize,
				 ((128 + 32) +
				  (sizeof (WireTrickleResponse)) +
				  (sysctl_trickles_mss)));
			  }
			__kfree_skb (skb);
			return;
		      }

		    recycle_headerinit (skb);

		    skb->tail = skb->data = skb->head;
		    skb->len = 0;
		    skb->cloned = 0;
		    skb->data_len = 0;

		    (((&skb->users)->counter) = (1));
		    (((&
		       (((struct skb_shared_info *) ((skb)->end))->dataref))->
		      counter) = (1));
		    ((struct skb_shared_info *) ((skb)->end))->nr_frags = 0;
		    ((struct skb_shared_info *) ((skb)->end))->frag_list =
		      ((void *) 0);

		    __skb_queue_tail (&tp->t.recycleList, skb);
		  }






		  static inline struct sk_buff *recycle (struct sock *sk)
		  {
		    struct tcp_opt *tp = &sk->tp_pinfo.af_tcp;

		    struct sk_buff *skb =
		      __skb_dequeue_tail (&tp->t.recycleList);

		    return skb;
		  }










		  struct exception_table_entry;


		  struct kernel_sym
		  {
		    unsigned long value;
		    char name[60];
		  };

		  struct module_symbol
		  {
		    unsigned long value;
		    const char *name;
		  };

		  struct module_ref
		  {
		    struct module *dep;
		    struct module *ref;
		    struct module_ref *next_ref;
		  };


		  struct module_persist;

		  struct module
		  {
		    unsigned long size_of_struct;
		    struct module *next;
		    const char *name;
		    unsigned long size;

		    union
		    {
		      atomic_t usecount;
		      long pad;
		    } uc;

		    unsigned long flags;

		    unsigned nsyms;
		    unsigned ndeps;

		    struct module_symbol *syms;
		    struct module_ref *deps;
		    struct module_ref *refs;
		    int (*init) (void);
		    void (*cleanup) (void);
		    const struct exception_table_entry *ex_table_start;
		    const struct exception_table_entry *ex_table_end;






		    const struct module_persist *persist_start;
		    const struct module_persist *persist_end;
		    int (*can_unload) (void);
		    int runsize;
		    const char *kallsyms_start;
		    const char *kallsyms_end;
		    const char *archdata_start;
		    const char *archdata_end;
		    const char *kernel_data;
		  };

		  struct module_info
		  {
		    unsigned long addr;
		    unsigned long size;
		    unsigned long flags;
		    long usecount;
		  };

		  extern void inter_module_register (const char *,
						     struct module *,
						     const void *);
		  extern void inter_module_unregister (const char *);
		  extern const void *inter_module_get (const char *);
		  extern const void *inter_module_get_request (const char *,
							       const char *);
		  extern void inter_module_put (const char *);

		  struct inter_module_entry
		  {
		    struct list_head list;
		    const char *im_name;
		    struct module *owner;
		    const void *userdata;
		  };

		  extern int try_inc_mod_count (struct module *mod);

		  extern struct module __this_module;








		  static const char __module_kernel_version[]
		    __attribute__ ((section (".modinfo"))) =
		    "kernel_version=" "2.4.26-gdb-trickles";





		  struct vm_struct
		  {
		    unsigned long flags;
		    void *addr;
		    unsigned long size;
		    struct vm_struct *next;
		  };

		  extern struct vm_struct *get_vm_area (unsigned long size,
							unsigned long flags);
		  extern void vfree (void *addr);

		  extern void *vmap (struct page **pages, int count,
				     unsigned long flags, pgprot_t prot);
		  extern void *__vmalloc (unsigned long size, int gfp_mask,
					  pgprot_t prot);
		  extern long vread (char *buf, char *addr,
				     unsigned long count);
		  extern void vmfree_area_pages (unsigned long address,
						 unsigned long size);
		  extern int vmalloc_area_pages (unsigned long address,
						 unsigned long size,
						 int gfp_mask, pgprot_t prot);





		  static inline void *vmalloc (unsigned long size)
		  {
		    return __vmalloc (size,
				      (0x20 | 0x10 | 0x40 | 0x80 | 0x100) |
				      0x02, ((pgprot_t)
					     {
					     (((0x001 | 0x002 | 0x040 |
						0x020)) | 0x100)}
				      ));
		  }





		  static inline void *vmalloc_dma (unsigned long size)
		  {
		    return __vmalloc (size,
				      (0x20 | 0x10 | 0x40 | 0x80 | 0x100) |
				      0x01, ((pgprot_t)
					     {
					     (((0x001 | 0x002 | 0x040 |
						0x020)) | 0x100)}
				      ));
		  }





		  static inline void *vmalloc_32 (unsigned long size)
		  {
		    return __vmalloc (size,
				      (0x20 | 0x10 | 0x40 | 0x80 | 0x100),
				      ((pgprot_t)
				       {
				       (((0x001 | 0x002 | 0x040 | 0x020)) |
					0x100)}
				      ));
		  }





		  extern rwlock_t vmlist_lock;

		  extern struct vm_struct *vmlist;
















		  extern void fput (struct file *)
		    __attribute__ ((regparm (3)));
		  extern struct file *fget (unsigned int fd)
		    __attribute__ ((regparm (3)));

		  static inline int get_close_on_exec (unsigned int fd)
		  {
		    struct files_struct *files = get_current ()->files;
		    int res;
		    (void) (&files->file_lock);
		    res = (__extension__ (
					   {
					   unsigned char __result;
		    __asm__ __volatile__ ("btl %1,%2 ; setb %0": "=q" (__result):"r" ((int) (fd)), "m" (*
								  (__kernel_fd_set
								   *) (files->
								       close_on_exec)));
					   __result;
					   }));
		    do
		      {
		      }
		    while (0);
		    return res;
		  }

		  static inline void set_close_on_exec (unsigned int fd,
							int flag)
		  {
		    struct files_struct *files = get_current ()->files;
		    (void) (&files->file_lock);
		    if (flag)
		      __asm__
			__volatile__ ("btsl %1,%0":"=m"
				      (*(__kernel_fd_set *)
				       (files->
					close_on_exec)):"r" ((int) (fd)));
		    else
		  __asm__ __volatile__ ("btrl %1,%0": "=m" (*(__kernel_fd_set *) (files->close_on_exec)):"r" ((int)
			 (fd)));
		    do
		      {
		      }
		    while (0);
		  }

		  static inline struct file *fcheck_files (struct files_struct
							   *files,
							   unsigned int fd)
		  {
		    struct file *file = ((void *) 0);

		    if (fd < files->max_fds)
		      file = files->fd[fd];
		    return file;
		  }




		  static inline struct file *fcheck (unsigned int fd)
		  {
		    struct file *file = ((void *) 0);
		    struct files_struct *files = get_current ()->files;

		    if (fd < files->max_fds)
		      file = files->fd[fd];
		    return file;
		  }

		  extern void put_filp (struct file *);

		  extern int get_unused_fd (void);

		  static inline void __put_unused_fd (struct files_struct
						      *files, unsigned int fd)
		  {
		    __asm__
		      __volatile__ ("btrl %1,%0":"=m"
				    (*(__kernel_fd_set *)
				     (files->open_fds)):"r" ((int) (fd)));
		    if (fd < files->next_fd)
		      files->next_fd = fd;
		  }

		  static inline void put_unused_fd (unsigned int fd)
		  {
		    struct files_struct *files = get_current ()->files;

		    (void) (&files->file_lock);
		    __put_unused_fd (files, fd);
		    do
		      {
		      }
		    while (0);
		  }

		  void fd_install (unsigned int fd, struct file *file);
		  void put_files_struct (struct files_struct *fs);




		  struct rand_pool_info
		  {
		    int entropy_count;
		    int buf_size;
		    __u32 buf[0];
		  };





		  extern void rand_initialize (void);
		  extern void rand_initialize_irq (int irq);
		  extern void rand_initialize_blkdev (int irq, int mode);

		  extern void batch_entropy_store (u32 a, u32 b, int num);

		  extern void add_keyboard_randomness (unsigned char
						       scancode);
		  extern void add_mouse_randomness (__u32 mouse_data);
		  extern void add_interrupt_randomness (int irq);
		  extern void add_blkdev_randomness (int major);

		  extern void get_random_bytes (void *buf, int nbytes);
		  void generate_random_uuid (unsigned char uuid_out[16]);

		  extern __u32 secure_ip_id (__u32 daddr);
		  extern __u32 secure_tcp_sequence_number (__u32 saddr,
							   __u32 daddr,
							   __u16 sport,
							   __u16 dport);
		  extern __u32 secure_tcp_syn_cookie (__u32 saddr,
						      __u32 daddr,
						      __u16 sport,
						      __u16 dport, __u32 sseq,
						      __u32 count,
						      __u32 data);
		  extern __u32 check_tcp_syn_cookie (__u32 cookie,
						     __u32 saddr, __u32 daddr,
						     __u16 sport, __u16 dport,
						     __u32 sseq, __u32 count,
						     __u32 maxdiff);
		  extern __u32 secure_tcpv6_sequence_number (__u32 * saddr,
							     __u32 * daddr,
							     __u16 sport,
							     __u16 dport);

		  extern __u32 secure_ipv6_id (__u32 * daddr);







		  extern unsigned char _ctype[];

		  static inline unsigned char __tolower (unsigned char c)
		  {
		    if ((((_ctype[(int) (unsigned char) (c)]) & (0x01)) != 0))
		      c -= 'A' - 'a';
		    return c;
		  }

		  static inline unsigned char __toupper (unsigned char c)
		  {
		    if ((((_ctype[(int) (unsigned char) (c)]) & (0x02)) != 0))
		      c -= 'a' - 'A';
		    return c;
		  }




		  struct udphdr
		  {
		    __u16 source;
		    __u16 dest;
		    __u16 len;
		    __u16 check;
		  };





		  double sqrt (double x);
		  float sqrtf (float x);




		  static inline int hexdump_helper (void *ptr, int len,
						    int format_offset)
		  {
		    int i, newlined = 0, format_val;
		    char *data = (char *) ptr;
		    for (i = 0, format_val = format_offset;
			 i < len; i++, format_val++)
		      {
			printk ("%02X ", (unsigned char) data[i]);
			newlined = 0;
			if (format_val > 0)
			  {
			    int mod = format_val % (16);
			    if (mod == 0)
			      {
				printk ("\n");
				newlined = 1;
			      }
			    else if (mod == (16) / 2)
			      {
				printk ("- ");
			      }
			  }
		      }





		    return format_val;
		  }

		  static inline int hexdump (void *data, int len)
		  {
		    return hexdump_helper (data, len, 0);
		  }




		  typedef unsigned long int u4;
		  typedef unsigned char u1;

		  static inline
		    u4 hash (register u1 * k, u4 length, u4 initval)
		  {
		    register u4 a, b, c;
		    u4 len;


		    len = length;
		    a = b = 0x9e3779b9;
		    c = initval;


		    while (len >= 12)
		      {
			a =
			  a + (k[0] + ((u4) k[1] << 8) + ((u4) k[2] << 16) +
			       ((u4) k[3] << 24));
			b =
			  b + (k[4] + ((u4) k[5] << 8) + ((u4) k[6] << 16) +
			       ((u4) k[7] << 24));
			c =
			  c + (k[8] + ((u4) k[9] << 8) + ((u4) k[10] << 16) +
			       ((u4) k[11] << 24));
			{
			  a = a - b;
			  a = a - c;
			  a = a ^ (c >> 13);
			  b = b - c;
			  b = b - a;
			  b = b ^ (a << 8);
			  c = c - a;
			  c = c - b;
			  c = c ^ (b >> 13);
			  a = a - b;
			  a = a - c;
			  a = a ^ (c >> 12);
			  b = b - c;
			  b = b - a;
			  b = b ^ (a << 16);
			  c = c - a;
			  c = c - b;
			  c = c ^ (b >> 5);
			  a = a - b;
			  a = a - c;
			  a = a ^ (c >> 3);
			  b = b - c;
			  b = b - a;
			  b = b ^ (a << 10);
			  c = c - a;
			  c = c - b;
			  c = c ^ (b >> 15);
			};
			k = k + 12;
			len = len - 12;
		      }


		    c = c + length;
		    switch (len)
		      {
		      case 11:
			c = c + ((u4) k[10] << 24);
		      case 10:
			c = c + ((u4) k[9] << 16);
		      case 9:
			c = c + ((u4) k[8] << 8);

		      case 8:
			b = b + ((u4) k[7] << 24);
		      case 7:
			b = b + ((u4) k[6] << 16);
		      case 6:
			b = b + ((u4) k[5] << 8);
		      case 5:
			b = b + k[4];
		      case 4:
			a = a + ((u4) k[3] << 24);
		      case 3:
			a = a + ((u4) k[2] << 16);
		      case 2:
			a = a + ((u4) k[1] << 8);
		      case 1:
			a = a + k[0];

		      }
		    {
		      a = a - b;
		      a = a - c;
		      a = a ^ (c >> 13);
		      b = b - c;
		      b = b - a;
		      b = b ^ (a << 8);
		      c = c - a;
		      c = c - b;
		      c = c ^ (b >> 13);
		      a = a - b;
		      a = a - c;
		      a = a ^ (c >> 12);
		      b = b - c;
		      b = b - a;
		      b = b ^ (a << 16);
		      c = c - a;
		      c = c - b;
		      c = c ^ (b >> 5);
		      a = a - b;
		      a = a - c;
		      a = a ^ (c >> 3);
		      b = b - c;
		      b = b - a;
		      b = b ^ (a << 10);
		      c = c - a;
		      c = c - b;
		      c = c ^ (b >> 15);
		    };

		    return c;
		  }

		  static inline void byte_diff (const void *_a,
						const void *_b, int len)
		  {
		    int i;
		    int state = 0;
		    int runStart = -1;
		    const unsigned char *a = _a, *b = _b;
		    for (i = 0; i < len; i++)
		      {
			if (state == 0)
			  {
			    if (a[i] != b[i])
			      {
				runStart = i;
				state = 1;
			      }
			  }
			else if (state == 1)
			  {
			    if (a[i] == b[i])
			      {
				printk ("[%d-%d]: ", runStart, i - 1);
				int j;
				for (j = runStart; j < i; j++)
				  {
				    printk ("%02X,%02X ", a[j], b[j]);
				  }
				printk ("\n");
				state = 0;
			      }
			  }
		      }
		  }

		  static inline int list_integrityCheck (struct
							 alloc_head_list
							 *list)
		  {
		    int count = 0;
		    struct alloc_head *elem;
		    for (elem = (typeof (elem)) (list)->next;
			 (elem != (typeof (elem)) (list));
			 elem = (typeof (elem)) elem->next)
		      {
			do
			  {
			    if (!(elem->list == list))
			      {
				printk ("(%s) failed at %s:%s():%d\n",
					"elem->list == list", "cache_util.h",
					__PRETTY_FUNCTION__, 135);
				return 0;
			      }
			  }
			while (0);
			count++;
		      }
		    do
		      {
			if (!(count == list->len))
			  {
			    printk ("(%s) failed at %s:%s():%d\n",
				    "count == list->len", "cache_util.h",
				    __PRETTY_FUNCTION__, 138);
			    return 0;
			  }
		      }
		    while (0);
		    return 1;
		  }


		  static void dump_sk (struct sock *sk, int lineno)
		  {
		    struct tcp_opt *tp = &(sk->tp_pinfo.af_tcp);
		    printk ("At %d: %X:%d => %X:%d\n", lineno, sk->saddr,
			    (int) ntohs (sk->sport), sk->daddr,
			    (int) ntohs (sk->dport));
		  }

		  int userapi_pkt_spew = 0;
		  int userapi_time_spew = 0;

		  __u64 numTxPackets = 0;
		  __u64 numTxBytes = 0;

		  int debugSimulation = 0;

		  extern const int dbgBadChunk;

		  extern int gNumRecoveryStates;
		  extern int gNumBootstrapStates;
		  extern int gNumBootstrapResponses;

		  static struct cminisock cpu_msk[1];

		  void queue_upcall_msk_prealloc (struct sock *sk,
						  enum cminisock_event_tag,
						  struct cminisock *msk);
		  void queue_upcall_msk (enum cminisock_event_tag,
					 struct cminisock *msk);

		  void queue_upcall_pmsk_prealloc (struct sock *sk,
						   enum cminisock_event_tag,
						   struct pminisock *msk);
		  void queue_upcall_pmsk (enum cminisock_event_tag,
					  struct pminisock *msk);

		  void queue_upcall_deliver (struct sock *sk);



		  static int ExecuteTrickle (struct sock *sk,
					     struct sk_buff *skb,
					     enum cminisock_event_tag event);

		  static unsigned int mborg_isqrt4 (unsigned long val)
		  {
		    unsigned int temp, g = 0;

		    if (val >= 0x40000000)
		      {
			g = 0x8000;
			val -= 0x40000000;
		      }

		    temp = (g << (15)) + (1 << ((15) * 2 - 2));
		    if (val >= temp)
		      {
			g += 1 << ((15) - 1);
			val -= temp;
		      }
		    temp = (g << (14)) + (1 << ((14) * 2 - 2));
		    if (val >= temp)
		      {
			g += 1 << ((14) - 1);
			val -= temp;
		      }
		    temp = (g << (13)) + (1 << ((13) * 2 - 2));
		    if (val >= temp)
		      {
			g += 1 << ((13) - 1);
			val -= temp;
		      }
		    temp = (g << (12)) + (1 << ((12) * 2 - 2));
		    if (val >= temp)
		      {
			g += 1 << ((12) - 1);
			val -= temp;
		      }
		    temp = (g << (11)) + (1 << ((11) * 2 - 2));
		    if (val >= temp)
		      {
			g += 1 << ((11) - 1);
			val -= temp;
		      }
		    temp = (g << (10)) + (1 << ((10) * 2 - 2));
		    if (val >= temp)
		      {
			g += 1 << ((10) - 1);
			val -= temp;
		      }
		    temp = (g << (9)) + (1 << ((9) * 2 - 2));
		    if (val >= temp)
		      {
			g += 1 << ((9) - 1);
			val -= temp;
		      }
		    temp = (g << (8)) + (1 << ((8) * 2 - 2));
		    if (val >= temp)
		      {
			g += 1 << ((8) - 1);
			val -= temp;
		      }
		    temp = (g << (7)) + (1 << ((7) * 2 - 2));
		    if (val >= temp)
		      {
			g += 1 << ((7) - 1);
			val -= temp;
		      }
		    temp = (g << (6)) + (1 << ((6) * 2 - 2));
		    if (val >= temp)
		      {
			g += 1 << ((6) - 1);
			val -= temp;
		      }
		    temp = (g << (5)) + (1 << ((5) * 2 - 2));
		    if (val >= temp)
		      {
			g += 1 << ((5) - 1);
			val -= temp;
		      }
		    temp = (g << (4)) + (1 << ((4) * 2 - 2));
		    if (val >= temp)
		      {
			g += 1 << ((4) - 1);
			val -= temp;
		      }
		    temp = (g << (3)) + (1 << ((3) * 2 - 2));
		    if (val >= temp)
		      {
			g += 1 << ((3) - 1);
			val -= temp;
		      }
		    temp = (g << (2)) + (1 << ((2) * 2 - 2));
		    if (val >= temp)
		      {
			g += 1 << ((2) - 1);
			val -= temp;
		      }



		    temp = g + g + 1;
		    if (val >= temp)
		      g++;
		    return g;
		  }

		  int AckTCPCwnd (unsigned seq, const struct cminisock *cont,
				  int *hintResult)
		  {
		    int res, hint = -1;

		    unsigned startCwnd = cont->startCwnd;
		    unsigned ssthresh =
		      ({
		       typeof (({typeof (cont->ssthresh) Z =
				 (typeof (cont->ssthresh)) (startCwnd);
				 (
				   {
				   const typeof (cont->ssthresh) _x =
				   (cont->ssthresh);
				   const typeof (Z) _y = (Z);
				   (void) (&_x == &_y);
				   _x > _y ? _x : _y;
				   });
				 })) Z = (typeof ((
						    {
						    typeof (cont->
							    ssthresh) Z =
						    (typeof (cont->ssthresh))
						    (startCwnd);
						    (
						      {
						      const typeof (cont->
								    ssthresh)
						      _x = (cont->ssthresh);
						      const typeof (Z) _y =
						      (Z);
						      (void) (&_x == &_y);
						      _x > _y ? _x : _y;
						      });
						    }))) (((1 << 13) - 1));
			       (
				 {
				 const typeof ((
						 {
						 typeof (cont->ssthresh) Z =
						 (typeof (cont->ssthresh))
						 (startCwnd);
						 (
						   {
						   const typeof (cont->
								 ssthresh) _x
						   = (cont->ssthresh);
						   const typeof (Z) _y = (Z);
						   (void) (&_x == &_y);
						   _x > _y ? _x : _y;
						   });
						 })) _x = ((
							     {
							     typeof (cont->
								     ssthresh)
							     Z =
							     (typeof
							      (cont->
							       ssthresh))
							     (startCwnd);
							     (
							       {
							       const
							       typeof (cont->
								       ssthresh)
							       _x =
							       (cont->
								ssthresh);
							       const
							       typeof (Z) _y =
							       (Z);
							       (void) (&_x ==
								       &_y);
							       _x >
							       _y ? _x : _y;
							       });
							     }));
				 const typeof (Z) _y = (Z);
				 (void) (&_x == &_y);
				 _x < _y ? _x : _y;
				 });
			       });
		       unsigned TCPBase = cont->TCPBase;
		       unsigned additiveStart =
		       (ssthresh - startCwnd + TCPBase) + ssthresh;
		       seq = TCPBase + (seq - TCPBase) * 1 / 2;
		       if (seq < TCPBase)
		       {
		       if (!disableSevereErrors) ((
						    {
						    printk
						    ("Seq (%u) < TCPBase (%u)\n"
						     "\n", seq, TCPBase); 1;}
						  )); res = -1; goto done;}

		       if (seq < ssthresh - startCwnd + TCPBase)
		       {
		       res = startCwnd + (seq - TCPBase);}
		       else
		       if (ssthresh - startCwnd + TCPBase <= seq &&
			   seq < additiveStart)
		       {
		       res = ssthresh;}
		       else
		       {




		       int offset = seq - additiveStart;
		       int position, cwnd;
		       cwnd =
		       (((-1 << ((1) - 1)) +
			 mborg_isqrt4 ((1 << (2 * (1) - 2)) -
				       ((-
					 ((int) (ssthresh) *
					  ((int) (ssthresh) + 1)) -
					 2 * (((int) seq) -
					      (TCPBase))) << (2 *
							      (1))))) >> (1));
		       cwnd = ((
					    {
					    typeof ((cwnd)) Z =
					    (typeof ((cwnd))) (((1 << 13) -
								1)); (
									 {
									 const
									 typeof
									 ((cwnd)) _x = ((cwnd)); const typeof (Z) _y = (Z); (void) (&_x == &_y); _x < _y ? _x : _y;});})); position = (cwnd * (cwnd + 1) - ssthresh * (ssthresh + 1)) / 2; if (cwnd == ((1 << 13) - 1))
		       {
		       res = cwnd; hint = -1;}
		       else
		       {
		       if (offset >= position)
		       {
		       int cwnd_1 = ((
				       {
				       typeof ((cwnd + 1)) Z =
				       (typeof ((cwnd + 1))) (((1 << 13) -
							       1)); (
									{
									const
									typeof
									((cwnd
									  +
									  1))
									_x =
									((cwnd
									  +
									  1));
									const
									typeof
									(Z) _y
									= (Z);
									(void)
									(&_x
									 ==
									 &_y);
									_x <
									_y ?
									_x :
									_y;});})),
		       cwnd_2 = ((
							{
							typeof ((cwnd +
								 2)) Z =
							(typeof ((cwnd + 2)))
							(((1 << 13) - 1)); (
										{
										const
										typeof
										((cwnd + 2)) _x = ((cwnd + 2)); const typeof (Z) _y = (Z); (void) (&_x == &_y); _x < _y ? _x : _y;});})); if (offset < position + cwnd_1)
		       {
		       res = cwnd_1; hint = additiveStart + position + cwnd_1;}
		       else
		       {
		       if (!(offset < position + cwnd_1 + cwnd_2))
		       {



		       }
		       res = cwnd_2;
		       hint = additiveStart + position + cwnd_1 + cwnd_2;}
		       }
		       else
		       if (offset < position)
		       {
		       if (offset > position - cwnd)
		       {
		       res = cwnd; hint = additiveStart + position;}
		       else
		       {
		       if (!(offset > position - cwnd - (cwnd - 1)))
		       {



		       }
		       if ((cwnd - 1) < ssthresh)
		       {




		       }



		       res = cwnd - 1; hint = additiveStart + position - cwnd;}
		       }
		       }

		       }
		done:
		       ;
		       if (res > ((1 << 13) - 1))
		       res = ((1 << 13) - 1);
		       if (hintResult != ((void *) 0))
		       * hintResult = (hint >= 0) ? hint : -1;
		       ((struct cminisock *) cont)->mark = res; return res;}

		       inline int AckTCPCwndScalar (unsigned seq,
						    const struct cminisock
						    *cont)
		       {
		       return AckTCPCwnd (seq, cont, ((void *)0));}

		       int Sack_validate (struct cminisock *cont, Sack * sack)
		       {
		       if (sack->left > sack->right)
		       {
		       return 0;}

		       if (!0)
		       {
		       __u32 genNonce =
		       generateRangeNonce (cont->sk, sack->left, sack->right);
		       if (genNonce != sack->nonceSummary)
		       {




		       if ((0))
		       {
		       printk
		       ("nonce check failed for [%d-%d] = 0x%0X != 0x%0X\n",
			sack->left, sack->right, genNonce,
			sack->nonceSummary);}
		       return 0;}
		       }





		       return 1;}

		       inline int Sack_contains (Sack * sack, int seq)
		       {
		       return sack->left <= seq && seq <= sack->right;}

		       inline int Sack_gapLen (Sack * left, Sack * right)
		       {
		       return right->left - left->right - 1;}

		       inline int Sack_adjacent (Sack * left, Sack * right)
		       {
		       return Sack_gapLen (left, right) == 0;}

		       int AckProof_isPoisoned (AckProof * proof, Sack * sack)
		       {

		       return 0;}

		       int AckProof_validate (AckProof * proof)
		       {
		       int i;
		       struct cminisock * cont = proof->cont;
		       Sack * sacks = proof->sacks;
		       int numSacks = proof->numSacks;
		       if (numSacks == 0 || numSacks > 64 ||
			   sacks[0].left > cont->TCPBase)
		       {
		       if (!disableSevereErrors)
		       printk
		       ("Zero sacks (%d), too many sacks, or start (%u) > TCPBase (%u) [seq = %u]\n",
			numSacks, sacks[0].left, cont->TCPBase, cont->seq);
		       return 0;}
		       for (i = 0; i < numSacks; i++)
		       {
		       if (!Sack_validate (cont, &sacks[i]))
		       {
		       return 0;}
		       if (i > 0 && sacks[i].left <= sacks[i - 1].right)
		       {
		       return 0;}
		       }
		       return 1;}


		       int AckProof_firstLoss (AckProof * proof)
		       {
		       int i, numSacks = proof->numSacks;
		       Sack * sacks = proof->sacks;
		       for (i = 1; i < numSacks; i++)
		       {
		       if (!Sack_adjacent (&sacks[i - 1], &sacks[i]))
		       {
		       return sacks[i - 1].right + 1;}
		       }
		       ((
			  {
			  printk ("No loss!\n" "\n"); 1;}
			)); return -1;}

		       enum CheckRangeResult AckProof_checkRange (AckProof *
								  proof,
								  int left,
								  int right)
		       {
		       int i;
		       int cursor;
		       int poisoned = 0;
		       Sack * sacks = proof->sacks;
		       cursor = left; for (i = 0; i < proof->numSacks; i++)
		       {
		       if (Sack_contains (&sacks[i], cursor))
		       {
		       if (AckProof_isPoisoned (proof, &sacks[i]))
		       {
		       poisoned = 1;}
		       cursor = sacks[i].right + 1; if (cursor > right) break;}
		       }
		       if (i == proof->numSacks)
		       {
		       return BADRANGE;}
		       return poisoned ? POISONEDRANGE : NORMALRANGE;}

		       __u32 AckProof_findRight (AckProof * proof, int start)
		       {
		       int i;
		       int cursor;
		       int poisoned = 0;
		       Sack * sacks = proof->sacks;
		       cursor = start; for (i = 0; i < proof->numSacks; i++)
		       {
		       if (Sack_contains (&sacks[i], cursor))
		       {
		       if (AckProof_isPoisoned (proof, &sacks[i]))
		       {
		       poisoned = 1;}
		       cursor = sacks[i].right + 1;}
		       }
		       if (cursor > start) return cursor - 1;
		       else
		       return start - 1;}

		       __u32 AckProof_findLeft (AckProof * proof, int start)
		       {
		       int i;
		       int cursor;
		       int poisoned = 0;
		       Sack * sacks = proof->sacks;
		       cursor = start;
		       for (i = proof->numSacks - 1; i >= 0; i--)
		       {
		       if (Sack_contains (&sacks[i], cursor))
		       {
		       if (AckProof_isPoisoned (proof, &sacks[i]))
		       {
		       poisoned = 1;}
		       cursor = sacks[i].left - 1;}
		       }
		       if (cursor < start) return cursor + 1;
		       else
		       return start + 1;}

		       static int DoNormalStep (struct cminisock **cont,
						AckProof * ackProof,
						enum cminisock_event_tag
						event);
		       static int DoRecoveryStep (struct cminisock **cont,
						  AckProof * ackProof,
						  enum cminisock_event_tag
						  event);
		       static int DoSlowStartStep (struct cminisock **cont,
						   AckProof * ackProof,
						   __u32 newBase,
						   enum cminisock_event_tag
						   event);
		       void AckProof_dump (AckProof * proof)
		       {
		       int i;
		       printk ("proof(%d) = ", proof->numSacks);
		       for (i = 0; i < proof->numSacks; i++)
		       {
		       printk ("[%d-%d]", proof->sacks[i].left,
			       proof->sacks[i].right);}
		       printk ("\n");}

		       WireTrickleRequest *
		       WireTrickleRequest_extract (struct sock *serverSK,
						   struct sk_buff *skb,
						   struct cminisock **pmsk,
						   int *error)
		       {
		       int sacks_len;
		       WireTrickleRequest * req =
		       (WireTrickleRequest *) skb->data;
		       int ucont_len, input_len;
		       char *ucont_data = ((void *)0), *input = ((void *)0);
		       struct cminisock * msk = (
						       {
						       struct cminisock *
						       __msk = &cpu_msk[0];
						       msk_initStatic (__msk);
						       __msk;});
		       struct pminisock * lookup, *packed_msk;
		       *pmsk = ((void *) 0); *error = 22;;
		       if (!pskb_may_pull (skb, sizeof (*req)))
		       {
		       if ((0))
		       {
		       printk
		       ("SKB too short for WireTrickleRequest, len = %d\n",
			skb->len);}
		       return ((void *) 0);}

		       ;
		       __skb_pull (skb, sizeof (*req));
		       sacks_len = req->ackProof.numSacks * sizeof (WireSack);
		       if (!(req->ackProof.numSacks <= 64 &&
			     pskb_may_pull (skb, sacks_len)))
		       {
		       printk
		       ("SKB too short for WireTrickleRequest (either too many sacks, or not enough space in packet header for sacks\n");
		       goto free_and_return;}
		       __skb_pull (skb, sacks_len);;
		       ucont_len = ntohs (req->ucont_len);
		       if (!pskb_may_pull (skb, ucont_len))
		       {
		       printk
		       ("WireTrickleRequest_extract: skb too short for ucont\n");
		       goto free_and_return;}
		       ;
		       if (!
			   (((serverSK)->tp_pinfo.af_tcp.trickles_opt & 0x1)
			    && !((serverSK)->tp_pinfo.af_tcp.
				 trickles_opt & (serverSK)->tp_pinfo.af_tcp.
				 trickles_opt & 0x8)))
		       {
		       ; if (ucont_len > 0)
		       {
		       ucont_data = tmalloc (serverSK, ucont_len);
		       if (ucont_data == ((void *) 0))
		       {





		       *error = 12; goto free_and_return;}
		       char *pkt_ucont_data;
		       (__builtin_constant_p (ucont_len) ?
			__constant_memcpy ((ucont_data),
					   (pkt_ucont_data =
					    (char *) skb->data),
					   (ucont_len)) :
			__memcpy ((ucont_data),
				  (pkt_ucont_data =
				   (char *) skb->data), (ucont_len)));
		       __skb_pull (skb, ucont_len);}
		       else
		       {
		       ucont_data = ((void *) 0);}
		       }
		       else
		       {
		       ; ucont_len = 0; ucont_data = ((void *) 0);}

		       if (!(skb->len >= 0))
		       {
		       printk ("KERNEL: assertion (" "skb->len >= 0"
			       ") failed at " "trickles-server.c" "(%d)\n",
			       536);};
		       if (!
			   (((serverSK)->tp_pinfo.af_tcp.trickles_opt & 0x1)
			    && !((serverSK)->tp_pinfo.af_tcp.
				 trickles_opt & (serverSK)->tp_pinfo.af_tcp.
				 trickles_opt & 0x8)))
		       {
		       ; input_len = skb->len; if (input_len > 0)
		       {
		       input = tmalloc (serverSK, input_len);;
		       if (input == ((void *) 0))
		       {





		       *error = 12; goto free_and_return;}
		       (__builtin_constant_p (input_len) ?
			__constant_memcpy ((input), ((char *) skb->data),
					   (input_len)) : __memcpy ((input),
								    ((char *)
								     skb->
								     data),
								    (input_len)));}
		       else
		       {
		       ; input = ((void *) 0);}
		       }
		       else
		       {
		       ; input_len = 0; input = ((void *) 0);}

		       __u32 seqno = ntohl (req->cont.seq); if ((0))
		       {
		       printk ("continuation cache forced off\n");}
		       if (!
			   (((serverSK)->tp_pinfo.af_tcp.trickles_opt & 0x1)
			    && !((serverSK)->tp_pinfo.af_tcp.
				 trickles_opt & (serverSK)->tp_pinfo.af_tcp.
				 trickles_opt & 0x8)) && 0
			   && sysctl_trickles_Continuation_enable)
		       {
		       ;
		       if ((lookup = pminisock_lookup (serverSK, seqno,
						       skb->nh.iph,
						       skb->h.th)) !=
			   ((void *) 0))
		       {
		       ;
		       struct WireContinuation * scont = &req->cont;
		       msk->sk = msk->serverSK = serverSK;
		       unmarshallContinuationServerPMSK2MSK (serverSK, msk,
							     lookup);
		       msk->pmsk = packed_msk = lookup;
		       msk->seq = ntohl (scont->seq);
		       msk->firstChild = packed_msk->firstChild =
		       scont->firstChild;
		       msk->clientState = packed_msk->clientState =
		       scont->clientState;
		       msk->parent = packed_msk->parent = scont->parent;
		       msk->clientTimestamp = packed_msk->clientTimestamp =
		       scont->clientTimestamp;
		       if (!
			   (msk->saddr == skb->nh.iph->daddr
			    && msk->daddr == skb->nh.iph->saddr
			    && msk->source == skb->h.th->dest
			    && msk->dest == skb->h.th->source))
		       {
		       printk ("KERNEL: assertion ("
			       "msk->saddr == skb->nh.iph->daddr && msk->daddr == skb->nh.iph->saddr && msk->source == skb->h.th->dest && msk->dest == skb->h.th->source"
			       ") failed at " "trickles-server.c" "(%d)\n",
			       607);}; if (!(msk->ctl == ALLOC_PENDING))
		       {
		       printk ("KERNEL: assertion ("
			       "msk->ctl == ALLOC_PENDING" ") failed at "
			       "trickles-server.c" "(%d)\n", 609);};
		       msk->ucont_len = ucont_len;
		       msk->ucont_data = ucont_data;
		       ucont_data = ((void *) 0); msk->input_len = input_len;
		       msk->input = input; input = ((void *) 0);;}
		       else
		       {
		       ; goto lookup_failed;}
		       }
		       else
		       {
		    lookup_failed:
		       ;
		       if (!
			   (((serverSK)->tp_pinfo.af_tcp.trickles_opt & 0x1)
			    && !((serverSK)->tp_pinfo.af_tcp.
				 trickles_opt & (serverSK)->tp_pinfo.af_tcp.
				 trickles_opt & 0x8)))
		       {
		       msk = (
			       {
			       struct cminisock * __msk = &cpu_msk[0];
			       msk_initStatic (__msk); __msk;});}
		       else
		       {
		       msk = alloc_trickles_msk (serverSK);}
		       skb->sk = msk->sk = msk->serverSK = serverSK;
		       packed_msk = alloc_trickles_pmsk (serverSK);
		       if (packed_msk == ((void *) 0))
		       {
		       printk ("no space for pmsk in extract\n");
		       return ((void *) 0);}
		       msk->pmsk = packed_msk;
		       if (!unmarshallContinuationServerMSK
			   (skb, msk, &req->cont))
		       {

		       if ((0)) printk ("Mac error\n"); goto free_and_return;}
		       msk->ucont_len = ucont_len;
		       msk->ucont_data = ucont_data;
		       ucont_data = ((void *) 0); msk->input_len = input_len;
		       msk->input = input; input = ((void *) 0);;}
		  ; *error = 0; *pmsk = msk; return req; free_and_return:
		       ; if (ucont_data != ((void *) 0))
		       {
		       tfree (serverSK, ucont_data);}
		       if (input != ((void *) 0))
		       {
		       tfree (serverSK, input);}
		       if (msk != ((void *) 0))
		       {
		       free_trickles_msk (serverSK, msk);
		       free_trickles_msk_finish (serverSK, msk);}
		       return ((void *) 0);}

		       static inline void pre_init_sock (struct cminisock
							 *msk,
							 struct sk_buff *skb)
		       {

		       if (!
			   (((msk->sk)->tp_pinfo.af_tcp.trickles_opt & 0x1)
			    && !((msk->sk)->tp_pinfo.af_tcp.
				 trickles_opt & (msk->sk)->tp_pinfo.af_tcp.
				 trickles_opt & 0x8)))
		       {
		       msk->saddr = skb->nh.iph->daddr;
		       msk->source = skb->h.th->dest;
		       msk->daddr = skb->nh.iph->saddr;
		       msk->dest = skb->h.th->source;}
		       }


		       void DoUpcall (struct cminisock *msk,
				      enum cminisock_event_tag event)
		       {
		       int i;
		       struct NonceCtx ctx;
		       if (!
			   (((msk->sk)->tp_pinfo.af_tcp.trickles_opt & 0x1)
			    && !((msk->sk)->tp_pinfo.af_tcp.
				 trickles_opt & (msk->sk)->tp_pinfo.af_tcp.
				 trickles_opt & 0x8)))
		       {
		       int responseLen = 0;
		       ctx.new = 1; for (i = 0; i < msk->num_packets; i++)
		       {
		       msk->packets[i].nonce =
		       generateSingleNonce (msk->sk, msk->packets[i].seq,
					    &ctx);
		       msk->packets[i].ucontLen = 0;
		       msk->packets[i].ucontData = ((void *) 0);
		       responseLen = 0;}

		       ;
		       unmarshallContinuationServerMSK2PMSK (msk->sk,
							     msk->pmsk, msk);
		       queue_upcall_pmsk_prealloc (msk->sk, event, msk->pmsk);
		       queue_upcall_pmsk (event, msk->pmsk);
		       struct cminisock * copy =
		       shallow_copy_msk (msk->serverSK, msk);
		       if (copy == ((void *) 0))
		       {
		       printk (" ran out of memory just before upcall\n");
		       free_trickles_msk (msk->serverSK, msk);
		       free_trickles_msk_finish (msk->serverSK, msk); return;}
		       queue_upcall_msk_prealloc (msk->sk, event, copy);
		       queue_upcall_msk (event, copy);
		       queue_upcall_deliver (msk->sk);}
		       }


		       static inline int doInitialCwnd (struct cminisock *msk,
							enum
							cminisock_event_tag
							tag, int seqno,
							int num_packets)
		       {
		       if (tag == SYN)
		       {
		       msk->ucont_len = 0;
		       msk->clientState = 0;
		       msk->mrtt = 0;
		       msk->firstLoss = 0x1055;
		       msk->firstBootstrapSeq = 0xb007;
		       msk->ssthresh = 0x3fff;}
		       msk->TCPBase = seqno;
		       if (!alloc_msk_packets (msk, num_packets))
		       {
		       return -12;}
		       int i, first = 1; for (i = 0; i < num_packets; i++)
		       {
		       __u32 seq = seqno + i;
		       makePacket (&msk->packets[i], seq, 1,
				   (sysctl_trickles_mss),
				   (first ? (0x80) : 0) | (0), (1),
				   1 * (sysctl_trickles_mss), -1, 1);
		       first = 0;}
		       msk->num_packets = num_packets; DoUpcall (msk, tag);
		       return 0;}

		       int server_rcv_impl (struct sock *sk,
					    struct sk_buff *in_skb)
		       {

		       int rval = -22;
		       struct tcphdr * ith = in_skb->h.th;
		       struct tcp_opt * tp = &(sk->tp_pinfo.af_tcp);
		       struct cminisock * msk;
		       if (0
			   && !(((sk)->tp_pinfo.af_tcp.trickles_opt & 0x1)
				&& !((sk)->tp_pinfo.af_tcp.
				     trickles_opt & (sk)->tp_pinfo.af_tcp.
				     trickles_opt & 0x8)))
		       {
		       static int count;
		       printk ("server_rcv_impl: %d\n", count++);}

		       ;;;;
		       if (!
			   (((sk)->tp_pinfo.af_tcp.trickles_opt & 0x1)
			    && !((sk)->tp_pinfo.af_tcp.trickles_opt & (sk)->
				 tp_pinfo.af_tcp.trickles_opt & 0x8))
			   && !((tp)->cminisock_api_config.cfg.mmap_base !=
				((void *) 0)
				&& (tp)->cminisock_api_config.cfg.ctl !=
				((void *) 0)))
		       {
		       printk ("Not configured\n"); goto out;}

		       ;
		       if ((((sk)->tp_pinfo.af_tcp.trickles_opt & 0x1)
			    && !((sk)->tp_pinfo.af_tcp.trickles_opt & (sk)->
				 tp_pinfo.af_tcp.trickles_opt & 0x8)))
		       {
		       goto normal;}
		       if (ith->syn)
		       {
		       if ((((sk)->tp_pinfo.af_tcp.trickles_opt & 0x1)
			    && !((sk)->tp_pinfo.af_tcp.trickles_opt & (sk)->
				 tp_pinfo.af_tcp.trickles_opt & 0x8)))
		       {
		       msk = alloc_trickles_msk (sk);}
		       else
		       {
		       msk = (
			       {
			       struct cminisock * __msk = &cpu_msk[0];
			       msk_initStatic (__msk);
			       __msk;});} msk->serverSK = sk; msk->sk = sk;
		       in_skb->sk = sk; pre_init_sock (msk, in_skb);;
		       __u32 firstSeq; if (ith->ack)
		       {
		       printk
		       ("warning: trickles server cannot handle syn/ack\n");}
		       firstSeq = 1;
		       msk->tokenCounterBase = tp->bigTokenCounter;
		       tp->bigTokenCounter += ((__u64) 1) << 32;
		       int num_packets; msk->input_len = in_skb->len;
		       if (msk->input_len > 0)
		       {

		       msk->input = tmalloc (in_skb->sk, msk->input_len);
		       if (msk->input == ((void *) 0))
		       {
		       if ((0))
		       {
		       printk
		       ("Could not allocate memory for SYN, len = %d\n",
			msk->input_len);}
		       goto out;}
		       (__builtin_constant_p (msk->input_len) ?
			__constant_memcpy ((msk->input),
					   ((char *) in_skb->data),
					   (msk->
					    input_len)) : __memcpy ((msk->
								     input),
								    ((char *)
								     in_skb->
								     data),
								    (msk->
								     input_len)));
		       num_packets = msk->startCwnd = (3);}
		       else
		       {

		       msk->input = ((void *) 0); num_packets = 1;
		       do
		       {
		       (msk)->startCwnd = 0;}
		       while (0);}
		       msk->pmsk = alloc_trickles_pmsk (sk);
		       if (msk->pmsk == ((void *) 0))
		       {
		       goto out;}


		       if (doInitialCwnd (msk, SYN, firstSeq, num_packets) !=
			   0) goto out;}
		       else
		       if (ith->fin)
		       {



		       ;
		       printk ("FIN execute trickle\n");
		       ExecuteTrickle (sk, in_skb, FIN);}
		       else
		       if (ith->rst)
		       {

		       return 0;}
		       else
		       {
		    normal:


		       ; ExecuteTrickle (sk, in_skb, ACK);}

		  ; return 0; out_dealloc_msk:
		       if (rval != -12)
		       {

		       free_trickles_msk (sk, msk);
		       free_trickles_msk_finish (sk, msk);}
		  out:
		       return rval;}

		       static int ExecuteTrickle (struct sock *sk,
						  struct sk_buff *skb,
						  enum cminisock_event_tag
						  event)
		       {

		       int rval = -22;
		       int error;
		       AckProof ackProof;
		       struct cminisock * cont;
		       WireTrickleRequest * treq_hdr =
		       WireTrickleRequest_extract (sk, skb, &cont, &error);
		       if (treq_hdr == ((void *) 0))
		       {
		       if (error == 22)
		       {
		       if ((0))
		       {
		       printk
		       ("ExecuteTrickle: Could not find request header, or mac failed\n");}
		       return -22;}
		       else
		       {
		       if (!(error == 12))
		       {
		       printk ("KERNEL: assertion (" "error == ENOMEM"
			       ") failed at " "trickles-server.c" "(%d)\n",
			       915);}; return -12;}
		       }

		       if (cont == ((void *) 0))
		       {
		       if ((0)) printk ("out of memory\n"); return -12;}

		       enum CheckRangeResult rangeCheck;;;;;;;
		       cont->executionTrace = 0;
		       if (!
			   (((cont->sk)->tp_pinfo.af_tcp.trickles_opt & 0x1)
			    && !((cont->sk)->tp_pinfo.af_tcp.
				 trickles_opt & (cont->sk)->tp_pinfo.af_tcp.
				 trickles_opt & 0x8)))
		       {
		       cont->ack_seq = skb->h.th->ack_seq;
		       cont->dbg_timestamp = jiffies;}


		       ;;
		       unmarshallAckProof (&ackProof, &treq_hdr->ackProof);;
		       ackProof.cont = cont;;
		       if (!
			   (((cont->sk)->tp_pinfo.af_tcp.trickles_opt & 0x1)
			    && !((cont->sk)->tp_pinfo.af_tcp.
				 trickles_opt & (cont->sk)->tp_pinfo.af_tcp.
				 trickles_opt & 0x8))
			   && !AckProof_validate (&ackProof))
		       {

		       if ((((skb->sk)->tp_pinfo.af_tcp.trickles_opt & 0x1)
			    && !((skb->sk)->tp_pinfo.af_tcp.
				 trickles_opt & (skb->sk)->tp_pinfo.af_tcp.
				 trickles_opt & 0x8))
			   && debugSimulation)
		       printk ("ackproof validation failed\n"); return -22;}

		       ;; if (serverDebugLevel >= 2)
		       {
		       printk ("Server processing: %u\n", cont->seq);
		       AckProof_dump (&ackProof);}


		       ;
		       rangeCheck =
		       AckProof_checkRange (&ackProof, cont->TCPBase,
					    cont->seq);;
		       switch ((enum TrickleRequestType) treq_hdr->type)
		       {
case TREQ_NORMAL:
		       {

		       cont->mrtt -= cont->mrtt >> 3;
		       cont->mrtt += jiffies - cont->timestamp;
		       (cont)->timestamp = jiffies;; switch (cont->state)
		       {
case CONT_NORMAL:
		       if (serverDebugLevel >= 2)
		       printk ("Normal request => Normal state\n");
		       switch (rangeCheck)
		       {
case NORMALRANGE:
		       if (serverDebugLevel >= 2)
		       printk ("  Normal Range\n");;

; rval = DoNormalStep (&cont, &ackProof, event);; break; case POISONEDRANGE:
case BADRANGE:
		       if (serverDebugLevel >= 2)
		       {
		       printk ("  Bad or poisoned Range (ack # %u)\n",
			       cont->seq); AckProof_dump (&ackProof);}
		       rval = DoRecoveryStep (&cont, &ackProof, event); break;}
break; case CONT_RECOVERY:
		       if (serverDebugLevel >= 1)
		       printk ("Normal request => Recovery state\n");
		       gNumRecoveryStates++; switch (rangeCheck)
		       {
default:

		       break;}
break; case CONT_BOOTSTRAP:
		       if (serverDebugLevel >= 1)
		       printk ("Normal request => Bootstrap state\n");
		       gNumBootstrapStates++; switch (rangeCheck)
		       {
case POISONEDRANGE:
		       if (serverDebugLevel >= 1)
		       printk ("  Poisoned Range\n");
		       if (!
			   (AckProof_checkRange
			    (&ackProof, cont->TCPBase,
			     cont->firstLoss - 1) == NORMALRANGE
			    && AckProof_checkRange (&ackProof,
						    cont->firstBootstrapSeq,
						    cont->seq) ==
			    NORMALRANGE))
		       {
		       ((
			  {
			  printk
			  ("poisoned packets where normal packets should be\n"
			   "\n"); 1;}
			)); goto slow_start;}
case NORMALRANGE:
if (serverDebugLevel >= 1) printk ("  Normal Range\n"); cont->TCPBase = cont->firstBootstrapSeq; if (serverDebugLevel >= 1) printk ("Bootstrap: TCPBase = %u CWND = %u SSTHRESH = %u\n", cont->TCPBase, cont->startCwnd, cont->ssthresh);; rval = DoNormalStep (&cont, &ackProof, event); break; case BADRANGE:
			    if (serverDebugLevel >= 1) printk ("  Bad Range\n"); slow_start:
		       if (serverDebugLevel >= 1)
		       {
		       printk ("slow start bad range: ");
		       AckProof_dump (&ackProof);}
rval = DoRecoveryStep (&cont, &ackProof, event); break; default:
		       printk ("  unknown state\n"); return -22;}
		       break;}
		       break;}
case TREQ_SLOWSTART:
		       {
		       __u32 seq;
		       cont->mrtt = (jiffies - cont->timestamp) << 3;
		       (cont)->timestamp = jiffies; if (serverDebugLevel >= 1)
		       {
		       printk ("Slow Start request => \n");
		       AckProof_dump (&ackProof);}
		       seq = AckProof_findRight (&ackProof, cont->TCPBase);
		       if (seq < cont->TCPBase)
		       {
		       printk ("  SlowStart: seq < cont->TCPBase\n");
		       return -22;}
		       rval =
		       DoSlowStartStep (&cont, &ackProof, seq + 1, event);
		       break;}
default:
		       printk ("  unknown request type\n");}

		       ; return rval;}

		       int msk_transmit_skb (struct cminisock *msk,
					     struct sk_buff *skb,
					     int packet_num)
		       {


		       static int packetID = 0;
		       int tcp_header_size;
		       struct tcphdr * th;
		       struct sock * sk;
		       struct tcp_func * af = &ipv4_specific;
		       struct WireTrickleResponse * resp_hdr;
		       int err;
		       struct cminisock_packet * packet =
		       &msk->packets[packet_num];
		       int ucontLen = packet->ucontLen;
		       int origSkbLen = skb->len;

		       sk = skb->sk = msk->sk;
		       if (userapi_time_spew)
		       printk ("transmit time: %lu\n", jiffies);
		       if (!(ucontLen >= 0))
		       {
		       printk ("KERNEL: assertion (" "ucontLen >= 0"
			       ") failed at " "trickles-server.c" "(%d)\n",
			       1173);}; if (ucontLen > 0)
		       {
		       if (packet->ucontData != ((void *) 0))
		       {
		       (__builtin_constant_p (ucontLen) ?
			__constant_memcpy ((skb_push (skb, ucontLen)),
					   (packet->ucontData),
					   (ucontLen)) :
			__memcpy ((skb_push (skb, ucontLen)),
				  (packet->ucontData), (ucontLen)));}
		       else
		       {

		       }
		       }

		       if (packet->contType & (0x80))
		       {
		       printk ("hash compressed\n");

		       printk
		       ("msk_transmit_skb: hash compress not enabled\n");
		       do
		       {
		       if (!(0))
		       {
		       printk ("kgdb assertion failed: %s\n", "BUG");
		       show_stack (((void *) 0)); breakpoint ();}}
		       while (0);}
		       else
		       {

		       switch (packet->contType)
		       {
case (0):
resp_hdr = (WireTrickleResponse *) skb_push (skb, (sizeof (WireTrickleResponse) - ((sizeof (struct WireContinuation)) - ((int) (((struct WireContinuation *) 0)->minimalContinuationEnd))))); resp_hdr->cont.seq = htonl (packet->seq); resp_hdr->cont.continuationType = (0); resp_hdr->cont.clientState = msk->clientState; resp_hdr->cont.parent = msk->parent; resp_hdr->cont.clientTimestamp = msk->clientTimestamp; break; case (1):
case (2):

		       resp_hdr =
		       (WireTrickleResponse *) skb_push (skb,
							 sizeof
							 (WireTrickleResponse));
		       marshallContinuationServer (sk, &resp_hdr->cont, msk,
						   packet_num);

		       if (sysctl_trickles_Continuation_enable)
		       {
		       if (((msk->pmsk)->cacheRecycleIndex >= 0))
		       {
		       pminisock_cache_child (msk->serverSK, msk,
					      msk->pmsk, packet_num,
					      (0x1) | (0x2));}
		       else
		       {

		       msk->pmsk->cacheRecycleIndex = msk->cacheRecycleIndex =
		       packet_num;
		       if (!(packet_num == msk->pmsk->cacheRecycleIndex))
		       {
		       printk ("KERNEL: assertion ("
			       "packet_num == msk->pmsk->cacheRecycleIndex"
			       ") failed at " "trickles-server.c" "(%d)\n",
			       1258);};}
		       }
break; default:
		       resp_hdr = ((void *) 0);
		       do
		       {
		       if (!(0))
		       {
		       printk ("kgdb assertion failed: %s\n", "BUG");
		       show_stack (((void *) 0)); breakpoint ();}}
		       while (0);}
		       }
		       resp_hdr->nonce = packet->nonce;
		       resp_hdr->ucont_len = htons ((short) ucontLen);
		       resp_hdr->numSiblings = packet->numSiblings;
		       resp_hdr->position = packet->position;
		       tcp_header_size = sizeof (struct tcphdr) + 4;
		       th = (struct tcphdr *) skb_push (skb, tcp_header_size);
		       skb->h.th = th;
		       th->source = sk->sport;
		       th->dest = msk->dest;
		       th->seq = htonl (packet->seq);
		       static int gSendPacketNumber = 0; if (sysctl_dbg_cwnd)
		       {
		       trickles_logCwnd_hook (CWND_RECORD,
					      msk->daddr, msk->dest,
					      packet->seq, gSendPacketNumber,
					      msk->startCwnd, msk->mark,
					      msk->ssthresh, msk->mrtt,
					      msk->mrtt);}
		       th->ack_seq = packetID; packetID++;
		       th->doff = tcp_header_size >> 2; th->res1 = 0;
		       th->cwr = 0; th->ece = 0; th->urg = 0; th->ack = 1;
		       th->psh = 0; th->rst = 0; th->syn = 0; th->fin = 0;
		       th->window = 0; th->check = 0; th->urg_ptr = 0;
		       *(__u32 *) (th + 1) =
		       htonl ((11 << 24) | (4 << 16) |
			      ((__u16)
			       (sizeof (WireTrickleResponse) +
				msk->ucont_len))); switch (msk->tag)
		       {
case SYN:
		       if (packet_num == 0)
		       {
		       th->syn = 1; th->ack = 1;}
		       else
		       {
		       goto ack;}
break; case FIN:
printk ("sending fin\n"); th->fin = 1; break; case ACK:
			    ack:
th->ack = 1; break; default:
		       printk ("msk_transmit_skb: unsupported event tag\n");}

		       numTxPackets++;
		       numTxBytes += skb->len;
		       if (!(sk->protocol == IPPROTO_TCP))
		       {
		       printk ("KERNEL: assertion ("
			       "sk->protocol == IPPROTO_TCP" ") failed at "
			       "trickles-server.c" "(%d)\n", 1350);};
		       trickles_checksum (skb, skb->len - origSkbLen);
		       err = af->queue_xmit (skb, 0); return err;}

		       void NormalizeContinuation (struct cminisock *cont,
						   AckProof * ackProof)
		       {

		       }

		       static int DoNormalStep (struct cminisock **cont,
						AckProof * ackProof,
						enum cminisock_event_tag
						event)
		       {

		       int i, numPackets = 0;
		       __u32 first_ack_seq =
		       (((*cont)->continuationType) ==
			(2) ? ((*cont)->seq) - 1 : ((*cont)->seq)),
		       firstResponseSeq; int prevCwnd, currCwnd;
		       int numOutput;
		       int first = 1, thisResponseLen = 0, hint; __u32 offset;
		       if (((*cont)->startCwnd == 0))
		       {

		       (*cont)->startCwnd = (3);
		       return doInitialCwnd (*cont, event, (*cont)->seq + 1,
					     (*cont)->startCwnd);}

		       (*cont)->executionTrace = 1;;;;;
		       prevCwnd = (first_ack_seq == (*cont)->TCPBase) ?
		       (*cont)->startCwnd :
		       AckTCPCwnd (first_ack_seq - 1, (*cont), &hint);;
		       currCwnd = AckTCPCwndScalar ((*cont)->seq, (*cont));
		       (*cont)->actualCwnd = currCwnd;; numOutput = (
									   {
									   typeof
									   (0)
									   Z =
									   (typeof
									    (0))
									   (currCwnd
									    -
									    (int)
									    prevCwnd);
									   (
										      {
										      const
										      typeof
										      (0)
										      _x
										      =
										      (0);
										      const
										      typeof
										      (Z)
										      _y
										      =
										      (Z);
										      (void)
										      (&_x
										       ==
										       &_y);
										      _x
										      >
										      _y
										      ?
										      _x
										      :
										      _y;});});
		       switch ((*cont)->continuationType)
		       {
case (1):
numOutput += 1; break; case (2):
numOutput += 2; break; default:
		       do
		       {
		       if (!(0))
		       {
		       printk ("kgdb assertion failed: %s\n", "BUG");
		       show_stack (((void *) 0)); breakpoint ();}}
		       while (0);}

		       if (prevCwnd < 0 || currCwnd < 0)
		       {

		       if ((0))
		       {
		       ((
			  {
			  printk
			  ("Error in acktcpcwnd base = %d %d=>%d %d=>%d\n"
			   "\n", (*cont)->TCPBase, first_ack_seq - 1,
			   prevCwnd, (*cont)->seq, currCwnd); 1;}
			));}
		       free_trickles_msk ((*cont)->sk, *cont);
		       free_trickles_msk_finish ((*cont)->sk, *cont);
		       return -22;}
		       if (numOutput < 0)
		       {
		       ((
			  {
			  printk ("Decrease in AckTCPCwnd\n" "\n"); 1;}
			)); numOutput = 0;}
		       if (numOutput > 5)
		       {
		       printk
		       ("bug in cwnd generation: ack_seq = %u-%u, TCPBase = %u, "
			"cwnd = %u, numOutput = %u, \n", first_ack_seq,
			(*cont)->seq, (*cont)->TCPBase, (*cont)->startCwnd,
			numOutput); free_trickles_msk ((*cont)->sk, (*cont));
		       free_trickles_msk_finish ((*cont)->sk, (*cont));
		       return -22;}
		       ; NormalizeContinuation (*cont, ackProof);;
		       firstResponseSeq = first_ack_seq + prevCwnd;
		       if (!alloc_msk_packets ((*cont), numOutput))
		       {
		       free_trickles_msk ((*cont)->sk, (*cont));
		       free_trickles_msk_finish ((*cont)->sk, (*cont));
		       return -12;}
		       for (i = 0; i < numOutput; i++)
		       {
		       __u32 seq = firstResponseSeq + i;
		       int thisMSS, nextResponseLen = 0, firstChild = -1,
		       numChildren = -1, contType; if (serverDebugLevel >= 1)
		       {
		       if ((*cont)->state == CONT_BOOTSTRAP)
		       {
		       printk ("  %u\n", seq);}
		       }

		       offset = seq - (*cont)->TCPBase;
		       contType =
		       (((offset) <
			 (7)) ? (1) : ((((offset)) % 2 == 0) ? (2) : (0)));

		       switch (contType)
		       {
case (1):
case (2):
thisMSS = (sysctl_trickles_mss); break; case (0):
thisMSS = ((sysctl_trickles_mss) + sizeof (struct WireContinuation) - (int) ((struct WireContinuation *) 0)->minimalContinuationEnd); break; default:
		       thisMSS = -1;
		       do
		       {
		       if (!(0))
		       {
		       printk ("kgdb assertion failed: %s\n", "BUG");
		       show_stack (((void *) 0)); breakpoint ();}}
		       while (0);}

		       thisResponseLen += thisMSS;
		       makePacket (&(*cont)->packets[numPackets], seq,
				   0xdeadbeef, thisMSS,
				   (first ? (0x80) : 0) | (0), contType,
				   nextResponseLen, firstChild, numChildren);
		       first = 0; numPackets++;}
		       (*cont)->num_packets = numPackets;
		       if (!(numPackets <= numOutput))
		       {
		       printk ("KERNEL: assertion (" "numPackets <= numOutput"
			       ") failed at " "trickles-server.c" "(%d)\n",
			       1601);};;; DoUpcall ((*cont), event);;
		       return 0;}


		       static int intersect (int start0, int end0, int start1,
					     int end1)
		       {
		       int start = (
				     {
				     typeof (start0) Z =
				     (typeof (start0)) (start1); (
								    {
								    const
								    typeof
								    (start0)
								    _x =
								    (start0);
								    const
								    typeof (Z)
								    _y = (Z);
								    (void)
								    (&_x ==
								     &_y);
								    _x >
								    _y ? _x :
								    _y;});}),
		       end = (
					     {
					     typeof (end0) Z =
					     (typeof (end0)) (end1); (
									{
									const
									typeof
									(end0)
									_x =
									(end0);
									const
									typeof
									(Z) _y
									= (Z);
									(void)
									(&_x
									 ==
									 &_y);
									_x <
									_y ?
									_x :
									_y;});});
		       if (start <= end)
		       {

		       return end - start + 1;}
		       else
		       {
		       return 0;}
		       }

		       static int DoRecoveryStep (struct cminisock **cont,
						  AckProof * ackProof,
						  enum cminisock_event_tag
						  event)
		       {
		       if (!(!((*cont)->startCwnd == 0)))
		       {
		       printk ("KERNEL: assertion ("
			       "!IS_DEFERRED_INITIALCWND(*cont)"
			       ") failed at " "trickles-server.c" "(%d)\n",
			       1632);}; int i; Sack * sacks = ackProof->sacks;
		       int numLosses = 0, numBootstrapLosses =
		       0, bootstrapStart, bootstrapEnd, afterGap =
		       0, gapLeft = ((int)(~0U >> 1)), gapRight =
		       ((int)(~0U >> 1)); unsigned numPackets = 0;
		       int origCwnd, origCwndPred =
		       ((int)(~0U >> 1)), newCwnd;
		       int gaplen = ((int)(~0U >> 1));
		       int adj = ((int)(~0U >> 1)); __u32 ack_seq;
		       __u32 lastRegularPacket; int numPacketsSendable;
		       int numPacketsAllocated;
		       int bootstrapIntersectStart, bootstrapIntersectLast;
		       (*cont)->executionTrace = 2;
		       origCwnd =
		       AckTCPCwndScalar (AckProof_firstLoss (ackProof),
					 (*cont)); if (origCwnd < 0)
		       {
		       if (!disableSevereErrors)
		       printk ("recoveryStep: OrigCwnd undefined\n");
		       free_trickles_msk ((*cont)->sk, (*cont));
		       free_trickles_msk_finish ((*cont)->sk, (*cont));
		       return -22;}
		       (*cont)->state = CONT_RECOVERY;
		       (*cont)->firstLoss = AckProof_firstLoss (ackProof);
		       switch (((((*cont)->firstLoss - (*cont)->TCPBase) <
				 (7)) ? (1)
				: (((((*cont)->firstLoss -
				      (*cont)->TCPBase)) % 2 ==
				    0) ? (2) : (0))))
		       {
case (1):
case (0):
origCwndPred = AckTCPCwndScalar (AckProof_firstLoss (ackProof) - 1, (*cont)); adj = 0; break; case (2):
		       origCwndPred =
		       AckTCPCwndScalar (AckProof_firstLoss (ackProof) - 2,
					 (*cont)); adj = -1; break;}
		       if (origCwnd < origCwndPred)
		       {
		       printk ("recoveryStep: OrigCwnd < OrigCwndPred\n");
		       free_trickles_msk ((*cont)->sk, (*cont));
		       free_trickles_msk_finish ((*cont)->sk, (*cont));
		       return -22;}
		       lastRegularPacket =
		       ((*cont)->firstLoss - 1 + adj) + origCwndPred;
		       (*cont)->num_packets = 0; newCwnd = origCwnd / 2;
		       (*cont)->actualCwnd = newCwnd;
		       (*cont)->TCPBase = (*cont)->firstBootstrapSeq =
		       lastRegularPacket + 1; (*cont)->startCwnd = newCwnd;
		       if (newCwnd == 0) (*cont)->ssthresh /= 2;
		       else
		       (*cont)->ssthresh = newCwnd;
		       bootstrapStart = lastRegularPacket - newCwnd;
		       bootstrapEnd = bootstrapStart + newCwnd - 1;
		       for (i = 0; i < ackProof->numSacks; i++)
		       {
		       int cursorgap = 0;
		       if (i > 0 && !Sack_adjacent (&sacks[i - 1], &sacks[i]))
		       {
		       gaplen = Sack_gapLen (&sacks[i - 1], &sacks[i]);
		       cursorgap = 1;
		       numLosses += gaplen;
		       numBootstrapLosses +=
		       intersect (bootstrapStart, sacks[i].left - 1,
				  bootstrapEnd, sacks[i - 1].right + 1);}
		       if (Sack_contains (&ackProof->sacks[i], (*cont)->seq))
		       {
		       if (((*cont)->seq == sacks[i].left ||
			    ((*cont)->continuationType == (2)
			     && (*cont)->seq - 1 == sacks[i].left))
			   && cursorgap)
		       {

		       afterGap = 1;
		       gapLeft = ackProof->sacks[i - 1].right + 1,
		       gapRight = ackProof->sacks[i].left - 1;}
		       }
		       }

		       if (serverDebugLevel >= 2)
		       {
		       printk ("RecoveryStep\n"); AckProof_dump (ackProof);}


		       numPacketsSendable = 0;
		       numPacketsAllocated = 0; if (afterGap)
		       {
		       int start, end;
		       numPacketsAllocated += (gapRight - gapLeft) + 1;
		       start = (
				   {
				   typeof (gapLeft) Z =
				   (typeof (gapLeft)) (bootstrapStart); (
									   {
									   const
									   typeof
									   (gapLeft)
									   _x
									   =
									   (gapLeft);
									   const
									   typeof
									   (Z)
									   _y
									   =
									   (Z);
									   (void)
									   (&_x
									    ==
									    &_y);
									   _x
									   >
									   _y
									   ?
									   _x
									   :
									   _y;});});
		       end = (
						      {
						      typeof (gapRight) Z =
						      (typeof (gapRight))
						      (bootstrapEnd); (
									  {
									  const
									  typeof
									  (gapRight)
									  _x =
									  (gapRight);
									  const
									  typeof
									  (Z)
									  _y =
									  (Z);
									  (void)
									  (&_x
									   ==
									   &_y);
									  _x <
									  _y ?
									  _x :
									  _y;});});
		       if (start <= end)
		       {
		       numPacketsAllocated += (end - start) + 1;}
		       }
		       {

		       bootstrapIntersectStart = (
						   {
						   typeof ((((*cont)->
							     continuationType)
							    ==
							    (2) ? ((*cont)->
								   seq) -
							    1 : ((*cont)->
								 seq))) Z =
						   (typeof
						    ((((*cont)->
						       continuationType) ==
						      (2) ? ((*cont)->seq) -
						      1 : ((*cont)->
							   seq))))
						   (bootstrapStart); (
										    {
										    const
										    typeof
										    ((((*cont)->continuationType) == (2) ? ((*cont)->seq) - 1 : ((*cont)->seq))) _x = ((((*cont)->continuationType) == (2) ? ((*cont)->seq) - 1 : ((*cont)->seq))); const typeof (Z) _y = (Z); (void) (&_x == &_y); _x > _y ? _x : _y;});}); bootstrapIntersectLast = (
																																											  {
																																											  typeof
																																											  ((*cont)->seq) Z = (typeof ((*cont)->seq)) (bootstrapEnd); (
																																																			{
																																																			const
																																																			typeof
																																																			((*cont)->seq) _x = ((*cont)->seq); const typeof (Z) _y = (Z); (void) (&_x == &_y); _x < _y ? _x : _y;});}); if (bootstrapIntersectStart <= bootstrapIntersectLast)
		       {
		       numPacketsAllocated +=
		       bootstrapIntersectLast - bootstrapIntersectStart + 1;}
		       }
		       if (numPacketsAllocated == 0)
		       {
		       free_trickles_msk ((*cont)->sk, (*cont));
		       free_trickles_msk_finish ((*cont)->sk, (*cont));
		       return 0;}
		       if (!alloc_msk_packets ((*cont), numPacketsAllocated))
		       {
		       free_trickles_msk ((*cont)->sk, (*cont));
		       free_trickles_msk_finish ((*cont)->sk, (*cont));
		       printk ("recovery nomem\n"); return -12;}

		       if (afterGap)
		       {
		       __u32 seq; if (serverDebugLevel >= 1)
		       {
		       printk ("  Bootstrap [%d - %d], newCwnd %d\n",
			       bootstrapStart, bootstrapEnd, newCwnd);
		       printk ("  Gaplen = %d (after gap)\n", gaplen);}

		       if (gapRight - gapLeft > 20)
		       {

		       free_trickles_msk ((*cont)->sk, (*cont));
		       free_trickles_msk_finish ((*cont)->sk, (*cont));
		       if ((0))
		       printk ("recovery gapsize too big - %d\n",
			       gapRight - gapLeft); return -22;}
		       for (seq = gapLeft; seq <= gapRight; seq++)
		       {
		       if (serverDebugLevel >= 1)
		       {

		       }

		       makePacket (&(*cont)->packets[numPackets], seq,
				   0xdeadbeef,
				   ((sysctl_trickles_mss) +
				    sizeof (struct WireContinuation) -
				    (int) ((struct WireContinuation *) 0)->
				    minimalContinuationEnd), (1), (0),
				   ((sysctl_trickles_mss) +
				    sizeof (struct WireContinuation) -
				    (int) ((struct WireContinuation *) 0)->
				    minimalContinuationEnd), -1, -1);
		       numPackets++;
		       if (seq >= bootstrapStart && seq <= bootstrapEnd)
		       {
		       gNumBootstrapResponses++;
		       __u32 bootstrap_seq =
		       lastRegularPacket + 1 + (seq - bootstrapStart);
		       unsigned firstChild;
		       int numChildren, prevCwnd, currCwnd;
		       if (serverDebugLevel >= 1)
		       {

		       }
		       if (seq == bootstrapStart)
		       {

		       }
		       if (bootstrap_seq == (*cont)->TCPBase)
		       {

		       firstChild = bootstrap_seq + (*cont)->startCwnd;
		       numChildren = 1;}
		       else
		       {
		       prevCwnd = AckTCPCwndScalar (bootstrap_seq - 1, *cont);
		       currCwnd = AckTCPCwndScalar (bootstrap_seq, *cont);
		       firstChild = bootstrap_seq + prevCwnd;
		       numChildren = currCwnd - prevCwnd + 1;}


		       makePacket (&(*cont)->packets[numPackets],
				   bootstrap_seq, 0xdeadbeef,
				   (sysctl_trickles_mss), (2), (1),
				   (sysctl_trickles_mss), firstChild,
				   numChildren); numPackets++;}
		       }
		       if (serverDebugLevel >= 1)
		       {
		       printk ("  After RTX: %u packets\n", numPackets);}
		       }
		       else
		       {
		       if (serverDebugLevel >= 2)
		       {
		       printk ("  Not after gap\n");}
		       }

		       if (!
			   ((*cont)->continuationType == (1)
			    || (*cont)->continuationType == (2)))
		       {
		       printk ("KERNEL: assertion ("
			       "(*cont)->continuationType == CONTTYPE_FULL1 || (*cont)->continuationType == CONTTYPE_FULL2"
			       ") failed at " "trickles-server.c" "(%d)\n",
			       1842);};
		       for (ack_seq = bootstrapIntersectStart;
			    ack_seq <= bootstrapIntersectLast; ack_seq++)
		       {


		       __u32 seq =
		       lastRegularPacket + 1 + (ack_seq - bootstrapStart);
		       unsigned firstChild;
		       int numChildren, prevCwnd, currCwnd;
		       if (serverDebugLevel >= 1) printk ("  Bootstrap %u\n",
							  seq);
		       if (seq == (*cont)->TCPBase)
		       {

		       firstChild = seq + (*cont)->startCwnd; numChildren = 1;}
		       else
		       {
		       prevCwnd = AckTCPCwndScalar (seq - 1, *cont);
		       currCwnd = AckTCPCwndScalar (seq, *cont);
		       firstChild = seq + prevCwnd;
		       numChildren = currCwnd - prevCwnd + 1;}


		       makePacket (&(*cont)->packets[numPackets], seq,
				   0xdeadbeef, (sysctl_trickles_mss), (2),
				   (1), (sysctl_trickles_mss), firstChild,
				   numChildren); numPackets++;
		       if (serverDebugLevel >= 1)
		       {
		       printk ("  After bootstrap: %u packets\n", numPackets);}
		       }
		       numPacketsSendable = numPackets;
		       (*cont)->num_packets = numPackets;
		       if (numPacketsSendable > numPacketsAllocated)
		       {
		       printk ("Sendable = %d, allocated = %d\n",
			       numPacketsSendable, numPacketsAllocated);
		       if (!(numPacketsSendable <= numPacketsAllocated))
		       {
		       printk ("KERNEL: assertion ("
			       "numPacketsSendable <= numPacketsAllocated"
			       ") failed at " "trickles-server.c" "(%d)\n",
			       1879);};}

		       ;; DoUpcall ((*cont), event); return 0;}

		       static int DoSlowStartStep (struct cminisock **cont,
						   AckProof * ackProof,
						   __u32 newBase,
						   enum cminisock_event_tag
						   event)
		       {






		       if ((*cont)->startCwnd == 0)
		       {
		       (*cont)->startCwnd = 1;}
		       (*cont)->executionTrace = 3;
		       int right =
		       AckProof_findRight (ackProof, (*cont)->TCPBase);
		       int effCwnd = AckTCPCwndScalar (right, (*cont));
		       (*cont)->actualCwnd = effCwnd;; if (effCwnd >= 2)
		       {
		       (*cont)->ssthresh = effCwnd / 2;}
		       else
		       {
		       (*cont)->ssthresh /= 2;}


		       (*cont)->TCPBase = newBase;
		       (*cont)->startCwnd = (2);
		       (*cont)->actualCwnd = (*cont)->startCwnd;
		       if (!alloc_msk_packets ((*cont), (*cont)->startCwnd))
		       {
		       free_trickles_msk ((*cont)->sk, (*cont));
		       free_trickles_msk_finish ((*cont)->sk, (*cont));
		       return -12;}
		       (*cont)->num_packets = (*cont)->startCwnd;
		       int i; for (i = 0; i < (*cont)->num_packets; i++)
		       {





		       int type = (1);
		       int len = (sysctl_trickles_mss);
		       makePacket (&(*cont)->packets[i], (*cont)->TCPBase + i,
				   0xdeadbeef, len,
				   (i == 0 ? (0x80) : 0) | (0), type, 0, -1,
				   -1);}

		       if (serverDebugLevel >= 1)
		       printk ("slow start step TCPBase - %u seq - %u\n",
			       (*cont)->TCPBase, (*cont)->packets[0].seq);;;
		       DoUpcall ((*cont), event); return 0;}

		       void pminisock_cache_child (struct sock *sk,
						   struct cminisock *msk,
						   struct pminisock *pmsk,
						   int packet_number,
						   int flags)
		       {
		       struct pminisock * newPmsk;
		       int new = 0; if (flags & (0x1))
		       {
		       newPmsk = shallow_copy_pmsk (sk, pmsk);
		       if (newPmsk == ((void *) 0))
		       {
		       if ((0))
		       {
		       printk ("out of memory\n");}
		       return;}
		       new = 1;}
		       else
		       {
		       newPmsk = pmsk;}

		       if (!(newPmsk->refCnt == 1))
		       {
		       printk ("KERNEL: assertion (" "newPmsk->refCnt == 1"
			       ") failed at " "trickles-server.c" "(%d)\n",
			       2001);}; if (newPmsk != ((void *) 0))
		       {
		       if (!new)
		       {
		       newPmsk->ctl = ALLOC_PENDING;}
		       if (!(newPmsk->ctl == ALLOC_PENDING))
		       {
		       printk ("KERNEL: assertion ("
			       "newPmsk->ctl == ALLOC_PENDING" ") failed at "
			       "trickles-server.c" "(%d)\n", 2006);}; (
									  {
									  (newPmsk)->seq = ((pmsk)->packets[packet_number].seq); (newPmsk)->continuationType = (pmsk)->packets[packet_number].contType; if ((pmsk)->packets[packet_number].type & (0x80))
									  {
									  (newPmsk)->firstChild = 1;}
									  else
									  {
									  (newPmsk)->firstChild = 0;}
									  static
									  const
									  int
									  stateConversionMap
									  [] =
									  {
									  0,
									  1,
									  2};
									  int
									  conversionOffset
									  =
									  (pmsk)->
									  packets
									  [packet_number].
									  type
									  &
									  (0x3);
									  if
									  (conversionOffset
									   >=
									   (3))
									  {
									  do
									  {
									  if
									  (!
									   (0))
									  {
									  printk
									  ("kgdb assertion failed: %s\n",
									   "BUG");
									  show_stack
									  (((void *) 0)); breakpoint ();}}
									  while
									  (0);}
									  (newPmsk)->state = stateConversionMap[conversionOffset];}
		       );
		       newPmsk->rawTimestamp = htonl (msk->timestamp);
		       newPmsk->rawMrtt = htonl (msk->mrtt);
		       newPmsk->num_packets = 0; if (flags & (0x2))
		       {
		       pmsk_clear_fields (newPmsk);}


		       if (pminisock_insert (sk, newPmsk))
		       {

		       pmsk_release (sk, newPmsk);
		       if (!(newPmsk->refCnt == 1))
		       {
		       printk ("KERNEL: assertion (" "newPmsk->refCnt == 1"
			       ") failed at " "trickles-server.c" "(%d)\n",
			       2025);};}
		       else
		       {

		       pmsk_release (sk, newPmsk);
		       if (!(newPmsk->refCnt == 0))
		       {
		       printk ("KERNEL: assertion (" "newPmsk->refCnt == 0"
			       ") failed at " "trickles-server.c" "(%d)\n",
			       2030);};}
		       }
		       }
