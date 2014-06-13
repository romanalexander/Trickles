#ifndef _GDB_DEFS_H_
#define _GDB_DEFS_H_

#include <asm/atomic.h>

/* Wait for GDB to connect. */
int gdb_hook(void);

/* To init the kgdb engine. (called by serial hook) */
void set_debug_traps(void);

/* To enter the debugger explicitly. */
void breakpoint(void);

/* Output a string via the GDB console.  Returns non-zero on success. */
int kgdb_output_string(const char *s, unsigned int count);

extern int gdb_enter; /* 1 = enter debugger on boot */
extern int gdb_ttyS;
extern int gdb_baud;
extern int gdb_initialized;

void putDebugChar(char);   /* write a single character      */
char getDebugChar(void);   /* read and return a single char */
int hexToInt(char **ptr, int *intValue);
int kgdb_handle_exception(int exVector, int signo, int err_code,
                          struct pt_regs *linux_regs);
char *hex2mem(char *buf, char *mem, int count, int can_fault);
char *mem2hex(char *mem, char *buf, int count, int can_fault);
void putpacket(char *buffer);

#ifdef CONFIG_KGDB
extern volatile int kgdb_memerr_expected;
#else
static const int kgdb_memerr_expected = 0;
#endif

typedef int gdb_debug_hook(int exVector, int signo, int err_code,
                            struct pt_regs *regs);

#ifndef KGDB_MAX_NO_CPUS
#define KGDB_MAX_NO_CPUS 8
#endif

extern gdb_debug_hook  *linux_debug_hook;
extern atomic_t kgdb_lock;
extern spinlock_t slavecpulocks[KGDB_MAX_NO_CPUS];
extern volatile int procindebug[KGDB_MAX_NO_CPUS];
extern int kgdb_initialized;
extern struct kgdb_arch arch_kgdb_ops;
extern struct task_struct *kgdb_usethread, *kgdb_contthread;
extern  volatile int kgdb_memerr;
extern atomic_t kgdb_setting_breakpoint;
extern atomic_t kgdb_killed_or_detached;
extern atomic_t kgdb_might_be_resumed;
extern volatile unsigned kgdb_step;
	 
#endif /* _GDB_DEFS_H_ */
