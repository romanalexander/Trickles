#ifndef _GDB_H_
#define _GDB_H_

/*
 * Copyright (C) 2001 Amit S. Kale
 */

#include <linux/ptrace.h>
#include <asm/kgdb.h>
#include <linux/spinlock.h>
#include <linux/kgdb-defs.h>

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

#ifndef BREAK_INSTR_SIZE
#error BREAK_INSTR_SIZE  needed by kgdb
#endif

struct gdb_breakpoint
{
       unsigned int            bpt_addr;
       unsigned char           saved_instr[BREAK_INSTR_SIZE];
       enum gdb_bptype         type;
       enum gdb_bpstate        state;
};

typedef struct gdb_breakpoint gdb_breakpoint_t;

#ifndef MAX_BREAKPOINTS
#define MAX_BREAKPOINTS        16
#endif

#define KGDB_HW_BREAKPOINT          1

struct kgdb_arch {
	unsigned char gdb_bpt_instr[BREAK_INSTR_SIZE];
	unsigned long flags;
	
	int  (*kgdb_init) (void);
	void (*regs_to_gdb_regs)(int *gdb_regs, struct pt_regs *regs);
	void (*sleeping_thread_to_gdb_regs)(int *gdb_regs,struct task_struct *p);
	void (*gdb_regs_to_regs)(int *gdb_regs, struct pt_regs *regs);
	void (*printexpinfo)(int exceptionNo, int errorcode, char *buffer);
	void (*disable_hw_debug) (struct pt_regs *regs);
	void (*post_master_code) (struct pt_regs *regs, int eVector, int err_code);
	int  (*handle_buffer) (int vector, int signo, int err_code,
			       char *InBuffer, char *outBuffer,
			       struct pt_regs *regs);
	int  (*set_break) (unsigned long addr, int type);
	int  (*remove_break) (unsigned long addr, int type);
	void (*correct_hw_break) (void);
	void (*handler_exit) (void);
};			


/* Thread reference */
typedef unsigned char threadref[8];

/* Routine prototypes */
struct console;
extern void gdb_console_write(struct console *co, const char *s, unsigned count);

#ifdef CONFIG_GDB_CONSOLE
extern void gdb_console_init(void);
#endif /* CONFIG_GDB_CONSOLE */

#endif /* _GDB_H_ */
