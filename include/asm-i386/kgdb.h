#ifndef _ASM_KGDB_H_
#define _ASM_KGDB_H_

/*
 * Copyright (C) 2001 Amit S. Kale
 */

#include <linux/ptrace.h>

/* gdb locks */
#define KGDB_MAX_NO_CPUS 8

extern int gdb_enter;	/* 1 = enter debugger on boot */
extern int gdb_ttyS;
extern int gdb_baud;
extern int gdb_initialized;
extern int gdb_irq;

/************************************************************************/
/* BUFMAX defines the maximum number of characters in inbound/outbound buffers*/
/* at least NUMREGBYTES*2 are needed for register packets */
/* Longer buffer is needed to list all threads */
#define BUFMAX 1024

/* Number of bytes of registers.  */
#define NUMREGBYTES 64
/*
 *  Note that this register image is in a different order than
 *  the register image that Linux produces at interrupt time.
 *  
 *  Linux's register image is defined by struct pt_regs in ptrace.h.
 *  Just why GDB uses a different order is a historical mystery.
 */
enum regnames { _EAX,  /* 0 */
	_ECX,  /* 1 */
	_EDX,  /* 2 */
	_EBX,  /* 3 */
	_ESP,  /* 4 */
	_EBP,  /* 5 */
	_ESI,  /* 6 */
	_EDI,  /* 7 */
	_PC,   /* 8 also known as eip */
	_PS,   /* 9 also known as eflags */
	_CS,   /* 10 */
	_SS,   /* 11 */
	_DS,   /* 12 */
	_ES,   /* 13 */
	_FS,   /* 14 */
	_GS    /* 15 */
};

#define BREAKPOINT() asm("   int $3");
#define BREAK_INSTR_SIZE       1
struct console;
void gdb_console_write(struct console *co, const char *s,
				unsigned count);
void gdb_console_init(void);

void gdb_wait(struct pt_regs *regs);


#endif /* _ASM_KGDB_H_ */
