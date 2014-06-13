/*
 * kgdb.h: Defines and declarations for serial line source level
 *         remote debugging of the Linux kernel using gdb.
 *
 * PPC Mods (C) 2003 John Whitney (john.whitney@timesys.com)
 *
 * PPC Mods (C) 1998 Michael Tesch (tesch@cs.wisc.edu)
 *
 * Copyright (C) 1995 David S. Miller (davem@caip.rutgers.edu)
 */
#ifdef __KERNEL__
#ifndef _ASMPPC_KGDB_H
#define _ASMPPC_KGDB_H

/*
 * For taking exceptions these are defined in traps.c
 */
extern void (*debugger)               (struct pt_regs *regs);
extern int  (*debugger_bpt)           (struct pt_regs *regs);
extern int  (*debugger_sstep)         (struct pt_regs *regs);
extern int  (*debugger_iabr_match)    (struct pt_regs *regs);
extern int  (*debugger_dabr_match)    (struct pt_regs *regs);
extern void (*debugger_fault_handler) (struct pt_regs *regs);

/*
 * external low-level support routines (ie macserial.c)
 */
extern void kgdb_interruptible (int); /* control interrupts from serial */
extern void putDebugChar (char);      /* write a single character       */
extern char getDebugChar (void);      /* read and return a single char  */

#define BREAK_INSTR_SIZE	4
#define MAXREG				(PT_FPSCR+1)
#define NUMREGBYTES			(MAXREG * sizeof (int))
#define BUFMAX				((NUMREGBYTES * 2) + 512)
#define OUTBUFMAX			((NUMREGBYTES * 2) + 512)

#define BREAKPOINT()        asm (".long	0x7d821008");

#endif /* !(_ASMPPC_KGDB_H) */
#endif /* __KERNEL__ */
