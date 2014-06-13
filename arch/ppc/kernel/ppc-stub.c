/*
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 */

/*
 * Copyright (C) 2003 Timesys Corporation.
 * KGDB for the PowerPC processor
 */

#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/config.h>
#include <linux/kgdb.h>
#include <linux/sched.h>
#include <asm/current.h>
#include <asm/ptrace.h>
#include <asm/processor.h>
#include <asm/signal.h>

/*
 * Forward prototypes
 */
static void kgdb_debugger (struct pt_regs *regs);
static int kgdb_breakpoint (struct pt_regs *regs);
static int kgdb_singlestep (struct pt_regs *regs);
static int kgdb_iabr_match(struct pt_regs *regs);
static int kgdb_dabr_match(struct pt_regs *regs);
static int ppc_kgdb_init (void);
static void ppc_regs_to_gdb_regs(int *gdb_regs, struct pt_regs *regs);
static void ppc_sleeping_thread_to_gdb_regs(int *gdb_regs, struct task_struct *p);
static void ppc_gdb_regs_to_regs(int *gdb_regs, struct pt_regs *regs);
void ppc_exit_handler (void);
int ppc_handle_exception (int            vector,
                           int            signo,
                           int            err_code,
                           char           *remcomInBuffer,
                           char           *remcomOutBuffer,
                           struct pt_regs *linux_regs);

/*
 * Global data
 */
struct kgdb_arch arch_kgdb_ops =
{
	{ 0x7d, 0x82, 0x10, 0x08 },       /* gdb_bpt_instr               */
	0,                                /* flags                       */
	ppc_kgdb_init,                   /* kgdb_init                   */
	ppc_regs_to_gdb_regs,            /* regs_to_gdb_regs            */
	ppc_sleeping_thread_to_gdb_regs, /* sleeping_thread_to_gdb_regs */
	ppc_gdb_regs_to_regs,            /* gdb_regs_to_regs            */
	NULL,                             /* printexpinfo                */
	NULL,                             /* disable_hw_debug            */
	NULL,                             /* post_master_code            */
	ppc_handle_exception,             /* handle_buffer               */
	NULL,                             /* set_break                   */
	NULL,                             /* remove_break                */
	NULL,                             /* correct_hw_break            */
	ppc_exit_handler,                /* handler_exit                */
};

/*
 * Routines
 */
static void kgdb_debugger (struct pt_regs *regs)
{
	kgdb_handle_exception (0, 0, 0, regs);
	return;
}

static int kgdb_breakpoint (struct pt_regs *regs)
{
	extern atomic_t kgdb_setting_breakpoint;

	kgdb_handle_exception (0, SIGTRAP, 0, regs);

	if (atomic_read (&kgdb_setting_breakpoint))
		regs->nip += 4;

	return 1;
}

static int kgdb_singlestep (struct pt_regs *regs)
{
	kgdb_handle_exception (0, SIGTRAP, 0, regs);
	return 1;
}

static int kgdb_iabr_match(struct pt_regs *regs)
{
	kgdb_handle_exception (0, 0, 0, regs);
	return 1;
}

static int kgdb_dabr_match(struct pt_regs *regs)
{
	kgdb_handle_exception (0, 0, 0, regs);
	return 1;
}

static int ppc_kgdb_init (void)
{
	debugger = kgdb_debugger;
	debugger_bpt = kgdb_breakpoint;
	debugger_sstep = kgdb_singlestep;
	debugger_iabr_match = kgdb_iabr_match;
	debugger_dabr_match = kgdb_dabr_match;

	return 0;
	
}

static void ppc_regs_to_gdb_regs(int *gdb_regs, struct pt_regs *regs)
{
	int reg;
	int *ptr = gdb_regs;

	memset(gdb_regs, 0, MAXREG*4);

	for (reg = 0; reg < 32; reg++)
		*(ptr++) = regs->gpr[reg];

	for (reg = 0; reg < 64; reg++)
		*(ptr++) = 0;

	*(ptr++) = regs->nip;
	*(ptr++) = regs->msr;
	*(ptr++) = regs->ccr;
	*(ptr++) = regs->link;
	*(ptr++) = regs->ctr;
	*(ptr++) = regs->xer;

	return;
}	/* regs_to_gdb_regs */

static void ppc_sleeping_thread_to_gdb_regs(int *gdb_regs, struct task_struct *p)
{
	struct pt_regs *regs = (struct pt_regs *) (p->thread.ksp +
	                                           STACK_FRAME_OVERHEAD);
	int reg;
	int *ptr = gdb_regs;

	memset(gdb_regs, 0, MAXREG*4);

	/* Regs GPR0-2 */
	for (reg = 0; reg < 3; reg++)
		*(ptr++) = regs->gpr[reg];

	/* Regs GPR3-13 are not saved */
	for (reg = 3; reg < 14; reg++)
		*(ptr++) = 0;

	/* Regs GPR14-31 */
	for (reg = 14; reg < 32; reg++)
		*(ptr++) = regs->gpr[reg];

	for (reg = 0; reg < 64; reg++)
		*(ptr++) = 0;

	*(ptr++) = regs->nip;
	*(ptr++) = regs->msr;
	*(ptr++) = regs->ccr;
	*(ptr++) = regs->link;
	*(ptr++) = regs->ctr;
	*(ptr++) = regs->xer;

	return;
}

static void ppc_gdb_regs_to_regs(int *gdb_regs, struct pt_regs *regs)
{
	int reg;
	int *ptr = gdb_regs;

	for (reg = 0; reg < 32; reg++)
		regs->gpr[reg] = *(ptr++);

	for (reg = 0; reg < 64; reg++)
		ptr++;

	regs->nip = *(ptr++);
	regs->msr = *(ptr++);
	regs->ccr = *(ptr++);
	regs->link = *(ptr++);
	regs->ctr = *(ptr++);
	regs->xer = *(ptr++);

	return;
}	/* gdb_regs_to_regs */


/* exit_handler:
 * 
 * This is called by the generic layer when it is about to return from 
 * the exception handler
 */
void ppc_exit_handler (void)
{
//	flush_instruction_cache ();
	return;
}


/*
 * This function does PoerPC specific procesing for interfacing to gdb.
 */
int ppc_handle_exception (int            vector,
                          int            signo,
                          int            err_code,
                          char           *remcomInBuffer,
                          char           *remcomOutBuffer,
                          struct pt_regs *linux_regs)
{
	char *ptr;
	int addr;
	
	switch (remcomInBuffer[0])
		{
		/*
		 * sAA..AA   Step one instruction from AA..AA 
		 * This will return an error to gdb ..
		 */
		case 's':
		case 'c':
			if (kgdb_contthread && kgdb_contthread != current)
			{
				strcpy(remcomOutBuffer, "E00");
				break;
			}

			kgdb_contthread = NULL;

			/* handle the optional parameter */
			ptr = &remcomInBuffer[1];
			if (hexToInt (&ptr, &addr))
				linux_regs->nip = addr;

			/* set the trace bit if we're stepping */
            if (remcomInBuffer[0] == 's')
			{
#if defined (CONFIG_4xx)
				linux_regs->msr |= MSR_DE;
				current->thread.dbcr0 |= (DBCR_IDM | DBCR_IC);
#else
				linux_regs->msr |= MSR_SE;
#endif
			}
			return 0;
	}

	return -1;
}
