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
 * Copyright (C) 2000-2001 VERITAS Software Corporation.
 */
/****************************************************************************
 *  Header: remcom.c,v 1.34 91/03/09 12:29:49 glenne Exp $
 *
 *  Module name: remcom.c $
 *  Revision: 1.34 $
 *  Date: 91/03/09 12:29:49 $
 *  Contributor:     Lake Stevens Instrument Division$
 *
 *  Description:     low level support for gdb debugger. $
 *
 *  Considerations:  only works on target hardware $
 *
 *  Written by:      Glenn Engel $
 *  Updated by:	     Amit Kale<akale@veritas.com>
 *  ModuleState:     Experimental $
 *
 *  NOTES:           See Below $
 *
 *  Modified for 386 by Jim Kingdon, Cygnus Support.
 *  Origianl kgdb, compatibility with 2.1.xx kernel by David Grothe <dave@gcom.com>
 *  Integrated into 2.2.5 kernel by Tigran Aivazian <tigran@sco.com>
 *      thread support,
 *      support for multiple processors,
 *  	support for ia-32(x86) hardware debugging,
 *  	Console support,
 *  	handling nmi watchdog
 *  	Amit S. Kale ( amitkale@emsyssoft.com )
 *
 *
 *  To enable debugger support, two things need to happen.  One, a
 *  call to set_debug_traps() is necessary in order to allow any breakpoints
 *  or error conditions to be properly intercepted and reported to gdb.
 *  Two, a breakpoint needs to be generated to begin communication.  This
 *  is most easily accomplished by a call to breakpoint().  Breakpoint()
 *  simulates a breakpoint by executing an int 3.
 *
 *************
 *
 *    The following gdb commands are supported:
 *
 * command          function                               Return value
 *
 *    g             return the value of the CPU registers  hex data or ENN
 *    G             set the value of the CPU registers     OK or ENN
 *
 *    mAA..AA,LLLL  Read LLLL bytes at address AA..AA      hex data or ENN
 *    MAA..AA,LLLL: Write LLLL bytes at address AA.AA      OK or ENN
 *
 *    c             Resume at current address              SNN   ( signal NN)
 *    cAA..AA       Continue at address AA..AA             SNN
 *
 *    s             Step one instruction                   SNN
 *    sAA..AA       Step one instruction from AA..AA       SNN
 *
 *    k             kill
 *
 *    ?             What was the last sigval ?             SNN   (signal NN)
 *
 * All commands and responses are sent with a packet which includes a
 * checksum.  A packet consists of
 *
 * $<packet info>#<checksum>.
 *
 * where
 * <packet info> :: <characters representing the command or response>
 * <checksum>    :: < two hex digits computed as modulo 256 sum of <packetinfo>>
 *
 * When a packet is received, it is first acknowledged with either '+' or '-'.
 * '+' indicates a successful transfer.  '-' indicates a failed transfer.
 *
 * Example:
 *
 * Host:                  Reply:
 * $m0,10#2a               +$00010203040506070809101112131415#42
 *
 ****************************************************************************/

#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/smp.h>
#include <linux/spinlock.h>
#include <linux/delay.h>
#include <asm/vm86.h>
#include <asm/system.h>
#include <asm/ptrace.h>			/* for linux pt_regs struct */
#include <linux/kgdb.h>
#ifdef CONFIG_GDB_CONSOLE
#include <linux/console.h>
#endif
#include <linux/init.h>

/* Put the error code here just in case the user cares.  */
int gdb_i386errcode;
/* Likewise, the vector number here (since GDB only gets the signal
   number through the usual means, and that's not very specific).  */
int gdb_i386vector = -1;

#if KGDB_MAX_NO_CPUS != 8
#error change the definition of slavecpulocks
#endif

static void i386_regs_to_gdb_regs(int *gdb_regs, struct pt_regs *regs)
{
    gdb_regs[_EAX] =  regs->eax;
    gdb_regs[_EBX] =  regs->ebx;
    gdb_regs[_ECX] =  regs->ecx;
    gdb_regs[_EDX] =  regs->edx;
    gdb_regs[_ESI] =  regs->esi;
    gdb_regs[_EDI] =  regs->edi;
    gdb_regs[_EBP] =  regs->ebp;
    gdb_regs[ _DS] =  regs->xds;
    gdb_regs[ _ES] =  regs->xes;
    gdb_regs[ _PS] =  regs->eflags;
    gdb_regs[ _CS] =  regs->xcs;
    gdb_regs[ _PC] =  regs->eip;
    gdb_regs[_ESP] =  (int) (&regs->esp) ;
    gdb_regs[ _SS] =  __KERNEL_DS;
    gdb_regs[ _FS] =  0xFFFF;
    gdb_regs[ _GS] =  0xFFFF;
} /* regs_to_gdb_regs */

static void i386_sleeping_thread_to_gdb_regs(int *gdb_regs, struct task_struct *p)
{
	gdb_regs[_EAX] = 0;
	gdb_regs[_EBX] = 0;
	gdb_regs[_ECX] = 0;
	gdb_regs[_EDX] = 0;
	gdb_regs[_ESI] = 0;
	gdb_regs[_EDI] = 0;
	gdb_regs[_EBP] = *(int *)p->thread.esp;
	gdb_regs[_DS]  = __KERNEL_DS;
	gdb_regs[_ES]  = __KERNEL_DS;
	gdb_regs[_PS]  = 0;
	gdb_regs[_CS]  = __KERNEL_CS;
	gdb_regs[_PC]  = p->thread.eip;
	gdb_regs[_ESP] = p->thread.esp;
	gdb_regs[_SS]  = __KERNEL_DS;
	gdb_regs[_FS]  = 0xFFFF;
	gdb_regs[_GS]  = 0xFFFF;
}

static void i386_gdb_regs_to_regs(int *gdb_regs, struct pt_regs *regs)
{
    regs->eax	=     gdb_regs[_EAX] ;
    regs->ebx	=     gdb_regs[_EBX] ;
    regs->ecx	=     gdb_regs[_ECX] ;
    regs->edx	=     gdb_regs[_EDX] ;
    regs->esi	=     gdb_regs[_ESI] ;
    regs->edi	=     gdb_regs[_EDI] ;
    regs->ebp	=     gdb_regs[_EBP] ;
    regs->xds	=     gdb_regs[ _DS] ;
    regs->xes	=     gdb_regs[ _ES] ;
    regs->eflags=     gdb_regs[ _PS] ;
    regs->xcs	=     gdb_regs[ _CS] ;
    regs->eip	=     gdb_regs[ _PC] ;
#if 0					/* can't change these */
    regs->esp	=     gdb_regs[_ESP] ;
    regs->xss	=     gdb_regs[ _SS] ;
    regs->fs	=     gdb_regs[ _FS] ;
    regs->gs	=     gdb_regs[ _GS] ;
#endif

} /* gdb_regs_to_regs */

struct hw_breakpoint {
	unsigned enabled;
	unsigned type;
	unsigned len;
	unsigned addr;
} breakinfo[4] = { {
enabled:0}, {
enabled:0}, {
enabled:0}, {
enabled:0}};

void i386_correct_hw_break(void)
{
	int breakno;
	int correctit;
	int breakbit;
	unsigned dr7;

	asm volatile ("movl %%db7, %0\n":"=r" (dr7)
		      :);
	do {
		unsigned addr0, addr1, addr2, addr3;
		asm volatile ("movl %%db0, %0\n"
			      "movl %%db1, %1\n"
			      "movl %%db2, %2\n"
			      "movl %%db3, %3\n":"=r" (addr0), "=r"(addr1),
			      "=r"(addr2), "=r"(addr3):);
	} while (0);
	correctit = 0;
	for (breakno = 0; breakno < 3; breakno++) {
		breakbit = 2 << (breakno << 1);
		if (!(dr7 & breakbit) && breakinfo[breakno].enabled) {
			correctit = 1;
			dr7 |= breakbit;
			dr7 &= ~(0xf0000 << (breakno << 2));
			dr7 |= (((breakinfo[breakno].len << 2) |
				 breakinfo[breakno].type) << 16) <<
			    (breakno << 2);
			switch (breakno) {
			case 0:
				asm volatile ("movl %0, %%dr0\n"::"r"
					      (breakinfo[breakno].addr));
				break;

			case 1:
				asm volatile ("movl %0, %%dr1\n"::"r"
					      (breakinfo[breakno].addr));
				break;

			case 2:
				asm volatile ("movl %0, %%dr2\n"::"r"
					      (breakinfo[breakno].addr));
				break;

			case 3:
				asm volatile ("movl %0, %%dr3\n"::"r"
					      (breakinfo[breakno].addr));
				break;
			}
		} else if ((dr7 & breakbit) && !breakinfo[breakno].enabled) {
			correctit = 1;
			dr7 &= ~breakbit;
			dr7 &= ~(0xf0000 << (breakno << 2));
		}
	}
	if (correctit) {
		asm volatile ("movl %0, %%db7\n"::"r" (dr7));
	}
}

int i386_remove_hw_break(unsigned long addr, int type)
{
	int i, idx = -1;
	for (i = 0; i < 4; i ++) {
		if (breakinfo[i].addr == addr && breakinfo[i].enabled) {
			idx = i;
			break;
		}
	}
	if (idx == -1)
		return -1;

	breakinfo[idx].enabled = 0;
	return 0;
}

int i386_set_hw_break(unsigned long addr, int type)
{
	int i, idx = -1;
	for (i = 0; i < 4; i ++) {
		if (!breakinfo[i].enabled) {
			idx = i;
			break;
		}
	}
	if (idx == -1)
		return -1;

	breakinfo[idx].enabled = 1;
	breakinfo[idx].type = type;
	breakinfo[idx].len = 1;
	breakinfo[idx].addr = addr;
	return 0;
}

int remove_hw_break(unsigned breakno)
{
	if (!breakinfo[breakno].enabled) {
		return -1;
	}
	breakinfo[breakno].enabled = 0;
	return 0;
}

int set_hw_break(unsigned breakno,
		 unsigned type, unsigned len, unsigned addr)
{
	if (breakinfo[breakno].enabled) {
		return -1;
	}
	breakinfo[breakno].enabled = 1;
	breakinfo[breakno].type = type;
	breakinfo[breakno].len = len;
	breakinfo[breakno].addr = addr;
	return 0;
}

static void i386_printexceptioninfo(int exceptionNo, int errorcode, char *buffer)
{
	unsigned	dr6;
	int		i;
	switch (exceptionNo) {
	case 1:		/* debug exception */
		break;
	case 3:		/* breakpoint */
		sprintf(buffer, "Software breakpoint");
		return;
	default:
		sprintf(buffer, "Details not available");
		return;
	}
	asm volatile ("movl %%db6, %0\n":"=r" (dr6)
		      :);
	if (dr6 & 0x4000) {
		sprintf(buffer, "Single step");
		return;
	}
	for (i = 0; i < 4; ++i) {
		if (dr6 & (1 << i)) {
			sprintf(buffer, "Hardware breakpoint %d", i);
			return;
		}
	}
	sprintf(buffer, "Unknown trap");
	return;
}

static void i386_disable_hw_debug(struct pt_regs *regs) 
{
	/* Disable hardware debugging while we are in kgdb */
	asm volatile("movl %0,%%db7": /* no output */ : "r"(0));
}

static void i386_post_master_code(struct pt_regs *regs, int eVector, int err_code)
{
	/* Master processor is completely in the debugger */
	gdb_i386vector = eVector;
	gdb_i386errcode = err_code;
}
static int i386_handle_exception(int exceptionVector, int signo, int err_code,
                                 char *remcomInBuffer, char *remcomOutBuffer,
                                 struct pt_regs *linux_regs)
{
	int addr, length;
	int breakno, breaktype;
	char *ptr;
	int newPC;
	int dr6;
	
	switch (remcomInBuffer[0]) {
	case 'c':
	case 's':
		if (kgdb_contthread && kgdb_contthread != current) {
			strcpy(remcomOutBuffer, "E00");
			break;
		}

		kgdb_contthread = NULL;

		/* try to read optional parameter, pc unchanged if no parm */
		ptr = &remcomInBuffer[1];
		if (hexToInt(&ptr, &addr)) {
			linux_regs->eip = addr;
		} 
		newPC = linux_regs->eip;
		
		/* clear the trace bit */
		linux_regs->eflags &= 0xfffffeff;

		/* set the trace bit if we're stepping */
		if (remcomInBuffer[0] == 's') {
			linux_regs->eflags |= 0x100;
			kgdb_step = 1;
		}

		asm volatile ("movl %%db6, %0\n" : "=r" (dr6));
		if (!(dr6 & 0x4000)) {
			for (breakno = 0; breakno < 4; ++breakno) {
				if (dr6 & (1 << breakno)) {
					if (breakinfo[breakno].type == 0) {
						/* Set restore flag */
						linux_regs->eflags |= 0x10000;
						break;
					}
				}
			}
		}
		i386_correct_hw_break();
		asm volatile ("movl %0, %%db6\n"::"r" (0));

		return (0);

	case 'Y':
		ptr = &remcomInBuffer[1];
		hexToInt(&ptr, &breakno);
		ptr++;
		hexToInt(&ptr, &breaktype);
		ptr++;
		hexToInt(&ptr, &length);
		ptr++;
		hexToInt(&ptr, &addr);
		if (set_hw_break(breakno & 0x3, breaktype & 0x3, 
				 length & 0x3, addr) == 0) {
			strcpy(remcomOutBuffer, "OK");
		} else {
			strcpy(remcomOutBuffer, "ERROR");
		}
		break;

		/* Remove hardware breakpoint */
	case 'y':
		ptr = &remcomInBuffer[1];
		hexToInt(&ptr, &breakno);
		if (remove_hw_break(breakno & 0x3) == 0) {
			strcpy(remcomOutBuffer, "OK");
		} else {
			strcpy(remcomOutBuffer, "ERROR");
		}
		break;

	}		/* switch */
	return -1; /* this means that we do not want to exit from the handler */
}

int i386_kgdb_init(void)
{
	return 0;
}

struct kgdb_arch arch_kgdb_ops =  {
	{0xcc},
	KGDB_HW_BREAKPOINT,
	i386_kgdb_init,
	i386_regs_to_gdb_regs,
	i386_sleeping_thread_to_gdb_regs,
	i386_gdb_regs_to_regs,
	i386_printexceptioninfo,
	i386_disable_hw_debug,
	i386_post_master_code,
	i386_handle_exception,
	i386_set_hw_break,
	i386_remove_hw_break,
	i386_correct_hw_break,
	NULL,
};
