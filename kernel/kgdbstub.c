/*
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
 * Generic KGDB Support
 * Copyright (C) 2002-2003 Timesys Corporation
 * Implemented by Anurekh Saxena (anurekh.saxena@timesys.com)
 * 
 * Copyright (C) 2000-2001 VERITAS Software Corporation.
 * Contributor:     Lake Stevens Instrument Division
 * Written by:      Glenn Engel
 *  
 * Modified for 386 by Jim Kingdon, Cygnus Support.
 * Origianl kgdb, compatibility with 2.1.xx kernel by David Grothe <dave@gcom.com>
 * Integrated into 2.2.5 kernel by Tigran Aivazian <tigran@sco.com>
 *  
 * thread support, support for multiple processors,support for ia-32(x86) 
 * hardware debugging, Console support, handling nmi watchdog
 * - Amit S. Kale ( amitkale@emsyssoft.com )
 *  
 */

#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/smp.h>
#include <linux/spinlock.h>
#include <linux/delay.h>
#include <linux/mm.h>
#include <asm/system.h>
#include <asm/ptrace.h>		/* for linux pt_regs struct */
#include <asm/uaccess.h>
#include <linux/kgdb.h>
#include <asm/atomic.h>
 
#ifdef CONFIG_GDB_CONSOLE
#include <linux/console.h>
#endif
 
#include <linux/init.h>



/* DEBUGGING THE DEBUGGER */
#undef KGDB_DEG
/**************************/

struct kgdb_arch *kgdb_ops = &arch_kgdb_ops;
gdb_breakpoint_t kgdb_break[MAX_BREAKPOINTS];

int kgdb_initialized = 0;
static const char hexchars[] = "0123456789abcdef";

int get_char(char *addr, unsigned char *data, int can_fault);
int set_char(char *addr, int data, int can_fault);

spinlock_t slavecpulocks[KGDB_MAX_NO_CPUS];
volatile int procindebug[KGDB_MAX_NO_CPUS];
volatile unsigned kgdb_step;
atomic_t kgdb_lock;
atomic_t kgdb_setting_breakpoint;
atomic_t kgdb_killed_or_detached;
atomic_t kgdb_might_be_resumed;
struct task_struct *kgdb_usethread, *kgdb_contthread;

/* 
 * Indicate to caller of mem2hex or hex2mem that there has been an
 * error.  
 */
volatile int kgdb_memerr = 0;
volatile int kgdb_memerr_expected = 0;

/* This will point to kgdb_handle_exception by default.
 * The architecture code can override this in its init function
 */
gdb_debug_hook *linux_debug_hook;


static char remcomInBuffer[BUFMAX];
static char remcomOutBuffer[BUFMAX];
static short error;

int hex(char ch)
{
	if ((ch >= 'a') && (ch <= 'f'))
		return (ch - 'a' + 10);
	if ((ch >= '0') && (ch <= '9'))
		return (ch - '0');
	if ((ch >= 'A') && (ch <= 'F'))
		return (ch - 'A' + 10);
	return (-1);
}


/* scan for the sequence $<data>#<checksum>	*/

void getpacket(char *buffer)
{
	unsigned char checksum;
	unsigned char xmitcsum;
	int i;
	int count;
	char ch;

	do {
	/* wait around for the start character, ignore all other characters */
		while ((ch = (getDebugChar() & 0x7f)) != '$');
		checksum = 0;
		xmitcsum = -1;

		count = 0;

		/* now, read until a # or end of buffer is found */
		while (count < BUFMAX) {
			ch = getDebugChar() & 0x7f;
			if (ch == '#')
				break;
			checksum = checksum + ch;
			buffer[count] = ch;
			count = count + 1;
		}
		buffer[count] = 0;

		if (ch == '#') {
			xmitcsum = hex(getDebugChar() & 0x7f) << 4;
			xmitcsum += hex(getDebugChar() & 0x7f);

			if (checksum != xmitcsum)
				putDebugChar('-');	/* failed checksum */
			else {
				putDebugChar('+');	/* successful transfer */
				/* if a sequence char is present, reply the sequence ID */
				if (buffer[2] == ':') {
					putDebugChar(buffer[0]);
					putDebugChar(buffer[1]);
					/* remove sequence chars from buffer */
					count = strlen(buffer);
					for (i = 3; i <= count; i++)
						buffer[i - 3] = buffer[i];
				}
			}
		}
	} while (checksum != xmitcsum);

}


/* send the packet in buffer.*/
void putpacket(char *buffer)
{
	unsigned char checksum;
	int count;
	char ch;

	/*  $<packet info>#<checksum>. */
	do {
		putDebugChar('$');
		checksum = 0;
		count = 0;

		while ((ch = buffer[count])) {
			putDebugChar(ch);
			checksum += ch;
			count += 1;
		}

		putDebugChar('#');
		putDebugChar(hexchars[checksum >> 4]);
		putDebugChar(hexchars[checksum % 16]);

	} while ((getDebugChar() & 0x7f) != '+');

}

/* convert the memory pointed to by mem into hex, placing result in buf */
/* return a pointer to the last char put in buf (null) */
/* If MAY_FAULT is non-zero, then we should set kgdb_memerr in response to
   a fault; if zero treat a fault like any other fault in the stub.  */

char *mem2hex(char *mem, char *buf, int count, int can_fault)
{
	int i;
	unsigned char ch;
	
	for (i = 0; i < count; i++) {

		if (get_char(mem++, &ch, can_fault) < 0) 
			break;
		
		*buf++ = hexchars[ch >> 4];
		*buf++ = hexchars[ch % 16];
	}
	*buf = 0;
	return (buf);
}

/* convert the hex array pointed to by buf into binary to be placed in mem */
/* return a pointer to the character AFTER the last byte written */

char *hex2mem(char *buf, char *mem, int count, int can_fault)
{
	int i;
	unsigned char ch;
	
	for (i = 0; i < count; i++) {
		ch = hex(*buf++) << 4;
		ch = ch + hex(*buf++);
		if (set_char(mem++, ch, can_fault) < 0) 
			break;
	}
	return (mem);
}


/*
 * WHILE WE FIND NICE HEX CHARS, BUILD AN INT 
 * RETURN NUMBER OF CHARS PROCESSED           
 */
int hexToInt(char **ptr, int *intValue)
{
	int numChars = 0;
	int hexValue;

	*intValue = 0;

	while (**ptr) {
		hexValue = hex(**ptr);
		if (hexValue >= 0) {
			*intValue = (*intValue << 4) | hexValue;
			numChars++;
		} else
			break;

		(*ptr)++;
	}

	return (numChars);
}

static int stubhex(int ch)
{
	if (ch >= 'a' && ch <= 'f')
		return ch - 'a' + 10;
	if (ch >= '0' && ch <= '9')
		return ch - '0';
	if (ch >= 'A' && ch <= 'F')
		return ch - 'A' + 10;
	return -1;
}


static int stub_unpack_int(char *buff, int fieldlength)
{
	int nibble;
	int retval = 0;

	while (fieldlength) {
		nibble = stubhex(*buff++);
		retval |= nibble;
		fieldlength--;
		if (fieldlength)
			retval = retval << 4;
	}
	return retval;
}

static inline char *pack_hex_byte(char *pkt, int byte)
{
	*pkt++ = hexchars[(byte >> 4) & 0xf];
	*pkt++ = hexchars[(byte & 0xf)];
	return pkt;
}

#define BUF_THREAD_ID_SIZE 16

static char *pack_threadid(char *pkt, threadref *id)
{
	char *limit;
	unsigned char *altid;

	altid = (unsigned char *) id;
	limit = pkt + BUF_THREAD_ID_SIZE;
	while (pkt < limit)
		pkt = pack_hex_byte(pkt, *altid++);

	return pkt;
}

static char *unpack_byte(char *buf, int *value)
{
	*value = stub_unpack_int(buf, 2);
	return buf + 2;
}

static char *unpack_threadid(char *inbuf, threadref *id)
{
	char *altref;
	char *limit = inbuf + BUF_THREAD_ID_SIZE;
	int x, y;

	altref = (char *) id;

	while (inbuf < limit) {
		x = stubhex(*inbuf++);
		y = stubhex(*inbuf++);
		*altref++ = (x << 4) | y;
	}
	return inbuf;
}

void int_to_threadref(threadref *id, int value)
{
	unsigned char *scan;

	scan = (unsigned char *) id;
	{
		int i = 4;
		while (i--)
			*scan++ = 0;
	}
	*scan++ = (value >> 24) & 0xff;
	*scan++ = (value >> 16) & 0xff;
	*scan++ = (value >> 8) & 0xff;
	*scan++ = (value & 0xff);
}

static int threadref_to_int(threadref * ref)
{
	int i, value = 0;
	unsigned char *scan;

	scan = (char *) ref;
	scan += 4;
	i = 4;
	while (i-- > 0)
		value = (value << 8) | ((*scan++) & 0xff);
	return value;
}


struct task_struct *getthread(int tid)
{
#if CONFIG_SMP
	if (tid >= PID_MAX && tid < PID_MAX + smp_num_cpus)
		return init_tasks[tid - PID_MAX];
#else
	if (tid == PID_MAX)
		tid = 0;
#endif
	return find_task_by_pid(tid);
}

#ifdef CONFIG_SMP
void gdb_wait(struct pt_regs *regs)
{
	unsigned flags;
	int processor;

	local_irq_save(flags);
	processor = smp_processor_id();
	procindebug[processor] = 1;
	current->thread.kgdbregs = regs;

	/* Wait till master processor goes completely into the debugger */
	while (!procindebug[atomic_read(&kgdb_lock) - 1]) {
		int i = 10;	/* an arbitrary number */

		while (--i)
			asm volatile ("nop": : : "memory");
		barrier();
	}

	/* Wait till master processor is done with debugging */
	spin_lock(slavecpulocks + processor);

	/* This has been taken from x86 kgdb implementation and
	 * will be needed by architectures that have SMP support
	 */
	if (kgdb_ops->correct_hw_break)
		kgdb_ops->correct_hw_break();

	/* Signal the master processor that we are done */
	procindebug[processor] = 0;
	spin_unlock(slavecpulocks + processor);
	local_irq_restore(flags);
}

#endif

static void get_mem (char *addr, unsigned char *buf, int count)
{
	while (count) {
		if(get_char(addr++, buf, 1) <  0) 
			return;
		buf++;
		count--;
	}
}

static void set_mem (char *addr,unsigned char *buf, int count)
{
	while (count) {
		if (set_char(addr++,*buf++, 1) < 0) 
			return;
		count--;
	}
}



static int set_break (unsigned long addr)
{
	int i, breakno = -1;

	for (i = 0; i < MAX_BREAKPOINTS; i++) {
		if ((kgdb_break[i].state == bp_enabled) &&
		    (kgdb_break[i].bpt_addr == addr)) {
			breakno = -1;
			break;
		}

		if (kgdb_break[i].state == bp_disabled) {
			if ((breakno == -1) || (kgdb_break[i].bpt_addr == addr))
				breakno = i;
		}
	}
	if (breakno == -1)
		return -1;

	get_mem((char *)addr, kgdb_break[breakno].saved_instr, BREAK_INSTR_SIZE);
	if (kgdb_memerr)
		return -1;

	set_mem((char *)addr, kgdb_ops->gdb_bpt_instr, BREAK_INSTR_SIZE);
	flush_cache_range (current->mm, addr, addr + BREAK_INSTR_SIZE);
	flush_icache_range (addr, addr + BREAK_INSTR_SIZE);
	if (kgdb_memerr)
		return -1;

	kgdb_break[breakno].state = bp_enabled;
	kgdb_break[breakno].type = bp_breakpoint;
	kgdb_break[breakno].bpt_addr = addr;
	
	return 0;
}	

static int remove_break (unsigned addr)
{
	int i;

	for (i=0; i < MAX_BREAKPOINTS; i++) {
		if ((kgdb_break[i].state == bp_enabled) &&
		   (kgdb_break[i].bpt_addr == addr)) {
			set_mem((char *)addr, kgdb_break[i].saved_instr,
			        BREAK_INSTR_SIZE);
			flush_cache_range (current->mm, addr, addr + BREAK_INSTR_SIZE);
			flush_icache_range (addr, addr + BREAK_INSTR_SIZE);
			if (kgdb_memerr)
				return -1;
			kgdb_break[i].state = bp_disabled;
			return 0;
		}
	}
	return -1;
}

int remove_all_break(void)
{
	int i;
	for (i=0; i < MAX_BREAKPOINTS; i++) {
		if(kgdb_break[i].state == bp_enabled) {
			unsigned long addr = kgdb_break[i].bpt_addr;
			set_mem((char *)addr, kgdb_break[i].saved_instr,
			       BREAK_INSTR_SIZE);
			flush_cache_range (current->mm, addr, addr + BREAK_INSTR_SIZE);
			flush_icache_range (addr, addr + BREAK_INSTR_SIZE);
		}
		kgdb_break[i].state = bp_disabled;
	}
	return 0;
}
		
int get_char(char *addr, unsigned char *data, int can_fault)
{
	mm_segment_t fs;
	int ret = 0;
	
	kgdb_memerr = 0;
	
	if (can_fault)
		kgdb_memerr_expected = 1;
	wmb();
	fs = get_fs();
	set_fs(KERNEL_DS);
	
	if (get_user(*data, addr) != 0) {
		ret = -EFAULT;
		kgdb_memerr = 1;
	}
	
	kgdb_memerr_expected = 0;	
	set_fs(fs);
	return ret;
}

int set_char(char *addr, int data, int can_fault)
{
	mm_segment_t fs;
	int ret = 0;
	
	kgdb_memerr = 0;
	
	if (can_fault)
		kgdb_memerr_expected = 1;
	wmb();
	fs = get_fs();
	set_fs(KERNEL_DS);

	if (put_user(data, addr) != 0) {
		ret = -EFAULT;
		kgdb_memerr = 1;
	}
	
	kgdb_memerr_expected = 0;
	set_fs(fs);
	return ret;
}

/*
 * This function does all command procesing for interfacing to gdb.
 */

int kgdb_handle_exception(int exVector, int signo, int err_code, 
                     struct pt_regs *linux_regs)
{
	int length, addr;
	char *ptr;
	unsigned long flags;
	int gdb_regs[NUMREGBYTES / 4];
	int i;
	int threadid;
#ifdef CONFIG_KGDB_THREAD
	threadref thref;
	struct task_struct *thread = NULL;
	int nothreads;
	int maxthreads;
#endif
	unsigned procid;
	int ret = 0;
	struct pt_regs *oldregs = current->thread.kgdbregs;

	/* 
	 * Interrupts will be restored by the 'trap return' code, except when
	 * single stepping.
	 */
	local_irq_save(flags);
	
	/* Hold kgdb_lock */
	procid = smp_processor_id();
	while (cmpxchg(&atomic_read(&kgdb_lock), 0, (procid + 1)) != 0) {
		int i = 25;	/* an arbitrary number */

		while (--i)
			asm volatile ("nop": : : "memory");
	}
	
	kgdb_step = 0;


	local_irq_save(flags);

	current->thread.kgdbregs = linux_regs;

	if (kgdb_ops->disable_hw_debug)
		kgdb_ops->disable_hw_debug(linux_regs);
	
	
	for (i = 0; i < smp_num_cpus; i++) {
		spin_lock(&slavecpulocks[i]);
	}

	/* spin_lock code is good enough as a barrier so we don't
	 * need one here */
	procindebug[smp_processor_id()] = 1;

	/* Master processor is completely in the debugger */

	if (kgdb_ops->post_master_code)
		kgdb_ops->post_master_code(linux_regs, exVector, err_code);

	if (atomic_read(&kgdb_killed_or_detached) &&
	    atomic_read(&kgdb_might_be_resumed)) {
		getpacket(remcomInBuffer);
		if(remcomInBuffer[0] == 'H' && remcomInBuffer[1] =='c') {
			remove_all_break();
			atomic_set(&kgdb_killed_or_detached, 0);
			remcomOutBuffer[0] = 'O';
			remcomOutBuffer[1] = 'K';
			remcomOutBuffer[2] = 0;
		}
		else
			return 1;
	}
	else {

		/* reply to host that an exception has occurred */
		remcomOutBuffer[0] = 'S';
		remcomOutBuffer[1] = hexchars[signo >> 4];
		remcomOutBuffer[2] = hexchars[signo % 16];
		remcomOutBuffer[3] = 'p';

		int_to_threadref(&thref, current->pid ? 
		                 current->pid :
		                 PID_MAX + cpu_number_map(smp_processor_id()));

		*pack_threadid(remcomOutBuffer + 4, &thref) = 0;
	}		
	putpacket(remcomOutBuffer);
	
	kgdb_usethread = current;

	while (1) {
		int bpt_type = 0;
		error = 0;
		remcomOutBuffer[0] = 0;
		remcomOutBuffer[1] = 0;
		getpacket(remcomInBuffer);

#if KGDB_DEBUG
		bust_spinlocks(1);
		printk("CPU%d pid%d GDB packet: %s\n", 
		       smp_processor_id(), current->pid, remcomInBuffer);
		bust_spinlocks(0);
#endif
		switch (remcomInBuffer[0]) {
		case '?':
			remcomOutBuffer[0] = 'S';
			remcomOutBuffer[1] = hexchars[signo >> 4];
			remcomOutBuffer[2] = hexchars[signo % 16];
			remcomOutBuffer[3] = 0;
			break;

		case 'g':	/* return the value of the CPU registers */
			thread = kgdb_usethread;
				
			if (!thread)
				thread = current;
			
			/* All threads that don't have kgdbregs should be
			   in __schedule() sleeping, since all other CPUs
			   are in gdbwait, and thus have kgdbregs. */
			   
			if (thread->thread.kgdbregs) 
				kgdb_ops->regs_to_gdb_regs(gdb_regs, thread->thread.kgdbregs);
			else {
				/* Pull stuff saved during 
				 * switch_to; nothing else is
				   accessible (or even particularly relevant).
				   This should be enough for a stack trace. */
				kgdb_ops->sleeping_thread_to_gdb_regs(gdb_regs, thread);
			}
				
			mem2hex((char *) gdb_regs, remcomOutBuffer, NUMREGBYTES, 0);
			break;

		case 'G':	/* set the value of the CPU registers - return OK */
			hex2mem(&remcomInBuffer[1], (char *) gdb_regs,
				NUMREGBYTES, 0);
				
			if (kgdb_usethread && kgdb_usethread != current)
				strcpy(remcomOutBuffer, "E00");
			else {
				kgdb_ops->gdb_regs_to_regs(gdb_regs, current->thread.kgdbregs);
				strcpy(remcomOutBuffer, "OK");
			}

			break;

			/* mAA..AA,LLLL  Read LLLL bytes at address AA..AA */
		case 'm':
			/* TRY TO READ %x,%x.  IF SUCCEED, SET PTR = 0 */
			ptr = &remcomInBuffer[1];
			if (hexToInt(&ptr, &addr) && *ptr++ == ',' &&
			    hexToInt(&ptr, &length)) {
				ptr = 0;
				mem2hex((char *) addr, remcomOutBuffer, length, 1);
				if (kgdb_memerr)
					strcpy(remcomOutBuffer, "E03");
					
			}

			if (ptr) 
				strcpy(remcomOutBuffer, "E01");
			break;

		/* MAA..AA,LLLL: Write LLLL bytes at address AA.AA return OK */
		case 'M':
			/* TRY TO READ '%x,%x:'.  IF SUCCEED, SET PTR = 0 */
			ptr = &remcomInBuffer[1];
			if (hexToInt(&ptr, &addr) && *(ptr++) == ',' && 
			    hexToInt(&ptr, &length) && *(ptr++) == ':') {
				hex2mem(ptr, (char *)addr, length, 1);
				if (kgdb_memerr)
					strcpy(remcomOutBuffer, "E03");
				else
					strcpy(remcomOutBuffer, "OK");
				ptr = 0;
			}
			if (ptr) {
				strcpy(remcomOutBuffer, "E02");
			}
			break;

			
			/* Continue and Single Step are Architecture specific
			 * and will not be handled by the generic code.
			 */


			/* kill the program. KGDB should treat this like a 
			 * continue.
			 */
		case 'D':
			remcomOutBuffer[0] = 'O';
			remcomOutBuffer[1] = 'K';
			remcomOutBuffer[2] = '\0';
			remove_all_break();
			putpacket(remcomOutBuffer);
			goto default_handle;

		case 'k':
			remove_all_break();
			goto default_handle;

			/* query */
		case 'q':
			switch (remcomInBuffer[1]) {
			case 'L':
				/* List threads */
				unpack_byte(remcomInBuffer + 3,
					    &maxthreads);
				unpack_threadid(remcomInBuffer + 5,
						&thref);

				remcomOutBuffer[0] = 'q';
				remcomOutBuffer[1] = 'M';
				remcomOutBuffer[4] = '0';
				pack_threadid(remcomOutBuffer + 5, &thref);

				threadid = threadref_to_int(&thref);
				for (nothreads = 0;
				     nothreads < maxthreads
				     && threadid < PID_MAX + smp_num_cpus; threadid++) {
					thread = getthread(threadid);
					if (thread) {
						int_to_threadref(&thref,
								 threadid);
						pack_threadid
						    (remcomOutBuffer + 21 +
						     nothreads * 16,
						     &thref);
						nothreads++;
					}
				}
				
				
				if (threadid == PID_MAX + smp_num_cpus) {
					remcomOutBuffer[4] = '1';
				}
				pack_hex_byte(remcomOutBuffer + 2,
					      nothreads);
				remcomOutBuffer[21 + nothreads * 16] = '\0';
				break;

			case 'C':
				/* Current thread id */
				remcomOutBuffer[0] = 'Q';
				remcomOutBuffer[1] = 'C';
				threadid = current->pid;
				
				if (threadid == 0)
					threadid = cpu_number_map(smp_processor_id()) + PID_MAX;
				
				int_to_threadref(&thref, threadid);
				pack_threadid(remcomOutBuffer + 2, &thref);
				remcomOutBuffer[18] = '\0';
				break;

			case 'E':
				/* Print exception info */
				if (kgdb_ops->printexpinfo)
					kgdb_ops->printexpinfo(exVector,
                   			                       err_code,
					                       remcomOutBuffer);
				break;
			}
			break;

			/* task related */
		case 'H':
			switch (remcomInBuffer[1]) {
			case 'g':
				ptr = &remcomInBuffer[2];
				hexToInt(&ptr, &threadid);
				thread = getthread(threadid);
				if (!thread && threadid > 0) {
					remcomOutBuffer[0] = 'E';
					remcomOutBuffer[1] = '\0';
					break;
				}
				kgdb_usethread = thread;
				remcomOutBuffer[0] = 'O';
				remcomOutBuffer[1] = 'K';
				remcomOutBuffer[2] = '\0';
				break;

			case 'c':
				atomic_set(&kgdb_killed_or_detached, 0);
				ptr = &remcomInBuffer[2];
				hexToInt(&ptr, &threadid);
				thread = getthread(threadid);
				if (!thread && threadid > 0) {
					remcomOutBuffer[0] = 'E';
					remcomOutBuffer[1] = '\0';
					break;
				}
				kgdb_contthread = thread;
				remcomOutBuffer[0] = 'O';
				remcomOutBuffer[1] = 'K';
				remcomOutBuffer[2] = '\0';
				break;
			}
			break;

			/* Query thread status */
		case 'T':
			ptr = &remcomInBuffer[1];
			hexToInt(&ptr, &threadid);
			thread = getthread(threadid);
			if (thread) {
				remcomOutBuffer[0] = 'O';
				remcomOutBuffer[1] = 'K';
				remcomOutBuffer[2] = '\0';
			} else {
				remcomOutBuffer[0] = 'E';
				remcomOutBuffer[1] = '\0';
			}
			break;
		case 'z':
		case 'Z':
			ptr = &remcomInBuffer[2];
			if (*(ptr++) != ',') {
				strcpy(remcomOutBuffer, "ERROR");
				break;
			}
			hexToInt(&ptr, &addr);
			
			bpt_type = remcomInBuffer[1];
			if (bpt_type != bp_breakpoint) {
				if (bpt_type == bp_hardware_breakpoint && 
				    !(kgdb_ops->flags & KGDB_HW_BREAKPOINT))
					break;

				/* if set_break is not defined, then
				 * remove_break does not matter
				 */
				if(!kgdb_ops->set_break)
					break;
			}
			
			if (remcomInBuffer[0] == 'Z') {
				if (bpt_type == bp_breakpoint)
					ret = set_break(addr);
				else
					ret = kgdb_ops->set_break(addr, bpt_type);
			}
			else {
				if (bpt_type == bp_breakpoint)
					ret = remove_break(addr);
				else
					ret = kgdb_ops->remove_break(addr, bpt_type);
			}
			
			if (ret == 0)
				strcpy(remcomOutBuffer, "OK");
			else
				strcpy(remcomOutBuffer, "ERROR");
			
			break;

		default:
		default_handle:
			ret = 0;
			if (kgdb_ops->handle_buffer)
				ret= kgdb_ops->handle_buffer(exVector, signo, 
				                             err_code,
				                             remcomInBuffer,
				                             remcomOutBuffer,
				                             linux_regs);
			if(ret >= 0 || remcomInBuffer[0] == 'D' ||
			    remcomInBuffer[0] == 'k')
				goto kgdb_exit;


		}		/* switch */
#if KGDB_DEBUG
		bust_spinlocks(1);
		printk("Response to GDB: %s\n", remcomOutBuffer);
		bust_spinlocks(0);
#endif

		/* reply to the request */
		putpacket(remcomOutBuffer);
	}
kgdb_exit:
	
	if(kgdb_ops->handler_exit)
		kgdb_ops->handler_exit();
	
	procindebug[smp_processor_id()] = 0;	
	
	for (i = 0; i < smp_num_cpus; i++) {
		spin_unlock(&slavecpulocks[i]);
	}
	/* Wait till all the processors have quit
	 * from the debugger 
	 */
	for (i = 0; i < smp_num_cpus; i++) { 
		while (procindebug[i]) {
			int j = 10; /* an arbitrary number */

			while (--j) {
				asm volatile ("nop" : : : "memory");
			}
			barrier();
		}
	}

	/* Free kgdb_lock */
	atomic_set(&kgdb_lock, 0);
	current->thread.kgdbregs = oldregs;
	atomic_set(&kgdb_killed_or_detached, 1);
	local_irq_restore(flags);
	return ret;
}

/* this function is used to set up exception handlers for tracing and
   breakpoints */
void set_debug_traps(void)
{
	int i;
	
	for (i = 0; i < KGDB_MAX_NO_CPUS; i++) 
		spin_lock_init(&slavecpulocks[i]);

	/* Free kgdb_lock */
	atomic_set(&kgdb_lock, 0);

	/* This flag is used, if gdb has detached and wants to start
	 * another session
	 */
	atomic_set(&kgdb_killed_or_detached, 0);
	atomic_set(&kgdb_might_be_resumed, 0);

	for (i = 0; i < MAX_BREAKPOINTS; i++) 
		kgdb_break[i].state = bp_disabled;

	
	/*
	 * In case GDB is started before us, ack any packets (presumably
	 * "$?#xx") sitting there.  */
	putDebugChar('+');

	linux_debug_hook = kgdb_handle_exception;
	
	if (kgdb_ops->kgdb_init)
		kgdb_ops->kgdb_init();

	kgdb_initialized = 1;
	atomic_set(&kgdb_setting_breakpoint, 0);
}

/* This function will generate a breakpoint exception.  It is used at the
   beginning of a program to sync up with a debugger and can be used
   otherwise as a quick means to stop program execution and "break" into
   the debugger. */

void breakpoint(void)
{
	if (kgdb_initialized) {
		atomic_set(&kgdb_setting_breakpoint, 1);
		wmb();
		BREAKPOINT();
		wmb();
		atomic_set(&kgdb_setting_breakpoint, 0);
	}
}

#ifdef CONFIG_GDB_CONSOLE
char gdbconbuf[BUFMAX];

void gdb_console_write(struct console *co, const char *s, unsigned count)
{
	int i;
	int wcount;
	char *bufptr;
	int flags;

	if (!gdb_initialized || atomic_read(&kgdb_killed_or_detached)) {
		return;
	}
	local_irq_save(flags);

	gdbconbuf[0] = 'O';
	bufptr = gdbconbuf + 1;
	while (count > 0) {
		if ((count << 1) > (BUFMAX - 2)) {
			wcount = (BUFMAX - 2) >> 1;
		} else {
			wcount = count;
		}
		count -= wcount;
		for (i = 0; i < wcount; i++) {
			bufptr = pack_hex_byte(bufptr, s[i]);
		}
		*bufptr = '\0';
		s += wcount;

		putpacket(gdbconbuf);

	}
	local_irq_restore(flags);
}
#endif

int gdb_enter;
int gdb_baud = 115200;
int gdb_ttyS;
int gdb_initialized;

static int __init kgdb_opt_gdb(char *str)
{
	gdb_enter = 1;
	return 1;
}
static int __init kgdb_opt_gdbttyS(char *str)
{
	gdb_ttyS = simple_strtoul(str, NULL, 10);
	return 1;
}
static int __init kgdb_opt_gdbbaud(char *str)
{
	gdb_baud = simple_strtoul(str, NULL, 10);
	return 1;
}

/*
 * Sequence of these lines has to be maintained because gdb option is a prefix
 * of the other two options
 */

__setup("gdbttyS=", kgdb_opt_gdbttyS);
__setup("gdbbaud=", kgdb_opt_gdbbaud);
__setup("gdb", kgdb_opt_gdb);
