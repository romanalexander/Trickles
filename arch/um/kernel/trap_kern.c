/* 
 * Copyright (C) 2000, 2001 Jeff Dike (jdike@karaya.com)
 * Licensed under the GPL
 */

#include "linux/kernel.h"
#include "linux/sched.h"
#include "linux/mm.h"
#include "linux/spinlock.h"
#include "linux/config.h"
#include "linux/init.h"
#include "asm/semaphore.h"
#include "asm/pgtable.h"
#include "asm/pgalloc.h"
#include "asm/a.out.h"
#include "asm/current.h"
#include "asm/irq.h"
#include "user_util.h"
#include "kern_util.h"
#include "kern.h"
#include "chan_kern.h"
#include "mconsole_kern.h"
#include "2_5compat.h"
#include "mem.h"
#include "mem_kern.h"

unsigned long handle_page_fault(unsigned long address, unsigned long ip, 
				int is_write, int is_user, int *code_out)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	pgd_t *pgd;
	pmd_t *pmd;
	pte_t *pte;
	unsigned long page;
	int handled = 0;

	*code_out = SEGV_MAPERR;
	down_read(&mm->mmap_sem);
	vma = find_vma(mm, address);
	if(!vma) 
		goto out;
	else if(vma->vm_start <= address) 
		goto good_area;
	else if(!(vma->vm_flags & VM_GROWSDOWN)) 
		goto out;
	else if(expand_stack(vma, address)) 
		goto out;

 good_area:
	*code_out = SEGV_ACCERR;
	if(is_write && !(vma->vm_flags & VM_WRITE)) 
		goto out;
	page = address & PAGE_MASK;
	if(page == (unsigned long) current + PAGE_SIZE)
		panic("Kernel stack overflow");
	pgd = pgd_offset(mm, page);
	pmd = pmd_offset(pgd, page);
	do {
 survive:
		switch (handle_mm_fault(mm, vma, address, is_write)) {
		case 1:
			current->min_flt++;
			break;
		case 2:
			current->maj_flt++;
			break;
		default:
			if (current->pid == 1) {
				up_read(&mm->mmap_sem);
				yield();
				down_read(&mm->mmap_sem);
				goto survive;
			}
			/* Fall through to bad area case */
		case 0:
			goto out;
		}
		pte = pte_offset(pmd, page);
	} while(!pte_present(*pte));
	handled = 1;
	*pte = pte_mkyoung(*pte);
	if(pte_write(*pte)) *pte = pte_mkdirty(*pte);
	flush_tlb_page(vma, page);
 out:
	up_read(&mm->mmap_sem);
	return(handled);
}

LIST_HEAD(physmem_remappers);

void register_remapper(struct remapper *info)
{
	list_add(&info->list, &physmem_remappers);
}

static int check_remapped_addr(unsigned long address, int is_write, int is_user)
{
	struct remapper *remapper;
	struct list_head *ele;
	__u64 offset;
	int fd;

	fd = phys_mapping(__pa(address), &offset);
	if(fd == -1)
		return(0);

	list_for_each(ele, &physmem_remappers){
		remapper = list_entry(ele, struct remapper, list);
		if((*remapper->proc)(fd, address, is_write, offset, is_user))
			return(1);
	}

	return(0);
}

unsigned long segv(unsigned long address, unsigned long ip, int is_write, 
		   int is_user, void *sc)
{
	struct siginfo si;
	void *catcher;
	int handled;

        if(!is_user && (address >= start_vm) && (address < end_vm)){
                flush_tlb_kernel_vm();
                return(0);
        }
	else if(check_remapped_addr(address & PAGE_MASK, is_write, is_user))
		return(0);
	else if(current->mm == NULL)
		panic("Segfault with no mm");

	handled = handle_page_fault(address, ip, is_write, is_user, 
				    &si.si_code);

	catcher = current->thread.fault_catcher;
	if(handled)
		return(0);
	else if(catcher != NULL){
		current->thread.fault_addr = (void *) address;
		do_longjmp(catcher, 1);
	} 
	else if(current->thread.fault_addr != NULL)
		panic("fault_addr set but no fault catcher");
	else if(arch_fixup(ip, sc))
		return(0);

 	if(!is_user) 
		panic("Kernel mode fault at addr 0x%lx, ip 0x%lx", 
		      address, ip);
	si.si_signo = SIGSEGV;
	si.si_addr = (void *) address;
	current->thread.cr2 = address;
	current->thread.err = is_write;
	force_sig_info(SIGSEGV, &si, current);
	return(0);
}

void bad_segv(unsigned long address, unsigned long ip, int is_write)
{
	struct siginfo si;

	si.si_signo = SIGSEGV;
	si.si_code = SEGV_ACCERR;
	si.si_addr = (void *) address;
	current->thread.cr2 = address;
	current->thread.err = is_write;
	force_sig_info(SIGSEGV, &si, current);
}

void relay_signal(int sig, union uml_pt_regs *regs)
{
	if(arch_handle_signal(sig, regs)) return;
	if(!UPT_IS_USER(regs))
		panic("Kernel mode signal %d", sig);
	force_sig(sig, current);
}

void bus_handler(int sig, union uml_pt_regs *regs)
{
	if(current->thread.fault_catcher != NULL)
		do_longjmp(current->thread.fault_catcher, 1);
	else relay_signal(sig, regs);
}

void winch(int sig, union uml_pt_regs *regs)
{
	do_IRQ(WINCH_IRQ, regs);
}

void trap_init(void)
{
}

spinlock_t trap_lock = SPIN_LOCK_UNLOCKED;

static int trap_index = 0;

int next_trap_index(int limit)
{
	int ret;

	spin_lock(&trap_lock);
	ret = trap_index;
	if(++trap_index == limit)
		trap_index = 0;
	spin_unlock(&trap_lock);
	return(ret);
}

/*
 * Overrides for Emacs so that we follow Linus's tabbing style.
 * Emacs will notice this stuff at the end of the file and automatically
 * adjust the settings for this buffer only.  This must remain at the end
 * of the file.
 * ---------------------------------------------------------------------------
 * Local variables:
 * c-file-style: "linux"
 * End:
 */
