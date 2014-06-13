/* 
 * Copyright (C) 2002 Jeff Dike (jdike@karaya.com)
 * Licensed under the GPL
 */

#include "linux/sched.h"
#include "linux/signal.h"
#include "linux/kernel.h"
#include "linux/slab.h"
#include "asm/system.h"
#include "asm/pgalloc.h"
#include "asm/ptrace.h"
#include "irq_user.h"
#include "signal_user.h"
#include "kern_util.h"
#include "user_util.h"
#include "os.h"
#include "kern.h"
#include "sigcontext.h"
#include "time_user.h"
#include "mem_user.h"
#include "tlb.h"
#include "mode.h"
#include "init.h"
#include "tt.h"
#include "filehandle.h"

void *_switch_to_tt(void *prev, void *next)
{
	struct task_struct *from, *to;
	struct file_handle *pipe;
	unsigned long flags;
	int err, vtalrm, alrm, prof, cpu;
	char c;
	/* jailing and SMP are incompatible, so this doesn't need to be 
	 * made per-cpu 
	 */
	static int reading;

	from = prev;
	to = next;

	to->thread.prev_sched = from;

	cpu = from->processor;
	if(cpu == 0)
		forward_interrupts(to->thread.mode.tt.extern_pid);
#ifdef CONFIG_SMP
	forward_ipi(cpu_data[cpu].ipi_pipe[0], to->thread.mode.tt.extern_pid);
#endif
	local_irq_save(flags);

	vtalrm = change_sig(SIGVTALRM, 0);
	alrm = change_sig(SIGALRM, 0);
	prof = change_sig(SIGPROF, 0);

	c = 0;
	set_current(to);

	reading = 0;
	pipe = to->thread.mode.tt.switch_pipe;
	err = write_file(&pipe[1], -1, &c, sizeof(c));
	if(err != sizeof(c))
		panic("write of switch_pipe failed, err = %d", -err);

	reading = 1;
	if(from->state == TASK_ZOMBIE)
		os_kill_process(os_getpid(), 0);

	pipe = from->thread.mode.tt.switch_pipe;
	err = read_file(&pipe[0], -1, &c, sizeof(c));
	if(err != sizeof(c))
		panic("read of switch_pipe failed, errno = %d", -err);

	/* This works around a nasty race with 'jail'.  If we are switching
	 * between two threads of a threaded app and the incoming process 
	 * runs before the outgoing process reaches the read, and it makes
	 * it all the way out to userspace, then it will have write-protected 
	 * the outgoing process stack.  Then, when the outgoing process 
	 * returns from the write, it will segfault because it can no longer
	 * write its own stack.  So, in order to avoid that, the incoming 
	 * thread sits in a loop yielding until 'reading' is set.  This 
	 * isn't entirely safe, since there may be a reschedule from a timer
	 * happening between setting 'reading' and sleeping in read.  But,
	 * it should get a whole quantum in which to reach the read and sleep,
	 * which should be enough.
	 */

	if(jail){
		while(!reading) sched_yield();
	}

	change_sig(SIGVTALRM, vtalrm);
	change_sig(SIGALRM, alrm);
	change_sig(SIGPROF, prof);

	arch_switch();

	flush_tlb_all();
	local_irq_restore(flags);

	return(current->thread.prev_sched);
}

void release_thread_tt(struct task_struct *task)
{
	os_kill_process(task->thread.mode.tt.extern_pid, 0);
}

void exit_thread_tt(void)
{
	struct file_handle *pipe = current->thread.mode.tt.switch_pipe;

	close_file(&pipe[0]);
	close_file(&pipe[1]);
	kfree(pipe);
}

static void suspend_new_thread(struct file_handle *fh)
{
	char c;

	os_stop_process(os_getpid());

	if(read_file(fh, -1, &c, sizeof(c)) != sizeof(c))
		panic("read failed in suspend_new_thread");
}

extern void schedule_tail(struct task_struct *prev);

static void new_thread_handler(int sig)
{
	struct file_handle *pipe;
	unsigned long disable;
	int (*fn)(void *);
	void *arg;

	fn = current->thread.request.u.thread.proc;
	arg = current->thread.request.u.thread.arg;

	UPT_SC(&current->thread.regs.regs) = (void *) (&sig + 1);
	disable = (1 << (SIGVTALRM - 1)) | (1 << (SIGALRM - 1)) |
		(1 << (SIGIO - 1)) | (1 << (SIGPROF - 1));
	SC_SIGMASK(UPT_SC(&current->thread.regs.regs)) &= ~disable;

	pipe = current->thread.mode.tt.switch_pipe;
	suspend_new_thread(&pipe[0]);

	init_new_thread_signals(1);
	enable_timer();
	free_page(current->thread.temp_stack);
	set_cmdline("(kernel thread)");
	force_flush_all();

	if(current->thread.prev_sched != NULL)
		schedule_tail(current->thread.prev_sched);
	current->thread.prev_sched = NULL;

	change_sig(SIGUSR1, 1);
	change_sig(SIGVTALRM, 1);
	change_sig(SIGPROF, 1);
	sti();
	if(!run_kernel_thread(fn, arg, &current->thread.exec_buf))
		do_exit(0);
	
	/* XXX No set_user_mode here because a newly execed process will
	 * immediately segfault on its non-existent IP, coming straight back
	 * to the signal handler, which will call set_user_mode on its way
	 * out.  This should probably change since it's confusing.
	 */
}

static int new_thread_proc(void *stack)
{
	/* cli is needed to block out signals until this thread is properly
	 * scheduled.  Otherwise, the tracing thread will get mighty upset 
	 * about any signals that arrive before that.  
	 * This has the complication that it sets the saved signal mask in
	 * the sigcontext to block signals.  This gets restored when this
	 * thread (or a descendant, since they get a copy of this sigcontext)
	 * returns to userspace.
	 * So, this is compensated for elsewhere.
	 * XXX There is still a small window until cli() actually finishes
	 * where signals are possible - shouldn't be a problem in practice 
	 * since SIGIO hasn't been forwarded here yet, and the cli should 
	 * finish before a SIGVTALRM has time to be delivered.
	 */
	cli();
	init_new_thread_stack(stack, new_thread_handler);
	os_usr1_process(os_getpid());
	change_sig(SIGUSR1, 1);
	return(0);
}

/* Signal masking - signals are blocked at the start of fork_tramp.  They
 * are re-enabled when finish_fork_handler is entered by fork_tramp hitting
 * itself with a SIGUSR1.  set_user_mode has to be run with SIGUSR1 off,
 * so it is blocked before it's called.  They are re-enabled on sigreturn
 * despite the fact that they were blocked when the SIGUSR1 was issued because
 * copy_thread copies the parent's sigcontext, including the signal mask
 * onto the signal frame.
 */

static void finish_fork_handler(int sig)
{
	struct file_handle *pipe = current->thread.mode.tt.switch_pipe;

	UPT_SC(&current->thread.regs.regs) = (void *) (&sig + 1);
	suspend_new_thread(&pipe[0]);
	
	init_new_thread_signals(1);
	enable_timer();
	sti();
	force_flush_all();
	if(current->mm != current->p_pptr->mm)
		protect_memory(uml_reserved, high_physmem - uml_reserved, 1, 
			       1, 0, 1);
	task_protections((unsigned long) current);

	if(current->thread.prev_sched != NULL)
		schedule_tail(current->thread.prev_sched);
	current->thread.prev_sched = NULL;

	free_page(current->thread.temp_stack);
	cli();
	change_sig(SIGUSR1, 0);
	set_user_mode(current);
}

int fork_tramp(void *stack)
{
	cli();
	arch_init_thread();
	init_new_thread_stack(stack, finish_fork_handler);
	os_usr1_process(os_getpid());
	change_sig(SIGUSR1, 1);
	return(0);
}

struct file_handle *make_switch_pipe(void)
{
	struct file_handle *pipe;
	int err;

	pipe = kmalloc(sizeof(struct file_handle [2]), GFP_KERNEL);
	if(pipe == NULL){
		pipe = ERR_PTR(-ENOMEM);
		goto out;
	}

	err = make_pipe(pipe);
	if(err)
		goto out_free;

 out:
	return(pipe);

 out_free:
	kfree(pipe);
	pipe = ERR_PTR(err);
	goto out;
}

int copy_thread_tt(int nr, unsigned long clone_flags, unsigned long sp,
		   unsigned long stack_top, struct task_struct * p, 
		   struct pt_regs *regs)
{
	int (*tramp)(void *);
	int new_pid, err;
	unsigned long stack;
	
	if(current->thread.forking)
		tramp = fork_tramp;
	else {
		tramp = new_thread_proc;
		p->thread.request.u.thread = current->thread.request.u.thread;
	}

	p->thread.mode.tt.switch_pipe = make_switch_pipe();
	if(IS_ERR(p->thread.mode.tt.switch_pipe)){
		err = PTR_ERR(p->thread.mode.tt.switch_pipe);
		goto out;
	}

	stack = alloc_stack(0, 0);
	if(stack == 0){
		printk(KERN_ERR "copy_thread : failed to allocate "
		       "temporary stack\n");
		err = -ENOMEM;
		goto out_close;
	}

	clone_flags &= CLONE_VM;
	p->thread.temp_stack = stack;
	new_pid = start_fork_tramp(p, stack, clone_flags, tramp);
	if(new_pid < 0){
		printk(KERN_ERR "copy_thread : clone failed - errno = %d\n", 
		       -new_pid);
		err = new_pid;
		goto out_stack;
	}

	if(current->thread.forking){
		sc_to_sc(UPT_SC(&p->thread.regs.regs), 
			 UPT_SC(&current->thread.regs.regs));
		SC_SET_SYSCALL_RETURN(UPT_SC(&p->thread.regs.regs), 0);
		if(sp != 0) SC_SP(UPT_SC(&p->thread.regs.regs)) = sp;
	}
	p->thread.mode.tt.extern_pid = new_pid;

	current->thread.request.op = OP_FORK;
	current->thread.request.u.fork.pid = new_pid;
	os_usr1_process(os_getpid());

	/* Enable the signal and then disable it to ensure that it is handled
	 * here, and nowhere else.
	 */
	change_sig(SIGUSR1, 1);

	change_sig(SIGUSR1, 0);
	err = 0;

 out:
	return(err);

 out_stack:
	free_stack(stack, 0);
 out_close:
	close_file(&((struct file_handle *) p->thread.mode.tt.switch_pipe)[0]);
	close_file(&((struct file_handle *) p->thread.mode.tt.switch_pipe)[1]);
	kfree(p->thread.mode.tt.switch_pipe);
	goto out;
}

void reboot_tt(void)
{
	current->thread.request.op = OP_REBOOT;
	os_usr1_process(os_getpid());
	change_sig(SIGUSR1, 1);
}

void halt_tt(void)
{
	current->thread.request.op = OP_HALT;
	os_usr1_process(os_getpid());
	change_sig(SIGUSR1, 1);
}

void kill_off_processes_tt(void)
{
	struct task_struct *p;
	int me;

	me = os_getpid();
	for_each_task(p){
		int pid = p->thread.mode.tt.extern_pid;
		if((pid != me) && (pid != -1))
			os_kill_process(p->thread.mode.tt.extern_pid, 0);
	}
	if((init_task.thread.mode.tt.extern_pid != me) &&
	   (init_task.thread.mode.tt.extern_pid != -1))
		os_kill_process(init_task.thread.mode.tt.extern_pid, 0);
}

void initial_thread_cb_tt(void (*proc)(void *), void *arg)
{
	if(os_getpid() == tracing_pid){
		(*proc)(arg);
	}
	else {
		current->thread.request.op = OP_CB;
		current->thread.request.u.cb.proc = proc;
		current->thread.request.u.cb.arg = arg;
		os_usr1_process(os_getpid());
		change_sig(SIGUSR1, 1);

		change_sig(SIGUSR1, 0);
	}
}

int do_proc_op(void *t, int proc_id)
{
	struct task_struct *task;
	struct thread_struct *thread;
	int op, pid;

	task = t;
	thread = &task->thread;
	op = thread->request.op;
	switch(op){
	case OP_NONE:
	case OP_TRACE_ON:
		break;
	case OP_EXEC:
		pid = thread->request.u.exec.pid;
		do_exec(thread->mode.tt.extern_pid, pid);
		thread->mode.tt.extern_pid = pid;
		cpu_tasks[task->processor].pid = pid;
		break;
	case OP_FORK:
		attach_process(thread->request.u.fork.pid);
		break;
	case OP_CB:
		(*thread->request.u.cb.proc)(thread->request.u.cb.arg);
		break;
	case OP_REBOOT:
	case OP_HALT:
		break;
	default:
		tracer_panic("Bad op in do_proc_op");
		break;
	}
	thread->request.op = OP_NONE;
	return(op);
}

void init_idle_tt(void)
{
	idle_timer();
}

/* Changed by jail_setup, which is a setup */
int jail = 0;

int __init jail_setup(char *line, int *add)
{
	int ok = 1;

	if(jail) return(0);
#ifdef CONFIG_SMP
	printf("'jail' may not used used in a kernel with CONFIG_SMP "
	       "enabled\n");
	ok = 0;
#endif
#ifdef CONFIG_HOSTFS
	printf("'jail' may not used used in a kernel with CONFIG_HOSTFS "
	       "enabled\n");
	ok = 0;
#endif
#ifdef CONFIG_MODULES
	printf("'jail' may not used used in a kernel with CONFIG_MODULES "
	       "enabled\n");
	ok = 0;
#endif	
	if(!ok) exit(1);

	/* CAP_SYS_RAWIO controls the ability to open /dev/mem and /dev/kmem.
	 * Removing it from the bounding set eliminates the ability of anything
	 * to acquire it, and thus read or write kernel memory.
	 */
	cap_lower(cap_bset, CAP_SYS_RAWIO);
	jail = 1;
	return(0);
}

__uml_setup("jail", jail_setup,
"jail\n"
"    Enables the protection of kernel memory from processes.\n\n"
);

static void mprotect_kernel_mem(int w)
{
	unsigned long start, end;
	int pages;

	if(!jail || (current == &init_task)) return;

	pages = (1 << CONFIG_KERNEL_STACK_ORDER);

	start = (unsigned long) current + PAGE_SIZE;
	end = (unsigned long) current + PAGE_SIZE * pages;
	protect_memory(uml_reserved, start - uml_reserved, 1, w, 1, 1);
	protect_memory(end, high_physmem - end, 1, w, 1, 1);

	start = (unsigned long) UML_ROUND_DOWN(&_stext);
	end = (unsigned long) UML_ROUND_UP(&_etext);
	protect_memory(start, end - start, 1, w, 1, 1);

	start = (unsigned long) UML_ROUND_DOWN(&_unprotected_end);
	end = (unsigned long) UML_ROUND_UP(&_edata);
	protect_memory(start, end - start, 1, w, 1, 1);

	start = (unsigned long) UML_ROUND_DOWN(&__bss_start);
	end = (unsigned long) UML_ROUND_UP(&_end);
	protect_memory(start, end - start, 1, w, 1, 1);

	mprotect_kernel_vm(w);
}

void unprotect_kernel_mem(void)
{
	mprotect_kernel_mem(1);
}

void protect_kernel_mem(void)
{
	mprotect_kernel_mem(0);
}

extern void start_kernel(void);

static int start_kernel_proc(void *unused)
{
	int pid;

	block_signals();
	pid = os_getpid();

	cpu_tasks[0].pid = pid;
	cpu_tasks[0].task = current;
#ifdef CONFIG_SMP
 	cpu_online_map = 1;
#endif
	if(debug) os_stop_process(pid);
	start_kernel();
	return(0);
}

void set_tracing(void *task, int tracing)
{
	((struct task_struct *) task)->thread.mode.tt.tracing = tracing;
}

int is_tracing(void *t)
{
	return (((struct task_struct *) t)->thread.mode.tt.tracing);
}

int set_user_mode(void *t)
{
	struct task_struct *task;

	task = t ? t : current;
	if(task->thread.mode.tt.tracing) 
		return(1);
	task->thread.request.op = OP_TRACE_ON;
	os_usr1_process(os_getpid());
	return(0);
}

/* This is static rather than kmalloced because this happens before kmalloc
 * is initialized.  Also, it is always needed, so might as well be static on
 * this ground.
 */
static struct file_handle init_switch_pipe[2];

void set_init_pid(int pid)
{
	int err;

	init_task.thread.mode.tt.extern_pid = pid;

	err = make_pipe(init_switch_pipe);
	if(err)
		panic("set_init_pid - make_pipe failed, errno = %d", err);
	init_task.thread.mode.tt.switch_pipe = init_switch_pipe;
}

int singlestepping_tt(void *t)
{
	struct task_struct *task = t;

	if(task->thread.mode.tt.singlestep_syscall)
		return(0);
	return(task->ptrace & PT_DTRACE);
}

void clear_singlestep(void *t)
{
	struct task_struct *task = t;

	task->ptrace &= ~PT_DTRACE;
}

int start_uml_tt(void)
{
	void *sp;
	int pages;

	pages = (1 << CONFIG_KERNEL_STACK_ORDER);
	sp = (void *) ((unsigned long) &init_task) + pages * PAGE_SIZE - 
		sizeof(unsigned long);
	return(tracer(start_kernel_proc, sp));
}

int external_pid_tt(struct task_struct *task)
{
	return(task->thread.mode.tt.extern_pid);
}

int thread_pid_tt(struct thread_struct *thread)
{
	return(thread->mode.tt.extern_pid);
}

int is_valid_pid(int pid)
{
	struct task_struct *task;

        read_lock(&tasklist_lock);
        for_each_task(task){
                if(task->thread.mode.tt.extern_pid == pid){
			read_unlock(&tasklist_lock);
			return(1);
                }
        }
	read_unlock(&tasklist_lock);
	return(0);
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
