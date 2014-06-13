# 
# Copyright (C) 2002 Jeff Dike (jdike@karaya.com)
# Licensed under the GPL
#

O_TARGET = built-in.o

obj-y = bugs.o checksum.o extable.o fault.o ksyms.o ldt.o ptrace.o \
	ptrace_user.o semaphore.o sigcontext.o syscalls.o sysrq.o
export-objs = ksyms.o

USER_OBJS = bugs.o ptrace_user.o sigcontext.o fault.o

SYMLINKS = semaphore.c extable.c

semaphore.c-dir = kernel
extable.c-dir = mm

include $(TOPDIR)/Rules.make

$(USER_OBJS) : %.o: %.c
	$(CC) $(CFLAGS_$@) $(USER_CFLAGS) -c -o $@ $<

define make_link
	-rm -f $1
	ln -sf $(TOPDIR)/arch/i386/$($1-dir)/$1 $1
endef

$(SYMLINKS): 
	$(call make_link,$@)

clean:
	$(MAKE) -C util clean
	rm -f $(SYMLINKS)

fastdep:

dep:

archmrproper:

archclean:

archdep:

modules:
