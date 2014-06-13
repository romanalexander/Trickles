# 
# Copyright (C) 2002 Jeff Dike (jdike@karaya.com)
# Licensed under the GPL
#

O_TARGET = skas.o

obj-y = exec_kern.o exec_user.o mem.o mem_user.o mmu.o process.o \
	process_kern.o syscall_kern.o syscall_user.o time.o tlb.o trap_user.o \
	uaccess.o

subdir-y = sys-$(SUBARCH)

obj-y += $(join $(subdir-y),$(subdir-y:%=/%.o))

USER_OBJS = $(filter %_user.o,$(obj-y)) process.o time.o

include $(TOPDIR)/Rules.make

include/skas_ptregs.h : util/mk_ptregs
	util/mk_ptregs > $@

util/mk_ptregs :
	$(MAKE) -C util

$(USER_OBJS) : %.o: %.c
	$(CC) $(CFLAGS_$@) $(USER_CFLAGS) -c -o $@ $<

clean :
	$(MAKE) -C util clean
	$(RM) -f include/skas_ptregs.h
