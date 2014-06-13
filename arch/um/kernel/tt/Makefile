# 
# Copyright (C) 2002 - 2003 Jeff Dike (jdike@addtoit.com)
# Licensed under the GPL
#

O_TARGET = tt.o

obj-y = exec_kern.o exec_user.o gdb.o ksyms.o mem.o mem_user.o process_kern.o \
	syscall_kern.o syscall_user.o time.o tlb.o tracer.o trap_user.o \
	uaccess.o uaccess_user.o

obj-$(CONFIG_PT_PROXY) += gdb_kern.o 

subdir-y = sys-$(SUBARCH)
subdir-$(CONFIG_PT_PROXY) += ptproxy

obj-y += $(join $(subdir-y),$(subdir-y:%=/%.o))

export-objs = ksyms.o

USER_OBJS = $(filter %_user.o,$(obj-y)) gdb.o time.o tracer.o

UNMAP_CFLAGS := $(patsubst -pg -DPROFILING,,$(USER_CFLAGS))
UNMAP_CFLAGS := $(patsubst -fprofile-arcs -ftest-coverage,,$(UNMAP_CFLAGS))

include $(TOPDIR)/Rules.make

$(USER_OBJS) : %.o: %.c
	$(CC) $(CFLAGS_$@) $(USER_CFLAGS) -c -o $@ $<

$(O_TARGET) : unmap_fin.o

unmap.o: unmap.c
	$(CC) $(UNMAP_CFLAGS) -c -o $@ $<

unmap_fin.o : unmap.o
	ld -r -o $@ $< -lc -L/usr/lib

clean :
