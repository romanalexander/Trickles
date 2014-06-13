# 
# Copyright (C) 2000 - 2004 Jeff Dike (jdike@addtoit.com)
# Licensed under the GPL
#

O_TARGET = built-in.o

obj-y = aio.o file.o process.o time.o tty.o

HAVE_AIO_ABI = $(shell [ -e /usr/include/linux/aio_abi.h ] && \
	echo -DHAVE_AIO_ABI)
HAVE_AIO_LIBC = $(shell objdump -T /lib/libc-*.so | grep io_submit && \
	echo -DHAVE_AIO_LIBC)
CFLAGS_aio.o = $(HAVE_AIO_ABI) $(HAVE_AIO_LIBC)

include $(TOPDIR)/Rules.make

$(obj-y) : %.o: %.c
	$(CC) $(CFLAGS_$@) $(USER_CFLAGS) -c -o $@ $<

clean :

archmrproper:
