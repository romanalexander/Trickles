# Makefile for MIPS kernel build tools.
#
# Copyright (C) 1996 David S. Miller (dm@engr.sgi.com)
# Copyright (C) 1997 Ralf Baechle (ralf@gnu.ai.mit.edu)
#
# $Id: Makefile,v 1.1.1.1 2004/06/19 05:04:08 ashieh Exp $
#
TARGET	:= $(TOPDIR)/include/asm-$(ARCH)/offset.h

.S.s:
	$(CPP) $(CFLAGS) $< -o $*.s
.S.o:
	$(CC) $(CFLAGS) -c $< -o $*.o

all: $(TARGET)

$(TARGET): offset.h
	cmp -s $^ $@ || (cp $^ $(TARGET).new && mv $(TARGET).new $(TARGET))

offset.h: offset.s
	sed -n '/^@@@/s///p' $^ >$@

offset.s: offset.c

include $(TOPDIR)/Rules.make
