#
# Makefile for the Linux TCP/IP (INET) layer.
#
# Note! Dependencies are done automagically by 'make dep', which also
# removes any old dependencies. DON'T put your own dependencies here
# unless it's something special (ie not a .c file).
#
# Note 2! The CFLAGS definition is now in the main makefile...

HMAC_CFLAGS := -DOPENSSL_HMAC -mcpu=pentiumpro -DMD5_ASM # -O0 
#EXTRA_CFLAGS := $(HMAC_CFLAGS)
#EXTRA_CFLAGS :=  -fno-inline -ggdb3 $(HMAC_CFLAGS) #-O0 
EXTRA_CFLAGS :=  -ggdb3 $(HMAC_CFLAGS) #-O0 

#O_TARGET := crypto.o

# Gladman's HMAC
#TRICKLES_MOD_DEPS=trickles.o sha1.o hmac.o aescrypt.o aeskey.o aestab.o

# OpenSSL HMAC
#sha1_one.o sha1dgst.o sx86-elf.o 

OBJS := aescrypt.o aeskey.o aestab.o md5_one.o md5_dgst.o mx86-elf.o
#obj-$(CONFIG_STCP) += $(OBJS) crypto.o
#obj-m += aescrypt.o aeskey.o aestab.o md5_one.o md5_dgst.o mx86-elf.o 

include $(TOPDIR)/Rules.make

modules: crypto.o

sx86-elf.o: sx86unix.cpp
	$(CPP) -DELF -x c sx86unix.cpp | as -o sx86-elf.o

mx86-elf.o: mx86unix.cpp
	$(CPP) -DELF -x c mx86unix.cpp | as -o mx86-elf.o

#aescrypt.o: aescrypt.asm
#	nasm -f elf -O2 -o $@ $^
aescrypt.o: aescrypt.asm
	nasm -f elf -O2 -o $@ aescrypt.asm

hmac.o: hmac.c
	icc $(CFLAGS) $(HMAC_CFLAGS) -c -o $@ $^

sha1.o: sha1.c
	icc $(CFLAGS) $(HMAC_CFLAGS) -c -o $@ $^

crypto.o:  $(OBJS)
	$(LD)  --relocatable $(OBJS) -o $@ 

