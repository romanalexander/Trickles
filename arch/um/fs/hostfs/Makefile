# 
# Copyright (C) 2000 - 2004 Jeff Dike (jdike@addtoit.com)
# Licensed under the GPL
#

O_TARGET := hostfs.o

obj-$(CONFIG_EXTERNFS) += externfs.o
obj-$(CONFIG_HOSTFS) += host_fs.o host_file.o
obj-$(CONFIG_HUMFS) += humfs.o host_file.o meta_fs.o

obj-m = $(O_TARGET)

include $(TOPDIR)/Rules.make
