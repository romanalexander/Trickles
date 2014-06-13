# 
# Copyright (C) 2000 Jeff Dike (jdike@karaya.com)
# Licensed under the GPL
#

O_TARGET := built-in.o

subdir-y =
subdir-m =

subdir-$(CONFIG_HOSTFS) += hostfs
subdir-$(CONFIG_HPPFS) += hppfs

obj-y += $(join $(subdir-y),$(subdir-y:%=/%.o))
obj-m += $(join $(subdir-m),$(subdir-m:%=/%.o))

include $(TOPDIR)/Rules.make

dep:

clean:

archmrproper:
