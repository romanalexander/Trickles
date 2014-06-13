O_TARGET := hppfs.o
obj-y = hppfs_kern.o #hppfs_user.o
obj-m = $(O_TARGET)

CFLAGS_hppfs_kern.o := $(CFLAGS)
#CFLAGS_hppfs_user.o := $(USER_CFLAGS)

override CFLAGS =  

include $(TOPDIR)/Rules.make
