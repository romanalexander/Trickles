# 
# Copyright (C) 2002 Jeff Dike (jdike@karaya.com)
# Licensed under the GPL
#

OS := $(shell uname -s)

ARCH_DIR = arch/um

core-y := kernel sys-$(SUBARCH) os-$(OS)
drivers-y := fs drivers
subdir-y := $(core-y) $(drivers-y)
SUBDIRS += $(foreach dir,$(subdir-y),$(ARCH_DIR)/$(dir))

CORE_FILES += $(foreach dir,$(core-y),$(ARCH_DIR)/$(dir)/built-in.o)
DRIVERS += $(foreach dir,$(drivers-y),$(ARCH_DIR)/$(dir)/built-in.o)

include $(ARCH_DIR)/Makefile-$(SUBARCH)
include $(ARCH_DIR)/Makefile-os-$(OS)

MAKEFILE-$(CONFIG_MODE_TT) += Makefile-tt
MAKEFILE-$(CONFIG_MODE_SKAS) += Makefile-skas

ifneq ($(MAKEFILE-y),)
  include $(addprefix $(ARCH_DIR)/,$(MAKEFILE-y))
endif

EXTRAVERSION := $(EXTRAVERSION)-3um

include/linux/version.h: arch/$(ARCH)/Makefile

# Recalculate MODLIB to reflect the EXTRAVERSION changes (via KERNELRELEASE)
# The way the toplevel Makefile is written EXTRAVERSION is not supposed
# to be changed outside the toplevel Makefile, but recalculating MODLIB is
# a sufficient workaround until we no longer need architecture dependent
# EXTRAVERSION...
MODLIB := $(INSTALL_MOD_PATH)/lib/modules/$(KERNELRELEASE)

ifeq ($(CONFIG_DEBUGSYM),y)
CFLAGS := $(subst -fomit-frame-pointer,,$(CFLAGS))
endif

CFLAGS-$(CONFIG_DEBUGSYM) += -g

ARCH_INCLUDE = -I$(TOPDIR)/$(ARCH_DIR)/include

# -Derrno=kernel_errno - This turns all kernel references to errno into
# kernel_errno to separate them from the libc errno.  This allows -fno-common
# in CFLAGS.  Otherwise, it would cause ld to complain about the two different
# errnos.

CFLAGS += $(ARCH_CFLAGS) $(CFLAGS-y) -D__arch_um__ -DSUBARCH=\"$(SUBARCH)\" \
	-D_LARGEFILE64_SOURCE $(ARCH_INCLUDE) -Derrno=kernel_errno \
	$(MODE_INCLUDE)

check_gcc = $(shell if $(CC) $(1) -S -o /dev/null -xc /dev/null > /dev/null 2>&1; then echo "$(1)"; else echo "$(2)"; fi)

CFLAGS += $(call check_gcc,-fno-unit-at-a-time,)

LINKFLAGS += -r

LINK_WRAPS = -Wl,--wrap,malloc -Wl,--wrap,free -Wl,--wrap,calloc

# These are needed for clean and mrproper, since in that case .config is not
# included; the values here are meaningless

CONFIG_NEST_LEVEL ?= 0
CONFIG_KERNEL_HALF_GIGS ?= 0

SIZE = (($(CONFIG_NEST_LEVEL) + $(CONFIG_KERNEL_HALF_GIGS)) * 0x20000000)

# These aren't in Makefile-tt because they are needed in the !CONFIG_MODE_TT +
# CONFIG_MODE_SKAS + CONFIG_STATIC_LINK case.

LINK_TT = -static
LD_SCRIPT_TT := link.ld

ifeq ($(CONFIG_STATIC_LINK),y)
  LINK-y += $(LINK_TT)
  LD_SCRIPT-y := $(LD_SCRIPT_TT)
else
ifeq ($(CONFIG_MODE_TT),y)
  LINK-y += $(LINK_TT)
  LD_SCRIPT-y := $(LD_SCRIPT_TT)
else
ifeq ($(CONFIG_MODE_SKAS),y)
  LINK-y += $(LINK_SKAS)
  LD_SCRIPT-y := $(LD_SCRIPT_SKAS)
endif
endif
endif

LD_SCRIPT-y := $(ARCH_DIR)/$(LD_SCRIPT-y)
M4_MODE_TT := $(shell [ "$(CONFIG_MODE_TT)" = "y" ] && echo -DMODE_TT)

ifndef START
  START = $$(($(TOP_ADDR) - $(SIZE)))
endif

$(LD_SCRIPT-y): $(LD_SCRIPT-y).in
	pages=$$(( 1 << $(CONFIG_KERNEL_STACK_ORDER) )) ; \
	m4 -DSTART=$(START) -DELF_ARCH=$(ELF_ARCH) \
		-DELF_FORMAT=$(ELF_FORMAT) $(M4_MODE_TT) \
		-DKERNEL_STACK_SIZE=$$(( 4096 * $$pages )) $< > $@

SYMLINK_HEADERS = archparam.h system.h sigcontext.h processor.h ptrace.h \
	arch-signal.h
SYMLINK_HEADERS := $(foreach header,$(SYMLINK_HEADERS),include/asm-um/$(header))

ARCH_SYMLINKS = include/asm-um/arch arch/um/include/sysdep arch/um/os \
	$(SYMLINK_HEADERS) $(ARCH_DIR)/include/uml-config.h

ifeq ($(CONFIG_MODE_SKAS), y)
$(SYS_HEADERS) : $(ARCH_DIR)/kernel/skas/include/skas_ptregs.h
endif

GEN_HEADERS += $(ARCH_DIR)/include/task.h $(ARCH_DIR)/include/kern_constants.h 

setup: $(ARCH_SYMLINKS) $(SYS_HEADERS) $(GEN_HEADERS) 

linux: setup $(ARCH_DIR)/main.o vmlinux $(LD_SCRIPT-y)
	mv vmlinux vmlinux.o
	$(CC) -Wl,-T,$(LD_SCRIPT-y) $(LINK-y) $(LINK_WRAPS) \
		-o linux $(ARCH_DIR)/main.o vmlinux.o -L/usr/lib -lutil

USER_CFLAGS := $(patsubst -I%,,$(CFLAGS))
USER_CFLAGS := $(patsubst -Derrno=kernel_errno,,$(USER_CFLAGS))
USER_CFLAGS := $(patsubst -D__KERNEL__,,$(USER_CFLAGS)) $(ARCH_INCLUDE) \
	$(MODE_INCLUDE)

# To get a definition of F_SETSIG
USER_CFLAGS += -D_GNU_SOURCE

CLEAN_FILES += linux x.i gmon.out $(ARCH_DIR)/link.ld $(ARCH_DIR)/dyn_link.ld \
	$(GEN_HEADERS) 
# $(ARCH_DIR)/include/uml-config.h removed temporarily because this causes
# make to fail after make clean

$(ARCH_DIR)/main.o: $(ARCH_DIR)/main.c
	$(CC) $(USER_CFLAGS) $(EXTRA_CFLAGS) -c -o $@ $<

archmrproper:
	rm -f $(SYMLINK_HEADERS) $(ARCH_SYMLINKS) include/asm \
		$(LD_SCRIPT) $(addprefix $(ARCH_DIR)/kernel/,$(KERN_SYMLINKS))

archclean: sysclean
	find . \( -name '*.bb' -o -name '*.bbg' -o -name '*.da' \
		-o -name '*.gcov' \) -type f -print | xargs rm -f
	cd $(ARCH_DIR) ; \
	for dir in $(subdir-y) util ; do $(MAKE) -C $$dir clean; done

archdep: 

$(SYMLINK_HEADERS):
	cd $(TOPDIR)/$(dir $@) ; \
	ln -sf $(basename $(notdir $@))-$(SUBARCH)$(suffix $@) $(notdir $@)

include/asm-um/arch:
	cd $(TOPDIR)/include/asm-um && ln -sf ../asm-$(SUBARCH) arch

arch/um/include/sysdep:
	cd $(TOPDIR)/arch/um/include && ln -sf sysdep-$(SUBARCH) sysdep

arch/um/os:
	cd $(ARCH_DIR) && ln -sf os-$(OS) os

$(ARCH_DIR)/include/task.h : $(ARCH_DIR)/util/mk_task
	$< > $@

$(ARCH_DIR)/include/kern_constants.h : $(ARCH_DIR)/util/mk_constants
	$< > $@

$(ARCH_DIR)/include/uml-config.h : $(TOPDIR)/include/linux/autoconf.h
	sed 's/ CONFIG/ UML_CONFIG/' $(TOPDIR)/include/linux/autoconf.h > $@

$(ARCH_DIR)/util/mk_task : $(ARCH_DIR)/util/mk_task_user.c \
	$(ARCH_DIR)/util/mk_task_kern.c $(SYS_HEADERS)
	$(MAKE) $(MFLAGS) -C $(ARCH_DIR)/util mk_task

$(ARCH_DIR)/util/mk_constants : $(ARCH_DIR)/util/mk_constants_user.c \
	$(ARCH_DIR)/util/mk_constants_kern.c 
	$(MAKE) $(MFLAGS) -C $(ARCH_DIR)/util mk_constants

export SUBARCH USER_CFLAGS OS

all: linux

define archhelp
  echo  '* linux	- Binary kernel image (./linux)'
endef
