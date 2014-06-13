# 
# Copyright (C) 2000, 2002, 2003 Jeff Dike (jdike@karaya.com)
# Licensed under the GPL
#

O_TARGET := built-in.o 

CHAN_OBJS := chan_kern.o chan_user.o line.o 

list-multi := slip.o slirp.o daemon.o mcast.o udp.o mconsole.o net.o ubd.o \
	hostaudio.o pcap.o port.o harddog.o

slip-objs := slip_kern.o slip_user.o
slirp-objs := slirp_kern.o slirp_user.o
daemon-objs := daemon_kern.o daemon_user.o
mcast-objs := mcast_kern.o mcast_user.o
udp-objs := udp_kern.o udp_user.o
pcap-objs := pcap_kern.o pcap_user.o
pcap-libs := -lpcap -L/usr/lib
net-objs := net_kern.o net_user.o
mconsole-objs := mconsole_kern.o mconsole_user.o
hostaudio-objs := hostaudio_kern.o
ubd-objs := ubd_kern.o ubd_user.o
port-objs := port_kern.o port_user.o
harddog-objs := harddog_kern.o harddog_user.o

export-objs := mconsole_kern.o

obj-y = 
obj-$(CONFIG_SSL) += ssl.o 
obj-$(CONFIG_UML_NET_SLIP) += slip.o
obj-$(CONFIG_UML_NET_SLIRP) += slirp.o
obj-$(CONFIG_UML_NET_DAEMON) += daemon.o 
obj-$(CONFIG_UML_NET_MCAST) += mcast.o 
obj-$(CONFIG_UML_NET_UDP) += udp.o 
obj-$(CONFIG_UML_NET_PCAP) += pcap.o 
obj-$(CONFIG_UML_NET) += net.o 
obj-$(CONFIG_MCONSOLE) += mconsole.o
obj-$(CONFIG_MMAPPER) += mmapper_kern.o 
obj-$(CONFIG_BLK_DEV_UBD) += ubd.o 
obj-$(CONFIG_HOSTAUDIO) += hostaudio.o
obj-$(CONFIG_FD_CHAN) += fd.o 
obj-$(CONFIG_NULL_CHAN) += null.o 
obj-$(CONFIG_PORT_CHAN) += port.o
obj-$(CONFIG_PTY_CHAN) += pty.o
obj-$(CONFIG_TTY_CHAN) += tty.o 
obj-$(CONFIG_XTERM_CHAN) += xterm.o xterm_kern.o
obj-$(CONFIG_UML_WATCHDOG) += harddog.o
obj-$(CONFIG_COW) += cow_kern.o
obj-$(CONFIG_COW_COMMON) += cow_user.o

CFLAGS_pcap_user.o = -I/usr/include/pcap

obj-y += stdio_console.o $(CHAN_OBJS)

USER_SINGLE_OBJS = $(foreach f,$(patsubst %.o,%,$(obj-y) $(obj-m)),$($(f)-objs))

USER_OBJS = $(filter %_user.o,$(obj-y) $(obj-m) $(USER_SINGLE_OBJS)) fd.o \
	null.o pty.o tty.o xterm.o

include $(TOPDIR)/Rules.make

$(USER_OBJS) : %.o: %.c
	$(CC) $(CFLAGS_$@) $(USER_CFLAGS) -c -o $@ $<

clean:

modules:

fastdep:

dep:

archmrproper:

daemon.o : $(daemon-objs)

slip.o : $(slip-objs)

slirp.o : $(slirp-objs)

mcast.o : $(mcast-objs)

udp.o : $(udp-objs)

pcap.o : $(pcap-objs)

mconsole.o : $(mconsole-objs)

net.o : $(net-objs)

hostaudio.o : $(hostaudio-objs)

ubd.o : $(ubd-objs)

port.o : $(port-objs)

harddog.o : $(harddog-objs)

$(list-multi) : # This doesn't work, but should : '%.o : $(%-objs)'
	$(LD) -r -o $@ $($(patsubst %.o,%,$@)-objs) $($(patsubst %.o,%,$@)-libs)
