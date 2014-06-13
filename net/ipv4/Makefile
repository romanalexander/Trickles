#
# Makefile for the Linux TCP/IP (INET) layer.
#
# Note! Dependencies are done automagically by 'make dep', which also
# removes any old dependencies. DON'T put your own dependencies here
# unless it's something special (ie not a .c file).
#
# Note 2! The CFLAGS definition is now in the main makefile...

#DEBUG=0

HMAC_CFLAGS := -DOPENSSL_HMAC -mcpu=pentiumpro # -O0
#EXTRA_CFLAGS := $(HMAC_CFLAGS)

ifdef DEBUG
EXTRA_CFLAGS :=  -fno-inline -ggdb3 $(HMAC_CFLAGS) -O0
DBGLIB := /local/ashieh/lib
EXTRA_LDFLAGS := $(DBGLIB)/htonl.o $(DBGLIB)/htons.o
else
EXTRA_CFLAGS := -ggdb3 $(HMAC_CFLAGS) #-fno-inline
endif

subdir-$(CONFIG_TRICKLES) := crypto

O_TARGET := ipv4.o

TRICKLES_MOD := trickles-mod.o

export-objs = ipip.o ip_gre.o

obj-y     := utils.o route.o inetpeer.o proc.o protocol.o \
	     ip_input.o ip_fragment.o ip_forward.o ip_options.o \
	     ip_output.o ip_sockglue.o \
	     tcp.o tcp_input.o tcp_output.o tcp_timer.o tcp_ipv4.o tcp_minisocks.o \
	     tcp_diag.o raw.o udp.o arp.o icmp.o devinet.o af_inet.o igmp.o \
	     sysctl_net_ipv4.o fib_frontend.o fib_semantics.o fib_hash.o trickles_shared.o

obj-$(CONFIG_IP_MULTIPLE_TABLES) += fib_rules.o
obj-$(CONFIG_IP_ROUTE_NAT) += ip_nat_dumb.o
obj-$(CONFIG_IP_MROUTE) += ipmr.o
obj-$(CONFIG_NET_IPIP) += ipip.o
obj-$(CONFIG_NET_IPGRE) += ip_gre.o
obj-$(CONFIG_SYN_COOKIES) += syncookies.o
obj-$(CONFIG_IP_PNP) += ipconfig.o
obj-$(CONFIG_TRICKLES) += $(TRICKLES_MOD) #trickles.o tmalloc.o trickles-server.o trickles-userapi.o


#.PHONY: crypto

TRICKLES_MOD_DEPS := trickles.o tmalloc.o trickles-server.o trickles-userapi.o crypto/crypto.o state_cache.o trickles-conversion.o msk_table.o
TRICKLES_LIBS := /local/ashieh/lib/htonl.o /local/ashieh/lib/htons.o /usr/lib/gcc-lib/i386-redhat-linux/3.2.3/libgcc.a /usr/lib/libm.a  #libintel.a  #/opt/intel_cc_80/lib/libirc.a

include $(TOPDIR)/Rules.make

## XXX build mechanism is a hack
crypto/crypto.o: crypto
	make -C crypto modules

$(TRICKLES_MOD): $(TRICKLES_MOD_DEPS)
	$(LD)  --relocatable $(TRICKLES_LIBS) $(TRICKLES_MOD_DEPS) -o $@

