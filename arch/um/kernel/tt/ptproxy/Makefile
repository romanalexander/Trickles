O_TARGET = ptproxy.o

obj-y = proxy.o ptrace.o sysdep.o wait.o

USER_OBJS = $(obj-y)

include $(TOPDIR)/Rules.make

$(USER_OBJS) : %.o: %.c
	$(CC) $(CFLAGS_$@) $(USER_CFLAGS) -c -o $@ $<

clean:
