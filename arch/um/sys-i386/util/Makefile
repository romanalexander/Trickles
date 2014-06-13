EXE = mk_sc mk_thread

include $(TOPDIR)/Rules.make

all : $(EXE)

mk_sc : mk_sc.o
	$(HOSTCC) -o mk_sc mk_sc.o

mk_sc.o : mk_sc.c
	$(HOSTCC) -c $< 

mk_thread : mk_thread_user.o mk_thread_kern.o
	$(HOSTCC) -o mk_thread mk_thread_user.o mk_thread_kern.o

mk_thread_user.o : mk_thread_user.c
	$(HOSTCC) -c $< 

mk_thread_kern.o : mk_thread_kern.c
	$(HOSTCC) $(CFLAGS) -c $< 

clean :
	$(RM) $(EXE) *.o

archmrproper : clean

fastdep :

