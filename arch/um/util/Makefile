ALL = mk_task mk_constants

all : $(ALL)

mk_task : mk_task_user.o mk_task_kern.o
	$(HOSTCC) -o mk_task mk_task_user.o mk_task_kern.o

mk_task_user.o : mk_task_user.c
	$(HOSTCC) -c $< 

mk_task_kern.o : mk_task_kern.c
	$(HOSTCC) $(CFLAGS) -c $< 

mk_constants : mk_constants_user.o mk_constants_kern.o
	$(HOSTCC) -o mk_constants mk_constants_user.o mk_constants_kern.o

mk_constants_user.o : mk_constants_user.c
	$(HOSTCC) -c $< 

mk_constants_kern.o : mk_constants_kern.c
	$(HOSTCC) $(CFLAGS) -c $< 

clean :
	$(RM) $(ALL) *.o *~

archmrproper : clean
