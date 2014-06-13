/* 
 * Copyright (C) 2001 Jeff Dike (jdike@karaya.com)
 * Licensed under the GPL
 */

#ifndef __2_5_COMPAT_H__
#define __2_5_COMPAT_H__

#include "linux/version.h"

#define INIT_ELV(queue, elv) elevator_init(elv, ELV_NOOP)

#define ELV_NOOP ELEVATOR_NOOP

#define INIT_HARDSECT(arr, maj, sizes) arr[maj] = sizes

#define IS_WRITE(req) ((req)->cmd == WRITE)

#define SET_PRI(task) \
	do { (task)->nice = 20; (task)->counter = -100; } while(0);

#endif

/*
 * Overrides for Emacs so that we follow Linus's tabbing style.
 * Emacs will notice this stuff at the end of the file and automatically
 * adjust the settings for this buffer only.  This must remain at the end
 * of the file.
 * ---------------------------------------------------------------------------
 * Local variables:
 * c-file-style: "linux"
 * End:
 */
