#ifndef _HOSTFS_FS_I
#define _HOSTFS_FS_I

#ifdef CONFIG_USERMODE
#include "filehandle.h"

struct externfs_file_ops;

struct hostfs_inode_info {
	struct externfs_file_ops *ops;
	struct file_handle *fh;
	int mode;
};

#else

struct hostfs_inode_info {
};

#endif

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
