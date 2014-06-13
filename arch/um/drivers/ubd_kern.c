/* 
 * Copyright (C) 2000 Jeff Dike (jdike@karaya.com)
 * Licensed under the GPL
 */

/* 2001-09-28...2002-04-17
 * Partition stuff by James_McMechan@hotmail.com
 * old style ubd by setting UBD_SHIFT to 0
 */

#define MAJOR_NR UBD_MAJOR
#define UBD_SHIFT 4

#include "linux/config.h"
#include "linux/blk.h"
#include "linux/blkdev.h"
#include "linux/hdreg.h"
#include "linux/init.h"
#include "linux/devfs_fs_kernel.h"
#include "linux/cdrom.h"
#include "linux/proc_fs.h"
#include "linux/ctype.h"
#include "linux/capability.h"
#include "linux/mm.h"
#include "linux/vmalloc.h"
#include "linux/blkpg.h"
#include "linux/genhd.h"
#include "linux/spinlock.h"
#include "asm/segment.h"
#include "asm/uaccess.h"
#include "asm/irq.h"
#include "asm/types.h"
#include "user_util.h"
#include "mem_user.h"
#include "kern_util.h"
#include "kern.h"
#include "mconsole_kern.h"
#include "init.h"
#include "irq_user.h"
#include "irq_kern.h"
#include "ubd_user.h"
#include "2_5compat.h"
#include "os.h"
#include "mem.h"
#include "mem_kern.h"

static int ubd_open(struct inode * inode, struct file * filp);
static int ubd_release(struct inode * inode, struct file * file);
static int ubd_ioctl(struct inode * inode, struct file * file,
		     unsigned int cmd, unsigned long arg);
static int ubd_revalidate(kdev_t rdev);
static int ubd_revalidate1(kdev_t rdev);

#define MAX_DEV (8)
#define MAX_MINOR (MAX_DEV << UBD_SHIFT)

/* Changed in early boot */
static int ubd_do_mmap = 0;
#define UBD_MMAP_BLOCK_SIZE PAGE_SIZE

/* Not modified by this driver */
static int blk_sizes[MAX_MINOR] = { [ 0 ... MAX_MINOR - 1 ] = BLOCK_SIZE };
static int hardsect_sizes[MAX_MINOR] = { [ 0 ... MAX_MINOR - 1 ] = 512 };

/* Protected by ubd_lock */
static int sizes[MAX_MINOR] = { [ 0 ... MAX_MINOR - 1 ] = 0 };

static struct block_device_operations ubd_blops = {
        .open		= ubd_open,
        .release	= ubd_release,
        .ioctl		= ubd_ioctl,
        .revalidate	= ubd_revalidate,
};

/* Protected by ubd_lock, except in prepare_request and ubd_ioctl because 
 * the block layer should ensure that the device is idle before closing it.
 */
static struct hd_struct	ubd_part[MAX_MINOR] =
	{ [ 0 ... MAX_MINOR - 1 ] = { 0, 0, 0 } };

/* Protected by io_request_lock */
static request_queue_t *ubd_queue;

/* Protected by ubd_lock */
static int fake_major = MAJOR_NR;

static spinlock_t ubd_lock = SPIN_LOCK_UNLOCKED;

#define INIT_GENDISK(maj, name, parts, shift, bsizes, max, blops) \
{ \
	.major 		= maj, \
	.major_name  	= name, \
	.minor_shift 	= shift, \
	.max_p  	= 1 << shift, \
	.part  		= parts, \
	.sizes  	= bsizes, \
	.nr_real  	= max, \
	.real_devices  	= NULL, \
	.next  		= NULL, \
	.fops  		= blops, \
	.de_arr  	= NULL, \
	.flags  	= 0 \
}

static struct gendisk ubd_gendisk = INIT_GENDISK(MAJOR_NR, "ubd", ubd_part,
						 UBD_SHIFT, sizes, MAX_DEV, 
						 &ubd_blops);
static struct gendisk fake_gendisk = INIT_GENDISK(0, "ubd", ubd_part, 
						  UBD_SHIFT, sizes, MAX_DEV, 
						  &ubd_blops);

#ifdef CONFIG_BLK_DEV_UBD_SYNC
#define OPEN_FLAGS ((struct openflags) { .r = 1, .w = 1, .s = 1, .c = 0, \
					 .cl = 1 })
#else
#define OPEN_FLAGS ((struct openflags) { .r = 1, .w = 1, .s = 0, .c = 0, \
					 .cl = 1 })
#endif

/* Not protected - changed only in ubd_setup_common and then only to
 * to enable O_SYNC.
 */
static struct openflags global_openflags = OPEN_FLAGS;

struct cow {
	char *file;
	int fd;
	unsigned long *bitmap;
	unsigned long bitmap_len;
	int bitmap_offset;
        int data_offset;
};

struct ubd {
	char *file;
	int count;
	int fd;
	__u64 size;
	struct openflags boot_openflags;
	struct openflags openflags;
	devfs_handle_t devfs;
	int no_cow;
	struct cow cow;

	int map_writes;
	int map_reads;
	int nomap_writes;
	int nomap_reads;
	int write_maps;
};

#define DEFAULT_COW { \
	.file			= NULL, \
        .fd			= -1, \
        .bitmap			= NULL, \
	.bitmap_offset		= 0, \
        .data_offset		= 0, \
}

#define DEFAULT_UBD { \
	.file 			= NULL, \
	.count			= 0, \
	.fd			= -1, \
	.size			= -1, \
	.boot_openflags		= OPEN_FLAGS, \
	.openflags		= OPEN_FLAGS, \
	.devfs			= NULL, \
	.no_cow			= 0, \
        .cow			= DEFAULT_COW, \
	.map_writes		= 0, \
	.map_reads		= 0, \
	.nomap_writes		= 0, \
	.nomap_reads		= 0, \
	.write_maps		= 0, \
}

struct ubd ubd_dev[MAX_DEV] = { [ 0 ... MAX_DEV - 1 ] = DEFAULT_UBD };

static int ubd0_init(void)
{
	struct ubd *dev = &ubd_dev[0];

	if(dev->file == NULL)
		dev->file = "root_fs";
	return(0);
}

__initcall(ubd0_init);

/* Only changed by fake_ide_setup which is a setup */
static int fake_ide = 0;
static struct proc_dir_entry *proc_ide_root = NULL;
static struct proc_dir_entry *proc_ide = NULL;

static void make_proc_ide(void)
{
	proc_ide_root = proc_mkdir("ide", 0);
	proc_ide = proc_mkdir("ide0", proc_ide_root);
}

static int proc_ide_read_media(char *page, char **start, off_t off, int count,
			       int *eof, void *data)
{
	int len;

	strcpy(page, "disk\n");
	len = strlen("disk\n");
	len -= off;
	if (len < count){
		*eof = 1;
		if (len <= 0) return 0;
	}
	else len = count;
	*start = page + off;
	return len;
}

static void make_ide_entries(char *dev_name)
{
	struct proc_dir_entry *dir, *ent;
	char name[64];

	if(!fake_ide) return;

	/* Without locking this could race if a UML was booted with no 
	 * disks and then two mconsole requests which add disks came in 
	 * at the same time.
	 */
	spin_lock(&ubd_lock);
	if(proc_ide_root == NULL) make_proc_ide();
	spin_unlock(&ubd_lock);

	dir = proc_mkdir(dev_name, proc_ide);
	if(!dir) return;

	ent = create_proc_entry("media", S_IFREG|S_IRUGO, dir);
	if(!ent) return;
	ent->nlink = 1;
	ent->data = NULL;
	ent->read_proc = proc_ide_read_media;
	ent->write_proc = NULL;
	sprintf(name,"ide0/%s", dev_name);
	proc_symlink(dev_name, proc_ide_root, name);
}

static int fake_ide_setup(char *str)
{
	fake_ide = 1;
	return(1);
}

__setup("fake_ide", fake_ide_setup);

__uml_help(fake_ide_setup,
"fake_ide\n"
"    Create ide0 entries that map onto ubd devices.\n\n"
);

static int parse_unit(char **ptr)
{
	char *str = *ptr, *end;
	int n = -1;

	if(isdigit(*str)) {
		n = simple_strtoul(str, &end, 0);
		if(end == str)
			return(-1);
		*ptr = end;
	}
	else if (('a' <= *str) && (*str <= 'h')) {
		n = *str - 'a';
		str++;
		*ptr = str;
	}
	return(n);
}

static int ubd_setup_common(char *str, int *index_out)
{
	struct openflags flags = global_openflags;
	struct ubd *dev;
	char *backing_file;
	int n, err;

	if(index_out) *index_out = -1;
	n = *str;
	if(n == '='){
		char *end;
		int major;

		str++;
		if(!strcmp(str, "mmap")){
			CHOOSE_MODE(printk("mmap not supported by the ubd "
					   "driver in tt mode\n"),
				    ubd_do_mmap = 1);
			return(0);
		}

		if(!strcmp(str, "sync")){
			global_openflags.s = 1;
			return(0);
		}
		major = simple_strtoul(str, &end, 0);
		if((*end != '\0') || (end == str)){
			printk(KERN_ERR 
			       "ubd_setup : didn't parse major number\n");
			return(1);
		}

		err = 1;
		spin_lock(&ubd_lock);
		if(fake_major != MAJOR_NR){
			printk(KERN_ERR "Can't assign a fake major twice\n");
			goto out1;
		}

		fake_gendisk.major = major;
		fake_major = major;
	
		printk(KERN_INFO "Setting extra ubd major number to %d\n",
		       major);
		err = 0;
	out1:
		spin_unlock(&ubd_lock);
		return(err);
	}

	n = parse_unit(&str);
	if(n < 0){
		printk(KERN_ERR "ubd_setup : couldn't parse unit number "
		       "'%s'\n", str);
		return(1);
	}

	if(n >= MAX_DEV){
		printk(KERN_ERR "ubd_setup : index %d out of range "
		       "(%d devices)\n", n, MAX_DEV);	
		return(1);
	}

	err = 1;
	spin_lock(&ubd_lock);

	dev = &ubd_dev[n];
	if(dev->file != NULL){
		printk(KERN_ERR "ubd_setup : device already configured\n");
		goto out2;
	}

	if(index_out) *index_out = n;

	if(*str == 'r'){
		flags.w = 0;
		str++;
	}
	if(*str == 's'){
		flags.s = 1;
		str++;
	}
	if(*str == 'd'){
		dev->no_cow = 1;
		str++;
	}

	if(*str++ != '='){
		printk(KERN_ERR "ubd_setup : Expected '='\n");
		goto out2;
	}

	err = 0;
	backing_file = strchr(str, ',');
	if(backing_file){
		if(dev->no_cow)
			printk(KERN_ERR "Can't specify both 'd' and a "
			       "cow file\n");
		else {
			*backing_file = '\0';
			backing_file++;
		}
	}
	dev->file = str;
	dev->cow.file = backing_file;
	dev->boot_openflags = flags;
 out2:
	spin_unlock(&ubd_lock);
	return(err);
}

static int ubd_setup(char *str)
{
	ubd_setup_common(str, NULL);
	return(1);
}

__setup("ubd", ubd_setup);
__uml_help(ubd_setup,
"ubd<n>=<filename>\n"
"    This is used to associate a device with a file in the underlying\n"
"    filesystem. Usually, there is a filesystem in the file, but \n"
"    that's not required. Swap devices containing swap files can be\n"
"    specified like this. Also, a file which doesn't contain a\n"
"    filesystem can have its contents read in the virtual \n"
"    machine by running dd on the device. n must be in the range\n"
"    0 to 7. Appending an 'r' to the number will cause that device\n"
"    to be mounted read-only. For example ubd1r=./ext_fs. Appending\n"
"    an 's' (has to be _after_ 'r', if there is one) will cause data\n"
"    to be written to disk on the host immediately.\n\n"
);

static int fakehd(char *str)
{
	printk(KERN_INFO 
	       "fakehd : Changing ubd_gendisk.major_name to \"hd\".\n");
	ubd_gendisk.major_name = "hd";
	return(1);
}

__setup("fakehd", fakehd);
__uml_help(fakehd,
"fakehd\n"
"    Change the ubd device name to \"hd\".\n\n"
);

static void do_ubd_request(request_queue_t * q);

/* Only changed by ubd_init, which is an initcall. */
int thread_fd = -1;

/* Changed by ubd_handler, which is serialized because interrupts only
 * happen on CPU 0.
 */
int intr_count = 0;

static void ubd_finish(int error)
{
	int nsect;

	if(error){
		end_request(0);
		return;
	}
	nsect = CURRENT->current_nr_sectors;
	CURRENT->sector += nsect;
	CURRENT->buffer += nsect << 9;
	CURRENT->errors = 0;
	CURRENT->nr_sectors -= nsect;
	CURRENT->current_nr_sectors = 0;
	end_request(1);
}

static void ubd_handler(void)
{
	struct io_thread_req req;
	int n, err;

	DEVICE_INTR = NULL;
	intr_count++;
	n = read_ubd_fs(thread_fd, &req, sizeof(req));
	if(n != sizeof(req)){
		printk(KERN_ERR "Pid %d - spurious interrupt in ubd_handler, "
		       "err = %d\n", os_getpid(), -n);
		spin_lock(&io_request_lock);
		end_request(0);
		spin_unlock(&io_request_lock);
		return;
	}
        
        if((req.op != UBD_MMAP) && 
	   ((req.offset != ((__u64) (CURRENT->sector)) << 9) ||
	    (req.length != (CURRENT->current_nr_sectors) << 9)))
		panic("I/O op mismatch");

	if(req.map_fd != -1){
		err = physmem_subst_mapping(req.buffer, req.map_fd, 
					    req.map_offset, 1);
		if(err)
			printk("ubd_handler - physmem_subst_mapping failed, "
			       "err = %d\n", -err);
	}

	spin_lock(&io_request_lock);
	ubd_finish(req.error);
	reactivate_fd(thread_fd, UBD_IRQ);	
	do_ubd_request(ubd_queue);
	spin_unlock(&io_request_lock);
}

static void ubd_intr(int irq, void *dev, struct pt_regs *unused)
{
	ubd_handler();
}

/* Only changed by ubd_init, which is an initcall. */
static int io_pid = -1;

void kill_io_thread(void)
{
	if(io_pid != -1)
		os_kill_process(io_pid, 1);
}

__uml_exitcall(kill_io_thread);

/* Initialized in an initcall, and unchanged thereafter */
devfs_handle_t ubd_dir_handle;

static int ubd_add(int n)
{
	struct ubd *dev = &ubd_dev[n];
	char name[sizeof("nnnnnn\0")], dev_name[sizeof("ubd0x")];
	int err = -EISDIR;

	if(dev->file == NULL)
		goto out;

	err = ubd_revalidate1(MKDEV(MAJOR_NR, n << UBD_SHIFT));
	if(err)
		goto out;

	if(dev->cow.file == NULL)
		blk_sizes[n] = UBD_MMAP_BLOCK_SIZE;

	sprintf(name, "%d", n);
	dev->devfs = devfs_register(ubd_dir_handle, name, DEVFS_FL_REMOVABLE,
				    MAJOR_NR, n << UBD_SHIFT, S_IFBLK | 
				    S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP,
				    &ubd_blops, NULL);

#if 0 /* 2.5 ... */
	sprintf(disk->disk_name, "ubd%c", 'a' + unit);
#endif

	sprintf(dev_name, "%s%c", ubd_gendisk.major_name, 
		     n + 'a');

	make_ide_entries(dev_name);
	return(0);

 out:
	return(err);
}

static int ubd_config(char *str)
{
	int n, err;

	str = uml_strdup(str);
	if(str == NULL){
		printk(KERN_ERR "ubd_config failed to strdup string\n");
		return(1);
	}
	err = ubd_setup_common(str, &n);
	if(err){
		kfree(str);
		return(-1);
	}
	if(n == -1) return(0);

	spin_lock(&ubd_lock);
	err = ubd_add(n);
	if(err)
		ubd_dev[n].file = NULL;
	spin_unlock(&ubd_lock);

	return(err);
}

static int ubd_get_config(char *name, char *str, int size, char **error_out)
{
	struct ubd *dev;
	char *end;
	int n, len = 0;

	n = simple_strtoul(name, &end, 0);
	if((*end != '\0') || (end == name)){
		*error_out = "ubd_get_config : didn't parse device number";
		return(-1);
	}

	if((n >= MAX_DEV) || (n < 0)){
		*error_out = "ubd_get_config : device number out of range";
		return(-1);
	}

	dev = &ubd_dev[n];
	spin_lock(&ubd_lock);

	if(dev->file == NULL){
		CONFIG_CHUNK(str, size, len, "", 1);
		goto out;
	}

	CONFIG_CHUNK(str, size, len, dev->file, 0);

	if(dev->cow.file != NULL){
		CONFIG_CHUNK(str, size, len, ",", 0);
		CONFIG_CHUNK(str, size, len, dev->cow.file, 1);
	}
	else CONFIG_CHUNK(str, size, len, "", 1);

 out:
	spin_unlock(&ubd_lock);
	return(len);
}

static int ubd_remove(char *str)
{
	struct ubd *dev;
	int n, err = -ENODEV;

	if(isdigit(*str)){
		char *end;
		n = simple_strtoul(str, &end, 0);
		if ((*end != '\0') || (end == str)) 
			return(err);
	}
	else if (('a' <= *str) && (*str <= 'h'))
		n = *str - 'a';
	else
		return(err);	/* it should be a number 0-7/a-h */

	if((n < 0) || (n >= MAX_DEV))
		return(err);

	dev = &ubd_dev[n];

	spin_lock(&ubd_lock);
	err = 0;
	if(dev->file == NULL)
		goto out;
	err = -1;
	if(dev->count > 0)
		goto out;
	if(dev->devfs != NULL) 
		devfs_unregister(dev->devfs);

	*dev = ((struct ubd) DEFAULT_UBD);
	err = 0;
 out:
	spin_unlock(&ubd_lock);
	return(err);
}

static struct mc_device ubd_mc = {
	.name		= "ubd",
	.config		= ubd_config,
	.get_config	= ubd_get_config,
	.remove		= ubd_remove,
};

static int ubd_mc_init(void)
{
	mconsole_register_dev(&ubd_mc);
	return(0);
}

__initcall(ubd_mc_init);

static request_queue_t *ubd_get_queue(kdev_t device)
{
	return(ubd_queue);
}

int ubd_init(void)
{
	unsigned long stack;
        int i, err;

	ubd_dir_handle = devfs_mk_dir (NULL, "ubd", NULL);
	if (devfs_register_blkdev(MAJOR_NR, "ubd", &ubd_blops)) {
		printk(KERN_ERR "ubd: unable to get major %d\n", MAJOR_NR);
		return -1;
	}
	read_ahead[MAJOR_NR] = 8;		/* 8 sector (4kB) read-ahead */
	blksize_size[MAJOR_NR] = blk_sizes;
	blk_size[MAJOR_NR] = sizes;
	INIT_HARDSECT(hardsect_size, MAJOR_NR, hardsect_sizes);

	ubd_queue = BLK_DEFAULT_QUEUE(MAJOR_NR);
	blk_init_queue(ubd_queue, DEVICE_REQUEST);
	INIT_ELV(ubd_queue, &ubd_queue->elevator);

        add_gendisk(&ubd_gendisk);
	if (fake_major != MAJOR_NR){
		/* major number 0 is used to auto select */
		err = devfs_register_blkdev(fake_major, "fake", &ubd_blops);
		if(fake_major == 0){
		/* auto device number case */
			fake_major = err;
			if(err == 0)
				return(-ENODEV);
		} 
		else if (err){
			/* not auto so normal error */
			printk(KERN_ERR "ubd: error %d getting major %d\n", 
			       -err, fake_major);
			return(-ENODEV);
		}

		blk_dev[fake_major].queue = ubd_get_queue;
		read_ahead[fake_major] = 8;	/* 8 sector (4kB) read-ahead */
		blksize_size[fake_major] = blk_sizes;
		blk_size[fake_major] = sizes;
		INIT_HARDSECT(hardsect_size, fake_major, hardsect_sizes);
                add_gendisk(&fake_gendisk);
	}

	for(i=0;i<MAX_DEV;i++) 
		ubd_add(i);

	if(global_openflags.s){
		printk(KERN_INFO "ubd : Synchronous mode\n");
		return(0);
	}
	stack = alloc_stack(0, 0);
	io_pid = start_io_thread(stack + PAGE_SIZE - sizeof(void *), 
				 &thread_fd);
	if(io_pid < 0){
		io_pid = -1;
		printk(KERN_ERR 
		       "ubd : Failed to start I/O thread (errno = %d) - "
		       "falling back to synchronous I/O\n", -io_pid);
		return(0);
	}
	err = um_request_irq(UBD_IRQ, thread_fd, IRQ_READ, ubd_intr, 
			     SA_INTERRUPT, "ubd", ubd_dev);
	if(err != 0) 
		printk(KERN_ERR "um_request_irq failed - errno = %d\n", -err);
	return(err);
}

__initcall(ubd_init);

static void ubd_close(struct ubd *dev)
{
	if(ubd_do_mmap)
		physmem_forget_descriptor(dev->fd);
	os_close_file(dev->fd);
	if(dev->cow.file != NULL)
		return;

	if(ubd_do_mmap)
		physmem_forget_descriptor(dev->cow.fd);
	os_close_file(dev->cow.fd);
	vfree(dev->cow.bitmap);
	dev->cow.bitmap = NULL;
}

static int ubd_open_dev(struct ubd *dev)
{
	struct openflags flags;
	char **back_ptr;
	int err, create_cow, *create_ptr;

	dev->openflags = dev->boot_openflags;
	create_cow = 0;
	create_ptr = (dev->cow.file != NULL) ? &create_cow : NULL;
	back_ptr = dev->no_cow ? NULL : &dev->cow.file;
	dev->fd = open_ubd_file(dev->file, &dev->openflags, back_ptr,
				&dev->cow.bitmap_offset, &dev->cow.bitmap_len, 
				&dev->cow.data_offset, create_ptr);

	if((dev->fd == -ENOENT) && create_cow){
		dev->fd = create_cow_file(dev->file, dev->cow.file, 
					  dev->openflags, 1 << 9, PAGE_SIZE,
					  &dev->cow.bitmap_offset, 
					  &dev->cow.bitmap_len,
					  &dev->cow.data_offset);
		if(dev->fd >= 0){
			printk(KERN_INFO "Creating \"%s\" as COW file for "
			       "\"%s\"\n", dev->file, dev->cow.file);
		}
	}

	if(dev->fd < 0) return(dev->fd);

	if(dev->cow.file != NULL){
		err = -ENOMEM;
		dev->cow.bitmap = (void *) vmalloc(dev->cow.bitmap_len);
		if(dev->cow.bitmap == NULL){
			printk(KERN_ERR "Failed to vmalloc COW bitmap\n");
			goto error;
		}
		flush_tlb_kernel_vm();

		err = read_cow_bitmap(dev->fd, dev->cow.bitmap, 
				      dev->cow.bitmap_offset, 
				      dev->cow.bitmap_len);
		if(err < 0) 
			goto error;

		flags = dev->openflags;
		flags.w = 0;
		err = open_ubd_file(dev->cow.file, &flags, NULL, NULL, NULL, 
				    NULL, NULL);
		if(err < 0) goto error;
		dev->cow.fd = err;
	}
	return(0);
 error:
	os_close_file(dev->fd);
	return(err);
}

static int ubd_file_size(struct ubd *dev, __u64 *size_out)
{
	char *file;

	file = dev->cow.file ? dev->cow.file : dev->file;
	return(os_file_size(file, size_out));
}

static int ubd_open(struct inode *inode, struct file *filp)
{
	struct ubd *dev;
	int n, offset, err = 0;

	n = DEVICE_NR(inode->i_rdev);
	dev = &ubd_dev[n];
	if(n >= MAX_DEV)
		return -ENODEV;

	spin_lock(&ubd_lock);
	offset = n << UBD_SHIFT;

	if(dev->count == 0){
		err = ubd_open_dev(dev);
		if(err){
			printk(KERN_ERR "ubd%d: Can't open \"%s\": "
			       "errno = %d\n", n, dev->file, -err);
			goto out;
		}
		err = ubd_file_size(dev, &dev->size);
		if(err < 0)
			goto out;
		sizes[offset] = dev->size / BLOCK_SIZE;
		ubd_part[offset].nr_sects = dev->size / hardsect_sizes[offset];
	}
	dev->count++;
	if((filp->f_mode & FMODE_WRITE) && !dev->openflags.w){
	        if(--dev->count == 0) ubd_close(dev);
	        err = -EROFS;
	}
 out:
	spin_unlock(&ubd_lock);
	return(err);
}

static int ubd_release(struct inode * inode, struct file * file)
{
        int n, offset;

	n =  DEVICE_NR(inode->i_rdev);
	offset = n << UBD_SHIFT;
	if(n >= MAX_DEV)
		return -ENODEV;

	spin_lock(&ubd_lock);
	if(--ubd_dev[n].count == 0)
		ubd_close(&ubd_dev[n]);
	spin_unlock(&ubd_lock);

	return(0);
}

static void cowify_bitmap(__u64 io_offset, int length, unsigned long *cow_mask, 
			  __u64 *cow_offset, unsigned long *bitmap, 
			  __u64 bitmap_offset, unsigned long *bitmap_words,
			  __u64 bitmap_len)
{
	__u64 sector = io_offset >> 9;
	int i, update_bitmap = 0;

	for(i = 0; i < length >> 9; i++){
		if(cow_mask != NULL)
			ubd_set_bit(i, (unsigned char *) cow_mask);
		if(ubd_test_bit(sector + i, (unsigned char *) bitmap))
			continue;

		update_bitmap = 1;
		ubd_set_bit(sector + i, (unsigned char *) bitmap);
	}

	if(!update_bitmap)
		return;

	*cow_offset = sector / (sizeof(unsigned long) * 8);

	/* This takes care of the case where we're exactly at the end of the
	 * device, and *cow_offset + 1 is off the end.  So, just back it up
	 * by one word.  Thanks to Lynn Kerby for the fix and James McMechan
	 * for the original diagnosis.
	 */
	if(*cow_offset == ((bitmap_len + sizeof(unsigned long) - 1) / 
			   sizeof(unsigned long) - 1))
		(*cow_offset)--;

	bitmap_words[0] = bitmap[*cow_offset];
	bitmap_words[1] = bitmap[*cow_offset + 1];

	*cow_offset *= sizeof(unsigned long);
	*cow_offset += bitmap_offset;
}

static void cowify_req(struct io_thread_req *req, unsigned long *bitmap, 
		       __u64 bitmap_offset, __u64 bitmap_len)
{
	__u64 sector = req->offset >> 9;
        int i;

	if(req->length > (sizeof(req->sector_mask) * 8) << 9)
		panic("Operation too long");

	if(req->op == UBD_READ) {
		for(i = 0; i < req->length >> 9; i++){
			if(ubd_test_bit(sector + i, (unsigned char *) bitmap)){
				ubd_set_bit(i, (unsigned char *) 
					    &req->sector_mask);
			}
                }
        } 
        else cowify_bitmap(req->offset, req->length, &req->sector_mask,
			   &req->cow_offset, bitmap, bitmap_offset, 
			   req->bitmap_words, bitmap_len);
}

static int mmap_fd(struct request *req, struct ubd *dev, __u64 offset)
{
	__u64 sector;
	unsigned char *bitmap;
	int bit, i;

	/* mmap must have been requested on the command line */
	if(!ubd_do_mmap)
		return(-1);

	/* The buffer must be page aligned */
	if(((unsigned long) req->buffer % UBD_MMAP_BLOCK_SIZE) != 0)
		return(-1);

	/* The request must be a page long */
	if((req->current_nr_sectors << 9) != PAGE_SIZE)
		return(-1);

	if(dev->cow.file == NULL)
		return(dev->fd);

	sector = offset >> 9;
	bitmap = (unsigned char *) dev->cow.bitmap;
	bit = ubd_test_bit(sector, bitmap);

	for(i = 1; i < req->current_nr_sectors; i++){
		if(ubd_test_bit(sector + i, bitmap) != bit)
			return(-1);
	}

	if(bit || (req->cmd == WRITE))
		offset += dev->cow.data_offset;

	/* The data on disk must be page aligned */
	if((offset % UBD_MMAP_BLOCK_SIZE) != 0)
		return(-1);

	return(bit ? dev->fd : dev->cow.fd);
}

static int prepare_mmap_request(struct ubd *dev, int fd, __u64 offset, 
				struct request *req, 
				struct io_thread_req *io_req)
{
	int err;

	if(req->cmd == WRITE){
		/* Writes are almost no-ops since the new data is already in the
		 * host page cache
		 */
		dev->map_writes++;
		if(dev->cow.file != NULL)
			cowify_bitmap(io_req->offset, io_req->length, 
				      &io_req->sector_mask, &io_req->cow_offset,
				      dev->cow.bitmap, dev->cow.bitmap_offset,
				      io_req->bitmap_words, 
				      dev->cow.bitmap_len);
	}
	else {
		int w;

		if((dev->cow.file != NULL) && (fd == dev->cow.fd))
			w = 0;
		else w = dev->openflags.w;

		if((dev->cow.file != NULL) && (fd == dev->fd))
			offset += dev->cow.data_offset;

		err = physmem_subst_mapping(req->buffer, fd, offset, w);
		if(err){
			printk("physmem_subst_mapping failed, err = %d\n", 
			       -err);
			return(1);
		}
		dev->map_reads++;
	}
	io_req->op = UBD_MMAP;
	io_req->buffer = req->buffer;
	return(0);
}

static int prepare_request(struct request *req, struct io_thread_req *io_req)
{
	struct ubd *dev;
	__u64 offset;
	int minor, n, len, fd;

	if(req->rq_status == RQ_INACTIVE) return(1);

	minor = MINOR(req->rq_dev);
	n = minor >> UBD_SHIFT;
	dev = &ubd_dev[n];

	if(IS_WRITE(req) && !dev->openflags.w){
		printk("Write attempted on readonly ubd device %d\n", n);
		end_request(0);
		return(1);
	}

        req->sector += ubd_part[minor].start_sect;
	offset = ((__u64) req->sector) << 9;
	len = req->current_nr_sectors << 9;

	io_req->fds[0] = (dev->cow.file != NULL) ? dev->cow.fd : dev->fd;
	io_req->fds[1] = dev->fd;
	io_req->map_fd = -1;
	io_req->cow_offset = -1;
	io_req->offset = offset;
	io_req->length = len;
	io_req->error = 0;
	io_req->sector_mask = 0;

	fd = mmap_fd(req, dev, io_req->offset);
	if(fd > 0){
		/* If mmapping is otherwise OK, but the first access to the 
		 * page is a write, then it's not mapped in yet.  So we have 
		 * to write the data to disk first, then we can map the disk
		 * page in and continue normally from there.
		 */
		if((req->cmd == WRITE) && !is_remapped(req->buffer, dev->fd, io_req->offset + dev->cow.data_offset)){
			io_req->map_fd = dev->fd;
			io_req->map_offset = io_req->offset + 
				dev->cow.data_offset;
			dev->write_maps++;
		}
		else return(prepare_mmap_request(dev, fd, io_req->offset, req, 
						 io_req));
	}

	if(req->cmd == READ)
		dev->nomap_reads++;
	else dev->nomap_writes++;

	io_req->op = (req->cmd == READ) ? UBD_READ : UBD_WRITE;
	io_req->offsets[0] = 0;
	io_req->offsets[1] = dev->cow.data_offset;
	io_req->buffer = req->buffer;
	io_req->sectorsize = 1 << 9;

        if(dev->cow.file != NULL) 
		cowify_req(io_req, dev->cow.bitmap, dev->cow.bitmap_offset,
			   dev->cow.bitmap_len);
	return(0);
}

static void do_ubd_request(request_queue_t *q)
{
	struct io_thread_req io_req;
	struct request *req;
	int err, n;

	if(thread_fd == -1){
		while(!list_empty(&q->queue_head)){
			req = blkdev_entry_next_request(&q->queue_head);
			err = prepare_request(req, &io_req);
			if(!err){
				do_io(&io_req);
				ubd_finish(io_req.error);
			}
		}
	}
	else {
		if(DEVICE_INTR || list_empty(&q->queue_head)) return;
		req = blkdev_entry_next_request(&q->queue_head);
		err = prepare_request(req, &io_req);
		if(!err){
			SET_INTR(ubd_handler);
			n = write_ubd_fs(thread_fd, (char *) &io_req, 
					 sizeof(io_req));
			if(n != sizeof(io_req))
				printk("write to io thread failed, "
				       "errno = %d\n", -n);
		}
	}
}

static int ubd_ioctl(struct inode * inode, struct file * file,
		     unsigned int cmd, unsigned long arg)
{
	struct hd_geometry *loc = (struct hd_geometry *) arg;
 	struct ubd *dev;
	int n, minor, err;
	struct hd_driveid ubd_id = {
		.cyls		= 0,
		.heads		= 128,
		.sectors	= 32,
	};
	
        if(!inode) return(-EINVAL);
	minor = MINOR(inode->i_rdev);
	n = minor >> UBD_SHIFT;
	if(n >= MAX_DEV)
		return(-EINVAL);
	dev = &ubd_dev[n];
	switch (cmd) {
	        struct hd_geometry g;
		struct cdrom_volctrl volume;
	case HDIO_GETGEO:
		if(!loc) return(-EINVAL);
		g.heads = 128;
		g.sectors = 32;
		g.cylinders = dev->size / (128 * 32 * hardsect_sizes[minor]);
		g.start = ubd_part[minor].start_sect;
		return(copy_to_user(loc, &g, sizeof(g)) ? -EFAULT : 0);
	case BLKGETSIZE:   /* Return device size */
		if(!arg) return(-EINVAL);
		err = verify_area(VERIFY_WRITE, (long *) arg, sizeof(long));
		if(err)
			return(err);
		put_user(ubd_part[minor].nr_sects, (long *) arg);
		return(0);
	case BLKRRPART: /* Re-read partition tables */
		return(ubd_revalidate(inode->i_rdev));

	case HDIO_SET_UNMASKINTR:
		if(!capable(CAP_SYS_ADMIN)) return(-EACCES);
		if((arg > 1) || (minor & 0x3F)) return(-EINVAL);
		return(0);

	case HDIO_GET_UNMASKINTR:
		if(!arg)  return(-EINVAL);
		err = verify_area(VERIFY_WRITE, (long *) arg, sizeof(long));
		if(err)
			return(err);
		return(0);

	case HDIO_GET_MULTCOUNT:
		if(!arg)  return(-EINVAL);
		err = verify_area(VERIFY_WRITE, (long *) arg, sizeof(long));
		if(err)
			return(err);
		return(0);

	case HDIO_SET_MULTCOUNT:
		if(!capable(CAP_SYS_ADMIN)) return(-EACCES);
		if(MINOR(inode->i_rdev) & 0x3F) return(-EINVAL);
		return(0);

	case HDIO_GET_IDENTITY:
		ubd_id.cyls = dev->size / (128 * 32 * hardsect_sizes[minor]);
		if(copy_to_user((char *) arg, (char *) &ubd_id, 
				 sizeof(ubd_id)))
			return(-EFAULT);
		return(0);
		
	case CDROMVOLREAD:
		if(copy_from_user(&volume, (char *) arg, sizeof(volume)))
			return(-EFAULT);
		volume.channel0 = 255;
		volume.channel1 = 255;
		volume.channel2 = 255;
		volume.channel3 = 255;
		if(copy_to_user((char *) arg, &volume, sizeof(volume)))
			return(-EFAULT);
		return(0);

	default:
		return blk_ioctl(inode->i_rdev, cmd, arg);
	}
}

static int ubd_revalidate1(kdev_t rdev)
{
	int i, n, offset, err = 0, pcount = 1 << UBD_SHIFT;
	struct ubd *dev;
	struct hd_struct *part;

	n = DEVICE_NR(rdev);
	offset = n << UBD_SHIFT;
	dev = &ubd_dev[n];

	part = &ubd_part[offset];

	/* clear all old partition counts */
	for(i = 1; i < pcount; i++) {
		part[i].start_sect = 0;
		part[i].nr_sects = 0;
	}

	/* If it already has been opened we can check the partitions 
	 * directly 
	 */
	if(dev->count){
		part->start_sect = 0;
		register_disk(&ubd_gendisk, MKDEV(MAJOR_NR, offset), pcount, 
			      &ubd_blops, part->nr_sects);
	} 
	else if(dev->file){
		err = ubd_open_dev(dev);
		if(err){
			printk(KERN_ERR "unable to open %s for validation\n",
			       dev->file);
			goto out;
		}

		/* have to recompute sizes since we opened it */
		err = ubd_file_size(dev, &dev->size);
		if(err < 0) {
			ubd_close(dev);
			goto out;
		}
		part->start_sect = 0;
		part->nr_sects = dev->size / hardsect_sizes[offset];
		register_disk(&ubd_gendisk, MKDEV(MAJOR_NR, offset), pcount, 
			      &ubd_blops, part->nr_sects);

		/* we are done so close it */
		ubd_close(dev);
	} 
	else err = -ENODEV;
 out:
	return(err);
}

static int ubd_revalidate(kdev_t rdev)
{
	int err;

	spin_lock(&ubd_lock);
	err = ubd_revalidate1(rdev);
	spin_unlock(&ubd_lock);
	return(err);
}

static int ubd_check_remapped(int fd, unsigned long address, int is_write,
			      __u64 offset, int is_user)
{
	__u64 bitmap_offset;
	unsigned long new_bitmap[2];
	int i, err, n;

	/* This can only fix kernelspace faults */
	if(is_user)
		return(0);

	/* ubd-mmap is only enabled in skas mode */
	if(CHOOSE_MODE(1, 0))
		return(0);

	/* If it's not a write access, we can't do anything about it */
	if(!is_write)
		return(0);

	/* We have a write */
	for(i = 0; i < sizeof(ubd_dev) / sizeof(ubd_dev[0]); i++){
		struct ubd *dev = &ubd_dev[i];

		if((dev->fd != fd) && (dev->cow.fd != fd))
			continue;

		/* It's a write to a ubd device */

		if(!dev->openflags.w){
			/* It's a write access on a read-only device - probably
			 * shouldn't happen.  If the kernel is trying to change
			 * something with no intention of writing it back out,
			 * then this message will clue us in that this needs
			 * fixing
			 */
			printk("Write access to mapped page from readonly ubd "
			       "device %d\n", i);
			return(0);
		}

		/* It's a write to a writeable ubd device - it must be COWed
		 * because, otherwise, the page would have been mapped in 
		 * writeable
		 */

		if(!dev->cow.file)
			panic("Write fault on writeable non-COW ubd device %d",
			      i);

		/* It should also be an access to the backing file since the 
		 * COW pages should be mapped in read-write
		 */

		if(fd == dev->fd)
			panic("Write fault on a backing page of ubd "
			      "device %d\n", i);

		/* So, we do the write, copying the backing data to the COW 
		 * file... 
		 */

		err = os_seek_file(dev->fd, offset + dev->cow.data_offset);
		if(err < 0)
			panic("Couldn't seek to %lld in COW file of ubd "
			      "device %d, err = %d", 
			      offset + dev->cow.data_offset, i, -err);

		n = os_write_file(dev->fd, (void *) address, PAGE_SIZE);
		if(n != PAGE_SIZE)
			panic("Couldn't copy data to COW file of ubd "
			      "device %d, err = %d", i, -n);

		/* ... updating the COW bitmap... */

		cowify_bitmap(offset, PAGE_SIZE, NULL, &bitmap_offset, 
			      dev->cow.bitmap, dev->cow.bitmap_offset, 
			      new_bitmap, dev->cow.bitmap_len);

		err = os_seek_file(dev->fd, bitmap_offset);
		if(err < 0)
			panic("Couldn't seek to %lld in COW file of ubd "
			      "device %d, err = %d", bitmap_offset, i, -err);

		n = os_write_file(dev->fd, new_bitmap, sizeof(new_bitmap));
		if(n != sizeof(new_bitmap))
			panic("Couldn't update bitmap  of ubd device %d, "
			      "err = %d", i, -n);
		
		/* Maybe we can map the COW page in, and maybe we can't.  If
		 * it is a pre-V3 COW file, we can't, since the alignment will 
		 * be wrong.  If it is a V3 or later COW file which has been 
		 * moved to a system with a larger page size, then maybe we 
		 * can't, depending on the exact location of the page.
		 */

		offset += dev->cow.data_offset;

		/* Remove the remapping, putting the original anonymous page
		 * back.  If the COW file can be mapped in, that is done.
		 * Otherwise, the COW page is read in.
		 */

		if(!physmem_remove_mapping((void *) address))
			panic("Address 0x%lx not remapped by ubd device %d", 
			      address, i);
		if((offset % UBD_MMAP_BLOCK_SIZE) == 0)
			physmem_subst_mapping((void *) address, dev->fd, 
					      offset, 1);
		else {
			err = os_seek_file(dev->fd, offset);
			if(err < 0)
				panic("Couldn't seek to %lld in COW file of "
				      "ubd device %d, err = %d", offset, i, 
				      -err);

			n = os_read_file(dev->fd, (void *) address, PAGE_SIZE);
			if(n != PAGE_SIZE)
				panic("Failed to read page from offset %llx of "
				      "COW file of ubd device %d, err = %d",
				      offset, i, -n);
		}

		return(1);
	}

	/* It's not a write on a ubd device */
	return(0);
}

static struct remapper ubd_remapper = {
	.list	= LIST_HEAD_INIT(ubd_remapper.list),
	.proc	= ubd_check_remapped,
};

static int ubd_remapper_setup(void)
{
	if(ubd_do_mmap)
		register_remapper(&ubd_remapper);

	return(0);
}

__initcall(ubd_remapper_setup);

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
