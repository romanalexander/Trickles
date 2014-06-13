/* 
 * Copyright (C) 2000 - 2004 Jeff Dike (jdike@addtoit.com)
 * Licensed under the GPL
 */

#include <linux/stddef.h>
#include <linux/fs.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/blkdev.h>
#include <asm/uaccess.h>
#include "hostfs.h"
#include "kern_util.h"
#include "kern.h"
#include "user_util.h"
#include "2_5compat.h"
#include "mem.h"
#include "filehandle.h"

struct externfs {
	struct list_head list;
	struct externfs_mount_ops *mount_ops;
	struct file_system_type type;
};

static inline struct externfs_inode *EXTERNFS_I(struct inode *inode)
{
	return(inode->u.generic_ip);
}

#define file_externfs_i(file) EXTERNFS_I((file)->f_dentry->d_inode)

int externfs_d_delete(struct dentry *dentry)
{
	return(1);
}

struct dentry_operations externfs_dentry_ops = {
};

#define EXTERNFS_SUPER_MAGIC 0x00c0ffee

static struct inode_operations externfs_iops;
static struct inode_operations externfs_dir_iops;
static struct address_space_operations externfs_link_aops;

static char *dentry_name(struct dentry *dentry, int extra)
{
	struct dentry *parent;
	char *name;
	int len;

	len = 0;
	parent = dentry;
	while(parent->d_parent != parent){
		len += parent->d_name.len + 1;
		parent = parent->d_parent;
	}
	
	name = kmalloc(len + extra + 1, GFP_KERNEL);
	if(name == NULL) return(NULL);

	name[len] = '\0';
	parent = dentry;
	while(parent->d_parent != parent){
		len -= parent->d_name.len + 1;
		name[len] = '/';
		strncpy(&name[len + 1], parent->d_name.name, 
			parent->d_name.len);
		parent = parent->d_parent;
	}

	return(name);
}

char *inode_name(struct inode *ino, int extra)
{
	struct dentry *dentry;

	dentry = list_entry(ino->i_dentry.next, struct dentry, d_alias);
	return(dentry_name(dentry, extra));
}

char *inode_name_prefix(struct inode *inode, char *prefix)
{
	int len;
	char *name;

	len = strlen(prefix);
	name = inode_name(inode, len);
	if(name == NULL)
		return(name);

	memmove(&name[len], name, strlen(name) + 1);
	memcpy(name, prefix, strlen(prefix));
	return(name);
}

static int read_name(struct inode *ino, char *name)
{
	struct externfs_file_ops *ops = EXTERNFS_I(ino)->ops;
	/* The non-int inode fields are copied into ints by stat_file and
	 * then copied into the inode because passing the actual pointers
	 * in and having them treated as int * breaks on big-endian machines
	 */
	int err;
	int i_dev, i_mode, i_nlink, i_blksize;
	unsigned long long i_size;
	unsigned long long i_ino;
	unsigned long long i_blocks;

	err = (*ops->stat_file)(name, ino->i_sb->u.generic_sbp, 
				(dev_t *) &i_dev, &i_ino, &i_mode, &i_nlink,
				&ino->i_uid, &ino->i_gid, &i_size, 
				&ino->i_atime, &ino->i_mtime, &ino->i_ctime, 
				&i_blksize, &i_blocks);
	if(err) return(err);
	ino->i_ino = i_ino;
	ino->i_dev = i_dev;
	ino->i_mode = i_mode;
	ino->i_nlink = i_nlink;
	ino->i_size = i_size;
	ino->i_blksize = i_blksize;
	ino->i_blocks = i_blocks;
	return(0);
}

static char *follow_link(char *link, 
			 int (*do_read_link)(char *path, int uid, int gid,
					     char *buf, int size, 
					     struct externfs_data *ed),
			 int uid, int gid, struct externfs_data *ed)
{
	int len, n;
	char *name, *resolved, *end;

	len = 64;
	while(1){
		n = -ENOMEM;
		name = kmalloc(len, GFP_KERNEL);
		if(name == NULL)
			goto out;

		n = (*do_read_link)(link, uid, gid, name, len, ed);
		if(n < len)
			break;
		len *= 2;
		kfree(name);
	}
	if(n < 0)
		goto out_free;

	if(*name == '/')
		return(name);

	end = strrchr(link, '/');
	if(end == NULL)
		return(name);

	*(end + 1) = '\0';
	len = strlen(link) + strlen(name) + 1;

	resolved = kmalloc(len, GFP_KERNEL);
	if(resolved == NULL){
		n = -ENOMEM;
		goto out_free;
	}

	sprintf(resolved, "%s%s", link, name);
	kfree(name);
	return(resolved);

 out_free:
	kfree(name);
 out:
	return(ERR_PTR(n));
}

static int read_inode(struct inode *ino)
{
	struct externfs_file_ops *ops = EXTERNFS_I(ino)->ops;
	struct externfs_data *ed = ino->i_sb->u.generic_sbp;
	char *name, *new;
	int err, type;

	err = -ENOMEM;
	name = inode_name(ino, 0);
	if(name == NULL) 
		goto out;

	type = (*ops->file_type)(name, NULL, ed);
	if(type < 0){
		err = type;
		goto out_free;
	}

	if(type == OS_TYPE_SYMLINK){
		new = follow_link(name, ops->read_link, current->fsuid,
				  current->fsgid, ed);
		if(IS_ERR(new)){
			err = PTR_ERR(new);
			goto out_free;
		}
		kfree(name);
		name = new;
	}
	
	err = read_name(ino, name);
 out_free:
	kfree(name);
 out:
	return(err);
}

void externfs_delete_inode(struct inode *ino)
{
	struct externfs_inode *ext = EXTERNFS_I(ino);
	struct externfs_file_ops *ops = ext->ops;

	(*ops->close_file)(ext, ino->i_size);

	clear_inode(ino);
}

int externfs_statfs(struct super_block *sb, struct statfs *sf)
{
	/* do_statfs uses struct statfs64 internally, but the linux kernel
	 * struct statfs still has 32-bit versions for most of these fields,
	 * so we convert them here
	 */
	int err;
	long long f_blocks;
	long long f_bfree;
	long long f_bavail;
	long long f_files;
	long long f_ffree;
	struct externfs_data *ed = sb->u.generic_sbp;
	
	err = (*ed->file_ops->statfs)(&sf->f_bsize, &f_blocks, &f_bfree, 
				      &f_bavail, &f_files, &f_ffree, 
				      &sf->f_fsid, sizeof(sf->f_fsid), 
				      &sf->f_namelen, sf->f_spare, ed);
	if(err)
		return(err);

	sf->f_blocks = f_blocks;
	sf->f_bfree = f_bfree;
	sf->f_bavail = f_bavail;
	sf->f_files = f_files;
	sf->f_ffree = f_ffree;
	sf->f_type = EXTERNFS_SUPER_MAGIC;
	return(0);
}

static struct super_operations externfs_sbops = { 
	.delete_inode	= externfs_delete_inode,
	.statfs		= externfs_statfs,
};

int externfs_readdir(struct file *file, void *ent, filldir_t filldir)
{
	void *dir;
	char *name;
	unsigned long long next, ino;
	int error, len;
	struct externfs_file_ops *ops = file_externfs_i(file)->ops;
	struct externfs_data *ed = 
		file->f_dentry->d_inode->i_sb->u.generic_sbp;

	name = dentry_name(file->f_dentry, 0);
	if(name == NULL) 
		return(-ENOMEM);

	dir = (*ops->open_dir)(name, current->fsuid, current->fsgid, ed);
	kfree(name);
	if(IS_ERR(dir)) 
		return(PTR_ERR(dir));

	next = file->f_pos;
	while((name = (*ops->read_dir)(dir, &next, &ino, &len, ed)) != NULL){
		error = (*filldir)(ent, name, len, file->f_pos, ino, 
				   DT_UNKNOWN);
		if(error) 
			break;
		file->f_pos = next;
	}
	(*ops->close_dir)(dir, ed);
	return(0);
}

int externfs_file_open(struct inode *ino, struct file *file)
{
	ino->i_nlink++;
	return(0);
}

int externfs_dir_open(struct inode *ino, struct file *file)
{
	return(0);	
}

int externfs_dir_release(struct inode *ino, struct file *file)
{
	return(0);
}

int externfs_fsync(struct file *file, struct dentry *dentry, int datasync)
{
	struct externfs_file_ops *ops = file_externfs_i(file)->ops;
	struct inode *inode = dentry->d_inode;
	struct externfs_data *ed = inode->i_sb->u.generic_sbp;

	return((*ops->truncate_file)(EXTERNFS_I(inode), inode->i_size, ed));
}

static struct file_operations externfs_file_fops = {
	.owner		= NULL,
	.read		= generic_file_read,
	.write		= generic_file_write,
	.mmap		= generic_file_mmap,
	.open		= externfs_file_open,
	.release	= NULL,
	.fsync		= externfs_fsync,
};

static struct file_operations externfs_dir_fops = {
	.owner		= NULL,
	.readdir	= externfs_readdir,
	.open		= externfs_dir_open,
	.release	= externfs_dir_release,
	.fsync		= externfs_fsync,
};

struct wp_info {
	struct page *page;
	int count;
	unsigned long long start;
	unsigned long long size;
	int (*truncate)(struct externfs_inode *ei, __u64 size, 
			struct externfs_data *ed);
	struct externfs_inode *ei;
	struct externfs_data *ed;
};

static void externfs_finish_writepage(char *buffer, int res, void *arg)
{
	struct wp_info *wp = arg;

	if(res == wp->count){
		ClearPageError(wp->page);
		if(wp->start + res > wp->size)
			(*wp->truncate)(wp->ei, wp->size, wp->ed);
	}
	else {
		SetPageError(wp->page);
		ClearPageUptodate(wp->page);
	}		

	kunmap(wp->page);
	unlock_page(wp->page);
	kfree(wp);
}

static int externfs_writepage(struct page *page)
{
	struct address_space *mapping = page->mapping;
	struct inode *inode = mapping->host;
	struct externfs_file_ops *ops = EXTERNFS_I(inode)->ops;
	struct wp_info *wp;
	struct externfs_data *ed = inode->i_sb->u.generic_sbp;
	char *buffer;
	unsigned long long base;
	int count = PAGE_CACHE_SIZE;
	int end_index = inode->i_size >> PAGE_CACHE_SHIFT;
	int err, offset;

	base = ((unsigned long long) page->index) << PAGE_CACHE_SHIFT;

	/* If we are entirely outside the file, then return an error */
	err = -EIO;
	offset = inode->i_size & (PAGE_CACHE_SIZE-1);
	if (page->index > end_index || 
	    ((page->index == end_index) && !offset))
		goto out_unlock;

	err = -ENOMEM;
	wp = kmalloc(sizeof(*wp), GFP_KERNEL);
	if(wp == NULL)
		goto out_unlock;

	*wp = ((struct wp_info) { .page		= page,
				  .count	= count,
				  .start	= base,
				  .size		= inode->i_size,
				  .truncate	= ops->truncate_file,
				  .ei		= EXTERNFS_I(inode),
				  .ed		= ed });

	buffer = kmap(page);
	err = (*ops->write_file)(EXTERNFS_I(inode), base, buffer, 0, 
				 count, externfs_finish_writepage, wp, ed);

	return err;

 out_unlock:
	unlock_page(page);
	return(err);
}

static void externfs_finish_readpage(char *buffer, int res, void *arg)
{
	struct page *page = arg;
	struct inode *inode;

	if(res < 0){
		SetPageError(page);
		goto out;
	}

	inode = page->mapping->host;
	if(inode->i_size >> PAGE_CACHE_SHIFT == page->index)
		res = inode->i_size % PAGE_CACHE_SIZE;

	memset(&buffer[res], 0, PAGE_CACHE_SIZE - res);

	flush_dcache_page(page);
	SetPageUptodate(page);
	if (PageError(page)) 
		ClearPageError(page);
 out:
	kunmap(page);
	unlock_page(page);
}

static int externfs_readpage(struct file *file, struct page *page)
{
	struct inode *ino = page->mapping->host;
	struct externfs_file_ops *ops = EXTERNFS_I(ino)->ops;
	struct externfs_data *ed = ino->i_sb->u.generic_sbp;
	char *buffer;
	long long start;
	int err = 0;

	start = (long long) page->index << PAGE_CACHE_SHIFT;
	buffer = kmap(page);

	if(ops->map_file_page != NULL){
		/* XXX What happens when PAGE_SIZE != PAGE_CACHE_SIZE? */
		err = (*ops->map_file_page)(file_externfs_i(file), start, 
					    buffer, file->f_mode & FMODE_WRITE,
					    ed);
		if(!err)
			err = PAGE_CACHE_SIZE;
	}
	else err = (*ops->read_file)(file_externfs_i(file), start, buffer,
				     PAGE_CACHE_SIZE, 0, 0, 
				     externfs_finish_readpage, page, ed);

	if(err > 0)
		err = 0;
	return(err);
}

struct writepage_info {
	struct semaphore sem;
	int res;
};

static void externfs_finish_prepare(char *buffer, int res, void *arg)
{
	struct writepage_info *wp = arg;

	wp->res = res;
	up(&wp->sem);
}

int externfs_prepare_write(struct file *file, struct page *page, 
			 unsigned int from, unsigned int to)
{
	struct address_space *mapping = page->mapping;
	struct inode *inode = mapping->host;
	struct externfs_file_ops *ops = EXTERNFS_I(inode)->ops;
	struct externfs_data *ed = inode->i_sb->u.generic_sbp;
	char *buffer;
	long long start;
	int err;
	struct writepage_info wp;

	if(Page_Uptodate(page))
		return(0);

	start = (long long) page->index << PAGE_CACHE_SHIFT;
	buffer = kmap(page);

	if(ops->map_file_page != NULL){
		err = (*ops->map_file_page)(file_externfs_i(file), start, 
					    buffer, file->f_mode & FMODE_WRITE,
					    ed);
		goto out;
	}

	init_MUTEX_LOCKED(&wp.sem);
	err = (*ops->read_file)(file_externfs_i(file), start, buffer,
				PAGE_CACHE_SIZE, from, to, 
				externfs_finish_prepare, &wp, ed);
	down(&wp.sem);
	if(err < 0) 
		goto out;

	err = wp.res;
	if(err < 0)
		goto out;

	if(from > 0)
		memset(buffer, 0, from);
	if(to < PAGE_CACHE_SIZE)
		memset(buffer + to, 0, PAGE_CACHE_SIZE - to);

	SetPageUptodate(page);
	err = 0;
 out:
	kunmap(page);
	return(err);
}

static int externfs_commit_write(struct file *file, struct page *page, 
			       unsigned from, unsigned to)
{
	struct address_space *mapping = page->mapping;
	struct inode *inode = mapping->host;
	struct externfs_file_ops *ops = EXTERNFS_I(inode)->ops;
	unsigned long long size;
	long long start;
	int err;

	start = (long long) (page->index << PAGE_CACHE_SHIFT);

	if(ops->map_file_page != NULL)
		err = to - from;
	else {
		size = start + to;
		if(size > inode->i_size){
			inode->i_size = size;
			mark_inode_dirty(inode);
		}
	}

	set_page_dirty(page);
	return(to - from);
}

static void externfs_removepage(struct page *page)
{
	physmem_remove_mapping(page_address(page));
}

static struct address_space_operations externfs_aops = {
	.writepage 	= externfs_writepage,
	.readpage	= externfs_readpage,
	.removepage	= externfs_removepage,
/* 	.set_page_dirty = __set_page_dirty_nobuffers, */
	.prepare_write	= externfs_prepare_write,
	.commit_write	= externfs_commit_write
};

static struct inode *get_inode(struct super_block *sb, struct dentry *dentry,
			       int need_fh)
{
	struct inode *inode;
	struct externfs_data *ed = sb->u.generic_sbp;
	struct externfs_mount_ops *ops = ed->mount_ops;
	char *name = NULL;
	int type, err = -ENOMEM, rdev;

	if(dentry){
		name = dentry_name(dentry, 0);
		if(name == NULL)
			goto out;
		type = (*ed->file_ops->file_type)(name, &rdev, ed);
	}
	else type = OS_TYPE_DIR;

	inode = new_inode(sb);
	if(inode == NULL)
		goto out_free;

	insert_inode_hash(inode);

	if(type == OS_TYPE_SYMLINK)
		inode->i_op = &page_symlink_inode_operations;
	else if(type == OS_TYPE_DIR)
		inode->i_op = &externfs_dir_iops;
	else inode->i_op = &externfs_iops;

	if(type == OS_TYPE_DIR) inode->i_fop = &externfs_dir_fops;
	else inode->i_fop = &externfs_file_fops;

	if(type == OS_TYPE_SYMLINK) 
		inode->i_mapping->a_ops = &externfs_link_aops;
	else inode->i_mapping->a_ops = &externfs_aops;

	switch (type) {
	case OS_TYPE_CHARDEV:
		init_special_inode(inode, S_IFCHR, rdev);
		break;
	case OS_TYPE_BLOCKDEV:
		init_special_inode(inode, S_IFBLK, rdev);
		break;
	case OS_TYPE_FIFO:
		init_special_inode(inode, S_IFIFO, 0);
		break;
	case OS_TYPE_SOCK:
		init_special_inode(inode, S_IFSOCK, 0);
		break;
	case OS_TYPE_SYMLINK:
		inode->i_mode = S_IFLNK | S_IRWXUGO;
	}
	
	if(need_fh){
		struct externfs_inode *ei;

		err = -ENOMEM;
		ei = (*ops->init_file)(ed);
		if(ei == NULL)
			goto out_put;

		*ei = ((struct externfs_inode) { .ops	= ed->file_ops });
		inode->u.generic_ip = ei;

		err = (*ed->file_ops->open_file)(ei, name, current->fsuid, 
						 current->fsgid, inode, ed);
		if(err && ((err != -ENOENT) && (err != -EISDIR)))
			goto out_put;
	}

	return(inode);

 out_put:
	iput(inode);
 out_free:
	kfree(name);
 out:
	return(ERR_PTR(err));
}

int externfs_create(struct inode *dir, struct dentry *dentry, int mode)
{
	struct externfs_file_ops *ops = EXTERNFS_I(dir)->ops;
	struct inode *inode;
	struct externfs_data *ed = dir->i_sb->u.generic_sbp;
	struct externfs_inode *ei;
	char *name;
	int err = -ENOMEM;

	name = dentry_name(dentry, 0);
	if(name == NULL)
		goto out;

	inode = get_inode(dir->i_sb, dentry, 0);
	if(IS_ERR(inode)){
		err = PTR_ERR(inode);
		goto out_free;
	}

	ei = (*ed->mount_ops->init_file)(ed);
	if(ei == NULL)
		/* XXX need a free_file() */
		goto out_put;

	*ei = ((struct externfs_inode) { .ops	= ed->file_ops });
	inode->u.generic_ip = ei;

	err = (*ops->create_file)(ei, name, mode, current->fsuid, 
				  current->fsuid, inode, ed);
	if(err)
		goto out_put;

	err = read_name(inode, name);
	if(err)
		goto out_rm;

	inode->i_nlink++;
	d_instantiate(dentry, inode);
 out_free:
	kfree(name);
 out:
	return(err);

 out_rm:
	(*ops->unlink_file)(name, ed);
 out_put:
	inode->i_nlink = 0;
	iput(inode);
	goto out_free;
}
 
struct dentry *externfs_lookup(struct inode *ino, struct dentry *dentry)
{
	struct inode *inode;
	char *name;
	int err;

	inode = get_inode(ino->i_sb, dentry, 1);
	if(IS_ERR(inode)){
		err = PTR_ERR(inode);
		goto out;
	}

	err = -ENOMEM;
	name = dentry_name(dentry, 0);
	if(name == NULL)
		goto out_put;

	err = read_name(inode, name);
	kfree(name);
	if(err){
		if(err != -ENOENT)
			goto out_put;

		inode->i_nlink = 0;
		iput(inode);
		inode = NULL;
	}
	d_add(dentry, inode);
	dentry->d_op = &externfs_dentry_ops;
	return(NULL);

 out_put:
	inode->i_nlink = 0;
	iput(inode);
 out:
	return(ERR_PTR(err));
}

static char *inode_dentry_name(struct inode *ino, struct dentry *dentry)
{
        char *file;
	int len;

	file = inode_name(ino, dentry->d_name.len + 1);
	if(file == NULL) return(NULL);
        strcat(file, "/");
	len = strlen(file);
        strncat(file, dentry->d_name.name, dentry->d_name.len);
	file[len + dentry->d_name.len] = '\0';
        return(file);
}

int externfs_link(struct dentry *to, struct inode *ino, struct dentry *from)
{
	struct externfs_file_ops *ops = EXTERNFS_I(ino)->ops;
	struct externfs_data *ed = ino->i_sb->u.generic_sbp;
        char *from_name, *to_name;
        int err = -ENOMEM;

        from_name = inode_dentry_name(ino, from); 
        if(from_name == NULL) 
		goto out;

        to_name = dentry_name(to, 0);
	if(to_name == NULL)
		goto out_free_from;

        err = (*ops->link_file)(to_name, from_name, current->fsuid, 
				current->fsgid, ed);
	if(err)
		goto out_free_to;

	d_instantiate(from, to->d_inode);
	to->d_inode->i_nlink++;
	atomic_inc(&to->d_inode->i_count);

 out_free_to:
        kfree(to_name);
 out_free_from:
        kfree(from_name);
 out:
        return(err);
}

int externfs_unlink(struct inode *ino, struct dentry *dentry)
{
	struct inode *inode;
	struct externfs_file_ops *ops = EXTERNFS_I(ino)->ops;
	struct externfs_data *ed = ino->i_sb->u.generic_sbp;
	char *file;
	int err;

	file = inode_dentry_name(ino, dentry);
	if(file == NULL) 
		return(-ENOMEM);

	inode = dentry->d_inode;
	if((inode->i_nlink == 1) && (ops->invisible != NULL))
		(*ops->invisible)(EXTERNFS_I(inode));

	err = (*ops->unlink_file)(file, ed);
	kfree(file);

	inode->i_nlink--;

	return(err);
}

int externfs_symlink(struct inode *ino, struct dentry *dentry, const char *to)
{
	struct externfs_file_ops *ops = EXTERNFS_I(ino)->ops;
	struct externfs_data *ed = ino->i_sb->u.generic_sbp;
	struct inode *inode;
	char *file;
	int err;

	file = inode_dentry_name(ino, dentry);
	if(file == NULL) 
		return(-ENOMEM);
	err = (*ops->make_symlink)(file, to, current->fsuid, current->fsgid,
				   ed);
	kfree(file);

	inode = get_inode(ino->i_sb, dentry, 1);
	if(IS_ERR(inode)){
		err = PTR_ERR(inode);
		goto out;
	}

	d_instantiate(dentry, inode);
	inode->i_nlink++;
	iput(inode);
 out:
	return(err);
}

int externfs_make_dir(struct inode *ino, struct dentry *dentry, int mode)
{
	struct externfs_file_ops *ops = EXTERNFS_I(ino)->ops;
	struct externfs_data *ed = ino->i_sb->u.generic_sbp;
	struct inode *inode;
	char *file;
	int err;

	file = inode_dentry_name(ino, dentry);
	if(file == NULL) 
		return(-ENOMEM);
	err = (*ops->make_dir)(file, mode, current->fsuid, current->fsgid, ed);

	inode = get_inode(ino->i_sb, dentry, 1);
	if(IS_ERR(inode)){
		err = PTR_ERR(inode);
		goto out_free;
	}

	err = read_name(inode, file);
	kfree(file);
	if(err)
		goto out_put;

	d_instantiate(dentry, inode);
	inode->i_nlink = 2;
	inode->i_mode = S_IFDIR | mode;
	iput(inode);

	ino->i_nlink++;
 out:
	return(err);
 out_free:
	kfree(file);
 out_put:
	inode->i_nlink = 0;
	iput(inode);
	goto out;	
}

int externfs_remove_dir(struct inode *ino, struct dentry *dentry)
{
	struct externfs_file_ops *ops = EXTERNFS_I(ino)->ops;
	void *mount = ino->i_sb->u.generic_sbp;
	char *file;
	int err;

	file = inode_dentry_name(ino, dentry);
	if(file == NULL) 
		return(-ENOMEM);
	err = (*ops->remove_dir)(file, current->fsuid, current->fsgid, mount);
	kfree(file);

	dentry->d_inode->i_nlink = 0;
	ino->i_nlink--;
	return(err);
}

int externfs_make_node(struct inode *dir, struct dentry *dentry, int mode, 
		     int dev)
{
	struct externfs_file_ops *ops = EXTERNFS_I(dir)->ops;
	struct externfs_data *ed = dir->i_sb->u.generic_sbp;
	struct inode *inode;
	char *name;
	int err = -ENOMEM;
 
	name = dentry_name(dentry, 0);
	if(name == NULL)
		goto out;

	inode = get_inode(dir->i_sb, dentry, 1);
	if(IS_ERR(inode)){
		err = PTR_ERR(inode);
		goto out_free;
	}

	init_special_inode(inode, mode, dev);
	err = (*ops->make_node)(name, mode & S_IRWXUGO, current->fsuid, 
				current->fsgid, mode & S_IFMT, major(dev), 
				minor(dev), ed);
	if(err)
		goto out_put;
	
	err = read_name(inode, name);
	if(err)
		goto out_rm;

	d_instantiate(dentry, inode);
 out_free:
	kfree(name);
 out:
	return(err);

 out_rm:
	(*ops->unlink_file)(name, ed);
 out_put:
	inode->i_nlink = 0;
	iput(inode);
	goto out_free;
}

int externfs_rename(struct inode *from_ino, struct dentry *from,
		  struct inode *to_ino, struct dentry *to)
{
	struct externfs_file_ops *ops = EXTERNFS_I(from_ino)->ops;
	struct externfs_data *ed = from_ino->i_sb->u.generic_sbp;
	char *from_name, *to_name;
	int err;

	from_name = inode_dentry_name(from_ino, from);
	if(from_name == NULL)
		return(-ENOMEM);
	to_name = inode_dentry_name(to_ino, to);
	if(to_name == NULL){
		kfree(from_name);
		return(-ENOMEM);
	}
	err = (*ops->rename_file)(from_name, to_name, ed);
	kfree(from_name);
	kfree(to_name);

	from_ino->i_nlink--;
	to_ino->i_nlink++;
	return(err);
}

void externfs_truncate(struct inode *ino)
{
	struct externfs_file_ops *ops = EXTERNFS_I(ino)->ops;
	struct externfs_data *ed = ino->i_sb->u.generic_sbp;

	(*ops->truncate_file)(EXTERNFS_I(ino), ino->i_size, ed);
}

int externfs_permission(struct inode *ino, int desired)
{
	struct externfs_file_ops *ops = EXTERNFS_I(ino)->ops;
	struct externfs_data *ed = ino->i_sb->u.generic_sbp;
	char *name;
	int r = 0, w = 0, x = 0, err;

	if(ops->access_file == NULL)
		return(vfs_permission(ino, desired));

	if(desired & MAY_READ) r = 1;
	if(desired & MAY_WRITE) w = 1;
	if(desired & MAY_EXEC) x = 1;
	name = inode_name(ino, 0);
	if(name == NULL) 
		return(-ENOMEM);

	err = (*ops->access_file)(name, r, w, x, current->fsuid, 
				  current->fsgid, ed);
	kfree(name);

	if(!err) 
		err = vfs_permission(ino, desired);
	return(err);
}

int externfs_setattr(struct dentry *dentry, struct iattr *attr)
{
	struct externfs_file_ops *ops = EXTERNFS_I(dentry->d_inode)->ops;
	struct externfs_data *ed = dentry->d_inode->i_sb->u.generic_sbp;
	struct externfs_iattr attrs;
	char *name;
	int err;
	
	attrs.ia_valid = 0;
	if(attr->ia_valid & ATTR_MODE){
		attrs.ia_valid |= EXTERNFS_ATTR_MODE;
		attrs.ia_mode = attr->ia_mode;
	}
	if(attr->ia_valid & ATTR_UID){
		attrs.ia_valid |= EXTERNFS_ATTR_UID;
		attrs.ia_uid = attr->ia_uid;
	}
	if(attr->ia_valid & ATTR_GID){
		attrs.ia_valid |= EXTERNFS_ATTR_GID;
		attrs.ia_gid = attr->ia_gid;
	}
	if(attr->ia_valid & ATTR_SIZE){
		attrs.ia_valid |= EXTERNFS_ATTR_SIZE;
		attrs.ia_size = attr->ia_size;
	}
	if(attr->ia_valid & ATTR_ATIME){
		attrs.ia_valid |= EXTERNFS_ATTR_ATIME;
		attrs.ia_atime = attr->ia_atime;
	}
	if(attr->ia_valid & ATTR_MTIME){
		attrs.ia_valid |= EXTERNFS_ATTR_MTIME;
		attrs.ia_mtime = attr->ia_mtime;
	}
	if(attr->ia_valid & ATTR_CTIME){
		attrs.ia_valid |= EXTERNFS_ATTR_CTIME;
		attrs.ia_ctime = attr->ia_ctime;
	}
	if(attr->ia_valid & ATTR_ATIME_SET){
		attrs.ia_valid |= EXTERNFS_ATTR_ATIME_SET;
	}
	if(attr->ia_valid & ATTR_MTIME_SET){
		attrs.ia_valid |= EXTERNFS_ATTR_MTIME_SET;
	}
	name = dentry_name(dentry, 0);
	if(name == NULL) 
		return(-ENOMEM);
	err = (*ops->set_attr)(name, &attrs, ed);
	kfree(name);
	if(err)
		return(err);

	return(inode_setattr(dentry->d_inode, attr));
}

int externfs_getattr(struct dentry *dentry, struct iattr *attr)
{
	not_implemented();
	return(-EINVAL);
}

static struct inode_operations externfs_iops = {
	.create		= externfs_create,
	.link		= externfs_link,
	.unlink		= externfs_unlink,
	.symlink	= externfs_symlink,
	.mkdir		= externfs_make_dir,
	.rmdir		= externfs_remove_dir,
	.mknod		= externfs_make_node,
	.rename		= externfs_rename,
	.truncate	= externfs_truncate,
	.permission	= externfs_permission,
	.setattr	= externfs_setattr,
	.getattr	= externfs_getattr,
};

static struct inode_operations externfs_dir_iops = {
	.create		= externfs_create,
	.lookup		= externfs_lookup,
	.link		= externfs_link,
	.unlink		= externfs_unlink,
	.symlink	= externfs_symlink,
	.mkdir		= externfs_make_dir,
	.rmdir		= externfs_remove_dir,
	.mknod		= externfs_make_node,
	.rename		= externfs_rename,
	.truncate	= externfs_truncate,
	.permission	= externfs_permission,
	.setattr	= externfs_setattr,
	.getattr	= externfs_getattr,
};

int externfs_link_readpage(struct file *file, struct page *page)
{
	struct inode *ino = page->mapping->host;
	struct externfs_file_ops *ops = EXTERNFS_I(ino)->ops;
	struct externfs_data *ed = ino->i_sb->u.generic_sbp;
	char *buffer, *name;
	long long start;
	int err;

	start = page->index << PAGE_CACHE_SHIFT;
	buffer = kmap(page);
	name = inode_name(ino, 0);
	if(name == NULL) 
		return(-ENOMEM);

	err = (*ops->read_link)(name, current->fsuid, current->fsgid, buffer, 
				PAGE_CACHE_SIZE, ed);

	kfree(name);
	if(err == PAGE_CACHE_SIZE)
		err = -E2BIG;
	else if(err > 0){
		flush_dcache_page(page);
		SetPageUptodate(page);
		if (PageError(page)) ClearPageError(page);
		err = 0;
	}
	kunmap(page);
	UnlockPage(page);
	return(err);
}

static int externfs_flushpage(struct page *page, unsigned long offset)
{
	return(externfs_writepage(page));
}

struct externfs_data *inode_externfs_info(struct inode *inode)
{
	return(inode->i_sb->u.generic_sbp);
}

static struct address_space_operations externfs_link_aops = {
	.readpage	= externfs_link_readpage,
	.removepage	= externfs_removepage,
	.flushpage	= externfs_flushpage,
};

DECLARE_MUTEX(externfs_sem);
struct list_head externfses = LIST_HEAD_INIT(externfses);

static struct externfs *find_externfs(struct file_system_type *type)
{
	struct list_head *ele;
	struct externfs *fs;

	down(&externfs_sem);
	list_for_each(ele, &externfses){
		fs = list_entry(ele, struct externfs, list);
		if(&fs->type == type)
			goto out;
	}
	fs = NULL;
 out:
	up(&externfs_sem);
	return(fs);
}

#define DEFAULT_ROOT "/"

char *host_root_filename(char *mount_arg)
{
	char *root = DEFAULT_ROOT;

	if((mount_arg != NULL) && (*mount_arg != '\0'))
		root = mount_arg;

	return(uml_strdup(root));
}

struct super_block *externfs_read_super(struct super_block *sb, void *data, 
					int silent)
{
	struct externfs *fs;
	struct inode *root_inode;
	struct externfs_data *sb_data;
	int err = -EINVAL;

	sb->s_blocksize = 1024;
	sb->s_blocksize_bits = 10;
	sb->s_magic = EXTERNFS_SUPER_MAGIC;
	sb->s_op = &externfs_sbops;

	fs = find_externfs(sb->s_type);
	if(fs == NULL){
		printk("Couldn't find externfs for filesystem '%s'\n",
		       sb->s_type->name);
		goto out;
	}

	sb_data = (*fs->mount_ops->mount)(data);
	if(IS_ERR(sb_data)){
		err = PTR_ERR(sb_data);
		goto out;
	}

	sb->u.generic_sbp = sb_data;
	sb_data->mount_ops = fs->mount_ops;

	root_inode = get_inode(sb, NULL, 1);
	if(IS_ERR(root_inode))
		goto out;

	sb->s_root = d_alloc_root(root_inode);
	if(sb->s_root == NULL)
		goto out_put;

	if(read_inode(root_inode))
		goto out_dput;
	return(sb);

 out_dput:
	/* dput frees the inode */
	dput(sb->s_root);
	return(NULL);
 out_put:
	root_inode->i_nlink = 0;
	make_bad_inode(root_inode);
	iput(root_inode);
 out:
	return(NULL);
}

void init_externfs(struct externfs_data *ed, struct externfs_file_ops *ops)
{
	ed->file_ops = ops;
}

int register_externfs(char *name, struct externfs_mount_ops *mount_ops)
{
	struct externfs *new;
	int err = -ENOMEM;

	new = kmalloc(sizeof(*new), GFP_KERNEL);
	if(new == NULL)
		goto out;

	memset(new, 0, sizeof(*new));
	*new = ((struct externfs) { .list	= LIST_HEAD_INIT(new->list),
				    .mount_ops	= mount_ops,
				    .type = { .name	= name,
					      .read_super = externfs_read_super,
					      .fs_flags	= 0,
					      .owner	= THIS_MODULE } });
	list_add(&new->list, &externfses);

	err = register_filesystem(&new->type);
	if(err)
		goto out_del;
	return(0);

 out_del:
	list_del(&new->list);
	kfree(new);
 out:
	return(err);
}

void unregister_externfs(char *name)
{
	struct list_head *ele;
	struct externfs *fs;

	down(&externfs_sem);
	list_for_each(ele, &externfses){
		fs = list_entry(ele, struct externfs, list);
		if(!strcmp(fs->type.name, name)){
			list_del(ele);
			up(&externfs_sem);
			return;
		}
	}
	up(&externfs_sem);
	printk("Unregister_externfs - filesystem '%s' not found\n", name);
}

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
