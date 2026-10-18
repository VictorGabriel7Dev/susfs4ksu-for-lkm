// SPDX-License-Identifier: GPL-2.0
/*
 * sufs_stat_entry.c - stat/statx for the view, at the syscall entry.
 *
 * The open entry answers a routed name with the target, and the dirent layer adds a name that is
 * not on disk.  Without this file the same name would still stat as the real file - or fail - and
 * that is the mismatch the design calls the detection surface ("stat says it exists, open says
 * ENOENT").  So the two path-taking stat entries answer with the same three-way decision the table
 * gives:
 *
 *   - not routed: hand the call back to the kernel untouched;
 *   - routed, caller not accepted: the name exists on disk, and the kernel would describe the real
 *     file, so this layer answers -ENOENT itself - that is what hides it;
 *   - routed, accepted: stat the target and write its attributes into the caller's buffer.
 *
 * Only newfstatat and statx are wired, and only flags that name a path: AT_EMPTY_PATH names a file
 * by descriptor and has no view key, so it goes back.  The compat ABIs are not wired yet (the
 * layouts differ; the native entries are what this device's userspace uses).
 *
 * The result is laid out the way fs/stat.c's cp_new_stat()/cp_statx() do it.  Those are static
 * there, so the field copy is spelled out here - if a field is ever added to struct stat/statx,
 * this file is the place it has to be added too.
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/fcntl.h>	/* AT_SYMLINK_NOFOLLOW, AT_EMPTY_PATH */
#include <linux/namei.h>	/* LOOKUP_* */
#include <linux/path.h>
#include <linux/stat.h>		/* struct kstat, struct statx, STATX_BASIC_STATS */
#include <linux/uaccess.h>
#include <linux/err.h>
#include <linux/slab.h>		/* kstrdup/kmemdup_nul */
#include <linux/string.h>
#include <linux/kdev_t.h>	/* new_encode_dev, MAJOR/MINOR */
#include <linux/cred.h>		/* from_kuid_munged */
#include <linux/ptrace.h>
#include <asm/stat.h>		/* struct stat: the arm64/uapi layout */
#include <asm/unistd.h>		/* __NR_newfstatat, __NR_statx */

#include "susfs.h"		/* SUSFS_OR_PATH_MAX */
#include "sufs_router.h"
#include "susfs_log.h"
#include "symbol_resolver.h"
#include "sufs_stat_entry.h"

static bool st_ready;
static struct filename *(*st_getname_flags_fn)(const char __user *name, int flags, int *empty);
static int (*st_filename_lookup_fn)(int dfd, struct filename *name, unsigned flags,
				    struct path *path, struct path *root);
static void (*st_putname_fn)(struct filename *name);
static struct filename *(*st_getname_kernel_fn)(const char *name);
static int (*st_vfs_getattr_fn)(const struct path *path, struct kstat *stat,
				u32 request_mask, unsigned int query_flags);

/* The lookup flags for the name, translated the way fs/stat.c translates the caller's AT_* bits. */
static unsigned int st_lookup_flags(unsigned int flags)
{
	return (flags & AT_SYMLINK_NOFOLLOW) ? 0 : LOOKUP_FOLLOW;
}

/* Same split as or_entry's: the parent directory is prepared as a kernel string and resolved from
 * the caller's dfd, so relative names and dirfds keep their meaning.  Only called for a lookup
 * that already answered ENOENT, i.e. for the isolated shape. */
static __nocfi noinline bool st_route_missing(int dfd, const char *pathname,
					      char *target, size_t buflen)
{
	const char *slash, *base;
	struct filename *dname;
	struct path dpath;
	char *dirbuf;
	bool hit = false;

	slash = strrchr(pathname, '/');
	if (slash && !slash[1])		/* "dir/" names a directory, never a route */
		return false;
	base = slash ? slash + 1 : pathname;
	if (!*base || !strcmp(base, ".") || !strcmp(base, ".."))
		return false;
	if (!slash)
		dirbuf = kstrdup(".", GFP_KERNEL);
	else if (slash == pathname)
		dirbuf = kstrdup("/", GFP_KERNEL);
	else
		dirbuf = kmemdup_nul(pathname, (size_t)(slash - pathname), GFP_KERNEL);
	if (!dirbuf)
		return false;
	dname = st_getname_kernel_fn(dirbuf);
	kfree(dirbuf);
	if (IS_ERR_OR_NULL(dname))
		return false;
	if (!st_filename_lookup_fn(dfd, dname, LOOKUP_DIRECTORY | LOOKUP_FOLLOW,
				   &dpath, NULL)) {
		hit = sufs_router_match_parent(d_inode(dpath.dentry), base,
					       strlen(base), target, buflen);
		path_put(&dpath);
	}
	st_putname_fn(dname);
	return hit;
}

/* Resolve the name the caller passed and ask the table.  On HIT, target holds the path. */
static __nocfi noinline int st_probe(int dfd, const char __user *uname, unsigned int flags,
				     char *target, size_t buflen)
{
	struct filename *name;
	struct path path;
	int res, m;

	if (!st_ready || !uname || !sufs_router_active())
		return SUFS_ROUTE_MISS;
	if (flags & AT_EMPTY_PATH)
		return SUFS_ROUTE_MISS;
	name = st_getname_flags_fn(uname, 0, NULL);
	if (IS_ERR(name))
		return SUFS_ROUTE_MISS;
	res = st_filename_lookup_fn(dfd, name, st_lookup_flags(flags), &path, NULL);
	if (!res) {
		m = sufs_router_match_path(&path, target, buflen);
		path_put(&path);
	} else if (res == -ENOENT) {
		m = st_route_missing(dfd, name->name, target, buflen) ?
		    SUFS_ROUTE_HIT : SUFS_ROUTE_MISS;
	} else {
		m = SUFS_ROUTE_MISS;
	}
	st_putname_fn(name);
	return m;
}

/* cp_new_stat(), spelled out for the arm64 struct stat layout. */
static void st_fill_newstat(const struct kstat *ks, struct stat *tmp)
{
	memset(tmp, 0, sizeof(*tmp));
	tmp->st_dev = new_encode_dev(ks->dev);
	tmp->st_ino = ks->ino;
	tmp->st_mode = ks->mode;
	tmp->st_nlink = ks->nlink;
	tmp->st_uid = from_kuid_munged(current_user_ns(), ks->uid);
	tmp->st_gid = from_kgid_munged(current_user_ns(), ks->gid);
	tmp->st_rdev = new_encode_dev(ks->rdev);
	tmp->st_size = ks->size;
	tmp->st_blksize = ks->blksize;
	tmp->st_blocks = ks->blocks;
	tmp->st_atime = ks->atime.tv_sec;
	tmp->st_atime_nsec = ks->atime.tv_nsec;
	tmp->st_mtime = ks->mtime.tv_sec;
	tmp->st_mtime_nsec = ks->mtime.tv_nsec;
	tmp->st_ctime = ks->ctime.tv_sec;
	tmp->st_ctime_nsec = ks->ctime.tv_nsec;
}

/* cp_statx(), same reasoning.  stx_mask is what vfs_getattr() says it filled. */
static void st_fill_statx(const struct kstat *ks, struct statx *tmp)
{
	memset(tmp, 0, sizeof(*tmp));
	tmp->stx_mask = ks->mask;
	tmp->stx_blksize = ks->blksize;
	tmp->stx_attributes = ks->attributes;
	tmp->stx_attributes_mask = ks->attributes_mask;
	tmp->stx_nlink = ks->nlink;
	tmp->stx_uid = from_kuid_munged(current_user_ns(), ks->uid);
	tmp->stx_gid = from_kgid_munged(current_user_ns(), ks->gid);
	tmp->stx_mode = ks->mode;
	tmp->stx_ino = ks->ino;
	tmp->stx_size = ks->size;
	tmp->stx_blocks = ks->blocks;
	tmp->stx_atime.tv_sec = ks->atime.tv_sec;
	tmp->stx_atime.tv_nsec = ks->atime.tv_nsec;
	tmp->stx_btime.tv_sec = ks->btime.tv_sec;
	tmp->stx_btime.tv_nsec = ks->btime.tv_nsec;
	tmp->stx_ctime.tv_sec = ks->ctime.tv_sec;
	tmp->stx_ctime.tv_nsec = ks->ctime.tv_nsec;
	tmp->stx_mtime.tv_sec = ks->mtime.tv_sec;
	tmp->stx_mtime.tv_nsec = ks->mtime.tv_nsec;
	tmp->stx_rdev_major = MAJOR(ks->rdev);
	tmp->stx_rdev_minor = MINOR(ks->rdev);
	tmp->stx_dev_major = MAJOR(ks->dev);
	tmp->stx_dev_minor = MINOR(ks->dev);
#ifdef STATX_MNT_ID
	tmp->stx_mnt_id = ks->mnt_id;
#endif
}

static __nocfi noinline bool st_answer_newstat(unsigned long statbuf, const char *target,
					       long *out)
{
	struct path p;
	struct kstat ks;
	struct stat tmp;
	int err;

	if (kern_path(target, LOOKUP_FOLLOW, &p)) {
		*out = -ENOENT;
		return true;
	}
	err = st_vfs_getattr_fn(&p, &ks, STATX_BASIC_STATS, 0);
	path_put(&p);
	if (err) {
		*out = err;
		return true;
	}
	st_fill_newstat(&ks, &tmp);
	*out = copy_to_user((void __user *)statbuf, &tmp, sizeof(tmp)) ? -EFAULT : 0;
	return true;
}

static __nocfi noinline bool st_answer_statx(unsigned long sbuf, unsigned int mask,
					     const char *target, long *out)
{
	struct path p;
	struct kstat ks;
	struct statx tmp;
	int err;

	if (mask & STATX__RESERVED) {	/* the kernel answers EINVAL, and so must this layer */
		*out = -EINVAL;
		return true;
	}
	if (!mask)
		mask = STATX_BASIC_STATS;
	if (kern_path(target, LOOKUP_FOLLOW, &p)) {
		*out = -ENOENT;
		return true;
	}
	err = st_vfs_getattr_fn(&p, &ks, mask, 0);
	path_put(&p);
	if (err) {
		*out = err;
		return true;
	}
	/* generic_fillattr() does not set ->mask on every tree; claiming the fields that were asked
	 * for is what the kernel's own statx does with a filesystem that leaves it at zero. */
	if (!ks.mask)
		ks.mask = mask;
	st_fill_statx(&ks, &tmp);
	*out = copy_to_user((void __user *)sbuf, &tmp, sizeof(tmp)) ? -EFAULT : 0;
	return true;
}

bool susfs_stat_pre(long nrval, bool compat, const struct pt_regs *regs, long *out)
{
	char target[SUSFS_OR_PATH_MAX];
	unsigned int flags;
	int dfd, m;

	if (!st_ready || compat)
		return false;

	switch (nrval) {
	case __NR_newfstatat:
		dfd = (int)regs->regs[0];
		flags = (unsigned int)regs->regs[3];
		/* The kernel answers an unknown flag with EINVAL before it looks at anything; a call
		 * this layer would answer instead must not turn that into success. */
		if (flags & ~(AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT | AT_EMPTY_PATH))
			return false;
		m = st_probe(dfd, (const char __user *)regs->regs[1], flags,
			     target, sizeof(target));
		if (m == SUFS_ROUTE_MISS)
			return false;
		if (m == SUFS_ROUTE_DENIED) {
			*out = -ENOENT;
			return true;
		}
		return st_answer_newstat(regs->regs[2], target, out);
	case __NR_statx:
		dfd = (int)regs->regs[0];
		flags = (unsigned int)regs->regs[2];
		if (flags & ~(AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT | AT_EMPTY_PATH |
			      AT_STATX_SYNC_TYPE))
			return false;
		m = st_probe(dfd, (const char __user *)regs->regs[1], flags,
			     target, sizeof(target));
		if (m == SUFS_ROUTE_MISS)
			return false;
		if (m == SUFS_ROUTE_DENIED) {
			*out = -ENOENT;
			return true;
		}
		return st_answer_statx(regs->regs[4], (unsigned int)regs->regs[3],
				       target, out);
	default:
		return false;
	}
}

int susfs_stat_entry_init(void)
{
	st_getname_flags_fn = (void *)find_kernel_symbol_exact("getname_flags");
	st_filename_lookup_fn = (void *)find_kernel_symbol_exact("filename_lookup");
	st_putname_fn = (void *)find_kernel_symbol_exact("putname");
	st_getname_kernel_fn = (void *)find_kernel_symbol_exact("getname_kernel");
	st_vfs_getattr_fn = (void *)find_kernel_symbol_exact("vfs_getattr");
	if (!st_getname_flags_fn || !st_filename_lookup_fn || !st_putname_fn ||
	    !st_getname_kernel_fn || !st_vfs_getattr_fn) {
		SUSFS_LOGI("stat_entry: not armed (getname_flags=%d filename_lookup=%d putname=%d getname_kernel=%d vfs_getattr=%d) - stat does not follow the view\n",
			   !!st_getname_flags_fn, !!st_filename_lookup_fn, !!st_putname_fn,
			   !!st_getname_kernel_fn, !!st_vfs_getattr_fn);
		return 0;
	}
	st_ready = true;
	smp_wmb();
	SUSFS_LOGI("stat_entry: newfstatat and statx follow the view\n");
	return 0;
}

void susfs_stat_entry_exit(void)
{
	WRITE_ONCE(st_ready, false);
	smp_mb();
}
