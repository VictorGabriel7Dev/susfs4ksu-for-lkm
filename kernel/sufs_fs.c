// SPDX-License-Identifier: GPL-2.0
/*
 * sufs_fs.c - sufs: the privileged view's backing filesystem (route A, milestone M1).
 *
 * WHAT THIS IS
 * ------------
 * One small filesystem of our own, mounted under a 0xx0 host directory.  The point is the
 * DIRECTION of the hiding: an unprivileged process is not told "ENOENT because we filtered
 * it" - it is stopped by the host directory's own DAC mode, i.e. by the kernel's real answer
 * about a directory that was always 0700 root.  Nothing here forges a negative result.
 *
 * Why a real filesystem instead of a synthesized struct file (route B): the privileged side
 * then gets REAL inodes and REAL struct file objects, so stat/read/write/lseek/mmap/fdinfo
 * all keep working by construction, and no syscall return path has to be intercepted.  See
 * the M0 report for the full comparison.
 *
 * WHY IT IS SAFE ON RKP/proca DEVICES
 * -----------------------------------
 * Nothing in this file writes read-only-after-init kernel memory: registering a filesystem
 * type and mounting it are ordinary kernel API calls, and the mount-table hiding it asks for
 * (sus_mount) is a kprobe layer.  That is the mechanism the v2 design replaces the LSM slot
 * write with, so the #80 class of device (CONFIG_RKP/CONFIG_PROCA, a hook page EL2 refuses
 * to have written) is not affected by this layer at all.
 *
 * THE SWITCH
 * ----------
 * privfs=0 (the default) makes this whole file a no-op: no filesystem is registered, no
 * prefix is added to sus_mount's list, sus_mount_register() is not called, and the existing
 * /proc/susfs_* path keeps upstream's "the user enables it explicitly" semantics.  Only
 * privfs=1 arms the privileged view.
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/version.h>
#include <linux/fs.h>
#include <linux/fs_context.h>
#include <linux/dcache.h>
#include <linux/namei.h>
#include <linux/mount.h>
#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/cred.h>
#include <linux/mutex.h>
#include <linux/atomic.h>
#include <linux/statfs.h>

#include "sufs_fs.h"
#include "susfs.h"
#include "susfs_log.h"
#include "symbol_resolver.h"

#define SUFS_FS_NAME		"sufs"
#define SUFS_MNTPT_DEFAULT	"/data/misc/update_engine/sufs"
#define SUFS_CTL_NAME		"control"
#define SUFS_CTL_BUF		256
#define SUFS_MAGIC		0x53465553	/* "SUFS" */
/* Fixed inode numbers: the first is the root d_make_root() owns, the second is the one node.
 * Both are created once, in fill_super(), and then held by the dcache - nothing here is built on
 * demand (see sufs_make_ctl_inode() for the WARN that on-demand creation produced). */
#define SUFS_ROOT_INO		1
#define SUFS_CTL_INO		2

/* ---- the switch, and where the view is mounted ------------------------------------------
 * Both are 0600: they decide where a root-only view appears on the filesystem, which is not
 * something an unprivileged caller has any business steering.  The mount point must EXIST
 * (this milestone does not create directories in the kernel: creating one means vfs_mkdir()
 * with a signature that changed in 6.6, and the host subdirectory is created once by the
 * loader/test script instead - see the M1 report). */
static bool sufs_privfs;
module_param_named(privfs, sufs_privfs, bool, 0600);

static char *sufs_mnt_point = SUFS_MNTPT_DEFAULT;
module_param_named(privfs_mnt, sufs_mnt_point, charp, 0600);

static bool sufs_is_registered;
/* Only the >= 5.12 build can mount (see the path_mount note below), so the flag lives inside the
 * same gate: an unreferenced variable is a build failure on the GKI trees (CONFIG_WERROR). */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
static bool sufs_is_mounted;
#endif

bool sufs_fs_registered(void)
{
	return sufs_is_registered;
}

/* ---- the one node ------------------------------------------------------------------------
 * "control" is a regular file: cat it for a status line, write a command line to it.  The
 * content lives in module memory (no page cache, no backing store), which is exactly the
 * point - it disappears with the module and leaves nothing on disk. */
static DEFINE_MUTEX(sufs_ctl_lock);
static char sufs_ctl_last[SUFS_CTL_BUF];
static size_t sufs_ctl_last_len;
static atomic_t sufs_ctl_reads = ATOMIC_INIT(0);
static atomic_t sufs_ctl_writes = ATOMIC_INIT(0);
static atomic_t sufs_ctl_denied = ATOMIC_INIT(0);

/* The timestamps are spelled three ways across the trees this module is built for, and no
 * spelling is a superset of another:
 *   - below 6.6 the three fields are plain members;
 *   - 6.6 made i_ctime private (__i_ctime) and added the setter for it, while i_atime/mtime
 *     were still direct members;
 *   - 6.11 split i_atime/mtime into sec/nsec pairs, so from 6.12 (the next GKI tree in the
 *     matrix) only the accessors compile.
 * The one-call helper for this (simple_inode_init_ts) is not present in every tree the matrix
 * builds, so this gate is the portable spelling. */
static void sufs_set_times(struct inode *inode)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
	struct timespec64 now = current_time(inode);

	inode_set_ctime_to_ts(inode, now);
	inode_set_atime_to_ts(inode, now);
	inode_set_mtime_to_ts(inode, now);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
	inode->i_atime = inode->i_mtime = current_time(inode);
	inode_set_ctime_current(inode);
#else
	inode->i_atime = inode->i_mtime = inode->i_ctime = current_time(inode);
#endif
}

static ssize_t sufs_ctl_read(struct file *file, char __user *buf, size_t len, loff_t *ppos)
{
	char tmp[SUFS_CTL_BUF];
	int n;

	mutex_lock(&sufs_ctl_lock);
	n = scnprintf(tmp, sizeof(tmp),
		      "sufs: node=%s privfs=%d reads=%d writes=%d denied=%d last=\"%s\"\n",
		      SUFS_CTL_NAME, sufs_privfs ? 1 : 0,
		      atomic_read(&sufs_ctl_reads), atomic_read(&sufs_ctl_writes),
		      atomic_read(&sufs_ctl_denied),
		      sufs_ctl_last_len ? sufs_ctl_last : "(none)");
	mutex_unlock(&sufs_ctl_lock);

	atomic_inc(&sufs_ctl_reads);
	return simple_read_from_buffer(buf, len, ppos, tmp, n);
}

static ssize_t sufs_ctl_write(struct file *file, const char __user *buf, size_t len,
			      loff_t *ppos)
{
	char tmp[SUFS_CTL_BUF];
	size_t n;

	if (!len)
		return 0;

	/* The node is 0600 root, and this is the second lock on the same door (same convention as
	 * the /proc/susfs_* handlers): an fd opened before privileges were dropped must not become
	 * a way in either. */
	if (current_uid().val != 0) {
		atomic_inc(&sufs_ctl_denied);
		return -ENOENT;
	}

	n = min(len, sizeof(tmp) - 1);
	if (copy_from_user(tmp, buf, n))
		return -EFAULT;
	tmp[n] = '\0';
	while (n && (tmp[n - 1] == '\n' || tmp[n - 1] == '\r'))
		tmp[--n] = '\0';

	mutex_lock(&sufs_ctl_lock);
	memcpy(sufs_ctl_last, tmp, n + 1);
	sufs_ctl_last_len = n;
	mutex_unlock(&sufs_ctl_lock);

	atomic_inc(&sufs_ctl_writes);
	SUSFS_LOGI("sufs_fs: control write \"%s\"\n", tmp);
	return len;
}

static const struct file_operations sufs_ctl_fops = {
	.owner = THIS_MODULE,
	.read = sufs_ctl_read,
	.write = sufs_ctl_write,
	/* no_llseek was renamed noop_llseek in 6.12, and leaving the member out is not the same
	 * thing either (vfs_llseek() substitutes its own default), so both names are spelled. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
	.llseek = noop_llseek,
#else
	.llseek = no_llseek,
#endif
};

/* The one node, built ONCE by sufs_fill_super() and then held by the dcache under its own
 * name.  It is deliberately NOT created on demand in ->lookup: the first version did that
 * (iget_locked() + d_splice_alias()) and every unmount that had followed an open() reported
 *   BUG: Dentry ...{i=2,n=control} still in use (-1) [unmount of sufs sufs]
 *   VFS: Busy inodes after unmount of sufs. Self-destruct in 5 seconds.
 * - the dentry/inode lifetime of a hand-rolled dynamic node is easy to get wrong, and this
 * filesystem does not need one: its node set is fixed and known at mount time. */
static struct inode *sufs_make_ctl_inode(struct super_block *sb)
{
	struct inode *inode = new_inode(sb);

	if (!inode)
		return NULL;
	inode->i_ino = SUFS_CTL_INO;
	inode->i_mode = S_IFREG | 0600;
	inode->i_uid = GLOBAL_ROOT_UID;
	inode->i_gid = GLOBAL_ROOT_GID;
	inode->i_fop = &sufs_ctl_fops;
	inode->i_size = 0;
	sufs_set_times(inode);
	return inode;
}

/* A lookup that gets here is a miss by definition - everything this filesystem has is already in
 * the dcache (see sufs_fill_super()) - so the honest answer is a negative dentry.  The method
 * itself must exist: the VFS refuses to call into a directory whose i_op has no ->lookup. */
static struct dentry *sufs_lookup(struct inode *dir, struct dentry *dentry, unsigned int flags)
{
	return NULL;
}

static const struct inode_operations sufs_dir_iops = {
	.lookup = sufs_lookup,
};

/* s_op must not be NULL: alloc_inode() dereferences it (fs/inode.c), so a filesystem without
 * one crashes on the first inode allocation.  There is deliberately no .drop_inode: the default
 * (evict once i_nlink reaches 0) is what generic_delete_inode() did, and that symbol is gone
 * from 6.12 on; the node's single cached inode makes accumulating anything impossible. */
static const struct super_operations sufs_sops = {
	.statfs = simple_statfs,
};

static int sufs_fill_super(struct super_block *sb, struct fs_context *fc)
{
	struct inode *root, *ctl;
	struct dentry *cd;

	sb->s_magic = SUFS_MAGIC;
	sb->s_op = &sufs_sops;
	sb->s_time_gran = 1;

	root = new_inode(sb);
	if (!root)
		return -ENOMEM;
	root->i_ino = SUFS_ROOT_INO;
	root->i_mode = S_IFDIR | 0700;
	root->i_uid = GLOBAL_ROOT_UID;
	root->i_gid = GLOBAL_ROOT_GID;
	root->i_op = &sufs_dir_iops;
	root->i_fop = &simple_dir_operations;
	set_nlink(root, 2);
	sufs_set_times(root);

	/* d_make_root() consumes the reference (it iputs on failure), so the error path must not. */
	sb->s_root = d_make_root(root);
	if (!sb->s_root)
		return -ENOMEM;

	/* The node: inode and dentry both built here, the dentry bound into the dcache before anyone
	 * can look for it.  d_add() consumes the inode reference, so the failure path is the only
	 * place that has to iput(). */
	ctl = sufs_make_ctl_inode(sb);
	if (!ctl)
		return -ENOMEM;
	cd = d_alloc_name(sb->s_root, SUFS_CTL_NAME);
	if (!cd) {
		iput(ctl);
		return -ENOMEM;
	}
	d_add(cd, ctl);
	return 0;
}

/* The fs_context path, not the legacy .mount callback: mount_nodev() - the helper the old shape
 * is written with - is gone from the 6.12/6.18 trees, and this is the path sys_mount() and
 * path_mount() take anyway. */
static int sufs_get_tree(struct fs_context *fc)
{
	return get_tree_nodev(fc, sufs_fill_super);
}

static const struct fs_context_operations sufs_fs_context_ops = {
	.get_tree = sufs_get_tree,
};

static int sufs_init_fs_context(struct fs_context *fc)
{
	fc->ops = &sufs_fs_context_ops;
	return 0;
}

static struct file_system_type sufs_fs_type = {
	.owner = THIS_MODULE,
	.name = SUFS_FS_NAME,
	.init_fs_context = sufs_init_fs_context,
	.kill_sb = kill_litter_super,
};

/* ---- mounting it ourselves ---------------------------------------------------------------
 * path_mount()/path_umount() are the internal entry points sys_mount()/sys_umount() use
 * (fs/namespace.c).  Both are global symbols but neither is exported, so they are resolved
 * from kallsyms at run time - like every other unexported name this module uses.  Called
 * through pointers, so both call sites carry __nocfi (kCFI would otherwise refuse the
 * indirect call: the module's own type hash for a kernel prototype is not the kernel's).
 *
 * 5.12 introduced path_mount() (before that sys_mount() did the work inline), so the 5.10
 * variants register the filesystem but leave mounting to userspace - the layer logs it
 * rather than pretending the view is up. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
typedef int (*sufs_path_mount_fn)(const char *dev_name, struct path *path,
				  const char *type_page, unsigned long flags,
				  void *data_page);
typedef int (*sufs_path_umount_fn)(struct path *path, int flags);

static sufs_path_mount_fn sufs_path_mount_p;
static sufs_path_umount_fn sufs_path_umount_p;

static bool sufs_resolve_mount_api(void)
{
	sufs_path_mount_p = (sufs_path_mount_fn)(void *)find_kernel_symbol_exact("path_mount");
	sufs_path_umount_p = (sufs_path_umount_fn)(void *)find_kernel_symbol_exact("path_umount");
	return sufs_path_mount_p && sufs_path_umount_p;
}

static __nocfi int sufs_do_mount(const char *mntpoint)
{
	struct path path;
	int rc;

	rc = kern_path(mntpoint, LOOKUP_FOLLOW | LOOKUP_DIRECTORY, &path);
	if (rc)
		return rc;
	if (!d_is_dir(path.dentry)) {
		path_put(&path);
		return -ENOTDIR;
	}
	rc = sufs_path_mount_p("none", &path, SUFS_FS_NAME, 0, NULL);
	path_put(&path);
	return rc;
}

static __nocfi int sufs_do_umount(const char *mntpoint, int flags)
{
	struct path path;
	int rc;

	/* ksys_umount()'s own lookup flags (fs/namespace.c): the mountpoint itself, as seen from the
	 * covering filesystem. */
	rc = kern_path(mntpoint, LOOKUP_FOLLOW | LOOKUP_MOUNTPOINT, &path);
	if (rc)
		return rc;
	/* NO path_put() here, and that is not an oversight: path_umount() consumes the path itself.
	 *   fs/namespace.c (identical in 5.15 and 6.6):
	 *     // we mustn't call path_put() as that would clear mnt_expiry_mark
	 *     dput(path->dentry);
	 *     mntput_no_expire(mnt);
	 * Putting it a second time released the root dentry twice, which is what the kernel then
	 * reported on the device:
	 *     BUG: Dentry ...{i=0,n=/} still in use (-128) [unmount of sufs sufs]
	 *     WARNING at fs/namespace.c:1193
	 * The path is handed over and forgotten. */
	rc = sufs_path_umount_p(&path, flags);
	return rc;
}
#endif /* >= 5.12 */

/* ---- detach / state ---------------------------------------------------------------------- */

bool sufs_fs_mounted(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
	return sufs_is_mounted;
#else
	return false;
#endif
}

/* Detach the mount WITHOUT unregistering the filesystem.  Idempotent, and the reason
 * /proc/susfs_unload can work at all: while this mount is up the superblock holds a reference on
 * this module (get_fs_type() -> try_module_get()), so the kernel refuses the unload with EAGAIN
 * until it is gone.
 *
 * -EINVAL/-ENOENT mean the path is not (or no longer) OUR mount - someone unmounted it from
 * userspace first - which is a SUCCESS here.  This branch is the difference between working and
 * a panic: the first version of this code read that -EINVAL as "cannot detach, hold the module
 * back", returned early from exit(), skipped unregister_filesystem(), and left the global
 * file_systems list pointing at freed module memory:
 *   filesystems_proc_show+0x50/0xa0 -> seq_read_iter -> __arm64_sys_read
 *   Kernel panic - not syncing: Oops: Fatal exception
 * i.e. a plain 'cat /proc/filesystems'.  A lazy detach is the fallback when something still
 * holds the mount; an open file cannot refuse it. */
int sufs_fs_detach(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
	int rc;

	if (!sufs_is_mounted)
		return 0;

	rc = sufs_do_umount(sufs_mnt_point, 0);
	if (rc == -EINVAL || rc == -ENOENT)
		rc = 0;
	if (rc) {
		rc = sufs_do_umount(sufs_mnt_point, MNT_DETACH);
		if (rc == -EINVAL || rc == -ENOENT)
			rc = 0;
	}
	if (!rc) {
		sufs_is_mounted = false;
		SUSFS_LOGI("sufs_fs: detached %s\n", sufs_mnt_point);
	}
	return rc;
#else
	return 0;
#endif
}

/* ---- layer entry points ------------------------------------------------------------------ */

int sufs_fs_init(void)
{
	int rc;

	if (!sufs_privfs) {
		SUSFS_LOGI("sufs_fs: privfs=0 - the privileged view stays off\n");
		return 0;
	}
	if (!sufs_mnt_point || sufs_mnt_point[0] != '/') {
		pr_warn("sufs_fs: privfs_mnt must be an absolute path\n");
		return -EINVAL;
	}

	rc = register_filesystem(&sufs_fs_type);
	if (rc) {
		pr_warn("sufs_fs: register_filesystem(\"%s\") failed %d\n", SUFS_FS_NAME, rc);
		return rc;
	}
	sufs_is_registered = true;
	SUSFS_LOGI("sufs_fs: registered \"%s\"\n", SUFS_FS_NAME);

	/* Hide it BEFORE it exists: the mount-time hook (kr_newmnt in sus_mount.c) and the enable
	 * scan both accept a mount whose mountpoint carries this prefix, and doing it in this
	 * order means the mount is never visible for a single moment.  An unhideable mount would
	 * be worse than no mount at all, so a failure here refuses to mount. */
	rc = sus_mount_privfs_arm(sufs_mnt_point);
	if (rc) {
		pr_warn("sufs_fs: sus_mount refused to hide %s (%d) - not mounting\n",
			sufs_mnt_point, rc);
		sufs_fs_exit();
		return rc;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
	if (!sufs_resolve_mount_api()) {
		pr_warn("sufs_fs: path_mount/path_umount not in kallsyms - mounting is left to userspace\n");
		return 0;
	}
	rc = sufs_do_mount(sufs_mnt_point);
	if (rc) {
		/* Reported, not fatal for the module: the filesystem is registered and the hiding is
		 * armed, so a userspace mount (or a second attempt after mkdir) still works. */
		pr_warn("sufs_fs: mount %s failed %d - mount it from userspace (mkdir first)\n",
			sufs_mnt_point, rc);
		return 0;
	}
	sufs_is_mounted = true;
	SUSFS_LOGI("sufs_fs: mounted \"%s\" at %s\n", SUFS_FS_NAME, sufs_mnt_point);
#else
	pr_warn("sufs_fs: this kernel (%d.%d) has no path_mount() - mount -t %s from userspace\n",
		LINUX_VERSION_CODE >> 16, (LINUX_VERSION_CODE >> 8) & 0xff, SUFS_FS_NAME);
#endif
	return 0;
}

void sufs_fs_exit(void)
{
	/* The mount has to be gone before the filesystem is unregistered, and a userspace umount
	 * may already have done it - sufs_fs_detach() is idempotent and treats "this is not our
	 * mount any more" as success (its comment records the panic that the opposite reading
	 * caused).  /proc/susfs_unload calls the very same function first, so both ways out of this
	 * module detach the same way. */
	(void)sufs_fs_detach();

	if (sufs_is_registered) {
		int rc = unregister_filesystem(&sufs_fs_type);

		/* NEVER skipped, and never a reason to hold the module back.  This one call decides
		 * whether the global file_systems list still points at this module's memory after the
		 * module is gone - and since exit runs after the kernel has already decided to unload
		 * us, there is no way to refuse from here (see the note above).  So: always try, and
		 * say loudly what state the list is left in if it fails. */
		if (rc) {
			pr_err("sufs_fs: unregister_filesystem failed %d - the file_systems list still references this module\n",
			       rc);
		} else {
			sufs_is_registered = false;
			SUSFS_LOGI("sufs_fs: unregistered\n");
		}
	}
}