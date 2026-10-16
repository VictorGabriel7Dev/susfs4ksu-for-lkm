// SPDX-License-Identifier: GPL-2.0
/*
 * susfs_unload.c - /proc/susfs_unload: the module takes itself out.
 *
 * WHY THIS EXISTS
 * ---------------
 * A mounted filesystem holds a reference on the module that provides its fs_type
 * (get_fs_type() -> try_module_get()), so "rmmod while the privileged view is mounted" is
 * refused by the kernel with EAGAIN - and the module's own exit path never runs at all.  Asking
 * the module to leave therefore has to do two things, in this order: detach the mount (drop
 * that reference), then unload.  Writing 1 to this node does exactly that.
 *
 * WHY A USERSPACE HELPER DOES THE UNLOAD, AND NOT delete_module() FROM HERE
 * -----------------------------------------------------------------------
 * A module cannot safely unload itself: the exit function runs on the caller's stack inside
 * this module's text, and the module's memory is released before that stack unwinds - so the
 * return from such a call lands in freed code.  Linux has no self-unload primitive for exactly
 * that reason.  What IS safe is asking a userspace process to run rmmod: the helper is executed
 * by the kernel's own worker (code in kernel/umh.c, not in this module), so once this module's
 * text is gone, nothing that still runs belongs to it.
 *
 * The request is queued as TWA_RESUME task_work - it fires on the way back to userspace, i.e.
 * AFTER the write has completed - and UMH_NO_WAIT is mandatory: waiting would park this module's
 * code on a completion that only finishes once the module is gone.
 *
 * Everything handed to call_usermodehelper() is deliberately LEAKED (kstrdup'd strings, no
 * cleanup callback): the helper keeps the pointers, its worker runs after this module may
 * already be unloaded, and a .rodata string or a callback living in this module would be read
 * out of freed memory.
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/version.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/cred.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/task_work.h>
#include <linux/kmod.h>

#include "susfs.h"
#include "sufs_fs.h"
#include "susfs_log.h"

#define SUSFS_UNLOAD_NODE	"/proc/susfs_unload"

/* What the helper runs, as a SHELL COMMAND LINE - executed through /system/bin/sh -c rather than
 * as "path argv[1]".  Two reasons, both learned the hard way: the helper's own stdout/stderr go
 * nowhere observable, so the only way to tell "did not exec" from "ran and failed" is to let the
 * caller append diagnostics to the command line, e.g.
 *   unload_helper="rmmod susfs_guard_lkm; echo rc=$? > /data/local/tmp/umh.log; id >> ..."
 * and a plain argv form cannot express that. */
static char *susfs_unload_helper = "rmmod susfs_guard_lkm";
module_param_named(unload_helper, susfs_unload_helper, charp, 0600);

struct susfs_unload_req {
	struct callback_head cb;
};

static struct proc_dir_entry *susfs_unload_entry;
static atomic_t susfs_unload_requests = ATOMIC_INIT(0);
static atomic_t susfs_unload_failures = ATOMIC_INIT(0);

/* Runs on the way back to userspace, i.e. in atomic context - hence GFP_ATOMIC and
 * UMH_NO_WAIT.  Nothing below may touch module memory after call_usermodehelper() returns
 * except this function's own frame, which is on a kernel stack and not in the module. */
static void susfs_unload_task_work(struct callback_head *cb)
{
	struct susfs_unload_req *req = container_of(cb, struct susfs_unload_req, cb);
	char *path, *flag, *cmdline, *env_home, *env_path;
	char **argv, **envp;
	int rc;

	path = kstrdup("/system/bin/sh", GFP_ATOMIC);
	flag = kstrdup("-c", GFP_ATOMIC);
	cmdline = kstrdup(susfs_unload_helper, GFP_ATOMIC);
	env_home = kstrdup("HOME=/", GFP_ATOMIC);
	env_path = kstrdup("PATH=/sbin:/system/bin:/system/xbin", GFP_ATOMIC);
	argv = kmalloc_array(4, sizeof(char *), GFP_ATOMIC);
	envp = kmalloc_array(3, sizeof(char *), GFP_ATOMIC);
	if (!path || !flag || !cmdline || !env_home || !env_path || !argv || !envp) {
		atomic_inc(&susfs_unload_failures);
		pr_warn("susfs_unload: out of memory - run rmmod %s by hand (the view is already detached, so it will work)\n",
			SUSFS_LKM_MODULE_NAME);
		goto out;
	}
	argv[0] = path;
	argv[1] = flag;
	argv[2] = cmdline;
	argv[3] = NULL;
	envp[0] = env_home;
	envp[1] = env_path;
	envp[2] = NULL;

	rc = call_usermodehelper(path, argv, envp, UMH_NO_WAIT);
	if (rc) {
		atomic_inc(&susfs_unload_failures);
		pr_warn("susfs_unload: could not start the helper (%d) - run '%s' by hand (the view is already detached)\n",
			rc, susfs_unload_helper);
	} else {
		SUSFS_LOGI("susfs_unload: asked the kernel to run: %s\n", susfs_unload_helper);
	}
out:
	kfree(req);
}

static ssize_t susfs_unload_write(struct file *file, const char __user *buf, size_t len,
				  loff_t *off)
{
	struct susfs_unload_req *req;
	char tmp[8];
	int rc;

	/* Same convention as every other control node: 0777 so DAC never answers for us, and the
	 * uid check is what actually refuses (an fd opened before privileges were dropped too). */
	if (current_uid().val != 0)
		return -ENOENT;
	if (len == 0 || len >= sizeof(tmp))
		return -EINVAL;
	if (copy_from_user(tmp, buf, len))
		return -EFAULT;
	tmp[len] = '\0';
	if (tmp[0] != '1')
		return -EINVAL;

	/* 1. drop the reference the mounted view holds on this module - without this the kernel
	 *    refuses the unload and nothing else here matters. */
	rc = sufs_fs_detach();
	if (rc) {
		atomic_inc(&susfs_unload_failures);
		pr_warn("susfs_unload: detaching the view failed %d - not requesting the unload\n", rc);
		return rc;
	}

	/* 2. queue the unload for after this write returns. */
	req = kzalloc(sizeof(*req), GFP_KERNEL);
	if (!req) {
		atomic_inc(&susfs_unload_failures);
		return -ENOMEM;
	}
	init_task_work(&req->cb, susfs_unload_task_work);
	rc = task_work_add(current, &req->cb, TWA_RESUME);
	if (rc) {
		kfree(req);
		atomic_inc(&susfs_unload_failures);
		return rc;
	}
	atomic_inc(&susfs_unload_requests);
	SUSFS_LOGI("susfs_unload: view detached, unload queued (helper: %s)\n", susfs_unload_helper);
	return len;
}

static int susfs_unload_show(struct seq_file *m, void *v)
{
	seq_printf(m, "susfs_unload: helper=%s requests=%d failures=%d view_mounted=%d\n",
		   susfs_unload_helper, atomic_read(&susfs_unload_requests),
		   atomic_read(&susfs_unload_failures), sufs_fs_mounted() ? 1 : 0);
	return 0;
}

static int susfs_unload_open(struct inode *inode, struct file *file)
{
	if (current_uid().val != 0)
		return -ENOENT;
	return single_open(file, susfs_unload_show, NULL);
}

static const struct proc_ops susfs_unload_ops = {
	.proc_open = susfs_unload_open,
	.proc_read = seq_read,
	.proc_write = susfs_unload_write,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

int susfs_unload_init(void)
{
	if (!susfs_control_node_allowed())
		return 0;

	/* Bare name, like every other control node here: proc_create(..., NULL, ...) creates it
	 * directly under /proc, and passing the full "/proc/..." path made the kernel build a
	 * directory entry it then refused (the node never appeared, with a WARN naming it). */
	susfs_unload_entry = proc_create("susfs_unload", 0777, NULL, &susfs_unload_ops);
	if (!susfs_unload_entry) {
		pr_warn("susfs_unload: proc_create(%s) failed\n", SUSFS_UNLOAD_NODE);
		return -ENOMEM;
	}
	SUSFS_LOGI("susfs_unload: node %s ready\n", SUSFS_UNLOAD_NODE);
	return 0;
}

void susfs_unload_exit(void)
{
	if (susfs_unload_entry) {
		proc_remove(susfs_unload_entry);
		susfs_unload_entry = NULL;
	}
}