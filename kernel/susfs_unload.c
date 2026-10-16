// SPDX-License-Identifier: GPL-2.0
/*
 * susfs_unload.c - /proc/susfs_unload: ask the module to make itself unloadable.
 *
 * WHY THIS EXISTS
 * ---------------
 * A mounted filesystem holds a reference on the module that provides its fs_type
 * (get_fs_type() -> try_module_get()), so "rmmod while the privileged view is mounted" is refused
 * by the kernel with EAGAIN - and the module's own exit function never runs at all.  Writing 1
 * here detaches the view, which drops that reference; the unload is then an ordinary rmmod.
 *
 * WHY THE MODULE DOES NOT RMOD ITSELF
 * -----------------------------------
 * Two reasons, both measured on the device (PJA110 / 5.15.180 / Android 16):
 *
 *  1. It cannot do it from its own code.  An exit function runs inside this module's text, on the
 *     caller's stack, and the module's memory is released before that stack unwinds - so a
 *     self-unload returns into freed code.  Linux has no self-unload primitive for exactly this
 *     reason.
 *
 *  2. It cannot ask userspace to do it either - on no Android kernel.  call_usermodehelper()
 *     returns 0 and runs NOTHING here, because Android builds with
 *         CONFIG_STATIC_USERMODEHELPER=y
 *         CONFIG_STATIC_USERMODEHELPER_PATH=""
 *     and kernel/umh.c then replaces the requested path with that empty string
 *     (#ifdef CONFIG_STATIC_USERMODEHELPER: sub_info->path = CONFIG_STATIC_USERMODEHELPER_PATH).
 *     The worker sees path[0] == '\0' and completes without executing anything.  Measured: the
 *     request was queued ("asked the kernel to run ..." in the log), no process ever started, the
 *     file the helper was told to write never appeared, and no avc denial was logged - it was not
 *     refused, it was ignored.  (Verified against /proc/config.gz on the device.)
 *
 * So this node does the half a kernel module CAN do - release the reference - and says so
 * instead of pretending: after writing 1 the module is an ordinary unloadable module again.
 *
 *     echo 1 > /proc/susfs_unload && rmmod susfs_guard_lkm
 *
 * That is the intended way to take the privileged view (and the module) down.
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/version.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/cred.h>
#include <linux/atomic.h>

#include "susfs.h"
#include "sufs_fs.h"
#include "susfs_log.h"

#define SUSFS_UNLOAD_NODE	"/proc/susfs_unload"

static struct proc_dir_entry *susfs_unload_entry;
static atomic_t susfs_unload_requests = ATOMIC_INIT(0);
static atomic_t susfs_unload_failures = ATOMIC_INIT(0);
static bool susfs_unload_ready;

static ssize_t susfs_unload_write(struct file *file, const char __user *buf, size_t len,
				  loff_t *off)
{
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

	/* The whole point: drop the reference the mounted view holds on this module.  Without this
	 * the kernel refuses rmmod and nothing else here matters. */
	rc = sufs_fs_detach();
	if (rc) {
		atomic_inc(&susfs_unload_failures);
		pr_warn("susfs_unload: detaching the view failed %d - not marking the module unloadable\n", rc);
		return rc;
	}

	WRITE_ONCE(susfs_unload_ready, true);
	atomic_inc(&susfs_unload_requests);
	SUSFS_LOGI("susfs_unload: view detached - this module is an ordinary module again, unload it with 'rmmod %s'\n",
		   SUSFS_LKM_MODULE_NAME);
	return len;
}

static int susfs_unload_show(struct seq_file *m, void *v)
{
	seq_printf(m, "susfs_unload: requests=%d failures=%d ready=%d view_mounted=%d\n",
		   atomic_read(&susfs_unload_requests), atomic_read(&susfs_unload_failures),
		   READ_ONCE(susfs_unload_ready) ? 1 : 0, sufs_fs_mounted() ? 1 : 0);
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
