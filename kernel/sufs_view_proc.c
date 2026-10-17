// SPDX-License-Identifier: GPL-2.0
/*
 * sufs_view_proc.c - the proc command surface of the view: /proc/susfs_view
 *
 * This is the first step of the migration and deliberately the smallest one: the view's commands
 * move onto a proc node whose path is OURS and therefore certain, while everything underneath
 * (open_redirect's rule table, the syscall-entry redirection, the old sus_path/sus_mount layers)
 * is left exactly as it was.  Nothing here invents a surface path: add_view_rule() resolves its
 * target with kern_path(), so the view path has to be a path that really exists today.
 *
 * The node follows the module's existing proc convention rather than inventing one:
 *   0777 mode + a uid check in ->open() that answers -ENOENT.
 * The mode is deliberately not 0600: a restrictive mode would answer EACCES to a non-root caller,
 * which advertises that the node exists, before this code gets the chance to answer "no such
 * file".  The name is listed in susfs_self_hide_paths so that the listing does not show it either.
 *
 * Commands (write):
 *   expose <view-path> <real-path>   mark an existing path as a view of real-path
 *   unexpose <view-path>             drop that view
 *   ping                            no-op
 * Failures are reported in dmesg (name + errno only - no full target, that stays out of a channel
 * other processes may read) and kept in a small ring that ->read() prints.
 */
#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uaccess.h>

#include "susfs.h"
#include "susfs_log.h"

#define SUFS_VIEW_CMD_MAX	512
#define SUFS_VIEW_ERRS		8

struct sufs_view_err {
	int err;
	char cmd[96];
};

static struct sufs_view_err sufs_view_errs[SUFS_VIEW_ERRS];
static unsigned int sufs_view_err_next;
static unsigned int sufs_view_err_total;
static unsigned int sufs_view_oks;
static DEFINE_MUTEX(sufs_view_lock);

static void sufs_view_record_error(const char *cmd, int err)
{
	struct sufs_view_err *e;

	mutex_lock(&sufs_view_lock);
	e = &sufs_view_errs[sufs_view_err_next++ % SUFS_VIEW_ERRS];
	strscpy(e->cmd, cmd, sizeof(e->cmd));
	e->err = err;
	sufs_view_err_total++;
	mutex_unlock(&sufs_view_lock);
	/* dmesg keeps only the name and the errno: the full target path stays out of a channel other
	 * processes may be able to read. */
	pr_err("susfs_guard_lkm: sufs_view: \"%s\" failed %d\n", cmd, err);
}

static ssize_t sufs_view_read(struct file *file, char __user *ubuf, size_t len, loff_t *ppos)
{
	char *buf;
	int n = 0, i;
	ssize_t ret;

	if (*ppos)
		return 0;
	buf = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	mutex_lock(&sufs_view_lock);
	n += scnprintf(buf + n, PAGE_SIZE - n,
			"sufs_view: oks=%u errors=%u last=\"%s\"\n",
			sufs_view_oks, sufs_view_err_total,
			sufs_view_errs[(sufs_view_err_next + SUFS_VIEW_ERRS - 1) % SUFS_VIEW_ERRS].cmd);
	for (i = 0; i < SUFS_VIEW_ERRS && i < sufs_view_err_total; i++) {
		unsigned int idx = (sufs_view_err_next + SUFS_VIEW_ERRS - 1 - i) % SUFS_VIEW_ERRS;

		if (!sufs_view_errs[idx].cmd[0])
			continue;
		n += scnprintf(buf + n, PAGE_SIZE - n, "  err %s -> -%d\n",
				sufs_view_errs[idx].cmd, -sufs_view_errs[idx].err);
	}
	mutex_unlock(&sufs_view_lock);

	ret = simple_read_from_buffer(ubuf, len, ppos, buf, n);
	kfree(buf);
	return ret;
}

static ssize_t sufs_view_write(struct file *file, const char __user *ubuf, size_t len,
			       loff_t *ppos)
{
	char *cmd;
	size_t n;
	int ret;

	if (!len)
		return 0;
	if (len > SUFS_VIEW_CMD_MAX)
		return -EINVAL;

	cmd = kzalloc(SUFS_VIEW_CMD_MAX, GFP_KERNEL);
	if (!cmd)
		return -ENOMEM;

	n = min(len, (size_t)SUFS_VIEW_CMD_MAX - 1);
	if (copy_from_user(cmd, ubuf, n)) {
		kfree(cmd);
		return -EFAULT;
	}
	while (n && (cmd[n - 1] == '\n' || cmd[n - 1] == '\r'))
		cmd[--n] = '\0';

	if (!strncmp(cmd, "expose ", 7)) {
		char *rest = cmd + 7, *view = rest, *real;

		real = strchr(rest, ' ');
		if (!real) {
			ret = -EINVAL;
			goto out_err;
		}
		*real++ = '\0';
		while (*real == ' ')
			real++;
		ret = susfs_open_redirect_add_view_rule(view, real);
		if (!ret) {
			mutex_lock(&sufs_view_lock);
			sufs_view_oks++;
			mutex_unlock(&sufs_view_lock);
		}
	} else if (!strncmp(cmd, "unexpose ", 9)) {
		/* del_view_rule() has nothing to report: a name that is not in the table is not an
		 * error for "make sure this view is gone". */
		susfs_open_redirect_del_view_rule(cmd + 9);
		mutex_lock(&sufs_view_lock);
		sufs_view_oks++;
		mutex_unlock(&sufs_view_lock);
		ret = 0;
	} else if (!strcmp(cmd, "ping")) {
		ret = 0;
	} else {
		ret = -EINVAL;
	}

out_err:
	if (ret)
		sufs_view_record_error(cmd, ret);
	kfree(cmd);
	return ret ? ret : (ssize_t)len;
}

static int sufs_view_open(struct inode *inode, struct file *file)
{
	if (current_uid().val != 0)
		return -ENOENT;
	return 0;
}

static const struct proc_ops sufs_view_pops = {
	.proc_open	= sufs_view_open,
	.proc_read	= sufs_view_read,
	.proc_write	= sufs_view_write,
};

static struct proc_dir_entry *sufs_view_node;

int sufs_view_proc_init(void)
{
	sufs_view_node = proc_create("susfs_view", 0777, NULL, &sufs_view_pops);
	if (!sufs_view_node) {
		pr_warn("susfs_guard_lkm: sufs_view: proc_create(susfs_view) failed - the view commands stay unreachable\n");
		return 0;	/* not fatal */
	}
	SUSFS_LOGI("sufs_view: /proc/susfs_view created\n");
	return 0;
}

void sufs_view_proc_exit(void)
{
	if (sufs_view_node) {
		remove_proc_entry("susfs_view", NULL);
		sufs_view_node = NULL;
	}
}