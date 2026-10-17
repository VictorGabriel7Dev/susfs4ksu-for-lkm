// SPDX-License-Identifier: GPL-2.0
/*
 * susfs_ctl.c - one control node, namespaced commands: /proc/susfs
 *
 * A write is a command whose first word names the subsystem, so the line says which layer it
 * belongs to; each namespace forwards to that layer's own logic, so the grammar is unchanged and
 * only the entry point moves.  A read prints every layer's own listing, one section each - the
 * per-layer nodes answer through the same functions, so the two surfaces cannot drift.
 *
 *     echo "sus_path add /data/adb/x"   > /proc/susfs
 *     echo "sus_mount add /data/adb/"   > /proc/susfs
 *     echo "hide_modules reset"         > /proc/susfs
 *     echo "sufs expose <view> <real>"  > /proc/susfs
 *     echo "log 1"                      > /proc/susfs
 *     echo "unload 1"                   > /proc/susfs
 *     cat /proc/susfs                    # banner + every layer's listing
 *
 * ro rules are deliberately absent: they exist only for the module's own nodes (this one included),
 * never as something a user can add.
 *
 * The node follows the module convention: 0777 mode plus a uid check in ->open() answering
 * -ENOENT, because a restrictive mode would answer EACCES and advertise the node's existence.  It
 * is listed in susfs_self_hide_paths so the listing does not show it either.
 */
#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uaccess.h>

#include "susfs.h"
#include "susfs_log.h"

#define SUSFS_CTL_MAX	768

/* The layers' command entry points (their own grammar). */
extern int sus_path_command(const char *val, int *removed_out);
extern int sus_mount_keep_command(const char *val, bool bare_list);
extern int hide_modules_command(const char *val, bool bare_list);
extern int susfs_unload_request(void);
extern int kstat_command(char *cmd);
extern int avc_spoof_set(int on);
extern bool log_enabled;

/* The layers' listings.  They print through their own seq_file, so calling them on ours gives the
 * same bytes the old nodes return - no second formatter to keep in sync. */
extern int sus_path_proc_show(struct seq_file *m, void *v);
extern int sus_mount_keep_proc_show(struct seq_file *m, void *v);
extern int hide_modules_proc_show(struct seq_file *m, void *v);
extern int kstat_proc_show(struct seq_file *m, void *v);
extern int avc_proc_show(struct seq_file *m, void *v);
extern int opath_proc_show(struct seq_file *m, void *v);
extern int or_proc_show(struct seq_file *m, void *v);
extern int susfs_unload_show(struct seq_file *m, void *v);
extern int log_proc_show(struct seq_file *m, void *v);

#define CTL_SECTION(m, name, fn)	\
	do {				\
		seq_printf((m), "\n== %s ==\n", (name));	\
		(fn)((m), NULL);	\
	} while (0)

static int susfs_ctl_show(struct seq_file *m, void *v)
{
	seq_puts(m, "susfs: one node, namespaced commands\n"
		     "  sus_path add|del <path> | clear\n"
		     "  sus_mount add|del <prefix> | set <p1,p2> | reset | clear\n"
		     "  hide_modules reset|clear|<name>|list\n"
		     "  sufs expose <view> <real> | del <view>\n"
		     "  log 0|1\n"
		     "  kstat add_sus_kstat <path> | update_sus_kstat <path> | del <path> | clear\n"
		     "  avc 0|1\n"
		     "  unload 1\n");

	CTL_SECTION(m, "sus_path", sus_path_proc_show);
	CTL_SECTION(m, "sus_mount", sus_mount_keep_proc_show);
	CTL_SECTION(m, "hide_modules", hide_modules_proc_show);
	CTL_SECTION(m, "kstat", kstat_proc_show);
	CTL_SECTION(m, "avc_spoof", avc_proc_show);
	CTL_SECTION(m, "opath", opath_proc_show);
	CTL_SECTION(m, "open_redirect", or_proc_show);
	CTL_SECTION(m, "log", log_proc_show);
	CTL_SECTION(m, "unload", susfs_unload_show);
	return 0;
}

/* Split off the first word; returns the rest (never NULL) and terminates the first word. */
static char *ctl_take_word(char *s)
{
	char *p = strchr(s, ' ');

	if (!p)
		return s + strlen(s);
	*p++ = '\0';
	while (*p == ' ')
		p++;
	return p;
}

static ssize_t susfs_ctl_write(struct file *file, const char __user *buf, size_t len, loff_t *off)
{
	char cmd[SUSFS_CTL_MAX];
	char *ns, *rest;
	int rc;

	if (current_uid().val != 0)
		return -ENOENT;
	if (!len)
		return 0;
	if (len >= sizeof(cmd))
		return -EINVAL;
	if (copy_from_user(cmd, buf, len))
		return -EFAULT;
	cmd[len] = '\0';
	while (len && (cmd[len - 1] == '\n' || cmd[len - 1] == '\r'))
		cmd[--len] = '\0';

	ns = cmd;
	rest = ctl_take_word(cmd);

	if (!strcmp(ns, "sus_path")) {
		rc = sus_path_command(rest, NULL);
	} else if (!strcmp(ns, "sus_mount")) {
		rc = sus_mount_keep_command(rest, false);
	} else if (!strcmp(ns, "hide_modules")) {
		rc = hide_modules_command(rest, false);
	} else if (!strcmp(ns, "log")) {
		if (!strcmp(rest, "1")) {
			WRITE_ONCE(log_enabled, true);
			rc = 0;
		} else if (!strcmp(rest, "0")) {
			WRITE_ONCE(log_enabled, false);
			rc = 0;
		} else {
			rc = -EINVAL;
		}
	} else if (!strcmp(ns, "kstat")) {
		rc = kstat_command(rest);
	} else if (!strcmp(ns, "avc")) {
		rc = !strcmp(rest, "1") ? avc_spoof_set(1) :
		     !strcmp(rest, "0") ? avc_spoof_set(0) : -EINVAL;
	} else if (!strcmp(ns, "unload")) {
		rc = !strcmp(rest, "1") ? susfs_unload_request() : -EINVAL;
	} else if (!strcmp(ns, "sufs")) {
		char *verb = rest, *args = ctl_take_word(rest);

		if (!strcmp(verb, "expose")) {
			char *vp = args, *rp = ctl_take_word(args);

			rc = (*vp && *rp) ? susfs_open_redirect_add_view_rule(vp, rp) : -EINVAL;
		} else if (!strcmp(verb, "del")) {
			if (*args) {
				susfs_open_redirect_del_view_rule(args);
				rc = 0;
			} else {
				rc = -EINVAL;
			}
		} else {
			rc = -EINVAL;
		}
	} else {
		rc = -EINVAL;
	}

	if (rc) {
		pr_warn("susfs_guard_lkm: /proc/susfs: \"%s\" -> %d\n", ns, rc);
		return rc;
	}
	return len;
}

static int susfs_ctl_open(struct inode *inode, struct file *file)
{
	if (current_uid().val != 0)
		return -ENOENT;
	return single_open(file, susfs_ctl_show, NULL);
}

static const struct proc_ops susfs_ctl_pops = {
	.proc_open	= susfs_ctl_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
	.proc_write	= susfs_ctl_write,
};

static struct proc_dir_entry *susfs_ctl_node;

int susfs_ctl_init(void)
{
	susfs_ctl_node = proc_create("susfs", 0777, NULL, &susfs_ctl_pops);
	if (!susfs_ctl_node) {
		pr_warn("susfs_guard_lkm: /proc/susfs: proc_create failed - the unified control node is unavailable\n");
		return 0;	/* not fatal */
	}
	SUSFS_LOGI("susfs_ctl: /proc/susfs created\n");
	return 0;
}

void susfs_ctl_exit(void)
{
	if (susfs_ctl_node) {
		remove_proc_entry("susfs", NULL);
		susfs_ctl_node = NULL;
	}
}
