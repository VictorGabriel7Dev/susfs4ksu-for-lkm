// SPDX-License-Identifier: GPL-2.0
/*
 * susfs_ctl.c - one control node, namespaced commands: /proc/susfs
 *
 * Replaces the per-layer nodes with a single surface.  A write is a command whose first word names
 * the subsystem, so the line says which layer it belongs to:
 *
 *     echo "sus_path add /data/adb/x"      > /proc/susfs
 *     echo "sus_path del /data/adb/x"      > /proc/susfs
 *     echo "sus_path clear"                > /proc/susfs
 *     echo "sus_mount add /data/adb/"      > /proc/susfs
 *     echo "hide_modules reset"            > /proc/susfs
 *     echo "sufs expose <view> <real>"     > /proc/susfs      (ours)
 *     echo "sufs del <view>"               > /proc/susfs      (ours)
 *
 * Each namespace forwards to the layer's existing command function, so the grammar those layers
 * already accept is unchanged - only the entry point moves.  Layers whose command surface is not
 * migrated yet keep their own node; this file does not pretend to own them.
 *
 * ro rules are not handled here on purpose: they exist only for the module's own nodes (the very
 * node this file creates is one), never as something a user can add.
 *
 * The node follows the module convention: 0777 mode plus a uid check in ->open() that answers
 * -ENOENT, because a restrictive mode would answer EACCES and advertise the node's existence.  It
 * is listed in susfs_self_hide_paths so the listing does not show it either.
 */
#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uaccess.h>

#include "susfs.h"
#include "susfs_log.h"

#define SUSFS_CTL_MAX	768

/* The layers' own command entry points.  Reused as-is: their grammar is what the old nodes
 * accepted, so callers see no difference beyond the namespace word. */
extern int sus_path_command(const char *val, int *removed_out);
extern int sus_mount_keep_command(const char *val, bool bare_list);
extern int hide_modules_command(const char *val, bool bare_list);

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
	} else if (!strcmp(ns, "sufs")) {
		char *view = rest, *real = ctl_take_word(rest);

		if (!strcmp(view, "expose")) {
			char *vp = real, *rp = ctl_take_word(real);

			rc = (*vp && *rp) ? susfs_open_redirect_add_view_rule(vp, rp) : -EINVAL;
		} else if (!strcmp(view, "del")) {
			rc = *real ? (susfs_open_redirect_del_view_rule(real), 0) : -EINVAL;
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

static ssize_t susfs_ctl_read(struct file *file, char __user *ubuf, size_t len, loff_t *pos)
{
	static const char banner[] =
		"susfs: one node, namespaced commands\n"
		"  sus_path add|del <path> | clear\n"
		"  sus_mount add|del <prefix> | set <p1,p2> | reset | clear\n"
		"  hide_modules reset|clear|<name>|list\n"
		"  sufs expose <view> <real> | del <view>\n";

	if (*pos)
		return 0;
	return simple_read_from_buffer(ubuf, len, pos, banner, sizeof(banner) - 1);
}

static int susfs_ctl_open(struct inode *inode, struct file *file)
{
	if (current_uid().val != 0)
		return -ENOENT;
	return 0;
}

static const struct proc_ops susfs_ctl_pops = {
	.proc_open	= susfs_ctl_open,
	.proc_read	= susfs_ctl_read,
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
