// SPDX-License-Identifier: GPL-2.0
/*
 * sufs_param.c - the view's commands as a module parameter
 *
 *     echo "expose /data/adb/x /data/adb/host/y" > /sys/module/susfs_guard_lkm/parameters/sufs
 *     echo "del /data/adb/x"                     > /sys/module/susfs_guard_lkm/parameters/sufs
 *     cat  /sys/module/susfs_guard_lkm/parameters/sufs
 *
 * Why a module parameter instead of a /proc node: the sysfs write path strips the trailing newline
 * before the callback sees the string (the shell's echo writes the text and the newline as two
 * separate write() calls, and a /proc write handler has to cope with the second, lone newline - the
 * first attempt at a /proc node got that wrong and made every "echo ... >" report failure after the
 * command had already been applied).  Permission 0600 keeps it root-only, and the whole
 * /sys/module/susfs_guard_lkm directory is already hidden by the hide_modules layer, so the
 * parameter does not add an observable surface.
 *
 * The grammar is one command per write, the first word being the verb.  The view itself is the
 * open_redirect rule table: "expose" is add_view_rule() and "del" is del_view_rule(), the same two
 * calls the /proc/susfs_open_redirect node offers.
 */
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/types.h>

#include "susfs.h"
#include "susfs_log.h"

#define SUFS_PARAM_MAX	768

static unsigned int sufs_param_oks;
static unsigned int sufs_param_errs;
static char sufs_param_last[96];

static void sufs_param_fail(const char *cmd, int err, char *out, size_t out_len)
{
	sufs_param_errs++;
	strscpy(sufs_param_last, cmd[0] ? cmd : "(empty)", sizeof(sufs_param_last));
	/* name + errno only: the full target path stays out of a channel other processes may read. */
	pr_err("susfs_guard_lkm: sufs param: \"%s\" failed %d\n", sufs_param_last, err);
	if (out && out_len)
		scnprintf(out, out_len, "err=%d\n", err);
}

static int sufs_param_set(const char *val, const struct kernel_param *kp)
{
	char cmd[SUFS_PARAM_MAX];
	char *verb, *rest;
	int rc;

	(void)kp;
	if (!val)
		return -EINVAL;
	strscpy(cmd, val, sizeof(cmd));

	/* sysfs already removed the newline; a command may still be empty. */
	verb = cmd;
	rest = strchr(cmd, ' ');
	if (rest) {
		*rest++ = '\0';
		while (*rest == ' ')
			rest++;
	} else {
		rest = cmd + strlen(cmd);
	}

	if (!strcmp(verb, "expose")) {
		char *view = rest;
		char *real = strchr(rest, ' ');

		if (!real) {
			rc = -EINVAL;
			goto fail;
		}
		*real++ = '\0';
		while (*real == ' ')
			real++;
		rc = (*view && *real) ? susfs_open_redirect_add_view_rule(view, real) : -EINVAL;
	} else if (!strcmp(verb, "del")) {
		if (*rest) {
			susfs_open_redirect_del_view_rule(rest);
			rc = 0;
		} else {
			rc = -EINVAL;
		}
	} else if (!strcmp(verb, "ping")) {
		rc = 0;
	} else {
		rc = -EINVAL;
	}

	if (!rc) {
		sufs_param_oks++;
		return 0;
	}
fail:
	sufs_param_fail(verb[0] ? verb : "(empty)", rc, NULL, 0);
	return rc;
}

static int sufs_param_get(char *buf, const struct kernel_param *kp)
{
	(void)kp;
	return scnprintf(buf, PAGE_SIZE,
			 "oks=%u errors=%u last=\"%s\"\n"
			 "commands: expose <view-path> <real-path> | del <view-path> | ping\n",
			 sufs_param_oks, sufs_param_errs, sufs_param_last);
}

static const struct kernel_param_ops sufs_param_ops = {
	.set = sufs_param_set,
	.get = sufs_param_get,
};

/* 0600: root only, and the directory itself is hidden by hide_modules. */
module_param_cb(sufs, &sufs_param_ops, NULL, 0600);
MODULE_PARM_DESC(sufs, "view commands: expose <view-path> <real-path> | del <view-path> | ping");
