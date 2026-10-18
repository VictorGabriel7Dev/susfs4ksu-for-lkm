/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __SUFS_STAT_ENTRY_H
#define __SUFS_STAT_ENTRY_H

#include <linux/ptrace.h>
#include <linux/types.h>

/* Called by the kstat wrappers before the original syscall runs.  Returns true when this layer
 * answered the call itself (the answer in *out); false hands the call back to the kernel.  Only
 * the path-taking stat entries are handled; fd-based ones and the compat ABIs return false. */
bool susfs_stat_pre(long nrval, bool compat, const struct pt_regs *regs, long *out);

int susfs_stat_entry_init(void);
void susfs_stat_entry_exit(void);

#endif /* __SUFS_STAT_ENTRY_H */
