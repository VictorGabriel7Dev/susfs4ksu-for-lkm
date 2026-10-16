/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __SUFS_FS_H
#define __SUFS_FS_H

#include <linux/types.h>

/*
 * sufs_fs - the "super user file system": the privileged view's backing store.
 *
 * A small, self-contained filesystem that is mounted under a 0xx0 host directory
 * (/data/misc/update_engine by default).  Non-root callers never reach it (the host's DAC
 * mode denies them at the host itself), so what an app sees is the kernel's own answer -
 * not an ENOENT this module forged.  Root/su callers get real inodes and real file objects.
 *
 * M1 scope: one node ("control") that answers a status line and accepts a command line.
 * The switch is privfs (default 0): with it off this file registers nothing, mounts nothing
 * and touches no other layer, i.e. the pre-existing behaviour is unchanged.
 */

int sufs_fs_init(void);
void sufs_fs_exit(void);

/* Non-zero only while the filesystem is registered (used by the layer teardown's own log). */
bool sufs_fs_registered(void);

#endif /* __SUFS_FS_H */
