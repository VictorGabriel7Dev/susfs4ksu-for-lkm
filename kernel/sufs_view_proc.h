/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __SUSFS_VIEW_PROC_H
#define __SUSFS_VIEW_PROC_H

/* Creates /proc/susfs_view, the view's command surface (expose / unexpose / ping).  Not fatal:
 * without it the commands are simply unreachable, everything else keeps working. */
int sufs_view_proc_init(void);
void sufs_view_proc_exit(void);

#endif /* __SUSFS_VIEW_PROC_H */
