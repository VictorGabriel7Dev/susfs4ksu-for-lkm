/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __SUFS_ROUTER_H
#define __SUFS_ROUTER_H

#include <linux/fs.h>
#include <linux/path.h>
#include <linux/types.h>

#define SUFS_ROUTE_MAX		32
#define SUFS_ROUTE_NAME_MAX	64

int sufs_router_add(const char *view_path, const char *target_path);
void sufs_router_del(const char *view_path);
bool sufs_router_match_path(const struct path *path, char *buf, size_t buflen);
bool sufs_router_has_name(const struct inode *dir, const char *name, size_t len);
int susfs_router_format(char *buf, size_t size);

#endif /* __SUFS_ROUTER_H */