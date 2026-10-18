/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __SUFS_ROUTER_H
#define __SUFS_ROUTER_H

#include <linux/fs.h>
#include <linux/path.h>
#include <linux/types.h>

#define SUFS_ROUTE_MAX		32
#define SUFS_ROUTE_NAME_MAX	64

/* What the dirent layer needs to emit a routed name: the target's identity and its type, so the
 * injected record looks like the file it stands for. */
struct sufs_route_desc {
	char name[SUFS_ROUTE_NAME_MAX];
	u64 ino;
	unsigned int d_type;
};

/* What a resolved path means to an entry layer.  There are three answers, not two: "not routed"
 * hands the call back to the kernel, "routed but this caller is not accepted" must be answered
 * -ENOENT by the entry itself (for a name that really exists on disk that is the hiding), and
 * "routed and accepted" carries the target. */
enum {
	SUFS_ROUTE_MISS = 0,
	SUFS_ROUTE_HIT = 1,
	SUFS_ROUTE_DENIED = 2,
};

int sufs_router_add(const char *view_path, const char *target_path);
void sufs_router_del(const char *view_path);
bool sufs_router_active(void);
int sufs_router_match_path(const struct path *path, char *buf, size_t buflen);
bool sufs_router_match_parent(const struct inode *dir, const char *name, size_t len,
			      char *buf, size_t buflen);
bool sufs_router_has_name(const struct inode *dir, const char *name, size_t len);
int sufs_router_collect_dir(const struct inode *dir, struct sufs_route_desc *out, int max);
int susfs_router_format(char *buf, size_t size);

#endif /* __SUFS_ROUTER_H */