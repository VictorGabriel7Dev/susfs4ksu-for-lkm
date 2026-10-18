// SPDX-License-Identifier: GPL-2.0
/*
 * sufs_router.c - the jump table, and the only state the view has.
 *
 * A route is (parent inode, name) -> target path.  It says: for a caller the allow predicate
 * accepts, a lookup of that name in that directory is answered with the target; for everyone else
 * the name simply is not there.  Everything else in the view is a projection of this table:
 *
 *   - sufs_router_match_path()   the open entry (kernel/susfs_or_entry.c), which already resolved
 *                                the path, so the key falls out of path->dentry->d_parent + d_name
 *   - sufs_router_has_name()     the dirent layer, which must not emit the name for a caller the
 *                                predicate rejects (and does emit it for one it accepts)
 *   - sufs_router_format()       the status listing
 *
 * There is deliberately no filesystem here: the table is the view, and nothing has to be mounted,
 * no inode has to be created, and no dentry has to be kept alive - which is also why the dentry
 * lifetime problems of the first attempt cannot come back.
 *
 * Concurrency is the same shape the open_redirect table already uses: writers hold sufs_router_lock
 * and publish by filling the slot first and raising ->live last; readers take no lock and scan up
 * to READ_ONCE(sufs_nroutes).  A removed slot only clears ->live and is never reused, so a reader
 * that raced the removal can still finish its comparison safely.
 */
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/dcache.h>
#include <linux/fs.h>

#include "sufs_router.h"
#include "susfs.h"	/* SUSFS_OR_PATH_MAX */
#include "susfs_log.h"

struct sufs_route {
	char name[SUFS_ROUTE_NAME_MAX];
	char target[SUSFS_OR_PATH_MAX];
	unsigned long pino;	/* parent inode */
	dev_t pdev;
	unsigned long tino;	/* target inode, for the status listing and later joins */
	dev_t tdev;
	bool live;
};

static struct sufs_route sufs_routes[SUFS_ROUTE_MAX];
static int sufs_nroutes;	/* highest slot ever used, plus one: the scan bound */
static DEFINE_MUTEX(sufs_router_lock);
static atomic_t sufs_router_hits = ATOMIC_INIT(0);
/* Diagnostics: the last key a lookup missed with.  When a route exists but the entry cannot find
 * it, this is what says whether the key is wrong (parent inode) or the name is. */
static unsigned long sufs_router_last_pino;
static char sufs_router_last_name[SUFS_ROUTE_NAME_MAX];
static atomic_t sufs_router_misses = ATOMIC_INIT(0);

/* Caller holds sufs_router_lock. */
static int sufs_router_find_locked(unsigned long pino, const char *name, size_t len)
{
	int i;

	for (i = 0; i < sufs_nroutes; i++) {
		if (!READ_ONCE(sufs_routes[i].live))
			continue;
		if (sufs_routes[i].pino != pino)
			continue;
		if (strlen(sufs_routes[i].name) == len &&
		    !memcmp(sufs_routes[i].name, name, len))
			return i;
	}
	return -1;
}

/* The name part of a resolved path, without copying: dentry names are stable while the caller
 * holds a reference, which or_entry does for the duration of its call. */
bool sufs_router_match_path(const struct path *path, char *buf, size_t buflen)
{
	struct dentry *d;
	struct inode *pino_inode;
	int i;
	bool hit = false;

	if (!path || !path->dentry)
		return false;
	d = path->dentry;
	if (d->d_parent == d)		/* the root of a mount is not a routed name */
		return false;
	pino_inode = d_inode(d->d_parent);
	if (!pino_inode)
		return false;

	/* Recorded before the scan: on a miss this is exactly what was looked for. */
	sufs_router_last_pino = pino_inode->i_ino;
	strscpy(sufs_router_last_name, d->d_name.name, sizeof(sufs_router_last_name));
	atomic_inc(&sufs_router_misses);

	rcu_read_lock();
	for (i = 0; i < READ_ONCE(sufs_nroutes); i++) {
		struct sufs_route *r = &sufs_routes[i];

		if (!READ_ONCE(r->live))
			continue;
		if (r->pino != pino_inode->i_ino)
			continue;
		if (strlen(r->name) != d->d_name.len ||
		    memcmp(r->name, d->d_name.name, d->d_name.len))
			continue;
		if (strscpy(buf, r->target, buflen) < 0)
			continue;
		hit = true;
		break;
	}
	rcu_read_unlock();

	if (hit)
		atomic_inc(&sufs_router_hits);
	return hit;
}

/* For the dirent layer: does this directory carry a routed name at all, and is this one of them? */
bool sufs_router_has_name(const struct inode *dir, const char *name, size_t len)
{
	int i;
	bool hit = false;

	if (!dir)
		return false;
	rcu_read_lock();
	for (i = 0; i < READ_ONCE(sufs_nroutes); i++) {
		struct sufs_route *r = &sufs_routes[i];

		if (!READ_ONCE(r->live))
			continue;
		if (r->pino != dir->i_ino)
			continue;
		if (strlen(r->name) != len || memcmp(r->name, name, len))
			continue;
		hit = true;
		break;
	}
	rcu_read_unlock();
	return hit;
}

/* add: the view path must resolve (the target must too) - the same rule or_add() has, because a
 * route without a target inode could not be reported honestly by the status listing. */
int sufs_router_add(const char *view_path, const char *target_path)
{
	struct path vp, tp;
	struct inode *pi, *ti;
	int rc;

	if (!view_path || !target_path || !*view_path || !*target_path)
		return -EINVAL;

	rc = kern_path(view_path, LOOKUP_FOLLOW, &vp);
	if (rc)
		return rc;
	rc = kern_path(target_path, LOOKUP_FOLLOW, &tp);
	if (rc) {
		path_put(&vp);
		return rc;
	}
	pi = d_inode(vp.dentry->d_parent);
	ti = d_inode(tp.dentry);
	if (!pi || !ti) {
		path_put(&tp);
		path_put(&vp);
		return -ENOENT;
	}

	mutex_lock(&sufs_router_lock);
	if (sufs_router_find_locked(pi->i_ino, vp.dentry->d_name.name,
				    vp.dentry->d_name.len) >= 0) {
		mutex_unlock(&sufs_router_lock);
		path_put(&tp);
		path_put(&vp);
		return -EEXIST;
	}
	if (sufs_nroutes >= SUFS_ROUTE_MAX) {
		mutex_unlock(&sufs_router_lock);
		path_put(&tp);
		path_put(&vp);
		return -ENOSPC;
	}
	{
		struct sufs_route *r = &sufs_routes[sufs_nroutes];

		/* fill everything, then raise live: a lockless reader that sees live must see a
		 * complete route. */
		if (vp.dentry->d_name.len >= sizeof(r->name) ||
		    strscpy(r->target, target_path, sizeof(r->target)) < 0) {
			mutex_unlock(&sufs_router_lock);
			path_put(&tp);
			path_put(&vp);
			return -ENAMETOOLONG;
		}
		memcpy(r->name, vp.dentry->d_name.name, vp.dentry->d_name.len);
		r->name[vp.dentry->d_name.len] = '\0';
		r->pino = pi->i_ino;
		r->pdev = pi->i_sb->s_dev;
		r->tino = ti->i_ino;
		r->tdev = ti->i_sb->s_dev;
		smp_wmb();
		WRITE_ONCE(r->live, true);
		sufs_nroutes++;
	}
	mutex_unlock(&sufs_router_lock);

	SUSFS_LOGI("sufs_router: route %s -> %s (parent ino %lu)\n",
		   view_path, target_path, pi->i_ino);
	path_put(&tp);
	path_put(&vp);
	return 0;
}

void sufs_router_del(const char *view_path)
{
	struct path vp;
	struct inode *pi;
	int rc, i;

	if (!view_path || !*view_path)
		return;
	rc = kern_path(view_path, LOOKUP_FOLLOW, &vp);
	if (rc)
		return;
	pi = d_inode(vp.dentry->d_parent);
	if (!pi) {
		path_put(&vp);
		return;
	}

	mutex_lock(&sufs_router_lock);
	i = sufs_router_find_locked(pi->i_ino, vp.dentry->d_name.name,
				    vp.dentry->d_name.len);
	if (i >= 0) {
		WRITE_ONCE(sufs_routes[i].live, false);
		/* the slot is not reused: the scan bound only grows, so no reader can be left
		 * pointing at a slot whose contents changed under it. */
	}
	mutex_unlock(&sufs_router_lock);
	path_put(&vp);
}

int susfs_router_format(char *buf, size_t size)
{
	int i, n = 0;

	n += scnprintf(buf + n, size - n,
		       "sufs_router: %d route(s), hits=%d, misses=%d, last miss %lu/%s\n",
		       sufs_nroutes, atomic_read(&sufs_router_hits),
		       atomic_read(&sufs_router_misses),
		       sufs_router_last_pino, sufs_router_last_name);
	for (i = 0; i < sufs_nroutes && (size_t)n < size; i++) {
		if (!READ_ONCE(sufs_routes[i].live))
			continue;
		n += scnprintf(buf + n, size - n,
			       "  %lu/%s -> %s (target ino %lu)\n",
			       sufs_routes[i].pino, sufs_routes[i].name,
			       sufs_routes[i].target, sufs_routes[i].tino);
	}
	return n;
}