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
 *   - sufs_router_has_name()     the dirent layer: wired for the hiding direction (a rejected
 *                                caller does not see the name in a listing); the injecting
 *                                direction - an accepted caller sees a name only the table carries
 *                                - belongs to the isolated shape and is not wired yet
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
#include <linux/stat.h>		/* S_ISREG/S_ISDIR: the injected record's d_type */
#include <linux/string.h>
#include <linux/slab.h>		/* kstrdup/kmemdup_nul: splitting the view path */
#include <linux/types.h>
#include <linux/dcache.h>
#include <linux/fs.h>

#include "sufs_router.h"
#include "ksu_allow_gate.h"	/* who is allowed to see the view */
#include "susfs.h"	/* SUSFS_OR_PATH_MAX */
#include "susfs_log.h"

struct sufs_route {
	char name[SUFS_ROUTE_NAME_MAX];
	char target[SUSFS_OR_PATH_MAX];
	unsigned long pino;	/* parent inode */
	dev_t pdev;
	unsigned long tino;	/* target inode, for the status listing and later joins */
	dev_t tdev;
	umode_t tmode;		/* target type, for the injected dirent's d_type */
	bool inject;		/* the name is not on disk: a listing has to add it */
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
static int sufs_router_find_locked(unsigned long pino, dev_t pdev,
				   const char *name, size_t len)
{
	int i;

	for (i = 0; i < sufs_nroutes; i++) {
		if (!READ_ONCE(sufs_routes[i].live))
			continue;
		if (sufs_routes[i].pino != pino)
			continue;
		if (sufs_routes[i].pdev != pdev)
			continue;
		if (strlen(sufs_routes[i].name) == len &&
		    !memcmp(sufs_routes[i].name, name, len))
			return i;
	}
	return -1;
}

/* Split a view path into the directory to resolve and the name inside it.  The name itself is
 * allowed not to exist: that is the isolated shape - for a caller the predicate rejects, the name
 * really is not there and the kernel answers ENOENT by itself, so nothing has to be hidden.  The
 * directory has to resolve, because that is where the name is looked up.
 *
 * Both pieces come back kstrdup'ed and the caller frees them.  A view path must be absolute: a
 * relative one would mean whatever the writing process's cwd meant, which is not a view. */
static int sufs_router_split(const char *view_path, char **dir, char **name)
{
	const char *slash;

	slash = strrchr(view_path, '/');
	if (!slash || !slash[1])	/* no name, or a trailing separator */
		return -EINVAL;
	*name = kstrdup(slash + 1, GFP_KERNEL);
	if (!*name)
		return -ENOMEM;
	if (slash == view_path)
		*dir = kstrdup("/", GFP_KERNEL);
	else
		*dir = kmemdup_nul(view_path, (size_t)(slash - view_path), GFP_KERNEL);
	if (!*dir) {
		kfree(*name);
		*name = NULL;
		return -ENOMEM;
	}
	return 0;
}

/* The record an injected dirent carries has to name a type, and the target is what the name stands
 * for: a directory route must read as a directory even though no inode of the view exists. */
static unsigned int sufs_dtype(umode_t mode)
{
	if (S_ISREG(mode))
		return DT_REG;
	if (S_ISDIR(mode))
		return DT_DIR;
	if (S_ISLNK(mode))
		return DT_LNK;
	if (S_ISCHR(mode))
		return DT_CHR;
	if (S_ISBLK(mode))
		return DT_BLK;
	if (S_ISFIFO(mode))
		return DT_FIFO;
	if (S_ISSOCK(mode))
		return DT_SOCK;
	return DT_UNKNOWN;
}

/* The name part of a resolved path, without copying: dentry names are stable while the caller
 * holds a reference, which or_entry does for the duration of its call. */
bool sufs_router_match_path(const struct path *path, char *buf, size_t buflen)
{
	struct dentry *d;
	struct inode *pino_inode;
	int i;
	bool hit = false;

	/* The predicate first: for a caller KernelSU does not accept, the route does not exist at
	 * all, and there is nothing to look up.  This is the whole difference between the two views -
	 * one question, one answer, and the table above is the only state either side reads. */
	if (!susfs_ksu_allow_current())
		return false;
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
		/* Same inode number on a different filesystem is a different directory; the key is
		 * (superblock, inode, name), and pdev is the superblock half. */
		if (r->pdev != pino_inode->i_sb->s_dev)
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

/* The entry layer's fast path: one load when the table is empty, which is the common case. */
bool sufs_router_active(void)
{
	return READ_ONCE(sufs_nroutes) > 0;
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
		if (r->pdev != dir->i_sb->s_dev)
			continue;
		if (strlen(r->name) != len || memcmp(r->name, name, len))
			continue;
		hit = true;
		break;
	}
	rcu_read_unlock();
	return hit;
}

/* The isolated shape's entry: the caller asked for a name that is not in the directory, so there
 * is no dentry to take the key from.  or_entry resolves the parent directory itself and hands over
 * the last component; the predicate is asked here, so to a caller it does not accept a routed name
 * is indistinguishable from an ordinary miss. */
bool sufs_router_match_parent(const struct inode *dir, const char *name, size_t len,
			      char *buf, size_t buflen)
{
	int i;
	bool hit = false;

	if (!susfs_ksu_allow_current())
		return false;
	if (!dir || !name || !len)
		return false;
	rcu_read_lock();
	for (i = 0; i < READ_ONCE(sufs_nroutes); i++) {
		struct sufs_route *r = &sufs_routes[i];

		if (!READ_ONCE(r->live))
			continue;
		if (r->pino != dir->i_ino || r->pdev != dir->i_sb->s_dev)
			continue;
		if (strlen(r->name) != len || memcmp(r->name, name, len))
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

/* The dirent side of the same shape: the routed names of this directory that the filesystem itself
 * does not emit.  Only slots marked inject come back - a name that is really there is already in
 * the listing and must not be added twice.  The scan is under rcu; the caller emits the records
 * outside of it, because copy_to_user() may sleep. */
int sufs_router_collect_dir(const struct inode *dir, struct sufs_route_desc *out, int max)
{
	int i, n = 0;

	if (!dir || !out || max <= 0)
		return 0;
	rcu_read_lock();
	for (i = 0; i < READ_ONCE(sufs_nroutes) && n < max; i++) {
		struct sufs_route *r = &sufs_routes[i];

		if (!READ_ONCE(r->live) || !r->inject)
			continue;
		if (r->pino != dir->i_ino || r->pdev != dir->i_sb->s_dev)
			continue;
		strscpy(out[n].name, r->name, sizeof(out[n].name));
		out[n].ino = r->tino;
		out[n].d_type = sufs_dtype(r->tmode);
		n++;
	}
	rcu_read_unlock();
	return n;
}

/* add: the view path's directory must resolve and the target must resolve; the view name itself
 * need not exist.  That is the isolated shape - the name is simply left absent on disk, so "it
 * does not exist" is the kernel's own answer for everyone the predicate rejects, and only the
 * privileged side is redirected.  `inject` records that a listing has to add the name. */
int sufs_router_add(const char *view_path, const char *target_path)
{
	struct path tp, vp;
	struct inode *pi, *ti;
	char *dir = NULL, *name = NULL;
	bool present;
	int rc;

	if (!view_path || !target_path || !*view_path || !*target_path)
		return -EINVAL;
	if (view_path[0] != '/')
		return -EINVAL;

	rc = kern_path(target_path, LOOKUP_FOLLOW, &tp);
	if (rc)
		return rc;
	ti = d_inode(tp.dentry);
	if (!ti) {
		path_put(&tp);
		return -ENOENT;
	}

	/* Probed before the split: a name that is there is emitted by the filesystem itself, and the
	 * dirent layer must not add it a second time.  A failed probe means absent. */
	present = (kern_path(view_path, LOOKUP_FOLLOW, &vp) == 0);
	if (present)
		path_put(&vp);

	rc = sufs_router_split(view_path, &dir, &name);
	if (rc) {
		path_put(&tp);
		return rc;
	}

	rc = kern_path(dir, LOOKUP_DIRECTORY | LOOKUP_FOLLOW, &vp);
	if (rc)
		goto out_free;
	pi = d_inode(vp.dentry);
	if (!pi) {
		rc = -ENOENT;
		goto out_put;
	}

	mutex_lock(&sufs_router_lock);
	if (sufs_router_find_locked(pi->i_ino, pi->i_sb->s_dev, name, strlen(name)) >= 0) {
		rc = -EEXIST;
		goto out_unlock;
	}
	if (sufs_nroutes >= SUFS_ROUTE_MAX) {
		rc = -ENOSPC;
		goto out_unlock;
	}
	{
		struct sufs_route *r = &sufs_routes[sufs_nroutes];

		/* fill everything, then raise live: a lockless reader that sees live must see a
		 * complete route. */
		if (strlen(name) >= sizeof(r->name) ||
		    strscpy(r->target, target_path, sizeof(r->target)) < 0) {
			rc = -ENAMETOOLONG;
			goto out_unlock;
		}
		strscpy(r->name, name, sizeof(r->name));
		r->pino = pi->i_ino;
		r->pdev = pi->i_sb->s_dev;
		r->tino = ti->i_ino;
		r->tdev = ti->i_sb->s_dev;
		r->tmode = ti->i_mode;
		r->inject = !present;
		smp_wmb();
		WRITE_ONCE(r->live, true);
		sufs_nroutes++;
	}
	mutex_unlock(&sufs_router_lock);

	SUSFS_LOGI("sufs_router: route %s -> %s (parent ino %lu%s)\n",
		   view_path, target_path, pi->i_ino, present ? ", name present" : "");
	rc = 0;
	goto out_put;

out_unlock:
	mutex_unlock(&sufs_router_lock);
out_put:
	path_put(&vp);
out_free:
	kfree(dir);
	kfree(name);
	path_put(&tp);
	return rc;
}

void sufs_router_del(const char *view_path)
{
	struct path vp;
	struct inode *pi;
	char *dir = NULL, *name = NULL;
	int i;

	/* The same split add() uses: the name itself need not exist, which is exactly the case this
	 * has to remove (the isolated shape leaves the name absent on disk). */
	if (!view_path || !*view_path || view_path[0] != '/')
		return;
	if (sufs_router_split(view_path, &dir, &name))
		return;
	if (kern_path(dir, LOOKUP_DIRECTORY | LOOKUP_FOLLOW, &vp))
		goto out_free;
	pi = d_inode(vp.dentry);
	if (pi) {
		mutex_lock(&sufs_router_lock);
		i = sufs_router_find_locked(pi->i_ino, pi->i_sb->s_dev, name, strlen(name));
		if (i >= 0) {
			WRITE_ONCE(sufs_routes[i].live, false);
			/* the slot is not reused: the scan bound only grows, so no reader can be
			 * left pointing at a slot whose contents changed under it. */
		}
		mutex_unlock(&sufs_router_lock);
	}
	path_put(&vp);
out_free:
	kfree(dir);
	kfree(name);
}

int susfs_router_format(char *buf, size_t size)
{
	int i, n = 0, nroutes = 0;

	/* live slots only: sufs_nroutes is the scan bound and only grows (a removed slot is never
	 * reused), so printing it said "1 route(s)" after the one route had been deleted. */
	for (i = 0; i < sufs_nroutes; i++) {
		if (READ_ONCE(sufs_routes[i].live))
			nroutes++;
	}
	n += scnprintf(buf + n, size - n,
		       "sufs_router: %d route(s), hits=%d, misses=%d, last miss %lu/%s\n",
		       nroutes, atomic_read(&sufs_router_hits),
		       atomic_read(&sufs_router_misses),
		       sufs_router_last_pino, sufs_router_last_name);
	for (i = 0; i < sufs_nroutes && (size_t)n < size; i++) {
		if (!READ_ONCE(sufs_routes[i].live))
			continue;
		n += scnprintf(buf + n, size - n,
			       "  %lu/%s -> %s (target ino %lu%s)\n",
			       sufs_routes[i].pino, sufs_routes[i].name,
			       sufs_routes[i].target, sufs_routes[i].tino,
			       sufs_routes[i].inject ? ", injected" : "");
	}
	return n;
}