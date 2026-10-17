/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __SUSFS_KSU_ALLOW_GATE_H
#define __SUSFS_KSU_ALLOW_GATE_H

#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/types.h>

/* "Is this process one KernelSU would allow?" - asked OF KernelSU, not re-derived here.
 *
 * The question this answers is not "is it root".  KernelSU's own predicate is
 * kernel/policy/allowlist.c:
 *     bool __ksu_is_allow_uid_for_current(uid_t uid)
 *     {
 *         if (unlikely(uid == 0))
 *                 return is_ksu_domain();     // root only counts in the ksu domain
 *         return __ksu_is_allow_uid(uid);     // the allowlist, plus the manager app
 *     }
 * so one call covers the ksu-domain root, the manager and every su-granted uid - and it is the same
 * answer KernelSU itself acts on, instead of a re-implementation that can drift from it.
 *
 * This is deliberately NOT TIF_SYSCALL_TRACEPOINT / syscall_work: KernelSU sets that bit for every
 * process whose syscalls it wants to see (its own tp_marker.c marks zygote, the adb shell and - when
 * another tracer is present - every process), and the bit is inherited across fork with nothing
 * clearing it.  It answers "will KernelSU's hook run for this task", not "does KernelSU trust it". */

/* WHICH allow source is in force.  0 = none found (the strict fallback, uid 0 only),
 * 1 = KernelSU's __ksu_is_allow_uid_for_current.  This is the extension point: a second source -
 * another root solution's predicate, or an extra local rule - becomes case 2 in
 * susfs_ksu_allow_ask() without touching a single caller, because callers only ever see
 * susfs_ksu_allow_uid()/susfs_ksu_allow_current().  Set once by the init, read by everybody. */
extern int susfs_ksu_allow_kind;

/* The one indirect call, through the address resolved at load. */
bool susfs_ksu_allow_ask(uid_t uid);

/* The whole predicate for the current process.  Fail-safe on the STRICT side: without KernelSU's
 * symbol the answer is "real root only", so a missing or renamed KernelSU loses features (the
 * privileged view stops being visible to su) instead of leaking it to apps. */
static inline bool susfs_ksu_allow_uid(uid_t uid)
{
	if (READ_ONCE(susfs_ksu_allow_kind) == 0)
		return uid == 0;	/* nothing resolved: the strict answer, by design */

	return susfs_ksu_allow_ask(uid);
}

static inline bool susfs_ksu_allow_current(void)
{
	return susfs_ksu_allow_uid(current_uid().val);
}

int susfs_ksu_allow_gate_init(void);

#endif /* __SUSFS_KSU_ALLOW_GATE_H */