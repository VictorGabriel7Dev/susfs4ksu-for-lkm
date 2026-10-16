// SPDX-License-Identifier: GPL-2.0
/*
 * ksu_allow_gate.c - resolve KernelSU's allow predicate once, at load, and hand it to the layers.
 *
 * The address is resolved by NAME through kallsyms (kernel/symbol_resolver.c), the same way
 * ksu_umount_gate.c does it and for the same two reasons: a weak import is emitted as a GOT entry
 * that arm64's module relocator cannot handle (the module then refuses to load at all), and
 * resolving by name answers the environment question directly - the symbol is there or it is not.
 *
 * Two spellings are tried.  The SukiSU build on the test device exports the compiler-prefixed
 * __ksu_is_allow_uid_for_current; another fork may have it without the prefix.  A KernelSU loaded
 * after this module is not noticed until this module is reloaded, and one that is UNLOADED leaves
 * the saved address dangling - both are the same residual ksu_umount_gate.c already documents,
 * nothing here holds a module reference.
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>

#include "ksu_allow_gate.h"
#include "symbol_resolver.h"
#include "susfs_log.h"

static const char *const ksu_allow_symbols[] = {
	"__ksu_is_allow_uid_for_current",
	"ksu_is_allow_uid_for_current",
};

/* Written once in init, read by every caller through susfs_ksu_allow_current().  Non-NULL exactly
 * while susfs_ksu_allow_gate_off == false, which is what lets the inline above test the flag
 * instead of the pointer on every call. */
static bool (*ksu_allow_fn)(uid_t uid);

bool susfs_ksu_allow_gate_off = true;

/* noinline __nocfi: an indirect call through a resolved address.  CFI checks indirect call sites,
 * and LTO would otherwise inline a small static helper back into a caller that is not marked. */
bool __nocfi noinline susfs_ksu_allow_ask(uid_t uid)
{
	return ksu_allow_fn(uid);
}

int susfs_ksu_allow_gate_init(void)
{
	unsigned long addr = 0;
	const char *used = NULL;
	int i;

	for (i = 0; i < ARRAY_SIZE(ksu_allow_symbols); i++) {
		addr = ksu_kallsyms_lookup_name(ksu_allow_symbols[i]);
		if (addr) {
			used = ksu_allow_symbols[i];
			break;
		}
	}

	if (!addr) {
		susfs_ksu_allow_gate_off = true;
		/* pr_warn, not SUSFS_LOGI: "the allowlist predicate is not in effect on this device"
		 * is something an operator has to be able to see from the load alone. */
		pr_warn("susfs_guard_lkm: neither %s nor %s is in kallsyms - the privileged-view predicate falls back to uid == 0, so a su-granted app and the manager app are NOT covered here.
",
			ksu_allow_symbols[0], ksu_allow_symbols[1]);
		return 0;
	}

	ksu_allow_fn = (bool (*)(uid_t))addr;
	susfs_ksu_allow_gate_off = false;	/* only now is there something to ask */
	SUSFS_LOGI("ksu_allow_gate: resolved %s at %px - the privileged-view predicate now answers KernelSU
",
		   used, (void *)addr);
	return 0;
}
