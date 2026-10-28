#!/system/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Load the susfs_guard_lkm .ko that matches the running GKI kernel, once, at boot.
MODDIR=${0%/*}
[ -f "$MODDIR/disable" ] && exit 0
[ -f "$MODDIR/remove" ] && exit 0
[ "$(getprop persist.sys.safemode)" != 1 ] || exit 0
[ "$(getprop ro.sys.safemode)" != 1 ] || exit 0
umask 077

# The KernelSU manager shows module.prop's description on the module card, so the outcome of
# the load is written there: a boot where this module failed and one where it worked must not
# look alike.  '#' is the sed delimiter because the text contains '-' (the KMI) but no '#'.
set_description() {
  prop="$MODDIR/module.prop"
  [ -f "$prop" ] || return 0
  sed -i "s#^description=.*#description=$1#" "$prop" 2>/dev/null
}

exec >"$MODDIR/load.log" 2>&1
echo "susfs_guard_lkm loader: $(date)"
# The /proc control nodes exist only while sus_path's LSM layer is installed, so
# their presence means susfs is already up (built-in or an earlier load). Do not stack.
if [ -e /proc/susfs_path ] || [ -d /sys/module/susfs_guard_lkm ]; then
  echo "susfs already present; nothing to do."
  set_description "already present (built-in or loaded earlier)"
  exit 0
fi
REL=$(cat /proc/sys/kernel/osrelease 2>/dev/null) || REL=""
[ -n "$REL" ] || REL="unknown"
. "$MODDIR/kmi.sh"
# A non-empty packaged override wins over the release string, but only when it
# names a KMI whose .ko is actually in this module.  The packaged file starts
# empty, and an empty value is the normal "automatic" path - not an error.
OVERRIDE=$(kmi_override_value "$MODDIR")
KMI=""
if [ -n "$OVERRIDE" ]; then
  KMI=$(select_kmi_override "$MODDIR")
  if [ -n "$KMI" ]; then
    MODE=custom
    echo "kmi_override: $KMI (kernel $REL)"
  else
    MODE=auto
    echo "kmi_override '$OVERRIDE' is not packaged; using automatic KMI detection"
  fi
else
  MODE=auto
fi
if [ "$MODE" = auto ]; then
  [ "$REL" != unknown ] || {
    echo "KMI detection failed: cannot read kernel release"
    set_description "❌ KMI detection failed: cannot read kernel release"
    exit 1
  }
  KMI=$(select_kmi "$REL" "$MODDIR") || {
    echo "KMI detection failed: no packaged .ko for kernel: $REL"
    set_description "❌ KMI detection failed: no packaged .ko for kernel $REL"
    exit 1
  }
fi
KO="$MODDIR/lib/susfs_guard_lkm-$KMI.ko"
[ -s "$KO" ] || {
  echo "KMI detection failed: missing .ko for $KMI"
  set_description "❌ KMI detection failed: missing .ko for $KMI"
  exit 1
}
echo "kernel $REL -> $KMI ($MODE)"
"$MODDIR/bin/susfs_insmod" "$KO" expose_proc=1
rc=$?
if [ "$rc" = 0 ]; then
  echo "loaded ($MODE)."
  if [ "$MODE" = custom ]; then
    set_description "✅ custom load ($KMI) | kernel $REL"
  else
    set_description "✅ auto-detected ($KMI) | kernel $REL"
  fi
else
  echo "susfs_insmod failed: $rc"
  set_description "❌ load failed [$MODE] ($KMI): susfs_insmod rc=$rc | kernel $REL"
fi
exit "$rc"
