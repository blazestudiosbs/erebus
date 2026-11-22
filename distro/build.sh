#!/usr/bin/env bash
# Erebus OS live-build wrapper. Debian/Ubuntu host + live-build required.
# This is a scaffold: review before running. It builds an ISO; it does NOT touch disks.
set -euo pipefail

EDITION="live"
ARCH="amd64"
usage() { echo "usage: $0 [--edition live|workstation] [--arch amd64|arm64]"; exit 1; }
while [ $# -gt 0 ]; do
  case "$1" in
    --edition) EDITION="${2:?}"; shift 2 ;;
    --arch)    ARCH="${2:?}";    shift 2 ;;
    -h|--help) usage ;;
    *) echo "unknown argument: $1"; usage ;;
  esac
done
case "$EDITION" in live|workstation) ;; *) echo "bad --edition: $EDITION"; usage ;; esac
case "$ARCH" in amd64|arm64) ;; *) echo "bad --arch: $ARCH"; usage ;; esac

command -v lb >/dev/null 2>&1 || {
  echo "error: live-build not installed. Run: sudo apt install live-build"; exit 1; }

HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="$HERE/.build-$EDITION-$ARCH"
rm -rf "$WORK"; mkdir -p "$WORK"; cd "$WORK"

echo "[*] configuring live-build ($EDITION / $ARCH)"
lb config \
  --architecture "$ARCH" \
  --distribution bookworm \
  --archive-areas "main contrib non-free non-free-firmware" \
  --debian-installer $([ "$EDITION" = workstation ] && echo live || echo none) \
  --bootappend-live "boot=live components $([ "$EDITION" = live ] && echo toram)"

mkdir -p config/package-lists config/includes.chroot
cp "$HERE/packages.list" config/package-lists/erebus.list.chroot
cp -r "$HERE/overlay/." config/includes.chroot/
# the authorized-use banner becomes the login banner
install -D -m644 config/includes.chroot/etc/issue.erebus config/includes.chroot/etc/issue

echo "[*] building (this takes a while and needs root)"
lb build

ISO="$(ls -1 *.iso 2>/dev/null | head -1 || true)"
[ -n "$ISO" ] && mv "$ISO" "$HERE/erebus-$EDITION-$ARCH.iso" \
  && echo "[+] wrote erebus-$EDITION-$ARCH.iso" \
  || { echo "error: no ISO produced — check the live-build logs in $WORK"; exit 1; }
