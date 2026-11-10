#!/usr/bin/env bash
# Renders pages of the app on a private Xvfb display with canned data (FASTCHECKUP_FIXTURES) and saves PNGs to
# target/ui-snapshots/<page>-<mode>.png. The real system is never scanned or changed.
# Usage: scripts/ui-snapshot.sh [page ...]   (names or numbers; default all)   MODES="empty single many" to narrow.
# STATE=expanded opens every disk's partitions (disk-health), or the swap/zram card (speed).
# Space (page 10; `leftovers` and `storage` are aliases of it) shows the disks and the clean-up tabs.
# STATE=group1|group2|group3 shows the Almost safe, Must analyze or Look only tab of Space (none = Safe).
# STATE=bulk0|bulk1 opens the bulk clean-up dialog of the Safe or Almost safe tab.
# STATE=bottom scrolls the Disk health (7) or System (13) page to its end.
# STATE=menu|about opens the sidebar menu or the About dialog on any page.
# STATE=sandboxed shows the "cannot reach the host" notice (Overview, page 9).
# STATE=admin-error shows the failed admin run on the Overview (the admin notice itself is always shown there).
# STATE=expanded|confirm opens a row or a confirm dialog (startup, services, apps; boot has confirm) -> <page>-<mode>-<state>.png.
set -euo pipefail
cd "$(dirname "$0")/.."

declare -A PAGES=([startup]=0 [services]=1 [boot]=2 [apps]=3 [leftovers]=10 [history]=5 [storage]=10 [disk-health]=7 [security]=8 [overview]=9 [space]=10 [safety]=11 [speed]=12 [system]=13)
MODES=${MODES:-"empty single many"}
OUT=target/ui-snapshots
DISPLAY_NUM=:99
mkdir -p "$OUT"
# Read by the app; unset (and so ignored) when STATE is empty.
[ -n "${STATE:-}" ] && export FASTCHECKUP_STATE=$STATE

cargo build --quiet

Xvfb "$DISPLAY_NUM" -screen 0 1280x800x24 >/dev/null 2>&1 &
XVFB=$!
APP=
cleanup() { [ -n "$APP" ] && kill "$APP" 2>/dev/null || true; kill "$XVFB" 2>/dev/null || true; }
trap cleanup EXIT
sleep 1

[ $# -gt 0 ] && names=("$@") || names=(overview space safety speed startup services boot apps history disk-health security system)

for name in "${names[@]}"; do
  page=${PAGES[$name]:-$name}
  for mode in $MODES; do
    DISPLAY=$DISPLAY_NUM FASTCHECKUP_FIXTURES=$mode FASTCHECKUP_PAGE=$page target/debug/fastcheckup >/dev/null 2>&1 &
    APP=$!
    for _ in $(seq 50); do
      DISPLAY=$DISPLAY_NUM xdotool search --name FastCheckup >/dev/null 2>&1 && break
      sleep 0.2
    done
    sleep 1
    DISPLAY=$DISPLAY_NUM import -window root "$OUT/$name-$mode${STATE:+-$STATE}.png"
    kill "$APP" 2>/dev/null || true
    wait "$APP" 2>/dev/null || true
    APP=
    echo "$OUT/$name-$mode${STATE:+-$STATE}.png"
  done
done
