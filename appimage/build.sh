#!/usr/bin/env bash
# Build FastCheckup-<version>-x86_64.AppImage (+ .zsync for delta updates) in the repo root.
# Needs: the system deps from AGENTS.md, a Rust toolchain, and `appimagetool` on PATH.
# Host libraries (fontconfig, xkbcommon, X11) are not bundled: every X11 desktop has them.
set -euo pipefail
cd "$(dirname "$0")/.."
id=io.github.evandro777.FastCheckup
version=$(grep -m1 '^version' Cargo.toml | cut -d'"' -f2)
out=FastCheckup-$version-x86_64.AppImage

cargo build --release --locked

rm -rf appimage/AppDir
d=appimage/AppDir
install -Dm755 target/release/fastcheckup "$d/usr/bin/fastcheckup"
install -Dm644 packaging/$id.desktop "$d/usr/share/applications/$id.desktop"
install -Dm644 packaging/$id.svg "$d/usr/share/icons/hicolor/scalable/apps/$id.svg"
install -Dm644 packaging/$id.metainfo.xml "$d/usr/share/metainfo/$id.metainfo.xml"
# The Lucide icons are compiled into the binary; their ISC licence asks for the notice to travel with it.
install -Dm644 crates/app/ui/icons/LICENSE "$d/usr/share/doc/fastcheckup/LICENSE.lucide"
# appimagetool wants the desktop file and icon at the root too.
cp "$d/usr/share/applications/$id.desktop" "$d/usr/share/icons/hicolor/scalable/apps/$id.svg" "$d/"
ln -s usr/bin/fastcheckup "$d/AppRun"

# Update info: AppImageUpdate-style tools read it from the file and fetch the .zsync from the latest release.
ARCH=x86_64 appimagetool --no-appstream \
  -u "gh-releases-zsync|evandro777|FastCheckup|latest|FastCheckup-*x86_64.AppImage.zsync" "$d" "$out"
echo ">> $out and $out.zsync"
