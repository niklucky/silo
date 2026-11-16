#!/bin/sh
# Regenerates every app icon from branding/ (macOS only: uses swiftc, sips and the Tauri CLI).
#   pnpm brand:icons
set -eu
cd "$(dirname "$0")/.."
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
swiftc -O scripts/brand-icons.swift -o "$work/icons"
master=branding/app-icons/black/icon-1024.png

# macOS app icon: Apple's grid, an 824 px rounded square on a 1024 px canvas.
"$work/icons" tile "$master" "$work/macos.png" 1024 100 185

# Desktop (Tauri writes every size and format it bundles).
pnpm --filter @silo/desktop exec tauri icon "$work/macos.png" -o src-tauri/icons >/dev/null
rm -rf apps/desktop/src-tauri/icons/android apps/desktop/src-tauri/icons/ios
# Favicon for the desktop page when it runs in a plain browser.
cp branding/favicon/favicon.svg branding/favicon/favicon.ico apps/desktop/public/

# Browser extension: a full tile at toolbar sizes, Chrome's 8 px margin at 128.
for size in 16 32 48 96; do
  "$work/icons" tile "$master" "apps/extension/public/icon/$size.png" "$size" 0 "$(echo "$size * 0.22" | bc)"
done
"$work/icons" tile "$master" apps/extension/public/icon/128.png 128 8 24

# Safari container app.
set -- apps/safari/App/Assets.xcassets/AppIcon.appiconset
for size in 16 32 128 256 512; do
  sips -z "$size" "$size" "$work/macos.png" --out "$1/mac-icon-$size@1x.png" >/dev/null
  double=$((size * 2))
  sips -z "$double" "$double" "$work/macos.png" --out "$1/mac-icon-$size@2x.png" >/dev/null
done
sips -z 256 256 "$work/macos.png" --out apps/safari/App/Resources/Icon.png >/dev/null
echo "Icons regenerated."
