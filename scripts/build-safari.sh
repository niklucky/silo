#!/usr/bin/env sh
# Builds the extension for Safari and wraps it in "Silo for Safari.app"
# (apps/safari), then opens the app once so Safari registers the extension.
#
# Signed ad hoc by default, which Safari loads only with Develop > Developer
# Settings > "Allow unsigned extensions" (reset every time Safari quits). To
# sign with your own certificate instead:
#   SILO_SAFARI_IDENTITY="Apple Development: Jane Doe (ABCDE12345)" \
#   SILO_SAFARI_TEAM=TEAMID1234 pnpm build:safari
# Requires: Xcode.
set -eu
cd "$(dirname "$0")/.."

pnpm --filter @silo/extension build:safari

out="$PWD/apps/safari/build"
identity="${SILO_SAFARI_IDENTITY:--}"
team="${SILO_SAFARI_TEAM:-}"

xcodebuild \
  -project "apps/safari/Silo for Safari.xcodeproj" \
  -target "Silo for Safari" \
  -configuration Release \
  -quiet \
  CODE_SIGN_STYLE=Manual \
  CODE_SIGN_IDENTITY="$identity" \
  DEVELOPMENT_TEAM="$team" \
  SYMROOT="$out" \
  OBJROOT="$out/obj" \
  CONFIGURATION_BUILD_DIR="$out"

app="$out/Silo for Safari.app"
echo "built $app"
open "$app"
