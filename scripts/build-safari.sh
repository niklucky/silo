#!/usr/bin/env sh
# Builds the extension for Safari and wraps it in "Secret for Safari.app"
# (apps/safari), then opens the app once so Safari registers the extension.
#
# Signed ad hoc by default, which Safari loads only with Develop > Developer
# Settings > "Allow unsigned extensions" (reset every time Safari quits). To
# sign with your own certificate instead:
#   SECRET_SAFARI_IDENTITY="Apple Development: Jane Doe (ABCDE12345)" \
#   SECRET_SAFARI_TEAM=TEAMID1234 pnpm build:safari
# Requires: Xcode.
set -eu
cd "$(dirname "$0")/.."

pnpm --filter @secret/extension build:safari

out="$PWD/apps/safari/build"
identity="${SECRET_SAFARI_IDENTITY:--}"
team="${SECRET_SAFARI_TEAM:-}"

xcodebuild \
  -project "apps/safari/Secret for Safari.xcodeproj" \
  -target "Secret for Safari" \
  -configuration Release \
  -quiet \
  CODE_SIGN_STYLE=Manual \
  CODE_SIGN_IDENTITY="$identity" \
  DEVELOPMENT_TEAM="$team" \
  SYMROOT="$out" \
  OBJROOT="$out/obj" \
  CONFIGURATION_BUILD_DIR="$out"

app="$out/Secret for Safari.app"
echo "built $app"
open "$app"
