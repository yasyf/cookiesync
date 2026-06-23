#!/usr/bin/env bash
# Build cookiesync-keyhelper.app UNSIGNED for local dev.
#
#   build-app.sh <TEAM_ID> [provisioning-profile-path]
#
# Compiles Sources/cookiesync-keyhelper/main.swift into the app bundle's
# Contents/MacOS, copies Info.plist, materializes the entitlements with $(TEAM_ID)
# substituted (so the CI signing step can pass it straight to codesign), and — when a
# profile path is given — copies it to Contents/embedded.provisionprofile.
#
# This script is deliberately SIGN-FREE. Signing + notarization + stapling is the CI
# release workflow's job; doing it here would touch a keychain on a dev Mac. An
# unsigned bundle CANNOT use the Secure Enclave (AMFI kills a Team-less signature at
# exec, and SE keygen is refused) — it only proves the bundle assembles correctly.
#
# Prints the absolute path to the produced .app on stdout.

set -euo pipefail

TEAM_ID="${1:?usage: build-app.sh <TEAM_ID> [provisioning-profile-path]}"
PROFILE_PATH="${2:-}"

# The Swift keychain-access-group is a COMPILE-TIME literal in main.swift
# (SXKCTF23Q2.com.yasyf.cookiesync.helper), but the entitlements template carries
# $(TEAM_ID) from the cert. A cert from a different team would build a bundle whose
# runtime keychain item group never matches the literal, so every SecItem call would
# errSecMissingEntitlement. Fail loud before compiling so that can't ship.
EXPECTED_TEAM_ID="SXKCTF23Q2"
if [ "$TEAM_ID" != "$EXPECTED_TEAM_ID" ]; then
	echo "build-app.sh: TEAM_ID '$TEAM_ID' != '$EXPECTED_TEAM_ID' — main.swift's keychain-access-group literal is bound to $EXPECTED_TEAM_ID; a different-team cert would errSecMissingEntitlement at runtime" >&2
	exit 1
fi

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$HERE/Sources/cookiesync-keyhelper/main.swift"
INFO_PLIST="$HERE/Info.plist"
ENTITLEMENTS_TEMPLATE="$HERE/cookiesync-keyhelper.entitlements"

BUILD_DIR="$HERE/build"
APP="$BUILD_DIR/cookiesync-keyhelper.app"
MACOS_DIR="$APP/Contents/MacOS"

rm -rf "$APP"
mkdir -p "$MACOS_DIR"

# Compile the merged CLI. swiftc links the same three frameworks both runtime
# helpers used; no signing flags so it never reaches a keychain.
swiftc "$SRC" \
	-framework Security \
	-framework LocalAuthentication \
	-framework Foundation \
	-o "$MACOS_DIR/cookiesync-keyhelper"

cp "$INFO_PLIST" "$APP/Contents/Info.plist"

# Materialize the entitlements with TEAM_ID substituted, next to the bundle, so the
# CI signing step can `codesign --entitlements build/cookiesync-keyhelper.entitlements`
# without re-templating.
sed "s/\$(TEAM_ID)/$TEAM_ID/g" "$ENTITLEMENTS_TEMPLATE" \
	> "$BUILD_DIR/cookiesync-keyhelper.entitlements"

if [ -n "$PROFILE_PATH" ]; then
	cp "$PROFILE_PATH" "$APP/Contents/embedded.provisionprofile"
fi

echo "$APP"
