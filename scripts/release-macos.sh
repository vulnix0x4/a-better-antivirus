#!/usr/bin/env bash
# The macOS files of a release, built on a Mac:
#
#   aba_<tag>_darwin_arm64, aba_<tag>_darwin_amd64
#       the program, what `aba update` downloads and what install.sh fetches
#   ABA-<tag>.pkg
#       an installer package: the app put in place, then `aba install --yes`
#   SHA256SUMS-macos.txt (+ .sig)
#       their checksums, signed with the release key (ABA_SIGNING_KEY), the
#       same way as the Windows list (SHA256SUMS.txt, which holds only the
#       Windows files)
#
#   scripts/release-macos.sh <tag> <out dir> [--upload]
#
# With ABA's Developer ID certificates (in the environment, see below) the
# programs and the app are signed with "Developer ID Application" and the
# hardened runtime, the package with "Developer ID Installer", and all of it
# is notarized by Apple (the package's ticket stapled to it). Without them
# everything is built unsigned, and the package isn't published: unsigned,
# macOS would refuse to open it when downloaded with a browser.
#
# Environment (all optional; secrets of the release workflow's "release"
# environment):
#   MACOS_APP_CERT, MACOS_APP_CERT_PASSWORD
#       "Developer ID Application" certificate and key, a .p12 in base64
#   MACOS_INSTALLER_CERT, MACOS_INSTALLER_CERT_PASSWORD
#       "Developer ID Installer" certificate and key, a .p12 in base64
#   NOTARY_KEY, NOTARY_KEY_ID, NOTARY_ISSUER_ID
#       App Store Connect API key for notarization: the .p8 in base64, its
#       key ID, and the issuer ID
#   ABA_SIGNING_KEY   the release key, to sign the checksum list
#   GITHUB_TOKEN      for --upload

set -euo pipefail

TAG=${1:?usage: release-macos.sh <tag> <out dir> [--upload]}
OUT=${2:?usage: release-macos.sh <tag> <out dir> [--upload]}
UPLOAD=${3:-}
BUNDLE_ID=com.fileaccessmonitor.service
APP_NAME="File Access Monitor"
SUPPORT="Library/Application Support/$APP_NAME"

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
rm -rf "$OUT"; mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
WORK=$(mktemp -d)
trap 'cleanup' EXIT
cleanup() {
  [ -n "${KEYCHAIN:-}" ] && security delete-keychain "$KEYCHAIN" 2>/dev/null
  rm -rf "$WORK"
}

# ---- certificates, in a keychain of their own that's deleted afterwards ----
SIGNED=""
APP_ID="" INSTALLER_ID=""
if [ -n "${MACOS_APP_CERT:-}" ] && [ -n "${MACOS_INSTALLER_CERT:-}" ]; then
  say "Certificates"
  KEYCHAIN="$WORK/build.keychain-db"
  KCPASS=$(openssl rand -hex 24)
  security create-keychain -p "$KCPASS" "$KEYCHAIN"
  security set-keychain-settings -lut 3600 "$KEYCHAIN"
  security unlock-keychain -p "$KCPASS" "$KEYCHAIN"
  printf '%s' "$MACOS_APP_CERT" | base64 --decode > "$WORK/app.p12"
  printf '%s' "$MACOS_INSTALLER_CERT" | base64 --decode > "$WORK/installer.p12"
  security import "$WORK/app.p12" -k "$KEYCHAIN" -P "${MACOS_APP_CERT_PASSWORD:-}" -T /usr/bin/codesign
  security import "$WORK/installer.p12" -k "$KEYCHAIN" -P "${MACOS_INSTALLER_CERT_PASSWORD:-}" -T /usr/bin/productbuild -T /usr/bin/productsign
  rm -f "$WORK/app.p12" "$WORK/installer.p12"
  security set-key-partition-list -S apple-tool:,apple: -s -k "$KCPASS" "$KEYCHAIN" >/dev/null
  security list-keychains -d user -s "$KEYCHAIN" $(security list-keychains -d user | tr -d '"')
  APP_ID=$(security find-identity -v -p codesigning "$KEYCHAIN" | sed -n 's/.*"\(Developer ID Application: .*\)"/\1/p' | head -1)
  INSTALLER_ID=$(security find-identity -v "$KEYCHAIN" | sed -n 's/.*"\(Developer ID Installer: .*\)"/\1/p' | head -1)
  [ -n "$APP_ID" ] || { echo "no Developer ID Application identity in MACOS_APP_CERT"; exit 1; }
  [ -n "$INSTALLER_ID" ] || { echo "no Developer ID Installer identity in MACOS_INSTALLER_CERT"; exit 1; }
  echo "signing as: $APP_ID / $INSTALLER_ID"
  SIGNED=yes
else
  say "No Developer ID certificates: building unsigned"
fi

sign() { # sign FILE: Developer ID and the hardened runtime, or nothing
  [ -n "$SIGNED" ] || return 0
  codesign --force --options runtime --timestamp --sign "$APP_ID" --identifier "$BUNDLE_ID" "$1"
  codesign --verify --strict --verbose=2 "$1"
}

# ---- the programs ----
say "Building $TAG"
for arch in arm64 amd64; do
  CGO_ENABLED=0 GOOS=darwin GOARCH=$arch go build -trimpath -ldflags "-s -w -X main.version=$TAG" -o "$OUT/aba_${TAG}_darwin_$arch" ./cmd/aba
  sign "$OUT/aba_${TAG}_darwin_$arch"
done
"$OUT/aba_${TAG}_darwin_$(uname -m | sed 's/x86_64/amd64/')" --version

# ---- the app, in a package ----
say "The app and the package"
ROOT="$WORK/root"
APP="$ROOT/$SUPPORT/$APP_NAME.app"
mkdir -p "$APP/Contents/MacOS"
lipo -create "$OUT/aba_${TAG}_darwin_arm64" "$OUT/aba_${TAG}_darwin_amd64" -output "$APP/Contents/MacOS/famsvc"
VERSION=${TAG#v}
cat > "$APP/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleIdentifier</key>
	<string>$BUNDLE_ID</string>
	<key>CFBundleName</key>
	<string>$APP_NAME</string>
	<key>CFBundleDisplayName</key>
	<string>$APP_NAME</string>
	<key>CFBundleExecutable</key>
	<string>famsvc</string>
	<key>CFBundlePackageType</key>
	<string>APPL</string>
	<key>CFBundleInfoDictionaryVersion</key>
	<string>6.0</string>
	<key>CFBundleShortVersionString</key>
	<string>$VERSION</string>
	<key>CFBundleVersion</key>
	<string>$VERSION</string>
	<key>LSMinimumSystemVersion</key>
	<string>14.0</string>
	<key>LSBackgroundOnly</key>
	<true/>
	<key>LSUIElement</key>
	<true/>
</dict>
</plist>
EOF
if [ -n "$SIGNED" ]; then
  codesign --force --options runtime --timestamp --sign "$APP_ID" --identifier "$BUNDLE_ID" "$APP"
  codesign --verify --strict --verbose=2 "$APP"
fi

mkdir -p "$WORK/scripts"
cat > "$WORK/scripts/postinstall" <<'EOF'
#!/bin/sh
# Runs as root once the app is in place: sets ABA up (or repairs and
# upgrades it, keeping your settings) for the person at the screen, with the
# recommended choices. `aba configure` changes them afterwards.
PROG="/Library/Application Support/File Access Monitor/File Access Monitor.app/Contents/MacOS/famsvc"
LOG="/Library/Application Support/File Access Monitor/install.log"
if [ -e "/Library/Application Support/File Access Monitor/Data/config.json" ]; then
  set -- install --yes --keep-settings
else
  set -- install --yes
fi
ABA_NO_WAIT=1 NO_COLOR=1 "$PROG" "$@" > "$LOG" 2>&1
EOF
chmod 755 "$WORK/scripts/postinstall"
# No extended attributes (they'd travel as ._ files and break the app's
# signature), and the app is never "relocated" to wherever macOS last saw an
# app with the same identifier: it goes where ABA expects it.
xattr -cr "$ROOT" "$WORK/scripts"
pkgbuild --analyze --root "$ROOT" "$WORK/components.plist" >/dev/null
plutil -replace 0.BundleIsRelocatable -bool NO "$WORK/components.plist"
plutil -replace 0.BundleOverwriteAction -string upgrade "$WORK/components.plist"
COPYFILE_DISABLE=1 pkgbuild --root "$ROOT" --component-plist "$WORK/components.plist" --identifier "$BUNDLE_ID.pkg" --version "$VERSION" \
  --install-location / --scripts "$WORK/scripts" --ownership recommended "$WORK/component.pkg"
if pkgutil --payload-files "$WORK/component.pkg" | grep -q '/\._'; then
  # Extended attributes macOS won't let this process remove (it marks what
  # some programs write with com.apple.provenance): the package would put ._
  # files inside the app. Never published like that.
  echo "the package holds ._ files (extended attributes on the build files)"
  [ "$UPLOAD" = --upload ] || [ -n "${CI:-}" ] && exit 1
fi
PKG="$OUT/ABA-$TAG.pkg"
if [ -n "$SIGNED" ]; then
  productbuild --package "$WORK/component.pkg" --sign "$INSTALLER_ID" --timestamp "$PKG"
  pkgutil --check-signature "$PKG"
else
  productbuild --package "$WORK/component.pkg" "$PKG"
fi

# ---- notarization ----
if [ -n "$SIGNED" ] && [ -n "${NOTARY_KEY:-}" ]; then
  say "Notarization"
  printf '%s' "$NOTARY_KEY" | base64 --decode > "$WORK/notary.p8"
  notarize() {
    xcrun notarytool submit "$1" --key "$WORK/notary.p8" --key-id "$NOTARY_KEY_ID" --issuer "$NOTARY_ISSUER_ID" --wait --timeout 30m | tee "$WORK/notary.out"
    grep -q 'status: Accepted' "$WORK/notary.out" || { echo "Apple didn't accept $1"; exit 1; }
  }
  notarize "$PKG"
  xcrun stapler staple "$PKG"
  xcrun stapler validate "$PKG"
  # The plain programs can't carry a ticket, but Apple's servers know them.
  mkdir -p "$WORK/programs"
  cp "$OUT"/aba_${TAG}_darwin_* "$WORK/programs/"
  ditto -c -k --keepParent "$WORK/programs" "$WORK/programs.zip"
  notarize "$WORK/programs.zip"
  rm -f "$WORK/notary.p8"
  spctl --assess --type install --verbose=2 "$PKG"
elif [ -n "$SIGNED" ]; then
  echo "no notarization key: signed, but not notarized"
fi
# The same package under a name that never changes, for a link that always
# gets the newest one (releases/latest/download/ABA-macOS.pkg), like
# ABA-Setup.exe on Windows. Copied after stapling, so it carries the ticket.
if [ -n "$SIGNED" ]; then
  cp "$PKG" "$OUT/ABA-macOS.pkg"
fi

# ---- the checksum list ----
say "Checksums"
(
  cd "$OUT"
  files=(aba_${TAG}_darwin_arm64 aba_${TAG}_darwin_amd64)
  [ -n "$SIGNED" ] && files+=("ABA-$TAG.pkg" "ABA-macOS.pkg")
  shasum -a 256 "${files[@]}" > SHA256SUMS-macos.txt
  cat SHA256SUMS-macos.txt
)
if [ -n "${ABA_SIGNING_KEY:-}" ]; then
  go run ./scripts/sign "$OUT/SHA256SUMS-macos.txt" "$OUT/SHA256SUMS-macos.txt.sig"
else
  echo "no ABA_SIGNING_KEY: the checksum list isn't signed"
fi

if [ "$UPLOAD" = --upload ]; then
  say "Uploading to the release $TAG"
  [ -n "${ABA_SIGNING_KEY:-}" ] || { echo "refusing to publish an unsigned checksum list"; exit 1; }
  files=("$OUT"/aba_${TAG}_darwin_* "$OUT/SHA256SUMS-macos.txt" "$OUT/SHA256SUMS-macos.txt.sig")
  [ -n "$SIGNED" ] && files+=("$PKG" "$OUT/ABA-macOS.pkg")
  gh release upload "$TAG" "${files[@]}" --clobber
fi
