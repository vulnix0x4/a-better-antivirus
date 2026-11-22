#!/bin/sh
# A Better Antivirus installer for Linux.
#
#   curl -fsSL https://raw.githubusercontent.com/vulnix0x4/a-better-antivirus/main/install.sh | sh
#
# Downloads the latest release for this machine, checks that the release's
# SHA256SUMS-linux.txt carries a valid signature from ABA's release key (the
# same key the automatic updates check, its public half written out below),
# checks the download against that list, and runs `sudo aba install`.
# Afterwards `aba` works in this terminal.
#
# Pass other arguments with ABA_ARGS, e.g. for a throwaway test machine:
#   curl -fsSL …/install.sh | ABA_ARGS='install --yes --preset strict --learning 0' sh
#
# For testing a local copy of a release (only from this machine, never from
# the internet): ABA_RELEASE_URL=http://127.0.0.1:PORT (or file:///dir), with
# ABA_TAG naming the release and ABA_RELEASE_KEY a PEM file with the public
# key it was signed with.

set -eu

REPO=vulnix0x4/a-better-antivirus
RELEASE_KEY='-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAVLEZ7MWwcu4LFSYPzA71J9M0WWbqQryOGki0GSvuihU=
-----END PUBLIC KEY-----'

if [ -t 1 ]; then G=$(printf '\033[32m'); R=$(printf '\033[31m'); D=$(printf '\033[2m'); N=$(printf '\033[0m'); else G=; R=; D=; N=; fi
say()  { printf ' %s✓%s %s  %s%s%s\n' "$G" "$N" "$1" "$D" "${2:-}" "$N"; }
stop() {
  printf '\n %s✗ %s%s\n' "$R" "$1" "$N"
  [ -n "${2:-}" ] && printf '   %s%s%s\n' "$D" "$2" "$N"
  printf '\n'
  exit 1
}

printf "\n A Better Antivirus   %sit's not an antivirus. it's a better one.%s\n\n" "$D" "$N"

[ "$(uname -s)" = Linux ] || stop "This installer is for Linux." "On Windows, see https://github.com/$REPO#install"
case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) stop "There's no build of A Better Antivirus for $(uname -m) yet." ;;
esac
[ -d /run/systemd/system ] || stop "A Better Antivirus needs a system run by systemd, for now."

fetch() { # fetch URL FILE
  case "$1" in
    file://*) cp "${1#file://}" "$2" ;;
    *)
      if command -v curl >/dev/null 2>&1; then curl -fsSL --proto '=https,http' --max-time 300 -o "$2" "$1"
      elif command -v wget >/dev/null 2>&1; then wget -q -T 300 -O "$2" "$1"
      else stop "Neither curl nor wget is installed." "Install one of them and run the command again."
      fi ;;
  esac
}

# A local copy of a release, for tests: only from this machine.
BASE=""
if [ -n "${ABA_RELEASE_URL:-}" ]; then
  case "$ABA_RELEASE_URL" in
    http://127.0.0.1:*|http://localhost:*|file:///*) ;;
    *) stop "ABA_RELEASE_URL may only point at this machine." ;;
  esac
  [ -n "${ABA_TAG:-}" ] || stop "ABA_RELEASE_URL needs ABA_TAG."
  if [ -n "${ABA_RELEASE_KEY:-}" ]; then RELEASE_KEY=$(cat "$ABA_RELEASE_KEY"); fi
  TAG=$ABA_TAG; BASE=${ABA_RELEASE_URL%/}
fi

DIR=$(mktemp -d "${TMPDIR:-/tmp}/aba-install.XXXXXX")
trap 'rm -rf "$DIR"' EXIT INT TERM

if [ -z "$BASE" ]; then
  fetch "https://api.github.com/repos/$REPO/releases/latest" "$DIR/release.json" 2>/dev/null \
    || stop "Couldn't reach GitHub to find the latest release." "Check your internet connection (or wait a few minutes if GitHub is rate-limiting this network) and run the command again."
  TAG=$(sed -n 's/^[[:space:]]*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' "$DIR/release.json" | head -n 1)
  [ -n "$TAG" ] || stop "GitHub's answer didn't name a release."
  BASE="https://github.com/$REPO/releases/download/$TAG"
fi
case "$TAG" in *[!A-Za-z0-9._-]*|"") stop "The release has an odd name ($TAG); not going on." ;; esac

NAME="aba_${TAG}_linux_${ARCH}"
SUMS=SHA256SUMS-linux.txt
fetch "$BASE/$NAME" "$DIR/aba" && fetch "$BASE/$SUMS" "$DIR/$SUMS" && fetch "$BASE/$SUMS.sig" "$DIR/$SUMS.sig" \
  || stop "Release $TAG has no build for this machine ($ARCH), or the download didn't finish." "Check your internet connection and run the command again."
say "Downloaded $TAG" "$(du -k "$DIR/aba" | cut -f1) KB, $ARCH"

# The checksum list must be signed with ABA's release key.
command -v openssl >/dev/null 2>&1 || stop "openssl is needed to check the release's signature." "Install it (it's the openssl package) and run the command again."
printf '%s\n' "$RELEASE_KEY" > "$DIR/key.pem"
base64 -d "$DIR/$SUMS.sig" > "$DIR/sig.bin" 2>/dev/null || stop "The release's signature is malformed, so nothing was run."
if ! openssl pkeyutl -verify -pubin -inkey "$DIR/key.pem" -rawin -in "$DIR/$SUMS" -sigfile "$DIR/sig.bin" >/dev/null 2>&1; then
  if ! openssl pkeyutl -help 2>&1 | grep -q rawin; then
    stop "This openssl is too old to check the release's signature (it needs OpenSSL 3)." "Install the release by hand instead: see https://github.com/$REPO#linux"
  fi
  stop "The release's checksum list isn't signed with ABA's key, so nothing was run." "Run the command again. If it keeps happening, please open an issue on GitHub."
fi
say "Signed with ABA's release key" "ed25519"

WANT=$(awk -v n="$NAME" '{ f = $2; sub(/^\*/, "", f) } f == n && length($1) == 64 { print tolower($1); exit }' "$DIR/$SUMS")
GOT=$(sha256sum "$DIR/aba" | cut -d' ' -f1)
[ -n "$WANT" ] && [ "$WANT" = "$GOT" ] || stop "The download doesn't match the release's signed checksum, so it was not run." "Run the command again. If it keeps happening, please open an issue on GitHub."
say "Checksum matches the signed list" "SHA-256"
chmod 755 "$DIR/aba"

SUDO=""
if [ "$(id -u)" != 0 ]; then
  command -v sudo >/dev/null 2>&1 || stop "Setting ABA up needs root, and sudo isn't here." "Run this as root instead."
  SUDO=sudo
fi
if [ -z "${ABA_ARGS:-}" ]; then
  printf ' %s›%s Starting setup  %ssudo asks for your password%s\n' "$G" "$N" "$D" "$N"
fi
# Piped into sh, this script's input is the script: setup asks its questions
# on the terminal instead, when there is one.
IN=/dev/null
if (exec </dev/tty) 2>/dev/null; then IN=/dev/tty; fi
set +e
# shellcheck disable=SC2086 # ABA_ARGS is a list of words on purpose
$SUDO "$DIR/aba" ${ABA_ARGS:-install} <"$IN"
CODE=$?
set -e
printf '\n'
if [ "$CODE" = 0 ] && [ -x /usr/local/lib/file-access-monitor/aba ]; then
  say "A Better Antivirus is installed."
  printf '   %sType%s aba%s for the dashboard, or%s aba test%s to watch it catch a fake stealer.%s\n\n' "$D" "$G" "$D" "$G" "$D" "$N"
elif [ "$CODE" != 0 ]; then
  printf ' %s✗ Setup didn'"'"'t finish (exit code %s).%s  %sRun the command again to retry.%s\n\n' "$R" "$CODE" "$N" "$D" "$N"
  exit "$CODE"
fi
