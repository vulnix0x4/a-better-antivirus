#!/usr/bin/env bash
# Checks the Linux files of a release (what .goreleaser-linux.yaml leaves in
# DIST) before anyone downloads them:
#
#   - SHA256SUMS-linux.txt lists the eight files, with their hashes;
#   - the program inside the .deb, the .rpm and the tarball is byte for byte
#     the aba_<tag>_linux_<arch> download (what `aba update` installs);
#   - install.sh, run against this copy of the release, checks the signature
#     and the checksum, and refuses a swapped file or a bad signature;
#   - the .deb installs, `sudo aba install` sets ABA up from it, and removing
#     the package takes ABA off the machine again.
#
#   scripts/packages-linux.sh <dist folder>
#
# A real release's checksum list is signed with the release key, and is
# checked against the key built into install.sh. A snapshot (CI) isn't
# signed: it's signed here with a throwaway key, handed to install.sh the way
# its tests can.
#
# Like the end-to-end script, it installs ABA as root: a throwaway machine only.

set -uo pipefail
DIST=$(readlink -f "${1:?usage: packages-linux.sh <dist folder>}")
HERE=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d /tmp/aba-pkg.XXXXXX)
UNIT=file-access-monitor.service
PORT=18791

say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
ok()   { printf '   \033[32mok\033[0m  %s\n' "$*"; }
fail() { printf '\n\033[31mFAILED: %s\033[0m\n' "$*" >&2; cleanup; exit 1; }
cleanup() {
  [ -n "${SERVER:-}" ] && kill "$SERVER" 2>/dev/null
  if dpkg -s a-better-antivirus >/dev/null 2>&1; then sudo apt-get remove -y -qq a-better-antivirus >/dev/null 2>&1; fi
  rm -rf "$WORK"
}
trap cleanup EXIT

say "The files"
SUMS="$DIST/SHA256SUMS-linux.txt"
[ -f "$SUMS" ] || fail "$SUMS is missing"
sed 's/^/      /' "$SUMS"
BIN=$(ls "$DIST"/aba_*_linux_amd64 2>/dev/null | head -n1)
[ -n "$BIN" ] || fail "no aba_<tag>_linux_amd64 in $DIST"
TAG=$(basename "$BIN"); TAG=${TAG#aba_}; TAG=${TAG%_linux_amd64}
for arch in amd64 arm64; do
  for f in "aba_${TAG}_linux_$arch" "aba_${TAG}_linux_$arch.tar.gz" "aba_${TAG}_linux_$arch.deb" "aba_${TAG}_linux_$arch.rpm"; do
    [ -f "$DIST/$f" ] || fail "$f is missing from $DIST"
    want=$(awk -v n="$f" '{ x = $2; sub(/^\*/, "", x) } x == n { print $1 }' "$SUMS")
    [ "$want" = "$(sha256sum "$DIST/$f" | cut -d' ' -f1)" ] || fail "$f: SHA256SUMS-linux.txt says '$want'"
  done
done
[ "$(grep -c . "$SUMS")" = 8 ] || fail "expected 8 files in SHA256SUMS-linux.txt, found $(grep -c . "$SUMS")"
ok "release $TAG: the program, a tarball, a .deb and an .rpm for amd64 and arm64, all in the checksum list"

say "The same program in every package"
for arch in amd64 arm64; do
  want=$(sha256sum "$DIST/aba_${TAG}_linux_$arch" | cut -d' ' -f1)
  mkdir -p "$WORK/deb-$arch" "$WORK/tar-$arch"
  dpkg-deb -x "$DIST/aba_${TAG}_linux_$arch.deb" "$WORK/deb-$arch" || fail "can't unpack the $arch .deb"
  [ "$(sha256sum "$WORK/deb-$arch/usr/bin/aba" | cut -d' ' -f1)" = "$want" ] || fail "/usr/bin/aba in the $arch .deb isn't aba_${TAG}_linux_$arch"
  tar -xzf "$DIST/aba_${TAG}_linux_$arch.tar.gz" -C "$WORK/tar-$arch" || fail "can't unpack the $arch tarball"
  [ "$(sha256sum "$WORK/tar-$arch/aba" | cut -d' ' -f1)" = "$want" ] || fail "aba in the $arch tarball isn't aba_${TAG}_linux_$arch"
  [ -x "$WORK/tar-$arch/aba" ] && [ -f "$WORK/tar-$arch/install.sh" ] || fail "the $arch tarball's aba isn't executable, or install.sh is missing"
  if command -v rpm2cpio >/dev/null && command -v cpio >/dev/null; then
    mkdir -p "$WORK/rpm-$arch"
    (cd "$WORK/rpm-$arch" && rpm2cpio "$DIST/aba_${TAG}_linux_$arch.rpm" | cpio -idm --quiet) || fail "can't unpack the $arch .rpm"
    [ "$(sha256sum "$WORK/rpm-$arch/usr/bin/aba" | cut -d' ' -f1)" = "$want" ] || fail "/usr/bin/aba in the $arch .rpm isn't aba_${TAG}_linux_$arch"
  fi
  ok "$arch: the .deb$(command -v rpm2cpio >/dev/null && echo ', the .rpm') and the tarball hold aba_${TAG}_linux_$arch"
done
dpkg-deb -I "$DIST/aba_${TAG}_linux_amd64.deb" | sed 's/^/      /'
"$DIST/aba_${TAG}_linux_amd64" --version || fail "the amd64 program doesn't run"

say "install.sh, against this copy of the release"
KEY=()
if [ ! -f "$SUMS.sig" ]; then
  # A snapshot: sign it with a throwaway key, and hand install.sh that key.
  openssl genpkey -algorithm ed25519 -out "$WORK/test.key" 2>/dev/null || fail "openssl can't make an ed25519 key"
  openssl pkey -in "$WORK/test.key" -pubout -out "$WORK/test.pub"
  openssl pkeyutl -sign -inkey "$WORK/test.key" -rawin -in "$SUMS" | base64 -w0 > "$SUMS.sig"
  KEY=(ABA_RELEASE_KEY="$WORK/test.pub")
  ok "a snapshot: signed with a throwaway key for this test"
fi
serve() { # serve DIR: a web server for DIR on 127.0.0.1:PORT
  [ -n "${SERVER:-}" ] && kill "$SERVER" 2>/dev/null && sleep 0.3
  python3 -m http.server "$PORT" --bind 127.0.0.1 --directory "$1" >/dev/null 2>&1 &
  SERVER=$!
  for _ in $(seq 1 50); do curl -s -o /dev/null "http://127.0.0.1:$PORT/" && return 0; sleep 0.1; done
  fail "the local web server didn't start"
}
run_installer() { env ABA_RELEASE_URL="http://127.0.0.1:$PORT" ABA_TAG="$TAG" "${KEY[@]}" ABA_ARGS=--version sh "$HERE/install.sh" </dev/null; }
serve "$DIST"
out=$(run_installer 2>&1) || { echo "$out"; fail "install.sh refused the release"; }
echo "$out" | sed 's/^/      /'
grep -q "Signed with ABA's release key" <<<"$out" && grep -q "Checksum matches" <<<"$out" || fail "install.sh didn't check the signature and the checksum"
ok "install.sh downloaded it, checked the signature and the checksum, and ran it"

cp -r "$DIST" "$WORK/swapped"; printf 'not aba' >> "$WORK/swapped/aba_${TAG}_linux_amd64"
serve "$WORK/swapped"
out=$(run_installer 2>&1) && { echo "$out"; fail "install.sh ran a program that doesn't match the checksum list"; }
grep -q "doesn't match the release's signed checksum" <<<"$out" || { echo "$out"; fail "install.sh failed for another reason than the swapped file"; }
ok "a swapped program is refused: $(grep -o "The download doesn't match[^,]*" <<<"$out")"

cp -r "$DIST" "$WORK/resigned"; echo "0000000000000000000000000000000000000000000000000000000000000000  aba_${TAG}_linux_amd64" > "$WORK/resigned/SHA256SUMS-linux.txt"
serve "$WORK/resigned"
out=$(run_installer 2>&1) && { echo "$out"; fail "install.sh accepted a checksum list that isn't signed with the key"; }
grep -q "isn't signed with ABA's key" <<<"$out" || { echo "$out"; fail "install.sh failed for another reason than the bad signature"; }
ok "a checksum list the signature doesn't cover is refused"
kill "$SERVER" 2>/dev/null; SERVER=""

say "The .deb: install, set up, remove"
[ -e "/etc/systemd/system/$UNIT" ] && fail "ABA is already set up on this machine"
sudo apt-get install -y -qq "$DIST/aba_${TAG}_linux_amd64.deb" > "$WORK/apt.txt" 2>&1 || { cat "$WORK/apt.txt"; fail "the .deb didn't install"; }
grep -q "sudo aba install" "$WORK/apt.txt" || { cat "$WORK/apt.txt"; fail "the package didn't say how to set ABA up"; }
[ "$(dpkg-query -W -f '${Status}' a-better-antivirus)" = "install ok installed" ] || fail "dpkg doesn't list the package as installed"
[ "$(readlink -f "$(command -v aba)")" = /usr/bin/aba ] || fail "aba on the PATH isn't the package's: $(command -v aba)"
ok "installed: $(dpkg-query -W -f '${Package} ${Version}' a-better-antivirus), /usr/bin/aba"
sudo aba install --yes --preset balanced --learning 0 --auto-update=false > "$WORK/install.txt" 2>&1 || { cat "$WORK/install.txt"; fail "sudo aba install from the package"; }
[ "$(systemctl is-active "$UNIT")" = active ] || fail "the service isn't running after setting up from the package"
sudo aba doctor | sed 's/^/      /'
ok "set up from the package: the service runs"
sudo apt-get remove -y -qq a-better-antivirus > "$WORK/remove.txt" 2>&1 || { cat "$WORK/remove.txt"; fail "removing the package"; }
sed 's/^/      /' "$WORK/remove.txt"
left=()
for p in "/etc/systemd/system/$UNIT" /usr/local/lib/file-access-monitor /usr/local/bin/aba /usr/bin/aba /run/file-access-monitor /sys/fs/cgroup/file-access-monitor.frozen; do
  { [ -e "$p" ] || [ -L "$p" ]; } && left+=("$p")
done
[ "${#left[@]}" = 0 ] || fail "left behind after removing the package: ${left[*]}"
[ "$(systemctl is-active "$UNIT" 2>/dev/null)" = active ] && fail "the service still runs after removing the package"
ok "removing the package took ABA off the machine (alert history stays in /var/lib/file-access-monitor until purged)"
sudo rm -rf /var/lib/file-access-monitor

printf '\n\033[32mThe Linux release files check out.\033[0m\n'
