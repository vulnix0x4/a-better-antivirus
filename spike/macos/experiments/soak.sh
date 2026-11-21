#!/bin/bash
# Plant fake baits where macOS stealers look, so the watcher can record which
# legitimate software reads them over time. Run as the ordinary user.
#
#   soak.sh plant   create them and print one path per line
#   soak.sh list    print the paths
#   soak.sh clean   remove them again
#
# Every file and folder it makes has "aba-spike" in its name or lives in a
# folder this script created, and nothing that already exists is overwritten.
set -u
H=$HOME
AS="$H/Library/Application Support"
BAITS=(
	"$H/Desktop/passwords aba-spike.txt"
	"$H/Documents/wallet recovery phrase aba-spike.txt"
	"$H/Downloads/2fa backup codes aba-spike.txt"
	"$H/aba-spike-passwords.kdbx"
	"$AS/Google/Chrome/Profile 23/Login Data"
	"$AS/Google/Chrome/Profile 23/Cookies"
	"$AS/BraveSoftware/Brave-Browser/Profile 23/Login Data"
	"$AS/Exodus/exodus.wallet/seed.seco"
	"$AS/Electrum/wallets/default_wallet"
	"$AS/atomic/Local Storage/leveldb/000003.log"
	"$AS/Telegram Desktop/tdata/key_datas"
	"$AS/Opera Software/Opera Stable/Login Data"
	"$AS/FileZilla/recentservers.xml"
	"$H/.ssh/id_ed25519_aba_spike"
	"$H/Library/Keychains/aba-spike.keychain-db"
)
MADE="$H/.aba-spike-soak-made"
case "${1:-}" in
plant)
	: > "$MADE"
	for b in "${BAITS[@]}"; do
		d=$(dirname "$b")
		if [ -e "$b" ]; then echo "SKIP (exists): $b" >&2; continue; fi
		# remember the topmost folder we had to create, to remove it later
		top="$d"; while [ ! -e "$(dirname "$top")" ]; do top=$(dirname "$top"); done
		[ -e "$d" ] || echo "D $top" >> "$MADE"
		mkdir -p "$d" || continue
		printf 'aba-spike fake bait, safe to delete\nhunter2\n' > "$b" && echo "F $b" >> "$MADE" && echo "$b"
	done ;;
list) grep '^F ' "$MADE" | cut -c3- ;;
clean)
	[ -f "$MADE" ] || exit 0
	grep '^F ' "$MADE" | cut -c3- | while IFS= read -r f; do rm -f "$f"; done
	grep '^D ' "$MADE" | cut -c3- | sort -u | while IFS= read -r d; do case "$d" in "$H"/*) rm -rf "$d";; esac; done
	rm -f "$MADE"; echo cleaned ;;
*) sed -n '2,10p' "$0"; exit 2 ;;
esac
