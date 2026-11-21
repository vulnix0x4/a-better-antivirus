#!/bin/bash
# Different ways a program can get at a file, each tried on its own bait so
# the watcher's log shows exactly what each one looks like. Run as an ordinary
# user while `aba-spike watch -baitdir <dir> -action none` is running as root.
#
#   readers.sh plant <dir>   create the baits (do this before starting the watcher)
#   readers.sh run   <dir>   do the reading
#
# Everything it reads is a file it made itself. Copies go to a staging folder
# inside <dir> and to a small scratch disk image; both are removed afterwards.
set -u
MODE=${1:?plant|run}
D=${2:?dir}
BAITS="cat cp cp-clone ditto zip tar python osa-shell osa-read finder-dup-same-volume finder-dup-other-volume finder-dup-as-app mdimport quicklook-thumb stat-only swift-nsdata"

if [ "$MODE" = plant ]; then
	mkdir -p "$D/baits" "$D/stage"
	for b in $BAITS; do echo "fake secret for $b: hunter2" > "$D/baits/$b.txt"; done
	ls "$D/baits" | wc -l | xargs echo "planted baits:"
	exit 0
fi

ST="$D/stage"
step() { echo; echo "--- $1  ($(date +%H:%M:%S))"; }
B() { echo "$D/baits/$1.txt"; }

step "cat (a shell running Apple's cat)"
cat "$(B cat)" > "$ST/cat.out"

step "cp"
cp "$(B cp)" "$ST/cp.out"

step "cp -c (clonefile)"
cp -c "$(B cp-clone)" "$ST/cp-clone.out"

step "ditto"
ditto "$(B ditto)" "$ST/ditto.out"

step "zip"
zip -q -j "$ST/zip.out.zip" "$(B zip)"

step "tar"
tar -cf "$ST/tar.out.tar" -C "$D/baits" tar.txt

step "python3 open().read()"
python3 -c "import sys; open(sys.argv[1],'rb').read()" "$(B python)" 2>&1 | tail -1

step "osascript: do shell script \"cat ...\" (how AMOS copies browser files)"
osascript -e "do shell script \"cat '$(B osa-shell)' > '$ST/osa-shell.out'\"" 2>&1 | tail -1

step "osascript reading the file itself"
osascript -e "read POSIX file \"$(B osa-read)\"" > /dev/null 2>&1; echo "exit $?"

step "osascript -> Finder: duplicate to a folder on the same volume (the AMOS file grabber)"
osascript -e "tell application \"Finder\" to duplicate (POSIX file \"$(B finder-dup-same-volume)\" as alias) to folder (POSIX file \"$ST\" as alias) with replacing" 2>&1 | tail -1

step "osascript -> Finder: duplicate to another volume (a real copy, not a clone)"
IMG="$D/scratch.dmg"
hdiutil create -quiet -size 8m -fs APFS -volname ABASpikeScratch "$IMG" 2>&1 | tail -1
MNT=$(hdiutil attach -nobrowse "$IMG" 2>/dev/null | awk -F'\t' '/Volumes/ {print $NF}')
echo "scratch volume: $MNT"
if [ -n "$MNT" ]; then
	osascript -e "tell application \"Finder\" to duplicate (POSIX file \"$(B finder-dup-other-volume)\" as alias) to folder (POSIX file \"$MNT\" as alias) with replacing" 2>&1 | tail -1
	sleep 2
fi

step "a compiled AppleScript app-like script (osacompile) telling Finder to duplicate"
osacompile -o "$ST/Installer.scpt" -e "tell application \"Finder\" to duplicate (POSIX file \"$(B finder-dup-as-app)\" as alias) to folder (POSIX file \"$ST\" as alias) with replacing" 2>&1 | tail -1
mkdir -p "$ST/sub"
( cd "$ST" && bash -c 'osascript Installer.scpt' ) 2>&1 | tail -1

step "Spotlight import (mdimport, what indexing does to a new file)"
mdimport -i "$(B mdimport)" 2>&1 | tail -1

step "Quick Look thumbnail (qlmanage -t, what Finder icon previews do)"
qlmanage -t -o "$ST" "$(B quicklook-thumb)" > /dev/null 2>&1; echo "exit $?"

step "stat only (ls -l, no open)"
ls -l "$(B stat-only)" > /dev/null

step "Swift/Foundation Data(contentsOf:) via the swift interpreter, if present"
if command -v swift > /dev/null && [ -z "${SKIP_SWIFT:-}" ]; then
	echo "import Foundation; _ = try? Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[1]))" > "$ST/r.swift"
	( swiftc -o "$ST/reader-swift" "$ST/r.swift" 2>/dev/null && "$ST/reader-swift" "$(B swift-nsdata)" ); echo "exit $?"
fi

sleep 2
[ -n "${MNT:-}" ] && hdiutil detach -quiet "$MNT" 2>/dev/null
rm -f "$IMG"
echo
echo "done"
