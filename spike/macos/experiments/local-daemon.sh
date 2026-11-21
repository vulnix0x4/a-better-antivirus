#!/bin/bash
# The spike daemon on a developer's own Mac.
#
# eslogger only works when the program *responsible* for it has Full Disk
# Access. Started from a terminal that is the terminal app; started by launchd
# it is the daemon itself. So the spike installs itself the way the real
# product would: an app-like bundle (Apple's advice for anything that needs
# Full Disk Access), run by a LaunchDaemon, and the developer flips its switch
# in System Settings > Privacy & Security > Full Disk Access.
#
#   local-daemon.sh bundle             build and sign the bundle        (no sudo)
#   sudo local-daemon.sh install UID   install and start it
#   sudo local-daemon.sh job NAME ARGS run `aba-spike ARGS` inside the daemon;
#                                      output: /var/db/aba-spike/out/NAME.log
#   sudo local-daemon.sh uninstall     remove every trace
#
# SPIKE_SIGN_ID: a signing identity so that rebuilding keeps the Full Disk
# Access grant (ad-hoc signatures change with every build). Default: ad-hoc.
set -eu
cd "$(dirname "$0")/.."
NAME="ABA Spike"
BID=dev.aba.spike
SRC="build/$NAME.app"
DST="/Library/Application Support/$NAME/$NAME.app"
PLIST=/Library/LaunchDaemons/$BID.plist
WORK=/var/db/aba-spike
BIN="$DST/Contents/MacOS/aba-spike"

case "${1:-}" in
bundle)
	mkdir -p build
	go build -o build/aba-spike ./cmd/aba-spike
	go build -o build/fake-stealer ./cmd/fake-stealer
	rm -rf "$SRC"
	mkdir -p "$SRC/Contents/MacOS" "$SRC/Contents/Resources"
	cp build/aba-spike "$SRC/Contents/MacOS/aba-spike"
	cp build/fake-stealer "$SRC/Contents/Resources/fake-stealer"
	cat > "$SRC/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
	<key>CFBundleIdentifier</key><string>$BID</string>
	<key>CFBundleName</key><string>$NAME</string>
	<key>CFBundleDisplayName</key><string>$NAME</string>
	<key>CFBundleExecutable</key><string>aba-spike</string>
	<key>CFBundlePackageType</key><string>APPL</string>
	<key>CFBundleShortVersionString</key><string>0.0.1</string>
	<key>CFBundleVersion</key><string>1</string>
	<key>LSBackgroundOnly</key><true/>
	<key>LSMinimumSystemVersion</key><string>13.0</string>
</dict></plist>
EOF
	# The fake stealer stays ad-hoc signed on purpose: that is what "unsigned"
	# means on Apple silicon, and it is what a real stealer looks like.
	codesign -f -s "${SPIKE_SIGN_ID:--}" --identifier "$BID" "$SRC" 2>&1 | sed -E 's/: .*$//'
	codesign -dv "$SRC" 2>&1 | grep -E "^(Identifier|TeamIdentifier|Signature)"
	;;
install)
	OWNER=${2:?uid that may read the output}
	launchctl bootout system "$PLIST" 2>/dev/null || true
	mkdir -p "$(dirname "$DST")"
	rm -rf "$DST"
	cp -R "$SRC" "$DST"
	chown -R root:wheel "$(dirname "$DST")"
	mkdir -p $WORK
	cat > $PLIST <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
	<key>Label</key><string>$BID</string>
	<key>ProgramArguments</key><array>
		<string>$BIN</string><string>serve</string>
		<string>-dir</string><string>$WORK</string>
		<string>-owner</string><string>$OWNER</string>
	</array>
	<key>AssociatedBundleIdentifiers</key><array><string>$BID</string></array>
	<key>RunAtLoad</key><true/>
	<key>KeepAlive</key><true/>
	<key>StandardOutPath</key><string>$WORK/daemon.log</string>
	<key>StandardErrorPath</key><string>$WORK/daemon.log</string>
</dict></plist>
EOF
	chown root:wheel $PLIST; chmod 644 $PLIST
	launchctl bootstrap system $PLIST
	sleep 1
	chmod 644 $WORK/daemon.log 2>/dev/null || true
	launchctl print system/$BID | grep -E "state =|pid =|program =" | head -3
	cat $WORK/daemon.log
	;;
job)
	N=${2:?job name}; shift 2
	python3 -c 'import json,sys; print(json.dumps({"args": sys.argv[1:]}))' "$@" > "$WORK/jobs/.$N.tmp"
	rm -f "$WORK/out/$N.done" "$WORK/out/$N.log"
	mv "$WORK/jobs/.$N.tmp" "$WORK/jobs/$N.json"
	;;
restart)
	launchctl kickstart -k system/$BID
	sleep 1; chmod 644 $WORK/daemon.log; tail -4 $WORK/daemon.log
	;;
uninstall)
	launchctl bootout system "$PLIST" 2>/dev/null || true
	rm -f $PLIST
	rm -rf "$(dirname "$DST")" $WORK
	tccutil reset SystemPolicyAllFiles $BID 2>&1 || true
	echo "removed. If '$NAME' is still listed under Full Disk Access, select it and press the minus button."
	;;
*)
	sed -n '2,20p' "$0"; exit 2 ;;
esac
