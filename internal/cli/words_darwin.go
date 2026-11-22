package cli

// The CLI's words that describe how macOS does things: a launchd service
// that watches the baits through Apple's Endpoint Security (eslogger, which
// needs Full Disk Access) and hears of an open a moment after it happened,
// code signatures, root.
var words = struct {
	watchedBy, welcomeWatch, welcomeNote, testNothingLeaves, testNetwork string
	uninstallShort, uninstallDesc, uninstallDone                         string
	signed, unsigned, learnWarning, noRules, ignoreExample, tricks       string
	catalogShort, renameShort, instantLong                               string
	demoTitle, demoSummary, demoBait, demoImage                          string
}{
	watchedBy:         "%d planted, watched through Apple's Endpoint Security (eslogger)",
	welcomeWatch:      "Watches them through Apple's Endpoint Security",
	welcomeNote:       "no kernel extension, no scanning of your files",
	testNothingLeaves: "You'll watch it get frozen and see the alert. Nothing leaves your Mac.",
	testNetwork:       "exactly the way a stealer would. Nothing leaves your Mac and your network isn't touched.",
	uninstallShort:    "Remove it and every bait, and undo everything it changed",
	uninstallDesc:     "Removes the service, every bait and ABA's network rules (pf), lets go of anything still frozen,\nand takes back its Full Disk Access.",
	uninstallDone:     " Everything it changed is undone.",
	signed:            "  signed: ",
	unsigned:          "  NO VALID SIGNATURE",
	learnWarning:      "Only ignore software you recognise. Programs without a valid signature are almost never safe to ignore.",
	noRules:           "No ignore rules (Spotlight, Time Machine, XProtect and known antivirus scanners are always ignored).",
	ignoreExample:     `  sudo aba ignore add "/Applications/Your Backup.app/**" --signer "Your Backup's developer"`,
	tricks:            "--allow-tricks needs --signer for a program in a folder you can write to: anything could be put at that path later",
	catalogShort:      "Every bait ABA knows and whether it fits this Mac",
	renameShort:       "Give the baits new file names, this Mac's own",
	instantLong: "On macOS ABA hears of a bait being opened from Apple's Endpoint Security (eslogger), a few\n" +
		"milliseconds after the open, and freezes a suspicious opener right then. macOS doesn't let it\n" +
		"hold a program inside its open yet, so this setting changes nothing here.",
	demoTitle:   "Possible stealer: FreeRobux read your bait",
	demoSummary: "DEMO: program with no valid signature (unsigned), running from /Users/you/Downloads: typical of stealers",
	demoBait:    "/Users/you/Desktop/passwords.txt",
	demoImage:   "/Users/you/Downloads/FreeRobux",
}
