package cli

// The CLI's words that describe how the system does things: on macOS, what it
// has shown so far (the Windows wording); its port chooses its own.
var words = struct {
	watchedBy, welcomeWatch, testNothingLeaves, testNetwork        string
	uninstallShort, uninstallDesc, uninstallDone                   string
	signed, unsigned, learnWarning, noRules, ignoreExample, tricks string
	catalogShort, renameShort, instantLong                         string
	demoTitle, demoSummary, demoBait, demoImage                    string
}{
	watchedBy:         "%d planted, watched by Windows' own file auditing",
	welcomeWatch:      "Watches them with Windows' own file auditing",
	testNothingLeaves: "You'll watch it get frozen and see the alert popup. Nothing leaves your PC.",
	testNetwork:       "exactly the way a stealer would. Nothing leaves your PC and your network isn't touched.",
	uninstallShort:    "Remove it and every bait, restoring Windows",
	uninstallDesc:     "Removes the service, every bait and any network blocks, and puts Windows' audit setting\nback the way it was.",
	uninstallDone:     " Windows' settings are back to how they were.",
	signed:            "  signed: ",
	unsigned:          "  UNSIGNED",
	learnWarning:      "Only ignore software you recognise. Unsigned programs are almost never safe to ignore.",
	noRules:           "No ignore rules (Defender and Windows Search are always ignored).",
	ignoreExample:     `  aba ignore add "C:\Program Files\Backblaze\bztransmit64.exe" --signer Backblaze`,
	tricks:            "--allow-tricks needs --signer for a program outside Program Files and Windows: anything could be put at that path later",
	catalogShort:      "Every bait ABA knows and whether it fits this PC",
	renameShort:       "Give the baits new file names, this PC's own",
	instantLong: "Instant freeze holds every bait with a Windows oplock. When a program opens one, Windows\n" +
		"pauses it inside the open; ABA works out who it is and, if it's suspicious, freezes it\n" +
		"before it reads anything. The normal detection keeps running as a backup.",
	demoTitle:   "Possible stealer: FreeRobux.exe read your bait",
	demoSummary: `DEMO: unsigned program running from a user-writable folder (C:\Users\you\Downloads): typical of stealers`,
	demoBait:    `C:\Users\you\Desktop\passwords.txt`,
	demoImage:   `C:\Users\you\Downloads\FreeRobux.exe`,
}
