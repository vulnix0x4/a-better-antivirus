package cli

// The CLI's words that describe how Linux does things.
var words = struct {
	watchedBy, welcomeWatch, welcomeNote, testNothingLeaves, testNetwork string
	uninstallShort, uninstallDesc, uninstallDone                         string
	signed, unsigned, learnWarning, noRules, ignoreExample, tricks       string
	catalogShort, renameShort, instantLong                               string
	demoTitle, demoSummary, demoBait, demoImage                          string
}{
	watchedBy:         "%d planted, watched by the kernel (fanotify)",
	welcomeWatch:      "Has the kernel watch them (fanotify)",
	welcomeNote:       "no driver, no scanning, no slowdown",
	testNothingLeaves: "You'll watch it get frozen and see the alert. Nothing leaves this machine.",
	testNetwork:       "exactly the way a stealer would. Nothing leaves this machine and your network isn't touched.",
	uninstallShort:    "Remove it and every bait, and undo everything it changed",
	uninstallDesc:     "Removes the service, every bait, ABA's firewall rules and its frozen and cut-off groups,\nletting go of anything still in them.",
	uninstallDone:     " Everything it changed is undone.",
	signed:            "  package: ",
	unsigned:          "  NO PACKAGE",
	learnWarning:      "Only ignore software you recognise. Programs no package owns are almost never safe to ignore.",
	noRules:           "No ignore rules (desktop search and antivirus scanners are always ignored).",
	ignoreExample:     `  sudo aba ignore add "/usr/bin/restic" --signer restic`,
	tricks:            "--allow-tricks needs --signer for a program in a folder you can write to: anything could be put at that path later",
	catalogShort:      "Every bait ABA knows and whether it fits this machine",
	renameShort:       "Give the baits new file names, this machine's own",
	instantLong: "On Linux the kernel stops every program that opens a bait inside the open and waits for ABA\n" +
		"(fanotify). With instant freeze on, a suspicious one is frozen right there, before it reads\n" +
		"anything. Off, it's let through and frozen a moment later, once ABA has judged it.",
	demoTitle:   "Possible stealer: free-robux read your bait",
	demoSummary: "DEMO: program nobody vouches for, running from a folder you can write to (/home/you/Downloads): typical of stealers",
	demoBait:    "/home/you/Desktop/passwords.txt",
	demoImage:   "/home/you/Downloads/free-robux",
}
