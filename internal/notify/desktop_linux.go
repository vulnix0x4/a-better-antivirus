package notify

// Linux isn't supported yet: this file only lets the rest of ABA build there.
// Everything in it is what a Linux backend has to provide.

import "github.com/vulnix0x4/a-better-antivirus/internal/platform"

// Toast shows a desktop notification (best effort, non-blocking).
func Toast(title, body string) {
	lastToastErr = platform.Unsupported("showing a notification").Error()
}

// messageBox puts a question on the screen, on top of everything, and waits
// for the answer. flags say which buttons and icon (mbYesNo, mbIconError…);
// the answer is idYes, idNo, or anything else for "closed without choosing".
func messageBox(title, text string, flags uint32) int32 { return 0 }

// RunElevated starts aba with args with administrator rights, after the
// operating system has asked the person at the screen (the click is the proof
// a human, not malware, asked for it).
func RunElevated(exe string, args ...string) error {
	return platform.Unsupported("asking for administrator rights")
}

var lastToastErr string
