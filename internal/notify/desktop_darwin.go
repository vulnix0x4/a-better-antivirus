package notify

// Notifications, questions and administrator prompts on macOS, through
// AppleScript (osascript), which every Mac has. These run in the person's own
// session, as them: the service starts the popup there (package session).

import (
	"os/exec"
	"strings"
)

// osascript runs an AppleScript that takes its text as arguments (never
// pasted into the script, so nothing in an alert can change what it does).
func osascript(lines []string, args ...string) (string, error) {
	var a []string
	for _, l := range lines {
		a = append(a, "-e", l)
	}
	out, err := exec.Command("/usr/bin/osascript", append(a, args...)...).Output()
	return strings.TrimSpace(string(out)), err
}

// Toast shows a notification (best effort, non-blocking).
func Toast(title, body string) {
	_, err := osascript([]string{"on run argv", "display notification (item 2 of argv) with title (item 1 of argv)", "end run"}, title, body)
	if err != nil {
		lastToastErr = err.Error()
	}
}

// messageBox puts a question on the screen, on top of everything, and waits
// for the answer. flags say which buttons and icon (mbYesNo, mbIconError…);
// the answer is idYes, idNo, or anything else for "closed without choosing".
func messageBox(title, text string, flags uint32) int32 {
	buttons, def := `{"OK"}`, `"OK"`
	switch flags & 0xf {
	case mbYesNo:
		buttons, def = `{"No", "Yes"}`, `"Yes"`
	case mbYesNoCancel:
		buttons, def = `{"Cancel", "No", "Yes"}`, `"Yes"`
	}
	icon := "note"
	switch flags & 0xf0 {
	case mbIconError:
		icon = "stop"
	case mbIconWarning:
		icon = "caution"
	}
	out, err := osascript([]string{
		"on run argv",
		"activate",
		"display dialog (item 2 of argv) with title (item 1 of argv) buttons " + buttons + " default button " + def + " with icon " + icon,
		"return button returned of result",
		"end run",
	}, title, text)
	switch {
	case err != nil:
		return 0 // Cancel, or the dialog couldn't be shown
	case out == "Yes":
		return idYes
	case out == "No":
		return idNo
	case out == "OK":
		return 1
	}
	return 0
}

// RunElevated starts aba with args with administrator rights, after macOS
// has asked the person at the screen for an administrator's password (the
// password is the proof a human, not malware, asked for it).
func RunElevated(exe string, args ...string) error {
	_, err := osascript([]string{
		"on run argv",
		`set cmd to ""`,
		"repeat with a in argv",
		`set cmd to cmd & quoted form of a & " "`,
		"end repeat",
		`do shell script cmd with prompt "A Better Antivirus needs an administrator's password to do this." with administrator privileges`,
		"end run",
	}, append([]string{exe}, args...)...)
	return err
}

var lastToastErr string

// vouchLabel names what vouches for a program, in an alert's details.
const vouchLabel = "Signature"
