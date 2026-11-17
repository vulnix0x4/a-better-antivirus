package notify

import (
	"encoding/base64"
	"fmt"
	"os/exec"
	"strings"
	"syscall"
	"unicode/utf16"

	"golang.org/x/sys/windows"

	"github.com/vulnix0x4/a-better-antivirus/internal/alerts"
	"github.com/vulnix0x4/a-better-antivirus/internal/config"
)

// Toast shows a Windows notification (best effort, non-blocking).
func Toast(title, body string) {
	esc := func(s string) string {
		r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&apos;")
		return r.Replace(s)
	}
	xml := fmt.Sprintf(`<toast><visual><binding template="ToastGeneric"><text>%s</text><text>%s</text></binding></visual><audio src="ms-winsoundevent:Notification.Looping.Alarm2"/></toast>`, esc(title), esc(body))
	script := `
[void][Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]
[void][Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime]
$x = New-Object Windows.Data.Xml.Dom.XmlDocument
$x.LoadXml(@'
` + xml + `
'@)
$id = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($id).Show([Windows.UI.Notifications.ToastNotification]::new($x))
`
	u := utf16.Encode([]rune(script))
	b := make([]byte, len(u)*2)
	for i, c := range u {
		b[2*i], b[2*i+1] = byte(c), byte(c>>8)
	}
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-EncodedCommand", base64.StdEncoding.EncodeToString(b))
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
	cmd.Start()
}

const (
	mbOK            = 0x0
	mbYesNoCancel   = 0x3
	mbYesNo         = 0x4
	mbIconError     = 0x10
	mbIconWarning   = 0x30
	mbIconInfo      = 0x40
	mbSetForeground = 0x10000
	mbTopmost       = 0x40000
	idYes           = 6
	idNo            = 7
)

func messageBox(title, text string, flags uint32) int32 {
	t, _ := windows.UTF16PtrFromString(text)
	c, _ := windows.UTF16PtrFromString(title)
	r, _ := windows.MessageBox(0, t, c, flags|mbTopmost|mbSetForeground)
	return r
}

// RunElevated starts aba with args via a UAC prompt (the click is the proof
// a human, not malware, asked for it).
func RunElevated(exe string, args ...string) error {
	verb, _ := windows.UTF16PtrFromString("runas")
	file, _ := windows.UTF16PtrFromString(exe)
	a, _ := windows.UTF16PtrFromString(strings.Join(quoteAll(args), " "))
	return windows.ShellExecute(0, verb, file, a, nil, windows.SW_SHOWNORMAL)
}

func quoteAll(args []string) []string {
	out := make([]string, len(args))
	for i, a := range args {
		out[i] = syscall.EscapeArg(a)
	}
	return out
}

// Details renders the long form of an alert for the popup.
func Details(a *alerts.Alert) string {
	var b strings.Builder
	fmt.Fprintln(&b, a.Summary)
	fmt.Fprintln(&b)
	for _, h := range a.Baits {
		fmt.Fprintf(&b, "Bait:      %s\n           %s\n", h.Name, h.Path)
	}
	if p := a.Process; p != nil {
		fmt.Fprintf(&b, "Process:   %s (pid %d)\n", a.ExeName(), p.PID)
		if p.Image != "" {
			fmt.Fprintf(&b, "Path:      %s\n", p.Image)
		}
		fmt.Fprintf(&b, "Signature: %s\n", p.Signature)
		if len(p.Parents) > 0 {
			par := p.Parents[0]
			name := par.Image
			if name == "" {
				name = "(exited)"
			}
			fmt.Fprintf(&b, "Parent:    %s (pid %d)\n", name, par.PID)
		}
	}
	if len(a.Verdict.Reasons) > 0 {
		fmt.Fprintf(&b, "Why:       %s\n", a.Verdict.Reasons[0])
	}
	if len(a.Actions) > 0 {
		fmt.Fprintln(&b)
		for _, r := range a.Actions {
			mark := "✓"
			if !r.OK {
				mark = "✗ FAILED:"
			}
			fmt.Fprintf(&b, "%s %s %s\n", mark, config.Action(r.Action).Describe(), r.Detail)
		}
	}
	if a.Learning {
		fmt.Fprintln(&b, "\nLearning mode: nothing was blocked. Review with `aba learn`.")
	}
	return b.String()
}

// ShowPopup displays the alert and acts on the user's choice. cli is the
// installed aba.exe used for privileged follow-ups.
func ShowPopup(a *alerts.Alert, cli string) {
	title := "ABA: " + a.Title
	body := Details(a)
	frozen := a.Did(config.ActionFreeze) && !a.Did(config.ActionKill)
	isolated := a.Did(config.ActionIsolate) || a.Did(config.ActionDisableAdapters)

	switch {
	case a.Test:
		messageBox(title, body+"\nThis was a test. Everything worked.", mbOK|mbIconInfo)
	case frozen:
		text := body + "\nWhat should happen to it?\n\nYes = Kill it (recommended if you didn't do this)\nNo = It's mine: unfreeze it and restore its internet\nCancel = Decide later (it stays frozen)"
		if isolated {
			text += "\n\nYour PC is isolated from the network. When it's safe, run `aba release` as admin."
		}
		switch messageBox(title, text, mbYesNoCancel|mbIconError) {
		case idYes:
			RunElevated(cli, "kill", a.ID)
		case idNo:
			RunElevated(cli, "resume", a.ID)
		}
	case isolated:
		text := body + "\nYour PC is isolated from the network (ABA's own alerts still get out).\n\nYes = Restore the internet now (only if you're sure)\nNo = Keep it isolated"
		if messageBox(title, text, mbYesNo|mbIconError) == idYes {
			RunElevated(cli, "release")
		}
	case a.Tier == config.TierCritical:
		messageBox(title, body, mbOK|mbIconError)
	default:
		messageBox(title, body, mbOK|mbIconWarning)
	}
}
