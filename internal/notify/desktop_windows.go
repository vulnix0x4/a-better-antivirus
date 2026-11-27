package notify

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
)

// toastScript shows a notification with the title and body it finds in the
// ABA_TOAST_TITLE and ABA_TOAST_BODY environment variables. It is the same
// text every time, in plain sight on PowerShell's command line: what an alert
// says reaches it only as data (XML text nodes, so nothing in it is markup or
// code), never as part of the command.
const toastScript = `[void][Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]; ` +
	`[void][Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime]; ` +
	`$x = New-Object Windows.Data.Xml.Dom.XmlDocument; ` +
	`$x.LoadXml('<toast><visual><binding template=''ToastGeneric''><text/><text/></binding></visual><audio src=''ms-winsoundevent:Notification.Looping.Alarm2''/></toast>'); ` +
	`$t = $x.GetElementsByTagName('text'); ` +
	`[void]$t.Item(0).AppendChild($x.CreateTextNode($env:ABA_TOAST_TITLE)); ` +
	`[void]$t.Item(1).AppendChild($x.CreateTextNode($env:ABA_TOAST_BODY)); ` +
	`$id = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'; ` +
	`[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($id).Show([Windows.UI.Notifications.ToastNotification]::new($x))`

// Toast shows a Windows notification (best effort, non-blocking).
func Toast(title, body string) {
	cmd := toastCmd(title, body)
	// PowerShell may print progress records; only a failed run is an error.
	if out, err := toastRun(cmd); err != nil {
		lastToastErr = fmt.Sprintf("%v %s", err, out)
	}
}

// toastCmd is the PowerShell run that shows one notification.
func toastCmd(title, body string) *exec.Cmd {
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", toastScript)
	cmd.Env = append(os.Environ(), "ABA_TOAST_TITLE="+oneLine(title), "ABA_TOAST_BODY="+oneLine(body))
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
	return cmd
}

// oneLine keeps an environment variable's value on one line, without the
// characters Windows can't carry in one.
func oneLine(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == 0:
			return -1
		case r < 0x20:
			return ' '
		}
		return r
	}, s)
}

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

// toastRun is swapped in tests to capture PowerShell's output.
var toastRun = func(cmd *exec.Cmd) ([]byte, error) { return nil, cmd.Start() }

var lastToastErr string

// vouchLabel names what vouches for a program, in an alert's details.
const vouchLabel = "Signature"
