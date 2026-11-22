package notify

import (
	"encoding/base64"
	"fmt"
	"os/exec"
	"strings"
	"syscall"
	"unicode/utf16"

	"golang.org/x/sys/windows"
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
	// PowerShell may print progress records; only a failed run is an error.
	if out, err := toastRun(cmd); err != nil {
		lastToastErr = fmt.Sprintf("%v %s", err, out)
	}
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
