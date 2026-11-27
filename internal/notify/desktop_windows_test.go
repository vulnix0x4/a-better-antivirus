package notify

import (
	"strings"
	"testing"

	"github.com/vulnix0x4/a-better-antivirus/internal/alerts"
	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/procinfo"
	"github.com/vulnix0x4/a-better-antivirus/internal/provenance"
)

func TestPopupTextReadsCleanly(t *testing.T) {
	a := &alerts.Alert{Summary: "unsigned program running from a user-writable folder",
		Baits:   []alerts.BaitHit{{Name: "passwords.txt on the Desktop", Path: `C:\Users\you\Desktop\passwords.txt`, Access: "read"}},
		Process: &alerts.Process{PID: 4242, Image: `C:\Users\you\Downloads\FreeRobux.exe`, Parents: []procinfo.Parent{{PID: 1, Image: `C:\Windows\explorer.exe`}}}}
	a.AddAction(config.ActionFreeze, nil, "2 process(es) frozen")
	a.AddAction(config.ActionBlockProgram, nil, `C:\Users\you\Downloads\FreeRobux.exe`)
	got := Details(a)
	for _, want := range []string{"Program: FreeRobux.exe (pid 4242)", "Started by: explorer.exe", "It read: passwords.txt on the Desktop",
		"What ABA did:", "✓ Froze it and 1 process(es) it started", "✓ Cut its internet"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, "   ") {
		t.Errorf("column padding left in popup text:\n%s", got)
	}
	if testing.Verbose() {
		t.Log("\n" + got)
	}
}

func TestMinerPopupSaysTheSignedFileWasHijacked(t *testing.T) {
	a := &alerts.Alert{Kind: alerts.KindMiner, Summary: "it tried to mine cryptocurrency on this PC",
		Mine: &alerts.Mine{Wallet: "43iNancbmDEMOkv43M"},
		Process: &alerts.Process{PID: 6892, Image: `C:\Windows\System32\conhost.exe`,
			Signature: provenance.Result{Signed: true, Valid: true, Signer: "Microsoft Windows", Catalog: true}}}
	got := Details(a)
	for _, want := range []string{"It tried to mine cryptocurrency", "The file itself is genuine: the miner is hiding inside it", "Wallet it mines for: 43iNancbmDEMOkv43M"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	// Other alerts keep their signature line as it was.
	a.Kind = ""
	if got := Details(a); strings.Contains(got, "hiding inside") {
		t.Errorf("non-miner alert mentions a hidden miner:\n%s", got)
	}
}

func TestSentence(t *testing.T) {
	for in, want := range map[string]string{"": "", "it read": "It read", "Already": "Already", "écrit": "Écrit"} {
		if got := sentence(in); got != want {
			t.Errorf("sentence(%q) = %q, want %q", in, got, want)
		}
	}
}

// The notification's PowerShell command is the same plain text every time:
// no encoded command, and what the alert says only in the environment.
func TestToastCommandIsPlain(t *testing.T) {
	title, body := `ABA: "x" & <y> '; Remove-Item C:\ -Recurse`, "line one\nline two $(whoami)"
	cmd := toastCmd(title, body)
	for _, a := range cmd.Args {
		if strings.Contains(strings.ToLower(a), "encodedcommand") || strings.Contains(a, "whoami") || strings.Contains(a, "Remove-Item") {
			t.Errorf("alert text or an encoded command on the command line: %q", cmd.Args)
		}
	}
	if strings.Contains(toastScript, `"`) {
		t.Error("the script has a double quote: Windows' command-line quoting would mangle it")
	}
	env := strings.Join(cmd.Env, "\x00")
	if !strings.Contains(env, "ABA_TOAST_TITLE="+title) || !strings.Contains(env, "ABA_TOAST_BODY=line one line two $(whoami)") {
		t.Errorf("title or body not passed as data: %q", cmd.Env[len(cmd.Env)-2:])
	}
}
