package classify

import (
	"testing"

	"github.com/vulnix0x4/a-better-antivirus/internal/authenticode"
	"github.com/vulnix0x4/a-better-antivirus/internal/config"
)

var env = Env{
	WinDir: `C:\Windows`, WinTemp: `C:\Windows\Temp`,
	ProgramFiles: `C:\Program Files`, ProgramFilesX86: `C:\Program Files (x86)`, ProgramData: `C:\ProgramData`,
}

var (
	ms       = authenticode.Result{Signed: true, Valid: true, Signer: "Microsoft Corporation"}
	discord  = authenticode.Result{Signed: true, Valid: true, Signer: "Discord Inc."}
	unsigned = authenticode.Result{}
	tampered = authenticode.Result{Signed: true, Valid: false, Error: "bad digest"}
)

func TestTiers(t *testing.T) {
	c := &Classifier{Env: env}
	cases := []struct {
		name  string
		image string
		pid   uint32
		sig   authenticode.Result
		bait  Bait
		tier  config.Tier
		ign   bool
		owner bool
	}{
		{"stealer in temp", `C:\Users\bob\AppData\Local\Temp\x7f3\svchost.exe`, 100, unsigned, Bait{}, config.TierCritical, false, false},
		{"stealer in downloads", `C:\Users\bob\Downloads\FreeRobux.exe`, 100, unsigned, Bait{}, config.TierCritical, false, false},
		{"tampered sig in appdata", `C:\Users\bob\AppData\Roaming\upd.exe`, 100, tampered, Bait{}, config.TierCritical, false, false},
		{"copilot", `C:\Program Files (x86)\Microsoft\Copilot\Application\copilotapp.exe`, 100, ms, Bait{}, config.TierInfo, false, false},
		{"unsigned in program files", `C:\Program Files\Foo\foo.exe`, 100, unsigned, Bait{}, config.TierWarn, false, false},
		{"powershell", `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, 100, ms, Bait{}, config.TierCritical, false, false},
		{"notepad", `C:\Windows\System32\notepad.exe`, 100, ms, Bait{}, config.TierInfo, false, false},
		{"signed node in appdata", `C:\Users\bob\AppData\Roaming\nvm\v22\node.exe`, 100, authenticode.Result{Signed: true, Valid: true, Signer: "OpenJS Foundation"}, Bait{}, config.TierWarn, false, false},
		{"unsigned python", `C:\Users\bob\AppData\Local\Temp\_MEI1\python.exe`, 100, unsigned, Bait{}, config.TierCritical, false, false},
		{"signed app in user folder", `C:\Users\bob\AppData\Local\Programs\Microsoft VS Code\Code.exe`, 100, ms, Bait{}, config.TierWarn, false, false},
		{"smb/kernel", ``, 4, unsigned, Bait{}, config.TierWarn, false, false},
		{"defender", `C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.24090.11-0\MsMpEng.exe`, 100, ms, Bait{}, config.TierInfo, true, false},
		{"fake defender in temp", `C:\Users\bob\AppData\Local\Temp\MsMpEng.exe`, 100, unsigned, Bait{}, config.TierCritical, false, false},
		{"windows temp", `C:\Windows\Temp\a.exe`, 100, unsigned, Bait{}, config.TierCritical, false, false},
		{"real discord owns decoy", `C:\Users\bob\AppData\Local\Discord\app-1.0.9172\Discord.exe`, 100, discord,
			Bait{ID: "discord", OwnerExes: []string{"discord.exe"}, OwnerSigner: "Discord"}, config.TierInfo, false, true},
		{"fake discord (unsigned) on decoy", `C:\Users\bob\AppData\Local\Discord\Discord.exe`, 100, unsigned,
			Bait{ID: "discord", OwnerExes: []string{"discord.exe"}, OwnerSigner: "Discord"}, config.TierCritical, false, false},
	}
	for _, tc := range cases {
		v := c.Final(tc.image, tc.pid, tc.bait, tc.sig)
		if v.Tier != tc.tier || v.Ignored != tc.ign || v.DecoyOwner != tc.owner {
			t.Errorf("%s: got %+v; want tier=%s ignored=%v owner=%v", tc.name, v, tc.tier, tc.ign, tc.owner)
		}
	}
}

func TestPrelimAssumesUnsigned(t *testing.T) {
	c := &Classifier{Env: env}
	if v := c.Prelim(`C:\Users\bob\AppData\Local\Programs\Microsoft VS Code\Code.exe`, 1, Bait{}); v.Tier != config.TierCritical {
		t.Fatalf("prelim for user-folder app should be critical (freeze first, verify after): %+v", v)
	}
	if v := c.Prelim(`C:\Program Files\Foo\foo.exe`, 1, Bait{}); v.Tier != config.TierWarn {
		t.Fatalf("prelim program files: %+v", v)
	}
}

func TestIgnoreRules(t *testing.T) {
	c := &Classifier{Env: env, Ignore: []config.IgnoreRule{
		{Path: `C:\Program Files (x86)\Microsoft\Copilot\**\copilotapp.exe`, Signer: "Microsoft"},
		{Path: `C:\Users\*\AppData\Local\Backblaze\bztransmit*.exe`},
	}}
	if v := c.Final(`C:\Program Files (x86)\Microsoft\Copilot\Application\copilotapp.exe`, 1, Bait{}, ms); !v.Ignored {
		t.Fatal("copilot rule should match")
	}
	// Same path but unsigned (e.g. replaced) must not match a signer rule.
	if v := c.Final(`C:\Program Files (x86)\Microsoft\Copilot\Application\copilotapp.exe`, 1, Bait{}, unsigned); v.Ignored {
		t.Fatal("signer rule matched an unsigned binary")
	}
	// Signer rules can't match before the signature is known.
	if v := c.Prelim(`C:\Program Files (x86)\Microsoft\Copilot\Application\copilotapp.exe`, 1, Bait{}); v.Ignored {
		t.Fatal("signer rule matched in prelim")
	}
	if v := c.Prelim(`C:\Users\bob\AppData\Local\Backblaze\bztransmit64.exe`, 1, Bait{}); !v.Ignored {
		t.Fatal("path-only rule should match in prelim")
	}
}

func TestGlobAndGeneralize(t *testing.T) {
	if !Glob(`C:\a\*\c.exe`, `c:\A\b\C.EXE`) || Glob(`C:\a\*\c.exe`, `C:\a\b\x\c.exe`) || !Glob(`C:\a\**\c.exe`, `C:\a\b\x\c.exe`) {
		t.Fatal("glob semantics")
	}
	got := GeneralizePath(`C:\Users\bob\AppData\Local\Discord\app-1.0.9172\Discord.exe`)
	if got != `C:\Users\bob\AppData\Local\Discord\app-*\Discord.exe` {
		t.Fatalf("generalize: %s", got)
	}
	got = GeneralizePath(`C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.24090.11-0\MsMpEng.exe`)
	if got != `C:\ProgramData\Microsoft\Windows Defender\Platform\*\MsMpEng.exe` {
		t.Fatalf("generalize: %s", got)
	}
}
