package appsec

import (
	"slices"
	"testing"
)

func TestScrubWebView2Env(t *testing.T) {
	in := []string{
		"PATH=C:\\Windows",
		"WEBVIEW2_BROWSER_EXECUTABLE_FOLDER=C:\\Users\\x\\evil",
		"webview2_additional_browser_arguments=--remote-debugging-port=9222",
		"WebView2_User_Data_Folder=C:\\Users\\x\\p",
		"WEBVIEW2_RELEASE_CHANNEL_PREFERENCE=1",
		"WEBVIEW2=not a prefix match",
		"MYWEBVIEW2_X=kept",
		"=C:=C:\\x",
		"EMPTY=",
	}
	keep, removed := ScrubWebView2Env(in)
	wantKeep := []string{"PATH=C:\\Windows", "WEBVIEW2=not a prefix match", "MYWEBVIEW2_X=kept", "=C:=C:\\x", "EMPTY="}
	if !slices.Equal(keep, wantKeep) {
		t.Errorf("keep = %q, want %q", keep, wantKeep)
	}
	wantRemoved := []string{"WEBVIEW2_BROWSER_EXECUTABLE_FOLDER", "webview2_additional_browser_arguments", "WebView2_User_Data_Folder", "WEBVIEW2_RELEASE_CHANNEL_PREFERENCE"}
	if !slices.Equal(removed, wantRemoved) {
		t.Errorf("removed = %q, want %q", removed, wantRemoved)
	}
}

func TestValidateRuntimeDir(t *testing.T) {
	roots := []string{`C:\Program Files (x86)`, `C:\Program Files\`}
	good := []string{
		`C:\Program Files (x86)\Microsoft\EdgeWebView\Application\142.0.3595.80`,
		`c:\program files (x86)\microsoft\edgewebview\application\142.0.3595.80`,
		`C:\Program Files\Microsoft\EdgeWebView\Application\1.2.3.4`,
	}
	for _, d := range good {
		if err := ValidateRuntimeDir(d, roots); err != nil {
			t.Errorf("%s: %v", d, err)
		}
	}
	bad := []string{
		``,
		`142.0.3595.80`,
		`\\server\share\Microsoft\EdgeWebView\Application\142.0.3595.80`,
		`\\?\C:\Program Files (x86)\Microsoft\EdgeWebView\Application\142.0.3595.80`,
		`C:\Users\x\AppData\Local\Microsoft\EdgeWebView\Application\142.0.3595.80`,
		`C:\Program Files (x86)\Microsoft\EdgeWebView\Application\..\..\..\..\Users\x\142.0.3595.80`,
		`C:\Program Files (x86)\Microsoft\EdgeWebView\Application\142.0.3595.80\..`,
		`C:\Program Files (x86)\Microsoft\EdgeWebView\Application\142.0.3595.80\sub`,
		`C:\Program Files (x86)\Microsoft\EdgeWebView\Application\latest`,
		`C:\PROGRA~2\Microsoft\EdgeWebView\Application\142.0.3595.80`,
		`C:\Program Files (x86)\Microsoft\EdgeWebView\Application\142.0.3595.80.`,
		`C:\Program Files (x86)\Microsoft\EdgeWebView\Application\142.0.3595.80:ads`,
		`C:\Program Files (x86)\Microsoft\EdgeWebView\Application\142.0.3595.80 `,
		`C:\Program Files (x86)\Microsoft\EdgeWebView\Application\\142.0.3595.80`,
		`C:/Program Files (x86)/Microsoft/EdgeWebView/Application/142.0.3595.80`,
		`D:\Program Files (x86)\Microsoft\EdgeWebView\Application\142.0.3595.80`,
		`C:\Program Files (x86)Evil\Microsoft\EdgeWebView\Application\142.0.3595.80`,
	}
	for _, d := range bad {
		if err := ValidateRuntimeDir(d, roots); err == nil {
			t.Errorf("%q accepted", d)
		}
	}
	if err := ValidateRuntimeDir(good[0], []string{`C:\Program Files\..`, ``}); err == nil {
		t.Error("accepted with no usable root")
	}
	if got := RuntimeDir(`C:\Program Files (x86)\Microsoft\EdgeWebView\Application\`, "1.2.3.4"); got != `C:\Program Files (x86)\Microsoft\EdgeWebView\Application\1.2.3.4` {
		t.Errorf("RuntimeDir = %q", got)
	}
}

func TestUntrustedWriters(t *testing.T) {
	const users, auth, me = "S-1-5-32-545", "S-1-5-11", "S-1-5-21-1-2-3-1001"
	// What Program Files (x86) looks like.
	programFiles := []ACE{
		{Allow: true, Mask: 0x1301bf, SID: SIDSystem},
		{Allow: true, Mask: 0x10000000, SID: SIDSystem, InheritOnly: true},
		{Allow: true, Mask: 0x1301bf, SID: SIDAdministrators},
		{Allow: true, Mask: 0x1200a9, SID: users},
		{Allow: true, Mask: 0xa0000000, SID: users, InheritOnly: true},
		{Allow: true, Mask: 0x1f01ff, SID: SIDTrustedInstaller},
		{Allow: true, Mask: 0x10000000, SID: "S-1-3-0", InheritOnly: true}, // CREATOR OWNER
		{Allow: true, Mask: 0x1200a9, SID: "S-1-15-2-1"},                   // ALL APPLICATION PACKAGES
	}
	if w := UntrustedWriters(SIDTrustedInstaller, programFiles); w != nil {
		t.Errorf("Program Files: %q", w)
	}
	cases := map[string]struct {
		owner string
		aces  []ACE
	}{
		"user owner":           {me, programFiles},
		"users may write":      {SIDSystem, append(programFiles, ACE{Allow: true, Mask: 0x2, SID: users})},
		"auth users modify":    {SIDSystem, []ACE{{Allow: true, Mask: 0x1301bf, SID: auth}}},
		"everyone generic all": {SIDSystem, []ACE{{Allow: true, Mask: 0x10000000, SID: "S-1-1-0"}}},
		"user may rewrite acl": {SIDSystem, []ACE{{Allow: true, Mask: 0x40000, SID: me}}},
		"user may delete":      {SIDSystem, []ACE{{Allow: true, Mask: 0x10000, SID: me}}},
	}
	for name, c := range cases {
		if w := UntrustedWriters(c.owner, c.aces); len(w) == 0 {
			t.Errorf("%s: not caught", name)
		}
	}
	// A deny entry never makes things worse.
	if w := UntrustedWriters(SIDSystem, []ACE{{Allow: false, Mask: 0x10000000, SID: me}}); w != nil {
		t.Errorf("deny entry: %q", w)
	}
}

func TestValidAlertID(t *testing.T) {
	for _, id := range []string{"20261128-153012-ab12", "a", "x.y_z-1"} {
		if !ValidAlertID(id) {
			t.Errorf("%q rejected", id)
		}
	}
	for _, id := range []string{"", "..", "a..b", `..\x`, "a/b", `a\b`, "-x", ".x", "a b", "a\"b", string(make([]byte, 70))} {
		if ValidAlertID(id) {
			t.Errorf("%q accepted", id)
		}
	}
}
