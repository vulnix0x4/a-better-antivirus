package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/vulnix0x4/a-better-antivirus/internal/appapi"
	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/doctor"
)

// Every command line the desktop app builds (appapi.Prepare) is one this
// CLI takes: the command exists, its flags parse, its arguments fit, and
// the ID after "--" stays an argument.
func TestAppCommandsParse(t *testing.T) {
	ex := appapi.Exists{
		Alert: func(string) bool { return true }, Bait: func(string) bool { return true },
		Catalog: func(string) bool { return true }, Rule: func(string) bool { return true },
	}
	const id = "20261127-140207-7f3a"
	cases := []struct{ kind, id, arg, wantArg string }{
		{"kill", id, "", id}, {"resume", id, "", id}, {"trust", id, "", id}, {"release", "", "", ""}, {"release", id, "", id},
		{"instant", "", "on", "on"}, {"clipboard", "", "off", "off"}, {"miners", "", "on", "on"}, {"recorder", "", "off", "off"},
		{"auto-update", "", "on", "on"}, {"preset", "", "strict", "strict"}, {"bait-show", "discord", "", "discord"},
		{"test", "", "", ""}, {"update-check", "", "", ""}, {"update", "", "", ""}, {"phone-test", "", "", ""},
		{"alert-json", id, "", id}, {"autopsy-now", id, "", id}, {"export-ioc", id, "", id},
		{"doctor", "", "", ""}, {"doctor-fix", "", "", ""}, {"learn-days", "", "3", ""}, {"learn-trust", "", "f51542e2a22a,07ff9b44dcbe", ""},
		{"ignore-add", "", `{"path":"C:\\Program Files\\Backblaze\\bztransmit64.exe","signer":"--allow-tricks","note":"-n x","allowTricks":true}`, `C:\Program Files\Backblaze\bztransmit64.exe`},
		{"ignore-remove", "3ca2e312d73e", "", "3ca2e312d73e"},
		{"bait-add", "chrome-profile", "", "chrome-profile"}, {"bait-add-file", "", `C:\Users\sam\-x.txt`, `C:\Users\sam\-x.txt`},
		{"bait-remove", "discord", "", "discord"}, {"bait-rename", "", "", ""},
		{"responses", "", `{"warn":[],"critical":["freeze","kill"]}`, "custom"}, {"recent", "", "on", "on"},
		{"phone-set", "", `{"kind":"ntfy","ntfy":{"topic":"abc"}}`, ""}, {"phone-off", "", "", ""}, {"phone-tier", "", "warn", "warn"},
		{"canary-on", "", `{"email":"a@b.co"}`, ""},
		{"clipboard-test", "", "", ""}, {"clipboard-key", "TJCnKsPa7y5okkXvQAidZBzqx3QyQ6sxMW", "", "TJCnKsPa7y5okkXvQAidZBzqx3QyQ6sxMW"},
		{"miners-test", "", "", ""}, {"uninstall", "", "", ""}, {"uninstall", "", "purge", ""},
	}
	for _, c := range cases {
		inv, err := appapi.Prepare(c.kind, c.id, c.arg, ex)
		if err != nil {
			t.Errorf("%s: %v", c.kind, err)
			continue
		}
		root := newRoot()
		cmd, rest, err := root.Find(inv.Args)
		if err != nil || cmd == root {
			t.Errorf("%s: %q: no such command (%v)", c.kind, inv.Args, err)
			continue
		}
		if cmd.Hidden {
			t.Errorf("%s: runs hidden command %s", c.kind, cmd.CommandPath())
		}
		if err := cmd.ParseFlags(rest); err != nil {
			t.Errorf("%s: %q: %v", c.kind, inv.Args, err)
			continue
		}
		pos := cmd.Flags().Args()
		if cmd.Args != nil {
			if err := cmd.Args(cmd, pos); err != nil {
				t.Errorf("%s: %q: %v", c.kind, inv.Args, err)
			}
		}
		if c.wantArg != "" && (len(pos) == 0 || pos[len(pos)-1] != c.wantArg) {
			t.Errorf("%s: %q: arguments %q, want the last to be %q", c.kind, inv.Args, pos, c.wantArg)
		}
		for _, f := range []string{"json", "yes"} {
			if v, err := cmd.Flags().GetBool(f); err != nil || !v {
				t.Errorf("%s: --%s not set (%v)", c.kind, f, err)
			}
		}
		switch c.kind {
		case "ignore-add":
			if s, _ := cmd.Flags().GetString("signer"); s != "--allow-tricks" {
				t.Errorf("signer %q", s)
			}
			if n, _ := cmd.Flags().GetString("note"); n != "-n x" {
				t.Errorf("note %q", n)
			}
		case "responses":
			w, _ := cmd.Flags().GetString("warn")
			cr, _ := cmd.Flags().GetString("critical")
			if w != "" || cr != "freeze,kill" || !cmd.Flags().Changed("warn") {
				t.Errorf("warn %q critical %q", w, cr)
			}
		case "learn-days":
			if d, _ := cmd.Flags().GetInt("days"); d != 3 || !cmd.Flags().Changed("days") {
				t.Errorf("days %d", d)
			}
		case "bait-add-file":
			if f, _ := cmd.Flags().GetBool("file"); !f {
				t.Error("--file not set")
			}
		}
	}
}

func TestReadStdinJSON(t *testing.T) {
	defer func(r func() bool) { stdinIsTerminal = r; stdin = os.Stdin }(stdinIsTerminal)
	stdinIsTerminal = func() bool { return false }
	var p config.PhoneSetting
	stdin = strings.NewReader(`{"kind":"ntfy","ntfy":{"topic":"abc"},"minTier":"critical"}`)
	if err := readStdinJSON(&p, ""); err != nil || p.Ntfy.Topic != "abc" || p.MinTier != config.TierCritical {
		t.Fatalf("%+v %v", p, err)
	}
	for _, in := range []string{``, `{"kind":"ntfy","x":1}`, `{"kind":"ntfy"}{"kind":"email"}`, `[1]`, `{"kind":` + strings.Repeat(" ", maxStdin) + `"ntfy"}`} {
		stdin = strings.NewReader(in)
		if err := readStdinJSON(&config.PhoneSetting{}, ""); err == nil {
			t.Errorf("%.40q: read", in)
		}
	}
	stdinIsTerminal = func() bool { return true }
	stdin = strings.NewReader(`{"kind":"ntfy"}`)
	if err := readStdinJSON(&p, "example"); err == nil || !strings.Contains(err.Error(), "example") {
		t.Fatalf("a terminal: %v", err)
	}
}

// phoneSet refuses bad settings before it touches a file.
func TestPhoneSetChecksFirst(t *testing.T) {
	for _, in := range []config.PhoneSetting{
		{PhoneConfig: config.PhoneConfig{Kind: "ntfy", Ntfy: config.NtfyConfig{Topic: "a b"}}},
		{PhoneConfig: config.PhoneConfig{Kind: "ntfy", Ntfy: config.NtfyConfig{Topic: "ok"}, Discord: config.DiscordConfig{WebhookURL: "https://x"}}},
		{PhoneConfig: config.PhoneConfig{Kind: "ntfy", Ntfy: config.NtfyConfig{Topic: "ok"}}, MinTier: "loud"},
		{PhoneConfig: config.PhoneConfig{Kind: "sms"}},
	} {
		if err := phoneSet(in, false); err == nil || strings.Contains(err.Error(), "not installed") {
			t.Errorf("%+v: %v", in, err)
		}
	}
}

func TestParseActions(t *testing.T) {
	got, err := parseActions(" freeze, Block-Program ,,kill")
	if err != nil || !reflect.DeepEqual(got, []config.Action{config.ActionFreeze, config.ActionBlockProgram, config.ActionKill}) {
		t.Fatalf("%v %v", got, err)
	}
	if got, err := parseActions(""); err != nil || len(got) != 0 {
		t.Fatalf("%v %v", got, err)
	}
	for _, s := range []string{"nuke", "freeze,freeze", "freeze;kill"} {
		if _, err := parseActions(s); err == nil {
			t.Errorf("%q parsed", s)
		}
	}
}

func TestWriteNew(t *testing.T) {
	dir := t.TempDir()
	p1, err := writeNew(dir, "aba-ioc-x", ".json", []byte("1"))
	if err != nil || filepath.Base(p1) != "aba-ioc-x.json" {
		t.Fatal(p1, err)
	}
	// A link already there is never written through.
	target := filepath.Join(dir, "target")
	os.WriteFile(target, []byte("keep"), 0o644)
	if err := os.Symlink(target, filepath.Join(dir, "aba-ioc-x (2).json")); err != nil {
		t.Skip("no symlinks here:", err)
	}
	p3, err := writeNew(dir, "aba-ioc-x", ".json", []byte("3"))
	if err != nil || filepath.Base(p3) != "aba-ioc-x (3).json" {
		t.Fatal(p3, err)
	}
	if b, _ := os.ReadFile(target); string(b) != "keep" {
		t.Fatal("wrote through the link")
	}
	if b, _ := os.ReadFile(p1); string(b) != "1" {
		t.Fatal("overwrote the first")
	}
	if _, err := writeNew(filepath.Join(dir, "nope"), "a", ".json", nil); err == nil {
		t.Fatal("no folder: written")
	}
	if _, err := writeNew("relative", "a", ".json", nil); err == nil {
		t.Fatal("relative folder: written")
	}
}

func TestDetails(t *testing.T) {
	d := doctorDetails(true, []string{"Restarted the service"}, []doctor.Result{
		{Level: doctor.OK, Name: "Service", Detail: "running"},
		{Level: doctor.Problem, Name: "Baits", Detail: "2 missing", Fix: "aba doctor --fix"},
	})
	b, _ := json.Marshal(d)
	want := `{"checks":[{"level":"ok","name":"Service","detail":"running"},{"level":"problem","name":"Baits","detail":"2 missing","fix":"aba doctor --fix"}],"fixed":["Restarted the service"]}`
	if string(b) != want {
		t.Fatalf("got  %s\nwant %s", b, want)
	}
	r := config.IgnoreRule{Path: `C:\x\a.exe`, Signer: "A Corp", Baits: []string{"discord"}}
	rd := ruleDetails([]config.IgnoreRule{r}, map[string]string{"discord": "Discord token store"})
	if len(rd) != 1 || rd[0].ID != r.ID() || rd[0].Number != 1 || !strings.Contains(rd[0].Says, "Discord token store") {
		t.Fatalf("%+v", rd)
	}
	if b, _ := json.Marshal(ruleDetails(nil, nil)); !bytes.Equal(b, []byte("[]")) {
		t.Fatalf("%s", b)
	}
	_ = time.Now
}
