package appapi

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/vulnix0x4/a-better-antivirus/internal/config"
)

const ruleID = "3ca2e312d73e"

var parityExists = Exists{
	Alert:   testExists.Alert,
	Bait:    testExists.Bait,
	Catalog: func(id string) bool { return id == "chrome-profile" || id == "discord" },
	Rule:    func(id string) bool { return id == ruleID },
}

// ParityCase is an action the app may ask for and the CLI it runs (the CLI's
// tests check every one parses: cli/parity_test.go).
type ParityCase struct {
	Kind, ID, Arg string
	Want          []string
	Stdin         string // JSON it gets on standard input ("" = none)
}

const alertID = "20261127-140207-7f3a"

// ParityCases are the good cases.
var ParityCases = []ParityCase{
	{"alert-json", alertID, "", []string{"alerts", "json", "--json", "--yes", "--", alertID}, ""},
	{"autopsy-now", alertID, "", []string{"autopsy", "--now", "--json", "--yes", "--", alertID}, ""},
	{"export-ioc", alertID, "", []string{"export-ioc", "--downloads", "--json", "--yes", "--", alertID}, ""},
	{"doctor", "", "", []string{"doctor", "--json", "--yes"}, ""},
	{"doctor-fix", "", "", []string{"doctor", "--fix", "--json", "--yes"}, ""},
	{"learn-days", "", "0", []string{"learn", "--days=0", "--json", "--yes"}, ""},
	{"learn-days", "", "7", []string{"learn", "--days=7", "--json", "--yes"}, ""},
	{"learn-trust", "", "f51542e2a22a,07ff9b44dcbe", []string{"learn", "--trust=f51542e2a22a,07ff9b44dcbe", "--json", "--yes"}, ""},
	{"ignore-add", "", `{"path":"C:\\Program Files\\Backblaze\\bztransmit64.exe","signer":"Backblaze","note":"backup","allowTricks":true}`,
		[]string{"ignore", "add", "--signer=Backblaze", "--note=backup", "--allow-tricks", "--json", "--yes", "--", `C:\Program Files\Backblaze\bztransmit64.exe`}, ""},
	{"ignore-add", "", `{"path":"C:\\Users\\*\\AppData\\Local\\Programs\\Tool\\tool.exe","signer":"-x --allow-tricks"}`,
		[]string{"ignore", "add", "--signer=-x --allow-tricks", "--json", "--yes", "--", `C:\Users\*\AppData\Local\Programs\Tool\tool.exe`}, ""},
	{"ignore-add", "", `{"path":"**\\Backblaze\\bztransmit64.exe"}`, []string{"ignore", "add", "--json", "--yes", "--", `**\Backblaze\bztransmit64.exe`}, ""},
	{"ignore-remove", ruleID, "", []string{"ignore", "remove", "--json", "--yes", "--", ruleID}, ""},
	{"bait-add", "chrome-profile", "", []string{"bait", "add", "--json", "--yes", "--", "chrome-profile"}, ""},
	{"bait-add-file", "", `C:\Users\sam\Documents\Taxes\bank logins.txt`, []string{"bait", "add", "--file", "--json", "--yes", "--", `C:\Users\sam\Documents\Taxes\bank logins.txt`}, ""},
	{"bait-add-file", "", `D:\Work\-secrets.txt`, []string{"bait", "add", "--file", "--json", "--yes", "--", `D:\Work\-secrets.txt`}, ""},
	{"bait-remove", "discord", "", []string{"bait", "remove", "--json", "--yes", "--", "discord"}, ""},
	{"bait-remove", "custom-1a2b3c4d", "", []string{"bait", "remove", "--json", "--yes", "--", "custom-1a2b3c4d"}, ""},
	{"bait-rename", "", "", []string{"bait", "rename", "--json", "--yes"}, ""},
	{"responses", "", `{"warn":["block-program"],"critical":["freeze","block-program","kill"]}`,
		[]string{"preset", "custom", "--warn=block-program", "--critical=freeze,block-program,kill", "--json", "--yes"}, ""},
	{"responses", "", `{"warn":[],"critical":[]}`, []string{"preset", "custom", "--warn=", "--critical=", "--json", "--yes"}, ""},
	{"recent", "", "off", []string{"recent", "off", "--json", "--yes"}, ""},
	{"phone-off", "", "", []string{"phone", "off", "--json", "--yes"}, ""},
	{"phone-tier", "", "critical", []string{"phone", "tier", "critical", "--json", "--yes"}, ""},
	{"phone-set", "", `{"kind":"ntfy","ntfy":{"server":"https://ntfy.sh","topic":"aba-k3m9q2x7wd"},"minTier":"warn"}`,
		[]string{"phone", "set", "--json", "--yes"}, `{"kind":"ntfy","ntfy":{"server":"https://ntfy.sh","topic":"aba-k3m9q2x7wd"},"pushover":{"appToken":"","userKey":""},"discord":{"webhookUrl":""},"email":{"host":"","port":0,"username":"","password":"","from":"","to":"","implicitTls":false},"minTier":"warn"}`},
	{"phone-set", "", `{"kind":"discord","discord":{"webhookUrl":"https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyz_-0123456789"}}`,
		[]string{"phone", "set", "--json", "--yes"}, ""},
	{"phone-set", "", `{"kind":"pushover","pushover":{"appToken":"azGDORePK8gMaC0QOYAMyEEuzJnyUi","userKey":"uQiRzpo4DXghDmr9QzzfQu27cmVRsG"}}`,
		[]string{"phone", "set", "--json", "--yes"}, ""},
	{"phone-set", "", `{"kind":"pushover","pushover":{}}`, []string{"phone", "set", "--json", "--yes"}, ""}, // keeps the stored keys
	{"phone-set", "", `{"kind":"email","email":{"host":"smtp.gmail.com","port":587,"username":"sam@gmail.com","password":"abcd efgh ijkl mnop","to":"sam@gmail.com"},"minTier":"critical"}`,
		[]string{"phone", "set", "--json", "--yes"}, ""},
	{"phone-set", "", `{"kind":"email","email":{"host":"mail.example.org","port":465,"implicitTls":true,"username":"sam","to":"sam@example.org","from":"aba@example.org"}}`,
		[]string{"phone", "set", "--json", "--yes"}, ""},
	{"canary-on", "", `{"email":"sam.okafor91@gmail.com"}`, []string{"canary", "on", "--json", "--yes"}, `{"email":"sam.okafor91@gmail.com"}`},
	{"clipboard-test", "", "", []string{"clipboard", "test", "--json", "--yes"}, ""},
	{"clipboard-key", "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", "", []string{"clipboard", "key", "--json", "--yes", "--", "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"}, ""},
	{"clipboard-key", "0x52908400098527886E0F7030069857D2E4169EE7", "", []string{"clipboard", "key", "--json", "--yes", "--", "0x52908400098527886E0F7030069857D2E4169EE7"}, ""},
	{"clipboard-key", "TJCnKsPa7y5okkXvQAidZBzqx3QyQ6sxMW", "", []string{"clipboard", "key", "--json", "--yes", "--", "TJCnKsPa7y5okkXvQAidZBzqx3QyQ6sxMW"}, ""},
	{"clipboard-key", "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", "", []string{"clipboard", "key", "--json", "--yes", "--", "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"}, ""},
	{"miners-test", "", "", []string{"miners", "test", "--json", "--yes"}, ""},
	{"uninstall", "", "", []string{"uninstall", "--json", "--yes"}, ""},
	{"uninstall", "", "purge", []string{"uninstall", "--purge", "--json", "--yes"}, ""},
}

func TestParityCommands(t *testing.T) {
	for _, c := range ParityCases {
		inv, err := Prepare(c.Kind, c.ID, c.Arg, parityExists)
		if err != nil || !reflect.DeepEqual(inv.Args, c.Want) {
			t.Errorf("%s %q %q: got %q, %v; want %q", c.Kind, c.ID, c.Arg, inv.Args, err, c.Want)
			continue
		}
		if c.Stdin != "" && string(inv.Stdin) != c.Stdin {
			t.Errorf("%s: stdin %s, want %s", c.Kind, inv.Stdin, c.Stdin)
		}
		secret := c.Kind == ActPhoneSet || c.Kind == ActCanaryOn
		if secret != (inv.Stdin != nil) {
			t.Errorf("%s: stdin %q", c.Kind, inv.Stdin)
		}
		if secret {
			for _, a := range inv.Args {
				if strings.Contains(c.Arg, a) && len(a) > 6 {
					t.Errorf("%s: %q from the settings is on the command line", c.Kind, a)
				}
			}
		}
	}
}

func TestParityRefused(t *testing.T) {
	long := strings.Repeat("a", 9000)
	bad := []struct{ kind, id, arg string }{
		// alerts
		{"alert-json", "", ""}, {"alert-json", "7f3a", ""}, {"alert-json", alertID, "x"},
		{"autopsy-now", "20261127-140207-0000", ""}, {"export-ioc", alertID, `C:\Windows\x.json`}, {"export-ioc", "--output=C:\\x", ""},
		{"doctor", "", "--fix"}, {"doctor", "x", ""}, {"doctor-fix", "", "x"},
		// learning
		{"learn-days", "", ""}, {"learn-days", "", "-1"}, {"learn-days", "", "31"}, {"learn-days", "", "07"}, {"learn-days", "", "3 "},
		{"learn-days", "", "3d"}, {"learn-days", "x", "3"}, {"learn-days", "", "+3"},
		{"learn-trust", "", ""}, {"learn-trust", "", "F51542E2A22A"}, {"learn-trust", "", "f51542e2a22a,"}, {"learn-trust", "", "f51542e2a22a --stop"},
		{"learn-trust", "", strings.TrimSuffix(strings.Repeat("f51542e2a22a,", 51), ",")}, {"learn-trust", "f51542e2a22a", ""},
		// ignore
		{"ignore-add", "", ""}, {"ignore-add", "", "C:\\x\\y.exe"}, {"ignore-add", "", `{"path":"C:\\x\\tool.exe","extra":1}`},
		{"ignore-add", "", `{"path":"C:\\x\\tool.exe"}{"path":"C:\\y\\a.exe"}`},
		{"ignore-add", "", `{"path":"*.exe"}`}, {"ignore-add", "", `{"path":"C:\\**"}`}, {"ignore-add", "", `{"path":"C:\\**\\*.exe"}`},
		{"ignore-add", "", `{"path":"C:\\Users\\*\\*"}`}, {"ignore-add", "", `{"path":"**\\*"}`}, {"ignore-add", "", `{"path":"**\\a?"}`},
		{"ignore-add", "", `{"path":"\\\\server\\share\\tool.exe"}`}, {"ignore-add", "", `{"path":"\\\\?\\C:\\tool.exe"}`},
		{"ignore-add", "", `{"path":"C:\\x\\..\\tool.exe"}`}, {"ignore-add", "", `{"path":"C:/x/tool.exe"}`}, {"ignore-add", "", `{"path":"tool.exe"}`},
		{"ignore-add", "", `{"path":"C:\\x\\tool.exe\n"}`}, {"ignore-add", "", `{"path":"C:\\x\\to\u202eol.exe"}`},
		{"ignore-add", "", `{"path":"C:\\x\\tool.exe:stream"}`}, {"ignore-add", "", `{"path":"C:\\x\\tool.exe","signer":"ab"}`},
		{"ignore-add", "", `{"path":"C:\\x\\tool.exe","note":"a\rb"}`}, {"ignore-add", "", `{"path":"C:\\x\\tool.exe","signer":"` + strings.Repeat("s", 201) + `"}`},
		{"ignore-add", "", `{"path":"C:\\x\\\"tool.exe"}`}, {"ignore-add", "x", `{"path":"C:\\x\\tool.exe"}`}, {"ignore-add", "", `[1]`},
		{"ignore-remove", "", ""}, {"ignore-remove", "1", ""}, {"ignore-remove", "000000000000", ""}, {"ignore-remove", ruleID, "x"},
		{"ignore-remove", strings.ToUpper(ruleID), ""},
		// baits
		{"bait-add", "", ""}, {"bait-add", "telegram", ""}, {"bait-add", "Discord", ""}, {"bait-add", "custom-1a2b3c4d", ""},
		{"bait-add", "discord", "x"}, {"bait-add", "-x", ""}, {"bait-add", `C:\x.txt`, ""},
		{"bait-add-file", "", ""}, {"bait-add-file", "x", `C:\Users\sam\x.txt`}, {"bait-add-file", "", `x.txt`},
		{"bait-add-file", "", `C:\x.txt`}, {"bait-add-file", "", `C:\Windows\System32\config\SAM`}, {"bait-add-file", "", `D:\Windows\x.txt`},
		{"bait-add-file", "", `C:\Program Files\App\a.txt`}, {"bait-add-file", "", `c:\programdata\File Access Monitor\config.json`},
		{"bait-add-file", "", `C:\Users\sam\..\..\Windows\x.txt`}, {"bait-add-file", "", `C:\Users\sam\*.txt`}, {"bait-add-file", "", `C:\Users\sam\`},
		{"bait-add-file", "", `\\server\share\x.txt`}, {"bait-add-file", "", `\\?\C:\Users\x.txt`}, {"bait-add-file", "", `C:\Users\sam\x.txt:ads`},
		{"bait-add-file", "", `C:\Users\sam\x.txt.`}, {"bait-add-file", "", `C:\Users\sam\` + strings.Repeat("a", 260)},
		{"bait-add-file", "", "C:\\Users\\sam\\x\x00.txt"}, {"bait-add-file", "", `C:\Users\sam\\x.txt`},
		{"bait-remove", "", ""}, {"bait-remove", "telegram", ""}, {"bait-remove", "../state", ""}, {"bait-remove", "discord", "x"},
		{"bait-rename", "", "x"},
		// responses
		{"responses", "", ""}, {"responses", "", `{"warn":["freeze","freeze"],"critical":[]}`}, {"responses", "", `{"warn":["nuke"],"critical":[]}`},
		{"responses", "", `{"warn":[],"critical":["freeze"],"info":["kill"]}`}, {"responses", "", `{"warn":["freeze,kill"],"critical":[]}`},
		{"responses", "x", `{"warn":[],"critical":[]}`},
		{"recent", "", ""}, {"recent", "", "yes"}, {"recent", "x", "on"},
		// phone
		{"phone-off", "", "x"}, {"phone-tier", "", ""}, {"phone-tier", "", "high"}, {"phone-tier", "", "WARN"},
		{"phone-set", "", ""}, {"phone-set", "", `{}`}, {"phone-set", "", `{"kind":"telegram"}`}, {"phone-set", "", `{"kind":"ntfy"}`},
		{"phone-set", "", `{"kind":"ntfy","ntfy":{"topic":"a b"}}`}, {"phone-set", "", `{"kind":"ntfy","ntfy":{"topic":"` + strings.Repeat("a", 65) + `"}}`},
		{"phone-set", "", `{"kind":"ntfy","ntfy":{"topic":"t","server":"ftp://x"}}`}, {"phone-set", "", `{"kind":"ntfy","ntfy":{"topic":"t","server":"https://u:p@ntfy.sh"}}`},
		{"phone-set", "", `{"kind":"ntfy","ntfy":{"topic":"t","server":"https://ntfy.sh/mytopic"}}`}, {"phone-set", "", `{"kind":"ntfy","ntfy":{"topic":"t","server":"https://ntfy.sh?x=1"}}`},
		{"phone-set", "", `{"kind":"ntfy","ntfy":{"topic":"t","token":"a\nb"}}`}, {"phone-set", "", `{"kind":"ntfy","ntfy":{"topic":"t"},"discord":{"webhookUrl":"https://discord.com/api/webhooks/123456/abcdefghijklmnopqrstuvwxyz"}}`},
		{"phone-set", "", `{"kind":"ntfy","ntfy":{"topic":"t"},"minTier":"all"}`}, {"phone-set", "", `{"kind":"ntfy","ntfy":{"topic":"t"},"secret":1}`},
		{"phone-set", "", `{"kind":"discord","discord":{"webhookUrl":"https://evil.example/api/webhooks/123456/abcdefghijklmnopqrstuvwxyz"}}`},
		{"phone-set", "", `{"kind":"discord","discord":{"webhookUrl":"http://discord.com/api/webhooks/123456/abcdefghijklmnopqrstuvwxyz"}}`},
		{"phone-set", "", `{"kind":"discord","discord":{"webhookUrl":"https://discord.com/api/webhooks/123456/short"}}`},
		{"phone-set", "", `{"kind":"discord","discord":{"webhookUrl":"https://discord.com:8443/api/webhooks/123456/abcdefghijklmnopqrstuvwxyz"}}`},
		{"phone-set", "", `{"kind":"discord","discord":{"webhookUrl":"https://discord.com.evil.example/api/webhooks/123456/abcdefghijklmnopqrstuvwxyz"}}`},
		{"phone-set", "", `{"kind":"pushover","pushover":{"appToken":"short","userKey":"uQiRzpo4DXghDmr9QzzfQu27cmVRsG"}}`},
		{"phone-set", "", `{"kind":"email","email":{"host":"smtp.gmail.com","port":0,"to":"a@b.co"}}`},
		{"phone-set", "", `{"kind":"email","email":{"host":"smtp.gmail.com","port":70000,"to":"a@b.co"}}`},
		{"phone-set", "", `{"kind":"email","email":{"host":"smtp gmail com","port":587,"to":"a@b.co"}}`},
		{"phone-set", "", `{"kind":"email","email":{"host":"-smtp.gmail.com","port":587,"to":"a@b.co"}}`},
		{"phone-set", "", `{"kind":"email","email":{"host":"smtp.gmail.com","port":587,"to":"Sam <a@b.co>"}}`},
		{"phone-set", "", `{"kind":"email","email":{"host":"smtp.gmail.com","port":587,"to":"a@b.co\r\nBcc: x@y.z"}}`},
		{"phone-set", "", `{"kind":"email","email":{"host":"smtp.gmail.com","port":587,"to":"a@b.co","from":"x"}}`},
		{"phone-set", "", `{"kind":"email","email":{"host":"smtp.gmail.com","port":587,"to":"a@b.co","username":"a\nb"}}`},
		{"phone-set", "", `{"kind":"email","email":{"host":"smtp.gmail.com","port":587,"to":"a@b.co","password":"p\u0000"}}`},
		{"phone-set", "x", `{"kind":"ntfy","ntfy":{"topic":"t"}}`}, {"phone-set", "", long},
		// canary
		{"canary-on", "", ""}, {"canary-on", "", `{"email":"not an email"}`}, {"canary-on", "", `{"email":"a@b.co","x":1}`},
		{"canary-on", "", `{"email":"Sam <a@b.co>"}`}, {"canary-on", "", `{"email":"a@localhost"}`}, {"canary-on", "x", `{"email":"a@b.co"}`},
		// traps
		{"clipboard-test", "", "x"}, {"miners-test", "x", ""},
		{"clipboard-key", "", ""}, {"clipboard-key", "--help", ""}, {"clipboard-key", "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", ""},
		{"clipboard-key", "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", "x"}, {"clipboard-key", "0x123", ""},
		// uninstall
		{"uninstall", "", "all"}, {"uninstall", "", "--purge"}, {"uninstall", "x", ""},
		// unknown
		{"phone-reveal-all", "", ""}, {"configure", "", ""}, {"install", "", ""}, {"service", "", ""}, {"notify", "", ""},
	}
	for _, c := range bad {
		if inv, err := Prepare(c.kind, c.id, c.arg, parityExists); err == nil {
			t.Errorf("%q %q %q: allowed (%q)", c.kind, c.id, c.arg, inv.Args)
		}
	}
	if _, err := Prepare("ignore-remove", ruleID, "", Exists{}); err == nil {
		t.Error("ignore-remove without an existence check")
	}
	if _, err := Prepare("bait-add", "discord", "", Exists{}); err == nil {
		t.Error("bait-add without a catalog")
	}
}

func TestActSendsStdin(t *testing.T) {
	var got []byte
	var args []string
	a := &Actor{CLI: `C:\aba.exe`, Exists: parityExists, Run: func(ctx context.Context, exe string, as []string, stdin []byte, line func(string)) error {
		got, args = stdin, as
		line(`{"ok":true,"message":"Phone alerts: ntfy","details":{"tested":true}}`)
		return nil
	}}
	res := a.Act("phone-set", "", `{"kind":"ntfy","ntfy":{"topic":"aba-k3m9q2x7wd","token":"tk_abc"}}`)
	if !res.OK {
		t.Fatal(res)
	}
	var p config.PhoneSetting
	if json.Unmarshal(got, &p) != nil || p.Ntfy.Token != "tk_abc" || p.Ntfy.Topic != "aba-k3m9q2x7wd" {
		t.Fatalf("stdin %s", got)
	}
	if strings.Contains(strings.Join(args, " "), "tk_abc") {
		t.Fatalf("the token is on the command line: %q", args)
	}
}

func TestClipboardKeyStaysOffThePage(t *testing.T) {
	const key = "L1aW4aubDFB7yfras2S1mN3bqg9nwySY8nkoLmJebSLD5BWv3ENZ"
	a := &Actor{CLI: `C:\aba.exe`, Exists: parityExists, Run: func(ctx context.Context, exe string, as []string, stdin []byte, line func(string)) error {
		line(`{"ok":true,"message":"Bait address bc1q… Private key ` + key + `","details":{"address":"bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq","coin":"bitcoin-segwit","key":"` + key + `","how":"Use it in a Bitcoin wallet."}}`)
		return nil
	}}
	res := a.Act("clipboard-key", "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", "")
	if !res.OK || res.Private == nil || !strings.Contains(res.Private.Text, key) {
		t.Fatalf("%+v", res)
	}
	page, _ := json.Marshal(res)
	if strings.Contains(string(page), key) || strings.Contains(string(page), "Private") {
		t.Fatalf("the page would get the key: %s", page)
	}
	for _, ev := range a.Progress().Events {
		if strings.Contains(ev.Text, key) {
			t.Fatal("the key is in the progress events")
		}
	}
	// A CLI that didn't give the key in its details: refused, nothing passed on.
	a.Run = func(ctx context.Context, exe string, as []string, stdin []byte, line func(string)) error {
		line(`{"ok":true,"message":"Private key ` + key + `"}`)
		return nil
	}
	if res := a.Act("clipboard-key", "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", ""); res.OK || strings.Contains(res.Message, key) {
		t.Fatalf("%+v", res)
	}
}

func TestPhoneReveal(t *testing.T) {
	ran := false
	a := &Actor{CLI: `C:\aba.exe`, Exists: parityExists,
		Run:     func(context.Context, string, []string, []byte, func(string)) error { ran = true; return nil },
		Secrets: func() (*config.Secrets, error) { return ntfySecrets(), nil }}
	res := a.Act("phone-reveal", "", "")
	if !res.OK || res.Private == nil || !strings.Contains(res.Private.Text, "aba-k3m9q2x7wd") || ran {
		t.Fatalf("%+v ran=%v", res, ran)
	}
	page, _ := json.Marshal(res)
	if strings.Contains(string(page), "aba-k3m9q2x7wd") || strings.Contains(string(page), "tk_secret") {
		t.Fatalf("the page would get the topic: %s", page)
	}
	if res := a.Act("phone-reveal", "", "x"); res.OK {
		t.Fatal("argument allowed")
	}
	a.Secrets = func() (*config.Secrets, error) { return customSettingsSource().Secrets, nil }
	if res := a.Act("phone-reveal", "", ""); res.OK || res.Private != nil {
		t.Fatalf("email password revealed: %+v", res)
	}
}

// The settings models never carry a stored secret.
func TestSettingsKeepSecrets(t *testing.T) {
	for _, m := range []any{settingsSource().Settings(), customSettingsSource().Settings()} {
		b, _ := json.Marshal(m)
		for _, s := range []string{"aba-k3m9q2x7wd", "tk_secret", "SECRET", "app-password", "canarytokens.org/manage"} {
			if strings.Contains(string(b), s) {
				t.Errorf("%q in %s", s, b)
			}
		}
	}
}
