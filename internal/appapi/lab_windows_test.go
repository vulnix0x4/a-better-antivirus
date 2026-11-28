package appapi

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/paths"
)

// TestLab drives every action of PARITY.md the way the app's bridge does
// (Actor with the installed CLI, the read models from disk), on a lab PC
// with ABA installed: ABA_PARITY_LAB=1, as an administrator. Never on a
// real PC: it changes the settings, plants and removes baits, runs the
// tests and ends by uninstalling ABA. Nothing goes to a real phone service:
// ntfy goes to a fake server here, and the lab's hosts file points
// discord.com, api.pushover.net and canarytokens.org at nothing.
func TestLab(t *testing.T) {
	if os.Getenv("ABA_PARITY_LAB") != "1" {
		t.Skip("lab only (ABA_PARITY_LAB=1)")
	}
	out := os.Getenv("ABA_PARITY_OUT")
	if out == "" {
		out = t.TempDir()
	}
	os.MkdirAll(out, 0o755)
	a := &Actor{CLI: paths.InstalledCLI(), Exists: DiskExists, Run: RunCLI, Secrets: config.LoadSecrets}
	var log []map[string]any
	save := func(name string, v any) {
		b, _ := json.MarshalIndent(v, "", "  ")
		os.WriteFile(filepath.Join(out, name+".json"), b, 0o644)
	}
	defer func() { save("log", log) }()
	act := func(kind, id, arg string, wantOK bool) Result {
		t.Helper()
		start := time.Now()
		r := a.Act(kind, id, arg)
		entry := map[string]any{"kind": kind, "id": id, "arg": arg, "ok": r.OK, "message": r.Message, "details": r.Details, "ms": time.Since(start).Milliseconds()}
		if r.Private != nil {
			entry["private"] = r.Private.Title // never its text in the log
		}
		log = append(log, entry)
		if r.OK != wantOK {
			t.Errorf("%s %q %q: ok=%v, want %v: %s", kind, id, arg, r.OK, wantOK, r.Message)
		}
		return r
	}
	src := func() *Source {
		t.Helper()
		s, err := Load("lab")
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	details := func(r Result, v any) {
		t.Helper()
		raw, _ := r.Details.(json.RawMessage)
		if err := json.Unmarshal(raw, v); err != nil {
			t.Errorf("details %s: %v", raw, err)
		}
	}

	// ---- read models ----
	s := src()
	save("settings-0", s.Settings())
	save("trusted-0", s.Trusted())
	s.LoadPlan()
	cat := s.Catalog()
	save("catalog-0", cat)
	if len(cat.Items) < 10 {
		t.Errorf("catalog has %d items", len(cat.Items))
	}

	// ---- doctor ----
	var doc struct {
		Checks []struct{ Level, Name, Detail, Fix string }
		Fixed  []string
	}
	details(act(ActDoctor, "", "", true), &doc)
	if len(doc.Checks) < 3 {
		t.Errorf("doctor: %+v", doc)
	}
	details(act(ActDoctorFix, "", "", true), &doc)

	// ---- response, learning, recent files ----
	act(ActRecent, "", "off", true)
	if src().Settings().CleanRecent {
		t.Error("recent off: still on")
	}
	act(ActRecent, "", "on", true)
	act(ActResponses, "", `{"warn":["block-program"],"critical":["freeze","block-program"]}`, true)
	st := src().Settings()
	if st.Preset != "custom" || strings.Join(st.Responses.Warn, ",") != "block-program" || strings.Join(st.Responses.Critical, ",") != "freeze,block-program" || !st.LearningMatters {
		t.Errorf("responses: %+v %+v", st.Preset, st.Responses)
	}
	act(ActLearnDays, "", "5", true)
	if st := src().Settings(); st.LearningUntil == nil || st.LearningUntil.Sub(time.Now()) < 119*time.Hour {
		t.Errorf("learning: %v", st.LearningUntil)
	}
	act(ActLearnDays, "", "0", true)
	if src().Settings().Learning {
		t.Error("learning still on")
	}
	act(ActResponses, "", `{"warn":["nuke"],"critical":[]}`, false)
	act(ActPreset, "", "balanced", true)

	// ---- phone: ntfy to a fake server here ----
	var mu sync.Mutex
	var got []string
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		got = append(got, r.Method+" "+r.URL.Path+" auth="+r.Header.Get("Authorization")+" "+string(b))
		mu.Unlock()
	})}
	go srv.Serve(ln)
	defer srv.Close()
	server := "http://" + ln.Addr().String()
	r := act(ActPhoneSet, "", `{"kind":"ntfy","ntfy":{"server":"`+server+`","topic":"aba-lab-parity42","token":"tk_labtoken"},"minTier":"warn"}`, true)
	var tested struct {
		Tested    bool
		TestError string
	}
	details(r, &tested)
	mu.Lock()
	if !tested.Tested || len(got) == 0 || !strings.Contains(got[0], "/aba-lab-parity42") || !strings.Contains(got[0], "tk_labtoken") {
		t.Errorf("ntfy test: %+v %q", tested, got)
	}
	mu.Unlock()
	st = src().Settings()
	save("settings-ntfy", st)
	if st.Phone.Ntfy == nil || st.Phone.Ntfy.Topic == "aba-lab-parity42" || !st.Phone.Ntfy.HasToken {
		t.Errorf("phone view: %+v", st.Phone)
	}
	b, _ := json.Marshal(st)
	if strings.Contains(string(b), "aba-lab-parity42") || strings.Contains(string(b), "tk_labtoken") {
		t.Error("a secret in Settings")
	}
	// Saved again without the token: kept.
	act(ActPhoneSet, "", `{"kind":"ntfy","ntfy":{"server":"`+server+`","topic":"aba-lab-parity42"},"minTier":"critical"}`, true)
	if sec, _ := config.LoadSecrets(); sec.Phone.Ntfy.Token != "tk_labtoken" {
		t.Error("token not kept")
	}
	if src().Settings().Phone.MinTier != "critical" {
		t.Error("minTier not set")
	}
	r = act(ActPhoneReveal, "", "", true)
	if r.Private == nil || !strings.Contains(r.Private.Text, "aba-lab-parity42") || strings.Contains(r.Message, "aba-lab-parity42") {
		t.Errorf("reveal: %+v", r)
	}
	act(ActPhoneTest, "", "", true)
	act(ActPhoneTier, "", "info", true)
	if src().Settings().Phone.MinTier != "info" {
		t.Error("phone-tier")
	}
	// The other channels: saved; their tests can't get out (hosts file).
	act(ActPhoneSet, "", `{"kind":"discord","discord":{"webhookUrl":"https://discord.com/api/webhooks/123456789012345678/labLABlabLABlabLABlabLAB_-0"}}`, true)
	if p := src().Settings().Phone; p.Via != "discord" || p.Discord == nil || p.Discord.Host != "discord.com" {
		t.Errorf("discord: %+v", p)
	}
	act(ActPhoneSet, "", `{"kind":"discord","discord":{}}`, true) // keeps the webhook
	if sec, _ := config.LoadSecrets(); !strings.HasSuffix(sec.Phone.Discord.WebhookURL, "LAB_-0") {
		t.Error("webhook not kept")
	}
	act(ActPhoneSet, "", `{"kind":"pushover","pushover":{"appToken":"azGDORePK8gMaC0QOYAMyEEuzJnyUi","userKey":"uQiRzpo4DXghDmr9QzzfQu27cmVRsG"}}`, true)
	act(ActPhoneSet, "", `{"kind":"pushover","pushover":{}}`, true)
	act(ActPhoneSet, "", `{"kind":"email","email":{"host":"localhost","port":2525,"username":"lab","password":"lab-pw","to":"lab@example.org"}}`, true)
	if p := src().Settings().Phone; p.Email == nil || p.Email.Port != 2525 || !p.Email.HasPassword || p.Email.ImplicitTLS {
		t.Errorf("email: %+v", p)
	}
	act(ActPhoneSet, "", `{"kind":"email","email":{"host":"localhost","port":465,"implicitTls":true,"username":"lab","to":"lab@example.org"}}`, true)
	if sec, _ := config.LoadSecrets(); sec.Phone.Email.Password != "lab-pw" || !sec.Phone.Email.ImplicitTLS {
		t.Error("email password not kept / TLS not set")
	}
	act(ActPhoneSet, "", `{"kind":"email","email":{"host":"localhost","port":587,"to":"Sam <a@b.co>"}}`, false)
	act(ActPhoneOff, "", "", true)
	if src().Settings().Phone.On {
		t.Error("phone still on")
	}
	act(ActPhoneTest, "", "", false)
	act(ActPhoneReveal, "", "", false)

	// ---- canary (canarytokens.org is unreachable here: the error comes back) ----
	act(ActCanaryOn, "", `{"email":"lab@example.org"}`, false)
	act(ActCanaryOn, "", `{"email":"nope"}`, false)

	// ---- ignore rules ----
	act(ActIgnoreAdd, "", `{"path":"C:\\Program Files\\LabBackup\\labbackup.exe","signer":"Lab Corp","note":"lab"}`, true)
	tr := src().Trusted()
	var rid string
	for _, ru := range tr.Rules {
		if ru.Path == `C:\Program Files\LabBackup\labbackup.exe` && ru.Signer == "Lab Corp" {
			rid = ru.ID
		}
	}
	if rid == "" {
		t.Fatalf("rule not there: %+v", tr.Rules)
	}
	act(ActIgnoreAdd, "", `{"path":"C:\\Users\\labuser\\AppData\\Local\\Tool\\tool.exe","allowTricks":true}`, false) // user-writable, no signer
	act(ActIgnoreAdd, "", `{"path":"C:\\Users\\*\\*.exe"}`, false)
	act(ActIgnoreRemove, rid, "", true)
	act(ActIgnoreRemove, rid, "", false)

	// ---- baits ----
	var add string
	for _, it := range cat.Items {
		if it.Available && !it.Planted && it.Category != "Browsers" {
			add = it.ID
			break
		}
	}
	if add == "" {
		t.Error("nothing in the catalog to add")
	} else {
		act(ActBaitAdd, add, "", true)
		s := src()
		s.LoadPlan()
		planted := false
		for _, it := range s.Catalog().Items {
			planted = planted || (it.ID == add && it.Planted)
		}
		if !planted {
			t.Errorf("%s not planted", add)
		}
		act(ActBaitRemove, add, "", true)
	}
	docs := `C:\Users\labuser\Documents\lab parity bait.txt`
	r = act(ActBaitAddFile, "", docs, true)
	var added struct{ ID, Path string }
	details(r, &added)
	if added.ID == "" {
		t.Error("no ID for the custom bait")
	} else {
		act(ActBaitShow, added.ID, "", true)
		act(ActBaitRemove, added.ID, "", true)
	}
	act(ActBaitAddFile, "", `C:\Windows\System32\drivers\etc\hosts`, false)
	act(ActBaitRename, "", "", true)
	save("baits-after", src().Baits())

	// ---- a catch, and what the alert screens do ----
	r = act(ActTest, "", "", true)
	var test struct{ AlertID string }
	details(r, &test)
	if test.AlertID != "" {
		act(ActAlertJSON, test.AlertID, "", true)
		act(ActAutopsyNow, test.AlertID, "", false) // the fake stealer is gone
		r = act(ActExportIOC, test.AlertID, "", true)
		var ex struct {
			Path string
			IOC  json.RawMessage
		}
		details(r, &ex)
		if fi, err := os.Stat(ex.Path); err != nil || fi.Size() == 0 || !strings.HasPrefix(strings.ToLower(ex.Path), `c:\users\labuser\downloads\`) || len(ex.IOC) == 0 {
			t.Errorf("export: %+v %v", ex, err)
		}
		r2 := act(ActExportIOC, test.AlertID, "", true)
		var ex2 struct{ Path string }
		details(r2, &ex2)
		if ex2.Path == ex.Path {
			t.Error("export wrote over the first file")
		}
	}

	// A program caught for real (catch.ps1 left one), trusted from the suggestions.
	tr = src().Trusted()
	save("trusted-1", tr)
	if len(tr.Suggestions) > 0 {
		act(ActLearnTrust, "", tr.Suggestions[0].ID, true)
		if len(src().Trusted().Rules) == 0 {
			t.Error("learn-trust added no rule")
		}
	} else {
		t.Log("no suggestions (run guest\\catch.ps1 first)")
	}
	act(ActLearnTrust, "", "000000000000", false)
	act(ActRelease, "", "", true)

	// ---- traps ----
	act(ActClipboard, "", "on", true)
	r = act(ActClipboardTest, "", "", true)
	save("clipboard-test", r)
	// A bait address the clipboard test put out (the record of them), and its key.
	wallet := ""
	if b, err := os.ReadFile(filepath.Join(paths.DataDir(), "clipboard-baits.txt")); err == nil {
		lines := strings.Split(strings.TrimSpace(string(b)), "\n")
		if f := strings.Fields(lines[len(lines)-1]); len(f) == 4 {
			wallet = f[3]
		}
	}
	if wallet == "" {
		t.Error("no bait address on record after the clipboard test")
	} else {
		r = act(ActClipboardKey, wallet, "", true)
		page, _ := json.Marshal(r)
		if r.Private == nil || len(r.Private.Text) < 60 || strings.Contains(string(page), "Private key:") {
			t.Errorf("clipboard-key: %s", page)
		}
	}
	act(ActMiners, "", "on", true)
	act(ActMinersTest, "", "", true)
	act(ActClipboardKey, "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", "", false) // never put out
	save("settings-end", src().Settings())
}

// TestLabUninstall is the last step of the lab run (ABA_PARITY_UNINSTALL=1):
// uninstall with --purge through the app's action.
func TestLabUninstall(t *testing.T) {
	if os.Getenv("ABA_PARITY_UNINSTALL") != "1" {
		t.Skip("lab only (ABA_PARITY_UNINSTALL=1)")
	}
	a := &Actor{CLI: paths.InstalledCLI(), Exists: DiskExists, Run: RunCLI, Secrets: config.LoadSecrets}
	if r := a.Act(ActUninstall, "", "everything"); r.OK {
		t.Fatal("bad argument ran")
	}
	r := a.Act(ActUninstall, "", "purge")
	t.Logf("%+v", r)
	if !r.OK {
		t.Fatal(r.Message)
	}
	if _, err := os.Stat(paths.ConfigFile()); err == nil {
		t.Error("config still there")
	}
}
