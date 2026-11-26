package engine

import (
	"strings"
	"testing"
	"time"

	"github.com/vulnix0x4/a-better-antivirus/internal/alerts"
	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/detect"
)

const conhost = `C:\Windows\System32\conhost.exe`

func mine(pid uint32, image string) *detect.Access {
	return &detect.Access{PID: pid, Image: image, Op: detect.OpMine, Time: time.Now(), Mine: &detect.Mine{
		Pool: "pool.hashvault.pro", PoolSure: true, Port: 443, TLS: true, Method: "login",
		Wallet: "43iNancbmDEMOkv43M", Pass: "RealBigTonka#", Agent: "XMRig/6.24.0 (Windows NT 10.0; Win64; x64)", Algo: []string{"rx/0"}}}
}

// The real case: a miner hollowed out conhost.exe, a program Microsoft
// signed. Its login at the fake pool is the evidence; the signature and the
// system folder change nothing.
func TestMinerInsideSignedSystemProgramIsCaught(t *testing.T) {
	e, f := setup("balanced")
	signed(f, conhost, "Microsoft Windows")
	e.HandleAccess(mine(600, conhost))
	a := only(f)
	if a == nil {
		t.Fatal("no alert for a miner")
	}
	if a.Kind != alerts.KindMiner || a.Tier != config.TierCritical || !a.Did(config.ActionFreeze) {
		t.Fatalf("want a critical miner alert that froze it: %+v", a)
	}
	if a.Title != "Crypto miner caught: conhost.exe tried to mine on your PC" {
		t.Errorf("title: %q", a.Title)
	}
	if len(a.Baits) != 1 || a.Baits[0].ID != MinerTrap || a.Baits[0].Access != "mine" || a.Baits[0].Path != "pool.hashvault.pro:443" {
		t.Errorf("bait hit: %+v", a.Baits)
	}
	why := strings.Join(a.Verdict.Reasons, " | ")
	for _, want := range []string{"tried to mine cryptocurrency", "43iNancbmDEMOkv43M", "XMRig/6.24.0", "pool.hashvault.pro", "conhost.exe is part of Windows, and Windows' own programs never mine", "aba miners off", "ABA sent nothing anywhere"} {
		if !strings.Contains(why, want) {
			t.Errorf("the alert should say %q: %v", want, a.Verdict.Reasons)
		}
	}
	if len(f.phone) != 1 || len(f.desktop) != 1 {
		t.Errorf("notified: phone %v desktop %v", f.phone, f.desktop)
	}
	if a.Mine == nil || a.Mine.Wallet != "43iNancbmDEMOkv43M" || a.Mine.Pool != "pool.hashvault.pro" {
		t.Errorf("the popup's facts: %+v", a.Mine)
	}
	// Looked into while frozen, with the wallet it mines for.
	waitAutopsy(t, f)
	if len(f.cases) != 1 || f.cases[0].Wallet != "43iNancbmDEMOkv43M" || f.cases[0].WalletNote == "" {
		t.Errorf("autopsy case: %+v", f.cases)
	}
}

func waitAutopsy(t *testing.T, f *fakeOps) {
	t.Helper()
	for i := 0; i < 100; i++ {
		f.mu.Lock()
		n := len(f.cases)
		f.mu.Unlock()
		if n > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A rule that trusts the program (from an earlier alert, or by hand) doesn't
// let it mine.
func TestMinerTrustedByRuleIsStillCaught(t *testing.T) {
	e, f := setup("balanced")
	img := `C:\Users\bob\AppData\Local\Programs\miner\xmrig.exe`
	signed(f, img, "Some Publisher")
	e.cfg.Ignore = []config.IgnoreRule{{Path: img}, {Signer: "Some Publisher"}}
	e.Configure(e.cfg, stateWithAll())
	e.HandleAccess(mine(601, img))
	a := only(f)
	if a == nil || a.Tier != config.TierCritical || !a.Did(config.ActionFreeze) || !a.Did(config.ActionBlockProgram) {
		t.Fatalf("want it frozen and cut off whatever the rules say: %+v", a)
	}
}

// Alert only: told, nothing touched.
func TestMinerAlertOnly(t *testing.T) {
	e, f := setup("alert")
	e.HandleAccess(mine(602, `C:\Users\bob\Downloads\game\launcher.exe`))
	a := only(f)
	if a == nil || a.Kind != alerts.KindMiner || len(a.Actions) != 0 || len(f.suspended) != 0 {
		t.Fatalf("want an alert and nothing else: %+v suspended %v", a, f.suspended)
	}
}

// The same miner connecting again (its next pool, its retry) joins the alert.
func TestMinerAgainJoinsTheAlert(t *testing.T) {
	e, f := setup("balanced")
	img := `C:\Users\bob\AppData\Local\Temp\m\svc.exe`
	e.HandleAccess(mine(603, img))
	again := mine(603, img)
	again.Mine.Pool, again.Mine.Port = "gulf.moneroocean.stream", 10128
	e.HandleAccess(again)
	e.HandleAccess(mine(603, img))
	if len(f.saved) != 1 {
		t.Fatalf("%d alerts", len(f.saved))
	}
	if a := only(f); len(a.Baits) != 2 {
		t.Errorf("baits: %+v", a.Baits)
	}
}

// `aba miners test`: frozen, reported as a test, then ended.
func TestMinerTest(t *testing.T) {
	e, f := setup("strict")
	img := `C:\Users\bob\AppData\Local\Temp\aba-test-0011223344556677.exe`
	f.test = &TestRequest{PID: 604, Miner: true, Since: time.Now()}
	e.HandleAccess(mine(604, img))
	a := only(f)
	if a == nil || a.Kind != alerts.KindTest || !a.Did(config.ActionFreeze) || a.Did(config.ActionIsolate) {
		t.Fatalf("test alert: %+v", a)
	}
	if !strings.Contains(a.Title, "caught trying to mine") {
		t.Errorf("title %q", a.Title)
	}
	if len(f.killed) == 0 || f.killed[0] != 604 || f.isolated != 0 {
		t.Errorf("killed %v isolated %d", f.killed, f.isolated)
	}
}

func TestMineWithoutDetailsIsIgnored(t *testing.T) {
	e, f := setup("balanced")
	e.HandleAccess(&detect.Access{PID: 605, Image: `C:\x.exe`, Op: detect.OpMine, Time: time.Now()})
	if len(f.saved) != 0 {
		t.Fatalf("a mine report without details raised an alert")
	}
}

// What the miner sent is shown as it was, never trusted as text to act on.
func TestMineVerdictWithoutPool(t *testing.T) {
	v := mineVerdict(&detect.Mine{Port: 3333}, `C:\Users\bob\x.exe`, false)
	if v.Tier != config.TierCritical || !strings.Contains(v.Reasons[0], "a mining pool,") {
		t.Errorf("%+v", v)
	}
	if strings.Contains(strings.Join(v.Reasons, " "), "part of Windows") {
		t.Error("an ordinary program called part of Windows")
	}
	if MinePlace(nil) != "a mining pool" || MinePlace(&detect.Mine{Port: 80}) != "a mining pool (port 80)" {
		t.Error("minePlace")
	}
}
