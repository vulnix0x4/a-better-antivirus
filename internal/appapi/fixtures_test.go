package appapi

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/vulnix0x4/a-better-antivirus/internal/alerts"
	"github.com/vulnix0x4/a-better-antivirus/internal/config"
)

// The fixtures in testdata/ are the contract with the page: each is a view
// model built from a scenario (scenarios_test.go). `go test -update` writes
// them again; run it on Windows (or GOOS=windows in the VM) so the words
// that depend on the system (the report's sections, the checklist) read as
// they do on a PC. Elsewhere those two are left out of the comparison.
var updateFixtures = flag.Bool("update", false, "write the fixtures in testdata/ again")

func TestMain(m *testing.M) {
	time.Local = time.UTC // the report's sections show clock times
	os.Exit(m.Run())
}

type fixture struct {
	name  string
	model func() any
}

func fixtures() []fixture {
	frozen, nitro := frozenSource(alerts.SentSome)
	nothingSrc, nothing := frozenSource(alerts.SentNothing)
	ct := cannotTell()
	ctSrc := source(baseState(), ct)
	ctSrc.State.Frozen = []config.FrozenProcess{{PID: 9120, Image: ct.Process.Image, AlertID: ct.ID, Since: ct.Time}}
	hostileSrc, _ := frozenSource(alerts.SentSome)
	h := hostile()
	hostileSrc.Alerts = append([]*alerts.Alert{h}, hostileSrc.Alerts...)
	hostileSrc.State.Frozen = append(hostileSrc.State.Frozen, config.FrozenProcess{PID: 9121, Image: h.Process.Image, AlertID: h.ID, Since: h.Time})
	prot := protectedSource()

	pub := func(st *config.State, open int) *config.Public {
		return config.MakePublic(baseConfig(), st, "v0.10.2", 9, open)
	}
	return []fixture{
		{"home-protected", func() any { return prot.Snapshot() }},
		{"home-frozen", func() any { return frozen.Snapshot() }},
		{"alert-frozen-sent", func() any { return frozen.Alert(nitro) }},
		{"alert-frozen-nothing-sent", func() any { return nothingSrc.Alert(nothing) }},
		{"alert-cannot-tell", func() any { return ctSrc.Alert(ct) }},
		{"alert-miner", func() any { return prot.Alert(miner()) }},
		{"alert-clipper", func() any { return prot.Alert(clipper()) }},
		{"alert-trusted", func() any { return prot.Alert(trusted()) }},
		{"alert-quiet", func() any { return prot.Alert(quietOnes()[0]) }},
		{"alert-test", func() any { return frozen.Alert(testCatch()) }},
		{"alert-hostile", func() any { return hostileSrc.Alert(h) }},
		{"history", func() any { return frozen.History() }},
		{"baits", func() any { return frozen.Baits() }},
		{"settings", func() any { return prot.Settings() }},
		{"locked", func() any { return LockedView(pub(baseState(), 0), "v0.10.2", "", now) }},
		{"locked-frozen", func() any {
			return LockedView(pub(frozen.State, 1), "v0.10.2", nitro.ID, now)
		}},
	}
}

// osWords are the fields whose words depend on the system the test runs on.
var osWords = map[string]bool{"sections": true, "checklist": true}

func strip(v any) any {
	switch x := v.(type) {
	case map[string]any:
		for k := range x {
			if osWords[k] {
				delete(x, k)
			} else {
				x[k] = strip(x[k])
			}
		}
	case []any:
		for i := range x {
			x[i] = strip(x[i])
		}
	}
	return v
}

func TestFixtures(t *testing.T) {
	for _, f := range fixtures() {
		t.Run(f.name, func(t *testing.T) {
			got, err := json.MarshalIndent(f.model(), "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			got = append(got, '\n')
			file := filepath.Join("testdata", f.name+".json")
			if *updateFixtures {
				if err := os.WriteFile(file, got, 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(file)
			if err != nil {
				t.Fatalf("%v (write the fixtures with go test -update)", err)
			}
			want = bytes.ReplaceAll(want, []byte("\r\n"), []byte("\n"))
			if runtime.GOOS == "windows" {
				if !bytes.Equal(got, want) {
					t.Errorf("%s changed; if on purpose, go test -update and say so in CONTRACT.md\n%s", file, diffHint(got, want))
				}
				return
			}
			var g, w any
			json.Unmarshal(got, &g)
			json.Unmarshal(want, &w)
			gb, _ := json.MarshalIndent(strip(g), "", "  ")
			wb, _ := json.MarshalIndent(strip(w), "", "  ")
			if !bytes.Equal(gb, wb) {
				t.Errorf("%s changed; if on purpose, go test -update (on Windows) and say so in CONTRACT.md\n%s", file, diffHint(gb, wb))
			}
		})
	}
}

// diffHint shows where two texts first differ.
func diffHint(a, b []byte) string {
	la, lb := bytes.Split(a, []byte("\n")), bytes.Split(b, []byte("\n"))
	for i := 0; i < len(la) && i < len(lb); i++ {
		if !bytes.Equal(la[i], lb[i]) {
			return "line " + itoa(i+1) + ":\n got:  " + string(la[i]) + "\n want: " + string(lb[i])
		}
	}
	return "lengths differ"
}

func itoa(i int) string { b, _ := json.Marshal(i); return string(b) }
