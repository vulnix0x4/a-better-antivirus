package eswatch

import (
	"strings"
	"testing"
)

const (
	chromeOpen  = `{"process":{"audit_token":{"euid":501,"pid":4242},"ppid":4200,"start_time":"2026-11-23T14:00:00.000001Z","executable":{"path":"/private/tmp/x/stealer"}},"event_type":10,"time":"2026-11-23T14:00:02.5Z","event":{"open":{"fflag":1,"file":{"path":"/Users/a/Library/Application Support/Google/Chrome/Default/Login Data"}}}}`
	chromeWrite = `{"process":{"audit_token":{"euid":501,"pid":77},"executable":{"path":"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"}},"event_type":10,"time":"2026-11-23T14:00:02Z","event":{"open":{"fflag":2,"file":{"path":"/Users/a/Library/Application Support/Google/Chrome/Default/Login Data"}}}}`
	otherOpen   = `{"process":{"audit_token":{"euid":501,"pid":88},"executable":{"path":"/usr/bin/vim"}},"event_type":10,"time":"2026-11-23T14:00:02Z","event":{"open":{"fflag":1,"file":{"path":"/Users/a/notes.txt"}}}}`
)

func TestStoreOpensGoToTheRecorder(t *testing.T) {
	w := New()
	w.SyncStores([]string{"/Users/a/Library/Application Support/Google/Chrome/"})
	var got []Event
	w.OnStoreOpen = func(e Event) { got = append(got, e) }
	w.OnEvent = func(e Event) { t.Errorf("a real store's open was reported as a bait: %+v", e) }
	w.read(strings.NewReader(strings.Join([]string{chromeOpen, chromeWrite, otherOpen}, "\n") + "\n"))
	if len(got) != 1 {
		t.Fatalf("got %+v", got)
	}
	e := got[0]
	if e.Proc.PID != 4242 || e.Proc.PPID != 4200 || e.Proc.Started.IsZero() || !strings.HasSuffix(e.Path, "Default/Login Data") || e.At.IsZero() {
		t.Errorf("%+v", e)
	}
}

// What eslogger's stream costs to filter: thousands of lines a second on a
// busy Mac, nearly all about neither a bait nor a store.
func BenchmarkPrefilter(b *testing.B) {
	w := New()
	var baits, stores []string
	for i := 0; i < 40; i++ {
		baits = append(baits, "/Users/a/Library/Application Support/Decoy"+strings.Repeat("x", i)+"/Default/Login Data")
	}
	for i := 0; i < 20; i++ {
		stores = append(stores, "/Users/a/Library/Application Support/Store"+strings.Repeat("y", i)+"/")
	}
	w.Sync(baits)
	w.SyncStores(stores)
	w.OnStoreOpen = func(Event) {}
	line := []byte(strings.Replace(otherOpen, "/Users/a/notes.txt", "/Users/a/Library/Caches/com.apple.Safari/"+strings.Repeat("z", 1200), 1) + "\n")
	b.SetBytes(int64(len(line)))
	for i := 0; i < b.N; i++ {
		w.line(line)
	}
}

// The grouped matcher finds exactly what looking for each needle finds.
func TestMatcherAgreesWithPlainSearch(t *testing.T) {
	ns := needlesFold([]string{"/Users/a/Documents/pass.txt", "/Users/a/.ssh/id_rsa.bak", "/Users/a/Library/Application Support/Exodus/exodus.wallet/seed.seco", "/tmp/x", "/U"})
	m := newMatcher(ns)
	lines := []string{openLine, writeLine, cloneLine, linkLine, execLine, otherOpen, chromeOpen, `{"a":"\/Users\/a\/.ssh\/id_rsa.bak"}`, `"/users/a/documents/pass.txt"`, "", "/", "/Users/a/Documents/pass.tx", "x/tmp/xy"}
	for _, l := range lines {
		if got, want := m.match([]byte(l)), matchAny([]byte(l), ns); got != want {
			t.Errorf("%q: matcher %v, plain %v", l, got, want)
		}
	}
	var nilM *matcher
	if nilM.match([]byte("x")) {
		t.Error("an empty matcher matched")
	}
}
