package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"os"
	"path"
	"regexp"
	"strings"
	"testing"
)

func TestVendorManifest(t *testing.T) {
	ffs := frontendFS()
	b, err := fs.ReadFile(ffs, "vendor/MANIFEST.sha256")
	if err != nil {
		t.Fatal(err)
	}
	listed := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(string(b)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		sum, name, ok := strings.Cut(line, "  ")
		if !ok {
			t.Fatalf("bad manifest line %q", line)
		}
		listed[name] = sum
	}
	seen := 0
	fs.WalkDir(ffs, "vendor", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || p == "vendor/MANIFEST.sha256" {
			return err
		}
		name := strings.TrimPrefix(p, "vendor/")
		want, ok := listed[name]
		if !ok {
			t.Errorf("%s: not in the manifest", name)
			return nil
		}
		data, _ := fs.ReadFile(ffs, p)
		sum := sha256.Sum256(data)
		if got := hex.EncodeToString(sum[:]); got != want {
			t.Errorf("%s: sha256 %s, manifest says %s", name, got, want)
		}
		seen++
		delete(listed, name)
		return nil
	})
	for name := range listed {
		t.Errorf("%s: in the manifest but not vendored", name)
	}
	if seen == 0 {
		t.Error("nothing vendored")
	}
}

func TestCSP(t *testing.T) {
	idx, err := fs.ReadFile(frontendFS(), "index.html")
	if err != nil {
		t.Fatal(err)
	}
	csp, err := contentSecurityPolicy(idx)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"default-src 'none'", "script-src 'self' 'sha256-", "connect-src 'none'", "frame-src 'none'", "object-src 'none'", "base-uri 'none'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP lacks %q: %s", want, csp)
		}
	}
	for _, bad := range []string{"unsafe-inline", "unsafe-eval", "*", "http:", "https:", "data:"} {
		if strings.Contains(csp, bad) {
			t.Errorf("CSP allows %q: %s", bad, csp)
		}
	}
	// The import map is the page's only inline script, and nothing has an
	// inline style or handler (CSP would block them).
	if n := len(regexp.MustCompile(`<script(?: [^>]*)?>`).FindAll(idx, -1)); n != 2 {
		t.Errorf("index.html has %d script tags, want the import map and app.js", n)
	}
	if regexp.MustCompile(`(?i)\s(style|on[a-z]+)=`).Match(idx) {
		t.Error("index.html has an inline style or event handler")
	}
	if _, err := contentSecurityPolicy([]byte("<html>")); err == nil {
		t.Error("no error without an import map")
	}
}

// The frontend never parses data as HTML, and the Go side never asks Wails
// to open a browser or a file dialog (elevated, both would be an
// administrator's).
func TestNoDangerousCalls(t *testing.T) {
	js, _ := fs.ReadFile(frontendFS(), "app.js")
	for _, bad := range []string{"innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function", "BrowserOpenURL"} {
		if strings.Contains(string(js), bad) {
			t.Errorf("app.js uses %s", bad)
		}
	}
	entries, _ := os.ReadDir(".")
	for _, e := range entries {
		if path.Ext(e.Name()) != ".go" || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		src, _ := os.ReadFile(e.Name())
		for _, bad := range []string{"BrowserOpenURL", "OpenFileDialog", "OpenMultipleFilesDialog", "OpenDirectoryDialog", "SaveFileDialog", "MessageDialog"} {
			if strings.Contains(string(src), "runtime."+bad) {
				t.Errorf("%s calls runtime.%s", e.Name(), bad)
			}
		}
	}
}

func TestAllowedNavigation(t *testing.T) {
	for _, u := range []string{"http://wails.localhost/", "http://wails.localhost/index.html?x=1#y"} {
		if !allowedNavigation(u) {
			t.Errorf("%s blocked", u)
		}
	}
	for _, u := range []string{"https://wails.localhost/", "http://wails.localhost.evil.com/", "http://evil.com/?wails.localhost",
		"http://x@wails.localhost/", "http://wails.localhost:8080/", "file:///C:/Windows/win.ini", "about:blank", "data:text/html,x",
		"javascript:alert(1)", "https://example.com/", "", "wails.localhost", "blob:http://wails.localhost/abc"} {
		if allowedNavigation(u) {
			t.Errorf("%s allowed", u)
		}
	}
}

func TestAllowedIPC(t *testing.T) {
	for _, m := range []string{"runtime:ready", "drag", "resize:n-resize", "Q", "Wm", "Wt", `C{"name":"main.API.Info","args":[],"callbackID":"x"}`} {
		if !allowedIPC(m) {
			t.Errorf("%q blocked", m)
		}
	}
	for _, m := range []string{"BO:https://example.com/", "EE:x:[]", "EX:x", "DD:1:2:C:\\x", "S", "H", "WR", "WT:title", "Ws:1:1", "Wp:0:0",
		"WF", "c{}", "L", "", "C", "Cx", "Q2"} {
		if allowedIPC(m) {
			t.Errorf("%q allowed", m)
		}
	}
}

func TestSelftestProblems(t *testing.T) {
	good := map[string]any{
		"gl":     map[string]any{"ok": true, "renderer": "ANGLE (Microsoft Basic Render Driver)"},
		"frames": float64(120),
		"attacks": map[string]any{"windowOpen": "blocked", "fetch": "blocked", "notifications": "denied",
			"clipboardRead": "blocked:NotAllowedError", "stillHere": true},
		"cspViolations": []any{map[string]any{"directive": "connect-src"}, map[string]any{"directive": "frame-src"}},
	}
	g := GuardStatus{OK: true, Navigations: 2, NewWindows: 1, Downloads: 1, IPC: 2}
	if p := selftestProblems("full", good, g); len(p) != 0 {
		t.Fatalf("good run: %q", p)
	}
	bad := func(name string, mode string, page map[string]any, g GuardStatus) {
		if p := selftestProblems(mode, page, g); len(p) == 0 {
			t.Errorf("%s: passed", name)
		}
	}
	clone := func(edit func(m map[string]any)) map[string]any {
		b, _ := json.Marshal(good)
		var m map[string]any
		json.Unmarshal(b, &m)
		edit(m)
		return m
	}
	bad("guard failed", "full", good, GuardStatus{Error: "x"})
	bad("no navigation blocked", "full", good, GuardStatus{OK: true, NewWindows: 1, Downloads: 1, IPC: 2})
	bad("page gone", "full", clone(func(m map[string]any) { delete(m["attacks"].(map[string]any), "stillHere") }), g)
	bad("few frames", "full", clone(func(m map[string]any) { m["frames"] = float64(3) }), g)
	bad("window opened", "full", clone(func(m map[string]any) { m["attacks"].(map[string]any)["windowOpen"] = "opened" }), g)
	bad("granted", "full", clone(func(m map[string]any) { m["attacks"].(map[string]any)["notifications"] = "granted" }), g)
	bad("odd CSP violation", "full", clone(func(m map[string]any) {
		m["cspViolations"] = append(m["cspViolations"].([]any), map[string]any{"directive": "script-src-elem"})
	}), g)
	bad("no CSP", "full", clone(func(m map[string]any) { m["cspViolations"] = []any{} }), g)
	bad("page error", "full", clone(func(m map[string]any) { m["error"] = "boom" }), g)
	bad("no WebGL", "locked", clone(func(m map[string]any) { m["gl"] = map[string]any{"ok": false} }), g)
	// The locked view draws no scene.
	if p := selftestProblems("locked", clone(func(m map[string]any) { m["frames"] = float64(0) }), g); len(p) != 0 {
		t.Errorf("locked: %q", p)
	}
}
