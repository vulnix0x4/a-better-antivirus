package main

import (
	"fmt"
	"net/url"
	"strings"
)

// startOrigin is where Wails serves the page from inside WebView2 (requests
// to it are answered in-process; there's no socket).
const startOrigin = "http://wails.localhost"

// allowedNavigation reports whether the WebView may go to uri: only the
// app's own page. Everything else (the web, file:, data:, about:, other
// hosts) is cancelled, whoever asked.
func allowedNavigation(uri string) bool {
	u, err := url.Parse(uri)
	if err != nil {
		return false
	}
	return u.Scheme == "http" && u.Host == "wails.localhost" && u.User == nil && u.Opaque == ""
}

// allowedIPC reports whether a message from the page to Wails gets through.
// Wails' JavaScript runtime can ask for much more than the app uses (open a
// URL in the browser, which elevated would be an administrator's browser;
// events; drops; show/hide; window size): only what the app needs passes.
func allowedIPC(msg string) bool {
	switch msg {
	case "runtime:ready", "drag", // Wails' own start-up, and moving the frameless window
		"Q",                                // quit
		"Wm", "Wt", "WM", "WU", "Wu", "WS": // minimise, toggle/maximise, restore, show
		return true
	}
	if strings.HasPrefix(msg, "resize:") { // resizing the frameless window by its edges
		return true
	}
	// Calls to the bound API methods (C{json}): that's the app's whole bridge.
	return strings.HasPrefix(msg, "C{")
}

// GuardStatus is what the page (and the self-test) learns about the guard
// (guard_windows.go).
type GuardStatus struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	// What it stopped so far.
	Navigations int64  `json:"navigationsBlocked"`
	Frames      int64  `json:"frameNavigationsBlocked"`
	NewWindows  int64  `json:"newWindowsBlocked"`
	Downloads   int64  `json:"downloadsBlocked"`
	IPC         int64  `json:"ipcBlocked"`
	LastBlocked string `json:"lastBlocked,omitempty"`
}

// expectedViolations are the CSP violations the self-test causes on purpose
// (a fetch and an iframe); any other is a failure.
var expectedViolations = map[string]bool{"connect-src": true, "frame-src": true}

// selftestProblems judges a self-test: the page's report (app.js) and the
// guard's counters. No problems means the app works and held.
func selftestProblems(mode string, page map[string]any, g GuardStatus) []string {
	var p []string
	bad := func(f string, args ...any) { p = append(p, fmt.Sprintf(f, args...)) }
	if e, ok := page["error"]; ok {
		bad("page error: %v", e)
	}
	if !g.OK {
		bad("guard not in place: %s", g.Error)
	}
	gl, _ := page["gl"].(map[string]any)
	if ok, _ := gl["ok"].(bool); !ok {
		bad("no WebGL")
	} else if r, _ := gl["renderer"].(string); r == "" {
		bad("WebGL renderer unknown")
	}
	if mode == "full" {
		if n, _ := page["frames"].(float64); n < 20 {
			bad("3D scene drew only %v frames", n)
		}
	}
	at, _ := page["attacks"].(map[string]any)
	want := map[string]string{"windowOpen": "blocked", "fetch": "blocked", "notifications": "denied"}
	for k, v := range want {
		if got, _ := at[k].(string); got != v {
			bad("%s: %q, want %q", k, got, v)
		}
	}
	if got, _ := at["clipboardRead"].(string); !strings.HasPrefix(got, "blocked") {
		bad("clipboardRead: %q", got)
	}
	if here, _ := at["stillHere"].(bool); !here {
		bad("page navigated away")
	}
	// (Chromium itself refuses the page's file: navigation before the guard
	// sees it; the https: one is the guard's.)
	if g.Navigations < 1 {
		bad("guard blocked no navigation (https:)")
	}
	if g.NewWindows < 1 {
		bad("guard blocked no new window")
	}
	if g.Downloads < 1 {
		bad("guard blocked no download")
	}
	if g.IPC < 2 {
		bad("guard blocked %d messages, want 2 (BO, EE)", g.IPC)
	}
	vs, _ := page["cspViolations"].([]any)
	sawConnect := false
	for _, v := range vs {
		m, _ := v.(map[string]any)
		d, _ := m["directive"].(string)
		if d == "connect-src" {
			sawConnect = true
		}
		if !expectedViolations[d] {
			bad("unexpected CSP violation: %v", m)
		}
	}
	if !sawConnect {
		bad("CSP didn't report the blocked fetch (is the CSP applied?)")
	}
	return p
}
