// Command aba-app is ABA's desktop app (phase 0 spike): the Home screen's
// 3D scene in a WebView2 window, hosted by Wails v2 used as a library.
//
// Elevated (the normal case: started from the Start menu with a UAC prompt,
// or by the service on a catch with the person's elevated token), it shows
// everything; without administrator rights it shows only a locked view
// whose one button asks Windows to start it again elevated.
//
//	aba-app.exe [--alert <id>] [--selftest [--selftest-out <file>]] [--probe]
//
// --selftest runs the app, has the page check WebGL and try what the guard
// must stop, prints a JSON report and exits 0 when everything held.
// --probe shows a button and counts clicks and keys reaching the page (for
// the VM check that lower programs can't drive the app).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"sync"
	"time"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/logger"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	wopts "github.com/wailsapp/wails/v2/pkg/options/windows"
	"github.com/wailsapp/wails/v2/pkg/runtime"

	"github.com/vulnix0x4/a-better-antivirus/internal/appsec"
	"github.com/vulnix0x4/a-better-antivirus/internal/paths"
)

var version = "dev"

const windowClass = "ABAAppWindow"

// trace logs start-up steps when --debug-log is given.
var trace = func(string, ...any) {}

func main() {
	// First: nothing below may see what the person put in WEBVIEW2_*.
	scrubbed := appsec.ScrubProcessEnv()

	alert := flag.String("alert", "", "alert ID to open")
	selftest := flag.Bool("selftest", false, "check the app works and is locked down, then exit")
	selftestOut := flag.String("selftest-out", "", "also write the self-test report here")
	probe := flag.Bool("probe", false, "show a probe button and count input reaching the page")
	debugLog := flag.String("debug-log", "", "write start-up steps to this file")
	flag.Parse()
	if *debugLog != "" {
		if f, err := os.Create(*debugLog); err == nil {
			trace = func(f2 string, args ...any) {
				fmt.Fprintf(f, time.Now().Format("15:04:05.000 ")+f2+"\n", args...)
				f.Sync()
			}
			go func() { // a stuck start: where is everyone?
				time.Sleep(12 * time.Second)
				buf := make([]byte, 1<<20)
				trace("goroutines at 12s:\n%s", buf[:goruntime.Stack(buf, true)])
			}()
		}
	}
	trace("start, planted WEBVIEW2_* variables removed: %v", scrubbed)

	a := &App{
		version: version, selftest: *selftest, selftestOut: *selftestOut, probe: *probe,
		elevated: appsec.IsElevated(), scrubbed: scrubbed, guard: newGuard(),
		report: map[string]any{}, done: make(chan int, 1),
	}
	if *alert != "" {
		if !appsec.ValidAlertID(*alert) {
			a.fatal(fmt.Errorf("not an alert ID: %q", *alert))
		}
		a.alert = *alert
	}
	a.mode = "locked"
	if a.elevated {
		a.mode = "full"
	}
	os.Exit(a.run())
}

// App is the running app; API (the methods the page may call) wraps it.
type App struct {
	version, mode, alert string
	elevated             bool
	selftest, probe      bool
	selftestOut          string
	scrubbed             []string
	runtimeDir, dataDir  string
	guard                *guard
	ctx                  context.Context

	mu       sync.Mutex
	report   map[string]any
	clicks   int
	keys     int
	done     chan int // the self-test's exit code
	finished bool
	logLines []string
}

func (a *App) run() int {
	if a.mode == "full" {
		inst, err := appsec.SingleInstance()
		trace("single instance: %v", err)
		if errors.Is(err, appsec.ErrAlreadyRunning) {
			if hwnd := findWindowInSession(windowClass); hwnd != 0 {
				procShowWindow.Call(hwnd, 9 /* SW_RESTORE */)
				procSetForegroundWindow.Call(hwnd)
			}
			if a.selftest {
				a.finish(map[string]any{"ok": false, "error": err.Error()})
				return 3
			}
			return 0
		}
		if err != nil {
			a.fatal(err)
		}
		defer inst.Release()
	}

	var err error
	a.runtimeDir, err = appsec.ResolveRuntime()
	trace("runtime %q: %v", a.runtimeDir, err)
	if err != nil {
		a.fatal(err)
	}
	if a.mode == "full" {
		_, err = appsec.PrepareAppDir()
	}
	if err == nil {
		a.dataDir = appsec.WebViewDir()
		err = os.MkdirAll(a.dataDir, 0o700)
	}
	trace("user data folder %q: %v", a.dataDir, err)
	if err != nil {
		a.fatal(err)
	}

	ffs := frontendFS()
	idx, err := fs.ReadFile(ffs, "index.html")
	if err != nil {
		a.fatal(err)
	}
	csp, err := contentSecurityPolicy(idx)
	if err != nil {
		a.fatal(err)
	}
	headers := securityHeaders(csp)

	if a.selftest {
		go func() { // a page that never reports is a failure too
			time.Sleep(90 * time.Second)
			a.finish(map[string]any{"ok": false, "error": "timed out waiting for the page"})
		}()
	}

	trace("wails.Run")
	err = wails.Run(&options.App{
		Title:     "ABA",
		Width:     1440,
		Height:    900,
		MinWidth:  1100,
		MinHeight: 720,
		Frameless: true,
		// Shown by the guard's owner (startup) once the guard is in place.
		StartHidden:      true,
		BackgroundColour: &options.RGBA{R: 11, G: 12, B: 11, A: 255},
		AssetServer: &assetserver.Options{
			Assets: ffs,
			Middleware: func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					for k, v := range headers {
						w.Header().Set(k, v)
					}
					next.ServeHTTP(w, r)
				})
			},
		},
		Bind:                             []any{&API{a}},
		OnStartup:                        a.startup,
		Logger:                           (*appLogger)(a),
		LogLevel:                         logger.WARNING,
		LogLevelProduction:               logger.WARNING,
		EnableDefaultContextMenu:         false,
		EnableFraudulentWebsiteDetection: false,
		DragAndDrop:                      &options.DragAndDrop{EnableFileDrop: false, DisableWebViewDrop: true},
		Windows: &wopts.Options{
			WebviewBrowserPath:  a.runtimeDir,
			WebviewUserDataPath: a.dataDir,
			WindowClassName:     windowClass,
			Theme:               wopts.Dark,
			DisablePinchZoom:    true,
			// DLLs only from System32 (and by full path, like WebView2's).
			DLLSearchPaths: wopts.DLLSearchSystem32,
		},
	})
	if err != nil {
		a.fatal(err)
	}
	select {
	case code := <-a.done:
		return code
	default:
		if a.selftest {
			a.finish(map[string]any{"ok": false, "error": "window closed before the self-test ended"})
			return <-a.done
		}
		return 0
	}
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	trace("startup")
	go func() {
		a.guard.attach(ctx, windowClass)
		trace("guard: %v", a.guard.wait(0))
		if err := a.guard.wait(0); err != nil {
			// Fail closed: nothing is shown with the WebView unguarded.
			a.fatal(err)
		}
		runtime.WindowShow(ctx)
	}()
}

// fatal tells the person (or the self-test) and ends the app.
func (a *App) fatal(err error) {
	trace("fatal: %v", err)
	if a.selftest {
		a.finish(map[string]any{"ok": false, "error": err.Error()})
		os.Exit(1)
	}
	messageBox("ABA", "ABA can't open: "+err.Error())
	os.Exit(1)
}

// finish writes the self-test report (once) and ends the app.
func (a *App) finish(r map[string]any) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.finished {
		return
	}
	a.finished = true
	r["version"] = a.version
	r["mode"] = a.mode
	r["elevated"] = a.elevated
	r["runtime"] = a.runtimeDir
	r["userDataFolder"] = a.dataDir
	r["envScrubbed"] = a.scrubbed
	r["guard"] = a.guard.status()
	if len(a.logLines) > 0 {
		r["log"] = a.logLines
	}
	b, _ := json.MarshalIndent(r, "", "  ")
	fmt.Println(string(b))
	if a.selftestOut != "" {
		os.WriteFile(a.selftestOut, append(b, '\n'), 0o644)
	}
	code := 1
	if ok, _ := r["ok"].(bool); ok {
		code = 0
	}
	a.done <- code
	if a.ctx != nil {
		go runtime.Quit(a.ctx)
	}
}

// API is what the page may call (bound by Wails as window.go.main.API).
// Every method checks its input; nothing takes a path or a command.
type API struct{ a *App }

// Info is the page's starting point. It waits until the guard is in place.
type Info struct {
	Mode     string      `json:"mode"` // "full" (elevated) or "locked"
	Elevated bool        `json:"elevated"`
	Version  string      `json:"version"`
	Alert    string      `json:"alert,omitempty"`
	Runtime  string      `json:"runtime"` // the WebView2 version in use
	Guard    GuardStatus `json:"guard"`
	Selftest bool        `json:"selftest"`
	Probe    bool        `json:"probe"`
}

func (p *API) Info() Info {
	a := p.a
	a.guard.wait(15 * time.Second)
	return Info{Mode: a.mode, Elevated: a.elevated, Version: a.version, Alert: a.alert,
		Runtime: filepath.Base(a.runtimeDir), Guard: a.guard.status(), Selftest: a.selftest, Probe: a.probe}
}

// OpenElevated (locked view's "Open ABA") starts the app again with
// administrator rights and closes this one. It returns a message for the
// page when that didn't happen.
func (p *API) OpenElevated() string {
	a := p.a
	if a.mode != "locked" {
		return ""
	}
	args := []string{}
	if a.alert != "" {
		args = append(args, "--alert", a.alert)
	}
	if err := appsec.RelaunchElevated(args...); err != nil {
		return "Windows didn't start ABA as administrator (" + err.Error() + ")."
	}
	go runtime.Quit(a.ctx)
	return ""
}

// ProbeCounts: input that reached the page, in --probe mode.
type ProbeCounts struct {
	Clicks int `json:"clicks"`
	Keys   int `json:"keys"`
}

// Probe counts a click or key press that reached the page and records the
// totals in the app's admin-only folder (for the VM check).
func (p *API) Probe(kind string) ProbeCounts {
	a := p.a
	if !a.probe {
		return ProbeCounts{}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	switch kind {
	case "click":
		a.clicks++
	case "key":
		a.keys++
	}
	c := ProbeCounts{a.clicks, a.keys}
	if a.mode == "full" {
		b, _ := json.Marshal(c)
		os.WriteFile(filepath.Join(paths.AppDir(), "probe.json"), b, 0o600)
	}
	return c
}

// SelftestDone takes the page's report, adds what Go knows and decides.
func (p *API) SelftestDone(report string) {
	a := p.a
	if !a.selftest {
		return
	}
	var page map[string]any
	if err := json.Unmarshal([]byte(report), &page); err != nil {
		page = map[string]any{"error": "bad report: " + err.Error()}
	}
	time.Sleep(500 * time.Millisecond) // let the last blocked events land
	g := a.guard.status()
	problems := selftestProblems(a.mode, page, g)
	a.finish(map[string]any{"ok": len(problems) == 0, "problems": problems, "page": page})
}

// appLogger keeps Wails' warnings and errors for the self-test report.
type appLogger App

func (l *appLogger) add(level, msg string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.logLines) < 50 {
		l.logLines = append(l.logLines, level+": "+strings.TrimSpace(msg))
	}
}
func (l *appLogger) Print(string)     {}
func (l *appLogger) Trace(string)     {}
func (l *appLogger) Debug(string)     {}
func (l *appLogger) Info(string)      {}
func (l *appLogger) Warning(m string) { l.add("warning", m) }
func (l *appLogger) Error(m string)   { l.add("error", m) }
func (l *appLogger) Fatal(m string)   { l.add("fatal", m) }
