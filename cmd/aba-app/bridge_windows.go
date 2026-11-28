package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/wailsapp/wails/v2/pkg/runtime"
	"golang.org/x/sys/windows"

	"github.com/vulnix0x4/a-better-antivirus/internal/appapi"
	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/paths"
)

// The bridge: what the page may ask for, on top of Info, OpenElevated and
// the self-test's methods (main_windows.go). The page is not trusted (its
// WebView2 processes run with the person's ordinary rights, see
// docs/app-phase0.md): every method checks what it's given, and the only
// things it can make happen are appapi's allowlisted actions.

var errLocked = errors.New("this needs administrator rights: use Open ABA")

// actor runs the page's actions through the installed CLI.
var actor = &appapi.Actor{CLI: paths.InstalledCLI(), Exists: appapi.DiskExists, Run: appapi.RunCLI, Secrets: config.LoadSecrets}

func (p *API) full() error {
	if p.a.mode != "full" {
		return errLocked
	}
	return nil
}

// source reads ABA's files fresh (they change under the app: the service
// adds the autopsy, the CLI resolves alerts).
func (p *API) source() (*appapi.Source, error) {
	if err := p.full(); err != nil {
		return nil, err
	}
	return appapi.Load(p.a.version)
}

// Snapshot is the Home screen.
func (p *API) Snapshot() (*appapi.Snapshot, error) {
	s, err := p.source()
	if err != nil {
		return nil, err
	}
	return s.Snapshot(), nil
}

// Alert is the Caught screen and Full report of alert id.
func (p *API) Alert(id string) (*appapi.Alert, error) {
	if err := p.full(); err != nil {
		return nil, err
	}
	a, err := appapi.LoadAlert(id)
	if err != nil {
		return nil, err
	}
	s, err := p.source()
	if err != nil {
		return nil, err
	}
	return s.Alert(a), nil
}

// History is every alert.
func (p *API) History() (*appapi.History, error) {
	s, err := p.source()
	if err != nil {
		return nil, err
	}
	return s.History(), nil
}

// Baits is the Baits screen.
func (p *API) Baits() (*appapi.Baits, error) {
	s, err := p.source()
	if err != nil {
		return nil, err
	}
	return s.Baits(), nil
}

// Settings is the Settings screen.
func (p *API) Settings() (*appapi.Settings, error) {
	s, err := p.source()
	if err != nil {
		return nil, err
	}
	return s.Settings(), nil
}

// Catalog is every bait ABA knows, for "Add a bait" (it looks at which
// apps are installed: the page asks when that screen opens).
func (p *API) Catalog() (*appapi.Catalog, error) {
	s, err := p.source()
	if err != nil {
		return nil, err
	}
	s.LoadPlan()
	return s.Catalog(), nil
}

// Trusted is the trusted programs, suggestions and learning mode.
func (p *API) Trusted() (*appapi.Trusted, error) {
	s, err := p.source()
	if err != nil {
		return nil, err
	}
	return s.Trusted(), nil
}

// Locked is the locked view (in either mode: it's what anyone may see).
func (p *API) Locked() *appapi.Locked {
	return appapi.LoadLocked(p.a.version, p.a.alert)
}

// Act runs one of appapi's actions.
func (p *API) Act(kind, id, arg string) appapi.Result {
	if err := p.full(); err != nil {
		return appapi.Result{OK: false, Message: err.Error()}
	}
	if p.a.selftest {
		return appapi.Result{OK: false, Message: "not during the self-test"}
	}
	res := actor.Act(kind, id, arg)
	if res.Private != nil {
		// A secret (a bait wallet's key, the ntfy topic): shown by the app
		// itself, in a window the page's processes can't read (they run with
		// the person's ordinary rights; see docs/app-phase0.md).
		if err := showPrivate(res.Private.Title, res.Private.Text); err != nil {
			return appapi.Result{OK: false, Message: "Couldn't show it: " + err.Error()}
		}
		res.Private = nil
	}
	if kind == appapi.ActUninstall && res.OK {
		// ABA is gone: so is the app, once the page has said so.
		go func() {
			time.Sleep(8 * time.Second)
			runtime.Quit(p.a.ctx)
		}()
	}
	return res
}

// Progress is what the running action (test, update) has said so far.
func (p *API) Progress() appapi.Progress {
	if p.full() != nil {
		return appapi.Progress{Events: []appapi.Event{}}
	}
	return actor.Progress()
}

// maxCopy is the most the page may put on the clipboard (a whole report).
const maxCopy = 256 << 10

// Copy puts text on the clipboard (the page itself may not: the guard
// denies it every permission).
func (p *API) Copy(text string) bool {
	if p.full() != nil || len(text) > maxCopy || !utf8.ValidString(text) || strings.ContainsRune(text, 0) {
		return false
	}
	return runtime.ClipboardSetText(p.a.ctx, text) == nil
}

// Pending is an alert ABA asked the app to show since the page last
// asked ("" if none): the service starts the app on a catch, and when it's
// already open, that second start leaves the alert's ID here for it.
func (p *API) Pending() string {
	if p.full() != nil {
		return ""
	}
	return takeOpenRequest()
}

// ---- the open request (a second start hands its alert to the first) ----

var openMu sync.Mutex

func openRequestFile() string { return filepath.Join(paths.AppDir(), "open-request.json") }

type openRequest struct {
	Alert string    `json:"alert"`
	Time  time.Time `json:"time"`
}

// leaveOpenRequest is a second (elevated) start's alert, for the app
// that's already open. The folder is administrators-only, so nothing
// running as the person can put an ID there.
func leaveOpenRequest(id string) error {
	if !appapi.ValidAlertID(id) {
		return errors.New("not an alert ID")
	}
	b, _ := json.Marshal(openRequest{Alert: id, Time: time.Now()})
	tmp := openRequestFile() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, openRequestFile())
}

func takeOpenRequest() string {
	openMu.Lock()
	defer openMu.Unlock()
	b, err := os.ReadFile(openRequestFile())
	if err != nil {
		return ""
	}
	os.Remove(openRequestFile())
	var r openRequest
	if json.Unmarshal(b, &r) != nil || !appapi.ValidAlertID(r.Alert) || time.Since(r.Time) > 10*time.Minute {
		return ""
	}
	return r.Alert
}

// showPrivate shows a secret in a plain Windows message box of the app's
// own (not Wails' dialogs, which the app doesn't use): Ctrl+C copies its
// text. It waits until it's closed.
func showPrivate(title, text string) error {
	t, err := windows.UTF16PtrFromString(title)
	if err != nil {
		return err
	}
	m, err := windows.UTF16PtrFromString(text)
	if err != nil {
		return err
	}
	_, err = windows.MessageBox(0, m, t, windows.MB_OK|windows.MB_ICONINFORMATION|windows.MB_TOPMOST|windows.MB_SETFOREGROUND)
	return err
}
