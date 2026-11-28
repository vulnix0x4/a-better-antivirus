package main

// The guard closes what Wails v2 leaves open in its WebView2 (v2.17.1):
//
//   - it grants every permission a page asks for (camera, microphone,
//     clipboard, notifications, location...): the guard denies them all;
//   - it never cancels a navigation, a new window or a download: the guard
//     cancels every navigation away from the app's own page, every new
//     window and every download;
//   - its JavaScript runtime can ask Go to open a URL in the default browser
//     (from an elevated app, an administrator's browser) and more: the guard
//     lets through only the messages the app uses (policy.go);
//   - DevTools, context menus, host objects, autofill, swipe navigation and
//     dropping files in are switched off (again, whatever Wails set).
//
// Wails doesn't expose its WebView2 or its UI thread, so the guard takes the
// *edge.Chromium from the Wails frontend by reflection and runs on the UI
// thread through a subclass of the window procedure. Both depend on Wails'
// internals: the version is pinned in go.mod, and if anything doesn't fit
// the guard fails, and the app refuses to show anything (fail closed); the
// self-test checks every part of it in CI.

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/wailsapp/go-webview2/pkg/edge"
)

type guard struct {
	ready chan struct{}
	err   error

	nav, frames, newWin, downloads, ipc atomic.Int64
	mu                                  sync.Mutex
	last                                string
}

func newGuard() *guard { return &guard{ready: make(chan struct{})} }

// wait waits up to d for the guard to be in place.
func (g *guard) wait(d time.Duration) error {
	select {
	case <-g.ready:
		return g.err
	default:
	}
	select {
	case <-g.ready:
		return g.err
	case <-time.After(d):
		return errors.New("guard: not in place (yet)")
	}
}

func (g *guard) status() GuardStatus {
	s := GuardStatus{Navigations: g.nav.Load(), Frames: g.frames.Load(), NewWindows: g.newWin.Load(), Downloads: g.downloads.Load(), IPC: g.ipc.Load()}
	if err := g.wait(0); err != nil {
		s.Error = err.Error()
	} else {
		s.OK = true
	}
	g.mu.Lock()
	s.LastBlocked = g.last
	g.mu.Unlock()
	return s
}

func (g *guard) blocked(counter *atomic.Int64, what string) {
	counter.Add(1)
	if len(what) > 200 {
		what = what[:200]
	}
	g.mu.Lock()
	g.last = what
	g.mu.Unlock()
}

// attach installs the guard on the Wails app whose OnStartup got ctx, in
// the window of class windowClass. Call it from OnStartup (in a goroutine).
func (g *guard) attach(ctx context.Context, windowClass string) {
	defer close(g.ready)
	g.err = g.install(ctx, windowClass)
}

func (g *guard) install(ctx context.Context, windowClass string) error {
	chromium, err := chromiumOf(ctx.Value("frontend"))
	if err != nil {
		return err
	}
	var hwnd uintptr
	for i := 0; i < 100 && hwnd == 0; i++ {
		if hwnd = findOwnWindow(windowClass); hwnd == 0 {
			time.Sleep(50 * time.Millisecond)
		}
	}
	if hwnd == 0 {
		return errors.New("guard: app window not found")
	}
	ui, err := newUIRunner(hwnd)
	if err != nil {
		return fmt.Errorf("guard: subclass: %w", err)
	}
	ui.run(func() { err = g.installOnUI(chromium) })
	return err
}

// chromiumOf digs the *edge.Chromium out of Wails' Windows frontend
// (internal/frontend/desktop/windows.Frontend.chromium).
func chromiumOf(frontend any) (*edge.Chromium, error) {
	v := reflect.ValueOf(frontend)
	if v.Kind() != reflect.Pointer || v.IsNil() || v.Elem().Kind() != reflect.Struct {
		return nil, fmt.Errorf("guard: unexpected Wails frontend %T", frontend)
	}
	f := v.Elem().FieldByName("chromium")
	if !f.IsValid() || f.Type() != reflect.TypeOf((*edge.Chromium)(nil)) {
		return nil, fmt.Errorf("guard: Wails frontend %T has no chromium field of the expected type", frontend)
	}
	c := *(**edge.Chromium)(unsafe.Pointer(f.UnsafeAddr()))
	if c == nil {
		return nil, errors.New("guard: WebView2 not created")
	}
	return c, nil
}

func (g *guard) installOnUI(c *edge.Chromium) error {
	ctrl := c.GetController()
	if ctrl == nil {
		return errors.New("guard: no WebView2 controller")
	}
	wv, err := ctrl.GetCoreWebView2()
	if err != nil {
		return fmt.Errorf("guard: %w", err)
	}
	obj := unsafe.Pointer(wv)

	// Navigations: only the app's own page.
	onNav := func(counter *atomic.Int64) func(_, args unsafe.Pointer) uintptr {
		return func(_, args unsafe.Pointer) uintptr {
			uri := getString(args, idxNavGetURI)
			trace("navigation starting: %.120s", uri)
			if !allowedNavigation(uri) {
				comCall(args, idxNavPutCancel, 1)
				g.blocked(counter, "navigation to "+uri)
			}
			return 0
		}
	}
	if err := addHandler(obj, idxAddNavigationStarting, onNav(&g.nav)); err != nil {
		return fmt.Errorf("guard: NavigationStarting: %w", err)
	}
	if err := addHandler(obj, idxAddFrameNavigationStarting, onNav(&g.frames)); err != nil {
		return fmt.Errorf("guard: FrameNavigationStarting: %w", err)
	}
	// New windows: none. Handled without a new WebView means window.open
	// gets null and nothing opens.
	if err := addHandler(obj, idxAddNewWindowRequested, func(_, args unsafe.Pointer) uintptr {
		uri := getString(args, idxNewWinGetURI)
		comCall(args, idxNewWinPutHandled, 1)
		g.blocked(&g.newWin, "new window for "+uri)
		return 0
	}); err != nil {
		return fmt.Errorf("guard: NewWindowRequested: %w", err)
	}
	// Downloads: none.
	wv4, err := queryInterface(obj, &iidICoreWebView2_4)
	if err != nil {
		return fmt.Errorf("guard: WebView2 runtime too old (no ICoreWebView2_4): %w", err)
	}
	err = addHandler(wv4, idxAddDownloadStarting, func(_, args unsafe.Pointer) uintptr {
		comCall(args, idxDlPutCancel, 1)
		comCall(args, idxDlPutHandled, 1)
		g.blocked(&g.downloads, "download")
		return 0
	})
	release(wv4)
	if err != nil {
		return fmt.Errorf("guard: DownloadStarting: %w", err)
	}

	// Permissions: deny all (Wails set "allow" for all).
	c.SetGlobalPermission(edge.CoreWebView2PermissionStateDeny)

	// Messages from the page: only what the app uses.
	wailsMsg := c.MessageCallback
	if wailsMsg == nil {
		return errors.New("guard: Wails message handler missing")
	}
	c.MessageCallback = func(msg string, sender *edge.ICoreWebView2, args *edge.ICoreWebView2WebMessageReceivedEventArgs) {
		if !allowedIPC(msg) {
			g.blocked(&g.ipc, "message "+msg)
			return
		}
		wailsMsg(msg, sender, args)
	}
	c.MessageWithAdditionalObjectsCallback = func(msg string, _ *edge.ICoreWebView2, _ *edge.ICoreWebView2WebMessageReceivedEventArgs) {
		g.blocked(&g.ipc, "message with objects "+msg)
	}

	// Settings, whatever Wails chose.
	s, err := c.GetSettings()
	if err != nil {
		return fmt.Errorf("guard: settings: %w", err)
	}
	for name, err := range map[string]error{
		"DevTools":       s.PutAreDevToolsEnabled(false),
		"context menus":  s.PutAreDefaultContextMenusEnabled(false),
		"host objects":   s.PutAreHostObjectsAllowed(false),
		"status bar":     s.PutIsStatusBarEnabled(false),
		"accelerators":   s.PutAreBrowserAcceleratorKeysEnabled(false),
		"zoom":           s.PutIsZoomControlEnabled(false),
		"pinch zoom":     s.PutIsPinchZoomEnabled(false),
		"swipe":          c.PutIsSwipeNavigationEnabled(false),
		"autofill":       c.PutIsGeneralAutofillEnabled(false),
		"password saver": c.PutIsPasswordAutosaveEnabled(false),
		"external drop":  c.AllowExternalDrag(false),
	} {
		if err != nil {
			return fmt.Errorf("guard: %s: %w", name, err)
		}
	}
	return nil
}
