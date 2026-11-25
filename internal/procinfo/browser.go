package procinfo

import (
	"errors"
	"strconv"
	"strings"
)

// Facts about a browser instance: the browser's main process and everything
// it started, and how it was started. A stealer that wants the cookies a
// browser protects with its own encryption starts the genuine browser itself,
// suspended and without a window, and runs its code inside it; the browser
// you are using was started by you and shows its windows. Each fact is kept
// on its own, so the engine can weigh them separately (see engine's host
// policy).

// ErrGone means the process isn't running (any more).
var ErrGone = errors.New("the process has exited")

// ErrUnsupported means this system doesn't tell ABA these facts.
var ErrUnsupported = errors.New("not available on this system")

// BrowserInstance is one running browser: its main process and what it started.
type BrowserInstance struct {
	Main        uint32
	MainCreate  int64
	Image       string // the main process's executable
	CommandLine string
	PIDs        []uint32 // the main process and everything it started (main first)

	// CreatedSuspended: the main process was created suspended and its first
	// thread has never run (see SysThread.NeverRan). A browser you start runs
	// right away.
	CreatedSuspended bool
	// Hidden says, in plain words, how it was told to start without showing
	// itself: told to hide its window, or put on a desktop other than the
	// one you see. Empty when it wasn't.
	Hidden []string
	// Flags are the command-line switches that start it without a window,
	// or let another program drive it (see BrowserFlags).
	Flags []string

	// Starter is the program that started the main process: the first
	// ancestor that isn't this same browser (a browser restarting itself to
	// update is skipped). 0 with StarterGone when it has exited.
	Starter       uint32
	StarterImage  string
	StarterCreate int64
	StarterGone   bool
}

// Has reports whether pid belongs to the instance.
func (b *BrowserInstance) Has(pid uint32) bool {
	if b == nil {
		return false
	}
	for _, p := range b.PIDs {
		if p == pid {
			return true
		}
	}
	return false
}

// BrowserChild reports whether a browser process's command line is that of
// one of the processes a browser starts for itself (a tab, the GPU, the
// network service…), not of the browser itself: Chromium passes --type=,
// Firefox -contentproc.
func BrowserChild(cmdline string) bool {
	for _, a := range strings.Fields(strings.ToLower(cmdline)) {
		a = strings.Trim(a, `"`)
		if strings.HasPrefix(a, "--type=") || a == "-contentproc" || a == "--contentproc" {
			return true
		}
	}
	return false
}

// BrowserFlags picks out of a browser's command line the switches that start
// it with no window to see (--headless, --no-startup-window, a window far off
// the screen), or let another program drive it and read its data (remote
// debugging). In plain words, one per switch.
func BrowserFlags(cmdline string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(s string) {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, a := range strings.Fields(cmdline) {
		a = strings.Trim(a, `"`)
		l := strings.ToLower(a)
		name, val, _ := strings.Cut(l, "=")
		switch name {
		case "--headless", "-headless":
			add("--headless (no window at all)")
		case "--no-startup-window":
			add("--no-startup-window (started without a window)")
		case "--remote-debugging-port", "--remote-debugging-pipe", "-remote-debugging-port", "--remote-debugging-address":
			add(a + " (lets another program drive it and read its data)")
		case "--window-position":
			if offScreen(val) {
				add(a + " (a window placed far off the screen)")
			}
		}
	}
	return out
}

// offScreen: a --window-position of "x,y" that no screen reaches.
func offScreen(v string) bool {
	x, y, ok := strings.Cut(v, ",")
	if !ok {
		return false
	}
	far := func(s string) bool {
		n, err := strconv.Atoi(strings.TrimSpace(s))
		return err == nil && (n <= -10000 || n >= 10000)
	}
	return far(x) || far(y)
}
