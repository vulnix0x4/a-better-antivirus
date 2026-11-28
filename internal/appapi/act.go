package appapi

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"
)

// The actions the page may ask for. Each runs the installed CLI (aba.exe)
// as a child of the (elevated) app, with --json --yes: what freezes, kills
// and cuts off stays in the CLI, and the app only reads its one-line result.
// Nothing the page sends reaches a command line unless it is one of a few
// fixed words, or an ID that matches a strict pattern and names an alert or
// a bait that exists.

// Kinds of action.
const (
	ActKill        = "kill"
	ActResume      = "resume"
	ActTrust       = "trust"
	ActRelease     = "release"
	ActInstant     = "instant"
	ActClipboard   = "clipboard"
	ActMiners      = "miners"
	ActRecorder    = "recorder"
	ActAutoUpdate  = "auto-update"
	ActPreset      = "preset"
	ActBaitShow    = "bait-show"
	ActTest        = "test"
	ActUpdateCheck = "update-check"
	ActUpdate      = "update"
	ActPhoneTest   = "phone-test"
)

var (
	// alertIDRe: what alerts.NewID makes (20261127-140207-7f3a), and the
	// IDs the tests use.
	alertIDRe = regexp.MustCompile(`^[0-9]{8}-[0-9]{6}-[0-9a-f]{4,8}$`)
	// baitIDRe: catalog IDs (discord, chrome-profile) and custom-<hex>.
	baitIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
)

// ValidAlertID reports whether id looks like an alert ID (whether it
// exists is up to the caller).
func ValidAlertID(id string) bool { return alertIDRe.MatchString(id) }

// ValidBaitID reports whether id looks like a bait ID.
func ValidBaitID(id string) bool { return baitIDRe.MatchString(id) }

// Exists tells Command whether an alert or bait is on disk.
type Exists struct {
	Alert func(id string) bool
	Bait  func(id string) bool
}

// Command is the CLI's arguments for an action, or why the action is refused.
func Command(kind, id, arg string, ex Exists) ([]string, error) {
	alert := func() error {
		if !ValidAlertID(id) {
			return fmt.Errorf("not an alert: %q", id)
		}
		if ex.Alert == nil || !ex.Alert(id) {
			return fmt.Errorf("no alert %s", id)
		}
		return nil
	}
	onOff := func() error {
		if arg != "on" && arg != "off" {
			return fmt.Errorf("%s takes on or off, not %q", kind, arg)
		}
		return nil
	}
	none := func() error {
		if id != "" || arg != "" {
			return fmt.Errorf("%s takes no ID or argument", kind)
		}
		return nil
	}
	var args []string
	var err error
	switch kind {
	case ActKill, ActResume, ActTrust:
		if err = alert(); err == nil && arg != "" {
			err = fmt.Errorf("%s takes no argument", kind)
		}
		args = []string{kind, "--", id}
	case ActRelease:
		switch {
		case arg != "":
			err = errors.New("release takes no argument")
		case id == "":
			args = []string{"release"}
		default:
			err = alert()
			args = []string{"release", "--", id}
		}
	case ActInstant, ActClipboard, ActMiners, ActRecorder:
		if err = onOff(); err == nil && id != "" {
			err = fmt.Errorf("%s takes no ID", kind)
		}
		args = []string{kind, arg}
	case ActAutoUpdate:
		if err = onOff(); err == nil && id != "" {
			err = fmt.Errorf("%s takes no ID", kind)
		}
		args = []string{"update", "auto", arg}
	case ActPreset:
		switch {
		case id != "":
			err = errors.New("preset takes no ID")
		case arg != "alert" && arg != "balanced" && arg != "strict":
			err = fmt.Errorf("no protection level %q", arg)
		}
		args = []string{"preset", arg}
	case ActBaitShow:
		switch {
		case arg != "":
			err = errors.New("bait-show takes no argument")
		case !ValidBaitID(id):
			err = fmt.Errorf("not a bait: %q", id)
		case ex.Bait == nil || !ex.Bait(id):
			err = fmt.Errorf("no bait %s", id)
		}
		args = []string{"bait", "show", "--", id}
	case ActTest:
		err = none()
		args = []string{"test"}
	case ActUpdateCheck:
		err = none()
		args = []string{"update", "--check"}
	case ActUpdate:
		err = none()
		args = []string{"update"}
	case ActPhoneTest:
		err = none()
		args = []string{"phone", "test"}
	default:
		return nil, fmt.Errorf("unknown action %q", kind)
	}
	if err != nil {
		return nil, err
	}
	// The flags go before "--": everything after it is an ID, never a flag.
	for i, a := range args {
		if a == "--" {
			out := append([]string{}, args[:i]...)
			out = append(out, "--json", "--yes")
			return append(out, args[i:]...), nil
		}
	}
	return append(args, "--json", "--yes"), nil
}

// timeout is how long an action may take.
func timeout(kind string) time.Duration {
	switch kind {
	case ActKill:
		return 4 * time.Minute // it waits up to 90 s for the evidence, then saves it itself
	case ActUpdate:
		return 16 * time.Minute
	case ActTest:
		return 90 * time.Second
	}
	return 2 * time.Minute
}

// Runner runs the CLI with args, calls line for every line it prints, and
// returns once it ends. (Windows: without a console window; see
// run_windows.go.)
type Runner func(ctx context.Context, exe string, args []string, line func(string)) error

// Actor runs actions, one at a time.
type Actor struct {
	CLI    string // the installed aba.exe
	Exists Exists
	Run    Runner

	run sync.Mutex // held while an action runs

	mu      sync.Mutex
	kind    string
	running bool
	events  []Event
}

// Progress is what the running action has said so far.
type Progress struct {
	Running bool    `json:"running"`
	Kind    string  `json:"kind,omitempty"`
	Events  []Event `json:"events"`
}

// Progress returns the running (or last) action's progress events.
func (a *Actor) Progress() Progress {
	a.mu.Lock()
	defer a.mu.Unlock()
	return Progress{Running: a.running, Kind: a.kind, Events: append([]Event{}, a.events...)}
}

// Act runs one action and returns its result.
func (a *Actor) Act(kind, id, arg string) Result {
	args, err := Command(kind, id, arg, a.Exists)
	if err != nil {
		return Result{OK: false, Message: err.Error()}
	}
	if !a.run.TryLock() {
		return Result{OK: false, Message: "ABA is still busy with the last thing you asked. Try again in a moment."}
	}
	defer a.run.Unlock()
	a.mu.Lock()
	a.kind, a.running, a.events = kind, true, nil
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		a.running = false
		a.mu.Unlock()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), timeout(kind))
	defer cancel()
	var last []byte
	var other []string
	runErr := a.Run(ctx, a.CLI, args, func(l string) {
		l = strings.TrimSpace(l)
		if l == "" {
			return
		}
		var ev Event
		if strings.HasPrefix(l, "{") && json.Unmarshal([]byte(l), &ev) == nil && ev.Event != "" {
			a.mu.Lock()
			a.events = append(a.events, ev)
			a.mu.Unlock()
			return
		}
		if strings.HasPrefix(l, "{") {
			last = []byte(l)
			return
		}
		if len(other) < 20 {
			other = append(other, l)
		}
	})
	res, perr := ParseResult(last)
	if perr != nil {
		msg := "ABA didn't answer as expected"
		switch {
		case errors.Is(ctx.Err(), context.DeadlineExceeded):
			msg = "ABA took too long to answer"
		case runErr != nil:
			msg += " (" + runErr.Error() + ")"
		}
		if len(other) > 0 {
			msg += ": " + strings.Join(other, " ")
		}
		return Result{OK: false, Message: msg}
	}
	a.mu.Lock()
	a.events = append(a.events, Event{Event: "done", Text: firstLine(res.Message), Time: time.Now()})
	a.mu.Unlock()
	return res
}

// ParseResult reads the CLI's --json result line.
func ParseResult(line []byte) (Result, error) {
	var raw struct {
		OK      *bool           `json:"ok"`
		Message string          `json:"message"`
		Details json.RawMessage `json:"details"`
	}
	if len(bytes.TrimSpace(line)) == 0 {
		return Result{}, errors.New("no result")
	}
	if err := json.Unmarshal(line, &raw); err != nil {
		return Result{}, err
	}
	if raw.OK == nil {
		return Result{}, errors.New("no ok in the result")
	}
	res := Result{OK: *raw.OK, Message: raw.Message}
	if len(raw.Details) > 0 && string(raw.Details) != "null" {
		res.Details = raw.Details
	}
	return res, nil
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// scanLines feeds line every line read from r (helper for Runners).
func scanLines(r interface{ Read([]byte) (int, error) }, line func(string)) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 8<<20)
	for sc.Scan() {
		line(sc.Text())
	}
}
