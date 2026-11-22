package cli

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"

	"github.com/vulnix0x4/a-better-antivirus/internal/alerts"
	"github.com/vulnix0x4/a-better-antivirus/internal/clipbait"
	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/engine"
	"github.com/vulnix0x4/a-better-antivirus/internal/paths"
	"github.com/vulnix0x4/a-better-antivirus/internal/svcctl"
	"github.com/vulnix0x4/a-better-antivirus/internal/ui"
)

// The clipboard guard: what the service runs in each session (as SYSTEM,
// see session.StartSystem) when the clipboard bait is on. It talks to the
// service over its standard input and output, one JSON object per line:
//
//	out: {"finding": {...}}  a clipper swapped a bait (clipbait.Finding)
//	     {"log": "..."}      for the service's log
//	in:  done                the service has dealt with the last finding
//	     bait                put a bait out now (`aba clipboard test`)
//
// It ends when its input closes (the service stopped, or the bait was
// switched off), putting the clipboard back first if a bait is out.
func clipGuardCmds() []*cobra.Command {
	return []*cobra.Command{{
		Use:    "clipboard-guard",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runClipGuard(os.Stdin, os.Stdout, clipGuardTiming{})
		},
	}, {
		Use:    "test-clipper",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			clipbait.RunFakeClipper(2 * time.Minute)
			return nil
		},
	}}
}

// clipGuardTiming says when baits go out. Zero values: the defaults.
type clipGuardTiming struct {
	Idle  time.Duration // nobody has touched the PC for this long
	Every time.Duration // at most one bait per this long (plus up to half again, at random)
	Check time.Duration // how often to look
}

func runClipGuard(in io.Reader, out io.Writer, t clipGuardTiming) error {
	if t.Idle == 0 {
		t.Idle = 10 * time.Minute
	}
	if t.Every == 0 {
		t.Every = 20 * time.Minute
	}
	if t.Check == 0 {
		t.Check = 30 * time.Second
	}
	var mu sync.Mutex
	enc := json.NewEncoder(out)
	say := func(v any) {
		mu.Lock()
		defer mu.Unlock()
		enc.Encode(v)
	}
	logf := func(format string, a ...any) { say(map[string]string{"log": fmt.Sprintf(format, a...)}) }

	g := &clipbait.Guard{Candidates: clipbait.Suspects, Logf: logf}
	if err := g.Start(); err != nil {
		return err
	}
	defer g.Stop()

	lines := make(chan string)
	go func() {
		sc := bufio.NewScanner(in)
		for sc.Scan() {
			lines <- sc.Text()
		}
		close(lines)
	}()
	spread := func(d time.Duration) time.Duration { return d + time.Duration(rand.Int64N(int64(d/2)+1)) }
	next := time.Now().Add(spread(t.Check))
	coin := 0
	for {
		now := false
		select {
		case line, ok := <-lines:
			if !ok {
				return nil // the service let go of us
			}
			if now = line == "bait"; !now {
				continue // a stray "done": nothing is waiting for one
			}
		case <-time.After(t.Check):
		}
		if !now && (time.Now().Before(next) || clipbait.IdleTime() < t.Idle) {
			continue
		}
		c := clipbait.Coins[coin%len(clipbait.Coins)]
		coin++
		f, err := g.Cycle(c)
		next = time.Now().Add(spread(t.Every))
		var skipped clipbait.Skipped
		switch {
		case errors.As(err, &skipped):
			if now {
				logf("clipboard bait: test: %v", err)
			}
			next = time.Now().Add(spread(t.Every / 4)) // try again sooner
		case err == nil && f == nil && now:
			logf("clipboard bait: test: the bait went out and nothing swapped it")
		case err != nil:
			logf("clipboard bait: %v", err)
		case f != nil:
			say(map[string]any{"finding": f})
			// The clipper stays paused (and the bait out) until the service has
			// frozen it, or decided not to.
			select {
			case _, ok := <-lines:
				if !ok {
					return nil
				}
			case <-time.After(time.Minute):
				logf("clipboard bait: no word from the service about the clipper; letting it go")
			}
			g.Finish()
		}
	}
}

// runClipboardTest is `aba clipboard test`: a harmless fake clipper, and a
// bait put out right away, the way `aba test` works for file baits.
func runClipboardTest() error {
	if s, _ := svcctl.Status(); s != svcctl.Running {
		return exitf("the service isn't running (%s); try `aba doctor --fix`", s)
	}
	cfg, err := mustConfig()
	if err != nil {
		return err
	}
	if !cfg.ClipboardBait {
		return exitf("the clipboard bait is off: switch it on with `aba clipboard on`")
	}
	self, _ := os.Executable()
	b, err := os.ReadFile(self)
	if err != nil {
		return err
	}
	fmt.Println()
	fmt.Println(ui.Banner("safe test"))
	fmt.Println()
	fmt.Println(" " + ui.Plain.Render("A harmless fake clipper in your Temp folder is about to swap the fake wallet address"))
	fmt.Println(" " + ui.Plain.Render("ABA puts on the clipboard. ") + ui.Bold.Render("Don't touch the mouse or keyboard for a few seconds."))
	fmt.Println()
	clipper, err := startTestCopy(b, "test-clipper")
	if err != nil {
		return err
	}
	defer func() {
		clipper.Close()
		for i := 0; i < 20; i++ {
			if _, err := os.Stat(clipper.Path); err != nil || os.Remove(clipper.Path) == nil {
				return
			}
			time.Sleep(250 * time.Millisecond)
		}
	}()
	pid := clipper.PID
	tr, _ := json.Marshal(engine.TestRequest{PID: pid, Nonce: strconv.Itoa(int(pid)), Since: time.Now(), Clipboard: true})
	if err := os.WriteFile(paths.TestFile(), tr, 0o644); err != nil {
		return err
	}
	time.Sleep(1500 * time.Millisecond) // the clipper gets going, and hands come off the keyboard
	if err := svcctl.Send(svcctl.CheckNow); err != nil {
		os.Remove(paths.TestFile())
		return err
	}
	fmt.Println(" " + ui.Good.Render(ui.IconArr) + ui.Dim.Render(" Bait out…"))
	start := time.Now()
	var found *alerts.Alert
	for time.Since(start) < 30*time.Second && found == nil {
		time.Sleep(200 * time.Millisecond)
		list, _ := alerts.List(5)
		for _, a := range list {
			if a.Test && a.Process != nil && a.Process.PID == pid {
				found = a
			}
		}
	}
	clipper.Close()
	fmt.Println()
	if found == nil {
		os.Remove(paths.TestFile())
		fmt.Println(" " + ui.Bad.Bold(true).Render(ui.IconBad) + " " + ui.Plain.Render("ABA didn't catch it within 30 seconds."))
		fmt.Println("   " + ui.Dim.Render("A bait only goes out while the clipboard holds text or nothing (copy some text and try"))
		fmt.Println("   " + ui.Dim.Render("again), and stops the moment the mouse or keyboard is used. The log says what happened: "+paths.LogFile()))
		return exitf("test failed")
	}
	rows := [][2]string{{"Caught", ui.TierWord(found.Tier) + ui.Dim.Render(": it swapped the fake wallet address")}}
	if found.Did(config.ActionFreeze) {
		rows = append(rows, [2]string{"Frozen", ui.Dim.Render("while ABA proved it was the one")})
	}
	rows = append(rows, [2]string{"Cleaned up", ui.Dim.Render("the fake clipper was killed and deleted, your clipboard put back")})
	for _, r := range rows {
		fmt.Printf(" %s %s %s\n", ui.Good.Bold(true).Render(ui.IconOK), ui.Plain.Render(fmt.Sprintf("%-11s", r[0])), r[1])
	}
	fmt.Println("\n " + ui.Plain.Render("That's what happens to a real one.") + ui.Dim.Render(" Everything ABA saw: ") +
		ui.Code.Render("aba alerts show "+found.ID[strings.LastIndex(found.ID, "-")+1:]))
	return nil
}
