package cli

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"sync"
	"time"

	"github.com/spf13/cobra"

	"github.com/vulnix0x4/a-better-antivirus/internal/clipbait"
)

// The clipboard guard: what the service runs in each session (as SYSTEM,
// see session.StartSystem) when the clipboard bait is on. It talks to the
// service over its standard input and output, one JSON object per line:
//
//	out: {"finding": {...}}  a clipper swapped a bait (clipbait.Finding)
//	     {"log": "..."}      for the service's log
//	in:  done                the service has dealt with the last finding
//
// It ends when its input closes (the service stopped, or the bait was
// switched off), putting the clipboard back first if a bait is out.
func clipGuardCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "clipboard-guard",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runClipGuard(os.Stdin, os.Stdout, clipGuardTiming{})
		},
	}
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
		select {
		case _, ok := <-lines:
			if !ok {
				return nil // the service let go of us
			}
			continue // a stray "done": nothing is waiting for one
		case <-time.After(t.Check):
		}
		if time.Now().Before(next) || clipbait.IdleTime() < t.Idle {
			continue
		}
		c := clipbait.Coins[coin%len(clipbait.Coins)]
		coin++
		f, err := g.Cycle(c)
		next = time.Now().Add(spread(t.Every))
		var skipped clipbait.Skipped
		switch {
		case errors.As(err, &skipped):
			next = time.Now().Add(spread(t.Every / 4)) // try again sooner
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
