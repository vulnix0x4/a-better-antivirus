package service

import (
	"testing"
	"time"
)

type fakeApp struct {
	endAt      int // tick it ends at (-1: never)
	code       uint32
	ticks      int
	terminated bool
}

func (f *fakeApp) Exited() (bool, uint32) {
	if f.endAt >= 0 && f.ticks >= f.endAt {
		return true, f.code
	}
	return false, 0
}
func (f *fakeApp) Terminate() { f.terminated = true }

func TestWaitAppShown(t *testing.T) {
	for _, c := range []struct {
		name       string
		endAt      int
		code       uint32
		shownAt    int // tick the marker appears at (-1: never)
		elevated   bool
		want       bool
		terminated bool
	}{
		{"shows its window", -1, 0, 3, true, true, false},
		{"can't open (guard broke): exit 1", 2, 1, -1, true, false, false},
		{"handed to the open copy: exit 0", 1, 0, -1, true, true, false},
		{"stuck, elevated: ended, popup", -1, 0, -1, true, false, true},
		{"locked view still running", -1, 0, -1, false, true, false},
		{"locked view can't open", 4, 1, -1, false, false, false},
		{"marker then exit 1 (closed with an error later)", 5, 1, 2, true, true, false},
	} {
		f := &fakeApp{endAt: c.endAt, code: c.code}
		shown := func() bool { return c.shownAt >= 0 && f.ticks >= c.shownAt }
		sleep := func(time.Duration) { f.ticks++ }
		got := waitAppShown(f, shown, c.elevated, 10*time.Second, time.Second, sleep)
		if got != c.want || f.terminated != c.terminated {
			t.Errorf("%s: shown %v (want %v), terminated %v (want %v)", c.name, got, c.want, f.terminated, c.terminated)
		}
		if f.ticks > 10 {
			t.Errorf("%s: waited %d ticks, past the deadline", c.name, f.ticks)
		}
	}
}
