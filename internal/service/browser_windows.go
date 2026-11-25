package service

import (
	"encoding/json"
	"fmt"
	"time"

	"golang.org/x/sys/windows"

	"github.com/vulnix0x4/a-better-antivirus/internal/session"
)

// windowCheckTimeout is how long the service waits for `aba window-check`
// before it takes the answer as unknown (which never counts as "hidden").
const windowCheckTimeout = 1500 * time.Millisecond

// VisibleWindow asks, in the session pids run in, whether any of them has a
// window the person can see: a service in session 0 can't see the windows
// of another session, so `aba window-check` runs there, as SYSTEM, and says.
func (s *server) VisibleWindow(pids []uint32) (visible, known bool) {
	if len(pids) == 0 {
		return false, false
	}
	var sid uint32
	if err := windows.ProcessIdToSessionId(pids[0], &sid); err != nil || sid == 0 {
		return false, false
	}
	args := []string{"window-check"}
	for _, p := range pids {
		args = append(args, fmt.Sprint(p))
	}
	h, err := session.StartSystem(sid, s.cliExe, args...)
	if err != nil {
		s.log.Printf("window check in session %d: %v", sid, err)
		return false, false
	}
	h.In.Close()
	type answer struct {
		Visible *bool  `json:"visible"`
		Windows int    `json:"windows"`
		Error   string `json:"error"`
	}
	got := make(chan answer, 1)
	go func() {
		var a answer
		json.NewDecoder(h.Out).Decode(&a)
		got <- a
	}()
	select {
	case a := <-got:
		h.Stop()
		if a.Visible == nil {
			s.log.Printf("window check in session %d: no answer (%s)", sid, a.Error)
			return false, false
		}
		s.log.Printf("window check in session %d: %d window(s) on screen for pids %v", sid, a.Windows, pids)
		return *a.Visible, true
	case <-time.After(windowCheckTimeout):
		windows.TerminateProcess(h.Process(), 1)
		h.Stop()
		s.log.Printf("window check in session %d: no answer within %v", sid, windowCheckTimeout)
		return false, false
	}
}
