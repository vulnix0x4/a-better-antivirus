package service

// Linux isn't supported yet: this file only lets the rest of ABA build there.
// Everything in it is what a Linux backend has to provide: how the program
// runs as a service, and how it notices a bait being opened. The rest of the
// service (service.go, health.go, updater.go) is shared and calls into this.

import (
	"context"
	"os/exec"

	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/detect"
	"github.com/vulnix0x4/a-better-antivirus/internal/platform"
)

// Run runs the service: under the system's service manager, or in the
// foreground when console is true. A backend builds a server with newServer
// and calls its run method, passing on what the CLI tells the service
// (svcctl.Signal) and cancelling the context when asked to stop.
func Run(console bool) error {
	return platform.Unsupported("the background service")
}

// watchers is whatever the service keeps for noticing bait opens.
type watchers struct{}

func (s *server) initWatchers() {}

// prepare gets the process ready to protect, before anything else runs (on
// Windows: the privileges it needs).
func (s *server) prepare() {}

// startWatching starts noticing bait opens, until ctx is done, and closes
// s.listening once it does. There are two ways to report one (see package
// detect): while the opener is held, call s.decideOpen; after the fact, send
// a detect.Access to s.accesses.
func (s *server) startWatching(ctx context.Context) {}

func (s *server) stopWatching() {}

// guard sets which bait files are watched for opens that can be held (nil:
// let go of them all, e.g. while files are being removed).
func (s *server) guard(files []string) {}

// guardCounts reports how many bait files are guarded right now, and how
// many should be.
func (s *server) guardCounts() (armed, want int) { return 0, 0 }

// baitsChanged is told whenever the set of bait files may have changed.
func (s *server) baitsChanged(st *config.State) {}

// saveProgress notes how far the service has read (in a log it resumes from
// after a restart), where there is such a thing.
func (s *server) saveProgress() {}

// resolve settles which bait an access reported without one (Path "") was
// about; false if it can't.
func (s *server) resolve(oa *detect.Access) bool { return false }

// detectionHealth checks whatever the operating system needs switched on for
// bait opens to be noticed at all, puts it right, and reports with add.
func (s *server) detectionHealth(startup bool, add func(name string, ok bool, detail string)) {
	add("Watching baits", false, platform.ErrUnsupported.Error())
}

// detach lets a program this service starts outlive it, in the background.
func detach(cmd *exec.Cmd) {}
