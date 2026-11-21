// Package svcctl manages ABA's background service: registering it with the
// operating system so it starts at boot, starting and stopping it, and
// telling the running one something.
//
// How is up to the operating system, in svcctl_<os>.go: the service control
// manager on Windows; systemd and launchd are the natural fits on Linux and
// macOS.
package svcctl

// State is a human-readable service state.
type State string

const (
	NotInstalled State = "not installed"
	Running      State = "running"
	Stopped      State = "stopped"
	Starting     State = "starting"
	Stopping     State = "stopping"
	Unknown      State = "unknown"
)

// Signal is something the CLI tells the running service (see Send).
type Signal int

const (
	// Reload: the configuration changed. Re-read it, then check the baits.
	Reload Signal = iota
	// CheckNow: run the health check now instead of at the next interval.
	CheckNow
	// Released: frozen processes were taken off the record (resumed or killed
	// through the CLI), so let go of the holds on them.
	Released
)
