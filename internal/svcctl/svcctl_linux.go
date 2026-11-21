package svcctl

// Linux isn't supported yet: this file only lets the rest of ABA build there.
// Everything in it is what a Linux backend has to provide.

import "github.com/vulnix0x4/a-better-antivirus/internal/platform"

var errNotYet = platform.Unsupported("the background service")

// Status reports whether the service is installed and running. It works
// without administrator rights.
func Status() (State, error) { return Unknown, errNotYet }

// InstallOrUpdate registers the service to run exe at boot, with the system's
// rights, restarting automatically if it ever dies.
func InstallOrUpdate(exe string) error { return errNotYet }

// Start starts the service and waits until it's protecting. Stop stops it
// and waits until it's gone (no service: nothing to do).
func Start() error { return errNotYet }
func Stop() error  { return errNotYet }

// Delete stops the service and unregisters it (no service: nothing to do).
func Delete() error { return errNotYet }

// Send tells the running service something (see Signal).
func Send(sig Signal) error { return errNotYet }
