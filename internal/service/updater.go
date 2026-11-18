package service

import (
	"context"
	"math/rand/v2"
	"os/exec"
	"syscall"
	"time"

	"golang.org/x/sys/windows"

	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/update"
)

// updateLoop checks for a new signed release a few minutes after start, then
// about once a day, when the user turned automatic updates on.
func (s *server) updateLoop(ctx context.Context) {
	wait := 5*time.Minute + rand.N(15*time.Minute)
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		s.safe("update check", func() { s.checkForUpdate(ctx) })
		wait = 24*time.Hour + rand.N(2*time.Hour)
	}
}

func recordUpdate(latest, result string) {
	config.UpdateState(func(st *config.State) error {
		if st.Update == nil {
			st.Update = &config.UpdateStatus{}
		}
		st.Update.LastCheck = time.Now()
		if latest != "" {
			st.Update.Latest = latest
		}
		st.Update.LastResult = result
		return nil
	})
}

func (s *server) checkForUpdate(ctx context.Context) {
	s.mu.Lock()
	on := s.cfg != nil && s.cfg.AutoUpdate
	s.mu.Unlock()
	if !on || !update.Updatable(Version) {
		return
	}
	// Never touch the install while something is frozen or the PC is isolated:
	// a restart in the middle of an incident is the last thing you want.
	if st, err := config.LoadState(); err == nil && (st.Isolation != nil || len(st.Frozen) > 0) {
		s.log.Printf("update check skipped: an incident is in progress")
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	rel, err := update.Latest(ctx)
	if err != nil {
		s.log.Printf("update check: %v", err)
		recordUpdate("", "check failed: "+err.Error())
		return
	}
	if !update.Newer(Version, rel.Tag) {
		recordUpdate(rel.Tag, "up to date")
		return
	}
	s.log.Printf("update: %s is available (running %s); downloading", rel.Tag, Version)
	exe, err := update.Download(ctx, rel, update.Dir())
	if err != nil {
		s.log.Printf("update: %v", err)
		recordUpdate(rel.Tag, "not installed: "+err.Error())
		return
	}
	update.Cleanup(exe)
	s.log.Printf("update: %s verified (signature + checksum); handing over to it", rel.Tag)
	recordUpdate(rel.Tag, "installing "+rel.Tag)

	// The new binary stops this service, swaps the files and starts itself.
	// It must outlive us, so it runs detached.
	cmd := exec.Command(exe, "update", "apply", "--file", exe, "--from", Version)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: windows.CREATE_NEW_PROCESS_GROUP | windows.DETACHED_PROCESS,
	}
	if err := cmd.Start(); err != nil {
		s.log.Printf("update: could not start the installer: %v", err)
		recordUpdate(rel.Tag, "not installed: "+err.Error())
		return
	}
	cmd.Process.Release()
}
