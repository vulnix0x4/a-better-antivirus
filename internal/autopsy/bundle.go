package autopsy

// The evidence folder: what the autopsy found, a copy of the program, what it
// staged, and (optionally) a copy of its memory, saved where only
// administrators can read before `aba kill` ends the program for good.
//
// The program's memory and what it staged hold whatever it collected, which
// may be your own passwords and cookies. They stay in that folder: nothing
// is ever uploaded, and `aba export-ioc` leaves them out.

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/vulnix0x4/a-better-antivirus/internal/alerts"
)

const readme = `ABA evidence for alert %s
==========================================

This folder was saved by A Better Antivirus while the program it caught was
frozen, before anything could end it. Only administrators can read it.

  autopsy.json     what ABA found: real data it opened, files it staged,
                   addresses it was sending to (also: aba autopsy %s)
  program/         a copy of the program itself (renamed so it can't be run
                   by a double-click). It is MALWARE: don't run it.
  staged/          copies of files it had collected, when there were any.
                   THEY MAY HOLD YOUR OWN PASSWORDS, COOKIES AND KEYS.
  memory/          a copy of the program's memory, when one was taken.
                   IT HOLDS WHATEVER THE PROGRAM HAD COLLECTED, WHICH MAY BE
                   YOUR OWN PASSWORDS, COOKIES AND KEYS. Don't share it with
                   anyone you wouldn't give those to.

To share what's safe to share (the program's fingerprint, where it was
sending, the attacker's wallet), use:  aba export-ioc %s
That never includes anything from staged/ or memory/.

Delete this folder when you no longer need it.
`

// memImage writes a copy of one process's memory: the bytes, one region
// after another, and an index of where each came from.
type memImage struct {
	dir     string
	pid     uint32
	f       *os.File
	w       *bufio.Writer
	index   *os.File
	written int64
	full    bool
	err     error
}

func newMemImage(dir string, pid uint32) *memImage {
	return &memImage{dir: filepath.Join(dir, "memory"), pid: pid}
}

func (m *memImage) write(base uint64, b []byte) {
	if m.full || m.err != nil {
		return
	}
	if m.f == nil {
		if m.err = os.MkdirAll(m.dir, 0o700); m.err != nil {
			return
		}
		if m.f, m.err = os.OpenFile(filepath.Join(m.dir, fmt.Sprintf("pid-%d.bin", m.pid)), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600); m.err != nil {
			return
		}
		if m.index, m.err = os.OpenFile(filepath.Join(m.dir, fmt.Sprintf("pid-%d.regions.txt", m.pid)), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600); m.err != nil {
			return
		}
		m.w = bufio.NewWriterSize(m.f, 1<<20)
		fmt.Fprintf(m.index, "# address size offset-in-pid-%d.bin\n", m.pid)
	}
	if m.written+int64(len(b)) > memImageMax {
		b = b[:memImageMax-m.written]
		m.full = true
	}
	fmt.Fprintf(m.index, "%#x %d %d\n", base, len(b), m.written)
	n, err := m.w.Write(b)
	m.written += int64(n)
	if err != nil {
		m.err = err
	}
}

func (m *memImage) close() error {
	if m == nil || m.f == nil {
		return nil
	}
	if m.w != nil {
		m.w.Flush()
	}
	m.f.Close()
	m.index.Close()
	return m.err
}

// saveEvidence writes the evidence folder for c.
func saveEvidence(c Case, h Hooks, a *alerts.Autopsy, img *memImage, staged []*alerts.Staged) error {
	dir := evidenceDir(h.EvidenceDir, c.AlertID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	a.Evidence = dir
	var errs []string
	if err := os.WriteFile(filepath.Join(dir, "README.txt"), []byte(fmt.Sprintf(readme, c.AlertID, c.AlertID, c.AlertID)), 0o600); err != nil {
		errs = append(errs, err.Error())
	}
	if img != nil {
		if err := img.close(); err != nil {
			errs = append(errs, "memory: "+err.Error())
		} else if img.written > 0 {
			a.MemoryImage = true
			if img.full {
				a.Notes = append(a.Notes, fmt.Sprintf("The copy of its memory stops at %d MB.", memImageMax>>20))
			}
		}
	}
	if c.Image != "" && !c.Test {
		if err := copyCapped(c.Image, filepath.Join(dir, "program", filepath.Base(c.Image)+".sample"), sampleMax); err != nil {
			errs = append(errs, "program: "+err.Error())
		}
	}
	var copied int64
	for i := range a.Staged {
		st := &a.Staged[i]
		if !st.HeldOpen && st.Archive == "" && !strings.HasPrefix(st.What, "your real") && !strings.Contains(st.What, "same bytes") {
			continue
		}
		if copied+st.Size > stagedCopyMax {
			continue
		}
		dst := filepath.Join(dir, "staged", fmt.Sprintf("%02d-%s", i, filepath.Base(st.Path)))
		if err := copyCapped(st.Path, dst, stagedCopyMax-copied); err == nil {
			st.Saved = dst
			copied += st.Size
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

// copyCapped copies src to dst (at most max bytes), readable by its owner only.
func copyCapped(src, dst string, max int64) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, io.LimitReader(in, max))
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	return err
}
