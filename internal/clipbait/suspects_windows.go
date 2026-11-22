package clipbait

import (
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/vulnix0x4/a-better-antivirus/internal/classify"
	"github.com/vulnix0x4/a-better-antivirus/internal/paths"
	"github.com/vulnix0x4/a-better-antivirus/internal/procinfo"
	"github.com/vulnix0x4/a-better-antivirus/internal/provenance"
)

// Suspects lists the programs in this session that a clipper Windows can't
// name could be, for Guard.Candidates. It's only asked once a bait has been
// swapped, so a clipper is known to be running.
//
// In: programs nobody vouches for (unsigned, or a broken signature), then
// Windows' own programs (malware likes to run inside one). Out: programs
// signed by anyone else, games among them, whose anti-cheat would object to
// being looked inside; the processes Windows can't run without; ABA.
func Suspects() []uint32 {
	snap, err := procinfo.Snapshot()
	if err != nil {
		return nil
	}
	var here uint32
	windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &here)
	self, _ := os.Executable()
	cls := &classify.Classifier{Env: classify.DefaultEnv()}
	winDir, _ := windows.GetWindowsDirectory()
	var unsigned, system []uint32
	for pid := range snap {
		if pid == 0 || pid == 4 || pid == windows.GetCurrentProcessId() {
			continue
		}
		var sid uint32
		if windows.ProcessIdToSessionId(pid, &sid) != nil || sid != here {
			continue
		}
		img, err := procinfo.ImagePath(pid)
		if err != nil || img == "" || paths.Same(img, self) || cls.ProtectedProcess(img) {
			continue
		}
		sig := provenance.Verify(img)
		switch {
		case !sig.Valid:
			unsigned = append(unsigned, pid)
		case strings.Contains(sig.Signer, "Microsoft") && winDir != "" && within(img, winDir) && !uiCritical(img):
			system = append(system, pid)
		}
	}
	return append(unsigned, system...)
}

func within(path, dir string) bool {
	rel, err := filepath.Rel(dir, path)
	return err == nil && !strings.HasPrefix(rel, "..")
}

// uiCritical: pausing these for a few seconds would freeze the screen or
// the keyboard for everyone, and malware doesn't hide in them.
func uiCritical(img string) bool {
	switch strings.ToLower(filepath.Base(img)) {
	case "dwm.exe", "ctfmon.exe", "textinputhost.exe", "fontdrvhost.exe", "winlogon.exe", "logonui.exe", "consent.exe":
		return true
	}
	return false
}

// IdleTime is how long it's been since anyone typed, clicked or moved the
// mouse in this session.
func IdleTime() time.Duration {
	var lii struct{ size, time uint32 }
	lii.size = uint32(unsafe.Sizeof(lii))
	if r, _, _ := pGetLastInputInfo.Call(uintptr(unsafe.Pointer(&lii))); r == 0 {
		return 0
	}
	now, _, _ := pGetTickCount.Call() // the same clock, wrapping the same way
	return time.Duration(uint32(now)-lii.time) * time.Millisecond
}
