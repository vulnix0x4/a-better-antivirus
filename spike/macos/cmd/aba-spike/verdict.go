//go:build darwin

package main

import (
	"bytes"
	"encoding/binary"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

// A first cut of ABA's severity table for macOS, enough for the spike to make
// the same decision the real engine would. The real rules belong in the shared
// core (internal/classify); this only shows the macOS inputs are sufficient.

type severity string

const (
	sevIgnored  severity = "ignored"
	sevInfo     severity = "info"
	sevWarn     severity = "warn"
	sevCritical severity = "critical"
)

// Apple-signed programs that do nothing on their own: they read a file because
// some other program told them to. Seeing one of these open a bait says
// nothing; the verdict has to come from whoever is driving it.
var errandRunners = map[string]bool{
	"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true, "tcsh": true, "csh": true,
	"osascript": true, "python3": true, "perl": true, "ruby": true, "php": true, "swift": true,
	"cat": true, "cp": true, "mv": true, "ditto": true, "zip": true, "tar": true, "bsdtar": true, "gzip": true,
	"curl": true, "scp": true, "sftp": true, "rsync": true, "nc": true, "dd": true, "find": true, "xargs": true,
	"grep": true, "awk": true, "sed": true, "head": true, "tail": true, "base64": true, "openssl": true,
	"sqlite3": true, "plutil": true, "defaults": true, "security": true, "xxd": true, "hexdump": true, "strings": true,
	"less": true, "more": true, "open": true, "env": true, "sudo": true, "script": true, "caffeinate": true,
}

// Apple's own background readers. Measured on this Mac (see the PR): these are
// the ones that really open files in bait locations.
var appleBackgroundReaders = map[string]bool{
	"mds": true, "mds_stores": true, "mdworker": true, "mdworker_shared": true, "mdsync": true,
	"backupd": true, "backupd-helper": true, "bird": true, "cloudd": true, "fileproviderd": true,
	"QuickLookUIService": true, "quicklookd": true, "QuickLookSatellite": true, "ThumbnailsAgent": true,
	"com.apple.quicklook.ThumbnailsAgent": true, "revisiond": true, "fseventsd": true, "XprotectService": true,
	"XProtectBehaviorService": true, "syspolicyd": true, "trustd": true, "amfid": true, "kernel_task": true,
	"corespotlightd": true, "spotlightknowledged": true, "mediaanalysisd": true, "photoanalysisd": true,
	"filecoordinationd": true, "lsd": true, "iconservicesagent": true, "suggestd": true, "searchpartyd": true,
}

func userWritable(path string) bool {
	for _, p := range []string{"/Users/", "/private/tmp/", "/tmp/", "/private/var/folders/", "/var/folders/", "/private/var/tmp/", "/Volumes/"} {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

type procFacts struct {
	Pid       int
	PPid      int // from the event when known: the opener may be gone before anyone can ask
	Path      string
	Platform  bool
	TeamID    string
	SigningID string
	CSFlags   uint32
}

type verdict struct {
	Severity severity
	Reason   string
	// The process the verdict is really about: the opener, or, when the opener
	// is an Apple tool running an errand, the first non-Apple program above it.
	Culprit procFacts
	Chain   []procFacts
}

func judgeOne(p procFacts) (severity, string) {
	base := filepath.Base(p.Path)
	switch {
	case p.Platform && appleBackgroundReaders[base]:
		return sevIgnored, "Apple background service (" + base + ")"
	case p.Platform:
		return sevInfo, "part of macOS (" + base + ")"
	case p.CSFlags&csValid == 0:
		if userWritable(p.Path) {
			return sevCritical, "program with no valid signature running from a user-writable folder: typical of stealers"
		}
		return sevCritical, "program with no valid signature"
	case p.CSFlags&csAdhoc != 0 || p.TeamID == "":
		if userWritable(p.Path) {
			return sevCritical, "unsigned (ad-hoc) program running from a user-writable folder: typical of stealers"
		}
		return sevWarn, "unsigned (ad-hoc) program"
	case strings.Contains(p.Path, "/AppTranslocation/"):
		return sevWarn, "signed by team " + p.TeamID + " but run straight from a download (translocated)"
	case userWritable(p.Path):
		return sevWarn, "signed by team " + p.TeamID + ", running from a user folder"
	default:
		return sevInfo, "signed by team " + p.TeamID + ", installed software"
	}
}

// judge decides about the opener. If the opener is an Apple tool that only
// runs errands (a shell, cat, osascript...), it walks up the parents to the
// first program that is not, and judges that one instead, never ending up
// better than "critical" for a script host with nothing above it but launchd.
func judge(opener procFacts) verdict {
	v := verdict{Culprit: opener, Chain: []procFacts{opener}}
	cur := opener
	for hops := 0; hops < 12; hops++ {
		base := filepath.Base(cur.Path)
		if !(cur.Platform && errandRunners[base]) {
			break
		}
		// A tool like cat lives for a millisecond: by now it has usually
		// exited, so its parent has to come from the event, not from asking.
		ppid := cur.PPid
		if ppid == 0 {
			ppid = parentOf(cur.Pid)
		}
		if ppid <= 1 {
			v.Severity, v.Reason = sevCritical, "script host or copy tool ("+filepath.Base(opener.Path)+") with no program above it"
			v.Culprit = cur
			return v
		}
		cur = factsForPid(ppid)
		if cur.Path == "" {
			// The parent has exited too: nothing left to judge or freeze.
			v.Severity, v.Reason = sevWarn, "script host or copy tool ("+filepath.Base(opener.Path)+") whose parent has already exited"
			v.Culprit = v.Chain[len(v.Chain)-1]
			return v
		}
		v.Chain = append(v.Chain, cur)
	}
	v.Culprit = cur
	v.Severity, v.Reason = judgeOne(cur)
	if cur.Pid != opener.Pid {
		v.Reason = filepath.Base(opener.Path) + " run by " + filepath.Base(cur.Path) + ": " + v.Reason
		// A terminal the user types into is the one case where an Apple tool
		// under a signed app is expected; everything else that sends a shell
		// after a bait is at least suspicious.
		if v.Severity == sevInfo {
			v.Severity = sevWarn
		}
	}
	return v
}

func factsForPid(pid int) procFacts {
	s := signInfoForPid(pid)
	return procFacts{Pid: pid, PPid: parentOf(pid), Path: pathOfPid(pid), Platform: s.Platform(), TeamID: s.TeamID, SigningID: s.SigningID, CSFlags: s.Flags}
}

// proc_info(2), the call behind libproc's proc_pidpath and proc_pidinfo,
// straight from Go: no cgo, no exec.
const (
	sysProcInfo         = 336
	procInfoCallPidinfo = 2
	procPidTBSDInfo     = 3
	procPidPathInfo     = 11
)

func procInfo(pid, flavor int, buf []byte) int {
	n, _, e := syscall.Syscall6(sysProcInfo, procInfoCallPidinfo, uintptr(pid), uintptr(flavor), 0,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if e != 0 {
		return -1
	}
	return int(n)
}

func pathOfPid(pid int) string {
	buf := make([]byte, 4096)
	if procInfo(pid, procPidPathInfo, buf) < 0 {
		return ""
	}
	if i := bytes.IndexByte(buf, 0); i >= 0 {
		buf = buf[:i]
	}
	return string(buf)
}

// struct proc_bsdinfo starts: flags, status, xstatus, pid, ppid (uint32 each).
func parentOf(pid int) int {
	buf := make([]byte, 136)
	if procInfo(pid, procPidTBSDInfo, buf) < 0 || int(binary.LittleEndian.Uint32(buf[12:16])) != pid {
		return 0
	}
	return int(binary.LittleEndian.Uint32(buf[16:20]))
}

// descendants returns every process below pid.
func descendants(pid int) []int {
	out, err := exec.Command("/bin/ps", "-axo", "pid=,ppid=").Output()
	if err != nil {
		return nil
	}
	kids := map[int][]int{}
	for _, l := range strings.Split(string(out), "\n") {
		f := strings.Fields(l)
		if len(f) != 2 {
			continue
		}
		p, _ := strconv.Atoi(f[0])
		pp, _ := strconv.Atoi(f[1])
		kids[pp] = append(kids[pp], p)
	}
	var all []int
	queue := []int{pid}
	for len(queue) > 0 {
		p := queue[0]
		queue = queue[1:]
		for _, k := range kids[p] {
			all = append(all, k)
			queue = append(queue, k)
		}
	}
	return all
}
