//go:build darwin

package main

import (
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
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
	Pid        int
	Path       string
	Platform   bool
	TeamID     string
	SigningID  string
	CSFlags    uint32
	Translocated bool
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
		ppid := parentOf(cur.Pid)
		if ppid <= 1 {
			v.Severity, v.Reason = sevCritical, "script host or copy tool ("+filepath.Base(opener.Path)+") with no program above it"
			v.Culprit = cur
			return v
		}
		cur = factsForPid(ppid)
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
	return procFacts{Pid: pid, Path: pathOfPid(pid), Platform: s.Platform(), TeamID: s.TeamID, SigningID: s.SigningID, CSFlags: s.Flags}
}

// ps is plenty for a spike; the real backend would use proc_pidinfo/sysctl.
func psField(pid int, field string) string {
	out, err := exec.Command("/bin/ps", "-o", field+"=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func parentOf(pid int) int {
	n, _ := strconv.Atoi(psField(pid, "ppid"))
	return n
}

func pathOfPid(pid int) string { return psField(pid, "comm") }

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
