package provenance

// Who made a program on macOS: its code signature, the way Gatekeeper sees
// it. Read with Apple's own codesign tool (the same checks the Security
// framework makes, without cgo), and kept per file until the file changes.
//
// What counts as vouched for (Valid):
//
//   - Apple's own code ("Software Signing"): Signer "Apple".
//   - A Developer ID signature, which Apple issues to identified developers
//     and revokes for malware: Signer "Name (TEAMID)".
//   - An app from the Mac App Store, which Apple re-signs.
//
// Not vouched for: no signature, an ad-hoc one (anyone can make one; that's
// what every program built on a Mac gets by default, and what macOS stealers
// almost always have), a development signature (only for the developer's own
// Macs), or a signature that doesn't match the file.

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// AppleSigner is Signer for Apple's own code.
const AppleSigner = "Apple"

type cached struct {
	key string
	r   Result
	at  time.Time
}

var (
	cacheMu sync.Mutex
	cache   = map[string]cached{}
	// One check per file at a time: several bait opens by one program arrive
	// together.
	inFlight = map[string]*sync.Mutex{}
)

// fileKey changes whenever the file at path is replaced or modified.
func fileKey(path string) (string, bool) {
	fi, err := os.Stat(path)
	if err != nil {
		return "", false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return "", false
	}
	return strings.Join([]string{itoa(uint64(st.Dev)), itoa(st.Ino), itoa(uint64(st.Size)), itoa(uint64(st.Mtimespec.Nano())), itoa(uint64(st.Ctimespec.Nano()))}, ":"), true
}

func itoa(v uint64) string {
	if v == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}

// Verify says who made the program at path.
func Verify(path string) Result {
	if path == "" {
		return Result{Error: "no file"}
	}
	key, ok := fileKey(path)
	if !ok {
		return Result{Error: "the file is gone"}
	}
	cacheMu.Lock()
	if c, hit := cache[path]; hit && c.key == key && time.Since(c.at) < 30*time.Minute {
		cacheMu.Unlock()
		return c.r
	}
	m := inFlight[path]
	if m == nil {
		m = &sync.Mutex{}
		inFlight[path] = m
	}
	cacheMu.Unlock()

	m.Lock()
	defer m.Unlock()
	cacheMu.Lock()
	if c, hit := cache[path]; hit && c.key == key {
		cacheMu.Unlock()
		return c.r
	}
	cacheMu.Unlock()

	r := check(path)
	cacheMu.Lock()
	if len(cache) > 2048 {
		cache = map[string]cached{}
	}
	cache[path] = cached{key: key, r: r, at: time.Now()}
	cacheMu.Unlock()
	return r
}

// Note records what the kernel said about the program at path when it ran:
// it validated Apple's own code (a "platform binary") as it mapped it. That
// spares a codesign run for each of the system's tools a stealer's script
// goes through. Only Apple's code is taken this way: everything else is
// looked at in full when it matters.
func Note(path string, platform, valid bool) {
	if !platform || !valid || path == "" {
		return
	}
	key, ok := fileKey(path)
	if !ok {
		return
	}
	cacheMu.Lock()
	defer cacheMu.Unlock()
	if c, hit := cache[path]; hit && c.key == key {
		return
	}
	cache[path] = cached{key: key, r: Result{Signed: true, Valid: true, Signer: AppleSigner}, at: time.Now()}
}

// codesignInfo is what `codesign -dv` says about a file.
type codesignInfo struct {
	unsigned   bool
	adhoc      bool
	authority  []string // leaf first
	teamID     string
	identifier string
}

func parseCodesign(out string) codesignInfo {
	var ci codesignInfo
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		switch {
		case strings.Contains(line, "code object is not signed at all"):
			ci.unsigned = true
		case !ok:
		case k == "Signature" && v == "adhoc":
			ci.adhoc = true
		case k == "Authority":
			ci.authority = append(ci.authority, v)
		case k == "TeamIdentifier" && v != "not set":
			ci.teamID = v
		case k == "Identifier":
			ci.identifier = v
		}
	}
	return ci
}

// judgeSignature turns codesign's description (and whether the signature
// matches the file) into a Result.
func judgeSignature(ci codesignInfo, verified bool, verifyErr string) Result {
	switch {
	case ci.unsigned:
		return Result{}
	case ci.adhoc || len(ci.authority) == 0:
		// "Signed" by nobody: a hash of itself, which anyone can make.
		return Result{Error: "ad-hoc signature (no developer)"}
	}
	leaf := ci.authority[0]
	r := Result{Signed: true}
	switch {
	case (leaf == "Software Signing" || leaf == "macOS Software Signing") && len(ci.authority) > 1 && ci.authority[len(ci.authority)-1] == "Apple Root CA":
		// (macOS 26 calls it "macOS Software Signing".)
		r.Signer = AppleSigner
	case leaf == "Apple Mac OS Application Signing":
		r.Signer = "Mac App Store app"
		if ci.teamID != "" {
			r.Signer += " (" + ci.teamID + ")"
		}
	case strings.HasPrefix(leaf, "Developer ID Application: "):
		r.Signer = strings.TrimPrefix(leaf, "Developer ID Application: ")
	case strings.HasPrefix(leaf, "Apple Development: "), strings.HasPrefix(leaf, "Mac Developer: "),
		strings.HasPrefix(leaf, "Apple Distribution: "), strings.HasPrefix(leaf, "3rd Party Mac Developer Application: "):
		r.Signer = leaf
		r.Error = "a development signature, which only works on the developer's own Macs"
		return r
	default:
		r.Signer = leaf
		r.Error = "signed by an authority macOS doesn't trust for programs (" + leaf + ")"
		return r
	}
	if !verified {
		r.Error = "the signature doesn't match the file"
		if verifyErr != "" {
			r.Error += " (" + verifyErr + ")"
		}
		return r
	}
	r.Valid = true
	return r
}

func check(path string) Result {
	var out bytes.Buffer
	cmd := exec.Command("/usr/bin/codesign", "-dv", "--verbose=2", path)
	cmd.Stdout, cmd.Stderr = &out, &out
	cmd.Run()
	ci := parseCodesign(out.String())
	if ci.unsigned || ci.adhoc || len(ci.authority) == 0 {
		return judgeSignature(ci, false, "")
	}
	vout, err := exec.Command("/usr/bin/codesign", "--verify", "--strict", path).CombinedOutput()
	msg := strings.TrimSpace(string(vout))
	if i := strings.LastIndex(msg, ": "); i >= 0 {
		msg = msg[i+2:]
	}
	return judgeSignature(ci, err == nil, msg)
}

// RootOnly reports whether only root can have put the file at path there or
// changed it: it, and every folder above it, belongs to root and can't be
// written by anyone else. /Applications isn't such a folder: on a Mac, every
// administrator account (usually the first person's own) may write to it
// without asking. why says what lets someone else in.
func RootOnly(path string) (ok bool, why string) {
	path = filepath.Clean(path)
	if !filepath.IsAbs(path) {
		return false, "not a full path"
	}
	cur := "/"
	for _, part := range strings.Split(strings.Trim(filepath.Dir(path), "/"), "/") {
		cur = filepath.Join(cur, part)
		if w := writable(cur); w != "" {
			return false, w
		}
	}
	if w := writable(path); w != "" {
		return false, w
	}
	return true, ""
}

// writable says why p could be changed by someone other than root ("" if it
// can't). The wheel group (0) is root's own.
func writable(p string) string {
	var st unix.Stat_t
	if err := unix.Lstat(p, &st); err != nil {
		return p + " doesn't exist"
	}
	if st.Mode&unix.S_IFMT == unix.S_IFLNK {
		if st.Uid != 0 {
			return p + " is a link that isn't root's"
		}
		return ""
	}
	switch {
	case st.Uid != 0:
		return p + " doesn't belong to root"
	case st.Mode&0o002 != 0 && st.Mode&unix.S_ISVTX == 0:
		return "anyone can write to " + p
	case st.Mode&0o020 != 0 && st.Gid != 0:
		return "a group other than root's can write to " + p
	}
	return ""
}
