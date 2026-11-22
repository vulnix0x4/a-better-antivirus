package classify

// What severity is judged by on macOS.
//
// macOS has code signatures, and nearly every real app has one: Apple's own,
// or a Developer ID that Apple issues to identified developers and revokes
// for malware (see package provenance). macOS stealers (Atomic, Banshee,
// Poseidon, Cthulhu…) almost never do. They come as a program built on a Mac,
// with the ad-hoc signature every such program gets, from a disk image or
// Downloads, and they do a lot of their reading through the system's own
// tools: osascript (AppleScript), a shell, cp, ditto, zip, curl, or Finder.
// Every one of those tools is Apple's. So, as on Linux, the program that
// opened a bait says little by itself; what counts is who is behind it, and
// byOrigin works that out from the chain of processes that led to the open:
//
//   - Anything in that chain without a valid signature makes the read
//     critical: an ad-hoc or unsigned program, wherever it is, unless only
//     root can have put it there; a script in a folder you can write to;
//     commands piped into a shell.
//   - A shell, an interpreter (osascript, python3…) or a file tool (a
//     "go-between") with nothing like that above it is a warning. If it was
//     run from a terminal someone types into, it may also read many apps'
//     data without being taken for a stealer.
//   - A signed app is a note, or a warning if it runs from where downloads
//     land (Downloads, a disk image, a quarantined copy). Apple's background
//     services that read every file (Spotlight, Time Machine, iCloud Drive,
//     Quick Look, XProtect) are never reported; backup and sync tools and
//     Finder may read many apps' data.
//
// Reading several apps' data stays critical for everything else, whoever it
// is (the engine's sweep rule). A copy made by Finder on a script's behalf is
// attributed to the script by the watcher (see package eswatch), so it's that
// script's chain that's judged here.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/procinfo"
	"github.com/vulnix0x4/a-better-antivirus/internal/provenance"
)

// What kind of program a name stands for.
const (
	kindApp    = iota // judged as itself
	kindShell         // runs commands: typed, from a script, or handed to it
	kindInterp        // runs a script or a program in its language
	kindTool          // reads, copies, packs or sends what it's told to, or starts what it's told to
)

var kinds = map[string]int{}

func init() {
	add := func(k int, names ...string) {
		for _, n := range names {
			kinds[n] = k
			runtimes[n] = true
		}
	}
	add(kindShell, "sh", "bash", "zsh", "dash", "ksh", "tcsh", "csh", "fish", "nu", "xonsh", "elvish")
	add(kindInterp, "osascript", "osacompile", "python", "python3", "Python", "pypy3", "perl", "ruby", "php", "node", "deno", "bun",
		"lua", "luajit", "java", "tclsh", "wish", "swift", "jsc", "expect", "make", "gmake", "pwsh", "Rscript", "julia", "groovy", "jshell")
	for _, v := range []string{"2.7", "3.8", "3.9", "3.10", "3.11", "3.12", "3.13", "3.14", "3.15"} {
		add(kindInterp, "python"+v)
	}
	for _, v := range []string{"5.18", "5.30", "5.34", "5.36", "5.38", "5.40"} {
		add(kindInterp, "perl"+v)
	}
	add(kindTool,
		// read or search
		"cat", "head", "tail", "less", "more", "nl", "od", "xxd", "hexdump", "strings", "file", "wc", "cut", "sort", "uniq",
		"paste", "split", "tee", "diff", "cmp", "grep", "egrep", "fgrep", "rg", "ag", "sed", "awk", "gawk", "jq", "sqlite3",
		"base64", "md5", "shasum", "openssl", "gpg", "plutil", "defaults", "security", "textutil", "mdls", "xattr", "pbcopy",
		"vi", "vim", "nvim", "view", "nano", "emacs", "ed", "bat",
		// copy, pack
		"cp", "mv", "dd", "install", "ditto", "rsync", "tar", "bsdtar", "cpio", "pax", "zip", "unzip", "7z", "7zz", "gzip", "bzip2",
		"xz", "zstd", "aa", "hdiutil", "rclone",
		// send
		"curl", "wget", "nc", "ncat", "socat", "scp", "sftp", "ssh", "ftp", "telnet",
		// start something else
		"find", "xargs", "env", "nice", "nohup", "timeout", "time", "watch", "script", "sudo", "su", "open", "caffeinate",
		"launchctl", "arch", "sandbox-exec", "login", "dtrace", "lldb", "taskpolicy")
}

var (
	// lolbins: on Windows, programs that are suspicious by name. macOS has
	// none: the same tool is a stealer's hands or yours, depending on who
	// started it (see byOrigin).
	lolbins = set()
	// runtimes are the shells, interpreters and tools of kinds: programs that
	// do what they're told, so they're never trusted or quieted as themselves
	// (classify.ScriptHost). Filled in by init.
	runtimes = set()
	// builtinIgnore is empty: the programs that are never reported are settled
	// in byOrigin, which also checks they're the real ones.
	builtinIgnore = []string{}
)

// Signed programs that read everything as part of their job.
var (
	// Apple's background services that read whatever is on the disk: never
	// reported. Only Apple's own code in the system's folders counts.
	appleReaders = set("mds", "mds_stores", "mdworker", "mdworker_shared", "mdsync", "mdbulkimport", "corespotlightd",
		"backupd", "backupd-helper", "bird", "cloudd", "fileproviderd", "QuickLookUIService", "quicklookd", "QuickLookSatellite",
		"ThumbnailsAgent", "com.apple.quicklook.ThumbnailsAgent", "revisiond", "fseventsd", "XprotectService",
		"XProtectBehaviorService", "XProtect", "XProtectRemediatorPirrit", "MRT", "syspolicyd", "trustd", "amfid",
		"spotlightknowledged", "mediaanalysisd", "photoanalysisd", "filecoordinationd", "lsd", "iconservicesagent",
		"suggestd", "searchpartyd", "storagekitd", "deleted", "diskmanagementd", "kernelmanagerd", "mobileassetd")
	// Other programs that read everything: antivirus scanners. Never reported
	// when signed.
	scanners = set("RTProtectionDaemon", "Malwarebytes", "falcond", "com.crowdstrike.falcon.Agent", "SentinelAgent", "sentineld",
		"SophosScanD", "SophosAntiVirus", "BDLDaemon", "bdlserv", "com.avast.daemon", "wsdaemon", "VShieldScanner", "clamd", "clamscan",
		"Intego", "VirusBarrier Scanner", "ESET", "esets_daemon")
	// Reported as a note, and allowed to go through many apps' data.
	backupTools = set("Arq", "ArqAgent", "Backblaze", "bzfilelist", "bztransmit", "bzserv", "CrashPlanService", "Code42",
		"Carbon Copy Cloner", "ccc_helper", "com.bombich.ccchelper", "SuperDuper!", "sdautomatedcopycontroller", "ChronoSync",
		"Dropbox", "DropboxMacUpdate", "Google Drive", "OneDrive", "FileProvider", "Box", "pCloud Drive", "MEGAclient",
		"Syncthing", "syncthing", "Resilio Sync", "Nextcloud", "owncloud", "Duplicati", "restic", "borg", "kopia", "duplicacy",
		"Time Machine", "rsnapshot")
	fileManagers = set("Finder", "ForkLift", "Path Finder", "Commander One", "Nimble Commander", "QSpace", "Marta", "muCommander",
		"The Unarchiver", "Archive Utility", "Keka")
	// The programs sessions hang off. A go-between right under one was
	// started by the system, not typed.
	managers = set("launchd")
)

// osVendor reports whether signer is Apple.
func osVendor(signer string) bool { return signer == provenance.AppleSigner }

// Env is where this machine keeps the folders the rules refer to. macOS's
// rules need none: they go by signatures and by who can write to a folder.
type Env struct{}

func DefaultEnv() Env { return Env{} }

func (e Env) expand(p string) string { return p }

// systemDirs are on the system's own volume, which nothing can change while
// the Mac runs (the signed system volume).
var systemDirs = []string{"/System/", "/usr/bin/", "/usr/sbin/", "/usr/libexec/", "/usr/lib/", "/bin/", "/sbin/", "/Library/Apple/"}

func inSystem(image string) bool {
	for _, d := range systemDirs {
		if strings.HasPrefix(image, d) {
			return true
		}
	}
	return false
}

// locate says where a program lives, as far as who could have put it there.
func (e Env) locate(image string, pid uint32) location {
	switch {
	case image == "":
		return locKernel
	case inSystem(image):
		return locSystem
	case strings.HasPrefix(image, "/Applications/") || view.RootOnly(image):
		// /Applications takes software installed for everyone; any
		// administrator may write there, so what's there counts as
		// installed only together with a valid signature.
		return locProgramFiles
	}
	return locUserWritable
}

// protected are the processes the desktop or the system goes down with.
var protected = set("launchd", "kernel_task", "WindowServer", "loginwindow", "Finder", "Dock", "SystemUIServer", "ControlCenter",
	"NotificationCenter", "coreaudiod", "opendirectoryd", "securityd", "trustd", "tccd", "syspolicyd", "configd", "mDNSResponder",
	"logd", "notifyd", "distnoted", "cfprefsd", "UserEventAgent", "powerd", "airportd", "bluetoothd", "hidd", "coreservicesd",
	"launchservicesd", "runningboardd", "sharingd", "usbd", "diskarbitrationd", "fseventsd", "mds", "backupd", "authd",
	"SecurityAgent", "coreauthd", "softwareupdated", "kextd", "kernelmanagerd", "sshd", "sshd-session", "Terminal", "iTerm2",
	"Spotlight", "WindowManager", "universalaccessd", "talagentd", "ScreenTimeAgent", "lsd")

// ProtectedProcess reports whether image is one of macOS's processes that
// ABA must never freeze, because the desktop or the system would go down with
// it. The name alone doesn't count: it has to be Apple's own code. (Terminal
// apps too: freezing one would freeze every shell in it with the stealer.)
func (c *Classifier) ProtectedProcess(image string) bool {
	if image == "" {
		return true
	}
	name := filepath.Base(image)
	if !protected[name] {
		return false
	}
	sig := view.Verify(image)
	return sig.Valid && (osVendor(sig.Signer) || name == "iTerm2")
}

// byLocation is what's left for a program byOrigin didn't judge. It judges
// them all, so this only says the same again.
func (c *Classifier) byLocation(image, name string, pid uint32, loc location, sig *provenance.Result, sigNote string) Verdict {
	v, _ := c.byOrigin(image, name, pid, sig, sigNote)
	return v
}

// DroppedScript belongs to the rule for runtimes in classify.go, which macOS
// doesn't use: byOrigin judges every script by where it is.
func DroppedScript(cmdline string) (path, where string) { return "", "" }

var (
	globMu    sync.Mutex
	globCache = map[string]*regexp.Regexp{}
)

// Glob matches a path against an ignore-rule pattern: '*' within a path
// segment, '**' across segments, '?' one character. Names are compared
// ignoring case, like the Mac's file systems do.
func Glob(pattern, path string) bool {
	globMu.Lock()
	re, ok := globCache[pattern]
	globMu.Unlock()
	if !ok {
		var b strings.Builder
		b.WriteString("(?i)^")
		for i := 0; i < len(pattern); i++ {
			switch {
			case strings.HasPrefix(pattern[i:], "**"):
				b.WriteString(`.*`)
				i++
			case pattern[i] == '*':
				b.WriteString(`[^/]*`)
			case pattern[i] == '?':
				b.WriteString(`[^/]`)
			default:
				b.WriteString(regexp.QuoteMeta(string(pattern[i])))
			}
		}
		b.WriteString("$")
		re = regexp.MustCompile(b.String())
		globMu.Lock()
		globCache[pattern] = re
		globMu.Unlock()
	}
	return re.MatchString(path)
}

var versionRun = regexp.MustCompile(`\d+(?:[.\-_]\d+)+`)

// GeneralizePath turns a version-specific path into a pattern that still
// matches after the app updates itself: …/Versions/1.2.3/… -> …/Versions/*/….
func GeneralizePath(image string) string {
	segs := strings.Split(image, "/")
	for i := 0; i < len(segs)-1; i++ { // keep the file name exact
		segs[i] = versionRun.ReplaceAllString(segs[i], "*")
	}
	return strings.Join(segs, "/")
}

// ---- looking at processes (replaced in tests) ----

type procView struct {
	Parent   func(pid uint32) uint32
	Image    func(pid uint32) string
	Args     func(pid uint32) []string
	Cwd      func(pid uint32) string
	Stdin    func(pid uint32) string
	TTY      func(pid uint32) int
	Started  func(pid uint32) int64 // 0 once it's gone
	Verify   func(path string) provenance.Result
	RootOnly func(path string) bool
}

var view = procView{
	Parent: procinfo.ParentPID,
	Image: func(pid uint32) string {
		p, _ := procinfo.ImagePath(pid)
		return p
	},
	Args: func(pid uint32) []string {
		a, _ := procinfo.Args(pid)
		return a
	},
	Cwd:   procinfo.Cwd,
	Stdin: procinfo.Stdin,
	TTY:   procinfo.TTY,
	Started: func(pid uint32) int64 {
		t, _ := procinfo.CreateTime(pid)
		return t
	},
	Verify: provenance.Verify,
	RootOnly: func(path string) bool {
		ok, _ := provenance.RootOnly(path)
		return ok
	},
}

// How a shell or interpreter got the code it runs.
const (
	codeNone   = iota // an ordinary program, or a tool
	codeScript        // a file: link.script
	codeGiven         // on its command line (-c, -e): whoever started it wrote that
	codeHidden        // from somewhere its command line doesn't show (a module, a class path)
	codeInput         // from its standard input: a terminal someone types into, or a pipe
)

// link is one process in the chain that led to a bait being opened.
type link struct {
	pid      uint32
	image    string
	name     string
	kind     int
	sig      provenance.Result
	rootOnly bool   // only root can have put the program there
	code     int    // for shells and interpreters
	script   string // the script it runs, when code is codeScript
	scriptOK bool   // … which a signed app or the system ships
	scriptRO bool   // … which at least only root can have put there
	terminal string // the terminal its input comes from, if it's one
	tty      int    // the terminal it's controlled from
}

// vouched: a valid signature, or (for a program root installed by hand,
// which an administrator chose) a folder only root can write to.
func (l *link) vouched() bool { return l.sig.Valid || l.rootOnly }

// actsAs is the name a link is a program in its own right under: itself for
// an ordinary program, the script for an interpreter running one that's part
// of a signed app or the system. "" for a go-between.
func (l *link) actsAs() string {
	switch {
	case l.kind == kindApp:
		return l.name
	case l.code == codeScript && (l.scriptOK || l.scriptRO):
		return filepath.Base(l.script)
	}
	return ""
}

// appBundle returns the app bundle a path is inside ("" if none).
func appBundle(p string) string {
	if i := strings.LastIndex(p, ".app/"); i >= 0 {
		return p[:i+4]
	}
	return ""
}

// scriptVouched: a script that's part of the system, or inside an app whose
// signature (which covers every file in the bundle) is valid.
func scriptVouched(p string) bool {
	if inSystem(p) {
		return true
	}
	if b := appBundle(p); b != "" {
		// The bundle's main program, by its usual name. (Another name, or no
		// such file, and the script doesn't count as the app's.)
		main := filepath.Join(b, "Contents", "MacOS", strings.TrimSuffix(filepath.Base(b), ".app"))
		return view.Verify(main).Valid
	}
	return false
}

func inspect(pid uint32, image string) link {
	l := link{pid: pid, image: image, name: filepath.Base(image)}
	l.kind = kinds[l.name]
	l.sig = view.Verify(image)
	l.rootOnly = !l.sig.Valid && view.RootOnly(image)
	l.tty = view.TTY(pid)
	if l.kind != kindShell && l.kind != kindInterp {
		return l
	}
	args := view.Args(pid)
	if len(args) == 0 {
		return l // it has exited and wasn't seen starting: nothing to go by
	}
	var operand string
	if l.kind == kindShell {
		var rc string
		operand, l.code, rc = shellCode(args)
		if rc != "" {
			if !filepath.IsAbs(rc) {
				rc = filepath.Join(view.Cwd(pid), rc)
			}
			if !view.RootOnly(filepath.Clean(rc)) {
				operand, l.code = rc, codeScript
			}
		}
	} else {
		operand, l.code = interpCode(l.name, args, view.Cwd(pid))
	}
	switch l.code {
	case codeScript:
		p := operand
		if !filepath.IsAbs(p) {
			p = filepath.Join(view.Cwd(pid), p)
		}
		l.script = filepath.Clean(p)
		l.scriptOK = scriptVouched(l.script)
		l.scriptRO = l.scriptOK || view.RootOnly(l.script)
	case codeInput:
		if in := view.Stdin(pid); strings.HasPrefix(in, "/dev/ttys") || strings.HasPrefix(in, "/dev/tty") {
			l.terminal = in
		}
	}
	return l
}

// shellCode says where a shell started with args gets its commands.
func shellCode(args []string) (operand string, code int, rc string) {
	for i := 1; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			if i+1 < len(args) {
				return args[i+1], codeScript, rc
			}
			return "", codeInput, rc
		case a == "--rcfile" || a == "--init-file":
			if i+1 < len(args) {
				rc = args[i+1]
				i++
			}
		case a == "-C" || strings.HasPrefix(a, "--init-command") || strings.HasPrefix(a, "--command"):
			return "", codeGiven, rc
		case a == "-o" || a == "+o" || a == "-O" || a == "+O":
			i++
		case strings.HasPrefix(a, "--") || a == "-":
		case len(a) > 1 && (a[0] == '-' || a[0] == '+'):
			if a[0] == '-' && strings.ContainsRune(a[1:], 'c') {
				return "", codeGiven, rc
			}
			// A cluster ending in o takes the option's name next (-euo pipefail).
			if a[len(a)-1] == 'o' || a[len(a)-1] == 'O' {
				i++
			}
		default:
			return a, codeScript, rc
		}
	}
	return "", codeInput, rc
}

// interpCode says where an interpreter started with args gets its program.
func interpCode(name string, args []string, cwd string) (operand string, code int) {
	lang := strings.ToLower(strings.TrimRight(name, "0123456789."))
	switch lang {
	case "gmake":
		lang = "make"
	case "pypy":
		lang = "python"
	}
	// Options that take a value as the next argument, per language; preload
	// are those whose value is code that gets loaded: a script by another name.
	var value, preload, given, hidden []string
	clusters := true // several one-letter options may be written as one (perl -lne)
	switch lang {
	case "osascript", "osacompile":
		// osascript -l JavaScript -e '…', or a script file. -s takes flags.
		value, given = []string{"-l", "-s", "-o"}, []string{"-e"}
		clusters = false
	case "python":
		value, given, hidden = []string{"-W", "-X", "-Q", "--check-hash-based-pycs"}, []string{"-c"}, []string{"-m"}
	case "node":
		clusters = false
		value = []string{"-C", "--conditions", "--title", "--env-file", "--input-type", "--inspect-port", "--max-http-header-size"}
		preload = []string{"-r", "--require", "--import", "--loader", "--experimental-loader"}
		given = []string{"-e", "--eval", "-p", "--print"}
	case "perl":
		value, given = []string{"-I", "-x"}, []string{"-e", "-E"}
	case "ruby":
		value, preload, given = []string{"-I", "-C", "-E", "-K", "-T", "-W"}, []string{"-r"}, []string{"-e"}
	case "php":
		value, preload, given = []string{"-c", "-d", "-z"}, []string{"-f", "-F"}, []string{"-r", "-R", "-B", "-E"}
	case "lua", "luajit":
		value, preload, given = nil, []string{"-l"}, []string{"-e"}
	case "swift":
		clusters = false
		value, given = []string{"-I", "-L", "-F", "-module-name", "-sdk", "-target"}, []string{"-e"}
	case "java":
		clusters = false
		value = []string{"-cp", "-classpath", "--class-path", "-p", "--module-path", "--add-modules", "--upgrade-module-path"}
		preload, hidden = []string{"-jar"}, []string{"-m", "--module"}
	case "make":
		return makeCode(args, cwd)
	case "deno", "bun":
		for _, a := range args[min(1, len(args)):] {
			if strings.HasPrefix(a, "-") {
				continue
			}
			if strings.Contains(a, "/") || strings.Contains(a, ".") {
				return a, codeScript
			}
			if a == "eval" || a == "repl" {
				return "", codeGiven
			}
		}
		return "", codeHidden
	default:
		given = []string{"-e", "-c"}
	}
	in := func(xs []string, a string) bool {
		for _, x := range xs {
			if a == x {
				return true
			}
		}
		return false
	}
	for i := 1; i < len(args); i++ {
		a := args[i]
		opt, val, hasVal := strings.Cut(a, "=")
		switch {
		case a == "--":
			if i+1 < len(args) {
				return args[i+1], codeScript
			}
			return "", codeInput
		case a == "-":
			return "", codeInput
		case in(preload, opt):
			if hasVal {
				return val, codeScript
			}
			if i+1 < len(args) {
				return args[i+1], codeScript
			}
		case in(given, opt):
			return "", codeGiven
		case in(hidden, opt):
			return "", codeHidden
		case in(value, opt):
			if !hasVal {
				i++
			}
		case strings.HasPrefix(a, "--"):
		case len(a) > 1 && a[0] == '-':
			for _, ch := range a[1:] {
				if !clusters {
					break
				}
				s := "-" + string(ch)
				if in(given, s) {
					return "", codeGiven
				}
				if in(hidden, s) {
					return "", codeHidden
				}
				if in(preload, s) || in(value, s) {
					break
				}
			}
		default:
			if lang == "java" {
				return "", codeHidden // a class name: what's on the class path isn't visible here
			}
			return a, codeScript
		}
	}
	return "", codeInput
}

// makeCode: make runs the Makefile of the folder it's in (or the one named
// with -f), which is a script like any other.
func makeCode(args []string, cwd string) (string, int) {
	dir := cwd
	for i := 1; i < len(args); i++ {
		a := args[i]
		switch {
		case (a == "-f" || a == "--file" || a == "--makefile") && i+1 < len(args):
			return filepath.Join(dir, args[i+1]), codeScript
		case strings.HasPrefix(a, "--file="):
			return filepath.Join(dir, strings.TrimPrefix(a, "--file=")), codeScript
		case (a == "-C" || a == "--directory") && i+1 < len(args):
			if filepath.IsAbs(args[i+1]) {
				dir = args[i+1]
			} else {
				dir = filepath.Join(dir, args[i+1])
			}
			i++
		}
	}
	for _, n := range []string{"GNUmakefile", "makefile", "Makefile"} {
		if _, err := os.Lstat(filepath.Join(dir, n)); err == nil {
			return filepath.Join(dir, n), codeScript
		}
	}
	return filepath.Join(dir, "Makefile"), codeScript
}

// ---- the verdict ----

type origin struct {
	tier    config.Tier
	reasons []string
	ignored bool // never reported: Spotlight, Time Machine, an antivirus scanner
	sweeps  bool // may go through many apps' data without being taken for a stealer
}

var (
	traceMu    sync.Mutex
	traceCache = map[uint32]traced{}
)

type traced struct {
	started int64
	image   string
	at      time.Time
	o       origin
}

// Remember works out who is behind pid now and keeps the answer for a couple
// of minutes. The watcher calls it as soon as it hears of a bait being
// opened: a short-lived reader (cat) is gone by the time the engine reports
// it.
func Remember(pid uint32) {
	if image := view.Image(pid); image != "" {
		trace(image, pid)
	}
}

// trace works out who is behind pid (running image) opening a bait.
func trace(image string, pid uint32) origin {
	started := view.Started(pid)
	traceMu.Lock()
	t, ok := traceCache[pid]
	traceMu.Unlock()
	if ok && t.image == image {
		switch {
		case started != 0 && started == t.started && time.Since(t.at) < 3*time.Second:
			return t.o
		case started == 0 && time.Since(t.at) < 2*time.Minute:
			return t.o // it has exited: what was seen while it ran
		}
	}
	o := judge(chain(pid, image), started == 0)
	traceMu.Lock()
	for p, x := range traceCache {
		if time.Since(x.at) > 2*time.Minute {
			delete(traceCache, p)
		}
	}
	traceCache[pid] = traced{started: started, image: image, at: time.Now(), o: o}
	traceMu.Unlock()
	return o
}

// chain lists pid and the processes that started it, nearest first, up to
// launchd.
func chain(pid uint32, image string) []link {
	var links []link
	cur := pid
	for depth := 0; depth < 16 && cur > 1; depth++ {
		img := image
		if depth > 0 {
			img = view.Image(cur)
		}
		if img == "" {
			break
		}
		l := inspect(cur, img)
		links = append(links, l)
		cur = view.Parent(cur)
	}
	return links
}

func vouchNote(l *link) string {
	switch {
	case l.sig.Valid:
		return "signed by " + l.sig.Signer
	case l.rootOnly:
		return "no valid signature, but only an administrator can have put it where it is"
	case l.sig.Error != "":
		return l.sig.Error
	}
	return "unsigned"
}

// downloaded: where programs that were just downloaded run from.
func downloaded(p string) bool {
	for _, s := range []string{"/Downloads/", "/Desktop/", "/AppTranslocation/"} {
		if strings.Contains(p, s) {
			return true
		}
	}
	for _, s := range []string{"/Volumes/", "/private/tmp/", "/tmp/", "/private/var/folders/", "/Users/Shared/"} {
		if strings.HasPrefix(p, s) {
			return true
		}
	}
	return false
}

func judge(links []link, gone bool) origin {
	if len(links) == 0 {
		return origin{tier: config.TierWarn, reasons: []string{"ABA couldn't see which program this was"}}
	}
	me := &links[0]
	critical := func(why string) origin {
		return origin{tier: config.TierCritical, reasons: []string{why, vouchNote(me)}}
	}

	// 1. Anything in the chain without a valid signature.
	for i := range links {
		l := &links[i]
		by := ""
		if i > 0 {
			by = me.name + " was started by "
		}
		switch {
		case !l.vouched() && i == 0:
			return critical("program with no valid signature (" + vouchNote(l) + "), running from " + filepath.Dir(l.image) + ": typical of stealers")
		case !l.vouched():
			return critical(by + l.image + ", a program with no valid signature (" + vouchNote(l) + "): what " + me.name + " reads, that program gets")
		case l.code == codeScript && !l.scriptRO && i == 0:
			return critical(l.name + " is running " + l.script + ", a script in a folder you can write to: typical of stealers hidden in downloads and packages")
		case l.code == codeScript && !l.scriptRO:
			return critical(by + l.script + " (run by " + l.name + "), a script in a folder you can write to: what " + me.name + " reads, that script gets")
		case l.code == codeInput && l.terminal == "":
			return critical(by + l.name + " running commands that were piped into it (the \"curl … | sh\" way of installing things, or an AppleScript fed to osascript): nobody vouches for those")
		}
	}

	// 2. Who asked: the first program in its own right (req), and whether a
	// shell someone types into comes before it (typed).
	var req, typed *link
	last := len(links) - 1
	plain := true // only tools and shells handed a command so far
	for i := range links {
		l := &links[i]
		if l.actsAs() != "" {
			req, last = l, i
			break
		}
		if plain && l.kind == kindShell && l.code == codeInput && l.terminal != "" {
			typed, last = l, i
			break
		}
		if l.kind == kindInterp || (l.kind == kindShell && l.code != codeGiven) {
			plain = false
		}
	}
	by := "the system"
	if len(links) > 1 {
		by = links[len(links)-1].name
	}

	// Something on the way that an administrator put there by hand, unsigned.
	unsigned := ""
	for i := 0; i <= last && unsigned == ""; i++ {
		if l := &links[i]; l.rootOnly {
			unsigned = l.image
		} else if l.code == codeScript && !l.scriptOK {
			unsigned = l.script
		}
	}

	var o origin
	switch {
	case me.actsAs() != "":
		name := me.actsAs()
		apple := me.sig.Valid && osVendor(me.sig.Signer)
		switch {
		case unsigned != "":
			o = origin{tier: config.TierWarn, reasons: []string{name + " has no valid signature, but sits where only an administrator can put things: someone installed it by hand", vouchNote(me)}}
		case apple && appleReaders[name] && inSystem(me.image):
			o = origin{tier: config.TierInfo, ignored: true, sweeps: true, reasons: []string{"built-in: macOS background service (" + name + ": Spotlight, Time Machine, iCloud Drive, Quick Look…)"}}
		case me.sig.Valid && !apple && scanners[name]:
			o = origin{tier: config.TierInfo, ignored: true, sweeps: true, reasons: []string{"built-in: antivirus scanner (" + me.sig.Signer + ")"}}
		case me.sig.Valid && backupTools[name]:
			o = origin{tier: config.TierInfo, sweeps: true, reasons: []string{name + " is a backup or sync tool: reading everything is its job", vouchNote(me)}}
		case me.sig.Valid && fileManagers[name] && (!apple || inSystem(me.image)):
			o = origin{tier: config.TierInfo, sweeps: true, reasons: []string{name + " is a file manager: showing and copying your files is its job", vouchNote(me)}}
		case me.sig.Valid && !apple && downloaded(me.image):
			o = origin{tier: config.TierWarn, reasons: []string{name + " is signed, but runs from " + filepath.Dir(me.image) + ", where downloads land, rather than from Applications", vouchNote(me)}}
		case apple:
			o = origin{tier: config.TierInfo, reasons: []string{"part of macOS", vouchNote(me)}}
		default:
			o = origin{tier: config.TierInfo, reasons: []string{"installed program", vouchNote(me)}}
		}
	case gone && len(links) == 1:
		o = origin{tier: config.TierWarn, reasons: []string{me.name + " reads whatever it's told to, and it had finished before ABA could see what started it", vouchNote(me)}}
	case typed != nil && me.tty != 0:
		o = origin{tier: config.TierWarn, sweeps: true, reasons: []string{
			me.name + " was run from a terminal (" + typed.name + " on " + typed.terminal + "): fine if you typed that yourself, but a script can read your files the same way", vouchNote(me)}}
	case me.code == codeHidden || me.code == codeGiven && me.kind == kindInterp:
		o = origin{tier: config.TierWarn, reasons: []string{me.name + " ran code that isn't in a file ABA can check (an AppleScript or program given on its command line, or a module)", vouchNote(me)}}
	case req == nil:
		o = origin{tier: config.TierWarn, reasons: []string{
			me.name + " was started in the background (by " + by + "), not typed at a terminal: it reads whatever it's told to", vouchNote(me)}}
	case unsigned == "" && (backupTools[req.actsAs()] || fileManagers[req.actsAs()]) && req.sig.Valid:
		o = origin{tier: config.TierInfo, sweeps: true, reasons: []string{me.name + " was started by " + req.actsAs() + ", a backup tool or file manager: reading everything is its job", vouchNote(req)}}
	default:
		o = origin{tier: config.TierWarn, reasons: []string{
			me.name + " was started by " + req.actsAs() + ", not typed at a terminal: it reads whatever it's told to, so what counts is what told it", vouchNote(me)}}
	}
	if unsigned != "" && me.actsAs() == "" {
		o.sweeps, o.ignored = false, false
		if o.tier == config.TierInfo {
			o.tier = config.TierWarn
		}
		o.reasons = append(o.reasons, unsigned+" has no valid signature, but sits where only an administrator can put things")
	}
	return o
}

// byOrigin judges a bait's reader by the chain of processes behind it (see
// the top of this file). On macOS it settles every reader that your own
// rules and the decoy's real app didn't.
func (c *Classifier) byOrigin(image, name string, pid uint32, sig *provenance.Result, sigNote string) (Verdict, bool) {
	o := trace(image, pid)
	return Verdict{Tier: o.tier, Ignored: o.ignored, Builtin: o.ignored, Reasons: o.reasons}, true
}

// sweepsAllowed reports whether this reader may go through many apps' data:
// a backup tool, a file manager, Spotlight and the like, or a command typed
// at a terminal.
func (c *Classifier) sweepsAllowed(image string, pid uint32) bool {
	return image != "" && trace(image, pid).sweeps
}

// sameStart lets an operating system add to what a rule pinned to a command
// line (or a folder) requires: that it was started the way it was when you
// trusted it. Nothing more is asked here.
func (c *Classifier) sameStart(r config.IgnoreRule, pid uint32) bool { return true }

// SweepTrustable reports whether a reader that went through several apps'
// data may be trusted permanently by its exact command line (a scheduled
// backup). Not here: see trust.Rule.
func SweepTrustable(image string) bool { return false }
