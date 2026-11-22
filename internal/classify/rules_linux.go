package classify

// What severity is judged by on Linux.
//
// Linux has no code signatures, and its stealers rarely come as one program:
// they are scripts (a malicious npm or PyPI package, a "curl … | sh"
// installer) that have the system's own tools do the reading: cat, cp, tar,
// python. Every one of those tools is genuine. So the program that opened a
// bait says little; what counts is who is behind it. byOrigin works that out
// from the chain of processes that led to the open:
//
//   - Anything in that chain that nobody vouches for makes the read critical:
//     a program or a script in a folder you can write to, commands piped into
//     a shell, a library slipped into a genuine program. (Who vouches: see
//     package provenance. A package that owns the file, in folders only root
//     can write to.)
//   - A shell, an interpreter or a file tool (a "go-between") with nothing
//     like that above it is a warning. If it was run from a terminal someone
//     types into, it may also read many apps' data without being taken for a
//     stealer: people grep and back up their own home folder.
//   - An ordinary installed program is a note. Backup tools and file
//     managers may read everything; desktop search and antivirus scanners
//     are never reported.
//
// Reading several apps' data stays critical for everything else, whoever it
// is (the engine's sweep rule).

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
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
	add(kindShell, "sh", "bash", "dash", "zsh", "fish", "ksh", "ksh93", "mksh", "tcsh", "csh", "ash", "busybox", "rbash", "yash", "elvish", "nu", "xonsh")
	add(kindInterp, "python", "python2", "python3", "pypy", "pypy3", "perl", "ruby", "php", "node", "nodejs", "deno", "bun",
		"lua", "luajit", "java", "tclsh", "wish", "Rscript", "rscript", "gjs", "guile", "pwsh", "expect", "make", "gmake", "julia", "groovy", "jshell")
	for _, v := range []string{"2.7", "3.6", "3.7", "3.8", "3.9", "3.10", "3.11", "3.12", "3.13", "3.14", "3.15"} {
		add(kindInterp, "python"+v)
	}
	for _, v := range []string{"5.1", "5.2", "5.3", "5.4", "7.4", "8.0", "8.1", "8.2", "8.3", "8.4", "3.0", "3.1", "3.2", "3.3", "3.4"} {
		add(kindInterp, "lua"+v, "php"+v, "ruby"+v)
	}
	add(kindTool,
		// read or search
		"cat", "tac", "head", "tail", "less", "more", "most", "nl", "od", "xxd", "hexdump", "strings", "file", "wc", "cut", "sort", "uniq",
		"paste", "split", "tee", "diff", "cmp", "grep", "egrep", "fgrep", "rg", "ag", "ack", "sed", "awk", "gawk", "mawk", "jq", "sqlite3",
		"base64", "base32", "md5sum", "sha1sum", "sha224sum", "sha256sum", "sha384sum", "sha512sum", "b2sum", "cksum", "openssl", "gpg", "gpg2", "age",
		"vi", "vim", "vim.basic", "vim.tiny", "nvim", "view", "nano", "emacs", "ed", "micro", "pico", "bat", "batcat",
		// copy, pack
		"cp", "mv", "dd", "install", "rsync", "tar", "bsdtar", "cpio", "pax", "zip", "7z", "7za", "7zr", "gzip", "bzip2", "xz", "zstd", "lz4", "ar", "gio", "rclone",
		// send
		"curl", "wget", "nc", "ncat", "netcat", "nc.openbsd", "nc.traditional", "socat", "scp", "sftp", "ssh", "ftp", "lftp", "telnet", "xclip", "xsel", "wl-copy",
		// start something else
		"find", "xargs", "parallel", "env", "nice", "ionice", "nohup", "timeout", "stdbuf", "setsid", "time", "watch", "script", "strace", "ltrace",
		"sudo", "su", "doas", "pkexec", "runuser", "flock", "chrt", "taskset", "unshare", "nsenter", "bwrap", "firejail", "systemd-run", "dbus-launch", "dbus-run-session")
}

var (
	// lolbins: on Windows, programs that are suspicious by name. Linux has
	// none: the same tool is a stealer's hands or yours, depending on who
	// started it (see byOrigin).
	lolbins = set()
	// runtimes are the shells, interpreters and tools of kinds: programs that
	// do what they're told, so they're never trusted or quieted as themselves
	// (classify.ScriptHost). Filled in by init.
	runtimes = set()
	// builtinIgnore is empty: the programs that are never reported are settled
	// in byOrigin, which also looks at what started them.
	builtinIgnore = []string{}
)

// Vouched programs that read everything as part of their job.
var (
	// Never reported: desktop search and antivirus scanners.
	indexers = set("tracker-miner-fs", "tracker-miner-fs-3", "tracker-extract", "tracker-extract-3", "localsearch-3", "localsearch-extractor-3",
		"baloo_file", "baloo_file_extractor", "baloorunner", "recollindex",
		"clamscan", "clamd", "clamdscan", "clamonacc", "rkhunter", "chkrootkit", "aide", "lynis")
	// Reported as a note, and allowed to go through many apps' data.
	backupTools = set("restic", "borg", "borgmatic", "duplicity", "deja-dup", "deja-dup-monitor", "duplicati", "timeshift", "backintime",
		"backintime-qt", "rsnapshot", "kopia", "vorta", "pika-backup", "syncthing", "nextcloud", "owncloud", "megasync", "insync", "dropbox", "rdiff-backup", "bup", "tarsnap")
	fileManagers = set("nautilus", "dolphin", "thunar", "nemo", "caja", "pcmanfm", "pcmanfm-qt", "krusader", "doublecmd", "mc", "ranger",
		"file-roller", "ark", "engrampa", "xarchiver", "gvfsd-admin", "kioslave5", "kioworker")
	// The programs sessions hang off. A go-between right under one was started
	// by the system or over the network, not typed.
	managers = set("systemd", "init")
)

// osVendor: nobody signs for the operating system on Linux.
func osVendor(signer string) bool { return false }

// Env is where this machine keeps the folders the rules refer to. Linux's
// rules need none: they ask who can write to a folder.
type Env struct{}

func DefaultEnv() Env { return Env{} }

func (e Env) expand(p string) string { return p }

// systemDirs are where the distribution keeps its own programs.
var systemDirs = []string{"/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/usr/lib/", "/usr/lib32/", "/usr/lib64/", "/usr/libexec/", "/lib/", "/lib32/", "/lib64/"}

// locate says where a program lives, as far as who could have put it there.
func (e Env) locate(image string, pid uint32) location {
	if image == "" {
		return locKernel
	}
	if !view.RootOnly(image) {
		return locUserWritable
	}
	for _, d := range systemDirs {
		if strings.HasPrefix(image, d) {
			return locSystem
		}
	}
	return locProgramFiles
}

// protected are the processes the desktop or the system goes down with.
var protected = set(
	"systemd", "init", "systemd-logind", "systemd-journald", "systemd-udevd", "systemd-resolved", "systemd-oomd", "systemd-userdbd", "systemd-homed",
	"dbus-daemon", "dbus-broker", "dbus-broker-launch", "Xorg", "Xwayland", "gnome-shell", "gnome-session-binary", "gdm", "gdm3",
	"gdm-session-worker", "gdm-wayland-session", "gdm-x-session", "sddm", "sddm-helper", "lightdm", "kwin_wayland", "kwin_x11", "plasmashell",
	"ksmserver", "startplasma-wayland", "startplasma-x11", "sway", "Hyprland", "weston", "mutter", "cinnamon", "xfwm4", "xfce4-session", "marco", "i3",
	"sshd", "sshd-session", "login", "agetty", "pipewire", "pipewire-pulse", "wireplumber", "pulseaudio", "NetworkManager", "wpa_supplicant",
	"polkitd", "udisksd", "upowerd", "accounts-daemon", "cron", "crond", "atd", "containerd", "dockerd", "snapd",
)

// ProtectedProcess reports whether image is one of the system's processes
// that ABA must never freeze, because the desktop or the system would go
// down with it. The name alone doesn't count: it has to be the real thing,
// owned by a package, where only root can have put it.
func (c *Classifier) ProtectedProcess(image string) bool {
	if image == "" {
		return true // a kernel thread
	}
	return protected[filepath.Base(image)] && view.Verify(image).Valid
}

// byLocation is what's left for a program byOrigin didn't judge. It judges
// them all, so this only says the same again.
func (c *Classifier) byLocation(image, name string, pid uint32, loc location, sig *provenance.Result, sigNote string) Verdict {
	v, _ := c.byOrigin(image, name, pid, sig, sigNote)
	return v
}

// DroppedScript belongs to the rule for runtimes in classify.go, which Linux
// doesn't use: byOrigin judges every script by who vouches for it.
func DroppedScript(cmdline string) (path, where string) { return "", "" }

var (
	globMu    sync.Mutex
	globCache = map[string]*regexp.Regexp{}
)

// Glob matches a path against an ignore-rule pattern: '*' within a path
// segment, '**' across segments, '?' one character. Linux file names are
// compared exactly.
func Glob(pattern, path string) bool {
	globMu.Lock()
	re, ok := globCache[pattern]
	globMu.Unlock()
	if !ok {
		var b strings.Builder
		b.WriteString("^")
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

var (
	versionRun = regexp.MustCompile(`\d+(?:[.\-_]\d+)+`)
	snapRev    = regexp.MustCompile(`^(/snap/[^/]+|/var/lib/snapd/snap/[^/]+)/x?\d+/`)
)

// GeneralizePath turns a version-specific path into a pattern that still
// matches after the app updates itself: /opt/app-1.0.9/app -> /opt/app-*/app,
// and a snap's revision folder (/snap/firefox/4793/…) -> /snap/firefox/*/….
func GeneralizePath(image string) string {
	image = snapRev.ReplaceAllString(image, "$1/*/")
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
	Foreign  func(pid uint32) (string, bool)
	Started  func(pid uint32) int64 // 0 once it's gone
	Verify   func(path string) provenance.Result
	RootOnly func(path string) bool
	Environ  func(pid uint32) []string // NAME=value
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
	Cwd:     procinfo.Cwd,
	Stdin:   procinfo.Stdin,
	TTY:     procinfo.TTY,
	Foreign: procinfo.ForeignCode,
	Started: func(pid uint32) int64 {
		t, _ := procinfo.CreateTime(pid)
		return t
	},
	Verify: provenance.Verify,
	Environ: func(pid uint32) []string {
		b, err := os.ReadFile("/proc/" + strconv.Itoa(int(pid)) + "/environ")
		if err != nil {
			return nil
		}
		return strings.Split(strings.TrimRight(string(b), "\x00"), "\x00")
	},
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
	scriptOK bool   // … which a package owns
	scriptRO bool   // … which at least only root can have put there
	terminal string // the terminal its input comes from, if it's one
	tty      int    // the terminal it's controlled from
	foreign  string // a library in it that nobody vouches for
}

// actsAs is the name a link is a program in its own right under: itself for
// an ordinary program, the script for an interpreter running one that root
// installed. "" for a go-between.
func (l *link) actsAs() string {
	switch {
	case l.kind == kindApp:
		return l.name
	case l.code == codeScript && (l.scriptOK || l.scriptRO):
		return filepath.Base(l.script)
	}
	return ""
}

func inspect(pid uint32, image string) link {
	l := link{pid: pid, image: image, name: filepath.Base(image)}
	l.kind = kinds[l.name]
	l.sig = view.Verify(image)
	l.rootOnly = l.sig.Valid || view.RootOnly(image)
	l.tty = view.TTY(pid)
	if strings.HasPrefix(image, "/proc/") {
		return l // in a container: its libraries and files aren't this system's
	}
	l.foreign, _ = view.Foreign(pid)
	if l.kind != kindShell && l.kind != kindInterp {
		return l
	}
	args := view.Args(pid)
	if len(args) == 0 {
		return l // it has exited: nothing to go by
	}
	var operand string
	if l.kind == kindShell {
		var rc string
		operand, l.code, rc = shellCode(args)
		// A file of commands to run before the first prompt (--rcfile) is a
		// script by another name, unless only root can have written it (an
		// editor's terminal sets one up that way).
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
		l.scriptOK = view.Verify(l.script).Valid
		l.scriptRO = l.scriptOK || view.RootOnly(l.script)
	case codeInput:
		if in := view.Stdin(pid); strings.HasPrefix(in, "/dev/pts/") || strings.HasPrefix(in, "/dev/tty") {
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
	lang := strings.TrimRight(name, "0123456789.")
	if lang == "gmake" {
		lang = "make"
	}
	if lang == "nodejs" {
		lang = "node"
	}
	// Options that take a value as the next argument, per language; preload
	// are those whose value is code that gets loaded: a script by another name.
	var value, preload, given, hidden []string
	// clusters: several one-letter options may be written as one (perl -lne).
	clusters := true
	switch lang {
	case "python", "pypy":
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
			// A cluster of short options (perl -lne, python -Ic): the first one
			// that stands for code decides.
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
	ignored bool // never reported: desktop search, an antivirus scanner
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
	// How it was started, for a rule pinned to a command (see sameStart).
	links []link
	cwd   string
	env   []string
}

// Remember works out who is behind pid now and keeps the answer for a couple
// of minutes. The watcher calls it while pid is held inside its open of a
// bait: a short-lived reader (cat) is gone by the time the engine reports it,
// and nothing can be learned from a process that no longer exists.
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
	links := chain(pid, image)
	o := judge(links, started == 0)
	var cwd string
	var env []string
	if started != 0 {
		cwd = view.Cwd(pid)
		if view.Environ != nil {
			env = view.Environ(pid)
		}
	}
	traceMu.Lock()
	for p, x := range traceCache {
		if time.Since(x.at) > 2*time.Minute {
			delete(traceCache, p)
		}
	}
	traceCache[pid] = traced{started: started, image: image, at: time.Now(), o: o, links: links, cwd: cwd, env: env}
	traceMu.Unlock()
	return o
}

// chain lists pid and the processes that started it, nearest first, up to the
// service manager its session hangs off.
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
		if depth > 0 && managers[l.name] && l.sig.Valid {
			break
		}
		cur = view.Parent(cur)
	}
	return links
}

func vouchNote(l *link) string {
	if l.sig.Valid {
		return "part of the " + l.sig.Signer + " package"
	}
	if l.sig.Error != "" {
		return l.sig.Error
	}
	return "no package owns it"
}

func judge(links []link, gone bool) origin {
	if len(links) == 0 {
		return origin{tier: config.TierWarn, reasons: []string{"ABA couldn't see which program this was"}}
	}
	me := &links[0]
	critical := func(why string) origin {
		return origin{tier: config.TierCritical, reasons: []string{why, vouchNote(me)}}
	}

	// 1. Anything in the chain that nobody vouches for.
	for i := range links {
		l := &links[i]
		by := ""
		if i > 0 {
			by = me.name + " was started by "
		}
		switch {
		case !l.rootOnly && i == 0:
			return critical("program nobody vouches for, running from a folder you can write to (" + filepath.Dir(l.image) + "): typical of stealers")
		case !l.rootOnly:
			return critical(by + l.image + ", a program nobody vouches for in a folder you can write to: what " + me.name + " reads, that program gets")
		case l.foreign != "":
			return critical(by + l.name + ", which is running code from " + l.foreign + ": a library anything running as you could have put there")
		case l.code == codeScript && !l.scriptRO && i == 0:
			return critical(l.name + " is running " + l.script + ", a script nobody vouches for in a folder you can write to: typical of stealers hidden in packages and downloads")
		case l.code == codeScript && !l.scriptRO:
			return critical(by + l.script + " (run by " + l.name + "), a script nobody vouches for in a folder you can write to: what " + me.name + " reads, that script gets")
		case l.code == codeInput && l.terminal == "":
			return critical(by + l.name + " running commands that were piped into it (the \"curl … | sh\" way of installing things): nobody vouches for those")
		}
	}

	// 2. Who asked: the first program in its own right (req), and whether a
	// shell someone types into comes before it (typed).
	var req, typed *link
	last := len(links) - 1 // how far up the chain the read is accounted for
	plain := true          // only tools and shells handed a command so far
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

	// Something on the way that root put there, but that no package owns.
	unowned := ""
	for i := 0; i <= last && unowned == ""; i++ {
		if l := &links[i]; !l.sig.Valid {
			unowned = l.image
		} else if l.code == codeScript && !l.scriptOK {
			unowned = l.script
		}
	}

	var o origin
	switch {
	case me.actsAs() != "":
		// An ordinary program (or a script root installed).
		name := me.actsAs()
		switch {
		case unowned != "":
			o = origin{tier: config.TierWarn, reasons: []string{name + " is in a folder only root can write to, but no package owns it: an administrator installed it by hand", vouchNote(me)}}
		case indexers[name]:
			o = origin{tier: config.TierInfo, ignored: true, sweeps: true, reasons: []string{"built-in: desktop search / antivirus scanner"}}
		case backupTools[name]:
			o = origin{tier: config.TierInfo, sweeps: true, reasons: []string{name + " is a backup or sync tool: reading everything is its job", vouchNote(me)}}
		case fileManagers[name]:
			o = origin{tier: config.TierInfo, sweeps: true, reasons: []string{name + " is a file manager: copying your files is its job", vouchNote(me)}}
		default:
			o = origin{tier: config.TierInfo, reasons: []string{"installed program", vouchNote(me)}}
		}
	case gone && len(links) == 1:
		o = origin{tier: config.TierWarn, reasons: []string{me.name + " reads whatever it's told to, and it had finished before ABA could see what started it", vouchNote(me)}}
	case typed != nil && me.tty != 0:
		o = origin{tier: config.TierWarn, sweeps: true, reasons: []string{
			me.name + " was run from a terminal (" + typed.name + " on " + typed.terminal + "): fine if you typed that yourself, but a script can read your files the same way", vouchNote(me)}}
	case me.code == codeHidden || me.code == codeGiven && me.kind == kindInterp:
		o = origin{tier: config.TierWarn, reasons: []string{me.name + " ran code that isn't in a file ABA can check (a module, or a program given on its command line)", vouchNote(me)}}
	case req == nil:
		o = origin{tier: config.TierWarn, reasons: []string{
			me.name + " was started in the background (by " + by + "), not typed at a terminal: it reads whatever it's told to", vouchNote(me)}}
	case unowned == "" && (backupTools[req.actsAs()] || fileManagers[req.actsAs()]):
		o = origin{tier: config.TierInfo, sweeps: true, reasons: []string{me.name + " was started by " + req.actsAs() + ", a backup tool or file manager: reading everything is its job", vouchNote(req)}}
	case unowned == "" && indexers[req.actsAs()]:
		o = origin{tier: config.TierInfo, ignored: true, sweeps: true, reasons: []string{"built-in: desktop search / antivirus scanner"}}
	default:
		o = origin{tier: config.TierWarn, reasons: []string{
			me.name + " was started by " + req.actsAs() + ", not typed at a terminal: it reads whatever it's told to, so what counts is what told it", vouchNote(me)}}
	}
	if unowned != "" && me.actsAs() == "" {
		o.sweeps, o.ignored = false, false
		if o.tier == config.TierInfo {
			o.tier = config.TierWarn
		}
		o.reasons = append(o.reasons, unowned+" is in a folder only root can write to, but no package owns it")
	}
	return o
}

// byOrigin judges a bait's reader by the chain of processes behind it (see
// the top of this file). On Linux it settles every reader that your own rules
// and the decoy's real app didn't.
func (c *Classifier) byOrigin(image, name string, pid uint32, sig *provenance.Result, sigNote string) (Verdict, bool) {
	o := trace(image, pid)
	return Verdict{Tier: o.tier, Ignored: o.ignored, Builtin: o.ignored, Reasons: o.reasons}, true
}

// sweepsAllowed reports whether this reader may go through many apps' data:
// a backup tool, a file manager, desktop search, or a command typed at a
// terminal.
func (c *Classifier) sweepsAllowed(image string, pid uint32) bool {
	return image != "" && trace(image, pid).sweeps
}
