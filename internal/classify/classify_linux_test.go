package classify

import (
	"strings"
	"testing"

	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/provenance"
)

// proc is one made-up process.
type proc struct {
	parent  uint32
	image   string
	args    []string
	cwd     string
	stdin   string
	tty     int
	foreign string
}

// world replaces the look at real processes with a made-up table. Files
// under /usr, /bin, /opt and /snap are root's; those under /usr and /snap
// are owned by a package too, except /usr/local.
func world(t *testing.T, procs map[uint32]proc) {
	t.Helper()
	old := view
	t.Cleanup(func() { view = old; traceCache = map[uint32]traced{} })
	traceCache = map[uint32]traced{}
	rootOnly := func(p string) bool {
		for _, d := range []string{"/usr/", "/bin/", "/opt/", "/snap/", "/etc/"} {
			if strings.HasPrefix(p, d) {
				return true
			}
		}
		return false
	}
	view = procView{
		Parent:  func(pid uint32) uint32 { return procs[pid].parent },
		Image:   func(pid uint32) string { return procs[pid].image },
		Args:    func(pid uint32) []string { return procs[pid].args },
		Cwd:     func(pid uint32) string { return procs[pid].cwd },
		Stdin:   func(pid uint32) string { return procs[pid].stdin },
		TTY:     func(pid uint32) int { return procs[pid].tty },
		Foreign: func(pid uint32) (string, bool) { f := procs[pid].foreign; return f, f != "" },
		Started: func(pid uint32) int64 {
			if _, ok := procs[pid]; ok {
				return int64(pid)
			}
			return 0
		},
		Verify: func(p string) provenance.Result {
			if rootOnly(p) && !strings.HasPrefix(p, "/usr/local/") && !strings.HasPrefix(p, "/opt/") && !strings.HasPrefix(p, "/etc/") {
				return provenance.Result{Signed: true, Valid: true, Signer: "pkg"}
			}
			return provenance.Result{Error: "no package owns it"}
		},
		RootOnly: rootOnly,
	}
}

const (
	pts  = "/dev/pts/3"
	pipe = "pipe:[4711]"
)

// A session: systemd (1) <- terminal (10) <- interactive bash (20).
func session() map[uint32]proc {
	return map[uint32]proc{
		1:  {image: "/usr/lib/systemd/systemd"},
		10: {parent: 1, image: "/usr/libexec/gnome-terminal-server", args: []string{"gnome-terminal-server"}},
		20: {parent: 10, image: "/usr/bin/bash", args: []string{"bash"}, stdin: pts, tty: 34819},
	}
}

func verdict(pid uint32, image string) (Verdict, bool) {
	c := &Classifier{}
	v := c.Final(image, pid, Bait{ID: "x"}, view.Verify(image))
	return v, c.SweepExempt(image, pid, nil)
}

func TestLinuxOrigins(t *testing.T) {
	cases := []struct {
		name    string
		procs   map[uint32]proc // added to session()
		pid     uint32
		tier    config.Tier
		sweeps  bool
		ignored bool
		reason  string // must be in the first reason
	}{
		{name: "a program dropped in Downloads",
			procs: map[uint32]proc{30: {parent: 20, image: "/home/u/Downloads/free-game", args: []string{"./free-game"}, tty: 34819}},
			pid:   30, tier: config.TierCritical, reason: "nobody vouches"},
		{name: "cat typed at a terminal",
			procs: map[uint32]proc{30: {parent: 20, image: "/usr/bin/cat", args: []string{"cat", "x"}, tty: 34819}},
			pid:   30, tier: config.TierWarn, sweeps: true, reason: "run from a terminal"},
		{name: "grep through sudo and find, typed",
			procs: map[uint32]proc{
				30: {parent: 20, image: "/usr/bin/sudo", args: []string{"sudo", "find", "/home"}, tty: 34819},
				31: {parent: 30, image: "/usr/bin/find", args: []string{"find", "/home", "-exec", "grep"}, tty: 34819},
				32: {parent: 31, image: "/usr/bin/grep", args: []string{"grep", "x"}, tty: 34819}},
			pid: 32, tier: config.TierWarn, sweeps: true, reason: "run from a terminal"},
		{name: "cat run by a script from the home folder",
			procs: map[uint32]proc{
				30: {parent: 20, image: "/usr/bin/bash", args: []string{"bash", "./evil.sh"}, cwd: "/home/u", stdin: pts, tty: 34819},
				31: {parent: 30, image: "/usr/bin/cat", args: []string{"cat", "x"}, tty: 34819}},
			pid: 31, tier: config.TierCritical, reason: "/home/u/evil.sh"},
		{name: "an npm package's install script",
			procs: map[uint32]proc{
				30: {parent: 20, image: "/usr/bin/node", args: []string{"node", "/usr/lib/node_modules/npm/bin/npm-cli.js", "install"}, cwd: "/home/u/proj", tty: 34819},
				31: {parent: 30, image: "/usr/bin/dash", args: []string{"sh", "-c", "node install.js"}, cwd: "/home/u/proj/node_modules/x", tty: 34819},
				32: {parent: 31, image: "/usr/bin/node", args: []string{"node", "install.js"}, cwd: "/home/u/proj/node_modules/x", tty: 34819}},
			pid: 32, tier: config.TierCritical, reason: "/home/u/proj/node_modules/x/install.js"},
		{name: "curl piped into sh",
			procs: map[uint32]proc{
				30: {parent: 20, image: "/usr/bin/dash", args: []string{"sh"}, stdin: pipe, tty: 34819},
				31: {parent: 30, image: "/usr/bin/cat", args: []string{"cat", "x"}, tty: 34819}},
			pid: 31, tier: config.TierCritical, reason: "piped into it"},
		{name: "a shell on a terminal that a script made for itself",
			procs: map[uint32]proc{
				30: {parent: 20, image: "/usr/bin/python3.12", args: []string{"python3", "/home/u/evil.py"}, tty: 34819},
				31: {parent: 30, image: "/usr/bin/bash", args: []string{"bash", "-i"}, stdin: "/dev/pts/9", tty: 34825},
				32: {parent: 31, image: "/usr/bin/cat", args: []string{"cat", "x"}, tty: 34825}},
			pid: 32, tier: config.TierCritical, reason: "/home/u/evil.py"},
		{name: "a library slipped into a genuine program",
			procs: map[uint32]proc{30: {parent: 20, image: "/usr/bin/cat", args: []string{"cat", "x"}, tty: 34819, foreign: "/home/u/.cache/x.so"}},
			pid:   30, tier: config.TierCritical, reason: "/home/u/.cache/x.so"},
		{name: "an installed program",
			procs: map[uint32]proc{30: {parent: 1, image: "/usr/bin/git", args: []string{"git", "hash-object", "x"}}},
			pid:   30, tier: config.TierInfo, reason: "installed program"},
		{name: "a file manager",
			procs: map[uint32]proc{30: {parent: 1, image: "/usr/bin/nautilus", args: []string{"nautilus"}}},
			pid:   30, tier: config.TierInfo, sweeps: true, reason: "file manager"},
		{name: "desktop search",
			procs: map[uint32]proc{30: {parent: 1, image: "/usr/libexec/tracker-extract-3", args: []string{"tracker-extract-3"}}},
			pid:   30, tier: config.TierInfo, sweeps: true, ignored: true, reason: "built-in"},
		{name: "rsync run by a packaged backup script",
			procs: map[uint32]proc{
				30: {parent: 1, image: "/usr/sbin/cron", args: []string{"cron"}},
				31: {parent: 30, image: "/usr/bin/perl", args: []string{"perl", "/usr/bin/rsnapshot", "daily"}},
				32: {parent: 31, image: "/usr/bin/rsync", args: []string{"rsync", "-a", "/home"}}},
			pid: 32, tier: config.TierInfo, sweeps: true, reason: "backup tool"},
		{name: "tar from a crontab line",
			procs: map[uint32]proc{
				30: {parent: 1, image: "/usr/sbin/cron", args: []string{"cron"}},
				31: {parent: 30, image: "/usr/bin/dash", args: []string{"sh", "-c", "tar czf /b.tgz /home/u"}},
				32: {parent: 31, image: "/usr/bin/tar", args: []string{"tar", "czf", "/b.tgz", "/home/u"}}},
			pid: 32, tier: config.TierWarn, reason: "started by cron"},
		{name: "a tool started straight by the service manager",
			procs: map[uint32]proc{30: {parent: 1, image: "/usr/bin/cat", args: []string{"cat", "x"}}},
			pid:   30, tier: config.TierWarn, reason: "in the background"},
		{name: "a program root installed by hand",
			procs: map[uint32]proc{30: {parent: 20, image: "/usr/local/bin/tool", args: []string{"tool"}, tty: 34819}},
			pid:   30, tier: config.TierWarn, reason: "no package owns it"},
		{name: "python -m, typed",
			procs: map[uint32]proc{30: {parent: 20, image: "/usr/bin/python3.12", args: []string{"python3", "-m", "pip", "install", "x"}, stdin: pts, tty: 34819}},
			pid:   30, tier: config.TierWarn, reason: "isn't in a file"},
		{name: "a packaged python program",
			procs: map[uint32]proc{30: {parent: 1, image: "/usr/bin/python3.12", args: []string{"python3", "/usr/bin/duplicity", "full"}}},
			pid:   30, tier: config.TierInfo, sweeps: true, reason: "backup"},
		{name: "an editor's terminal, with its own start-up file",
			procs: map[uint32]proc{
				11: {parent: 1, image: "/usr/share/code/code", args: []string{"code"}},
				21: {parent: 11, image: "/usr/bin/bash", args: []string{"bash", "--init-file", "/usr/share/code/shell.sh"}, stdin: pts, tty: 34819},
				30: {parent: 21, image: "/usr/bin/cat", args: []string{"cat", "x"}, tty: 34819}},
			pid: 30, tier: config.TierWarn, sweeps: true, reason: "run from a terminal"},
		{name: "a shell with a start-up file from the home folder",
			procs: map[uint32]proc{
				21: {parent: 10, image: "/usr/bin/bash", args: []string{"bash", "--rcfile", "/home/u/x.rc", "-i"}, stdin: pts, tty: 34819},
				30: {parent: 21, image: "/usr/bin/cat", args: []string{"cat", "x"}, tty: 34819}},
			pid: 30, tier: config.TierCritical, reason: "/home/u/x.rc"},
		{name: "started by a program nobody vouches for",
			procs: map[uint32]proc{
				30: {parent: 20, image: "/tmp/.mount_Xy12/app", args: []string{"app"}, tty: 34819},
				31: {parent: 30, image: "/usr/bin/git", args: []string{"git", "hash-object", "x"}, tty: 34819}},
			pid: 31, tier: config.TierCritical, reason: "/tmp/.mount_Xy12/app"},
		{name: "make in a folder of yours",
			procs: map[uint32]proc{
				30: {parent: 20, image: "/usr/bin/make", args: []string{"make"}, cwd: "/home/u/nonexistent-proj", tty: 34819},
				31: {parent: 30, image: "/usr/bin/dash", args: []string{"sh", "-c", "cat x"}, tty: 34819},
				32: {parent: 31, image: "/usr/bin/cat", args: []string{"cat", "x"}, tty: 34819}},
			pid: 32, tier: config.TierCritical, reason: "Makefile"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			procs := session()
			for pid, p := range tc.procs {
				procs[pid] = p
			}
			world(t, procs)
			v, sweeps := verdict(tc.pid, procs[tc.pid].image)
			if v.Tier != tc.tier || sweeps != tc.sweeps || v.Ignored != tc.ignored {
				t.Fatalf("got tier=%s sweeps=%v ignored=%v, want %s %v %v\nreasons: %q", v.Tier, sweeps, v.Ignored, tc.tier, tc.sweeps, tc.ignored, v.Reasons)
			}
			if len(v.Reasons) == 0 || !strings.Contains(v.Reasons[0], tc.reason) {
				t.Fatalf("first reason %q doesn't mention %q", v.Reasons, tc.reason)
			}
		})
	}
}

// A reader that's gone by the time it's judged is judged by what was seen
// while it ran (Remember), and without that, cautiously.
func TestLinuxReaderThatExited(t *testing.T) {
	procs := session()
	procs[30] = proc{parent: 20, image: "/usr/bin/bash", args: []string{"bash", "/home/u/evil.sh"}, tty: 34819}
	procs[31] = proc{parent: 30, image: "/usr/bin/cat", args: []string{"cat", "x"}, tty: 34819}
	world(t, procs)
	Remember(31)
	delete(procs, 31)
	if v, _ := verdict(31, "/usr/bin/cat"); v.Tier != config.TierCritical {
		t.Fatalf("remembered reader: got %s (%q), want critical", v.Tier, v.Reasons)
	}
	if v, sweeps := verdict(77, "/usr/bin/cat"); v.Tier != config.TierWarn || sweeps {
		t.Fatalf("unseen reader: got %s sweeps=%v (%q), want warn, no sweeps", v.Tier, sweeps, v.Reasons)
	}
}

func TestLinuxShellCode(t *testing.T) {
	for _, tc := range []struct {
		args    []string
		operand string
		code    int
	}{
		{[]string{"bash"}, "", codeInput},
		{[]string{"-bash"}, "", codeInput},
		{[]string{"bash", "-l", "-i"}, "", codeInput},
		{[]string{"sh", "-c", "cat x"}, "", codeGiven},
		{[]string{"bash", "-lc", "cat x"}, "", codeGiven},
		{[]string{"bash", "-euo", "pipefail", "x.sh"}, "x.sh", codeScript},
		{[]string{"bash", "-o", "pipefail", "x.sh", "arg"}, "x.sh", codeScript},
		{[]string{"sh", "--", "-odd-name.sh"}, "-odd-name.sh", codeScript},
		{[]string{"zsh", "-s"}, "", codeInput},
	} {
		op, code, _ := shellCode(tc.args)
		if op != tc.operand || code != tc.code {
			t.Errorf("%q: got (%q, %d), want (%q, %d)", tc.args, op, code, tc.operand, tc.code)
		}
	}
}

func TestLinuxInterpCode(t *testing.T) {
	for _, tc := range []struct {
		name    string
		args    []string
		operand string
		code    int
	}{
		{"python3.12", []string{"python3", "x.py", "-c"}, "x.py", codeScript},
		{"python3", []string{"python3", "-u", "-W", "ignore", "x.py"}, "x.py", codeScript},
		{"python3", []string{"python3", "-c", "print(1)"}, "", codeGiven},
		{"python3", []string{"python3", "-Im", "pip"}, "", codeHidden},
		{"python3", []string{"python3"}, "", codeInput},
		{"python3", []string{"python3", "-"}, "", codeInput},
		{"node", []string{"node", "--require", "./hook.js", "app.js"}, "./hook.js", codeScript},
		{"node", []string{"node", "-e", "1"}, "", codeGiven},
		{"node", []string{"node", "--max-old-space-size=4096", "app.js"}, "app.js", codeScript},
		{"perl", []string{"perl", "-lne", "print"}, "", codeGiven},
		{"perl", []string{"perl", "/usr/bin/rsnapshot"}, "/usr/bin/rsnapshot", codeScript},
		{"java", []string{"java", "-cp", "x", "Main"}, "", codeHidden},
		{"java", []string{"java", "-Xmx1g", "-jar", "game.jar"}, "game.jar", codeScript},
		{"ruby3.2", []string{"ruby", "-rjson", "x.rb"}, "x.rb", codeScript},
		{"make", []string{"make", "-C", "/src", "-f", "build.mk"}, "/src/build.mk", codeScript},
	} {
		op, code := interpCode(tc.name, tc.args, "/cwd")
		if op != tc.operand || code != tc.code {
			t.Errorf("%s %q: got (%q, %d), want (%q, %d)", tc.name, tc.args, op, code, tc.operand, tc.code)
		}
	}
}

func TestLinuxGlobAndGeneralize(t *testing.T) {
	for _, tc := range []struct {
		pattern, path string
		want          bool
	}{
		{"/usr/bin/restic", "/usr/bin/restic", true},
		{"/usr/bin/Restic", "/usr/bin/restic", false},
		{"/opt/app-*/app", "/opt/app-1.2.3/app", true},
		{"/opt/*/app", "/opt/a/b/app", false},
		{"/opt/**/app", "/opt/a/b/app", true},
		{"/snap/firefox/*/usr/lib/firefox/firefox", "/snap/firefox/4793/usr/lib/firefox/firefox", true},
	} {
		if got := Glob(tc.pattern, tc.path); got != tc.want {
			t.Errorf("Glob(%q, %q) = %v", tc.pattern, tc.path, got)
		}
	}
	for in, want := range map[string]string{
		"/snap/firefox/4793/usr/lib/firefox/firefox": "/snap/firefox/*/usr/lib/firefox/firefox",
		"/opt/app-1.0.9172/app":                      "/opt/app-*/app",
		"/usr/bin/python3.12":                        "/usr/bin/python3.12",
	} {
		if got := GeneralizePath(in); got != want {
			t.Errorf("GeneralizePath(%q) = %q, want %q", in, got, want)
		}
	}
}

// Shells, interpreters and tools are never trusted or quieted as themselves.
func TestLinuxScriptHosts(t *testing.T) {
	for _, n := range []string{"/usr/bin/bash", "/usr/bin/python3.12", "/usr/bin/cat", "/usr/bin/tar", "node"} {
		if !ScriptHost(n) {
			t.Errorf("%s should count as a script host", n)
		}
	}
	if ScriptHost("/usr/bin/nautilus") {
		t.Error("nautilus isn't a script host")
	}
}
