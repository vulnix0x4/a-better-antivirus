package classify

import (
	"strings"
	"testing"

	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/provenance"
)

// proc is one made-up process.
type proc struct {
	parent uint32
	image  string
	args   []string
	cwd    string
	stdin  string
	tty    int
}

// world replaces the look at real processes with a made-up table. Apple's
// programs are the system's folders; programs under /Applications/Signed and
// in a "Signed" app anywhere carry a Developer ID; everything else is ad hoc.
// /usr, /bin, /System and /Library are root's.
func world(t *testing.T, procs map[uint32]proc) {
	t.Helper()
	old := view
	t.Cleanup(func() { view = old; traceCache = map[uint32]traced{} })
	traceCache = map[uint32]traced{}
	rootOnly := func(p string) bool {
		for _, d := range []string{"/usr/", "/bin/", "/sbin/", "/System/", "/Library/"} {
			if strings.HasPrefix(p, d) {
				return true
			}
		}
		return false
	}
	view = procView{
		Parent: func(pid uint32) uint32 { return procs[pid].parent },
		Image:  func(pid uint32) string { return procs[pid].image },
		Args:   func(pid uint32) []string { return procs[pid].args },
		Cwd:    func(pid uint32) string { return procs[pid].cwd },
		Stdin:  func(pid uint32) string { return procs[pid].stdin },
		TTY:    func(pid uint32) int { return procs[pid].tty },
		Started: func(pid uint32) int64 {
			if _, ok := procs[pid]; ok {
				return int64(pid)
			}
			return 0
		},
		Verify: func(p string) provenance.Result {
			switch {
			case inSystem(p):
				return provenance.Result{Signed: true, Valid: true, Signer: provenance.AppleSigner}
			case strings.Contains(p, "/Signed"):
				return provenance.Result{Signed: true, Valid: true, Signer: "Good Developer (ABCDE12345)"}
			}
			return provenance.Result{Error: "ad-hoc signature (no developer)"}
		},
		RootOnly: rootOnly,
	}
}

const tty = "/dev/ttys003"

// A session: launchd (1) <- Terminal (10) <- interactive zsh (20).
func session() map[uint32]proc {
	return map[uint32]proc{
		1:  {image: "/sbin/launchd"},
		10: {parent: 1, image: "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal"},
		20: {parent: 10, image: "/bin/zsh", args: []string{"-zsh"}, stdin: tty, tty: 0x10000003},
	}
}

func verdict(pid uint32, image string) (Verdict, bool) {
	c := &Classifier{}
	v := c.Final(image, pid, Bait{ID: "x"}, view.Verify(image))
	return v, c.SweepExempt(image, pid, nil)
}

const dl = "/Users/a/Downloads/"

func TestDarwinOrigins(t *testing.T) {
	cases := []struct {
		name    string
		procs   map[uint32]proc // added to session()
		pid     uint32
		tier    config.Tier
		sweeps  bool
		ignored bool
		reason  string // must be in the first reason
	}{
		{name: "ad-hoc program from Downloads",
			procs: map[uint32]proc{30: {parent: 1, image: dl + "FreeGame"}},
			pid:   30, tier: config.TierCritical, reason: "no valid signature"},
		{name: "a stealer's shell one-liner",
			procs: map[uint32]proc{
				30: {parent: 1, image: dl + "FreeGame"},
				31: {parent: 30, image: "/bin/sh", args: []string{"sh", "-c", "cat ~/x"}},
				32: {parent: 31, image: "/bin/cat", args: []string{"cat", "x"}},
			},
			pid: 32, tier: config.TierCritical, reason: dl + "FreeGame"},
		{name: "an AppleScript piped into osascript",
			procs: map[uint32]proc{40: {parent: 1, image: "/usr/bin/osascript", args: []string{"osascript"}, stdin: ""}},
			pid:   40, tier: config.TierCritical, reason: "piped into it"},
		{name: "osascript running a script from Downloads",
			procs: map[uint32]proc{40: {parent: 1, image: "/usr/bin/osascript", args: []string{"osascript", "grab.scpt"}, cwd: "/Users/a/Downloads"}},
			pid:   40, tier: config.TierCritical, reason: "/Users/a/Downloads/grab.scpt"},
		{name: "python running a downloaded game",
			procs: map[uint32]proc{50: {parent: 20, image: "/usr/bin/python3", args: []string{"python3", dl + "game.py"}, stdin: tty, tty: 0x10000003}},
			pid:   50, tier: config.TierCritical, reason: "a script in a folder you can write to"},
		{name: "cat typed at a terminal",
			procs: map[uint32]proc{60: {parent: 20, image: "/bin/cat", args: []string{"cat", "x"}, stdin: tty, tty: 0x10000003}},
			pid:   60, tier: config.TierWarn, sweeps: true, reason: "run from a terminal"},
		{name: "cat started in the background",
			procs: map[uint32]proc{60: {parent: 1, image: "/bin/cat", args: []string{"cat", "x"}}},
			pid:   60, tier: config.TierWarn, reason: "in the background"},
		{name: "osascript given a one-liner by a signed app",
			procs: map[uint32]proc{
				70: {parent: 1, image: "/Applications/Signed.app/Contents/MacOS/Signed"},
				71: {parent: 70, image: "/usr/bin/osascript", args: []string{"osascript", "-e", "tell app \"Finder\" to get name"}},
			},
			pid: 71, tier: config.TierWarn, reason: "isn't in a file"},
		{name: "a signed app in Applications",
			procs: map[uint32]proc{80: {parent: 1, image: "/Applications/Signed.app/Contents/MacOS/Signed"}},
			pid:   80, tier: config.TierInfo, reason: "installed program"},
		{name: "a signed app run from a disk image",
			procs: map[uint32]proc{80: {parent: 1, image: "/Volumes/Installer/Signed.app/Contents/MacOS/Signed"}},
			pid:   80, tier: config.TierWarn, reason: "where downloads land"},
		{name: "Spotlight",
			procs: map[uint32]proc{90: {parent: 1, image: "/System/Library/Frameworks/CoreServices.framework/Frameworks/Metadata.framework/Versions/A/Support/mdworker_shared"}},
			pid:   90, tier: config.TierInfo, sweeps: true, ignored: true, reason: "built-in"},
		{name: "a fake Spotlight worker",
			procs: map[uint32]proc{91: {parent: 1, image: "/Users/a/Library/mdworker_shared"}},
			pid:   91, tier: config.TierCritical},
		{name: "Finder",
			procs: map[uint32]proc{92: {parent: 1, image: "/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder"}},
			pid:   92, tier: config.TierInfo, sweeps: true, reason: "file manager"},
		{name: "an unsigned tool an administrator put in /usr/local",
			procs: map[uint32]proc{93: {parent: 1, image: "/usr/local/bin/sometool"}},
			pid:   93, tier: config.TierWarn, reason: "installed it by hand"},
		{name: "a script inside a signed app",
			procs: map[uint32]proc{
				70: {parent: 1, image: "/Applications/Signed.app/Contents/MacOS/Signed"},
				94: {parent: 70, image: "/bin/sh", args: []string{"sh", "/Applications/Signed.app/Contents/Resources/helper.sh"}},
			},
			pid: 94, tier: config.TierInfo},
		{name: "a shell reading piped commands from a stealer",
			procs: map[uint32]proc{
				95: {parent: 20, image: "/usr/bin/curl", args: []string{"curl", "https://x"}, stdin: tty, tty: 0x10000003},
				96: {parent: 20, image: "/bin/bash", args: []string{"bash"}, stdin: "", tty: 0x10000003},
				97: {parent: 96, image: "/bin/cp", args: []string{"cp", "x", "y"}, tty: 0x10000003},
			},
			pid: 97, tier: config.TierCritical, reason: "piped into it"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			procs := session()
			for k, v := range tc.procs {
				procs[k] = v
			}
			world(t, procs)
			v, sweeps := verdict(tc.pid, procs[tc.pid].image)
			if v.Tier != tc.tier || sweeps != tc.sweeps || v.Ignored != tc.ignored {
				t.Errorf("tier %s sweeps %v ignored %v, want %s %v %v: %q", v.Tier, sweeps, v.Ignored, tc.tier, tc.sweeps, tc.ignored, v.Reasons)
			}
			if tc.reason != "" && (len(v.Reasons) == 0 || !strings.Contains(v.Reasons[0], tc.reason)) {
				t.Errorf("reason %q doesn't say %q", v.Reasons, tc.reason)
			}
		})
	}
}

func TestDarwinProtected(t *testing.T) {
	world(t, session())
	c := &Classifier{}
	if !c.ProtectedProcess("/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder") {
		t.Error("Finder isn't protected")
	}
	if c.ProtectedProcess(dl + "Finder") {
		t.Error("a program that calls itself Finder is protected")
	}
}

func TestDarwinGlob(t *testing.T) {
	if !Glob("/Applications/Foo.app/**", "/applications/foo.app/Contents/MacOS/Foo") {
		t.Error("case")
	}
	if Glob("/Applications/*/Foo", "/Applications/a/b/Foo") {
		t.Error("* crossed a folder")
	}
	if g := GeneralizePath("/Applications/Foo.app/Contents/Versions/1.2.3/Foo"); g != "/Applications/Foo.app/Contents/Versions/*/Foo" {
		t.Error(g)
	}
}
