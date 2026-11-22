package classify

import (
	"testing"

	"github.com/vulnix0x4/a-better-antivirus/internal/config"
)

// A scheduled backup trusted by its exact command, in its folder, with every
// bait: the backup itself goes through; the same words don't, from anything
// else.
func TestTrustedBackupCommand(t *testing.T) {
	backup := []string{"tar", "czf", "/var/backups/home.tgz", "/home/u"}
	cmdline := func(args []string) string { return joinArgs(args) }
	procs := session()
	// cron (5) <- sh -c "…" (6) <- tar (7)
	procs[5] = proc{parent: 1, image: "/usr/sbin/cron", args: []string{"/usr/sbin/cron", "-f"}}
	procs[6] = proc{parent: 5, image: "/usr/bin/dash", args: []string{"/bin/sh", "-c", cmdline(backup)}, cwd: "/home/u"}
	procs[7] = proc{parent: 6, image: "/usr/bin/tar", args: backup, cwd: "/home/u"}
	// A stealer's script running the same words (30, 31), the same words in
	// another folder (40), the same words handed to another program (50).
	procs[30] = proc{parent: 20, image: "/usr/bin/bash", args: []string{"bash", "./evil.sh"}, cwd: "/home/u", stdin: pts, tty: 34819}
	procs[31] = proc{parent: 30, image: "/usr/bin/tar", args: backup, cwd: "/home/u", tty: 34819}
	procs[40] = proc{parent: 6, image: "/usr/bin/tar", args: backup, cwd: "/home/u/.config"}
	procs[50] = proc{parent: 6, image: "/home/u/.local/bin/tar", args: backup, cwd: "/home/u"}
	world(t, procs)
	env := map[uint32][]string{}
	view.Environ = func(pid uint32) []string { return env[pid] }
	ro := view.RootOnly
	view.RootOnly = func(p string) bool { return ro(p) || ro(p+"/") }

	rule := config.IgnoreRule{Path: "/usr/bin/tar", Signer: "pkg", CommandLine: cmdline(backup), Dir: "/home/u"}
	c := &Classifier{Ignore: []config.IgnoreRule{rule}, CommandLine: func(pid uint32) string { return cmdline(procs[pid].args) }}
	check := func(pid uint32, want bool, what string) {
		t.Helper()
		traceCache = map[uint32]traced{}
		img := procs[pid].image
		sig := view.Verify(img)
		v := c.Final(img, pid, Bait{ID: "vivaldi"}, sig)
		if v.ByRule != want || c.SweepExempt(img, pid, &sig) != want {
			t.Errorf("%s: trusted = %v, want %v (%v)", what, v.ByRule, want, v.Reasons)
		}
	}
	check(7, true, "the backup, started by cron")
	check(31, false, "the same words from a script nobody vouches for")
	check(40, false, "the same words in another folder")
	check(50, false, "the same words to another program")
	env[7] = []string{"HOME=/home/u", "TAR_OPTIONS=--to-command=sh"}
	check(7, false, "with TAR_OPTIONS")
	env[7] = []string{"PATH=/home/u/bin:/usr/bin"}
	check(7, false, "with a folder of yours on PATH")
	env[7] = []string{"PATH=/usr/bin:/bin", "LANG=C.UTF-8"}
	check(7, true, "with an ordinary environment")
	procs[7] = proc{parent: 6, image: "/usr/bin/tar", args: []string{"tar", "czf", "/var/backups/HOME.tgz", "/home/u"}, cwd: "/home/u"}
	check(7, false, "with words that differ only in case")
}

func joinArgs(args []string) string {
	out := ""
	for i, a := range args {
		if i > 0 {
			out += " "
		}
		out += a
	}
	return out
}
