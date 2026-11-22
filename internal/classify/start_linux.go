package classify

// Trusting one exact command, on Linux.
//
// A shell, interpreter or file tool is never trusted as itself: what it does
// is what it's told. So a rule for one is pinned to its exact command line
// (trust.Rule), and a scheduled backup (tar or rsync of your home folder,
// started by cron or a systemd timer) may be trusted that way with every bait.
//
// The same words can still be made to do something else, and sameStart
// refuses those:
//
//   - started by something nobody vouches for: a stealer's own script running
//     your backup command word for word. Only a chain that is clean all the way
//     up (programs packages own, scripts only root can have written, a
//     terminal someone types into) counts. The command itself may run a script
//     of yours: that script is what you trusted.
//   - with settings in its environment that change what the program does
//     (TAR_OPTIONS adds options to tar, RSYNC_RSH chooses the program rsync
//     sends through, LD_PRELOAD loads code into anything).
//   - in another folder, for a rule that names one: `tar czf b.tgz .` packs
//     whatever folder it's run in.
//   - with a library in it that nobody vouches for.

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/vulnix0x4/a-better-antivirus/internal/config"
)

// SweepTrustable reports whether a reader that went through several apps'
// data may be trusted permanently by its exact command line, in the folder
// it ran in: a shell, an interpreter or a tool (a scheduled backup). An
// ordinary program is trusted by its file instead (see trust.Rule).
func SweepTrustable(image string) bool { return ScriptHost(image) }

// behaviourEnv are environment variables that change what a trusted command
// does without changing its words (prefixes end in _).
var behaviourEnv = []string{
	"LD_", "TAR_OPTIONS", "RSYNC_", "GZIP", "XZ_OPT", "XZ_DEFAULTS", "BZIP", "BZIP2", "ZIPOPT", "ZSTD_",
	"BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS", "PROMPT_COMMAND", "PYTHON", "PERL5", "PERLLIB", "NODE_OPTIONS", "NODE_PATH", "RUBYOPT", "RUBYLIB",
	"GIT_SSH", "GIT_CONFIG", "GIT_EXEC_PATH", "SSH_ASKPASS", "CURL_HOME", "WGETRC", "SED_", "AWKPATH", "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS",
}

func changesBehaviour(env []string) string {
	for _, kv := range env {
		name, _, _ := strings.Cut(kv, "=")
		if name == "PATH" {
			// A program found through PATH (tar runs gzip that way) must come
			// from folders only root can write to.
			_, val, _ := strings.Cut(kv, "=")
			for _, d := range strings.Split(val, ":") {
				if d == "" || !strings.HasPrefix(d, "/") || view.RootOnly == nil {
					return "PATH"
				}
				// A folder that isn't there is fine where only root could make it.
				if _, err := os.Lstat(d); err != nil && view.RootOnly(filepath.Dir(d)) {
					continue
				}
				if !view.RootOnly(d) {
					return "PATH"
				}
			}
			continue
		}
		for _, b := range behaviourEnv {
			if name == b || (strings.HasSuffix(b, "_") && strings.HasPrefix(name, b)) || (b == "PYTHON" && strings.HasPrefix(name, "PYTHON")) {
				return name
			}
		}
	}
	return ""
}

// StartLog, when set, is told why a command that matches a rule's words
// wasn't taken as the trusted one (the service log: "why was my backup
// frozen?").
var StartLog func(format string, args ...any)

// sameStart reports whether pid was started the way a rule pinned to a
// command line means (see the top of this file).
func (c *Classifier) sameStart(r config.IgnoreRule, pid uint32) bool {
	why := startDiffers(r, pid)
	if why != "" && StartLog != nil {
		StartLog("pid %d runs the command of a trust rule (%s), but not the trusted way: %s", pid, r.Note, why)
	}
	return why == ""
}

func startDiffers(r config.IgnoreRule, pid uint32) string {
	if pid == 0 {
		return "no process"
	}
	if cwd := view.Cwd(pid); r.Dir != "" && cwd != r.Dir {
		return "it runs in " + cwd + ", not " + r.Dir
	}
	if view.Environ != nil {
		if name := changesBehaviour(view.Environ(pid)); name != "" {
			return "its environment sets " + name
		}
	}
	image := view.Image(pid)
	if image == "" {
		return "it has exited"
	}
	links := chain(pid, image)
	if len(links) == 0 {
		return "it has exited"
	}
	if links[0].foreign != "" {
		return "it runs code from " + links[0].foreign
	}
	for i := 1; i < len(links); i++ {
		l := &links[i]
		switch {
		case !l.rootOnly:
			return "it was started by " + l.image + ", which nobody vouches for"
		case l.foreign != "":
			return "it was started by " + l.name + ", which runs code from " + l.foreign
		case l.code == codeScript && !l.scriptRO:
			return "it was started by " + l.script + ", a script nobody vouches for"
		case l.code == codeInput && l.terminal == "":
			return "it was started by " + l.name + " running commands piped into it"
		}
	}
	return ""
}
