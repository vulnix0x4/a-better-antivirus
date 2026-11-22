// Package classify decides how suspicious a bait reader is.
//
// The key insight: stealers almost always run as unsigned executables from
// user-writable folders (Temp, AppData, Downloads), or through script hosts and
// "living off the land" binaries. Malware without admin rights cannot write to
// Program Files or Windows, so location + signature is a strong, cheap signal.
//
// The reasoning in this file is the same on every operating system: your own
// rules, the built-in exceptions, the real app reading its own decoy, script
// hosts and runtimes, then where the program lives and who vouches for it.
// What differs is the data it reasons with, in rules_<os>.go: which programs
// are script hosts and runtimes, which folders only administrators can write
// to, what the operating system's own programs look like, how paths and
// command lines are written, and the wording of the final verdict.
package classify

import (
	"path/filepath"
	"strings"

	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/paths"
	"github.com/vulnix0x4/a-better-antivirus/internal/provenance"
)

// Bait is what the classifier needs to know about the touched bait.
type Bait struct {
	ID          string
	OwnerExes   []string // genuine app executables for a decoy (lowercase)
	OwnerSigner string   // substring of the genuine app's signer
	// OwnerDirs are the folders the genuine app installs into. Its name and
	// signature aren't enough to be "the real app": anyone can copy the
	// genuine, signed executable somewhere else and run their own DLL in it.
	// (Program Files always counts. Empty: any location.)
	OwnerDirs []string
	// Unadopted: the bait is a fake profile inside the real app's own data
	// that the app hasn't taken up. The app has no reason to open it, so its
	// read isn't "the owner reading its own data".
	Unadopted bool
	SharedSDK bool // read by a vendor SDK's default credential lookup (see baits.Spec)
}

type Verdict struct {
	Tier       config.Tier `json:"tier"`
	Ignored    bool        `json:"ignored,omitempty"`
	Reasons    []string    `json:"reasons"`
	DecoyOwner bool        `json:"decoyOwner,omitempty"` // the real app this decoy imitates is now installed
	Builtin    bool        `json:"builtin,omitempty"`    // Defender / Windows Search: never escalated
	ByRule     bool        `json:"byRule,omitempty"`     // ignored because of one of your rules
	Swept      []string    `json:"swept,omitempty"`      // bait IDs it went through (a sweep: several apps' data)
	Evasion    bool        `json:"evasion,omitempty"`    // it used a trick meant to dodge detection
}

// ScriptHost reports whether name (an executable's file name) runs code it's
// given: what it does depends on the script, not on the program.
func ScriptHost(name string) bool {
	n := strings.ToLower(filepath.Base(name))
	return lolbins[n] || runtimes[n]
}

func set(xs ...string) map[string]bool {
	m := map[string]bool{}
	for _, x := range xs {
		m[x] = true
	}
	return m
}

// location is where a program lives, as far as who could have put it there.
type location int

const (
	locKernel       location = iota // no file: the kernel itself
	locSystem                       // the operating system's own folder
	locProgramFiles                 // where software gets installed, with administrator rights
	locUserWritable                 // anywhere a program running as you can write
)

// Classifier holds the environment and user rules.
type Classifier struct {
	Env    Env
	Ignore []config.IgnoreRule
	// Optional probes (nil: unknown). Hash returns a file's SHA-256 (for rules
	// pinned to one file), CommandLine a process's command line (for rules
	// pinned to one script), UserSession whether it runs in a user's session.
	Hash        func(image string) string
	CommandLine func(pid uint32) string
	UserSession func(pid uint32) bool
}

// SweepExempt reports whether a reader may go through many apps' baits:
// Defender and Windows Search, or a program you trusted for all baits (e.g. a
// backup tool, with `aba ignore add` or by trusting it from a sweep alert).
// Rules from trusting an app's single alert cover only that bait, so they
// don't exempt it. sig may be nil (not checked yet).
func (c *Classifier) SweepExempt(image string, pid uint32, sig *provenance.Result) bool {
	signer := ""
	if sig != nil {
		signer = sig.Signer
	}
	if c.sweepsAllowed(image, pid) {
		return true
	}
	for _, p := range builtinIgnore {
		if Glob(c.Env.expand(p), image) && (sig == nil || (sig.Valid && osVendor(signer))) {
			return true
		}
	}
	for _, r := range c.Ignore {
		if len(r.Baits) == 0 && c.ruleMatches(r, image, pid, "", signer, sig != nil) {
			return true
		}
	}
	return false
}

// HasTricksRule reports whether any of your rules allows evasion-like reads.
func (c *Classifier) HasTricksRule() bool {
	for _, r := range c.Ignore {
		if r.Tricks {
			return true
		}
	}
	return false
}

// TricksAllowed reports whether one of your rules lets this program read
// baitID in a way that otherwise counts as evasion (config.IgnoreRule.Tricks).
// sig may be nil (not checked yet): rules that name a signer then don't match.
func (c *Classifier) TricksAllowed(image string, pid uint32, baitID string, sig *provenance.Result) bool {
	signer := ""
	if sig != nil {
		signer = sig.Signer
	}
	for _, r := range c.Ignore {
		if r.Tricks && c.ruleMatches(r, image, pid, baitID, signer, sig != nil) {
			return true
		}
	}
	return false
}

// SystemBinary reports whether image lives where the operating system keeps
// its own programs (the Windows folder).
func (c *Classifier) SystemBinary(image string) bool {
	return c.Env.locate(image, 1) == locSystem
}

// Prelim is the instant verdict before the (slower) signature check, assuming
// the binary is unsigned. Used to decide whether to freeze immediately.
func (c *Classifier) Prelim(image string, pid uint32, bait Bait) Verdict {
	return c.decide(image, pid, bait, nil)
}

// Final is the verdict once the signature is known.
func (c *Classifier) Final(image string, pid uint32, bait Bait, sig provenance.Result) Verdict {
	return c.decide(image, pid, bait, &sig)
}

func (c *Classifier) decide(image string, pid uint32, bait Bait, sig *provenance.Result) Verdict {
	name := strings.ToLower(filepath.Base(image))
	valid := sig != nil && sig.Valid
	signer := ""
	if sig != nil {
		signer = sig.Signer
	}

	for _, r := range c.Ignore {
		if c.ruleMatches(r, image, pid, bait.ID, signer, sig != nil) {
			why := "matches your ignore rule"
			if r.Note != "" {
				why += " (" + r.Note + ")"
			}
			return Verdict{Tier: config.TierInfo, Ignored: true, ByRule: true, Reasons: []string{why}}
		}
	}
	for _, p := range builtinIgnore {
		if Glob(c.Env.expand(p), image) && (sig == nil || (valid && osVendor(signer))) {
			return Verdict{Tier: config.TierInfo, Ignored: true, Builtin: true, Reasons: []string{"built-in: antivirus / search indexer"}}
		}
	}

	loc := c.Env.locate(image, pid)
	if loc == locKernel {
		return Verdict{Tier: config.TierWarn, Reasons: []string{"read by the kernel: usually a remote read over a network share (SMB)"}}
	}

	if sig != nil && valid && bait.OwnerSigner != "" && contains(bait.OwnerExes, name) &&
		strings.Contains(strings.ToLower(signer), strings.ToLower(bait.OwnerSigner)) && c.installedAt(image, bait.OwnerDirs) {
		if bait.Unadopted {
			return Verdict{Tier: config.TierWarn, Reasons: []string{
				name + " opened a fake profile that isn't one of its own: the browser only opens the profiles it knows, so this is something else going through its data (an add-on tool, or code running inside it)", sig.String()}}
		}
		// A warning, not a note: you should hear about a bait going away. Running
		// the genuine app is also the one way left to make ABA remove a decoy.
		return Verdict{Tier: config.TierWarn, DecoyOwner: true,
			Reasons: []string{"the genuine " + signer + " app read its own (decoy) data: it looks like you installed it, so this decoy is being retired. If you didn't install it, something is trying to switch that bait off"}}
	}

	// Credential files every SDK reads on startup (~/.aws): a validly signed
	// app doing that is normal. Unsigned programs, script hosts and runtimes
	// still trip it, which is what stealers are.
	if sig != nil && valid && bait.SharedSDK && !lolbins[name] && !runtimes[name] {
		return Verdict{Tier: config.TierInfo, Ignored: true,
			Reasons: []string{"signed program (" + signer + ") doing the standard SDK credential lookup"}}
	}

	sigNote := "signature not checked yet"
	if sig != nil {
		sigNote = sig.String()
	}

	// Where the program's own file says too little about who is behind a
	// read, the operating system's rules judge first: on Linux a shell or a
	// tool like cat is judged by what started it (byOrigin, rules_<os>.go).
	if v, ok := c.byOrigin(image, name, pid, sig, sigNote); ok {
		return v
	}

	if lolbins[name] {
		return Verdict{Tier: config.TierCritical, Reasons: []string{name + " is a script host / built-in tool that malware commonly abuses", sigNote}}
	}
	if runtimes[name] {
		if valid {
			// The runtime is signed, but the program is the script it runs. One
			// sitting where downloads and double-clicked "games" land (a .jar on
			// the Desktop, a .py in Downloads) is what a stealer looks like.
			if c.CommandLine != nil {
				if script, where := DroppedScript(c.CommandLine(pid)); script != "" {
					return Verdict{Tier: config.TierCritical, Reasons: []string{
						name + " is running " + filepath.Base(script) + " from your " + where + ": typical of stealers disguised as games, cheats and tools", sigNote}}
				}
			}
			return Verdict{Tier: config.TierWarn, Reasons: []string{name + " is a scripting runtime: some script read the bait", sigNote}}
		}
		return Verdict{Tier: config.TierCritical, Reasons: []string{"unsigned scripting runtime " + name, sigNote}}
	}

	return c.byLocation(image, name, pid, loc, sig, sigNote)
}

func (c *Classifier) ruleMatches(r config.IgnoreRule, image string, pid uint32, baitID, signer string, sigKnown bool) bool {
	if r.Path == "" && r.Signer == "" && r.SHA256 == "" {
		return false
	}
	if !r.CoversBait(baitID) {
		return false
	}
	if r.Path != "" && !Glob(r.Path, image) {
		return false
	}
	if r.Signer != "" {
		if !sigKnown || !strings.Contains(strings.ToLower(signer), strings.ToLower(r.Signer)) {
			return false
		}
	}
	if r.SHA256 != "" {
		if c.Hash == nil || !strings.EqualFold(c.Hash(image), r.SHA256) {
			return false
		}
	}
	if r.CommandLine != "" {
		if c.CommandLine == nil || !SameCommandLine(c.CommandLine(pid), r.CommandLine) {
			return false
		}
	}
	if (r.CommandLine != "" || r.Dir != "") && !c.sameStart(r, pid) {
		return false
	}
	return true
}

// installedAt reports whether image sits where the genuine app installs:
// under one of dirs, or anywhere in Program Files.
func (c *Classifier) installedAt(image string, dirs []string) bool {
	if len(dirs) == 0 || c.Env.locate(image, 1) == locProgramFiles {
		return true
	}
	for _, d := range dirs {
		if paths.Under(image, d) {
			return true
		}
	}
	return false
}

// UserWritable reports whether image lives outside the folders only
// administrators can write to (Windows, Program Files).
func (c *Classifier) UserWritable(image string) bool {
	return c.Env.locate(image, 1) == locUserWritable
}

// SameCommandLine compares command lines, ignoring outer spaces, and case
// where the operating system's file names do (on Linux a command naming
// /home/u/Notes isn't the one naming /home/u/notes).
func SameCommandLine(a, b string) bool {
	a, b = strings.TrimSpace(a), strings.TrimSpace(b)
	if a == "" {
		return false
	}
	if paths.FoldsCase() {
		return strings.EqualFold(a, b)
	}
	return a == b
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if strings.EqualFold(v, x) {
			return true
		}
	}
	return false
}

func shortDir(image string) string { return filepath.Dir(image) }
