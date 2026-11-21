package classify

// macOS isn't supported yet: this file only lets the rest of ABA build there.
// Everything in it is what a macOS backend has to provide: the data the
// severity logic in classify.go reasons with (see rules_windows.go for a
// filled-in one). Until then every reader that your own rules don't cover
// comes out as "warn", saying that the rules aren't written.

import (
	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/platform"
	"github.com/vulnix0x4/a-better-antivirus/internal/provenance"
)

var (
	// lolbins are script hosts and built-in tools that malware commonly abuses
	// (file names, lowercase): always critical.
	lolbins = set()
	// runtimes run whatever script they're given (python, node, java…): judged
	// by the script, not by who signed the runtime.
	runtimes = set()
	// builtinIgnore are the programs that touch every file and are never
	// reported (the system's own antivirus, its search indexer): path patterns
	// for Glob, after Env.expand.
	builtinIgnore = []string{}
)

// osVendor reports whether signer (provenance.Result.Signer) is the maker of
// the operating system.
func osVendor(signer string) bool { return false }

// Env is where this machine keeps the folders the rules refer to.
type Env struct{}

func DefaultEnv() Env { return Env{} }

// expand fills the placeholders of a builtinIgnore pattern in.
func (e Env) expand(p string) string { return p }

// locate says where a program lives, as far as who could have put it there.
// Not knowing, it gives the least trusted answer.
func (e Env) locate(image string, pid uint32) location { return locUserWritable }

// ProtectedProcess reports whether image is one of the operating system's
// processes that ABA must never freeze, because the desktop or the system
// would go down with it. It has to go by the real file, not the name.
func (c *Classifier) ProtectedProcess(image string) bool { return false }

// byLocation is the verdict for a program that none of the earlier rules in
// decide settled: by where it lives (loc) and who vouches for it (sig, nil
// while that isn't known yet).
func (c *Classifier) byLocation(image, name string, pid uint32, loc location, sig *provenance.Result, sigNote string) Verdict {
	return Verdict{Tier: config.TierWarn, Reasons: []string{"judging how suspicious a program is " + platform.ErrUnsupported.Error(), sigNote}}
}

// DroppedScript returns the first argument of a runtime's command line that is
// a script where downloads and double-clicked files land, and which place.
func DroppedScript(cmdline string) (path, where string) { return "", "" }

// Glob matches a path against an ignore-rule pattern ('*' within a path
// segment, '**' across segments, '?' one character). Not written for macOS
// yet: only the exact path matches.
func Glob(pattern, path string) bool { return pattern == path }

// GeneralizePath turns a version-specific path into a pattern that still
// matches after the app updates itself (…/app-1.0.9172/… -> …/app-*/…).
func GeneralizePath(image string) string { return image }

// byOrigin lets an operating system judge a reader by more than its own
// program, ahead of the rules in classify.go. macOS has no such rules yet.
func (c *Classifier) byOrigin(image, name string, pid uint32, sig *provenance.Result, sigNote string) (Verdict, bool) {
	return Verdict{}, false
}

// sweepsAllowed reports whether the operating system's rules let this reader
// go through many apps' data (besides builtinIgnore and your own rules).
func (c *Classifier) sweepsAllowed(image string, pid uint32) bool { return false }
