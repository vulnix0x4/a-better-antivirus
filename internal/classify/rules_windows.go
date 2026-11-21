package classify

// What severity is judged by on Windows: the programs stealers run as or hide
// in, the folders only administrators can write to, and how Windows writes
// paths and command lines.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/paths"
	"github.com/vulnix0x4/a-better-antivirus/internal/provenance"
)

// systemCritical are the Windows processes ABA never suspends or kills:
// doing so would hang or crash Windows or the desktop.
var systemCritical = set(
	"csrss.exe", "lsass.exe", "wininit.exe", "winlogon.exe", "services.exe", "smss.exe", "svchost.exe",
	"explorer.exe", "dwm.exe", "msmpeng.exe", "fontdrvhost.exe", "lsaiso.exe", "sihost.exe", "ctfmon.exe", "audiodg.exe",
)

// kernelNames are processes without an executable on disk.
var kernelNames = set("system", "registry", "memory compression", "secure system")

// ProtectedProcess reports whether image is one of the Windows processes ABA
// must never freeze. The name alone doesn't count: a stealer calling itself
// svchost.exe in your Temp folder would otherwise be untouchable. It has to be
// the real file, in the folder Windows keeps it in (which only administrators
// can write to).
func (c *Classifier) ProtectedProcess(image string) bool {
	if !strings.Contains(image, `\`) {
		return kernelNames[strings.ToLower(image)]
	}
	name := strings.ToLower(filepath.Base(image))
	if !systemCritical[name] {
		return false
	}
	dir := filepath.Dir(image)
	switch name {
	case "explorer.exe":
		return paths.Same(dir, c.Env.WinDir)
	case "msmpeng.exe":
		return paths.Under(image, filepath.Join(c.Env.ProgramData, `Microsoft\Windows Defender`)) ||
			paths.Under(image, filepath.Join(c.Env.ProgramFiles, "Windows Defender"))
	}
	return paths.Same(dir, filepath.Join(c.Env.WinDir, "System32"))
}

var lolbins = set(
	"powershell.exe", "powershell_ise.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
	"mshta.exe", "rundll32.exe", "regsvr32.exe", "msbuild.exe", "installutil.exe", "regasm.exe",
	"regsvcs.exe", "certutil.exe", "bitsadmin.exe", "curl.exe", "tar.exe", "forfiles.exe",
	"cmstp.exe", "wmic.exe", "xcopy.exe", "robocopy.exe", "findstr.exe", "msxsl.exe", "hh.exe",
	"pcalua.exe", "scriptrunner.exe", "msdt.exe", "esentutl.exe", "expand.exe", "makecab.exe",
	// Windows tools that copy, print out or upload whatever file they're given:
	// a stealer that never opens a file itself has one of these do it.
	"extrac32.exe", "replace.exe", "print.exe", "diantz.exe", "certreq.exe", "clip.exe", "sort.exe",
	"ftp.exe", "scp.exe", "sftp.exe", "ssh.exe", "wsl.exe", "bash.exe",
	// Small console tools that loaders hollow out and run inside.
	"more.com", "choice.exe", "mavinject.exe",
	// .NET Framework tools that stealers (RedLine, AgentTesla, Lumma…) hollow
	// out and run inside, so their reads look like a Microsoft-signed program.
	"applaunch.exe", "vbc.exe", "csc.exe", "jsc.exe", "aspnet_compiler.exe", "addinprocess.exe",
	"addinprocess32.exe", "addinutil.exe", "cvtres.exe", "caspol.exe", "ilasm.exe", "ieexec.exe",
)

// windowsReaders are the Windows programs with a real reason to open a file
// in your profile in the background (preview pane). Any other Windows program
// reading a bait is suspicious: malware hides inside them (injection).
var windowsReaders = set("prevhost.exe")

var runtimes = set(
	"python.exe", "pythonw.exe", "py.exe", "pyw.exe", "node.exe", "java.exe", "javaw.exe",
	"ruby.exe", "rubyw.exe", "perl.exe", "php.exe", "bun.exe", "deno.exe", "autoit3.exe",
	"autohotkey.exe", "autohotkey64.exe", "autohotkeyu64.exe", "dotnet.exe", "lua.exe", "tclsh.exe", "wish.exe",
	"autoit3_x64.exe", "luajit.exe", "electron.exe", "nw.exe",
)

// dropZones are where downloaded and double-clicked files land. AppData is left
// out on purpose: tools installed with npm or pip run their scripts from there.
var dropZones = []struct{ seg, name string }{
	{`\desktop\`, "Desktop"},
	{`\downloads\`, "Downloads folder"},
	{`\appdata\local\temp\`, "Temp folder"},
	{`\windows\temp\`, "Temp folder"},
}

// DroppedScript returns the first argument of a runtime's command line that is
// an absolute path in a drop zone (Desktop, Downloads, Temp), and which zone.
func DroppedScript(cmdline string) (path, where string) {
	args := SplitCommandLine(cmdline)
	for _, a := range args[min(1, len(args)):] {
		if len(a) < 3 || !(a[1] == ':' && (a[2] == '\\' || a[2] == '/') || strings.HasPrefix(a, `\\`)) {
			continue
		}
		p := strings.ToLower(strings.ReplaceAll(a, "/", `\`)) + `\`
		for _, z := range dropZones {
			if strings.Contains(p, z.seg) {
				return a, z.name
			}
		}
	}
	return "", ""
}

// SplitCommandLine splits a Windows command line into arguments (double quotes
// group, a backslash before a quote escapes it).
func SplitCommandLine(s string) []string {
	var args []string
	var cur strings.Builder
	inQuote, have := false, false
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case ch == '\\' && i+1 < len(s) && s[i+1] == '"':
			cur.WriteByte('"')
			i++
			have = true
		case ch == '"':
			inQuote = !inQuote
			have = true
		case (ch == ' ' || ch == '\t') && !inQuote:
			if have {
				args = append(args, cur.String())
				cur.Reset()
				have = false
			}
		default:
			cur.WriteByte(ch)
			have = true
		}
	}
	if have {
		args = append(args, cur.String())
	}
	return args
}

// Built-in ignores: real-time AV and the search indexer touch everything.
// Matched on full path (dirs are admin-only), plus a Microsoft signature when known.
var builtinIgnore = []string{
	`%ProgramData%\Microsoft\Windows Defender\Platform\*\MsMpEng.exe`,
	`%ProgramData%\Microsoft\Windows Defender\Platform\*\MpDefenderCoreService.exe`,
	`%ProgramData%\Microsoft\Windows Defender\Platform\*\NisSrv.exe`,
	`%ProgramFiles%\Windows Defender\MsMpEng.exe`,
	`%SystemRoot%\System32\SearchProtocolHost.exe`,
	`%SystemRoot%\System32\SearchIndexer.exe`,
	`%SystemRoot%\System32\SearchFilterHost.exe`,
}

// osVendor reports whether signer is the maker of the operating system.
func osVendor(signer string) bool { return strings.Contains(signer, "Microsoft") }

type Env struct {
	WinDir, WinTemp, ProgramFiles, ProgramFilesX86, ProgramData string
}

func DefaultEnv() Env {
	win := os.Getenv("SystemRoot")
	if win == "" {
		win = `C:\Windows`
	}
	pf := os.Getenv("ProgramW6432")
	if pf == "" {
		pf = os.Getenv("ProgramFiles")
	}
	return Env{
		WinDir:          win,
		WinTemp:         filepath.Join(win, "Temp"),
		ProgramFiles:    pf,
		ProgramFilesX86: os.Getenv("ProgramFiles(x86)"),
		ProgramData:     os.Getenv("ProgramData"),
	}
}

func (e Env) expand(p string) string {
	r := strings.NewReplacer("%ProgramData%", e.ProgramData, "%ProgramFiles%", e.ProgramFiles, "%SystemRoot%", e.WinDir)
	return r.Replace(p)
}

func (e Env) locate(image string, pid uint32) location {
	if pid == 4 || image == "" || strings.EqualFold(image, "System") {
		return locKernel
	}
	switch {
	case paths.Under(image, e.WinTemp):
		return locUserWritable
	case paths.Under(image, e.WinDir):
		return locSystem
	case paths.Under(image, e.ProgramFiles), e.ProgramFilesX86 != "" && paths.Under(image, e.ProgramFilesX86):
		return locProgramFiles
	case paths.Under(image, filepath.Join(e.ProgramData, `Microsoft\Windows Defender\Platform`)):
		return locProgramFiles
	}
	return locUserWritable
}

// byLocation is the verdict for a program that none of the earlier rules
// settled: by where it lives and who signed it.
func (c *Classifier) byLocation(image, name string, pid uint32, loc location, sig *provenance.Result, sigNote string) Verdict {
	valid := sig != nil && sig.Valid
	signer := ""
	if sig != nil {
		signer = sig.Signer
	}
	switch loc {
	case locSystem:
		// Being in the Windows folder proves nothing by itself: a few of its
		// subfolders (Tasks, tracing, spool\drivers\color…) can be written to
		// without admin rights. What Windows ships is signed by Microsoft.
		microsoft := valid && strings.Contains(signer, "Microsoft")
		if microsoft && (windowsReaders[name] || (c.UserSession != nil && !c.UserSession(pid))) {
			return Verdict{Tier: config.TierInfo, Reasons: []string{"Windows component", sigNote}}
		}
		if microsoft {
			return Verdict{Tier: config.TierWarn, Reasons: []string{name + " (part of Windows) has no reason to read app data: fine if you were copying or opening these files yourself, but malware also hides inside Windows programs", sigNote}}
		}
		if valid {
			return Verdict{Tier: config.TierWarn, Reasons: []string{"program inside the Windows folder that isn't from Microsoft", sigNote}}
		}
		if sig == nil {
			return Verdict{Tier: config.TierWarn, Reasons: []string{"program inside the Windows folder", sigNote}}
		}
		return Verdict{Tier: config.TierCritical, Reasons: []string{"unsigned program inside the Windows folder (" + shortDir(image) + "): everything Windows ships is signed, and parts of that folder can be written to without admin rights", sigNote}}
	case locProgramFiles:
		if valid {
			return Verdict{Tier: config.TierInfo, Reasons: []string{"installed program (Program Files)", sigNote}}
		}
		return Verdict{Tier: config.TierWarn, Reasons: []string{"unsigned program in Program Files", sigNote}}
	default:
		if valid {
			return Verdict{Tier: config.TierWarn, Reasons: []string{"signed program running from a user-writable folder", sigNote}}
		}
		return Verdict{Tier: config.TierCritical, Reasons: []string{"unsigned program running from a user-writable folder (" + shortDir(image) + "): typical of stealers", sigNote}}
	}
}

var (
	globMu    sync.Mutex
	globCache = map[string]*regexp.Regexp{}
)

// Glob matches a Windows path pattern case-insensitively: '*' within a path
// segment, '**' across segments, '?' one character.
func Glob(pattern, path string) bool {
	globMu.Lock()
	re, ok := globCache[pattern]
	globMu.Unlock()
	if !ok {
		var b strings.Builder
		b.WriteString("(?i)^")
		p := strings.ReplaceAll(pattern, "/", `\`)
		for i := 0; i < len(p); i++ {
			switch {
			case strings.HasPrefix(p[i:], "**"):
				b.WriteString(`.*`)
				i++
			case p[i] == '*':
				b.WriteString(`[^\\]*`)
			case p[i] == '?':
				b.WriteString(`[^\\]`)
			default:
				b.WriteString(regexp.QuoteMeta(string(p[i])))
			}
		}
		b.WriteString("$")
		re = regexp.MustCompile(b.String())
		globMu.Lock()
		globCache[pattern] = re
		globMu.Unlock()
	}
	return re.MatchString(strings.ReplaceAll(path, "/", `\`))
}

var versionRun = regexp.MustCompile(`\d+(?:[.\-_]\d+)+`)

// GeneralizePath turns version-specific paths into a stable ignore pattern, e.g.
// ...\Discord\app-1.0.9172\Discord.exe -> ...\Discord\app-*\Discord.exe
func GeneralizePath(image string) string {
	segs := strings.Split(image, `\`)
	for i := 0; i < len(segs)-1; i++ { // keep the file name exact
		segs[i] = versionRun.ReplaceAllString(segs[i], "*")
	}
	return strings.Join(segs, `\`)
}

// byOrigin lets an operating system judge a reader by more than its own
// program, ahead of the rules in classify.go. Windows doesn't need to: who
// signed the program settles it.
func (c *Classifier) byOrigin(image, name string, pid uint32, sig *provenance.Result, sigNote string) (Verdict, bool) {
	return Verdict{}, false
}

// sweepsAllowed reports whether the operating system's rules let this reader
// go through many apps' data (besides builtinIgnore and your own rules).
func (c *Classifier) sweepsAllowed(image string, pid uint32) bool { return false }
