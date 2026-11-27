// Package install puts ABA on the machine (and takes it off again).
// Every step is idempotent, so re-running install reconfigures in place.
//
// The plan (program files, settings, baits, service) is the same on every
// operating system and lives in this file. install_<os>.go has the steps and
// lookups that aren't: who the user is and where their folders are, what has
// to be switched on for bait opens to be noticed, putting `aba` on the PATH,
// and deleting a program that's still running.
package install

import (
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/vulnix0x4/a-better-antivirus/internal/baits"
	"github.com/vulnix0x4/a-better-antivirus/internal/canary"
	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/minertrap"
	"github.com/vulnix0x4/a-better-antivirus/internal/netguard"
	"github.com/vulnix0x4/a-better-antivirus/internal/notify"
	"github.com/vulnix0x4/a-better-antivirus/internal/paths"
	"github.com/vulnix0x4/a-better-antivirus/internal/platform"
	"github.com/vulnix0x4/a-better-antivirus/internal/procinfo"
	"github.com/vulnix0x4/a-better-antivirus/internal/respond"
	"github.com/vulnix0x4/a-better-antivirus/internal/svcctl"
)

// Options chosen in the wizard (or flags).
type Options struct {
	Baits        []string // catalog IDs
	CustomBaits  []string // extra file paths
	Preset       string
	Responses    map[config.Tier][]config.Action // when Preset == "custom"
	LearningDays int
	Phone        config.PhoneConfig
	PhoneMinTier config.Tier
	CanaryEmail  string // non-empty: create canary tokens
	CleanRecent  bool
	KeepLearning bool // reconfigure: don't reset an active learning period
	AutoUpdate   bool // install signed releases automatically
	// ClipboardBait and MinerTrap switch those traps on or off. nil leaves
	// them as they are (off on a first install): nothing switches one on
	// unless someone chose it.
	ClipboardBait *bool
	MinerTrap     *bool
	Version       string // this build's version, shown where the system lists installed programs
}

// Step is one unit of work, shown with a spinner by the UI.
type Step struct {
	Name string
	Run  func() (string, error) // returns an optional detail line
	Soft bool                   // failure is a warning, not fatal
}

// CustomID derives a stable ID for a custom bait path.
func CustomID(path string) string {
	h := sha1.Sum([]byte(strings.ToLower(filepath.Clean(path))))
	return "custom-" + hex.EncodeToString(h[:4])
}

// Steps returns the install plan.
func Steps(o Options) []Step {
	var u config.UserInfo
	var cfg *config.Config
	var sec *config.Secrets
	self, _ := os.Executable()
	warnings := []string{}
	// What phone alerts were set to before, to only send a test when they change.
	var prevPhone config.PhoneConfig
	if old, err := config.LoadSecrets(); err == nil {
		prevPhone = old.Phone
	}

	steps := []Step{
		{Name: "Checking this " + platform.PC, Run: func() (string, error) {
			if !procinfo.SelfElevated() {
				return "", errors.New("installing needs administrator rights")
			}
			var err error
			u, err = CurrentUser()
			if err != nil {
				return "", err
			}
			return "protecting " + u.Name + " · " + u.Profile, nil
		}},
	}
	steps = append(steps, cleanupSteps()...)
	steps = append(steps, []Step{
		{Name: "Stopping the running service", Run: func() (string, error) {
			if st, _ := svcctl.Status(); st == svcctl.NotInstalled {
				return "first install", nil
			}
			return "paused while files are replaced", svcctl.Stop()
		}},
		{Name: "Installing program files", Run: func() (string, error) {
			if err := os.MkdirAll(paths.InstallDir(), 0o755); err != nil {
				return "", err
			}
			for _, dst := range []string{paths.InstalledCLI(), paths.InstalledService()} {
				if paths.Same(self, dst) {
					continue
				}
				if err := CopyFile(self, dst); err != nil {
					return "", fmt.Errorf("%s: %w", dst, err)
				}
			}
			if err := installPools(self); err != nil {
				return "", err
			}
			return paths.InstallDir(), nil
		}},
		{Name: "Locking down the data folder", Run: func() (string, error) {
			// SYSTEM + Administrators only: it lists every bait (see config.LockDataDir).
			return "only admins can read or change it", config.LockDataDir()
		}},
		{Name: "Saving your settings", Run: func() (string, error) {
			old, err := config.LoadConfig()
			if err != nil {
				old = nil
			}
			cfg = config.Default()
			if old != nil {
				*cfg = *old
			}
			// This install's own bait names: chosen once, when the first baits are
			// planted. An install that already has baits keeps the names it has.
			variant, embedded, names := cfg.User.Variant, cfg.User.Embedded, cfg.User.Names
			if variant == "" && len(ourBaits()) == 0 {
				b := make([]byte, 8)
				rand.Read(b)
				variant = hex.EncodeToString(b)
				names = nil // picked for the old variant's names
			}
			cfg.User = u
			cfg.User.Variant, cfg.User.Embedded, cfg.User.Names = variant, embedded, names
			if cfg.InstalledAt.IsZero() {
				cfg.InstalledAt = time.Now()
			}
			if o.Preset == "custom" {
				cfg.Preset, cfg.Responses = "custom", o.Responses
			} else if err := cfg.ApplyPreset(o.Preset); err != nil {
				return "", err
			}
			if !(o.KeepLearning && cfg.Learning(time.Now())) {
				cfg.LearningUntil = time.Time{}
				if o.LearningDays > 0 {
					cfg.LearningUntil = time.Now().Add(time.Duration(o.LearningDays) * 24 * time.Hour)
				}
			}
			if o.PhoneMinTier != "" {
				cfg.PhoneMinTier = o.PhoneMinTier
			}
			cfg.CleanRecent = o.CleanRecent
			cfg.AutoUpdate = o.AutoUpdate
			if o.ClipboardBait != nil {
				cfg.ClipboardBait = *o.ClipboardBait
			}
			if o.MinerTrap != nil {
				cfg.MinerTrap = *o.MinerTrap
			}
			if !minertrap.Supported() {
				cfg.MinerTrap = false
			}
			if !cfg.MinerTrap {
				// The service puts the redirect in place when the trap is on;
				// off, there must be none, service or not. (The service
				// removes it too, and `aba doctor` says if any is left.)
				minertrap.Remove()
			}
			cfg.Version = config.CurrentConfigVersion
			cfg.Baits = nil
			selected := map[string]bool{}
			for _, id := range o.Baits {
				selected[id] = true
			}
			cfg.User.DecoyBrowser = baits.ChooseHost(selected)
			planted := ourBaits()
			for _, a := range baits.Plan(cfg.User, planted) {
				if selected[a.Spec.ID] && a.Available {
					cfg.Baits = append(cfg.Baits, config.BaitConfig{ID: a.Spec.ID})
					placeEmbedded(cfg, a.Spec, planted)
					settleNames(cfg, a.Spec, planted)
				}
			}
			for _, p := range o.CustomBaits {
				p = filepath.Clean(p)
				cfg.Baits = append(cfg.Baits, config.BaitConfig{ID: CustomID(p), Path: p})
			}
			sec, _ = config.LoadSecrets()
			if sec == nil {
				sec = &config.Secrets{}
			}
			sec.Phone = o.Phone
			if err := config.SaveSecrets(sec); err != nil {
				return "", err
			}
			upd := "manual updates"
			if cfg.AutoUpdate {
				upd = "automatic updates"
			}
			return fmt.Sprintf("%s · %d baits · %s%s", cfg.PresetName(), len(cfg.Baits), upd, TrapsSummary(cfg)), config.SaveConfig(cfg)
		}},
	}...)
	steps = append(steps, detectionSteps()...)
	if o.CanaryEmail != "" {
		steps = append(steps, Step{Name: "Creating canary tokens", Soft: true, Run: func() (string, error) {
			cfg.CanaryEnabled = true
			sec.Canary.Email = o.CanaryEmail
			have := map[string]bool{}
			for _, t := range sec.Canary.Tokens {
				have[t.Kind] = true
			}
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			made := 0
			want := []struct{ kind, memo, bait string }{
				{"aws_keys", "A Better Antivirus: someone used the AWS keys from a decoy ~/.aws/credentials file. Treat that " + platform.PC + " as compromised.", "aws"},
				{"web", "A Better Antivirus: someone opened the link from a decoy passwords.txt. Treat that " + platform.PC + " as compromised.", "passwords"},
			}
			for _, w := range want {
				if have[w.kind] {
					continue
				}
				t, err := canary.Create(ctx, w.kind, o.CanaryEmail, w.memo, w.bait)
				if err != nil {
					warnings = append(warnings, err.Error())
					continue
				}
				sec.Canary.Tokens = append(sec.Canary.Tokens, t)
				made++
			}
			if err := config.SaveSecrets(sec); err != nil {
				return "", err
			}
			if err := config.SaveConfig(cfg); err != nil {
				return "", err
			}
			if len(warnings) > 0 {
				return "", errors.New(strings.Join(warnings, "; "))
			}
			return fmt.Sprintf("%d token(s), alerts go to %s", made+len(have), o.CanaryEmail), nil
		}})
	}
	steps = append(steps,
		Step{Name: "Planting baits", Run: func() (string, error) { return plantBaits(cfg, sec) }},
		Step{Name: "Starting the background service", Run: func() (string, error) {
			// Start fresh in the event log: reads made by this installer must not be replayed as alerts.
			config.UpdateState(func(st *config.State) error { st.Bookmark = ""; return nil })
			if err := svcctl.InstallOrUpdate(paths.InstalledService()); err != nil {
				return "", err
			}
			return "\"" + paths.ServiceDisplayName + "\", starts with " + platform.OSName(), svcctl.Start()
		}},
		Step{Name: "Adding aba to your PATH", Soft: true, Run: func() (string, error) { return "", AddToPath(paths.InstallDir()) }},
	)
	steps = append(steps, permissionSteps()...)
	steps = append(steps, appSteps(o.Version)...)
	if o.Phone.Enabled() && o.Phone != prevPhone {
		steps = append(steps, Step{Name: "Sending a test to your phone", Soft: true, Run: func() (string, error) {
			if err := SendTest(o.Phone); err != nil {
				return "", fmt.Errorf("couldn't reach %s: %v (check the settings with `aba configure`, retry with `aba phone test`)", o.Phone.Describe(), err)
			}
			return "sent via " + o.Phone.Describe() + ": check your phone", nil
		}})
	}
	return steps
}

// ClipboardBaitSupported reports whether the clipboard bait works here
// (package clipbait: Windows only for now). The miner trap's is
// minertrap.Supported.
func ClipboardBaitSupported() bool { return runtime.GOOS == "windows" }

// TrapsSummary is " · clippers and miners caught" (or one of them, or
// nothing), for the "Saving your settings" line.
func TrapsSummary(cfg *config.Config) string {
	switch {
	case cfg.ClipboardBait && cfg.MinerTrap:
		return " · clipper and miner traps on"
	case cfg.ClipboardBait:
		return " · clipper trap on"
	case cfg.MinerTrap:
		return " · miner trap on"
	}
	return ""
}

// SendTest sends a test alert through the given phone settings.
func SendTest(p config.PhoneConfig) error {
	var cache map[string][]string
	if st, err := config.LoadState(); err == nil {
		cache = st.DialCache
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return notify.NewSender(p, notify.NewDialCache(cache)).Send(ctx, notify.Message{
		Title: "A Better Antivirus is set up", Body: "Phone alerts work: if something takes the bait on your " + platform.PC + ", you'll hear about it here.", Priority: 3})
}

// ourBaits returns IDs of baits currently in state (so our own decoy folders
// don't count as "the real app is installed").
func ourBaits() map[string]bool {
	m := map[string]bool{}
	if st, err := config.LoadState(); err == nil {
		for id, b := range st.Baits {
			if b.Status != "retired" {
				m[id] = true
			}
		}
	}
	return m
}

// placeEmbedded settles which folder a bait inside a real app gets (one the
// app isn't using), unless it's planted already.
func placeEmbedded(cfg *config.Config, spec baits.Spec, planted map[string]bool) {
	if spec.Inside == nil || (planted[spec.ID] && cfg.User.Embedded[spec.ID] != "") {
		return
	}
	if cfg.User.Embedded == nil {
		cfg.User.Embedded = map[string]string{}
	}
	cfg.User.Embedded[spec.ID] = baits.FreeProfile(spec, cfg.User)
}

// settleNames gives a bait that isn't planted yet file names nothing of yours
// has (see baits.Settle): a file of your own is never taken for a bait.
func settleNames(cfg *config.Config, spec baits.Spec, planted map[string]bool) {
	if !planted[spec.ID] {
		baits.Settle(spec, &cfg.User, nil)
	}
}

// AddCatalogBait switches on one bait from the catalog (`aba bait add
// chrome-profile`) without going through setup again.
func AddCatalogBait(cfg *config.Config, id string) error {
	spec, ok := baits.ByID(id)
	if !ok {
		return fmt.Errorf("no bait %q in the catalog (see `aba bait catalog`)", id)
	}
	selected := map[string]bool{id: true}
	for _, b := range cfg.Baits {
		if b.ID == id {
			return fmt.Errorf("%s is already planted", id)
		}
		selected[b.ID] = true
	}
	planted := ourBaits()
	if cfg.User.DecoyBrowser == "" {
		cfg.User.DecoyBrowser = baits.ChooseHost(selected)
	}
	for _, a := range baits.Plan(cfg.User, planted) {
		if a.Spec.ID != id {
			continue
		}
		if !a.Available {
			return fmt.Errorf("%s doesn't fit this "+platform.PC+": %s", spec.Name, a.Reason)
		}
	}
	placeEmbedded(cfg, spec, planted)
	settleNames(cfg, spec, planted)
	cfg.Baits = append(cfg.Baits, config.BaitConfig{ID: id})
	// (cfg.Version stays as it is: it says which baits setup has offered you,
	// and adding one by hand doesn't mean you've seen the others.)
	return config.SaveConfig(cfg)
}

// RenameBaits gives this install a new set of bait names (see baits: every
// install has its own), removes the baits whose names changed and plants
// them again under the new ones. Baits you added yourself keep their path.
func RenameBaits(cfg *config.Config) (string, error) {
	b := make([]byte, 8)
	rand.Read(b)
	cfg.User.Variant = hex.EncodeToString(b)
	// The new names, kept off files of your own (see baits.Settle). ABA's own
	// baits, still under their old names, aren't in the way.
	cfg.User.Names = nil
	ours := map[string]bool{}
	if st, err := config.LoadState(); err == nil {
		for _, bs := range st.Baits {
			for _, f := range bs.Files {
				ours[paths.Key(f.Path)] = true
			}
		}
	}
	custom := map[string]bool{}
	for _, bc := range cfg.Baits {
		custom[bc.ID] = bc.Path != ""
		if spec, ok := baits.ByID(bc.ID); ok && bc.Path == "" {
			baits.Settle(spec, &cfg.User, ours)
		}
	}
	if err := config.SaveConfig(cfg); err != nil {
		return "", err
	}
	moved := 0
	err := config.UpdateState(func(st *config.State) error {
		// Baits that live inside another one first (see plantBaits).
		for _, dependentsFirst := range []bool{true, false} {
			for id, bs := range st.Baits {
				spec, ok := baits.ByID(id)
				if !ok || custom[id] || bs.Status == "retired" || (len(spec.RequiresAny) > 0) != dependentsFirst || !baits.Moved(bs, spec, cfg.User) {
					continue
				}
				if baits.Remove(bs) != nil {
					continue // stays where it is, and on record: see plantBaits
				}
				delete(st.Baits, id)
				moved++
			}
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	if _, err := SyncBaits(cfg); err != nil {
		return "", err
	}
	return fmt.Sprintf("%d baits renamed", moved), nil
}

// SyncBaits makes the planted baits match cfg.Baits (create new, remove deselected).
func SyncBaits(cfg *config.Config) (string, error) {
	sec, err := config.LoadSecrets()
	if err != nil {
		sec = &config.Secrets{}
	}
	return plantBaits(cfg, sec)
}

func plantBaits(cfg *config.Config, sec *config.Secrets) (string, error) {
	created, removed, n := 0, 0, 0
	var errs []string
	err := config.UpdateState(func(st *config.State) error {
		g := baits.GenFromPersona(st.Persona)
		st.Persona = g.Persona()
		for _, t := range sec.Canary.Tokens {
			g.Canary[t.Kind] = t.Data
		}
		want := map[string]config.BaitConfig{}
		for _, b := range cfg.Baits {
			want[b.ID] = b
		}
		// Remove baits that are no longer selected, and dependents (MetaMask)
		// whose host browser changed. Dependents go first so their files don't
		// keep the host's folders alive.
		host := baits.BrowserUserData(cfg.User, cfg.User.DecoyBrowser)
		drop := func(id string) bool {
			bs := st.Baits[id]
			if _, ok := want[id]; !ok {
				return true
			}
			if spec, ok := baits.ByID(id); ok && len(spec.RequiresAny) > 0 && len(bs.Files) > 0 {
				return !paths.Under(bs.Files[0].Path, host)
			}
			return false
		}
		for _, dependentsFirst := range []bool{true, false} {
			for id, bs := range st.Baits {
				spec, _ := baits.ByID(id)
				if (len(spec.RequiresAny) > 0) != dependentsFirst || !drop(id) {
					continue
				}
				if err := baits.Remove(bs); err != nil {
					// Keep it on record (and watched) rather than leave a decoy
					// nobody knows about: the next change to the baits, or
					// `aba bait remove` again, tries once more.
					errs = append(errs, fmt.Sprintf("couldn't take away bait %s (%v); it stays in place for now, try again in a moment", id, err))
					continue
				}
				delete(st.Baits, id)
				if _, still := want[id]; !still {
					removed++
				}
			}
		}
		// Create new ones (and re-assert existing ones).
		for _, b := range cfg.Baits {
			spec, ok := baits.SpecFor(b)
			if !ok {
				continue
			}
			if old := st.Baits[b.ID]; old != nil {
				if old.Status == "retired" {
					continue // the real app moved in: never plant fake data over it again
				}
				if probs := baits.Check(old); len(probs) > 0 {
					baits.Repair(old, spec, cfg.User, g, probs)
				}
				continue
			}
			if baits.InstalledMarker(spec, cfg.User) != "" {
				continue // installed since the plan was made
			}
			bs, err := baits.Create(spec, cfg.User, g)
			if err != nil {
				errs = append(errs, err.Error())
				if bs != nil && len(bs.Files) == 0 {
					continue
				}
			}
			st.Baits[b.ID] = bs
			created++
		}
		for _, b := range cfg.Baits {
			if bs := st.Baits[b.ID]; bs != nil && bs.Status != "retired" {
				n++
			}
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	if len(errs) > 0 {
		return "", errors.New(strings.Join(errs, "; "))
	}
	out := fmt.Sprintf("%d in place", n)
	if created > 0 && created != n {
		out += fmt.Sprintf(", %d new", created)
	}
	if removed > 0 {
		out += fmt.Sprintf(", %d removed", removed)
	}
	return out, nil
}

// installPools installs the miner trap's list of mining pools that came with
// the program (next to it: ABA-Setup.exe and a release's download put it
// there). Without one an install keeps the list it has, or the service
// fetches its own release's (see minertrap.PoolsFileName).
func installPools(self string) error {
	if !minertrap.Supported() {
		return nil
	}
	src := filepath.Join(filepath.Dir(self), minertrap.PoolsFileName)
	b, err := os.ReadFile(src)
	if errors.Is(err, os.ErrNotExist) || paths.Same(src, minertrap.PoolsFile()) {
		return nil
	}
	if err != nil {
		return err
	}
	if _, err := minertrap.ParsePools(b); err != nil {
		return fmt.Errorf("%s: %w", src, err)
	}
	return CopyFile(src, minertrap.PoolsFile())
}

// CopyFile installs src at dst, moving a running dst out of the way first.
func CopyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".new"
	os.Remove(tmp)
	// A program: executable, where the operating system keeps track of that.
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	// The old binary may be running (e.g. this is `aba install` from PATH);
	// it can be renamed out of the way while it runs (Windows allows that too).
	// Old copies can still be in use (e.g. an alert popup nobody clicked), so
	// each gets a unique name and is deleted now or at the next reboot.
	if olds, _ := filepath.Glob(dst + ".old*"); len(olds) > 0 {
		for _, o := range olds {
			os.Remove(o)
		}
	}
	if _, err := os.Stat(dst); err == nil {
		old := fmt.Sprintf("%s.old-%d", dst, time.Now().UnixNano())
		if err := os.Rename(dst, old); err != nil {
			return err
		}
		scheduleDelete(old)
	}
	return os.Rename(tmp, dst)
}

// ---- Uninstall ----

// UninstallSteps removes ABA. Alerts and logs are kept unless purge.
func UninstallSteps(purge bool) []Step {
	var canaryLinks []string
	steps := []Step{
		{Name: "Stopping and removing the service", Run: func() (string, error) { return "", svcctl.Delete() }},
		{Name: "Removing the miner trap", Run: func() (string, error) {
			n, err := minertrap.Remove()
			if n == 0 && err == nil {
				return "it wasn't on", nil
			}
			return "mining pools' names resolve normally again", err
		}},
		{Name: "Releasing frozen processes and network blocks", Soft: true, Run: func() (string, error) {
			rep, err := respond.Release("")
			if err != nil {
				return "", err
			}
			netguard.RemoveAll()
			return strings.Join(rep.Lines, "; "), nil
		}},
		{Name: "Removing baits", Run: func() (string, error) {
			n := 0
			if s, err := config.LoadSecrets(); err == nil {
				for _, t := range s.Canary.Tokens {
					canaryLinks = append(canaryLinks, t.ManageURL)
				}
			}
			err := config.UpdateState(func(st *config.State) error {
				// Baits that live inside another one (MetaMask inside a fake
				// browser) first: a folder ABA made is only removed once it's
				// empty, so the browser's goes after what's inside it.
				ids := make([]string, 0, len(st.Baits))
				for id := range st.Baits {
					ids = append(ids, id)
				}
				inside := func(id string) bool { s, ok := baits.ByID(id); return ok && len(s.RequiresAny) > 0 }
				sort.SliceStable(ids, func(i, j int) bool { return inside(ids[i]) && !inside(ids[j]) })
				for _, id := range ids {
					baits.Remove(st.Baits[id])
					delete(st.Baits, id)
					n++
				}
				return nil
			})
			return fmt.Sprintf("%d removed", n), err
		}},
	}
	steps = append(steps, restoreSteps()...)
	steps = append(steps, []Step{
		{Name: "Removing from PATH", Soft: true, Run: func() (string, error) { return "", RemoveFromPath(paths.InstallDir()) }},
	}...)
	steps = append(steps, removeAppSteps()...)
	steps = append(steps, []Step{
		{Name: "Deleting program files", Soft: true, Run: deleteProgramFiles},
		{Name: "Cleaning up data", Run: func() (string, error) {
			if purge {
				return "everything deleted", os.RemoveAll(paths.DataDir())
			}
			for _, f := range []string{paths.ConfigFile(), paths.StateFile(), paths.SecretsFile(), paths.TestFile(), paths.ClipboardTestFile(), paths.PublicStatusFile()} {
				os.Remove(f)
			}
			msg := "kept alert history in " + paths.DataDir()
			if len(canaryLinks) > 0 {
				msg += ". Deactivate your canary tokens at: " + strings.Join(canaryLinks, " , ")
			}
			return msg, nil
		}},
	}...)
	return steps
}

// Reload asks the running service to re-read its configuration.
func Reload() error { return svcctl.Send(svcctl.Reload) }
