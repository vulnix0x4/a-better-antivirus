package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/huh"
	"github.com/spf13/cobra"

	"github.com/vulnix0x4/a-better-antivirus/internal/alerts"
	"github.com/vulnix0x4/a-better-antivirus/internal/baits"
	"github.com/vulnix0x4/a-better-antivirus/internal/classify"
	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/doctor"
	"github.com/vulnix0x4/a-better-antivirus/internal/engine"
	"github.com/vulnix0x4/a-better-antivirus/internal/install"
	"github.com/vulnix0x4/a-better-antivirus/internal/notify"
	"github.com/vulnix0x4/a-better-antivirus/internal/paths"
	"github.com/vulnix0x4/a-better-antivirus/internal/procinfo"
	"github.com/vulnix0x4/a-better-antivirus/internal/respond"
	"github.com/vulnix0x4/a-better-antivirus/internal/svcctl"
	"github.com/vulnix0x4/a-better-antivirus/internal/trust"
	"github.com/vulnix0x4/a-better-antivirus/internal/ui"
)

var timeNow = time.Now

// ---- alerts ----

func alertsCmd() *cobra.Command {
	var all bool
	c := &cobra.Command{
		Use:   "alerts",
		Short: "What touched your baits",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAdmin(); err != nil {
				return err
			}
			limit := 25
			if all {
				limit = 0
			}
			list, err := alerts.List(limit)
			if err != nil {
				return err
			}
			if len(list) == 0 {
				fmt.Println(ui.Dim.Render("No alerts yet. ") + ui.Hint("Try", "aba test"))
				return nil
			}
			fmt.Println(ui.AlertTable(list, ui.Width()))
			fmt.Println("\n" + ui.Hint("Details:", "aba alerts show <id>") + ui.Dim.Render("  (the last part of the ID is enough)"))
			return nil
		},
	}
	c.Flags().BoolVar(&all, "all", false, "show every alert")
	c.AddCommand(&cobra.Command{
		Use:   "show <id>",
		Short: "Everything about one alert",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAdmin(); err != nil {
				return err
			}
			a, err := alerts.Load(args[0])
			if err != nil {
				return err
			}
			fmt.Print(ui.AlertDetail(a))
			return nil
		},
	})
	c.AddCommand(&cobra.Command{
		Use:   "json <id>",
		Short: "Raw alert JSON (for scripts)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAdmin(); err != nil {
				return err
			}
			a, err := alerts.Load(args[0])
			if err != nil {
				return err
			}
			b, _ := json.MarshalIndent(a, "", "  ")
			fmt.Println(string(b))
			return nil
		},
	})
	return c
}

// ---- release / kill / resume ----

func printReport(rep *respond.Report) {
	for _, l := range rep.Lines {
		fmt.Println(ui.Good.Render(ui.IconOK) + " " + l)
	}
	for _, l := range rep.Errors {
		fmt.Println(ui.Bad.Render(ui.IconBad) + " " + l)
	}
	if len(rep.Lines) == 0 && len(rep.Errors) == 0 {
		fmt.Println(ui.Dim.Render("Nothing to undo: no isolation, frozen processes or blocks are active."))
	}
}

func releaseCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "release [alert-id]",
		Short: "Undo everything: reconnect, unfreeze, unblock",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAdmin(); err != nil {
				return err
			}
			id := ""
			if len(args) == 1 {
				a, err := alerts.Load(args[0])
				if err != nil {
					return err
				}
				id = a.ID
			}
			rep, err := respond.Release(id)
			printReport(rep)
			return err
		},
	}
}

func killCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "kill <alert-id>",
		Short: "It's malware: end what an alert froze",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAdmin(); err != nil {
				return err
			}
			rep, err := respond.Kill(args[0])
			printReport(rep)
			return err
		},
	}
}

func resumeCmd() *cobra.Command {
	var ignore bool
	c := &cobra.Command{
		Use:   "resume <alert-id>",
		Short: "Let it run again, without trusting it",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAdmin(); err != nil {
				return err
			}
			a, err := alerts.Load(args[0])
			if err != nil {
				return err
			}
			rep, err := respond.Resume(a.ID)
			printReport(rep)
			if err != nil {
				return err
			}
			if a.Process == nil || a.Process.Image == "" {
				return nil
			}
			rule, why := trust.Rule(a)
			if why != "" {
				if ignore {
					fmt.Println(ui.Dim.Render("Not adding a rule: " + why + "."))
				}
				return nil
			}
			if !ignore && ui.IsTTY() {
				huh.NewConfirm().Title("Trust " + a.ExeName() + " from now on?").
					Description(rule.Path + "\n" + trust.Describe(rule, baitNames())).
					Affirmative("Yes").Negative("No").Value(&ignore).WithTheme(theme()).Run()
			}
			if ignore {
				return addIgnore(rule)
			}
			return nil
		},
	}
	c.Flags().BoolVar(&ignore, "ignore", false, "also add an ignore rule for this program")
	return c
}

// trustCmd is the one-click "it's mine" from an alert: undo anything done to
// the program and stop alerting on it. The rule is as narrow as possible (see
// package trust): only the baits it read, pinned to its publisher, its exact
// file if unsigned, or its exact command line if it's a script host.
func trustCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "trust <alert-id>",
		Short: "It's yours: undo everything, stop alerting about it",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAdmin(); err != nil {
				return err
			}
			a, err := alerts.Load(args[0])
			if err != nil {
				return err
			}
			if a.Process == nil || a.Process.Image == "" {
				return exitf("alert %s has no program to trust", a.ID)
			}
			rep, err := respond.Resume(a.ID)
			printReport(rep)
			if err != nil {
				return err
			}
			rule, why := trust.Rule(a)
			if why != "" {
				alerts.Update(a.ID, func(x *alerts.Alert) {
					x.Status, x.Note = "resolved", "you said it was yours (not trusted permanently)"
				})
				fmt.Println(ui.Warn.Render("Unfrozen this once, not trusted permanently: " + why + "."))
				return nil
			}
			alerts.Update(a.ID, func(x *alerts.Alert) { x.Status, x.Note = "resolved", "you trusted this program" })
			return addIgnore(rule)
		},
	}
}

// baitNames maps bait IDs to their display names (best effort).
func baitNames() map[string]string {
	names := map[string]string{}
	if st, err := config.LoadState(); err == nil {
		for id, b := range st.Baits {
			names[id] = b.Name
		}
	}
	return names
}

// addIgnore saves rules. A rule for a program that already has one widens the
// existing rule's baits instead of adding a duplicate.
func addIgnore(rules ...config.IgnoreRule) error {
	cfg, err := mustConfig()
	if err != nil {
		return err
	}
	names := baitNames()
	for _, r := range rules {
		merged := false
		for i, x := range cfg.Ignore {
			if !x.SameProgram(r) {
				continue
			}
			merged = true
			if r.Tricks {
				cfg.Ignore[i].Tricks = true
			}
			switch {
			case len(x.Baits) == 0:
			case len(r.Baits) == 0:
				cfg.Ignore[i].Baits = nil
			default:
				for _, b := range r.Baits {
					if !x.CoversBait(b) {
						cfg.Ignore[i].Baits = append(cfg.Ignore[i].Baits, b)
					}
				}
			}
			fmt.Println(ui.Good.Render(ui.IconOK) + " trusting " + r.Path + ui.Dim.Render(" ("+trust.Describe(cfg.Ignore[i], names)+")"))
			break
		}
		if !merged {
			cfg.Ignore = append(cfg.Ignore, r)
			fmt.Println(ui.Good.Render(ui.IconOK) + " trusting " + r.Path + ui.Dim.Render(" ("+trust.Describe(r, names)+")"))
		}
	}
	if err := config.SaveConfig(cfg); err != nil {
		return err
	}
	return install.Reload()
}

// ---- test ----

func testCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "test",
		Short: "Watch it catch a harmless fake stealer",
		Long: "Copies ABA to your Temp folder (where stealers run from) and reads a bait with it.\n" +
			"You'll see the detection, the freeze and the popup. The network is never touched during a test.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAdmin(); err != nil {
				return err
			}
			return runTest()
		},
	}
}

func runTest() error {
	if s, _ := svcctl.Status(); s != svcctl.Running {
		return exitf("the service isn't running (%s); try `aba doctor --fix`", s)
	}
	st, err := config.LoadState()
	if err != nil {
		return err
	}
	target := ""
	for _, pref := range []string{"desktop-passwords", "documents-passwords", "home-passwords"} {
		if bs := st.Baits[pref]; bs != nil && bs.Status != "retired" && len(bs.Files) > 0 {
			target = bs.Files[0].Path
			break
		}
	}
	if target == "" {
		for _, bs := range st.Baits {
			for _, f := range bs.Files {
				if f.Audit && bs.Status != "retired" {
					target = f.Path
				}
			}
		}
	}
	if target == "" {
		return exitf("no active baits to test with")
	}

	self, _ := os.Executable()
	b, err := os.ReadFile(self)
	if err != nil {
		return err
	}

	baitName := filepath.Base(target)
	for _, bs := range st.Baits {
		for _, f := range bs.Files {
			if strings.EqualFold(f.Path, target) {
				baitName = bs.Name
			}
		}
	}
	fmt.Println()
	fmt.Println(ui.Banner("safe test"))
	fmt.Println()
	fmt.Println(" " + ui.Plain.Render("A harmless copy of ABA in your Temp folder is about to read ") + ui.Bold.Render(baitName) + ui.Plain.Render(","))
	fmt.Println(" " + ui.Plain.Render("exactly the way a stealer would. Nothing leaves your PC and your network isn't touched."))
	fmt.Println()
	fmt.Println(" " + ui.Good.Render(ui.IconArr) + ui.Dim.Render(" Running the fake stealer…"))

	reader, err := startTestReader(b, target)
	if err != nil {
		return err
	}
	defer func() {
		reader.Close()
		for i := 0; i < 20; i++ { // the file can linger for a moment after the process ends
			if _, err := os.Stat(reader.Path); err != nil || os.Remove(reader.Path) == nil {
				return
			}
			time.Sleep(250 * time.Millisecond)
		}
	}()
	pid := reader.PID
	tr, _ := json.Marshal(engine.TestRequest{PID: pid, Nonce: strconv.Itoa(int(pid)), Since: time.Now()})
	if err := os.WriteFile(paths.TestFile(), tr, 0o644); err != nil {
		return err
	}
	start := time.Now()
	var found *alerts.Alert
	for time.Since(start) < 20*time.Second && found == nil {
		time.Sleep(200 * time.Millisecond)
		list, _ := alerts.List(5)
		for _, a := range list {
			if a.Test && a.Process != nil && a.Process.PID == pid {
				found = a
			}
		}
	}
	died := !procinfo.Alive(pid, 0)
	reader.Close()
	if found == nil {
		os.Remove(paths.TestFile())
		fmt.Println()
		if died {
			// Not a miss by ABA: there was nothing to catch.
			fmt.Println(" " + ui.Bad.Bold(true).Render(ui.IconBad) + " " + ui.Plain.Render("The fake stealer ("+reader.As+") stopped before it read anything, so there was nothing to catch."))
			return exitf("test could not run")
		}
		fmt.Println(" " + ui.Bad.Bold(true).Render(ui.IconBad) + " " + ui.Plain.Render("ABA didn't react within 20 seconds."))
		fmt.Println("   " + ui.Hint("Find out why with", "aba doctor") + ui.Dim.Render(", and the log at "+paths.LogFile()))
		return exitf("test failed")
	}
	fmt.Println()
	phone := ""
	if sec, err := config.LoadSecrets(); err == nil && sec.Phone.Enabled() {
		phone = sec.Phone.Kind
	}
	fmt.Print(renderTestResult(found, phone))
	return nil
}

func testReaderCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "test-reader <path>",
		Hidden: true,
		Args:   cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			time.Sleep(700 * time.Millisecond) // let `aba test` register our PID
			f, err := os.Open(args[0])
			if err == nil {
				buf := make([]byte, 512)
				f.Read(buf)
				f.Close()
			}
			time.Sleep(60 * time.Second) // stay alive so the freeze is real; ABA kills us
			return nil
		},
	}
}

// ---- doctor ----

func doctorCmd() *cobra.Command {
	var fix bool
	c := &cobra.Command{
		Use:   "doctor",
		Short: "Check that everything is armed (--fix repairs)",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Checking the baits means knowing where they are: admin only.
			if err := requireAdmin(); err != nil {
				return err
			}
			if fix {
				for _, d := range doctor.Fix() {
					fmt.Println(ui.Good.Render(ui.IconOK) + " " + d)
				}
				svcctl.Send(svcctl.CheckNow)
				fmt.Println()
			}
			fmt.Println(ui.Banner("doctor"))
			fmt.Println()
			fixes := 0
			for _, r := range doctor.Run() {
				var icon string
				switch r.Level {
				case doctor.OK:
					icon = ui.Good.Render(ui.IconOK)
				case doctor.Note:
					icon = ui.Info.Render("i")
				case doctor.Warning:
					icon = ui.Warn.Render(ui.IconWarn)
				default:
					icon = ui.Bad.Render(ui.IconBad)
				}
				fmt.Printf(" %s %-17s %s\n", icon, r.Name, r.Detail)
				if r.Fix != "" && r.Level >= doctor.Warning {
					fmt.Println("   " + strings.Repeat(" ", 17) + " " + ui.Hint("→", r.Fix))
					fixes++
				}
			}
			return nil
		},
	}
	c.Flags().BoolVar(&fix, "fix", false, "repair what can be repaired (admin)")
	return c
}

// ---- learn ----

type suggestion struct {
	rule  config.IgnoreRule
	count int
	tier  config.Tier
	last  time.Time
}

func learnCmd() *cobra.Command {
	var stop bool
	var extend int
	c := &cobra.Command{
		Use:   "learn",
		Short: "Trust several of your apps at once",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAdmin(); err != nil {
				return err
			}
			cfg, err := mustConfig()
			if err != nil {
				return err
			}
			if stop || extend > 0 {
				if stop {
					cfg.LearningUntil = time.Time{}
					fmt.Println(ui.Good.Render(ui.IconOK) + " Learning mode ended. ABA now responds as configured (" + cfg.PresetName() + ").")
				} else {
					base := time.Now()
					if cfg.Learning(base) {
						base = cfg.LearningUntil
					}
					cfg.LearningUntil = base.Add(time.Duration(extend) * 24 * time.Hour)
					fmt.Println(ui.Good.Render(ui.IconOK) + " Learning mode until " + cfg.LearningUntil.Format("Mon Jan 2 15:04"))
				}
				if err := config.SaveConfig(cfg); err != nil {
					return err
				}
				return install.Reload()
			}

			list, _ := alerts.List(0)
			byPath := map[string]*suggestion{}
			for _, a := range list {
				if a.Test || a.Process == nil || a.Process.Image == "" || a.Kind != alerts.KindRead {
					continue
				}
				r, why := trust.Rule(a)
				if why != "" {
					continue // can't be trusted permanently (script host without a command line, a sweep…)
				}
				key := strings.ToLower(r.Path + "|" + r.Signer + "|" + r.SHA256 + "|" + r.CommandLine)
				s := byPath[key]
				if s == nil {
					s = &suggestion{rule: r, tier: a.Tier}
					byPath[key] = s
				} else {
					for _, b := range r.Baits {
						if !s.rule.CoversBait(b) {
							s.rule.Baits = append(s.rule.Baits, b)
						}
					}
				}
				if a.Tier.Rank() > s.tier.Rank() {
					s.tier = a.Tier
				}
				s.count++
				if a.Time.After(s.last) {
					s.last = a.Time
				}
			}
			var sugg []*suggestion
			for _, s := range byPath {
				ignored := false
				for _, x := range cfg.Ignore {
					if x.SameProgram(s.rule) {
						covered := len(x.Baits) == 0
						if !covered {
							covered = len(s.rule.Baits) > 0
							for _, b := range s.rule.Baits {
								covered = covered && x.CoversBait(b)
							}
						}
						ignored = ignored || covered
					}
				}
				if !ignored {
					sugg = append(sugg, s)
				}
			}
			sort.Slice(sugg, func(i, j int) bool { return sugg[i].count > sugg[j].count })

			fmt.Println(ui.Banner("learn"))
			fmt.Println()
			if cfg.Learning(time.Now()) {
				fmt.Println(ui.Warn.Render("Learning mode: " + ui.Until(cfg.LearningUntil) + ". Critical threats are stopped; suspicious ones only alert for now."))
			} else {
				fmt.Println(ui.Dim.Render("Learning mode is off. ") + ui.Hint("Turn it back on:", "aba learn --extend 3"))
			}
			fmt.Println()
			if len(sugg) == 0 {
				fmt.Println(ui.Dim.Render("No programs to review: nothing new has touched your baits."))
				return nil
			}
			names := baitNames()
			var opts []huh.Option[int]
			for i, s := range sugg {
				label := fmt.Sprintf("%-9s %3d× %s", s.tier, s.count, ui.TruncateMiddle(s.rule.Path, 70))
				if s.rule.Signer != "" {
					label += ui.Dim.Render("  signed: " + s.rule.Signer)
				} else {
					label += ui.Bad.Render("  UNSIGNED")
				}
				label += ui.Fainter.Render("  (" + trust.Describe(s.rule, names) + ")")
				opts = append(opts, huh.NewOption(label, i).Selected(s.tier == config.TierInfo && s.rule.Signer != ""))
			}
			if !ui.IsTTY() {
				for _, o := range opts {
					fmt.Println("  " + o.Key)
				}
				return nil
			}
			var pick []int
			if err := huh.NewMultiSelect[int]().Title("Ignore which programs from now on?").
				Description("Only ignore software you recognise. Unsigned programs are almost never safe to ignore.").
				Options(opts...).Value(&pick).WithTheme(theme()).Run(); err != nil || len(pick) == 0 {
				fmt.Println(ui.Dim.Render("No changes."))
				return nil
			}
			if err := requireAdmin(); err != nil {
				return err
			}
			var rules []config.IgnoreRule
			for _, i := range pick {
				rules = append(rules, sugg[i].rule)
			}
			return addIgnore(rules...)
		},
	}
	c.Flags().BoolVar(&stop, "stop", false, "end learning mode now")
	c.Flags().IntVar(&extend, "extend", 0, "extend (or restart) learning mode by N days")
	return c
}

// ---- ignore ----

func ignoreCmd() *cobra.Command {
	c := &cobra.Command{Use: "ignore", Short: "Programs you trust to touch baits"}
	c.AddCommand(&cobra.Command{
		Use: "list", Short: "Show ignore rules",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAdmin(); err != nil {
				return err
			}
			cfg, err := mustConfig()
			if err != nil {
				return err
			}
			if len(cfg.Ignore) == 0 {
				fmt.Println(ui.Dim.Render("No ignore rules (Defender and Windows Search are always ignored)."))
				return nil
			}
			names := baitNames()
			for i, r := range cfg.Ignore {
				fmt.Printf(" %2d  %s %s %s\n", i+1, r.Path, ui.Dim.Render("("+trust.Describe(r, names)+")"), ui.Fainter.Render(r.Note))
			}
			return nil
		},
	})
	var signer, note string
	var tricks bool
	add := &cobra.Command{
		Use: "add <path-pattern>", Short: "Ignore a program (globs: * within a folder, ** across folders)",
		Example: `  aba ignore add "C:\Program Files\Backblaze\bztransmit64.exe" --signer Backblaze`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAdmin(); err != nil {
				return err
			}
			if why := tricksRuleProblem(args[0], signer, tricks); why != "" {
				return exitf("%s", why)
			}
			return addIgnore(config.IgnoreRule{Path: args[0], Signer: signer, Note: note, Tricks: tricks})
		},
	}
	add.Flags().StringVar(&signer, "signer", "", "also require this code-signing publisher (recommended)")
	add.Flags().StringVar(&note, "note", "", "a note for yourself")
	add.Flags().BoolVar(&tricks, "allow-tricks", false, "also when it reads baits in ways that look like evasion (some backup and security tools do)")
	c.AddCommand(add)
	c.AddCommand(&cobra.Command{
		Use: "remove <number>", Short: "Remove an ignore rule (number from `ignore list`)", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAdmin(); err != nil {
				return err
			}
			cfg, err := mustConfig()
			if err != nil {
				return err
			}
			n, err := strconv.Atoi(args[0])
			if err != nil || n < 1 || n > len(cfg.Ignore) {
				return exitf("no rule %s", args[0])
			}
			r := cfg.Ignore[n-1]
			cfg.Ignore = append(cfg.Ignore[:n-1], cfg.Ignore[n:]...)
			if err := config.SaveConfig(cfg); err != nil {
				return err
			}
			fmt.Println(ui.Good.Render(ui.IconOK) + " removed " + r.Path)
			return install.Reload()
		},
	})
	return c
}

// tricksRuleProblem says why a rule may not allow evasion-like reads ("" if
// it may). Such a rule is the one thing that lets a program read baits unseen,
// so it has to name a program nothing else can pass for: one with a publisher,
// or one in a folder only administrators can write to.
func tricksRuleProblem(pattern, signer string, tricks bool) string {
	if !tricks || signer != "" {
		return ""
	}
	if (&classify.Classifier{Env: classify.DefaultEnv()}).UserWritable(pattern) {
		return "--allow-tricks needs --signer for a program outside Program Files and Windows: anything could be put at that path later"
	}
	return ""
}

// ---- bait ----

func baitCmd() *cobra.Command {
	c := &cobra.Command{Use: "bait", Short: "See, add or remove baits"}
	c.AddCommand(&cobra.Command{
		Use: "list", Short: "Planted baits and their health",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAdmin(); err != nil {
				return err
			}
			st, err := config.LoadState()
			if err != nil {
				return err
			}
			var ids []string
			for id := range st.Baits {
				ids = append(ids, id)
			}
			sort.Strings(ids)
			for _, id := range ids {
				bs := st.Baits[id]
				status := ui.Good.Render(bs.Status)
				switch bs.Status {
				case "retired":
					status = ui.Dim.Render("retired")
				case "error", "missing":
					status = ui.Bad.Render(bs.Status)
				}
				fmt.Printf(" %-20s %-8s %s\n", id, status, bs.Name)
				for _, f := range bs.Files {
					if f.Audit {
						fmt.Println("   " + ui.Fainter.Render(f.Path))
					}
				}
			}
			fmt.Println("\n" + ui.Hint("View one without tripping it:", "aba bait show <id>"))
			return nil
		},
	})
	c.AddCommand(&cobra.Command{
		Use: "catalog", Short: "Every bait ABA knows and whether it fits this PC",
		RunE: func(cmd *cobra.Command, args []string) error {
			if svcState, _ := svcctl.Status(); svcState != svcctl.NotInstalled {
				if err := requireAdmin(); err != nil { // which ones are planted is admin-only
					return err
				}
			}
			cfg, err := config.LoadConfig()
			u := config.UserInfo{}
			if err == nil {
				u = cfg.User
			} else if u, err = install.CurrentUser(); err != nil {
				return err
			}
			st, _ := config.LoadState()
			ours := map[string]bool{}
			if st != nil {
				for id := range st.Baits {
					ours[id] = true
				}
			}
			for _, cat := range baits.Categories() {
				fmt.Println(ui.Heading(cat))
				for _, a := range baits.Plan(u, ours) {
					if a.Spec.Category != cat {
						continue
					}
					mark := ui.Good.Render(ui.IconOK)
					extra := ui.Dim.Render(a.Spec.Description)
					if ours[a.Spec.ID] {
						mark = ui.Good.Render("●")
					} else if !a.Available {
						mark, extra = ui.Fainter.Render("–"), ui.Fainter.Render(a.Reason)
					}
					fmt.Printf(" %s %-20s %s\n   %s\n", mark, a.Spec.ID, a.Spec.Name, extra)
				}
			}
			fmt.Println("\n" + ui.Dim.Render("● planted  ✓ available  – not suitable here") + "    " + ui.Hint("Change:", "aba configure"))
			return nil
		},
	})
	c.AddCommand(&cobra.Command{
		Use: "show <id>", Short: "Print a bait's contents without opening (tripping) it", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAdmin(); err != nil {
				return err
			}
			st, err := config.LoadState()
			if err != nil {
				return err
			}
			bs := st.Baits[args[0]]
			if bs == nil {
				return exitf("no bait %q (see `aba bait list`)", args[0])
			}
			for _, f := range bs.Files {
				fmt.Println(ui.Heading(f.Path))
				if f.Text != "" {
					fmt.Println(strings.ReplaceAll(f.Text, "\r\n", "\n"))
				} else {
					fmt.Println(ui.Dim.Render(fmt.Sprintf("(binary, %d bytes)", f.Size)))
				}
			}
			return nil
		},
	})
	c.AddCommand(&cobra.Command{
		Use: "add <path | catalog id>", Short: "Turn any file into a bait, or switch on one from the catalog",
		Long: "With a path: that file becomes a bait (created with fake passwords if it doesn't exist).\n" +
			"With an ID from `aba bait catalog` (e.g. chrome-profile): that bait is planted.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAdmin(); err != nil {
				return err
			}
			cfg, err := mustConfig()
			if err != nil {
				return err
			}
			if spec, ok := baits.ByID(args[0]); ok {
				if err := install.AddCatalogBait(cfg, spec.ID); err != nil {
					return err
				}
				d, err := install.SyncBaits(cfg)
				if err != nil {
					return err
				}
				fmt.Println(ui.Good.Render(ui.IconOK) + " planted: " + spec.Name + ". " + ui.Dim.Render(d))
				return install.Reload()
			}
			p, _ := filepath.Abs(args[0])
			id := install.CustomID(p)
			for _, b := range cfg.Baits {
				if b.ID == id {
					return exitf("%s is already a bait", p)
				}
			}
			cfg.Baits = append(cfg.Baits, config.BaitConfig{ID: id, Path: p})
			if err := config.SaveConfig(cfg); err != nil {
				return err
			}
			d, err := install.SyncBaits(cfg)
			if err != nil {
				return err
			}
			fmt.Println(ui.Good.Render(ui.IconOK) + " " + p + " is now a bait (" + id + "). " + ui.Dim.Render(d))
			return install.Reload()
		},
	})
	c.AddCommand(&cobra.Command{
		Use: "rename", Short: "Give the baits new file names, this PC's own",
		Long: "ABA is open source, so the names it gives baits are no secret: every install picks its own from what file\n" +
			"grabbers look for. This picks again: baits whose name changes are removed and planted under the new one.\n" +
			"Baits you added yourself, and fake profiles inside your browsers, stay where they are.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAdmin(); err != nil {
				return err
			}
			cfg, err := mustConfig()
			if err != nil {
				return err
			}
			d, err := install.RenameBaits(cfg)
			if err != nil {
				return err
			}
			fmt.Println(ui.Good.Render(ui.IconOK) + " " + d + ". " + ui.Hint("See them:", "aba bait list"))
			return install.Reload()
		},
	})
	c.AddCommand(&cobra.Command{
		Use: "remove <id>", Short: "Remove a bait", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAdmin(); err != nil {
				return err
			}
			cfg, err := mustConfig()
			if err != nil {
				return err
			}
			var keep []config.BaitConfig
			for _, b := range cfg.Baits {
				if b.ID != args[0] {
					keep = append(keep, b)
				}
			}
			if len(keep) == len(cfg.Baits) {
				// Not selected any more, but still planted: an earlier removal
				// couldn't delete it (see plantBaits). Syncing tries again.
				st, _ := config.LoadState()
				if st == nil || st.Baits[args[0]] == nil {
					return exitf("no bait %q", args[0])
				}
			}
			cfg.Baits = keep
			if err := config.SaveConfig(cfg); err != nil {
				return err
			}
			_, err = install.SyncBaits(cfg)
			// The service re-reads the baits either way: anything the sync did
			// change, it has to know about.
			if rerr := install.Reload(); err == nil {
				err = rerr
			}
			if err != nil {
				return err
			}
			fmt.Println(ui.Good.Render(ui.IconOK) + " removed " + args[0])
			return nil
		},
	})
	return c
}

// ---- phone ----

func phoneCmd() *cobra.Command {
	c := &cobra.Command{Use: "phone", Short: "Test your phone alerts"}
	c.AddCommand(&cobra.Command{
		Use: "test", Short: "Send a test alert to your phone",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAdmin(); err != nil {
				return err
			}
			sec, err := config.LoadSecrets()
			if err != nil {
				return err
			}
			if !sec.Phone.Enabled() {
				return exitf("phone alerts are off; set them up with `aba configure`")
			}
			st, _ := config.LoadState()
			var cache map[string][]string
			if st != nil {
				cache = st.DialCache
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			err = notify.NewSender(sec.Phone, notify.NewDialCache(cache)).Send(ctx, notify.Message{
				Title: "A Better Antivirus test alert", Body: "If you can read this, phone alerts work.", Priority: 3})
			if err != nil {
				return err
			}
			fmt.Println(ui.Good.Render(ui.IconOK) + " Sent via " + sec.Phone.Describe())
			return nil
		},
	})
	return c
}

// ---- notify (runs in the user's session, started by the service) ----

func notifyCmd() *cobra.Command {
	var demo bool
	c := &cobra.Command{
		Use: "notify <alert-id>", Hidden: true, Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if demo {
				// Preview the alert UI with fake data; the buttons do nothing.
				a := demoAlert()
				notify.Toast("ABA: "+a.Title, a.Summary)
				notify.ShowPopup(a, "")
				return nil
			}
			// Started by the service, the alert arrives on standard input (ABA's
			// alert files are for administrators only; this runs as you). Given an
			// ID instead, it's read from the files: that takes admin rights.
			var env notify.Envelope
			if len(args) == 1 {
				a, err := alerts.Load(args[0])
				if err != nil {
					return err
				}
				env.Alert = a
			} else {
				b, err := io.ReadAll(io.LimitReader(os.Stdin, 4<<20))
				if err != nil || json.Unmarshal(b, &env) != nil || (env.Alert == nil && !env.LearningEnded) {
					return exitf("usage: aba notify <alert-id>")
				}
			}
			if env.LearningEnded {
				body := "From now on suspicious programs get the full response, not just critical ones."
				if env.Trusted > 0 {
					body += fmt.Sprintf(" %d program(s) you trusted stay allowed.", env.Trusted)
				}
				body += " Caught something of yours? Click \"It's mine\" on the alert."
				notify.Toast("ABA: learning mode is over", body)
				time.Sleep(3 * time.Second)
				return nil
			}
			a := env.Alert
			notify.Toast("ABA: "+a.Title, a.Summary)
			// Info is just noted. Everything else (learning alerts included) gets
			// the popup, so marking an app as yours is one click.
			quiet := !a.Test && a.Tier == config.TierInfo
			if quiet {
				time.Sleep(3 * time.Second) // let the toast process start before we exit
				return nil
			}
			cli := paths.InstalledCLI()
			if _, err := os.Stat(cli); err != nil {
				cli, _ = os.Executable()
			}
			notify.ShowPopup(a, cli)
			return nil
		},
	}
	c.Flags().BoolVar(&demo, "demo", false, "show a sample alert (nothing is installed or changed)")
	return c
}

func demoAlert() *alerts.Alert {
	a := &alerts.Alert{
		ID: "DEMO", Time: time.Now(), Kind: alerts.KindRead, Tier: config.TierCritical,
		Title:   "Possible stealer: FreeRobux.exe read your bait",
		Summary: `DEMO: unsigned program running from a user-writable folder (C:\Users\you\Downloads): typical of stealers`,
		Baits:   []alerts.BaitHit{{Name: "passwords.txt on the Desktop", Path: `C:\Users\you\Desktop\passwords.txt`, Access: "read", Time: time.Now()}},
		Process: &alerts.Process{PID: 4242, Image: `C:\Users\you\Downloads\FreeRobux.exe`},
	}
	a.AddAction(config.ActionFreeze, nil, "1 process(es) frozen")
	a.AddAction(config.ActionBlockProgram, nil, "")
	return a
}

// ---- instant freeze ----

func instantCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "instant [on|off]",
		Short: "Freeze readers the moment they open a bait",
		Long: "Instant freeze holds every bait with a Windows oplock. When a program opens one, Windows\n" +
			"pauses it inside the open; ABA works out who it is and, if it's suspicious, freezes it\n" +
			"before it reads anything. The normal detection keeps running as a backup.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAdmin(); err != nil {
				return err
			}
			cfg, err := mustConfig()
			if err != nil {
				return err
			}
			if len(args) == 0 {
				state := ui.Bad.Render("off")
				if cfg.InstantFreeze {
					state = ui.Good.Render("on")
				}
				fmt.Println("Instant freeze is " + state + ".  " + ui.Hint("Change:", "aba instant on|off"))
				return nil
			}
			switch strings.ToLower(args[0]) {
			case "on":
				cfg.InstantFreeze = true
			case "off":
				cfg.InstantFreeze = false
			default:
				return exitf("use `aba instant on` or `aba instant off`")
			}
			if err := config.SaveConfig(cfg); err != nil {
				return err
			}
			fmt.Println(ui.Good.Render(ui.IconOK) + " Instant freeze " + args[0])
			return install.Reload()
		},
	}
	return c
}

// testReason is the verdict of the test alert in a few words.
func testReason(a *alerts.Alert) string {
	r := a.Summary
	if len(a.Verdict.Reasons) > 0 {
		r = a.Verdict.Reasons[0]
	}
	if i := strings.Index(r, " ("); i > 0 {
		if j := strings.Index(r[i:], ")"); j > 0 {
			r = r[:i] + r[i+j+1:]
		}
	}
	return r
}

// renderTestResult is what `aba test` prints once ABA has reacted.
func renderTestResult(found *alerts.Alert, phoneKind string) string {
	var b strings.Builder
	rows := [][3]string{{"", "Caught", ui.TierWord(found.Tier) + ui.Dim.Render(": "+testReason(found))}}
	switch {
	case found.Did(config.ActionFreeze) && found.Instant:
		rows = append(rows, [3]string{"", "Frozen", ui.Good.Bold(true).Render(fmt.Sprintf("%d ms", found.LatencyMS)) + ui.Dim.Render(" after it opened the bait, before it could read a byte")})
	case found.Did(config.ActionFreeze):
		rows = append(rows, [3]string{"", "Frozen", ui.Good.Bold(true).Render(fmt.Sprintf("%d ms", found.LatencyMS)) + ui.Dim.Render(" after the read")})
	default:
		rows = append(rows, [3]string{"x", "Not frozen", ui.Dim.Render("see the alert for why")})
	}
	alert := "popup on your desktop"
	if phoneKind != "" {
		alert += ", and your phone (" + phoneKind + ")"
	}
	rows = append(rows, [3]string{"", "Alerted", ui.Dim.Render(alert)}, [3]string{"", "Cleaned up", ui.Dim.Render("the fake stealer was killed and deleted")})
	for _, r := range rows {
		mark := ui.Good.Bold(true).Render(ui.IconOK)
		if r[0] == "x" {
			mark = ui.Bad.Bold(true).Render(ui.IconBad)
		}
		fmt.Fprintf(&b, " %s %s %s\n", mark, ui.Plain.Render(fmt.Sprintf("%-11s", r[1])), r[2])
	}
	b.WriteString("\n " + ui.Plain.Render("That's what happens to a real one.") + ui.Dim.Render(" Everything ABA saw: ") + ui.Code.Render("aba alerts show "+found.ID[strings.LastIndex(found.ID, "-")+1:]) + "\n")
	return b.String()
}
