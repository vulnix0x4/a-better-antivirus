package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
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
	"github.com/vulnix0x4/a-better-antivirus/internal/respond"
	"github.com/vulnix0x4/a-better-antivirus/internal/service"
	"github.com/vulnix0x4/a-better-antivirus/internal/svcctl"
	"github.com/vulnix0x4/a-better-antivirus/internal/ui"
)

var timeNow = time.Now

// ---- alerts ----

func alertsCmd() *cobra.Command {
	var all bool
	c := &cobra.Command{
		Use:   "alerts",
		Short: "List what touched your baits",
		RunE: func(cmd *cobra.Command, args []string) error {
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
		Short: "Restore the network, unfreeze and unblock (all, or one alert's)",
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
		Short: "Kill the processes frozen by an alert (they stay blocked)",
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
		Short: "It was yours: unfreeze it and restore its internet",
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
			if !ignore && ui.IsTTY() {
				huh.NewConfirm().Title("Ignore " + a.ExeName() + " from now on?").
					Description(ruleFor(a).Path).Affirmative("Yes").Negative("No").Value(&ignore).WithTheme(theme()).Run()
			}
			if ignore {
				return addIgnore(ruleFor(a))
			}
			return nil
		},
	}
	c.Flags().BoolVar(&ignore, "ignore", false, "also add an ignore rule for this program")
	return c
}

func ruleFor(a *alerts.Alert) config.IgnoreRule {
	r := config.IgnoreRule{Path: classify.GeneralizePath(a.Process.Image), Note: "added " + time.Now().Format("2006-01-02")}
	if a.Process.Signature.Valid {
		r.Signer = a.Process.Signature.Signer
	}
	return r
}

func addIgnore(rules ...config.IgnoreRule) error {
	cfg, err := mustConfig()
	if err != nil {
		return err
	}
	for _, r := range rules {
		dup := false
		for _, x := range cfg.Ignore {
			dup = dup || (strings.EqualFold(x.Path, r.Path) && strings.EqualFold(x.Signer, r.Signer))
		}
		if !dup {
			cfg.Ignore = append(cfg.Ignore, r)
			fmt.Println(ui.Good.Render(ui.IconOK) + " ignoring " + r.Path + signerNote(r))
		}
	}
	if err := config.SaveConfig(cfg); err != nil {
		return err
	}
	return install.Reload()
}

func signerNote(r config.IgnoreRule) string {
	if r.Signer == "" {
		return ""
	}
	return ui.Dim.Render(" (signed by " + r.Signer + ")")
}

// ---- test ----

func testCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "test",
		Short: "Safely simulate a stealer and watch ABA catch it",
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
	reader := filepath.Join(os.TempDir(), fmt.Sprintf("aba-test-%d.exe", time.Now().UnixNano()%100000))
	b, err := os.ReadFile(self)
	if err != nil {
		return err
	}
	if err := os.WriteFile(reader, b, 0o755); err != nil {
		return err
	}
	defer func() {
		for i := 0; i < 20; i++ {
			if os.Remove(reader) == nil {
				return
			}
			time.Sleep(250 * time.Millisecond)
		}
	}()

	fmt.Println(ui.Banner("test"))
	fmt.Println()
	fmt.Println(ui.KV([][2]string{
		{"Fake stealer", reader},
		{"Reads bait", target},
		{"Expected", "critical (unsigned program in Temp) → frozen → popup → killed"},
	}))
	fmt.Println()

	cmd := exec.Command(reader, "test-reader", target)
	if err := cmd.Start(); err != nil {
		return err
	}
	pid := uint32(cmd.Process.Pid)
	tr, _ := json.Marshal(engine.TestRequest{PID: pid, Nonce: strconv.Itoa(int(pid)), Since: time.Now()})
	if err := os.WriteFile(paths.TestFile(), tr, 0o644); err != nil {
		cmd.Process.Kill()
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
	cmd.Process.Kill()
	cmd.Wait()
	if found == nil {
		os.Remove(paths.TestFile())
		fmt.Println(ui.Bad.Render(ui.IconBad) + " No detection within 20 seconds.")
		fmt.Println(ui.Hint("Diagnose with", "aba doctor"), ui.Dim.Render("and check "+paths.LogFile()))
		return exitf("test failed")
	}
	fmt.Println(ui.Check(true, "Detected: ") + ui.TierWord(found.Tier) + ui.Dim.Render(" ("+found.Summary+")"))
	if found.Did(config.ActionFreeze) {
		if found.BeforeRead {
			fmt.Println(ui.Check(true, "Frozen while opening the bait, before it read a single byte") + ui.Dim.Render(fmt.Sprintf(" (instant freeze, %d ms after it tried)", found.LatencyMS)))
		} else {
			fmt.Println(ui.Check(true, fmt.Sprintf("Frozen %d ms after the read", found.LatencyMS)) + ui.Dim.Render(fmt.Sprintf(" (Windows delivered the event after %d ms)", found.DeliveryMS)))
		}
	} else {
		fmt.Println(ui.Check(false, "Not frozen") + ui.Dim.Render(" (check the alert for why)"))
	}
	fmt.Println(ui.Check(true, "Desktop alert sent (shows if you're signed in)"))
	fmt.Println(ui.Check(true, "Test process killed and removed"))
	if sec, err := config.LoadSecrets(); err == nil && sec.Phone.Enabled() {
		fmt.Println(ui.Check(true, "Phone alert sent via "+sec.Phone.Describe()))
	}
	fmt.Println("\n" + ui.Hint("Full details:", "aba alerts show "+found.ID))
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
		Short: "Check that everything is armed, and fix what isn't",
		RunE: func(cmd *cobra.Command, args []string) error {
			if fix {
				if err := requireAdmin(); err != nil {
					return err
				}
				for _, d := range doctor.Fix() {
					fmt.Println(ui.Good.Render(ui.IconOK) + " " + d)
				}
				svcctl.Control(service.ControlCheckNow)
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
		Short: "Review what touched baits and ignore legit apps",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := mustConfig()
			if err != nil {
				return err
			}
			if stop || extend > 0 {
				if err := requireAdmin(); err != nil {
					return err
				}
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
				r := ruleFor(a)
				key := strings.ToLower(r.Path + "|" + r.Signer)
				s := byPath[key]
				if s == nil {
					s = &suggestion{rule: r, tier: a.Tier}
					byPath[key] = s
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
					ignored = ignored || (strings.EqualFold(x.Path, s.rule.Path) && strings.EqualFold(x.Signer, s.rule.Signer))
				}
				if !ignored {
					sugg = append(sugg, s)
				}
			}
			sort.Slice(sugg, func(i, j int) bool { return sugg[i].count > sugg[j].count })

			fmt.Println(ui.Banner("learn"))
			fmt.Println()
			if cfg.Learning(time.Now()) {
				fmt.Println(ui.Warn.Render("Learning mode: " + ui.Until(cfg.LearningUntil) + ". Nothing is blocked yet."))
			} else {
				fmt.Println(ui.Dim.Render("Learning mode is off. ") + ui.Hint("Turn it back on:", "aba learn --extend 3"))
			}
			fmt.Println()
			if len(sugg) == 0 {
				fmt.Println(ui.Dim.Render("No programs to review: nothing new has touched your baits."))
				return nil
			}
			var opts []huh.Option[int]
			for i, s := range sugg {
				label := fmt.Sprintf("%-9s %3d× %s", s.tier, s.count, ui.TruncateMiddle(s.rule.Path, 70))
				if s.rule.Signer != "" {
					label += ui.Dim.Render("  signed: " + s.rule.Signer)
				} else {
					label += ui.Bad.Render("  UNSIGNED")
				}
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
	c := &cobra.Command{Use: "ignore", Short: "Manage programs that may touch baits"}
	c.AddCommand(&cobra.Command{
		Use: "list", Short: "Show ignore rules",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := mustConfig()
			if err != nil {
				return err
			}
			if len(cfg.Ignore) == 0 {
				fmt.Println(ui.Dim.Render("No ignore rules (Defender and Windows Search are always ignored)."))
				return nil
			}
			for i, r := range cfg.Ignore {
				fmt.Printf(" %2d  %s%s %s\n", i+1, r.Path, signerNote(r), ui.Fainter.Render(r.Note))
			}
			return nil
		},
	})
	var signer, note string
	add := &cobra.Command{
		Use: "add <path-pattern>", Short: "Ignore a program (globs: * within a folder, ** across folders)",
		Example: `  aba ignore add "C:\Program Files\Backblaze\bztransmit64.exe" --signer Backblaze`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAdmin(); err != nil {
				return err
			}
			return addIgnore(config.IgnoreRule{Path: args[0], Signer: signer, Note: note})
		},
	}
	add.Flags().StringVar(&signer, "signer", "", "also require this code-signing publisher (recommended)")
	add.Flags().StringVar(&note, "note", "", "a note for yourself")
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

// ---- bait ----

func baitCmd() *cobra.Command {
	c := &cobra.Command{Use: "bait", Short: "List, view, add or remove baits"}
	c.AddCommand(&cobra.Command{
		Use: "list", Short: "Planted baits and their health",
		RunE: func(cmd *cobra.Command, args []string) error {
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
		Use: "add <path>", Short: "Turn any file into a bait (created with fake passwords if it doesn't exist)", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAdmin(); err != nil {
				return err
			}
			cfg, err := mustConfig()
			if err != nil {
				return err
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
				return exitf("no bait %q", args[0])
			}
			cfg.Baits = keep
			if err := config.SaveConfig(cfg); err != nil {
				return err
			}
			if _, err := install.SyncBaits(cfg); err != nil {
				return err
			}
			fmt.Println(ui.Good.Render(ui.IconOK) + " removed " + args[0])
			return install.Reload()
		},
	})
	return c
}

// ---- phone ----

func phoneCmd() *cobra.Command {
	c := &cobra.Command{Use: "phone", Short: "Phone alerts"}
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
			if len(args) != 1 {
				return exitf("usage: aba notify <alert-id>")
			}
			a, err := alerts.Load(args[0])
			if err != nil {
				return err
			}
			notify.Toast("ABA: "+a.Title, a.Summary)
			quiet := !a.Test && (a.Tier == config.TierInfo || (a.Learning && a.Tier != config.TierCritical))
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
		Short: "Instant freeze: stop readers before they read a single byte",
		Long: "Instant freeze holds every bait with a Windows oplock. When a program opens one, Windows\n" +
			"pauses it inside the open; ABA works out who it is and, if it's suspicious, freezes it\n" +
			"before it reads anything. The normal detection keeps running as a backup.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
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
			if err := requireAdmin(); err != nil {
				return err
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
