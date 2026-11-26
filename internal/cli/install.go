package cli

import (
	"fmt"
	"github.com/vulnix0x4/a-better-antivirus/internal/platform"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"

	"github.com/vulnix0x4/a-better-antivirus/internal/baits"
	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/install"
	"github.com/vulnix0x4/a-better-antivirus/internal/minertrap"
	"github.com/vulnix0x4/a-better-antivirus/internal/ui"
)

type installFlags struct {
	yes         bool
	preset      string
	learning    int
	canaryEmail string
	ntfyTopic   string
	baits       []string
	autoUpdate  bool
	keep        bool
	clippers    bool
	miners      bool
	setClippers bool // the flag was given
	setMiners   bool
}

func theme() *huh.Theme { return ui.Theme() }

func installCmd() *cobra.Command {
	var f installFlags
	c := &cobra.Command{
		Use:   "install",
		Short: "Set it up, or repair it",
		Long:  "Installs A Better Antivirus with a guided setup. Run it again any time to repair or change settings.",
		Example: "  aba install\n" +
			"  aba install --yes --preset balanced\n" +
			"  aba install --yes --preset strict --learning 3 --ntfy-topic my-secret-topic\n" +
			"  aba install --yes --auto-update=false\n" +
			"  aba install --yes --clippers --miners\n" +
			"  aba install --yes --keep-settings",
		RunE: func(cmd *cobra.Command, args []string) error {
			f.setClippers, f.setMiners = cmd.Flags().Changed("clippers"), cmd.Flags().Changed("miners")
			if f.setClippers && f.clippers && !install.ClipboardBaitSupported() {
				return exitf("the clipboard bait is %s", platform.ErrUnsupported)
			}
			if f.setMiners && f.miners && !minertrap.Supported() {
				return exitf("the miner trap is %s", platform.ErrUnsupported)
			}
			return runInstall(false, f)
		},
	}
	c.Flags().BoolVarP(&f.yes, "yes", "y", false, "non-interactive: use defaults and flags")
	c.Flags().StringVar(&f.preset, "preset", "balanced", "alert | balanced | strict")
	c.Flags().IntVar(&f.learning, "learning", 3, "learning mode days, 0 = respond fully right away (only changes something with strict)")
	c.Flags().StringVar(&f.canaryEmail, "canary-email", "", "create canary tokens that email this address")
	c.Flags().StringVar(&f.ntfyTopic, "ntfy-topic", "", "send phone alerts to this ntfy.sh topic")
	c.Flags().StringSliceVar(&f.baits, "baits", nil, "bait IDs to plant (default: recommended); see `aba bait catalog`")
	c.Flags().BoolVar(&f.autoUpdate, "auto-update", true, "install new signed releases automatically (--auto-update=false to turn off)")
	c.Flags().BoolVar(&f.clippers, "clippers", false, "detect clippers with the clipboard bait (--clippers=false to turn it off; not given: as it is, off on a first install)")
	c.Flags().BoolVar(&f.miners, "miners", false, "detect hidden crypto miners with the miner trap (--miners=false to turn it off; not given: as it is, off on a first install)")
	c.Flags().BoolVar(&f.keep, "keep-settings", false, "with --yes, when ABA is already installed: repair or upgrade it and keep every setting (the other flags then only count on a first install)")
	return c
}

func configureCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "configure",
		Short: "Change baits, response, phone alerts, updates",
		RunE:  func(cmd *cobra.Command, args []string) error { return runInstall(true, installFlags{}) },
	}
}

func runInstall(reconfigure bool, f installFlags) error {
	if err := requireAdmin(); err != nil {
		return err
	}
	u, err := install.CurrentUser()
	if err != nil {
		return err
	}
	existing, _ := config.LoadConfig()
	ours := map[string]bool{}
	if st, err := config.LoadState(); err == nil {
		for id, b := range st.Baits {
			if b.Status != "retired" {
				ours[id] = true
			}
		}
	}
	plan := baits.Plan(u, ours)

	fmt.Println()
	fmt.Println(ui.Banner("setup"))
	fmt.Println()

	var o install.Options
	if f.yes && f.keep && existing != nil {
		// What "Keep my settings" does in the guided setup, without the questions.
		sec, _ := config.LoadSecrets()
		o = ui.KeepOptions(ui.WizardInput{User: u, Plan: plan, Existing: existing, Secrets: sec})
	} else if f.yes {
		o = install.Options{Preset: f.preset, LearningDays: f.learning, CanaryEmail: f.canaryEmail, CleanRecent: true, PhoneMinTier: config.TierWarn, AutoUpdate: f.autoUpdate}
		// Only what was asked for: a silent install never switches a trap on
		// by itself, and an existing one keeps what it has.
		if f.setClippers {
			o.ClipboardBait = &f.clippers
		}
		if f.setMiners {
			o.MinerTrap = &f.miners
		}
		if f.ntfyTopic != "" {
			o.Phone = config.PhoneConfig{Kind: "ntfy", Ntfy: config.NtfyConfig{Server: "https://ntfy.sh", Topic: f.ntfyTopic}}
		} else if sec, err := config.LoadSecrets(); err == nil {
			o.Phone = sec.Phone
		}
		want := map[string]bool{}
		for _, id := range f.baits {
			want[strings.TrimSpace(id)] = true
		}
		for _, a := range plan {
			if a.Available && ((len(want) == 0 && a.Spec.Default) || want[a.Spec.ID]) {
				o.Baits = append(o.Baits, a.Spec.ID)
			}
		}
		if existing != nil {
			for _, b := range existing.Baits {
				if b.Path != "" {
					o.CustomBaits = append(o.CustomBaits, b.Path)
				}
			}
		}
	} else {
		if !ui.IsTTY() {
			return exitf("no terminal for the interactive setup; use `aba install --yes`")
		}
		sec, _ := config.LoadSecrets()
		var ok bool
		o, ok, err = ui.RunWizard(ui.WizardInput{User: u, Plan: plan, Existing: existing, Secrets: sec, Change: reconfigure})
		if err != nil {
			return err
		}
		if !ok {
			fmt.Println(ui.Dim.Render("Cancelled. Nothing was changed."))
			return nil
		}
	}

	o.Version = Version
	fmt.Println()
	title := "Setting up A Better Antivirus"
	if existing != nil {
		title = "Updating your setup"
	}
	if err := ui.RunSteps(title, install.Steps(o)); err != nil {
		return err
	}
	fmt.Println()
	fmt.Println(doneCard(existing == nil))
	if f.yes || !ui.IsTTY() {
		return nil
	}
	fmt.Println()
	run := true
	if err := huh.NewConfirm().Title("Want to see it catch something?").
		Description("A harmless copy of ABA in your Temp folder reads a bait, the way a stealer would.\n" +
			words.testNothingLeaves).
		Affirmative("Run the safe test").Negative("Not now").Value(&run).WithTheme(theme()).Run(); err != nil || !run {
		fmt.Println(ui.Hint("Any time:", "aba test"))
		return nil
	}
	fmt.Println()
	return runTest()
}

// doneCard is the "you're protected" summary at the end of setup, built from
// what was actually saved.
func doneCard(first bool) string {
	cfg, err := config.LoadConfig()
	if err != nil {
		return ui.Good.Render(ui.IconOK) + " A Better Antivirus is installed."
	}
	st, _ := config.LoadState()
	sec, _ := config.LoadSecrets()
	return renderDoneCard(cfg, st, sec, first)
}

func renderDoneCard(cfg *config.Config, st *config.State, sec *config.Secrets, first bool) string {
	w := min(ui.Width()-2, 84)
	inner := w - 6

	active := 0
	if st != nil {
		for _, b := range st.Baits {
			if b.Status != "retired" {
				active++
			}
		}
	}
	head := "You're protected."
	if !first {
		head = "All set. You're protected."
	}
	rows := [][2]string{
		{"Baits", fmt.Sprintf(words.watchedBy, active)},
		{"Response", cfg.PresetName() + ui.Fainter.Render("  ·  "+responseLine(cfg))},
	}
	if cfg.Learning(timeNow()) && cfg.LearningMatters() {
		rows = append(rows, [2]string{"Learning", ui.Until(cfg.LearningUntil) + ui.Fainter.Render("  ·  critical threats are stopped meanwhile")})
	}
	if sec != nil && sec.Phone.Enabled() {
		rows = append(rows, [2]string{"Phone", sec.Phone.Describe()})
	} else {
		rows = append(rows, [2]string{"Phone", ui.Fainter.Render("off  ·  ") + ui.Code.Render("aba configure")})
	}
	switch {
	case cfg.ClipboardBait && cfg.MinerTrap:
		rows = append(rows, [2]string{"Also catches", "clippers and hidden crypto miners"})
	case cfg.ClipboardBait:
		rows = append(rows, [2]string{"Also catches", "clippers"})
	case cfg.MinerTrap:
		rows = append(rows, [2]string{"Also catches", "hidden crypto miners"})
	}
	if cfg.AutoUpdate {
		rows = append(rows, [2]string{"Updates", "automatic" + ui.Fainter.Render("  ·  signed releases only")})
	} else {
		rows = append(rows, [2]string{"Updates", "manual" + ui.Fainter.Render("  ·  ") + ui.Code.Render("aba update")})
	}

	body := []string{
		ui.Good.Bold(true).Render(ui.IconOK+" ") + ui.Bold.Render(head),
		"",
		ui.KV(rows),
		"",
		ui.Cmd([][2]string{
			{"aba test", "watch it catch a harmless fake stealer"},
			{"aba", "live dashboard: health and alerts"},
			{"aba doctor", "check that everything is armed"},
		}),
		"",
		ui.Callout("Don't open the bait files yourself: that counts as a read. To look at one safely: "+ui.Code.Render("aba bait show <id>"), inner),
	}
	card := lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(ui.Leaf).Padding(1, 2).Width(w)
	return card.Render(strings.Join(body, "\n")) + "\n" + ui.Fainter.Render("  New terminal windows have the aba command on their PATH.")
}

// responseLine says in a few words what happens to a critical reader.
func responseLine(cfg *config.Config) string {
	acts := cfg.Responses[config.TierCritical]
	switch {
	case len(acts) == 0:
		return "alerts only, never acts"
	case config.Has(acts, config.ActionIsolate):
		return "critical: frozen, " + platform.PC + " cut off the network"
	case config.Has(acts, config.ActionKill):
		return "critical: killed"
	case config.Has(acts, config.ActionFreeze) && config.Has(acts, config.ActionBlockProgram):
		return "critical: frozen and cut off the internet"
	case config.Has(acts, config.ActionFreeze):
		return "critical: frozen"
	}
	return "critical: blocked"
}

func uninstallCmd() *cobra.Command {
	var purge, yes bool
	c := &cobra.Command{
		Use:   "uninstall",
		Short: words.uninstallShort,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAdmin(); err != nil {
				return err
			}
			fmt.Println()
			fmt.Println(ui.Banner("uninstall"))
			fmt.Println()
			if !yes && ui.IsTTY() {
				ok := false
				desc := words.uninstallDesc
				if !purge {
					desc += "\nYour alert history is kept (add --purge to delete it too)."
				}
				huh.NewConfirm().Title("Uninstall A Better Antivirus?").Description(desc).Affirmative("Uninstall").Negative("Cancel").Value(&ok).WithTheme(theme()).Run()
				if !ok {
					fmt.Println(ui.Dim.Render("Cancelled. Nothing was changed."))
					return nil
				}
				fmt.Println()
			}
			if err := ui.RunSteps("Removing A Better Antivirus", install.UninstallSteps(purge)); err != nil {
				return err
			}
			fmt.Println("\n" + ui.Good.Render(ui.IconOK) + " " + ui.Bold.Render("A Better Antivirus is uninstalled.") + ui.Dim.Render(words.uninstallDone))
			return nil
		},
	}
	c.Flags().BoolVar(&purge, "purge", false, "also delete alert history and logs")
	c.Flags().BoolVarP(&yes, "yes", "y", false, "don't ask for confirmation")
	return c
}
