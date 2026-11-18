package cli

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/spf13/cobra"

	"github.com/vulnix0x4/a-better-antivirus/internal/baits"
	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/install"
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
}

func theme() *huh.Theme { return ui.Theme() }

func installCmd() *cobra.Command {
	var f installFlags
	c := &cobra.Command{
		Use:   "install",
		Short: "Install A Better Antivirus (interactive setup)",
		Long:  "Installs A Better Antivirus with a guided setup. Run it again any time to change settings.",
		Example: "  aba install\n" +
			"  aba install --yes --preset balanced --learning 3\n" +
			"  aba install --yes --preset strict --ntfy-topic my-secret-topic\n" +
			"  aba install --yes --auto-update=false",
		RunE: func(cmd *cobra.Command, args []string) error { return runInstall(false, f) },
	}
	c.Flags().BoolVarP(&f.yes, "yes", "y", false, "non-interactive: use defaults and flags")
	c.Flags().StringVar(&f.preset, "preset", "balanced", "alert | balanced | strict")
	c.Flags().IntVar(&f.learning, "learning", 3, "learning mode days (0 = protect right away)")
	c.Flags().StringVar(&f.canaryEmail, "canary-email", "", "create canary tokens that email this address")
	c.Flags().StringVar(&f.ntfyTopic, "ntfy-topic", "", "send phone alerts to this ntfy.sh topic")
	c.Flags().StringSliceVar(&f.baits, "baits", nil, "bait IDs to plant (default: recommended); see `aba bait catalog`")
	c.Flags().BoolVar(&f.autoUpdate, "auto-update", true, "install new signed releases automatically (--auto-update=false to turn off)")
	return c
}

func configureCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "configure",
		Short: "Change baits, response, learning, phone alerts or canary tokens",
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

	fmt.Println(ui.Banner("setup"))
	fmt.Println()

	var o install.Options
	if f.yes {
		o = install.Options{Preset: f.preset, LearningDays: f.learning, CanaryEmail: f.canaryEmail, CleanRecent: true, PhoneMinTier: config.TierWarn, AutoUpdate: f.autoUpdate}
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
		o, ok, err = ui.RunWizard(ui.WizardInput{User: u, Plan: plan, Existing: existing, Secrets: sec})
		if err != nil {
			return err
		}
		if !ok {
			fmt.Println(ui.Dim.Render("Cancelled. Nothing was changed."))
			return nil
		}
	}

	fmt.Println()
	if err := ui.RunSteps(install.Steps(o)); err != nil {
		return err
	}
	fmt.Println()
	cfg, _ := config.LoadConfig()
	lines := []string{
		ui.Good.Bold(true).Render("A Better Antivirus is armed."),
		"",
	}
	if cfg != nil && cfg.Learning(timeNow()) && cfg.LearningMatters() {
		lines = append(lines, ui.Warn.Render("Learning mode is on ("+ui.Until(cfg.LearningUntil)+"): critical threats are stopped, suspicious programs only alert. Answer \"It's mine\" on an alert to trust an app."))
		lines = append(lines, "")
	}
	lines = append(lines,
		ui.Hint("See it work safely:  ", "aba test"),
		ui.Hint("Dashboard:           ", "aba"),
		ui.Hint("Health check:        ", "aba doctor"),
		"",
		ui.Dim.Render("Don't open the bait files yourself: that counts as a read. To see one: ")+ui.Code.Render("aba bait show <id>"),
		ui.Dim.Render("Open a new terminal for the `aba` command to be on your PATH."),
	)
	fmt.Println(ui.Card.Render(strings.Join(lines, "\n")))
	return nil
}

func uninstallCmd() *cobra.Command {
	var purge, yes bool
	c := &cobra.Command{
		Use:   "uninstall",
		Short: "Remove A Better Antivirus and every bait, restoring Windows settings",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAdmin(); err != nil {
				return err
			}
			if !yes && ui.IsTTY() {
				ok := false
				desc := "Removes the service, every bait, network blocks, and restores the Windows audit setting."
				if !purge {
					desc += "\nAlert history is kept (use --purge to delete it)."
				}
				huh.NewConfirm().Title("Uninstall A Better Antivirus?").Description(desc).Affirmative("Uninstall").Negative("Cancel").Value(&ok).WithTheme(theme()).Run()
				if !ok {
					fmt.Println(ui.Dim.Render("Cancelled."))
					return nil
				}
			}
			if err := ui.RunSteps(install.UninstallSteps(purge)); err != nil {
				return err
			}
			fmt.Println("\n" + ui.Good.Render(ui.IconOK) + " A Better Antivirus is uninstalled.")
			return nil
		},
	}
	c.Flags().BoolVar(&purge, "purge", false, "also delete alert history and logs")
	c.Flags().BoolVarP(&yes, "yes", "y", false, "don't ask for confirmation")
	return c
}
