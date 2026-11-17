// Package cli implements the aba command line.
package cli

import (
	"errors"
	"fmt"

	"github.com/charmbracelet/huh"
	"github.com/spf13/cobra"

	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/service"
	"github.com/vulnix0x4/a-better-antivirus/internal/ui"
)

var Version = "dev"

// Execute runs the CLI and returns the process exit code.
func Execute() int {
	service.Version = Version
	root := newRoot()
	err := root.Execute()
	code := 0
	if err != nil && !errors.Is(err, errRelaunched) {
		ui.Fail(err)
		code = 1
	}
	if shouldPause() {
		pause()
	}
	return code
}

func newRoot() *cobra.Command {
	root := &cobra.Command{
		Use:   "aba",
		Short: "It's not an antivirus. It's a better one.",
		Long: ui.Banner(ui.Tagline) + "\n\n" +
			"ABA plants fake passwords, wallets and app data that only malware would read.\n" +
			"When something touches them, it freezes the reader, cuts its internet and alerts you.",
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       Version,
		RunE: func(cmd *cobra.Command, args []string) error {
			if _, err := config.LoadConfig(); errors.Is(err, config.ErrNotInstalled) {
				return welcome()
			}
			return ui.RunDashboard(false)
		},
	}
	root.PersistentFlags().Bool(pauseFlag[2:], false, "")
	root.PersistentFlags().MarkHidden(pauseFlag[2:])
	root.SetVersionTemplate("A Better Antivirus {{.Version}}\n")
	root.CompletionOptions.HiddenDefaultCmd = true

	root.AddGroup(&cobra.Group{ID: "main", Title: "Everyday:"}, &cobra.Group{ID: "respond", Title: "When something trips:"}, &cobra.Group{ID: "setup", Title: "Setup:"})
	add := func(group string, cmds ...*cobra.Command) {
		for _, c := range cmds {
			c.GroupID = group
			root.AddCommand(c)
		}
	}
	add("main", statusCmd(), alertsCmd(), testCmd(), doctorCmd(), learnCmd())
	add("respond", releaseCmd(), killCmd(), resumeCmd())
	add("setup", installCmd(), configureCmd(), baitCmd(), ignoreCmd(), instantCmd(), phoneCmd(), uninstallCmd())
	root.AddCommand(serviceCmd(), notifyCmd(), testReaderCmd())
	return root
}

func welcome() error {
	fmt.Println(ui.Banner(ui.Tagline))
	fmt.Println()
	fmt.Println("A Better Antivirus isn't installed yet. It will:")
	for _, l := range []string{
		"plant fake passwords, wallets and app data that only malware would read",
		"watch them with Windows' own file auditing (no driver, no background scanning)",
		"freeze anything suspicious that reads them and cut its internet, then alert you",
	} {
		fmt.Println("  " + ui.Good.Render(ui.IconArr) + " " + l)
	}
	fmt.Println()
	if !ui.IsTTY() {
		fmt.Println(ui.Hint("Install with", "aba install"))
		return nil
	}
	ok := true
	if err := huh.NewConfirm().Title("Set it up now?").Affirmative("Yes").Negative("Not now").Value(&ok).WithTheme(theme()).Run(); err != nil || !ok {
		fmt.Println(ui.Hint("Whenever you're ready:", "aba install"))
		return nil
	}
	return runInstall(false, installFlags{})
}

func statusCmd() *cobra.Command {
	var once bool
	c := &cobra.Command{
		Use:   "status",
		Short: "Live dashboard: protection health and recent alerts",
		RunE:  func(cmd *cobra.Command, args []string) error { return ui.RunDashboard(once) },
	}
	c.Flags().BoolVar(&once, "once", false, "print once instead of a live view")
	return c
}

func serviceCmd() *cobra.Command {
	c := &cobra.Command{Use: "service", Hidden: true}
	var console bool
	run := &cobra.Command{
		Use: "run",
		RunE: func(cmd *cobra.Command, args []string) error {
			return service.Run(console)
		},
	}
	run.Flags().BoolVar(&console, "console", false, "run in the foreground (debugging)")
	c.AddCommand(run)
	return c
}

func mustConfig() (*config.Config, error) {
	cfg, err := config.LoadConfig()
	if err != nil {
		return nil, err
	}
	return cfg, nil
}

func exitf(format string, a ...any) error { return fmt.Errorf(format, a...) }
