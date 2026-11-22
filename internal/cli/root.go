// Package cli implements the aba command line.
package cli

import (
	"errors"
	"fmt"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"
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
		Long: "A Better Antivirus plants fake passwords, wallets and app data that only malware would read.\n" +
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
	cobra.EnableCommandSorting = false // keep the order below: most useful first
	root.SetVersionTemplate("A Better Antivirus {{.Version}}\n")
	root.CompletionOptions.HiddenDefaultCmd = true
	defaultHelp := root.HelpFunc()
	root.SetHelpFunc(func(c *cobra.Command, args []string) {
		if c == root {
			fmt.Print(rootHelp(root))
			return
		}
		defaultHelp(c, args)
	})

	root.AddGroup(&cobra.Group{ID: "main", Title: "Everyday"}, &cobra.Group{ID: "respond", Title: "When something trips"}, &cobra.Group{ID: "setup", Title: "Setup"})
	add := func(group string, cmds ...*cobra.Command) {
		for _, c := range cmds {
			c.GroupID = group
			root.AddCommand(c)
		}
	}
	add("main", statusCmd(), alertsCmd(), testCmd(), doctorCmd(), learnCmd())
	add("respond", trustCmd(), killCmd(), resumeCmd(), releaseCmd())
	add("setup", installCmd(), configureCmd(), updateCmd(), baitCmd(), ignoreCmd(), instantCmd(), phoneCmd(), uninstallCmd())
	root.AddCommand(serviceCmd(), notifyCmd(), testReaderCmd())
	return root
}

func welcome() error {
	fmt.Print(renderWelcome())
	if !ui.IsTTY() {
		fmt.Println("\n" + ui.Hint(" Install with", "aba install"))
		return nil
	}
	fmt.Println()
	ok := true
	if err := huh.NewConfirm().Title("Set it up now?").Description("Takes about a minute. You can change everything later with aba configure.").
		Affirmative("Set it up").Negative("Not now").Value(&ok).WithTheme(theme()).Run(); err != nil || !ok {
		fmt.Println(ui.Hint(" Whenever you're ready:", "aba install"))
		return nil
	}
	return runInstall(false, installFlags{})
}

func renderWelcome() string {
	var b strings.Builder
	b.WriteString("\n" + ui.Banner(ui.Tagline) + "\n\n")
	b.WriteString(" " + ui.Bold.Render("Not set up yet.") + ui.Dim.Render(" Here's what it does:") + "\n\n")
	for _, l := range [][2]string{
		{"Plants fake passwords, wallets and app data", "that nothing legitimate ever reads"},
		{words.welcomeWatch, words.welcomeNote},
		{"Freezes whatever takes the bait", "and cuts its internet before your real data leaves"},
	} {
		b.WriteString("  " + ui.Good.Render(ui.IconArr) + " " + ui.Plain.Render(l[0]) + ui.Dim.Render(", "+l[1]) + "\n")
	}
	return b.String()
}

// rootHelp is `aba --help`: the commands people actually use, grouped and aligned.
func rootHelp(root *cobra.Command) string {
	var b strings.Builder
	b.WriteString("\n" + ui.Banner(ui.Tagline) + "\n\n")
	b.WriteString(" " + ui.Dim.Render("Plants fake passwords, wallets and app data that only malware would read. When") + "\n")
	b.WriteString(" " + ui.Dim.Render("something touches them, ABA freezes it, cuts its internet and tells you.") + "\n")
	// One column width for every group, so all descriptions line up.
	w := 0
	for _, c := range root.Commands() {
		if !c.Hidden && c.GroupID != "" {
			w = max(w, lipgloss.Width("aba "+c.Use))
		}
	}
	for _, g := range root.Groups() {
		type row struct{ name, args, short string }
		var rows []row
		for _, c := range root.Commands() {
			if c.GroupID != g.ID || c.Hidden {
				continue
			}
			rows = append(rows, row{"aba " + c.Name(), strings.TrimPrefix(c.Use, c.Name()), c.Short})
		}
		b.WriteString("\n " + ui.Section.Render(g.Title) + "\n")
		for _, r := range rows {
			pad := strings.Repeat(" ", w-lipgloss.Width(r.name+r.args))
			b.WriteString("   " + ui.Code.Render(r.name) + ui.Fainter.Render(r.args) + pad + "   " + ui.Dim.Render(r.short) + "\n")
		}
	}
	b.WriteString("\n " + ui.Hint("Run", "aba") + ui.Dim.Render(" on its own for the live dashboard, and ") + ui.Code.Render("aba <command> --help") + ui.Dim.Render(" for details.") + "\n\n")
	return b.String()
}

func statusCmd() *cobra.Command {
	var once bool
	c := &cobra.Command{
		Use:   "status",
		Short: "Live dashboard (same as plain aba)",
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
