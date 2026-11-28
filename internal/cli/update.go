package cli

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/huh"
	"github.com/spf13/cobra"

	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/install"
	"github.com/vulnix0x4/a-better-antivirus/internal/logx"
	"github.com/vulnix0x4/a-better-antivirus/internal/paths"
	"github.com/vulnix0x4/a-better-antivirus/internal/ui"
	"github.com/vulnix0x4/a-better-antivirus/internal/update"
)

func updateCmd() *cobra.Command {
	var check bool
	c := &cobra.Command{
		Use:   "update",
		Short: "Install the latest signed version",
		Long: "Checks GitHub for a newer release. Updates are only installed if the release is signed\n" +
			"with A Better Antivirus' release key and the download matches its signed checksum.\n" +
			"Automatic updates can be turned on or off with `aba configure`.",
		Example: "  aba update\n  aba update --check",
		RunE: func(cmd *cobra.Command, args []string) error {
			if !check {
				if err := requireAdmin(); err != nil {
					return err
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
			defer cancel()
			fmt.Println(ui.Dim.Render("Checking for a new version…"))
			rel, err := update.Latest(ctx)
			if err != nil {
				return err
			}
			cfg, _ := config.LoadConfig()
			autoLine := func() {
				if cfg == nil {
					return
				}
				if cfg.AutoUpdate {
					fmt.Println(ui.Dim.Render("Automatic updates are on."))
				} else {
					fmt.Println(ui.Dim.Render("Automatic updates are off. Turn them on with ") + ui.Code.Render("aba configure"))
				}
			}
			setDetails(map[string]any{"current": Version, "latest": rel.Tag, "url": rel.HTMLURL,
				"available": update.Updatable(Version) && update.Newer(Version, rel.Tag)})
			if !update.Updatable(Version) {
				fmt.Printf("This is a %s build, which doesn't update itself. The latest release is %s.\n", Version, rel.Tag)
				return nil
			}
			if !update.Newer(Version, rel.Tag) {
				fmt.Println(ui.Good.Render(ui.IconOK) + " You're on the latest version (" + Version + ").")
				autoLine()
				return nil
			}
			fmt.Printf("%s %s is available (you have %s)\n  %s\n", ui.Warn.Render(ui.IconArr), ui.Bold.Render(rel.Tag), Version, ui.Dim.Render(rel.HTMLURL))
			if check {
				fmt.Println(ui.Hint("Install it with", "aba update"))
				return nil
			}
			if !yesMode && ui.IsTTY() {
				ok := true
				huh.NewConfirm().Title("Install " + rel.Tag + " now?").
					Description("Protection pauses for a few seconds while the service restarts.").
					Affirmative("Update").Negative("Not now").Value(&ok).WithTheme(theme()).Run()
				if !ok {
					return nil
				}
			}
			var exe string
			steps := []install.Step{
				{Name: "Downloading " + rel.Tag, Run: func() (string, error) {
					step("Downloading " + rel.Tag)
					var err error
					exe, err = update.Download(ctx, rel, update.Dir())
					if err != nil {
						return "", err
					}
					update.Cleanup(exe)
					return "signature and checksum verified", nil
				}},
				{Name: "Installing and restarting the service", Run: func() (string, error) {
					step("Installing and restarting the service")
					log := logx.New(paths.LogFile(), false)
					if err := update.Apply(exe, log.Printf); err != nil {
						return "", err
					}
					log.Printf("update: %s -> %s (aba update)", Version, rel.Tag)
					recordUpdated(Version, rel.Tag)
					return "", nil
				}},
			}
			fmt.Println()
			if err := ui.RunSteps("Updating A Better Antivirus", steps); err != nil {
				return err
			}
			fmt.Println("\n" + ui.Good.Render(ui.IconOK) + " Updated to " + rel.Tag + ".")
			autoLine()
			return nil
		},
	}
	c.Flags().BoolVar(&check, "check", false, "only check, don't install")
	c.Flags().BoolVarP(&yesMode, "yes", "y", yesMode, "don't ask for confirmation")
	c.AddCommand(updateApplyCmd(), updateAutoCmd())
	return c
}

// updateApplyCmd is run by the service, as the new (already verified) binary:
// it stops the service, swaps the files and starts the new version.
func updateApplyCmd() *cobra.Command {
	var file, from string
	c := &cobra.Command{
		Use:    "apply",
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			log := logx.New(paths.LogFile(), false)
			time.Sleep(time.Second) // let the service finish logging the hand-over
			if err := update.Apply(file, log.Printf); err != nil {
				log.Printf("update to %s failed: %v", Version, err)
				config.UpdateState(func(st *config.State) error {
					if st.Update == nil {
						st.Update = &config.UpdateStatus{}
					}
					st.Update.LastResult = "update to " + Version + " failed: " + err.Error()
					return nil
				})
				return err
			}
			log.Printf("update: %s -> %s (automatic)", from, Version)
			recordUpdated(from, Version)
			return nil
		},
	}
	c.Flags().StringVar(&file, "file", "", "verified update to install")
	c.Flags().StringVar(&from, "from", "", "version being replaced")
	return c
}

func recordUpdated(from, to string) {
	// Windows' "Installed apps" list shows the version too.
	install.RefreshApp(to)
	config.UpdateState(func(st *config.State) error {
		if st.Update == nil {
			st.Update = &config.UpdateStatus{}
		}
		st.Update.UpdatedAt = time.Now()
		st.Update.UpdatedTo = to
		st.Update.Latest = to
		st.Update.LastResult = "updated from " + from + " to " + to
		return nil
	})
}

// updateAutoCmd switches automatic updates on or off (what `aba configure`
// asks), without questions.
func updateAutoCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "auto [on|off]",
		Short: "Whether updates install themselves",
		Args:  cobra.MaximumNArgs(1),
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
				if cfg.AutoUpdate {
					state = ui.Good.Render("on")
				}
				fmt.Println("Automatic updates are " + state + ".  " + ui.Hint("Change:", "aba update auto on|off"))
				return nil
			}
			switch strings.ToLower(args[0]) {
			case "on":
				cfg.AutoUpdate = true
			case "off":
				cfg.AutoUpdate = false
			default:
				return exitf("use `aba update auto on` or `aba update auto off`")
			}
			if err := config.SaveConfig(cfg); err != nil {
				return err
			}
			fmt.Println(ui.Good.Render(ui.IconOK) + " Automatic updates " + strings.ToLower(args[0]))
			return install.Reload()
		},
	}
}
