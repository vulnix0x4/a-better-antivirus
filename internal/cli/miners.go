package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/install"
	"github.com/vulnix0x4/a-better-antivirus/internal/minertrap"
	"github.com/vulnix0x4/a-better-antivirus/internal/platform"
	"github.com/vulnix0x4/a-better-antivirus/internal/ui"
)

// ---- miner trap ----

func minersCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "miners [on|off|test]",
		Short: "Catch hidden crypto miners with a fake mining pool",
		Long: "Hidden crypto miners use your PC to make money for someone else. To be paid, a miner has to\n" +
			"reach a mining pool, and nearly all of them use a few dozen public pools. With this on, those\n" +
			"pools' names lead to a fake pool on this PC. A program that logs in there to mine is frozen,\n" +
			"cut off and you're alerted, with the wallet it mines for and where it came from.\n\n" +
			"Only the pools' names are changed, nothing else, and nothing is sent anywhere. The pools'\n" +
			"websites don't open while it's on. If you mine on purpose, turn it off.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !minertrap.Supported() {
				return exitf("the miner trap is %s", platform.ErrUnsupported)
			}
			if err := requireAdmin(); err != nil {
				return err
			}
			cfg, err := mustConfig()
			if err != nil {
				return err
			}
			if len(args) == 0 {
				state := ui.Bad.Render("off")
				if cfg.MinerTrap {
					state = ui.Good.Render("on")
				}
				fmt.Println("The miner trap is " + state + ".  " + ui.Hint("Change:", "aba miners on|off"))
				if cfg.MinerTrap {
					fmt.Println(ui.Dim.Render(fmt.Sprintf("%d mining pools' names lead to ABA's fake pool on this %s.", len(minertrap.Pools), platform.PC)))
				}
				return nil
			}
			switch strings.ToLower(args[0]) {
			case "on":
				cfg.MinerTrap = true
			case "off":
				cfg.MinerTrap = false
			default:
				return exitf("use `aba miners on` or `aba miners off`")
			}
			if err := config.SaveConfig(cfg); err != nil {
				return err
			}
			if !cfg.MinerTrap {
				// Right away, whatever the service is doing: the names resolve
				// normally again.
				if _, err := minertrap.Remove(); err != nil {
					return fmt.Errorf("removing the miner trap's redirect: %w", err)
				}
				fmt.Println(ui.Good.Render(ui.IconOK) + " Miner trap off" + ui.Dim.Render(": mining pools' names work normally again"))
			} else {
				fmt.Println(ui.Good.Render(ui.IconOK) + " Miner trap on" + ui.Dim.Render(".  Watch it work: ") + ui.Code.Render("aba miners test"))
			}
			return install.Reload()
		},
	}
	c.AddCommand(&cobra.Command{
		Use:   "test",
		Short: "Watch it catch a harmless fake miner",
		Long: "Starts a harmless fake miner from your Temp folder. It looks up a real mining pool's name, which\n" +
			"the trap points at ABA's fake pool, and logs in there. Nothing leaves this PC: it connects only\n" +
			"once the name has led to the fake pool.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAdmin(); err != nil {
				return err
			}
			return runMinerTest()
		},
	})
	return c
}
