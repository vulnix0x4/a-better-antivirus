package cli

// After a catch: what the caught program had already done (`aba autopsy`),
// what can be shared about it (`aba export-ioc`), and the flight recorder
// that makes the first possible (`aba recorder`).

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/vulnix0x4/a-better-antivirus/internal/alerts"
	"github.com/vulnix0x4/a-better-antivirus/internal/autopsy"
	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/install"
	"github.com/vulnix0x4/a-better-antivirus/internal/procinfo"
	"github.com/vulnix0x4/a-better-antivirus/internal/ui"
)

func autopsyCmd() *cobra.Command {
	var now bool
	c := &cobra.Command{
		Use:   "autopsy <alert-id>",
		Short: "Did it take your real data? Everything ABA found about a caught program",
		Long: "Shows what ABA found out about a program it caught, while it was frozen: which of your real\n" +
			"passwords, cookies, wallets and keys it had opened (from the flight recorder), what it has open,\n" +
			"what it staged, and where it was sending. ABA does this by itself a moment after every catch.\n\n" +
			"--now looks into the program again from here (if it's still frozen), without the flight\n" +
			"recorder and the network record, which only the service has.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAdmin(); err != nil {
				return err
			}
			a, err := alerts.Load(args[0])
			if err != nil {
				return err
			}
			if now {
				cfg, _ := config.LoadConfig()
				st, _ := config.LoadState()
				cs, err := autopsy.CaseFrom(a, cfg, st)
				if err != nil {
					return err
				}
				if len(cs.Frozen) == 0 && !procinfo.Alive(cs.PID, 0) {
					return exitf("the program of this alert isn't running any more: there's nothing left to look into")
				}
				fmt.Println(ui.Dim.Render("Looking into it (this can take a few seconds)…"))
				ap := autopsy.Run(cs, autopsy.SystemHooks(cfg == nil || !cfg.NoMemoryImage))
				if a, err = alerts.Update(a.ID, func(x *alerts.Alert) { x.Autopsy = ap }); err != nil {
					return err
				}
			}
			if a.Autopsy == nil {
				fmt.Println(ui.Dim.Render("No autopsy for this alert."))
				switch {
				case a.Process == nil:
					fmt.Println(ui.Dim.Render("It isn't about a program."))
				case a.Tier != config.TierCritical && !a.Did(config.ActionFreeze):
					fmt.Println(ui.Dim.Render("ABA looks into programs it caught as stealers, and anything it froze; this one was only noted."))
				default:
					fmt.Println(ui.Hint("If it's still frozen:", "aba autopsy "+args[0]+" --now"))
				}
				return nil
			}
			if a.Autopsy.Finished.IsZero() {
				fmt.Println(ui.Warn.Render("The autopsy is still running; this is what it has so far."))
			}
			printAutopsy(a)
			return nil
		},
	}
	c.Flags().BoolVar(&now, "now", false, "look into the program again from here, if it's still frozen")
	return c
}

func printAutopsy(a *alerts.Alert) {
	w := ui.Width() - 4
	fmt.Println("\n" + ui.Bold.Render(a.Title))
	fmt.Println(ui.Dim.Render(a.Time.Local().Format("Mon Jan 2 2006, 15:04:05") + "  ·  alert " + a.ID))
	for i, s := range autopsy.Render(a) {
		fmt.Println(ui.Heading(s.Title))
		for j, l := range s.Lines {
			text := l
			if i == 0 && j == 0 {
				switch a.Autopsy.Answer {
				case alerts.AnswerRead:
					if a.Autopsy.Sent == alerts.SentNothing {
						text = ui.Warn.Render(l) // it read, but nothing left
					} else {
						text = ui.Bad.Render(l)
					}
				case alerts.AnswerNoSign:
					text = ui.Good.Render(l)
				default:
					text = ui.Warn.Render(l)
				}
			}
			fmt.Println(indentWrap(text, w))
		}
	}
	fmt.Println()
}

// indentWrap wraps a line to w columns, two spaces in.
func indentWrap(s string, w int) string {
	if w < 20 {
		w = 20
	}
	var out []string
	for _, para := range strings.Split(s, "\n") {
		line := ""
		for _, word := range strings.Fields(para) {
			if line != "" && len(line)+1+len(word) > w {
				out = append(out, "  "+line)
				line = word
				continue
			}
			if line != "" {
				line += " "
			}
			line += word
		}
		out = append(out, "  "+line)
	}
	return strings.Join(out, "\n")
}

func exportIOCCmd() *cobra.Command {
	var out string
	c := &cobra.Command{
		Use:   "export-ioc <alert-id>",
		Short: "Write a file of what's safe to share about a caught program",
		Long: "Writes a local file with the caught program's fingerprint (SHA-256, file name, where it was, with your\n" +
			"home folder written as ~), where it was sending (bot tokens, webhooks, addresses in its own file,\n" +
			"connections), and the attacker's wallet when a clipper was caught. Nothing of yours: no file contents,\n" +
			"no memory, no user name, no addresses that could be from your own data.\n\n" +
			"Nothing is sent anywhere. Sharing the file (with your antivirus vendor, a CERT, abuse desks) is up to you.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAdmin(); err != nil {
				return err
			}
			a, err := alerts.Load(args[0])
			if err != nil {
				return err
			}
			if a.Process == nil && (a.Autopsy == nil || a.Autopsy.AttackerWallet == "") {
				return exitf("this alert isn't about a program: there's nothing to share")
			}
			home := ""
			if cfg, err := config.LoadConfig(); err == nil {
				home = cfg.User.Profile
			}
			b, err := autopsy.MarshalIOC(autopsy.MakeIOC(a, home))
			if err != nil {
				return err
			}
			if out == "" {
				out = "aba-ioc-" + a.ID + ".json"
			}
			if err := os.WriteFile(out, b, 0o644); err != nil {
				return err
			}
			abs, _ := filepath.Abs(out)
			fmt.Println(ui.Good.Render(ui.IconOK) + " Wrote " + abs)
			fmt.Println(ui.Dim.Render("It holds the program's fingerprint and where it was sending, nothing of yours. Nothing was uploaded: share it only if you choose to."))
			if a.Autopsy == nil {
				fmt.Println(ui.Dim.Render("(This alert has no autopsy, so only its connections are in it.)"))
			}
			return nil
		},
	}
	c.Flags().StringVarP(&out, "output", "o", "", "where to write it (default: aba-ioc-<alert id>.json here)")
	return c
}

func recorderCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "recorder [on|off]",
		Short: "Note who opens your real passwords, cookies and keys, for after a catch",
		Long: "The flight recorder quietly notes which program opens your real browser data, wallets and keys,\n" +
			"and keeps that in memory. It never alerts on its own: after ABA catches a stealer, it's how ABA\n" +
			"can tell whether the stealer had already been at the real thing. On unless you switch it off.",
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
				state := ui.Good.Render("on")
				if cfg.NoRecorder {
					state = ui.Bad.Render("off")
				}
				fmt.Println("The flight recorder is " + state + ".  " + ui.Hint("Change:", "aba recorder on|off"))
				return nil
			}
			switch strings.ToLower(args[0]) {
			case "on":
				cfg.NoRecorder = false
			case "off":
				cfg.NoRecorder = true
			default:
				return exitf("use `aba recorder on` or `aba recorder off`")
			}
			if err := config.SaveConfig(cfg); err != nil {
				return err
			}
			fmt.Println(ui.Good.Render(ui.IconOK) + " Flight recorder " + args[0])
			return install.Reload()
		},
	}
}
