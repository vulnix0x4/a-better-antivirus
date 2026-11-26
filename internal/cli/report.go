package cli

// A caught program's full report as a page in the web browser (`aba
// report`), and every report, newest first (`aba reports`, the Start
// menu's "ABA reports"). What the page says is `aba autopsy`'s report; how
// it gets to the browser without a copy being left anywhere is package
// report.

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/vulnix0x4/a-better-antivirus/internal/alerts"
	"github.com/vulnix0x4/a-better-antivirus/internal/report"
	"github.com/vulnix0x4/a-better-antivirus/internal/ui"
)

// whyAdmin is what the reports need administrator rights for, in words.
const whyAdmin = "ABA's reports name its bait files, so only administrators can open them."

func reportCmd() *cobra.Command {
	var noBrowser bool
	c := &cobra.Command{
		Use:   "report <alert-id>",
		Short: "A caught program's full report, as a page in your web browser",
		Long: "Opens everything ABA found about a program it caught (the same as `aba autopsy`) as a page in your\n" +
			"web browser: what it opened of yours, where it sent it, what it left behind, and what to do.\n\n" +
			"The page isn't saved anywhere: your browser gets it once, from this computer only. To see it again,\n" +
			"open it again (or `aba reports` for all of them).",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAdminQuietly(whyAdmin); err != nil {
				return err
			}
			a, err := alerts.Load(args[0])
			if err != nil {
				return err
			}
			if a.Autopsy == nil {
				return exitf("alert %s has no report: ABA writes one when it catches a program and looks into what it did (see `aba alerts show %s`)", args[0], args[0])
			}
			return showPage(report.Page(a), noBrowser)
		},
	}
	c.Flags().BoolVar(&noBrowser, "no-browser", false, "don't open the browser: print the page's one-time address instead")
	return c
}

func reportsCmd() *cobra.Command {
	var noBrowser bool
	c := &cobra.Command{
		Use:   "reports",
		Short: "Every caught program's report, newest first, in your web browser",
		Long: "Opens the list of ABA's reports in your web browser, newest first: pick one to see it whole.\n" +
			"The Start menu's \"ABA reports\" opens the same list. The page isn't saved anywhere.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAdminQuietly(whyAdmin); err != nil {
				return err
			}
			list, err := alerts.List(0)
			if err != nil {
				return err
			}
			return showPage(report.Index(list), noBrowser)
		},
	}
	c.Flags().BoolVar(&noBrowser, "no-browser", false, "don't open the browser: print the page's one-time address instead")
	return c
}

// showPage hands page to the browser once and waits until it has it.
func showPage(page []byte, noBrowser bool) error {
	o, err := report.Serve(page)
	if err != nil {
		return err
	}
	defer o.Close()
	if noBrowser {
		fmt.Println(o.URL)
		fmt.Println(ui.Dim.Render(fmt.Sprintf("Open that address in your web browser within %d minutes. It works once, on this computer only.", int(report.OpenTime.Minutes()))))
	} else {
		fmt.Println(ui.Dim.Render("Opening it in your web browser…"))
		if err := report.Open(o.URL); err != nil {
			fmt.Println(ui.Warn.Render("Couldn't open the browser ("+err.Error()+"). Open this address in it yourself:") + "\n" + o.URL)
		}
	}
	if err := o.Wait(report.OpenTime); err != nil {
		if errors.Is(err, report.ErrNotOpened) {
			return exitf("the browser didn't pick the page up in %d minutes; it's no longer served. Run this again to open it", int(report.OpenTime.Minutes()))
		}
		return err
	}
	noPause = true
	return nil
}
