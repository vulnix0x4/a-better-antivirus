package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/doctor"
	"github.com/vulnix0x4/a-better-antivirus/internal/install"
	"github.com/vulnix0x4/a-better-antivirus/internal/procinfo"
	"github.com/vulnix0x4/a-better-antivirus/internal/trust"
	"github.com/vulnix0x4/a-better-antivirus/internal/ui"
)

// The steps of `aba configure`, one command each, without questions: what
// the desktop app runs (internal/appapi/PARITY.md), and handy in scripts.
// Secrets come on standard input as JSON, never on the command line, where
// every program on the PC can read them.

// maxStdin is the most a command reads from standard input.
const maxStdin = 64 << 10

// stdin is where settings are read from (the tests swap it).
var stdin io.Reader = os.Stdin

// stdinIsTerminal: nothing was piped in.
var stdinIsTerminal = func() bool {
	fi, err := os.Stdin.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// readStdinJSON reads one JSON object from standard input into v; fields v
// doesn't have are an error.
func readStdinJSON(v any, example string) error {
	if stdinIsTerminal() {
		return exitf("this reads its settings as JSON on standard input, e.g.\n  %s", example)
	}
	b, err := io.ReadAll(io.LimitReader(stdin, maxStdin+1))
	if err != nil {
		return err
	}
	if len(b) > maxStdin {
		return exitf("too much on standard input")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return exitf("standard input isn't the settings this takes: %v", err)
	}
	if d.More() {
		return exitf("standard input has more than one set of settings")
	}
	return nil
}

// requireAdminHere: a command whose input comes on standard input can't be
// started again as administrator (the input doesn't follow it): it has to
// be run as one.
func requireAdminHere() error {
	if procinfo.SelfElevated() {
		return nil
	}
	return errors.New("this needs administrator rights: run it from an administrator terminal (its settings come on standard input, which can't follow it into a new window)")
}

// ---- phone set / off / tier ----

func phoneSetCmd() *cobra.Command {
	var noTest bool
	c := &cobra.Command{
		Use:   "set",
		Short: "Set up phone alerts from JSON on standard input",
		Long: "Reads phone alerts' settings as JSON on standard input, saves them and sends a test.\n" +
			"A secret left out (token, webhook, keys, password) keeps the one saved now, if phone alerts\n" +
			"already go the same way. The guided way is `aba configure`.",
		Example: `  echo {"kind":"ntfy","ntfy":{"topic":"my-secret-topic"}} | aba phone set` + "\n" +
			`  aba phone set < discord.json      {"kind":"discord","discord":{"webhookUrl":"https://discord.com/api/webhooks/…"}}` + "\n" +
			`  aba phone set < email.json        {"kind":"email","email":{"host":"smtp.gmail.com","port":587,"username":"…","password":"…","to":"me@example.com"},"minTier":"critical"}`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAdminHere(); err != nil {
				return err
			}
			var in config.PhoneSetting
			if err := readStdinJSON(&in, `echo {"kind":"ntfy","ntfy":{"topic":"my-secret-topic"}} | aba phone set`); err != nil {
				return err
			}
			return phoneSet(in, !noTest)
		},
	}
	c.Flags().BoolVar(&noTest, "no-test", false, "don't send a test alert")
	return c
}

// phoneSet saves phone settings and (test) sends a test through them.
func phoneSet(in config.PhoneSetting, test bool) error {
	p := in.PhoneConfig
	if p.Kind == "ntfy" {
		p.Ntfy.Server = strings.TrimSuffix(strings.TrimSpace(p.Ntfy.Server), "/")
		if p.Ntfy.Server == "" {
			p.Ntfy.Server = "https://ntfy.sh"
		}
	}
	if p.Kind == "email" {
		p.Email.Host, p.Email.To, p.Email.From = strings.TrimSpace(p.Email.Host), strings.TrimSpace(p.Email.To), strings.TrimSpace(p.Email.From)
	}
	if !p.Only() {
		return exitf("these settings are for %s alerts but hold another kind's too", p.Kind)
	}
	if in.MinTier != "" && !config.ValidTier(in.MinTier) {
		return exitf("minTier is info, warn or critical")
	}
	if err := p.Check(true); err != nil {
		return err
	}
	cfg, err := mustConfig()
	if err != nil {
		return err
	}
	sec, err := config.LoadSecrets()
	if err != nil {
		return err
	}
	p = p.KeepSecrets(sec.Phone)
	if err := p.Check(false); err != nil {
		return err
	}
	changed := p != sec.Phone
	sec.Phone = p
	if err := config.SaveSecrets(sec); err != nil {
		return err
	}
	if in.MinTier != "" && in.MinTier != cfg.PhoneMinTier {
		cfg.PhoneMinTier = in.MinTier
		if err := config.SaveConfig(cfg); err != nil {
			return err
		}
	}
	fmt.Println(ui.Good.Render(ui.IconOK) + " Phone alerts: " + p.Describe() + ui.Dim.Render(" ("+tierWords(cfg.PhoneMinTier)+")"))
	details := map[string]any{"tested": false}
	if err := install.Reload(); err != nil {
		fmt.Println(ui.Warn.Render("!") + " " + ui.Plain.Render("Saved, but the service didn't pick it up yet ("+err.Error()+")."))
	}
	if test && changed { // the same settings again: `aba phone test` sends one
		if err := install.SendTest(p); err != nil {
			details["testError"] = err.Error()
			fmt.Println(ui.Warn.Render("!") + " " + ui.Plain.Render("Saved, but the test didn't get through: "+err.Error()))
		} else {
			details["tested"] = true
			fmt.Println(ui.Good.Render(ui.IconOK) + " Sent a test: check your phone.")
		}
	}
	setDetails(details)
	return nil
}

func tierWords(t config.Tier) string {
	switch t {
	case config.TierInfo:
		return "every alert"
	case config.TierCritical:
		return "critical alerts only"
	}
	return "suspicious and critical alerts"
}

func phoneOffCmd() *cobra.Command {
	return &cobra.Command{
		Use: "off", Short: "No more phone alerts", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAdmin(); err != nil {
				return err
			}
			if _, err := mustConfig(); err != nil {
				return err
			}
			sec, err := config.LoadSecrets()
			if err != nil {
				return err
			}
			if !sec.Phone.Enabled() {
				fmt.Println(ui.Dim.Render("Phone alerts were already off."))
				return nil
			}
			sec.Phone = config.PhoneConfig{}
			if err := config.SaveSecrets(sec); err != nil {
				return err
			}
			fmt.Println(ui.Good.Render(ui.IconOK) + " Phone alerts off. " + ui.Hint("Set them up again:", "aba configure"))
			return install.Reload()
		},
	}
}

func phoneTierCmd() *cobra.Command {
	return &cobra.Command{
		Use: "tier [info|warn|critical]", Short: "Which alerts reach your phone", Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAdmin(); err != nil {
				return err
			}
			cfg, err := mustConfig()
			if err != nil {
				return err
			}
			if len(args) == 0 {
				fmt.Println("Your phone gets " + ui.Bold.Render(tierWords(cfg.PhoneMinTier)) + ".  " + ui.Hint("Change:", "aba phone tier info|warn|critical"))
				return nil
			}
			t := config.Tier(strings.ToLower(args[0]))
			if !config.ValidTier(t) {
				return exitf("use `aba phone tier info` (everything), `warn` (suspicious and critical) or `critical`")
			}
			cfg.PhoneMinTier = t
			if err := config.SaveConfig(cfg); err != nil {
				return err
			}
			fmt.Println(ui.Good.Render(ui.IconOK) + " Your phone gets " + tierWords(t))
			return install.Reload()
		},
	}
}

// ---- canary ----

func canaryCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "canary [on]",
		Short: "Canary tokens: baits that email you when someone uses them",
		Long: "Canary tokens are fake AWS keys and a link, made with the free canarytokens.org service and hidden in\n" +
			"your baits. If a stealer gets away with your files and uses them later, you get an email, even if this\n" +
			"computer never got the chance to warn you. Your email address is shared with canarytokens.org.\n\n" +
			"`aba canary on --email you@example.com` makes them (or the address as JSON on standard input:\n" +
			"{\"email\": \"you@example.com\"}). Baits planted from then on carry them. Once made, a token can only be\n" +
			"switched off at canarytokens.org.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAdmin(); err != nil {
				return err
			}
			if _, err := mustConfig(); err != nil {
				return err
			}
			sec, err := config.LoadSecrets()
			if err != nil {
				return err
			}
			if len(sec.Canary.Tokens) == 0 {
				fmt.Println("Canary tokens are " + ui.Bad.Render("off") + ".  " + ui.Hint("Make them:", "aba canary on --email you@example.com"))
				return nil
			}
			kinds := []string{}
			for _, t := range sec.Canary.Tokens {
				kinds = append(kinds, t.Kind)
			}
			fmt.Println("Canary tokens are " + ui.Good.Render("on") + ": " + strings.Join(kinds, ", ") + ui.Dim.Render(", emailing "+sec.Canary.Email))
			return nil
		},
	}
	var email string
	on := &cobra.Command{
		Use: "on", Short: "Make canary tokens that email this address", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if email == "" {
				if err := requireAdminHere(); err != nil {
					return err
				}
				var in struct {
					Email string `json:"email"`
				}
				if err := readStdinJSON(&in, `aba canary on --email you@example.com`); err != nil {
					return err
				}
				email = in.Email
			} else if err := requireAdmin(); err != nil {
				return err
			}
			email = strings.TrimSpace(email)
			if !config.ValidEmail(email) {
				return exitf("%q isn't an email address", email)
			}
			cfg, err := mustConfig()
			if err != nil {
				return err
			}
			sec, err := config.LoadSecrets()
			if err != nil {
				return err
			}
			made, err := install.MakeCanaryTokens(cfg, sec, email)
			if err != nil && made == 0 {
				return err
			}
			fmt.Println(ui.Good.Render(ui.IconOK) + " " + fmt.Sprintf("%d canary token(s), alerts go to %s", len(sec.Canary.Tokens), email))
			if err != nil {
				fmt.Println(ui.Warn.Render("!") + " " + ui.Plain.Render(err.Error()))
			}
			if made > 0 {
				fmt.Println(ui.Dim.Render("Baits planted from now on carry them (`aba bait remove` and `aba bait add` plant one again)."))
			}
			return install.Reload()
		},
	}
	on.Flags().StringVar(&email, "email", "", "where canarytokens.org writes (else read as JSON on standard input)")
	c.AddCommand(on)
	return c
}

// ---- recent ----

func recentCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "recent [on|off]",
		Short: "Keep baits out of your Recent files",
		Long: "If you open a bait yourself, Windows lists it under Recent files, and apps like Copilot then read it.\n" +
			"With this on (the default), ABA removes those shortcuts.",
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
				if cfg.CleanRecent {
					state = ui.Good.Render("on")
				}
				fmt.Println("Keeping baits out of Recent files is " + state + ".  " + ui.Hint("Change:", "aba recent on|off"))
				return nil
			}
			switch strings.ToLower(args[0]) {
			case "on":
				cfg.CleanRecent = true
			case "off":
				cfg.CleanRecent = false
			default:
				return exitf("use `aba recent on` or `aba recent off`")
			}
			if err := config.SaveConfig(cfg); err != nil {
				return err
			}
			fmt.Println(ui.Good.Render(ui.IconOK) + " Keeping baits out of Recent files: " + strings.ToLower(args[0]))
			return install.Reload()
		},
	}
}

// parseActions reads a custom response: action IDs, comma-separated
// ("" = only alert).
func parseActions(s string) ([]config.Action, error) {
	var out []config.Action
	for _, f := range strings.Split(s, ",") {
		f = strings.TrimSpace(strings.ToLower(f))
		if f == "" {
			continue
		}
		known := false
		for _, a := range config.AllActions {
			known = known || string(a) == f
		}
		if !known {
			return nil, fmt.Errorf("no action %q (use %s)", f, actionList())
		}
		if config.Has(out, config.Action(f)) {
			return nil, fmt.Errorf("%s is there twice", f)
		}
		out = append(out, config.Action(f))
	}
	return out, nil
}

func actionList() string {
	var s []string
	for _, a := range config.AllActions {
		s = append(s, string(a))
	}
	return strings.Join(s, ", ")
}

// ---- what --json gives programs ----

// DoctorCheck is one line of `aba doctor`.
type DoctorCheck struct {
	Level  string `json:"level"` // ok | note | warning | problem
	Name   string `json:"name"`
	Detail string `json:"detail"`
	Fix    string `json:"fix,omitempty"`
}

func doctorDetails(fix bool, fixed []string, results []doctor.Result) map[string]any {
	checks := []DoctorCheck{}
	for _, r := range results {
		level := "problem"
		switch r.Level {
		case doctor.OK:
			level = "ok"
		case doctor.Note:
			level = "note"
		case doctor.Warning:
			level = "warning"
		}
		checks = append(checks, DoctorCheck{Level: level, Name: r.Name, Detail: r.Detail, Fix: r.Fix})
	}
	out := map[string]any{"checks": checks}
	if fix {
		out["fixed"] = fixed
	}
	return out
}

// RuleDetail is one ignore rule, for programs.
type RuleDetail struct {
	ID     string            `json:"id"`
	Number int               `json:"number"`
	Rule   config.IgnoreRule `json:"rule"`
	Says   string            `json:"says"`
}

func ruleDetails(rules []config.IgnoreRule, names map[string]string) []RuleDetail {
	out := []RuleDetail{}
	for i, r := range rules {
		out = append(out, RuleDetail{ID: r.ID(), Number: i + 1, Rule: r, Says: trust.Describe(r, names)})
	}
	return out
}

// SuggestionDetail is one program `aba learn` offers to trust.
type SuggestionDetail struct {
	ID          string            `json:"id"`
	Rule        config.IgnoreRule `json:"rule"`
	Tier        config.Tier       `json:"tier"`
	Count       int               `json:"count"`
	Last        time.Time         `json:"last"`
	Recommended bool              `json:"recommended"`
	Says        string            `json:"says"`
	Alerts      []string          `json:"alerts"`
}

func suggestionDetails(sugg []trust.Suggestion, names map[string]string) []SuggestionDetail {
	out := []SuggestionDetail{}
	for _, s := range sugg {
		out = append(out, SuggestionDetail{ID: s.ID, Rule: s.Rule, Tier: s.Tier, Count: s.Count, Last: s.Last,
			Recommended: s.Recommended(), Says: trust.Describe(s.Rule, names), Alerts: s.Alerts})
	}
	return out
}
