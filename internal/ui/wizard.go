package ui

import (
	"errors"
	"fmt"
	"net/mail"
	"net/url"
	"strconv"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"

	"github.com/vulnix0x4/a-better-antivirus/internal/baits"
	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/install"
)

// WizardInput is what the wizard knows before asking.
type WizardInput struct {
	User     config.UserInfo
	Plan     []baits.Availability
	Existing *config.Config  // nil on first install
	Secrets  *config.Secrets // may be empty
}

func Theme() *huh.Theme {
	t := huh.ThemeCharm()
	t.Focused.Title = t.Focused.Title.Foreground(Leaf)
	t.Focused.SelectSelector = t.Focused.SelectSelector.Foreground(Leaf)
	t.Focused.MultiSelectSelector = t.Focused.MultiSelectSelector.Foreground(Leaf)
	t.Focused.SelectedOption = t.Focused.SelectedOption.Foreground(Leaf)
	t.Focused.SelectedPrefix = lipgloss.NewStyle().Foreground(Leaf).SetString("[✓] ")
	t.Focused.FocusedButton = t.Focused.FocusedButton.Background(lipgloss.Color("#1E8A4C"))
	return t
}

// RunWizard asks everything and returns install options. ok=false if cancelled.
func RunWizard(in WizardInput) (install.Options, bool, error) {
	o := install.Options{CleanRecent: true, Preset: "balanced", LearningDays: 3, PhoneMinTier: config.TierWarn}
	existing := map[string]bool{}
	if in.Existing != nil {
		o.Preset = in.Existing.Preset
		o.CleanRecent = in.Existing.CleanRecent
		o.PhoneMinTier = in.Existing.PhoneMinTier
		o.KeepLearning = true
		o.LearningDays = 0
		for _, b := range in.Existing.Baits {
			existing[b.ID] = true
			if b.Path != "" {
				o.CustomBaits = append(o.CustomBaits, b.Path)
			}
		}
	}
	sec := in.Secrets
	if sec == nil {
		sec = &config.Secrets{}
	}

	// ---- Baits ----
	var opts []huh.Option[string]
	var skipped []string
	for _, a := range in.Plan {
		if !a.Available {
			skipped = append(skipped, fmt.Sprintf("%s %s: %s", IconDot, a.Spec.Name, a.Reason))
			continue
		}
		label := a.Spec.Name
		if a.Spec.Caveat != "" {
			label += Warn.Render("  (opt-in: " + a.Spec.Caveat + ")")
		} else {
			label += Fainter.Render("  " + a.Spec.Description)
		}
		pre := a.Spec.Default
		if in.Existing != nil {
			pre = existing[a.Spec.ID]
		}
		opts = append(opts, huh.NewOption(fmt.Sprintf("%-9s %s", a.Spec.Category, label), a.Spec.ID).Selected(pre))
	}
	skippedNote := "Nothing skipped."
	if len(skipped) > 0 {
		skippedNote = "Skipped because you use these apps (fake data would get in their way):\n" + strings.Join(skipped, "\n")
	}

	// ---- Response ----
	var presetOpts []huh.Option[string]
	for _, p := range config.Presets {
		presetOpts = append(presetOpts, huh.NewOption(p.Name+Fainter.Render("  "+p.Description), p.ID))
	}
	presetOpts = append(presetOpts, huh.NewOption("Custom"+Fainter.Render("  Choose actions per severity yourself"), "custom"))
	var warnActs, critActs []string
	if in.Existing != nil && in.Existing.Preset == "custom" {
		for _, a := range in.Existing.Responses[config.TierWarn] {
			warnActs = append(warnActs, string(a))
		}
		for _, a := range in.Existing.Responses[config.TierCritical] {
			critActs = append(critActs, string(a))
		}
	} else {
		critActs = []string{string(config.ActionFreeze), string(config.ActionBlockProgram)}
	}
	actionOpts := func() []huh.Option[string] {
		var out []huh.Option[string]
		for _, a := range config.AllActions {
			out = append(out, huh.NewOption(a.Describe(), string(a)))
		}
		return out
	}

	learning := strconv.Itoa(o.LearningDays)
	learnOpts := []huh.Option[string]{
		huh.NewOption("3 days (recommended)"+Fainter.Render("  watch and learn what's normal on this PC first"), "3"),
		huh.NewOption("7 days", "7"),
		huh.NewOption("No: protect right away", "0"),
	}
	if in.Existing != nil {
		learnOpts = append([]huh.Option[string]{huh.NewOption("Keep current setting", "keep")}, learnOpts...)
		learning = "keep"
	}

	// ---- Phone ----
	p := sec.Phone
	phoneKind := p.Kind
	ntfyServer, ntfyTopic, ntfyToken := p.Ntfy.Server, p.Ntfy.Topic, p.Ntfy.Token
	if ntfyServer == "" {
		ntfyServer = "https://ntfy.sh"
	}
	if ntfyTopic == "" {
		ntfyTopic = "aba-" + strings.ToLower(randomWord())
	}
	poApp, poUser := p.Pushover.AppToken, p.Pushover.UserKey
	webhook := p.Discord.WebhookURL
	em := p.Email
	emPort := "587"
	if em.Port != 0 {
		emPort = strconv.Itoa(em.Port)
	}
	minTier := string(o.PhoneMinTier)

	// ---- Canary ----
	canaryOn := sec.Canary.Email != ""
	canaryEmail := sec.Canary.Email

	cleanRecent := o.CleanRecent
	// Configs from before auto-update existed haven't chosen yet: suggest on.
	autoUpdate := in.Existing == nil || in.Existing.Version < config.CurrentConfigVersion || in.Existing.AutoUpdate
	confirm := true

	notEmpty := func(s string) error {
		if strings.TrimSpace(s) == "" {
			return errors.New("required")
		}
		return nil
	}

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewNote().Title("Set up A Better Antivirus").Description(
				"ABA plants convincing fake files and fake app data that only malware would ever read.\n"+
					"When something touches them you're alerted instantly, and it can freeze the reader\n"+
					"and cut its internet before your real data leaves.\n\n"+
					"Protecting: "+in.User.Name+"\n\n"+
					Fainter.Render("Use ↑/↓, space to toggle, enter to continue. Esc goes back.")),
		),
		huh.NewGroup(
			huh.NewMultiSelect[string]().Title("Which baits should ABA plant?").
				Description("Recommended ones are preselected. Every one is fake and harmless.").
				Options(opts...).Height(16).Value(&o.Baits).
				Validate(func(v []string) error {
					if len(v) == 0 {
						return errors.New("pick at least one bait")
					}
					return nil
				}),
			huh.NewNote().Title("Skipped").Description(skippedNote),
		),
		huh.NewGroup(
			huh.NewSelect[string]().Title("What should happen when a bait is read?").
				Description("Severity is automatic: unsigned programs from Temp/AppData/Downloads and script hosts are critical;\nsigned installed apps are just noted.").
				Options(presetOpts...).Value(&o.Preset),
		),
		huh.NewGroup(
			huh.NewMultiSelect[string]().Title("Custom: for SUSPICIOUS readers (warn)").Options(actionOpts()...).Value(&warnActs),
			huh.NewMultiSelect[string]().Title("Custom: for CRITICAL readers").Options(actionOpts()...).Value(&critActs),
		).WithHideFunc(func() bool { return o.Preset != "custom" }),
		huh.NewGroup(
			huh.NewSelect[string]().Title("Start in learning mode?").
				Description("Learning mode alerts but never blocks, and suggests rules for legit apps that touch baits\n(backup tools, sync clients). Review with `aba learn`.").
				Options(learnOpts...).Value(&learning),
		),
		huh.NewGroup(
			huh.NewSelect[string]().Title("Phone alerts").
				Description("Get alerts even when you're away. They're sent before isolation kicks in, and still\nget out while the PC is isolated.").
				Options(
					huh.NewOption("None", ""),
					huh.NewOption("ntfy"+Fainter.Render("  free app, no account: install ntfy on your phone and subscribe to a topic"), "ntfy"),
					huh.NewOption("Discord webhook", "discord"),
					huh.NewOption("Pushover", "pushover"),
					huh.NewOption("Email (SMTP)", "email"),
				).Value(&phoneKind),
		),
		huh.NewGroup(
			huh.NewInput().Title("ntfy topic").Description("Pick something hard to guess: anyone who knows it can read your alerts.").Value(&ntfyTopic).Validate(notEmpty),
			huh.NewInput().Title("ntfy server").Value(&ntfyServer).Validate(validURL),
			huh.NewInput().Title("Access token (optional, for protected topics)").EchoMode(huh.EchoModePassword).Value(&ntfyToken),
		).WithHideFunc(func() bool { return phoneKind != "ntfy" }),
		huh.NewGroup(
			huh.NewInput().Title("Discord webhook URL").Description("Server Settings > Integrations > Webhooks > New Webhook > Copy URL").EchoMode(huh.EchoModePassword).Value(&webhook).Validate(validURL),
		).WithHideFunc(func() bool { return phoneKind != "discord" }),
		huh.NewGroup(
			huh.NewInput().Title("Pushover application token").EchoMode(huh.EchoModePassword).Value(&poApp).Validate(notEmpty),
			huh.NewInput().Title("Pushover user key").EchoMode(huh.EchoModePassword).Value(&poUser).Validate(notEmpty),
		).WithHideFunc(func() bool { return phoneKind != "pushover" }),
		huh.NewGroup(
			huh.NewInput().Title("SMTP server").Placeholder("smtp.gmail.com").Value(&em.Host).Validate(notEmpty),
			huh.NewInput().Title("Port").Description("587 = STARTTLS, 465 = TLS").Value(&emPort).Validate(func(s string) error {
				if _, err := strconv.Atoi(s); err != nil {
					return errors.New("number")
				}
				return nil
			}),
			huh.NewInput().Title("Username").Value(&em.Username),
			huh.NewInput().Title("Password / app password").EchoMode(huh.EchoModePassword).Value(&em.Password),
			huh.NewInput().Title("Send alerts to").Value(&em.To).Validate(validEmail),
		).WithHideFunc(func() bool { return phoneKind != "email" }),
		huh.NewGroup(
			huh.NewSelect[string]().Title("Which alerts go to your phone?").Options(
				huh.NewOption("Suspicious and critical", string(config.TierWarn)),
				huh.NewOption("Critical only", string(config.TierCritical)),
				huh.NewOption("Everything", string(config.TierInfo)),
			).Value(&minTier),
		).WithHideFunc(func() bool { return phoneKind == "" }),
		huh.NewGroup(
			huh.NewConfirm().Title("Use canary tokens?").
				Description("ABA puts fake AWS keys and a tracking link inside your baits, created with the free\n"+
					"canarytokens.org service. If a stealer gets your files and USES them later, you get an email,\n"+
					"even if this PC was never online to tell you. Your email is shared with canarytokens.org.").
				Affirmative("Yes").Negative("No").Value(&canaryOn),
		),
		huh.NewGroup(
			huh.NewInput().Title("Email for canary alerts").Value(&canaryEmail).Validate(validEmail),
		).WithHideFunc(func() bool { return !canaryOn }),
		huh.NewGroup(
			huh.NewConfirm().Title("Keep baits out of your Recent files?").
				Description("If you open a bait, Windows lists it under Recent files and apps like Copilot then read it.\nABA removes those shortcuts automatically.").
				Affirmative("Yes").Negative("No").Value(&cleanRecent),
		),
		huh.NewGroup(
			huh.NewConfirm().Title("Keep A Better Antivirus up to date automatically?").
				Description("Once a day it checks GitHub for a new version and installs it, but only if the release is\n"+
					"signed with ABA's release key and the download matches its signed checksum.\n"+
					"Change this any time with `aba configure`, or update by hand with `aba update`.").
				Affirmative("Yes, keep it updated").Negative("No, I'll update myself").Value(&autoUpdate),
			huh.NewConfirm().Title("Ready to install?").Affirmative("Install").Negative("Cancel").Value(&confirm),
		),
	).WithTheme(Theme()).WithShowHelp(true)

	if err := form.Run(); err != nil {
		if errors.Is(err, huh.ErrUserAborted) {
			return o, false, nil
		}
		return o, false, err
	}
	if !confirm {
		return o, false, nil
	}

	if o.Preset == "custom" {
		o.Responses = map[config.Tier][]config.Action{}
		for _, a := range warnActs {
			o.Responses[config.TierWarn] = append(o.Responses[config.TierWarn], config.Action(a))
		}
		for _, a := range critActs {
			o.Responses[config.TierCritical] = append(o.Responses[config.TierCritical], config.Action(a))
		}
	}
	if learning == "keep" {
		o.KeepLearning = true
	} else {
		o.KeepLearning = false
		o.LearningDays, _ = strconv.Atoi(learning)
	}
	o.PhoneMinTier = config.Tier(minTier)
	o.CleanRecent = cleanRecent
	o.AutoUpdate = autoUpdate
	o.Phone = config.PhoneConfig{Kind: phoneKind}
	switch phoneKind {
	case "ntfy":
		o.Phone.Ntfy = config.NtfyConfig{Server: ntfyServer, Topic: strings.TrimSpace(ntfyTopic), Token: ntfyToken}
	case "discord":
		o.Phone.Discord = config.DiscordConfig{WebhookURL: strings.TrimSpace(webhook)}
	case "pushover":
		o.Phone.Pushover = config.PushoverConfig{AppToken: poApp, UserKey: poUser}
	case "email":
		em.Port, _ = strconv.Atoi(emPort)
		em.ImplicitTLS = em.Port == 465
		o.Phone.Email = em
	}
	if canaryOn {
		o.CanaryEmail = strings.TrimSpace(canaryEmail)
	}
	return o, true, nil
}

func validURL(s string) error {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return errors.New("enter a full URL starting with https://")
	}
	return nil
}

func validEmail(s string) error {
	if _, err := mail.ParseAddress(strings.TrimSpace(s)); err != nil {
		return errors.New("enter a valid email address")
	}
	return nil
}

func randomWord() string {
	const letters = "abcdefghijkmnpqrstuvwxyz23456789"
	b := make([]byte, 10)
	for i := range b {
		b[i] = letters[int(randByte())%len(letters)]
	}
	return string(b)
}
