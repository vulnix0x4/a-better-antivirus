package appapi

import (
	"net/url"
	"strings"

	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/trust"
)

// The rest of `aba configure`, the bait catalog and the trusted programs
// (see PARITY.md).

func actionIDs(acts []config.Action) []string {
	out := []string{}
	for _, a := range acts {
		out = append(out, string(a))
	}
	return out
}

// moreSettings fills in Settings beyond the first screen's switches.
func (s *Source) moreSettings(out *Settings) {
	cfg := s.cfg()
	if cfg.Learning(s.Now) {
		out.LearningUntil = tp(cfg.LearningUntil)
	}
	out.LearningMatters = cfg.LearningMatters()
	out.Responses = Responses{Info: actionIDs(cfg.Responses[config.TierInfo]), Warn: actionIDs(cfg.Responses[config.TierWarn]),
		Critical: actionIDs(cfg.Responses[config.TierCritical])}
	out.Actions = []ActionOption{}
	for _, a := range config.AllActions {
		out.Actions = append(out.Actions, ActionOption{ID: string(a), Says: a.Describe()})
	}
	out.CleanRecent = cfg.CleanRecent
	out.Phone = s.phoneView()
	out.Canary = s.canaryView()
}

// phoneView is phone alerts without their secrets.
func (s *Source) phoneView() Phone {
	cfg := s.cfg()
	tier := string(cfg.PhoneMinTier)
	if tier == "" {
		tier = string(config.TierWarn)
	}
	out := Phone{On: s.PhoneVia != "", Via: s.PhoneVia, MinTier: tier}
	if s.Secrets == nil || !s.Secrets.Phone.Enabled() {
		return out
	}
	p := s.Secrets.Phone
	out.On, out.Via, out.Describe = true, p.Kind, p.Describe()
	switch p.Kind {
	case "ntfy":
		srv := p.Ntfy.Server
		if srv == "" {
			srv = "https://ntfy.sh"
		}
		out.Ntfy = &PhoneNtfy{Server: strings.TrimSuffix(srv, "/"), Topic: config.Mask(p.Ntfy.Topic), HasToken: p.Ntfy.Token != ""}
	case "discord":
		host := ""
		if u, err := url.Parse(p.Discord.WebhookURL); err == nil {
			host = u.Hostname()
		}
		out.Discord = &PhoneDiscord{Host: host}
	case "pushover":
		out.Pushover = &PhonePushover{Set: p.Pushover.AppToken != "" && p.Pushover.UserKey != ""}
	case "email":
		e := p.Email
		out.Email = &PhoneEmail{Host: e.Host, Port: e.Port, ImplicitTLS: e.ImplicitTLS, Username: e.Username,
			HasPassword: e.Password != "", From: e.From, To: e.To}
	}
	return out
}

var canaryLabels = map[string]string{"aws_keys": "Fake AWS keys", "web": "A link in the password list"}

func (s *Source) canaryView() Canary {
	out := Canary{Tokens: []CanaryToken{}}
	if s.Secrets == nil {
		return out
	}
	c := s.Secrets.Canary
	out.Email = c.Email
	for _, t := range c.Tokens {
		label := canaryLabels[t.Kind]
		if label == "" {
			label = t.Kind
		}
		out.Tokens = append(out.Tokens, CanaryToken{Kind: t.Kind, Bait: t.BaitID, Label: label})
	}
	out.On = len(out.Tokens) > 0
	return out
}

// ---- Bait catalog ----

// Catalog builds the "Add a bait" list from the plan for this PC.
func (s *Source) Catalog() *Catalog {
	st := s.state()
	out := &Catalog{Schema: Schema, Categories: []string{}, Items: []CatalogItem{}}
	seen := map[string]bool{}
	cfg := s.cfg()
	for _, a := range s.Plan {
		sp := a.Spec
		if !seen[sp.Category] {
			seen[sp.Category] = true
			out.Categories = append(out.Categories, sp.Category)
		}
		info := baitInfo(sp.ID, sp.Name)
		it := CatalogItem{ID: sp.ID, Label: info.Label, Icon: info.Icon, Name: sp.Name, Category: sp.Category, Kind: sp.Kind,
			Description: sp.Description, Caveat: sp.Caveat, Recommended: sp.Default, Available: a.Available, Reason: a.Reason}
		if sp.Synced != nil {
			it.Synced = sp.Synced(cfg.User)
		}
		if bs := st.Baits[sp.ID]; bs != nil && bs.Status != "retired" {
			it.Planted, it.Available, it.Reason, it.Health = true, true, "", health(bs.Status)
		}
		out.Items = append(out.Items, it)
	}
	return out
}

// ---- Trusted programs ----

// Trusted builds the trusted programs screen.
func (s *Source) Trusted() *Trusted {
	cfg := s.cfg()
	names := map[string]string{}
	for id, bs := range s.state().Baits {
		names[id] = bs.Name
	}
	refs := func(ids []string) []BaitRef {
		out := []BaitRef{}
		for _, id := range ids {
			label := baitInfo(id, names[id]).Label
			out = append(out, BaitRef{ID: id, Label: label})
		}
		return out
	}
	out := &Trusted{Schema: Schema, Rules: []TrustRule{}, Suggestions: []TrustSuggestion{}, Builtin: builtinTrusted}
	for _, r := range cfg.Ignore {
		out.Rules = append(out.Rules, TrustRule{ID: r.ID(), Path: r.Path, Signer: r.Signer, SHA256: r.SHA256, CommandLine: r.CommandLine,
			Dir: r.Dir, Baits: refs(r.Baits), Tricks: r.Tricks, Note: r.Note, Says: trust.Describe(r, names)})
	}
	for _, sg := range trust.Suggest(s.Alerts, cfg.Ignore) {
		out.Suggestions = append(out.Suggestions, TrustSuggestion{ID: sg.ID, Program: base(sg.Rule.Path), Path: sg.Rule.Path,
			Signer: sg.Rule.Signer, Tier: string(sg.Tier), Count: sg.Count, Last: sg.Last, Baits: refs(sg.Rule.Baits),
			Says: trust.Describe(sg.Rule, names), Recommended: sg.Recommended(), Alerts: nonNil(sg.Alerts)})
	}
	out.Learning = Learning{On: cfg.Learning(s.Now), Matters: cfg.LearningMatters()}
	if out.Learning.On {
		out.Learning.Until = tp(cfg.LearningUntil)
	}
	return out
}

// builtinTrusted: what's never alerted on, rule or not.
const builtinTrusted = "Windows Defender and Windows Search are always left alone."
