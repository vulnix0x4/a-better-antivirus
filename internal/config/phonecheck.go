package config

import (
	"errors"
	"fmt"
	"net/mail"
	"net/url"
	"regexp"
	"strings"
)

// PhoneSetting is what `aba phone set` reads on standard input (and the
// desktop app sends): phone alerts' settings, and which alerts go to the
// phone.
type PhoneSetting struct {
	PhoneConfig
	MinTier Tier `json:"minTier,omitempty"`
}

var (
	ntfyTopicRe  = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	pushoverRe   = regexp.MustCompile(`^[A-Za-z0-9]{30}$`)
	hostnameRe   = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?)*$`)
	discordPath  = regexp.MustCompile(`^/api/webhooks/[0-9]{5,25}/[A-Za-z0-9_-]{20,120}$`)
	discordHosts = map[string]bool{"discord.com": true, "discordapp.com": true, "canary.discord.com": true, "ptb.discord.com": true}
)

// plain: no control characters (no line breaks to smuggle a header into an
// email or a request), at most max bytes.
func plain(what, s string, max int) error {
	if len(s) > max {
		return fmt.Errorf("%s is too long", what)
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || r == ' ' || r == ' ' {
			return fmt.Errorf("%s has a character that can't be in it", what)
		}
	}
	return nil
}

// PlainText checks a short line of text (a note, a publisher's name).
func PlainText(what, s string, max int) error { return plain(what, s, max) }

// ValidEmail reports whether s is a plain address (name@domain, no display
// name, no line breaks).
func ValidEmail(s string) bool {
	if plain("", s, 254) != nil || strings.ContainsAny(s, "<>\" ,;") {
		return false
	}
	a, err := mail.ParseAddress(s)
	return err == nil && a.Address == s && a.Name == "" && strings.Contains(s[strings.LastIndexByte(s, '@')+1:], ".")
}

// ValidNtfyTopic reports whether s can be an ntfy topic.
func ValidNtfyTopic(s string) bool { return ntfyTopicRe.MatchString(s) }

// webAddress checks a server's address: http(s), a host, nothing after it
// but an optional path, no user name or password in it.
func webAddress(what, s string, httpsOnly bool) (*url.URL, error) {
	if err := plain(what, s, 512); err != nil {
		return nil, err
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" || u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.Fragment != "" || strings.Contains(s, "#") {
		return nil, fmt.Errorf("%s isn't a web address (https://…)", what)
	}
	if u.Scheme != "https" && (httpsOnly || u.Scheme != "http") {
		return nil, fmt.Errorf("%s has to start with https://", what)
	}
	if !hostnameRe.MatchString(u.Hostname()) {
		return nil, fmt.Errorf("%s has a bad host name", what)
	}
	return u, nil
}

// Check reports what's wrong with phone settings. partial: secrets may be
// left empty (to keep the stored ones; see KeepSecrets).
func (p PhoneConfig) Check(partial bool) error {
	need := func(what, v string) error {
		if v == "" && !partial {
			return fmt.Errorf("%s is missing", what)
		}
		return nil
	}
	switch p.Kind {
	case "ntfy":
		n := p.Ntfy
		if n.Server != "" {
			u, err := webAddress("the ntfy server", n.Server, false)
			if err != nil {
				return err
			}
			if u.Path != "" && u.Path != "/" {
				return errors.New("the ntfy server is just its address (https://ntfy.sh), without a topic")
			}
		}
		if !ValidNtfyTopic(n.Topic) {
			return errors.New("an ntfy topic is 1 to 64 letters, digits, - or _")
		}
		if err := plain("the ntfy token", n.Token, 256); err != nil || strings.Contains(n.Token, " ") {
			return errors.New("the ntfy token has a character that can't be in it")
		}
	case "discord":
		if p.Discord.WebhookURL == "" {
			return need("the Discord webhook", "")
		}
		u, err := webAddress("the Discord webhook", p.Discord.WebhookURL, true)
		if err != nil {
			return err
		}
		if !discordHosts[strings.ToLower(u.Hostname())] || u.Port() != "" || !discordPath.MatchString(u.Path) {
			return errors.New("that isn't a Discord webhook (https://discord.com/api/webhooks/…)")
		}
	case "pushover":
		for what, v := range map[string]string{"the Pushover application token": p.Pushover.AppToken, "the Pushover user key": p.Pushover.UserKey} {
			if v == "" {
				if err := need(what, v); err != nil {
					return err
				}
				continue
			}
			if !pushoverRe.MatchString(v) {
				return fmt.Errorf("%s is 30 letters and digits", what)
			}
		}
	case "email":
		e := p.Email
		if len(e.Host) > 253 || !hostnameRe.MatchString(e.Host) {
			return errors.New("the SMTP server isn't a host name (smtp.example.com)")
		}
		if e.Port < 1 || e.Port > 65535 {
			return errors.New("the SMTP port is a number from 1 to 65535 (587 or 465)")
		}
		if err := plain("the user name", e.Username, 256); err != nil {
			return err
		}
		if err := plain("the password", e.Password, 256); err != nil {
			return err
		}
		if e.Username != "" {
			if err := need("the password", e.Password); err != nil {
				return err
			}
		}
		if !ValidEmail(e.To) {
			return errors.New("\"send alerts to\" isn't an email address")
		}
		if e.From != "" && !ValidEmail(e.From) {
			return errors.New("\"from\" isn't an email address")
		}
	case "":
		return errors.New("say which way phone alerts go (ntfy, discord, pushover or email)")
	default:
		return fmt.Errorf("no phone alerts by %q (ntfy, discord, pushover or email)", p.Kind)
	}
	return nil
}

// Only reports whether p holds the settings of its own kind and nothing
// else (an ntfy setting with a Discord webhook in it is a mistake).
func (p PhoneConfig) Only() bool {
	q := PhoneConfig{Kind: p.Kind}
	switch p.Kind {
	case "ntfy":
		q.Ntfy = p.Ntfy
	case "discord":
		q.Discord = p.Discord
	case "pushover":
		q.Pushover = p.Pushover
	case "email":
		q.Email = p.Email
	}
	return q == p
}

// KeepSecrets fills in the secrets p leaves empty from old, when old goes
// the same way: a form saved without typing the password again keeps it.
func (p PhoneConfig) KeepSecrets(old PhoneConfig) PhoneConfig {
	if old.Kind != p.Kind {
		return p
	}
	switch p.Kind {
	case "ntfy":
		if p.Ntfy.Token == "" && strings.TrimSuffix(p.Ntfy.Server, "/") == strings.TrimSuffix(old.Ntfy.Server, "/") {
			p.Ntfy.Token = old.Ntfy.Token
		}
	case "discord":
		if p.Discord.WebhookURL == "" {
			p.Discord.WebhookURL = old.Discord.WebhookURL
		}
	case "pushover":
		if p.Pushover.AppToken == "" {
			p.Pushover.AppToken = old.Pushover.AppToken
		}
		if p.Pushover.UserKey == "" {
			p.Pushover.UserKey = old.Pushover.UserKey
		}
	case "email":
		if p.Email.Password == "" && strings.EqualFold(p.Email.Host, old.Email.Host) && p.Email.Username == old.Email.Username {
			p.Email.Password = old.Email.Password
		}
	}
	return p
}

// ValidTier reports whether t is a tier.
func ValidTier(t Tier) bool { return t == TierInfo || t == TierWarn || t == TierCritical }
