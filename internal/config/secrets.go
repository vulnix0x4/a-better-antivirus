package config

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"

	"github.com/vulnix0x4/a-better-antivirus/internal/paths"
)

// Secrets hold credentials for phone alerts and canary tokens. The file is
// encrypted with a key the operating system keeps for this machine (DPAPI on
// Windows) and only the system and administrators may open it, so malware
// running as the user can't read your webhook or SMTP password. Both halves
// are in protect_<os>.go.
type Secrets struct {
	Phone  PhoneConfig  `json:"phone"`
	Canary CanaryConfig `json:"canary"`

	// ClipboardSeed (hex) is what the clipboard bait's addresses and their
	// keys are made from (see clipbait.Keys).
	ClipboardSeed string `json:"clipboardSeed,omitempty"`
}

type PhoneConfig struct {
	Kind     string         `json:"kind"` // "" | ntfy | pushover | discord | email
	Ntfy     NtfyConfig     `json:"ntfy,omitempty"`
	Pushover PushoverConfig `json:"pushover,omitempty"`
	Discord  DiscordConfig  `json:"discord,omitempty"`
	Email    EmailConfig    `json:"email,omitempty"`
}

type NtfyConfig struct {
	Server string `json:"server"` // default https://ntfy.sh
	Topic  string `json:"topic"`
	Token  string `json:"token,omitempty"`
}

type PushoverConfig struct {
	AppToken string `json:"appToken"`
	UserKey  string `json:"userKey"`
}

type DiscordConfig struct {
	WebhookURL string `json:"webhookUrl"`
}

type EmailConfig struct {
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	From        string `json:"from"`
	To          string `json:"to"`
	ImplicitTLS bool   `json:"implicitTls"` // port 465 style
}

type CanaryConfig struct {
	Email  string        `json:"email,omitempty"`
	Tokens []CanaryToken `json:"tokens,omitempty"`
}

type CanaryToken struct {
	Kind      string `json:"kind"` // aws_keys | web
	Token     string `json:"token"`
	AuthToken string `json:"authToken"`
	ManageURL string `json:"manageUrl"`
	BaitID    string `json:"baitId"`
	// Kind-specific payload (access key id/secret/region, or URL).
	Data map[string]string `json:"data"`
}

func (p PhoneConfig) Enabled() bool { return p.Kind != "" }

func (p PhoneConfig) Describe() string {
	switch p.Kind {
	case "ntfy":
		srv := p.Ntfy.Server
		if srv == "" {
			srv = "https://ntfy.sh"
		}
		return "ntfy (" + strings.TrimSuffix(srv, "/") + "/" + mask(p.Ntfy.Topic) + ")"
	case "pushover":
		return "Pushover"
	case "discord":
		return "Discord webhook"
	case "email":
		return "Email to " + p.Email.To
	}
	return "off"
}

// Mask shows a secret's first and last two characters only.
func Mask(s string) string { return mask(s) }

func mask(s string) string {
	if len(s) <= 4 {
		return "****"
	}
	return s[:2] + strings.Repeat("*", len(s)-4) + s[len(s)-2:]
}

func LoadSecrets() (*Secrets, error) {
	b, err := os.ReadFile(paths.SecretsFile())
	if errors.Is(err, os.ErrNotExist) {
		return &Secrets{}, nil
	}
	if err != nil {
		return nil, err
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil {
		return nil, err
	}
	plain, err := unprotect(raw)
	if err != nil {
		return nil, err
	}
	s := &Secrets{}
	return s, json.Unmarshal(plain, s)
}

func SaveSecrets(s *Secrets) error {
	plain, err := json.Marshal(s)
	if err != nil {
		return err
	}
	enc, err := protect(plain)
	if err != nil {
		return err
	}
	if err := writeFileAtomic(paths.SecretsFile(), []byte(base64.StdEncoding.EncodeToString(enc))); err != nil {
		return err
	}
	// The system and administrators only, whatever the folder it's in allows.
	return restrictSecrets(paths.SecretsFile())
}
