// Package config defines ABA's persistent configuration, runtime state and
// secrets, and how they are read and written safely by the service (SYSTEM) and
// the elevated CLI at the same time.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/vulnix0x4/a-better-antivirus/internal/paths"
)

// Tier is how suspicious a reader is.
type Tier string

const (
	TierInfo     Tier = "info"     // known, signed software (Defender-like scanners, Copilot, Edge import…)
	TierWarn     Tier = "warn"     // plausible but unusual (runtimes, signed apps in user folders, SMB)
	TierCritical Tier = "critical" // unsigned code from user-writable folders, script hosts, LOLBins
)

var Tiers = []Tier{TierInfo, TierWarn, TierCritical}

func (t Tier) Rank() int {
	switch t {
	case TierInfo:
		return 1
	case TierWarn:
		return 2
	case TierCritical:
		return 3
	}
	return 0
}

// Action is something the service does in response to a bait read.
type Action string

const (
	ActionFreeze          Action = "freeze"           // suspend the reader + its children
	ActionBlockProgram    Action = "block-program"    // WFP block for that executable
	ActionKill            Action = "kill"             // terminate the reader tree
	ActionIsolate         Action = "isolate"          // WFP block everything (except ABA's own alerts)
	ActionDisableAdapters Action = "disable-adapters" // fallback isolation: turn adapters off
)

var AllActions = []Action{ActionFreeze, ActionBlockProgram, ActionKill, ActionIsolate, ActionDisableAdapters}

func (a Action) Describe() string {
	switch a {
	case ActionFreeze:
		return "Freeze the process (and its children) so it can't upload"
	case ActionBlockProgram:
		return "Block that program's internet access"
	case ActionKill:
		return "Kill the process tree"
	case ActionIsolate:
		return "Isolate the PC from the network (ABA alerts still get out)"
	case ActionDisableAdapters:
		return "Disable network adapters (blunt fallback)"
	}
	return string(a)
}

// Presets bundle per-tier responses. Every tier always notifies.
type Preset struct {
	ID          string
	Name        string
	Description string
	Responses   map[Tier][]Action
}

var Presets = []Preset{
	{
		ID: "alert", Name: "Alert only",
		Description: "Notify you, never touch processes or the network.",
		Responses:   map[Tier][]Action{},
	},
	{
		ID: "balanced", Name: "Balanced (recommended)",
		Description: "Critical readers get frozen and cut off from the internet. Your internet stays on.",
		Responses: map[Tier][]Action{
			TierCritical: {ActionFreeze, ActionBlockProgram},
		},
	},
	{
		ID: "strict", Name: "Strict",
		Description: "Critical readers get frozen and the whole PC is isolated. Suspicious ones get frozen.",
		Responses: map[Tier][]Action{
			TierWarn:     {ActionFreeze},
			TierCritical: {ActionFreeze, ActionBlockProgram, ActionIsolate},
		},
	},
}

func PresetByID(id string) (Preset, bool) {
	for _, p := range Presets {
		if p.ID == id {
			return p, true
		}
	}
	return Preset{}, false
}

// UserInfo is the protected user's identity and folders, resolved at install
// time (the service runs as SYSTEM and can't ask the shell for them).
type UserInfo struct {
	SID            string `json:"sid"`
	Name           string `json:"name"`
	Profile        string `json:"profile"`
	Desktop        string `json:"desktop"`
	Documents      string `json:"documents"`
	Downloads      string `json:"downloads"`
	LocalAppData   string `json:"localAppData"`
	RoamingAppData string `json:"roamingAppData"`
	DecoyBrowser   string `json:"decoyBrowser,omitempty"` // fake browser hosting MetaMask etc.
}

// BaitConfig selects a bait from the catalog, or defines a custom file bait.
type BaitConfig struct {
	ID   string `json:"id"`
	Path string `json:"path,omitempty"` // custom baits only
}

// IgnoreRule suppresses alerts for a reader. All non-empty fields must match.
type IgnoreRule struct {
	Path   string `json:"path,omitempty"`   // glob on full image path, case-insensitive ('*' matches within a segment, '**' across)
	Signer string `json:"signer,omitempty"` // substring of the Authenticode signer, case-insensitive
	Note   string `json:"note,omitempty"`
}

type Config struct {
	Version       int               `json:"version"`
	User          UserInfo          `json:"user"`
	Baits         []BaitConfig      `json:"baits"`
	Preset        string            `json:"preset"`
	Responses     map[Tier][]Action `json:"responses"`
	LearningUntil time.Time         `json:"learningUntil,omitempty"`
	Ignore        []IgnoreRule      `json:"ignore"`
	PhoneMinTier  Tier              `json:"phoneMinTier"`
	CleanRecent   bool              `json:"cleanRecent"`
	CanaryEnabled bool              `json:"canaryEnabled"`
	InstalledAt   time.Time         `json:"installedAt"`
	Extra         map[string]any    `json:"extra,omitempty"`
}

func Default() *Config {
	p, _ := PresetByID("balanced")
	return &Config{
		Version:      1,
		Preset:       p.ID,
		Responses:    cloneResponses(p.Responses),
		PhoneMinTier: TierWarn,
		CleanRecent:  true,
	}
}

func cloneResponses(in map[Tier][]Action) map[Tier][]Action {
	out := map[Tier][]Action{}
	for k, v := range in {
		out[k] = append([]Action(nil), v...)
	}
	return out
}

// ApplyPreset replaces the responses with a preset's.
func (c *Config) ApplyPreset(id string) error {
	p, ok := PresetByID(id)
	if !ok {
		return fmt.Errorf("unknown preset %q", id)
	}
	c.Preset = p.ID
	c.Responses = cloneResponses(p.Responses)
	return nil
}

// Learning reports whether learning mode is active at t.
func (c *Config) Learning(t time.Time) bool {
	return !c.LearningUntil.IsZero() && t.Before(c.LearningUntil)
}

// ActionsFor returns the configured actions for a tier at time t (none while learning).
func (c *Config) ActionsFor(t Tier, now time.Time) []Action {
	if c.Learning(now) {
		return nil
	}
	return c.Responses[t]
}

func Has(actions []Action, a Action) bool {
	for _, x := range actions {
		if x == a {
			return true
		}
	}
	return false
}

func (c *Config) PresetName() string {
	if p, ok := PresetByID(c.Preset); ok {
		return p.Name
	}
	return "Custom"
}

// SortedIgnore returns ignore rules in a stable order for display.
func (c *Config) SortedIgnore() []IgnoreRule {
	out := append([]IgnoreRule(nil), c.Ignore...)
	sort.SliceStable(out, func(i, j int) bool { return strings.ToLower(out[i].Path) < strings.ToLower(out[j].Path) })
	return out
}

func LoadConfig() (*Config, error) { return loadConfigFrom(paths.ConfigFile()) }

func loadConfigFrom(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNotInstalled
		}
		return nil, err
	}
	c := Default()
	if err := json.Unmarshal(b, c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if c.Responses == nil {
		c.Responses = map[Tier][]Action{}
	}
	return c, nil
}

func SaveConfig(c *Config) error { return writeJSONAtomic(paths.ConfigFile(), c) }

var ErrNotInstalled = errors.New("ABA is not installed (run `aba install`)")

// writeJSONAtomic writes v to path via a temp file + rename so readers never
// see a half-written file.
func writeJSONAtomic(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(path, b)
}

func writeFileAtomic(path string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Rename(name, path); err != nil {
		os.Remove(name)
		return err
	}
	return nil
}
