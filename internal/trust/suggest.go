package trust

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"time"

	"github.com/vulnix0x4/a-better-antivirus/internal/alerts"
	"github.com/vulnix0x4/a-better-antivirus/internal/config"
)

// Suggestion is a program `aba learn` offers to trust: every alert about
// the same program folded into one rule (the narrowest one, see Rule),
// covering every bait it was seen reading.
type Suggestion struct {
	// ID names the suggestion (`aba learn --trust <id>`): the same program
	// gives the same ID for as long as its alerts are there.
	ID    string
	Rule  config.IgnoreRule
	Count int
	Tier  config.Tier // the highest of its alerts
	Last  time.Time
	// Alerts are the IDs of its alerts, newest first.
	Alerts []string
}

// Recommended: what `aba learn` ticks to start with (a signed program that
// was only ever noted).
func (s Suggestion) Recommended() bool { return s.Tier == config.TierInfo && s.Rule.Signer != "" }

func programKey(r config.IgnoreRule) string {
	return strings.ToLower(r.Path + "|" + r.Signer + "|" + r.SHA256 + "|" + r.CommandLine + "|" + r.Dir)
}

func shortHash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:6])
}

// Suggest lists the programs that read baits (not tests) and could be
// trusted for good, minus the ones the rules already cover for every bait
// they read; the most frequent first. list is newest first.
func Suggest(list []*alerts.Alert, ignore []config.IgnoreRule) []Suggestion {
	byKey := map[string]*Suggestion{}
	var order []string
	for _, a := range list {
		if a.Test || a.Process == nil || a.Process.Image == "" || a.Kind != alerts.KindRead {
			continue
		}
		r, why := Rule(a)
		if why != "" {
			continue // can't be trusted permanently (script host without a command line, a sweep…)
		}
		key := programKey(r)
		s := byKey[key]
		if s == nil {
			s = &Suggestion{ID: shortHash(key), Rule: r, Tier: a.Tier}
			byKey[key] = s
			order = append(order, key)
		} else {
			for _, b := range r.Baits {
				if !s.Rule.CoversBait(b) {
					s.Rule.Baits = append(s.Rule.Baits, b)
				}
			}
		}
		if a.Tier.Rank() > s.Tier.Rank() {
			s.Tier = a.Tier
		}
		s.Count++
		s.Alerts = append(s.Alerts, a.ID)
		if a.Time.After(s.Last) {
			s.Last = a.Time
		}
	}
	var out []Suggestion
	for _, key := range order {
		s := byKey[key]
		if !Covered(s.Rule, ignore) {
			out = append(out, *s)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	return out
}

// Covered reports whether rules already trust r's program for every bait r
// names.
func Covered(r config.IgnoreRule, rules []config.IgnoreRule) bool {
	for _, x := range rules {
		if !x.SameProgram(r) {
			continue
		}
		if len(x.Baits) == 0 {
			return true
		}
		ok := len(r.Baits) > 0
		for _, b := range r.Baits {
			ok = ok && x.CoversBait(b)
		}
		if ok {
			return true
		}
	}
	return false
}
