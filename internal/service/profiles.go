package service

import (
	"strings"
	"sync"

	"github.com/vulnix0x4/a-better-antivirus/internal/baits"
	"github.com/vulnix0x4/a-better-antivirus/internal/config"
)

var moving sync.Mutex

// A fake profile inside a real browser has to stay out of that browser's
// way. A Chromium browser names the profile you add "Profile N", N from how
// many it has ever made, and walks right into a folder of that name: it wipes
// the fake profile and makes the folder a real one (see baits.Crowded,
// baits.TakenOver). So when that count comes near a fake profile's number,
// or the browser has taken its folder all the same, the fake profile is
// planted afresh under a name further out. Quietly: nothing happened that
// you need to act on, and the bait stays.

// profilesToMove lists the fake profiles that are to be moved, and why.
func profilesToMove(cfg *config.Config, st *config.State) map[string]string {
	out := map[string]string{}
	for id, bs := range st.Baits {
		if bs.Status == "retired" {
			continue
		}
		spec, ok := baits.SpecByID(cfg, id)
		if !ok || spec.Inside == nil {
			continue
		}
		switch {
		case baits.Adopted(spec, cfg.User) || baits.TakenOver(spec, cfg.User):
			out[id] = "the browser made its folder a profile of its own"
		case baits.Crowded(spec, cfg.User):
			out[id] = "the browser is about to name a new profile after its folder"
		}
	}
	return out
}

// moveCrowdedProfiles moves every fake profile that's in a browser's way (see
// above). It reports whether it moved any (the configuration and the baits
// were reloaded).
func (s *server) moveCrowdedProfiles(cfg *config.Config) bool {
	moving.Lock() // one at a time: the health check, an alert and a held-open bait can all ask
	defer moving.Unlock()
	if s.mu.Lock(); s.cfg != nil {
		cfg = s.cfg // another move may have just changed it
	}
	s.mu.Unlock()
	st, err := config.LoadState()
	if err != nil {
		return false
	}
	return s.moveProfiles(profilesToMove(cfg, st))
}

// moveProfiles plants the fake profiles ids (id -> why) afresh under new
// names and takes the old ones away. Only what ABA made and that is as it
// made it is removed: a profile the browser made in that folder stays.
func (s *server) moveProfiles(ids map[string]string) bool {
	if len(ids) == 0 {
		return false
	}
	c2, err := config.LoadConfig()
	if err != nil {
		s.log.Printf("moving fake profiles out of the browsers' way: %v", err)
		return false
	}
	if c2.User.Embedded == nil {
		c2.User.Embedded = map[string]string{}
	}
	from := map[string]string{}
	for id := range ids {
		spec, ok := baits.SpecByID(c2, id)
		if !ok || spec.Inside == nil {
			continue
		}
		old := baits.ProfileFolder(c2.User, id)
		name := baits.FreeProfile(spec, c2.User)
		if strings.EqualFold(name, old) {
			continue
		}
		from[id] = old
		c2.User.Embedded[id] = name
	}
	if len(from) == 0 {
		return false
	}
	if err := config.SaveConfig(c2); err != nil {
		s.log.Printf("moving fake profiles out of the browsers' way: %v", err)
		return false
	}
	s.guard(nil) // let go of the files about to be removed; reload re-arms the rest
	config.UpdateState(func(st *config.State) error {
		g := baits.GenFromPersona(st.Persona)
		for id, old := range from {
			bs := st.Baits[id]
			spec, ok := baits.SpecByID(c2, id)
			if bs == nil || bs.Status == "retired" || !ok {
				continue
			}
			if err := baits.Remove(bs); err != nil {
				s.log.Printf("moving the fake %s: taking away %s: %v (it stays for now)", bs.Name, old, err)
			}
			nb, err := baits.Create(spec, c2.User, g)
			if err != nil {
				s.log.Printf("moving the fake %s to %s: %v", bs.Name, c2.User.Embedded[id], err)
			}
			if nb != nil && len(nb.Files) > 0 {
				st.Baits[id] = nb
			}
			s.log.Printf("%s (%s): moved the fake %s to %s", old, ids[id], bs.Name, c2.User.Embedded[id])
		}
		return nil
	})
	if err := s.reload(); err != nil {
		s.log.Printf("reload after moving fake profiles: %v", err)
	}
	return true
}

// tookProfile reports whether path is a file of a fake profile whose folder
// the real browser has made its own: the browser holding it open is just the
// browser using its own profile (see onBlocked).
func (s *server) tookProfile(path string, st *config.State) bool {
	s.mu.Lock()
	cfg := s.cfg
	s.mu.Unlock()
	id, ok := s.eng.IsBait(path)
	if !ok || cfg == nil || st == nil || st.Baits[id] == nil {
		return false
	}
	spec, ok := baits.SpecByID(cfg, id)
	return ok && spec.Inside != nil && (baits.Adopted(spec, cfg.User) || baits.TakenOver(spec, cfg.User))
}
