package service

import (
	"strings"

	"github.com/vulnix0x4/a-better-antivirus/internal/baits"
	"github.com/vulnix0x4/a-better-antivirus/internal/config"
)

// moveCrowdedProfiles keeps the fake profiles inside the real browsers out of
// the browsers' way. A Chromium browser names the profile you add after how
// many it has ever made, and walks right into a folder of that name, wiping
// it (see baits.Crowded). When that count comes near a fake profile's number,
// the fake is planted afresh under a name further out and the old one taken
// away, quietly: nothing happened that you need to hear about. It reports
// whether it moved any (the configuration and the baits were reloaded).
func (s *server) moveCrowdedProfiles(cfg *config.Config) bool {
	st, err := config.LoadState()
	if err != nil {
		return false
	}
	var crowded []string
	for id, bs := range st.Baits {
		if bs.Status == "retired" {
			continue
		}
		if spec, ok := baits.SpecByID(cfg, id); ok && spec.Inside != nil && baits.Crowded(spec, cfg.User) && !baits.Adopted(spec, cfg.User) {
			crowded = append(crowded, id)
		}
	}
	if len(crowded) == 0 {
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
	for _, id := range crowded {
		spec, _ := baits.SpecByID(c2, id)
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
			s.log.Printf("the browser is about to name a new profile %s: moved the fake %s to %s", old, bs.Name, c2.User.Embedded[id])
		}
		return nil
	})
	if err := s.reload(); err != nil {
		s.log.Printf("reload after moving fake profiles: %v", err)
	}
	return true
}
