package engine

import (
	"path/filepath"
	"strings"

	"github.com/vulnix0x4/a-better-antivirus/internal/baits"
	"github.com/vulnix0x4/a-better-antivirus/internal/paths"
	"github.com/vulnix0x4/a-better-antivirus/internal/provenance"
)

// Reads that never count toward a sweep, besides the genuine browser going
// through its fake profile (hostRead):
//
//   - The genuine app at home in a decoy: the real app moved in where ABA had
//     put fake data for it (classify's DecoyOwner), and uses what's in that
//     folder, the baits that live inside the decoy included (the MetaMask
//     wallet inside a fake browser). ABA retires the decoy; meanwhile the app
//     reading and writing its own folder is nothing to report.
//   - A genuine browser opening another browser's `Local State`. Chromium
//     browsers do that on their first start, and Brave on every start, to
//     offer to import from the browsers they find: it says which profiles
//     there are, nothing more. A newly installed Brave opened the fake
//     Vivaldi, Opera and Yandex `Local State` files one after another and was
//     frozen as a stealer sweeping three apps' data.
//
// A stealer running inside a genuine browser still sweeps as soon as it goes
// for what's worth taking (Login Data, Cookies, Web Data: each app counts as
// before), and a read of one of those is still the read that completes it.

// localStateProbe reports whether path is the `Local State` file of a fake
// browser profile (baitID): the file a browser's import probe opens.
func localStateProbe(baitID, path string) bool {
	if !strings.EqualFold(filepath.Base(path), "Local State") {
		return false
	}
	s, ok := baits.ByID(baitID)
	return ok && s.Category == "Browsers" && s.Inside == nil
}

// browserCandidates are the catalog's browsers that image could be: its
// program's name, where that browser installs (signature not checked).
func (e *Engine) browserCandidates(image string) []baits.Spec {
	e.mu.Lock()
	cls := e.classifier
	e.mu.Unlock()
	if cls == nil || image == "" {
		return nil
	}
	var out []baits.Spec
	for _, s := range baits.Catalog {
		if s.Category == "Browsers" && s.Signer != "" && len(s.OwnerExes) > 0 && cls.OwnerCandidate(image, e.baitRef(s.ID)) {
			out = append(out, s)
		}
	}
	return out
}

// signedBy reports whether sig is a valid signature whose signer names one
// of specs' makers.
func signedBy(sig provenance.Result, specs []baits.Spec) bool {
	if !sig.Valid {
		return false
	}
	for _, s := range specs {
		if strings.Contains(strings.ToLower(sig.Signer), strings.ToLower(s.Signer)) {
			return true
		}
	}
	return false
}

// importProbe reports whether image (signature sig) opening path (of bait
// baitID) is a genuine browser's import probe (see above).
func (e *Engine) importProbe(image, baitID, path string, sig provenance.Result) bool {
	return localStateProbe(baitID, path) && signedBy(sig, e.browserCandidates(image))
}

// homeCandidates are the decoys whose folder path (of baitID) is in and whose genuine app
// image could be (by its name and where it lives; signature not checked).
func (e *Engine) homeCandidates(image, baitID, path string) []baits.Spec {
	e.mu.Lock()
	cls, cfg := e.classifier, e.cfg
	e.mu.Unlock()
	if cls == nil || cfg == nil || image == "" || embedded(baitID) {
		return nil
	}
	var out []baits.Spec
	for _, s := range baits.Catalog {
		if s.Root == nil || s.Inside != nil || s.Signer == "" || len(s.OwnerExes) == 0 {
			continue
		}
		if root := s.Root(cfg.User); root != "" && paths.Under(path, root) && cls.OwnerCandidate(image, e.baitRef(s.ID)) {
			out = append(out, s)
		}
	}
	return out
}

// atHome reports whether image (signature sig) is the genuine app at home in
// the decoy that path is in (see above).
func (e *Engine) atHome(image, baitID, path string, sig provenance.Result) bool {
	return signedBy(sig, e.homeCandidates(image, baitID, path))
}

// quietAccess reports whether pid (running image) opening path (of baitID)
// is an access that never counts toward a sweep (see above). home is the
// decoy it's the genuine app of, when it's at home in that decoy's folder
// ("" if not). The signature is only checked for a program that could be
// either.
func (e *Engine) quietAccess(image string, pid uint32, baitID, path string) (quiet bool, home string) {
	if live, err := e.Ops.ImagePath(pid); err == nil && live != "" {
		image = live
	}
	probe := localStateProbe(baitID, path) && len(e.browserCandidates(image)) > 0
	homes := e.homeCandidates(image, baitID, path)
	if !probe && len(homes) == 0 {
		return false, ""
	}
	sig := e.Ops.Verify(image)
	for _, s := range homes {
		if signedBy(sig, []baits.Spec{s}) {
			return true, s.ID
		}
	}
	return probe && e.importProbe(image, baitID, path, sig), ""
}
