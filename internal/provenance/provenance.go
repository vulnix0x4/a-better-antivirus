// Package provenance answers "who made this program, and does the operating
// system vouch for that?". The severity and trust logic is built on the
// answer: stealers are almost always programs nobody vouches for.
//
// Each operating system has its own way of knowing, in provenance_<os>.go:
//
//   - Windows: the Authenticode code signature (embedded or from a catalog).
//   - macOS: the code signature (codesign), Signer being the developer.
//   - Linux: there are no code signatures. The nearest thing is a file that an
//     installed package owns, in a folder only root can write to; Signer would
//     be the package or its vendor.
//
// Whatever the source, the rest of ABA only reads Result: Valid means "the
// operating system vouches for this file", Signer says for whom.
package provenance

// Result of checking a program file.
type Result struct {
	Signed  bool   `json:"signed"`            // claims a maker at all (has a signature)
	Valid   bool   `json:"valid"`             // and the operating system vouches for it (chain + hash verified)
	Signer  string `json:"signer,omitempty"`  // who: the publisher's display name
	Catalog bool   `json:"catalog,omitempty"` // Windows: signed through a system catalog, not in the file
	Error   string `json:"error,omitempty"`
}

func (r Result) String() string {
	switch {
	case r.Valid:
		s := "signed by " + r.Signer
		if r.Catalog {
			s += " (catalog)"
		}
		return s
	case r.Signed:
		return "INVALID signature (" + r.Error + ")"
	}
	return "unsigned"
}
