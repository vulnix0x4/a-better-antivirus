package autopsy

// Indicators to share: what lets someone else recognise the same malware,
// or take down where it sends, and nothing of yours. The file is written
// locally; sharing it is up to you.

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"time"

	"github.com/vulnix0x4/a-better-antivirus/internal/alerts"
	"github.com/vulnix0x4/a-better-antivirus/internal/paths"
)

// IOC is the shareable record of one catch.
type IOC struct {
	Format    string    `json:"format"`
	Generated time.Time `json:"generated"`
	Detected  time.Time `json:"detected"`
	Kind      string    `json:"kind"` // stealer | clipper
	File      *IOCFile  `json:"file,omitempty"`
	Sending   []IOCAddr `json:"sendingTo,omitempty"`
	// AttackerWallet is the address a clipper swapped in for yours: where
	// it wanted your money sent.
	AttackerWallet string `json:"attackerWallet,omitempty"`
	Note           string `json:"note"`
}

// IOCFile is the program, by its fingerprint.
type IOCFile struct {
	SHA256     string `json:"sha256,omitempty"`
	Name       string `json:"name"`
	Path       string `json:"path,omitempty"` // with your home folder written as ~
	Signed     bool   `json:"signed"`
	Signer     string `json:"signer,omitempty"`
	VirusTotal string `json:"virustotal,omitempty"`
}

// IOCAddr is somewhere it was sending to.
type IOCAddr struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
	Where string `json:"seenIn"`
}

const iocNote = "Written by A Better Antivirus for you to share if you choose. It holds the program's fingerprint and where it was sending, and nothing of yours: no file contents, no memory, no user name, no addresses that could be your own data. ABA never uploads it."

// MakeIOC builds the shareable record of a.
func MakeIOC(a *alerts.Alert, home string) IOC {
	out := IOC{Format: "aba-ioc/1", Generated: time.Now().UTC(), Detected: a.Time.UTC(), Kind: "stealer", Note: iocNote}
	if a.Kind == alerts.KindClipper {
		out.Kind = "clipper"
	}
	if p := a.Process; p != nil && p.Image != "" {
		f := &IOCFile{SHA256: p.SHA256, Name: filepath.Base(p.Image), Path: redactHome(p.Image, home), Signed: p.Signature.Valid, Signer: p.Signature.Signer}
		if p.SHA256 != "" {
			f.VirusTotal = "https://www.virustotal.com/gui/file/" + p.SHA256
		}
		out.File = f
	}
	if ap := a.Autopsy; ap != nil {
		out.AttackerWallet = ap.AttackerWallet
		for _, ad := range ap.Addresses {
			if Shareable(ad.Kind, ad.Value, ad.Where) {
				out.Sending = append(out.Sending, IOCAddr{Kind: ad.Kind, Value: ad.Value, Where: ad.Where})
			}
		}
	} else if p := a.Process; p != nil {
		for _, c := range p.Connections {
			if c.Remote != "" {
				out.Sending = append(out.Sending, IOCAddr{Kind: KindConn, Value: c.Remote, Where: "connection"})
			}
		}
	}
	return out
}

// redactHome writes the home folder as "~": the rest of a path says where
// the malware put itself, the home folder says who you are.
func redactHome(p, home string) string {
	if home != "" && (paths.Same(p, home) || paths.Under(p, home)) {
		rel := strings.TrimPrefix(p[len(home):], string(filepath.Separator))
		return "~" + string(filepath.Separator) + rel
	}
	return p
}

// MarshalIOC is the file's contents.
func MarshalIOC(i IOC) ([]byte, error) {
	b, err := json.MarshalIndent(i, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}
