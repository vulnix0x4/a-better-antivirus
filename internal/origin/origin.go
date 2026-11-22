// Package origin says where a program came from, as the browser or the
// system wrote it down when the file was downloaded:
//
//   - Windows: the Mark of the Web, a Zone.Identifier stream on the file.
//   - macOS: the quarantine attribute (which app downloaded it) and the
//     "where from" attribute (the address).
//   - Linux: the user.xdg.origin.url attribute Chromium-based browsers, curl
//     --xattr and wget --xattr write.
//
// It's a lead for the person reading the alert ("so that's the 'free
// Photoshop' I got yesterday"), not evidence: the program could have written
// the mark itself. Nothing here decides how severe an alert is.
package origin

import (
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Origin is where a file was downloaded from.
type Origin struct {
	File     string `json:"file"`               // the file that carries the mark
	URL      string `json:"url,omitempty"`      // the download address
	Referrer string `json:"referrer,omitempty"` // the page it was downloaded from (or, Windows, the archive it was unpacked from)
	Via      string `json:"via,omitempty"`      // the app that downloaded it, when the system says (macOS)
}

// Where is the one-line form: the address, or the next best thing.
func (o *Origin) Where() string {
	switch {
	case o == nil:
		return ""
	case o.URL != "":
		return o.URL
	case o.Referrer != "":
		return o.Referrer
	case o.Via != "":
		return "the internet, by " + o.Via
	}
	return "the internet"
}

// Find returns the origin of the first of files that has one, or nil.
func Find(files ...string) *Origin {
	seen := map[string]bool{}
	for _, f := range files {
		if f == "" || seen[strings.ToLower(f)] {
			continue
		}
		seen[strings.ToLower(f)] = true
		if o := Of(f); o != nil {
			return o
		}
	}
	return nil
}

// maxLen is the longest address kept: enough for any real download link,
// not for a page of text a program wrote into its own mark.
const maxLen = 400

// clean makes an attribute value safe to show: printable, one line, bounded.
func clean(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == unicode.ReplacementChar {
			return -1
		}
		return r
	}, s)
	if len(s) > maxLen {
		n := maxLen
		for n > 0 && !utf8.RuneStart(s[n]) {
			n--
		}
		s = s[:n] + "…"
	}
	return s
}

// Unknown marks are about:internet (Windows' placeholder) or empty.
func useful(s string) bool {
	return s != "" && !strings.EqualFold(s, "about:internet") && !strings.EqualFold(s, "about:blank")
}

// Line is the labelled one-line form for an alert about the program image,
// naming the marked file when it's another one (its script, its parent).
func (o *Origin) Line(image string) string {
	if o == nil {
		return ""
	}
	s := "Downloaded from: " + o.Where()
	if !strings.EqualFold(o.File, image) {
		s += " (" + filepath.Base(o.File) + ")"
	}
	return s
}
