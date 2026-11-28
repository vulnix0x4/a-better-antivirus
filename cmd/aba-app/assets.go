package main

import (
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"errors"
	"io/fs"
	"regexp"
)

// The page and everything it loads, built in: there's no web server and no
// files on disk to swap. Third-party files are under frontend/vendor, each
// listed with its SHA-256 in frontend/vendor/MANIFEST.sha256 (checked by
// the tests).
//
//go:embed all:frontend
var embedded embed.FS

func frontendFS() fs.FS {
	sub, err := fs.Sub(embedded, "frontend")
	if err != nil {
		panic(err)
	}
	return sub
}

var importMapRe = regexp.MustCompile(`(?s)<script type="importmap">(.*?)</script>`)

// contentSecurityPolicy is the page's CSP: scripts, styles, fonts and images
// from the app only (plus the one inline import map, by its hash), nothing
// over the network, no frames, plugins, workers or forms.
func contentSecurityPolicy(indexHTML []byte) (string, error) {
	m := importMapRe.FindSubmatch(indexHTML)
	if m == nil {
		return "", errors.New("index.html: no import map")
	}
	sum := sha256.Sum256(m[1])
	return "default-src 'none'; " +
		"script-src 'self' 'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'; " +
		"style-src 'self'; font-src 'self'; img-src 'self'; " +
		"connect-src 'none'; media-src 'none'; object-src 'none'; frame-src 'none'; child-src 'none'; worker-src 'none'; " +
		"manifest-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'", nil
}

// securityHeaders go on every response the page gets.
func securityHeaders(csp string) map[string]string {
	return map[string]string{
		"Content-Security-Policy":      csp,
		"X-Content-Type-Options":       "nosniff",
		"Referrer-Policy":              "no-referrer",
		"Cross-Origin-Opener-Policy":   "same-origin",
		"Cross-Origin-Resource-Policy": "same-origin",
		"Cache-Control":                "no-store",
	}
}
