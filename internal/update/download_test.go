package update

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vulnix0x4/a-better-antivirus/internal/minertrap"
)

// fakeReleases serves one release, v9.9.9, the way GitHub does: its JSON,
// and its files, the checksum list signed with a key of the test's own.
func fakeReleases(t *testing.T, files map[string][]byte, tamper string) (*httptest.Server, *Release) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	oldKey, oldAPI, oldRel, oldHosts, oldClient := PublicKey, API, ReleasesAPI, TrustedHosts, client
	t.Cleanup(func() {
		PublicKey, API, ReleasesAPI, TrustedHosts, client = oldKey, oldAPI, oldRel, oldHosts, oldClient
	})
	PublicKey = base64.StdEncoding.EncodeToString(pub)

	var sums strings.Builder
	for name, b := range files {
		h := sha256.Sum256(b)
		fmt.Fprintf(&sums, "%s  %s\n", hex.EncodeToString(h[:]), name)
	}
	all := map[string][]byte{sumsName: []byte(sums.String())}
	all[sumsName+".sig"] = []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv, all[sumsName])))
	for name, b := range files {
		all[name] = b
	}
	if tamper != "" {
		all[tamper] = append([]byte("tampered "), all[tamper]...)
	}
	mux := http.NewServeMux()
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	rel := &Release{Tag: "v9.9.9"}
	for name := range all {
		rel.Assets = append(rel.Assets, Asset{Name: name, URL: srv.URL + "/dl/" + name})
	}
	mux.HandleFunc("/dl/", func(w http.ResponseWriter, r *http.Request) {
		b, ok := all[strings.TrimPrefix(r.URL.Path, "/dl/")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write(b)
	})
	mux.HandleFunc("/releases/tags/v9.9.9", func(w http.ResponseWriter, r *http.Request) { json.NewEncoder(w).Encode(rel) })
	ReleasesAPI = srv.URL + "/releases"
	TrustedHosts = []string{strings.TrimPrefix(srv.URL, "https://")}
	client = srv.Client()
	return srv, rel
}

func TestDownloadBringsThePoolList(t *testing.T) {
	exe := AssetName("v9.9.9")
	list := []byte("pool.example.org\n")
	_, rel := fakeReleases(t, map[string][]byte{exe: []byte("new program"), minertrap.PoolsFileName: list}, "")
	dir := t.TempDir()
	out, err := Download(context.Background(), rel, dir)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(out); string(b) != "new program" {
		t.Errorf("exe: %q", b)
	}
	if b, err := os.ReadFile(PoolsBeside(out)); err != nil || string(b) != string(list) {
		t.Errorf("pool list beside the exe: %q %v", b, err)
	}
	got, err := Pools(context.Background(), "v9.9.9")
	if err != nil || string(got) != string(list) {
		t.Errorf("Pools: %q %v", got, err)
	}
	// Only published versions have one to fetch.
	if _, err := Pools(context.Background(), "ci-abc"); err == nil {
		t.Error("fetched a list for a build that was never published")
	}
}

func TestDownloadRefusesATamperedPoolList(t *testing.T) {
	exe := AssetName("v9.9.9")
	_, rel := fakeReleases(t, map[string][]byte{exe: []byte("new program"), minertrap.PoolsFileName: []byte("pool.example.org\n")}, minertrap.PoolsFileName)
	dir := t.TempDir()
	if _, err := Download(context.Background(), rel, dir); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Errorf("a list that isn't the signed one was taken: %v", err)
	}
	if _, err := Pools(context.Background(), "v9.9.9"); err == nil {
		t.Error("Pools took a list that isn't the signed one")
	}
	if files, _ := filepath.Glob(filepath.Join(dir, "*")); len(files) != 0 {
		t.Errorf("left behind: %v", files)
	}
}

func TestDownloadWithoutAPoolList(t *testing.T) {
	// Releases from before the list was a file of its own.
	exe := AssetName("v9.9.9")
	_, rel := fakeReleases(t, map[string][]byte{exe: []byte("new program")}, "")
	out, err := Download(context.Background(), rel, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(PoolsBeside(out)); err == nil {
		t.Error("a pool list out of nowhere")
	}
}
