package cli

import (
	"bufio"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
)

func TestReportCommandsAreThere(t *testing.T) {
	root := newRoot()
	for _, name := range []string{"report", "reports"} {
		c, _, err := root.Find([]string{name})
		if err != nil || c.Name() != name {
			t.Fatalf("no `aba %s`: %v", name, err)
		}
		if c.Flags().Lookup("no-browser") == nil {
			t.Errorf("`aba %s` has no --no-browser", name)
		}
		if c.Hidden || c.GroupID != "respond" {
			t.Errorf("`aba %s` should be listed with the commands for when something trips", name)
		}
	}
}

// --no-browser prints the one-time address first, on a line of its own,
// and returns once the page has been fetched: what the e2e test and anyone
// without a browser on this computer use.
func TestShowPagePrintsTheAddressAndWaitsForTheLoad(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = stdout }()
	done := make(chan error, 1)
	noPause = false
	go func() { done <- showPage([]byte("<p>the report</p>"), true) }()
	url, err := bufio.NewReader(r).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	url = strings.TrimSpace(url)
	if !strings.HasPrefix(url, "http://127.0.0.1:") {
		t.Fatalf("first line %q, want the page's address", url)
	}
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != "<p>the report</p>" {
		t.Errorf("page %q", b)
	}
	if err := <-done; err != nil {
		t.Errorf("showPage: %v", err)
	}
	if !noPause {
		t.Error("the window should close by itself once the page is open")
	}
	if _, err := http.Get(url); err == nil {
		t.Error("the page is still served after the command ended")
	}
	w.Close()
}
