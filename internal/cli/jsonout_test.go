package cli

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
)

// runJSON runs aba with args the way the desktop app does and returns its
// exit code and every line it printed.
func runJSON(t *testing.T, args ...string) (int, []string) {
	t.Helper()
	oldArgs, oldOut := os.Args, os.Stdout
	defer func() {
		os.Args, os.Stdout = oldArgs, oldOut
		jsonMode, yesMode, jsonOut, jsonDetails = false, false, nil, nil
	}()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Args = append([]string{"aba"}, args...)
	os.Stdout = w
	code := Execute()
	w.Close()
	b, _ := io.ReadAll(r)
	var lines []string
	sc := bufio.NewScanner(strings.NewReader(string(b)))
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	return code, lines
}

func lastResult(t *testing.T, lines []string) JSONResult {
	t.Helper()
	if len(lines) == 0 {
		t.Fatal("no output")
	}
	var res JSONResult
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &res); err != nil {
		t.Fatalf("last line isn't JSON: %q (%v)", lines[len(lines)-1], err)
	}
	return res
}

func TestJSONSuccess(t *testing.T) {
	code, lines := runJSON(t, "--json", "--version")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	if len(lines) != 1 {
		t.Fatalf("want exactly one line (the result), got %q", lines)
	}
	res := lastResult(t, lines)
	if !res.OK || !strings.Contains(res.Message, "A Better Antivirus") {
		t.Fatalf("got %+v", res)
	}
}

func TestJSONFailureKeepsExitCode(t *testing.T) {
	if isAdmin() {
		t.Skip("running as administrator")
	}
	// --json implies --yes: nothing asks for administrator rights, it fails.
	code, lines := runJSON(t, "preset", "strict", "--json")
	if code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
	res := lastResult(t, lines)
	if res.OK || !strings.Contains(res.Message, "administrator") {
		t.Fatalf("got %+v", res)
	}
}

func TestJSONUnknownCommand(t *testing.T) {
	code, lines := runJSON(t, "--json", "no-such-command")
	if code != 1 {
		t.Fatalf("exit %d", code)
	}
	if res := lastResult(t, lines); res.OK || res.Message == "" {
		t.Fatalf("got %+v", res)
	}
}

func TestScanModes(t *testing.T) {
	defer func() { jsonMode, yesMode = false, false }()
	scanModes([]string{"kill", "abcd", "--yes"})
	if jsonMode || !yesMode {
		t.Fatal("--yes alone")
	}
	jsonMode, yesMode = false, false
	scanModes([]string{"bait", "show", "--", "--json"})
	if jsonMode || yesMode {
		t.Fatal("after --")
	}
	scanModes([]string{"--json", "test"})
	if !jsonMode || !yesMode {
		t.Fatal("--json implies --yes")
	}
}

func TestPlainMessage(t *testing.T) {
	in := "\x1b[32m✓\x1b[0m killed NitroGen-Free.exe (pid 9120)\n\n ✗ kill pid 9188: access denied\n  Press Enter to close this window…\n"
	want := "killed NitroGen-Free.exe (pid 9120)\nkill pid 9188: access denied"
	if got := plainMessage(in); got != want {
		t.Fatalf("got %q", got)
	}
}

func TestStepOnlyWithJSON(t *testing.T) {
	defer func() { jsonMode, jsonOut = false, nil }()
	var b strings.Builder
	jsonOut = &b
	step("nothing")
	if b.Len() != 0 {
		t.Fatal("step printed without --json")
	}
	jsonMode = true
	step("Waiting for ABA to catch it…")
	var ev JSONEvent
	if err := json.Unmarshal([]byte(strings.TrimSpace(b.String())), &ev); err != nil || ev.Event != "step" || ev.Text == "" {
		t.Fatalf("got %q", b.String())
	}
}

// isAdmin: with --yes, requireAdmin only checks.
func isAdmin() bool {
	yesMode = true
	defer func() { yesMode = false }()
	return requireAdmin() == nil
}
