package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/x/ansi"

	"github.com/vulnix0x4/a-better-antivirus/internal/ui"
)

// --json and --yes are for programs that run aba (the desktop app):
//
//   - --json: whatever the command prints for people is kept back; at the
//     end one line of JSON is printed instead, {"ok", "message", "details"}.
//     A long command (test, update) prints progress lines before it, each
//     {"event": "step", "text", "time"}. The exit code is the same as without.
//   - --yes: never ask. A question gets its default answer (the one that
//     changes least), and a command that needs administrator rights fails
//     instead of asking Windows for them.
var (
	jsonMode bool
	yesMode  bool
)

// JSONResult is the last line --json prints.
type JSONResult struct {
	OK      bool   `json:"ok"`
	Message string `json:"message"`
	Details any    `json:"details,omitempty"`
}

// JSONEvent is a progress line.
type JSONEvent struct {
	Event string    `json:"event"`
	Text  string    `json:"text"`
	Time  time.Time `json:"time"`
}

var (
	jsonOut     io.Writer // the real standard output, while it's captured
	jsonMu      sync.Mutex
	jsonDetails any
)

// setDetails gives the --json result its details.
func setDetails(v any) {
	jsonMu.Lock()
	jsonDetails = v
	jsonMu.Unlock()
}

// step prints a progress line (only with --json).
func step(text string) {
	if !jsonMode || jsonOut == nil {
		return
	}
	b, _ := json.Marshal(JSONEvent{Event: "step", Text: text, Time: time.Now()})
	jsonMu.Lock()
	jsonOut.Write(append(b, '\n'))
	jsonMu.Unlock()
}

// scanModes sets jsonMode and yesMode from the command line before cobra
// parses it (they decide how the whole run behaves, the parsing's errors
// included).
func scanModes(args []string) {
	for _, a := range args {
		if a == "--" {
			break
		}
		switch a {
		case "--json":
			jsonMode = true
		case "--yes":
			yesMode = true
		}
	}
	if jsonMode {
		yesMode = true // nobody is there to answer
	}
}

// captureStdout sends what's printed for people to a buffer; the returned
// function ends that and gives it back.
func captureStdout() (restore func() string) {
	real := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		jsonOut = real
		return func() string { return "" }
	}
	jsonOut = real
	os.Stdout = w
	var buf bytes.Buffer
	done := make(chan struct{})
	go func() {
		io.Copy(&buf, io.LimitReader(r, 4<<20))
		io.Copy(io.Discard, r)
		close(done)
	}()
	return func() string {
		w.Close()
		<-done
		r.Close()
		os.Stdout = real
		return buf.String()
	}
}

// plainMessage turns what a command printed for people into the message:
// colours and the ✓/✗ marks off, blank lines and banners out.
func plainMessage(out string) string {
	var lines []string
	for _, l := range strings.Split(ansi.Strip(out), "\n") {
		l = strings.TrimSpace(l)
		for _, icon := range []string{ui.IconOK, ui.IconBad, ui.IconWarn, ui.IconArr, "!"} {
			if strings.HasPrefix(l, icon+" ") {
				l = strings.TrimSpace(strings.TrimPrefix(l, icon))
			}
		}
		if l == "" || strings.HasPrefix(l, "Press Enter") {
			continue
		}
		lines = append(lines, l)
	}
	return strings.Join(lines, "\n")
}

// printJSON prints the result line.
func printJSON(err error, printed string) {
	res := JSONResult{OK: err == nil, Message: plainMessage(printed)}
	jsonMu.Lock()
	res.Details = jsonDetails
	jsonMu.Unlock()
	if err != nil {
		msg := err.Error()
		if res.Message != "" {
			msg = res.Message + "\n" + msg
		}
		res.Message = msg
	}
	b, _ := json.Marshal(res)
	w := jsonOut
	if w == nil {
		w = os.Stdout
	}
	jsonMu.Lock()
	w.Write(append(b, '\n'))
	jsonMu.Unlock()
}
