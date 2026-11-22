package clipbait

// The clipboard keeper: saving and putting back the person's clipboard from a
// program running as them (`aba clipboard-keeper save|restore`, started by
// the Guard through AsUser).
//
// Why: the Guard runs as SYSTEM, and as SYSTEM, Windows hands it only the
// plain text of what most programs copy. The rest (a browser's or an
// editor's HTML, the new Notepad's OLE formats) comes back as "Element not
// found", though it's there and the person's own programs read it fine. The
// Guard won't put a bait over what it couldn't put back, so without the
// keeper it would skip nearly every real copy.
//
// The keeper only ever handles the person's own clipboard, and anything else
// running as them could read or change that anyway: tampering with it can't
// fake a catch, or hide a clipper, which is all the Guard's (and SYSTEM's) job.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"runtime"
	"slices"
	"time"

	"golang.org/x/sys/windows"
)

const keeperTimeout = 10 * time.Second

// keeperMsg is what goes between the Guard and the keeper, one JSON object
// each way.
type keeperMsg struct {
	Seq     uint32         `json:"seq,omitempty"`     // save: the clipboard's sequence number when read
	Formats []keeperFormat `json:"formats,omitempty"` // save: what was read; restore: what to put back
	Baits   []string       `json:"baits,omitempty"`   // restore: what may be replaced
	Skip    string         `json:"skip,omitempty"`    // save: why it can't be put back exactly (see Skipped)
	Done    bool           `json:"done,omitempty"`
	Error   string         `json:"error,omitempty"`
}

type keeperFormat struct {
	ID   uint32 `json:"id"`
	Name string `json:"name,omitempty"`
	Data []byte `json:"data"`
}

// RunKeeper is `aba clipboard-keeper <op>`: op "save" writes what's on the
// clipboard to out; "restore" reads what to put back from in, and does.
func RunKeeper(op string, in io.Reader, out io.Writer) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	// Its own window: putting things on the clipboard takes one.
	hwnd := makeWindow()
	if hwnd == 0 {
		return errors.New("clipbait: could not create a window")
	}
	defer pDestroyWindow.Call(hwnd)
	var m keeperMsg
	switch op {
	case "save":
		saved, at, err := readClipboard(hwnd)
		var skipped Skipped
		switch {
		case errors.As(err, &skipped):
			m.Skip = string(skipped)
		case err != nil:
			m.Error = err.Error()
		default:
			m.Seq, m.Done = at, true
			for _, f := range saved {
				m.Formats = append(m.Formats, keeperFormat{f.id, f.name, f.data})
			}
		}
	case "restore":
		var req keeperMsg
		if err := json.NewDecoder(io.LimitReader(in, 4*maxSavedBytes)).Decode(&req); err != nil {
			m.Error = "reading what to put back: " + err.Error()
			break
		}
		saved := make([]clipFormat, 0, len(req.Formats))
		for _, f := range req.Formats {
			saved = append(saved, clipFormat{f.ID, f.Name, f.Data})
		}
		isBait := func(s string) bool { return slices.Contains(req.Baits, s) }
		if writeClipboard(hwnd, saved, isBait) {
			m.Done = true
		} else {
			m.Error = "couldn't open the clipboard"
		}
	default:
		return fmt.Errorf("clipbait: no such keeper job %q", op)
	}
	return json.NewEncoder(out).Encode(m)
}

func (g *Guard) keeperSave() ([]clipFormat, uint32, error) {
	m, err := g.runKeeper("save", nil)
	if err != nil {
		return nil, 0, err
	}
	if m.Skip != "" {
		return nil, 0, Skipped(m.Skip)
	}
	saved := make([]clipFormat, 0, len(m.Formats))
	for _, f := range m.Formats {
		saved = append(saved, clipFormat{f.ID, f.Name, f.Data})
	}
	return saved, m.Seq, nil
}

func (g *Guard) keeperRestore() error {
	req := keeperMsg{Baits: g.baits}
	for _, f := range g.saved {
		req.Formats = append(req.Formats, keeperFormat{f.id, f.name, f.data})
	}
	in, err := json.Marshal(req)
	if err != nil {
		return err
	}
	_, err = g.runKeeper("restore", in)
	return err
}

// runKeeper starts the keeper as the person, hands it input, and returns its
// answer. It keeps answering the Guard's window meanwhile: putting the
// clipboard back empties a clipboard the Guard owns, and Windows tells the
// Guard's window before that can go on.
func (g *Guard) runKeeper(op string, input []byte) (keeperMsg, error) {
	h, err := g.AsUser("clipboard-keeper", op)
	if err != nil {
		return keeperMsg{}, fmt.Errorf("starting the keeper: %w", err)
	}
	defer h.Stop()
	type result struct {
		b   []byte
		err error
	}
	got := make(chan result, 1)
	go func() {
		b, err := io.ReadAll(io.LimitReader(h.Out, 4*maxSavedBytes))
		got <- result{b, err}
	}()
	go func() {
		if len(input) > 0 {
			h.In.Write(input)
		}
		h.In.Close()
	}()
	deadline := time.Now().Add(keeperTimeout)
	for {
		select {
		case r := <-got:
			if r.err != nil {
				return keeperMsg{}, r.err
			}
			var m keeperMsg
			if err := json.Unmarshal(r.b, &m); err != nil {
				s := string(r.b)
				if len(s) > 200 {
					s = s[:200] + "…"
				}
				return keeperMsg{}, fmt.Errorf("the keeper said %q", s)
			}
			if m.Error != "" {
				return m, errors.New(m.Error)
			}
			return m, nil
		default:
		}
		if time.Now().After(deadline) {
			windows.TerminateProcess(h.Process(), 1)
			return keeperMsg{}, errors.New("the keeper didn't answer in time")
		}
		pMsgWaitForMultipleObjects.Call(0, 0, 0, 10, qsAllInput)
		pump()
	}
}
