//go:build darwin

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

// eslogger is Apple's command-line Endpoint Security client. It needs root and
// Full Disk Access (for whoever is "responsible" for it: under launchd, the
// daemon that starts it) but no entitlement. It prints one JSON object per
// event. It cannot be told which paths to watch, so it reports every open on
// the Mac and the filtering is ours to do.

type auditToken struct {
	Pid        int `json:"pid"`
	PidVersion int `json:"pidversion"`
	EUID       int `json:"euid"`
	RUID       int `json:"ruid"`
}

type esProcess struct {
	AuditToken            auditToken  `json:"audit_token"`
	ParentAuditToken      *auditToken `json:"parent_audit_token"`
	ResponsibleAuditToken *auditToken `json:"responsible_audit_token"`
	PPid                  int         `json:"ppid"`
	OriginalPPid          int         `json:"original_ppid"`
	Executable            struct {
		Path string `json:"path"`
	} `json:"executable"`
	SigningID        string  `json:"signing_id"`
	TeamID           *string `json:"team_id"`
	CDHash           string  `json:"cdhash"`
	CodesigningFlags uint32  `json:"codesigning_flags"`
	IsPlatformBinary bool    `json:"is_platform_binary"`
	StartTime        string  `json:"start_time"`
}

type esEvent struct {
	Time         string                     `json:"time"`
	MachTime     uint64                     `json:"mach_time"`
	SeqNum       uint64                     `json:"seq_num"`
	GlobalSeqNum uint64                     `json:"global_seq_num"`
	EventType    int                        `json:"event_type"`
	Process      esProcess                  `json:"process"`
	Event        map[string]json.RawMessage `json:"event"`
}

func (e *esEvent) kind() string {
	for k := range e.Event {
		return k
	}
	return "?"
}

func (e *esEvent) when() time.Time {
	t, _ := time.Parse(time.RFC3339Nano, e.Time)
	return t
}

func (p *esProcess) facts() procFacts {
	team := ""
	if p.TeamID != nil {
		team = *p.TeamID
	}
	return procFacts{Pid: p.AuditToken.Pid, PPid: p.PPid, Path: p.Executable.Path, Platform: p.IsPlatformBinary,
		TeamID: team, SigningID: p.SigningID, CSFlags: p.CodesigningFlags}
}

type esStream struct {
	cmd    *exec.Cmd
	out    io.ReadCloser
	stderr bytes.Buffer
	Lines  atomic.Uint64
	Bytes  atomic.Uint64
}

// startEslogger runs eslogger for the given events. eslogger leaves out
// everything done by its own process group, which here means this daemon and
// whatever it starts without a new process group: the watcher never sees
// itself.
func startEslogger(events []string) (*esStream, error) {
	s := &esStream{}
	s.cmd = exec.Command("/usr/bin/eslogger", events...)
	s.cmd.Stderr = &s.stderr
	var err error
	if s.out, err = s.cmd.StdoutPipe(); err != nil {
		return nil, err
	}
	if err := s.cmd.Start(); err != nil {
		return nil, err
	}
	return s, nil
}

// each calls fn with every line eslogger prints, until it exits. The slice is
// only valid during the call.
func (s *esStream) each(fn func(line []byte)) error {
	r := bufio.NewReaderSize(s.out, 4<<20)
	for {
		line, err := r.ReadSlice('\n')
		if err == bufio.ErrBufferFull {
			// A single event bigger than the buffer (an exec with a huge
			// environment). Skip the rest of it.
			for err == bufio.ErrBufferFull {
				_, err = r.ReadSlice('\n')
			}
			continue
		}
		if len(line) > 0 {
			s.Lines.Add(1)
			s.Bytes.Add(uint64(len(line)))
			fn(line)
		}
		if err != nil {
			werr := s.cmd.Wait()
			if msg := strings.TrimSpace(s.stderr.String()); msg != "" {
				return fmt.Errorf("eslogger: %s (%v)", msg, werr)
			}
			return werr
		}
	}
}

func (s *esStream) stop() {
	if s.cmd.Process != nil {
		s.cmd.Process.Signal(syscall.SIGTERM)
	}
}

// cpu returns the CPU time eslogger itself used; valid after it has exited.
func (s *esStream) cpu() time.Duration {
	if s.cmd.ProcessState == nil {
		return 0
	}
	return s.cmd.ProcessState.UserTime() + s.cmd.ProcessState.SystemTime()
}

func selfCPU() time.Duration {
	var ru syscall.Rusage
	syscall.Getrusage(syscall.RUSAGE_SELF, &ru)
	return time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
}

// needles turns bait paths into the byte strings to look for in a raw event
// line, so that only lines about a bait are ever parsed as JSON. JSON may
// write "/" as "\/", so both spellings are searched.
func needles(paths []string) [][]byte {
	var n [][]byte
	for _, p := range paths {
		q, _ := json.Marshal(p)
		plain := q[1 : len(q)-1]
		n = append(n, append([]byte(nil), plain...))
		esc := bytes.ReplaceAll(plain, []byte("/"), []byte(`\/`))
		if !bytes.Equal(esc, plain) {
			n = append(n, esc)
		}
	}
	return n
}

func matchAny(line []byte, ns [][]byte) bool {
	for _, n := range ns {
		if bytes.Contains(line, n) {
			return true
		}
	}
	return false
}

// pathsIn pulls every "path" string out of an event's payload, whatever the
// event type: open has file.path, clone has source.path, rename has
// source.path and destination..., and so on.
func pathsIn(raw json.RawMessage) []string {
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return nil
	}
	var out []string
	var walk func(any)
	walk = func(x any) {
		switch t := x.(type) {
		case map[string]any:
			for k, val := range t {
				if s, ok := val.(string); ok && k == "path" {
					out = append(out, s)
				} else {
					walk(val)
				}
			}
		case []any:
			for _, val := range t {
				walk(val)
			}
		}
	}
	walk(v)
	return out
}

func die(format string, a ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
	os.Exit(1)
}
