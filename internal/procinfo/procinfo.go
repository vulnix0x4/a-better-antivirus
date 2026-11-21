// Package procinfo inspects and controls processes: image path, command line,
// parent chain, process trees, suspend/resume/kill, hashes and open connections.
//
// This file is the part that's the same on every operating system: walking
// process trees and freezing or killing them, built on a handful of
// primitives. The primitives themselves (list processes, name a process's
// executable, suspend, resume, kill, hold frozen, list connections…) are in
// the *_<os>.go files.
package procinfo

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sort"
)

// Entry is one row of a process snapshot.
type Entry struct {
	PID        uint32
	PPID       uint32
	Exe        string // file name only
	CreateTime int64  // when it started, in the operating system's own units (only ever compared); 0 if unavailable
}

// Parent describes one ancestor.
type Parent struct {
	PID         uint32 `json:"pid"`
	Image       string `json:"image,omitempty"`
	CommandLine string `json:"commandLine,omitempty"`
	Exited      bool   `json:"exited,omitempty"`
}

// ParentChain walks up to depth ancestors, stopping at PID reuse.
func ParentChain(snap map[uint32]Entry, pid uint32, depth int) []Parent {
	var out []Parent
	cur, ok := snap[pid]
	if !ok {
		return nil
	}
	for i := 0; i < depth; i++ {
		pp, ok := snap[cur.PPID]
		if !ok || cur.PPID == 0 || cur.PPID == cur.PID {
			if cur.PPID != 0 {
				out = append(out, Parent{PID: cur.PPID, Exited: true})
			}
			break
		}
		// A parent created after the child means the PID was reused.
		if pp.CreateTime != 0 && cur.CreateTime != 0 && pp.CreateTime > cur.CreateTime {
			out = append(out, Parent{PID: cur.PPID, Exited: true})
			break
		}
		p := Parent{PID: pp.PID, Image: pp.Exe}
		if img, err := ImagePath(pp.PID); err == nil {
			p.Image = img
		}
		p.CommandLine, _ = CommandLine(pp.PID)
		out = append(out, p)
		cur = pp
	}
	return out
}

// Tree returns pid and all its descendants (parents first), guarding against PID reuse.
func Tree(snap map[uint32]Entry, pid uint32) []uint32 {
	children := map[uint32][]uint32{}
	for _, e := range snap {
		if e.PID != e.PPID {
			children[e.PPID] = append(children[e.PPID], e.PID)
		}
	}
	for k := range children {
		sort.Slice(children[k], func(i, j int) bool { return children[k][i] < children[k][j] })
	}
	seen := map[uint32]bool{}
	out := []uint32{}
	var walk func(uint32)
	walk = func(p uint32) {
		if seen[p] {
			return
		}
		seen[p] = true
		out = append(out, p)
		parent := snap[p]
		for _, c := range children[p] {
			ce := snap[c]
			if parent.CreateTime != 0 && ce.CreateTime != 0 && ce.CreateTime < parent.CreateTime {
				continue // older than "parent": PID reuse, not a real child
			}
			walk(c)
		}
	}
	walk(pid)
	return out
}

// SuspendTree freezes pid and its descendants. It re-snapshots once to catch
// children spawned while we were freezing. Returns the PIDs frozen.
func SuspendTree(pid uint32) ([]uint32, error) {
	var frozen []uint32
	done := map[uint32]bool{}
	var firstErr error
	// Freeze the reader itself immediately: every millisecond counts, and the
	// process snapshot below takes a while on a busy machine.
	if !systemPID(pid) && pid != uint32(os.Getpid()) {
		done[pid] = true
		if err := Suspend(pid); err != nil {
			firstErr = err
		} else {
			frozen = append(frozen, pid)
		}
	}
	for pass := 0; pass < 2; pass++ {
		snap, err := Snapshot()
		if err != nil {
			return frozen, err
		}
		for _, p := range Tree(snap, pid) {
			if done[p] || systemPID(p) || p == uint32(os.Getpid()) {
				continue
			}
			done[p] = true
			if err := Suspend(p); err != nil {
				if firstErr == nil && p == pid {
					firstErr = err
				}
				continue
			}
			frozen = append(frozen, p)
		}
	}
	return frozen, firstErr
}

// KillTree terminates pid and its descendants (children first).
func KillTree(pid uint32) error {
	snap, err := Snapshot()
	if err != nil {
		return err
	}
	tree := Tree(snap, pid)
	var firstErr error
	for i := len(tree) - 1; i >= 0; i-- {
		if tree[i] == uint32(os.Getpid()) {
			continue
		}
		if err := Kill(tree[i]); err != nil && firstErr == nil && tree[i] == pid {
			firstErr = err
		}
	}
	return firstErr
}

// FileSHA256 hashes a file (used on the reader's executable, never on baits).
func FileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Conn is one socket owned by a process.
type Conn struct {
	PID    uint32 `json:"pid"`
	Proto  string `json:"proto"` // tcp | tcp6 | udp | udp6
	Local  string `json:"local"`
	Remote string `json:"remote,omitempty"`
	State  string `json:"state,omitempty"`
}

// HoldName identifies a process for holds: its PID and creation time.
func HoldName(pid uint32, createTime int64) string {
	return fmt.Sprintf("%d-%x", pid, uint64(createTime))
}

// SuspendTreeExcept freezes pid and its descendants, leaving out the
// processes in skip (already frozen: suspensions stack, so freezing one twice
// would need two unfreezes) and any that ok (if given) turns down. Returns
// the PIDs it froze.
func SuspendTreeExcept(pid uint32, skip map[uint32]bool, ok func(pid uint32) bool) []uint32 {
	var frozen []uint32
	done := map[uint32]bool{}
	for pass := 0; pass < 2; pass++ {
		snap, err := Snapshot()
		if err != nil {
			return frozen
		}
		for _, p := range Tree(snap, pid) {
			if done[p] || skip[p] || systemPID(p) || p == uint32(os.Getpid()) {
				continue
			}
			done[p] = true
			if ok != nil && !ok(p) {
				continue
			}
			if Suspend(p) == nil {
				frozen = append(frozen, p)
			}
		}
	}
	return frozen
}

// Ancestor is one process up the chain from a reader.
type Ancestor struct {
	PID        uint32
	Image      string
	CreateTime int64
}

// Ancestors walks up from pid: its parent, grandparent… (at most depth),
// stopping where the chain can't be trusted (the parent exited and its PID
// was reused).
func Ancestors(pid uint32, depth int) []Ancestor {
	snap, err := Snapshot()
	if err != nil {
		return nil
	}
	var out []Ancestor
	cur, ok := snap[pid]
	for i := 0; ok && i < depth; i++ {
		pp, found := snap[cur.PPID]
		if !found || cur.PPID == 0 || cur.PPID == cur.PID {
			break
		}
		if pp.CreateTime != 0 && cur.CreateTime != 0 && pp.CreateTime > cur.CreateTime {
			break // created after its "child": a reused PID
		}
		img, _ := ImagePath(pp.PID)
		out = append(out, Ancestor{PID: pp.PID, Image: img, CreateTime: pp.CreateTime})
		cur = pp
	}
	return out
}
