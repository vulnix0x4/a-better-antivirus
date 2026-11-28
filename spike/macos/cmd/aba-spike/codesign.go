//go:build darwin

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os/exec"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// Code-signing facts about a *running* process, straight from the kernel via
// csops(2). No cgo, no file I/O, a few microseconds. This is what the kernel
// itself validated when it mapped the code, so it describes what is running,
// not whatever file sits at that path now.
//
// It only says how the code is signed. Whether Apple notarized it is a
// separate question, answered (slowly) by notarized() below.

const (
	csOpsStatus   = 0
	csOpsCDHash   = 5
	csOpsIdentity = 11
	csOpsTeamID   = 14

	csValid          = 0x00000001
	csAdhoc          = 0x00000002
	csGetTaskAllow   = 0x00000004
	csHard           = 0x00000100
	csKill           = 0x00000200
	csRuntime        = 0x00010000
	csLinkerSigned   = 0x00020000
	csPlatformBinary = 0x04000000
	csSigned         = 0x20000000
	csDevCode        = 0x40000000
)

type signInfo struct {
	Flags     uint32
	SigningID string
	TeamID    string
	CDHash    string
	Err       string
}

func (s signInfo) Valid() bool    { return s.Flags&csValid != 0 }
func (s signInfo) Adhoc() bool    { return s.Flags&csAdhoc != 0 }
func (s signInfo) Platform() bool { return s.Flags&csPlatformBinary != 0 }
func (s signInfo) Hardened() bool { return s.Flags&csRuntime != 0 }

func (s signInfo) String() string {
	var f []string
	for _, x := range []struct {
		bit  uint32
		name string
	}{{csValid, "valid"}, {csAdhoc, "adhoc"}, {csLinkerSigned, "linker-signed"}, {csRuntime, "hardened-runtime"},
		{csPlatformBinary, "apple-platform-binary"}, {csGetTaskAllow, "get-task-allow"}, {csDevCode, "dev-signed"},
		{csHard, "hard"}, {csKill, "kill"}} {
		if s.Flags&x.bit != 0 {
			f = append(f, x.name)
		}
	}
	team := s.TeamID
	if team == "" {
		team = "none"
	}
	return fmt.Sprintf("id=%s team=%s flags=0x%x(%s) cdhash=%s", s.SigningID, team, s.Flags, strings.Join(f, ","), s.CDHash)
}

func csops(pid int, op int, buf []byte) error {
	_, _, e := syscall.Syscall6(syscall.SYS_CSOPS, uintptr(pid), uintptr(op),
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), 0, 0)
	if e != 0 {
		return e
	}
	return nil
}

// csopsString reads the blob-shaped answers (identity, team id): an 8-byte
// header (type, big-endian length including the header) and a C string.
func csopsString(pid, op int) string {
	buf := make([]byte, 1024)
	if err := csops(pid, op, buf); err != nil {
		return ""
	}
	n := int(binary.BigEndian.Uint32(buf[4:8]))
	if n < 8 || n > len(buf) {
		return ""
	}
	return string(bytes.TrimRight(buf[8:n], "\x00"))
}

func signInfoForPid(pid int) signInfo {
	var s signInfo
	var fl [4]byte
	if err := csops(pid, csOpsStatus, fl[:]); err != nil {
		s.Err = err.Error()
		return s
	}
	s.Flags = binary.LittleEndian.Uint32(fl[:])
	s.SigningID = csopsString(pid, csOpsIdentity)
	s.TeamID = csopsString(pid, csOpsTeamID)
	var h [20]byte
	if csops(pid, csOpsCDHash, h[:]) == nil {
		s.CDHash = hex.EncodeToString(h[:])
	}
	return s
}

// notarized asks the system whether the code at path satisfies the built-in
// "notarized" requirement. It shells out to codesign, which is what a cgo-free
// build can do; the cgo equivalent is SecStaticCodeCheckValidity with the same
// requirement string. Returns the answer and how long it took.
func notarized(path string) (bool, time.Duration, string) {
	t0 := time.Now()
	out, err := exec.Command("/usr/bin/codesign", "--verify", "-R=notarized", path).CombinedOutput()
	return err == nil, time.Since(t0), strings.TrimSpace(string(out))
}
