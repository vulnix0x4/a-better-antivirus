package procinfo

import (
	"strings"

	"golang.org/x/sys/windows"
)

// systemPID: the idle process and the kernel ("System"). Never touched.
func systemPID(pid uint32) bool { return pid == 0 || pid == 4 }

// SelfElevated reports whether this process runs with an elevated admin token.
func SelfElevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

// Elevated reports whether pid runs at high (admin) or system integrity, the
// same line UAC draws. (TokenIsElevated isn't enough: restricted tokens made
// from an admin, e.g. by `runas /trustlevel`, can still claim to be elevated.)
func Elevated(pid uint32) bool {
	lvl, err := IntegrityLevel(pid)
	if err != nil {
		return true // can't inspect it: don't instant-freeze
	}
	return lvl >= IntegrityHigh
}

// UserSession reports whether pid is an ordinary user's program rather than
// part of Windows' services. Normally that's "not in session 0". But a
// scheduled task can run a program as you in session 0 too, without admin
// rights, and that must not make a stealer count as a service: there, it's
// the account that tells.
func UserSession(pid uint32) bool {
	var sid uint32
	if err := windows.ProcessIdToSessionId(pid, &sid); err != nil {
		return false
	}
	if sid != 0 {
		return true
	}
	u, err := UserID(pid)
	return err == nil && !ServiceAccount(u)
}

// ServiceAccount reports whether the account with this ID (a SID) is one
// services run as: SYSTEM, LOCAL/NETWORK SERVICE and per-service accounts.
func ServiceAccount(sid string) bool {
	switch sid {
	case "S-1-5-18", "S-1-5-19", "S-1-5-20":
		return true
	}
	for _, p := range []string{"S-1-5-80-", "S-1-5-82-", "S-1-5-90-", "S-1-5-96-"} {
		if strings.HasPrefix(sid, p) {
			return true
		}
	}
	return false
}
