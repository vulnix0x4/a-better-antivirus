package session

// How the service picks the token to start the desktop app with, on a
// catch: the app should run with the person's full administrator rights (so
// what it shows is out of reach of their ordinary programs), without a UAC
// prompt (the service already is SYSTEM), and only when they are an
// administrator at all.

// Token elevation types (TOKEN_ELEVATION_TYPE).
const (
	elevationDefault = 1 // no split token: UAC off, a standard user, or the built-in Administrator
	elevationFull    = 2 // the elevated half of a split token
	elevationLimited = 3 // the filtered half: an admin with UAC on, signed in normally
)

// TokenPick is which token the app gets.
type TokenPick int

const (
	// PickLinked: the person is an administrator with UAC on; their session
	// token is the filtered one, so use its linked (elevated) twin.
	PickLinked TokenPick = iota
	// PickOwnFull: the session token already has full administrator rights
	// (UAC off, or the built-in Administrator).
	PickOwnFull
	// PickOwnLocked: a standard user. The app starts in its locked view
	// ("an administrator needs to decide"), with their own token.
	PickOwnLocked
)

func (p TokenPick) String() string {
	switch p {
	case PickLinked:
		return "linked (elevated) token"
	case PickOwnFull:
		return "own token (already full admin)"
	}
	return "own token (standard user: locked view)"
}

// Elevated reports whether the app will run with administrator rights.
func (p TokenPick) Elevated() bool { return p != PickOwnLocked }

// pickToken decides from the session token's elevation type and whether it
// has the Administrators group enabled (not deny-only).
func pickToken(elevationType uint32, adminEnabled bool) TokenPick {
	switch elevationType {
	case elevationLimited:
		return PickLinked
	case elevationFull:
		return PickOwnFull
	}
	if adminEnabled {
		return PickOwnFull
	}
	return PickOwnLocked
}

// tokenGroup is one group of a token: its SID and SE_GROUP_* attributes.
type tokenGroup struct {
	sid   string
	attrs uint32
}

const (
	seGroupEnabled           = 0x4
	seGroupUseForDenyOnly    = 0x10
	sidBuiltinAdministrators = "S-1-5-32-544"
)

// adminEnabled reports whether groups include Administrators, enabled and
// not just for deny (as a filtered UAC token has it).
func adminEnabled(groups []tokenGroup) bool {
	for _, g := range groups {
		if g.sid == sidBuiltinAdministrators && g.attrs&seGroupEnabled != 0 && g.attrs&seGroupUseForDenyOnly == 0 {
			return true
		}
	}
	return false
}
