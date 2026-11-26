package engine

const (
	// disguiseWhy: a copy of ABA's own program read a bait without the rights
	// ABA's tooling always has.
	disguiseWhy = "it's a copy of ABA's own program reading a bait without root: ABA never does that, so something is using it as a disguise"
	asAdmin     = " runs as root"
	// instantJudgesAdmins: a program running as root got there through sudo
	// (your password) or is a system service, so the instant path leaves it to
	// the event path, which judges its read in full.
	instantJudgesAdmins = false
)
