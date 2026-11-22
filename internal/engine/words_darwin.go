package engine

const (
	// disguiseWhy: a copy of ABA's own program read a bait without the rights
	// ABA's tooling always has (on macOS, root: through sudo or the service).
	disguiseWhy = "it's a copy of ABA's own program reading a bait without root: ABA never does that, so something is using it as a disguise"
	asAdmin     = " runs as root"
)
