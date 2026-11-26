package engine

const (
	// disguiseWhy: a copy of ABA's own program read a bait without the rights
	// ABA's tooling always has.
	disguiseWhy = "it's a copy of ABA's own program reading a bait without admin rights: ABA never does that, so something is using it as a disguise"
	asAdmin     = " runs as administrator"
	// instantJudgesAdmins: on Windows a stealer often gets administrator
	// rights without you noticing (a silent UAC bypass, or one prompt you
	// clicked through), so the instant path judges elevated programs too.
	instantJudgesAdmins = true
)
