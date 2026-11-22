package trust

// How Linux vouches for programs (a package owns them), in what trust says.
const (
	fingerprintWhy = "no package owns it, so it's only trusted by fingerprint"
	vouchedBy      = "from the package "
)
