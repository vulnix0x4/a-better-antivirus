package trust

// How macOS vouches for programs (a valid code signature: Apple's, a
// Developer ID or the App Store's), in what trust says.
const (
	fingerprintWhy = "it has no valid signature, so it's only trusted by fingerprint"
	vouchedBy      = "signed by "
)
