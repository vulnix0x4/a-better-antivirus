package provenance

// describe is how a Result reads in an alert. On macOS a program that isn't
// vouched for is often signed after a fashion (ad-hoc, which anyone can do,
// or for development only): Error says how.
func describe(r Result) string {
	switch {
	case r.Valid:
		return "signed by " + r.Signer
	case r.Error != "":
		return "no valid signature: " + r.Error
	}
	return "unsigned"
}
