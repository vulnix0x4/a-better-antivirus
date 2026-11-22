package provenance

// describe is how a Result reads in an alert. Linux has no signatures: what
// vouches for a program is the package that owns it.
func describe(r Result) string {
	switch {
	case r.Valid:
		return "part of the " + r.Signer + " package"
	case r.Error != "":
		return r.Error
	}
	return "no package owns it"
}
