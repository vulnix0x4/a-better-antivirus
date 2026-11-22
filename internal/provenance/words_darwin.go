package provenance

// describe is how a Result reads in an alert.
func describe(r Result) string {
	switch {
	case r.Valid:
		s := "signed by " + r.Signer
		if r.Catalog {
			s += " (catalog)"
		}
		return s
	case r.Signed:
		return "INVALID signature (" + r.Error + ")"
	}
	return "unsigned"
}
