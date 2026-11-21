package provenance

import "github.com/vulnix0x4/a-better-antivirus/internal/platform"

// Verify says who made the program at path. Not written for macOS yet: every
// program comes back as one nobody vouches for, which is the cautious answer.
func Verify(path string) Result {
	return Result{Error: platform.Unsupported("checking who made a program").Error()}
}
