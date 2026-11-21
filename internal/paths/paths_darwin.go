package paths

// macOS isn't supported yet: this file only lets the rest of ABA build there.
// Where ABA installs and keeps its data on macOS is for the port to decide.
// Until then both point at a folder that doesn't exist, so nothing is read or
// written by accident and ABA reports itself as not installed.

const (
	CLIExe     = "aba"
	ServiceExe = "famsvc"

	// The Mac's file systems ignore case unless a volume was formatted
	// otherwise.
	foldCase = true
)

const notPorted = "/nonexistent/aba-not-ported"

func InstallDir() string { return notPorted + "/program" }
func DataDir() string    { return notPorted + "/data" }

// Long has nothing to expand: there are no 8.3 short names here.
func Long(p string) string { return p }

// FileID identifies the file at p whatever name it's reached by (two hard
// links to one file have the same ID). Not written for macOS yet.
func FileID(p string) (string, bool) { return "", false }
