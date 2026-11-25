//go:build windows && !amd64

package procinfo

// atThreadStart reads a thread's instruction pointer on x64 only; elsewhere
// NeverRan goes by its state and times alone.
func atThreadStart(tid uint32) (at, known bool) { return false, false }
