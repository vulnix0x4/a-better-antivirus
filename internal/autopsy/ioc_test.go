package autopsy

import "testing"

// The shareable file names no account: not through the home folder's short
// name on Windows, and not when the program ran from someone else's folder.
func TestRedactHomeUnderAnyName(t *testing.T) {
	for _, c := range []struct{ path, home, want string }{
		{`C:\Users\RUNNER~1\AppData\Local\Temp\stealer1.exe`, `C:\Users\runneradmin`, `~\AppData\Local\Temp\stealer1.exe`},
		{`c:\users\Other Person\Downloads\x.exe`, `C:\Users\bob`, `~\Downloads\x.exe`},
		{"/Users/someone/Downloads/x", "/Users/bob", "~/Downloads/x"},
		{"/home/someone/.cache/x", "/home/bob", "~/.cache/x"},
		{`C:\ProgramData\x\y.exe`, `C:\Users\bob`, `C:\ProgramData\x\y.exe`},
		{"/tmp/x", "/home/bob", "/tmp/x"},
	} {
		if got := redactHome(c.path, c.home); got != c.want {
			t.Errorf("redactHome(%q, %q) = %q, want %q", c.path, c.home, got, c.want)
		}
	}
}
