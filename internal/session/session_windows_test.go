package session

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// The test binary doubles as the launched program: it copies its standard
// input to the file named by its last argument.
func TestMain(m *testing.M) {
	if os.Getenv("ABA_SESSION_TEST_CHILD") == "1" {
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			b = []byte("read error: " + err.Error())
		}
		out := os.Args[len(os.Args)-1]
		os.WriteFile(out+".tmp", b, 0o644)
		os.Rename(out+".tmp", out)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// The service hands each alert to the popup program on its standard input.
// If that plumbing broke there would be no popups at all, so it's tested with
// this process's own token (the real thing needs the service's rights to get
// a user's token, but the pipe and the launch are the same).
func TestInputReachesTheLaunchedProgram(t *testing.T) {
	var tok windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY|windows.TOKEN_ASSIGN_PRIMARY, &tok); err != nil {
		t.Fatal(err)
	}
	defer tok.Close()
	var dup windows.Token
	if err := windows.DuplicateTokenEx(tok, windows.MAXIMUM_ALLOWED, nil, windows.SecurityImpersonation, windows.TokenPrimary, &dup); err != nil {
		t.Fatal(err)
	}
	defer dup.Close()
	t.Setenv("ABA_SESSION_TEST_CHILD", "1")

	for name, input := range map[string][]byte{
		"an alert":       []byte(`{"alert":{"id":"20260101-000000-abcd","title":"Possible stealer: crack.exe read your bait"}}`),
		"a large alert":  bytes.Repeat([]byte("0123456789abcdef"), 40_000), // 640 KB: more than a pipe buffers by default
		"an empty input": {},
	} {
		out := filepath.Join(t.TempDir(), "got.txt")
		if err := start(dup, nil, nil, os.Args[0], []string{"-test.run=^$", out}, input); err != nil {
			t.Skipf("can't start a program with a copy of this token here: %v", err)
		}
		var got []byte
		var err error
		for i := 0; i < 100; i++ {
			if got, err = os.ReadFile(out); err == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if err != nil {
			t.Fatalf("%s: the launched program never got its input (it would hang waiting for it): %v", name, err)
		}
		if !bytes.Equal(got, input) {
			t.Fatalf("%s: launched program received %d bytes, want %d", name, len(got), len(input))
		}
	}
}
