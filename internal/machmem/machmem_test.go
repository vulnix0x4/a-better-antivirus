//go:build darwin && cgo

package machmem

import (
	"bytes"
	"os"
	"runtime"
	"testing"
)

// A process may always look into itself, which is enough to check the
// walk over its regions and the reads.
func TestReadsOwnMemory(t *testing.T) {
	marker := bytes.Repeat([]byte("ABA-machmem-marker:"), 1000)
	found := false
	n, err := Read(uint32(os.Getpid()), 1<<34, func(base uint64, b []byte) bool {
		if bytes.Contains(b, []byte("ABA-machmem-marker:ABA-machmem-marker:")) {
			found = true
			return false
		}
		return true
	})
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Errorf("read %d bytes of its own memory without finding the marker", n)
	}
	runtime.KeepAlive(marker)
}

func TestLimit(t *testing.T) {
	n, err := Read(uint32(os.Getpid()), 3<<20, func(uint64, []byte) bool { return true })
	if err != nil || n > 3<<20 {
		t.Errorf("read %d (%v)", n, err)
	}
}
