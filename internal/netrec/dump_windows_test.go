package netrec

import (
	"encoding/hex"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/vulnix0x4/a-better-antivirus/internal/etw"
)

// ABA_ETW_DUMP=1: print the process and DNS events of a curl run, raw.
func TestDumpEvents(t *testing.T) {
	if os.Getenv("ABA_ETW_DUMP") == "" {
		t.Skip("ABA_ETW_DUMP=1")
	}
	s, err := etw.Start(SessionName+" dump", providers)
	if err != nil {
		t.Fatal(err)
	}
	s.OnEvent = func(e *etw.EventRecord) {
		if e.Header.ProviderID == kernelNetwork {
			return
		}
		t.Logf("prov %s id %d v%d hdrpid %d len %d\n%s", e.Header.ProviderID, e.Header.ID, e.Header.Version, e.Header.ProcessID, len(e.Data()), hex.Dump(e.Data()))
	}
	done := make(chan error, 1)
	go func() { done <- s.Read() }()
	time.Sleep(500 * time.Millisecond)
	cmd := exec.Command(`C:\Windows\System32\curl.exe`, "-s", "-o", "NUL", "http://example.org/")
	cmd.Run()
	t.Logf("curl pid %d, me %d", cmd.ProcessState.Pid(), os.Getpid())
	time.Sleep(2500 * time.Millisecond)
	s.Stop()
	<-done
}
