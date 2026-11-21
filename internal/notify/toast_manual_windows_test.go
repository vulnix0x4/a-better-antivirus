package notify

import (
	"os"
	"os/exec"
	"testing"
)

// Run manually: ABA_TOAST_TEST=1 go test -run TestToastManual ./internal/notify/
func TestToastManual(t *testing.T) {
	if os.Getenv("ABA_TOAST_TEST") != "1" {
		t.Skip("shows a real notification; set ABA_TOAST_TEST=1")
	}
	toastRun = func(cmd *exec.Cmd) ([]byte, error) { return cmd.CombinedOutput() }
	Toast("ABA: Possible stealer: FreeRobux.exe read your bait", "DEMO notification from ABA's real code path. Nothing happened.")
	if lastToastErr != "" {
		t.Fatalf("toast failed: %s", lastToastErr)
	}
}
