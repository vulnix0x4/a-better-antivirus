package autopsy

import (
	"testing"

	"github.com/vulnix0x4/a-better-antivirus/internal/recorder"
)

// A real browser frozen for something else opens its own profiles all day:
// those opens aren't counted as taken. Its opens of another app's data, and
// anyone else's opens of its data, still are.
func TestOwnAppsOpensOfItsOwnDataDontCount(t *testing.T) {
	res := recorder.Result{
		Reads: []recorder.Read{
			{Store: "edge-profile", PID: 1116},   // Edge reading Edge: its own
			{Store: "chrome-profile", PID: 1116}, // Edge reading Chrome: not its own
			{Store: "edge-profile", PID: 777},    // a stealer reading Edge
		},
		Doubts: []recorder.Doubt{{Store: "edge-profile", PID: 1116}, {Store: "edge-profile", PID: 777}},
	}
	got := withoutOwn(res, map[uint32]string{1116: "edge-profile"})
	if len(got.Reads) != 2 || got.Reads[0].Store != "chrome-profile" || got.Reads[1].PID != 777 {
		t.Fatalf("reads: %+v", got.Reads)
	}
	if len(got.Doubts) != 1 || got.Doubts[0].PID != 777 {
		t.Fatalf("doubts: %+v", got.Doubts)
	}
	if same := withoutOwn(res, nil); len(same.Reads) != 3 {
		t.Fatal("nothing to leave out")
	}
}
