package netrec

import (
	"context"
	"os"
	"runtime"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// ABA_NET_COST=<seconds>: run the record that long and say what it cost
// (drive traffic meanwhile).
func TestCost(t *testing.T) {
	secs, _ := strconv.Atoi(os.Getenv("ABA_NET_COST"))
	if secs == 0 {
		t.Skip("ABA_NET_COST=<seconds>")
	}
	sessionName = SessionName + " (test)"
	r := New()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Watch(ctx, r, t.Logf) }()
	time.Sleep(time.Second)
	cpu0 := cpuTime()
	ev0 := events.Load()
	t0 := time.Now()
	var peak uint64
	for time.Since(t0) < time.Duration(secs)*time.Second {
		time.Sleep(5 * time.Second)
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		if m.HeapInuse > peak {
			peak = m.HeapInuse
		}
		r.Prune()
	}
	el := time.Since(t0)
	cpu := cpuTime() - cpu0
	n := events.Load() - ev0
	t.Logf("%.0f s: %d events (%.1f/s), CPU %v = %.3f%% of one core, heap peak %.1f MB, status %+v",
		el.Seconds(), n, float64(n)/el.Seconds(), cpu, 100*cpu.Seconds()/el.Seconds(), float64(peak)/(1<<20), r.Status())
	cancel()
	<-done
}

func cpuTime() time.Duration {
	var c, e, k, u windows.Filetime
	windows.GetProcessTimes(windows.CurrentProcess(), &c, &e, &k, &u)
	return time.Duration((int64(k.HighDateTime)<<32|int64(k.LowDateTime))+(int64(u.HighDateTime)<<32|int64(u.LowDateTime))) * 100
}
