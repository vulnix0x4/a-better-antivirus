package etw

import (
	"testing"
	"unsafe"
)

// The structures must be laid out as Windows' own (64-bit).
func TestLayouts(t *testing.T) {
	if unsafe.Sizeof(uintptr(0)) != 8 {
		t.Skip("64-bit only")
	}
	for _, c := range []struct {
		name      string
		got, want uintptr
	}{
		{"EVENT_TRACE_PROPERTIES", unsafe.Sizeof(traceProperties{}), 120},
		{"EVENT_TRACE_LOGFILEW", unsafe.Sizeof(eventTraceLogfile{}), 448},
		{"TRACE_LOGFILE_HEADER", unsafe.Sizeof(traceLogfileHeader{}), 280},
		{"EVENT_TRACE", unsafe.Sizeof(eventTrace{}), 88},
		{"EVENT_RECORD", unsafe.Sizeof(EventRecord{}), 112},
		{"EVENT_HEADER", unsafe.Sizeof(EventHeader{}), 80},
		{"ENABLE_TRACE_PARAMETERS", unsafe.Sizeof(enableParameters{}), 48},
		{"EventRecordCallback offset", unsafe.Offsetof(eventTraceLogfile{}.EventRecordCallback), 424},
		{"BufferCallback offset", unsafe.Offsetof(eventTraceLogfile{}.BufferCallback), 400},
		{"UserData offset", unsafe.Offsetof(EventRecord{}.UserData), 96},
	} {
		if c.got != c.want {
			t.Errorf("%s: %d, want %d", c.name, c.got, c.want)
		}
	}
}
