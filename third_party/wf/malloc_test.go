package wf

import (
	"runtime"
	"testing"
	"unsafe"
)

// Everything the arena hands out must be pointer-aligned: the structs put
// there hold pointers, and copying one to an unaligned address while a GC is
// running makes the runtime throw (see Alloc). Strings come in sizes that are
// only even, so the struct after one used to land 2, 4 or 6 bytes off.
func TestAllocIsAligned(t *testing.T) {
	var a arena
	defer a.Dispose()
	for i, n := range []uintptr{6, 1, 2, 3, 10, 14, 7, 8, 4090, 2, 30} {
		p := uintptr(a.Alloc(n))
		if p%allocAlign != 0 {
			t.Fatalf("allocation %d (%d bytes) at %#x, not %d-aligned", i, n, p, allocAlign)
		}
	}
}

// The crash itself: a rule whose name is an odd number of characters long
// (a 2-byte multiple once it is UTF-16 with its terminator), converted while
// the garbage collector keeps its write barrier on.
func TestToFilterDuringGC(t *testing.T) {
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
				runtime.GC()
			}
		}
	}()
	lt := layerTypes{}
	for i := 0; i < 20000; i++ {
		var a arena
		a.Alloc(6) // what a condition stores first, e.g. a UTF-16 program path
		r := &Rule{Name: "ab", Description: "abcd", Layer: LayerALEAuthConnectV4}
		f, err := toFilter0(&a, r, lt)
		if err != nil {
			t.Fatal(err)
		}
		if uintptr(unsafe.Pointer(f))%allocAlign != 0 {
			t.Fatalf("filter at %#x, not %d-aligned", uintptr(unsafe.Pointer(f)), allocAlign)
		}
		a.Dispose()
	}
}
