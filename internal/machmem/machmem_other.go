//go:build darwin && !cgo

package machmem

import "errors"

// Read can't read another process's memory in a build without cgo.
func Read(pid uint32, limit int64, fn func(base uint64, b []byte) bool) (int64, error) {
	return 0, errors.New("this build of ABA can't read a program's memory on macOS (it was built without cgo)")
}
